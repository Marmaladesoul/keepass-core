//! Group-tree LWW reconciliation, entry / group timestamp
//! reconciliation, and tombstone union. Pure tree-mutation helpers
//! split off from `apply::mod`'s top-level `apply_merge` flow so the
//! file stays a manageable size.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Binary, DeletedObject, Entry, EntryId, Group, GroupId, Vault};
use uuid::Uuid;

use crate::binary_pool::BinaryPoolRemap;
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::hash::entry_content_hash;
use crate::history_merge::merge_histories;

use super::resolution::{apply_attachment_resolutions, rebind_history, set_field_from};
use super::{collect_group_ids, collect_groups, find_group_mut};

// ---------------------------------------------------------------------------
// Group-tree LWW reconciliation
// ---------------------------------------------------------------------------

pub(super) fn apply_group_tree(local: &mut Vault, remote: &Vault) {
    let local_tombstones: HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>> = local
        .deleted_objects
        .iter()
        .map(|t| (t.uuid, t.deleted_at))
        .collect();
    let remote_tombstones: HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>> = remote
        .deleted_objects
        .iter()
        .map(|t| (t.uuid, t.deleted_at))
        .collect();

    // Pass 1: take later-mtime metadata for every group present on both
    // sides. Recursive so nested groups are handled.
    take_later_group_metadata(&mut local.root, &remote.root);

    // Pass 2: drop any local group whose id is in remote's tombstones,
    // unless the local group's last_modification_time is later than
    // the tombstone's deleted_at (conservative: don't silently delete a
    // locally-edited group).
    drop_remotely_tombstoned_groups(&mut local.root, &remote_tombstones);

    // Pass 3: add any remote group not present locally and not in
    // local's tombstones. Insert under the resolved parent (matches
    // remote's path) or under local's root as fallback.
    add_remote_only_groups(local, remote, &local_tombstones);
}

pub(super) fn take_later_group_metadata(local: &mut Group, remote: &Group) {
    // Walk both trees in lockstep where ids match.
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(remote, &mut remote_by_id);
    take_later_recursive(local, &remote_by_id);
}

pub(super) fn take_later_recursive(
    local_group: &mut Group,
    remote_by_id: &HashMap<GroupId, &Group>,
) {
    if let Some(r) = remote_by_id.get(&local_group.id) {
        let local_t = local_group.times.last_modification_time;
        if let Some(rt) = r.times.last_modification_time {
            if local_t.is_none_or(|lt| rt > lt) {
                local_group.name = r.name.clone();
                local_group.notes = r.notes.clone();
                local_group.icon_id = r.icon_id;
                local_group.custom_icon_uuid = r.custom_icon_uuid;
                local_group.previous_parent_group = r.previous_parent_group;
                local_group.enable_auto_type = r.enable_auto_type;
                local_group.enable_searching = r.enable_searching;
                local_group.default_auto_type_sequence = r.default_auto_type_sequence.clone();
                local_group.is_expanded = r.is_expanded;
            }
        }
    }
    for sub in &mut local_group.groups {
        take_later_recursive(sub, remote_by_id);
    }
}

pub(super) fn drop_remotely_tombstoned_groups(
    group: &mut Group,
    tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
) {
    group.groups.retain(|g| {
        let Some(deleted_at) = tombstones.get(&g.id.0) else {
            return true;
        };
        // Conservative keep: if the local group's mtime is later than
        // the tombstone's deleted_at (or either is missing), keep.
        match (g.times.last_modification_time, *deleted_at) {
            (Some(local_mt), Some(deleted)) => local_mt > deleted,
            _ => true,
        }
    });
    for sub in &mut group.groups {
        drop_remotely_tombstoned_groups(sub, tombstones);
    }
}

pub(super) fn add_remote_only_groups(
    local: &mut Vault,
    remote: &Vault,
    local_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
) {
    let local_ids = collect_group_ids(&local.root);
    let remote_groups: Vec<(GroupId, GroupId, Group)> = {
        // (id, parent_id, cloned group with no children — children are
        // handled by their own recursion as we walk remote)
        let mut out = Vec::new();
        gather_remote_groups_with_parents(&remote.root, remote.root.id, &mut out);
        out
    };
    for (id, parent_id, group_meta) in remote_groups {
        if local_ids.contains(&id) {
            continue;
        }
        if local_tombstones.contains_key(&id.0) {
            continue;
        }
        // Insert a child copy with empty children — the children, if
        // any, are covered by their own iteration (we collected them
        // depth-first from remote with their own parent ids).
        let mut child = group_meta;
        child.groups.clear();
        child.entries.clear();
        match find_group_mut(&mut local.root, parent_id) {
            Some(parent) => parent.groups.push(child),
            None => local.root.groups.push(child),
        }
    }
}

pub(super) fn gather_remote_groups_with_parents(
    group: &Group,
    parent_id: GroupId,
    out: &mut Vec<(GroupId, GroupId, Group)>,
) {
    // Skip the root itself — it's always present on local by
    // construction.
    if group.id != parent_id {
        out.push((group.id, parent_id, group.clone()));
    }
    for sub in &group.groups {
        gather_remote_groups_with_parents(sub, group.id, out);
    }
}

// ---------------------------------------------------------------------------
// Per-entry rebuild
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(super) enum EntryWinner {
    Local,
    Remote,
}

/// Build a merged entry by cloning the winning side and stitching
/// in the combined history plus a pre-merge snapshot of whichever
/// side is being overwritten.
///
/// `remap` translates remote-pool `Attachment::ref_id` values into
/// local-pool indices for every cloned piece sourced from `remote`:
/// the winner=Remote current-state clone, the winner=Local snapshot
/// of remote (when remote is the loser), and every remote-sourced
/// history record.
pub(super) fn build_merged_entry(
    local: &Entry,
    remote: &Entry,
    winner: EntryWinner,
    attachment_resolutions: &[AttachmentAutoResolution],
    field_resolutions: &[(String, Side)],
    icon_resolution: Option<Side>,
    remap: &mut BinaryPoolRemap<'_>,
) -> Entry {
    // Rebind remote's history before merging so the combined output
    // carries only local-pool ref_ids regardless of which records win
    // the dedup. Slice 4's merge_histories handles dedup + ordering.
    let rebound_remote_history = rebind_history(&remote.history, remap);

    // Snapshot the loser's pre-merge state into history so a later
    // viewer can see what was overwritten. The snapshot has its
    // history field cleared (KDBX doesn't nest history). The
    // remote-side snapshot needs its attachment ref_ids translated
    // first; do that before we drop the mutable borrow on remap.
    let snapshot = match winner {
        EntryWinner::Remote => {
            let mut s = local.clone();
            s.history.clear();
            s
        }
        EntryWinner::Local => {
            let mut s = remote.clone();
            s.history.clear();
            remap.rebind(&mut s.attachments);
            s
        }
    };

    // Past this point we only need read-only access to the local
    // pool for hashing + history dedup.
    let local_binaries: &[Binary] = remap.local_binaries();
    let mut combined = merge_histories(&local.history, &rebound_remote_history, local_binaries);
    // Dedup the snapshot if a record at its mtime *and content* is
    // already present (avoids spurious duplication on a no-op merge).
    // Tightened in slice 5b per #R21 to use the slice-2 content hash
    // alongside the mtime, matching the slice-4 dedup discipline.
    let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
    let already_present = combined.iter().any(|h| {
        h.times.last_modification_time == snapshot.times.last_modification_time
            && entry_content_hash(h, local_binaries) == snapshot_hash
    });
    if !already_present {
        combined.push(snapshot);
    }

    let mut merged = match winner {
        EntryWinner::Remote => {
            let mut e = remote.clone();
            remap.rebind(&mut e.attachments);
            e
        }
        EntryWinner::Local => local.clone(),
    };
    // Overlay per-field auto-resolutions whose side differs from the
    // bucket winner. Without this the wholesale clone above would
    // silently lose any field where the per-field classifier picked
    // the other side — the "mixed-side field wins" data-loss class.
    // `set_field_from` handles both "take value" (source has the
    // field) and "clear field" (source lacks it, for custom keys) the
    // same way `build_resolved_entry` does for the conflict path.
    let winner_side = match winner {
        EntryWinner::Local => Side::Local,
        EntryWinner::Remote => Side::Remote,
    };
    for (key, side) in field_resolutions {
        if *side == winner_side {
            continue;
        }
        let source = match side {
            Side::Local => local,
            Side::Remote => remote,
        };
        set_field_from(&mut merged, source, key);
    }
    // Overlay the icon auto-resolution if the classifier picked a
    // side different from the bucket winner. Mirrors the per-field
    // overlay above; base icon ID is intentionally untouched (rides
    // along with whichever side won the entry-level merge per spec
    // rule 4). `custom_icons` pool reconciliation is the FFI / write-
    // back layer's responsibility — out of scope for v0.1 merge.
    if let Some(side) = icon_resolution {
        if side != winner_side {
            let source = match side {
                Side::Local => local,
                Side::Remote => remote,
            };
            merged.custom_icon_uuid = source.custom_icon_uuid;
        }
    }
    // Apply per-attachment auto-resolutions on top of the entry-level
    // winner's clone, overriding the ride-along behaviour for the names
    // the classifier had a clear answer on.
    apply_attachment_resolutions(&mut merged, local, remote, attachment_resolutions, remap);
    merged.history = combined;
    merged
}

// ---------------------------------------------------------------------------
// Tombstone union
// ---------------------------------------------------------------------------

pub(super) fn union_tombstones(
    local: &mut Vec<DeletedObject>,
    remote: &[DeletedObject],
    skip: &HashSet<Uuid>,
) {
    let existing: HashSet<(Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        local.iter().map(|t| (t.uuid, t.deleted_at)).collect();
    for t in remote {
        if skip.contains(&t.uuid) {
            // Caller chose KeepLocal for this uuid — drop the remote
            // tombstone from the union so the local entry isn't
            // re-deleted by the format's own merge semantics.
            continue;
        }
        let key = (t.uuid, t.deleted_at);
        if !existing.contains(&key) {
            local.push(DeletedObject::new(t.uuid, t.deleted_at));
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp reconciliation
// ---------------------------------------------------------------------------

pub(super) fn reconcile_entry_timestamps_recursive(
    group: &mut Group,
    remote_entries: &HashMap<EntryId, &Entry>,
) {
    for entry in &mut group.entries {
        if let Some(r) = remote_entries.get(&entry.id) {
            take_later_opt(
                &mut entry.times.last_modification_time,
                r.times.last_modification_time,
            );
            take_later_opt(&mut entry.times.last_access_time, r.times.last_access_time);
            take_later_opt(&mut entry.times.location_changed, r.times.location_changed);
        }
    }
    for sub in &mut group.groups {
        reconcile_entry_timestamps_recursive(sub, remote_entries);
    }
}

pub(super) fn reconcile_group_timestamps_recursive(group: &mut Group, remote: &Vault) {
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(&remote.root, &mut remote_by_id);
    reconcile_group_timestamps_walk(group, &remote_by_id);
}

pub(super) fn reconcile_group_timestamps_walk(
    group: &mut Group,
    remote_by_id: &HashMap<GroupId, &Group>,
) {
    if let Some(r) = remote_by_id.get(&group.id) {
        take_later_opt(
            &mut group.times.last_modification_time,
            r.times.last_modification_time,
        );
        take_later_opt(&mut group.times.last_access_time, r.times.last_access_time);
        take_later_opt(&mut group.times.location_changed, r.times.location_changed);
    }
    for sub in &mut group.groups {
        reconcile_group_timestamps_walk(sub, remote_by_id);
    }
}

pub(super) fn take_later_opt(
    target: &mut Option<chrono::DateTime<chrono::Utc>>,
    candidate: Option<chrono::DateTime<chrono::Utc>>,
) {
    match (*target, candidate) {
        (None, Some(c)) => *target = Some(c),
        (Some(t), Some(c)) if c > t => *target = Some(c),
        _ => {}
    }
}
