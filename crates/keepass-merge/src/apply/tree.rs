//! Group-tree LWW reconciliation, entry / group timestamp
//! reconciliation, and tombstone union. Pure tree-mutation helpers
//! split off from `apply::mod`'s top-level `apply_merge` flow so the
//! file stays a manageable size.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Binary, DeletedObject, Entry, EntryId, Group, GroupId, Vault};
use uuid::Uuid;

use crate::binary_pool::BinaryPoolRemap;
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::hash::{entry_content_hash, sha256};
use crate::history_merge::merge_histories;
use crate::time::{
    advance_only_max, conservative_edit_wins, later_wins, second_resolution, strictly_after,
};
use crate::tombstone::{
    parse_tombstones, tombstone_set, union_history_tombstones, write_tombstones_to_custom_data,
};

use super::resolution::{apply_attachment_resolutions, rebind_history};
use crate::field_access::copy_field;

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

    // Pass 3: reparent groups whose parent differs between sides and
    // whose remote `location_changed` is strictly newer. Spec §2.2
    // arbitrates concurrent group-moves via LWW on `location_changed`
    // — the kdbx-native "when was this last reparented" signal.
    // Must run BEFORE `add_remote_only_groups` so the move target
    // exists locally (or fails the safety check) before any new
    // remote-side group is inserted.
    apply_concurrent_group_moves(local, remote);

    // Pass 4: add any remote group not present locally and not in
    // local's tombstones. Insert under the resolved parent (matches
    // remote's path) or under local's root as fallback.
    add_remote_only_groups(local, remote, &local_tombstones);

    // Pass 5: reparent entries whose owning group differs between
    // sides. Spec §2.3 arbitrates concurrent entry moves by LWW; we
    // follow the group-move pass's posture and key on `location_changed`
    // — the more precise "when was this last reparented" signal —
    // rather than `last_modification_time`, which advances on every
    // field edit and would over-trigger.
    //
    // Must run AFTER `add_remote_only_groups` so the move target group
    // exists locally when the entry lands.
    apply_concurrent_entry_moves(local, remote);
}

/// Reparent locally-existing entries whose remote-side owning group
/// differs from local's and whose `location_changed` advanced on
/// remote.
///
/// Same shape as `apply_concurrent_group_moves`: snapshot parents +
/// `location_changed` before mutating, then for each entry on both
/// sides under different parents with `remote.location_changed >
/// local.location_changed`, detach from the current parent and
/// re-attach under the remote-side parent. Falls back to root when
/// the new parent isn't present locally (defensive — shouldn't be
/// reachable because `add_remote_only_groups` has already run).
///
/// No cycle check is needed for entries: entries can't contain other
/// entries, so a move can't induce a tree-shape cycle.
pub(super) fn apply_concurrent_entry_moves(local: &mut Vault, remote: &Vault) {
    let remote_parents: HashMap<EntryId, GroupId> = remote
        .root
        .iter_entries_with_parent()
        .map(|(e, p)| (e.id, p))
        .collect();
    let local_parents: HashMap<EntryId, GroupId> = local
        .root
        .iter_entries_with_parent()
        .map(|(e, p)| (e.id, p))
        .collect();
    let remote_loc: HashMap<EntryId, Option<chrono::DateTime<chrono::Utc>>> = remote
        .root
        .iter_entries()
        .map(|e| (e.id, e.times.location_changed))
        .collect();
    let local_loc: HashMap<EntryId, Option<chrono::DateTime<chrono::Utc>>> = local
        .root
        .iter_entries()
        .map(|e| (e.id, e.times.location_changed))
        .collect();

    let mut moves: Vec<(EntryId, GroupId)> = Vec::new();
    for (id, remote_parent) in &remote_parents {
        let Some(local_parent) = local_parents.get(id) else {
            continue;
        };
        if remote_parent == local_parent {
            continue;
        }
        let r_loc = remote_loc.get(id).copied().flatten();
        let l_loc = local_loc.get(id).copied().flatten();
        if later_wins(l_loc, r_loc) {
            moves.push((*id, *remote_parent));
        }
    }

    for (id, new_parent_id) in moves {
        let local_parent = local_parents.get(&id).copied();
        let Some((detached, _)) = local.root.detach_entry(id) else {
            continue;
        };
        let title = detached.title.clone();
        match local.root.group_mut(new_parent_id) {
            Some(parent) => parent.entries.push(detached),
            None => local.root.entries.push(detached),
        }
        if let Some(local_parent) = local_parent {
            crate::events::emit(&crate::MergeEvent::EntryConcurrentMove {
                entry: id,
                title,
                local_parent,
                remote_parent: new_parent_id,
            });
        }
    }
}

/// Reparent locally-existing groups whose remote-side parent differs
/// from local's and whose `location_changed` advanced on remote.
///
/// For each group present on both sides with `remote_parent !=
/// local_parent` and `remote.location_changed > local.location_changed`,
/// detach the group from its local parent and re-attach it under the
/// remote-side parent — provided the move is structurally safe (the
/// new parent isn't the group itself or a descendant of it; otherwise
/// the relocation would create a cycle and the move is skipped, with
/// the locally-recorded position retained).
///
/// Spec §6 prose templates the activity-log entry; emission is audit
/// item 10 / future slice.
pub(super) fn apply_concurrent_group_moves(local: &mut Vault, remote: &Vault) {
    // `iter_groups_with_parent` yields `(group, Option<parent>)` self-
    // first; the root's `None` parent is filtered out so the map holds
    // only child→parent edges (root has no parent), matching the old
    // `collect_parents`.
    let remote_parents: HashMap<GroupId, GroupId> = remote
        .root
        .iter_groups_with_parent()
        .filter_map(|(g, p)| p.map(|pid| (g.id, pid)))
        .collect();
    let local_parents: HashMap<GroupId, GroupId> = local
        .root
        .iter_groups_with_parent()
        .filter_map(|(g, p)| p.map(|pid| (g.id, pid)))
        .collect();
    let remote_loc: HashMap<GroupId, Option<chrono::DateTime<chrono::Utc>>> = remote
        .root
        .iter_groups()
        .map(|g| (g.id, g.times.location_changed))
        .collect();
    let local_loc: HashMap<GroupId, Option<chrono::DateTime<chrono::Utc>>> = local
        .root
        .iter_groups()
        .map(|g| (g.id, g.times.location_changed))
        .collect();

    // Build the move list before mutating; mutating local mid-iteration
    // would invalidate the parent map.
    let mut moves: Vec<(GroupId, GroupId)> = Vec::new();
    for (id, remote_parent) in &remote_parents {
        let Some(local_parent) = local_parents.get(id) else {
            // Group not on local at all — handled by
            // `add_remote_only_groups` in the next pass.
            continue;
        };
        if remote_parent == local_parent {
            continue;
        }
        let r_loc = remote_loc.get(id).copied().flatten();
        let l_loc = local_loc.get(id).copied().flatten();
        if later_wins(l_loc, r_loc) {
            moves.push((*id, *remote_parent));
        }
    }

    for (id, new_parent_id) in moves {
        if !is_safe_reparent(&local.root, id, new_parent_id) {
            continue;
        }
        let local_parent = local_parents.get(&id).copied();
        let Some((detached, _)) = local.root.detach_group(id) else {
            continue;
        };
        let name = detached.name.clone();
        // Find new parent and insert. If the new parent isn't present
        // locally either (e.g. concurrent restructure on both sides),
        // restore at the root so the group isn't lost.
        match local.root.group_mut(new_parent_id) {
            Some(parent) => parent.groups.push(detached),
            None => local.root.groups.push(detached),
        }
        if let Some(local_parent) = local_parent {
            crate::events::emit(&crate::MergeEvent::GroupConcurrentMove {
                group: id,
                name,
                local_parent,
                remote_parent: new_parent_id,
            });
        }
    }
}

/// `true` iff moving `subject` under `new_parent` preserves a tree
/// (no cycle): the new parent is neither the subject itself nor any
/// descendant of it.
fn is_safe_reparent(root: &Group, subject: GroupId, new_parent: GroupId) -> bool {
    if subject == new_parent {
        return false;
    }
    let Some(subject_group) = root.group(subject) else {
        // Subject isn't even present — bail; the caller's detach will
        // also bail.
        return false;
    };
    // `Group::group` is self-inclusive, but `subject == new_parent` is
    // already rejected above, so a hit here can only be a *proper*
    // descendant of `subject` — exactly the cycle-inducing case.
    subject_group.group(new_parent).is_none()
}

pub(super) fn take_later_group_metadata(local: &mut Group, remote: &Group) {
    // Walk both trees in lockstep where ids match. Each group is
    // reconciled independently against its remote twin, so visit order
    // is immaterial.
    let remote_by_id: HashMap<GroupId, &Group> = remote.iter_groups().map(|g| (g.id, g)).collect();
    local.for_each_group_mut(&mut |local_group| {
        if let Some(r) = remote_by_id.get(&local_group.id) {
            let local_t = local_group.times.last_modification_time;
            if later_wins(local_t, r.times.last_modification_time) {
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
    });
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
        conservative_edit_wins(g.times.last_modification_time, *deleted_at)
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
    let local_ids: HashSet<GroupId> = local.root.iter_groups().map(|g| g.id).collect();
    // (id, parent_id, cloned group) for every non-root remote group;
    // each group's children are covered by their own iteration, so the
    // clone's `groups`/`entries` are cleared before insertion below.
    // The root is filtered out (its `None` parent) — it's always
    // present on local by construction.
    let remote_groups: Vec<(GroupId, GroupId, Group)> = remote
        .root
        .iter_groups_with_parent()
        .filter_map(|(g, p)| p.map(|pid| (g.id, pid, g.clone())))
        .collect();
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
        match local.root.group_mut(parent_id) {
            Some(parent) => parent.groups.push(child),
            None => local.root.groups.push(child),
        }
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
    // Union the two sides' history tombstones before merging. Both
    // sides' lists must contribute so a deletion issued on either
    // peer survives this merge — see history-tombstones design doc.
    // Parse failures degrade silently to empty (a corrupt custom_data
    // value shouldn't crash a merge; the value will be overwritten
    // by the unioned-and-reserialised list below regardless).
    let local_ts = parse_tombstones(&local.custom_data).unwrap_or_default();
    let remote_ts = parse_tombstones(&remote.custom_data).unwrap_or_default();
    let unioned_ts = union_history_tombstones(&local_ts, &remote_ts);
    let ts_set = tombstone_set(&unioned_ts);
    let mut combined = merge_histories(
        &local.history,
        &rebound_remote_history,
        local_binaries,
        &ts_set,
    );
    // Dedup the snapshot if a record at its mtime *and content* is
    // already present (avoids spurious duplication on a no-op merge).
    // Tightened in slice 5b per #R21 to use the slice-2 content hash
    // alongside the mtime, matching the slice-4 dedup discipline.
    //
    // The mtime comparison is at whole-second resolution
    // (`second_resolution`), matching `merge_histories`: the engine
    // stamps mtimes in milliseconds and the KDBX round-trip truncates
    // to seconds, so the loser's pre-merge snapshot can carry a
    // sub-second mtime while its already-merged twin in `combined`
    // carries the truncated one (or vice-versa). Exact-mtime comparison
    // missed that and pushed the snapshot alongside its twin — the
    // "history bloat" half of Bug A (see `the design notes`). The
    // tombstone lookup uses the same resolution (`ts_set` is truncated
    // by `tombstone_set`).
    let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
    let snapshot_mtime = second_resolution(snapshot.times.last_modification_time);
    let snapshot_is_tombstoned = ts_set.contains(&(snapshot_mtime, snapshot_hash));
    let already_present = combined.iter().any(|h| {
        second_resolution(h.times.last_modification_time) == snapshot_mtime
            && entry_content_hash(h, local_binaries) == snapshot_hash
    });
    // Don't push a snapshot that the user has already tombstoned: it
    // would defeat the deletion the moment the merge runs.
    if !already_present && !snapshot_is_tombstoned {
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
    // `copy_field` handles both "take value" (source has the
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
        copy_field(&mut merged, source, key);
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
    // Persist the unioned tombstone list so it propagates to peers on
    // next sync. Without this, the merged side would carry only its
    // own pre-merge tombstones and the other side's would have to
    // arrive (and need re-merging) on every subsequent sync round.
    // Apply path is pure → no wall-clock stamp.
    write_tombstones_to_custom_data(&mut merged.custom_data, &unioned_ts, None);
    merged
}

// ---------------------------------------------------------------------------
// History-tombstone pre-pass
// ---------------------------------------------------------------------------

/// Walk every entry present on both sides; union their history
/// tombstones into local in-place, and filter local's `<History>`
/// against the result.
///
/// Required because the bucket-driven mutations downstream
/// ([`build_merged_entry`], [`crate::apply::resolution::build_resolved_entry`])
/// only run for entries whose **standard fields** diverged — and the
/// entry-merge classifier deliberately excludes `<History>` and
/// `<CustomData>` from its comparator. An entry that differs *only*
/// in its tombstone list would route to no bucket at all, leaving
/// local's tombstones unmerged. This pass closes the gap: it touches
/// every both-sides-present entry regardless of bucket.
///
/// Idempotent w.r.t. the downstream bucket logic: the latter re-reads
/// tombstones from both sides and recomputes the union when it builds
/// its merged entry, so the pre-pass's in-place mutation just feeds
/// it a head start.
pub(super) fn union_history_tombstones_across_entries(local_root: &mut Group, remote: &Vault) {
    let remote_entries: HashMap<EntryId, &Entry> =
        remote.root.iter_entries().map(|e| (e.id, e)).collect();
    for entry in local_root.iter_entries_mut() {
        let Some(&remote_entry) = remote_entries.get(&entry.id) else {
            continue;
        };
        let local_ts = crate::tombstone::parse_tombstones(&entry.custom_data).unwrap_or_default();
        let remote_ts =
            crate::tombstone::parse_tombstones(&remote_entry.custom_data).unwrap_or_default();
        // Skip the rewrite work entirely when neither side has any
        // tombstones — the overwhelmingly common case. Bare scan
        // cost only.
        if local_ts.is_empty() && remote_ts.is_empty() {
            continue;
        }
        let unioned = crate::tombstone::union_history_tombstones(&local_ts, &remote_ts);
        let ts_set = crate::tombstone::tombstone_set(&unioned);
        // Filter local's history against the unioned set. Records
        // tombstoned on either side drop here. We treat content-hash
        // mismatch as "not in set"; binaries are passed as &[]
        // because slice B5's attachment-hashing extension isn't
        // landed yet and the production paths in build_*_entry use
        // the local pool — empty matches the current
        // `entry_content_hash` contract (uses binaries only for
        // attachment refs, no-op for the entries we hold here).
        entry.history.retain(|h| {
            let hash = crate::hash::entry_content_hash(h, &[]);
            // Second-resolution mtime to match the (truncated) keys in
            // `ts_set` — see `build_merged_entry` and `merge_histories`.
            let mtime = crate::time::second_resolution(h.times.last_modification_time);
            !ts_set.contains(&(mtime, hash))
        });
        // Write unioned tombstones back so downstream bucket logic
        // and future syncs see the merged set on local. `None` for
        // last_modified — apply path is pure.
        crate::tombstone::write_tombstones_to_custom_data(&mut entry.custom_data, &unioned, None);
    }
}

/// Walk every entry present on both sides; union their
/// attachment-tombstone lists into local in-place, and filter local's
/// `attachments` against the result.
///
/// Same rationale as [`union_tag_states_across_entries`]: the
/// entry-merge classifier excludes `<CustomData>` from its
/// comparator, so an entry that differs *only* in its attachment-
/// tombstone surface would route to no bucket and the tombstone state
/// would never propagate. `local_binaries` is the local vault's
/// binary pool — used to dereference each attachment's `ref_id` for
/// hashing.
pub(super) fn union_attachment_tombstones_across_entries(
    local_root: &mut Group,
    remote: &Vault,
    local_binaries: &[Binary],
) {
    let remote_entries: HashMap<EntryId, &Entry> =
        remote.root.iter_entries().map(|e| (e.id, e)).collect();
    for entry in local_root.iter_entries_mut() {
        let Some(&remote_entry) = remote_entries.get(&entry.id) else {
            continue;
        };
        let local_ts =
            crate::tombstone::parse_attachment_tombstones(&entry.custom_data).unwrap_or_default();
        let remote_ts = crate::tombstone::parse_attachment_tombstones(&remote_entry.custom_data)
            .unwrap_or_default();
        if local_ts.is_empty() && remote_ts.is_empty() {
            continue;
        }
        let unioned = crate::tombstone::union_attachment_tombstones(&local_ts, &remote_ts);
        let ts_set = crate::tombstone::attachment_tombstone_set(&unioned);
        let local_mtime = entry.times.last_modification_time;
        entry.attachments.retain(|att| {
            let Some(bin) = local_binaries.get(att.ref_id as usize) else {
                return true;
            };
            let hash = sha256(&bin.data);
            let key = (att.name.clone(), hash);
            if !ts_set.contains(&key) {
                return true;
            }
            // Re-attach wins only when local's mtime is strictly newer
            // than the tombstone's `at`. The pre-pass can't observe the
            // remote side's mtime relative to remote's bytes — that
            // case is covered by the per-bucket
            // `apply_attachment_tombstones` after the bucket logic
            // installs remote's bytes locally.
            let rm_at = unioned
                .iter()
                .find(|t| t.filename == att.name && t.hash == hash)
                .map(|t| t.at);
            match rm_at {
                Some(a) => strictly_after(local_mtime, a),
                None => false,
            }
        });
        crate::tombstone::write_attachment_tombstones_to_custom_data(
            &mut entry.custom_data,
            &unioned,
            None,
        );
    }
}

/// Walk every entry present on both sides; union their tag-state
/// tombstones into local in-place, and filter local's `tags` against
/// the result.
///
/// Same rationale as [`union_history_tombstones_across_entries`]:
/// the entry-merge classifier excludes `<CustomData>` from its
/// comparator, so an entry that differs *only* in its tag-state would
/// route to no bucket and the tombstone surface would never propagate.
/// This pass touches every both-sides-present entry regardless of
/// bucket. Idempotent with the downstream bucket logic — the apply
/// step re-reads tag-state on the entries it rebuilds.
///
/// Filter rule (the design notes §4): a tag is dropped when
/// tombstoned and the holding side's `last_modification_time` is at
/// or before the tombstone's `at`. An absent mtime can't beat a
/// concrete tombstone — same conservative posture as the per-bucket
/// filter in `apply::resolution::apply_merged_tags`.
pub(super) fn union_tag_states_across_entries(local_root: &mut Group, remote: &Vault) {
    let remote_entries: HashMap<EntryId, &Entry> =
        remote.root.iter_entries().map(|e| (e.id, e)).collect();
    for entry in local_root.iter_entries_mut() {
        let Some(&remote_entry) = remote_entries.get(&entry.id) else {
            continue;
        };
        let local_state = crate::tombstone::parse_tag_state(&entry.custom_data).unwrap_or_default();
        let remote_state =
            crate::tombstone::parse_tag_state(&remote_entry.custom_data).unwrap_or_default();
        // Skip the rewrite when neither side has tag-state — the
        // common case. Bare scan cost.
        if local_state.is_empty() && remote_state.is_empty() {
            continue;
        }
        let unioned = crate::tombstone::union_tag_states(&local_state, &remote_state);
        let local_mtime = entry.times.last_modification_time;
        entry.tags.retain(|tag| match unioned.remove.get(tag) {
            None => true,
            Some(rm) => strictly_after(local_mtime, rm.at),
        });
        crate::tombstone::write_tag_state_to_custom_data(&mut entry.custom_data, &unioned, None);
    }
}

// ---------------------------------------------------------------------------
// Tombstone union (vault-level DeletedObjects — distinct from history
// tombstones above)
// ---------------------------------------------------------------------------

/// Union the two sides' `<DeletedObjects>` tombstone lists, keyed by
/// `UUID` only. On duplicate UUID, prefer the earliest `deleted_at`
/// timestamp — earliest deletion provenance wins per spec §2.8. An
/// absent (`None`) `deleted_at` is treated as later than any present
/// timestamp so concrete provenance is preferred over unknown.
pub(super) fn union_tombstones(
    local: &mut Vec<DeletedObject>,
    remote: &[DeletedObject],
    skip: &HashSet<Uuid>,
) {
    let mut by_uuid: HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>> =
        local.iter().map(|t| (t.uuid, t.deleted_at)).collect();
    for t in remote {
        if skip.contains(&t.uuid) {
            // Caller chose KeepLocal for this uuid — drop the remote
            // tombstone from the union so the local entry isn't
            // re-deleted by the format's own merge semantics.
            continue;
        }
        by_uuid
            .entry(t.uuid)
            .and_modify(|existing| *existing = earliest(*existing, t.deleted_at))
            .or_insert(t.deleted_at);
    }
    // Walk local first so we update in place where the UUID already
    // existed; append any UUIDs that arrived purely from remote.
    let mut seen: HashSet<Uuid> = HashSet::new();
    for t in local.iter_mut() {
        if let Some(merged_at) = by_uuid.get(&t.uuid).copied() {
            t.deleted_at = merged_at;
            seen.insert(t.uuid);
        }
    }
    for (uuid, deleted_at) in by_uuid {
        if seen.insert(uuid) {
            local.push(DeletedObject::new(uuid, deleted_at));
        }
    }
}

/// Pick the earlier of two optional timestamps. `None` is treated as
/// later than any concrete time so provenance with a known
/// `DeletionTime` is preferred over an unknown one — matches the
/// history-tombstone union behaviour in `tombstone::union_history_tombstones`.
fn earliest(
    a: Option<chrono::DateTime<chrono::Utc>>,
    b: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    }
}

// ---------------------------------------------------------------------------
// Timestamp reconciliation
// ---------------------------------------------------------------------------

pub(super) fn reconcile_entry_timestamps_recursive(
    group: &mut Group,
    remote_entries: &HashMap<EntryId, &Entry>,
) {
    for entry in group.iter_entries_mut() {
        if let Some(r) = remote_entries.get(&entry.id) {
            // Advancing timestamps — max-of-two.
            take_later_opt(
                &mut entry.times.last_modification_time,
                r.times.last_modification_time,
            );
            take_later_opt(&mut entry.times.last_access_time, r.times.last_access_time);
            take_later_opt(&mut entry.times.location_changed, r.times.location_changed);
            // Identity-bearing timestamp (spec §2.3 entry row) —
            // min-of-two. The first creation time is the canonical one;
            // a later write that revised this timestamp upward is
            // discarded.
            take_earlier_opt(&mut entry.times.creation_time, r.times.creation_time);
        }
    }
}

pub(super) fn reconcile_group_timestamps_recursive(group: &mut Group, remote: &Vault) {
    let remote_by_id: HashMap<GroupId, &Group> =
        remote.root.iter_groups().map(|g| (g.id, g)).collect();
    group.for_each_group_mut(&mut |g| {
        if let Some(r) = remote_by_id.get(&g.id) {
            take_later_opt(
                &mut g.times.last_modification_time,
                r.times.last_modification_time,
            );
            take_later_opt(&mut g.times.last_access_time, r.times.last_access_time);
            take_later_opt(&mut g.times.location_changed, r.times.location_changed);
            // Identity-bearing (spec §2.2 group row) — min-of-two.
            take_earlier_opt(&mut g.times.creation_time, r.times.creation_time);
        }
    });
}

pub(super) fn take_later_opt(
    target: &mut Option<chrono::DateTime<chrono::Utc>>,
    candidate: Option<chrono::DateTime<chrono::Utc>>,
) {
    *target = advance_only_max(*target, candidate);
}

/// Take the earlier of two optional timestamps — the "identity-bearing"
/// reconciliation rule for creation times. `None` is treated as
/// "unknown" and loses to any concrete value; once a concrete value
/// is on either side, the earliest one wins.
pub(super) fn take_earlier_opt(
    target: &mut Option<chrono::DateTime<chrono::Utc>>,
    candidate: Option<chrono::DateTime<chrono::Utc>>,
) {
    match (*target, candidate) {
        (None, Some(c)) => *target = Some(c),
        (Some(t), Some(c)) if c < t => *target = Some(c),
        _ => {}
    }
}
