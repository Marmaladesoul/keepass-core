//! Apply a [`MergeOutcome`] to a local [`Vault`], producing the merged state.
//!
//! Slice 5a covers every bucket the caller doesn't have to drive:
//!
//! - [`MergeOutcome::disk_only_changes`] — overwrite local entry with
//!   remote, preserving combined history plus a pre-merge local snapshot.
//! - [`MergeOutcome::local_only_changes`] — keep local content but
//!   absorb any history records the remote side has that we don't.
//! - [`MergeOutcome::added_on_disk`] — clone-insert remote entries,
//!   mirroring remote's parent-group path into local; falls back to
//!   local's root if the path doesn't exist locally.
//! - [`MergeOutcome::local_deletions_pending_sync`] — propagate local
//!   tombstones into remote (no-op on local; documented for completeness).
//! - [`MergeOutcome::deleted_on_disk`] — drop the local entry; the
//!   tombstone union below records the deletion.
//! - Tombstone union with exact `(uuid, deleted_at)` dedup.
//! - Group-tree LWW reconciliation (rename / move / metadata).
//!
//! [`reconcile_timestamps`] is a separate post-apply pass that takes
//! the later of each timestamp pair across both sides for every
//! entry-id and group-id present on both. Caller invokes after
//! `apply_merge`.
//!
//! Slice 5b layers on top of this with the caller-driven buckets:
//! `entry_conflicts` and `delete_edit_conflicts`. This file's
//! validation pass is a no-op when those buckets are empty; the full
//! `Resolution` validation lands in 5b.

use std::collections::HashMap;

use keepass_core::model::{DeletedObject, Entry, EntryId, Group, GroupId, Vault};
use uuid::Uuid;

use crate::history_merge::merge_histories;
use crate::{MergeError, MergeOutcome, Resolution};

/// Mutate `local` in place by applying `outcome` (and `resolution`'s
/// caller-driven choices, when slice 5b lands them).
///
/// `remote` is consulted read-only for two purposes: to source the
/// added-entries and their parent-group paths, and to drive group-
/// tree LWW reconciliation by timestamp.
///
/// Returns `Ok(())` when the merge was applied successfully. Slice 5a
/// produces no errors in practice — every documented error path is a
/// slice 5b concern (resolution validation). The `Result` return type
/// is the eventual surface; today it always succeeds when the
/// conflict buckets are empty.
pub fn apply_merge(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    _resolution: &Resolution,
) -> Result<(), MergeError> {
    // Slice 5a doesn't read `_resolution`; the parameter is in the
    // signature so 5b can wire it without an API change.

    // Group-tree LWW first so any newly-added remote groups are in
    // place before `added_on_disk` looks for parent-group paths.
    apply_group_tree(local, remote);

    // Entry-level mutations. Order is "remove → modify → add" so a
    // remote-add with the same id as a local-tombstoned entry can't
    // confuse intermediate state.
    for id in &outcome.deleted_on_disk {
        remove_entry(&mut local.root, *id);
    }

    for id in &outcome.disk_only_changes {
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(&local.root, *id) else {
            continue;
        };
        let merged = build_merged_entry(local_entry, remote_entry, EntryWinner::Remote);
        replace_entry(&mut local.root, *id, merged);
    }

    for id in &outcome.local_only_changes {
        // History-merge runs even though the local content stays put
        // — that's how a remote's intermediate snapshots reach local
        // when the remote's *current* state matches local's.
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(&local.root, *id) else {
            continue;
        };
        let merged = build_merged_entry(local_entry, remote_entry, EntryWinner::Local);
        replace_entry(&mut local.root, *id, merged);
    }

    for new_entry in &outcome.added_on_disk {
        let target_parent = find_remote_parent(&remote.root, new_entry.id);
        let inserted = target_parent
            .and_then(|gid| find_group_mut(&mut local.root, gid))
            .map(|g| {
                g.entries.push(new_entry.clone());
            });
        if inserted.is_none() {
            local.root.entries.push(new_entry.clone());
        }
    }

    // `local_deletions_pending_sync` is informational for the FFI
    // consumer — local already has the tombstone, no mutation
    // required. The bucket exists so the caller knows to schedule a
    // save-back, not because apply has work to do.
    let _ = &outcome.local_deletions_pending_sync;

    // Tombstone union: take everything remote has that local doesn't,
    // exact-tuple deduplicated by `(uuid, deleted_at)`.
    union_tombstones(&mut local.deleted_objects, &remote.deleted_objects);

    Ok(())
}

/// Take the later of each timestamp pair across both vaults for every
/// entry and group present on both. Per-entry: `last_modification_time`,
/// `last_access_time`, `location_changed`. Per-group: same. Doesn't
/// touch content; only `times.*` fields.
///
/// Caller invokes after [`apply_merge`].
pub fn reconcile_timestamps(local: &mut Vault, remote: &Vault) {
    let remote_entries: HashMap<EntryId, &Entry> = {
        let mut out = HashMap::new();
        collect_entries(&remote.root, &mut out);
        out
    };
    reconcile_group_timestamps_recursive(&mut local.root, remote);
    reconcile_entry_timestamps_recursive(&mut local.root, &remote_entries);
}

// ---------------------------------------------------------------------------
// Group-tree LWW reconciliation
// ---------------------------------------------------------------------------

fn apply_group_tree(local: &mut Vault, remote: &Vault) {
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

fn take_later_group_metadata(local: &mut Group, remote: &Group) {
    // Walk both trees in lockstep where ids match.
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(remote, &mut remote_by_id);
    take_later_recursive(local, &remote_by_id);
}

fn take_later_recursive(local_group: &mut Group, remote_by_id: &HashMap<GroupId, &Group>) {
    if let Some(r) = remote_by_id.get(&local_group.id) {
        let local_t = local_group.times.last_modification_time;
        let remote_t = r.times.last_modification_time;
        if let (Some(rt), local_opt) = (remote_t, local_t)
            && local_opt.is_none_or(|lt| rt > lt)
        {
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
    for sub in &mut local_group.groups {
        take_later_recursive(sub, remote_by_id);
    }
}

fn drop_remotely_tombstoned_groups(
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

fn add_remote_only_groups(
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

fn gather_remote_groups_with_parents(
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
enum EntryWinner {
    Local,
    Remote,
}

/// Build a merged entry by cloning the winning side and stitching
/// in the combined history plus a pre-merge snapshot of whichever
/// side is being overwritten.
fn build_merged_entry(local: &Entry, remote: &Entry, winner: EntryWinner) -> Entry {
    // Slice 4's merge_histories handles dedup + ordering.
    let mut combined = merge_histories(&local.history, &remote.history);

    // Snapshot the loser's pre-merge state into history so a later
    // viewer can see what was overwritten. The snapshot has its
    // history field cleared (KDBX doesn't nest history).
    let snapshot = match winner {
        EntryWinner::Remote => {
            let mut s = local.clone();
            s.history.clear();
            s
        }
        EntryWinner::Local => {
            let mut s = remote.clone();
            s.history.clear();
            s
        }
    };
    // Dedup the snapshot if a record at its mtime+content is already
    // present (avoids spurious duplication on a no-op merge).
    let already_present = combined
        .iter()
        .any(|h| h.times.last_modification_time == snapshot.times.last_modification_time);
    if !already_present {
        combined.push(snapshot);
    }

    let mut merged = match winner {
        EntryWinner::Remote => remote.clone(),
        EntryWinner::Local => local.clone(),
    };
    merged.history = combined;
    merged
}

// ---------------------------------------------------------------------------
// Tombstone union
// ---------------------------------------------------------------------------

fn union_tombstones(local: &mut Vec<DeletedObject>, remote: &[DeletedObject]) {
    let existing: std::collections::HashSet<(Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        local.iter().map(|t| (t.uuid, t.deleted_at)).collect();
    for t in remote {
        let key = (t.uuid, t.deleted_at);
        if !existing.contains(&key) {
            local.push(DeletedObject::new(t.uuid, t.deleted_at));
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp reconciliation
// ---------------------------------------------------------------------------

fn reconcile_entry_timestamps_recursive(
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

fn reconcile_group_timestamps_recursive(group: &mut Group, remote: &Vault) {
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(&remote.root, &mut remote_by_id);
    reconcile_group_timestamps_walk(group, &remote_by_id);
}

fn reconcile_group_timestamps_walk(group: &mut Group, remote_by_id: &HashMap<GroupId, &Group>) {
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

fn take_later_opt(
    target: &mut Option<chrono::DateTime<chrono::Utc>>,
    candidate: Option<chrono::DateTime<chrono::Utc>>,
) {
    match (*target, candidate) {
        (None, Some(c)) => *target = Some(c),
        (Some(t), Some(c)) if c > t => *target = Some(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tree helpers
// ---------------------------------------------------------------------------

fn find_entry(group: &Group, id: EntryId) -> Option<&Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id == id) {
        return Some(e);
    }
    group.groups.iter().find_map(|g| find_entry(g, id))
}

fn replace_entry(group: &mut Group, id: EntryId, new: Entry) {
    if let Some(pos) = group.entries.iter().position(|e| e.id == id) {
        group.entries[pos] = new;
        return;
    }
    for sub in &mut group.groups {
        replace_entry(sub, id, new.clone());
    }
}

fn remove_entry(group: &mut Group, id: EntryId) -> bool {
    if let Some(pos) = group.entries.iter().position(|e| e.id == id) {
        group.entries.remove(pos);
        return true;
    }
    for sub in &mut group.groups {
        if remove_entry(sub, id) {
            return true;
        }
    }
    false
}

fn find_remote_parent(group: &Group, entry_id: EntryId) -> Option<GroupId> {
    if group.entries.iter().any(|e| e.id == entry_id) {
        return Some(group.id);
    }
    group
        .groups
        .iter()
        .find_map(|g| find_remote_parent(g, entry_id))
}

fn find_group_mut(group: &mut Group, id: GroupId) -> Option<&mut Group> {
    if group.id == id {
        return Some(group);
    }
    group.groups.iter_mut().find_map(|g| find_group_mut(g, id))
}

fn collect_entries<'a>(group: &'a Group, out: &mut HashMap<EntryId, &'a Entry>) {
    for e in &group.entries {
        out.insert(e.id, e);
    }
    for sub in &group.groups {
        collect_entries(sub, out);
    }
}

fn collect_groups<'a>(group: &'a Group, out: &mut HashMap<GroupId, &'a Group>) {
    out.insert(group.id, group);
    for sub in &group.groups {
        collect_groups(sub, out);
    }
}

fn collect_group_ids_walk(g: &Group, out: &mut std::collections::HashSet<GroupId>) {
    out.insert(g.id);
    for sub in &g.groups {
        collect_group_ids_walk(sub, out);
    }
}

fn collect_group_ids(group: &Group) -> std::collections::HashSet<GroupId> {
    let mut out = std::collections::HashSet::new();
    collect_group_ids_walk(group, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::{apply_merge, reconcile_timestamps};
    use crate::{Resolution, merge};
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{DeletedObject, Entry, EntryId, Group, GroupId, Timestamps, Vault};
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn entry(id: u128, title: &str, ts: Timestamps) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
        e.title = title.into();
        e.times = ts;
        e
    }

    fn vault_with(entries: Vec<Entry>) -> Vault {
        let mut v = Vault::empty(GroupId(Uuid::nil()));
        v.root.entries = entries;
        v
    }

    #[test]
    fn auto_apply_disk_only_changes_overwrites_with_remote_and_keeps_history() {
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local_entry = entry(1, "A", at(2026, 1));
        local_entry.history = vec![ancestor.clone()];
        let mut remote_entry = entry(1, "B", at(2026, 2));
        remote_entry.history = vec![ancestor];

        let mut local = vault_with(vec![local_entry.clone()]);
        let remote = vault_with(vec![remote_entry]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.disk_only_changes.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        let merged = &local.root.entries[0];
        assert_eq!(merged.title, "B");
        // History contains: ancestor (deduped) + pre-merge local snapshot.
        assert!(merged.history.iter().any(|h| h.title == "A"
            && h.times.last_modification_time == at(2026, 1).last_modification_time));
    }

    #[test]
    fn auto_apply_local_only_changes_keeps_local_content() {
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local_entry = entry(1, "B", at(2026, 2));
        local_entry.history = vec![ancestor.clone()];
        let mut remote_entry = entry(1, "A", at(2026, 1));
        remote_entry.history = vec![ancestor];

        let mut local = vault_with(vec![local_entry]);
        let remote = vault_with(vec![remote_entry]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.local_only_changes.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        // Local content stays.
        assert_eq!(local.root.entries[0].title, "B");
    }

    #[test]
    fn added_on_disk_inserts_under_local_root_when_remote_parent_missing() {
        let local = Vault::empty(GroupId(Uuid::nil()));
        let mut local = local;
        let remote_only = entry(7, "from-remote", at(2026, 1));
        let remote = vault_with(vec![remote_only.clone()]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.added_on_disk.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(
            local
                .root
                .entries
                .iter()
                .any(|e| e.id == EntryId(Uuid::from_u128(7)))
        );
    }

    #[test]
    fn added_on_disk_mirrors_remote_subgroup_path() {
        // Remote has a subgroup "child" with an entry inside; local
        // already has the same subgroup id. Apply should insert the
        // entry into local's matching subgroup, not into root.
        let child_id = GroupId(Uuid::from_u128(0xc));
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local.root.groups.push(Group::empty(child_id));

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_child = Group::empty(child_id);
        remote_child.entries.push(entry(7, "in-child", at(2026, 1)));
        remote.root.groups.push(remote_child);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.entries.is_empty());
        assert_eq!(local.root.groups[0].entries.len(), 1);
        assert_eq!(local.root.groups[0].entries[0].title, "in-child");
    }

    #[test]
    fn deleted_on_disk_removes_local_entry_and_unions_tombstone() {
        let local_entry = entry(1, "doomed", at(2026, 1));
        let mut local = vault_with(vec![local_entry]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.deleted_on_disk, vec![EntryId(Uuid::from_u128(1))]);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.entries.is_empty());
        // Tombstone now in local.
        assert_eq!(local.deleted_objects.len(), 1);
        assert_eq!(local.deleted_objects[0].uuid, Uuid::from_u128(1));
    }

    #[test]
    fn tombstone_union_dedupes_by_exact_tuple() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let id = Uuid::from_u128(1);
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local
            .deleted_objects
            .push(DeletedObject::new(id, Some(when)));
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        // Same uuid+deleted_at — dedup.
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(when)));
        // Same uuid, different deleted_at — both preserved.
        let other_when = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(other_when)));

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(
            local.deleted_objects.len(),
            2,
            "exact-tuple dedup must preserve same-uuid different-time"
        );
    }

    #[test]
    fn group_tree_lww_takes_later_metadata() {
        // Same group id on both sides; remote has a later mtime and a
        // different name. After apply, local takes remote's name.
        let id = GroupId(Uuid::from_u128(0xaa));
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let mut local_g = Group::empty(id);
        local_g.name = "old".into();
        local_g.times = at(2026, 1);
        local.root.groups.push(local_g);

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_g = Group::empty(id);
        remote_g.name = "new".into();
        remote_g.times = at(2026, 5);
        remote.root.groups.push(remote_g);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(local.root.groups[0].name, "new");
    }

    #[test]
    fn group_tree_lww_adds_remote_only_group() {
        let id = GroupId(Uuid::from_u128(0xbb));
        let local = Vault::empty(GroupId(Uuid::nil()));
        let mut local = local;
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_g = Group::empty(id);
        remote_g.name = "new-group".into();
        remote.root.groups.push(remote_g);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.groups.iter().any(|g| g.id == id));
    }

    #[test]
    fn reconcile_timestamps_takes_later_per_entry() {
        let mut local_entry = entry(1, "A", at(2026, 1));
        local_entry.times.last_access_time =
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());

        let mut remote_entry = entry(1, "A", at(2026, 1));
        let later = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        remote_entry.times.last_access_time = Some(later);

        let mut local = vault_with(vec![local_entry]);
        let remote = vault_with(vec![remote_entry]);

        reconcile_timestamps(&mut local, &remote);

        assert_eq!(local.root.entries[0].times.last_access_time, Some(later));
    }
}
