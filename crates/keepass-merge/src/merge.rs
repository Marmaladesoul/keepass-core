//! Vault-level entry diff producing a [`MergeOutcome`].
//!
//! [`merge`] is the public entry point: walks both vaults' entry trees,
//! intersects with each side's `<DeletedObjects>` tombstones, and
//! routes every entry into one of the seven entry buckets on
//! [`MergeOutcome`]. Per-entry 3-way classification is delegated to
//! the private entry-merge module.
//!
//! Group-tree structural merge (rename / move / parent change LWW
//! reconciliation) is intentionally *not* in slice 3 — slice 5's
//! apply step handles it. Slice 3 walks groups only to enumerate
//! entries; the [`MergeOutcome::group_conflicts`] bucket stays empty
//! per the v0.1 spec.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Entry, EntryId, Group, GroupId, Vault};
use uuid::Uuid;

use crate::conflict::EntryConflict;
use crate::entry_merge::{Side, local_edited_after, merge_entry};
use crate::{MergeError, MergeOutcome};

/// Three-way merge of two KeePass vaults.
///
/// `local` is the side the caller intends to apply changes to;
/// `remote` is the incoming side (typically a freshly-read disk
/// version). The returned [`MergeOutcome`] describes what slice 5's
/// apply step should do; this function is pure (no mutation, no I/O).
///
/// Returns `Result<MergeOutcome, MergeError>` for forward-compatibility
/// with future error paths (e.g. ambiguous tombstone disambiguation in
/// v0.2). v0.1 never produces an error.
///
/// # Algorithm
///
/// 1. Collect every entry on each side keyed by [`EntryId`], preserving
///    parent-group context for slice 5.
/// 2. Build [`HashSet<Uuid>`] views of each side's
///    `<DeletedObjects>` tombstones.
/// 3. For every [`EntryId`] in the union of both sides:
///    - present-on-both → 3-way merge via the per-entry walker; route to
///      `entry_conflicts`, `disk_only_changes`, or
///      `local_only_changes` per the per-field auto-resolution
///      classification.
///    - local-only:
///      - tombstoned remotely with `deleted_at < local.mtime` →
///        `delete_edit_conflicts`.
///      - tombstoned remotely with `deleted_at >= local.mtime` →
///        `deleted_on_disk`.
///      - not tombstoned → presumed locally-added; nothing to bucket.
///    - remote-only:
///      - tombstoned locally → `local_deletions_pending_sync` (we
///        deleted it; remote needs the tombstone propagated).
///      - not tombstoned → `added_on_disk`.
pub fn merge(local: &Vault, remote: &Vault) -> Result<MergeOutcome, MergeError> {
    let local_entries = collect_entries_by_id(&local.root);
    let remote_entries = collect_entries_by_id(&remote.root);

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

    let mut outcome = MergeOutcome::default();

    let all_ids: HashSet<EntryId> = local_entries
        .keys()
        .chain(remote_entries.keys())
        .copied()
        .collect();

    for id in all_ids {
        match (local_entries.get(&id), remote_entries.get(&id)) {
            (Some(l), Some(r)) => route_both_present(id, l.entry, r.entry, &mut outcome),
            (Some(l), None) => route_local_only(id, l.entry, &remote_tombstones, &mut outcome),
            (None, Some(r)) => route_remote_only(id, r.entry, &local_tombstones, &mut outcome),
            (None, None) => unreachable!("id collected from union of local + remote"),
        }
    }

    Ok(outcome)
}

/// Per-entry classification when both sides have the entry. Runs the
/// 3-way merge and routes by the auto-resolution profile.
fn route_both_present(id: EntryId, local: &Entry, remote: &Entry, outcome: &mut MergeOutcome) {
    let merge_out = merge_entry(local, remote);

    if !merge_out.conflicts.is_empty() {
        outcome.entry_conflicts.push(EntryConflict {
            entry_id: id,
            local: local.clone(),
            remote: remote.clone(),
            field_deltas: merge_out.conflicts,
        });
        return;
    }

    // No conflicts. Route by whether any auto-resolution would change
    // the local side's value: if the remote wins on at least one
    // field, the local side has work to do (apply the remote value)
    // → `disk_only_changes`. Otherwise the local side is up-to-date
    // and the remote is stale → `local_only_changes`.
    let any_remote_wins = merge_out
        .auto_resolutions
        .iter()
        .any(|(_, side)| matches!(side, Side::Remote));
    if any_remote_wins {
        outcome.disk_only_changes.push(id);
    } else {
        outcome.local_only_changes.push(id);
    }
}

/// Per-entry classification when only the local side has the entry.
fn route_local_only(
    id: EntryId,
    local: &Entry,
    remote_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
    outcome: &mut MergeOutcome,
) {
    let Some(deleted_at) = remote_tombstones.get(&id.0) else {
        // Not tombstoned remotely — presumed locally-added; nothing to do.
        return;
    };
    if local_edited_after(local, *deleted_at) {
        outcome.delete_edit_conflicts.push(id);
    } else {
        outcome.deleted_on_disk.push(id);
    }
}

/// Per-entry classification when only the remote side has the entry.
fn route_remote_only(
    id: EntryId,
    remote: &Entry,
    local_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
    outcome: &mut MergeOutcome,
) {
    if local_tombstones.contains_key(&id.0) {
        outcome.local_deletions_pending_sync.push(id);
    } else {
        outcome.added_on_disk.push(remote.clone());
    }
}

/// Reference into a [`Vault`]'s entry tree, retaining parent-group
/// context for slice 5's apply step.
struct EntryRef<'a> {
    entry: &'a Entry,
    #[allow(dead_code)] // slice 5's apply step is the consumer
    parent_group: GroupId,
}

/// Build a lookup from [`EntryId`] to [`EntryRef`] over the entire
/// group tree rooted at `root`. Depth-first traversal; insertion
/// order matches `iter_entries`.
fn collect_entries_by_id(root: &Group) -> HashMap<EntryId, EntryRef<'_>> {
    let mut out = HashMap::new();
    walk_group(root, &mut out);
    out
}

fn walk_group<'a>(group: &'a Group, out: &mut HashMap<EntryId, EntryRef<'a>>) {
    for entry in &group.entries {
        out.insert(
            entry.id,
            EntryRef {
                entry,
                parent_group: group.id,
            },
        );
    }
    for sub in &group.groups {
        walk_group(sub, out);
    }
}

#[cfg(test)]
mod tests {
    use super::merge;
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{DeletedObject, Entry, EntryId, GroupId, Timestamps, Vault};
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

    fn tombstone(id: u128, deleted_at: Option<chrono::DateTime<chrono::Utc>>) -> DeletedObject {
        DeletedObject::new(Uuid::from_u128(id), deleted_at)
    }

    #[test]
    fn empty_vaults_produce_empty_outcome() {
        let v = Vault::empty(GroupId(Uuid::nil()));
        let out = merge(&v, &v).expect("merge");
        assert!(out.disk_only_changes.is_empty());
        assert!(out.local_only_changes.is_empty());
        assert!(out.entry_conflicts.is_empty());
        assert!(out.added_on_disk.is_empty());
        assert!(out.deleted_on_disk.is_empty());
        assert!(out.local_deletions_pending_sync.is_empty());
        assert!(out.delete_edit_conflicts.is_empty());
        assert!(out.group_conflicts.is_empty());
    }

    #[test]
    fn local_only_entry_with_no_remote_tombstone_is_silent() {
        let local = vault_with(vec![entry(1, "a", at(2026, 1))]);
        let remote = Vault::empty(GroupId(Uuid::nil()));
        let out = merge(&local, &remote).expect("merge");
        assert!(out.deleted_on_disk.is_empty());
        assert!(out.delete_edit_conflicts.is_empty());
        assert!(out.added_on_disk.is_empty());
    }

    #[test]
    fn local_entry_remote_tombstone_old_is_safe_delete() {
        // Local mtime > tombstone deleted_at → local edit happened
        // *after* the deletion was recorded → conflict, not delete.
        // Inverse: tombstone newer than local mtime → safe delete.
        let local = vault_with(vec![entry(1, "a", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote.deleted_objects.push(tombstone(
            1,
            Some(Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap()),
        ));
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(out.deleted_on_disk, vec![EntryId(Uuid::from_u128(1))]);
        assert!(out.delete_edit_conflicts.is_empty());
    }

    #[test]
    fn local_entry_remote_tombstone_recent_is_delete_edit_conflict() {
        let local = vault_with(vec![entry(1, "a", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        // Tombstone before local edit.
        remote.deleted_objects.push(tombstone(
            1,
            Some(Utc.with_ymd_and_hms(2025, 12, 1, 0, 0, 0).unwrap()),
        ));
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(out.delete_edit_conflicts, vec![EntryId(Uuid::from_u128(1))]);
        assert!(out.deleted_on_disk.is_empty());
    }

    #[test]
    fn local_tombstone_remote_present_is_pending_sync() {
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local.deleted_objects.push(tombstone(
            1,
            Some(Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap()),
        ));
        let remote = vault_with(vec![entry(1, "a", at(2026, 1))]);
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(
            out.local_deletions_pending_sync,
            vec![EntryId(Uuid::from_u128(1))]
        );
    }

    #[test]
    fn remote_only_entry_with_no_local_tombstone_is_added_on_disk() {
        let local = Vault::empty(GroupId(Uuid::nil()));
        let remote = vault_with(vec![entry(1, "a", at(2026, 1))]);
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(out.added_on_disk.len(), 1);
        assert_eq!(out.added_on_disk[0].id, EntryId(Uuid::from_u128(1)));
    }

    #[test]
    fn divergent_edit_with_no_lca_is_entry_conflict() {
        // Both sides have entry 1 with different titles, no shared history.
        let local = vault_with(vec![entry(1, "L", at(2026, 1))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 2))]);
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(out.entry_conflicts.len(), 1);
        assert_eq!(out.entry_conflicts[0].entry_id, EntryId(Uuid::from_u128(1)));
    }

    #[test]
    fn one_sided_remote_edit_with_lca_routes_to_disk_only_changes() {
        // Ancestor has Title="A" at day 1. Local stayed at "A". Remote
        // moved to "B" at day 2.
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local = entry(1, "A", at(2026, 1));
        local.history = vec![ancestor.clone()];
        let mut remote = entry(1, "B", at(2026, 2));
        remote.history = vec![ancestor];
        let out = merge(&vault_with(vec![local]), &vault_with(vec![remote])).expect("merge");
        assert_eq!(out.disk_only_changes, vec![EntryId(Uuid::from_u128(1))]);
        assert!(out.entry_conflicts.is_empty());
    }

    #[test]
    fn one_sided_local_edit_with_lca_routes_to_local_only_changes() {
        // Local moved A→B, remote stayed at A. Local doesn't need to
        // pick up anything from remote → local_only_changes.
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local = entry(1, "B", at(2026, 2));
        local.history = vec![ancestor.clone()];
        let mut remote = entry(1, "A", at(2026, 1));
        remote.history = vec![ancestor];
        let out = merge(&vault_with(vec![local]), &vault_with(vec![remote])).expect("merge");
        assert_eq!(out.local_only_changes, vec![EntryId(Uuid::from_u128(1))]);
        assert!(out.entry_conflicts.is_empty());
        assert!(out.disk_only_changes.is_empty());
    }

    #[test]
    fn divergent_edits_with_lca_is_entry_conflict() {
        // Ancestor "A"; local → "L", remote → "R". Both moved off the
        // ancestor → conflict.
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local = entry(1, "L", at(2026, 2));
        local.history = vec![ancestor.clone()];
        let mut remote = entry(1, "R", at(2026, 3));
        remote.history = vec![ancestor];
        let out = merge(&vault_with(vec![local]), &vault_with(vec![remote])).expect("merge");
        assert_eq!(out.entry_conflicts.len(), 1);
        assert!(out.disk_only_changes.is_empty());
        assert!(out.local_only_changes.is_empty());
    }

    #[test]
    fn local_edited_after_with_both_timestamps_none_is_conservative_conflict() {
        // Pinpoint the missing-timestamp fallback: local has no mtime,
        // tombstone has no deleted_at — without info, surface as
        // delete-vs-edit conflict, never silently delete.
        let mut local_entry = Entry::empty(EntryId(Uuid::from_u128(1)));
        // Times stay default (all None).
        local_entry.title = "no-times".into();
        let local = vault_with(vec![local_entry]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote.deleted_objects.push(tombstone(1, None));
        let out = merge(&local, &remote).expect("merge");
        assert_eq!(out.delete_edit_conflicts, vec![EntryId(Uuid::from_u128(1))]);
        assert!(out.deleted_on_disk.is_empty());
    }

    #[test]
    fn orphan_tombstone_is_silently_dropped() {
        // Tombstone for a uuid neither side has → no panic, no bucket
        // population.
        let local = Vault::empty(GroupId(Uuid::nil()));
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote.deleted_objects.push(tombstone(
            0xdead,
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        ));
        let out = merge(&local, &remote).expect("merge");
        assert!(out.deleted_on_disk.is_empty());
        assert!(out.delete_edit_conflicts.is_empty());
        assert!(out.added_on_disk.is_empty());
    }
}
