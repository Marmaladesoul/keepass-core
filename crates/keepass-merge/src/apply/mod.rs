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
//! Slice 5b adds the caller-driven buckets:
//!
//! - [`MergeOutcome::entry_conflicts`] — per-field resolution drives
//!   which side wins each conflicting field. Pre-merge local snapshot
//!   lands in history.
//! - [`MergeOutcome::delete_edit_conflicts`] — `KeepLocal` drops the
//!   remote tombstone (kept-local skip-set), `AcceptRemoteDelete`
//!   removes the local entry and the standard tombstone-union
//!   propagates the remote tombstone.
//!
//! Resolution validation runs first as a read-only single-pass walk
//! returning the first violation as one of `MergeError::
//! UnknownEntryInResolution` / `UnknownFieldInResolution` /
//! `MissingResolutionForConflict`. No mutation has occurred when an
//! error is returned; the caller can fix the resolution and retry.

use std::collections::HashMap;

use keepass_core::model::{Entry, EntryId, Group, GroupId, Vault};

use crate::binary_pool::BinaryPoolRemap;
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::{MergeError, MergeOutcome, Resolution};

// Helpers split off from this file by concern. The top-level
// `apply_merge` flow + the post-apply `reconcile_timestamps` + the
// small tree helpers stay here; `resolution` carries the
// caller-driven choice-application path (validate + apply per-field /
// per-attachment / delete-edit), and `tree` carries the group-tree
// LWW reconciliation + tombstone union + timestamp reconciliation.
mod resolution;
mod tree;

use resolution::{
    apply_delete_edit_resolutions, apply_entry_conflict_resolutions, apply_merged_tags,
    validate_resolution,
};
use tree::{
    EntryWinner, apply_group_tree, build_merged_entry, reconcile_entry_timestamps_recursive,
    reconcile_group_timestamps_recursive, union_history_tombstones_across_entries,
    union_tombstones,
};

/// Mutate `local` in place by applying `outcome` and `resolution`'s
/// caller-driven choices.
///
/// `remote` is consulted read-only for three purposes: to source the
/// added-entries and their parent-group paths, to drive group-tree
/// LWW reconciliation by timestamp, and to source the field values
/// that the resolution has the caller pulling across the merge.
///
/// Returns `Err` if the resolution doesn't cover the outcome's
/// conflict buckets — see the validation pass for the exact contract.
/// On `Err` no mutation has occurred and `local` is untouched.
///
/// `Resolution::default()` is the auto-apply incantation: when the
/// outcome's `entry_conflicts` and `delete_edit_conflicts` buckets
/// are empty, an empty resolution is sufficient.
pub fn apply_merge(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    resolution: &Resolution,
) -> Result<(), MergeError> {
    // Validation pass first — read-only, fail-fast. No mutation has
    // occurred when this returns Err; caller can fix and retry.
    validate_resolution(outcome, resolution)?;

    // Group-tree LWW first so any newly-added remote groups are in
    // place before `added_on_disk` looks for parent-group paths.
    apply_group_tree(local, remote);

    // History-tombstone pre-pass: union both sides' per-entry
    // tombstone lists in-place on local, and filter local's history
    // against the result. Runs over every both-sides-present entry,
    // regardless of which bucket (if any) the entry routes through
    // — the entry-merge classifier excludes <History> and <CustomData>
    // from its comparator, so an entry whose only divergence is a
    // tombstone list would otherwise hit no bucket and never get
    // unioned.
    union_history_tombstones_across_entries(&mut local.root, remote);
    // Same shape, different surface: tag remove-tombstones
    // (`keys.tag_state.v1`). The classifier excludes `<CustomData>`,
    // so this pre-pass covers the entries that route to no bucket.
    tree::union_tag_states_across_entries(&mut local.root, remote);

    // Split-borrow Vault fields so `BinaryPoolRemap` can hold
    // `&mut local.binaries` while the entry-mutation steps work on
    // `&mut local.root`. The two fields are disjoint; the compiler
    // accepts the split when we name each field explicitly.
    let local_root = &mut local.root;
    let local_tombstones = &mut local.deleted_objects;
    let mut remap = BinaryPoolRemap::new(&mut local.binaries, &remote.binaries);

    // Conflict-driven mutations come *before* the auto-merge buckets:
    // conflict resolution is the most opinionated mutation, so we land
    // it first and then auto-merge against the resolved tree. Defends
    // against any future bucket-overlap refactor at zero cost.
    let kept_local =
        apply_delete_edit_resolutions(local_root, local_tombstones, outcome, resolution);
    apply_entry_conflict_resolutions(local_root, outcome, resolution, &mut remap);

    // Entry-level mutations. Order is "remove → modify → add" so a
    // remote-add with the same id as a local-tombstoned entry can't
    // confuse intermediate state.
    for id in &outcome.deleted_on_disk {
        remove_entry(local_root, *id);
    }

    let empty_attachment_resolutions: Vec<AttachmentAutoResolution> = Vec::new();
    let empty_field_resolutions: Vec<(String, Side)> = Vec::new();
    for id in &outcome.disk_only_changes {
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(local_root, *id) else {
            continue;
        };
        let atts = outcome
            .attachment_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_attachment_resolutions);
        let fields = outcome
            .field_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_field_resolutions);
        let icon = outcome.icon_auto_resolutions_per_entry.get(id).copied();
        let mut merged = build_merged_entry(
            local_entry,
            remote_entry,
            EntryWinner::Remote,
            atts,
            fields,
            icon,
            &mut remap,
        );
        apply_merged_tags(&mut merged, outcome, *id, local_entry, remote_entry);
        replace_entry(local_root, *id, merged);
    }

    for id in &outcome.local_only_changes {
        // History-merge runs even though the local content stays put
        // — that's how a remote's intermediate snapshots reach local
        // when the remote's *current* state matches local's.
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(local_root, *id) else {
            continue;
        };
        let atts = outcome
            .attachment_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_attachment_resolutions);
        let fields = outcome
            .field_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_field_resolutions);
        let icon = outcome.icon_auto_resolutions_per_entry.get(id).copied();
        let mut merged = build_merged_entry(
            local_entry,
            remote_entry,
            EntryWinner::Local,
            atts,
            fields,
            icon,
            &mut remap,
        );
        apply_merged_tags(&mut merged, outcome, *id, local_entry, remote_entry);
        replace_entry(local_root, *id, merged);
    }

    for new_entry in &outcome.added_on_disk {
        let target_parent = find_remote_parent(&remote.root, new_entry.id);
        let mut to_insert = new_entry.clone();
        // `new_entry` originates from `remote`; its current-state and
        // every history snapshot's `Attachment::ref_id` references
        // `remote.binaries`. Translate before install.
        remap.rebind(&mut to_insert.attachments);
        for hist in &mut to_insert.history {
            remap.rebind(&mut hist.attachments);
        }
        let inserted = target_parent
            .and_then(|gid| find_group_mut(local_root, gid))
            .map(|g| {
                g.entries.push(to_insert.clone());
            });
        if inserted.is_none() {
            local_root.entries.push(to_insert);
        }
    }

    // `local_deletions_pending_sync` is informational for the FFI
    // consumer — local already has the tombstone, no mutation
    // required. The bucket exists so the caller knows to schedule a
    // save-back, not because apply has work to do.
    let _ = &outcome.local_deletions_pending_sync;

    // Tombstone union: take everything remote has that local doesn't,
    // exact-tuple deduplicated by `(uuid, deleted_at)`. Skip uuids
    // covered by a `KeepLocal` delete-edit choice — those are the
    // "user said keep mine, drop the remote tombstone" path.
    union_tombstones(local_tombstones, &remote.deleted_objects, &kept_local);

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
// Tree helpers
// ---------------------------------------------------------------------------

pub(super) fn find_entry(group: &Group, id: EntryId) -> Option<&Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id == id) {
        return Some(e);
    }
    group.groups.iter().find_map(|g| find_entry(g, id))
}

pub(super) fn replace_entry(group: &mut Group, id: EntryId, new: Entry) {
    if let Some(pos) = group.entries.iter().position(|e| e.id == id) {
        group.entries[pos] = new;
        return;
    }
    for sub in &mut group.groups {
        replace_entry(sub, id, new.clone());
    }
}

pub(super) fn remove_entry(group: &mut Group, id: EntryId) -> bool {
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

pub(super) fn find_remote_parent(group: &Group, entry_id: EntryId) -> Option<GroupId> {
    if group.entries.iter().any(|e| e.id == entry_id) {
        return Some(group.id);
    }
    group
        .groups
        .iter()
        .find_map(|g| find_remote_parent(g, entry_id))
}

pub(super) fn find_group_mut(group: &mut Group, id: GroupId) -> Option<&mut Group> {
    if group.id == id {
        return Some(group);
    }
    group.groups.iter_mut().find_map(|g| find_group_mut(g, id))
}

pub(super) fn collect_entries<'a>(group: &'a Group, out: &mut HashMap<EntryId, &'a Entry>) {
    for e in &group.entries {
        out.insert(e.id, e);
    }
    for sub in &group.groups {
        collect_entries(sub, out);
    }
}

pub(super) fn collect_groups<'a>(group: &'a Group, out: &mut HashMap<GroupId, &'a Group>) {
    out.insert(group.id, group);
    for sub in &group.groups {
        collect_groups(sub, out);
    }
}

pub(super) fn collect_group_ids_walk(g: &Group, out: &mut std::collections::HashSet<GroupId>) {
    out.insert(g.id);
    for sub in &g.groups {
        collect_group_ids_walk(sub, out);
    }
}

pub(super) fn collect_group_ids(group: &Group) -> std::collections::HashSet<GroupId> {
    let mut out = std::collections::HashSet::new();
    collect_group_ids_walk(group, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::{apply_merge, reconcile_timestamps};
    use crate::conflict::{EntryConflict, FieldDelta, FieldDeltaKind};
    use crate::resolution::{ConflictSide, DeleteEditChoice};
    use crate::{MergeError, MergeOutcome, Resolution, merge};
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{DeletedObject, Entry, EntryId, Group, GroupId, Timestamps, Vault};
    use std::collections::HashMap;
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
    fn tombstone_union_dedupes_by_uuid_and_takes_earliest_deleted_at() {
        // Spec §2.8: `<DeletedObjects>` is a grow-only set keyed by
        // UUID; on duplicate UUID, take min `DeletionTime` (earliest
        // deletion wins as provenance).
        let earlier = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let later = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        let id = Uuid::from_u128(1);

        let mut local = Vault::empty(GroupId(Uuid::nil()));
        // Local saw the deletion at `later` (its clock or write order).
        local
            .deleted_objects
            .push(DeletedObject::new(id, Some(later)));

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        // Remote saw the deletion at `earlier` — earliest known
        // provenance.
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(earlier)));

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(
            local.deleted_objects.len(),
            1,
            "duplicate UUID must dedup to a single tombstone"
        );
        assert_eq!(
            local.deleted_objects[0].deleted_at,
            Some(earlier),
            "earliest deleted_at wins on duplicate UUID per spec §2.8"
        );
    }

    #[test]
    fn tombstone_union_treats_none_deleted_at_as_later_than_known() {
        // An `Option<DateTime>` of `None` means "unknown deletion time".
        // Concrete provenance should win over unknown.
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let id = Uuid::from_u128(1);

        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local.deleted_objects.push(DeletedObject::new(id, None));

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(when)));

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(local.deleted_objects.len(), 1);
        assert_eq!(
            local.deleted_objects[0].deleted_at,
            Some(when),
            "concrete deleted_at must win over None"
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

    // ---------- slice 5b: validation + conflict-driven apply ----------

    fn make_entry_conflict(
        id: u128,
        local_title: &str,
        remote_title: &str,
        ts: Timestamps,
    ) -> EntryConflict {
        let l = entry(id, local_title, ts.clone());
        let r = entry(id, remote_title, ts);
        EntryConflict {
            entry_id: EntryId(Uuid::from_u128(id)),
            local: l,
            remote: r,
            field_deltas: vec![FieldDelta {
                key: "Title".into(),
                kind: FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: Vec::new(),
            icon_delta: None,
        }
    }

    #[test]
    fn validation_extra_entry_in_resolution_returns_unknown_entry() {
        let outcome = MergeOutcome::default();
        let mut resolution = Resolution::default();
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(99)), HashMap::new());
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let remote = Vault::empty(GroupId(Uuid::nil()));
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(err, MergeError::UnknownEntryInResolution { .. }));
    }

    #[test]
    fn validation_extra_field_key_returns_unknown_field() {
        let mut outcome = MergeOutcome::default();
        outcome
            .entry_conflicts
            .push(make_entry_conflict(1, "L", "R", at(2026, 1)));
        let mut resolution = Resolution::default();
        let mut fields = HashMap::new();
        fields.insert("Title".into(), ConflictSide::Local);
        fields.insert("BogusField".into(), ConflictSide::Local);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), fields);
        let mut local = vault_with(vec![entry(1, "L", at(2026, 1))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 1))]);
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(err, MergeError::UnknownFieldInResolution { .. }));
    }

    #[test]
    fn validation_missing_entry_conflict_returns_missing_resolution() {
        let mut outcome = MergeOutcome::default();
        outcome
            .entry_conflicts
            .push(make_entry_conflict(1, "L", "R", at(2026, 1)));
        let resolution = Resolution::default();
        let mut local = vault_with(vec![entry(1, "L", at(2026, 1))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 1))]);
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(
            err,
            MergeError::MissingResolutionForConflict { .. }
        ));
    }

    #[test]
    fn validation_missing_delete_edit_returns_missing_resolution() {
        let mut outcome = MergeOutcome::default();
        outcome
            .delete_edit_conflicts
            .push(EntryId(Uuid::from_u128(1)));
        let resolution = Resolution::default();
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let remote = Vault::empty(GroupId(Uuid::nil()));
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(
            err,
            MergeError::MissingResolutionForConflict { .. }
        ));
    }

    #[test]
    fn entry_conflict_apply_with_remote_choice_overwrites_field() {
        let mut local_e = entry(1, "L", at(2026, 1));
        local_e.username = "alice".into();
        let mut remote_e = entry(1, "R", at(2026, 1));
        remote_e.username = "bob".into();
        let conflict = EntryConflict {
            entry_id: EntryId(Uuid::from_u128(1)),
            local: local_e.clone(),
            remote: remote_e.clone(),
            field_deltas: vec![
                FieldDelta {
                    key: "Title".into(),
                    kind: FieldDeltaKind::BothDiffer,
                },
                FieldDelta {
                    key: "UserName".into(),
                    kind: FieldDeltaKind::BothDiffer,
                },
            ],
            attachment_deltas: Vec::new(),
            icon_delta: None,
        };
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(conflict);

        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        choices.insert("UserName".into(), ConflictSide::Local);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        let mut local = vault_with(vec![local_e]);
        let remote = vault_with(vec![remote_e]);
        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let merged = &local.root.entries[0];
        assert_eq!(merged.title, "R", "Title resolved Remote");
        assert_eq!(merged.username, "alice", "UserName resolved Local");
        // Pre-merge local snapshot landed in history.
        assert!(
            merged
                .history
                .iter()
                .any(|h| h.title == "L" && h.username == "alice")
        );
    }

    #[test]
    fn delete_edit_keep_local_drops_remote_tombstone_and_keeps_entry() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let mut local = vault_with(vec![entry(1, "kept", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));
        // Override: pretend local edited after the tombstone so the
        // bucket lands in delete_edit_conflicts.
        local.root.entries[0].times.last_modification_time =
            Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.delete_edit_conflicts.len(), 1);

        let mut resolution = Resolution::default();
        resolution
            .delete_edit_choices
            .insert(EntryId(Uuid::from_u128(1)), DeleteEditChoice::KeepLocal);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        assert!(
            local
                .root
                .entries
                .iter()
                .any(|e| e.id == EntryId(Uuid::from_u128(1)))
        );
        assert!(
            !local
                .deleted_objects
                .iter()
                .any(|t| t.uuid == Uuid::from_u128(1)),
            "KeepLocal must drop the remote tombstone"
        );
    }

    #[test]
    fn delete_edit_accept_remote_removes_entry_and_propagates_tombstone() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let mut local = vault_with(vec![entry(1, "doomed", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));
        local.root.entries[0].times.last_modification_time =
            Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());

        let outcome = merge(&local, &remote).expect("merge");
        let mut resolution = Resolution::default();
        resolution.delete_edit_choices.insert(
            EntryId(Uuid::from_u128(1)),
            DeleteEditChoice::AcceptRemoteDelete,
        );

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        assert!(local.root.entries.is_empty());
        assert!(
            local
                .deleted_objects
                .iter()
                .any(|t| t.uuid == Uuid::from_u128(1))
        );
    }

    #[test]
    fn applied_conflict_is_idempotent_under_remerge() {
        // Apply a resolution; re-merge the resulting vault against
        // the original remote; outcome should be conflict-free.
        let mut local_e = entry(1, "L", at(2026, 1));
        local_e.username = "alice".into();
        let mut remote_e = entry(1, "R", at(2026, 1));
        remote_e.username = "bob".into();

        let mut local = vault_with(vec![local_e.clone()]);
        let remote = vault_with(vec![remote_e.clone()]);

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.entry_conflicts.len(), 1);

        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        choices.insert("UserName".into(), ConflictSide::Remote);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let outcome2 = merge(&local, &remote).expect("re-merge");
        assert!(
            outcome2.entry_conflicts.is_empty(),
            "second merge should produce no further conflicts"
        );
    }

    #[test]
    fn snapshot_dedup_uses_content_hash_at_same_mtime() {
        // Two entries share an mtime but differ in content; the
        // pre-merge local snapshot must be preserved (not collapsed
        // against an existing combined record at the same mtime
        // whose content differs).
        let ancestor = entry(1, "ancestor", at(2026, 1));
        let mut local_e = entry(1, "local-now", at(2026, 5));
        local_e.history = vec![ancestor.clone()];
        let mut remote_e = entry(1, "remote-now", at(2026, 5));
        // Insert a remote history record at the local-now mtime but
        // with different content. Without the content-hash check the
        // snapshot would collapse against this record.
        let mut decoy = entry(1, "decoy", at(2026, 5));
        decoy.history.clear();
        remote_e.history = vec![ancestor, decoy];

        let mut local = vault_with(vec![local_e.clone()]);
        let remote = vault_with(vec![remote_e]);
        let outcome = merge(&local, &remote).expect("merge");
        // Both local and remote share an mtime → conflict; resolve
        // remote so build_resolved_entry exercises the dedup path.
        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let merged = &local.root.entries[0];
        // Snapshot of pre-merge local ("local-now") must be present.
        assert!(
            merged.history.iter().any(|h| h.title == "local-now"),
            "snapshot of overwritten local content must be preserved despite mtime collision with decoy"
        );
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
