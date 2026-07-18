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
    // Pre-flight: refuse the merge outright on a master-key rotation
    // disagreement (sync-merge spec §6). Two replicas that both record
    // a concrete `<Meta><MasterKeyChanged>` and those timestamps
    // differ have rotated the master key independently — silently
    // picking one side's `Meta` would drop the other's password
    // rotation. The engine layer surfaces the variant as the spec's
    // hard-fault banner. We check before any entry-walking work
    // because there is nothing safe to compute on a divergent-key
    // vault: an entry-level merge would still write a single Meta
    // back, smuggling one side's master-key state through.
    if let (Some(local_at), Some(remote_at)) = (
        local.meta.master_key_changed,
        remote.meta.master_key_changed,
    ) {
        if local_at != remote_at {
            crate::events::emit(&crate::MergeEvent::MasterKeyDisagreement {
                local_changed_at: local_at,
                remote_changed_at: remote_at,
            });
            return Err(MergeError::MasterKeyDisagreement {
                local_changed_at: local_at,
                remote_changed_at: remote_at,
            });
        }
    }

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

    // Parent-map for remote-only entries so the symmetric edit-vs-
    // delete restore can target the right group on apply.
    let remote_parents = collect_entry_parents(&remote.root);

    for id in all_ids {
        match (local_entries.get(&id), remote_entries.get(&id)) {
            (Some(l), Some(r)) => {
                route_both_present(id, l, r, &local.binaries, &remote.binaries, &mut outcome);
            }
            (Some(l), None) => route_local_only(id, l, &remote_tombstones, &mut outcome),
            (None, Some(r)) => route_remote_only(
                id,
                r,
                remote_parents.get(&id).copied().unwrap_or(remote.root.id),
                &local_tombstones,
                &remote_tombstones,
                &mut outcome,
            ),
            (None, None) => unreachable!("id collected from union of local + remote"),
        }
    }

    Ok(outcome)
}

/// Build a `entry_id → owning_group_id` map for every entry in
/// `root`'s subtree. Used by `merge` to know where to restore a
/// symmetric edit-vs-delete entry.
fn collect_entry_parents(root: &Group) -> HashMap<EntryId, GroupId> {
    let mut out = HashMap::new();
    walk_entry_parents(root, &mut out);
    out
}

fn walk_entry_parents(group: &Group, out: &mut HashMap<EntryId, GroupId>) {
    for entry in &group.entries {
        out.insert(entry.id, group.id);
    }
    for sub in &group.groups {
        walk_entry_parents(sub, out);
    }
}

/// Per-entry classification when both sides have the entry. Runs the
/// 3-way merge and routes by the auto-resolution profile.
///
/// `local_binaries` / `remote_binaries` thread through to the
/// attachment classifier in [`merge_entry`] for payload-SHA dereference.
fn route_both_present(
    id: EntryId,
    local: &Entry,
    remote: &Entry,
    local_binaries: &[keepass_core::model::Binary],
    remote_binaries: &[keepass_core::model::Binary],
    outcome: &mut MergeOutcome,
) {
    let mut merge_out = merge_entry(local, remote, local_binaries, remote_binaries);

    // Surface the LCA-mechanics signals. The merge keeps proceeding
    // (conservative parking already covers the data-safety side); these
    // lists exist so the FFI layer can emit the spec §6 warn / error
    // logs and surface the "no shared history" banner.
    if !merge_out.had_ancestor {
        outcome.lca_missing_entries.push(id);
        crate::events::emit(&crate::MergeEvent::LcaMissing {
            entry: id,
            title: local.title.clone(),
        });
    }
    if merge_out.corruption_signal {
        outcome.corruption_signals.push(id);
        crate::events::emit(&crate::MergeEvent::CorruptionSignal {
            entry: id,
            title: local.title.clone(),
        });
    }

    // Tag-merge routing flags. Compute them before the merged set moves
    // into the plan below (`tags_differ_from_remote` requires `remote`).
    let tag_work_for_local = merge_out.tags_changed_from_local;
    let merged_set: std::collections::BTreeSet<&str> =
        merge_out.merged_tags.iter().map(String::as_str).collect();
    let remote_set: std::collections::BTreeSet<&str> =
        remote.tags.iter().map(String::as_str).collect();
    let tag_work_for_remote = merged_set != remote_set;
    drop(merged_set);
    drop(remote_set);

    // Bundle the four auto-resolution facets `merge_entry` produced for
    // this entry into one plan (see `PerEntryPlan`) so apply re-joins
    // them by a single per-entry lookup. Moving them out of `merge_out`
    // leaves the *conflict* facets (`conflicts`, `attachment_conflicts`,
    // `icon_conflict`) in place for the entry-conflict push below.
    let plan = crate::outcome::PerEntryPlan {
        attachment_auto_resolutions: std::mem::take(&mut merge_out.attachment_auto_resolutions),
        field_auto_resolutions: std::mem::take(&mut merge_out.auto_resolutions),
        icon_auto_resolution: merge_out.icon_auto_resolution,
        merged_tags: std::mem::take(&mut merge_out.merged_tags),
    };

    // An entry routes to `entry_conflicts` when *either* field or
    // attachment conflicts (or an icon conflict) need caller input. Both
    // delta lists ride through on the same `EntryConflict` record (the
    // resolver UI walks both).
    if !merge_out.conflicts.is_empty()
        || !merge_out.attachment_conflicts.is_empty()
        || merge_out.icon_conflict.is_some()
    {
        outcome.per_entry.insert(id, plan);
        outcome.entry_conflicts.push(EntryConflict {
            entry_id: id,
            local: local.clone(),
            remote: remote.clone(),
            field_deltas: merge_out.conflicts,
            attachment_deltas: merge_out.attachment_conflicts,
            icon_delta: merge_out.icon_conflict,
        });
        return;
    }

    // Truly identical entry — nothing to do; omit from every bucket so
    // callers iterating `local_only_changes` to log "unchanged" don't
    // see false positives. Tag-only and icon-only edits (in either
    // direction) count as "something to do". Icon-only conflicts (no
    // auto-resolution) still omit here; PR I3 will route them through
    // `entry_conflicts` once the public surface lands. The plan is still
    // stashed so "every both-present entry has a plan" holds uniformly
    // (the stash is harmlessly unread for an omitted entry).
    let tag_work_anywhere = tag_work_for_local || tag_work_for_remote;
    let icon_auto_work = plan.icon_auto_resolution.is_some();
    if plan.field_auto_resolutions.is_empty()
        && plan.attachment_auto_resolutions.is_empty()
        && !tag_work_anywhere
        && !icon_auto_work
    {
        outcome.per_entry.insert(id, plan);
        return;
    }

    // Route by whether any auto-resolution would change the local
    // side's value: if the remote wins on at least one field /
    // attachment / tag / icon, the local side has work to do →
    // `disk_only_changes`. Otherwise the local side is up-to-date
    // (but remote might be stale, including for tags) →
    // `local_only_changes`. The plan (built above) carries the per-field
    // and icon winners apply overlays on the bucket-level clone; without
    // that overlay apply would silently lose any facet whose winning
    // side differs from the bucket winner — the "mixed-side field wins"
    // data-loss bug the per-facet maps let through once.
    let any_remote_wins = plan
        .field_auto_resolutions
        .iter()
        .any(|(_, side)| matches!(side, Side::Remote))
        || plan
            .attachment_auto_resolutions
            .iter()
            .any(|r| matches!(r.side, Side::Remote))
        || tag_work_for_local
        || matches!(plan.icon_auto_resolution, Some(Side::Remote));
    outcome.per_entry.insert(id, plan);
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
///
/// Two-way edit-vs-delete check: if local has a tombstone for the
/// uuid AND remote's `last_modification_time` is strictly newer than
/// local's `deleted_at`, this is the symmetric edit-vs-delete case
/// (remote edited after local deleted). The entry id lands in
/// `delete_edit_conflicts`; the apply step uses the
/// `delete_edit_restore_from_remote` sidecar to restore the entry
/// under `remote_parent` per spec §4 "edit wins". Without that
/// symmetric check, the remote edit would silently fall into
/// `local_deletions_pending_sync` (a no-op bucket on apply) and the
/// two peers would diverge — a real bug the Tier 2 chaos runner
/// surfaced.
fn route_remote_only(
    id: EntryId,
    remote: &Entry,
    remote_parent: GroupId,
    local_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
    remote_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
    outcome: &mut MergeOutcome,
) {
    let Some(local_deleted_at) = local_tombstones.get(&id.0) else {
        // Not tombstoned locally — fresh remote-added entry.
        outcome.added_on_disk.push(remote.clone());
        return;
    };
    // Symmetric edit-vs-delete: remote's mtime strictly newer than
    // local's deletion → "edit wins" per spec §4.
    //
    // Guard against the pathological "entry alive on remote AND
    // tombstone for it in remote's `<DeletedObjects>`" state. That
    // configuration is remote's own self-contradiction (a clean kdbx
    // pipeline either holds the entry alive XOR carries the
    // tombstone — see `keepass-core::kdbx::import_entry_with_uuid`'s
    // tombstone scrub on restore). When it arises here — most
    // commonly from a pathological proptest fixture but in principle
    // from a corrupt-but-readable file — punting it to
    // `local_deletions_pending_sync` matches the "remote will eventually
    // reconcile itself" intuition and preserves the auto-apply
    // fixed-point property the proptest exercises.
    if remote_tombstones.contains_key(&id.0) {
        outcome.local_deletions_pending_sync.push(id);
        return;
    }
    if remote_edited_after(remote, *local_deleted_at) {
        outcome.delete_edit_conflicts.push(id);
        outcome
            .delete_edit_restore_from_remote
            .insert(id, (remote.clone(), remote_parent));
        return;
    }
    // Local's tombstone postdates remote's edit (or either is
    // missing) — local's deletion wins, but it hasn't been
    // propagated to remote yet.
    outcome.local_deletions_pending_sync.push(id);
}

/// True mirror of `local_edited_after`: shares its
/// [`conservative_edit_wins`](crate::time::conservative_edit_wins)
/// policy, with the roles swapped (remote's `last_modification_time`
/// vs. local's `deleted_at`). Any missing timestamp — including a
/// remote entry with no mtime facing a concrete local tombstone —
/// resolves to "edit wins" (keep), so both peers reach the same
/// keep/drop decision from either direction and the vault converges.
fn remote_edited_after(
    remote: &Entry,
    local_deleted_at: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    crate::time::conservative_edit_wins(remote.times.last_modification_time, local_deleted_at)
}

/// Build a lookup from [`EntryId`] to its `&Entry` over the entire
/// group tree rooted at `root`. Depth-first traversal.
///
/// Slice 5a's apply step walks remote independently to find parent
/// groups for `added_on_disk` insertions, so the walker doesn't need
/// to retain parent-group context here.
fn collect_entries_by_id(root: &Group) -> HashMap<EntryId, &Entry> {
    let mut out = HashMap::new();
    walk_group(root, &mut out);
    out
}

fn walk_group<'a>(group: &'a Group, out: &mut HashMap<EntryId, &'a Entry>) {
    for entry in &group.entries {
        out.insert(entry.id, entry);
    }
    for sub in &group.groups {
        walk_group(sub, out);
    }
}

#[cfg(test)]
mod tests {
    use super::{MergeError, merge};
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
    fn identical_entries_on_both_sides_are_omitted() {
        let e = entry(1, "same", at(2026, 1));
        let local = vault_with(vec![e.clone()]);
        let remote = vault_with(vec![e]);
        let out = merge(&local, &remote).expect("merge");
        assert!(out.disk_only_changes.is_empty());
        assert!(out.local_only_changes.is_empty());
        assert!(out.entry_conflicts.is_empty());
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
    fn lca_missing_surfaces_when_both_histories_empty() {
        // Two same-UUID entries with disjoint state and no history on
        // either side trip the spec §3 corruption signal AND
        // necessarily route through the no-LCA path.
        let local = entry(1, "L", at(2026, 5));
        let remote = entry(1, "R", at(2026, 4));
        let out = merge(&vault_with(vec![local]), &vault_with(vec![remote])).expect("merge");
        let id = EntryId(Uuid::from_u128(1));
        assert!(
            out.lca_missing_entries.contains(&id),
            "no-LCA entry must appear in lca_missing_entries"
        );
        assert!(
            out.corruption_signals.contains(&id),
            "same-UUID + no LCA + empty histories on both sides is a corruption signal"
        );
    }

    #[test]
    fn lca_missing_does_not_imply_corruption_when_history_exists() {
        // Long-divergence case (spec §3 case 1): both sides hold the
        // entry, neither side has the LCA in their history (truncated),
        // but at least one side carries *some* history. That's a
        // truncation, not a corruption — surfaces in
        // `lca_missing_entries` only.
        let mut local = entry(1, "L", at(2026, 5));
        let mut local_hist = entry(1, "H-local", at(2026, 1));
        local_hist.history.clear();
        local.history.push(local_hist);
        let mut remote = entry(1, "R", at(2026, 4));
        let mut remote_hist = entry(1, "H-remote", at(2026, 2));
        remote_hist.history.clear();
        remote.history.push(remote_hist);
        let out = merge(&vault_with(vec![local]), &vault_with(vec![remote])).expect("merge");
        let id = EntryId(Uuid::from_u128(1));
        assert!(out.lca_missing_entries.contains(&id));
        assert!(
            !out.corruption_signals.contains(&id),
            "long-divergence is not a corruption signal — both sides have history"
        );
    }

    #[test]
    fn master_key_disagreement_aborts_merge_when_both_timestamps_differ() {
        let local = vault_with(vec![entry(1, "L", at(2026, 5))]);
        let mut remote = vault_with(vec![entry(1, "R", at(2026, 4))]);
        let local_at = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let remote_at = Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap();
        let mut local = local;
        local.meta.master_key_changed = Some(local_at);
        remote.meta.master_key_changed = Some(remote_at);
        let err = merge(&local, &remote).expect_err("hard fault expected");
        match err {
            MergeError::MasterKeyDisagreement {
                local_changed_at,
                remote_changed_at,
            } => {
                assert_eq!(local_changed_at, local_at);
                assert_eq!(remote_changed_at, remote_at);
            }
            other => panic!("expected MasterKeyDisagreement, got {other:?}"),
        }
    }

    #[test]
    fn master_key_disagreement_does_not_fire_when_only_one_side_rotated() {
        // One side rotated, the other never has — that's a normal
        // unsynced rotation, not a disagreement. The vault-meta merge
        // path (PR-3.2 item 5) will LWW the timestamp through; for now
        // the merge proceeds.
        let mut local = vault_with(vec![entry(1, "L", at(2026, 5))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 4))]);
        local.meta.master_key_changed = Some(Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap());
        // remote.meta.master_key_changed stays None.
        let _ = merge(&local, &remote).expect("single-side rotation must not fault");
    }

    #[test]
    fn master_key_disagreement_does_not_fire_when_both_match() {
        // Both sides record the same rotation timestamp — by far the
        // common case, where rotation propagated cleanly.
        let when = Utc.with_ymd_and_hms(2026, 4, 1, 0, 0, 0).unwrap();
        let mut local = vault_with(vec![entry(1, "L", at(2026, 5))]);
        let mut remote = vault_with(vec![entry(1, "R", at(2026, 4))]);
        local.meta.master_key_changed = Some(when);
        remote.meta.master_key_changed = Some(when);
        let _ = merge(&local, &remote).expect("matching rotation timestamps must not fault");
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
