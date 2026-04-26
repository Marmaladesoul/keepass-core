//! Property-based invariants for the merge crate.
//!
//! Run thoroughly with `PROPTEST_CASES=2048 cargo test -p keepass-merge
//! --test properties`. Default 32 cases is enough to flush most
//! shape-invariant bugs in CI without blowing the macOS runtime
//! ceiling.
//!
//! Properties:
//!
//! 1. **Determinism** — `merge(a, b)` produces identical bucket counts
//!    when called twice on the same inputs.
//! 2. **Conflict-count direction-independence** — entry conflicts are
//!    a property of "both sides edited off a shared LCA," which
//!    doesn't depend on which side is `local`. (Bucket placement of
//!    single-side adds / deletes / edits *is* asymmetric since the
//!    algorithm treats `local` as the apply target with delete-vs-
//!    edit semantics that flip when sides swap, so we don't assert
//!    full bucket symmetry.)
//! 3. **Auto-apply fixed-point** — applying `Resolution::default()`
//!    against an outcome with no caller-driven conflicts produces a
//!    vault that re-merges to zero conflicts. Indirectly exercises
//!    slice 4's `merge_histories` under apply-time composition.

mod common;

use chrono::{TimeZone, Utc};
use keepass_core::model::{DeletedObject, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
use proptest::prelude::*;
use uuid::Uuid;

// Strategy: small vaults with bounded entry / history / tombstone
// counts and a small UUID domain so cross-side overlap is common.

fn entry_strategy() -> impl Strategy<Value = Entry> {
    (
        0u8..6,   // small uuid domain → frequent overlap
        ".{0,8}", // title regex
        0u32..40, // mtime day offset within Jan 2026
        prop::collection::vec((".{0,4}", ".{0,4}", any::<bool>()), 0..2), // custom fields
        0u8..3,   // history record count
    )
        .prop_map(|(id, title, mtime_day, customs, history_count)| {
            let mut e = Entry::empty(EntryId(Uuid::from_u128(u128::from(id))));
            e.title = title;
            let mut t = Timestamps::default();
            t.last_modification_time = Some(
                Utc.with_ymd_and_hms(2026, 1, mtime_day.clamp(1, 28), 0, 0, 0)
                    .unwrap(),
            );
            e.times = t;
            e.custom_fields = customs
                .into_iter()
                .map(|(k, v, p)| keepass_core::model::CustomField::new(k, v, p))
                .collect();
            // Synthesise a tiny history so the LCA matcher has
            // candidates roughly half the time.
            for i in 0..history_count {
                let mut snap = e.clone();
                snap.history.clear();
                let mut ts = Timestamps::default();
                ts.last_modification_time = Some(
                    Utc.with_ymd_and_hms(2025, 12, u32::from(i + 1), 0, 0, 0)
                        .unwrap(),
                );
                snap.times = ts;
                snap.title = format!("hist-{i}");
                e.history.push(snap);
            }
            e
        })
}

fn tombstone_strategy() -> impl Strategy<Value = DeletedObject> {
    (0u8..6, 1u32..28).prop_map(|(id, day)| {
        DeletedObject::new(
            Uuid::from_u128(u128::from(id)),
            Some(Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()),
        )
    })
}

fn vault_strategy() -> impl Strategy<Value = Vault> {
    (
        prop::collection::vec(entry_strategy(), 0..5),
        prop::collection::vec(tombstone_strategy(), 0..3),
    )
        .prop_map(|(entries, tombstones)| {
            let mut v = Vault::empty(GroupId(Uuid::nil()));
            // Dedup entries by id (last write wins) so a vault doesn't
            // contain two entries with the same id (the model permits
            // it but it's not a meaningful test shape).
            let mut by_id: std::collections::HashMap<EntryId, Entry> =
                std::collections::HashMap::new();
            for e in entries {
                by_id.insert(e.id, e);
            }
            v.root.entries = by_id.into_values().collect();
            v.deleted_objects = tombstones;
            v
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn merge_is_deterministic(local in vault_strategy(), remote in vault_strategy()) {
        let a = merge(&local, &remote).expect("merge a");
        let b = merge(&local, &remote).expect("merge b");
        prop_assert_eq!(a.disk_only_changes.len(), b.disk_only_changes.len());
        prop_assert_eq!(a.local_only_changes.len(), b.local_only_changes.len());
        prop_assert_eq!(a.entry_conflicts.len(), b.entry_conflicts.len());
        prop_assert_eq!(a.added_on_disk.len(), b.added_on_disk.len());
        prop_assert_eq!(a.deleted_on_disk.len(), b.deleted_on_disk.len());
        prop_assert_eq!(a.local_deletions_pending_sync.len(), b.local_deletions_pending_sync.len());
        prop_assert_eq!(a.delete_edit_conflicts.len(), b.delete_edit_conflicts.len());
    }

    #[test]
    fn entry_conflicts_count_is_direction_independent(
        local in vault_strategy(),
        remote in vault_strategy(),
    ) {
        // Per-field 3-way conflict classification doesn't depend on
        // which side is "local"; both sides edited the entry off a
        // shared LCA either way. Bucket *placement* of single-side
        // adds/deletes/edits is asymmetric (the algorithm treats
        // `local` as the apply target, which carries delete-vs-edit
        // semantics that flip when sides swap), so this is the only
        // robust symmetric invariant.
        let forward = merge(&local, &remote).expect("forward");
        let reverse = merge(&remote, &local).expect("reverse");
        prop_assert_eq!(forward.entry_conflicts.len(), reverse.entry_conflicts.len());
    }

    #[test]
    fn auto_apply_is_fixed_point(local in vault_strategy(), remote in vault_strategy()) {
        let outcome = merge(&local, &remote).expect("merge");
        // Only exercise the auto-mergeable path: skip generations that
        // produced caller-driven conflicts since proptest can't pick
        // resolutions sensibly.
        prop_assume!(outcome.entry_conflicts.is_empty());
        prop_assume!(outcome.delete_edit_conflicts.is_empty());

        let mut local_mut = local.clone();
        apply_merge(&mut local_mut, &remote, &outcome, &Resolution::default()).expect("apply");

        let outcome2 = merge(&local_mut, &remote).expect("re-merge");
        prop_assert!(
            outcome2.entry_conflicts.is_empty(),
            "auto-merge fixed-point: re-merge must produce no entry conflicts"
        );
        prop_assert!(
            outcome2.delete_edit_conflicts.is_empty(),
            "auto-merge fixed-point: re-merge must produce no delete-edit conflicts"
        );
    }
}
