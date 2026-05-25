//! End-to-end coverage for `apply_merge_park_conflicts` — the
//! non-blocking conflict-parking variant of `apply_merge`.
//!
//! Property surface:
//!
//! 1. `apply_merge_park_conflicts` never errors on
//!    conflict-bearing outcomes (the synthesised KeepLocal
//!    resolution is always valid).
//! 2. After parking, every entry whose conflict was parked has at
//!    least one history record carrying the parked-conflict marker.
//! 3. Local's *current* state for parked entries is unchanged —
//!    parking only adds to history, never mutates the live entry's
//!    main fields. (This is what makes the rework "preserve user
//!    edits" rather than the silently-LWW design we're replacing.)
//! 4. Two peers running `apply_merge_park_conflicts` on the same
//!    `(local, remote)` pair converge on the same set of parked
//!    conflicts.

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomField, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker, MergeOutcome, ParkConflictsConfig,
    apply_merge_park_conflicts, merge,
};
use proptest::prelude::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Strategies — same shape as p2p_convergence.rs / auto_merge previous slice.
// ---------------------------------------------------------------------------

fn entry_strategy() -> impl Strategy<Value = Entry> {
    (
        0u8..6,
        ".{0,8}",
        0u32..40,
        prop::collection::vec((".{0,4}", ".{0,4}", any::<bool>()), 0..2),
        0u8..3,
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
                .map(|(k, v, p)| CustomField::new(k, v, p))
                .collect();
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

fn vault_strategy() -> impl Strategy<Value = Vault> {
    prop::collection::vec(entry_strategy(), 0..5).prop_map(|entries| {
        let mut v = Vault::empty(GroupId(Uuid::nil()));
        let mut by_id: std::collections::HashMap<EntryId, Entry> = std::collections::HashMap::new();
        for e in entries {
            by_id.insert(e.id, e);
        }
        v.root.entries = by_id.into_values().collect();
        v
    })
}

fn now() -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 25, 12, 0, 0).unwrap()
}

fn config() -> ParkConflictsConfig {
    ParkConflictsConfig::with_now(now())
}

/// `MergeOutcome` doesn't expose a trivial "is anything to do?"
/// check; gathers everything the auto-merge would touch.
fn outcome_has_work(outcome: &MergeOutcome) -> bool {
    !outcome.entry_conflicts.is_empty()
        || !outcome.delete_edit_conflicts.is_empty()
        || !outcome.disk_only_changes.is_empty()
        || !outcome.local_only_changes.is_empty()
        || !outcome.added_on_disk.is_empty()
        || !outcome.deleted_on_disk.is_empty()
        || !outcome.local_deletions_pending_sync.is_empty()
}

// ---------------------------------------------------------------------------
// 1. apply_merge_park_conflicts never errors.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 50_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn park_never_errors(a in vault_strategy(), b in vault_strategy()) {
        let outcome = merge(&a, &b).expect("merge");
        let mut local = a.clone();
        let _report = apply_merge_park_conflicts(&mut local, &b, &outcome, &config())
            .expect("apply_merge_park_conflicts must never error on a valid merge outcome");
    }
}

// ---------------------------------------------------------------------------
// 2. Every parked-conflict entry has a marker on a history record.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 100_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn parked_conflict_pushes_remote_as_marked_history(
        a in vault_strategy(), b in vault_strategy(),
    ) {
        let outcome = merge(&a, &b).expect("merge");
        prop_assume!(!outcome.entry_conflicts.is_empty());
        let mut local = a.clone();
        let report = apply_merge_park_conflicts(&mut local, &b, &outcome, &config())
            .expect("apply");
        for entry_id in &report.entries_with_parked_conflict {
            let entry = find_entry(&local.root, *entry_id).expect("entry survives merge");
            let marked: Vec<&Entry> = entry
                .history
                .iter()
                .filter(|h| {
                    h.custom_data
                        .iter()
                        .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
                })
                .collect();
            prop_assert!(
                !marked.is_empty(),
                "parked entry {entry_id:?} has no marked history record"
            );
            // Marker JSON round-trips.
            for h in &marked {
                let cd = h
                    .custom_data
                    .iter()
                    .find(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
                    .unwrap();
                let parsed = FieldConflictMarker::from_value(&cd.value)
                    .expect("marker JSON must round-trip");
                prop_assert_eq!(parsed.at, now(), "marker timestamp matches config");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Parked entries' main state is unchanged. This is the core
// behavioural promise of the rework: we don't silently overwrite a
// user's edit with the other side's edit just because the merge
// classifier saw a conflict.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 100_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn parked_entry_main_state_unchanged(
        a in vault_strategy(), b in vault_strategy(),
    ) {
        let outcome = merge(&a, &b).expect("merge");
        prop_assume!(!outcome.entry_conflicts.is_empty());

        // Capture pre-merge titles for the conflict entries.
        let pre_titles: std::collections::HashMap<EntryId, String> = outcome
            .entry_conflicts
            .iter()
            .filter_map(|c| {
                find_entry(&a.root, c.entry_id)
                    .map(|e| (c.entry_id, e.title.clone()))
            })
            .collect();

        let mut local = a.clone();
        apply_merge_park_conflicts(&mut local, &b, &outcome, &config()).expect("apply");

        for (entry_id, pre_title) in &pre_titles {
            let post = find_entry(&local.root, *entry_id).expect("entry survives");
            prop_assert_eq!(
                &post.title,
                pre_title,
                "parked entry {:?}'s current title changed from {:?} to {:?} — \
                 the rework promises NOT to mutate parked entries' main state",
                entry_id, pre_title, post.title,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Two peers running park_conflicts on the same (a, b) end up with
// the same set of parked-conflict entries. The merge crate already
// guarantees `entry_conflicts.len()` is symmetric — this propagates
// that to the parked-marker bookkeeping.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_global_rejects: 50_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_peers_park_same_conflict_set(
        a in vault_strategy(), b in vault_strategy(),
    ) {
        let outcome_ab = merge(&a, &b).expect("merge a<-b");
        let outcome_ba = merge(&b, &a).expect("merge b<-a");
        prop_assume!(outcome_has_work(&outcome_ab) || outcome_has_work(&outcome_ba));

        let mut a_prime = a.clone();
        let report_a = apply_merge_park_conflicts(&mut a_prime, &b, &outcome_ab, &config())
            .expect("apply on peer A");
        let mut b_prime = b.clone();
        let report_b = apply_merge_park_conflicts(&mut b_prime, &a, &outcome_ba, &config())
            .expect("apply on peer B");

        // Same SET of parked entries (order may differ).
        let mut parked_a: Vec<EntryId> = report_a.entries_with_parked_conflict.clone();
        let mut parked_b: Vec<EntryId> = report_b.entries_with_parked_conflict.clone();
        parked_a.sort_by_key(|id| id.0);
        parked_b.sort_by_key(|id| id.0);
        prop_assert_eq!(
            parked_a, parked_b,
            "two peers must park the same set of entries"
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_entry(group: &keepass_core::model::Group, id: EntryId) -> Option<&Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id == id) {
        return Some(e);
    }
    group.groups.iter().find_map(|g| find_entry(g, id))
}
