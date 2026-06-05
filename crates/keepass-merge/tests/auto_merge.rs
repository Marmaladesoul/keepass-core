//! End-to-end coverage for `apply_merge_park_conflicts` — the
//! **hold-open** conflict variant of `apply_merge`.
//!
//! Property surface:
//!
//! 1. `apply_merge_park_conflicts` never errors on conflict-bearing
//!    outcomes (the synthesised keep-local resolution is always valid).
//! 2. A held conflict keeps **this side's own** current value for the
//!    conflicting facet — no winner is picked, nothing is overwritten.
//! 3. Two peers running `apply_merge_park_conflicts` on the same
//!    `(local, remote)` pair surface the same set of held conflicts.
//!
//! (The old park-and-converge marker assertions are gone: hold-open
//! writes no `<History>` marker; the conflict is surfaced via the merge
//! outcome and resolved by an explicit later choice.)

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomField, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{MergeOutcome, ParkConflictsConfig, apply_merge_park_conflicts, merge};
use proptest::prelude::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Strategies — same shape as p2p_convergence.rs.
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

/// `MergeOutcome` doesn't expose a trivial "is anything to do?" check;
/// gathers everything the auto-merge would touch.
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
// 2. Hold-open keeps THIS side's own value. After apply, a conflicted
// entry's current title equals local's pre-merge title — the merge never
// overwrites the local side of a held conflict with the remote's value.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 100_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn held_conflict_keeps_local_current_value(
        a in vault_strategy(), b in vault_strategy(),
    ) {
        let outcome = merge(&a, &b).expect("merge");
        prop_assume!(!outcome.entry_conflicts.is_empty());

        // Local's pre-merge value for each conflicted entry.
        let expected: std::collections::HashMap<EntryId, String> = outcome
            .entry_conflicts
            .iter()
            .map(|c| (c.entry_id, c.local.title.clone()))
            .collect();

        let mut local = a.clone();
        let report = apply_merge_park_conflicts(&mut local, &b, &outcome, &config())
            .expect("apply");

        for (entry_id, local_title) in &expected {
            let post = find_entry(&local.root, *entry_id).expect("entry survives");
            prop_assert_eq!(
                &post.title,
                local_title,
                "held conflict for {:?} overwrote local's value (got {:?}, expected local's {:?})",
                entry_id, post.title, local_title,
            );
        }

        // No FieldConflictMarker is written any more: the entry's history
        // must carry no `keys.field_conflict.v1` custom_data.
        for entry_id in &report.entries_with_parked_conflict {
            let entry = find_entry(&local.root, *entry_id).expect("entry survives");
            let has_marker = entry.history.iter().any(|h| {
                h.custom_data
                    .iter()
                    .any(|cd| cd.key == "keys.field_conflict.v1")
            });
            prop_assert!(!has_marker, "hold-open must not write a parked-conflict marker");
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Two peers running park_conflicts on the same (a, b) surface the same
// set of held-conflict entries.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_global_rejects: 50_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_peers_hold_same_conflict_set(
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

        let mut held_a: Vec<EntryId> = report_a.entries_with_parked_conflict.clone();
        let mut held_b: Vec<EntryId> = report_b.entries_with_parked_conflict.clone();
        held_a.sort_by_key(|id| id.0);
        held_b.sort_by_key(|id| id.0);
        prop_assert_eq!(
            held_a, held_b,
            "two peers must surface the same set of held conflicts"
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
