//! End-to-end coverage for `apply_merge_auto` — the auto-resolving
//! merge that powers `conflict-resolution-rework`.
//!
//! Property surface (matching §6.tests of the design doc):
//!
//! 1. `apply_merge_auto` never errors on conflict-bucket-bearing
//!    outcomes (the synthesised Resolution is always valid).
//! 2. After auto-merge, every entry that went through a field-LWW
//!    resolution has a marker on at least one of its history
//!    records.
//! 3. Two peers running `apply_merge_auto` on the same `(local,
//!    remote)` pair converge — same shape as `p2p_convergence.rs`'s
//!    pre-existing test, but without the `is_auto_mergeable` guard
//!    because `apply_merge_auto` handles everything.

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomField, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    AutoMergeConfig, FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker, MergeOutcome,
    apply_merge_auto, merge,
};
use proptest::prelude::*;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Strategies — same shape as `p2p_convergence.rs` for consistency.
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

fn config() -> AutoMergeConfig {
    AutoMergeConfig::with_now(now())
}

/// `MergeOutcome` doesn't expose a trivial "is anything to do?"
/// check; this gathers everything the auto-merge would touch.
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
// 1. apply_merge_auto never errors on conflict-bearing outcomes.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 50_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn auto_resolve_never_errors(a in vault_strategy(), b in vault_strategy()) {
        let outcome = merge(&a, &b).expect("merge");
        let mut local = a.clone();
        let _report = apply_merge_auto(&mut local, &b, &outcome, &config())
            .expect("apply_merge_auto must never error on a valid merge outcome");
    }
}

// ---------------------------------------------------------------------------
// 2. Every field-LWW entry gets a marker on at least one history record.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 100_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn field_lww_resolution_marks_loser_snapshot(
        a in vault_strategy(), b in vault_strategy(),
    ) {
        let outcome = merge(&a, &b).expect("merge");
        // Only exercise generations that actually produce a
        // field-LWW conflict, otherwise there's nothing to assert.
        prop_assume!(outcome
            .entry_conflicts
            .iter()
            .any(|c| !c.field_deltas.is_empty()));
        let mut local = a.clone();
        let report = apply_merge_auto(&mut local, &b, &outcome, &config()).expect("apply");
        for entry_id in &report.entries_with_field_lww {
            let entry = find_entry(&local.root, *entry_id).expect("entry survives merge");
            let has_marker = entry
                .history
                .iter()
                .any(|h| h.custom_data.iter().any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY));
            prop_assert!(
                has_marker,
                "entry {entry_id:?} went through field-LWW but no history record carries a marker",
            );
            // Pin the marker's JSON shape too — round-trip should parse.
            for h in &entry.history {
                if let Some(cd) = h.custom_data.iter().find(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY) {
                    let _marker: FieldConflictMarker = FieldConflictMarker::from_value(&cd.value)
                        .expect("marker JSON must round-trip");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Two peers running apply_merge_auto on the same (a, b) converge.
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        max_global_rejects: 50_000,
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_peers_auto_resolve_converge(a in vault_strategy(), b in vault_strategy()) {
        // Each peer merges the other's vault into its own state.
        let outcome_ab = merge(&a, &b).expect("merge a<-b");
        let outcome_ba = merge(&b, &a).expect("merge b<-a");

        prop_assume!(outcome_has_work(&outcome_ab) || outcome_has_work(&outcome_ba));

        let mut a_prime = a.clone();
        apply_merge_auto(&mut a_prime, &b, &outcome_ab, &config())
            .expect("apply on peer A");
        let mut b_prime = b.clone();
        apply_merge_auto(&mut b_prime, &a, &outcome_ba, &config())
            .expect("apply on peer B");

        // Convergence: re-merging the two `_prime` vaults produces
        // an outcome with nothing left to do.
        let convergence = merge(&a_prime, &b_prime).expect("convergence merge");
        prop_assert!(
            !outcome_has_work(&convergence),
            "two-peer convergence failed; convergence outcome = {convergence:?}"
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
