//! Scenario corpus driver. One `#[test]` per named scenario; each
//! asserts:
//!
//! 1. `merge` produces the expected bucket counts (and field-conflict
//!    keys, where the scenario specifies them).
//! 2. `apply_merge` with the scenario's `default_resolution` runs
//!    cleanly (no `MergeError`).
//! 3. Re-merging the resulting vault against the original remote
//!    produces a conflict-free outcome (the round-trip fixed-point
//!    invariant promoted from slice 5b's idempotence test).

mod common;

use common::{
    Scenario, all, assert_outcome_matches, clean_add, clean_delete, delete_vs_edit, disjoint_edit,
    edit_vs_delete, history_divergence, history_truncation_fallback, overlap_edit,
    protected_flag_flip, tombstone_union,
};
use keepass_merge::{apply_merge, merge};

/// Run a scenario through merge → apply_merge → re-merge.
///
/// `expect_fixed_point` controls whether the post-apply re-merge must
/// produce zero conflicts. True for scenarios whose resolution
/// converges both sides to the same state (auto-merge or full-Remote
/// conflict choices). False for `delete-vs-edit` with `KeepLocal`:
/// without a save-roundtrip writing local's "I un-deleted this" back
/// to remote, the next merge will keep re-detecting the conflict.
/// That's a sync-protocol concern, not a merge-correctness one.
fn run(mut scenario: Scenario, expect_fixed_point: bool) {
    let outcome = merge(&scenario.local, &scenario.remote).expect("merge");
    assert_outcome_matches(scenario.name, &outcome, &scenario.expected);

    apply_merge(
        &mut scenario.local,
        &scenario.remote,
        &outcome,
        &scenario.default_resolution,
    )
    .unwrap_or_else(|e| panic!("{}: apply_merge: {e:?}", scenario.name));

    if expect_fixed_point {
        let outcome2 = merge(&scenario.local, &scenario.remote).expect("re-merge");
        assert!(
            outcome2.entry_conflicts.is_empty() && outcome2.delete_edit_conflicts.is_empty(),
            "{}: re-merge after apply must produce no conflicts (got {} entry-conflicts, {} delete-edit conflicts)",
            scenario.name,
            outcome2.entry_conflicts.len(),
            outcome2.delete_edit_conflicts.len(),
        );
    }
}

#[test]
fn corpus_clean_add() {
    run(clean_add(), true);
}

#[test]
fn corpus_clean_delete() {
    run(clean_delete(), true);
}

#[test]
fn corpus_disjoint_edit() {
    run(disjoint_edit(), true);
}

#[test]
fn corpus_overlap_edit() {
    run(overlap_edit(), true);
}

#[test]
fn corpus_delete_vs_edit() {
    run(delete_vs_edit(), false);
}

#[test]
fn corpus_edit_vs_delete() {
    run(edit_vs_delete(), true);
}

#[test]
fn corpus_history_divergence() {
    run(history_divergence(), true);
}

#[test]
fn corpus_history_truncation_fallback() {
    run(history_truncation_fallback(), true);
}

#[test]
fn corpus_protected_flag_flip() {
    run(protected_flag_flip(), true);
}

#[test]
fn corpus_tombstone_union() {
    let mut scenario = tombstone_union();
    let outcome = merge(&scenario.local, &scenario.remote).expect("merge");
    assert_outcome_matches(scenario.name, &outcome, &scenario.expected);
    apply_merge(
        &mut scenario.local,
        &scenario.remote,
        &outcome,
        &scenario.default_resolution,
    )
    .expect("apply");
    // Tombstone-union-specific assertion: post-apply local has both
    // (uuid=1, 2026-01-05) and (uuid=1, 2026-02-05) tombstones plus
    // the orphan (uuid=0xdead, 2026-03-05).
    let count_for = |id: u128| {
        scenario
            .local
            .deleted_objects
            .iter()
            .filter(|t| t.uuid == uuid::Uuid::from_u128(id))
            .count()
    };
    assert_eq!(
        count_for(1),
        2,
        "two tombstones for uuid=1 preserved by exact-tuple union"
    );
    assert_eq!(
        count_for(0xdead),
        1,
        "orphan tombstone propagated through union"
    );
}

#[test]
fn corpus_smoke_all_scenarios_have_unique_names() {
    use std::collections::HashSet;
    let mut seen: HashSet<&'static str> = HashSet::new();
    for s in all() {
        assert!(seen.insert(s.name), "duplicate scenario name: {}", s.name);
    }
}
