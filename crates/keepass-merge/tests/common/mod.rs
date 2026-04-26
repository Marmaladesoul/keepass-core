//! Shared scenario builders for the keepass-merge integration tests.
//!
//! Each scenario is an in-memory `(local, remote)` `Vault` pair plus
//! an `ExpectedOutcome` describing what bucket counts a successful
//! `merge` should produce. Conflict-bearing scenarios additionally
//! ship a `default_resolution` so the corpus can drive `apply_merge`
//! through to a clean re-merge.
//!
//! See `scenarios.rs` for the corpus driver and `properties.rs` for
//! the proptest-driven invariants.

#![allow(dead_code)] // used selectively across multiple integration test crates

use std::collections::HashMap;

use chrono::{DateTime, TimeZone, Utc};
use keepass_core::model::{CustomField, DeletedObject, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{ConflictSide, DeleteEditChoice, Resolution};
use uuid::Uuid;

/// One scenario in the corpus.
pub(crate) struct Scenario {
    pub(crate) name: &'static str,
    pub(crate) local: Vault,
    pub(crate) remote: Vault,
    pub(crate) expected: ExpectedOutcome,
    /// Resolution to apply for the conflict-bearing scenarios. For
    /// auto-mergeable scenarios this is `Resolution::default()`.
    pub(crate) default_resolution: Resolution,
}

/// What the corpus driver asserts about `merge`'s outcome.
#[derive(Debug, Default)]
pub(crate) struct ExpectedOutcome {
    pub(crate) disk_only_changes: usize,
    pub(crate) local_only_changes: usize,
    pub(crate) entry_conflicts: usize,
    pub(crate) added_on_disk: usize,
    pub(crate) deleted_on_disk: usize,
    pub(crate) local_deletions_pending_sync: usize,
    pub(crate) delete_edit_conflicts: usize,
    /// Optional richer assertion: when `Some`, the per-conflict-entry
    /// `field_deltas` keys must equal this set (order-independent).
    pub(crate) field_conflict_keys: Option<Vec<&'static str>>,
}

pub(crate) fn at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(time(year, month, day));
    t
}

pub(crate) fn time(year: i32, month: u32, day: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

pub(crate) fn entry(id: u128, title: &str, ts: Timestamps) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.title = title.into();
    e.times = ts;
    e
}

pub(crate) fn vault_with(entries: Vec<Entry>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = entries;
    v
}

pub(crate) fn tombstone(id: u128, when: DateTime<Utc>) -> DeletedObject {
    DeletedObject::new(Uuid::from_u128(id), Some(when))
}

/// Assert that `outcome` matches `expected`. Bucket counts must be
/// equal; if `field_conflict_keys` is set, the union of every
/// `EntryConflict::field_deltas`'s `key` must equal it as a set.
pub(crate) fn assert_outcome_matches(
    scenario: &str,
    outcome: &keepass_merge::MergeOutcome,
    expected: &ExpectedOutcome,
) {
    assert_eq!(
        outcome.disk_only_changes.len(),
        expected.disk_only_changes,
        "{scenario}: disk_only_changes",
    );
    assert_eq!(
        outcome.local_only_changes.len(),
        expected.local_only_changes,
        "{scenario}: local_only_changes",
    );
    assert_eq!(
        outcome.entry_conflicts.len(),
        expected.entry_conflicts,
        "{scenario}: entry_conflicts",
    );
    assert_eq!(
        outcome.added_on_disk.len(),
        expected.added_on_disk,
        "{scenario}: added_on_disk",
    );
    assert_eq!(
        outcome.deleted_on_disk.len(),
        expected.deleted_on_disk,
        "{scenario}: deleted_on_disk",
    );
    assert_eq!(
        outcome.local_deletions_pending_sync.len(),
        expected.local_deletions_pending_sync,
        "{scenario}: local_deletions_pending_sync",
    );
    assert_eq!(
        outcome.delete_edit_conflicts.len(),
        expected.delete_edit_conflicts,
        "{scenario}: delete_edit_conflicts",
    );

    if let Some(want) = &expected.field_conflict_keys {
        let mut got: Vec<&str> = outcome
            .entry_conflicts
            .iter()
            .flat_map(|c| c.field_deltas.iter().map(|d| d.key.as_str()))
            .collect();
        got.sort_unstable();
        let mut want_sorted = want.clone();
        want_sorted.sort_unstable();
        assert_eq!(got, want_sorted, "{scenario}: field_conflict_keys");
    }
}

// -----------------------------------------------------------------
// Scenario builders
// -----------------------------------------------------------------

pub(crate) fn clean_add() -> Scenario {
    let local = Vault::empty(GroupId(Uuid::nil()));
    let remote = vault_with(vec![entry(1, "added", at(2026, 1, 1))]);
    Scenario {
        name: "clean-add",
        local,
        remote,
        expected: ExpectedOutcome {
            added_on_disk: 1,
            ..Default::default()
        },
        default_resolution: Resolution::default(),
    }
}

pub(crate) fn clean_delete() -> Scenario {
    let local = vault_with(vec![entry(1, "doomed", at(2026, 1, 1))]);
    let mut remote = Vault::empty(GroupId(Uuid::nil()));
    remote.deleted_objects.push(tombstone(1, time(2026, 1, 5)));
    Scenario {
        name: "clean-delete",
        local,
        remote,
        expected: ExpectedOutcome {
            deleted_on_disk: 1,
            ..Default::default()
        },
        default_resolution: Resolution::default(),
    }
}

pub(crate) fn disjoint_edit() -> Scenario {
    // Two different entries, each edited on its own side. No overlap.
    let local = vault_with(vec![
        entry(1, "L-touched", at(2026, 1, 1)),
        entry(2, "shared", at(2026, 1, 1)),
    ]);
    let remote = vault_with(vec![
        entry(1, "L-touched", at(2026, 1, 1)),
        entry(3, "R-touched", at(2026, 1, 1)),
    ]);
    Scenario {
        name: "disjoint-edit",
        local,
        remote,
        expected: ExpectedOutcome {
            // entry 1 is identical → omitted; entry 2 only on local;
            // entry 3 only on remote → added_on_disk.
            added_on_disk: 1,
            ..Default::default()
        },
        default_resolution: Resolution::default(),
    }
}

pub(crate) fn overlap_edit() -> Scenario {
    // Same entry, both sides edited the title differently with a
    // shared LCA so it's a true conflict (not a one-sided edit).
    let ancestor = entry(1, "ancestor", at(2026, 1, 1));
    let mut local_e = entry(1, "L-title", at(2026, 1, 5));
    local_e.history = vec![ancestor.clone()];
    let mut remote_e = entry(1, "R-title", at(2026, 1, 6));
    remote_e.history = vec![ancestor];

    let local = vault_with(vec![local_e]);
    let remote = vault_with(vec![remote_e]);

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("Title".into(), ConflictSide::Remote);
    resolution
        .entry_field_choices
        .insert(EntryId(Uuid::from_u128(1)), choices);

    Scenario {
        name: "overlap-edit",
        local,
        remote,
        expected: ExpectedOutcome {
            entry_conflicts: 1,
            field_conflict_keys: Some(vec!["Title"]),
            ..Default::default()
        },
        default_resolution: resolution,
    }
}

pub(crate) fn delete_vs_edit() -> Scenario {
    // Local edited; remote tombstoned with deleted_at *before* the
    // local edit's mtime → conflict (local edit is newer than the
    // tombstone).
    let mut local_e = entry(1, "edited", at(2026, 6, 1));
    local_e.times.last_modification_time = Some(time(2026, 6, 1));
    let local = vault_with(vec![local_e]);

    let mut remote = Vault::empty(GroupId(Uuid::nil()));
    remote.deleted_objects.push(tombstone(1, time(2026, 1, 5)));

    let mut resolution = Resolution::default();
    resolution
        .delete_edit_choices
        .insert(EntryId(Uuid::from_u128(1)), DeleteEditChoice::KeepLocal);

    Scenario {
        name: "delete-vs-edit",
        local,
        remote,
        expected: ExpectedOutcome {
            delete_edit_conflicts: 1,
            ..Default::default()
        },
        default_resolution: resolution,
    }
}

pub(crate) fn edit_vs_delete() -> Scenario {
    // The mirror: local tombstoned; remote still has the entry. Goes
    // to local_deletions_pending_sync (not delete_edit_conflicts —
    // local already decided).
    let mut local = Vault::empty(GroupId(Uuid::nil()));
    local.deleted_objects.push(tombstone(1, time(2026, 1, 5)));
    let remote = vault_with(vec![entry(1, "still-here", at(2026, 1, 1))]);
    Scenario {
        name: "edit-vs-delete",
        local,
        remote,
        expected: ExpectedOutcome {
            local_deletions_pending_sync: 1,
            ..Default::default()
        },
        default_resolution: Resolution::default(),
    }
}

pub(crate) fn history_divergence() -> Scenario {
    // Entry edited on both sides with a shared ancestor; both moved
    // off the ancestor → conflict (true divergent merge).
    let ancestor = entry(1, "v0", at(2026, 1, 1));
    let mut local_e = entry(1, "L-v1", at(2026, 1, 5));
    local_e.history = vec![ancestor.clone()];
    let mut remote_e = entry(1, "R-v1", at(2026, 1, 6));
    remote_e.history = vec![ancestor];

    let local = vault_with(vec![local_e]);
    let remote = vault_with(vec![remote_e]);

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("Title".into(), ConflictSide::Remote);
    resolution
        .entry_field_choices
        .insert(EntryId(Uuid::from_u128(1)), choices);

    Scenario {
        name: "history-divergence",
        local,
        remote,
        expected: ExpectedOutcome {
            entry_conflicts: 1,
            field_conflict_keys: Some(vec!["Title"]),
            ..Default::default()
        },
        default_resolution: resolution,
    }
}

pub(crate) fn history_truncation_fallback() -> Scenario {
    // Both sides edited the entry and have history, but their history
    // lists don't overlap (truncated past divergence on both sides).
    // No LCA → conservative fallback: every overlapping field is a
    // conflict.
    let mut local_e = entry(1, "L-current", at(2026, 6, 1));
    local_e.history = vec![entry(1, "L-old-1", at(2026, 5, 1))];
    let mut remote_e = entry(1, "R-current", at(2026, 6, 2));
    remote_e.history = vec![entry(1, "R-old-1", at(2026, 5, 2))];

    let local = vault_with(vec![local_e]);
    let remote = vault_with(vec![remote_e]);

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("Title".into(), ConflictSide::Remote);
    resolution
        .entry_field_choices
        .insert(EntryId(Uuid::from_u128(1)), choices);

    Scenario {
        name: "history-truncation-fallback",
        local,
        remote,
        expected: ExpectedOutcome {
            entry_conflicts: 1,
            // Conservative fallback never auto-merges:
            disk_only_changes: 0,
            delete_edit_conflicts: 0,
            field_conflict_keys: Some(vec!["Title"]),
            ..Default::default()
        },
        default_resolution: resolution,
    }
}

pub(crate) fn protected_flag_flip() -> Scenario {
    // Same custom-field key + value; protected bit flipped between
    // sides. No shared ancestor history → conservative conflict on
    // the field.
    let mut local_e = entry(1, "same", at(2026, 1, 1));
    local_e.custom_fields = vec![CustomField::new("OTPSecret", "ABC", false)];
    let mut remote_e = entry(1, "same", at(2026, 1, 1));
    remote_e.custom_fields = vec![CustomField::new("OTPSecret", "ABC", true)];

    let local = vault_with(vec![local_e]);
    let remote = vault_with(vec![remote_e]);

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("OTPSecret".into(), ConflictSide::Remote);
    resolution
        .entry_field_choices
        .insert(EntryId(Uuid::from_u128(1)), choices);

    Scenario {
        name: "protected-flag-flip",
        local,
        remote,
        expected: ExpectedOutcome {
            entry_conflicts: 1,
            field_conflict_keys: Some(vec!["OTPSecret"]),
            ..Default::default()
        },
        default_resolution: resolution,
    }
}

pub(crate) fn tombstone_union() -> Scenario {
    // Both sides have unique tombstones for the same entry with
    // different deleted_at times. Merge unions both. No live entries.
    let mut local = Vault::empty(GroupId(Uuid::nil()));
    local.deleted_objects.push(tombstone(1, time(2026, 1, 5)));
    let mut remote = Vault::empty(GroupId(Uuid::nil()));
    remote.deleted_objects.push(tombstone(1, time(2026, 2, 5)));
    // Plus a third on remote only — orphan tombstone, dropped by merge.
    remote
        .deleted_objects
        .push(tombstone(0xdead, time(2026, 3, 5)));
    Scenario {
        name: "tombstone-union",
        local,
        remote,
        // No live entries means no entry-bucket activity. The
        // tombstone union itself is asserted by the corpus driver
        // post-apply (see scenarios.rs).
        expected: ExpectedOutcome::default(),
        default_resolution: Resolution::default(),
    }
}

/// All scenarios in the corpus.
pub(crate) fn all() -> Vec<Scenario> {
    vec![
        clean_add(),
        clean_delete(),
        disjoint_edit(),
        overlap_edit(),
        delete_vs_edit(),
        edit_vs_delete(),
        history_divergence(),
        history_truncation_fallback(),
        protected_flag_flip(),
        tombstone_union(),
    ]
}
