//! Public-surface coverage for [`keepass_merge::classify`] — the
//! per-entry conflict-detection brain behind the multi-peer owner-rows
//! store (see `_project-management/sync-multipeer-store.md` §9 Phase 1).
//!
//! The exhaustive scenario matrix lives next to the code as unit tests
//! in `entry_merge.rs`; this file pins the *public* API shape (the
//! `classify` / `Classification` / `Granularity` re-exports are
//! reachable and usable from outside the crate) and the
//! no-shared-ancestor fallback the task calls out explicitly.

use chrono::{DateTime, TimeZone, Utc};
use keepass_core::model::{Entry, EntryId, Timestamps};
use keepass_merge::{Classification, Granularity, classify};
use uuid::Uuid;

fn t(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(secs, 0)
        .single()
        .expect("valid timestamp")
}

/// An entry sharing the entry id `id`, whose CURRENT value is `current`
/// and whose `<History>` holds one ancestor snapshot `base` stamped
/// `base_secs` — the LCA the two device forks share.
fn forked(
    id: Uuid,
    base: (&str, &str, &str),
    base_secs: i64,
    current: (&str, &str, &str),
) -> Entry {
    let mut snap = Entry::empty(EntryId(id));
    snap.title = base.0.into();
    snap.password = base.1.into();
    snap.notes = base.2.into();
    let mut ts = Timestamps::default();
    ts.last_modification_time = Some(t(base_secs));
    snap.times = ts;

    let mut e = Entry::empty(EntryId(id));
    e.title = current.0.into();
    e.password = current.1.into();
    e.notes = current.2.into();
    e.history = vec![snap];
    e
}

const BASE: (&str, &str, &str) = ("Acme", "pw0", "notes");

#[test]
fn public_classify_auto_merges_one_sided_edit() {
    let id = Uuid::new_v4();
    let local = forked(id, BASE, 1_000, BASE); // untouched
    let peer = forked(id, BASE, 1_000, ("Acme", "pw-new", "notes")); // peer rotated the password

    match classify(&local, &peer, &[], &[], Granularity::Field) {
        Classification::AutoMerged { merged, .. } => {
            assert_eq!(merged.password, "pw-new", "peer's rotation adopted");
        }
        other => panic!("expected AutoMerged, got {other:?}"),
    }
}

#[test]
fn public_classify_flags_concurrent_same_field_edit() {
    let id = Uuid::new_v4();
    let local = forked(id, BASE, 1_000, ("Acme", "pw-mine", "notes"));
    let peer = forked(id, BASE, 1_000, ("Acme", "pw-theirs", "notes"));

    match classify(&local, &peer, &[], &[], Granularity::Field) {
        Classification::Conflict { conflict } => {
            let keys: Vec<&str> = conflict
                .field_deltas
                .iter()
                .map(|d| d.key.as_str())
                .collect();
            assert_eq!(keys, vec!["Password"]);
            // Hold-open: both sides preserved, no winner picked.
            assert_eq!(conflict.local.password, "pw-mine");
            assert_eq!(conflict.remote.password, "pw-theirs");
        }
        other => panic!("expected Conflict, got {other:?}"),
    }
}

#[test]
fn public_classify_no_shared_ancestor_falls_back_to_conflict() {
    // Histories trimmed past the fork point on both sides ⇒ no shared
    // snapshot. A both-present field that differs parks conservatively
    // rather than guessing a winner — the same fallback as today's merge.
    let id = Uuid::new_v4();
    let local = forked(id, BASE, 1_000, ("Acme", "pw-a", "notes"));
    let peer = forked(id, ("Other", "Y", "Z"), 9_999, ("Acme", "pw-b", "notes"));

    match classify(&local, &peer, &[], &[], Granularity::Field) {
        Classification::Conflict { conflict } => {
            let keys: Vec<&str> = conflict
                .field_deltas
                .iter()
                .map(|d| d.key.as_str())
                .collect();
            assert_eq!(keys, vec!["Password"]);
        }
        other => panic!("expected Conflict on the no-LCA fallback, got {other:?}"),
    }
}

#[test]
fn public_granularity_knob_flips_diff_field_verdict() {
    let id = Uuid::new_v4();
    let local = forked(id, BASE, 1_000, ("Acme-mine", "pw0", "notes"));
    let peer = forked(id, BASE, 1_000, ("Acme", "pw0", "notes-theirs"));

    assert!(matches!(
        classify(&local, &peer, &[], &[], Granularity::Field),
        Classification::AutoMerged { .. }
    ));
    assert!(matches!(
        classify(&local, &peer, &[], &[], Granularity::Item),
        Classification::Conflict { .. }
    ));
}
