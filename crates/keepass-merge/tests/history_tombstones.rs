//! Integration tests for the history-tombstone mechanism.
//!
//! These tests exercise the public crate API end-to-end: callers
//! issue tombstones via `add_history_tombstone`, then verify that
//! `merge` + `apply_merge` respect them across the round trips that
//! make up real-world sync scenarios.
//!
//! See `_project-management/history-tombstones.md` (in the Keys repo)
//! for the §8 test list this file implements.

use chrono::{TimeZone, Utc};
use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    HistoryTombstone, Resolution, TOMBSTONE_CUSTOM_DATA_KEY, TombstoneReason,
    add_history_tombstone, apply_merge, merge, parse_tombstones, reconcile_history_tombstones,
};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Tiny helpers — keep the test bodies declarative.
// ---------------------------------------------------------------------------

fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn timestamps_at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(ts(year, month, day));
    t
}

fn entry_with_id(id_byte: u8) -> Entry {
    Entry::empty(EntryId(Uuid::from_u128(u128::from(id_byte))))
}

/// Build a vault containing a single entry. The entry's history is
/// populated from `history_records` (each tuple is a title + mtime).
fn vault_with_entry(
    entry_id: u8,
    current_title: &str,
    current_mtime: (i32, u32, u32),
    history_records: &[(&str, (i32, u32, u32))],
) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    let mut e = entry_with_id(entry_id);
    e.title = current_title.into();
    e.times = timestamps_at(current_mtime.0, current_mtime.1, current_mtime.2);
    for (title, mtime) in history_records {
        let mut snap = entry_with_id(entry_id);
        snap.title = (*title).into();
        snap.times = timestamps_at(mtime.0, mtime.1, mtime.2);
        e.history.push(snap);
    }
    v.root.entries.push(e);
    v
}

fn first_entry(v: &Vault) -> &Entry {
    v.root.entries.first().expect("vault has no entries")
}

fn first_entry_mut(v: &mut Vault) -> &mut Entry {
    v.root.entries.first_mut().expect("vault has no entries")
}

/// Build a standalone entry (no vault wrapper) with `current` as its
/// live title and a history list. Used by the `reconcile_history_tombstones`
/// tests, which exercise the per-entry peer-pull path directly.
fn entry_with_history(id_byte: u8, history_records: &[(&str, (i32, u32, u32))]) -> Entry {
    let mut e = entry_with_id(id_byte);
    e.title = "current".into();
    e.times = timestamps_at(2026, 5, 1);
    for (title, mtime) in history_records {
        let mut snap = entry_with_id(id_byte);
        snap.title = (*title).into();
        snap.times = timestamps_at(mtime.0, mtime.1, mtime.2);
        e.history.push(snap);
    }
    e
}

fn history_titles(e: &Entry) -> Vec<&str> {
    e.history.iter().map(|h| h.title.as_str()).collect()
}

/// Round-trip a merge in the "local absorbs remote" direction with
/// the default (no caller-driven) resolution. Returns the merged
/// vault for assertions.
fn merge_into(mut local: Vault, remote: &Vault) -> Vault {
    let outcome = merge(&local, remote).expect("merge");
    apply_merge(&mut local, remote, &outcome, &Resolution::default()).expect("apply_merge");
    local
}

// ---------------------------------------------------------------------------
// §8.1 — deletion propagates via tombstone.
// ---------------------------------------------------------------------------

#[test]
fn deletion_propagates_via_tombstone() {
    // Local has [A, B] in history after the user deleted C; remote
    // still has [A, B, C]. Without tombstones, merge_histories'
    // additive behaviour would re-introduce C on the local side.
    // With tombstones, C stays gone.
    let mut local = vault_with_entry(
        1,
        "current",
        (2026, 5, 1),
        &[("a", (2026, 1, 1)), ("b", (2026, 2, 1))],
    );
    let remote = vault_with_entry(
        1,
        "current",
        (2026, 5, 1),
        &[
            ("a", (2026, 1, 1)),
            ("b", (2026, 2, 1)),
            ("c", (2026, 3, 1)),
        ],
    );

    // Simulate "the user deleted C on local"; tombstone it.
    let c_snap = remote
        .root
        .entries
        .first()
        .unwrap()
        .history
        .iter()
        .find(|h| h.title == "c")
        .cloned()
        .unwrap();
    add_history_tombstone(
        first_entry_mut(&mut local),
        &c_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 24),
    )
    .expect("add tombstone");

    let merged = merge_into(local, &remote);
    let titles: Vec<&str> = first_entry(&merged)
        .history
        .iter()
        .map(|h| h.title.as_str())
        .collect();
    assert!(
        !titles.contains(&"c"),
        "tombstoned record must not resurrect, got {titles:?}"
    );
}

// ---------------------------------------------------------------------------
// §8.2 — tombstones themselves merge via union, NOT via LWW on the
// CustomData value (the load-bearing correctness property).
// ---------------------------------------------------------------------------

#[test]
fn tombstones_themselves_merge_via_union() {
    // Local tombstoned snapshot C (out of common history [A,B,C,D]).
    // Remote independently tombstoned D. After merge, both
    // tombstones must be on the merged side. If standard custom_data
    // LWW were used, one side's tombstone list would silently
    // overwrite the other's.
    let common = &[
        ("a", (2026, 1, 1)),
        ("b", (2026, 2, 1)),
        ("c", (2026, 3, 1)),
        ("d", (2026, 4, 1)),
    ];
    let mut local = vault_with_entry(1, "current", (2026, 5, 1), common);
    let mut remote = vault_with_entry(1, "current", (2026, 5, 1), common);

    let c_snap = first_entry(&local)
        .history
        .iter()
        .find(|h| h.title == "c")
        .cloned()
        .unwrap();
    let d_snap = first_entry(&local)
        .history
        .iter()
        .find(|h| h.title == "d")
        .cloned()
        .unwrap();

    add_history_tombstone(
        first_entry_mut(&mut local),
        &c_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 10),
    )
    .unwrap();
    add_history_tombstone(
        first_entry_mut(&mut remote),
        &d_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 11),
    )
    .unwrap();

    let merged = merge_into(local, &remote);
    let merged_tombstones: Vec<HistoryTombstone> =
        parse_tombstones(&first_entry(&merged).custom_data).unwrap();
    assert_eq!(
        merged_tombstones.len(),
        2,
        "both sides' tombstones must survive the merge; got {merged_tombstones:?}"
    );

    let merged_titles: Vec<&str> = first_entry(&merged)
        .history
        .iter()
        .map(|h| h.title.as_str())
        .collect();
    assert!(!merged_titles.contains(&"c"));
    assert!(!merged_titles.contains(&"d"));
    assert!(merged_titles.contains(&"a"));
    assert!(merged_titles.contains(&"b"));
}

// ---------------------------------------------------------------------------
// §8.3 — an unaware client that resurrects a tombstoned record gets
// the record re-filtered by the next merge.
// ---------------------------------------------------------------------------

#[test]
fn unaware_resurrection_is_re_filtered() {
    // Local: history [a, b], tombstone for c.
    // Remote (an "unaware" client that added c back): history [a, b, c],
    // no tombstone for c on its side.
    // Merge: c must be filtered out again on local; tombstone must
    // remain on the merged side so future merges keep filtering.
    let mut local = vault_with_entry(
        1,
        "current",
        (2026, 5, 1),
        &[("a", (2026, 1, 1)), ("b", (2026, 2, 1))],
    );
    let remote = vault_with_entry(
        1,
        "current",
        (2026, 5, 1),
        &[
            ("a", (2026, 1, 1)),
            ("b", (2026, 2, 1)),
            ("c", (2026, 3, 1)),
        ],
    );

    let c_snap = remote
        .root
        .entries
        .first()
        .unwrap()
        .history
        .iter()
        .find(|h| h.title == "c")
        .cloned()
        .unwrap();
    add_history_tombstone(
        first_entry_mut(&mut local),
        &c_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 24),
    )
    .unwrap();

    let merged = merge_into(local, &remote);
    let titles: Vec<&str> = first_entry(&merged)
        .history
        .iter()
        .map(|h| h.title.as_str())
        .collect();
    assert!(
        !titles.contains(&"c"),
        "tombstoned record must not resurrect even when remote re-introduced it"
    );

    // The tombstone must STILL be on the merged entry so a subsequent
    // sync round against another unaware peer continues to re-filter.
    let surviving: Vec<HistoryTombstone> =
        parse_tombstones(&first_entry(&merged).custom_data).unwrap();
    assert_eq!(
        surviving.len(),
        1,
        "tombstone must persist for next-merge re-filtering"
    );
}

// ---------------------------------------------------------------------------
// §8.4 — null-mtime history records can be tombstoned and respected.
// ---------------------------------------------------------------------------

#[test]
fn null_mtime_records_can_be_tombstoned() {
    // Build local with a history record that has no mtime (KDBX
    // permits this for legacy / broken-metadata records). Tombstone
    // it. Merge against a remote that still has the record. The
    // null-mtime record must drop out of the merged history.
    let mut local = Vault::empty(GroupId(Uuid::nil()));
    let mut e = entry_with_id(1);
    e.title = "current".into();
    e.times = timestamps_at(2026, 5, 1);

    let mut untimed = entry_with_id(1);
    untimed.title = "untimed-loser".into();
    // No mtime — Timestamps::default() leaves last_modification_time as None.
    untimed.times = Timestamps::default();
    e.history.push(untimed.clone());
    local.root.entries.push(e);

    // Remote: same shape (so the record is on both sides too).
    let mut remote = Vault::empty(GroupId(Uuid::nil()));
    let mut e_r = entry_with_id(1);
    e_r.title = "current".into();
    e_r.times = timestamps_at(2026, 5, 1);
    e_r.history.push(untimed.clone());
    remote.root.entries.push(e_r);

    add_history_tombstone(
        first_entry_mut(&mut local),
        &untimed,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 24),
    )
    .unwrap();

    let merged = merge_into(local, &remote);
    let titles: Vec<&str> = first_entry(&merged)
        .history
        .iter()
        .map(|h| h.title.as_str())
        .collect();
    assert!(
        !titles.contains(&"untimed-loser"),
        "null-mtime tombstoned record must drop, got {titles:?}"
    );
}

// ---------------------------------------------------------------------------
// Extra: verify the custom_data key choice is the one the doc pins.
// A schema-name change requires migration; locking it down here.
// ---------------------------------------------------------------------------

#[test]
fn custom_data_key_is_the_documented_one() {
    let mut local = vault_with_entry(1, "current", (2026, 5, 1), &[("a", (2026, 1, 1))]);
    let a_snap = first_entry(&local).history.first().cloned().unwrap();
    add_history_tombstone(
        first_entry_mut(&mut local),
        &a_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 24),
    )
    .unwrap();

    let key_present = first_entry(&local)
        .custom_data
        .iter()
        .any(|cd| cd.key == TOMBSTONE_CUSTOM_DATA_KEY);
    assert!(
        key_present,
        "expected custom_data key {TOMBSTONE_CUSTOM_DATA_KEY:?}"
    );
}

// ---------------------------------------------------------------------------
// `reconcile_history_tombstones` — the per-entry peer-pull twin of the
// disk-reconcile pre-pass. Drives the engine's `ingest_peer` history-deletion
// propagation: an entry that differs only in its tombstone list is `InSync`
// to the classifier, so this is what carries the deletion across.
// ---------------------------------------------------------------------------

#[test]
fn reconcile_propagates_peer_deletion_and_is_idempotent() {
    // peer (the deleter): had [a, b, c], scrubbed b → history [a, c] + tombstone.
    let mut peer = entry_with_history(
        1,
        &[
            ("a", (2026, 1, 1)),
            ("b", (2026, 2, 1)),
            ("c", (2026, 3, 1)),
        ],
    );
    let b_snap = peer
        .history
        .iter()
        .find(|h| h.title == "b")
        .cloned()
        .unwrap();
    add_history_tombstone(
        &mut peer,
        &b_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 24),
    )
    .unwrap();
    assert_eq!(history_titles(&peer), ["a", "c"]);

    // local (unaware): still holds the full history, no tombstone.
    let mut local = entry_with_history(
        1,
        &[
            ("a", (2026, 1, 1)),
            ("b", (2026, 2, 1)),
            ("c", (2026, 3, 1)),
        ],
    );

    let changed = reconcile_history_tombstones(&mut local, &peer, &[]).unwrap();
    assert!(changed, "local must change: b pruned and tombstone adopted");
    assert_eq!(
        history_titles(&local),
        ["a", "c"],
        "the tombstoned record must be pruned from local history"
    );
    assert_eq!(
        parse_tombstones(&local.custom_data).unwrap().len(),
        1,
        "the peer's tombstone must be adopted onto local"
    );

    // Idempotent: a second reconcile against the same peer is a no-op,
    // which is what makes the real sync loop terminate.
    let again = reconcile_history_tombstones(&mut local, &peer, &[]).unwrap();
    assert!(!again, "second reconcile must report no change (loop-safe)");
    assert_eq!(history_titles(&local), ["a", "c"]);
}

#[test]
fn reconcile_unions_independent_deletions_symmetrically() {
    // A and B each scrub a different record out of common history
    // [a, b, c, d]: A deletes b, B deletes c. After a bidirectional
    // reconcile both must agree on [a, d] with both tombstones.
    let common = &[
        ("a", (2026, 1, 1)),
        ("b", (2026, 2, 1)),
        ("c", (2026, 3, 1)),
        ("d", (2026, 4, 1)),
    ];
    let mut a = entry_with_history(1, common);
    let b_snap = a.history.iter().find(|h| h.title == "b").cloned().unwrap();
    add_history_tombstone(
        &mut a,
        &b_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 10),
    )
    .unwrap();
    let mut b = entry_with_history(1, common);
    let c_snap = b.history.iter().find(|h| h.title == "c").cloned().unwrap();
    add_history_tombstone(
        &mut b,
        &c_snap,
        &[],
        TombstoneReason::UserDelete,
        None,
        ts(2026, 5, 11),
    )
    .unwrap();

    // Sync both directions.
    reconcile_history_tombstones(&mut a, &b, &[]).unwrap(); // a learns c-deletion
    reconcile_history_tombstones(&mut b, &a, &[]).unwrap(); // b learns b-deletion

    assert_eq!(history_titles(&a), ["a", "d"]);
    assert_eq!(history_titles(&b), ["a", "d"]);
    assert_eq!(parse_tombstones(&a.custom_data).unwrap().len(), 2);
    assert_eq!(parse_tombstones(&b.custom_data).unwrap().len(), 2);
}

#[test]
fn reconcile_without_tombstones_is_a_noop() {
    // The two sides differ in history depth but neither carries a
    // tombstone. Depth divergence is legitimate (sync excludes history
    // from the convergence digest); only a tombstone propagates a
    // deletion — so reconcile must NOT resurrect or import peer-only
    // records, and must report no change.
    let mut local = entry_with_history(1, &[("a", (2026, 1, 1)), ("b", (2026, 2, 1))]);
    let peer = entry_with_history(
        1,
        &[
            ("a", (2026, 1, 1)),
            ("b", (2026, 2, 1)),
            ("c", (2026, 3, 1)),
        ],
    );
    let changed = reconcile_history_tombstones(&mut local, &peer, &[]).unwrap();
    assert!(!changed, "no tombstone on either side ⇒ no change");
    assert_eq!(history_titles(&local), ["a", "b"]);
    assert!(parse_tombstones(&local.custom_data).unwrap().is_empty());
}
