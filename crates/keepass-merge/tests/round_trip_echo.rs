//! Round-trip (echo-back) convergence for a one-sided edit — the Bug A
//! repro from the PR-2 soak. See `internal design notes`.
//!
//! The existing `p2p_convergence` proptests model a *single* round of
//! independent merges and assert only that the merge *outcome* is empty
//! (`is_converged`) — they never inspect `<History>` or parked conflict
//! markers, and never model the **echo-back**: A makes a one-sided edit,
//! B merges it, then B's merged result comes back to A and A re-merges
//! it. A re-merging the peer's echo of its *own* change must be a no-op:
//! no parked conflict, no history bloat.
//!
//! Observed in the field (sync-test4 KDBX 4 and sync-test5 KDBX 3.1): the
//! editing side ends up with a spurious `keys.field_conflict.v1` marker
//! and redundant history. These tests pin where that originates.

use chrono::{TimeZone, Timelike, Utc};
use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{ParkConflictsConfig, apply_merge_park_conflicts, merge};
use uuid::Uuid;

fn at(s: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, s).unwrap());
    t
}

/// Like [`at`] but with sub-second precision, modelling the engine's
/// millisecond mtimes (`keys-engine::now_ms`) before a KDBX round-trip
/// truncates them to the whole second [`at`] produces.
fn at_ms(s: u32, millis: u32) -> Timestamps {
    let base = Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, s).unwrap();
    let mut t = Timestamps::default();
    t.last_modification_time = Some(base.with_nanosecond(millis * 1_000_000).unwrap());
    t
}

fn cfg(now_s: u32) -> ParkConflictsConfig {
    ParkConflictsConfig::with_now(Utc.with_ymd_and_hms(2026, 6, 4, 1, 0, now_s).unwrap())
}

fn vault_of(e: Entry) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = vec![e];
    v
}

fn entry(id: u128) -> Entry {
    Entry::empty(EntryId(Uuid::from_u128(id)))
}

fn find(v: &Vault, id: u128) -> &Entry {
    v.root
        .entries
        .iter()
        .find(|e| e.id == EntryId(Uuid::from_u128(id)))
        .expect("entry present")
}

/// Faithful round-trip: B' is produced by the *real* apply, then echoed
/// back to A. No hand-stamped divergence. If this parks, the bug is
/// entirely inside keepass-merge.
#[test]
fn faithful_round_trip_of_one_sided_edit_is_a_noop() {
    // Both peers start identical: a fresh synced entry "alpha" @ t0.
    let mut base = entry(1);
    base.title = "alpha".into();
    base.times = at(0);

    // A renames; engine archives the pre-edit snapshot (keeps t0) and
    // bumps current to t1.
    let mut a = base.clone();
    a.title = "alpha renamed".into();
    a.times = at(5);
    let mut pre = base.clone();
    pre.history.clear();
    a.history = vec![pre];
    let vault_a = vault_of(a);

    // B untouched: "alpha" @ t0, no history.
    let vault_b = vault_of(base.clone());

    // Step 1 — B merges A's edit.
    let out_b = merge(&vault_b, &vault_a).expect("merge b<-a");
    let mut b_prime = vault_b.clone();
    apply_merge_park_conflicts(&mut b_prime, &vault_a, &out_b, &cfg(10)).expect("apply B");
    let b_e = find(&b_prime, 1);
    assert_eq!(
        b_e.title, "alpha renamed",
        "B should take A's one-sided rename"
    );
    assert!(
        out_b.entry_conflicts.is_empty(),
        "B surfaced a spurious conflict on a one-sided edit"
    );

    // Step 2 — echo back: A merges B's merged result.
    let out_a = merge(&vault_a, &b_prime).expect("merge a<-b'");
    let mut a_prime = vault_a.clone();
    apply_merge_park_conflicts(&mut a_prime, &b_prime, &out_a, &cfg(15)).expect("apply A");
    let a_e = find(&a_prime, 1);
    assert_eq!(
        a_e.title, "alpha renamed",
        "A's current must stay the rename"
    );
    assert!(
        out_a.entry_conflicts.is_empty(),
        "A surfaced a spurious conflict on the echo-back of its OWN edit"
    );
}

/// Bug A (history bloat): the engine stamps mtimes in **milliseconds**
/// but a KDBX round-trip truncates them to **whole seconds**, so the
/// editing side's own history record (ms-precise) and the peer's
/// truncated copy of that *same* record are byte-identical yet carry
/// different mtimes. The history-dedup paths must collapse them — both
/// `merge_histories`' grouping and `build_merged_entry`'s loser-snapshot
/// guard run at second resolution, so the echo-back must NOT pile up
/// duplicate history records. (Pre-fix this produced the observed
/// `Five`×2 / `Five edited`×2 bloat on the editing Mac.)
#[test]
fn truncated_echo_back_does_not_bloat_history() {
    // A: renamed current "Five edited" @ t1 (ms-precise), with the
    // pre-edit snapshot "Five" @ t0 (ms-precise) archived in history.
    let mut a = entry(1);
    a.title = "Five edited".into();
    a.times = at_ms(5, 500);
    let mut a_pre = entry(1);
    a_pre.title = "Five".into();
    a_pre.times = at_ms(0, 250);
    a.history = vec![a_pre];
    let vault_a = vault_of(a);

    // B: still holds the stale "Five", and its mtimes have been
    // truncated to whole seconds by a KDBX save/reload. Both B's current
    // and its lone history record are second-truncated twins of A's
    // archived "Five" snapshot — so they exercise the loser-snapshot
    // guard AND `merge_histories`' grouping.
    let mut b = entry(1);
    b.title = "Five".into();
    b.times = at(0);
    let mut b_pre = entry(1);
    b_pre.title = "Five".into();
    b_pre.times = at(0);
    b.history = vec![b_pre];
    let vault_b = vault_of(b);

    let out = merge(&vault_a, &vault_b).expect("merge a<-b");
    let mut a_prime = vault_a.clone();
    apply_merge_park_conflicts(&mut a_prime, &vault_b, &out, &cfg(20)).expect("apply A");
    let e = find(&a_prime, 1);

    assert_eq!(
        e.title, "Five edited",
        "A's edit must win over the stale peer value"
    );
    assert!(
        out.entry_conflicts.is_empty(),
        "stale-vs-current must not surface a conflict"
    );
    let five_count = e.history.iter().filter(|h| h.title == "Five").count();
    assert_eq!(
        five_count, 1,
        "ms-vs-second twins of the pre-edit snapshot must collapse to ONE history record"
    );
    assert_eq!(
        e.history.len(),
        1,
        "history should hold exactly the single pre-edit snapshot — no bloat on the truncated echo-back"
    );
}

/// The field mechanism: the remote still holds the *pre-edit* value, but
/// its mtime doesn't line up with A's archived snapshot (KDBX-3.1 second
/// truncation, or a re-stamp across the round-trip), so exact
/// `(mtime, hash)` LCA matching misses the ancestor. The remote's value
/// is nonetheless a *prior version in A's own history* — so it's
/// stale-vs-current, not a genuine clash, and must NOT park.
#[test]
fn stale_ancestor_value_off_by_mtime_is_not_parked() {
    let mut a = entry(1);
    a.title = "alpha renamed".into();
    a.times = at(5); // t1
    let mut pre = entry(1);
    pre.title = "alpha".into();
    pre.times = at(0); // t0 — the archived pre-edit snapshot
    a.history = vec![pre];
    let vault_a = vault_of(a);

    // Remote: still "alpha", but stamped at a DIFFERENT second than A's
    // archived snapshot (t0' != t0). Exact-mtime LCA matching can't pair
    // it with A.history[0].
    let mut r = entry(1);
    r.title = "alpha".into();
    r.times = at(2); // t0' — off by a couple of seconds
    let vault_r = vault_of(r);

    let out = merge(&vault_a, &vault_r).expect("merge a<-r");
    let mut a_prime = vault_a.clone();
    apply_merge_park_conflicts(&mut a_prime, &vault_r, &out, &cfg(20)).expect("apply A");
    let e = find(&a_prime, 1);
    assert_eq!(e.title, "alpha renamed", "current must stay the rename");
    assert!(
        out.entry_conflicts.is_empty(),
        "remote's value is an ancestor in local history — must not surface a conflict"
    );
}
