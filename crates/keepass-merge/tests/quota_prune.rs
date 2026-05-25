//! End-to-end check that quota-driven history pruning survives a
//! subsequent sync with a peer that hadn't yet pruned.
//!
//! The unit tests in `src/prune.rs` verify the pruning algorithm in
//! isolation; this integration test pins the full merge round-trip
//! that motivates the tombstone-aware variant existing at all.

use chrono::{TimeZone, Utc};
use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    Resolution, TombstoneReason, apply_merge, merge, prune_history_with_tombstones,
};
use uuid::Uuid;

fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn timestamps_at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(ts(year, month, day));
    t
}

fn vault_with_history(history_titles: &[&str]) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    let mut e = Entry::empty(EntryId(Uuid::from_u128(1)));
    e.title = "current".into();
    e.times = timestamps_at(2026, 5, 1);
    for (i, title) in history_titles.iter().enumerate() {
        let mut snap = Entry::empty(EntryId(Uuid::from_u128(1)));
        snap.title = (*title).into();
        // Spread the snapshots across distinct mtimes so the merge
        // crate's per-(mtime,hash) dedup doesn't conflate them.
        snap.times = timestamps_at(2026, 1, u32::try_from(i).unwrap() + 1);
        e.history.push(snap);
    }
    v.root.entries.push(e);
    v
}

#[test]
fn pruned_records_dont_resurrect_after_sync_with_unaware_peer() {
    // Local: pruned down to 2 history items (the latest two).
    // Remote: still has the full 5 history items (hasn't pruned).
    // After merge: local must keep its 2; the older 3 must not be
    // resurrected from remote even though remote still has them.
    let titles_full = ["v0", "v1", "v2", "v3", "v4"];
    let mut local = vault_with_history(&titles_full);
    let remote = vault_with_history(&titles_full);

    // Prune local down to 2.
    let pruned = prune_history_with_tombstones(
        local.root.entries.first_mut().unwrap(),
        2,
        -1,
        &[],
        TombstoneReason::QuotaTrim,
        None,
        ts(2026, 5, 24),
    )
    .expect("prune");
    assert_eq!(pruned, 3);
    assert_eq!(local.root.entries[0].history.len(), 2);

    // Now merge against the un-pruned remote.
    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    // The merged local must still have only the 2 newest history
    // entries — the 3 oldest must stay pruned despite remote still
    // holding them.
    let merged_titles: Vec<&str> = local.root.entries[0]
        .history
        .iter()
        .map(|h| h.title.as_str())
        .collect();
    assert_eq!(
        merged_titles,
        vec!["v3", "v4"],
        "quota-pruned records must not resurrect from an unaware peer"
    );
}
