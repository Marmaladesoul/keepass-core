//! Lossless history merge for the entry-level apply step.
//!
//! [`merge_histories`] takes the `<History>` lists from two pre-merge
//! sides of the same entry and produces a single combined list,
//! deduplicating identical records that share an mtime+content while
//! preserving every divergent record. Slice 5's apply step calls this
//! when constructing the merged entry's `<History>` so neither side's
//! intermediate snapshots are lost in the wholesale-replace.
//!
//! ## Dedup contract
//!
//! Records are grouped by [`Timestamps::last_modification_time`]
//! (mtime), **truncated to whole-second resolution**
//! ([`crate::time::second_resolution`]). The engine stamps mtimes in
//! milliseconds but the KDBX on-disk format is whole-second, so the
//! same snapshot can carry a sub-second mtime on one side and a
//! truncated one on the other after a sync round-trip; coarsening the
//! key collapses those twins (see `sync-soak-bugs.md` Bug A). Records
//! at genuinely different seconds stay in distinct groups. Within a
//! group:
//!
//! - All hash-identical → keep one (the first encountered, with
//!   local before remote per the local-first invariant).
//! - Some differ in content → keep all of them. KDBX permits multiple
//!   history records sharing an mtime; downstream readers don't break
//!   on it.
//!
//! Content equality is decided by [`crate::hash::entry_content_hash`]
//! — i.e. the same canonical bytestream the LCA matcher uses. A
//! custom-field `protected` bit flip with no value change *does*
//! produce two distinct records.
//!
//! ## Ordering
//!
//! Output is sorted oldest → newest by mtime. Records with `mtime =
//! None` lead the list (chosen over trailing per #R16): a history
//! record without a timestamp is by definition a past state with
//! broken metadata, not a fresh edit, so the conservative read is
//! "we don't know when, but it's older than anything timed". The
//! choice is pinned by a test so a future refactor can't silently
//! flip it.
//!
//! Stable-sort preserves the local-first invariant within an mtime
//! group; we depend on `Vec::sort_by`'s stability per Rust's
//! contract.
//!
//! ## Scope
//!
//! `Meta::HistoryMaxItems` enforcement is **not** in this function —
//! `merge_histories` is purely additive and may produce a list
//! longer than the configured cap. `keepass-core`'s save path does
//! the truncation; the merge crate doesn't read or enforce the cap.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use keepass_core::model::{Binary, Entry};

use crate::hash::{ct_eq, entry_content_hash};
use crate::time::second_resolution;

type Mtime = Option<DateTime<Utc>>;
type Bucket<'a> = Vec<([u8; 32], &'a Entry)>;

/// True when `entry` carries a parked-conflict marker in its
/// `custom_data`. The marker is excluded from `entry_content_hash`, so
/// the dedup in [`merge_histories`] consults this directly to keep a
/// marked record from being evicted by its unmarked content-twin.
fn has_conflict_marker(entry: &Entry) -> bool {
    entry
        .custom_data
        .iter()
        .any(|c| c.key == crate::field_conflict::FIELD_CONFLICT_CUSTOM_DATA_KEY)
}

/// Merge two `<History>` lists losslessly **except** for records
/// the caller has explicitly tombstoned. See module docs for the
/// dedup, ordering, and scope contracts.
///
/// `binaries` is the (single) binary pool every record in `local` and
/// `remote` references. Callers must rebind any remote-side history
/// records to local's pool before calling — `apply.rs` does this via
/// `BinaryPoolRemap`. Once attachments are part of `entry_content_hash`
/// (slice B5), the dedup needs the pool to dereference `ref_id`s.
///
/// `tombstones` is the unioned `(mtime, hash)` set from both sides'
/// `keys.history_tombstones.v1` lists. Any candidate record matching
/// an entry in this set is filtered out — that's the mechanism by
/// which user-driven history deletions, quota truncations, and
/// conflict-resolution cleanup all persist across merges. Pass an
/// empty set to recover the prior purely-additive behaviour.
///
/// See `tombstone.rs` for the schema and the
/// [`crate::tombstone::union_tombstones`] / [`crate::tombstone::tombstone_set`]
/// helpers callers use to build the set.
pub(crate) fn merge_histories(
    local: &[Entry],
    remote: &[Entry],
    binaries: &[Binary],
    tombstones: &crate::tombstone::TombstoneSet,
) -> Vec<Entry> {
    // Group by mtime; within a group dedup by content hash. Walking
    // local first then remote gives us the "local before remote on
    // collision" invariant. Tombstoned `(mtime, hash)` pairs are
    // filtered at the point of grouping so they never enter the
    // output.
    //
    // The grouping key is the mtime truncated to whole-second
    // resolution (`second_resolution`): the engine stamps mtimes in
    // milliseconds but the KDBX round-trip truncates to seconds, so the
    // same snapshot can arrive with a sub-second mtime on one side and
    // a truncated one on the other. Keying at second resolution
    // collapses those ms-vs-second twins into one bucket so the
    // content-hash dedup below recognises them as the same record —
    // the "history bloat" fix for Bug A. The bucket still stores the
    // original `&Entry`, so the output record keeps its full-precision
    // mtime; only the dedup *key* is coarsened. The tombstone lookup
    // uses the same coarsened key (`tombstone_set` truncates to match).
    let mut by_mtime: HashMap<Mtime, Bucket<'_>> = HashMap::new();
    for snap in local.iter().chain(remote.iter()) {
        let hash = entry_content_hash(snap, binaries);
        let mtime = second_resolution(snap.times.last_modification_time);
        if tombstones.contains(&(mtime, hash)) {
            continue;
        }
        let bucket = by_mtime.entry(mtime).or_default();
        match bucket.iter().position(|(h, _)| ct_eq(h, &hash)) {
            None => bucket.push((hash, snap)),
            Some(idx) => {
                // Content-twin already in the bucket. The parked-conflict
                // marker lives in `custom_data`, which `entry_content_hash`
                // excludes — so a marked snapshot and its unmarked twin
                // collide here. Prefer the MARKED record: otherwise the
                // first-encountered (local) unmarked twin would evict the
                // peer's marked one and the conflict would surface on only
                // one device (see `sync-soak-bugs.md`). The rule is
                // deterministic and symmetric in (local, remote) — marked
                // beats unmarked regardless of side or order — so it stays
                // convergent. A resolved marker is still cleared everywhere:
                // its history tombstone keys on the same content hash, so it
                // filters both twins out before this dedup runs.
                if !has_conflict_marker(bucket[idx].1) && has_conflict_marker(snap) {
                    bucket[idx] = (hash, snap);
                }
            }
        }
    }

    // Flatten and sort: untimed records lead (`None` < `Some`), then
    // ascending mtime — `Option`'s natural `Ord` does both for us.
    let mut groups: Vec<(Mtime, Bucket<'_>)> = by_mtime.into_iter().collect();
    groups.sort_by_key(|g| g.0);
    let mut out: Vec<Entry> = Vec::new();
    for (_, bucket) in groups {
        for (_, entry) in bucket {
            out.push(entry.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::merge_histories;
    use crate::tombstone::TombstoneSet;
    use chrono::{TimeZone, Timelike, Utc};
    use keepass_core::model::{CustomField, Entry, EntryId, Timestamps};
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    /// Timestamps at a fixed second, optionally carrying sub-second
    /// nanoseconds — used to model the engine's millisecond mtime vs the
    /// KDBX whole-second truncation of the same logical instant.
    fn at_secs(sec: u32, nanos: u32) -> Timestamps {
        let base = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, sec).unwrap();
        let mut t = Timestamps::default();
        t.last_modification_time = Some(base.with_nanosecond(nanos).unwrap());
        t
    }

    fn snapshot(title: &str, ts: Timestamps) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::nil()));
        e.title = title.into();
        e.times = ts;
        e
    }

    /// Tests that exercise the pre-tombstone behaviour use this empty
    /// set — additive merge is recovered by passing it.
    fn no_tombstones() -> TombstoneSet {
        TombstoneSet::default()
    }

    #[test]
    fn empty_inputs_produce_empty_output() {
        assert!(merge_histories(&[], &[], &[], &no_tombstones()).is_empty());
    }

    #[test]
    fn disjoint_mtimes_interleave_by_sort_order() {
        let local = vec![snapshot("a", at(2026, 1)), snapshot("c", at(2026, 3))];
        let remote = vec![snapshot("b", at(2026, 2))];
        let out = merge_histories(&local, &remote, &[], &no_tombstones());
        let titles: Vec<&str> = out.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["a", "b", "c"]);
    }

    #[test]
    fn identical_record_on_both_sides_is_deduped() {
        let s = snapshot("same", at(2026, 1));
        let out = merge_histories(
            std::slice::from_ref(&s),
            std::slice::from_ref(&s),
            &[],
            &no_tombstones(),
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn same_mtime_divergent_content_keeps_both_local_first() {
        let local = vec![snapshot("L", at(2026, 1))];
        let remote = vec![snapshot("R", at(2026, 1))];
        let out = merge_histories(&local, &remote, &[], &no_tombstones());
        let titles: Vec<&str> = out.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["L", "R"]);
    }

    #[test]
    fn untimed_records_lead_in_encounter_order() {
        // Per #R16: history records without an mtime have broken
        // metadata, not a fresh-entry default, so they belong at the
        // "we don't know when, but it's older" end. Pinned by this
        // test so a future refactor can't silently flip the choice.
        let mut untimed_local = Entry::empty(EntryId(Uuid::nil()));
        untimed_local.title = "UL".into();
        let mut untimed_remote = Entry::empty(EntryId(Uuid::nil()));
        untimed_remote.title = "UR".into();
        let timed = snapshot("T", at(2026, 1));
        let out = merge_histories(
            &[untimed_local, timed.clone()],
            &[untimed_remote],
            &[],
            &no_tombstones(),
        );
        let titles: Vec<&str> = out.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["UL", "UR", "T"]);
    }

    #[test]
    fn merging_is_idempotent() {
        let a = vec![snapshot("a", at(2026, 1)), snapshot("b", at(2026, 2))];
        let b = vec![snapshot("b", at(2026, 2)), snapshot("c", at(2026, 3))];
        let once = merge_histories(&a, &b, &[], &no_tombstones());
        let twice = merge_histories(&once, &b, &[], &no_tombstones());
        let once_titles: Vec<&str> = once.iter().map(|e| e.title.as_str()).collect();
        let twice_titles: Vec<&str> = twice.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(once_titles, twice_titles);
    }

    #[test]
    fn protected_flag_distinguishes_records_at_same_mtime() {
        // Two snapshots with the same mtime, same standard fields,
        // but a custom-field `protected` bit that flips between
        // them. `entry_content_hash` (slice 2) treats these as
        // different content, so both are preserved.
        let mtime = at(2026, 1);
        let mut a = snapshot("same", mtime.clone());
        a.custom_fields = vec![CustomField::new("k", "v", false)];
        let mut b = snapshot("same", mtime);
        b.custom_fields = vec![CustomField::new("k", "v", true)];
        let out = merge_histories(&[a], &[b], &[], &no_tombstones());
        assert_eq!(
            out.len(),
            2,
            "protected-flag flip must not collapse records"
        );
    }

    #[test]
    fn tombstoned_record_is_filtered_even_when_only_one_side_has_it() {
        use crate::hash::entry_content_hash;
        let a = snapshot("keep", at(2026, 1));
        let b = snapshot("drop", at(2026, 2));
        let mut tombstones = TombstoneSet::default();
        tombstones.insert((b.times.last_modification_time, entry_content_hash(&b, &[])));
        let out = merge_histories(&[a], &[b], &[], &tombstones);
        let titles: Vec<&str> = out.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["keep"]);
    }

    #[test]
    fn ms_vs_second_mtime_twins_dedup_to_one() {
        // Bug A (history bloat): the engine stamps mtimes in
        // milliseconds; the KDBX round-trip truncates to whole seconds.
        // So the *same* snapshot arrives with a sub-second mtime on the
        // editing side and a truncated one on the side that re-read it
        // from disk. Second-resolution dedup must collapse the twins.
        let local = vec![snapshot("Five", at_secs(30, 123_000_000))];
        let remote = vec![snapshot("Five", at_secs(30, 0))];
        let out = merge_histories(&local, &remote, &[], &no_tombstones());
        assert_eq!(
            out.len(),
            1,
            "ms-vs-second twins of the same record must collapse to one"
        );
    }

    #[test]
    fn same_content_distinct_seconds_are_kept() {
        // Truncation is to the *second*, not content-only: a genuine
        // same-content record a full second apart (e.g. an edit-then-
        // revert) stays a distinct history record.
        let local = vec![snapshot("Five", at_secs(30, 0))];
        let remote = vec![snapshot("Five", at_secs(31, 0))];
        let out = merge_histories(&local, &remote, &[], &no_tombstones());
        assert_eq!(
            out.len(),
            2,
            "records a full second apart must not collapse"
        );
    }

    #[test]
    fn tombstone_fires_across_ms_vs_second_divergence() {
        // A tombstone issued against the ms-precise record must still
        // filter its whole-second twin (and vice-versa) — the
        // `tombstone_set` keys and the lookup both truncate to seconds.
        use crate::tombstone::{HistoryTombstone, TombstoneReason, tombstone_set};
        let ms = snapshot("Five", at_secs(30, 123_000_000));
        let truncated = snapshot("Five", at_secs(30, 0));
        // Tombstone the ms-precise record; expect the truncated twin gone.
        let tombstones = vec![HistoryTombstone {
            mtime: ms.times.last_modification_time,
            hash: crate::hash::entry_content_hash(&ms, &[]),
            at: Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
            by: None,
            reason: TombstoneReason::UserDelete,
        }];
        let out = merge_histories(
            std::slice::from_ref(&truncated),
            &[],
            &[],
            &tombstone_set(&tombstones),
        );
        assert!(
            out.is_empty(),
            "tombstone on the ms-precise record must filter its second-truncated twin"
        );
    }

    #[test]
    fn marked_conflict_record_wins_dedup_against_unmarked_twin() {
        // The parked-conflict marker lives in `custom_data`, which
        // `entry_content_hash` excludes — so a marked snapshot and its
        // unmarked content-twin at the same mtime collapse in dedup. The
        // MARKED one must win, else the conflict marker is silently
        // dropped on any peer that merges against an unmarked twin → the
        // conflict surfaces on only one device (Bug, sync-soak-bugs.md).
        use keepass_core::model::CustomDataItem;
        let mtime = at(2026, 1);
        let unmarked = snapshot("item", mtime.clone());
        let mut marked = snapshot("item", mtime);
        marked.custom_data.push(CustomDataItem::new(
            crate::field_conflict::FIELD_CONFLICT_CUSTOM_DATA_KEY.to_string(),
            "{\"at\":\"2026-01-02T00:00:00Z\"}".to_string(),
            None,
        ));
        // Local peer has only the unmarked twin; remote peer has both.
        let out = merge_histories(
            std::slice::from_ref(&unmarked),
            &[unmarked.clone(), marked],
            &[],
            &no_tombstones(),
        );
        assert_eq!(out.len(), 1, "content-twins collapse to a single record");
        assert!(
            out[0]
                .custom_data
                .iter()
                .any(|c| { c.key == crate::field_conflict::FIELD_CONFLICT_CUSTOM_DATA_KEY }),
            "the marked record must win the dedup so the conflict propagates to every peer",
        );
    }

    #[test]
    fn tombstoned_record_present_on_both_sides_is_still_filtered() {
        use crate::hash::entry_content_hash;
        let s = snapshot("drop", at(2026, 1));
        let mut tombstones = TombstoneSet::default();
        tombstones.insert((s.times.last_modification_time, entry_content_hash(&s, &[])));
        let out = merge_histories(
            std::slice::from_ref(&s),
            std::slice::from_ref(&s),
            &[],
            &tombstones,
        );
        assert!(
            out.is_empty(),
            "presence on both sides shouldn't override a tombstone"
        );
    }
}
