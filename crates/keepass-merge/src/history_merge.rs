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
//! (mtime). Within a group:
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

type Mtime = Option<DateTime<Utc>>;
type Bucket<'a> = Vec<([u8; 32], &'a Entry)>;

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
    let mut by_mtime: HashMap<Mtime, Bucket<'_>> = HashMap::new();
    for snap in local.iter().chain(remote.iter()) {
        let hash = entry_content_hash(snap, binaries);
        let mtime = snap.times.last_modification_time;
        if tombstones.contains(&(mtime, hash)) {
            continue;
        }
        let bucket = by_mtime.entry(mtime).or_default();
        if !bucket.iter().any(|(h, _)| ct_eq(h, &hash)) {
            bucket.push((hash, snap));
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
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{CustomField, Entry, EntryId, Timestamps};
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
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
