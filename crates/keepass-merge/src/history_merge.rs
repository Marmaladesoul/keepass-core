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
//! key collapses those twins (see `the design notes` Bug A). Records
//! at genuinely different seconds stay in distinct groups. Within a
//! group:
//!
//! - All hash-identical → keep one (local's copy when both sides hold
//!   it, so the output keeps local's full-precision mtime).
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
//! A history list is oldest → newest, and its order is the only record
//! of which version came before which: the LCA matcher
//! (`find_common_ancestor`) reads a later rank as a later generation.
//! The merge must therefore keep each side's order.
//!
//! Groups are sorted oldest → newest by (whole-second) mtime. Records
//! with `mtime = None` lead the list (chosen over trailing per #R16): a
//! history record without a timestamp is by definition a past state
//! with broken metadata, not a fresh edit, so the conservative read is
//! "we don't know when, but it's older than anything timed". The
//! choice is pinned by a test so a future refactor can't silently flip
//! it.
//!
//! Within one second the mtime says nothing about order, so the two
//! sides' records are merged the way two ordered sequences are: each
//! side's own order is kept, and a record both sides hold anchors the
//! other side's records around it — a record one side has *before* a
//! shared record lands before it in the output too. Without this, a
//! peer-only snapshot that is an ancestor of a later shared version in
//! the same second (one side's edit, then the merge that took it) was
//! placed after that version, and the matcher then chose the older
//! snapshot as the common ancestor and parked a spurious conflict.
//! Each side's *current* version is the newest member of its lineage,
//! so it anchors too, though it is never emitted as history unless the
//! other side's history holds it (a tombstoned record likewise orders
//! without being emitted): a peer snapshot that is an ancestor
//! of local's current version lands before any local snapshot taken
//! after that version, and vice versa. Records no anchor orders (each
//! held by one side only, at the same point) are genuinely concurrent
//! and go in content-hash order, so the merged order is the same
//! whichever side is `local`.
//!
//! ## Scope
//!
//! `Meta::HistoryMaxItems` enforcement is **not** in this function —
//! `merge_histories` is purely additive and may produce a list
//! longer than the configured cap. `keepass-core`'s save path does
//! the truncation; the merge crate doesn't read or enforce the cap.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use keepass_core::model::{Binary, Entry};

use crate::hash::{ct_eq, ct_lt, entry_content_hash};
use crate::time::second_resolution;

type Mtime = Option<DateTime<Utc>>;
type Hash = [u8; 32];

/// One side of a history merge: its `<History>` list and its current
/// version. Only `history` records are merged into the output; `current`
/// orders them (see the module's Ordering section).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lineage<'a> {
    /// The side's `<History>` records, oldest first, referencing the
    /// merge's shared pool (`merge_histories`' `binaries`).
    pub(crate) history: &'a [Entry],
    /// The side's live version. Its own `history` field is ignored.
    pub(crate) current: &'a Entry,
    /// The pool `current`'s attachments reference — the side's own pool,
    /// so a remote current needs no rebinding (and imports no bytes) just
    /// to be hashed. Its content hash matches a rebound copy's, because
    /// rebinding dedups on the same payload bytes and `protected` flag.
    pub(crate) current_binaries: &'a [Binary],
}

/// Merge two sides' `<History>` lists losslessly **except** for records
/// the caller has explicitly tombstoned. See module docs for the
/// dedup, ordering, and scope contracts.
///
/// `binaries` is the (single) binary pool every *history* record in
/// `local` and `remote` references. Callers must rebind any remote-side
/// history record to local's pool before calling — `apply.rs` does this
/// via `BinaryPoolRemap`. Once attachments are part of
/// `entry_content_hash` (slice B5), the dedup needs the pool to
/// dereference `ref_id`s. Each side's current is hashed against its own
/// [`Lineage::current_binaries`].
///
/// `tombstones` is the unioned `(mtime, hash)` set from both sides'
/// `keys.history_tombstones.v1` lists. Any record matching an entry in
/// this set is left out of the output — that's the mechanism by which
/// user-driven history deletions, quota truncations, and
/// conflict-resolution cleanup all persist across merges. (A tombstoned
/// record still orders the records around it, like a current.) Pass an
/// empty set to recover the prior purely-additive behaviour.
///
/// See `tombstone.rs` for the schema and the
/// [`crate::tombstone::union_tombstones`] / [`crate::tombstone::tombstone_set`]
/// helpers callers use to build the set.
pub(crate) fn merge_histories(
    local: Lineage<'_>,
    remote: Lineage<'_>,
    binaries: &[Binary],
    tombstones: &crate::tombstone::TombstoneSet,
) -> Vec<Entry> {
    // Group each side by mtime truncated to whole-second resolution
    // (`second_resolution`): the engine stamps mtimes in milliseconds
    // but the KDBX round-trip truncates to seconds, so the same
    // snapshot can arrive with a sub-second mtime on one side and a
    // truncated one on the other. Keying at second resolution collapses
    // those ms-vs-second twins so the content-hash dedup recognises them
    // as the same record — the "history bloat" fix for Bug A. The output
    // record keeps its full-precision mtime; only the key is coarsened.
    let local_groups = group_by_second(local, binaries, tombstones);
    let remote_groups = group_by_second(remote, binaries, tombstones);

    // Untimed records lead (`None` < `Some`), then ascending mtime —
    // `Option`'s natural `Ord` does both for us.
    let mut seconds: Vec<Mtime> = local_groups
        .keys()
        .chain(remote_groups.keys())
        .copied()
        .collect();
    seconds.sort();
    seconds.dedup();

    let mut out: Vec<Entry> = Vec::new();
    for second in seconds {
        let local_group = local_groups.get(&second).map_or(&[][..], Vec::as_slice);
        let remote_group = remote_groups.get(&second).map_or(&[][..], Vec::as_slice);
        merge_group(local_group, remote_group, &mut out);
    }
    out
}

/// A record in one side's lineage.
#[derive(Debug, Clone, Copy)]
struct Record<'a> {
    hash: Hash,
    entry: &'a Entry,
    /// Whether this copy may appear in the output: a `<History>` record
    /// that no tombstone covers. A side's current, and a tombstoned
    /// record, only order the others.
    emit: bool,
}

/// One side's lineage (history, then current) grouped by whole-second
/// mtime, each group in the side's own order and deduplicated by
/// content hash (first occurrence kept).
fn group_by_second<'a>(
    side: Lineage<'a>,
    binaries: &[Binary],
    tombstones: &crate::tombstone::TombstoneSet,
) -> BTreeMap<Mtime, Vec<Record<'a>>> {
    let history = side.history.iter().map(|h| (h, binaries, true));
    let current = std::iter::once((side.current, side.current_binaries, false));
    let mut by_second: BTreeMap<Mtime, Vec<Record<'a>>> = BTreeMap::new();
    for (entry, pool, in_history) in history.chain(current) {
        let hash = entry_content_hash(entry, pool);
        let mtime = second_resolution(entry.times.last_modification_time);
        let emit = in_history && !tombstones.contains(&(mtime, hash));
        let group = by_second.entry(mtime).or_default();
        if !holds(group, &hash) {
            group.push(Record { hash, entry, emit });
        }
    }
    by_second
}

/// Merge the two sides' records for one second into `out`, keeping each
/// side's own order (see the module's Ordering section). Every step
/// takes the head of one side:
///
/// - one head is a record the other side holds further on → that
///   record must wait for the other side's records before it, so take
///   the other head;
/// - otherwise (the heads are the same record, or unordered) → take
///   the lower content hash, which is the same choice whichever side is
///   `local`.
///
/// A taken record is emitted if either side's copy may be (local's
/// first, so the output keeps local's full-precision mtime).
fn merge_group(local: &[Record<'_>], remote: &[Record<'_>], out: &mut Vec<Entry>) {
    let mut taken: Vec<Hash> = Vec::new();
    let is_taken = |taken: &[Hash], r: &Record<'_>| taken.iter().any(|h| ct_eq(h, &r.hash));
    let (mut li, mut ri) = (0, 0);
    loop {
        while li < local.len() && is_taken(&taken, &local[li]) {
            li += 1;
        }
        while ri < remote.len() && is_taken(&taken, &remote[ri]) {
            ri += 1;
        }
        let hash = match (local.get(li), remote.get(ri)) {
            (None, None) => break,
            (Some(l), None) => l.hash,
            (None, Some(r)) => r.hash,
            (Some(l), Some(r)) => {
                let local_head_waits = holds(&remote[ri..], &l.hash);
                let remote_head_waits = holds(&local[li..], &r.hash);
                match (local_head_waits, remote_head_waits) {
                    (true, false) => r.hash,
                    (false, true) => l.hash,
                    // Unordered: both heads one-sided, or the two sides
                    // hold the pair in opposite orders. (Equal heads hold
                    // each other, so they land here too, and are one
                    // record whichever hash is taken.)
                    _ if ct_lt(&r.hash, &l.hash) => r.hash,
                    _ => l.hash,
                }
            }
        };
        taken.push(hash);
        let emitted = local
            .iter()
            .chain(remote)
            .find(|r| r.emit && ct_eq(&r.hash, &hash));
        if let Some(record) = emitted {
            out.push(record.entry.clone());
        }
    }
}

/// Does `records` hold a record with content hash `hash`?
fn holds(records: &[Record<'_>], hash: &Hash) -> bool {
    records.iter().any(|r| ct_eq(&r.hash, hash))
}

#[cfg(test)]
mod tests {
    use super::{Lineage, merge_histories};
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

    /// `merge_histories` over two bare history lists, each side's
    /// current version a distinct record in a far-future second, so it
    /// neither anchors nor joins any record under test.
    fn merge(
        local: &[Entry],
        remote: &[Entry],
        binaries: &[keepass_core::model::Binary],
        tombstones: &TombstoneSet,
    ) -> Vec<Entry> {
        let local_current = snapshot("local-current", at(2099, 1));
        let remote_current = snapshot("remote-current", at(2099, 1));
        merge_histories(
            Lineage {
                history: local,
                current: &local_current,
                current_binaries: binaries,
            },
            Lineage {
                history: remote,
                current: &remote_current,
                current_binaries: binaries,
            },
            binaries,
            tombstones,
        )
    }

    /// Tests that exercise the pre-tombstone behaviour use this empty
    /// set — additive merge is recovered by passing it.
    fn no_tombstones() -> TombstoneSet {
        TombstoneSet::default()
    }

    #[test]
    fn empty_inputs_produce_empty_output() {
        assert_eq!(merge(&[], &[], &[], &no_tombstones()).len(), 0);
    }

    #[test]
    fn disjoint_mtimes_interleave_by_sort_order() {
        let local = vec![snapshot("a", at(2026, 1)), snapshot("c", at(2026, 3))];
        let remote = vec![snapshot("b", at(2026, 2))];
        let out = merge(&local, &remote, &[], &no_tombstones());
        let titles: Vec<&str> = out.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["a", "b", "c"]);
    }

    #[test]
    fn identical_record_on_both_sides_is_deduped() {
        let s = snapshot("same", at(2026, 1));
        let out = merge(
            std::slice::from_ref(&s),
            std::slice::from_ref(&s),
            &[],
            &no_tombstones(),
        );
        assert_eq!(out.len(), 1);
    }

    fn titles(out: &[Entry]) -> Vec<&str> {
        out.iter().map(|e| e.title.as_str()).collect()
    }

    #[test]
    fn same_mtime_divergent_content_keeps_both_in_a_side_independent_order() {
        // Two one-sided records in one second are concurrent: neither
        // side's order says which came first. Both are kept, in the same
        // order whichever side is local, so the replicas' histories agree.
        let l = vec![snapshot("L", at(2026, 1))];
        let r = vec![snapshot("R", at(2026, 1))];
        let forward = merge(&l, &r, &[], &no_tombstones());
        let swapped = merge(&r, &l, &[], &no_tombstones());
        assert_eq!(forward.len(), 2);
        assert_eq!(titles(&forward), titles(&swapped));
    }

    #[test]
    fn same_second_peer_ancestor_lands_before_its_shared_descendant() {
        // In one second: the peer edited the base to P, the two sides
        // merged P into M, and local then edited M. Local's history never
        // held P; the peer's holds P before M. The merge must keep P
        // before M — the history order is the only record that M descends
        // from P, and the LCA matcher reads a later rank as a later
        // generation (it would otherwise choose P over M as an ancestor).
        let sec = |title| snapshot(title, at_secs(30, 0));
        let local = vec![sec("base"), sec("M"), sec("L2")];
        let remote = vec![sec("base"), sec("P"), sec("M")];
        let out = merge(&local, &remote, &[], &no_tombstones());
        assert_eq!(titles(&out), ["base", "P", "M", "L2"]);
        let swapped = merge(&remote, &local, &[], &no_tombstones());
        assert_eq!(titles(&swapped), titles(&out));
    }

    #[test]
    fn a_current_version_orders_the_snapshots_before_it() {
        // In one second: local's history holds M (a merge of P) and its
        // current is a later edit; the peer's current IS M, its history
        // holds P. P is an ancestor of the peer's current, so it lands
        // before M — even though M is not in the peer's history.
        let sec = |title| snapshot(title, at_secs(30, 0));
        let local_history = vec![sec("base"), sec("M")];
        let local_current = sec("L2");
        let remote_history = vec![sec("base"), sec("P")];
        let remote_current = sec("M");
        let out = merge_histories(
            Lineage {
                history: &local_history,
                current: &local_current,
                current_binaries: &[],
            },
            Lineage {
                history: &remote_history,
                current: &remote_current,
                current_binaries: &[],
            },
            &[],
            &no_tombstones(),
        );
        assert_eq!(titles(&out), ["base", "P", "M"]);
    }

    #[test]
    fn a_current_version_alone_is_not_emitted_as_history() {
        // A side's live version is history only once the other side's
        // history holds it; on its own it only orders the merge.
        let local_history = vec![snapshot("a", at(2026, 1))];
        let local_current = snapshot("live-local", at(2026, 2));
        let remote_history = vec![snapshot("a", at(2026, 1))];
        let remote_current = snapshot("live-remote", at(2026, 2));
        let out = merge_histories(
            Lineage {
                history: &local_history,
                current: &local_current,
                current_binaries: &[],
            },
            Lineage {
                history: &remote_history,
                current: &remote_current,
                current_binaries: &[],
            },
            &[],
            &no_tombstones(),
        );
        assert_eq!(titles(&out), ["a"]);
    }

    #[test]
    fn untimed_records_lead() {
        // Per #R16: history records without an mtime have broken
        // metadata, not a fresh-entry default, so they belong at the
        // "we don't know when, but it's older" end. Pinned by this
        // test so a future refactor can't silently flip the choice.
        // (The two untimed records are one-sided, so concurrent: their
        // relative order is content-hash order, checked loosely here.)
        let mut untimed_local = Entry::empty(EntryId(Uuid::nil()));
        untimed_local.title = "UL".into();
        let mut untimed_remote = Entry::empty(EntryId(Uuid::nil()));
        untimed_remote.title = "UR".into();
        let timed = snapshot("T", at(2026, 1));
        let out = merge(
            &[untimed_local, timed.clone()],
            &[untimed_remote],
            &[],
            &no_tombstones(),
        );
        let titles = titles(&out);
        assert_eq!(titles.len(), 3);
        assert!(titles[..2].contains(&"UL") && titles[..2].contains(&"UR"));
        assert_eq!(titles[2], "T");
    }

    #[test]
    fn merging_is_idempotent() {
        let a = vec![snapshot("a", at(2026, 1)), snapshot("b", at(2026, 2))];
        let b = vec![snapshot("b", at(2026, 2)), snapshot("c", at(2026, 3))];
        let once = merge(&a, &b, &[], &no_tombstones());
        let twice = merge(&once, &b, &[], &no_tombstones());
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
        let out = merge(&[a], &[b], &[], &no_tombstones());
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
        let out = merge(&[a], &[b], &[], &tombstones);
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
        let out = merge(&local, &remote, &[], &no_tombstones());
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
        let out = merge(&local, &remote, &[], &no_tombstones());
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
        let out = merge(
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
    fn tombstoned_record_present_on_both_sides_is_still_filtered() {
        use crate::hash::entry_content_hash;
        let s = snapshot("drop", at(2026, 1));
        let mut tombstones = TombstoneSet::default();
        tombstones.insert((s.times.last_modification_time, entry_content_hash(&s, &[])));
        let out = merge(
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
