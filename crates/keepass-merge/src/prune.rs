//! Tombstone-aware history pruning.
//!
//! Bridge between `keepass-core`'s `Meta::history_max_items` /
//! `Meta::history_max_size` budgets and this crate's tombstone
//! mechanism: when a record is dropped to fit a budget, leave a
//! tombstone behind so the deletion survives subsequent merges with
//! peers that hadn't truncated yet.
//!
//! Why this lives here rather than in `keepass-core`: writing the
//! tombstone JSON requires `serde_json`, which `keepass-core`
//! deliberately keeps out of the library proper (see its
//! `Cargo.toml` comment — "the library itself stays JSON-free").
//! Callers who want save-path truncation to write tombstones invoke
//! [`prune_history_with_tombstones`] *before* save; the save path's
//! own `truncate_history` then becomes a no-op because history is
//! already within budget.

use chrono::{DateTime, Utc};
use keepass_core::model::{Binary, Entry};

use crate::hash::entry_content_hash;
use crate::tombstone::{
    HistoryTombstone, TombstoneError, TombstoneReason, parse_tombstones, union_history_tombstones,
    write_tombstones_to_custom_data,
};

/// Apply `max_items` / `max_size` budgets to `entry.history`,
/// writing a [`HistoryTombstone`] for every dropped record so the
/// deletion survives subsequent merges with peers that hadn't yet
/// truncated.
///
/// Semantics match `keepass-core`'s `truncate_history` (defined in
/// `kdbx.rs`):
///
/// - `max_items < 0` → no item-count cap.
/// - `max_size < 0` → no size-cap.
/// - Oldest records (index 0) are dropped first.
/// - Item-count budget applied first, then size budget.
/// - Size is measured by the same approximation `keepass-core` uses
///   (the string-fields sum + a 200-byte wrapper constant).
///
/// Returns the number of records dropped (and tombstoned). Returns
/// `Ok(0)` when no records exceed the budgets — idempotent in
/// steady state.
///
/// # Errors
///
/// Returns [`TombstoneError::Parse`] only if the entry already has
/// a malformed `keys.history_tombstones.v1` value. A fresh entry
/// never errors.
pub fn prune_history_with_tombstones(
    entry: &mut Entry,
    max_items: i32,
    max_size: i64,
    binaries: &[Binary],
    reason: TombstoneReason,
    by: Option<[u8; 32]>,
    now: DateTime<Utc>,
) -> Result<usize, TombstoneError> {
    let drop_count = compute_drop_count(&entry.history, max_items, max_size);
    if drop_count == 0 {
        return Ok(0);
    }

    // Build tombstones for the records being dropped, before we
    // remove them from the history vector.
    let new_tombstones: Vec<HistoryTombstone> = entry.history[..drop_count]
        .iter()
        .map(|h| HistoryTombstone {
            mtime: h.times.last_modification_time,
            hash: entry_content_hash(h, binaries),
            at: now,
            by,
            reason,
        })
        .collect();

    // Merge with whatever tombstones the entry already carries.
    let existing = parse_tombstones(&entry.custom_data)?;
    let combined = union_history_tombstones(&existing, &new_tombstones);
    write_tombstones_to_custom_data(&mut entry.custom_data, &combined, Some(now));

    entry.history.drain(0..drop_count);
    Ok(drop_count)
}

/// How many records to drop from the front of `history` to satisfy
/// the two budgets. Mirrors `keepass-core::kdbx::truncate_history`
/// closely enough that we can keep them in sync by inspection.
fn compute_drop_count(history: &[Entry], max_items: i32, max_size: i64) -> usize {
    let mut drop_count: usize = 0;

    if max_items >= 0 {
        let cap = usize::try_from(max_items).unwrap_or(usize::MAX);
        if history.len() > cap {
            drop_count = history.len() - cap;
        }
    }

    if max_size >= 0 {
        let cap = u64::try_from(max_size).unwrap_or(u64::MAX);
        let mut total: u64 = history.iter().map(approx_entry_size).sum();
        // Account for the items already to-be-dropped by the
        // max_items pass.
        for h in &history[..drop_count] {
            total = total.saturating_sub(approx_entry_size(h));
        }
        while total > cap && drop_count < history.len() {
            total = total.saturating_sub(approx_entry_size(&history[drop_count]));
            drop_count += 1;
        }
    }

    drop_count
}

/// Approximate the byte footprint an entry takes up when serialised
/// inside a `<History>` block.
///
/// **Mirror** of `keepass-core::kdbx::approx_entry_size`. Kept here
/// rather than `pub`-exposed from keepass-core because (a) it's a
/// few lines, (b) the algorithm is stable, (c) duplicating avoids
/// growing keepass-core's public surface for an internal helper.
/// If the keepass-core version ever changes the heuristic, this
/// function should be updated to match.
fn approx_entry_size(e: &Entry) -> u64 {
    let mut n: u64 = 200;
    n = n.saturating_add(e.title.len() as u64);
    n = n.saturating_add(e.username.len() as u64);
    n = n.saturating_add(e.password.len() as u64);
    n = n.saturating_add(e.url.len() as u64);
    n = n.saturating_add(e.notes.len() as u64);
    for cf in &e.custom_fields {
        n = n.saturating_add(cf.key.len() as u64);
        n = n.saturating_add(cf.value.len() as u64);
    }
    for t in &e.tags {
        n = n.saturating_add(t.len() as u64);
    }
    n
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use keepass_core::model::{EntryId, Timestamps};
    use uuid::Uuid;

    fn at(day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn entry_with_history(history_count: usize) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::nil()));
        e.title = "current".into();
        e.times = at(31);
        for i in 0..history_count {
            let mut snap = Entry::empty(EntryId(Uuid::nil()));
            snap.title = format!("v{i}");
            snap.times = at(u32::try_from(i).unwrap() + 1);
            e.history.push(snap);
        }
        e
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 24, 0, 0, 0).unwrap()
    }

    #[test]
    fn no_budget_means_no_pruning() {
        let mut e = entry_with_history(5);
        let pruned = prune_history_with_tombstones(
            &mut e,
            -1,
            -1,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(pruned, 0);
        assert_eq!(e.history.len(), 5);
    }

    #[test]
    fn under_budget_is_idempotent_noop() {
        let mut e = entry_with_history(3);
        let first = prune_history_with_tombstones(
            &mut e,
            10,
            -1,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        let second = prune_history_with_tombstones(
            &mut e,
            10,
            -1,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(first, 0);
        assert_eq!(second, 0);
        assert_eq!(e.history.len(), 3);
        assert!(parse_tombstones(&e.custom_data).unwrap().is_empty());
    }

    #[test]
    fn max_items_drops_oldest_first() {
        let mut e = entry_with_history(5);
        let pruned = prune_history_with_tombstones(
            &mut e,
            2,
            -1,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(e.history.len(), 2);
        let surviving_titles: Vec<&str> = e.history.iter().map(|h| h.title.as_str()).collect();
        assert_eq!(surviving_titles, ["v3", "v4"]);
        // Three tombstones for the three dropped records.
        let ts = parse_tombstones(&e.custom_data).unwrap();
        assert_eq!(ts.len(), 3);
        assert!(ts.iter().all(|t| t.reason == TombstoneReason::QuotaTrim));
    }

    #[test]
    fn prune_is_idempotent_after_oversize_call() {
        let mut e = entry_with_history(5);
        prune_history_with_tombstones(&mut e, 2, -1, &[], TombstoneReason::QuotaTrim, None, now())
            .unwrap();
        let again = prune_history_with_tombstones(
            &mut e,
            2,
            -1,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(again, 0);
        // Tombstone list should still be 3 — re-running with the same
        // budget doesn't double up.
        let ts = parse_tombstones(&e.custom_data).unwrap();
        assert_eq!(ts.len(), 3);
    }

    #[test]
    fn dropping_zero_records_writes_no_tombstone_key() {
        let mut e = entry_with_history(3);
        prune_history_with_tombstones(&mut e, 10, -1, &[], TombstoneReason::QuotaTrim, None, now())
            .unwrap();
        assert!(
            !e.custom_data
                .iter()
                .any(|cd| cd.key == crate::tombstone::TOMBSTONE_CUSTOM_DATA_KEY),
            "no-op prune must not write a tombstone custom_data key"
        );
    }

    #[test]
    fn max_size_only_drops_oldest_until_within_budget() {
        // Each entry's `approx_entry_size`: 200 (wrapper) + 2 (title
        // "vN") = 202 bytes. 5 entries → 1010 bytes total. A cap of
        // 500 bytes should drop the 3 oldest (leaving 2 × 202 = 404).
        let mut e = entry_with_history(5);
        let pruned = prune_history_with_tombstones(
            &mut e,
            -1,
            500,
            &[],
            TombstoneReason::QuotaTrim,
            None,
            now(),
        )
        .unwrap();
        assert_eq!(pruned, 3);
        assert_eq!(e.history.len(), 2);
    }
}
