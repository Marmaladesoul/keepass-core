//! Entry-history snapshot policy and budget truncation.

use crate::model::{Entry, HistoryPolicy};

/// Decide whether a mutation that carries `policy` should push a
/// pre-mutation snapshot given the live entry's current `history` and
/// the current wall-clock `now`.
///
/// Shared by [`Kdbx::edit_entry`](crate::kdbx::Kdbx::edit_entry) and
/// [`Kdbx::restore_entry_from_history`](crate::kdbx::Kdbx::restore_entry_from_history) — both need the same
/// SnapshotIfOlderThan semantics, and extracting the helper keeps the
/// two call sites from drifting.
pub(crate) fn should_snapshot_now(
    policy: HistoryPolicy,
    history: &[Entry],
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match policy {
        HistoryPolicy::NoSnapshot => false,
        HistoryPolicy::Snapshot => true,
        HistoryPolicy::SnapshotIfOlderThan(window) => match history.last() {
            None => true,
            Some(last) => {
                let threshold = now - window;
                // Absent timestamp → treat as "ancient" and snapshot.
                last.times
                    .last_modification_time
                    .is_none_or(|t| t < threshold)
            }
        },
    }
}

/// How many records to drop from the front of `history` to satisfy
/// the `max_items` (negative = unlimited) and `max_size` (negative =
/// unlimited) budgets. Oldest records — index 0 first — go first.
/// The item-count budget is applied first, then the size budget.
///
/// `max_items` and `max_size` are the KDBX `Meta` budgets
/// (`history_max_items` / `history_max_size`) and can be passed
/// straight through; the negative sentinel is the format's own
/// encoding of "unlimited", not an invention of this crate.
///
/// Call this when you need to know *which* records a save-time
/// truncation will drop **before** it drops them — to record, react
/// to, or veto those deletions. Saving already applies these budgets
/// on its own; you do not need to call this to get truncation.
///
/// `max_size` is a soft budget measured against an approximation of
/// each entry's serialised XML size: the byte length of the five
/// canonical string fields plus custom fields and tags, plus a
/// 200-byte constant for wrapper markup. Good enough for "don't let
/// a megabyte of history accumulate"; not byte-exact. **The
/// approximation may be refined in any release** — treat the return
/// value as a budget decision, not a stable count to assert against.
///
/// # Why this is public
///
/// This is the single source of truth for *which* history records a
/// budget drops, and it is deliberately exported because more than
/// one layer has to agree on that answer. The save path here drops
/// the records outright. A layer that syncs a vault with peers has a
/// harder job: it must leave a marker behind for each dropped record
/// (a *tombstone*), or a peer that hasn't truncated yet will send
/// the record back on the next merge and resurrect it. Those two
/// sets must be identical — any record the save path drops but the
/// sync layer did not tombstone comes back. Sharing this function
/// makes that agreement structural rather than a matter of keeping
/// two copies of the heuristic aligned by inspection.
///
/// (`keepass-merge`'s `prune_history_with_tombstones` is the
/// in-workspace consumer that does exactly this.)
#[must_use]
pub fn compute_history_drop_count(history: &[Entry], max_items: i32, max_size: i64) -> usize {
    let mut drop_count: usize = 0;

    // Item-count budget first, since it's cheapest and common.
    if max_items >= 0 {
        let cap = usize::try_from(max_items).unwrap_or(usize::MAX);
        if history.len() > cap {
            drop_count = history.len() - cap;
        }
    }

    // Size budget, if one is declared. Compute the prefix length to
    // drop in one walk — dropping one record at a time and re-summing
    // is O(N²) on the worst-case path.
    if max_size >= 0 {
        let cap = u64::try_from(max_size).unwrap_or(u64::MAX);
        // Saturating, to match `approx_entry_size`'s own discipline:
        // a plain `sum()` would panic in debug on a total past `u64`.
        // Unreachable with real string lengths, but this function is
        // the canonical copy — it shouldn't carry a panic edge at all.
        let mut total: u64 = history
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(approx_entry_size(e)));
        // Discount the records the item-count pass already claimed.
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

/// Truncate `history` per `max_items` / `max_size`, dropping the
/// records [`compute_history_drop_count`] selects.
pub(crate) fn truncate_history(history: &mut Vec<Entry>, max_items: i32, max_size: i64) {
    let drop_count = compute_history_drop_count(history, max_items, max_size);
    if drop_count > 0 {
        history.drain(0..drop_count);
    }
}

/// Approximate the byte footprint an entry takes up when serialised
/// inside a `<History>` block. Counts the user-visible string bytes
/// plus a constant for XML wrapping overhead.
fn approx_entry_size(e: &Entry) -> u64 {
    let mut n: u64 = 200; // wrapper markup for <Entry>...<History>...</History></Entry>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EntryId;

    /// History of `count` records, each `approx_entry_size` = 200
    /// (wrapper) + 2 (a two-byte title) = 202 bytes. The per-record
    /// arithmetic the size tests rely on only holds while
    /// `count <= 10`; past that the titles grow a third byte.
    fn sized_history(count: usize) -> Vec<Entry> {
        assert!(count <= 10, "sized_history: records stop being 202 bytes");
        (0..count)
            .map(|i| {
                let mut e = Entry::empty(EntryId(uuid::Uuid::nil()));
                e.title = format!("v{i}");
                e
            })
            .collect()
    }

    #[test]
    fn drop_count_is_zero_when_both_budgets_are_unlimited() {
        assert_eq!(compute_history_drop_count(&sized_history(5), -1, -1), 0);
        // Any negative means unlimited, not just -1 — the extremes
        // pin the sentinel contract against a future signature change.
        assert_eq!(
            compute_history_drop_count(&sized_history(5), i32::MIN, i64::MIN),
            0
        );
    }

    #[test]
    fn drop_count_honours_item_budget() {
        assert_eq!(compute_history_drop_count(&sized_history(5), 2, -1), 3);
        assert_eq!(compute_history_drop_count(&sized_history(5), 5, -1), 0);
        assert_eq!(compute_history_drop_count(&sized_history(5), 0, -1), 5);
    }

    #[test]
    fn drop_count_honours_size_budget() {
        // 5 × 202 = 1010 bytes; a 500-byte cap leaves 2 (404 bytes).
        assert_eq!(compute_history_drop_count(&sized_history(5), -1, 500), 3);
        assert_eq!(compute_history_drop_count(&sized_history(5), -1, 1010), 0);
    }

    /// The interesting case: both budgets active. The size pass must
    /// measure only the records the item pass leaves behind, and must
    /// never un-drop what the item pass already claimed.
    #[test]
    fn drop_count_applies_both_budgets_together() {
        // Item cap 4 drops 1, leaving 4 × 202 = 808 bytes. A 500-byte
        // cap then drops 2 more (leaving 404) → 3 total.
        assert_eq!(compute_history_drop_count(&sized_history(5), 4, 500), 3);
        // The item budget alone already satisfies a slack size budget:
        // the size pass must not widen the drop beyond it.
        assert_eq!(compute_history_drop_count(&sized_history(5), 2, 5000), 3);
    }

    #[test]
    fn drop_count_never_exceeds_history_length() {
        assert_eq!(compute_history_drop_count(&sized_history(3), -1, 0), 3);
        assert_eq!(compute_history_drop_count(&[], 0, 0), 0);
    }
}
