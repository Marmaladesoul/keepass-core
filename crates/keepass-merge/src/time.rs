//! Timestamp normalisation for history dedup.
//!
//! keys-engine stamps entry mtimes in **milliseconds**
//! (`keys-engine::mutations::now_ms`), but the KDBX on-disk time format
//! is **whole-second**. So after a project→sync→ingest round-trip the
//! *same* snapshot can carry a sub-second mtime on the editing side and
//! a truncated whole-second mtime on the side that re-read it from disk.
//!
//! The history-dedup paths key on `last_modification_time`, so without
//! normalisation those ms-vs-second twins land in different buckets and
//! both survive — the "history bloat" half of Bug A
//! (`internal design notes`).
//!
//! [`second_resolution`] truncates an mtime to whole seconds so the
//! twins collapse, while records at genuinely *different* seconds stay
//! distinct. We chose second-resolution over content-only dedup
//! (which would also collapse a legitimate same-content revert) as the
//! safer match to the KDBX format. Every dedup key and tombstone-set
//! key derived from an mtime must pass through this function so the
//! build side and the lookup side agree on resolution.

use chrono::{DateTime, SubsecRound, Utc};

/// Truncate an mtime to whole-second resolution for history-dedup
/// keying. `None` (untimed history records) passes through unchanged.
pub(crate) fn second_resolution(mtime: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    mtime.map(|t| t.trunc_subsecs(0))
}

// ---------------------------------------------------------------------------
// LWW timestamp comparators
//
// The merge paths make the same handful of last-writer-wins timestamp
// decisions over and over. Historically each site inlined its own
// `match (a, b)` and distinguished itself from its twins only by a
// doc-comment — which is precisely how a comparator's *code* can drift
// away from its *documented* policy without anyone noticing. These named
// comparators pin each policy's exact truth table (see the per-function
// tables below) and lock it under a unit test, so the intent is enforced
// by the type-checker and CI rather than by prose. Every LWW timestamp
// site routes through one of these.
// ---------------------------------------------------------------------------

/// Group A — plain last-writer-wins: does `challenger` beat the
/// `incumbent`?
///
/// A concrete timestamp beats an absent one (the challenger positively
/// recorded a change; an absent challenger has no signal to swap on),
/// and among two concrete timestamps the strictly-later one wins. Ties
/// (equal timestamps) keep the incumbent.
///
/// Truth table (`incumbent` / `challenger` → result):
/// - `Some(i)` / `Some(c)` → `c > i` (tie ⇒ `false`)
/// - `None`    / `Some(_)` → `true`
/// - `Some(_)` / `None`    → `false`
/// - `None`    / `None`    → `false`
pub(crate) fn later_wins(
    incumbent: Option<DateTime<Utc>>,
    challenger: Option<DateTime<Utc>>,
) -> bool {
    match (incumbent, challenger) {
        (Some(i), Some(c)) => c > i,
        (None, Some(_)) => true,
        (Some(_) | None, None) => false,
    }
}

/// Group B — advancing (grow-only) merge of two optional timestamps:
/// the later of the two, but never regressing to `None`.
///
/// Used where a timestamp only ever moves forward (mtime, access time,
/// location-changed): any concrete value survives, and two concrete
/// values collapse to their `max`.
///
/// Truth table (`a` / `b` → result):
/// - `Some(x)` / `Some(y)` → `Some(max(x, y))`
/// - `Some(x)` / `None`    → `Some(x)`
/// - `None`    / `Some(y)` → `Some(y)`
/// - `None`    / `None`    → `None`
pub(crate) fn advance_only_max(
    a: Option<DateTime<Utc>>,
    b: Option<DateTime<Utc>>,
) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x @ Some(_), None) | (None, x @ Some(_)) => x,
        (None, None) => None,
    }
}

/// Group C1 — conservative delete-vs-edit arbitration: did an edit
/// (`mtime`) land after a tombstone (`cutoff`)?
///
/// Only when *both* timestamps are concrete do we compare them; **any**
/// missing timestamp returns `true` ("edit wins"). The conservative
/// posture is deliberate: with no provenance we surface a conflict / keep
/// the entry rather than silently dropping a possibly-edited record. A
/// false-positive conflict is strictly less harmful than a false-negative
/// silent delete.
///
/// Truth table (`mtime` / `cutoff` → result):
/// - `Some(m)` / `Some(c)` → `m > c` (tie ⇒ `false`)
/// - `Some(_)` / `None`    → `true`
/// - `None`    / `Some(_)` → `true`
/// - `None`    / `None`    → `true`
pub(crate) fn conservative_edit_wins(
    mtime: Option<DateTime<Utc>>,
    cutoff: Option<DateTime<Utc>>,
) -> bool {
    match (mtime, cutoff) {
        (Some(m), Some(c)) => m > c,
        _ => true,
    }
}

/// Group C3 — strict "edited after a *known* cutoff": is `mtime`
/// strictly later than a **concrete** `cutoff`?
///
/// Distinct from [`conservative_edit_wins`]: here the cutoff is a
/// concrete [`DateTime`] (a tombstone / resolution timestamp we already
/// hold), not an `Option`, so the missing-cutoff cell doesn't exist.
/// A missing `mtime` loses — with no edit provenance the cutoff
/// (tombstone / resolution) stands.
///
/// Truth table (`mtime` → result, `cutoff` always concrete):
/// - `Some(m)` → `m > cutoff` (tie ⇒ `false`)
/// - `None`    → `false`
pub(crate) fn strictly_after(mtime: Option<DateTime<Utc>>, cutoff: DateTime<Utc>) -> bool {
    mtime.is_some_and(|m| m > cutoff)
}

#[cfg(test)]
mod tests {
    use super::{
        advance_only_max, conservative_edit_wins, later_wins, second_resolution, strictly_after,
    };
    use chrono::{DateTime, TimeZone, Timelike, Utc};

    /// Two distinct, ordered timestamps for cell-by-cell truth-table
    /// assertions: `EARLY < LATE`.
    fn early() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 5).unwrap()
    }
    fn late() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 6).unwrap()
    }

    #[test]
    fn later_wins_truth_table() {
        // Some/Some: strictly-later challenger wins; earlier and tie lose.
        assert!(later_wins(Some(early()), Some(late())));
        assert!(!later_wins(Some(late()), Some(early())));
        assert!(!later_wins(Some(early()), Some(early()))); // tie ⇒ incumbent
        // None/Some: concrete challenger wins.
        assert!(later_wins(None, Some(early())));
        // Some/None: absent challenger loses.
        assert!(!later_wins(Some(early()), None));
        // None/None: nothing to swap on.
        assert!(!later_wins(None, None));
    }

    #[test]
    fn advance_only_max_truth_table() {
        // Some/Some ⇒ the later of the two, order-independent.
        assert_eq!(advance_only_max(Some(early()), Some(late())), Some(late()));
        assert_eq!(advance_only_max(Some(late()), Some(early())), Some(late()));
        assert_eq!(
            advance_only_max(Some(early()), Some(early())),
            Some(early())
        );
        // Some/None and None/Some ⇒ the concrete value survives.
        assert_eq!(advance_only_max(Some(early()), None), Some(early()));
        assert_eq!(advance_only_max(None, Some(early())), Some(early()));
        // None/None ⇒ None.
        assert_eq!(advance_only_max(None, None), None);
    }

    #[test]
    fn conservative_edit_wins_truth_table() {
        // Some/Some: strict mtime > cutoff; earlier and tie lose.
        assert!(conservative_edit_wins(Some(late()), Some(early())));
        assert!(!conservative_edit_wins(Some(early()), Some(late())));
        assert!(!conservative_edit_wins(Some(early()), Some(early()))); // tie ⇒ false
        // ANY missing timestamp ⇒ conservative keep (true).
        assert!(conservative_edit_wins(Some(early()), None));
        assert!(conservative_edit_wins(None, Some(early())));
        assert!(conservative_edit_wins(None, None));
    }

    #[test]
    fn strictly_after_truth_table() {
        // Concrete cutoff; only a strictly-later mtime beats it.
        assert!(strictly_after(Some(late()), early()));
        assert!(!strictly_after(Some(early()), late()));
        assert!(!strictly_after(Some(early()), early())); // tie ⇒ false
        // Missing mtime ⇒ cutoff stands.
        assert!(!strictly_after(None, early()));
    }

    #[test]
    fn truncates_subsecond_to_whole_second() {
        let ms = Utc
            .with_ymd_and_hms(2026, 6, 4, 0, 0, 5)
            .unwrap()
            .with_nanosecond(123_000_000)
            .unwrap();
        let truncated = Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 5).unwrap();
        assert_eq!(second_resolution(Some(ms)), Some(truncated));
    }

    #[test]
    fn whole_second_is_unchanged() {
        let t = Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 5).unwrap();
        assert_eq!(second_resolution(Some(t)), Some(t));
    }

    #[test]
    fn distinct_seconds_stay_distinct() {
        let a = Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 5).unwrap();
        let b = Utc.with_ymd_and_hms(2026, 6, 4, 0, 0, 6).unwrap();
        assert_ne!(second_resolution(Some(a)), second_resolution(Some(b)));
    }

    #[test]
    fn none_passes_through() {
        assert_eq!(second_resolution(None), None);
    }
}
