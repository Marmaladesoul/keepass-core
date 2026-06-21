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

#[cfg(test)]
mod tests {
    use super::second_resolution;
    use chrono::{TimeZone, Timelike, Utc};

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
