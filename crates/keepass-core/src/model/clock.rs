//! Clock abstraction for vault mutations.
//!
//! Every mutation that stamps a timestamp on an entry, group, or meta
//! routes `now()` through a [`Clock`] held on the [`crate::kdbx::Kdbx`]
//! container. Production callers get [`SystemClock`]; tests swap in
//! [`FixedClock`] (or any other implementation) so assertions on
//! timestamps can be precise, not approximate.
//!
//! The clock is set at unlock time via
//! [`crate::kdbx::Kdbx::<HeaderRead>::unlock_with_clock`] and is not
//! swappable afterwards. A mid-session clock change would let
//! timestamps travel backwards through the same vault, which breaks
//! history ordering.
//!
//! ## Why a trait and not a function pointer
//!
//! The trait is tiny (one method) but stateful implementations are
//! useful — a monotonic counter clock for reproducing ordering bugs,
//! for example, is hard to express as a function pointer without
//! leaking `static mut`.

use chrono::{DateTime, Utc};

/// The source of "now" for all mutation bookkeeping.
///
/// Implementations should be cheap and non-blocking. The mutation API
/// calls [`Self::now`] multiple times per operation (e.g. one stamp
/// per field a mutation touches), so heavy per-call work would show
/// up in profiles.
pub trait Clock: std::fmt::Debug + Send + Sync {
    /// Return the current [`DateTime<Utc>`].
    fn now(&self) -> DateTime<Utc>;
}

/// The clock used by default — reads the host operating system's
/// wall clock via [`Utc::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// A clock that always returns the same instant. Useful in tests for
/// pinning timestamps to a known value so assertions on
/// `entry.times.*` can use `assert_eq!` instead of approximate ranges.
///
/// For tests that need to advance the clock between calls, prefer a
/// `std::cell::Cell<DateTime<Utc>>`-backed type or similar; this one
/// is deliberately immutable.
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub DateTime<Utc>);

impl Clock for FixedClock {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_a_reasonable_instant() {
        let now = SystemClock.now();
        // Sanity: should be >= 2020 and <= 2100 regardless of when the
        // test runs. Exact assertion would be flaky.
        let year = now.format("%Y").to_string().parse::<i32>().unwrap();
        assert!((2020..=2100).contains(&year), "unexpected year: {year}");
    }

    #[test]
    fn fixed_clock_returns_the_same_instant_repeatedly() {
        let t = DateTime::parse_from_rfc3339("2025-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let c = FixedClock(t);
        assert_eq!(c.now(), t);
        assert_eq!(c.now(), t);
    }

    #[test]
    fn clock_trait_is_object_safe() {
        // Compile-time check: trait can be used behind `dyn Clock`.
        let _: Box<dyn Clock> = Box::new(SystemClock);
        let _: Box<dyn Clock> = Box::new(FixedClock(Utc::now()));
    }
}
