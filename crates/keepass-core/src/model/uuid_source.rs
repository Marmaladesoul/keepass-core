//! UUID source for fresh-vault creation.
//!
//! The root group of a fresh vault (and any group/entry the model layer
//! mints during creation) draws its id from a [`UuidSource`], the same
//! shape as the injected [`crate::model::Clock`]. Production callers get
//! [`RandomUuids`] (`Uuid::new_v4`); tests and the keyhole fuzzer inject
//! [`SeededUuids`] so a freshly-created vault is byte-reproducible.
//!
//! This mirrors `keys-engine`'s own `UuidSource` (which covers every id
//! minted *after* a vault is open). keepass-core sits below keys-engine,
//! so it can't borrow that trait; the two are deliberately parallel, just
//! as each layer carries its own [`crate::model::Clock`]. The seeded
//! implementation uses
//! the identical `from_u64_pair(seed, counter)` scheme, so a vault created
//! with seed `S` and then mutated by an engine seeded with `S` draws from
//! one coherent, replayable id space.
//!
//! ## Why a counter, not a seeded v4 RNG
//!
//! Creation ids only need to be (a) stable for a given `(seed, n)` and
//! (b) unique within a run. [`Uuid::from_u64_pair`] of `(seed, counter)`
//! gives both directly, with the seed in the high half so two devices
//! seeded differently never mint the same id. The version/variant bits are
//! not v4 — fine: KDBX entity ids are arbitrary 128-bit values and nothing
//! inspects the version nibble.

use std::sync::atomic::{AtomicU64, Ordering};

use uuid::Uuid;

/// The source of fresh ids for vault creation.
///
/// Implementations must be cheap and thread-safe; creation calls
/// [`Self::next_uuid`] a small fixed number of times (the root group, and
/// — via the caller — the eager recycle bin).
pub trait UuidSource: std::fmt::Debug + Send + Sync {
    /// Return a fresh id. Must be unique within the lifetime of this
    /// source (a duplicate would alias two distinct entities).
    fn next_uuid(&self) -> Uuid;
}

/// Production source — a fresh random v4 UUID per call.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomUuids;

impl UuidSource for RandomUuids {
    fn next_uuid(&self) -> Uuid {
        Uuid::new_v4()
    }
}

/// Deterministic source — `Uuid::from_u64_pair(seed, counter)` with a
/// per-source monotonic counter. Reproducible across runs for a given
/// `seed`, and collision-free both within a source (the counter) and
/// across sources with distinct seeds (the high half).
#[derive(Debug)]
pub struct SeededUuids {
    seed: u64,
    counter: AtomicU64,
}

impl SeededUuids {
    /// Create a deterministic source rooted at `seed`. Distinct seeds
    /// never collide; use one seed per device in a multi-device test.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            counter: AtomicU64::new(0),
        }
    }
}

impl UuidSource for SeededUuids {
    fn next_uuid(&self) -> Uuid {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        Uuid::from_u64_pair(self.seed, n)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_is_reproducible_and_unique() {
        let a = SeededUuids::new(7);
        let first: Vec<Uuid> = (0..5).map(|_| a.next_uuid()).collect();
        // A fresh source with the same seed reproduces the sequence.
        let b = SeededUuids::new(7);
        let second: Vec<Uuid> = (0..5).map(|_| b.next_uuid()).collect();
        assert_eq!(first, second);
        // All distinct within the run.
        let mut sorted = first.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), first.len());
    }

    #[test]
    fn distinct_seeds_do_not_collide() {
        let a = SeededUuids::new(1);
        let b = SeededUuids::new(2);
        // Same counter position, different seed → different id.
        assert_ne!(a.next_uuid(), b.next_uuid());
    }

    #[test]
    fn random_source_is_distinct() {
        let r = RandomUuids;
        assert_ne!(r.next_uuid(), r.next_uuid());
    }

    #[test]
    fn uuid_source_trait_is_object_safe() {
        let _: Box<dyn UuidSource> = Box::new(RandomUuids);
        let _: Box<dyn UuidSource> = Box::new(SeededUuids::new(1));
    }
}
