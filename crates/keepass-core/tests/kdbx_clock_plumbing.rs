//! Plumbing test for the mutation-API clock field on
//! [`Kdbx::<Unlocked>`].
//!
//! This slice adds `Clock` + `SystemClock` + `FixedClock` and an
//! `unlock_with_clock` entry point alongside the existing `unlock`.
//! No behaviour changes yet — mutations land in follow-up slices —
//! so the test just confirms:
//!
//! 1. `unlock` still produces an `Unlocked` with a usable clock
//!    (defaults to `SystemClock`, returns a plausible "now").
//! 2. `unlock_with_clock` threads a caller-supplied clock through,
//!    and `kdbx.clock().now()` returns exactly that instant.
//! 3. The existing round-trip `unlock → save_to_bytes → open → unlock`
//!    is unaffected by the new field.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::FixedClock;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn kdbx4_basic() -> PathBuf {
    fixtures_root().join("kdbxweb/kdbx4-basic.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let sidecar_path = path.with_extension("json");
    let text = fs::read_to_string(sidecar_path).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

#[test]
fn default_unlock_sets_a_system_clock_that_returns_a_plausible_now() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    // SystemClock.now() is approximately the real wall clock.
    let before = Utc::now();
    let clock_now = kdbx.clock().now();
    let after = Utc::now();
    assert!(
        clock_now >= before && clock_now <= after,
        "default clock should be the system clock, got {clock_now} outside [{before}, {after}]"
    );
}

#[test]
fn unlock_with_clock_threads_through_caller_supplied_instant() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let pinned: DateTime<Utc> = "2025-07-04T12:34:56Z".parse().unwrap();
    let kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(pinned)))
        .unwrap();

    assert_eq!(kdbx.clock().now(), pinned);
    // Repeat call should be stable.
    assert_eq!(kdbx.clock().now(), pinned);
}

#[test]
fn existing_round_trip_still_green_after_clock_plumbing() {
    // Regression guard: the Unlocked struct gained a `clock` field in
    // this slice. The existing save-to-bytes pipeline touches every
    // other field on Unlocked; make sure the new one didn't shake
    // anything loose.
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let unlocked = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let vault_before = unlocked.vault().clone();

    let bytes = unlocked.save_to_bytes().unwrap();
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    // Subset check: same generator + same entry count is plenty to
    // prove save_to_bytes didn't regress.
    assert_eq!(vault_before.meta.generator, reopened.vault().meta.generator);
    assert_eq!(
        vault_before.total_entries(),
        reopened.vault().total_entries()
    );
}
