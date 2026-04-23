//! Slice 9 — `Kdbx::<Unlocked>::rekey(&CompositeKey)`.
//!
//! Per MUTATION.md §"Slicing plan" slice 9. Rotates the master seed,
//! the encryption IV, and the KDF salt/seed before re-deriving the
//! transformed key against the new composite key. Stamps
//! `Meta::master_key_changed` and `Meta::settings_changed` from the
//! injected clock; does not touch entries.
//!
//! The integrity check is the load-bearing assertion: after `rekey`
//! and `save_to_bytes`, opening the same bytes with the OLD key
//! must fail (as `Error::Crypto`, per the §4.8.7 error-collapse
//! discipline). If the rekey silently no-op'd, the OLD key would
//! still unlock the file and that assertion would catch it.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::Error;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::FixedClock;
use std::fs;
use std::path::{Path, PathBuf};

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
    let sidecar = path.with_extension("json");
    let text = fs::read_to_string(sidecar).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

#[test]
fn rekey_rotates_seeds_so_old_key_no_longer_unlocks_the_saved_bytes() {
    let path = kdbx4_basic();
    let old_password = password_from_sidecar(&path);
    let old_key = CompositeKey::from_password(old_password.as_bytes());
    let new_key = CompositeKey::from_password(b"a-new-master-key-XYZ");
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&old_key, Box::new(FixedClock(at)))
        .unwrap();

    let entries_before: Vec<(String, String)> = kdbx
        .vault()
        .iter_entries()
        .map(|e| (e.title.clone(), e.password.clone()))
        .collect();
    assert!(
        !entries_before.is_empty(),
        "fixture must carry at least one entry"
    );

    kdbx.rekey(&new_key).unwrap();

    // Bookkeeping stamped from the injected clock.
    assert_eq!(kdbx.vault().meta.master_key_changed, Some(at));
    assert_eq!(kdbx.vault().meta.settings_changed, Some(at));

    let saved = kdbx.save_to_bytes().unwrap();

    // Leg 1: the new key opens the saved bytes and the entries
    // round-trip unchanged — rekey must not have touched them.
    let reopened = Kdbx::<Sealed>::open_from_bytes(saved.clone())
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&new_key)
        .expect("new key must unlock the rekeyed file");
    let entries_after: Vec<(String, String)> = reopened
        .vault()
        .iter_entries()
        .map(|e| (e.title.clone(), e.password.clone()))
        .collect();
    assert_eq!(entries_before, entries_after);

    // Leg 2 — the integrity check. The OLD key MUST NOT unlock the
    // rekeyed bytes. If rekey silently no-op'd, this would succeed
    // and the test would catch it. Per §4.8.7, the failure must
    // surface as `Error::Crypto` (the same variant a corrupt-file
    // open returns), so an attacker can't tell wrong-key from
    // tampering.
    let err = Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&old_key)
        .expect_err("old key must NOT unlock the rekeyed file");
    assert!(
        matches!(err, Error::Crypto(_)),
        "expected Error::Crypto, got {err:?}"
    );
}
