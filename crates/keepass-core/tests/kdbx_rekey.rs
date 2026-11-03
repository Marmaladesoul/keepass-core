//! Slice 9 — `Kdbx::<Unlocked>::rekey(&CompositeKey)`.
//!
//! Per the design notes §"Slicing plan" slice 9. Rotates the master seed,
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

fn kdbx3_fixture() -> PathBuf {
    fixtures_root().join("keepassxc/kdbx3-basic.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let sidecar = path.with_extension("json");
    let text = fs::read_to_string(sidecar).unwrap();
    serde_json::from_str::<serde_json::Value>(&text)
        .unwrap()
        .get("master_password")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap()
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

// --- rekey_with_kdf -----------------------------------------------------

use keepass_core::format::{Argon2Variant, Argon2Version, KdfParams};

fn open_unlocked(path: &Path, key: &CompositeKey) -> Kdbx<keepass_core::kdbx::Unlocked> {
    Kdbx::<Sealed>::open(path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(key)
        .unwrap()
}

fn kdf_of_bytes(bytes: &[u8]) -> KdfParams {
    Kdbx::<Sealed>::open_from_bytes(bytes.to_vec())
        .unwrap()
        .read_header()
        .unwrap()
        .header()
        .decode_kdf_params()
        .unwrap()
}

#[test]
fn rekey_with_kdf_installs_the_new_parameters_under_a_fresh_salt() {
    let path = kdbx4_basic();
    let key = CompositeKey::from_password(password_from_sidecar(&path).as_bytes());
    let mut kdbx = open_unlocked(&path, &key);
    let passed_salt = vec![7u8; 32];
    let wanted = KdfParams::Argon2 {
        variant: Argon2Variant::Argon2id,
        salt: passed_salt.clone(),
        iterations: 3,
        memory_bytes: 8 * 1024 * 1024,
        parallelism: 1,
        version: Argon2Version::V13,
    };

    kdbx.rekey_with_kdf(&key, &wanted).unwrap();
    let saved = kdbx.save_to_bytes().unwrap();

    // The saved header names the new parameters, salt aside: the salt is
    // fresh, of the length passed in.
    let KdfParams::Argon2 {
        variant,
        salt,
        iterations,
        memory_bytes,
        parallelism,
        version,
    } = kdf_of_bytes(&saved)
    else {
        panic!("expected Argon2 parameters");
    };
    assert_eq!(
        (variant, iterations, memory_bytes, parallelism, version),
        (
            Argon2Variant::Argon2id,
            3,
            8 * 1024 * 1024,
            1,
            Argon2Version::V13
        )
    );
    assert_eq!(salt.len(), passed_salt.len());
    assert_ne!(
        salt, passed_salt,
        "the salt must be fresh, not the one passed"
    );

    // The same key opens it — the transformed key was re-derived under the
    // new parameters — and the entries survive.
    let reopened = Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&key)
        .expect("the key must unlock the file under its new KDF parameters");
    assert_eq!(
        reopened.vault().iter_entries().count(),
        open_unlocked(&path, &key).vault().iter_entries().count()
    );
}

#[test]
fn rekey_with_kdf_switches_a_kdbx4_file_between_kdf_families() {
    let path = kdbx4_basic();
    let key = CompositeKey::from_password(password_from_sidecar(&path).as_bytes());
    let mut kdbx = open_unlocked(&path, &key);

    kdbx.rekey_with_kdf(
        &key,
        &KdfParams::AesKdf {
            seed: [0; 32],
            rounds: 1_000,
        },
    )
    .unwrap();
    let saved = kdbx.save_to_bytes().unwrap();

    assert!(matches!(
        kdf_of_bytes(&saved),
        KdfParams::AesKdf { rounds: 1_000, .. }
    ));
    Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&key)
        .expect("the key must unlock the file under AES-KDF");
}

#[test]
fn rekey_with_kdf_changes_kdbx3_rounds_and_refuses_argon2() {
    let path = kdbx3_fixture();
    let key = CompositeKey::from_password(password_from_sidecar(&path).as_bytes());
    let mut kdbx = open_unlocked(&path, &key);

    kdbx.rekey_with_kdf(
        &key,
        &KdfParams::AesKdf {
            seed: [0; 32],
            rounds: 1_234,
        },
    )
    .unwrap();
    let saved = kdbx.save_to_bytes().unwrap();
    assert!(matches!(
        kdf_of_bytes(&saved),
        KdfParams::AesKdf { rounds: 1_234, .. }
    ));
    Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&key)
        .expect("the key must unlock the KDBX3 file under its new rounds");

    let mut kdbx = open_unlocked(&path, &key);
    let err = kdbx
        .rekey_with_kdf(
            &key,
            &KdfParams::Argon2 {
                variant: Argon2Variant::Argon2id,
                salt: vec![0; 32],
                iterations: 2,
                memory_bytes: 8 * 1024 * 1024,
                parallelism: 1,
                version: Argon2Version::V13,
            },
        )
        .expect_err("a KDBX3 header can't carry Argon2 parameters");
    assert!(matches!(err, Error::Format(_)), "got {err:?}");
}
