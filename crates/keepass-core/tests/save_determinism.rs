//! `save_to_bytes` determinism / non-determinism contract.
//!
//! The save path has a two-sided contract that's easy to break in
//! either direction:
//!
//! 1. **Bytes are non-deterministic.** Each save rotates the outer
//!    cipher IV and the master seed (see `kdbx::fresh_save_header`).
//!    Two saves of the same vault under the same key MUST produce
//!    different bytes — otherwise a ChaCha20 keystream would be
//!    reused across save versions and `v1 XOR v2` would leak the
//!    plaintext directly. (Already pinned by
//!    `successive_saves_use_fresh_iv` in `kdbx_save_to_bytes`.)
//!
//! 2. **Vault state IS deterministic across save→open.** No matter
//!    how many save→open cycles a vault goes through, the decoded
//!    vault state must remain byte-equal (except for the
//!    legitimately-rotating `meta.header_hash` in KDBX3, which is
//!    a SHA-256 of the outer header bytes and so changes with the
//!    IV / master seed).
//!
//! This file pins (2) — the fixed-point property — across the
//! corpus. It complements the existing single-save round-trip in
//! `kdbx_save_to_bytes::every_writable_fixture_round_trips_save_to_bytes`
//! by extending the assertion to multiple successive save→open
//! cycles. A bug that drifted vault state on each save (e.g. an
//! editor mutator that re-stamped a timestamp on every emit, or a
//! canonicaliser that wasn't idempotent) would fail here, on the
//! second save, not the first.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::format::{FileSignature, KnownCipher, Version};
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::Vault;
use keepass_core::secret::keyfile_hash;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Fixture-corpus harness — copied from kdbx_save_to_bytes.rs because we want
// the same set of inputs and want to evolve independently of that file's
// internal helpers. Trying to share these would burn a `tests/common/`
// directory that AGENTS.md's "don't DRY tests" guidance steers away from.
// ---------------------------------------------------------------------------

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn load_sidecar(path: &Path) -> Option<Value> {
    let p = path.with_extension("json");
    let text = fs::read_to_string(p).ok()?;
    serde_json::from_str(&text).ok()
}

fn composite_for(sidecar: &Value, path: &Path) -> Result<CompositeKey, String> {
    let password = sidecar
        .get("master_password")
        .and_then(Value::as_str)
        .ok_or("sidecar has no master_password")?
        .to_owned();
    match sidecar.get("key_file").and_then(Value::as_str) {
        Some(name) if !name.is_empty() => {
            let kf_path = path.parent().unwrap().join(name);
            let kf_bytes = fs::read(&kf_path).map_err(|e| format!("read keyfile: {e}"))?;
            let hash = keyfile_hash(&kf_bytes).map_err(|e| format!("keyfile_hash: {e}"))?;
            Ok(CompositeKey::from_password_and_keyfile_hash(
                password.as_bytes(),
                &hash,
            ))
        }
        _ => Ok(CompositeKey::from_password(password.as_bytes())),
    }
}

fn is_writable_cipher(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    let Ok(sig) = FileSignature::read(&bytes) else {
        return false;
    };
    let _ = sig;
    let Ok(kdbx) = Kdbx::<Sealed>::open_from_bytes(bytes) else {
        return false;
    };
    let Ok(header) = kdbx.read_header() else {
        return false;
    };
    matches!(
        header.header().cipher_id.well_known(),
        Some(KnownCipher::Aes256Cbc | KnownCipher::ChaCha20)
    )
}

/// Strip the meta fields that legitimately rotate on every KDBX3
/// save (so equality is asserted on the parts that should NOT
/// rotate). `header_hash` is a SHA-256 of the outer header bytes,
/// which include the IV / master seed and so change every save.
fn strip_rotating_meta(v: &mut Vault) {
    v.meta.header_hash.clear();
}

// ---------------------------------------------------------------------------
// Determinism contract
// ---------------------------------------------------------------------------

/// Multiple successive save→open cycles converge on a fixed-point
/// vault. The first save may normalise the model (canonicalisation,
/// default fills); after that, the model must be stable.
///
/// Concretely: starting from the original unlocked fixture, do
///
///   save → reopen → save → reopen → save → reopen
///
/// and assert that the second and third reopens yield byte-equal
/// `Vault`s. The first reopen is allowed to differ from the
/// original (the existing round-trip test pins that single-save
/// case); this test layers on top to catch state drift across
/// repeated saves.
///
/// `meta.header_hash` is stripped before comparison because it
/// legitimately rotates with the outer header IV / master seed.
#[test]
fn save_open_is_a_fixed_point_across_repeated_cycles() {
    // Restricted to one KDBX3 + one KDBX4 fixture rather than the
    // whole corpus: each cycle runs an Argon2 derivation per
    // re-unlock, so corpus-wide three-cycle coverage was burning
    // ~100s of CI time per platform. The single-save round-trip in
    // `kdbx_save_to_bytes` already provides corpus-wide coverage of
    // save → open → equal; this test layers on top to catch
    // constant-rate state drift, which two representative fixtures
    // detect just as reliably as twenty.
    let root = fixtures_root();
    let kdbxs: Vec<PathBuf> = vec![
        root.join("keepassxc").join("kdbx3-minimal.kdbx"),
        root.join("kdbxweb").join("kdbx4-argon2d-p8.kdbx"),
    ];

    let mut checked = 0;
    for path in &kdbxs {
        if !is_writable_cipher(path) {
            continue;
        }
        let sidecar = load_sidecar(path).unwrap_or_else(|| panic!("{path:?}: no sidecar"));
        let composite =
            composite_for(&sidecar, path).unwrap_or_else(|e| panic!("{path:?}: composite: {e}"));

        let unlocked = Kdbx::<Sealed>::open(path)
            .unwrap_or_else(|e| panic!("{path:?}: open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: read_header: {e}"))
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: unlock: {e}"));

        // Cycle 1: save the original-state vault.
        let bytes_1 = unlocked.save_to_bytes().expect("save cycle 1");
        let unlocked_1 = Kdbx::<Sealed>::open_from_bytes(bytes_1.clone())
            .expect("reopen 1")
            .read_header()
            .expect("read_header 1")
            .unlock(&composite)
            .expect("unlock 1");

        // Cycle 2: save the just-reopened vault.
        let bytes_2 = unlocked_1.save_to_bytes().expect("save cycle 2");
        let unlocked_2 = Kdbx::<Sealed>::open_from_bytes(bytes_2.clone())
            .expect("reopen 2")
            .read_header()
            .expect("read_header 2")
            .unlock(&composite)
            .expect("unlock 2");

        // Cycle 3: one more, for safety. If state drifts at a
        // constant rate, cycle 2 vs 3 catches the offset that the
        // first cycle's canonicalisation doesn't reveal.
        let bytes_3 = unlocked_2.save_to_bytes().expect("save cycle 3");
        let unlocked_3 = Kdbx::<Sealed>::open_from_bytes(bytes_3.clone())
            .expect("reopen 3")
            .read_header()
            .expect("read_header 3")
            .unlock(&composite)
            .expect("unlock 3");

        // Byte-level non-determinism: every saved blob must differ.
        // (`successive_saves_use_fresh_iv` covers cycle1 vs cycle2;
        // this adds cycle2 vs cycle3.)
        assert_ne!(
            bytes_2, bytes_3,
            "{path:?}: cycle 2 and cycle 3 produced identical bytes — IV/master_seed not rotated"
        );

        // Vault state determinism: cycle 2 reopens to the same
        // vault as cycle 3. Strip the legitimately-rotating
        // header_hash before comparison.
        let mut v2 = unlocked_2.vault().clone();
        let mut v3 = unlocked_3.vault().clone();
        strip_rotating_meta(&mut v2);
        strip_rotating_meta(&mut v3);
        assert_eq!(
            v2, v3,
            "{path:?}: vault state drifted between cycle-2 and cycle-3 reopens"
        );

        checked += 1;
    }
    assert!(checked > 0, "no writable fixtures exercised");
}

/// Companion to the byte-non-determinism: regardless of which save
/// cycle's bytes you reopen, the decoded vault state is the same.
/// Pins the "deterministic decoding under non-deterministic
/// encoding" half of the contract explicitly — a future encoder
/// change that introduced order-sensitive emission (e.g. iterating
/// over a `HashMap` instead of a `BTreeMap`) would fail this test
/// on the third cycle even if cycle 1 happened to coincide with
/// cycle 2 by chance.
#[test]
fn different_save_bytes_reopen_to_identical_vaults() {
    // Single KDBX4 fixture; the property under test is encoder
    // determinism (decoded vault is the same regardless of which
    // save-bytes you reopen), which doesn't depend on input shape.
    let root = fixtures_root();
    let kdbxs: Vec<PathBuf> = vec![root.join("kdbxweb").join("kdbx4-argon2d-p8.kdbx")];

    let mut checked = 0;
    for path in &kdbxs {
        if !is_writable_cipher(path) {
            continue;
        }
        let sidecar = load_sidecar(path).unwrap_or_else(|| panic!("{path:?}: no sidecar"));
        let composite =
            composite_for(&sidecar, path).unwrap_or_else(|e| panic!("{path:?}: composite: {e}"));

        let unlocked = Kdbx::<Sealed>::open(path)
            .unwrap_or_else(|e| panic!("{path:?}: open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: read_header: {e}"))
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: unlock: {e}"));

        // Save the same in-memory vault twice. Bytes differ; the
        // decoded vaults must not.
        let a = unlocked.save_to_bytes().expect("save a");
        let b = unlocked.save_to_bytes().expect("save b");
        assert_ne!(
            a, b,
            "{path:?}: same vault saved twice yielded identical bytes"
        );

        let vault_a = Kdbx::<Sealed>::open_from_bytes(a)
            .expect("reopen a")
            .read_header()
            .expect("read_header a")
            .unlock(&composite)
            .expect("unlock a")
            .vault()
            .clone();
        let vault_b = Kdbx::<Sealed>::open_from_bytes(b)
            .expect("reopen b")
            .read_header()
            .expect("read_header b")
            .unlock(&composite)
            .expect("unlock b")
            .vault()
            .clone();

        let mut va = vault_a;
        let mut vb = vault_b;
        // KDBX3 only mutates header_hash on save, but cycle here is
        // KDBX4 (kdbxweb fixtures) — header_hash isn't carried in
        // KDBX4 inner XML. Strip anyway for symmetry with the
        // fixed-point test; it's a no-op on KDBX4.
        strip_rotating_meta(&mut va);
        strip_rotating_meta(&mut vb);
        assert_eq!(
            va, vb,
            "{path:?}: two non-deterministic save bytes reopened to different vaults"
        );

        checked += 1;
    }
    assert!(checked > 0, "no kdbxweb fixtures exercised");
}

/// KDBX3 only: each save emits a fresh `<Meta><HeaderHash>` matching
/// SHA-256 of the new outer header bytes. Existing
/// `kdbx3_save_emits_a_correct_header_hash` covers a single save;
/// this test confirms the header_hash *changes* across saves (it
/// must, because the IV / master seed inside the header changed),
/// so a stale-cache regression would be caught.
#[test]
fn kdbx3_header_hash_rotates_across_saves() {
    // Restricted to a single KDBX3 fixture; the rotation guarantee
    // is the same shape regardless of input, and corpus-wide
    // coverage isn't worth two extra Argon2 runs.
    let root = fixtures_root();
    let kdbxs: Vec<PathBuf> = vec![root.join("keepassxc").join("kdbx3-minimal.kdbx")];

    let mut checked = 0;
    for path in &kdbxs {
        if !is_writable_cipher(path) {
            continue;
        }
        let kdbx = Kdbx::<Sealed>::open(path)
            .unwrap_or_else(|e| panic!("{path:?}: open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: read_header: {e}"));
        if kdbx.version() != Version::V3 {
            continue;
        }
        let sidecar = load_sidecar(path).unwrap_or_else(|| panic!("{path:?}: no sidecar"));
        let composite =
            composite_for(&sidecar, path).unwrap_or_else(|e| panic!("{path:?}: composite: {e}"));
        let unlocked = kdbx
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: unlock: {e}"));

        let bytes_a = unlocked.save_to_bytes().expect("save a");
        let bytes_b = unlocked.save_to_bytes().expect("save b");

        let hash_a = Kdbx::<Sealed>::open_from_bytes(bytes_a)
            .expect("reopen a")
            .read_header()
            .expect("read_header a")
            .unlock(&composite)
            .expect("unlock a")
            .vault()
            .meta
            .header_hash
            .clone();
        let hash_b = Kdbx::<Sealed>::open_from_bytes(bytes_b)
            .expect("reopen b")
            .read_header()
            .expect("read_header b")
            .unlock(&composite)
            .expect("unlock b")
            .vault()
            .meta
            .header_hash
            .clone();

        assert!(
            !hash_a.is_empty(),
            "{path:?}: KDBX3 save A produced no header_hash"
        );
        assert!(
            !hash_b.is_empty(),
            "{path:?}: KDBX3 save B produced no header_hash"
        );
        assert_ne!(
            hash_a, hash_b,
            "{path:?}: KDBX3 header_hash did not rotate between saves — \
             likely cached from the original parsed file rather than \
             recomputed against the new outer header"
        );
        checked += 1;
    }
    assert!(checked > 0, "no KDBX3 writable fixtures exercised");
}
