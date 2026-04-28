//! End-to-end round-trip for [`Kdbx::<Unlocked>::save_to_bytes`].
//!
//! For every fixture with a JSON sidecar whose outer cipher the save
//! path can write (today: AES-256-CBC and ChaCha20, on both KDBX3 and
//! KDBX4):
//! 1. Open, read header, derive composite key, unlock.
//! 2. Call `save_to_bytes` to re-encrypt the vault as fresh KDBX bytes.
//! 3. Open those bytes fresh, unlock with the same composite key, and
//!    assert the round-tripped [`Vault`] equals the original.
//!
//! Twofish fixtures are skipped — `save_to_bytes` rejects them with a
//! typed error for now.
//!
//! ## Scope of the equality assertion
//!
//! Full `Vault` equality, with one principled exclusion:
//! `meta.header_hash` is recomputed on every KDBX3 save against the
//! file's own outer header bytes, so a re-saved file legitimately
//! carries a different hash than the original. The dedicated
//! [`kdbx3_save_emits_a_correct_header_hash`] test validates that the
//! emitted hash actually matches the header it was written with.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::format::{FileSignature, KnownCipher, Version};
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::secret::keyfile_hash;
use serde_json::Value;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn find_kdbxs(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, acc: &mut Vec<PathBuf>) {
        if !dir.is_dir() {
            return;
        }
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, acc);
            } else if p.extension().and_then(|s| s.to_str()) == Some("kdbx") {
                acc.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out
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

/// `true` if the fixture uses an outer cipher the save path can write.
///
/// Currently AES-256-CBC and ChaCha20 on both KDBX3 and KDBX4.
/// Twofish-CBC is still deferred.
fn is_writable_cipher(path: &Path) -> bool {
    let Ok(bytes) = fs::read(path) else {
        return false;
    };
    if bytes.len() < FileSignature::LEN {
        return false;
    }
    let Ok(sig) = FileSignature::read(&bytes[..FileSignature::LEN]) else {
        return false;
    };
    if sig.version().is_err() {
        return false;
    }
    let Ok(kdbx) = Kdbx::<Sealed>::open_from_bytes(bytes) else {
        return false;
    };
    let Ok(header_read) = kdbx.read_header() else {
        return false;
    };
    matches!(
        header_read.header().cipher_id.well_known(),
        Some(KnownCipher::Aes256Cbc | KnownCipher::ChaCha20)
    )
}

#[test]
fn every_writable_fixture_round_trips_save_to_bytes() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("pykeepass"));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    kdbxs.extend(find_kdbxs(&root.join("keepassxc")));

    let mut saw_v3 = false;
    let mut saw_v4 = false;
    for path in &kdbxs {
        if !is_writable_cipher(path) {
            continue;
        }

        let sidecar = load_sidecar(path).unwrap_or_else(|| panic!("{path:?}: no sidecar"));
        let composite =
            composite_for(&sidecar, path).unwrap_or_else(|e| panic!("{path:?}: composite: {e}"));

        // --- Leg 1: original unlock ------------------------------------
        let kdbx = Kdbx::<Sealed>::open(path)
            .unwrap_or_else(|e| panic!("{path:?}: open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: read_header: {e}"));
        match kdbx.version() {
            Version::V3 => saw_v3 = true,
            Version::V4 => saw_v4 = true,
            _ => {}
        }
        let unlocked1 = kdbx
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: unlock: {e}"));
        let vault1 = unlocked1.vault().clone();

        // --- Save to bytes ---------------------------------------------
        let bytes = unlocked1
            .save_to_bytes()
            .unwrap_or_else(|e| panic!("{path:?}: save_to_bytes: {e}"));

        // --- Leg 2: re-open the saved bytes ---------------------------
        let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
            .unwrap_or_else(|e| panic!("{path:?}: re-open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: re-read_header: {e}"));
        let unlocked2 = reopened
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: re-unlock: {e}"));
        let vault2 = unlocked2.vault();

        // Full `Vault` equality, with `meta.header_hash` cleared on
        // both sides — see the module doc-comment for the rationale.
        let mut v1 = vault1.clone();
        let mut v2 = vault2.clone();
        v1.meta.header_hash.clear();
        v2.meta.header_hash.clear();
        if v1 != v2 {
            // Identify which sub-tree differs so the failure is
            // legible.
            assert_eq!(v1.meta, v2.meta, "{path:?}: meta differs");
            assert_eq!(v1.root, v2.root, "{path:?}: root group differs");
            assert_eq!(v1.binaries, v2.binaries, "{path:?}: binaries differ");
            assert_eq!(
                v1.deleted_objects, v2.deleted_objects,
                "{path:?}: deleted_objects differ"
            );
            panic!("{path:?}: round-tripped vault differs in some other field");
        }
    }

    assert!(saw_v3, "no KDBX3 fixtures exercised under {root:?}");
    assert!(saw_v4, "no KDBX4 fixtures exercised under {root:?}");
}

/// KDBX3 spec: `<Meta><HeaderHash>` carries the base64-encoded
/// SHA-256 of the outer header (signature + TLVs). After
/// `save_to_bytes`, the freshly-written file's inner XML must
/// declare a hash that matches the recomputed digest of the file's
/// own outer header bytes — anything else means classic readers
/// (KeePass 2.x, KeePassXC) will reject the file as corrupt.
#[test]
fn kdbx3_save_emits_a_correct_header_hash() {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use sha2::{Digest, Sha256};

    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("pykeepass"));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    kdbxs.extend(find_kdbxs(&root.join("keepassxc")));

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

        let saved = unlocked
            .save_to_bytes()
            .unwrap_or_else(|e| panic!("{path:?}: save_to_bytes: {e}"));

        // Re-open the saved bytes and pull `meta.header_hash` out of
        // the inner XML (the decoder stores it verbatim there).
        let reopened = Kdbx::<Sealed>::open_from_bytes(saved)
            .unwrap_or_else(|e| panic!("{path:?}: re-open: {e}"))
            .read_header()
            .unwrap_or_else(|e| panic!("{path:?}: re-read_header: {e}"));
        let expected = BASE64.encode(Sha256::digest(reopened.header_bytes()));
        let unlocked2 = reopened
            .unlock(&composite)
            .unwrap_or_else(|e| panic!("{path:?}: re-unlock: {e}"));

        let stored = unlocked2.vault().meta.header_hash.as_str();
        assert!(
            !stored.is_empty(),
            "{path:?}: KDBX3 save did not emit <Meta><HeaderHash>"
        );
        assert_eq!(
            stored, expected,
            "{path:?}: <Meta><HeaderHash> does not match SHA-256 of outer header bytes"
        );
        checked += 1;
    }
    assert!(checked > 0, "no KDBX3 writable fixtures exercised");
}
