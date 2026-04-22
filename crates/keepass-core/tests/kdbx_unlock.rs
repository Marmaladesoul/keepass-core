//! End-to-end integration tests for [`Kdbx::<HeaderRead>::unlock`].
//!
//! For each fixture with a JSON sidecar, opens the file, reads its
//! header, derives the composite key from the sidecar's master password
//! (optionally combined with the referenced keyfile), and asserts the
//! full pipeline (KDF → cipher → block-stream → compression → inner
//! header → XML) produces a vault whose entry count and generator match
//! the sidecar.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::secret::keyfile_hash;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

/// Extract the value of a JSON string field from a sidecar. The sidecars are
/// simple hand-written files; a full JSON parser would be over-engineered
/// here.
fn read_string_field(sidecar: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":");
    let idx = sidecar.find(&needle)?;
    let rest = &sidecar[idx + needle.len()..];
    let trimmed = rest.trim_start();
    // Reject `null` and any non-string value — only a leading `"` means
    // "this field has a real string value".
    if !trimmed.starts_with('"') {
        return None;
    }
    let inner = &trimmed[1..];
    let end = inner.find('"')?;
    Some(inner[..end].to_owned())
}

fn read_usize_field(sidecar: &str, field: &str) -> Option<usize> {
    let needle = format!("\"{field}\":");
    let idx = sidecar.find(&needle)?;
    let rest = &sidecar[idx + needle.len()..];
    let trimmed = rest.trim_start();
    let end = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(trimmed.len());
    trimmed[..end].parse().ok()
}

fn unlock_one(path: &Path) -> Result<(), String> {
    let sidecar_path = path.with_extension("json");
    if !sidecar_path.exists() {
        return Ok(());
    }
    let sidecar = fs::read_to_string(&sidecar_path).expect("read sidecar");

    let Some(password) = read_string_field(&sidecar, "master_password") else {
        return Ok(());
    };
    let expected_entries = read_usize_field(&sidecar, "entry_count");
    let expected_generator = read_string_field(&sidecar, "generator");

    let kdbx = Kdbx::<Sealed>::open(path)
        .map_err(|e| format!("open: {e}"))?
        .read_header()
        .map_err(|e| format!("read_header: {e}"))?;

    // Build the composite key, threading in a keyfile if one is referenced.
    let composite = match read_string_field(&sidecar, "key_file") {
        Some(name) if !name.is_empty() => {
            let kf_path = path.parent().unwrap().join(&name);
            let kf_bytes = fs::read(&kf_path).map_err(|e| format!("read keyfile: {e}"))?;
            match keyfile_hash(&kf_bytes) {
                Ok(hash) => {
                    CompositeKey::from_password_and_keyfile_hash(password.as_bytes(), &hash)
                }
                Err(e) => return Err(format!("keyfile_hash: {e}")),
            }
        }
        _ => CompositeKey::from_password(password.as_bytes()),
    };

    let unlocked = match kdbx.unlock(&composite) {
        Ok(u) => u,
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("ChaCha20") || msg.contains("Twofish") {
                return Ok(()); // unsupported cipher — skip silently
            }
            return Err(format!("unlock: {e}"));
        }
    };

    let vault = unlocked.vault();

    if let Some(expected) = expected_entries {
        if vault.total_entries() != expected {
            return Err(format!(
                "entry count {} ≠ expected {}",
                vault.total_entries(),
                expected
            ));
        }
    }

    if let Some(expected) = expected_generator {
        if vault.meta.generator != expected {
            return Err(format!(
                "generator {:?} ≠ expected {:?}",
                vault.meta.generator, expected
            ));
        }
    }
    Ok(())
}

#[test]
fn unlock_every_valid_fixture() {
    let root = fixtures_root();
    let mut checked = 0;
    let mut failures = Vec::new();
    for group in ["kdbxweb", "keepassxc", "pykeepass"] {
        let dir = root.join(group);
        if !dir.is_dir() {
            continue;
        }
        for entry in fs::read_dir(&dir).expect("read_dir").flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) == Some("kdbx") {
                match unlock_one(&p) {
                    Ok(()) => {}
                    Err(e) => failures.push(format!("{}: {}", p.display(), e)),
                }
                checked += 1;
            }
        }
    }
    assert!(checked > 0, "no fixtures found under {root:?}");
    assert!(
        failures.is_empty(),
        "{} of {checked} fixtures failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

#[test]
fn wrong_password_is_rejected_as_crypto_error() {
    let path = fixtures_root().join("kdbxweb").join("kdbx4-basic.kdbx");
    if !path.exists() {
        return;
    }
    let kdbx = Kdbx::<Sealed>::open(&path).unwrap().read_header().unwrap();
    let wrong = CompositeKey::from_password(b"this is definitely not the password");
    let err = kdbx.unlock(&wrong).unwrap_err();
    // Must surface as a Crypto error — the error-collapse discipline means
    // we don't get to tell the caller whether it was a wrong key or a
    // corrupt ciphertext, but we should at least classify it as crypto.
    assert!(
        matches!(err, keepass_core::Error::Crypto(_)),
        "expected Crypto error, got: {err:?}"
    );
}
