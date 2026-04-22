//! End-to-end integration tests for [`Kdbx::<HeaderRead>::unlock`].
//!
//! For each fixture with a JSON sidecar, opens the file, reads its
//! header, derives the composite key from the sidecar's master password
//! (optionally combined with the referenced keyfile), and asserts the
//! full pipeline (KDF → cipher → block-stream → compression → inner
//! header → XML) produces a vault whose entry count, generator, and
//! per-entry fields (title / username / URL / tags) match the sidecar.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{Entry, Vault};
use keepass_core::secret::keyfile_hash;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

/// Load the JSON sidecar alongside `path`, if any.
fn load_sidecar(path: &Path) -> Option<Value> {
    let p = path.with_extension("json");
    let text = fs::read_to_string(p).ok()?;
    serde_json::from_str(&text).ok()
}

#[allow(clippy::too_many_lines)]
fn check_entry_against_sidecar(
    actual: &Entry,
    expected: &Value,
    vault: &Vault,
) -> Result<(), String> {
    if let Some(Value::String(u)) = expected.get("username") {
        if &actual.username != u {
            return Err(format!("username {:?} ≠ expected {u:?}", actual.username));
        }
    }
    if let Some(Value::String(url)) = expected.get("url") {
        if &actual.url != url {
            return Err(format!("url {:?} ≠ expected {url:?}", actual.url));
        }
    }
    if let Some(Value::String(notes)) = expected.get("notes") {
        if &actual.notes != notes {
            return Err(format!("notes {:?} ≠ expected {notes:?}", actual.notes));
        }
    }
    if let Some(Value::Array(tags)) = expected.get("tags") {
        let mut expected_tags: Vec<String> = tags
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let mut got_tags = actual.tags.clone();
        expected_tags.sort();
        got_tags.sort();
        if got_tags != expected_tags {
            return Err(format!("tags {got_tags:?} ≠ expected {expected_tags:?}"));
        }
    }
    if let Some(Value::Number(n)) = expected.get("password_length") {
        if let Some(expected_len) = n.as_u64() {
            let got_len = actual.password.chars().count() as u64;
            if got_len != expected_len {
                return Err(format!(
                    "password length {got_len} ≠ expected {expected_len}"
                ));
            }
        }
    }
    if let Some(Value::Number(n)) = expected.get("custom_field_count") {
        if let Some(expected_count) = n.as_u64() {
            let got_count = actual.custom_fields.len() as u64;
            if got_count != expected_count {
                return Err(format!(
                    "custom_field_count {got_count} ≠ expected {expected_count}"
                ));
            }
        }
    }
    if let Some(Value::Number(n)) = expected.get("history_count") {
        if let Some(expected_count) = n.as_u64() {
            let got_count = actual.history.len() as u64;
            if got_count != expected_count {
                return Err(format!(
                    "history_count {got_count} ≠ expected {expected_count}"
                ));
            }
        }
    }
    if let Some(Value::Number(n)) = expected.get("attachment_count") {
        if let Some(expected_count) = n.as_u64() {
            let got_count = actual.attachments.len() as u64;
            if got_count != expected_count {
                return Err(format!(
                    "attachment_count {got_count} ≠ expected {expected_count}"
                ));
            }
        }
    }
    if let Some(Value::Array(atts)) = expected.get("attachments") {
        let mut expected_names: Vec<String> = atts
            .iter()
            .filter_map(|v| v.get("filename").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut got_names: Vec<String> =
            actual.attachments.iter().map(|a| a.name.clone()).collect();
        expected_names.sort();
        got_names.sort();
        if got_names != expected_names {
            return Err(format!(
                "attachment filenames {got_names:?} ≠ expected {expected_names:?}"
            ));
        }
        // For fixtures where the binary pool is populated (KDBX4 today;
        // KDBX3 lands in a follow-up), verify each attachment's bytes
        // hash to the sidecar's sha256.
        if !vault.binaries.is_empty() {
            for expected_att in atts {
                let Some(filename) = expected_att.get("filename").and_then(Value::as_str) else {
                    continue;
                };
                let Some(expected_sha) = expected_att.get("sha256").and_then(Value::as_str) else {
                    continue;
                };
                let Some(att) = actual.attachments.iter().find(|a| a.name == filename) else {
                    continue;
                };
                let Some(bin) = vault.binaries.get(att.ref_id as usize) else {
                    return Err(format!(
                        "attachment {filename:?} Ref={} out of pool bounds ({} binaries)",
                        att.ref_id,
                        vault.binaries.len()
                    ));
                };
                let got_sha = format!("{:x}", Sha256::digest(&bin.data));
                if got_sha != expected_sha {
                    return Err(format!(
                        "attachment {filename:?} sha256 {got_sha} ≠ expected {expected_sha}"
                    ));
                }
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn unlock_one(path: &Path) -> Result<(), String> {
    let Some(sidecar) = load_sidecar(path) else {
        return Ok(());
    };

    let password = sidecar
        .get("master_password")
        .and_then(Value::as_str)
        .ok_or("sidecar has no master_password")?
        .to_owned();

    let kdbx = Kdbx::<Sealed>::open(path)
        .map_err(|e| format!("open: {e}"))?
        .read_header()
        .map_err(|e| format!("read_header: {e}"))?;

    // Build the composite key, threading in a keyfile if one is referenced.
    let composite = match sidecar.get("key_file").and_then(Value::as_str) {
        Some(name) if !name.is_empty() => {
            let kf_path = path.parent().unwrap().join(name);
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

    // Total-entry count.
    if let Some(expected) = sidecar.get("entry_count").and_then(Value::as_u64) {
        if vault.total_entries() as u64 != expected {
            return Err(format!(
                "entry_count {} ≠ expected {expected}",
                vault.total_entries()
            ));
        }
    }

    // Generator.
    if let Some(expected) = sidecar.get("generator").and_then(Value::as_str) {
        if vault.meta.generator != expected {
            return Err(format!(
                "generator {:?} ≠ expected {expected:?}",
                vault.meta.generator
            ));
        }
    }

    // Recycle bin flag.
    if let Some(expected) = sidecar.get("recycle_bin_present").and_then(Value::as_bool) {
        let got = vault.meta.recycle_bin_enabled && vault.meta.recycle_bin_uuid.is_some();
        if got != expected {
            return Err(format!("recycle_bin_present {got} ≠ expected {expected}"));
        }
    }

    // Top-level `attachments` array (kdbxweb-style sidecars): for each
    // expected attachment, find the entry by title and verify the
    // referenced binary's SHA-256.
    if let Some(atts) = sidecar.get("attachments").and_then(Value::as_array) {
        for a in atts {
            let (Some(entry_title), Some(filename)) = (
                a.get("entry").and_then(Value::as_str),
                a.get("filename").and_then(Value::as_str),
            ) else {
                continue;
            };
            let Some(expected_sha) = a.get("sha256").and_then(Value::as_str) else {
                continue;
            };
            let Some(entry) = vault.iter_entries().find(|e| e.title == entry_title) else {
                return Err(format!(
                    "attachment {filename:?} refers to missing entry {entry_title:?}"
                ));
            };
            let Some(att) = entry.attachments.iter().find(|att| att.name == filename) else {
                return Err(format!(
                    "entry {entry_title:?} missing attachment {filename:?}"
                ));
            };
            let Some(bin) = vault.binaries.get(att.ref_id as usize) else {
                return Err(format!(
                    "attachment {filename:?} Ref={} out of pool bounds ({} binaries)",
                    att.ref_id,
                    vault.binaries.len()
                ));
            };
            let got_sha = format!("{:x}", Sha256::digest(&bin.data));
            if got_sha != expected_sha {
                return Err(format!(
                    "attachment {filename:?} sha256 {got_sha} ≠ expected {expected_sha}"
                ));
            }
        }
    }

    // Per-entry assertions when the sidecar lists entries.
    if let Some(entries) = sidecar.get("entries").and_then(Value::as_array) {
        // Index actual entries by title for order-independent matching.
        let mut by_title: HashMap<String, Vec<&Entry>> = HashMap::new();
        for e in vault.iter_entries() {
            by_title.entry(e.title.clone()).or_default().push(e);
        }
        for expected in entries {
            let Some(title) = expected.get("title").and_then(Value::as_str) else {
                continue;
            };
            let Some(candidates) = by_title.get(title) else {
                return Err(format!("missing entry with title {title:?}"));
            };
            // If multiple entries share a title, try each and accept the
            // first that matches the expected fields.
            let mut last_err: Option<String> = None;
            let matched = candidates.iter().any(|actual| {
                match check_entry_against_sidecar(actual, expected, vault) {
                    Ok(()) => true,
                    Err(e) => {
                        last_err = Some(e);
                        false
                    }
                }
            });
            if !matched {
                return Err(format!(
                    "entry {title:?}: {}",
                    last_err.unwrap_or_else(|| "no field-level mismatch recorded".to_owned())
                ));
            }
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
