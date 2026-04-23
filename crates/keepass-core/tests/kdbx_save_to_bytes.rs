//! End-to-end round-trip for [`Kdbx::<Unlocked>::save_to_bytes`].
//!
//! For every KDBX4 + AES-256-CBC fixture with a JSON sidecar:
//! 1. Open, read header, derive composite key, unlock.
//! 2. Call `save_to_bytes` to re-encrypt the vault as fresh KDBX bytes.
//! 3. Open those bytes fresh, unlock with the same composite key, and
//!    assert that the user-facing entry fields match the original.
//!
//! Skips Twofish fixtures — `save_to_bytes` rejects them with a typed
//! error for now. AES-256-CBC and ChaCha20 (on both KDBX3 and KDBX4)
//! are exercised.
//!
//! ## Scope of the equality assertion
//!
//! We do **not** assert full `Vault` equality. The XML encoder this
//! crate currently ships is still "minimum viable" — it emits entry
//! core fields (UUID, title, username, password, URL, notes, tags,
//! custom fields) and group core fields (UUID, name, notes) but does
//! not yet cover every timestamp, custom-data item, auto-type
//! association, memory-protection flag, or recycle-bin state. A
//! byte-for-byte round-trip of an arbitrary third-party vault is the
//! long-term goal; this milestone demonstrates the crypto and framing
//! pipeline works end-to-end on what the encoder does cover.
//!
//! As the XML encoder grows coverage in follow-up PRs, move fields
//! from the "skipped" list into `PreservedSubset` below. When the
//! subset equals `Vault`, replace the helper with direct equality.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::format::{FileSignature, KnownCipher, Version};
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::Vault;
use keepass_core::secret::keyfile_hash;
use serde_json::Value;

/// The subset of a [`Vault`] that the current XML encoder round-trips
/// losslessly. When the encoder's coverage catches up with the
/// decoder, this can be retired.
#[derive(Debug, PartialEq, Eq)]
struct PreservedSubset {
    generator: String,
    database_name: String,
    entry_count: usize,
    entries: Vec<PreservedEntry>,
}

#[derive(Debug, PartialEq, Eq)]
struct PreservedEntry {
    title: String,
    username: String,
    password: String,
    url: String,
    notes: String,
    tags: Vec<String>,
    custom_fields: Vec<(String, String, bool)>,
}

fn preserved(v: &Vault) -> PreservedSubset {
    PreservedSubset {
        generator: v.meta.generator.clone(),
        database_name: v.meta.database_name.clone(),
        entry_count: v.total_entries(),
        entries: v
            .iter_entries()
            .map(|e| PreservedEntry {
                title: e.title.clone(),
                username: e.username.clone(),
                password: e.password.clone(),
                url: e.url.clone(),
                notes: e.notes.clone(),
                tags: {
                    let mut t = e.tags.clone();
                    t.sort();
                    t
                },
                custom_fields: {
                    let mut cfs: Vec<_> = e
                        .custom_fields
                        .iter()
                        .map(|c| (c.key.clone(), c.value.clone(), c.protected))
                        .collect();
                    cfs.sort();
                    cfs
                },
            })
            .collect(),
    }
}

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

        assert_eq!(
            preserved(&vault1),
            preserved(vault2),
            "{path:?}: round-tripped vault differs from original (in the encoder-covered subset)"
        );
    }

    assert!(saw_v3, "no KDBX3 fixtures exercised under {root:?}");
    assert!(saw_v4, "no KDBX4 fixtures exercised under {root:?}");
}
