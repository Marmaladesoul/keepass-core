//! KDBX 3.1 `<Meta><HeaderHash>` verification.
//!
//! A KDBX3 outer header carries no MAC of its own. KDBX 3.1 closes the
//! gap from the inside: the writer stores the SHA-256 of the outer
//! header as `<Meta><HeaderHash>` in the inner XML, which sits inside
//! the encrypted, hashed-block-framed payload. These tests pin the
//! reader's side of that contract:
//!
//! * an outer header that no longer matches the stored hash is refused
//!   under the correct key, and the refusal is
//!   [`CryptoError::Decrypt`] — the same variant as a wrong key — never
//!   an XML error and never a successful unlock;
//! * the check runs whatever the header change is: a field that keys
//!   the inner stream (`ProtectedStreamKey`, `InnerRandomStreamID`) or
//!   one nothing reads (an added comment field);
//! * every intact KDBX3 fixture in the corpus still unlocks.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::crypto::CryptoError;
use keepass_core::format::Version;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::secret::keyfile_hash;
use keepass_core::{CompositeKey, Error};
use serde_json::Value;

/// All fixtures in the corpus share this master password — see
/// `tests/fixtures/README.md`.
const FIXTURE_PASSWORD: &str = "tëst pässwörd 🔑/\\";

/// Length of the KDBX file signature (two magic `u32`s + the version
/// `u32`) that precedes the outer-header TLVs.
const SIGNATURE_LEN: usize = 12;

/// KDBX3 outer-header TLV tags used here.
const TAG_END_OF_HEADER: u8 = 0;
const TAG_COMMENT: u8 = 1;
const TAG_PROTECTED_STREAM_KEY: u8 = 8;
const TAG_INNER_RANDOM_STREAM_ID: u8 = 10;

/// `InnerRandomStreamID` values the header parser accepts.
const INNER_STREAM_NONE: u32 = 0;
const INNER_STREAM_CHACHA20: u32 = 3;

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

/// A KDBX 3.1 fixture with protected values (six entries, each with a
/// password), so a desynchronised inner stream has something to garble.
fn kdbx31_fixture() -> Vec<u8> {
    fs::read(fixtures_root().join("keepassxc").join("kdbx3-basic.kdbx")).expect("read fixture")
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes())
}

fn unlock(bytes: Vec<u8>) -> Result<(), Error> {
    Kdbx::<Sealed>::open_from_bytes(bytes)?
        .read_header()?
        .unlock(&composite())
        .map(|_| ())
}

/// Byte range of the value of the first outer-header TLV with `tag`.
/// KDBX3 TLVs are `[tag: u8][len: u16 LE][value]`.
fn kdbx3_tlv_value(bytes: &[u8], tag: u8) -> std::ops::Range<usize> {
    let mut pos = SIGNATURE_LEN;
    loop {
        let t = bytes[pos];
        let len = usize::from(u16::from_le_bytes([bytes[pos + 1], bytes[pos + 2]]));
        let start = pos + 3;
        if t == tag {
            return start..start + len;
        }
        assert_ne!(t, TAG_END_OF_HEADER, "header has no TLV with tag {tag}");
        pos = start + len;
    }
}

/// Assert the doctored file is refused exactly as a wrong key would be.
fn assert_refused_as_decrypt(bytes: Vec<u8>, context: &str) {
    match unlock(bytes) {
        Err(Error::Crypto(CryptoError::Decrypt)) => {}
        Ok(()) => panic!("{context}: altered KDBX3.1 header silently unlocked"),
        Err(e) => panic!("{context}: expected CryptoError::Decrypt, got {e:?}"),
    }
}

#[test]
fn baseline_fixture_unlocks() {
    unlock(kdbx31_fixture()).expect("baseline unlock");
}

/// A one-bit change to the inner-stream key under the correct master key
/// is refused as `Decrypt`, before any protected value is decrypted
/// against the wrong keystream — whether the garbled values would have
/// happened to be valid UTF-8 or not. Each change yields an unrelated
/// keystream, so a few byte positions cover the range of outcomes; every
/// unlock pays the full KDF, so the sweep stays short.
#[test]
fn altered_protected_stream_key_is_decrypt() {
    let bytes = kdbx31_fixture();
    let range = kdbx3_tlv_value(&bytes, TAG_PROTECTED_STREAM_KEY);
    assert_eq!(range.len(), 32, "premise: 32-byte ProtectedStreamKey");
    for offset in [
        range.start,
        range.start + 1,
        range.start + 16,
        range.end - 1,
    ] {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0x01;
        assert_refused_as_decrypt(
            tampered,
            &format!("ProtectedStreamKey byte {offset} ^ 0x01"),
        );
    }
}

/// Switching the inner-stream algorithm (to one the reader supports) is
/// refused as `Decrypt` too.
#[test]
fn altered_inner_random_stream_id_is_decrypt() {
    let bytes = kdbx31_fixture();
    let range = kdbx3_tlv_value(&bytes, TAG_INNER_RANDOM_STREAM_ID);
    for id in [INNER_STREAM_NONE, INNER_STREAM_CHACHA20] {
        let mut tampered = bytes.clone();
        tampered[range.clone()].copy_from_slice(&id.to_le_bytes());
        assert_refused_as_decrypt(tampered, &format!("InnerRandomStreamID = {id}"));
    }
}

/// A header change that touches no key material — an added comment
/// field, which the reader otherwise ignores — still changes the
/// header's SHA-256, so it is refused the same way.
#[test]
fn added_header_comment_is_decrypt() {
    let bytes = kdbx31_fixture();
    let comment = b"x";
    let mut tampered = bytes[..SIGNATURE_LEN].to_vec();
    tampered.push(TAG_COMMENT);
    tampered.extend_from_slice(&u16::try_from(comment.len()).unwrap().to_le_bytes());
    tampered.extend_from_slice(comment);
    tampered.extend_from_slice(&bytes[SIGNATURE_LEN..]);
    assert_refused_as_decrypt(tampered, "added Comment TLV");
}

/// Control: every intact KDBX3 fixture, across every fixture group,
/// still unlocks — and every KDBX 3.1 one carries a `<HeaderHash>`, so
/// the matching path is what this exercises.
#[test]
fn every_intact_kdbx3_fixture_unlocks() {
    let root = fixtures_root();
    let mut checked = 0;
    let mut failures = Vec::new();
    for group in fs::read_dir(&root).expect("read fixtures").flatten() {
        let dir = group.path();
        if !dir.is_dir() || dir.file_name().is_some_and(|n| n == "malformed") {
            continue;
        }
        for file in fs::read_dir(&dir).expect("read_dir").flatten() {
            let path = file.path();
            if path.extension().and_then(|s| s.to_str()) != Some("kdbx") {
                continue;
            }
            let header_read = Kdbx::<Sealed>::open(&path)
                .and_then(Kdbx::read_header)
                .unwrap_or_else(|e| panic!("{}: {e:?}", path.display()));
            if header_read.version() != Version::V3 {
                continue;
            }
            let minor = header_read.signature().minor;
            let key = sidecar_composite(&path);
            match header_read.unlock(&key) {
                Ok(unlocked) => {
                    if minor >= 1 && unlocked.vault().meta.header_hash.is_empty() {
                        failures.push(format!("{}: KDBX3.1 without HeaderHash", path.display()));
                    }
                }
                Err(e) => failures.push(format!("{}: {e:?}", path.display())),
            }
            checked += 1;
        }
    }
    assert!(checked > 0, "no KDBX3 fixtures found under {root:?}");
    assert!(
        failures.is_empty(),
        "{} of {checked} KDBX3 fixtures failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

/// Composite key from a fixture's JSON sidecar: its master password,
/// plus the keyfile it references, if any.
fn sidecar_composite(path: &Path) -> CompositeKey {
    let text = fs::read_to_string(path.with_extension("json"))
        .unwrap_or_else(|e| panic!("{}: sidecar: {e}", path.display()));
    let sidecar: Value = serde_json::from_str(&text).expect("sidecar JSON");
    let password = sidecar
        .get("master_password")
        .and_then(Value::as_str)
        .expect("sidecar master_password");
    match sidecar.get("key_file").and_then(Value::as_str) {
        Some(name) => {
            let keyfile = fs::read(path.parent().unwrap().join(name)).expect("read keyfile");
            let hash = keyfile_hash(&keyfile).expect("keyfile hash");
            CompositeKey::from_password_and_keyfile_hash(password.as_bytes(), &hash)
        }
        None => CompositeKey::from_password(password.as_bytes()),
    }
}
