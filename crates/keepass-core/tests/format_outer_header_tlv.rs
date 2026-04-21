//! Integration tests for the outer-header TLV reader against real fixtures.
//!
//! For every well-formed fixture in the corpus, skip past the 12-byte file
//! signature, then read the TLV sequence using the width appropriate for the
//! declared KDBX version. Assert that every fixture yields at least the
//! mandatory cipher / master-seed / IV fields, that the end-of-header
//! sentinel is present, and that the cursor stops in a reasonable place.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{FileSignature, LengthWidth, Version, read_header_fields};

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

// Tag values common to KDBX3 and KDBX4 outer headers. Every well-formed
// vault must carry these three at minimum; a parser that misses one of them
// cannot proceed to decryption.
const TAG_CIPHER_ID: u8 = 2;
const TAG_MASTER_SEED: u8 = 4;
const TAG_ENCRYPTION_IV: u8 = 7;

/// Every well-formed fixture should yield a header with at least the three
/// mandatory fields and an end-of-header sentinel.
#[test]
fn every_well_formed_fixture_has_mandatory_header_fields() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("keepassxc"));
    kdbxs.extend(find_kdbxs(&root.join("pykeepass")));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));

    assert!(
        !kdbxs.is_empty(),
        "no fixtures found — corpus missing from {root:?}"
    );

    for path in &kdbxs {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path:?}: read: {e}"));
        assert!(
            bytes.len() > FileSignature::LEN,
            "{path:?}: too small to contain a header"
        );

        let sig = FileSignature::read(&bytes[..FileSignature::LEN])
            .unwrap_or_else(|e| panic!("{path:?}: signature: {e}"));
        let version = sig
            .version()
            .unwrap_or_else(|e| panic!("{path:?}: version: {e}"));
        let width = version.header_length_width();

        let mut cursor = &bytes[FileSignature::LEN..];
        let before = cursor.len();
        let (fields, end) =
            read_header_fields(&mut cursor, width).unwrap_or_else(|e| panic!("{path:?}: TLV: {e}"));
        let consumed = before - cursor.len();

        assert!(
            end.is_end(),
            "{path:?}: last record should be end-of-header"
        );
        assert!(
            consumed < bytes.len() - FileSignature::LEN,
            "{path:?}: TLV should not consume the entire rest of the file"
        );

        let tags: Vec<u8> = fields.iter().map(|f| f.tag).collect();
        for mandatory in [TAG_CIPHER_ID, TAG_MASTER_SEED, TAG_ENCRYPTION_IV] {
            assert!(
                tags.contains(&mandatory),
                "{path:?}: missing mandatory tag {mandatory} (got {tags:?})"
            );
        }

        // Cipher ID is a 16-byte UUID per the KDBX spec.
        let cipher = fields.iter().find(|f| f.tag == TAG_CIPHER_ID).unwrap();
        assert_eq!(
            cipher.value.len(),
            16,
            "{path:?}: cipher ID should be a 16-byte UUID"
        );

        // Master seed is conventionally 32 bytes (SHA-256 width).
        let seed = fields.iter().find(|f| f.tag == TAG_MASTER_SEED).unwrap();
        assert_eq!(
            seed.value.len(),
            32,
            "{path:?}: master seed should be 32 bytes"
        );

        // Encryption IV width depends on the cipher; both AES (16 bytes) and
        // ChaCha20 (12 bytes) are legal. Just sanity-check it's non-empty
        // and plausibly sized.
        let iv = fields.iter().find(|f| f.tag == TAG_ENCRYPTION_IV).unwrap();
        assert!(
            (12..=16).contains(&iv.value.len()),
            "{path:?}: IV length {} is out of plausible range [12, 16]",
            iv.value.len()
        );
    }
}

/// The KDBX3 fixtures should specifically have TransformSeed (tag 5) and
/// TransformRounds (tag 6) — AES-KDF parameters that exist only in v3.
#[test]
fn kdbx3_fixtures_carry_aes_kdf_params() {
    let root = fixtures_root();
    for path in find_kdbxs(&root.join("keepassxc")) {
        let bytes = fs::read(&path).unwrap();
        let sig = FileSignature::read(&bytes[..FileSignature::LEN]).unwrap();
        if sig.version().unwrap() != Version::V3 {
            continue;
        }
        let mut cursor = &bytes[FileSignature::LEN..];
        let (fields, _end) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        let tags: Vec<u8> = fields.iter().map(|f| f.tag).collect();
        assert!(
            tags.contains(&5),
            "{path:?}: v3 should have TransformSeed (tag 5)"
        );
        assert!(
            tags.contains(&6),
            "{path:?}: v3 should have TransformRounds (tag 6)"
        );
    }
}

/// KDBX4 fixtures should carry KdfParameters (tag 11) — a VarDictionary
/// describing Argon2 (or AES-KDF) parameters.
#[test]
fn kdbx4_fixtures_carry_kdf_parameters() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("pykeepass"));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));

    for path in kdbxs {
        let bytes = fs::read(&path).unwrap();
        let sig = FileSignature::read(&bytes[..FileSignature::LEN]).unwrap();
        assert_eq!(
            sig.version().unwrap(),
            Version::V4,
            "{path:?}: expected KDBX4 fixtures here"
        );
        let mut cursor = &bytes[FileSignature::LEN..];
        let (fields, _end) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        let tags: Vec<u8> = fields.iter().map(|f| f.tag).collect();
        assert!(
            tags.contains(&11),
            "{path:?}: v4 should have KdfParameters (tag 11), got {tags:?}"
        );
    }
}
