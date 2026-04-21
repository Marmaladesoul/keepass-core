//! Integration tests for typed KDF-parameter decoding against the corpus.
//!
//! Covers both KDBX3 (AES-KDF via header fields) and KDBX4 (Argon2 via
//! VarDictionary), exercising the `OuterHeader::decode_kdf_params`
//! convenience method end-to-end.

#![allow(clippy::unnecessary_debug_formatting)]

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{
    Argon2Variant, Argon2Version, FileSignature, KdfParams, KnownKdf, OuterHeader, Version,
    read_header_fields,
};

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

fn parse_outer_header(path: &Path) -> OuterHeader {
    let bytes = fs::read(path).unwrap();
    let sig = FileSignature::read(&bytes[..FileSignature::LEN]).unwrap();
    let version = sig.version().unwrap();
    let mut cursor = &bytes[FileSignature::LEN..];
    let (tlv_fields, _end) =
        read_header_fields(&mut cursor, version.header_length_width()).unwrap();
    OuterHeader::parse(&tlv_fields, version).unwrap()
}

#[test]
fn every_kdbx3_fixture_decodes_as_aes_kdf() {
    for path in find_kdbxs(&fixtures_root().join("keepassxc")) {
        let header = parse_outer_header(&path);
        assert_eq!(header.version, Version::V3);
        let params = header
            .decode_kdf_params()
            .unwrap_or_else(|e| panic!("{path:?}: decode_kdf_params: {e}"));
        assert_eq!(params.family(), KnownKdf::AesKdf);
        match params {
            KdfParams::AesKdf { seed, rounds } => {
                assert_eq!(seed.len(), 32);
                assert!(
                    rounds > 0,
                    "{path:?}: AES-KDF rounds must be > 0 (got {rounds})"
                );
            }
            other => panic!("{path:?}: expected AesKdf, got {other:?}"),
        }
    }
}

#[test]
fn every_kdbx4_fixture_decodes_as_argon2() {
    let mut kdbxs: Vec<_> = find_kdbxs(&fixtures_root().join("pykeepass"));
    kdbxs.extend(find_kdbxs(&fixtures_root().join("kdbxweb")));
    assert!(!kdbxs.is_empty());

    for path in kdbxs {
        let header = parse_outer_header(&path);
        assert_eq!(header.version, Version::V4);
        let params = header
            .decode_kdf_params()
            .unwrap_or_else(|e| panic!("{path:?}: decode_kdf_params: {e}"));

        match params {
            KdfParams::Argon2 {
                variant,
                salt,
                iterations,
                memory_bytes,
                parallelism,
                version,
            } => {
                // Both variants acceptable; pykeepass & kdbxweb both default
                // to Argon2d but either would be valid.
                assert!(matches!(variant, Argon2Variant::Argon2d | Argon2Variant::Argon2id));
                assert!(salt.len() >= 8, "{path:?}: salt too short");
                assert!(iterations > 0);
                assert!(memory_bytes >= 8 * 1024);
                assert!(parallelism > 0);
                // In practice every fixture we produce uses v1.3.
                assert_eq!(version, Argon2Version::V13, "{path:?}: unexpected Argon2 version");
            }
            other => panic!("{path:?}: expected Argon2, got {other:?}"),
        }
    }
}

#[test]
fn family_classifier_matches_version() {
    // Every KDBX3 fixture → AesKdf; every KDBX4 fixture → Argon2-family.
    for path in find_kdbxs(&fixtures_root().join("keepassxc")) {
        let params = parse_outer_header(&path).decode_kdf_params().unwrap();
        assert_eq!(params.family(), KnownKdf::AesKdf);
    }
    let mut kdbx4s: Vec<_> = find_kdbxs(&fixtures_root().join("pykeepass"));
    kdbx4s.extend(find_kdbxs(&fixtures_root().join("kdbxweb")));
    for path in kdbx4s {
        let params = parse_outer_header(&path).decode_kdf_params().unwrap();
        assert!(matches!(
            params.family(),
            KnownKdf::Argon2d | KnownKdf::Argon2id
        ));
    }
}
