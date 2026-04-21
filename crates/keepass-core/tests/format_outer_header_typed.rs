//! Integration tests for [`OuterHeader::parse`] against real fixtures.
//!
//! For every well-formed fixture, read the signature, read the TLV records,
//! decode them into an [`OuterHeader`], and sanity-check the version-specific
//! fields. These tests are the parser's first end-to-end integration — they
//! exercise FileSignature → TLV → typed header on real kdbx files produced
//! by three distinct implementations (keepassxc-cli, pykeepass, kdbxweb).

// `{path:?}` is the natural formatter for panic messages; Display would mean
// littering every assertion with `.display()`.
#![allow(clippy::unnecessary_debug_formatting)]

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{
    CompressionFlags, FileSignature, InnerStreamAlgorithm, KnownCipher, OuterHeader, Version,
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

fn parse_outer_header(path: &Path) -> (Version, OuterHeader) {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path:?}: read: {e}"));
    let sig = FileSignature::read(&bytes[..FileSignature::LEN])
        .unwrap_or_else(|e| panic!("{path:?}: signature: {e}"));
    let version = sig
        .version()
        .unwrap_or_else(|e| panic!("{path:?}: version: {e}"));
    let mut cursor = &bytes[FileSignature::LEN..];
    let (tlv_fields, _end) = read_header_fields(&mut cursor, version.header_length_width())
        .unwrap_or_else(|e| panic!("{path:?}: tlv: {e}"));
    let header = OuterHeader::parse(&tlv_fields, version)
        .unwrap_or_else(|e| panic!("{path:?}: header: {e}"));
    (version, header)
}

#[test]
fn every_well_formed_fixture_parses_a_complete_outer_header() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("keepassxc"));
    kdbxs.extend(find_kdbxs(&root.join("pykeepass")));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));

    assert!(!kdbxs.is_empty(), "no fixtures under {root:?}");

    for path in &kdbxs {
        let (version, h) = parse_outer_header(path);
        assert_eq!(h.version, version);
        // Every fixture should identify its cipher as one of the three known.
        assert!(
            h.cipher_id.well_known().is_some(),
            "{path:?}: unrecognised cipher {:?}",
            h.cipher_id
        );
        // IV must be plausibly sized for its cipher.
        let iv_len = h.encryption_iv.0.len();
        match h.cipher_id.well_known() {
            Some(KnownCipher::Aes256Cbc | KnownCipher::TwofishCbc) => {
                assert_eq!(iv_len, 16, "{path:?}: CBC IV must be 16 bytes");
            }
            Some(KnownCipher::ChaCha20) => {
                assert_eq!(iv_len, 12, "{path:?}: ChaCha20 nonce must be 12 bytes");
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn kdbx3_fixtures_have_v3_only_fields_populated() {
    for path in find_kdbxs(&fixtures_root().join("keepassxc")) {
        let (version, h) = parse_outer_header(&path);
        if version != Version::V3 {
            continue;
        }
        assert!(
            h.transform_seed.is_some(),
            "{path:?}: expected TransformSeed"
        );
        assert!(
            h.transform_rounds.is_some(),
            "{path:?}: expected TransformRounds"
        );
        assert!(
            h.protected_stream_key.is_some(),
            "{path:?}: expected ProtectedStreamKey"
        );
        assert!(
            h.stream_start_bytes.is_some(),
            "{path:?}: expected StreamStartBytes"
        );
        assert!(
            matches!(
                h.inner_stream_algorithm,
                Some(InnerStreamAlgorithm::Salsa20 | InnerStreamAlgorithm::ChaCha20)
            ),
            "{path:?}: expected a known inner-stream algorithm, got {:?}",
            h.inner_stream_algorithm
        );
        // KDBX3 fixtures should NOT have the KDBX4 VarDictionary fields.
        assert!(
            h.kdf_parameters.is_none(),
            "{path:?}: v3 should not have KdfParameters"
        );
    }
}

#[test]
fn kdbx4_fixtures_have_kdf_parameters_populated() {
    let mut kdbxs: Vec<_> = find_kdbxs(&fixtures_root().join("pykeepass"));
    kdbxs.extend(find_kdbxs(&fixtures_root().join("kdbxweb")));
    for path in kdbxs {
        let (version, h) = parse_outer_header(&path);
        assert_eq!(version, Version::V4);
        assert!(
            h.kdf_parameters.is_some(),
            "{path:?}: expected KdfParameters (tag 11)"
        );
        // KDBX4 should NOT populate any of the KDBX3-only transform fields.
        assert!(
            h.transform_seed.is_none(),
            "{path:?}: v4 leaked v3 TransformSeed"
        );
        assert!(
            h.transform_rounds.is_none(),
            "{path:?}: v4 leaked v3 TransformRounds"
        );
        assert!(
            h.protected_stream_key.is_none(),
            "{path:?}: v4 leaked v3 ProtectedStreamKey"
        );
    }
}

#[test]
fn keepassxc_cli_uses_aes_cbc_by_default() {
    // keepassxc-cli 2.7.7 writes KDBX3 with AES-256-CBC outer cipher.
    for path in find_kdbxs(&fixtures_root().join("keepassxc")) {
        let (_, h) = parse_outer_header(&path);
        assert_eq!(
            h.cipher_id.well_known(),
            Some(KnownCipher::Aes256Cbc),
            "{path:?}: keepassxc-cli should produce AES-256-CBC"
        );
        // No compression by default (keepassxc-cli sets it to None for db-create).
        // But be forgiving — accept either.
        assert!(matches!(
            h.compression,
            CompressionFlags::None | CompressionFlags::Gzip
        ));
    }
}

#[test]
fn every_fixture_has_a_known_compression_value() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("keepassxc"));
    kdbxs.extend(find_kdbxs(&root.join("pykeepass")));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    for path in kdbxs {
        let (_, h) = parse_outer_header(&path);
        // Because CompressionFlags is #[non_exhaustive] we include a wildcard
        // for future variants; today both known values are accepted.
        match h.compression {
            CompressionFlags::None | CompressionFlags::Gzip => (),
            _ => panic!(
                "{path:?}: unexpected compression variant {:?}",
                h.compression
            ),
        }
    }
}
