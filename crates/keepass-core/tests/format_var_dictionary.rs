//! Integration tests: parse the real KdfParameters VarDictionary from
//! every KDBX4 fixture.
//!
//! For every KDBX4 vault in the corpus, read its outer header, extract the
//! `KdfParameters` (tag 11) blob, and assert that the VarDictionary
//! decoder produces a plausible Argon2-parameter set:
//!
//! - `$UUID` key is present and 16 bytes long (identifies the KDF family)
//! - `S` (salt) is present, 16–64 bytes
//! - `I` (iterations) is present, > 0
//! - `M` (memory in bytes) is present, ≥ 8 KiB
//! - `P` (parallelism) is present, > 0
//! - `V` (version) is either 0x10 or 0x13 per the Argon2 spec

#![allow(clippy::unnecessary_debug_formatting)]

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{
    FileSignature, OuterHeader, VarDictionary, VarValue, Version, read_header_fields,
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
fn every_kdbx4_fixture_has_a_well_formed_kdf_parameters_dictionary() {
    let mut kdbxs: Vec<_> = find_kdbxs(&fixtures_root().join("pykeepass"));
    kdbxs.extend(find_kdbxs(&fixtures_root().join("kdbxweb")));
    assert!(!kdbxs.is_empty(), "no KDBX4 fixtures found");

    for path in kdbxs {
        let header = parse_outer_header(&path);
        assert_eq!(header.version, Version::V4);
        let blob = header
            .kdf_parameters
            .as_ref()
            .unwrap_or_else(|| panic!("{path:?}: KDBX4 header must have KdfParameters"));

        let dict = VarDictionary::parse(blob)
            .unwrap_or_else(|e| panic!("{path:?}: VarDictionary parse: {e}"));

        // $UUID: 16-byte KDF identifier
        match dict.get("$UUID") {
            Some(VarValue::Bytes(b)) => assert_eq!(
                b.len(),
                16,
                "{path:?}: $UUID should be 16 bytes, got {}",
                b.len()
            ),
            other => panic!("{path:?}: $UUID missing or wrong type: {other:?}"),
        }

        // S: salt/seed — 16–64 bytes is the sensible range
        match dict.get("S") {
            Some(VarValue::Bytes(b)) => assert!(
                (16..=64).contains(&b.len()),
                "{path:?}: salt length {} outside [16, 64]",
                b.len()
            ),
            other => panic!("{path:?}: S missing or wrong type: {other:?}"),
        }

        // I: iterations, > 0
        let iterations = dict.get_u64("I").unwrap_or_else(|| {
            panic!("{path:?}: iterations (I) missing or wrong type")
        });
        assert!(iterations > 0, "{path:?}: iterations must be > 0");

        // M: memory in bytes, ≥ 8 KiB
        let memory = dict.get_u64("M").unwrap_or_else(|| {
            panic!("{path:?}: memory (M) missing or wrong type")
        });
        assert!(
            memory >= 8 * 1024,
            "{path:?}: memory {memory} bytes is below Argon2 minimum 8 KiB"
        );

        // P: parallelism, > 0
        let parallelism = dict.get_u32("P").unwrap_or_else(|| {
            panic!("{path:?}: parallelism (P) missing or wrong type")
        });
        assert!(parallelism > 0, "{path:?}: parallelism must be > 0");

        // V: Argon2 version, either 0x10 or 0x13
        let version = dict.get_u32("V").unwrap_or_else(|| {
            panic!("{path:?}: argon2 version (V) missing or wrong type")
        });
        assert!(
            version == 0x10 || version == 0x13,
            "{path:?}: unexpected Argon2 version 0x{version:x}"
        );
    }
}

#[test]
fn kdbx3_fixtures_have_no_kdf_parameters() {
    for path in find_kdbxs(&fixtures_root().join("keepassxc")) {
        let header = parse_outer_header(&path);
        assert_eq!(header.version, Version::V3);
        assert!(
            header.kdf_parameters.is_none(),
            "{path:?}: KDBX3 should not carry KdfParameters"
        );
    }
}
