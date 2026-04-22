//! Fixture round-trip for the typed outer-header writer.
//!
//! For every well-formed fixture: read the signature, parse the raw TLV
//! stream, build a typed [`OuterHeader`] via [`OuterHeader::parse`],
//! re-serialise via [`OuterHeader::write`], re-read the re-serialised
//! bytes, re-parse, and assert the round-tripped typed header equals
//! the original field-by-field.
//!
//! Byte-exact equality is *not* asserted. Tag ordering and any optional
//! `COMMENT` records a writer may have emitted are not preserved by a
//! canonical re-encoder, and a KDBX4 header's `KDF_PARAMETERS` blob is
//! round-tripped as opaque bytes — the VarDictionary encoder (upcoming
//! slice) will let us verify that layer too.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{FileSignature, OuterHeader, read_header_fields};

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

#[test]
fn every_well_formed_fixture_round_trips_outer_header() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("keepassxc"));
    kdbxs.extend(find_kdbxs(&root.join("pykeepass")));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));

    assert!(!kdbxs.is_empty(), "no fixtures found under {root:?}");

    for path in &kdbxs {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path:?}: read: {e}"));
        let sig = FileSignature::read(&bytes[..FileSignature::LEN])
            .unwrap_or_else(|e| panic!("{path:?}: signature: {e}"));
        let version = sig
            .version()
            .unwrap_or_else(|e| panic!("{path:?}: version: {e}"));
        let width = version.header_length_width();

        let mut cursor = &bytes[FileSignature::LEN..];
        let (fields, _end) = read_header_fields(&mut cursor, width)
            .unwrap_or_else(|e| panic!("{path:?}: TLV read: {e}"));
        let original = OuterHeader::parse(&fields, version)
            .unwrap_or_else(|e| panic!("{path:?}: typed parse: {e}"));

        let rewritten = original
            .write()
            .unwrap_or_else(|e| panic!("{path:?}: write: {e}"));

        let mut cursor2 = rewritten.as_slice();
        let (fields2, end2) = read_header_fields(&mut cursor2, width)
            .unwrap_or_else(|e| panic!("{path:?}: re-read TLV: {e}"));
        assert!(cursor2.is_empty(), "{path:?}: writer over-emitted");
        assert!(end2.is_end(), "{path:?}: missing end-of-header sentinel");
        let reparsed = OuterHeader::parse(&fields2, version)
            .unwrap_or_else(|e| panic!("{path:?}: typed re-parse: {e}"));

        assert_eq!(reparsed.version, original.version, "{path:?}: version");
        assert_eq!(
            reparsed.cipher_id, original.cipher_id,
            "{path:?}: cipher_id"
        );
        assert_eq!(
            reparsed.compression, original.compression,
            "{path:?}: compression"
        );
        assert_eq!(
            reparsed.master_seed, original.master_seed,
            "{path:?}: master_seed"
        );
        assert_eq!(
            reparsed.encryption_iv, original.encryption_iv,
            "{path:?}: encryption_iv"
        );
        assert_eq!(
            reparsed.transform_seed, original.transform_seed,
            "{path:?}: transform_seed"
        );
        assert_eq!(
            reparsed.transform_rounds, original.transform_rounds,
            "{path:?}: transform_rounds"
        );
        assert_eq!(
            reparsed.protected_stream_key, original.protected_stream_key,
            "{path:?}: protected_stream_key"
        );
        assert_eq!(
            reparsed.stream_start_bytes, original.stream_start_bytes,
            "{path:?}: stream_start_bytes"
        );
        assert_eq!(
            reparsed.inner_stream_algorithm, original.inner_stream_algorithm,
            "{path:?}: inner_stream_algorithm"
        );
        assert_eq!(
            reparsed.kdf_parameters, original.kdf_parameters,
            "{path:?}: kdf_parameters"
        );
        assert_eq!(
            reparsed.public_custom_data, original.public_custom_data,
            "{path:?}: public_custom_data"
        );
    }
}
