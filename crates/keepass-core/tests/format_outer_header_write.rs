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

use keepass_core::format::{FileSignature, OuterHeader, VersionFields, read_header_fields};

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

        assert_eq!(reparsed.version(), original.version(), "{path:?}: version");
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
        // Version-specific fields: destructure both arms and compare each
        // disjoint field. This is the byte-identity guard — the writer must
        // reproduce every version-specific field the parse yielded.
        match (&reparsed.version_fields, &original.version_fields) {
            (
                VersionFields::V3 {
                    transform_seed: got_seed,
                    transform_rounds: got_rounds,
                    protected_stream_key: got_psk,
                    stream_start_bytes: got_ssb,
                    inner_stream_algorithm: got_algo,
                },
                VersionFields::V3 {
                    transform_seed: want_seed,
                    transform_rounds: want_rounds,
                    protected_stream_key: want_psk,
                    stream_start_bytes: want_ssb,
                    inner_stream_algorithm: want_algo,
                },
            ) => {
                assert_eq!(got_seed, want_seed, "{path:?}: transform_seed");
                assert_eq!(got_rounds, want_rounds, "{path:?}: transform_rounds");
                assert_eq!(got_psk, want_psk, "{path:?}: protected_stream_key");
                assert_eq!(got_ssb, want_ssb, "{path:?}: stream_start_bytes");
                assert_eq!(got_algo, want_algo, "{path:?}: inner_stream_algorithm");
            }
            (
                VersionFields::V4 {
                    kdf_parameters: got_kdf,
                    public_custom_data: got_pcd,
                },
                VersionFields::V4 {
                    kdf_parameters: want_kdf,
                    public_custom_data: want_pcd,
                },
            ) => {
                assert_eq!(got_kdf, want_kdf, "{path:?}: kdf_parameters");
                assert_eq!(got_pcd, want_pcd, "{path:?}: public_custom_data");
            }
            _ => panic!("{path:?}: version-fields arm mismatch across round-trip"),
        }
    }
}
