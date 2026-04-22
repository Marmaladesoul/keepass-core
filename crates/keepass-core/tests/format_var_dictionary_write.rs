//! Fixture round-trip for [`VarDictionary`] encoding.
//!
//! For every KDBX4 fixture: parse the outer header, pull the raw
//! `KdfParameters` blob (tag 11), parse it as a [`VarDictionary`],
//! re-encode via [`VarDictionary::write`], and assert that the
//! re-encoded bytes parse back to an equal dictionary.
//!
//! Byte-exactness is **not** asserted at the fixture level. kdbxweb
//! (and some pykeepass versions) emit VarDictionary entries in
//! insertion order rather than ASCII-sorted order; the writer here
//! canonicalises to sorted order because that's what BTreeMap
//! iteration yields. Byte-exact round-trip for sorted-input sources
//! is covered by the `byte_exact_round_trip_when_source_is_sorted`
//! unit test in the module.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{
    FileSignature, OuterHeader, VarDictionary, Version, read_header_fields,
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

#[test]
fn every_kdbx4_fixture_kdf_parameters_round_trips() {
    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("pykeepass"));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    // keepassxc may also have kdbx4 fixtures.
    kdbxs.extend(find_kdbxs(&root.join("keepassxc")));

    let mut saw_any = false;
    for path in &kdbxs {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("{path:?}: read: {e}"));
        let sig = FileSignature::read(&bytes[..FileSignature::LEN])
            .unwrap_or_else(|e| panic!("{path:?}: signature: {e}"));
        if sig.version().unwrap() != Version::V4 {
            continue;
        }
        saw_any = true;
        let mut cursor = &bytes[FileSignature::LEN..];
        let (fields, _end) =
            read_header_fields(&mut cursor, sig.version().unwrap().header_length_width())
                .unwrap_or_else(|e| panic!("{path:?}: TLV read: {e}"));
        let header = OuterHeader::parse(&fields, Version::V4)
            .unwrap_or_else(|e| panic!("{path:?}: typed parse: {e}"));
        let blob = header
            .kdf_parameters
            .as_ref()
            .unwrap_or_else(|| panic!("{path:?}: v4 must have KdfParameters"));

        let dict = VarDictionary::parse_consuming(blob)
            .unwrap_or_else(|e| panic!("{path:?}: VarDictionary parse: {e}"));
        let rewritten = dict
            .write()
            .unwrap_or_else(|e| panic!("{path:?}: VarDictionary write: {e}"));
        let reparsed = VarDictionary::parse_consuming(&rewritten)
            .unwrap_or_else(|e| panic!("{path:?}: re-parse: {e}"));
        assert_eq!(
            reparsed, dict,
            "{path:?}: typed round-trip of KdfParameters"
        );
    }
    assert!(saw_any, "no KDBX4 fixtures under {root:?}");
}
