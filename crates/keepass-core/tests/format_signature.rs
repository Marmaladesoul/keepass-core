//! Integration tests for [`FileSignature`] parsing against the corpus.
//!
//! Every `.kdbx` fixture under `tests/fixtures/` is opened, its first 12
//! bytes are parsed, and the resulting [`Version`] is compared against the
//! format declared in the fixture's JSON sidecar.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::{FileSignature, FormatError, Version};

/// Path to the fixture corpus root (`tests/fixtures/` from the workspace root).
fn fixtures_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/keepass-core/ at test time.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

/// Recursively walk a directory and return every file whose extension matches.
fn find_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(find_files(&path, ext));
        } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
            out.push(path);
        }
    }
    out
}

/// Read the first N bytes of a file.
fn read_prefix(path: &Path, n: usize) -> Vec<u8> {
    let mut buf = fs::read(path).expect("read fixture");
    buf.truncate(n);
    buf
}

/// Extract the `format` string ("KDBX3" or "KDBX4") from a sidecar JSON file.
///
/// Uses a tiny hand-rolled parser so that the test crate doesn't need a
/// JSON dependency. The sidecar always emits `"format": "KDBX<n>"` with
/// stable key ordering.
fn sidecar_format(sidecar: &Path) -> String {
    let text = fs::read_to_string(sidecar).expect("read sidecar");
    let needle = "\"format\":";
    let start = text.find(needle).expect("sidecar has format") + needle.len();
    let rest = &text[start..];
    let q1 = rest.find('"').expect("open quote") + 1;
    let q2 = rest[q1..].find('"').expect("close quote");
    rest[q1..q1 + q2].to_string()
}

/// Every well-formed fixture parses and matches the format its sidecar declares.
#[test]
fn every_well_formed_fixture_parses_as_declared_version() {
    let root = fixtures_root();
    let kdbxs: Vec<_> = ["keepassxc", "pykeepass"]
        .iter()
        .flat_map(|sub| find_files(&root.join(sub), "kdbx"))
        .collect();

    assert!(
        !kdbxs.is_empty(),
        "no fixtures found — corpus missing from {root:?}"
    );

    for path in &kdbxs {
        let bytes = read_prefix(path, FileSignature::LEN);
        let sig = FileSignature::read(&bytes).unwrap_or_else(|e| panic!("{path:?}: {e}"));
        let version = sig
            .version()
            .unwrap_or_else(|e| panic!("{path:?}: unsupported version: {e}"));

        let sidecar = path.with_extension("json");
        let declared = sidecar_format(&sidecar);
        let expected = match declared.as_str() {
            "KDBX3" => Version::V3,
            "KDBX4" => Version::V4,
            other => panic!("{sidecar:?}: unknown declared format {other:?}"),
        };
        assert_eq!(
            version, expected,
            "{path:?}: parsed {version:?} but sidecar says {declared} ({sig:?})"
        );
    }
}

/// `malformed/bad-magic.kdbx` has its first four bytes zeroed; parsing must
/// fail with [`FormatError::BadSignature1`].
#[test]
fn malformed_bad_magic_rejected() {
    let path = fixtures_root().join("malformed").join("bad-magic.kdbx");
    let bytes = read_prefix(&path, FileSignature::LEN);
    let err = FileSignature::read(&bytes).expect_err("must fail");
    assert!(
        matches!(err, FormatError::BadSignature1),
        "expected BadSignature1, got {err:?}"
    );
}

/// `malformed/truncated.kdbx` is 64 bytes — enough to parse the 12-byte
/// signature prefix successfully. (Full-header parsing would fail later.)
#[test]
fn malformed_truncated_at_64_bytes_has_valid_signature() {
    let path = fixtures_root().join("malformed").join("truncated.kdbx");
    let data = fs::read(&path).expect("read");
    assert_eq!(data.len(), 64, "fixture is expected to be 64 bytes");
    let sig = FileSignature::read(&data).expect("sig parses");
    assert_eq!(sig.version().unwrap(), Version::V3); // derived from keepassxc/kdbx3-minimal
}

/// `malformed/hmac-fail.kdbx` has only its last byte munged; the signature
/// prefix is intact and should parse successfully. (The HMAC failure would
/// be caught later by block verification.)
#[test]
fn malformed_hmac_fail_has_valid_signature() {
    let path = fixtures_root().join("malformed").join("hmac-fail.kdbx");
    let bytes = read_prefix(&path, FileSignature::LEN);
    let sig = FileSignature::read(&bytes).expect("sig parses");
    assert_eq!(sig.version().unwrap(), Version::V3);
}
