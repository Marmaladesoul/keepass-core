//! Integration tests for the [`Kdbx<Sealed>`] → [`Kdbx<HeaderRead>`] pipeline
//! against the fixture corpus.
//!
//! For every `.kdbx` fixture under `tests/fixtures/`, open the bytes, verify
//! the signature classifies to a supported [`Version`], parse the outer
//! header, and sanity-check cross-cutting invariants (seeds are the right
//! length, KDBX4 files have KDF parameters, etc.).

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::format::Version;
use keepass_core::kdbx::{HeaderRead, Kdbx, Sealed};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn find_kdbx(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return out;
    }
    for entry in fs::read_dir(dir).expect("read_dir").flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(find_kdbx(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("kdbx") {
            out.push(path);
        }
    }
    out
}

/// Paths under `tests/fixtures/malformed/` are expected to fail at some
/// stage; we test them separately.
fn is_malformed(path: &Path) -> bool {
    path.components().any(|c| c.as_os_str() == "malformed")
}

#[test]
fn every_valid_fixture_passes_sealed_and_header() {
    let root = fixtures_root();
    let fixtures = find_kdbx(&root);
    assert!(!fixtures.is_empty(), "no fixtures found under {root:?}");

    let mut checked = 0;
    for path in fixtures {
        if is_malformed(&path) {
            continue;
        }

        let kdbx =
            Kdbx::<Sealed>::open(&path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
        let version = kdbx.version();
        assert!(matches!(version, Version::V3 | Version::V4));

        let kdbx = kdbx
            .read_header()
            .unwrap_or_else(|e| panic!("read_header {}: {e}", path.display()));

        // Mandatory invariants on every valid header.
        let h = kdbx.header();
        assert_eq!(h.version, version);
        assert_eq!(h.master_seed.0.len(), 32);
        assert!(!h.encryption_iv.0.is_empty());

        // KDBX4 must expose KDF parameters; KDBX3 must expose the legacy
        // transform seed + rounds in the raw field set.
        match version {
            Version::V4 => {
                assert!(
                    h.kdf_parameters.is_some(),
                    "KDBX4 fixture {} missing KDF params",
                    path.display()
                );
            }
            Version::V3 => {
                assert!(
                    h.transform_seed.is_some(),
                    "KDBX3 fixture {} missing transform seed",
                    path.display()
                );
                assert!(
                    h.transform_rounds.is_some(),
                    "KDBX3 fixture {} missing transform rounds",
                    path.display()
                );
            }
            _ => unreachable!("version is non-exhaustive but V3/V4 are the only known"),
        }

        // Payload slice must be non-empty — there's an encrypted body to
        // decrypt in a later stage.
        assert!(
            !Kdbx::<HeaderRead>::payload_bytes(&kdbx).is_empty(),
            "no payload after header in {}",
            path.display()
        );

        checked += 1;
    }
    assert!(
        checked >= 4,
        "expected at least 4 valid fixtures, got {checked}"
    );
}

#[test]
fn malformed_truncated_fixture_fails_cleanly() {
    let path = fixtures_root().join("malformed").join("truncated.kdbx");
    if !path.exists() {
        return; // optional fixture
    }
    // "truncated" might fail at open_from_bytes or at read_header, but either
    // way it must not panic.
    let result = Kdbx::<Sealed>::open(&path).and_then(Kdbx::read_header);
    assert!(
        result.is_err(),
        "truncated fixture unexpectedly parsed successfully"
    );
}

#[test]
fn malformed_bad_magic_fixture_fails_at_open() {
    let path = fixtures_root().join("malformed").join("bad-magic.kdbx");
    if !path.exists() {
        return;
    }
    let err = Kdbx::<Sealed>::open(&path).unwrap_err();
    // Should be a signature error specifically.
    assert!(
        format!("{err}").contains("signature") || format!("{err}").contains("KDBX"),
        "expected signature-related error, got: {err}"
    );
}
