//! Integration tests: run the real KDF against every fixture.
//!
//! For each well-formed fixture we:
//!   1. Read its sidecar to get the master password.
//!   2. Build a `CompositeKey` from that password.
//!   3. Parse the outer header and decode `KdfParams`.
//!   4. Run `derive_transformed_key` and assert we get a deterministic
//!      32-byte output.
//!
//! We don't yet have a reference "expected" transformed key per fixture
//! (that would require a third-party re-run and pinning the bytes); the
//! assertion here is structural: each fixture's KDF parameters are valid
//! enough that the derivation *completes* and returns 32 bytes, and a
//! second call with the same inputs yields identical bytes.
//!
//! Once we land outer-payload decryption, the transformed key will be
//! implicitly validated by "the payload decrypts correctly" — the
//! strongest test of all.

#![allow(clippy::unnecessary_debug_formatting)]

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::crypto::derive_transformed_key;
use keepass_core::format::{FileSignature, OuterHeader, read_header_fields};
use keepass_core::secret::CompositeKey;

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

/// Pull the `master_password` string out of the sidecar JSON with a
/// hand-rolled tiny parser (avoids a JSON dep in the test crate).
fn sidecar_password(kdbx: &Path) -> String {
    let sidecar = kdbx.with_extension("json");
    let text = fs::read_to_string(&sidecar)
        .unwrap_or_else(|e| panic!("{sidecar:?}: {e}"));
    // Sidecars have "master_password": "..." with sorted keys.
    let needle = "\"master_password\":";
    let i = text.find(needle).unwrap_or_else(|| {
        panic!("{sidecar:?}: missing master_password key")
    }) + needle.len();
    let after = &text[i..];
    // null is allowed (no password) but our corpus doesn't use it.
    let open = after.find('"').expect("open quote");
    let rest = &after[open + 1..];
    let close = rest.find('"').expect("close quote");
    rest[..close].to_owned()
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

/// Run the KDF against every KDBX4 fixture with **override parameters**
/// so the test is fast even in debug builds. We take each fixture's real
/// `KdfParams` shape (variant, salt, version) and replace iterations /
/// memory / parallelism with minimum-cost values. This exercises the
/// real decode-then-derive pipeline on real on-disk data without paying
/// the fixture's actual KDF cost on every CI run.
///
/// The real per-fixture KDF runtime is covered by
/// [`full_cost_kdf_against_every_fixture`] below, gated with `#[ignore]`.
#[test]
fn kdf_runs_end_to_end_against_every_fixture() {
    use keepass_core::format::{Argon2Version, KdfParams};

    let root = fixtures_root();
    let mut kdbxs: Vec<_> = find_kdbxs(&root.join("pykeepass"));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    assert!(!kdbxs.is_empty(), "no KDBX4 fixtures found");

    for path in kdbxs {
        let header = parse_outer_header(&path);
        let real = header
            .decode_kdf_params()
            .unwrap_or_else(|e| panic!("{path:?}: decode_kdf_params: {e}"));
        // Override iterations / memory / parallelism to minimum-cost values.
        // `KdfParams` is #[non_exhaustive]; handle the two known variants
        // and panic on any future-added one we haven't thought about.
        let fast = match real {
            KdfParams::Argon2 { variant, salt, .. } => KdfParams::Argon2 {
                variant,
                salt,
                iterations: 2,
                memory_bytes: 8 * 1024,
                parallelism: 1,
                version: Argon2Version::V13,
            },
            KdfParams::AesKdf { seed, .. } => KdfParams::AesKdf { seed, rounds: 100 },
            other => panic!("unhandled KdfParams variant: {other:?}"),
        };

        let pw = sidecar_password(&path);
        let composite = CompositeKey::from_password(pw.as_bytes());

        let k1 = derive_transformed_key(&composite, &fast)
            .unwrap_or_else(|e| panic!("{path:?}: KDF: {e}"));
        let k2 = derive_transformed_key(&composite, &fast)
            .unwrap_or_else(|e| panic!("{path:?}: KDF (second run): {e}"));
        assert_eq!(
            k1.as_bytes(),
            k2.as_bytes(),
            "{path:?}: KDF must be deterministic"
        );
        assert_eq!(k1.as_bytes().len(), 32);
    }
}

/// Exercise the AES-KDF pipeline against a KDBX3 fixture but override the
/// round count to something tractable in debug (100 rounds) — just to
/// prove the code path works on real fixture shape without the real 6M-
/// rounds cost. Full-rounds verification lives in the `#[ignore]`d test
/// below.
#[test]
fn aes_kdf_code_path_runs_on_kdbx3_shape() {
    use keepass_core::format::KdfParams;
    let path = fixtures_root()
        .join("keepassxc")
        .join("kdbx3-minimal.kdbx");
    if !path.exists() {
        return; // corpus not present in this build
    }
    let header = parse_outer_header(&path);
    let params = match header.decode_kdf_params().unwrap() {
        KdfParams::AesKdf { seed, .. } => KdfParams::AesKdf { seed, rounds: 100 },
        other => panic!("{path:?}: expected AesKdf, got {other:?}"),
    };
    let pw = sidecar_password(&path);
    let composite = CompositeKey::from_password(pw.as_bytes());
    let k = derive_transformed_key(&composite, &params).unwrap();
    assert_eq!(k.as_bytes().len(), 32);
}

/// Full-cost KDF against every fixture, at each fixture's real parameters.
/// Ignored by default because:
///
/// - KDBX3 (`keepassxc-cli` default): AES-KDF with ~6M rounds — ~10-30 s
///   per fixture in debug.
/// - KDBX4 (`pykeepass` default):    Argon2 with 64 MiB memory / 14
///   iterations — ~1 s per fixture.
///
/// Run locally to verify the real pipeline end-to-end:
///
/// ```text
/// cargo test --release -- --ignored full_cost_kdf
/// ```
#[test]
#[ignore = "slow — runs each fixture's real-cost KDF"]
fn full_cost_kdf_against_every_fixture() {
    let root = fixtures_root();
    let mut kdbxs = find_kdbxs(&root.join("keepassxc"));
    kdbxs.extend(find_kdbxs(&root.join("pykeepass")));
    kdbxs.extend(find_kdbxs(&root.join("kdbxweb")));
    for path in kdbxs {
        let header = parse_outer_header(&path);
        let params = header.decode_kdf_params().unwrap();
        let pw = sidecar_password(&path);
        let composite = CompositeKey::from_password(pw.as_bytes());
        let k = derive_transformed_key(&composite, &params).unwrap();
        assert_eq!(k.as_bytes().len(), 32);
    }
}
