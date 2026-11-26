//! End-to-end tamper-detection matrix.
//!
//! Per-block / per-record tamper tests already live next to the relevant
//! modules (`format::hmac_block_stream`, `format::hashed_block_stream`,
//! `format::header_hmac`). This integration suite catches the
//! higher-level invariant the per-module tests can't: that a single
//! byte flipped anywhere in a real KDBX file *before* unlock surfaces
//! as an integrity error, never as a silently-decoded vault.
//!
//! Coverage:
//!
//! * **KDBX4 outer header byte flip** — must fail the unkeyed header
//!   SHA-256. Surfaces as `FormatError::HeaderHashMismatch` whatever
//!   credential is supplied: the hash does not depend on the key, so
//!   reporting it distinctly from a wrong key leaks nothing.
//! * **KDBX4 stored header-hash byte flip** — same.
//! * **KDBX4 header-HMAC tag byte flip** — must fail the keyed header
//!   HMAC. Surfaces as `CryptoError::Decrypt`, collapsed with a wrong
//!   key per the §4.8.7 error-collapse rule.
//! * **KDBX4 payload block byte flip** — must fail per-block HMAC.
//!   Surfaces as `FormatError::MalformedHeader("HMAC-block tag mismatch")`
//!   (the block index is preserved internally for debugging but not
//!   leaked through the wrapping `From` impl).
//! * **KDBX4 payload truncation** — must fail either header-stage or
//!   block-stage integrity, never silently parse.
//! * **KDBX3 outer header byte flip** — CBC decrypt of a tampered
//!   header yields a wrong cipher key (the master seed is in the
//!   header), so decryption fails. Surfaces as `CryptoError::Decrypt`.
//! * **KDBX3 payload byte flip** — CBC IV pollution makes the next
//!   block unreliable, but the stream-start-bytes sentinel or PKCS7
//!   padding catches it. Surfaces as `CryptoError::Decrypt` or
//!   `FormatError::MalformedHeader`.
//!
//! The "what variant exactly" axis is deliberately a loose assertion
//! (one of a small whitelist) because the threat model only requires
//! "doesn't silently unlock" — pinning the exact variant would over-
//! constrain the integrity pipeline and turn legitimate refactors
//! into test failures.

use std::fs;
use std::path::{Path, PathBuf};

use keepass_core::crypto::CryptoError;
use keepass_core::format::FormatError;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::{CompositeKey, Error};

/// All fixtures in the corpus share this master password — see
/// `tests/fixtures/README.md`.
const FIXTURE_PASSWORD: &str = "tëst pässwörd 🔑/\\";

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn kdbx4_fixture() -> PathBuf {
    fixtures_root()
        .join("kdbxweb")
        .join("kdbx4-argon2d-p8.kdbx")
}

fn kdbx3_fixture() -> PathBuf {
    fixtures_root().join("keepassxc").join("kdbx3-minimal.kdbx")
}

fn composite() -> CompositeKey {
    CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes())
}

/// Confirm the chosen fixture unlocks cleanly before we start
/// tampering with it. Useful self-test: if the fixture or the
/// password drifts, the rest of the suite would emit confusing
/// "unlock failed" assertions when in fact tampering wasn't the
/// cause. Failing here points the finger at the right place.
fn assert_baseline_unlocks(bytes: &[u8]) {
    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.to_vec()).expect("open");
    let header = kdbx.read_header().expect("read header");
    header.unlock(&composite()).expect("baseline unlock");
}

/// Return the error from unlocking these (possibly tampered) bytes,
/// or panic if the bytes successfully unlocked — the whole point of
/// tampering tests is that they DON'T silently succeed.
fn unlock_must_fail(bytes: Vec<u8>, context: &str) -> Error {
    unlock_must_fail_with(bytes, &composite(), context)
}

/// [`unlock_must_fail`] with a caller-chosen credential.
fn unlock_must_fail_with(bytes: Vec<u8>, key: &CompositeKey, context: &str) -> Error {
    let opened = match Kdbx::<Sealed>::open_from_bytes(bytes) {
        Ok(k) => k,
        Err(e) => return e,
    };
    let header_read = match opened.read_header() {
        Ok(k) => k,
        Err(e) => return e,
    };
    match header_read.unlock(key) {
        Ok(_) => panic!("{context}: tampered file silently unlocked — integrity check is broken"),
        Err(e) => e,
    }
}

/// Common predicate: the error is one of the integrity-related
/// variants the unlock path is allowed to produce on a tampered file.
fn is_integrity_error(err: &Error) -> bool {
    matches!(
        err,
        Error::Crypto(CryptoError::Decrypt | CryptoError::HmacMismatch { .. } | CryptoError::Kdf)
            | Error::Format(
                FormatError::MalformedHeader(_)
                    | FormatError::HeaderHashMismatch
                    | FormatError::Truncated { .. }
                    | FormatError::UnsupportedVersion { .. },
            )
            | Error::Xml(_)
    )
}

fn assert_integrity_error(err: &Error, context: &str) {
    assert!(
        is_integrity_error(err),
        "{context}: expected an integrity-class error, got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// KDBX4
// ---------------------------------------------------------------------------

/// Flip one byte at a stable position inside the outer header
/// (between the signature and the end-of-header sentinel). The exact
/// position is chosen so it lands inside a TLV value rather than on
/// a tag or length byte — the header hash catches either, but a TLV
/// length flip would also be caught by the structural decoder before
/// we ever reach the hash, which is a different code path. The
/// position is verified by re-reading the header after the flip and
/// asserting it still parses.
#[test]
fn kdbx4_header_byte_flip_fails_integrity() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_end = kdbx.read_header().unwrap().header_bytes().len();
    // Pick a byte ~3/4 of the way through the header — likely inside
    // a TLV value (master seed, KDF parameters, etc.) given typical
    // KDBX4 layouts at this fixture size.
    let pos = header_end * 3 / 4;
    let mut tampered = bytes.clone();
    tampered[pos] ^= 0x01;
    Kdbx::<Sealed>::open_from_bytes(tampered.clone())
        .unwrap()
        .read_header()
        .expect("tampered header still parses");

    let err = unlock_must_fail(tampered, "kdbx4 header byte flip");
    assert!(
        matches!(err, Error::Format(FormatError::HeaderHashMismatch)),
        "kdbx4 header byte flip should surface FormatError::HeaderHashMismatch, got {err:?}"
    );
}

/// Flip one byte inside the master-seed value of the KDBX4 outer
/// header. The header still parses (only a field value changed, not a
/// tag or length), so the first check to fail is the unkeyed header
/// SHA-256. Unlocking with the *correct* credential must report a
/// damaged header, never a wrong key — and because the hash is
/// unkeyed, a wrong credential must get exactly the same answer.
#[test]
fn kdbx4_header_field_flip_is_header_hash_mismatch_not_wrong_key() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_read = kdbx.read_header().unwrap();
    let seed = header_read.header().master_seed.0;
    let seed_offset = header_read
        .header_bytes()
        .windows(seed.len())
        .position(|w| w == seed)
        .expect("master seed present in header bytes");
    let mut tampered = bytes.clone();
    tampered[seed_offset + seed.len() / 2] ^= 0x01;

    // The flip must leave the header parseable, so the failure under
    // test is the hash check rather than the structural decoder.
    Kdbx::<Sealed>::open_from_bytes(tampered.clone())
        .unwrap()
        .read_header()
        .expect("tampered header still parses");

    let err = unlock_must_fail(tampered.clone(), "kdbx4 master-seed flip");
    assert!(
        !matches!(err, Error::Crypto(CryptoError::Decrypt)),
        "kdbx4 master-seed flip with the correct key must not look like a wrong key, got {err:?}"
    );
    assert!(
        matches!(err, Error::Format(FormatError::HeaderHashMismatch)),
        "kdbx4 master-seed flip should surface FormatError::HeaderHashMismatch, got {err:?}"
    );

    let wrong = CompositeKey::from_password(b"definitely not the fixture password");
    let err = unlock_must_fail_with(tampered, &wrong, "kdbx4 master-seed flip, wrong key");
    assert!(
        matches!(err, Error::Format(FormatError::HeaderHashMismatch)),
        "header-hash verdict must not depend on the credential, got {err:?}"
    );
}

/// Flip one byte inside the stored 32-byte header SHA-256 (the bytes
/// immediately after the outer header). The header itself is intact,
/// but it no longer matches its stored hash: same verdict as a damaged
/// header.
#[test]
fn kdbx4_stored_header_hash_flip_is_header_hash_mismatch() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_end = kdbx.read_header().unwrap().header_bytes().len();
    let mut tampered = bytes.clone();
    tampered[header_end + 5] ^= 0x01;

    let err = unlock_must_fail(tampered, "kdbx4 stored header-hash flip");
    assert!(
        matches!(err, Error::Format(FormatError::HeaderHashMismatch)),
        "kdbx4 stored header-hash flip should surface FormatError::HeaderHashMismatch, got {err:?}"
    );
}

/// The unkeyed header hash is verified *before* the KDF runs, so an
/// accidentally damaged header fails without paying for a key
/// derivation driven by its damaged parameters. (A deliberately crafted
/// header can recompute the hash; the parse-time KDF ceilings bound
/// that case, not this check.)
///
/// The tamper rewrites the Argon2 memory value to 8 KiB: it passes the
/// parse-time parameter ceilings, but Argon2 itself rejects it for this
/// fixture's parallelism (it needs at least 8 KiB per lane). So if the
/// KDF ran first, unlock would fail with `CryptoError::Kdf`; only a
/// hash check that runs first can report `HeaderHashMismatch`. The
/// value is chosen to make the KDF fail cheaply rather than allocate a
/// huge matrix, so an ordering regression fails this test instead of
/// exhausting the test host's memory.
#[test]
fn kdbx4_header_hash_is_checked_before_kdf() {
    use keepass_core::crypto::derive_transformed_key;
    use keepass_core::format::KdfParams;

    const ARGON2_MIN_MEMORY_BYTES: u64 = 8 * 1024;
    // VarDictionary record for the Argon2 memory parameter: UInt64 type
    // byte, key length 1, key "M", value length 8.
    const MEMORY_RECORD_PREFIX: [u8; 10] = [0x05, 1, 0, 0, 0, b'M', 8, 0, 0, 0];

    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_bytes = kdbx.read_header().unwrap().header_bytes().to_vec();
    let value_offset = header_bytes
        .windows(MEMORY_RECORD_PREFIX.len())
        .position(|w| w == MEMORY_RECORD_PREFIX)
        .expect("Argon2 memory record present in header")
        + MEMORY_RECORD_PREFIX.len();
    let mut tampered = bytes.clone();
    tampered[value_offset..value_offset + 8]
        .copy_from_slice(&ARGON2_MIN_MEMORY_BYTES.to_le_bytes());

    // Premise: the tampered parameters parse, and the KDF rejects them.
    let tampered_read = Kdbx::<Sealed>::open_from_bytes(tampered.clone())
        .unwrap()
        .read_header()
        .expect("tampered header still parses");
    let params = tampered_read
        .header()
        .decode_kdf_params()
        .expect("tampered KDF parameters pass the parse-time ceilings");
    assert!(
        matches!(params, KdfParams::Argon2 { memory_bytes, .. } if memory_bytes == ARGON2_MIN_MEMORY_BYTES),
        "tamper did not land on the Argon2 memory value: {params:?}"
    );
    assert!(
        derive_transformed_key(&composite(), &params).is_err(),
        "premise: the KDF must reject the tampered parameters"
    );

    let err = unlock_must_fail(tampered, "kdbx4 Argon2 memory tamper");
    assert!(
        matches!(err, Error::Format(FormatError::HeaderHashMismatch)),
        "header hash must be verified before the KDF runs, got {err:?}"
    );
}

/// Control: a wrong credential on an intact KDBX4 file is reported as
/// `CryptoError::Decrypt` (via the keyed header HMAC), not as header
/// damage.
#[test]
fn kdbx4_wrong_key_on_intact_file_is_decrypt() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let wrong = CompositeKey::from_password(b"definitely not the fixture password");
    let err = unlock_must_fail_with(bytes, &wrong, "kdbx4 wrong key");
    assert!(
        matches!(err, Error::Crypto(CryptoError::Decrypt)),
        "kdbx4 wrong key should surface CryptoError::Decrypt, got {err:?}"
    );
}

/// Flip one byte inside the 32-byte header-HMAC tag (the 32 bytes
/// after the stored header SHA-256). Even with an
/// untouched header, the verifier must reject the tag.
#[test]
fn kdbx4_header_hmac_tag_byte_flip_fails_integrity() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_end = kdbx.read_header().unwrap().header_bytes().len();
    // KDBX4 layout: [outer header][32-byte header SHA-256][32-byte header HMAC][blocks].
    // Flip a byte inside the HMAC tag region.
    let pos = header_end + 32 + 7;
    let mut tampered = bytes.clone();
    tampered[pos] ^= 0x01;

    let err = unlock_must_fail(tampered, "kdbx4 header-HMAC tag flip");
    // This one we can pin tightly: header HMAC failure is mapped to
    // CryptoError::Decrypt at the kdbx.rs call site (the error-collapse
    // rule). If the mapping drifts, the user-facing oracle resistance
    // is at risk and we want to know.
    assert!(
        matches!(err, Error::Crypto(CryptoError::Decrypt)),
        "kdbx4 header-HMAC tag flip should surface CryptoError::Decrypt, got {err:?}"
    );
}

/// Flip one byte deep inside a payload HMAC block. The per-block
/// verifier should reject the block.
#[test]
fn kdbx4_payload_byte_flip_fails_integrity() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_end = kdbx.read_header().unwrap().header_bytes().len();
    // First block payload starts at header_end + 32 (header hash) + 32
    // (header HMAC) + 32 (block-0 HMAC tag) + 4 (block-0 size). Flip
    // a byte well inside block-0 data.
    let pos = header_end + 64 + 32 + 4 + 16;
    assert!(pos < bytes.len(), "fixture is too small for this offset");
    let mut tampered = bytes.clone();
    tampered[pos] ^= 0x80;

    let err = unlock_must_fail(tampered, "kdbx4 payload byte flip");
    assert_integrity_error(&err, "kdbx4 payload byte flip");
}

/// Drop the last byte. The HMAC-block stream's end marker (last
/// 32-byte tag + 4-byte zero size) is now truncated; the verifier
/// must catch it.
#[test]
fn kdbx4_truncation_fails_integrity() {
    let bytes = fs::read(kdbx4_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let mut tampered = bytes.clone();
    tampered.pop();

    let err = unlock_must_fail(tampered, "kdbx4 truncation");
    assert_integrity_error(&err, "kdbx4 truncation");
}

// ---------------------------------------------------------------------------
// KDBX3
// ---------------------------------------------------------------------------

/// Flip one byte inside the KDBX3 outer header. KDBX3 has no
/// per-header HMAC — the tamper is caught indirectly because the
/// master seed lives in the header, so the derived cipher key
/// becomes wrong and CBC decryption produces garbage. The garbage
/// either fails PKCS7 padding (`CryptoError::Decrypt`) or fails the
/// stream-start-bytes sentinel (`FormatError::MalformedHeader`).
#[test]
fn kdbx3_header_byte_flip_fails_integrity() {
    let bytes = fs::read(kdbx3_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_bytes = kdbx.read_header().unwrap().header_bytes().to_vec();
    // Flip somewhere inside the master seed / transform seed region
    // — the exact byte doesn't matter, both alter the derived key.
    let pos = header_bytes.len() / 2;
    let mut tampered = bytes.clone();
    tampered[pos] ^= 0x01;

    let err = unlock_must_fail(tampered, "kdbx3 header byte flip");
    assert_integrity_error(&err, "kdbx3 header byte flip");
}

/// Flip one byte inside the KDBX3 payload. The CBC decryption garbles
/// the surrounding block, and either the stream-start-bytes sentinel
/// or the hashed-block stream's per-block SHA-256 catches it.
#[test]
fn kdbx3_payload_byte_flip_fails_integrity() {
    let bytes = fs::read(kdbx3_fixture()).expect("read fixture");
    assert_baseline_unlocks(&bytes);

    let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes.clone()).unwrap();
    let header_end = kdbx.read_header().unwrap().header_bytes().len();
    // Flip a byte well inside the encrypted payload.
    let pos = header_end + 64;
    assert!(pos < bytes.len(), "fixture is too small for this offset");
    let mut tampered = bytes.clone();
    tampered[pos] ^= 0x80;

    let err = unlock_must_fail(tampered, "kdbx3 payload byte flip");
    assert_integrity_error(&err, "kdbx3 payload byte flip");
}
