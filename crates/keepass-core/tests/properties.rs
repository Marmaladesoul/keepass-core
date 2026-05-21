//! Property-based round-trip invariants for the format and crypto layers.
//!
//! These exist to pin the read/write symmetry that AGENTS.md calls out
//! as a project rule: "every decoder change ships with an encoder test
//! that round-trips the same shape, and vice versa." Example-based
//! tests next to each module already cover the obvious shapes; the
//! generators here exercise widths, edge lengths, and value mixes that
//! example-based tests don't reach.
//!
//! Defaults to 64 cases per property — enough to flush shape-invariant
//! bugs in CI on every PR without bloating the macOS runtime. Run more
//! locally with `PROPTEST_CASES=2048 cargo test -p keepass-core
//! --test properties`.
//!
//! Scope is deliberately limited to the layers that don't run the KDF —
//! a vault-level save→open round-trip would burn an Argon2 derivation
//! per case (~1s) and isn't a good fit for generative testing. The
//! existing fixture-driven `kdbx_save_to_bytes` test already covers
//! that path end-to-end.

use keepass_core::crypto::{InnerStreamCipher, derive_hmac_base_key};
use keepass_core::format::{
    InnerStreamAlgorithm, LengthWidth, MasterSeed, TlvField, VarDictionary, VarValue,
    hashed_block_stream, hmac_block_stream, read_header_fields, write_header_fields,
};
use keepass_core::secret::TransformedKey;
use proptest::collection::{btree_map, vec};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// TLV (outer-header records)
// ---------------------------------------------------------------------------

/// Generate `(tag, payload)` pairs where the tag is non-zero (zero is
/// the end-of-header sentinel, which the writer emits separately).
///
/// Payload size is capped at 4 KiB so the test suite doesn't burn time
/// on multi-megabyte allocations — nothing about TLV framing changes
/// past that boundary, and the per-block-size-bound tests below
/// exercise the large-payload axis explicitly.
fn tlv_record() -> impl Strategy<Value = (u8, Vec<u8>)> {
    (1u8..=255, vec(any::<u8>(), 0..=4096))
}

/// Strategy for the length-prefix width — KDBX3 uses u16, KDBX4 uses u32.
fn any_length_width() -> impl Strategy<Value = LengthWidth> {
    prop_oneof![Just(LengthWidth::U16), Just(LengthWidth::U32)]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// TLV records survive write→read for both KDBX3 (u16 length) and
    /// KDBX4 (u32 length) framings, regardless of payload size and
    /// record count. Caps record payloads at 65 535 for the u16 path
    /// since that's the format's hard limit.
    #[test]
    fn tlv_roundtrips(
        width in any_length_width(),
        records in vec(tlv_record(), 0..16),
        end_payload in vec(any::<u8>(), 0..=64),
    ) {
        // u16 width can't represent payloads ≥ 65 536. Filter rather
        // than panic so the strategy stays simple.
        if matches!(width, LengthWidth::U16) {
            for (_, v) in &records {
                prop_assume!(u16::try_from(v.len()).is_ok());
            }
            prop_assume!(u16::try_from(end_payload.len()).is_ok());
        }

        let fields: Vec<TlvField<'_>> =
            records.iter().map(|(t, v)| TlvField { tag: *t, value: v }).collect();
        let end = TlvField { tag: TlvField::END_OF_HEADER, value: &end_payload };

        let encoded = write_header_fields(&fields, end, width).expect("encode");
        let mut cursor: &[u8] = &encoded;
        let (decoded, decoded_end) = read_header_fields(&mut cursor, width).expect("decode");

        prop_assert!(cursor.is_empty(), "cursor should be fully consumed");
        prop_assert!(decoded_end.is_end());
        prop_assert_eq!(decoded_end.value, &end_payload[..]);
        prop_assert_eq!(decoded.len(), records.len());
        for (got, (want_tag, want_val)) in decoded.iter().zip(records.iter()) {
            prop_assert_eq!(got.tag, *want_tag);
            prop_assert_eq!(got.value, &want_val[..]);
        }
    }
}

// ---------------------------------------------------------------------------
// VarDictionary (KDBX4 KDF / custom-data blob)
// ---------------------------------------------------------------------------

/// All seven typed [`Value`] variants. Bytes/strings are size-capped at
/// 1 KiB for the same reason as TLV records — semantics don't change
/// past that and proptest shrinking is much faster on small inputs.
fn vd_value() -> impl Strategy<Value = VarValue> {
    prop_oneof![
        any::<u32>().prop_map(VarValue::U32),
        any::<u64>().prop_map(VarValue::U64),
        any::<bool>().prop_map(VarValue::Bool),
        any::<i32>().prop_map(VarValue::I32),
        any::<i64>().prop_map(VarValue::I64),
        ".{0,32}".prop_map(VarValue::String),
        vec(any::<u8>(), 0..=1024).prop_map(VarValue::Bytes),
    ]
}

/// Generate full [`VarDictionary`] values with the canonical
/// `version_major = 1, version_minor = 0` prefix (the writer doesn't
/// support emitting any other version yet).
fn vd_dictionary() -> impl Strategy<Value = VarDictionary> {
    btree_map(".{1,16}", vd_value(), 0..8).prop_map(|entries| VarDictionary {
        version_major: 1,
        version_minor: 0,
        entries,
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Arbitrary VarDictionaries round-trip losslessly through
    /// `write → parse`. Covers every typed variant and the
    /// sorted-by-key iteration order that the codec promises.
    #[test]
    fn var_dictionary_roundtrips(dict in vd_dictionary()) {
        let bytes = dict.write().expect("write");
        let parsed = VarDictionary::parse(&bytes).expect("parse");
        prop_assert_eq!(parsed.version_major, dict.version_major);
        prop_assert_eq!(parsed.version_minor, dict.version_minor);
        prop_assert_eq!(parsed.entries, dict.entries);
    }
}

// ---------------------------------------------------------------------------
// Block-stream framings (KDBX3 HashedBlockStream, KDBX4 HmacBlockStream)
// ---------------------------------------------------------------------------

/// Block sizes deliberately picked to land on a mix of "smaller than
/// the payload", "exact divisor", and "larger than the payload". The
/// per-block fields are u32-sized so anything ≤ u32::MAX is legal;
/// 1, 64, 4 KiB, and the default 1 MiB cover all the interesting
/// chunking shapes.
fn block_size() -> impl Strategy<Value = usize> {
    prop_oneof![Just(1usize), Just(64), Just(4096), Just(1024 * 1024)]
}

fn payload() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..=64 * 1024)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// KDBX3 hashed-block-stream framing round-trips losslessly for any
    /// payload + block size. Each chunk's SHA-256 is recomputed on
    /// read, so the property also guards against silent corruption.
    #[test]
    fn hashed_block_stream_roundtrips(payload in payload(), block_size in block_size()) {
        let encoded = hashed_block_stream::write_hashed_block_stream(&payload, block_size)
            .expect("encode");
        let decoded = hashed_block_stream::read_hashed_block_stream(&encoded).expect("decode");
        prop_assert_eq!(decoded, payload);
    }

    /// KDBX4 HMAC-block-stream framing round-trips losslessly for any
    /// payload + block size + base key. Per-block HMAC-SHA-256 is
    /// recomputed on read against a fresh per-block key derived from
    /// the base, so the property covers both framing and integrity.
    #[test]
    fn hmac_block_stream_roundtrips(
        payload in payload(),
        block_size in block_size(),
        key_bytes in any::<[u8; 32]>(),
    ) {
        // Derive an HmacBaseKey via the same code path the kdbx pipeline
        // uses, rather than fabricating a 64-byte blob directly — keeps
        // the property aligned with how the rest of the crate produces
        // these keys.
        let master_seed = MasterSeed(key_bytes);
        let transformed = TransformedKey::from_raw_bytes(key_bytes);
        let base = derive_hmac_base_key(&master_seed, &transformed);

        let encoded = hmac_block_stream::write_hmac_block_stream(&payload, &base, block_size)
            .expect("encode");
        let decoded = hmac_block_stream::read_hmac_block_stream(&encoded, &base).expect("decode");
        prop_assert_eq!(decoded, payload);
    }
}

// ---------------------------------------------------------------------------
// InnerStreamCipher (Salsa20 / ChaCha20 keystream)
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Stream ciphers are involutive: XOR-ing the same keystream over a
    /// buffer twice returns the original bytes. The property holds
    /// across split points too — two `process` calls that together
    /// cover the buffer should produce the same output as one call
    /// over the whole buffer.
    #[test]
    fn inner_stream_is_involutive_salsa20(
        key in any::<[u8; 32]>(),
        plaintext in vec(any::<u8>(), 0..=8192),
        split_ratio in 0u8..=255,
    ) {
        let split = if plaintext.is_empty() {
            0
        } else {
            (plaintext.len() * split_ratio as usize) / 255
        };

        // Encrypt in one shot.
        let mut a = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let mut whole = plaintext.clone();
        a.process(&mut whole);

        // Encrypt in two shots — fresh cipher with the same key, then
        // process the prefix and suffix separately.
        let mut b = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let mut split_buf = plaintext.clone();
        let (lo, hi) = split_buf.split_at_mut(split);
        b.process(lo);
        b.process(hi);

        prop_assert_eq!(&whole, &split_buf, "single-shot vs split process must match");

        // Decrypt by running the same keystream again.
        let mut c = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        c.process(&mut whole);
        prop_assert_eq!(whole, plaintext);
    }

    /// Same as above for ChaCha20. ChaCha20 derives its key+nonce by
    /// SHA-512'ing the inner-stream key and so accepts any length;
    /// the strategy uses a 64-byte key (the KeePass convention).
    #[test]
    fn inner_stream_is_involutive_chacha20(
        key in vec(any::<u8>(), 1..=64),
        plaintext in vec(any::<u8>(), 0..=8192),
    ) {
        let mut a = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        let mut buf = plaintext.clone();
        a.process(&mut buf);
        let mut b = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        b.process(&mut buf);
        prop_assert_eq!(buf, plaintext);
    }
}
