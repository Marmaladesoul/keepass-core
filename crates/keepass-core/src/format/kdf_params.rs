//! Typed key-derivation-function parameters.
//!
//! [`KdfParams`] is the domain-modelled form of the KDF configuration that
//! KDBX files carry:
//!
//! - **KDBX3** stores `TransformSeed` (tag 5) and `TransformRounds` (tag 6)
//!   in the outer header as its AES-KDF parameters.
//! - **KDBX4** stores a [`VarDictionary`] under `KdfParameters` (tag 11); the
//!   `$UUID` key identifies which KDF family applies and the other keys
//!   carry the family-specific parameters.
//!
//! This module is **parsing only** — no cryptography happens here. Turning
//! a [`KdfParams`] into an actual transformed key is the next layer up.
//!
//! ## KDF identification
//!
//! KDBX identifies KDF families by UUID. Three are defined:
//!
//! | UUID (hex-groups)                          | KDF        |
//! |--------------------------------------------|------------|
//! | `c9d9f39a-628a-4460-bf74-0d08c18a4fea`     | AES-KDF    |
//! | `ef636ddf-8c29-444b-91f7-a9a403e30a0c`     | Argon2d    |
//! | `9e298b19-56db-4773-b23d-fc3ec6f0a1e6`     | Argon2id   |

use std::fmt;

use thiserror::Error;
use uuid::Uuid;

use super::var_dictionary::{Value as VarValue, VarDictionary, VarDictionaryError};

// ---------------------------------------------------------------------------
// UUIDs identifying KDF families
// ---------------------------------------------------------------------------

/// Newtype wrapping the 16-byte UUID that identifies a KDF family.
///
/// Prefer [`KdfId::well_known`] to classify a value into one of the
/// supported families. Equivalent to [`crate::format::CipherId`] in spirit
/// but for the KDF selector.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct KdfId(pub Uuid);

impl KdfId {
    /// AES-KDF: repeated AES-256-ECB transforms. KDBX3 default; also legal
    /// in KDBX4.
    pub const AES_KDF: Uuid = Uuid::from_bytes([
        0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f,
        0xea,
    ]);
    /// Argon2d: the Argon2 variant optimised for resistance against GPU
    /// cracking attacks. KDBX4 default.
    pub const ARGON2D: Uuid = Uuid::from_bytes([
        0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a,
        0x0c,
    ]);
    /// Argon2id: the hybrid variant resistant to both side-channel and GPU
    /// attacks. Available in KDBX4 clients from ~2019 onwards.
    pub const ARGON2ID: Uuid = Uuid::from_bytes([
        0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1,
        0xe6,
    ]);

    /// Classify this UUID into one of the supported KDF families, or
    /// `None` if unknown.
    #[must_use]
    pub fn well_known(self) -> Option<KnownKdf> {
        match self.0 {
            u if u == Self::AES_KDF => Some(KnownKdf::AesKdf),
            u if u == Self::ARGON2D => Some(KnownKdf::Argon2d),
            u if u == Self::ARGON2ID => Some(KnownKdf::Argon2id),
            _ => None,
        }
    }
}

impl fmt::Debug for KdfId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.well_known() {
            Some(kdf) => write!(f, "KdfId({kdf:?} / {})", self.0),
            None => write!(f, "KdfId(unknown / {})", self.0),
        }
    }
}

/// Known KDF families. `#[non_exhaustive]` so future KDFs can be added
/// without a semver break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownKdf {
    /// AES-KDF — repeated AES-256-ECB transforms. KDBX3 default.
    AesKdf,
    /// Argon2d.
    Argon2d,
    /// Argon2id.
    Argon2id,
}

// ---------------------------------------------------------------------------
// Argon2 variant + version
// ---------------------------------------------------------------------------

/// Argon2 family member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Argon2Variant {
    /// Argon2d — data-dependent, GPU-resistant, time-memory tradeoff hard.
    /// Vulnerable to side-channel attacks, so inappropriate for shared
    /// hardware. Used when the attacker is assumed offline.
    Argon2d,
    /// Argon2id — hybrid of Argon2d and Argon2i; first half Argon2i (side-
    /// channel resistant) and second half Argon2d (cracking resistant).
    /// Recommended default for password hashing.
    Argon2id,
}

/// Argon2 algorithm version byte, as encoded in the KDBX VarDictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Argon2Version {
    /// Argon2 v1.0 (value 0x10).
    V10,
    /// Argon2 v1.3 (value 0x13) — current.
    V13,
}

impl Argon2Version {
    /// The on-disk byte encoding per the Argon2 / KDBX4 spec.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::V10 => 0x10,
            Self::V13 => 0x13,
        }
    }

    fn from_u32(raw: u32) -> Result<Self, KdfParamsError> {
        match raw {
            0x10 => Ok(Self::V10),
            0x13 => Ok(Self::V13),
            other => Err(KdfParamsError::UnsupportedArgon2Version(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// The main typed enum
// ---------------------------------------------------------------------------

/// Typed key-derivation parameters — a flattened, validated view over a
/// KDBX4 [`VarDictionary`] (or the v3 outer-header fields).
///
/// Construct via [`Self::from_var_dictionary`] for KDBX4, or via the
/// direct constructors for v3.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfParams {
    /// Legacy AES-KDF (KDBX3 default). Transformed key is obtained by
    /// `rounds` successive AES-256-ECB encryptions of the composite key
    /// under `seed`, then SHA-256 of the result.
    AesKdf {
        /// 32-byte transform seed.
        seed: [u8; 32],
        /// Number of AES transformation rounds. Modern KeePassXC uses
        /// ~6 million.
        rounds: u64,
    },
    /// Argon2 (either Argon2d or Argon2id).
    Argon2 {
        /// Which Argon2 variant.
        variant: Argon2Variant,
        /// Salt bytes (spec requires ≥ 8 bytes; 32 bytes is typical).
        salt: Vec<u8>,
        /// Number of passes (iterations).
        iterations: u64,
        /// Memory cost in **bytes** (the on-disk unit; convert to KiB
        /// before passing to an Argon2 implementation).
        memory_bytes: u64,
        /// Parallelism (threads). Usually 1 in a desktop client.
        parallelism: u32,
        /// Algorithm version.
        version: Argon2Version,
    },
}

impl KdfParams {
    /// Decode typed KDF parameters from a parsed KDBX4
    /// [`VarDictionary`] (the `KdfParameters` header blob).
    ///
    /// # Errors
    ///
    /// Returns [`KdfParamsError`] if the `$UUID` identifier is missing or
    /// unknown, or if any of the per-family required keys are missing, of
    /// the wrong type, or out of range.
    pub fn from_var_dictionary(dict: &VarDictionary) -> Result<Self, KdfParamsError> {
        let uuid_bytes = match dict.get("$UUID") {
            Some(VarValue::Bytes(b)) => b,
            Some(_) => return Err(KdfParamsError::InvalidValue { key: "$UUID", expected: "bytes" }),
            None => return Err(KdfParamsError::Missing("$UUID")),
        };
        let uuid_array: [u8; 16] = uuid_bytes.as_slice().try_into().map_err(|_| {
            KdfParamsError::InvalidLength {
                key: "$UUID",
                expected: 16,
                got: uuid_bytes.len(),
            }
        })?;
        let kdf_id = KdfId(Uuid::from_bytes(uuid_array));
        match kdf_id.well_known() {
            Some(KnownKdf::AesKdf) => decode_aes_kdf(dict),
            Some(KnownKdf::Argon2d) => decode_argon2(dict, Argon2Variant::Argon2d),
            Some(KnownKdf::Argon2id) => decode_argon2(dict, Argon2Variant::Argon2id),
            None => Err(KdfParamsError::UnknownKdfUuid(kdf_id.0)),
        }
    }

    /// Classify this `KdfParams` into the corresponding [`KnownKdf`] family.
    #[must_use]
    pub fn family(&self) -> KnownKdf {
        match self {
            Self::AesKdf { .. } => KnownKdf::AesKdf,
            Self::Argon2 { variant: Argon2Variant::Argon2d, .. } => KnownKdf::Argon2d,
            Self::Argon2 { variant: Argon2Variant::Argon2id, .. } => KnownKdf::Argon2id,
        }
    }
}

fn decode_aes_kdf(dict: &VarDictionary) -> Result<KdfParams, KdfParamsError> {
    // S = seed (32 bytes)
    let seed_bytes = dict
        .get_bytes("S")
        .ok_or(KdfParamsError::Missing("S"))?;
    let seed: [u8; 32] = seed_bytes.try_into().map_err(|_| KdfParamsError::InvalidLength {
        key: "S",
        expected: 32,
        got: seed_bytes.len(),
    })?;
    // R = rounds (u64)
    let rounds = dict
        .get_u64("R")
        .ok_or(KdfParamsError::Missing("R"))?;
    Ok(KdfParams::AesKdf { seed, rounds })
}

fn decode_argon2(
    dict: &VarDictionary,
    variant: Argon2Variant,
) -> Result<KdfParams, KdfParamsError> {
    // S = salt (bytes, any length ≥ 8 per the Argon2 spec)
    let salt_bytes = dict
        .get_bytes("S")
        .ok_or(KdfParamsError::Missing("S"))?;
    if salt_bytes.len() < 8 {
        return Err(KdfParamsError::InvalidLength {
            key: "S",
            expected: 8, // minimum
            got: salt_bytes.len(),
        });
    }
    let salt = salt_bytes.to_vec();

    // I = iterations (u64), > 0
    let iterations = dict.get_u64("I").ok_or(KdfParamsError::Missing("I"))?;
    if iterations == 0 {
        return Err(KdfParamsError::OutOfRange {
            key: "I",
            detail: "iterations must be > 0",
        });
    }

    // M = memory in bytes (u64), ≥ 8 KiB
    let memory_bytes = dict.get_u64("M").ok_or(KdfParamsError::Missing("M"))?;
    if memory_bytes < 8 * 1024 {
        return Err(KdfParamsError::OutOfRange {
            key: "M",
            detail: "memory must be ≥ 8 KiB (8192 bytes)",
        });
    }

    // P = parallelism (u32), > 0
    let parallelism = dict.get_u32("P").ok_or(KdfParamsError::Missing("P"))?;
    if parallelism == 0 {
        return Err(KdfParamsError::OutOfRange {
            key: "P",
            detail: "parallelism must be > 0",
        });
    }

    // V = Argon2 version (u32)
    let version_raw = dict.get_u32("V").ok_or(KdfParamsError::Missing("V"))?;
    let version = Argon2Version::from_u32(version_raw)?;

    Ok(KdfParams::Argon2 {
        variant,
        salt,
        iterations,
        memory_bytes,
        parallelism,
        version,
    })
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for typed-KDF-parameter parsing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KdfParamsError {
    /// A mandatory key was not present in the dictionary.
    #[error("missing KDF parameter key {0:?}")]
    Missing(&'static str),

    /// A key was present but with the wrong value type for its KDF family.
    #[error("KDF parameter {key:?} has wrong type (expected {expected})")]
    InvalidValue {
        /// The key whose value was of the wrong type.
        key: &'static str,
        /// The type that was expected.
        expected: &'static str,
    },

    /// A byte-array value had the wrong length (or was outside an allowed
    /// range).
    #[error("KDF parameter {key:?} has wrong length: expected {expected}, got {got}")]
    InvalidLength {
        /// The key whose value was of the wrong length.
        key: &'static str,
        /// Expected length in bytes (or minimum acceptable).
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// A numeric value fell outside the acceptable range for its parameter.
    #[error("KDF parameter {key:?} out of range: {detail}")]
    OutOfRange {
        /// The key whose value was out of range.
        key: &'static str,
        /// Human-readable detail describing the range.
        detail: &'static str,
    },

    /// The `$UUID` key identified a KDF family this crate does not implement.
    #[error("unknown KDF family UUID: {0}")]
    UnknownKdfUuid(Uuid),

    /// The Argon2 `V` field was neither 0x10 nor 0x13.
    #[error("unsupported Argon2 version 0x{0:x}")]
    UnsupportedArgon2Version(u32),

    /// Error propagated from the underlying VarDictionary decoder.
    #[error(transparent)]
    VarDictionary(#[from] VarDictionaryError),
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn dict_from<I: IntoIterator<Item = (&'static str, VarValue)>>(entries: I) -> VarDictionary {
        let mut m: BTreeMap<String, VarValue> = BTreeMap::new();
        for (k, v) in entries {
            m.insert(k.to_owned(), v);
        }
        VarDictionary {
            version_major: 1,
            version_minor: 0,
            entries: m,
        }
    }

    fn argon2d_uuid() -> Vec<u8> {
        KdfId::ARGON2D.as_bytes().to_vec()
    }

    fn argon2id_uuid() -> Vec<u8> {
        KdfId::ARGON2ID.as_bytes().to_vec()
    }

    fn aes_kdf_uuid() -> Vec<u8> {
        KdfId::AES_KDF.as_bytes().to_vec()
    }

    // --- UUID classification ---

    #[test]
    fn classifies_known_kdf_uuids() {
        assert_eq!(
            KdfId(Uuid::from_bytes(*KdfId::AES_KDF.as_bytes())).well_known(),
            Some(KnownKdf::AesKdf)
        );
        assert_eq!(
            KdfId(Uuid::from_bytes(*KdfId::ARGON2D.as_bytes())).well_known(),
            Some(KnownKdf::Argon2d)
        );
        assert_eq!(
            KdfId(Uuid::from_bytes(*KdfId::ARGON2ID.as_bytes())).well_known(),
            Some(KnownKdf::Argon2id)
        );
        assert_eq!(
            KdfId(Uuid::from_bytes([0xAAu8; 16])).well_known(),
            None
        );
    }

    #[test]
    fn kdf_id_debug_is_classifier_style() {
        let s = format!(
            "{:?}",
            KdfId(Uuid::from_bytes(*KdfId::ARGON2ID.as_bytes()))
        );
        assert!(s.contains("Argon2id"), "expected classifier in Debug: {s}");
    }

    // --- Argon2d parsing ---

    #[test]
    fn parses_argon2d_params() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2d_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 32])),
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(65_536 * 1024)),
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x13)),
        ]);
        let params = KdfParams::from_var_dictionary(&dict).unwrap();
        match params {
            KdfParams::Argon2 {
                variant: Argon2Variant::Argon2d,
                salt,
                iterations: 2,
                memory_bytes,
                parallelism: 1,
                version: Argon2Version::V13,
            } => {
                assert_eq!(salt.len(), 32);
                assert_eq!(memory_bytes, 65_536 * 1024);
            }
            other => panic!("expected Argon2d, got {other:?}"),
        }
    }

    #[test]
    fn parses_argon2id_params() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 16])),
            ("I", VarValue::U64(3)),
            ("M", VarValue::U64(1_048_576)),
            ("P", VarValue::U32(2)),
            ("V", VarValue::U32(0x13)),
        ]);
        let params = KdfParams::from_var_dictionary(&dict).unwrap();
        assert_eq!(params.family(), KnownKdf::Argon2id);
        assert!(matches!(
            params,
            KdfParams::Argon2 { variant: Argon2Variant::Argon2id, .. }
        ));
    }

    // --- AES-KDF parsing ---

    #[test]
    fn parses_aes_kdf_params() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(aes_kdf_uuid())),
            ("S", VarValue::Bytes(vec![0xCD; 32])),
            ("R", VarValue::U64(6_000_000)),
        ]);
        let params = KdfParams::from_var_dictionary(&dict).unwrap();
        match params {
            KdfParams::AesKdf { seed, rounds: 6_000_000 } => {
                assert_eq!(seed.len(), 32);
                assert!(seed.iter().all(|&b| b == 0xCD));
            }
            other => panic!("expected AesKdf, got {other:?}"),
        }
    }

    // --- Rejections ---

    #[test]
    fn rejects_missing_uuid() {
        let dict = dict_from([("I", VarValue::U64(2))]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::Missing("$UUID")
        ));
    }

    #[test]
    fn rejects_uuid_of_wrong_type() {
        let dict = dict_from([("$UUID", VarValue::U32(0))]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::InvalidValue { key: "$UUID", .. }
        ));
    }

    #[test]
    fn rejects_uuid_of_wrong_length() {
        let dict = dict_from([("$UUID", VarValue::Bytes(vec![0x00; 8]))]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::InvalidLength { key: "$UUID", expected: 16, got: 8 }
        ));
    }

    #[test]
    fn rejects_unknown_kdf_uuid() {
        let dict = dict_from([("$UUID", VarValue::Bytes(vec![0xFFu8; 16]))]);
        let err = KdfParams::from_var_dictionary(&dict).unwrap_err();
        assert!(matches!(err, KdfParamsError::UnknownKdfUuid(_)));
    }

    #[test]
    fn rejects_missing_argon2_salt() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(65_536)),
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x13)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::Missing("S")
        ));
    }

    #[test]
    fn rejects_short_argon2_salt() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xABu8; 4])), // too short
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(65_536)),
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x13)),
        ]);
        let err = KdfParams::from_var_dictionary(&dict).unwrap_err();
        assert!(matches!(
            err,
            KdfParamsError::InvalidLength { key: "S", expected: 8, got: 4 }
        ));
    }

    #[test]
    fn rejects_zero_argon2_iterations() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 16])),
            ("I", VarValue::U64(0)),
            ("M", VarValue::U64(65_536)),
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x13)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::OutOfRange { key: "I", .. }
        ));
    }

    #[test]
    fn rejects_low_argon2_memory() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 16])),
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(1024)), // 1 KiB < 8 KiB minimum
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x13)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::OutOfRange { key: "M", .. }
        ));
    }

    #[test]
    fn rejects_zero_argon2_parallelism() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 16])),
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(65_536)),
            ("P", VarValue::U32(0)),
            ("V", VarValue::U32(0x13)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::OutOfRange { key: "P", .. }
        ));
    }

    #[test]
    fn rejects_unsupported_argon2_version() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(argon2id_uuid())),
            ("S", VarValue::Bytes(vec![0xAB; 16])),
            ("I", VarValue::U64(2)),
            ("M", VarValue::U64(65_536)),
            ("P", VarValue::U32(1)),
            ("V", VarValue::U32(0x99)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::UnsupportedArgon2Version(0x99)
        ));
    }

    #[test]
    fn rejects_missing_aes_kdf_rounds() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(aes_kdf_uuid())),
            ("S", VarValue::Bytes(vec![0xCD; 32])),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::Missing("R")
        ));
    }

    #[test]
    fn rejects_wrong_length_aes_kdf_seed() {
        let dict = dict_from([
            ("$UUID", VarValue::Bytes(aes_kdf_uuid())),
            ("S", VarValue::Bytes(vec![0xCD; 16])), // should be 32
            ("R", VarValue::U64(1)),
        ]);
        assert!(matches!(
            KdfParams::from_var_dictionary(&dict).unwrap_err(),
            KdfParamsError::InvalidLength { key: "S", expected: 32, got: 16 }
        ));
    }

    #[test]
    fn argon2_version_roundtrips_to_u32() {
        assert_eq!(Argon2Version::V10.as_u32(), 0x10);
        assert_eq!(Argon2Version::V13.as_u32(), 0x13);
    }

    #[test]
    fn family_classifier() {
        assert_eq!(
            KdfParams::AesKdf { seed: [0; 32], rounds: 1 }.family(),
            KnownKdf::AesKdf
        );
        assert_eq!(
            KdfParams::Argon2 {
                variant: Argon2Variant::Argon2d,
                salt: vec![0; 16],
                iterations: 1,
                memory_bytes: 8192,
                parallelism: 1,
                version: Argon2Version::V13,
            }
            .family(),
            KnownKdf::Argon2d
        );
    }
}
