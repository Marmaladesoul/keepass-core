//! Typed outer-header fields.
//!
//! This module takes the raw [`TlvField`] records produced by
//! [`super::tlv::read_header_fields`] and decodes them into strongly-typed
//! values — [`CipherId`], [`MasterSeed`], [`EncryptionIv`], and so on —
//! which [`OuterHeader`] collects into a single struct per file.
//!
//! The TLV tag numbers are format-version-specific but overlap; the `v3`
//! and `v4` submodules of [`super`] list which tags apply per version.
//! [`OuterHeader::parse`] dispatches on [`Version`] to pick up the right
//! set of fields.

use std::fmt;

use thiserror::Error;
use uuid::Uuid;

use super::tlv::TlvField;
use super::{FormatError, Version};

// ---------------------------------------------------------------------------
// Tag numbers — shared constants
// ---------------------------------------------------------------------------

/// Canonical tag values for outer-header fields.
///
/// These are the same on KDBX3 and KDBX4, though KDBX4 retires most of the
/// 5/6/8/9/10 tags in favour of the VarDictionary-based KDF parameters
/// (tag 11).
pub mod tag {
    /// End-of-header sentinel (value bytes are ignored).
    pub const END_OF_HEADER: u8 = 0;
    /// Comment — unused in practice, rarely emitted.
    pub const COMMENT: u8 = 1;
    /// Cipher identifier — 16-byte UUID.
    pub const CIPHER_ID: u8 = 2;
    /// Compression flags — `u32` little-endian (0 = none, 1 = gzip).
    pub const COMPRESSION_FLAGS: u8 = 3;
    /// Master seed — 32 bytes.
    pub const MASTER_SEED: u8 = 4;
    /// Transform seed — 32 bytes (KDBX3 only; KDBX4 uses [`KDF_PARAMETERS`]).
    pub const TRANSFORM_SEED: u8 = 5;
    /// Transform rounds — `u64` little-endian (KDBX3 only).
    pub const TRANSFORM_ROUNDS: u8 = 6;
    /// Outer-cipher initialisation vector — 12 or 16 bytes depending on cipher.
    pub const ENCRYPTION_IV: u8 = 7;
    /// Inner-stream protection key (KDBX3 only).
    pub const PROTECTED_STREAM_KEY: u8 = 8;
    /// Stream start bytes — first 32 bytes of the decrypted stream, used as
    /// a plaintext sentinel (KDBX3 only).
    pub const STREAM_START_BYTES: u8 = 9;
    /// Inner random-stream algorithm — `u32` little-endian (KDBX3 only;
    /// values: 2 = Salsa20, 3 = ChaCha20).
    pub const INNER_RANDOM_STREAM_ID: u8 = 10;
    /// Key-derivation function parameters (KDBX4 only; VarDictionary).
    pub const KDF_PARAMETERS: u8 = 11;
    /// Public custom data (KDBX4 only; optional; VarDictionary).
    pub const PUBLIC_CUSTOM_DATA: u8 = 12;
}

// ---------------------------------------------------------------------------
// Newtypes for domain values
// ---------------------------------------------------------------------------

/// The cipher used to encrypt the outer payload. Stored as a 16-byte UUID.
///
/// Prefer [`CipherId::well_known`] to classify a value into one of the
/// canonical ciphers (AES-256-CBC, ChaCha20, Twofish-CBC).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherId(pub Uuid);

impl CipherId {
    /// KDBX default: AES-256 in CBC mode. UUID `31c1f2e6-bf71-4350-be58-05216afc5aff`.
    pub const AES256_CBC: Uuid = Uuid::from_bytes([
        0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a,
        0xff,
    ]);
    /// KDBX4 alternative: ChaCha20. UUID `d6038a2b-8b6f-4cb5-a524-339a31dbb59a`.
    pub const CHACHA20: Uuid = Uuid::from_bytes([
        0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5,
        0x9a,
    ]);
    /// Legacy: Twofish in CBC mode. UUID `ad68f29f-576f-4bb9-a36a-d47af965346c`.
    pub const TWOFISH_CBC: Uuid = Uuid::from_bytes([
        0xad, 0x68, 0xf2, 0x9f, 0x57, 0x6f, 0x4b, 0xb9, 0xa3, 0x6a, 0xd4, 0x7a, 0xf9, 0x65, 0x34,
        0x6c,
    ]);

    /// Classify this UUID as a known cipher, or `None` if unknown.
    #[must_use]
    pub fn well_known(self) -> Option<KnownCipher> {
        match self.0 {
            u if u == Self::AES256_CBC => Some(KnownCipher::Aes256Cbc),
            u if u == Self::CHACHA20 => Some(KnownCipher::ChaCha20),
            u if u == Self::TWOFISH_CBC => Some(KnownCipher::TwofishCbc),
            _ => None,
        }
    }
}

impl fmt::Debug for CipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.well_known() {
            Some(c) => write!(f, "CipherId({c:?} / {})", self.0),
            None => write!(f, "CipherId(unknown / {})", self.0),
        }
    }
}

/// Enumerated known outer ciphers, for the common case where code wants to
/// match on a cipher rather than compare UUIDs directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KnownCipher {
    /// AES-256 in CBC mode — the default, and the only cipher mandated by KDBX3.
    Aes256Cbc,
    /// ChaCha20 — an alternative available in KDBX4.
    ChaCha20,
    /// Twofish-CBC — a legacy alternative, rarely seen.
    TwofishCbc,
}

/// Payload-compression flags declared in the outer header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompressionFlags {
    /// No compression — the decrypted payload is the inner document verbatim.
    None,
    /// Gzip compression — the decrypted payload is gzipped inner document.
    Gzip,
}

impl CompressionFlags {
    fn from_u32(raw: u32) -> Result<Self, HeaderError> {
        match raw {
            0 => Ok(Self::None),
            1 => Ok(Self::Gzip),
            other => Err(HeaderError::UnknownCompression(other)),
        }
    }
}

/// The 32-byte master seed mixed into the composite key derivation.
#[derive(Clone, PartialEq, Eq)]
pub struct MasterSeed(pub [u8; 32]);

impl fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterSeed").field("len", &32).finish()
    }
}

/// Outer cipher initialisation vector — 12 bytes for ChaCha20, 16 for AES/Twofish.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptionIv(pub Vec<u8>);

impl fmt::Debug for EncryptionIv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptionIv")
            .field("len", &self.0.len())
            .finish()
    }
}

/// KDBX3-only: 32-byte transform seed used by AES-KDF.
#[derive(Clone, PartialEq, Eq)]
pub struct TransformSeed(pub [u8; 32]);

impl fmt::Debug for TransformSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransformSeed").field("len", &32).finish()
    }
}

/// KDBX3-only: 32-byte key used by the inner-stream cipher (Salsa20 / ChaCha20).
#[derive(Clone, PartialEq, Eq)]
pub struct ProtectedStreamKey(pub [u8; 32]);

impl fmt::Debug for ProtectedStreamKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedStreamKey")
            .field("len", &32)
            .finish()
    }
}

/// KDBX3-only: 32-byte sentinel written at the start of the decrypted stream,
/// used to verify that decryption succeeded.
#[derive(Clone, PartialEq, Eq)]
pub struct StreamStartBytes(pub [u8; 32]);

impl fmt::Debug for StreamStartBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamStartBytes")
            .field("len", &32)
            .finish()
    }
}

/// KDBX3-only: inner-stream cipher algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InnerStreamAlgorithm {
    /// No inner-stream protection. Rarely seen.
    None,
    /// Salsa20 — the KDBX3 default.
    Salsa20,
    /// ChaCha20 — sometimes used in KDBX3 by modern clients.
    ChaCha20,
}

impl InnerStreamAlgorithm {
    fn from_u32(raw: u32) -> Result<Self, HeaderError> {
        match raw {
            0 => Ok(Self::None),
            2 => Ok(Self::Salsa20),
            3 => Ok(Self::ChaCha20),
            other => Err(HeaderError::UnknownInnerStreamAlgorithm(other)),
        }
    }
}

// ---------------------------------------------------------------------------
// OuterHeader — the whole parsed header
// ---------------------------------------------------------------------------

/// Typed representation of the outer header.
///
/// Constructed by [`Self::parse`] from a slice of [`TlvField`] records —
/// typically the output of [`super::read_header_fields`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct OuterHeader {
    /// The KDBX major version this header is for.
    pub version: Version,
    /// Outer cipher identifier.
    pub cipher_id: CipherId,
    /// Payload compression flags.
    pub compression: CompressionFlags,
    /// 32-byte master seed.
    pub master_seed: MasterSeed,
    /// Outer-cipher initialisation vector.
    pub encryption_iv: EncryptionIv,

    // --- KDBX3-only fields -----------------------------------------------
    /// AES-KDF transform seed. Populated on KDBX3 only.
    pub transform_seed: Option<TransformSeed>,
    /// AES-KDF round count. Populated on KDBX3 only.
    pub transform_rounds: Option<u64>,
    /// Inner-stream cipher key. Populated on KDBX3 only.
    pub protected_stream_key: Option<ProtectedStreamKey>,
    /// Plaintext sentinel at the start of the decrypted stream. Populated on
    /// KDBX3 only.
    pub stream_start_bytes: Option<StreamStartBytes>,
    /// Inner-stream algorithm. Populated on KDBX3 only.
    pub inner_stream_algorithm: Option<InnerStreamAlgorithm>,

    // --- KDBX4-only fields -----------------------------------------------
    /// KDF parameters as a VarDictionary (raw bytes — parsing is a future
    /// concern). Populated on KDBX4 only.
    pub kdf_parameters: Option<Vec<u8>>,
    /// Optional public custom data as a VarDictionary (raw bytes). May appear
    /// on KDBX4 but is rarely present.
    pub public_custom_data: Option<Vec<u8>>,
}

impl OuterHeader {
    /// Build an [`OuterHeader`] from a list of TLV records.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderError`] if any mandatory field is missing, malformed
    /// (wrong length, unparseable value), or duplicated.
    //
    // The dispatch loop is straight-line per-tag decoding — splitting into
    // helpers would add indirection without clarity.
    #[allow(clippy::too_many_lines)]
    pub fn parse(fields: &[TlvField<'_>], version: Version) -> Result<Self, HeaderError> {
        let mut cipher_id: Option<CipherId> = None;
        let mut compression: Option<CompressionFlags> = None;
        let mut master_seed: Option<MasterSeed> = None;
        let mut encryption_iv: Option<EncryptionIv> = None;
        let mut transform_seed: Option<TransformSeed> = None;
        let mut transform_rounds: Option<u64> = None;
        let mut protected_stream_key: Option<ProtectedStreamKey> = None;
        let mut stream_start_bytes: Option<StreamStartBytes> = None;
        let mut inner_stream_algorithm: Option<InnerStreamAlgorithm> = None;
        let mut kdf_parameters: Option<Vec<u8>> = None;
        let mut public_custom_data: Option<Vec<u8>> = None;

        for field in fields {
            match field.tag {
                tag::COMMENT => { /* ignore */ }
                tag::CIPHER_ID => {
                    reject_duplicate(cipher_id.is_some(), field.tag)?;
                    let bytes: [u8; 16] =
                        field
                            .value
                            .try_into()
                            .map_err(|_| HeaderError::WrongLength {
                                tag: field.tag,
                                expected: 16,
                                got: field.value.len(),
                            })?;
                    cipher_id = Some(CipherId(Uuid::from_bytes(bytes)));
                }
                tag::COMPRESSION_FLAGS => {
                    reject_duplicate(compression.is_some(), field.tag)?;
                    let raw = read_u32_le(field)?;
                    compression = Some(CompressionFlags::from_u32(raw)?);
                }
                tag::MASTER_SEED => {
                    reject_duplicate(master_seed.is_some(), field.tag)?;
                    let bytes: [u8; 32] =
                        field
                            .value
                            .try_into()
                            .map_err(|_| HeaderError::WrongLength {
                                tag: field.tag,
                                expected: 32,
                                got: field.value.len(),
                            })?;
                    master_seed = Some(MasterSeed(bytes));
                }
                tag::TRANSFORM_SEED => {
                    reject_duplicate(transform_seed.is_some(), field.tag)?;
                    let bytes: [u8; 32] =
                        field
                            .value
                            .try_into()
                            .map_err(|_| HeaderError::WrongLength {
                                tag: field.tag,
                                expected: 32,
                                got: field.value.len(),
                            })?;
                    transform_seed = Some(TransformSeed(bytes));
                }
                tag::TRANSFORM_ROUNDS => {
                    reject_duplicate(transform_rounds.is_some(), field.tag)?;
                    transform_rounds = Some(read_u64_le(field)?);
                }
                tag::ENCRYPTION_IV => {
                    reject_duplicate(encryption_iv.is_some(), field.tag)?;
                    encryption_iv = Some(EncryptionIv(field.value.to_vec()));
                }
                tag::PROTECTED_STREAM_KEY => {
                    reject_duplicate(protected_stream_key.is_some(), field.tag)?;
                    let bytes: [u8; 32] =
                        field
                            .value
                            .try_into()
                            .map_err(|_| HeaderError::WrongLength {
                                tag: field.tag,
                                expected: 32,
                                got: field.value.len(),
                            })?;
                    protected_stream_key = Some(ProtectedStreamKey(bytes));
                }
                tag::STREAM_START_BYTES => {
                    reject_duplicate(stream_start_bytes.is_some(), field.tag)?;
                    let bytes: [u8; 32] =
                        field
                            .value
                            .try_into()
                            .map_err(|_| HeaderError::WrongLength {
                                tag: field.tag,
                                expected: 32,
                                got: field.value.len(),
                            })?;
                    stream_start_bytes = Some(StreamStartBytes(bytes));
                }
                tag::INNER_RANDOM_STREAM_ID => {
                    reject_duplicate(inner_stream_algorithm.is_some(), field.tag)?;
                    inner_stream_algorithm =
                        Some(InnerStreamAlgorithm::from_u32(read_u32_le(field)?)?);
                }
                tag::KDF_PARAMETERS => {
                    reject_duplicate(kdf_parameters.is_some(), field.tag)?;
                    kdf_parameters = Some(field.value.to_vec());
                }
                tag::PUBLIC_CUSTOM_DATA => {
                    reject_duplicate(public_custom_data.is_some(), field.tag)?;
                    public_custom_data = Some(field.value.to_vec());
                }
                other => return Err(HeaderError::UnknownTag(other)),
            }
        }

        // --- Mandatory fields (every version) --------------------------------
        let cipher_id = cipher_id.ok_or(HeaderError::Missing(tag::CIPHER_ID))?;
        let compression = compression.ok_or(HeaderError::Missing(tag::COMPRESSION_FLAGS))?;
        let master_seed = master_seed.ok_or(HeaderError::Missing(tag::MASTER_SEED))?;
        let encryption_iv = encryption_iv.ok_or(HeaderError::Missing(tag::ENCRYPTION_IV))?;

        // --- Version-specific mandatory fields --------------------------------
        match version {
            Version::V3 => {
                if transform_seed.is_none() {
                    return Err(HeaderError::Missing(tag::TRANSFORM_SEED));
                }
                if transform_rounds.is_none() {
                    return Err(HeaderError::Missing(tag::TRANSFORM_ROUNDS));
                }
                if protected_stream_key.is_none() {
                    return Err(HeaderError::Missing(tag::PROTECTED_STREAM_KEY));
                }
                if stream_start_bytes.is_none() {
                    return Err(HeaderError::Missing(tag::STREAM_START_BYTES));
                }
                if inner_stream_algorithm.is_none() {
                    return Err(HeaderError::Missing(tag::INNER_RANDOM_STREAM_ID));
                }
            }
            Version::V4 => {
                if kdf_parameters.is_none() {
                    return Err(HeaderError::Missing(tag::KDF_PARAMETERS));
                }
            }
        }

        Ok(Self {
            version,
            cipher_id,
            compression,
            master_seed,
            encryption_iv,
            transform_seed,
            transform_rounds,
            protected_stream_key,
            stream_start_bytes,
            inner_stream_algorithm,
            kdf_parameters,
            public_custom_data,
        })
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for typed-header parsing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HeaderError {
    /// A mandatory tag was not present in the TLV stream.
    #[error("missing mandatory header field (tag {0})")]
    Missing(u8),

    /// A tag appeared more than once.
    #[error("duplicate header field (tag {0})")]
    Duplicate(u8),

    /// A field had the wrong length for its tag.
    #[error("header field (tag {tag}) has wrong length: expected {expected}, got {got}")]
    WrongLength {
        /// The tag whose value was wrongly sized.
        tag: u8,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// A tag number outside the known set was encountered.
    #[error("unknown header tag {0}")]
    UnknownTag(u8),

    /// Compression flags had an unknown value.
    #[error("unknown compression flag value: {0}")]
    UnknownCompression(u32),

    /// Inner-stream algorithm had an unknown identifier.
    #[error("unknown inner-stream algorithm: {0}")]
    UnknownInnerStreamAlgorithm(u32),
}

// Allow wrapping into FormatError via `?` at higher layers.
impl From<HeaderError> for FormatError {
    fn from(err: HeaderError) -> Self {
        Self::MalformedHeader(match err {
            HeaderError::Missing(_) => "missing mandatory field",
            HeaderError::Duplicate(_) => "duplicate field",
            HeaderError::WrongLength { .. } => "wrong field length",
            HeaderError::UnknownTag(_) => "unknown tag",
            HeaderError::UnknownCompression(_) => "unknown compression",
            HeaderError::UnknownInnerStreamAlgorithm(_) => "unknown inner-stream algorithm",
        })
    }
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn reject_duplicate(already_set: bool, tag: u8) -> Result<(), HeaderError> {
    if already_set {
        Err(HeaderError::Duplicate(tag))
    } else {
        Ok(())
    }
}

fn read_u32_le(field: &TlvField<'_>) -> Result<u32, HeaderError> {
    let bytes: [u8; 4] = field
        .value
        .try_into()
        .map_err(|_| HeaderError::WrongLength {
            tag: field.tag,
            expected: 4,
            got: field.value.len(),
        })?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(field: &TlvField<'_>) -> Result<u64, HeaderError> {
    let bytes: [u8; 8] = field
        .value
        .try_into()
        .map_err(|_| HeaderError::WrongLength {
            tag: field.tag,
            expected: 8,
            got: field.value.len(),
        })?;
    Ok(u64::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TlvField from a tag and a value slice (test helper).
    fn f(tag: u8, value: &[u8]) -> TlvField<'_> {
        TlvField { tag, value }
    }

    fn aes_cipher_id() -> [u8; 16] {
        *CipherId::AES256_CBC.as_bytes()
    }

    fn chacha_cipher_id() -> [u8; 16] {
        *CipherId::CHACHA20.as_bytes()
    }

    #[test]
    fn classifies_known_ciphers() {
        assert_eq!(
            CipherId(Uuid::from_bytes(aes_cipher_id())).well_known(),
            Some(KnownCipher::Aes256Cbc)
        );
        assert_eq!(
            CipherId(Uuid::from_bytes(chacha_cipher_id())).well_known(),
            Some(KnownCipher::ChaCha20)
        );
        // A random UUID should be "unknown"
        assert_eq!(CipherId(Uuid::from_bytes([0xAA; 16])).well_known(), None);
    }

    #[test]
    fn cipher_id_debug_is_redacted_style() {
        let s = format!("{:?}", CipherId(Uuid::from_bytes(aes_cipher_id())));
        // Should contain the classifier, not just the UUID.
        assert!(s.contains("Aes256Cbc"), "expected classifier in Debug: {s}");
    }

    #[test]
    fn compression_roundtrips_known_values() {
        assert_eq!(
            CompressionFlags::from_u32(0).unwrap(),
            CompressionFlags::None
        );
        assert_eq!(
            CompressionFlags::from_u32(1).unwrap(),
            CompressionFlags::Gzip
        );
        assert!(matches!(
            CompressionFlags::from_u32(99).unwrap_err(),
            HeaderError::UnknownCompression(99)
        ));
    }

    // Helper: produce the small byte arrays needed by most tests. Keeping
    // these as locals ensures their lifetimes outlive the borrow'd TlvField.
    struct V4Scaffold {
        aes: [u8; 16],
        comp_none: [u8; 4],
        comp_gzip: [u8; 4],
        iv16: [u8; 16],
        iv12: [u8; 12],
        seed32: [u8; 32],
        kdf: [u8; 16],
    }
    impl V4Scaffold {
        fn new() -> Self {
            Self {
                aes: aes_cipher_id(),
                comp_none: 0u32.to_le_bytes(),
                comp_gzip: 1u32.to_le_bytes(),
                iv16: [0u8; 16],
                iv12: [0u8; 12],
                seed32: [0u8; 32],
                kdf: [0u8; 16],
            }
        }
    }

    #[test]
    fn parses_minimal_v3_header() {
        let aes = aes_cipher_id();
        let comp = 0u32.to_le_bytes();
        let seed = [1u8; 32];
        let xs = [2u8; 32];
        let rounds = 6_000_000u64.to_le_bytes();
        let iv = [0u8; 16];
        let psk = [3u8; 32];
        let ssb = [4u8; 32];
        let innerid = 2u32.to_le_bytes();
        let fields = [
            f(tag::CIPHER_ID, &aes),
            f(tag::COMPRESSION_FLAGS, &comp),
            f(tag::MASTER_SEED, &seed),
            f(tag::TRANSFORM_SEED, &xs),
            f(tag::TRANSFORM_ROUNDS, &rounds),
            f(tag::ENCRYPTION_IV, &iv),
            f(tag::PROTECTED_STREAM_KEY, &psk),
            f(tag::STREAM_START_BYTES, &ssb),
            f(tag::INNER_RANDOM_STREAM_ID, &innerid),
        ];
        let h = OuterHeader::parse(&fields, Version::V3).unwrap();
        assert_eq!(h.version, Version::V3);
        assert_eq!(h.cipher_id.well_known(), Some(KnownCipher::Aes256Cbc));
        assert_eq!(h.compression, CompressionFlags::None);
        assert_eq!(h.transform_rounds, Some(6_000_000));
        assert_eq!(
            h.inner_stream_algorithm,
            Some(InnerStreamAlgorithm::Salsa20)
        );
        assert!(h.kdf_parameters.is_none());
    }

    #[test]
    fn parses_minimal_v4_header() {
        let s = V4Scaffold::new();
        let chacha = chacha_cipher_id();
        let fields = [
            f(tag::CIPHER_ID, &chacha),
            f(tag::COMPRESSION_FLAGS, &s.comp_gzip),
            f(tag::MASTER_SEED, &s.seed32),
            f(tag::ENCRYPTION_IV, &s.iv12),
            f(tag::KDF_PARAMETERS, &s.kdf),
        ];
        let h = OuterHeader::parse(&fields, Version::V4).unwrap();
        assert_eq!(h.version, Version::V4);
        assert_eq!(h.cipher_id.well_known(), Some(KnownCipher::ChaCha20));
        assert_eq!(h.compression, CompressionFlags::Gzip);
        assert_eq!(h.encryption_iv.0.len(), 12);
        assert!(h.kdf_parameters.is_some());
        assert!(h.transform_seed.is_none(), "v4 should not carry v3 fields");
    }

    #[test]
    fn rejects_missing_mandatory_v3_fields() {
        let aes = aes_cipher_id();
        let comp = 0u32.to_le_bytes();
        let seed = [0u8; 32];
        let rounds = 100u64.to_le_bytes();
        let iv = [0u8; 16];
        let psk = [0u8; 32];
        let ssb = [0u8; 32];
        let innerid = 2u32.to_le_bytes();
        // TRANSFORM_SEED deliberately absent
        let fields = [
            f(tag::CIPHER_ID, &aes),
            f(tag::COMPRESSION_FLAGS, &comp),
            f(tag::MASTER_SEED, &seed),
            f(tag::TRANSFORM_ROUNDS, &rounds),
            f(tag::ENCRYPTION_IV, &iv),
            f(tag::PROTECTED_STREAM_KEY, &psk),
            f(tag::STREAM_START_BYTES, &ssb),
            f(tag::INNER_RANDOM_STREAM_ID, &innerid),
        ];
        assert!(matches!(
            OuterHeader::parse(&fields, Version::V3).unwrap_err(),
            HeaderError::Missing(tag::TRANSFORM_SEED)
        ));
    }

    #[test]
    fn rejects_missing_mandatory_v4_kdf() {
        let s = V4Scaffold::new();
        let fields = [
            f(tag::CIPHER_ID, &s.aes),
            f(tag::COMPRESSION_FLAGS, &s.comp_none),
            f(tag::MASTER_SEED, &s.seed32),
            f(tag::ENCRYPTION_IV, &s.iv16),
        ];
        assert!(matches!(
            OuterHeader::parse(&fields, Version::V4).unwrap_err(),
            HeaderError::Missing(tag::KDF_PARAMETERS)
        ));
    }

    #[test]
    fn rejects_wrong_length_master_seed() {
        let s = V4Scaffold::new();
        let short_seed = [0u8; 16]; // should be 32
        let fields = [
            f(tag::CIPHER_ID, &s.aes),
            f(tag::COMPRESSION_FLAGS, &s.comp_none),
            f(tag::MASTER_SEED, &short_seed),
            f(tag::ENCRYPTION_IV, &s.iv16),
            f(tag::KDF_PARAMETERS, &s.kdf),
        ];
        let err = OuterHeader::parse(&fields, Version::V4).unwrap_err();
        assert!(matches!(
            err,
            HeaderError::WrongLength {
                tag: tag::MASTER_SEED,
                expected: 32,
                got: 16
            }
        ));
    }

    #[test]
    fn rejects_duplicate_fields() {
        let s = V4Scaffold::new();
        let fields = [
            f(tag::CIPHER_ID, &s.aes),
            f(tag::CIPHER_ID, &s.aes), // duplicate
            f(tag::COMPRESSION_FLAGS, &s.comp_none),
            f(tag::MASTER_SEED, &s.seed32),
            f(tag::ENCRYPTION_IV, &s.iv16),
            f(tag::KDF_PARAMETERS, &s.kdf),
        ];
        assert!(matches!(
            OuterHeader::parse(&fields, Version::V4).unwrap_err(),
            HeaderError::Duplicate(tag::CIPHER_ID)
        ));
    }

    #[test]
    fn rejects_unknown_compression() {
        let s = V4Scaffold::new();
        let bad_comp = 42u32.to_le_bytes();
        let fields = [
            f(tag::CIPHER_ID, &s.aes),
            f(tag::COMPRESSION_FLAGS, &bad_comp),
            f(tag::MASTER_SEED, &s.seed32),
            f(tag::ENCRYPTION_IV, &s.iv16),
            f(tag::KDF_PARAMETERS, &s.kdf),
        ];
        assert!(matches!(
            OuterHeader::parse(&fields, Version::V4).unwrap_err(),
            HeaderError::UnknownCompression(42)
        ));
    }

    #[test]
    fn comment_tag_is_ignored() {
        let s = V4Scaffold::new();
        let fields = [
            f(tag::COMMENT, b"ignore me"),
            f(tag::CIPHER_ID, &s.aes),
            f(tag::COMPRESSION_FLAGS, &s.comp_none),
            f(tag::MASTER_SEED, &s.seed32),
            f(tag::ENCRYPTION_IV, &s.iv16),
            f(tag::KDF_PARAMETERS, &s.kdf),
        ];
        assert!(OuterHeader::parse(&fields, Version::V4).is_ok());
    }

    #[test]
    fn secret_types_debug_is_redacted() {
        // Master seed, transform seed, protected stream key, stream start bytes
        // should all redact their bytes — only length appears.
        let s = format!("{:?}", MasterSeed([0xFF; 32]));
        assert!(
            !s.contains("FF"),
            "MasterSeed Debug should not dump bytes: {s}"
        );
        assert!(
            s.contains("32"),
            "MasterSeed Debug should expose length: {s}"
        );

        let s = format!("{:?}", TransformSeed([0xFF; 32]));
        assert!(!s.contains("FF"), "TransformSeed should redact: {s}");

        let s = format!("{:?}", ProtectedStreamKey([0xFF; 32]));
        assert!(!s.contains("FF"), "ProtectedStreamKey should redact: {s}");
    }
}
