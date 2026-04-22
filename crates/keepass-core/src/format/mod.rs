//! Format-version-specific framing (KDBX3, KDBX4, future KDBX5).
//!
//! This module contains the on-disk framing for each supported KDBX version.
//! The [`crate::model`] types are format-agnostic; this module translates
//! between them and concrete byte streams.
//!
//! The [`Version`] enum enumerates supported major versions. Per-version
//! code lives in the `v3` and `v4` submodules.

pub mod hashed_block_stream;
pub mod header;
pub mod hmac_block_stream;
pub mod kdf_params;
pub mod tlv;
pub mod v3;
pub mod v4;
pub mod var_dictionary;

pub use hashed_block_stream::{HashedBlockError, read_hashed_block_stream};
pub use hmac_block_stream::{HEADER_HMAC_BLOCK_INDEX, HmacBlockError, read_hmac_block_stream};

pub use header::{
    CipherId, CompressionFlags, EncryptionIv, HeaderError, InnerStreamAlgorithm, KnownCipher,
    MasterSeed, OuterHeader, ProtectedStreamKey, StreamStartBytes, TransformSeed,
};
pub use kdf_params::{Argon2Variant, Argon2Version, KdfId, KdfParams, KdfParamsError, KnownKdf};
pub use tlv::{LengthWidth, TlvField, read_header_fields};
pub use var_dictionary::{Value as VarValue, VarDictionary, VarDictionaryError};

// ---------------------------------------------------------------------------
// Magic bytes
// ---------------------------------------------------------------------------

/// First KeePass signature — identifies the file as a KeePass database.
///
/// Every KDBX file begins with these four bytes. A file that does not start
/// with this sequence is not a KeePass database and is rejected immediately.
pub const SIGNATURE_1: [u8; 4] = [0x03, 0xD9, 0xA2, 0x9A];

/// Second KeePass signature — identifies the file as a KDBX variant (as
/// opposed to the older KDB format, which uses a different signature 2).
pub const SIGNATURE_2: [u8; 4] = [0x67, 0xFB, 0x4B, 0xB5];

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Supported KDBX major versions.
///
/// `#[non_exhaustive]` allows future variants (`V5`, distinct KDBX 4.1
/// handling, etc.) to be added without a semver break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Version {
    /// KDBX 3.x — AES-KDF by default, Salsa20 inner stream.
    V3,
    /// KDBX 4.x — Argon2 KDF by default, ChaCha20 inner stream, per-block HMAC.
    V4,
}

impl Version {
    /// Classify a `(major, minor)` version pair from the file header.
    ///
    /// Returns `None` for versions this crate does not support (`< 3` or
    /// `> 4`). The minor component is retained separately by the caller for
    /// sub-version-specific behaviour (e.g. KDBX 4.1 additions).
    #[must_use]
    pub const fn from_major(major: u16) -> Option<Self> {
        match major {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }

    /// The width of the length prefix used in this version's outer-header
    /// TLV records.
    #[must_use]
    pub const fn header_length_width(self) -> LengthWidth {
        match self {
            Self::V3 => LengthWidth::U16,
            Self::V4 => LengthWidth::U32,
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for format-level failures (header parsing, version dispatch).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FormatError {
    /// The file's first signature did not match the KeePass magic.
    #[error("not a KeePass database (bad first signature)")]
    BadSignature1,

    /// The first signature matched but the second did not (likely a legacy
    /// KDB file or a corrupted KDBX file).
    #[error("not a KDBX database (bad second signature)")]
    BadSignature2,

    /// The file claims a KDBX major version this crate does not support.
    #[error("unsupported KDBX major version {major} (minor {minor})")]
    UnsupportedVersion {
        /// Major version number from the file header.
        major: u16,
        /// Minor version number from the file header.
        minor: u16,
    },

    /// The file ended before a complete structure could be parsed.
    #[error("unexpected end of file (need at least {needed} bytes, got {got})")]
    Truncated {
        /// Number of bytes the parser needed at this point.
        needed: usize,
        /// Number of bytes actually available.
        got: usize,
    },

    /// A header field had an unexpected shape.
    #[error("malformed header field: {0}")]
    MalformedHeader(&'static str),
}

// ---------------------------------------------------------------------------
// Magic + version detection
// ---------------------------------------------------------------------------

/// Bytes parsed from the first 12 bytes of a KDBX file: two 4-byte magic
/// signatures followed by a 2-byte minor version and a 2-byte major version
/// (both little-endian).
///
/// Parsing this header is cheap — 12 bytes and two `u16` reads — and it is
/// the first thing a consumer does before deciding whether to continue
/// reading the larger outer header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSignature {
    /// Parsed major version (3 for KDBX3.x, 4 for KDBX4.x).
    pub major: u16,
    /// Parsed minor version (e.g. 0 for 4.0, 1 for 4.1).
    pub minor: u16,
}

impl FileSignature {
    /// Length in bytes of the file-level signature prefix.
    pub const LEN: usize = 12;

    /// Try to read and validate the file signature from the start of `bytes`.
    ///
    /// Returns the parsed signature on success, or a [`FormatError`] describing
    /// which specific check failed. The two signature bytes are checked in
    /// order so that callers can distinguish "not a KeePass database at all"
    /// from "KeePass but not KDBX" from "KDBX but wrong version".
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::Truncated`] if `bytes` has fewer than
    /// [`Self::LEN`] bytes; [`FormatError::BadSignature1`] if the first four
    /// bytes do not match [`SIGNATURE_1`]; [`FormatError::BadSignature2`] if
    /// the second four do not match [`SIGNATURE_2`].
    pub fn read(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < Self::LEN {
            return Err(FormatError::Truncated {
                needed: Self::LEN,
                got: bytes.len(),
            });
        }
        if bytes[0..4] != SIGNATURE_1 {
            return Err(FormatError::BadSignature1);
        }
        if bytes[4..8] != SIGNATURE_2 {
            return Err(FormatError::BadSignature2);
        }
        // Little-endian per the KDBX spec.
        let minor = u16::from_le_bytes([bytes[8], bytes[9]]);
        let major = u16::from_le_bytes([bytes[10], bytes[11]]);
        Ok(Self { major, minor })
    }

    /// Classify this signature as a supported [`Version`].
    ///
    /// # Errors
    ///
    /// Returns [`FormatError::UnsupportedVersion`] if the major version is
    /// neither 3 nor 4.
    pub const fn version(self) -> Result<Version, FormatError> {
        match Version::from_major(self.major) {
            Some(v) => Ok(v),
            None => Err(FormatError::UnsupportedVersion {
                major: self.major,
                minor: self.minor,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 12-byte signature header with the given major/minor.
    fn fake_header(major: u16, minor: u16) -> Vec<u8> {
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&SIGNATURE_1);
        v.extend_from_slice(&SIGNATURE_2);
        v.extend_from_slice(&minor.to_le_bytes());
        v.extend_from_slice(&major.to_le_bytes());
        v
    }

    #[test]
    fn reads_valid_kdbx4_signature() {
        let sig = FileSignature::read(&fake_header(4, 0)).expect("valid");
        assert_eq!(sig.major, 4);
        assert_eq!(sig.minor, 0);
        assert_eq!(sig.version().unwrap(), Version::V4);
    }

    #[test]
    fn reads_valid_kdbx3_signature() {
        let sig = FileSignature::read(&fake_header(3, 1)).expect("valid");
        assert_eq!(sig.major, 3);
        assert_eq!(sig.minor, 1);
        assert_eq!(sig.version().unwrap(), Version::V3);
    }

    #[test]
    fn rejects_truncated_header() {
        let err = FileSignature::read(&[0; 4]).unwrap_err();
        assert!(matches!(err, FormatError::Truncated { needed: 12, got: 4 }));
    }

    #[test]
    fn rejects_empty_input() {
        let err = FileSignature::read(&[]).unwrap_err();
        assert!(matches!(err, FormatError::Truncated { needed: 12, got: 0 }));
    }

    #[test]
    fn rejects_bad_first_signature() {
        let mut hdr = fake_header(4, 0);
        hdr[0] = 0xFF;
        let err = FileSignature::read(&hdr).unwrap_err();
        assert!(matches!(err, FormatError::BadSignature1));
    }

    #[test]
    fn rejects_bad_second_signature() {
        let mut hdr = fake_header(4, 0);
        hdr[5] = 0xFF; // munge byte in SIGNATURE_2 range
        let err = FileSignature::read(&hdr).unwrap_err();
        assert!(matches!(err, FormatError::BadSignature2));
    }

    #[test]
    fn rejects_unsupported_major_version() {
        let sig = FileSignature::read(&fake_header(99, 0)).expect("parses");
        assert!(matches!(
            sig.version(),
            Err(FormatError::UnsupportedVersion {
                major: 99,
                minor: 0
            })
        ));
    }

    #[test]
    fn rejects_legacy_kdb_major_1() {
        let sig = FileSignature::read(&fake_header(1, 0)).expect("parses");
        assert!(matches!(
            sig.version(),
            Err(FormatError::UnsupportedVersion { major: 1, .. })
        ));
    }

    #[test]
    fn distinguishes_signature_1_vs_2_failures() {
        // All-zeros fails sig 1 first
        assert!(matches!(
            FileSignature::read(&[0u8; 12]).unwrap_err(),
            FormatError::BadSignature1
        ));
        // Good sig 1, bad sig 2
        let mut hdr = [0u8; 12];
        hdr[0..4].copy_from_slice(&SIGNATURE_1);
        assert!(matches!(
            FileSignature::read(&hdr).unwrap_err(),
            FormatError::BadSignature2
        ));
    }

    #[test]
    fn signature_constants_are_canonical() {
        // Canonical KeePass signatures — guard against accidental edits.
        assert_eq!(SIGNATURE_1, [0x03, 0xD9, 0xA2, 0x9A]);
        assert_eq!(SIGNATURE_2, [0x67, 0xFB, 0x4B, 0xB5]);
    }
}
