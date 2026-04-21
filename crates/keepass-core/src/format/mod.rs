//! Format-version-specific framing (KDBX3, KDBX4, future KDBX5).
//!
//! This module contains the on-disk framing for each supported KDBX version.
//! The [`crate::model`] types are format-agnostic; this module translates
//! between them and concrete byte streams.
//!
//! The [`Version`] enum enumerates supported versions. Per-version code
//! lives in the `v3` and `v4` submodules.

pub mod v3;
pub mod v4;

/// Supported KDBX major versions.
///
/// `#[non_exhaustive]` allows future variants (`V5`, KDBX 4.1 distinctions,
/// etc.) to be added without a semver break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Version {
    /// KDBX 3.1 — AES-KDF + Salsa20 inner stream.
    V3,
    /// KDBX 4.x — Argon2 KDF + ChaCha20 inner stream + HMAC block tags.
    V4,
}

/// Error type for format-level failures (header parsing, version dispatch).
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum FormatError {
    /// The file's magic bytes did not match a KeePass signature.
    #[error("not a KeePass database (bad magic bytes)")]
    NotKeePass,

    /// The file claims a KDBX version this crate does not support.
    #[error("unsupported KDBX version {major}.{minor}")]
    UnsupportedVersion {
        /// Major version number from the file header.
        major: u16,
        /// Minor version number from the file header.
        minor: u16,
    },

    /// The file ended before a complete structure could be parsed.
    #[error("unexpected end of file")]
    Truncated,

    /// A header field had an unexpected shape.
    #[error("malformed header field: {0}")]
    MalformedHeader(&'static str),
}
