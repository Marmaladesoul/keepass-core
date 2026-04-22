//! The [`Kdbx`] typestate machine.
//!
//! A KDBX file passes through four distinct states on the way from bytes on
//! disk to a usable vault, and through three states on the way back out:
//!
//! ```text
//!  ┌────────┐  read_header   ┌────────────┐  unlock   ┌──────────┐  write
//!  │ Sealed │ ──────────────▶│ HeaderRead │ ─────────▶│ Unlocked │ ─────▶ bytes
//!  └────────┘                └────────────┘           └──────────┘
//! ```
//!
//! Each state is a distinct Rust type. Methods that only make sense in a
//! particular state exist only on the impl block for that state. The compiler
//! therefore statically prevents misuse: `vault.entries()` on a sealed vault
//! is a compile error, not a runtime one.
//!
//! ## Why each state exists
//!
//! - [`Sealed`] — the file bytes have been read into memory and the signature
//!   block has been validated. The outer header is still unparsed.
//! - [`HeaderRead`] — the outer header has been parsed; we know the KDBX
//!   version, cipher, KDF parameters, and seeds. The master key has **not**
//!   yet been applied. The only legal operation is `unlock`.
//! - [`Unlocked`] — the master key has been derived, block HMACs verified
//!   (on KDBX4), payload decrypted, decompressed, and the inner XML parsed
//!   into the [`crate::model::Vault`] tree. Read and write operations are
//!   available. **Not yet implemented.**

use std::fs;
use std::marker::PhantomData;
use std::path::Path;

use crate::error::Error;
use crate::format::{FileSignature, FormatError, OuterHeader, Version, read_header_fields};

// ---------------------------------------------------------------------------
// State markers
// ---------------------------------------------------------------------------

/// State marker: the file bytes are present and the signature block has been
/// validated; the outer header has not yet been parsed.
#[derive(Debug)]
pub struct Sealed {
    _private: PhantomData<()>,
}

/// State marker: the outer header has been parsed; the payload is still
/// encrypted.
#[derive(Debug)]
pub struct HeaderRead {
    header: OuterHeader,
    /// Offset (in `Kdbx::bytes`) of the first byte past the end of the outer
    /// header. For KDBX3 this is the start of the encrypted payload; for
    /// KDBX4 it is the start of the 32-byte header SHA-256, followed by the
    /// 32-byte header HMAC, followed by the HMAC-block stream.
    header_end: usize,
}

/// State marker: the vault has been fully decrypted and parsed.
///
/// Not yet populated — the unlock pipeline lands in a follow-up PR.
#[derive(Debug)]
pub struct Unlocked {
    _private: PhantomData<()>,
}

// ---------------------------------------------------------------------------
// The typestate container
// ---------------------------------------------------------------------------

/// A KeePass database in one of the lifecycle states [`Sealed`],
/// [`HeaderRead`], or [`Unlocked`].
///
/// Create a [`Kdbx<Sealed>`] from bytes via [`Kdbx::open_from_bytes`] or from
/// a path via [`Kdbx::open`]. Transition to [`Kdbx<HeaderRead>`] by calling
/// [`Kdbx::<Sealed>::read_header`]. The transition to [`Kdbx<Unlocked>`] is
/// pending.
#[derive(Debug)]
pub struct Kdbx<State> {
    /// The full file bytes. Held across state transitions so that later
    /// stages can slice the encrypted payload, HMAC blocks, etc.
    bytes: Vec<u8>,
    /// Parsed signature block (magic + major + minor).
    signature: FileSignature,
    /// Version derived from the signature's major number. Cached so that
    /// every state can expose it without re-parsing.
    version: Version,
    /// State-specific data. In `Sealed` this is a zero-sized marker; in
    /// `HeaderRead` it carries the parsed header.
    state: State,
}

// ---------------------------------------------------------------------------
// Methods available in every state
// ---------------------------------------------------------------------------

impl<S> Kdbx<S> {
    /// The validated signature block from the first 12 bytes.
    #[must_use]
    pub fn signature(&self) -> FileSignature {
        self.signature
    }

    /// The KDBX major version (`V3` or `V4`).
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }
}

// ---------------------------------------------------------------------------
// Sealed: open and read_header
// ---------------------------------------------------------------------------

impl Kdbx<Sealed> {
    /// Open a KDBX database from its raw bytes.
    ///
    /// Validates the 12-byte signature block and classifies the version. No
    /// further parsing — the outer header stays sealed until
    /// [`Self::read_header`] is called.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if the magic bytes are wrong, the file is
    /// shorter than 12 bytes, or the major version is not 3 or 4.
    pub fn open_from_bytes(bytes: Vec<u8>) -> Result<Self, Error> {
        let signature = FileSignature::read(&bytes)?;
        let version = signature.version()?;
        Ok(Self {
            bytes,
            signature,
            version,
            state: Sealed {
                _private: PhantomData,
            },
        })
    }

    /// Convenience: read a path into memory and pass it to
    /// [`Self::open_from_bytes`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the file can't be read, or the underlying
    /// format errors from [`Self::open_from_bytes`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let bytes = fs::read(path)?;
        Self::open_from_bytes(bytes)
    }

    /// Parse the outer header, transitioning to [`Kdbx<HeaderRead>`].
    ///
    /// After this call the outer header is available via
    /// [`Kdbx::<HeaderRead>::header`]. Seeds, cipher IDs, and (for KDBX4) the
    /// VarDictionary-encoded KDF parameters are all decoded; key derivation
    /// has not happened yet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Format`] if any TLV record is malformed, any
    /// mandatory field is missing, or an unknown cipher / compression ID is
    /// encountered.
    pub fn read_header(self) -> Result<Kdbx<HeaderRead>, Error> {
        let mut cursor = &self.bytes[FileSignature::LEN..];
        let before = cursor.len();
        let (fields, _end) = read_header_fields(&mut cursor, self.version.header_length_width())?;
        let header = OuterHeader::parse(&fields, self.version).map_err(FormatError::from)?;
        // `cursor` has been advanced past the end-of-header sentinel.
        let header_end = FileSignature::LEN + (before - cursor.len());

        Ok(Kdbx {
            bytes: self.bytes,
            signature: self.signature,
            version: self.version,
            state: HeaderRead { header, header_end },
        })
    }
}

// ---------------------------------------------------------------------------
// HeaderRead: accessors; unlock lands in a follow-up
// ---------------------------------------------------------------------------

impl Kdbx<HeaderRead> {
    /// The parsed outer header.
    #[must_use]
    pub fn header(&self) -> &OuterHeader {
        &self.state.header
    }

    /// Byte slice of everything after the outer header — i.e. the encrypted
    /// payload on KDBX3, or the header-HMAC + HMAC-block stream on KDBX4.
    ///
    /// Exposed for testing and for downstream unlock wiring.
    #[must_use]
    pub fn payload_bytes(&self) -> &[u8] {
        &self.bytes[self.state.header_end..]
    }

    /// Byte slice of the outer header itself — signature + TLV records up to
    /// and including the end-of-header sentinel. Used by KDBX4 to compute
    /// the header SHA-256 and HMAC.
    #[must_use]
    pub fn header_bytes(&self) -> &[u8] {
        &self.bytes[..self.state.header_end]
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal "just signature, no header fields" byte sequence that
    /// is enough to pass [`Kdbx::open_from_bytes`] but would fail
    /// `read_header` (no end-of-header sentinel).
    fn signature_only(major: u16, minor: u16) -> Vec<u8> {
        use crate::format::{SIGNATURE_1, SIGNATURE_2};
        let mut v = Vec::with_capacity(12);
        v.extend_from_slice(&SIGNATURE_1);
        v.extend_from_slice(&SIGNATURE_2);
        v.extend_from_slice(&minor.to_le_bytes());
        v.extend_from_slice(&major.to_le_bytes());
        v
    }

    #[test]
    fn open_from_bytes_accepts_valid_signature() {
        let bytes = signature_only(4, 1);
        let kdbx = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap();
        assert_eq!(kdbx.version(), Version::V4);
        assert_eq!(kdbx.signature().major, 4);
        assert_eq!(kdbx.signature().minor, 1);
    }

    #[test]
    fn open_from_bytes_rejects_bad_magic() {
        let bytes = vec![0u8; 12];
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::BadSignature1)
        ));
    }

    #[test]
    fn open_from_bytes_rejects_unsupported_major() {
        let bytes = signature_only(99, 0);
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::UnsupportedVersion { major: 99, .. })
        ));
    }

    #[test]
    fn open_from_bytes_rejects_truncated_file() {
        let bytes = vec![0x03, 0xD9, 0xA2];
        let err = Kdbx::<Sealed>::open_from_bytes(bytes).unwrap_err();
        assert!(matches!(
            err,
            Error::Format(crate::format::FormatError::Truncated { .. })
        ));
    }
}
