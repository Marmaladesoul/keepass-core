//! Payload compression.
//!
//! KeePass databases may carry their inner XML compressed. The outer
//! header's [`crate::format::CompressionFlags`] field declares whether the
//! decrypted payload is raw or gzipped:
//!
//! | Variant                       | On disk                      |
//! |-------------------------------|------------------------------|
//! | [`CompressionFlags::None`]    | raw inner XML (KDBX3 only)   |
//! | [`CompressionFlags::Gzip`]    | standard RFC 1952 gzip stream|
//!
//! Most real-world vaults are gzipped. This module owns the thin wrappers
//! around [`flate2`] for both compression and decompression.
//!
//! [`CompressionFlags`]: crate::format::CompressionFlags
//! [`CompressionFlags::None`]: crate::format::CompressionFlags::None
//! [`CompressionFlags::Gzip`]: crate::format::CompressionFlags::Gzip

use std::io::{Read, Write};

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use thiserror::Error;

use crate::format::CompressionFlags;

/// Decompress a payload according to the declared [`CompressionFlags`].
///
/// For [`CompressionFlags::None`], returns the input bytes as an owned
/// `Vec<u8>` (a copy — callers that want to avoid the copy in the
/// no-compression case should dispatch on the flag themselves).
///
/// For [`CompressionFlags::Gzip`], decompresses via [`flate2`] and
/// returns the resulting plaintext.
///
/// # Errors
///
/// Returns [`CompressionError::Gzip`] if the gzip stream is malformed
/// (bad magic, corrupted CRC, truncated, etc.).
///
/// # Size limit
///
/// The default limit is 256 MiB. If the decompressed payload exceeds
/// this limit, returns [`CompressionError::OutputTooLarge`]. Callers
/// that need a different limit can use [`decompress_with_limit`].
/// A limit prevents a malicious gzip "bomb" from allocating arbitrarily
/// large buffers during parsing.
pub fn decompress(flags: CompressionFlags, payload: &[u8]) -> Result<Vec<u8>, CompressionError> {
    decompress_with_limit(flags, payload, DEFAULT_LIMIT_BYTES)
}

/// Same as [`decompress`] but with a caller-chosen output-size limit.
///
/// # Errors
///
/// Returns [`CompressionError::Gzip`] if the gzip stream is malformed
/// or [`CompressionError::OutputTooLarge`] if the decompressed output
/// would exceed `max_output_bytes`.
pub fn decompress_with_limit(
    flags: CompressionFlags,
    payload: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, CompressionError> {
    // Note: CompressionFlags is #[non_exhaustive] at its definition site, so
    // downstream consumers in other crates could in principle see variants
    // we don't know about here. Within this crate the compiler sees all
    // variants, so we match them exhaustively. If a future variant is
    // added, compilation here must be updated in lockstep (which is what
    // we want — silently mishandling compression is not an option).
    match flags {
        CompressionFlags::None => {
            if payload.len() > max_output_bytes {
                return Err(CompressionError::OutputTooLarge {
                    limit: max_output_bytes,
                    attempted: payload.len(),
                });
            }
            Ok(payload.to_vec())
        }
        CompressionFlags::Gzip => decompress_gzip(payload, max_output_bytes),
    }
}

/// Compress a payload according to the declared [`CompressionFlags`] — the
/// inverse of [`decompress`].
///
/// For [`CompressionFlags::None`], returns the input bytes as an owned
/// `Vec<u8>` (a copy).
///
/// For [`CompressionFlags::Gzip`], encodes the payload as an RFC 1952
/// gzip stream with [`flate2::Compression::default()`]. Output is a
/// fresh `Vec<u8>`.
///
/// # Errors
///
/// Returns [`CompressionError::Gzip`] if the underlying `flate2` writer
/// fails — which in practice only happens under memory exhaustion, since
/// the underlying `Vec<u8>` sink never returns an I/O error.
pub fn compress(flags: CompressionFlags, payload: &[u8]) -> Result<Vec<u8>, CompressionError> {
    match flags {
        CompressionFlags::None => Ok(payload.to_vec()),
        CompressionFlags::Gzip => {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(payload)
                .map_err(|e| CompressionError::Gzip(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| CompressionError::Gzip(e.to_string()))
        }
    }
}

/// Default maximum decompressed output size: 256 MiB.
///
/// Chosen as roughly two orders of magnitude above the largest plausible
/// KeePass vault (a pathological case with tens of thousands of entries
/// and very large attachments would still sit well under 64 MiB).
pub const DEFAULT_LIMIT_BYTES: usize = 256 * 1024 * 1024;

fn decompress_gzip(payload: &[u8], max_output_bytes: usize) -> Result<Vec<u8>, CompressionError> {
    let mut decoder = GzDecoder::new(payload);
    let mut output = Vec::new();

    // Read in 64 KiB chunks so we can enforce the size limit as we go
    // rather than waiting for read_to_end to blow up. Heap-allocated so
    // we keep the stack frame small.
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = decoder
            .read(&mut buf)
            .map_err(|e| CompressionError::Gzip(e.to_string()))?;
        if n == 0 {
            return Ok(output);
        }
        if output.len() + n > max_output_bytes {
            return Err(CompressionError::OutputTooLarge {
                limit: max_output_bytes,
                attempted: output.len() + n,
            });
        }
        output.extend_from_slice(&buf[..n]);
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for [`decompress`] / [`decompress_with_limit`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CompressionError {
    /// The gzip stream was malformed.
    #[error("gzip decompression failed: {0}")]
    Gzip(String),

    /// The output would exceed the caller-specified size limit.
    #[error("decompressed output too large: {attempted} bytes exceeds limit {limit}")]
    OutputTooLarge {
        /// The size limit that was exceeded.
        limit: usize,
        /// The output size the stream was trying to produce.
        attempted: usize,
    },
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    fn gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn none_flag_returns_payload_as_is() {
        let payload = b"already plaintext, thanks".to_vec();
        let out = decompress(CompressionFlags::None, &payload).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn none_flag_respects_size_limit() {
        let payload = vec![0u8; 100];
        let err = decompress_with_limit(CompressionFlags::None, &payload, 50).unwrap_err();
        assert!(matches!(
            err,
            CompressionError::OutputTooLarge {
                limit: 50,
                attempted: 100
            }
        ));
    }

    #[test]
    fn round_trips_gzip_small() {
        let original = b"The quick brown fox jumps over the lazy dog.".to_vec();
        let compressed = gzip(&original);
        let decompressed = decompress(CompressionFlags::Gzip, &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn round_trips_gzip_large() {
        // 1 MiB of repeating 0..255 pattern — gzip will compress heavily.
        let original: Vec<u8> = (0..(1024 * 1024))
            .map(|i| u8::try_from(i & 0xFF).unwrap())
            .collect();
        let compressed = gzip(&original);
        assert!(
            compressed.len() < original.len(),
            "gzip should have compressed the pattern"
        );
        let decompressed = decompress(CompressionFlags::Gzip, &compressed).unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn round_trips_gzip_empty() {
        let compressed = gzip(b"");
        let decompressed = decompress(CompressionFlags::Gzip, &compressed).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn rejects_malformed_gzip() {
        let err = decompress(CompressionFlags::Gzip, b"not gzipped").unwrap_err();
        assert!(matches!(err, CompressionError::Gzip(_)));
    }

    #[test]
    fn rejects_truncated_gzip() {
        let compressed = gzip(b"some payload");
        let truncated = &compressed[..compressed.len() / 2];
        let err = decompress(CompressionFlags::Gzip, truncated).unwrap_err();
        assert!(matches!(err, CompressionError::Gzip(_)));
    }

    #[test]
    fn rejects_oversized_output() {
        // Compress 10 KiB of zeros — gzips down tiny but decompresses back
        // to 10 KiB. With a 1 KiB limit, we should abort mid-stream.
        let payload = vec![0u8; 10 * 1024];
        let compressed = gzip(&payload);
        let err = decompress_with_limit(CompressionFlags::Gzip, &compressed, 1024).unwrap_err();
        assert!(matches!(
            err,
            CompressionError::OutputTooLarge { limit: 1024, .. }
        ));
    }

    #[test]
    fn zip_bomb_is_thwarted_by_default_limit() {
        // A small, high-ratio gzip stream (50 MiB of zeros compresses to
        // ~51 KiB). Verify that if we configure a low limit, it stops
        // early and doesn't allocate the full output.
        let bomb_plaintext = vec![0u8; 50 * 1024 * 1024];
        let compressed = gzip(&bomb_plaintext);
        assert!(
            compressed.len() < 100 * 1024,
            "sanity: 50 MiB of zeros should compress to well under 100 KiB"
        );

        // With a 1 MiB limit, decompression must stop before allocating
        // the full 50 MiB.
        let err =
            decompress_with_limit(CompressionFlags::Gzip, &compressed, 1024 * 1024).unwrap_err();
        assert!(matches!(
            err,
            CompressionError::OutputTooLarge {
                limit: 1_048_576,
                ..
            }
        ));
    }

    #[test]
    fn decompression_is_deterministic() {
        let payload = b"same input produces same output".to_vec();
        let compressed = gzip(&payload);
        let a = decompress(CompressionFlags::Gzip, &compressed).unwrap();
        let b = decompress(CompressionFlags::Gzip, &compressed).unwrap();
        assert_eq!(a, b);
    }
}
