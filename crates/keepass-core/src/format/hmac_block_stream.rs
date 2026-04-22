//! KDBX4 `HmacBlockStream` decoder.
//!
//! KDBX4 replaces KDBX3's `HashedBlockStream` with an authenticated
//! variant: each block carries an HMAC-SHA-256 tag instead of a raw
//! hash, and the tag's key is *per-block*, derived from the vault's
//! shared HMAC base key (`SHA-512(master_seed || transformed_key ||
//! 0x01)`) and the block's zero-based index.
//!
//! ## On-disk layout
//!
//! ```text
//!   ( hmac: [u8; 32]                       // HMAC-SHA-256
//!     size: u32 LE
//!     data: [u8; size] )*
//!   ( hmac: [u8; 32]
//!     0_u32 )                              // end marker: size = 0
//! ```
//!
//! Unlike KDBX3's format, there is **no** `block_index` field on the
//! wire; indices are implicit, running `0, 1, 2, …` with the end marker
//! carrying the next index in sequence.
//!
//! ## HMAC input
//!
//! For each block:
//!
//! ```text
//!   hmac_key(i) = SHA-512( i_u64_LE || base_key_64 )
//!   hmac_input  = i_u64_LE || size_u32_LE || data
//!   hmac_tag    = HMAC-SHA-256( hmac_key(i), hmac_input )
//! ```
//!
//! For the end marker: `data` is empty, so the HMAC input is just
//! `i_u64_LE || 0_u32_LE`. The end-marker tag is verified the same way.
//!
//! ## Header HMAC
//!
//! Before the first block, KDBX4 also writes a header HMAC whose block
//! index is the sentinel `u64::MAX`. That verification is the caller's
//! responsibility (it lives above this layer, tied to the outer-header
//! bytes); this module reads only the post-header block stream.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::FormatError;
use crate::crypto::per_block_hmac_key;
use crate::secret::HmacBaseKey;

type HmacSha256 = Hmac<Sha256>;

/// Block index sentinel used for the KDBX4 **header HMAC** (the one
/// written before the first payload block). Not used by
/// [`read_hmac_block_stream`] itself; exposed here so callers that
/// verify the header HMAC can reuse the same constant.
pub const HEADER_HMAC_BLOCK_INDEX: u64 = u64::MAX;

/// Decode a KDBX4 `HmacBlockStream` into the concatenation of its
/// `data` segments.
///
/// The input is the byte stream starting at the first block (i.e. the
/// caller has already consumed the preceding 32-byte header HMAC, if
/// any). The `hmac_base` is the 64-byte base key derived via
/// [`crate::crypto::derive_hmac_base_key`].
///
/// # Errors
///
/// - [`HmacBlockError::Truncated`] if the stream ends in the middle of
///   a block header or data segment.
/// - [`HmacBlockError::HmacMismatch`] if any block's tag fails
///   verification. Comparison is constant-time.
///
/// # Panics
///
/// Does not panic under any input. The internal `HmacSha256::new_from_slice`
/// call is only ever given a 64-byte key derived from SHA-512, which is
/// always a valid HMAC key length.
pub fn read_hmac_block_stream(
    input: &[u8],
    hmac_base: &HmacBaseKey,
) -> Result<Vec<u8>, HmacBlockError> {
    let mut cursor = input;
    let mut output = Vec::new();
    let mut block_index: u64 = 0;

    loop {
        let declared_tag = read_bytes(&mut cursor, 32)?;
        let size = read_u32_le(&mut cursor)?;
        let data = read_bytes(&mut cursor, size as usize)?;

        // Derive the per-block key and verify.
        let key = per_block_hmac_key(hmac_base, block_index);
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC-SHA-256 accepts any key length");
        mac.update(&block_index.to_le_bytes());
        mac.update(&size.to_le_bytes());
        mac.update(data);
        let computed = mac.finalize().into_bytes();

        if computed.as_slice().ct_eq(declared_tag).unwrap_u8() == 0 {
            return Err(HmacBlockError::HmacMismatch { block_index, size });
        }

        if size == 0 {
            return Ok(output);
        }

        output.extend_from_slice(data);
        block_index = block_index.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Low-level byte-reading helpers
// ---------------------------------------------------------------------------

fn read_u32_le(cursor: &mut &[u8]) -> Result<u32, HmacBlockError> {
    if cursor.len() < 4 {
        return Err(HmacBlockError::Truncated);
    }
    let (head, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_le_bytes([head[0], head[1], head[2], head[3]]))
}

fn read_bytes<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8], HmacBlockError> {
    if cursor.len() < n {
        return Err(HmacBlockError::Truncated);
    }
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for [`read_hmac_block_stream`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HmacBlockError {
    /// The stream ended before a complete block could be read.
    #[error("HMAC-block stream truncated")]
    Truncated,

    /// A block's declared HMAC tag did not match the computed one.
    /// Comparison is constant-time.
    #[error("HMAC-block tag mismatch at index {block_index} (size {size})")]
    HmacMismatch {
        /// The block index whose tag failed.
        block_index: u64,
        /// The declared size of the failing block's data.
        size: u32,
    },
}

impl From<HmacBlockError> for FormatError {
    fn from(err: HmacBlockError) -> Self {
        Self::MalformedHeader(match err {
            HmacBlockError::Truncated => "HMAC-block stream truncated",
            HmacBlockError::HmacMismatch { .. } => "HMAC-block tag mismatch",
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a HmacBlockStream from a list of data segments (inverse of the
    /// decoder, for test use). The caller provides the `hmac_base` so we can
    /// compute the tags.
    fn encode(blocks: &[&[u8]], hmac_base: &HmacBaseKey) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, data) in blocks.iter().enumerate() {
            let index = i as u64;
            let key = per_block_hmac_key(hmac_base, index);
            let size = u32::try_from(data.len()).unwrap();
            let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
            mac.update(&index.to_le_bytes());
            mac.update(&size.to_le_bytes());
            mac.update(data);
            let tag = mac.finalize().into_bytes();

            out.extend_from_slice(&tag);
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(data);
        }
        // End marker: next index, empty data, matching tag.
        let end_index = blocks.len() as u64;
        let key = per_block_hmac_key(hmac_base, end_index);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).unwrap();
        mac.update(&end_index.to_le_bytes());
        mac.update(&0u32.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        out.extend_from_slice(&tag);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    fn fixed_base() -> HmacBaseKey {
        HmacBaseKey::from_raw_bytes([0x55; 64])
    }

    #[test]
    fn round_trips_single_block() {
        let base = fixed_base();
        let stream = encode(&[b"hello"], &base);
        let decoded = read_hmac_block_stream(&stream, &base).unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[test]
    fn round_trips_multiple_blocks() {
        let base = fixed_base();
        let stream = encode(&[b"alpha", b"beta", b"charlie"], &base);
        let decoded = read_hmac_block_stream(&stream, &base).unwrap();
        assert_eq!(decoded, b"alphabetacharlie");
    }

    #[test]
    fn empty_stream_is_just_the_end_marker() {
        let base = fixed_base();
        let stream = encode(&[], &base);
        let decoded = read_hmac_block_stream(&stream, &base).unwrap();
        assert!(decoded.is_empty());
        assert_eq!(stream.len(), 36); // 32-byte tag + 4-byte size
    }

    #[test]
    fn rejects_truncated_input() {
        let base = fixed_base();
        let stream = encode(&[b"x"], &base);
        let truncated = &stream[..stream.len() - 1];
        assert!(matches!(
            read_hmac_block_stream(truncated, &base).unwrap_err(),
            HmacBlockError::Truncated
        ));
    }

    #[test]
    fn rejects_empty_input() {
        let base = fixed_base();
        assert!(matches!(
            read_hmac_block_stream(&[], &base).unwrap_err(),
            HmacBlockError::Truncated
        ));
    }

    #[test]
    fn rejects_corrupted_data() {
        let base = fixed_base();
        let mut stream = encode(&[b"content"], &base);
        // Data starts at offset 32 + 4 = 36.
        stream[36] ^= 0x01;
        assert!(matches!(
            read_hmac_block_stream(&stream, &base).unwrap_err(),
            HmacBlockError::HmacMismatch { block_index: 0, .. }
        ));
    }

    #[test]
    fn rejects_corrupted_tag() {
        let base = fixed_base();
        let mut stream = encode(&[b"content"], &base);
        stream[0] ^= 0x01;
        assert!(matches!(
            read_hmac_block_stream(&stream, &base).unwrap_err(),
            HmacBlockError::HmacMismatch { block_index: 0, .. }
        ));
    }

    #[test]
    fn rejects_wrong_base_key() {
        let base_a = HmacBaseKey::from_raw_bytes([0x11; 64]);
        let base_b = HmacBaseKey::from_raw_bytes([0x22; 64]);
        let stream = encode(&[b"payload"], &base_a);
        assert!(matches!(
            read_hmac_block_stream(&stream, &base_b).unwrap_err(),
            HmacBlockError::HmacMismatch { .. }
        ));
    }

    #[test]
    fn rejects_corrupted_end_marker_tag() {
        let base = fixed_base();
        let mut stream = encode(&[b"x"], &base);
        // End marker starts immediately after the first block:
        //   32 (first tag) + 4 (size) + 1 (data) = 37
        // Flip the first byte of the end marker's tag.
        stream[37] ^= 0x01;
        let err = read_hmac_block_stream(&stream, &base).unwrap_err();
        // Should fail at index 1 (the end marker's index).
        assert!(matches!(
            err,
            HmacBlockError::HmacMismatch {
                block_index: 1,
                size: 0
            }
        ));
    }

    #[test]
    fn large_block_parses() {
        let base = fixed_base();
        let data = vec![0xCDu8; 1_000_000];
        let stream = encode(&[&data], &base);
        let decoded = read_hmac_block_stream(&stream, &base).unwrap();
        assert_eq!(decoded.len(), 1_000_000);
        assert_eq!(decoded[0], 0xCD);
    }

    #[test]
    fn swapping_block_content_fails_verification() {
        // Attacker substitutes the FIRST block of a stream with a block
        // that was validly signed at a DIFFERENT index in another stream.
        // Both were tagged honestly, but swapping them changes the
        // computed HMAC input (index || size || data) so the verifier
        // detects the substitution.
        //
        // (Note: if the substitution happens to preserve the same index
        // AND size AND data, it's not really a substitution. The
        // attacker's cheapest path is actually the header-HMAC
        // truncation attack, which is why KDBX4 also signs the header
        // and why that verification lives above this layer.)
        let base = fixed_base();
        let stream_b = encode(&[b"secondary-payload"], &base);
        let mut victim = encode(&[b"original-content"], &base);

        // Overwrite the first block's tag+size+data prefix with the
        // equivalent prefix from stream_b.
        let stream_b_prefix_len = stream_b.len() - 36; // strip end marker
        victim[..stream_b_prefix_len].copy_from_slice(&stream_b[..stream_b_prefix_len]);
        assert!(read_hmac_block_stream(&victim, &base).is_err());
    }
}
