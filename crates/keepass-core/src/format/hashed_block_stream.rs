//! KDBX3 `HashedBlockStream` decoder.
//!
//! In KDBX3 the decrypted outer payload is structured as:
//!
//! ```text
//! ┌──────────────────────────────┐
//! │ 32 bytes: StreamStartBytes   │  ← sentinel, must match header
//! ├──────────────────────────────┤
//! │ HashedBlockStream:           │
//! │   ( block_index: u32 LE      │
//! │     hash: [u8; 32]           │  ← SHA-256 of `data`
//! │     size: u32 LE             │
//! │     data: [u8; size] )*      │
//! │   ( 0_u32, [0; 32], 0_u32 )  │  ← end marker
//! └──────────────────────────────┘
//! ```
//!
//! The hash in each block is SHA-256 over `data`. This module verifies
//! every block's hash and returns the concatenation of the `data`
//! segments. The end marker carries a size of zero and an all-zero hash;
//! any mismatch on the sentinel is itself a hard error.
//!
//! The `block_index` field is expected to count up sequentially from
//! zero. In practice KeePass clients always emit this correctly; we
//! verify it rather than silently accept out-of-order blocks.
//!
//! KDBX4 has a different (HMAC-based) block stream and lives in the
//! sibling module `hmac_block_stream`.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::FormatError;

/// Decode a KDBX3 `HashedBlockStream` into the concatenation of its
/// `data` segments.
///
/// The input is the bytes of the stream (starting with the first block,
/// i.e. *after* the 32-byte StreamStartBytes sentinel). On success,
/// returns the reassembled payload; trailing bytes after the end marker
/// are ignored.
///
/// # Errors
///
/// - [`HashedBlockError::Truncated`] if a block header or data segment
///   runs off the end of the input.
/// - [`HashedBlockError::BlockIndexOutOfOrder`] if the `block_index`
///   fields do not count up sequentially from zero.
/// - [`HashedBlockError::HashMismatch`] if a non-empty block's declared
///   hash does not match SHA-256 of its data. Compared in constant time.
/// - [`HashedBlockError::MalformedEndMarker`] if the end marker's hash
///   is not all zeros.
pub fn read_hashed_block_stream(input: &[u8]) -> Result<Vec<u8>, HashedBlockError> {
    let mut cursor = input;
    let mut output = Vec::new();
    let mut expected_index: u32 = 0;

    loop {
        let block_index = read_u32_le(&mut cursor)?;
        let declared_hash = read_bytes(&mut cursor, 32)?;
        let size = read_u32_le(&mut cursor)?;

        if size == 0 {
            // End marker. The hash must be all zeros; anything else is a
            // malformed stream.
            if !declared_hash.iter().all(|&b| b == 0) {
                return Err(HashedBlockError::MalformedEndMarker);
            }
            return Ok(output);
        }

        if block_index != expected_index {
            return Err(HashedBlockError::BlockIndexOutOfOrder {
                expected: expected_index,
                got: block_index,
            });
        }

        let data = read_bytes(&mut cursor, size as usize)?;

        // SHA-256 the data and compare in constant time.
        let computed = Sha256::digest(data);
        if computed.as_slice().ct_eq(declared_hash).unwrap_u8() == 0 {
            return Err(HashedBlockError::HashMismatch { block_index, size });
        }

        output.extend_from_slice(data);
        expected_index = expected_index.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// Low-level byte-reading helpers
// ---------------------------------------------------------------------------

fn read_u32_le(cursor: &mut &[u8]) -> Result<u32, HashedBlockError> {
    if cursor.len() < 4 {
        return Err(HashedBlockError::Truncated);
    }
    let (head, rest) = cursor.split_at(4);
    *cursor = rest;
    Ok(u32::from_le_bytes([head[0], head[1], head[2], head[3]]))
}

fn read_bytes<'a>(cursor: &mut &'a [u8], n: usize) -> Result<&'a [u8], HashedBlockError> {
    if cursor.len() < n {
        return Err(HashedBlockError::Truncated);
    }
    let (head, rest) = cursor.split_at(n);
    *cursor = rest;
    Ok(head)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for [`read_hashed_block_stream`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HashedBlockError {
    /// A block header or data segment ran off the end of the input.
    #[error("hashed-block stream truncated")]
    Truncated,

    /// The `block_index` field did not count up sequentially from zero.
    #[error("hashed-block index out of order: expected {expected}, got {got}")]
    BlockIndexOutOfOrder {
        /// The next index the decoder was expecting.
        expected: u32,
        /// The index actually present in the stream.
        got: u32,
    },

    /// A block's declared hash did not match SHA-256 of its data.
    /// The comparison itself is constant-time.
    #[error("hashed-block hash mismatch at index {block_index} (size {size})")]
    HashMismatch {
        /// The block index that failed.
        block_index: u32,
        /// The size of the failing block's data.
        size: u32,
    },

    /// The end marker carried a non-zero hash. Per the KDBX3 spec, the
    /// end-marker block has `size = 0` and a 32-byte all-zero hash.
    #[error("hashed-block end marker has non-zero hash")]
    MalformedEndMarker,
}

impl From<HashedBlockError> for FormatError {
    fn from(err: HashedBlockError) -> Self {
        // Funnel into the format-level error type at the call site. The
        // enum variant is deliberately coarse; callers that want the
        // inner distinction should match on HashedBlockError directly.
        Self::MalformedHeader(match err {
            HashedBlockError::Truncated => "hashed-block stream truncated",
            HashedBlockError::BlockIndexOutOfOrder { .. } => "hashed-block index out of order",
            HashedBlockError::HashMismatch { .. } => "hashed-block hash mismatch",
            HashedBlockError::MalformedEndMarker => "hashed-block end marker malformed",
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a HashedBlockStream from a list of data segments — a one-to-one
    /// inverse of the decoder, for tests only.
    fn encode(blocks: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, data) in blocks.iter().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let index = i as u32;
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&Sha256::digest(data));
            #[allow(clippy::cast_possible_truncation)]
            let size = data.len() as u32;
            out.extend_from_slice(&size.to_le_bytes());
            out.extend_from_slice(data);
        }
        // End marker: index = blocks.len(), hash = all zeros, size = 0.
        #[allow(clippy::cast_possible_truncation)]
        let end_index = blocks.len() as u32;
        out.extend_from_slice(&end_index.to_le_bytes());
        out.extend_from_slice(&[0u8; 32]);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn round_trips_single_block() {
        let stream = encode(&[b"hello, world"]);
        let decoded = read_hashed_block_stream(&stream).unwrap();
        assert_eq!(decoded, b"hello, world");
    }

    #[test]
    fn round_trips_multiple_blocks() {
        let a = b"alpha";
        let b = b"beta";
        let c = b"charlie";
        let stream = encode(&[a, b, c]);
        let decoded = read_hashed_block_stream(&stream).unwrap();
        assert_eq!(decoded, [&a[..], &b[..], &c[..]].concat());
    }

    #[test]
    fn empty_stream_is_just_the_end_marker() {
        let stream = encode(&[]);
        let decoded = read_hashed_block_stream(&stream).unwrap();
        assert!(decoded.is_empty());
        // end marker is 4 + 32 + 4 = 40 bytes exactly
        assert_eq!(stream.len(), 40);
    }

    #[test]
    fn trailing_bytes_after_end_marker_are_ignored() {
        let mut stream = encode(&[b"x"]);
        stream.extend_from_slice(b"trailing garbage that should be ignored");
        let decoded = read_hashed_block_stream(&stream).unwrap();
        assert_eq!(decoded, b"x");
    }

    #[test]
    fn rejects_truncated_input() {
        let stream = encode(&[b"data"]);
        // Cut off the last byte — truncates the end marker's size field.
        let truncated = &stream[..stream.len() - 1];
        assert!(matches!(
            read_hashed_block_stream(truncated).unwrap_err(),
            HashedBlockError::Truncated
        ));
    }

    #[test]
    fn rejects_truncated_inside_block_data() {
        let mut stream = encode(&[b"longer data here"]);
        // Strip off the final byte of the first block's data + everything after.
        // Tag the data's start: header is 4 + 32 + 4 = 40 bytes, then 16 bytes of data.
        stream.truncate(40 + 8); // keep half the data
        assert!(matches!(
            read_hashed_block_stream(&stream).unwrap_err(),
            HashedBlockError::Truncated
        ));
    }

    #[test]
    fn rejects_wrong_block_index() {
        let mut stream = encode(&[b"a", b"b"]);
        // The second block's index lives at offset 40 + 1 (= after first block).
        // More precisely: first block header is 40 bytes, then 1 byte of data.
        // Second block's index starts at offset 41.
        let pos = 4 + 32 + 4 + 1; // = 41
        assert_eq!(
            u32::from_le_bytes([
                stream[pos],
                stream[pos + 1],
                stream[pos + 2],
                stream[pos + 3]
            ]),
            1
        );
        stream[pos] = 42;
        let err = read_hashed_block_stream(&stream).unwrap_err();
        assert!(matches!(
            err,
            HashedBlockError::BlockIndexOutOfOrder {
                expected: 1,
                got: 42
            }
        ));
    }

    #[test]
    fn rejects_corrupted_data() {
        let mut stream = encode(&[b"important data"]);
        // The data lives at offset 40 (after the first header).
        stream[40] ^= 0x01;
        let err = read_hashed_block_stream(&stream).unwrap_err();
        assert!(matches!(
            err,
            HashedBlockError::HashMismatch { block_index: 0, .. }
        ));
    }

    #[test]
    fn rejects_corrupted_hash() {
        let mut stream = encode(&[b"data"]);
        // The hash lives at offset 4 (after the index).
        stream[4] ^= 0x01;
        let err = read_hashed_block_stream(&stream).unwrap_err();
        assert!(matches!(
            err,
            HashedBlockError::HashMismatch { block_index: 0, .. }
        ));
    }

    #[test]
    fn rejects_non_zero_end_marker_hash() {
        let mut stream = encode(&[]);
        // End marker starts at offset 0 (empty stream). Its hash is at offset 4.
        stream[4] = 0x42;
        assert!(matches!(
            read_hashed_block_stream(&stream).unwrap_err(),
            HashedBlockError::MalformedEndMarker
        ));
    }

    #[test]
    fn accepts_zero_size_intermediate_block() {
        // The first block with size=0 terminates. But what if a client
        // emits what looks like an early end marker? Spec says size=0
        // always ends the stream. Verify that's what we do.
        let mut stream = encode(&[b"x"]);
        // Overwrite the first block's size field (at offset 36) with 0
        // and its hash field (offset 4..36) with zeros.
        for b in &mut stream[4..36] {
            *b = 0;
        }
        stream[36..40].copy_from_slice(&0u32.to_le_bytes());
        let decoded = read_hashed_block_stream(&stream).unwrap();
        // We terminated at the (now-zeroed) block-0; output is empty.
        assert!(decoded.is_empty());
    }

    #[test]
    fn large_block_parses() {
        let data = vec![0xABu8; 100_000];
        let stream = encode(&[&data]);
        let decoded = read_hashed_block_stream(&stream).unwrap();
        assert_eq!(decoded.len(), 100_000);
        assert_eq!(decoded[0], 0xAB);
    }

    #[test]
    fn hash_mismatch_compare_is_constant_time() {
        // We can't directly prove constant-time — the subtle crate handles
        // that guarantee — but we can at least verify the error path is
        // exercised on a hash that differs at various byte positions.
        for flip_byte in [0, 15, 31] {
            let mut stream = encode(&[b"consistent"]);
            stream[4 + flip_byte] ^= 0x80;
            assert!(matches!(
                read_hashed_block_stream(&stream).unwrap_err(),
                HashedBlockError::HashMismatch { .. }
            ));
        }
    }
}
