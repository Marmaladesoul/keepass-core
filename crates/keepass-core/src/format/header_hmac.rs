//! KDBX4 outer-header HMAC verification.
//!
//! In KDBX4, the encrypted payload is preceded by two 32-byte tags:
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │   (header bytes, signature + TLVs)    │
//! │   ...                                 │
//! │   (end-of-header record)              │
//! ├──────────────────────────────────────┤
//! │   SHA-256 of all header bytes: 32 B   │  ← "header hash"
//! ├──────────────────────────────────────┤
//! │   Header HMAC-SHA-256: 32 B            │  ← signs all header bytes
//! ├──────────────────────────────────────┤
//! │   HmacBlockStream of encrypted payload│
//! └──────────────────────────────────────┘
//! ```
//!
//! The **header hash** is a plain SHA-256 of the bytes from file start
//! through end-of-header, bound by convention but not by the master key —
//! it detects accidental corruption but not deliberate tampering.
//!
//! The **header HMAC** is an HMAC-SHA-256 over the same header bytes,
//! using a per-block HMAC key at the sentinel block index
//! [`super::HEADER_HMAC_BLOCK_INDEX`] (`u64::MAX`). Because the key
//! depends on the composite key + master seed, a wrong password
//! produces a mismatched tag — the header HMAC is the first
//! authentication check on a KDBX4 open.
//!
//! This module verifies both. Compared in constant time.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

use super::{HEADER_HMAC_BLOCK_INDEX, hmac_block_stream};
use crate::crypto::per_block_hmac_key;
use crate::secret::HmacBaseKey;

type HmacSha256 = Hmac<Sha256>;

// Ensure the module-internal constant we reference in docs lives on —
// this keeps the path `hmac_block_stream::HEADER_HMAC_BLOCK_INDEX` stable
// if the re-export shape ever changes.
#[allow(dead_code)]
const _: u64 = hmac_block_stream::HEADER_HMAC_BLOCK_INDEX;

/// Verify the SHA-256 header hash.
///
/// The hash lives immediately after the end-of-header record in the
/// file. A mismatch indicates either corruption or a truncated read.
/// The hash is **not** keyed — it's a simple integrity check, not an
/// authentication check. The HMAC that follows is the authentication
/// step.
///
/// # Errors
///
/// Returns [`HeaderAuthError::HeaderHashMismatch`] if the SHA-256 of
/// `header_bytes` does not equal `declared_hash`. Compared in
/// constant time.
pub fn verify_header_hash(
    header_bytes: &[u8],
    declared_hash: &[u8; 32],
) -> Result<(), HeaderAuthError> {
    let computed = Sha256::digest(header_bytes);
    if computed.as_slice().ct_eq(declared_hash).unwrap_u8() == 0 {
        return Err(HeaderAuthError::HeaderHashMismatch);
    }
    Ok(())
}

/// Verify the KDBX4 header HMAC-SHA-256 tag.
///
/// The tag lives immediately after the header hash in the file and is
/// computed as:
///
/// ```text
///   key = per_block_hmac_key(hmac_base, HEADER_HMAC_BLOCK_INDEX)
///   tag = HMAC-SHA-256(key, header_bytes)
/// ```
///
/// A mismatch indicates either a wrong password (the `hmac_base` is
/// derived from the composite key) or a tampered header.
///
/// # Errors
///
/// Returns [`HeaderAuthError::HeaderHmacMismatch`] on any tag mismatch.
/// Compared in constant time. We do not distinguish "wrong password"
/// from "tampered header" per the error-collapse discipline in design
/// doc §4.8.7 — distinguishing would leak information to an attacker.
///
/// # Panics
///
/// Does not panic under any input. The internal `HmacSha256::new_from_slice`
/// call receives a 64-byte key derived from SHA-512, always a valid HMAC
/// key length.
pub fn verify_header_hmac(
    header_bytes: &[u8],
    declared_tag: &[u8; 32],
    hmac_base: &HmacBaseKey,
) -> Result<(), HeaderAuthError> {
    let key = per_block_hmac_key(hmac_base, HEADER_HMAC_BLOCK_INDEX);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key)
        .expect("HMAC-SHA-256 accepts any key length");
    mac.update(header_bytes);
    let computed = mac.finalize().into_bytes();

    if computed.as_slice().ct_eq(declared_tag).unwrap_u8() == 0 {
        return Err(HeaderAuthError::HeaderHmacMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for header hash / HMAC verification.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HeaderAuthError {
    /// The plain SHA-256 header hash did not match.
    #[error("KDBX4 header hash does not match stored value (corrupt or truncated file)")]
    HeaderHashMismatch,

    /// The keyed HMAC-SHA-256 header tag did not match.
    ///
    /// In practice this means either the master password is wrong or
    /// the header has been tampered with. The two cases are not
    /// distinguished; distinguishing them would leak information to
    /// an attacker.
    #[error("KDBX4 header HMAC mismatch (wrong password or tampered header)")]
    HeaderHmacMismatch,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(bytes));
        out
    }

    fn hmac_tag(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
        mac.update(data);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn fixed_base() -> HmacBaseKey {
        HmacBaseKey::from_raw_bytes([0x55; 64])
    }

    #[test]
    fn header_hash_accepts_correct_value() {
        let header = b"pretend this is a 300-byte header";
        let hash = sha256(header);
        assert!(verify_header_hash(header, &hash).is_ok());
    }

    #[test]
    fn header_hash_rejects_mismatch() {
        let header = b"original header";
        let wrong = [0u8; 32];
        assert!(matches!(
            verify_header_hash(header, &wrong).unwrap_err(),
            HeaderAuthError::HeaderHashMismatch
        ));
    }

    #[test]
    fn header_hash_rejects_one_bit_corruption_of_body() {
        let mut header = b"original header".to_vec();
        let hash = sha256(&header);
        header[0] ^= 0x01;
        assert!(matches!(
            verify_header_hash(&header, &hash).unwrap_err(),
            HeaderAuthError::HeaderHashMismatch
        ));
    }

    #[test]
    fn header_hmac_accepts_correct_value() {
        let header = b"pretend header";
        let base = fixed_base();
        let key = per_block_hmac_key(&base, HEADER_HMAC_BLOCK_INDEX);
        let tag = hmac_tag(&key, header);
        assert!(verify_header_hmac(header, &tag, &base).is_ok());
    }

    #[test]
    fn header_hmac_rejects_wrong_tag() {
        let header = b"header";
        let base = fixed_base();
        let bad_tag = [0u8; 32];
        assert!(matches!(
            verify_header_hmac(header, &bad_tag, &base).unwrap_err(),
            HeaderAuthError::HeaderHmacMismatch
        ));
    }

    #[test]
    fn header_hmac_rejects_wrong_base_key() {
        let header = b"same header";
        let base_a = HmacBaseKey::from_raw_bytes([0x11; 64]);
        let base_b = HmacBaseKey::from_raw_bytes([0x22; 64]);
        let key_a = per_block_hmac_key(&base_a, HEADER_HMAC_BLOCK_INDEX);
        let tag = hmac_tag(&key_a, header);
        // Verify with the wrong base — should fail.
        assert!(matches!(
            verify_header_hmac(header, &tag, &base_b).unwrap_err(),
            HeaderAuthError::HeaderHmacMismatch
        ));
        // Same base is fine.
        assert!(verify_header_hmac(header, &tag, &base_a).is_ok());
    }

    #[test]
    fn header_hmac_rejects_one_bit_corruption_of_body() {
        let base = fixed_base();
        let key = per_block_hmac_key(&base, HEADER_HMAC_BLOCK_INDEX);
        let mut header = b"original header".to_vec();
        let tag = hmac_tag(&key, &header);
        header[0] ^= 0x01;
        assert!(matches!(
            verify_header_hmac(&header, &tag, &base).unwrap_err(),
            HeaderAuthError::HeaderHmacMismatch
        ));
    }

    #[test]
    fn header_hmac_rejects_one_bit_corruption_of_tag() {
        let base = fixed_base();
        let key = per_block_hmac_key(&base, HEADER_HMAC_BLOCK_INDEX);
        let header = b"header".to_vec();
        let mut tag = hmac_tag(&key, &header);
        tag[0] ^= 0x01;
        assert!(matches!(
            verify_header_hmac(&header, &tag, &base).unwrap_err(),
            HeaderAuthError::HeaderHmacMismatch
        ));
    }

    #[test]
    fn empty_header_is_handled() {
        // Degenerate case: a zero-length header. Both hash and HMAC should
        // still be computable and verifiable.
        let base = fixed_base();
        let hash = sha256(&[]);
        assert!(verify_header_hash(&[], &hash).is_ok());
        let key = per_block_hmac_key(&base, HEADER_HMAC_BLOCK_INDEX);
        let tag = hmac_tag(&key, &[]);
        assert!(verify_header_hmac(&[], &tag, &base).is_ok());
    }
}
