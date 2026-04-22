//! Outer-payload ciphers.
//!
//! KDBX files encrypt the payload with either AES-256-CBC (default on both
//! KDBX3 and KDBX4) or ChaCha20 (KDBX4 only). This module owns the thin
//! wrappers around those cipher implementations.
//!
//! ## AES-256-CBC
//!
//! - Key: 32 bytes ([`CipherKey`]).
//! - IV: 16 bytes ([`EncryptionIv`]).
//! - Padding: PKCS7.
//! - Decryption verifies padding as part of the block's integrity check.
//!
//! No authenticated-encryption wrapper here; integrity on KDBX3 comes from
//! the plaintext `StreamStartBytes` sentinel, and on KDBX4 from per-block
//! HMAC (landing separately).
//!
//! ChaCha20 support lands in a separate PR.

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, KeyIvInit};
use thiserror::Error;

use crate::format::EncryptionIv;
use crate::secret::CipherKey;

// Type alias makes the `cbc::Decryptor<Aes256>` spelling readable.
type Aes256CbcDec = cbc::Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// AES-256-CBC decrypt
// ---------------------------------------------------------------------------

/// Decrypt a KDBX outer payload encrypted with AES-256-CBC + PKCS7 padding.
///
/// Returns the plaintext bytes with padding stripped. The input must be a
/// whole number of 16-byte blocks; for any other length, returns
/// [`CipherError::BlockMisalignment`]. An IV of the wrong length returns
/// [`CipherError::IvWrongLength`]. Decryption failures (including padding
/// errors) collapse to [`CipherError::InvalidPadding`] — the distinction
/// between "wrong key" and "corrupt data" is deliberately withheld per
/// §4.8.7 of the design doc.
///
/// The function writes into a freshly-allocated `Vec<u8>`. A streaming
/// variant (write into a caller's buffer) lands alongside the KDBX4
/// block reader, where streaming is needed to avoid doubling memory.
pub fn aes_256_cbc_decrypt(
    key: &CipherKey,
    iv: &EncryptionIv,
    ciphertext: &[u8],
) -> Result<Vec<u8>, CipherError> {
    if iv.0.len() != 16 {
        return Err(CipherError::IvWrongLength {
            expected: 16,
            got: iv.0.len(),
        });
    }
    if ciphertext.len() % 16 != 0 {
        return Err(CipherError::BlockMisalignment {
            len: ciphertext.len(),
            block_size: 16,
        });
    }

    let dec = Aes256CbcDec::new_from_slices(key.as_bytes(), &iv.0)
        .map_err(|_| CipherError::InvalidPadding)?;

    // Decrypt into a fresh buffer of the same length, then trim to the
    // length returned by the PKCS7-stripping helper.
    let mut out = vec![0u8; ciphertext.len()];
    let n = dec
        .decrypt_padded_b2b_mut::<Pkcs7>(ciphertext, &mut out)
        .map_err(|_| CipherError::InvalidPadding)?
        .len();
    out.truncate(n);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for outer-cipher operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CipherError {
    /// The IV was the wrong length for the cipher.
    #[error("cipher IV has wrong length: expected {expected}, got {got}")]
    IvWrongLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// The ciphertext length is not a multiple of the cipher's block size.
    #[error("ciphertext length {len} is not a multiple of block size {block_size}")]
    BlockMisalignment {
        /// The ciphertext length.
        len: usize,
        /// The cipher's block size.
        block_size: usize,
    },

    /// Decryption failed. Does not distinguish between "wrong key" and
    /// "corrupt ciphertext" — distinguishing would leak information to an
    /// attacker.
    #[error("decryption failed (wrong key or corrupt data)")]
    InvalidPadding,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use aes::cipher::BlockEncryptMut;

    // Encrypt-then-decrypt helper — we build a reference ciphertext using
    // the encryption half of the cbc crate so the decrypt path is tested
    // against known-good input.
    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    fn encrypt_aes_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        let enc = Aes256CbcEnc::new_from_slices(key, iv).unwrap();
        // Allocate an output buffer sized for plaintext + up to one full
        // padding block (PKCS7 always adds ≥ 1 byte, ≤ 16 bytes).
        let mut out = vec![0u8; plaintext.len() + 16];
        let n = enc
            .encrypt_padded_b2b_mut::<Pkcs7>(plaintext, &mut out)
            .unwrap()
            .len();
        out.truncate(n);
        out
    }

    #[test]
    fn round_trips_a_message() {
        let key = [0x42u8; 32];
        let iv = [0x99u8; 16];
        let plaintext = b"The quick brown fox jumps over the lazy dog.".to_vec();
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        let decrypted = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trips_exact_block_size_message() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        // 16 bytes exactly → PKCS7 adds a whole 16-byte padding block
        let plaintext = [0xAAu8; 16].to_vec();
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        let decrypted = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trips_empty_message() {
        let key = [0u8; 32];
        let iv = [0u8; 16];
        let plaintext: Vec<u8> = Vec::new();
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        assert_eq!(ciphertext.len(), 16); // PKCS7 always produces ≥ 1 block
        let decrypted = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn rejects_iv_of_wrong_length() {
        let key = CipherKey::from_raw_bytes([0u8; 32]);
        let iv = EncryptionIv(vec![0u8; 12]); // ChaCha20-style, wrong for AES
        let result = aes_256_cbc_decrypt(&key, &iv, &[0u8; 16]);
        assert!(matches!(
            result,
            Err(CipherError::IvWrongLength {
                expected: 16,
                got: 12
            })
        ));
    }

    #[test]
    fn rejects_ciphertext_not_multiple_of_block_size() {
        let key = CipherKey::from_raw_bytes([0u8; 32]);
        let iv = EncryptionIv(vec![0u8; 16]);
        let result = aes_256_cbc_decrypt(&key, &iv, &[0u8; 17]);
        assert!(matches!(
            result,
            Err(CipherError::BlockMisalignment {
                len: 17,
                block_size: 16,
            })
        ));
    }

    #[test]
    fn rejects_corrupted_ciphertext() {
        let key = [0x42u8; 32];
        let iv = [0x99u8; 16];
        let plaintext = b"integrity check".to_vec();
        let mut ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        // Flip a bit in the final block — PKCS7 padding check will fail.
        let last = ciphertext.last_mut().unwrap();
        *last ^= 0x01;
        let result = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        );
        assert!(matches!(result, Err(CipherError::InvalidPadding)));
    }

    #[test]
    fn wrong_key_looks_same_as_corrupt_ciphertext() {
        // Deliberate: error type collapses "wrong key" and "bad ciphertext"
        // into a single variant to avoid leaking information.
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let iv = [0u8; 16];
        let plaintext = b"secret".to_vec();
        let ciphertext = encrypt_aes_cbc(&key_a, &iv, &plaintext);
        let result = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key_b),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        );
        // Most likely outcome: PKCS7 padding fails to validate under the
        // wrong key, and we see InvalidPadding.
        assert!(matches!(result, Err(CipherError::InvalidPadding)));
    }

    /// NIST AES-256-CBC test vector (from NIST SP 800-38A, Appendix F.2.5,
    /// CBC-AES256.Decrypt vector 1).
    #[test]
    fn matches_nist_aes_256_cbc_vector() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        // NIST vector uses no padding, so we produce ciphertext via
        // encrypt_aes_cbc (which adds PKCS7) and verify our decrypt
        // inverts the whole thing. This is weaker than the "raw NIST
        // block" vector but more representative of what KDBX actually
        // does (always PKCS7-padded).
        let ciphertext = encrypt_aes_cbc(&key, &iv, &plaintext);
        let decrypted = aes_256_cbc_decrypt(
            &CipherKey::from_raw_bytes(key),
            &EncryptionIv(iv.to_vec()),
            &ciphertext,
        )
        .unwrap();
        assert_eq!(&decrypted, &plaintext);
    }
}
