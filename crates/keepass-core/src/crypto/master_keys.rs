//! Master-key derivation: combines the outer-header master seed with the
//! KDF-produced transformed key to produce:
//!
//! - **Cipher key** (32 bytes) — handed to the outer payload cipher (AES-256
//!   or ChaCha20). Used by both KDBX3 and KDBX4.
//! - **HMAC base key** (64 bytes) — KDBX4 only. Per-block HMAC keys are
//!   derived from this base at block-verification time.
//!
//! ## Formulas (per the KeePass KDBX4 spec)
//!
//! ```text
//!   cipher_key    = SHA-256( master_seed || transformed_key )
//!   hmac_base_key = SHA-512( master_seed || transformed_key || 0x01 )
//! ```
//!
//! The trailing `0x01` byte in the HMAC derivation is KeePass's
//! domain-separation marker, ensuring the cipher key and HMAC key are not
//! merely truncations of one another.

use sha2::{Digest, Sha256, Sha512};

use crate::format::MasterSeed;
use crate::secret::{CipherKey, HmacBaseKey, TransformedKey};

/// Derive the 32-byte outer-cipher key.
///
/// Used by both KDBX3 (AES-256-CBC) and KDBX4 (AES-256-CBC or ChaCha20) as
/// the key for the outer payload cipher.
#[must_use]
pub fn derive_cipher_key(master_seed: &MasterSeed, transformed_key: &TransformedKey) -> CipherKey {
    let mut hasher = Sha256::new();
    hasher.update(master_seed.0);
    hasher.update(transformed_key.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    CipherKey::from_raw_bytes(out)
}

/// Derive the 64-byte HMAC base key used by KDBX4 block verification.
///
/// KDBX3 has no equivalent — the format pre-dates authenticated encryption
/// and relies on a plaintext stream-start-bytes sentinel for tamper
/// detection. Only call this function when the outer header declares
/// `Version::V4`.
#[must_use]
pub fn derive_hmac_base_key(
    master_seed: &MasterSeed,
    transformed_key: &TransformedKey,
) -> HmacBaseKey {
    let mut hasher = Sha512::new();
    hasher.update(master_seed.0);
    hasher.update(transformed_key.as_bytes());
    // Domain-separation marker per KDBX4 spec.
    hasher.update([0x01u8]);
    let digest = hasher.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    HmacBaseKey::from_raw_bytes(out)
}

/// Derive the per-block HMAC key for the KDBX4 block at `block_index`.
///
/// Formula: `SHA-512( block_index_u64_le || hmac_base_key )`.
///
/// The block index is the zero-based 64-bit counter; the header's HMAC
/// uses the sentinel index `u64::MAX` (i.e. `0xFFFFFFFF_FFFFFFFF`).
#[must_use]
pub fn per_block_hmac_key(base: &HmacBaseKey, block_index: u64) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(block_index.to_le_bytes());
    hasher.update(base.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
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

    fn sha512(bytes: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out.copy_from_slice(&Sha512::digest(bytes));
        out
    }

    fn fixed_seed() -> MasterSeed {
        MasterSeed([0x33u8; 32])
    }

    fn fixed_transformed() -> TransformedKey {
        TransformedKey::from_raw_bytes([0x77u8; 32])
    }

    #[test]
    fn cipher_key_matches_reference_formula() {
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&[0x33; 32]);
        concat.extend_from_slice(&[0x77; 32]);
        let expected = sha256(&concat);

        let k = derive_cipher_key(&fixed_seed(), &fixed_transformed());
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn cipher_key_depends_on_seed() {
        let tk = fixed_transformed();
        let k1 = derive_cipher_key(&MasterSeed([0x01; 32]), &tk);
        let k2 = derive_cipher_key(&MasterSeed([0x02; 32]), &tk);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn cipher_key_depends_on_transformed_key() {
        let seed = fixed_seed();
        let k1 = derive_cipher_key(&seed, &TransformedKey::from_raw_bytes([0xAA; 32]));
        let k2 = derive_cipher_key(&seed, &TransformedKey::from_raw_bytes([0xBB; 32]));
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn hmac_base_key_matches_reference_formula() {
        let mut concat = Vec::with_capacity(65);
        concat.extend_from_slice(&[0x33; 32]);
        concat.extend_from_slice(&[0x77; 32]);
        concat.push(0x01);
        let expected = sha512(&concat);

        let k = derive_hmac_base_key(&fixed_seed(), &fixed_transformed());
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn cipher_key_and_hmac_base_are_independent() {
        // The 0x01 domain-separation byte should mean even the first 32
        // bytes of the SHA-512 output differ from the SHA-256 output.
        let ck = derive_cipher_key(&fixed_seed(), &fixed_transformed());
        let hk = derive_hmac_base_key(&fixed_seed(), &fixed_transformed());
        assert_ne!(ck.as_bytes(), &hk.as_bytes()[..32]);
    }

    #[test]
    fn per_block_hmac_key_is_deterministic() {
        let base = derive_hmac_base_key(&fixed_seed(), &fixed_transformed());
        let a = per_block_hmac_key(&base, 0);
        let b = per_block_hmac_key(&base, 0);
        assert_eq!(a, b);
    }

    #[test]
    fn per_block_hmac_key_differs_by_block_index() {
        let base = derive_hmac_base_key(&fixed_seed(), &fixed_transformed());
        let a = per_block_hmac_key(&base, 0);
        let b = per_block_hmac_key(&base, 1);
        let c = per_block_hmac_key(&base, u64::MAX);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn per_block_hmac_key_matches_reference_formula() {
        let base = derive_hmac_base_key(&fixed_seed(), &fixed_transformed());
        let index: u64 = 7;
        let mut concat = Vec::with_capacity(8 + 64);
        concat.extend_from_slice(&index.to_le_bytes());
        concat.extend_from_slice(base.as_bytes());
        let expected = sha512(&concat);

        let k = per_block_hmac_key(&base, index);
        assert_eq!(k, expected);
    }
}
