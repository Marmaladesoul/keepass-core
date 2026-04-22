//! Inner-stream ciphers for protected XML field values.
//!
//! KeePass XML carries two kinds of `<Value>` elements: plain text
//! for unprotected fields, and base64-encoded ciphertext for fields
//! marked `Protected="True"`. The ciphertext is XOR'd against a
//! stream-cipher keystream keyed by the vault's *inner-stream key*:
//!
//! | KDBX version | Default inner stream |
//! |--------------|----------------------|
//! | KDBX 3.x     | Salsa20              |
//! | KDBX 4.x     | ChaCha20 (or Salsa20 for older files) |
//!
//! The keystream is **not reset per field**: each protected `<Value>`
//! consumes from a single shared keystream in document order. A
//! consumer therefore instantiates one [`InnerStreamCipher`] per
//! vault-open and calls [`InnerStreamCipher::process`] in the
//! document's traversal order.
//!
//! ## Key and nonce derivation
//!
//! KeePass derives the stream-cipher key deterministically from the
//! single "inner-stream key" value carried in the header:
//!
//! - **Salsa20** always uses the well-known 8-byte nonce
//!   `[0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]` with the raw
//!   32-byte header key.
//! - **ChaCha20** hashes the header key with SHA-512, takes the first
//!   32 bytes as the key and the next 12 bytes as the nonce.
//!
//! Both are stream ciphers, so encrypt and decrypt are the same
//! operation (XOR with keystream). The name is "process" not
//! "decrypt" to reflect that.
//!
//! The cipher is deliberately not `Clone` — cloning would let callers
//! generate the same keystream twice, which in a stream cipher
//! produces catastrophic key-reuse. Advancing the stream is a
//! mutation; copies would desynchronise.

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit as _, StreamCipher as _};
use salsa20::Salsa20;
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::format::InnerStreamAlgorithm;

/// The 8-byte Salsa20 nonce fixed by the KeePass spec.
///
/// Defined in the KeePass 2.x source (`KdbHandler.cs`) as:
/// `new byte[] { 0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A }`.
pub const KEEPASS_SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

// ---------------------------------------------------------------------------
// InnerStreamCipher — stateful keystream applicator
// ---------------------------------------------------------------------------

/// A stateful stream cipher used to XOR the keystream over protected
/// `<Value>` fields in insertion order.
///
/// Construct via [`Self::new`] and call [`Self::process`] with each
/// base64-decoded ciphertext in the order the values appear in the
/// XML document. The cipher advances through its internal keystream;
/// re-running the same buffer through it will produce different
/// results.
///
/// `Debug` is implemented manually to redact the underlying cipher
/// state — exposing it would leak keystream bytes.
pub enum InnerStreamCipher {
    /// No inner-stream cipher — [`Self::process`] is a no-op.
    None,
    /// Salsa20 keystream over the caller's buffer.
    Salsa20(Box<Salsa20>),
    /// ChaCha20 keystream over the caller's buffer.
    ChaCha20(Box<ChaCha20>),
}

impl std::fmt::Debug for InnerStreamCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            Self::None => "None",
            Self::Salsa20(_) => "Salsa20",
            Self::ChaCha20(_) => "ChaCha20",
        };
        f.debug_tuple("InnerStreamCipher").field(&variant).finish()
    }
}

impl InnerStreamCipher {
    /// Build a new inner-stream cipher from an [`InnerStreamAlgorithm`]
    /// identifier and the single inner-stream key from the header.
    ///
    /// # Errors
    ///
    /// Returns [`InnerStreamError::InvalidKey`] if the key cannot be
    /// accepted by the selected cipher — for Salsa20 that means the
    /// key isn't 32 bytes; for ChaCha20 the post-SHA-512 derivation
    /// is always valid so we'd only hit this on genuinely adverse
    /// inputs from the `chacha20` crate.
    ///
    /// # Panics
    ///
    /// Does not panic under any input. The `.expect(...)` calls on
    /// `digest[..32]` and `digest[32..44]` are guaranteed by
    /// SHA-512 always producing 64 bytes.
    pub fn new(
        algorithm: InnerStreamAlgorithm,
        inner_stream_key: &[u8],
    ) -> Result<Self, InnerStreamError> {
        match algorithm {
            InnerStreamAlgorithm::None => Ok(Self::None),
            InnerStreamAlgorithm::Salsa20 => {
                let key: [u8; 32] =
                    inner_stream_key
                        .try_into()
                        .map_err(|_| InnerStreamError::InvalidKey {
                            algorithm,
                            detail: "Salsa20 requires a 32-byte key",
                        })?;
                let cipher = Salsa20::new(&key.into(), &KEEPASS_SALSA20_NONCE.into());
                Ok(Self::Salsa20(Box::new(cipher)))
            }
            InnerStreamAlgorithm::ChaCha20 => {
                // KeePass spec: SHA-512 of the header key; first 32 bytes
                // are the ChaCha20 key, next 12 bytes are the nonce.
                let digest = Sha512::digest(inner_stream_key);
                let key: [u8; 32] = digest[..32].try_into().expect("SHA-512 is 64 bytes");
                let nonce: [u8; 12] = digest[32..44].try_into().expect("SHA-512 is 64 bytes");
                let cipher = ChaCha20::new(&key.into(), &nonce.into());
                Ok(Self::ChaCha20(Box::new(cipher)))
            }
        }
    }

    /// XOR the keystream over `buf` in place, advancing the internal
    /// keystream by `buf.len()` bytes.
    ///
    /// For [`Self::None`], does nothing.
    pub fn process(&mut self, buf: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Salsa20(c) => c.apply_keystream(buf),
            Self::ChaCha20(c) => c.apply_keystream(buf),
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for inner-stream cipher construction.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InnerStreamError {
    /// The inner-stream key was not acceptable to the selected cipher.
    #[error("inner-stream key invalid for {algorithm:?}: {detail}")]
    InvalidKey {
        /// Which algorithm was selected.
        algorithm: InnerStreamAlgorithm,
        /// Human-readable detail about the problem.
        detail: &'static str,
    },
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_passthrough() {
        let mut c = InnerStreamCipher::new(InnerStreamAlgorithm::None, &[]).unwrap();
        let mut buf = *b"unchanged";
        let before = buf;
        c.process(&mut buf);
        assert_eq!(buf, before);
    }

    #[test]
    fn salsa20_xor_is_involutive() {
        // Stream ciphers are self-inverse: applying twice yields the
        // original buffer.
        let key = [0x42u8; 32];
        let plaintext = b"The quick brown fox jumps over the lazy dog.".to_vec();

        let mut c1 = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let mut buf = plaintext.clone();
        c1.process(&mut buf);
        assert_ne!(buf, plaintext, "Salsa20 should have altered the buffer");

        // Re-apply with a fresh cipher instance (fresh keystream) → inverse.
        let mut c2 = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        c2.process(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn chacha20_xor_is_involutive() {
        let key = b"my-inner-stream-key-opaque-bytes".to_vec();
        let plaintext = b"secret value 123".to_vec();

        let mut c1 = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        let mut buf = plaintext.clone();
        c1.process(&mut buf);
        assert_ne!(buf, plaintext);

        let mut c2 = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        c2.process(&mut buf);
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn chacha20_accepts_any_length_key() {
        // ChaCha20's SHA-512 derivation means any key length works.
        for key_len in [0, 1, 16, 32, 64, 128] {
            let key = vec![0x55u8; key_len];
            assert!(InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).is_ok());
        }
    }

    #[test]
    fn salsa20_requires_32_byte_key() {
        for key_len in [0, 16, 24, 31, 33, 64] {
            let key = vec![0x55u8; key_len];
            let err = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap_err();
            assert!(matches!(
                err,
                InnerStreamError::InvalidKey {
                    algorithm: InnerStreamAlgorithm::Salsa20,
                    ..
                }
            ));
        }
        // Exactly 32 bytes is accepted.
        assert!(InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &[0u8; 32]).is_ok());
    }

    #[test]
    fn keystream_advances_across_calls() {
        // Two calls of 8 bytes should produce the same result as one
        // call of 16 bytes — the keystream is continuous.
        let key = [0u8; 32];
        let plaintext = [0xAAu8; 16];

        let mut one_shot = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let mut a = plaintext;
        one_shot.process(&mut a);

        let mut two_shot = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let mut b = plaintext;
        let (first, second) = b.split_at_mut(8);
        two_shot.process(first);
        two_shot.process(second);
        assert_eq!(a, b);
    }

    #[test]
    fn different_keys_produce_different_streams() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let buf_plain = [0u8; 32];

        let mut a = buf_plain;
        InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key_a)
            .unwrap()
            .process(&mut a);

        let mut b = buf_plain;
        InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key_b)
            .unwrap()
            .process(&mut b);

        assert_ne!(a, b);
    }

    #[test]
    fn salsa20_and_chacha20_produce_different_streams_for_same_key() {
        let key = [0u8; 32];
        let buf_plain = [0u8; 32];

        let mut salsa_out = buf_plain;
        InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key)
            .unwrap()
            .process(&mut salsa_out);

        let mut chacha_out = buf_plain;
        InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key)
            .unwrap()
            .process(&mut chacha_out);

        assert_ne!(salsa_out, chacha_out);
    }

    #[test]
    fn empty_buffer_is_fine() {
        let mut c = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &[0u8; 32]).unwrap();
        let mut empty: [u8; 0] = [];
        c.process(&mut empty);
        // If we got here, the cipher accepted a zero-byte input without
        // panicking — which is what we want.
    }

    #[test]
    fn salsa20_nonce_constant_is_canonical() {
        // Guard against accidental edits — the KeePass-family Salsa20
        // nonce is fixed by the spec.
        assert_eq!(
            KEEPASS_SALSA20_NONCE,
            [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A]
        );
    }
}
