//! Cryptographic primitives used by the KDBX format.
//!
//! This module owns the [`Cipher`] trait (sealed — see below), implementations
//! for AES-256-CBC, ChaCha20, and Salsa20, and key-derivation machinery for
//! Argon2 and the legacy AES-KDF used by KDBX3.
//!
//! All primitives are thin wrappers around audited [`RustCrypto`] crates.
//! This crate implements no cryptography itself.
//!
//! [`RustCrypto`]: https://github.com/RustCrypto

pub mod kdf;
pub mod master_keys;

pub use kdf::{KdfError, derive_transformed_key};
pub use master_keys::{derive_cipher_key, derive_hmac_base_key, per_block_hmac_key};

/// Error type for cryptographic operations.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum CryptoError {
    /// Key derivation failed.
    #[error("key derivation failed")]
    Kdf,

    /// Decryption failed — either the key is wrong or the ciphertext is
    /// corrupt. The two cases are deliberately not distinguished, as doing so
    /// would leak information to an attacker.
    #[error("decryption failed (wrong key or corrupt data)")]
    Decrypt,

    /// HMAC verification failed at a specific block index. In KDBX4 each
    /// 1 MiB block carries its own HMAC-SHA-256 tag; this variant identifies
    /// which block failed.
    #[error("HMAC verification failed at block {index}")]
    HmacMismatch {
        /// Zero-indexed position of the failing block.
        index: u64,
    },
}

// Sealed-trait guard. `Cipher` is implemented only for types within this
// crate. External crates may *call* `Cipher` methods but may not add new
// cipher variants — this lets us evolve the trait without a semver break.
mod sealed {
    pub trait Sealed {}
}

/// Trait implemented by supported block or stream ciphers.
///
/// This trait is
/// [sealed](https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed).
/// Consumers cannot implement it for their own types; new ciphers must be
/// added in this crate. This is deliberate — every cipher choice has
/// security implications and must be reviewed here.
pub trait Cipher: sealed::Sealed {
    // Method signatures filled in as implementations land.
}
