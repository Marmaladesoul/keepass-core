//! Secret-handling types.
//!
//! Every type in this module that holds key material follows four rules:
//!
//! 1. **`Zeroize` on `Drop`** — when the value goes out of scope, its bytes
//!    are wiped. Implemented via the [`zeroize`] crate's derive macros so
//!    the compiler cannot optimise the wipe away.
//! 2. **Heap-boxed inner buffer** — keys are held in `Box<[u8; N]>` rather
//!    than `[u8; N]` on the stack, so `mem::take` / move semantics cannot
//!    leave stale copies behind.
//! 3. **Manually redacted `Debug`** — formatters expose only a length, never
//!    the bytes. `Display` is deliberately not implemented.
//! 4. **Domain-specific newtypes** — a `CompositeKey` cannot be silently
//!    substituted for a `TransformedKey` or a `MasterKey`; each stage of
//!    the KDF pipeline takes a type that only that stage can produce.
//!
//! The composite-key derivation at the end of this module is the first
//! real use of these types: it combines a password and optional keyfile
//! hash into the 32-byte composite key that feeds the KDF stage.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
// CompositeKey — SHA-256 chain over (password, keyfile_hash)
// ---------------------------------------------------------------------------

/// The 32-byte composite key derived from a password and/or keyfile.
///
/// Per the KeePass spec, the composite key is:
///
/// ```text
/// SHA-256( SHA-256(password) || SHA-256(keyfile_material) )
/// ```
///
/// If only one of password or keyfile is supplied, that component is used
/// on its own (wrapped in an outer `SHA-256` for uniformity). KDBX files
/// that have neither are not representable; at least one must be present.
///
/// The composite key is the input to the KDF (AES-KDF or Argon2), which
/// produces the transformed key — see the next pipeline layer.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CompositeKey(Box<[u8; 32]>);

impl CompositeKey {
    /// Derive a composite key from a password only.
    ///
    /// Computes `SHA-256(SHA-256(password))`. The password bytes are hashed
    /// inside this function and never retained.
    #[must_use]
    pub fn from_password(password: &[u8]) -> Self {
        let inner = Sha256::digest(password);
        let outer = Sha256::digest(inner);
        Self(Box::new(outer.into()))
    }

    /// Derive a composite key from a keyfile hash only.
    ///
    /// The keyfile must have already been reduced to its 32-byte key
    /// material per the KeePass keyfile formats (binary, hex, XML v1,
    /// XML v2, or "raw file SHA-256"). Parsing the keyfile is a separate
    /// concern; this function takes the resulting 32 bytes.
    ///
    /// Computes `SHA-256(keyfile_hash)` (one extra outer hash for
    /// uniformity with the password+keyfile path).
    #[must_use]
    pub fn from_keyfile_hash(keyfile_hash: &[u8; 32]) -> Self {
        let outer = Sha256::digest(keyfile_hash);
        Self(Box::new(outer.into()))
    }

    /// Derive a composite key from both a password and a keyfile hash.
    ///
    /// Computes `SHA-256(SHA-256(password) || keyfile_hash)` — the
    /// KeePass standard.
    #[must_use]
    pub fn from_password_and_keyfile_hash(password: &[u8], keyfile_hash: &[u8; 32]) -> Self {
        let pwd_hash = Sha256::digest(password);
        let mut hasher = Sha256::new();
        hasher.update(pwd_hash);
        hasher.update(keyfile_hash);
        Self(Box::new(hasher.finalize().into()))
    }

    /// Construct a composite key from pre-computed 32 bytes. Useful for
    /// round-trip tests and reserved for callers that know what they're
    /// doing — the [`Self::from_password`] / [`Self::from_keyfile_hash`]
    /// constructors should be preferred for production use.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte key as a slice reference.
    ///
    /// Callers should keep the borrow as short as possible and never copy
    /// the bytes into a longer-lived `Vec` / `String` — the whole point of
    /// `CompositeKey`'s `Drop` is that the bytes vanish when it goes out
    /// of scope.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// TransformedKey — output of the KDF stage
// ---------------------------------------------------------------------------

/// The 32-byte transformed key — output of the KDF applied to a
/// [`CompositeKey`].
///
/// For KDBX3: AES-KDF of the composite key under `TransformSeed` for
/// `TransformRounds` rounds, then SHA-256 of the result.
///
/// For KDBX4: Argon2d / Argon2id of the composite key with the declared
/// parameters, direct 32-byte output.
///
/// This is the distinct-type reinforcement of §4.8.3's "newtype for every
/// semantic quantity" — a [`CompositeKey`] cannot be substituted for a
/// `TransformedKey` (or vice versa) even though they happen to share a
/// 32-byte width today.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct TransformedKey(Box<[u8; 32]>);

impl TransformedKey {
    /// Construct a transformed key from raw bytes. Intended for KDF
    /// implementations to emit their output; callers doing their own
    /// research may also use it.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte transformed key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TransformedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransformedKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// CipherKey — key handed to the outer AES-256 / ChaCha20 cipher
// ---------------------------------------------------------------------------

/// The 32-byte key handed to the outer payload cipher.
///
/// Derived as `SHA-256(master_seed || transformed_key)`. Used as-is by
/// AES-256-CBC (KDBX3 and KDBX4) and ChaCha20 (KDBX4 only).
///
/// Distinct type from [`TransformedKey`] even though both are 32 bytes:
/// substituting one for the other is a correctness bug, so the type
/// system prevents it.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CipherKey(Box<[u8; 32]>);

impl CipherKey {
    /// Construct a cipher key from raw bytes. Intended for the derivation
    /// function to emit; prefer
    /// [`crate::crypto::derive_cipher_key`] for the standard path.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte cipher key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// HmacKey — 64-byte base key for KDBX4 block HMAC verification
// ---------------------------------------------------------------------------

/// The 64-byte base key used to derive per-block HMAC keys in KDBX4.
///
/// Derived as `SHA-512(master_seed || transformed_key || 0x01)`. The
/// trailing 0x01 byte is KeePass's domain-separation marker.
///
/// Per-block HMAC keys are then computed as
/// `SHA-512(block_index_u64_le || base_key)` for each `u64` block
/// index. This module stores only the base; per-block derivation lives
/// with the block-verification logic.
///
/// KDBX3 has no HMAC step; this type is KDBX4-only.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct HmacBaseKey(Box<[u8; 64]>);

impl HmacBaseKey {
    /// Construct an HMAC base key from raw bytes. Intended for the
    /// derivation function; prefer [`crate::crypto::derive_hmac_base_key`]
    /// for the standard path.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 64]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 64-byte base key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for HmacBaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacBaseKey").field("len", &64).finish()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: SHA-256 as a 32-byte array, for constructing reference values
    /// in tests.
    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(bytes));
        out
    }

    #[test]
    fn password_only_matches_double_sha256() {
        let pw = b"correct horse battery staple";
        let expected = sha256(&sha256(pw));
        let k = CompositeKey::from_password(pw);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn keyfile_only_hashes_once_externally() {
        // The external "keyfile_hash" parameter is already a single SHA-256
        // (or equivalent 32-byte key material). `from_keyfile_hash` wraps
        // it in one more SHA-256 pass for uniformity.
        let keyfile_hash = [0x42u8; 32];
        let expected = sha256(&keyfile_hash);
        let k = CompositeKey::from_keyfile_hash(&keyfile_hash);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn password_plus_keyfile_concatenates_then_hashes() {
        let pw = b"hunter2";
        let keyfile_hash = [0x99u8; 32];
        // Expected = SHA-256( SHA-256(pw) || keyfile_hash )
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&sha256(pw));
        concat.extend_from_slice(&keyfile_hash);
        let expected = sha256(&concat);

        let k = CompositeKey::from_password_and_keyfile_hash(pw, &keyfile_hash);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn different_inputs_produce_different_keys() {
        let k1 = CompositeKey::from_password(b"alpha");
        let k2 = CompositeKey::from_password(b"beta");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn same_inputs_produce_identical_keys() {
        let k1 = CompositeKey::from_password(b"same");
        let k2 = CompositeKey::from_password(b"same");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn password_and_keyfile_yields_different_key_than_password_alone() {
        let pw = b"same";
        let keyfile_hash = [0x11u8; 32];
        let with_kf = CompositeKey::from_password_and_keyfile_hash(pw, &keyfile_hash);
        let pw_only = CompositeKey::from_password(pw);
        assert_ne!(with_kf.as_bytes(), pw_only.as_bytes());
    }

    #[test]
    fn empty_password_is_legal() {
        // KeePass permits a blank password (usually when a keyfile is the
        // sole factor). The chain still runs.
        let k = CompositeKey::from_password(b"");
        // SHA-256(SHA-256(b"")) is a deterministic known value.
        let expected = sha256(&sha256(b""));
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn from_raw_bytes_stores_as_is() {
        let raw = [0xAA; 32];
        let k = CompositeKey::from_raw_bytes(raw);
        assert_eq!(k.as_bytes(), &raw);
    }

    #[test]
    fn debug_output_is_redacted() {
        let k = CompositeKey::from_password(b"secret value");
        let s = format!("{k:?}");
        assert!(
            !s.contains("secret"),
            "Debug should not leak the input: {s}"
        );
        // We don't assert absence of specific bytes (too risky given hash
        // output); the generic check is that the structure exposes only
        // a length.
        assert!(s.contains("len"));
        assert!(s.contains("32"));
    }

    #[test]
    fn clone_produces_equal_key() {
        let k = CompositeKey::from_password(b"clone me");
        let k2 = k.clone();
        assert_eq!(k.as_bytes(), k2.as_bytes());
    }

    /// Reference vector — single-SHA of the empty string, for sanity.
    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn sha256_helper_matches_known_vector() {
        let h = sha256(b"");
        assert_eq!(
            h,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
        );
    }
}
