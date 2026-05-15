//! Optional in-memory wrap layer for protected-field plaintext.
//!
//! By default, [`Kdbx::<Unlocked>`](crate::kdbx::Kdbx) holds protected-field
//! plaintext in [`Entry::password`](crate::model::Entry::password) and
//! [`CustomField::value`](crate::model::CustomField::value) as ordinary Rust
//! `String`s — decrypted from the inner-stream cipher on unlock, re-encrypted
//! by the encoder on save. That matches what every other KeePass library
//! does, but it leaves protected-field bytes addressable in process memory
//! between unlock and save.
//!
//! Downstream consumers who want a stronger in-memory posture can implement
//! [`FieldProtector`] and pass it to
//! [`Kdbx::<HeaderRead>::unlock_with_protector`](crate::kdbx::Kdbx) or
//! [`Kdbx::<Unlocked>::create_empty_v4_with_protector`](crate::kdbx::Kdbx).
//!
//! ## Design: one key fetch per pass, AES-GCM in Rust
//!
//! The trait surface is a single method: [`FieldProtector::acquire_session_key`].
//! The implementation returns a 32-byte AES-256 key (typically derived from
//! a Secure Enclave / TPM / DPAPI primitive on the frontend). This crate
//! then performs AES-GCM seal/open in Rust against that key, with the raw
//! bytes held briefly in a [`SessionKey`] wrapper that zeroes on drop.
//!
//! Why a key, not per-field wrap/unwrap callbacks: the wrap pass at unlock
//! time touches every protected field across every history snapshot in
//! every entry — thousands of calls on a real vault. Routing each through
//! a Rust↔frontend callback (UniFFI marshalling + an SE IPC inside the
//! callback) cost ~16s on an 877-entry vault in production. Fetching the
//! key once and doing the seal/open locally collapses that to a single
//! cross-boundary call plus in-process AES-GCM (microseconds per field).
//!
//! ## Caller discipline
//!
//! Every site that needs the key fetches it via `acquire_session_key`,
//! uses it inside a scope, and lets the returned [`SessionKey`] drop —
//! which zeroes the underlying bytes. Implementations MUST treat each
//! call as a fresh request (no caching across calls on the frontend
//! side) so the bytes live in memory only for the duration of the
//! caller's scope.

use std::fmt::Debug;

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use zeroize::Zeroizing;

/// A 32-byte AES-256 session key for in-memory protected-field wrap.
///
/// Zeroes the underlying bytes on drop. Callers should hold instances
/// only inside the narrowest scope that needs them.
///
/// Constructed by [`FieldProtector`] implementations and consumed by
/// this crate's internal wrap/unwrap helpers.
#[derive(Clone)]
pub struct SessionKey(Zeroizing<[u8; 32]>);

impl SessionKey {
    /// Wrap a raw 32-byte key.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Borrow the underlying key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(<redacted>)")
    }
}

/// A pluggable provider of an AES-256 key used for in-memory protected-
/// field wrap.
///
/// Implementations must be `Send + Sync` so the protector can be shared
/// across threads alongside the unlocked vault.
///
/// The implementation is expected to do whatever the platform requires
/// to materialise the key (e.g. unwrap a Secure Enclave-wrapped blob)
/// and return the raw 32 bytes. The caller will zeroise the returned
/// [`SessionKey`] as soon as it's done.
pub trait FieldProtector: Send + Sync + Debug {
    /// Return the session AES-256 key for in-memory wrap.
    ///
    /// Called once per bulk pass (unlock wrap, save unwrap, conflict
    /// merge) and once per single-field operation (reveal, edit). The
    /// implementation is responsible for fetching/unwrapping its
    /// backing key material on each call — this crate does not cache
    /// the returned [`SessionKey`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtectorError::KeyUnavailable`] if the underlying key
    /// material can't be produced (e.g. Secure Enclave auth failure).
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError>;
}

/// Errors surfaced by a [`FieldProtector`] implementation or by the
/// in-process AES-GCM seal/open this module performs against the key.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtectorError {
    /// The implementation could not produce the session key.
    #[error("field protector key unavailable: {0}")]
    KeyUnavailable(String),

    /// AES-GCM seal failed against the supplied key.
    #[error("field protector seal failed: {0}")]
    Seal(String),

    /// AES-GCM open failed (auth tag mismatch or malformed ciphertext).
    #[error("field protector open failed: {0}")]
    Open(String),
}

/// Seal `plaintext` under `key` using AES-256-GCM. Returns
/// `nonce(12) || ciphertext || tag(16)`.
///
/// Used by this crate's wrap-pass and single-field wrap helpers. Not
/// part of the public trait surface — frontends never call this
/// directly.
pub(crate) fn seal_with_key(key: &SessionKey, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| ProtectorError::Seal(e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| ProtectorError::Seal(e.to_string()))?;
    let mut out = Vec::with_capacity(nonce.len() + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob previously produced by [`seal_with_key`].
pub(crate) fn open_with_key(key: &SessionKey, wrapped: &[u8]) -> Result<Vec<u8>, ProtectorError> {
    if wrapped.len() < 12 + 16 {
        return Err(ProtectorError::Open("wrapped blob too short".into()));
    }
    let (nonce_bytes, ciphertext) = wrapped.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes())
        .map_err(|e| ProtectorError::Open(e.to_string()))?;
    let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| ProtectorError::Open(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct FixedKey([u8; 32]);
    impl FieldProtector for FixedKey {
        fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
            Ok(SessionKey::from_bytes(self.0))
        }
    }

    #[test]
    fn round_trip() {
        let p = FixedKey([7u8; 32]);
        let k = p.acquire_session_key().unwrap();
        let sealed = seal_with_key(&k, b"hello world").unwrap();
        let opened = open_with_key(&k, &sealed).unwrap();
        assert_eq!(opened, b"hello world");
    }

    #[test]
    fn distinct_nonces_per_seal() {
        let p = FixedKey([3u8; 32]);
        let k = p.acquire_session_key().unwrap();
        let a = seal_with_key(&k, b"same").unwrap();
        let b = seal_with_key(&k, b"same").unwrap();
        assert_ne!(
            a, b,
            "AES-GCM uses random nonces — same plaintext should yield different ciphertext"
        );
    }

    #[test]
    fn open_rejects_short_blob() {
        let p = FixedKey([0u8; 32]);
        let k = p.acquire_session_key().unwrap();
        assert!(matches!(
            open_with_key(&k, &[0u8; 5]),
            Err(ProtectorError::Open(_))
        ));
    }
}
