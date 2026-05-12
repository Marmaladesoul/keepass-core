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
//! When set, the unlock pipeline wraps every protected-field plaintext via
//! the protector and replaces the in-model `String` with an empty placeholder.
//! Reveal-side access goes through
//! [`Kdbx::<Unlocked>::reveal_password`](crate::kdbx::Kdbx) and
//! [`Kdbx::<Unlocked>::reveal_custom_field`](crate::kdbx::Kdbx), which
//! unwrap via the same protector. On save, the protected plaintext is
//! reconstituted on a local clone of the vault before the encoder runs;
//! the canonical in-memory state stays in its wrapped shape across saves.
//!
//! The trait is intentionally simple: arbitrary bytes in, arbitrary bytes
//! out. The Keys app's downstream consumer implements `wrap` / `unwrap`
//! against a Secure Enclave–backed key whose plaintext never lives in
//! process memory; this crate stays oblivious to that detail.
//!
//! When no protector is set, behaviour is unchanged — protected plaintext
//! lives in `String` fields exactly as it does today.

use std::fmt::Debug;

/// A pluggable wrap / unwrap layer for protected-field plaintext.
///
/// Implementations transform between cleartext (the user-visible password
/// or custom-field value) and an opaque wrapped byte blob. The blob shape
/// is implementation-defined; this crate treats it as a sealed envelope.
///
/// Implementations must be `Send + Sync` so the protector can be shared
/// across threads alongside the unlocked vault.
///
/// `wrap` and `unwrap` must round-trip: `unwrap(wrap(x)) == x` for every
/// `x` an implementation accepts. They are not required to be deterministic
/// — implementations backed by a random nonce per call are fine, provided
/// the wrapped output decodes correctly.
pub trait FieldProtector: Send + Sync + Debug {
    /// Wrap `plaintext` into an opaque byte blob.
    ///
    /// # Errors
    ///
    /// Returns [`ProtectorError::Wrap`] if the underlying key is
    /// unavailable, the wrap operation fails, or the input is rejected
    /// by the implementation.
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError>;

    /// Unwrap a blob previously produced by [`Self::wrap`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtectorError::Unwrap`] if the blob is malformed, the
    /// underlying key is unavailable, or authentication fails.
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, ProtectorError>;
}

/// Errors surfaced by a [`FieldProtector`] implementation.
///
/// The two variants distinguish direction (wrap vs unwrap) so callers can
/// log the surrounding context without losing the implementation-supplied
/// detail. The detail is intentionally a `String` rather than a generic
/// `Box<dyn Error>` so this enum stays `Clone` / `PartialEq` for testing.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtectorError {
    /// A [`FieldProtector::wrap`] call failed.
    #[error("field protector wrap failed: {0}")]
    Wrap(String),

    /// A [`FieldProtector::unwrap`] call failed.
    #[error("field protector unwrap failed: {0}")]
    Unwrap(String),
}
