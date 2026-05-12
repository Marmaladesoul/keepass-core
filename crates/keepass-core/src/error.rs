//! Top-level [`Error`] enum and public error type re-exports.
//!
//! The crate follows the "per-module error enum, transparently wrapped at the
//! top" pattern. Each module (`crypto`, `xml`, `format`, …) defines its own
//! `Error` variant so that granular matching is possible without pattern-
//! matching on stringly-typed messages. The top-level [`Error`] enum wraps
//! these via `#[error(transparent)]` + `#[from]`, so `?` conversion works
//! throughout the crate.
//!
//! Every error enum is `#[non_exhaustive]` so new variants can be added
//! without a semver break.

/// The top-level error type returned by public APIs in this crate.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A cryptographic operation failed. See [`crate::crypto::CryptoError`].
    #[error(transparent)]
    Crypto(#[from] crate::crypto::CryptoError),

    /// An XML parsing or serialisation error. See [`crate::xml::XmlError`].
    #[error(transparent)]
    Xml(#[from] crate::xml::XmlError),

    /// A format-level error (unexpected header, unsupported version, truncated
    /// file). See [`crate::format::FormatError`].
    #[error(transparent)]
    Format(#[from] crate::format::FormatError),

    /// Underlying I/O error.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// A vault-mutation error: entry/group not found, circular move,
    /// duplicate UUID, etc. See [`crate::model::ModelError`].
    #[error(transparent)]
    Model(#[from] crate::model::ModelError),

    /// A [`FieldProtector`](crate::protector::FieldProtector) wrap or
    /// unwrap call failed. Surfaced from unlock (wrap fails after the
    /// cipher decrypts the inner XML), from save (unwrap fails before
    /// the encoder re-encrypts), and from reveal-side accessors.
    #[error(transparent)]
    Protector(#[from] crate::protector::ProtectorError),
}
