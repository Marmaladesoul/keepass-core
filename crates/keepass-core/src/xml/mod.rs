//! XML reading and writing for KDBX inner documents.
//!
//! KDBX's inner payload is a UTF-8 XML document with KeePass-specific
//! conventions (e.g. `Protected="True"` attributes on sensitive fields,
//! base64-encoded binary attachments, KeePass-flavoured timestamp encoding).
//! This module provides thin wrappers around [`quick-xml`] plus the
//! machinery for *unknown-element preservation* — the forward-compatibility
//! mechanism that lets a vault edited by this crate round-trip through newer
//! KeePass versions without losing fields this crate doesn't understand.
//!
//! [`quick-xml`]: https://docs.rs/quick-xml

/// Error type for XML-related failures.
#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum XmlError {
    /// The XML document was malformed.
    #[error("malformed XML: {0}")]
    Malformed(String),

    /// A required element was missing.
    #[error("missing required element: {0}")]
    MissingElement(&'static str),

    /// An element contained a value that could not be parsed.
    #[error("invalid value in element {element}: {detail}")]
    InvalidValue {
        /// The element whose value failed to parse.
        element: &'static str,
        /// Human-readable detail about the failure.
        detail: String,
    },
}
