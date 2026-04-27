//! XML reading and writing for KDBX inner documents.
//!
//! KDBX's inner payload is a UTF-8 XML document with KeePass-specific
//! conventions: `Protected="True"` attributes on sensitive fields, base64-
//! encoded binary attachments, KeePass-flavoured timestamp encoding, an
//! `<UnknownXML>`-like preservation discipline, and so on.
//!
//! This module provides thin wrappers around [`quick-xml`] for streaming
//! the inner document and extracting typed values from specific paths. The
//! full typed-model decoder (entries, groups, metadata) sits on top of
//! these primitives in a follow-up module.
//!
//! [`quick-xml`]: https://docs.rs/quick-xml

pub mod decoder;
pub mod encoder;
pub mod reader;

pub use decoder::{decode_vault, decode_vault_with_cipher};
pub use encoder::{encode_vault, encode_vault_kdbx3_with_cipher, encode_vault_with_cipher};
pub use reader::{XmlError, extract_generator, extract_text_at_path};
