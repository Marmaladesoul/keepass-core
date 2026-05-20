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
pub use encoder::{
    encode_vault, encode_vault_kdbx3_with_cipher, encode_vault_kdbx3_with_cipher_and_header_hash,
    encode_vault_with_cipher,
};
pub use reader::{XmlError, extract_generator, extract_text_at_path};

// ---------------------------------------------------------------------------
// Entity-reference resolution (quick-xml v0.38+ migration)
// ---------------------------------------------------------------------------
//
// As of quick-xml 0.38, `Event::Text` no longer carries `&amp;`-style
// escape sequences inline — they're reported as a separate
// `Event::GeneralRef(BytesRef)` between two `Event::Text` events. Every
// text-collection loop has to handle the ref-arm itself.
//
// `resolve_general_ref` accepts the content between `&` and `;` and
// returns the expanded text. Predefined XML entities (`amp`, `lt`, `gt`,
// `quot`, `apos`) plus numeric character references (`#NN`, `#xNN`) are
// supported. Unknown entity names are rejected as `Malformed` — KDBX
// payloads come straight off our own encoder or another KeePass
// implementation, so non-standard entities would be a real anomaly.

pub(crate) fn resolve_general_ref(content: &[u8]) -> Result<String, XmlError> {
    let s = std::str::from_utf8(content)
        .map_err(|e| XmlError::Malformed(format!("entity ref not UTF-8: {e}")))?;
    if let Some(rest) = s.strip_prefix('#') {
        let cp = if let Some(hex) = rest.strip_prefix('x').or_else(|| rest.strip_prefix('X')) {
            u32::from_str_radix(hex, 16)
        } else {
            rest.parse::<u32>()
        }
        .map_err(|e| XmlError::Malformed(format!("bad numeric character reference &{s};: {e}")))?;
        let c = char::from_u32(cp)
            .ok_or_else(|| XmlError::Malformed(format!("character ref &{s}; out of range")))?;
        Ok(c.to_string())
    } else {
        quick_xml::escape::resolve_predefined_entity(s)
            .map(str::to_owned)
            .ok_or_else(|| XmlError::Malformed(format!("unknown entity reference &{s};")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_predefined_entities() {
        assert_eq!(resolve_general_ref(b"amp").unwrap(), "&");
        assert_eq!(resolve_general_ref(b"lt").unwrap(), "<");
        assert_eq!(resolve_general_ref(b"gt").unwrap(), ">");
        assert_eq!(resolve_general_ref(b"quot").unwrap(), "\"");
        assert_eq!(resolve_general_ref(b"apos").unwrap(), "'");
    }

    #[test]
    fn resolves_decimal_character_refs() {
        assert_eq!(resolve_general_ref(b"#65").unwrap(), "A");
        assert_eq!(resolve_general_ref(b"#955").unwrap(), "λ");
    }

    #[test]
    fn resolves_hex_character_refs() {
        assert_eq!(resolve_general_ref(b"#x41").unwrap(), "A");
        assert_eq!(resolve_general_ref(b"#X41").unwrap(), "A");
        assert_eq!(resolve_general_ref(b"#x3BB").unwrap(), "λ");
    }

    #[test]
    fn rejects_unknown_entity_name() {
        let err = resolve_general_ref(b"nbsp").unwrap_err();
        assert!(matches!(err, XmlError::Malformed(ref s) if s.contains("unknown entity")));
    }

    #[test]
    fn rejects_oor_numeric_ref() {
        // U+110000 is just past the Unicode range.
        let err = resolve_general_ref(b"#x110000").unwrap_err();
        assert!(matches!(err, XmlError::Malformed(ref s) if s.contains("out of range")));
    }
}
