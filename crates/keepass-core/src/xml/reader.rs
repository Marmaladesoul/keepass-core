//! Streaming XML-reading primitives.
//!
//! Thin wrappers around [`quick_xml::Reader`] that (a) translate its
//! errors into our [`XmlError`] type, and (b) offer convenience helpers
//! for extracting typed values at specific element paths.
//!
//! The full typed-model decoder (which produces [`crate::model::Vault`])
//! is a separate layer that composes these primitives.

use quick_xml::Reader;
use quick_xml::events::Event;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for XML-reading failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum XmlError {
    /// The XML document was malformed at the bytes level (bad UTF-8,
    /// mismatched tags, invalid entities, etc.).
    #[error("malformed XML: {0}")]
    Malformed(String),

    /// A required element was missing from the document at an expected path.
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

impl From<quick_xml::Error> for XmlError {
    fn from(err: quick_xml::Error) -> Self {
        Self::Malformed(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// extract_text_at_path
// ---------------------------------------------------------------------------

/// Extract the text content of the first element found at the given path.
///
/// The path is a list of element names starting at the document root. For
/// example, `["KeePassFile", "Meta", "Generator"]` walks into the `Meta`
/// element inside `KeePassFile` and returns the text of the first
/// `Generator` element it finds.
///
/// Comparison is case-sensitive — KeePass element names are CamelCase by
/// convention and matched exactly.
///
/// Attribute-only elements (empty text) return `Some("")`. A missing path
/// returns `None`.
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] if the XML is invalid at the bytes
/// level (unterminated tag, bad entity, etc.).
pub fn extract_text_at_path(
    xml: &[u8],
    path: &[&str],
) -> Result<Option<String>, XmlError> {
    if path.is_empty() {
        return Ok(None);
    }

    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    // Stack of tag names we're currently inside. The document's root is at
    // index 0 once we see it; a match occurs when this stack == `path`.
    let mut stack: Vec<String> = Vec::new();
    let mut in_target = false;
    let mut collected = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| XmlError::Malformed(err.to_string()))?
                    .to_owned();
                stack.push(name);
                if !in_target && stack_matches(&stack, path) {
                    in_target = true;
                    collected.clear();
                }
            }
            Ok(Event::End(_)) => {
                if in_target && stack_matches(&stack, path) {
                    return Ok(Some(collected));
                }
                stack.pop();
            }
            Ok(Event::Empty(e)) => {
                // A self-closing element `<Foo/>` at the target path
                // contributes an empty string.
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| XmlError::Malformed(err.to_string()))?
                    .to_owned();
                stack.push(name);
                if stack_matches(&stack, path) {
                    return Ok(Some(String::new()));
                }
                stack.pop();
            }
            Ok(Event::Text(t)) if in_target => {
                let decoded = t
                    .unescape()
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
                collected.push_str(&decoded);
            }
            Ok(Event::CData(c)) if in_target => {
                // CDATA is passed through verbatim (no entity decoding).
                let s = std::str::from_utf8(&c)
                    .map_err(|err| XmlError::Malformed(err.to_string()))?;
                collected.push_str(s);
            }
            Ok(Event::Eof) => return Ok(None),
            _ => { /* declaration, comment, PI — ignore */ }
        }
        buf.clear();
    }
}

/// Convenience: extract the `<Meta>/<Generator>` value from a KeePass
/// inner XML document.
///
/// Returns the generator string (e.g. `"KeePassXC"` or `"KdbxWeb"`) if
/// present, or `None` if the document does not carry a `Meta/Generator`
/// pair.
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] on invalid XML at the bytes level.
pub fn extract_generator(xml: &[u8]) -> Result<Option<String>, XmlError> {
    extract_text_at_path(xml, &["KeePassFile", "Meta", "Generator"])
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn stack_matches(stack: &[String], path: &[&str]) -> bool {
    if stack.len() != path.len() {
        return false;
    }
    stack.iter().zip(path.iter()).all(|(s, p)| s == p)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_generator_from_minimal_document() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
  <Meta>
    <Generator>KeePassXC</Generator>
  </Meta>
</KeePassFile>"#;
        let out = extract_generator(xml).unwrap();
        assert_eq!(out.as_deref(), Some("KeePassXC"));
    }

    #[test]
    fn extracts_generator_from_realistic_preamble() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<KeePassFile>
  <Meta>
    <Generator>KdbxWeb</Generator>
    <HeaderHash>Zm9vYmFy</HeaderHash>
    <DatabaseName>Example</DatabaseName>
    <MemoryProtection>
      <ProtectPassword>True</ProtectPassword>
    </MemoryProtection>
  </Meta>
  <Root>
    <Group><UUID>AAAA</UUID></Group>
  </Root>
</KeePassFile>"#;
        let out = extract_generator(xml).unwrap();
        assert_eq!(out.as_deref(), Some("KdbxWeb"));
    }

    #[test]
    fn returns_none_when_generator_absent() {
        let xml = br"<KeePassFile><Meta><DatabaseName>Foo</DatabaseName></Meta></KeePassFile>";
        assert_eq!(extract_generator(xml).unwrap(), None);
    }

    #[test]
    fn returns_none_on_empty_document() {
        let xml = br#"<?xml version="1.0" ?><KeePassFile/>"#;
        assert_eq!(extract_generator(xml).unwrap(), None);
    }

    #[test]
    fn self_closing_generator_returns_empty_string() {
        let xml = br"<KeePassFile><Meta><Generator/></Meta></KeePassFile>";
        assert_eq!(extract_generator(xml).unwrap().as_deref(), Some(""));
    }

    #[test]
    fn extract_text_at_path_walks_arbitrary_depth() {
        let xml = br"<A><B><C><D>deep value</D></C></B></A>";
        let out = extract_text_at_path(xml, &["A", "B", "C", "D"]).unwrap();
        assert_eq!(out.as_deref(), Some("deep value"));
    }

    #[test]
    fn returns_first_match_on_repeated_element() {
        let xml = br"<A><B>first</B><B>second</B></A>";
        let out = extract_text_at_path(xml, &["A", "B"]).unwrap();
        assert_eq!(out.as_deref(), Some("first"));
    }

    #[test]
    fn empty_path_returns_none() {
        let xml = br"<A>anything</A>";
        assert_eq!(extract_text_at_path(xml, &[]).unwrap(), None);
    }

    #[test]
    fn malformed_xml_reports_error() {
        // Genuinely invalid at the bytes level — a tag with an unterminated
        // attribute value. quick-xml catches this; an EOF mid-content (which
        // we used to test) is silently terminated as "no more events".
        let xml = br#"<KeePassFile><Meta attr="unterminated</KeePassFile>"#;
        let err = extract_generator(xml).unwrap_err();
        assert!(matches!(err, XmlError::Malformed(_)));
    }

    #[test]
    fn handles_utf8_content() {
        let xml = "<KeePassFile><Meta><Generator>KéePässXÇ</Generator></Meta></KeePassFile>".as_bytes();
        assert_eq!(
            extract_generator(xml).unwrap().as_deref(),
            Some("KéePässXÇ")
        );
    }

    #[test]
    fn handles_entities() {
        let xml = br"<A>&lt;tag&gt; &amp; &quot;ok&quot;</A>";
        let out = extract_text_at_path(xml, &["A"]).unwrap();
        assert_eq!(out.as_deref(), Some("<tag> & \"ok\""));
    }

    #[test]
    fn handles_cdata() {
        let xml = br"<A><![CDATA[<not>really</a tag>]]></A>";
        let out = extract_text_at_path(xml, &["A"]).unwrap();
        assert_eq!(out.as_deref(), Some("<not>really</a tag>"));
    }

    #[test]
    fn ignores_siblings_outside_target_path() {
        let xml = br"<KeePassFile>
            <Head>garbage</Head>
            <Meta>
              <Generator>Target</Generator>
            </Meta>
            <Tail>more</Tail>
        </KeePassFile>";
        let out = extract_generator(xml).unwrap();
        assert_eq!(out.as_deref(), Some("Target"));
    }

    #[test]
    fn does_not_match_nested_same_named_element_at_wrong_depth() {
        // <Generator> nested too deep — not at Meta/Generator position.
        let xml = br"<KeePassFile>
          <Meta>
            <DatabaseName>
              <Generator>wrong depth, should not match</Generator>
            </DatabaseName>
          </Meta>
        </KeePassFile>";
        assert_eq!(extract_generator(xml).unwrap(), None);
    }
}
