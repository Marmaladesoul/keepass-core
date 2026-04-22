//! Typed decoder: KeePass inner XML → [`crate::model::Vault`].
//!
//! Takes the decrypted, decompressed inner XML and produces a typed
//! [`Vault`] with its group tree and entries. This is the "minimum
//! viable slice" — enough to answer "what entries does this vault
//! contain?" for downstream interop tests and early integration work.
//!
//! Deferred to follow-up PRs:
//!
//! - Timestamps (`<Times>` blocks)
//! - Entry history (`<History>`)
//! - Deleted objects (`<DeletedObjects>`)
//! - `<Meta>` fields beyond `<Generator>` (database name, memory
//!   protection flags, recycle-bin config, custom icons, custom data)
//! - Binary references (`<Value Ref="N"/>`)
//! - Protected-value decryption (the value is preserved as the
//!   base64 ciphertext string until a higher layer applies the inner
//!   stream cipher)
//!
//! Implementation pattern: a single pass over the [`quick_xml::Reader`]
//! event stream with a small manual state machine. No DOM allocation,
//! constant-ish memory regardless of vault size.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use uuid::Uuid;

use super::reader::XmlError;
use crate::model::{CustomField, Entry, EntryId, Group, GroupId, Vault};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Decode a KeePass inner XML document into a typed [`Vault`].
///
/// The input must be the already-decrypted, already-decompressed inner
/// XML bytes — i.e. what comes out of the
/// [`crate::format::hashed_block_stream`] (KDBX3) or
/// [`crate::format::hmac_block_stream`] + AES-CBC + gzip pipeline
/// (KDBX4).
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] on invalid XML, or
/// [`XmlError::MissingElement`] if either `<KeePassFile>` or
/// `<Root>` is absent. A missing `<Meta>` is tolerated (rare in real
/// vaults but the decoder doesn't require it).
pub fn decode_vault(xml: &[u8]) -> Result<Vault, XmlError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut state = DecoderState {
        generator: String::new(),
        root: None,
    };

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                stack.push(name.clone());

                // The root group sits at KeePassFile/Root/Group. When we
                // see that Start event, hand control to read_group, which
                // consumes through the matching </Group>. Pop the stack
                // frame we pushed for it so our own End handling stays
                // balanced.
                if stack == ["KeePassFile", "Root", "Group"] && state.root.is_none() {
                    let root = read_group(&mut reader, &mut buf)?;
                    state.root = Some(root);
                    stack.pop();
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Empty(e)) => {
                let _ = tag_name(&e)?;
                // Empty elements at top-level (rare) contribute nothing
                // to our state.
            }
            // Collect <Generator> text when we're at the right depth.
            Ok(Event::Text(t)) if stack == ["KeePassFile", "Meta", "Generator"] => {
                let decoded = t
                    .unescape()
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
                state.generator.push_str(&decoded);
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }

    let root = state
        .root
        .ok_or(XmlError::MissingElement("KeePassFile/Root/Group"))?;
    Ok(Vault {
        root,
        generator: state.generator,
    })
}

struct DecoderState {
    generator: String,
    root: Option<Group>,
}

// ---------------------------------------------------------------------------
// Group reader
// ---------------------------------------------------------------------------

/// Read one `<Group>` and its contents. Assumes the opening `<Group>`
/// tag has just been consumed by the caller; reads up to and including
/// the matching `</Group>`.
fn read_group<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Group, XmlError> {
    let mut group = Group {
        id: GroupId(Uuid::nil()),
        name: String::new(),
        notes: String::new(),
        groups: Vec::new(),
        entries: Vec::new(),
    };

    // Depth 0 = directly inside <Group>; we only act on depth-0 tags.
    let mut depth: i32 = 0;

    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    match name.as_str() {
                        "Group" => {
                            let child = read_group(reader, buf)?;
                            group.groups.push(child);
                            // read_group consumed the full nested block
                            // up through its closing </Group>; depth
                            // stays at 0 for us.
                            continue;
                        }
                        "Entry" => {
                            let entry = read_entry(reader, buf)?;
                            group.entries.push(entry);
                            continue;
                        }
                        "UUID" => {
                            let text = read_text(reader, buf)?;
                            group.id = GroupId(parse_uuid(&text)?);
                            continue;
                        }
                        "Name" => {
                            group.name = read_text(reader, buf)?;
                            continue;
                        }
                        "Notes" => {
                            group.notes = read_text(reader, buf)?;
                            continue;
                        }
                        _ => {
                            // Unknown child of <Group>. Skip silently for
                            // now; future work adds full preservation.
                            depth += 1;
                        }
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(group);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Group>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

// ---------------------------------------------------------------------------
// Entry reader
// ---------------------------------------------------------------------------

fn read_entry<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Entry, XmlError> {
    let mut entry = Entry {
        id: EntryId(Uuid::nil()),
        title: String::new(),
        username: String::new(),
        password: String::new(),
        url: String::new(),
        notes: String::new(),
        custom_fields: Vec::new(),
    };

    let mut depth: i32 = 0;

    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    match name.as_str() {
                        "UUID" => {
                            let text = read_text(reader, buf)?;
                            entry.id = EntryId(parse_uuid(&text)?);
                            continue;
                        }
                        "String" => {
                            let (key, value, protected) = read_string_kv(reader, buf)?;
                            assign_well_known_field(&mut entry, &key, value, protected);
                            continue;
                        }
                        _ => {
                            // Unknown child of <Entry>: History, AutoType,
                            // Times, Binary, etc. Skip for now.
                            depth += 1;
                        }
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(entry);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Entry>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<String>` KV element: `<String><Key>Title</Key><Value>foo</Value></String>`.
///
/// The `<Value>` element may carry `Protected="True"`; the caller gets
/// the boolean so they can decide what to do with the (still base64)
/// payload.
fn read_string_kv<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<(String, String, bool), XmlError> {
    let mut key = String::new();
    let mut value = String::new();
    let mut protected = false;

    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    match name.as_str() {
                        "Key" => {
                            key = read_text(reader, buf)?;
                            continue;
                        }
                        "Value" => {
                            protected = has_protected_attribute(&e)?;
                            value = read_text(reader, buf)?;
                            continue;
                        }
                        _ => depth += 1,
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok((key, value, protected));
                }
                depth -= 1;
            }
            Ok(Event::Empty(e)) => {
                // A `<Value />` (self-closing) still counts — the value
                // is empty but we should capture the Protected attribute.
                let name = tag_name(&e)?;
                if depth == 0 && name == "Value" {
                    protected = has_protected_attribute(&e)?;
                    // value remains empty
                }
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <String>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn assign_well_known_field(entry: &mut Entry, key: &str, value: String, protected: bool) {
    match key {
        "Title" => entry.title = value,
        "UserName" => entry.username = value,
        "Password" => entry.password = value,
        "URL" => entry.url = value,
        "Notes" => entry.notes = value,
        _ => entry.custom_fields.push(CustomField {
            key: key.to_owned(),
            value,
            protected,
        }),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the text content of the current open element until its close.
/// Assumes the opening tag has just been consumed. Leaves the reader
/// positioned past the matching close tag.
fn read_text<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<String, XmlError> {
    let mut collected = String::new();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(collected);
                }
                depth -= 1;
            }
            Ok(Event::Text(t)) => {
                let decoded = t
                    .unescape()
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
                collected.push_str(&decoded);
            }
            Ok(Event::CData(c)) => {
                let s = std::str::from_utf8(&c).map_err(|e| XmlError::Malformed(e.to_string()))?;
                collected.push_str(s);
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside element text".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn tag_name(e: &BytesStart<'_>) -> Result<String, XmlError> {
    std::str::from_utf8(e.name().as_ref())
        .map(ToOwned::to_owned)
        .map_err(|err| XmlError::Malformed(err.to_string()))
}

fn has_protected_attribute(e: &BytesStart<'_>) -> Result<bool, XmlError> {
    for attr in e.attributes() {
        let a = attr.map_err(|err| XmlError::Malformed(err.to_string()))?;
        if a.key.as_ref() == b"Protected" {
            // KeePass writes "True" / "False" (case-sensitive in practice).
            let value = std::str::from_utf8(&a.value)
                .map_err(|err| XmlError::Malformed(err.to_string()))?;
            return Ok(value.eq_ignore_ascii_case("true"));
        }
    }
    Ok(false)
}

/// Parse a KeePass UUID. KeePass always stores UUIDs as base64-encoded
/// 16 bytes (e.g. `wlh5TRcdRkWyLKo5Rfl0Vg==`).
fn parse_uuid(text: &str) -> Result<Uuid, XmlError> {
    let trimmed = text.trim();
    let bytes = BASE64.decode(trimmed).map_err(|e| XmlError::InvalidValue {
        element: "UUID",
        detail: format!("not valid base64: {e}"),
    })?;
    let arr: [u8; 16] = bytes
        .try_into()
        .map_err(|b: Vec<u8>| XmlError::InvalidValue {
            element: "UUID",
            detail: format!("expected 16 bytes, got {}", b.len()),
        })?;
    Ok(Uuid::from_bytes(arr))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal, well-formed KeePass XML document we can embed in tests.
    ///
    /// Uses hand-crafted base64 UUIDs: `AAAAAAAAAAAAAAAAAAAAAA==` → all
    /// zeros; `AAAAAAAAAAAAAAAAAAAAAQ==` → last byte = 1; etc.
    fn sample_xml() -> &'static [u8] {
        br#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
  <Meta>
    <Generator>KeePassXC</Generator>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Passwords</Name>
      <Notes>root group notes</Notes>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>Gmail</Value></String>
        <String><Key>UserName</Key><Value>alice@example.com</Value></String>
        <String><Key>Password</Key><Value Protected="True">cGxhaW4=</Value></String>
        <String><Key>URL</Key><Value>https://mail.google.com</Value></String>
        <String><Key>Notes</Key><Value>Primary email</Value></String>
        <String><Key>CustomKey</Key><Value>arbitrary</Value></String>
      </Entry>
      <Group>
        <UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>
        <Name>Work</Name>
        <Entry>
          <UUID>AAAAAAAAAAAAAAAAAAAAAw==</UUID>
          <String><Key>Title</Key><Value>Work VPN</Value></String>
          <String><Key>UserName</Key><Value>bob</Value></String>
        </Entry>
      </Group>
    </Group>
  </Root>
</KeePassFile>"#
    }

    #[test]
    fn decodes_generator_and_root_name() {
        let vault = decode_vault(sample_xml()).unwrap();
        assert_eq!(vault.generator, "KeePassXC");
        assert_eq!(vault.root.name, "Passwords");
        assert_eq!(vault.root.notes, "root group notes");
    }

    #[test]
    fn decodes_entry_fields() {
        let vault = decode_vault(sample_xml()).unwrap();
        let gmail = vault
            .iter_entries()
            .find(|e| e.title == "Gmail")
            .expect("Gmail entry");
        assert_eq!(gmail.username, "alice@example.com");
        assert_eq!(gmail.url, "https://mail.google.com");
        assert_eq!(gmail.notes, "Primary email");
        // Password content is preserved as the (base64-encoded) XML value;
        // higher layers decrypt it via the inner-stream cipher.
        assert_eq!(gmail.password, "cGxhaW4=");
    }

    #[test]
    fn custom_fields_are_preserved() {
        let vault = decode_vault(sample_xml()).unwrap();
        let gmail = vault.iter_entries().find(|e| e.title == "Gmail").unwrap();
        assert_eq!(gmail.custom_fields.len(), 1);
        assert_eq!(gmail.custom_fields[0].key, "CustomKey");
        assert_eq!(gmail.custom_fields[0].value, "arbitrary");
        assert!(!gmail.custom_fields[0].protected);
    }

    #[test]
    fn protected_flag_captured_for_password() {
        // Our sample XML has Password marked Protected="True". The XML
        // decoder itself doesn't currently surface that info on Entry
        // (the password is just assigned to Entry::password as a
        // string), but the information is observable on custom fields —
        // test that path is at least exercised by another element.
        let xml = br#"<?xml version="1.0"?>
<KeePassFile>
  <Meta><Generator>X</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>TOTP Seed</Key><Value Protected="True">secret</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.custom_fields.len(), 1);
        assert!(e.custom_fields[0].protected);
    }

    #[test]
    fn counts_nested_groups_and_entries() {
        let vault = decode_vault(sample_xml()).unwrap();
        // 2 entries total (Gmail at root, Work VPN in Work subgroup)
        assert_eq!(vault.total_entries(), 2);
        // 1 subgroup (Work) under root
        assert_eq!(vault.root.total_subgroups(), 1);
    }

    #[test]
    fn iter_entries_walks_depth_first() {
        let vault = decode_vault(sample_xml()).unwrap();
        let titles: Vec<_> = vault.iter_entries().map(|e| e.title.clone()).collect();
        assert_eq!(titles, ["Gmail", "Work VPN"]);
    }

    #[test]
    fn uuids_are_decoded_correctly() {
        let vault = decode_vault(sample_xml()).unwrap();
        assert_eq!(vault.root.id.0, Uuid::from_bytes([0u8; 16]));

        // First entry's UUID has last byte = 1.
        let mut expected = [0u8; 16];
        expected[15] = 1;
        let gmail = vault.iter_entries().next().unwrap();
        assert_eq!(gmail.id.0, Uuid::from_bytes(expected));
    }

    #[test]
    fn missing_root_errors() {
        let xml = br"<KeePassFile><Meta><Generator>G</Generator></Meta></KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(err, XmlError::MissingElement(_)));
    }

    #[test]
    fn missing_meta_tolerated() {
        let xml = br"<KeePassFile>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Only</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.generator, "");
        assert_eq!(vault.root.name, "Only");
    }

    #[test]
    fn unknown_entry_children_are_skipped() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>OK</Value></String>
        <Times>
          <CreationTime>2026-04-21T00:00:00Z</CreationTime>
          <LastModificationTime>2026-04-22T00:00:00Z</LastModificationTime>
        </Times>
        <AutoType>
          <Enabled>True</Enabled>
        </AutoType>
        <History/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.title, "OK");
        // Times / AutoType / History were skipped silently without
        // breaking the rest of the parse.
    }

    #[test]
    fn rejects_bad_base64_uuid() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>NOT-BASE64-AT-ALL!@#</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "UUID",
                ..
            }
        ));
    }

    #[test]
    fn rejects_wrong_length_uuid() {
        // Valid base64 but produces != 16 bytes.
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>aGVsbG8=</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "UUID",
                ..
            }
        ));
    }

    #[test]
    fn self_closing_value_produces_empty_string() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value/></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.title, "");
    }
}
