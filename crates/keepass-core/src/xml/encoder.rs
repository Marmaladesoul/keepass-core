//! Typed encoder: [`crate::model::Vault`] → KeePass inner XML.
//!
//! Mirrors the [`crate::xml::decoder`] layer in the other direction.
//! The encoder walks a [`Vault`] and emits a byte-for-byte legal
//! KeePass XML document that the decoder can parse back to an equal
//! [`Vault`].
//!
//! ## Scope
//!
//! This first encoder slice writes the minimum viable document:
//!
//! - `<KeePassFile>`
//!   - `<Meta>` — Generator, DatabaseName, DatabaseDescription,
//!     DefaultUserName, and the three `*Changed` timestamps.
//!   - `<Root>` — the root `<Group>` with recursive `<Group>` and
//!     `<Entry>` children.
//!     - Group: UUID, Name, Notes, Times.
//!     - Entry: UUID, Title / UserName / Password / URL / Notes
//!       as `<String>` K/V pairs, Tags, Times.
//!
//! Intentionally deferred to follow-up PRs:
//!
//! - Inner-stream cipher encryption of protected values (currently
//!   all values are written plain; the encoder parallels
//!   [`decode_vault`] rather than [`decode_vault_with_cipher`]).
//! - Binaries pool, attachments, history snapshots, custom icons,
//!   custom data, memory protection, recycle bin, deleted objects,
//!   auto-type, entry/group decorative fields (colours, override
//!   URL, custom-icon UUIDs).
//!
//! Those will land alongside their own round-trip assertions once
//! the scaffolding is merged.
//!
//! [`decode_vault`]: crate::xml::decode_vault
//! [`decode_vault_with_cipher`]: crate::xml::decode_vault_with_cipher
//! [`Vault`]: crate::model::Vault

use std::io::Cursor;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::SecondsFormat;
use quick_xml::Writer;
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};

use super::reader::XmlError;
use crate::model::{Entry, Group, Meta, Vault};

/// Encode a [`Vault`] into a byte-for-byte legal KeePass inner XML
/// document.
///
/// Protected values are written as plain text (no `Protected="True"`
/// attribute, no base64-wrapped ciphertext). A companion
/// `encode_vault_with_cipher` will be added once the inner-stream
/// cipher is threaded through the encoder in a follow-up.
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] only if `quick_xml` refuses to
/// write a byte (vanishingly unlikely against an in-memory `Vec`).
/// The decoder round-trip tests exercise the emitted XML end-to-end.
pub fn encode_vault(vault: &Vault) -> Result<Vec<u8>, XmlError> {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    writer
        .write_event(Event::Decl(quick_xml::events::BytesDecl::new(
            "1.0",
            Some("UTF-8"),
            None,
        )))
        .map_err(xml_err)?;
    open(&mut writer, "KeePassFile")?;
    write_meta(&mut writer, &vault.meta)?;
    open(&mut writer, "Root")?;
    write_group(&mut writer, &vault.root)?;
    close(&mut writer, "Root")?;
    close(&mut writer, "KeePassFile")?;
    Ok(writer.into_inner().into_inner())
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

fn write_meta<W: std::io::Write>(w: &mut Writer<W>, meta: &Meta) -> Result<(), XmlError> {
    open(w, "Meta")?;
    write_text_element(w, "Generator", &meta.generator)?;
    write_optional_text_element(w, "DatabaseName", &meta.database_name)?;
    write_optional_timestamp(w, "DatabaseNameChanged", meta.database_name_changed)?;
    write_optional_text_element(w, "DatabaseDescription", &meta.database_description)?;
    write_optional_timestamp(
        w,
        "DatabaseDescriptionChanged",
        meta.database_description_changed,
    )?;
    write_optional_text_element(w, "DefaultUserName", &meta.default_username)?;
    write_optional_timestamp(w, "DefaultUserNameChanged", meta.default_username_changed)?;
    close(w, "Meta")
}

// ---------------------------------------------------------------------------
// Group / Entry
// ---------------------------------------------------------------------------

fn write_group<W: std::io::Write>(w: &mut Writer<W>, group: &Group) -> Result<(), XmlError> {
    open(w, "Group")?;
    write_text_element(w, "UUID", &uuid_to_base64(group.id.0))?;
    write_text_element(w, "Name", &group.name)?;
    if !group.notes.is_empty() {
        write_text_element(w, "Notes", &group.notes)?;
    }
    for entry in &group.entries {
        write_entry(w, entry)?;
    }
    for child in &group.groups {
        write_group(w, child)?;
    }
    close(w, "Group")
}

fn write_entry<W: std::io::Write>(w: &mut Writer<W>, entry: &Entry) -> Result<(), XmlError> {
    open(w, "Entry")?;
    write_text_element(w, "UUID", &uuid_to_base64(entry.id.0))?;
    // Canonical string fields first, in the KeePass-conventional order.
    write_string_kv(w, "Title", &entry.title)?;
    write_string_kv(w, "UserName", &entry.username)?;
    write_string_kv(w, "Password", &entry.password)?;
    write_string_kv(w, "URL", &entry.url)?;
    write_string_kv(w, "Notes", &entry.notes)?;
    // Custom fields in their original order.
    for field in &entry.custom_fields {
        write_string_kv(w, &field.key, &field.value)?;
    }
    // Tags — rejoined with the canonical `;` separator.
    if !entry.tags.is_empty() {
        write_text_element(w, "Tags", &entry.tags.join(";"))?;
    }
    close(w, "Entry")
}

/// Write a `<String><Key>…</Key><Value>…</Value></String>` pair.
fn write_string_kv<W: std::io::Write>(
    w: &mut Writer<W>,
    key: &str,
    value: &str,
) -> Result<(), XmlError> {
    open(w, "String")?;
    write_text_element(w, "Key", key)?;
    write_text_element(w, "Value", value)?;
    close(w, "String")
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

fn open<W: std::io::Write>(w: &mut Writer<W>, tag: &'static str) -> Result<(), XmlError> {
    w.write_event(Event::Start(BytesStart::new(tag)))
        .map_err(xml_err)
}

fn close<W: std::io::Write>(w: &mut Writer<W>, tag: &'static str) -> Result<(), XmlError> {
    w.write_event(Event::End(BytesEnd::new(tag)))
        .map_err(xml_err)
}

fn write_text_element<W: std::io::Write>(
    w: &mut Writer<W>,
    tag: &'static str,
    text: &str,
) -> Result<(), XmlError> {
    open(w, tag)?;
    if !text.is_empty() {
        w.write_event(Event::Text(BytesText::new(text)))
            .map_err(xml_err)?;
    }
    close(w, tag)
}

fn write_optional_text_element<W: std::io::Write>(
    w: &mut Writer<W>,
    tag: &'static str,
    text: &str,
) -> Result<(), XmlError> {
    // Always emit the element, even when empty — KeePass writers do,
    // and round-trip symmetry with the decoder depends on "absent vs
    // present-but-empty" collapsing to the same Vault.
    write_text_element(w, tag, text)
}

fn write_optional_timestamp<W: std::io::Write>(
    w: &mut Writer<W>,
    tag: &'static str,
    value: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), XmlError> {
    if let Some(ts) = value {
        // Always emit ISO-8601 for now. KDBX4 writers prefer base64
        // ticks, but the decoder accepts both — so either form
        // round-trips. Choosing ISO keeps the output human-readable.
        let s = ts.to_rfc3339_opts(SecondsFormat::Secs, true);
        write_text_element(w, tag, &s)?;
    }
    Ok(())
}

fn uuid_to_base64(uuid: uuid::Uuid) -> String {
    BASE64.encode(uuid.as_bytes())
}

// `map_err(xml_err)` hands us the Error by value, so matching that
// callback shape is cleaner than juggling borrows.
#[allow(clippy::needless_pass_by_value)]
fn xml_err(e: quick_xml::Error) -> XmlError {
    XmlError::Malformed(e.to_string())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::decode_vault;

    /// Build a non-trivial Vault, encode it, decode it back, and assert
    /// the round-trip is a no-op on the fields we currently write.
    fn round_trip(vault: &Vault) -> Vault {
        let bytes = encode_vault(vault).expect("encode");
        decode_vault(&bytes).expect("decode")
    }

    #[test]
    fn empty_vault_round_trips() {
        use crate::model::{GroupId, Timestamps};
        let root = Group {
            id: GroupId(uuid::Uuid::nil()),
            name: "Root".to_owned(),
            notes: String::new(),
            groups: Vec::new(),
            entries: Vec::new(),
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps::default(),
        };
        let vault = Vault {
            root,
            meta: Meta {
                generator: "keepass-core-tests".to_owned(),
                ..Meta::default()
            },
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        };
        let got = round_trip(&vault);
        assert_eq!(got.meta.generator, "keepass-core-tests");
        assert_eq!(got.root.name, "Root");
        assert_eq!(got.root.total_entries(), 0);
    }

    #[test]
    fn entries_and_nested_groups_round_trip() {
        use crate::model::{Entry, EntryId, GroupId, Timestamps};
        let inner = Entry {
            id: EntryId(uuid::Uuid::from_u128(
                0x4242_4242_4242_4242_4242_4242_4242_4242,
            )),
            title: "Inner".to_owned(),
            username: "alice@example.com".to_owned(),
            password: "s3cret".to_owned(),
            url: "https://example.com".to_owned(),
            notes: "line 1\nline 2".to_owned(),
            custom_fields: Vec::new(),
            tags: vec!["personal".to_owned(), "work".to_owned()],
            history: Vec::new(),
            attachments: Vec::new(),
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            custom_icon_uuid: None,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: crate::model::AutoType::default(),
            times: Timestamps::default(),
        };
        let child = Group {
            id: GroupId(uuid::Uuid::from_u128(0xAAAA_1111)),
            name: "Child".to_owned(),
            notes: "child notes".to_owned(),
            groups: Vec::new(),
            entries: vec![inner],
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps::default(),
        };
        let root = Group {
            id: GroupId(uuid::Uuid::nil()),
            name: "Root".to_owned(),
            notes: String::new(),
            groups: vec![child],
            entries: Vec::new(),
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps::default(),
        };
        let vault = Vault {
            root,
            meta: Meta {
                generator: "keepass-core-tests".to_owned(),
                database_name: "Example Vault".to_owned(),
                database_description: "Round-trip test fixture".to_owned(),
                default_username: "alice@example.com".to_owned(),
                ..Meta::default()
            },
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        };

        let got = round_trip(&vault);
        assert_eq!(got.meta.database_name, "Example Vault");
        assert_eq!(got.meta.database_description, "Round-trip test fixture");
        assert_eq!(got.meta.default_username, "alice@example.com");
        assert_eq!(got.total_entries(), 1);
        let e = got.iter_entries().next().unwrap();
        assert_eq!(e.title, "Inner");
        assert_eq!(e.username, "alice@example.com");
        assert_eq!(e.password, "s3cret");
        assert_eq!(e.url, "https://example.com");
        assert_eq!(e.notes, "line 1\nline 2");
        let mut tags = e.tags.clone();
        tags.sort();
        assert_eq!(tags, vec!["personal", "work"]);
    }

    #[test]
    fn custom_fields_round_trip_alongside_canonical_fields() {
        use crate::model::{CustomField, Entry, EntryId, GroupId, Timestamps};
        let entry = Entry {
            id: EntryId(uuid::Uuid::from_u128(0x1234)),
            title: "With Customs".to_owned(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            custom_fields: vec![
                CustomField {
                    key: "Recovery Code".to_owned(),
                    value: "ABC-DEF-GHI".to_owned(),
                    protected: false,
                },
                CustomField {
                    key: "PIN".to_owned(),
                    value: "1234".to_owned(),
                    protected: false,
                },
            ],
            tags: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            custom_icon_uuid: None,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: crate::model::AutoType::default(),
            times: Timestamps::default(),
        };
        let root = Group {
            id: GroupId(uuid::Uuid::nil()),
            name: "Root".to_owned(),
            notes: String::new(),
            groups: Vec::new(),
            entries: vec![entry],
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps::default(),
        };
        let vault = Vault {
            root,
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        };

        let got = round_trip(&vault);
        let e = got.iter_entries().next().unwrap();
        assert_eq!(e.custom_fields.len(), 2);
        let mut names: Vec<_> = e.custom_fields.iter().map(|c| c.key.clone()).collect();
        names.sort();
        assert_eq!(names, vec!["PIN", "Recovery Code"]);
    }

    #[test]
    fn xml_escaping_round_trips_cleanly() {
        use crate::model::{Entry, EntryId, GroupId, Timestamps};
        // KeePass values may contain <, >, &, ', ". quick-xml's
        // BytesText escapes on write; the decoder's unescape mirrors
        // that. Round-trip proves the chain.
        let entry = Entry {
            id: EntryId(uuid::Uuid::nil()),
            title: "<tag> & \"quoted\"".to_owned(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: "line with & ampersand < and > angle brackets".to_owned(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            custom_icon_uuid: None,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: crate::model::AutoType::default(),
            times: Timestamps::default(),
        };
        let root = Group {
            id: GroupId(uuid::Uuid::nil()),
            name: "Root".to_owned(),
            notes: String::new(),
            groups: Vec::new(),
            entries: vec![entry],
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            times: Timestamps::default(),
        };
        let vault = Vault {
            root,
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        };
        let got = round_trip(&vault);
        let e = got.iter_entries().next().unwrap();
        assert_eq!(e.title, "<tag> & \"quoted\"");
        assert_eq!(e.notes, "line with & ampersand < and > angle brackets");
    }

    #[test]
    fn declaration_is_written() {
        use crate::model::{GroupId, Timestamps};
        let vault = Vault {
            root: Group {
                id: GroupId(uuid::Uuid::nil()),
                name: "R".to_owned(),
                notes: String::new(),
                groups: Vec::new(),
                entries: Vec::new(),
                is_expanded: true,
                default_auto_type_sequence: String::new(),
                enable_auto_type: None,
                enable_searching: None,
                custom_data: Vec::new(),
                previous_parent_group: None,
                last_top_visible_entry: None,
                custom_icon_uuid: None,
                times: Timestamps::default(),
            },
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        };
        let bytes = encode_vault(&vault).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(text.starts_with("<?xml"));
        assert!(text.contains("encoding=\"UTF-8\""));
    }
}
