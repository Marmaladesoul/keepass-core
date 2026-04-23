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
use crate::crypto::InnerStreamCipher;
use crate::model::{AutoType, Entry, Group, Meta, Vault};

/// Encode a [`Vault`] into a byte-for-byte legal KeePass inner XML
/// document, **without** applying an inner-stream cipher.
///
/// Protected values are written as plain text — no `Protected="True"`
/// attribute, no base64-wrapped ciphertext. Useful for tests and for
/// XML that will never be decrypted (diagnostic dumps, round-trip
/// harnesses, `decode_vault` symmetry).
///
/// Real KDBX writers should use [`encode_vault_with_cipher`] with
/// the same [`InnerStreamCipher`] the outer format layer will bind
/// to the file's header.
///
/// # Errors
///
/// See [`encode_vault_with_cipher`].
pub fn encode_vault(vault: &Vault) -> Result<Vec<u8>, XmlError> {
    let mut cipher = InnerStreamCipher::None;
    encode_vault_with_cipher(vault, &mut cipher)
}

/// Encode a [`Vault`] into KeePass inner XML, encrypting every
/// protected value against the given inner-stream cipher.
///
/// The `Password` field on every [`Entry`] is always written with
/// `Protected="True"` (matching KeePass's default memory-protection
/// policy). Custom fields are protected iff
/// [`crate::model::CustomField::protected`] is `true`.
///
/// The cipher is advanced once per protected value in the exact same
/// document order the decoder consumes. Passing
/// [`InnerStreamCipher::None`] produces output whose protected values
/// are the base64 of the raw plaintext bytes — a format
/// [`crate::xml::decode_vault`] still round-trips correctly via the
/// same no-op cipher path.
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] only if `quick_xml` refuses to
/// write a byte (vanishingly unlikely against an in-memory `Vec`).
pub fn encode_vault_with_cipher(
    vault: &Vault,
    cipher: &mut InnerStreamCipher,
) -> Result<Vec<u8>, XmlError> {
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
    write_group(&mut writer, &vault.root, cipher)?;
    if !vault.deleted_objects.is_empty() {
        write_deleted_objects(&mut writer, &vault.deleted_objects)?;
    }
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

fn write_group<W: std::io::Write>(
    w: &mut Writer<W>,
    group: &Group,
    cipher: &mut InnerStreamCipher,
) -> Result<(), XmlError> {
    open(w, "Group")?;
    write_text_element(w, "UUID", &uuid_to_base64(group.id.0))?;
    write_text_element(w, "Name", &group.name)?;
    if !group.notes.is_empty() {
        write_text_element(w, "Notes", &group.notes)?;
    }
    write_times(w, &group.times)?;
    for entry in &group.entries {
        write_entry(w, entry, cipher)?;
    }
    for child in &group.groups {
        write_group(w, child, cipher)?;
    }
    close(w, "Group")
}

fn write_entry<W: std::io::Write>(
    w: &mut Writer<W>,
    entry: &Entry,
    cipher: &mut InnerStreamCipher,
) -> Result<(), XmlError> {
    open(w, "Entry")?;
    write_text_element(w, "UUID", &uuid_to_base64(entry.id.0))?;
    // Canonical string fields first, in the KeePass-conventional order.
    // Title / UserName / URL / Notes are never encrypted.
    write_string_kv_plain(w, "Title", &entry.title)?;
    write_string_kv_plain(w, "UserName", &entry.username)?;
    // Password is always written protected: KeePass convention, and
    // MemoryProtection::protect_password defaults to `true`.
    write_string_kv_protected(w, "Password", &entry.password, cipher)?;
    write_string_kv_plain(w, "URL", &entry.url)?;
    write_string_kv_plain(w, "Notes", &entry.notes)?;
    // Custom fields, protected per their individual flag and always
    // in source order so the keystream stays in sync with the
    // decoder's reads.
    for field in &entry.custom_fields {
        if field.protected {
            write_string_kv_protected(w, &field.key, &field.value, cipher)?;
        } else {
            write_string_kv_plain(w, &field.key, &field.value)?;
        }
    }
    // Tags — rejoined with the canonical `;` separator.
    if !entry.tags.is_empty() {
        write_text_element(w, "Tags", &entry.tags.join(";"))?;
    }
    // Decorative fields — emit only when non-default so a vanilla
    // entry stays minimal. The decoder treats absent and present-but-
    // empty as the same, so elision is safe.
    if !entry.foreground_color.is_empty() {
        write_text_element(w, "ForegroundColor", &entry.foreground_color)?;
    }
    if !entry.background_color.is_empty() {
        write_text_element(w, "BackgroundColor", &entry.background_color)?;
    }
    if !entry.override_url.is_empty() {
        write_text_element(w, "OverrideURL", &entry.override_url)?;
    }
    if let Some(icon) = entry.custom_icon_uuid {
        write_text_element(w, "CustomIconUUID", &uuid_to_base64(icon))?;
    }
    // QualityCheck defaults to true; emit only when the entry has
    // explicitly opted out, matching what KeePassXC writes.
    if !entry.quality_check {
        write_text_element(w, "QualityCheck", "False")?;
    }
    write_times(w, &entry.times)?;
    // `<PreviousParentGroup>` — only emitted when the entry has been
    // moved at least once. The decoder accepts either an empty string
    // or a nil UUID as "no previous parent"; we elide the element
    // entirely in that case for a more minimal document.
    if let Some(prev) = entry.previous_parent_group {
        write_text_element(w, "PreviousParentGroup", &uuid_to_base64(prev.0))?;
    }
    // AutoType — emit only when the block carries any non-default
    // setting. AutoType has no protected values, so its placement
    // does not affect the inner-stream cipher's keystream sync.
    if !is_default_auto_type(&entry.auto_type) {
        write_auto_type(w, &entry.auto_type)?;
    }
    // `<History>` — prior snapshots of this entry. Emitted before the
    // closing `</Entry>` (matching KeePassXC's output) and recursively
    // rendered through `write_entry` so protected values in history
    // consume the same inner-stream keystream the decoder expects on
    // read. Elided entirely when history is empty to keep the XML
    // minimal.
    if !entry.history.is_empty() {
        open(w, "History")?;
        for snap in &entry.history {
            write_entry(w, snap, cipher)?;
        }
        close(w, "History")?;
    }
    close(w, "Entry")
}

fn write_times<W: std::io::Write>(
    w: &mut Writer<W>,
    times: &crate::model::Timestamps,
) -> Result<(), XmlError> {
    // Emit `<Times>` whenever any sub-field is set. An all-default
    // Timestamps (no timestamps, expires=false, usage_count=0) is
    // indistinguishable from "no <Times> block at all" to the
    // decoder, so skip emission in that case to keep round-tripped
    // XML minimal.
    let any_set = times.creation_time.is_some()
        || times.last_modification_time.is_some()
        || times.last_access_time.is_some()
        || times.location_changed.is_some()
        || times.expiry_time.is_some()
        || times.expires
        || times.usage_count != 0;
    if !any_set {
        return Ok(());
    }
    open(w, "Times")?;
    write_optional_timestamp(w, "CreationTime", times.creation_time)?;
    write_optional_timestamp(w, "LastModificationTime", times.last_modification_time)?;
    write_optional_timestamp(w, "LastAccessTime", times.last_access_time)?;
    write_optional_timestamp(w, "LocationChanged", times.location_changed)?;
    write_optional_timestamp(w, "ExpiryTime", times.expiry_time)?;
    write_text_element(w, "Expires", if times.expires { "True" } else { "False" })?;
    write_text_element(w, "UsageCount", &times.usage_count.to_string())?;
    close(w, "Times")
}

fn is_default_auto_type(at: &AutoType) -> bool {
    let d = AutoType::default();
    at.enabled == d.enabled
        && at.data_transfer_obfuscation == d.data_transfer_obfuscation
        && at.default_sequence == d.default_sequence
        && at.associations.is_empty()
}

fn write_auto_type<W: std::io::Write>(w: &mut Writer<W>, at: &AutoType) -> Result<(), XmlError> {
    open(w, "AutoType")?;
    write_text_element(w, "Enabled", if at.enabled { "True" } else { "False" })?;
    write_text_element(
        w,
        "DataTransferObfuscation",
        &at.data_transfer_obfuscation.to_string(),
    )?;
    if !at.default_sequence.is_empty() {
        write_text_element(w, "DefaultSequence", &at.default_sequence)?;
    }
    for assoc in &at.associations {
        open(w, "Association")?;
        write_text_element(w, "Window", &assoc.window)?;
        write_text_element(w, "KeystrokeSequence", &assoc.keystroke_sequence)?;
        close(w, "Association")?;
    }
    close(w, "AutoType")
}

fn write_deleted_objects<W: std::io::Write>(
    w: &mut Writer<W>,
    objects: &[crate::model::DeletedObject],
) -> Result<(), XmlError> {
    open(w, "DeletedObjects")?;
    for obj in objects {
        open(w, "DeletedObject")?;
        write_text_element(w, "UUID", &uuid_to_base64(obj.uuid))?;
        write_optional_timestamp(w, "DeletionTime", obj.deleted_at)?;
        close(w, "DeletedObject")?;
    }
    close(w, "DeletedObjects")
}

/// Write a plain `<String><Key>…</Key><Value>…</Value></String>` pair.
fn write_string_kv_plain<W: std::io::Write>(
    w: &mut Writer<W>,
    key: &str,
    value: &str,
) -> Result<(), XmlError> {
    open(w, "String")?;
    write_text_element(w, "Key", key)?;
    write_text_element(w, "Value", value)?;
    close(w, "String")
}

/// Write `<String><Key>…</Key><Value Protected="True">…</Value></String>`,
/// XOR-ing the plaintext bytes against the inner-stream cipher and
/// base64-encoding the result. The cipher advances by `value.len()`
/// bytes — matching the decoder's consumption order on read.
fn write_string_kv_protected<W: std::io::Write>(
    w: &mut Writer<W>,
    key: &str,
    value: &str,
    cipher: &mut InnerStreamCipher,
) -> Result<(), XmlError> {
    open(w, "String")?;
    write_text_element(w, "Key", key)?;

    // <Value Protected="True">base64(XOR(plaintext, keystream))</Value>
    let mut buf = value.as_bytes().to_vec();
    cipher.process(&mut buf);
    let payload = BASE64.encode(&buf);
    let mut value_tag = BytesStart::new("Value");
    value_tag.push_attribute(("Protected", "True"));
    w.write_event(Event::Start(value_tag)).map_err(xml_err)?;
    if !payload.is_empty() {
        w.write_event(Event::Text(BytesText::new(&payload)))
            .map_err(xml_err)?;
    }
    w.write_event(Event::End(BytesEnd::new("Value")))
        .map_err(xml_err)?;

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

    // -----------------------------------------------------------------
    // encode_vault_with_cipher — protected-value round-trips
    // -----------------------------------------------------------------

    use crate::crypto::InnerStreamCipher;
    use crate::format::InnerStreamAlgorithm;
    use crate::xml::decode_vault_with_cipher;

    fn vault_with_protected_entries() -> Vault {
        use crate::model::{CustomField, Entry, EntryId, GroupId, Timestamps};
        let e1 = Entry {
            id: EntryId(uuid::Uuid::from_u128(1)),
            title: "Gmail".to_owned(),
            username: "alice@example.com".to_owned(),
            password: "hunter2".to_owned(),
            url: "https://mail.google.com".to_owned(),
            notes: String::new(),
            custom_fields: vec![
                CustomField {
                    key: "Recovery Code".to_owned(),
                    value: "PUBLIC-123".to_owned(),
                    protected: false,
                },
                CustomField {
                    key: "TOTP Seed".to_owned(),
                    value: "JBSWY3DPEHPK3PXP".to_owned(),
                    protected: true,
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
        let e2 = Entry {
            id: EntryId(uuid::Uuid::from_u128(2)),
            title: "VPN".to_owned(),
            username: "bob".to_owned(),
            password: "correct horse battery staple".to_owned(),
            url: String::new(),
            notes: String::new(),
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
            name: "R".to_owned(),
            notes: String::new(),
            groups: Vec::new(),
            entries: vec![e1, e2],
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
        Vault {
            root,
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        }
    }

    #[test]
    fn salsa20_encode_decode_round_trip() {
        let vault = vault_with_protected_entries();
        let key = [0x11u8; 32];
        let mut enc = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let bytes = encode_vault_with_cipher(&vault, &mut enc).unwrap();

        // Fresh cipher with the same key — keystream restarts from 0.
        let mut dec = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let got = decode_vault_with_cipher(&bytes, &mut dec).unwrap();

        let e1 = got.iter_entries().find(|e| e.title == "Gmail").unwrap();
        assert_eq!(e1.password, "hunter2");
        // TOTP Seed was protected; Recovery Code was not.
        let totp = e1
            .custom_fields
            .iter()
            .find(|f| f.key == "TOTP Seed")
            .unwrap();
        assert_eq!(totp.value, "JBSWY3DPEHPK3PXP");
        assert!(totp.protected);
        let recov = e1
            .custom_fields
            .iter()
            .find(|f| f.key == "Recovery Code")
            .unwrap();
        assert_eq!(recov.value, "PUBLIC-123");
        assert!(!recov.protected);

        let e2 = got.iter_entries().find(|e| e.title == "VPN").unwrap();
        assert_eq!(e2.password, "correct horse battery staple");
    }

    #[test]
    fn chacha20_encode_decode_round_trip() {
        let vault = vault_with_protected_entries();
        let key = b"inner-stream-key-arbitrary-len".to_vec();
        let mut enc = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        let bytes = encode_vault_with_cipher(&vault, &mut enc).unwrap();

        let mut dec = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        let got = decode_vault_with_cipher(&bytes, &mut dec).unwrap();
        let e = got.iter_entries().find(|e| e.title == "VPN").unwrap();
        assert_eq!(e.password, "correct horse battery staple");
    }

    #[test]
    fn none_cipher_round_trip_is_base64_of_plaintext() {
        // Sanity check: passing an InnerStreamCipher::None produces
        // protected values that are base64(plaintext). The decoder's
        // None path reads them back to the same plaintext string.
        let vault = vault_with_protected_entries();
        let mut none = InnerStreamCipher::None;
        let bytes = encode_vault_with_cipher(&vault, &mut none).unwrap();

        let mut none_again = InnerStreamCipher::None;
        let got = decode_vault_with_cipher(&bytes, &mut none_again).unwrap();
        let e = got.iter_entries().find(|e| e.title == "Gmail").unwrap();
        assert_eq!(e.password, "hunter2");
    }

    #[test]
    fn encrypted_output_differs_from_plaintext() {
        // Cheap smoke test — if the cipher is actually applied, the
        // emitted bytes should not contain the plaintext password.
        let vault = vault_with_protected_entries();
        let key = [0x33u8; 32];
        let mut enc = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let bytes = encode_vault_with_cipher(&vault, &mut enc).unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(!text.contains("hunter2"));
        assert!(!text.contains("correct horse battery staple"));
        assert!(!text.contains("JBSWY3DPEHPK3PXP"));
        // Non-protected values still appear in plaintext.
        assert!(text.contains("PUBLIC-123"));
        assert!(text.contains("alice@example.com"));
    }
}
