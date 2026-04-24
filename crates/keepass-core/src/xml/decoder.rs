//! Typed decoder: KeePass inner XML → [`crate::model::Vault`].
//!
//! Takes the decrypted, decompressed inner XML and produces a typed
//! [`Vault`] with its group tree and entries. This is the "minimum
//! viable slice" — enough to answer "what entries does this vault
//! contain?" for downstream interop tests and early integration work.
//!
//! Deferred to follow-up PRs:
//!
//! - Deleted objects (`<DeletedObjects>`)
//! - `<Meta>` fields beyond the basic name/description/generator set
//!   (memory protection flags, recycle-bin config, custom icons,
//!   custom data, header hash, history settings)
//! - Binary references (`<Value Ref="N"/>`)
//!
//! ## Protected values
//!
//! Fields whose `<Value>` carries `Protected="True"` are stored as
//! base64-encoded ciphertext under the *inner-stream cipher*. The
//! keystream is **document-continuous** — a single stream, consumed
//! by every protected value in source order. That means decryption
//! must happen *during* XML parsing, not in a post-pass, or the
//! keystream desynchronises.
//!
//! [`decode_vault_with_cipher`] threads a mutable
//! [`InnerStreamCipher`] through the parser and decrypts each
//! protected value in place. [`decode_vault`] is a convenience that
//! runs with [`InnerStreamCipher::None`] — useful for tests and for
//! documents whose payloads are plain text (rare in real vaults).
//!
//! Implementation pattern: a single pass over the [`quick_xml::Reader`]
//! event stream with a small manual state machine. No DOM allocation,
//! constant-ish memory regardless of vault size.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, TimeZone as _, Utc};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use uuid::Uuid;

use super::reader::XmlError;
use crate::crypto::InnerStreamCipher;
use crate::model::{
    Attachment, AutoType, AutoTypeAssociation, Binary, CustomDataItem, CustomField, CustomIcon,
    DeletedObject, Entry, EntryId, Group, GroupId, MemoryProtection, Meta, Timestamps,
    UnknownElement, Vault,
};

/// .NET ticks between `0001-01-01T00:00:00Z` (KeePass's epoch) and
/// `1970-01-01T00:00:00Z` (the Unix epoch). Used to convert KDBX4
/// base64-encoded tick counts into `DateTime<Utc>`.
const TICKS_FROM_YEAR_ONE_TO_UNIX_EPOCH: i64 = 621_355_968_000_000_000;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Decode a KeePass inner XML document into a typed [`Vault`], with no
/// inner-stream cipher applied.
///
/// Equivalent to calling [`decode_vault_with_cipher`] with
/// [`InnerStreamCipher::None`]: protected values are base64-decoded and
/// the raw bytes taken as UTF-8 plaintext (i.e. the ciphertext is
/// treated as the plaintext). Useful in tests and for documents whose
/// protected payloads were never encrypted. Real vaults should go
/// through [`decode_vault_with_cipher`] with a real cipher.
///
/// # Errors
///
/// See [`decode_vault_with_cipher`].
pub fn decode_vault(xml: &[u8]) -> Result<Vault, XmlError> {
    let mut cipher = InnerStreamCipher::None;
    decode_vault_with_cipher(xml, &mut cipher)
}

/// Decode a KeePass inner XML document into a typed [`Vault`],
/// decrypting protected values via the given inner-stream cipher.
///
/// The input must be the already-decrypted, already-decompressed inner
/// XML bytes — i.e. what comes out of the
/// [`crate::format::hashed_block_stream`] (KDBX3) or
/// [`crate::format::hmac_block_stream`] + AES-CBC + gzip pipeline
/// (KDBX4).
///
/// `cipher` is advanced once per `Protected="True"` `<Value>` element,
/// in document order, consuming `ciphertext.len()` bytes of keystream
/// for each. Pass [`InnerStreamCipher::None`] (or use [`decode_vault`])
/// to skip decryption.
///
/// After a successful call, every [`Entry::password`] and every
/// [`CustomField`] whose `protected` is `true` holds the *plaintext*
/// UTF-8 value. The `protected` flag remains `true` to mark the field
/// as secret for downstream consumers (audit, write-back).
///
/// # Errors
///
/// Returns [`XmlError::Malformed`] on invalid XML,
/// [`XmlError::MissingElement`] if `<KeePassFile>/<Root>/<Group>` is
/// absent, or [`XmlError::InvalidValue`] if a protected payload is not
/// valid base64 or decrypts to non-UTF-8 bytes. A missing `<Meta>` is
/// tolerated (rare in real vaults but the decoder doesn't require it).
pub fn decode_vault_with_cipher(
    xml: &[u8],
    cipher: &mut InnerStreamCipher,
) -> Result<Vault, XmlError> {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut meta = Meta::default();
    let mut root: Option<Group> = None;
    // Populated by <Meta><Binaries> on KDBX3. KDBX4 leaves this empty;
    // the unlock pipeline attaches the inner-header binaries after
    // decode_vault_with_cipher returns.
    let mut binaries: Vec<Binary> = Vec::new();
    let mut deleted_objects: Vec<DeletedObject> = Vec::new();

    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                stack.push(name.clone());

                // Dispatch top-level children of KeePassFile:
                //   KeePassFile/Meta → read_meta
                //   KeePassFile/Root/Group → read_group
                //   KeePassFile/Root/DeletedObjects → read_deleted_objects
                if stack == ["KeePassFile", "Meta"] {
                    meta = read_meta(&mut reader, &mut buf, &mut binaries)?;
                    stack.pop();
                } else if stack == ["KeePassFile", "Root", "Group"] && root.is_none() {
                    root = Some(read_group(&mut reader, &mut buf, cipher)?);
                    stack.pop();
                } else if stack == ["KeePassFile", "Root", "DeletedObjects"] {
                    deleted_objects = read_deleted_objects(&mut reader, &mut buf)?;
                    stack.pop();
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::Empty(e)) => {
                let _ = tag_name(&e)?;
                // Empty elements at top-level (rare) contribute nothing.
            }
            Ok(Event::Eof) => break,
            _ => {}
        }
        buf.clear();
    }

    let root = root.ok_or(XmlError::MissingElement("KeePassFile/Root/Group"))?;
    // KDBX3 populates `binaries` above via Meta/Binaries. KDBX4 leaves it
    // empty — the unlock pipeline replaces it with the inner-header
    // binaries after we return.
    Ok(Vault {
        root,
        meta,
        binaries,
        deleted_objects,
    })
}

// ---------------------------------------------------------------------------
// Group reader
// ---------------------------------------------------------------------------

/// Read one `<Group>` and its contents. Assumes the opening `<Group>`
/// tag has just been consumed by the caller; reads up to and including
/// the matching `</Group>`.
///
/// Linear per-child dispatch, same shape as `read_entry` — breaking up
/// by category would scatter the logic without meaningful clarity gain.
#[allow(clippy::too_many_lines)]
fn read_group<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    cipher: &mut InnerStreamCipher,
) -> Result<Group, XmlError> {
    let mut group = Group {
        id: GroupId(Uuid::nil()),
        name: String::new(),
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
        unknown_xml: Vec::new(),
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
                            let child = read_group(reader, buf, cipher)?;
                            group.groups.push(child);
                            // read_group consumed the full nested block
                            // up through its closing </Group>; depth
                            // stays at 0 for us.
                            continue;
                        }
                        "Entry" => {
                            let entry = read_entry(reader, buf, cipher)?;
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
                        "Times" => {
                            group.times = read_times(reader, buf)?;
                            continue;
                        }
                        "IsExpanded" => {
                            let text = read_text(reader, buf)?;
                            group.is_expanded = parse_bool(&text, "IsExpanded")?;
                            continue;
                        }
                        "DefaultAutoTypeSequence" => {
                            group.default_auto_type_sequence = read_text(reader, buf)?;
                            continue;
                        }
                        "EnableAutoType" => {
                            let text = read_text(reader, buf)?;
                            group.enable_auto_type = parse_tristate(&text);
                            continue;
                        }
                        "EnableSearching" => {
                            let text = read_text(reader, buf)?;
                            group.enable_searching = parse_tristate(&text);
                            continue;
                        }
                        "CustomData" => {
                            group.custom_data = read_custom_data(reader, buf)?;
                            continue;
                        }
                        "PreviousParentGroup" => {
                            let text = read_text(reader, buf)?;
                            group.previous_parent_group = parse_optional_group_id(&text)?;
                            continue;
                        }
                        "LastTopVisibleEntry" => {
                            let text = read_text(reader, buf)?;
                            group.last_top_visible_entry = parse_optional_entry_id(&text)?;
                            continue;
                        }
                        "CustomIconUUID" => {
                            let text = read_text(reader, buf)?;
                            let trimmed = text.trim();
                            if !trimmed.is_empty() {
                                let uuid = parse_uuid(trimmed)?;
                                if !uuid.is_nil() {
                                    group.custom_icon_uuid = Some(uuid);
                                }
                            }
                            continue;
                        }
                        _ => {
                            // Unknown child of <Group> — capture verbatim
                            // for round-trip. See `capture_unknown_subtree`
                            // for the fidelity contract.
                            let unknown = capture_unknown_subtree(reader, e)?;
                            group.unknown_xml.push(unknown);
                            continue;
                        }
                    }
                }
                // depth > 0: nested element inside some already-entered
                // block; just track the nesting so End events balance.
                depth += 1;
            }
            // Self-closing unknown child like `<Favourite/>` at top
            // level — capture so round-trip preservation doesn't depend
            // on whether a foreign writer chose Start+End or the
            // empty-element shorthand for a content-free field. Nested
            // `Empty` events (depth > 0) are unreachable in practice:
            // unknown subtrees are drained by `capture_unknown_subtree`.
            Ok(Event::Empty(e)) if depth == 0 => {
                let unknown = capture_unknown_empty(e)?;
                group.unknown_xml.push(unknown);
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

// Linear switch over every <Entry> child element — breaking up by
// category (text / protected / metadata / timestamps / history) would
// spread the dispatch across several helpers without meaningful
// clarity gain. The function body is still readable top-to-bottom.
#[allow(clippy::too_many_lines)]
fn read_entry<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    cipher: &mut InnerStreamCipher,
) -> Result<Entry, XmlError> {
    let mut entry = Entry {
        id: EntryId(Uuid::nil()),
        title: String::new(),
        username: String::new(),
        password: String::new(),
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
        auto_type: AutoType::default(),
        times: Timestamps::default(),
        unknown_xml: Vec::new(),
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
                            let (key, value, protected) = read_string_kv(reader, buf, cipher)?;
                            assign_well_known_field(&mut entry, &key, value, protected);
                            continue;
                        }
                        "Binary" => {
                            if let Some(att) = read_binary_kv(reader, buf)? {
                                entry.attachments.push(att);
                            }
                            continue;
                        }
                        "Times" => {
                            entry.times = read_times(reader, buf)?;
                            continue;
                        }
                        "Tags" => {
                            let raw = read_text(reader, buf)?;
                            entry.tags = parse_tags(&raw);
                            continue;
                        }
                        "ForegroundColor" => {
                            entry.foreground_color = read_text(reader, buf)?;
                            continue;
                        }
                        "BackgroundColor" => {
                            entry.background_color = read_text(reader, buf)?;
                            continue;
                        }
                        "OverrideURL" => {
                            entry.override_url = read_text(reader, buf)?;
                            continue;
                        }
                        "CustomIconUUID" => {
                            let text = read_text(reader, buf)?;
                            let trimmed = text.trim();
                            if !trimmed.is_empty() {
                                let uuid = parse_uuid(trimmed)?;
                                // Nil UUID means "no custom icon" per the
                                // same convention we use for RecycleBinUUID.
                                if !uuid.is_nil() {
                                    entry.custom_icon_uuid = Some(uuid);
                                }
                            }
                            continue;
                        }
                        "CustomData" => {
                            entry.custom_data = read_custom_data(reader, buf)?;
                            continue;
                        }
                        "QualityCheck" => {
                            let text = read_text(reader, buf)?;
                            entry.quality_check = parse_bool(&text, "QualityCheck")?;
                            continue;
                        }
                        "PreviousParentGroup" => {
                            let text = read_text(reader, buf)?;
                            entry.previous_parent_group = parse_optional_group_id(&text)?;
                            continue;
                        }
                        "AutoType" => {
                            entry.auto_type = read_auto_type(reader, buf)?;
                            continue;
                        }
                        "History" => {
                            // KeePass stores previous snapshots of an entry
                            // as <Entry> children inside <History>. Their
                            // protected values share the same document-
                            // continuous keystream, so we recurse into
                            // them to keep the inner-stream cipher in sync
                            // for every following entry.
                            entry.history = read_history_entries(reader, buf, cipher)?;
                            continue;
                        }
                        _ => {
                            // Unknown child of <Entry> — capture verbatim
                            // for round-trip. An unknown subtree may in
                            // principle contain `<Value Protected="True">`
                            // payloads whose plaintext we can't recover
                            // (we don't know the intended semantics), so
                            // we treat the whole captured fragment as
                            // opaque bytes. The inner-stream keystream
                            // stays in sync because `capture_unknown_subtree`
                            // does not invoke the cipher.
                            let unknown = capture_unknown_subtree(reader, e)?;
                            entry.unknown_xml.push(unknown);
                            continue;
                        }
                    }
                }
                // depth > 0: nested element inside some already-entered
                // block; just track the nesting so End events balance.
                depth += 1;
            }
            // Self-closing unknown child at top level — see the matching
            // comment in `read_group`. A self-closing element carries no
            // `<Value>` payload, so the inner-stream keystream is
            // unaffected.
            Ok(Event::Empty(e)) if depth == 0 => {
                let unknown = capture_unknown_empty(e)?;
                entry.unknown_xml.push(unknown);
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

/// Consume a `<History>` block, reading each child `<Entry>` through
/// the full entry parser so the inner-stream cipher keystream advances
/// for every protected value inside the snapshot. Returns the snapshots
/// in source order (typically oldest → newest).
///
/// KeePass does not nest history (a history snapshot does not itself
/// have a `<History>` child in any writer we've observed), but the
/// decoder does not enforce this — if a snapshot does carry its own
/// `<History>`, that nested history lands on the snapshot's `history`
/// field like any other.
fn read_history_entries<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    cipher: &mut InnerStreamCipher,
) -> Result<Vec<Entry>, XmlError> {
    let mut snapshots = Vec::new();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "Entry" {
                    snapshots.push(read_entry(reader, buf, cipher)?);
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(snapshots);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <History>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<String>` KV element: `<String><Key>Title</Key><Value>foo</Value></String>`.
///
/// If the `<Value>` element carries `Protected="True"`, the raw content
/// is base64-decoded and passed through `cipher`, and the resulting
/// UTF-8 plaintext becomes the returned value. The `protected` flag is
/// still set so downstream consumers know the field was stored as a
/// secret.
fn read_string_kv<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    cipher: &mut InnerStreamCipher,
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
                            let raw = read_text(reader, buf)?;
                            value = if protected {
                                decrypt_protected_value(&raw, cipher)?
                            } else {
                                raw
                            };
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
                // An empty protected value consumes zero keystream bytes,
                // which is correct: the cipher state is unchanged.
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

/// Read a `<Binary>` KV element on an entry:
/// `<Binary><Key>filename</Key><Value Ref="N"/></Binary>`.
///
/// Returns `Some(Attachment)` when the element carries both a key and
/// a `Ref` attribute. Returns `Ok(None)` for malformed or incomplete
/// elements — some writers emit leftover `<Binary/>` placeholders,
/// and we'd rather silently drop them than fail the whole decode.
fn read_binary_kv<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Option<Attachment>, XmlError> {
    let mut key: Option<String> = None;
    let mut ref_id: Option<u32> = None;
    let mut depth: i32 = 0;

    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    match name.as_str() {
                        "Key" => {
                            key = Some(read_text(reader, buf)?);
                            continue;
                        }
                        "Value" => {
                            ref_id = parse_ref_attribute(&e)?;
                            // Consume the (possibly non-empty) <Value>
                            // body so the cursor ends up past </Value>.
                            let _ = read_text(reader, buf)?;
                            continue;
                        }
                        _ => depth += 1,
                    }
                } else {
                    depth += 1;
                }
            }
            Ok(Event::Empty(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "Value" {
                    ref_id = parse_ref_attribute(&e)?;
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(match (key, ref_id) {
                        (Some(name), Some(ref_id)) => Some(Attachment { name, ref_id }),
                        _ => None,
                    });
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Binary>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn parse_ref_attribute(e: &BytesStart<'_>) -> Result<Option<u32>, XmlError> {
    for attr in e.attributes() {
        let a = attr.map_err(|err| XmlError::Malformed(err.to_string()))?;
        if a.key.as_ref() == b"Ref" {
            let s = std::str::from_utf8(&a.value)
                .map_err(|err| XmlError::Malformed(err.to_string()))?;
            return s
                .parse::<u32>()
                .map(Some)
                .map_err(|e| XmlError::InvalidValue {
                    element: "Value",
                    detail: format!("binary Ref is not a non-negative integer: {e}"),
                });
        }
    }
    Ok(None)
}

/// Base64-decode a protected `<Value>` payload, XOR it in place against
/// the cipher's keystream, and interpret the result as UTF-8.
fn decrypt_protected_value(raw: &str, cipher: &mut InnerStreamCipher) -> Result<String, XmlError> {
    let trimmed = raw.trim();
    let mut bytes = BASE64.decode(trimmed).map_err(|e| XmlError::InvalidValue {
        element: "Value",
        detail: format!("protected payload is not valid base64: {e}"),
    })?;
    cipher.process(&mut bytes);
    String::from_utf8(bytes).map_err(|e| XmlError::InvalidValue {
        element: "Value",
        detail: format!("decrypted protected payload is not valid UTF-8: {e}"),
    })
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

/// Capture an unknown depth-0 `<Start>…</End>` subtree from a
/// container-level reader (`read_entry`, `read_group`, `read_meta`) as
/// a self-contained [`UnknownElement`], so foreign XML survives a
/// read → save round-trip.
///
/// Consumes events from `reader` up to and including the matching end
/// of `start`, re-emitting each into a private buffer via
/// [`quick_xml::Writer`]. Returns once the subtree is closed; the
/// caller's outer loop resumes at the next sibling.
///
/// Fidelity contract: structural (re-parse) equality is promised;
/// byte-exact equality with the source is not. `quick-xml` normalises
/// attribute whitespace and empty-element shorthand on write. Nested
/// CDATA and comments are preserved; nested `<?xml ?>` declarations
/// and processing instructions are dropped (neither is legal inside
/// a KeePass element).
///
/// Unknown self-closing elements (`<Foo/>`) are captured separately
/// through [`capture_unknown_empty`]; this helper requires a matching
/// end tag.
fn capture_unknown_subtree<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    start: BytesStart<'_>,
) -> Result<UnknownElement, XmlError> {
    let tag = tag_name(&start)?;
    let mut out = quick_xml::Writer::new(std::io::Cursor::new(Vec::new()));
    out.write_event(Event::Start(start))
        .map_err(|e| XmlError::Malformed(e.to_string()))?;
    let mut depth: i32 = 0;
    let mut inner_buf = Vec::new();
    loop {
        match reader.read_event_into(&mut inner_buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                depth += 1;
                out.write_event(Event::Start(e))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::End(e)) => {
                if depth == 0 {
                    out.write_event(Event::End(e))
                        .map_err(|e| XmlError::Malformed(e.to_string()))?;
                    break;
                }
                depth -= 1;
                out.write_event(Event::End(e))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::Empty(e)) => {
                out.write_event(Event::Empty(e))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::Text(t)) => {
                out.write_event(Event::Text(t))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::CData(t)) => {
                out.write_event(Event::CData(t))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::Comment(t)) => {
                out.write_event(Event::Comment(t))
                    .map_err(|e| XmlError::Malformed(e.to_string()))?;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed(format!("EOF inside unknown <{tag}>")));
            }
            // PIs and nested declarations are illegal inside a KeePass
            // element; drop them rather than refuse the document.
            Ok(_) => {}
        }
        inner_buf.clear();
    }
    Ok(UnknownElement {
        tag,
        raw_xml: out.into_inner().into_inner(),
    })
}

/// Capture a self-closing `<Foo/>` unknown element as an
/// [`UnknownElement`]. Complement to [`capture_unknown_subtree`] for
/// the empty-event shape — no descendants to consume, so this is a
/// one-shot serialise of the `BytesStart` payload as an `Event::Empty`.
///
/// Same fidelity contract as the subtree capture: structural, not
/// byte-exact.
fn capture_unknown_empty(start: BytesStart<'_>) -> Result<UnknownElement, XmlError> {
    let tag = tag_name(&start)?;
    let mut out = quick_xml::Writer::new(std::io::Cursor::new(Vec::new()));
    out.write_event(Event::Empty(start))
        .map_err(|e| XmlError::Malformed(e.to_string()))?;
    Ok(UnknownElement {
        tag,
        raw_xml: out.into_inner().into_inner(),
    })
}

/// Allowlist of `<Meta>` child tag names the decoder produces typed
/// output for. Used by [`read_meta`] to decide whether a depth-0 start
/// element is a known-canonical field (read as text + routed through
/// [`assign_meta_field`]) or an unknown subtree to capture verbatim.
///
/// Nested-structured children (`Binaries`, `MemoryProtection`,
/// `CustomData`, `CustomIcons`) have their own read helpers and are
/// intercepted before this check.
fn is_known_meta_text_field(name: &str) -> bool {
    matches!(
        name,
        "Generator"
            | "DatabaseName"
            | "DatabaseDescription"
            | "DatabaseNameChanged"
            | "DatabaseDescriptionChanged"
            | "DefaultUserName"
            | "DefaultUserNameChanged"
            | "RecycleBinEnabled"
            | "RecycleBinUUID"
            | "RecycleBinChanged"
            | "SettingsChanged"
            | "MasterKeyChanged"
            | "MasterKeyChangeRec"
            | "MasterKeyChangeForce"
            | "HistoryMaxItems"
            | "HistoryMaxSize"
            | "MaintenanceHistoryDays"
            | "Color"
            | "HeaderHash"
    )
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

/// Read a `<DeletedObjects>` block into a list of [`DeletedObject`].
/// Assumes the opening `<DeletedObjects>` tag has just been consumed;
/// reads up to and including the matching `</DeletedObjects>`.
///
/// Each child is a `<DeletedObject>` with a `<UUID>` and an optional
/// `<DeletionTime>`. Unknown children are silently ignored, and a
/// `<DeletedObject>` missing a UUID is silently skipped — tombstones
/// with no identity are meaningless.
fn read_deleted_objects<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Vec<DeletedObject>, XmlError> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "DeletedObject" {
                    if let Some(obj) = read_one_deleted_object(reader, buf)? {
                        out.push(obj);
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(out);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed(
                    "EOF inside <DeletedObjects>".to_owned(),
                ));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn read_one_deleted_object<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Option<DeletedObject>, XmlError> {
    let mut uuid: Option<Uuid> = None;
    let mut deleted_at: Option<DateTime<Utc>> = None;
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    match name.as_str() {
                        "UUID" => uuid = Some(parse_uuid(&text)?),
                        "DeletionTime" => {
                            deleted_at = Some(parse_timestamp(&text, "DeletionTime")?);
                        }
                        _ => { /* unknown child — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(uuid.map(|u| DeletedObject {
                        uuid: u,
                        deleted_at,
                    }));
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <DeletedObject>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<Meta>` block into a [`Meta`]. Assumes the opening `<Meta>`
/// tag has just been consumed; reads up to and including the matching
/// `</Meta>`.
///
/// Unknown children are skipped silently — KeePass writers emit a wide
/// and version-dependent set of Meta children; we surface only the
/// fields we currently model.
fn read_meta<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    binaries: &mut Vec<Binary>,
) -> Result<Meta, XmlError> {
    let mut meta = Meta::default();
    let mut depth: i32 = 0;

    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    if name == "Binaries" {
                        read_binaries_pool(reader, buf, binaries)?;
                        continue;
                    }
                    if name == "MemoryProtection" {
                        meta.memory_protection = read_memory_protection(reader, buf)?;
                        continue;
                    }
                    if name == "CustomData" {
                        meta.custom_data = read_custom_data(reader, buf)?;
                        continue;
                    }
                    if name == "CustomIcons" {
                        meta.custom_icons = read_custom_icons(reader, buf)?;
                        continue;
                    }
                    if is_known_meta_text_field(&name) {
                        let text = read_text(reader, buf)?;
                        assign_meta_field(&mut meta, &name, text)?;
                        continue;
                    }
                    // Unknown child of <Meta> — capture verbatim. A
                    // foreign writer's addition must survive even though
                    // we don't know its shape (scalar, struct, repeated
                    // element).
                    let unknown = capture_unknown_subtree(reader, e)?;
                    meta.unknown_xml.push(unknown);
                    continue;
                }
                depth += 1;
            }
            // Self-closing unknown child at top level — see the matching
            // comment in `read_group`.
            Ok(Event::Empty(e)) if depth == 0 => {
                let unknown = capture_unknown_empty(e)?;
                meta.unknown_xml.push(unknown);
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(meta);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Meta>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read an `<AutoType>` block into an [`AutoType`]. Assumes the
/// opening `<AutoType>` tag has just been consumed; reads up to and
/// including the matching `</AutoType>`.
///
/// Unknown children are silently ignored; known flags that are absent
/// keep their default values (see [`AutoType::default`]).
fn read_auto_type<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<AutoType, XmlError> {
    let mut at = AutoType::default();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    if name == "Association" {
                        if let Some(assoc) = read_auto_type_association(reader, buf)? {
                            at.associations.push(assoc);
                        }
                        continue;
                    }
                    let text = read_text(reader, buf)?;
                    match name.as_str() {
                        "Enabled" => at.enabled = parse_bool(&text, "Enabled")?,
                        "DataTransferObfuscation" => {
                            at.data_transfer_obfuscation =
                                parse_int::<u32>(&text, "DataTransferObfuscation")?;
                        }
                        "DefaultSequence" => at.default_sequence = text,
                        _ => { /* unknown — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(at);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <AutoType>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn read_auto_type_association<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Option<AutoTypeAssociation>, XmlError> {
    let mut window = String::new();
    let mut keystroke_sequence = String::new();
    let mut saw_any = false;
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    match name.as_str() {
                        "Window" => {
                            window = text;
                            saw_any = true;
                        }
                        "KeystrokeSequence" => {
                            keystroke_sequence = text;
                            saw_any = true;
                        }
                        _ => { /* unknown — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(if saw_any {
                        Some(AutoTypeAssociation {
                            window,
                            keystroke_sequence,
                        })
                    } else {
                        None
                    });
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Association>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<CustomIcons>` block — a flat list of `<Icon>` children.
///
/// Each icon supplies a UUID, a base64-encoded image payload, an
/// optional `<Name>`, and an optional `<LastModificationTime>`. Icons
/// without both a UUID and a Data payload are silently dropped — an
/// icon record with no identity or no bytes can't usefully round-trip.
fn read_custom_icons<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Vec<CustomIcon>, XmlError> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "Icon" {
                    if let Some(icon) = read_one_custom_icon(reader, buf)? {
                        out.push(icon);
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(out);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <CustomIcons>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn read_one_custom_icon<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Option<CustomIcon>, XmlError> {
    let mut uuid: Option<Uuid> = None;
    let mut data: Option<Vec<u8>> = None;
    let mut name = String::new();
    let mut last_modified: Option<DateTime<Utc>> = None;
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let tag = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    match tag.as_str() {
                        "UUID" => uuid = Some(parse_uuid(&text)?),
                        "Data" => {
                            let bytes =
                                BASE64
                                    .decode(text.trim())
                                    .map_err(|e| XmlError::InvalidValue {
                                        element: "Data",
                                        detail: format!("not valid base64: {e}"),
                                    })?;
                            data = Some(bytes);
                        }
                        "Name" => name = text,
                        "LastModificationTime" => {
                            last_modified = Some(parse_timestamp(&text, "LastModificationTime")?);
                        }
                        _ => { /* unknown child — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(match (uuid, data) {
                        (Some(uuid), Some(data)) => Some(CustomIcon {
                            uuid,
                            data,
                            name,
                            last_modified,
                        }),
                        _ => None,
                    });
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Icon>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<CustomData>` block — a flat list of `<Item>` children, each
/// with a `<Key>`, `<Value>`, and optional `<LastModificationTime>`.
///
/// Items without both a Key and Value are silently dropped; partial
/// items round-trip to nothing rather than an opaque error because
/// KeePass doesn't specify what writers should do when they see such a
/// record.
fn read_custom_data<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Vec<CustomDataItem>, XmlError> {
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "Item" {
                    if let Some(item) = read_custom_data_item(reader, buf)? {
                        out.push(item);
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(out);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <CustomData>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn read_custom_data_item<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Option<CustomDataItem>, XmlError> {
    let mut key: Option<String> = None;
    let mut value: Option<String> = None;
    let mut last_modified: Option<DateTime<Utc>> = None;
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    match name.as_str() {
                        "Key" => key = Some(text),
                        "Value" => value = Some(text),
                        "LastModificationTime" => {
                            last_modified = Some(parse_timestamp(&text, "LastModificationTime")?);
                        }
                        _ => { /* unknown — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(match (key, value) {
                        (Some(key), Some(value)) => Some(CustomDataItem {
                            key,
                            value,
                            last_modified,
                        }),
                        _ => None,
                    });
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Item>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a `<MemoryProtection>` block into a [`MemoryProtection`].
/// Unknown children are silently ignored; known flags that are absent
/// keep their default values (see [`MemoryProtection::default`]).
fn read_memory_protection<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<MemoryProtection, XmlError> {
    let mut mp = MemoryProtection::default();
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    match name.as_str() {
                        "ProtectTitle" => mp.protect_title = parse_bool(&text, "ProtectTitle")?,
                        "ProtectUserName" => {
                            mp.protect_username = parse_bool(&text, "ProtectUserName")?;
                        }
                        "ProtectPassword" => {
                            mp.protect_password = parse_bool(&text, "ProtectPassword")?;
                        }
                        "ProtectURL" => mp.protect_url = parse_bool(&text, "ProtectURL")?,
                        "ProtectNotes" => mp.protect_notes = parse_bool(&text, "ProtectNotes")?,
                        _ => { /* unknown flag — ignore */ }
                    }
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(mp);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed(
                    "EOF inside <MemoryProtection>".to_owned(),
                ));
            }
            _ => {}
        }
        buf.clear();
    }
}

/// Read a KDBX3 `<Binaries>` pool. Each child is a
/// `<Binary ID="N" Compressed="True|False">base64</Binary>` element.
///
/// Entries with `Compressed="True"` are gzip-decompressed on the fly so
/// the resulting [`Binary::data`] is always the raw payload that
/// downstream `<Binary Ref="N"/>` references expect.
///
/// The output vector is indexed by `ID` (not insertion order). Gaps
/// (skipped IDs) are filled with empty placeholder [`Binary`] entries
/// so that `binaries[ref_id]` works without off-by-N surprises — this
/// matches how KeePass writers actually use the pool, which is always
/// densely numbered from zero.
fn read_binaries_pool<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
    binaries: &mut Vec<Binary>,
) -> Result<(), XmlError> {
    let mut depth: i32 = 0;
    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 && name == "Binary" {
                    let (id, compressed) = parse_binary_attributes(&e)?;
                    let text = read_text(reader, buf)?;
                    let bin = decode_kdbx3_binary(&text, compressed)?;
                    insert_binary_at(binaries, id, bin);
                    continue;
                }
                depth += 1;
            }
            Ok(Event::Empty(e)) => {
                // <Binary ID="N"/> with no payload — zero-byte attachment.
                let name = tag_name(&e)?;
                if depth == 0 && name == "Binary" {
                    let (id, _compressed) = parse_binary_attributes(&e)?;
                    insert_binary_at(
                        binaries,
                        id,
                        Binary {
                            data: Vec::new(),
                            protected: false,
                        },
                    );
                }
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(());
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Binaries>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn parse_binary_attributes(e: &BytesStart<'_>) -> Result<(u32, bool), XmlError> {
    let mut id: Option<u32> = None;
    let mut compressed = false;
    for attr in e.attributes() {
        let a = attr.map_err(|err| XmlError::Malformed(err.to_string()))?;
        match a.key.as_ref() {
            b"ID" => {
                let s = std::str::from_utf8(&a.value)
                    .map_err(|err| XmlError::Malformed(err.to_string()))?;
                id = Some(s.parse::<u32>().map_err(|e| XmlError::InvalidValue {
                    element: "Binary",
                    detail: format!("ID is not a non-negative integer: {e}"),
                })?);
            }
            b"Compressed" => {
                let s = std::str::from_utf8(&a.value)
                    .map_err(|err| XmlError::Malformed(err.to_string()))?;
                compressed = s.eq_ignore_ascii_case("true");
            }
            _ => { /* ignore unknown attrs */ }
        }
    }
    let id = id.ok_or(XmlError::InvalidValue {
        element: "Binary",
        detail: "missing required ID attribute".to_owned(),
    })?;
    Ok((id, compressed))
}

fn decode_kdbx3_binary(text: &str, compressed: bool) -> Result<Binary, XmlError> {
    let trimmed = text.trim();
    let raw = BASE64.decode(trimmed).map_err(|e| XmlError::InvalidValue {
        element: "Binary",
        detail: format!("payload is not valid base64: {e}"),
    })?;
    let data = if compressed {
        crate::crypto::decompress(crate::format::CompressionFlags::Gzip, &raw).map_err(|e| {
            XmlError::InvalidValue {
                element: "Binary",
                detail: format!("compressed payload failed to decompress: {e}"),
            }
        })?
    } else {
        raw
    };
    Ok(Binary {
        data,
        protected: false,
    })
}

/// Insert a [`Binary`] at position `id`, growing the pool with empty
/// placeholders as needed so that `pool[id]` is a valid index.
fn insert_binary_at(pool: &mut Vec<Binary>, id: u32, bin: Binary) {
    let idx = id as usize;
    if idx >= pool.len() {
        pool.resize(
            idx + 1,
            Binary {
                data: Vec::new(),
                protected: false,
            },
        );
    }
    pool[idx] = bin;
}

fn assign_meta_field(meta: &mut Meta, field: &str, text: String) -> Result<(), XmlError> {
    match field {
        "Generator" => meta.generator = text,
        "DatabaseName" => meta.database_name = text,
        "DatabaseDescription" => meta.database_description = text,
        "DatabaseNameChanged" => {
            meta.database_name_changed = Some(parse_timestamp(&text, "DatabaseNameChanged")?);
        }
        "DatabaseDescriptionChanged" => {
            meta.database_description_changed =
                Some(parse_timestamp(&text, "DatabaseDescriptionChanged")?);
        }
        "DefaultUserName" => meta.default_username = text,
        "DefaultUserNameChanged" => {
            meta.default_username_changed = Some(parse_timestamp(&text, "DefaultUserNameChanged")?);
        }
        "RecycleBinEnabled" => meta.recycle_bin_enabled = parse_bool(&text, "RecycleBinEnabled")?,
        "RecycleBinUUID" => {
            let uuid = parse_uuid(&text)?;
            // KeePass writers sometimes emit an all-zero UUID to mean
            // "no recycle bin". Treat that as None for symmetry with
            // the explicitly-absent case.
            meta.recycle_bin_uuid = if uuid.is_nil() {
                None
            } else {
                Some(GroupId(uuid))
            };
        }
        "RecycleBinChanged" => {
            meta.recycle_bin_changed = Some(parse_timestamp(&text, "RecycleBinChanged")?);
        }
        "SettingsChanged" => {
            meta.settings_changed = Some(parse_timestamp(&text, "SettingsChanged")?);
        }
        "MasterKeyChanged" => {
            meta.master_key_changed = Some(parse_timestamp(&text, "MasterKeyChanged")?);
        }
        "MasterKeyChangeRec" => {
            meta.master_key_change_rec = parse_int(&text, "MasterKeyChangeRec")?;
        }
        "MasterKeyChangeForce" => {
            meta.master_key_change_force = parse_int(&text, "MasterKeyChangeForce")?;
        }
        "HistoryMaxItems" => {
            meta.history_max_items = parse_int(&text, "HistoryMaxItems")?;
        }
        "HistoryMaxSize" => {
            meta.history_max_size = parse_int(&text, "HistoryMaxSize")?;
        }
        "MaintenanceHistoryDays" => {
            meta.maintenance_history_days = parse_int::<u32>(&text, "MaintenanceHistoryDays")?;
        }
        "Color" => meta.color = text,
        "HeaderHash" => meta.header_hash = text,
        _ => { /* unknown Meta child — ignore for now */ }
    }
    Ok(())
}

/// Parse a decimal integer (signed or unsigned) out of an XML element's
/// trimmed text content. Maps parse failures to
/// [`XmlError::InvalidValue`] tagged with the source element.
fn parse_int<T>(text: &str, element: &'static str) -> Result<T, XmlError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    text.trim()
        .parse::<T>()
        .map_err(|e| XmlError::InvalidValue {
            element,
            detail: format!("not a valid integer: {e}"),
        })
}

/// Read a `<Times>` block into a [`Timestamps`]. Assumes the opening
/// `<Times>` tag has just been consumed; reads up to and including the
/// matching `</Times>`.
///
/// Unknown children are skipped silently — KeePass writers occasionally
/// emit extensions we don't recognise.
fn read_times<R: std::io::BufRead>(
    reader: &mut Reader<R>,
    buf: &mut Vec<u8>,
) -> Result<Timestamps, XmlError> {
    let mut times = Timestamps::default();
    let mut depth: i32 = 0;

    loop {
        match reader.read_event_into(buf) {
            Err(e) => return Err(XmlError::Malformed(e.to_string())),
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if depth == 0 {
                    let text = read_text(reader, buf)?;
                    assign_times_field(&mut times, &name, &text)?;
                    continue;
                }
                depth += 1;
            }
            Ok(Event::End(_)) => {
                if depth == 0 {
                    return Ok(times);
                }
                depth -= 1;
            }
            Ok(Event::Eof) => {
                return Err(XmlError::Malformed("EOF inside <Times>".to_owned()));
            }
            _ => {}
        }
        buf.clear();
    }
}

fn assign_times_field(times: &mut Timestamps, field: &str, text: &str) -> Result<(), XmlError> {
    match field {
        "CreationTime" => times.creation_time = Some(parse_timestamp(text, "CreationTime")?),
        "LastModificationTime" => {
            times.last_modification_time = Some(parse_timestamp(text, "LastModificationTime")?);
        }
        "LastAccessTime" => {
            times.last_access_time = Some(parse_timestamp(text, "LastAccessTime")?);
        }
        "LocationChanged" => {
            times.location_changed = Some(parse_timestamp(text, "LocationChanged")?);
        }
        "ExpiryTime" => times.expiry_time = Some(parse_timestamp(text, "ExpiryTime")?),
        "Expires" => times.expires = parse_bool(text, "Expires")?,
        "UsageCount" => {
            times.usage_count = text
                .trim()
                .parse::<u64>()
                .map_err(|e| XmlError::InvalidValue {
                    element: "UsageCount",
                    detail: format!("not a non-negative integer: {e}"),
                })?;
        }
        _ => { /* unknown <Times> child — ignore */ }
    }
    Ok(())
}

/// Parse a KeePass timestamp.
///
/// KDBX3 uses ISO-8601 (`2024-03-01T12:34:56Z`). KDBX4 uses a base64
/// encoding of a little-endian `i64` tick count since
/// `0001-01-01T00:00:00Z`, with 100-nanosecond resolution. We
/// auto-detect: if the trimmed text contains `T` or `-`, treat it as
/// ISO-8601; otherwise try base64.
fn parse_timestamp(text: &str, element: &'static str) -> Result<DateTime<Utc>, XmlError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(XmlError::InvalidValue {
            element,
            detail: "empty timestamp".to_owned(),
        });
    }
    if trimmed.contains(['T', '-']) {
        return DateTime::parse_from_rfc3339(trimmed)
            .map(|dt| dt.with_timezone(&Utc))
            .map_err(|e| XmlError::InvalidValue {
                element,
                detail: format!("not a valid ISO-8601 timestamp: {e}"),
            });
    }
    let bytes = BASE64.decode(trimmed).map_err(|e| XmlError::InvalidValue {
        element,
        detail: format!("not valid base64: {e}"),
    })?;
    let arr: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| XmlError::InvalidValue {
            element,
            detail: format!("expected 8 bytes of ticks, got {}", bytes.len()),
        })?;
    let ticks = i64::from_le_bytes(arr);
    ticks_to_datetime(ticks).ok_or(XmlError::InvalidValue {
        element,
        detail: "tick count out of representable UTC range".to_owned(),
    })
}

fn ticks_to_datetime(ticks: i64) -> Option<DateTime<Utc>> {
    // ticks are 100-ns units since year-1 AD. Convert to Unix-epoch
    // seconds + sub-second nanoseconds, then let chrono assemble the
    // DateTime.
    let from_unix = ticks.checked_sub(TICKS_FROM_YEAR_ONE_TO_UNIX_EPOCH)?;
    let secs = from_unix.div_euclid(10_000_000);
    let subsec_ticks = from_unix.rem_euclid(10_000_000);
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    let nanos = (subsec_ticks * 100) as u32; // 0..=999_999_900 fits in u32
    match Utc.timestamp_opt(secs, nanos) {
        chrono::LocalResult::Single(dt) => Some(dt),
        _ => None,
    }
}

/// Parse a KeePass tri-state boolean as written in `<EnableAutoType>` and
/// `<EnableSearching>`:
///
/// - `"null"` (case-insensitive) → `None` (inherit from parent)
/// - `"True"` / `"true"` → `Some(true)`
/// - `"False"` / `"false"` → `Some(false)`
/// - Anything else → `None` (treat as inherit; tri-state has no error
///   channel by spec)
fn parse_tristate(text: &str) -> Option<bool> {
    match text.trim() {
        "True" | "true" => Some(true),
        "False" | "false" => Some(false),
        _ => None,
    }
}

fn parse_bool(text: &str, element: &'static str) -> Result<bool, XmlError> {
    match text.trim() {
        "True" | "true" => Ok(true),
        "False" | "false" => Ok(false),
        other => Err(XmlError::InvalidValue {
            element,
            detail: format!("expected True/False, got {other:?}"),
        }),
    }
}

/// Split a raw `<Tags>` string into individual tag values.
///
/// KeePass writers are inconsistent: the reference KeePass 2.x source
/// uses `;` as the canonical separator, but some clients (KeePassXC
/// among them) emit `,`. We accept either interchangeably. Empty and
/// whitespace-only segments are dropped; surrounding whitespace on each
/// tag is trimmed.
fn parse_tags(raw: &str) -> Vec<String> {
    raw.split([';', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Parse a `<PreviousParentGroup>` payload into an `Option<GroupId>`.
/// Empty string or nil UUID both map to `None`, matching the KeePass
/// convention that "no previous parent" is written as either.
fn parse_optional_group_id(text: &str) -> Result<Option<GroupId>, XmlError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let uuid = parse_uuid(trimmed)?;
    Ok(if uuid.is_nil() {
        None
    } else {
        Some(GroupId(uuid))
    })
}

/// Parse a `<LastTopVisibleEntry>` payload into an `Option<EntryId>`.
/// Mirrors [`parse_optional_group_id`] but wraps into [`EntryId`].
fn parse_optional_entry_id(text: &str) -> Result<Option<EntryId>, XmlError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let uuid = parse_uuid(trimmed)?;
    Ok(if uuid.is_nil() {
        None
    } else {
        Some(EntryId(uuid))
    })
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
        assert_eq!(vault.meta.generator, "KeePassXC");
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
        // Password is base64-decoded and XOR'd against the (None) cipher,
        // which is a passthrough — so we see the raw plaintext bytes
        // that the test payload encoded (cGxhaW4= == "plain").
        assert_eq!(gmail.password, "plain");
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
        // Protected="True" on a custom field survives into CustomField.
        // The base64 payload (c2VjcmV0 == "secret") is decoded through
        // the None cipher, yielding the plaintext string directly.
        let xml = br#"<?xml version="1.0"?>
<KeePassFile>
  <Meta><Generator>X</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>TOTP Seed</Key><Value Protected="True">c2VjcmV0</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.custom_fields.len(), 1);
        assert!(e.custom_fields[0].protected);
        assert_eq!(e.custom_fields[0].value, "secret");
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
        assert_eq!(vault.meta.generator, "");
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

    // -----------------------------------------------------------------
    // Cipher-threaded decoding
    // -----------------------------------------------------------------

    use crate::format::InnerStreamAlgorithm;

    /// Build an XML document where each protected value is the base64 of
    /// the XOR of the corresponding plaintext against the keystream
    /// generated by `key`. Two protected values in document order, so
    /// that keystream-advancement is observable in the output.
    fn encrypt(plaintext: &[u8], keystream: &mut [u8]) -> String {
        assert!(keystream.len() >= plaintext.len());
        let mut buf = plaintext.to_vec();
        for (b, k) in buf.iter_mut().zip(keystream.iter()) {
            *b ^= k;
        }
        BASE64.encode(&buf)
    }

    #[test]
    fn salsa20_cipher_decrypts_protected_values_in_document_order() {
        // Derive the keystream we'll XOR against our two secrets.
        let key = [0x42u8; 32];
        let mut stream = [0u8; 64];
        let mut ks = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        ks.process(&mut stream);

        let pw_plain = b"hunter2";
        let totp_plain = b"JBSWY3DPEHPK3PXP";

        // First protected value consumes bytes 0..pw_plain.len() of the
        // keystream; the second consumes the following totp_plain.len()
        // bytes. Encrypt accordingly.
        let (head, rest) = stream.split_at_mut(pw_plain.len());
        let pw_cipher = encrypt(pw_plain, head);
        let (mid, _) = rest.split_at_mut(totp_plain.len());
        let totp_cipher = encrypt(totp_plain, mid);

        let xml = format!(
            r#"<KeePassFile>
  <Meta><Generator>T</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>Gmail</Value></String>
        <String><Key>Password</Key><Value Protected="True">{pw_cipher}</Value></String>
        <String><Key>TOTP Seed</Key><Value Protected="True">{totp_cipher}</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#
        );

        let mut cipher = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let vault = decode_vault_with_cipher(xml.as_bytes(), &mut cipher).unwrap();
        let entry = vault.iter_entries().next().unwrap();

        assert_eq!(entry.title, "Gmail");
        assert_eq!(entry.password, "hunter2");
        assert_eq!(entry.custom_fields.len(), 1);
        assert_eq!(entry.custom_fields[0].key, "TOTP Seed");
        assert_eq!(entry.custom_fields[0].value, "JBSWY3DPEHPK3PXP");
        assert!(entry.custom_fields[0].protected);
    }

    #[test]
    fn chacha20_cipher_decrypts_protected_values() {
        let key = b"inner-stream-key-arbitrary-len".to_vec();
        let mut stream = [0u8; 64];
        let mut ks = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        ks.process(&mut stream);

        let plain = b"correct horse battery staple";
        let (head, _) = stream.split_at_mut(plain.len());
        let cipher_b64 = encrypt(plain, head);

        let xml = format!(
            r#"<KeePassFile>
  <Meta><Generator>T</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Password</Key><Value Protected="True">{cipher_b64}</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#
        );

        let mut cipher = InnerStreamCipher::new(InnerStreamAlgorithm::ChaCha20, &key).unwrap();
        let vault = decode_vault_with_cipher(xml.as_bytes(), &mut cipher).unwrap();
        let entry = vault.iter_entries().next().unwrap();
        assert_eq!(entry.password, "correct horse battery staple");
    }

    #[test]
    fn non_base64_protected_value_is_rejected() {
        let xml = br#"<KeePassFile>
  <Meta><Generator>T</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Password</Key><Value Protected="True">!!!not base64!!!</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let mut cipher = InnerStreamCipher::None;
        let err = decode_vault_with_cipher(xml, &mut cipher).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "Value",
                ..
            }
        ));
    }

    #[test]
    fn non_utf8_plaintext_is_rejected() {
        // A Salsa20 keystream over an arbitrary 8-byte ciphertext will
        // almost never yield valid UTF-8; engineer that directly by
        // XOR-ing valid base64-decoded bytes that result in 0xFF bytes
        // under the None cipher.
        // 0xFF 0xFE 0xFD is never valid UTF-8 as a standalone sequence.
        let payload = BASE64.encode([0xFF_u8, 0xFE, 0xFD]);
        let xml = format!(
            r#"<KeePassFile>
  <Meta><Generator>T</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Password</Key><Value Protected="True">{payload}</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#
        );
        let mut cipher = InnerStreamCipher::None;
        let err = decode_vault_with_cipher(xml.as_bytes(), &mut cipher).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "Value",
                ..
            }
        ));
    }

    #[test]
    fn decode_vault_is_decode_vault_with_cipher_none() {
        // The plain wrapper should produce identical output to
        // decode_vault_with_cipher(&mut None).
        let xml = sample_xml();
        let a = decode_vault(xml).unwrap();
        let mut none = InnerStreamCipher::None;
        let b = decode_vault_with_cipher(xml, &mut none).unwrap();
        assert_eq!(a, b);
    }

    // -----------------------------------------------------------------
    // <Times> block
    // -----------------------------------------------------------------

    #[test]
    fn parses_kdbx3_iso8601_timestamps_on_entry() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <Times>
          <CreationTime>2026-04-21T10:11:12Z</CreationTime>
          <LastModificationTime>2026-04-22T13:14:15Z</LastModificationTime>
          <LastAccessTime>2026-04-22T13:14:16Z</LastAccessTime>
          <LocationChanged>2026-04-22T13:14:17Z</LocationChanged>
          <ExpiryTime>2026-04-22T13:14:18Z</ExpiryTime>
          <Expires>True</Expires>
          <UsageCount>7</UsageCount>
        </Times>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        let t = &e.times;
        assert_eq!(
            t.creation_time,
            Some(Utc.with_ymd_and_hms(2026, 4, 21, 10, 11, 12).unwrap())
        );
        assert_eq!(
            t.last_modification_time,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 13, 14, 15).unwrap())
        );
        assert_eq!(
            t.last_access_time,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 13, 14, 16).unwrap())
        );
        assert_eq!(
            t.location_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 13, 14, 17).unwrap())
        );
        assert_eq!(
            t.expiry_time,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 13, 14, 18).unwrap())
        );
        assert!(t.expires);
        assert_eq!(t.usage_count, 7);
    }

    #[test]
    fn parses_kdbx4_base64_tick_timestamp_on_group() {
        // Derive the ticks for a known UTC instant and round-trip it.
        let expected = Utc.with_ymd_and_hms(2026, 4, 21, 10, 11, 12).unwrap();
        let ticks = expected.timestamp() * 10_000_000 + TICKS_FROM_YEAR_ONE_TO_UNIX_EPOCH;
        let b64 = BASE64.encode(ticks.to_le_bytes());
        let xml = format!(
            r"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Times>
        <CreationTime>{b64}</CreationTime>
      </Times>
    </Group>
  </Root>
</KeePassFile>"
        );
        let vault = decode_vault(xml.as_bytes()).unwrap();
        assert_eq!(vault.root.times.creation_time, Some(expected));
    }

    #[test]
    fn missing_times_block_gives_default() {
        let vault = decode_vault(sample_xml()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.times, Timestamps::default());
        assert_eq!(vault.root.times, Timestamps::default());
    }

    #[test]
    fn unknown_times_children_are_ignored() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Times>
        <CreationTime>2026-01-01T00:00:00Z</CreationTime>
        <FutureExtension>some value</FutureExtension>
      </Times>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(
            vault.root.times.creation_time,
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
        );
    }

    #[test]
    fn rejects_malformed_iso8601_timestamp() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Times>
        <CreationTime>2026-bad-date</CreationTime>
      </Times>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "CreationTime",
                ..
            }
        ));
    }

    #[test]
    fn rejects_wrong_length_tick_timestamp() {
        // Valid base64 that doesn't give 8 bytes.
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Times>
        <CreationTime>aGVsbG8=</CreationTime>
      </Times>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "CreationTime",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------
    // <Meta> block
    // -----------------------------------------------------------------

    #[test]
    fn parses_meta_string_fields() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>KeePassXC</Generator>
    <DatabaseName>My Vault</DatabaseName>
    <DatabaseDescription>Shared household passwords</DatabaseDescription>
    <DefaultUserName>alice</DefaultUserName>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.generator, "KeePassXC");
        assert_eq!(vault.meta.database_name, "My Vault");
        assert_eq!(
            vault.meta.database_description,
            "Shared household passwords"
        );
        assert_eq!(vault.meta.default_username, "alice");
    }

    #[test]
    fn parses_meta_changed_timestamps() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <DatabaseName>N</DatabaseName>
    <DatabaseNameChanged>2026-04-22T11:22:33Z</DatabaseNameChanged>
    <DatabaseDescription>D</DatabaseDescription>
    <DatabaseDescriptionChanged>2026-04-22T11:22:34Z</DatabaseDescriptionChanged>
    <DefaultUserName>U</DefaultUserName>
    <DefaultUserNameChanged>2026-04-22T11:22:35Z</DefaultUserNameChanged>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(
            vault.meta.database_name_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 11, 22, 33).unwrap())
        );
        assert_eq!(
            vault.meta.database_description_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 11, 22, 34).unwrap())
        );
        assert_eq!(
            vault.meta.default_username_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 11, 22, 35).unwrap())
        );
    }

    #[test]
    fn unknown_meta_children_are_skipped() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <DatabaseName>N</DatabaseName>
    <MemoryProtection>
      <ProtectPassword>True</ProtectPassword>
    </MemoryProtection>
    <HeaderHash>Zm9vYmFy</HeaderHash>
    <CustomData>
      <Item><Key>x</Key><Value>y</Value></Item>
    </CustomData>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.generator, "G");
        assert_eq!(vault.meta.database_name, "N");
        // Unknown Meta children parsed silently, no state bleeds into
        // modelled fields.
        assert_eq!(vault.meta.database_description, "");
        assert_eq!(vault.meta.default_username, "");
    }

    #[test]
    fn empty_meta_gives_default() {
        let xml = br"<KeePassFile>
  <Meta/>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta, Meta::default());
    }

    #[test]
    fn parses_recycle_bin_meta_fields() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <RecycleBinEnabled>True</RecycleBinEnabled>
    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAg==</RecycleBinUUID>
    <RecycleBinChanged>2026-04-22T11:22:33Z</RecycleBinChanged>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(vault.meta.recycle_bin_enabled);
        let mut expected = [0u8; 16];
        expected[15] = 2;
        assert_eq!(
            vault.meta.recycle_bin_uuid,
            Some(GroupId(Uuid::from_bytes(expected)))
        );
        assert_eq!(
            vault.meta.recycle_bin_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 11, 22, 33).unwrap())
        );
    }

    #[test]
    fn parses_meta_custom_icons_pool() {
        let png = b"\x89PNG\r\n\x1a\n-fake-icon-payload";
        let png_b64 = BASE64.encode(png);
        let uuid_b64 = BASE64.encode([0u8; 15].iter().chain(&[0x2a]).copied().collect::<Vec<_>>());
        let xml = format!(
            r"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <CustomIcons>
      <Icon>
        <UUID>{uuid_b64}</UUID>
        <Data>{png_b64}</Data>
        <Name>Bank logo</Name>
        <LastModificationTime>2026-04-22T10:00:00Z</LastModificationTime>
      </Icon>
      <Icon>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <Data>{png_b64}</Data>
      </Icon>
    </CustomIcons>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>"
        );
        let vault = decode_vault(xml.as_bytes()).unwrap();
        assert_eq!(vault.meta.custom_icons.len(), 2);
        assert_eq!(vault.meta.custom_icons[0].data, png);
        assert_eq!(vault.meta.custom_icons[0].name, "Bank logo");
        assert_eq!(
            vault.meta.custom_icons[0].last_modified,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 10, 0, 0).unwrap())
        );
        assert_eq!(vault.meta.custom_icons[1].name, "");
        assert_eq!(vault.meta.custom_icons[1].last_modified, None);
    }

    #[test]
    fn custom_icon_missing_uuid_or_data_is_dropped() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <CustomIcons>
      <Icon><Data>YWJj</Data></Icon>
      <Icon><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID></Icon>
      <Icon>
        <UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>
        <Data>YWJj</Data>
      </Icon>
    </CustomIcons>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.custom_icons.len(), 1);
        assert_eq!(vault.meta.custom_icons[0].data, b"abc");
    }

    #[test]
    fn custom_icon_bad_base64_rejected() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <CustomIcons>
      <Icon>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <Data>!!!not base64!!!</Data>
      </Icon>
    </CustomIcons>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "Data",
                ..
            }
        ));
    }

    #[test]
    fn parses_meta_history_and_master_key_settings() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <SettingsChanged>2026-04-22T10:00:00Z</SettingsChanged>
    <MasterKeyChanged>2026-04-21T10:00:00Z</MasterKeyChanged>
    <MasterKeyChangeRec>180</MasterKeyChangeRec>
    <MasterKeyChangeForce>365</MasterKeyChangeForce>
    <HistoryMaxItems>20</HistoryMaxItems>
    <HistoryMaxSize>12582912</HistoryMaxSize>
    <MaintenanceHistoryDays>90</MaintenanceHistoryDays>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(
            vault.meta.settings_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 22, 10, 0, 0).unwrap())
        );
        assert_eq!(
            vault.meta.master_key_changed,
            Some(Utc.with_ymd_and_hms(2026, 4, 21, 10, 0, 0).unwrap())
        );
        assert_eq!(vault.meta.master_key_change_rec, 180);
        assert_eq!(vault.meta.master_key_change_force, 365);
        assert_eq!(vault.meta.history_max_items, 20);
        assert_eq!(vault.meta.history_max_size, 12_582_912);
        assert_eq!(vault.meta.maintenance_history_days, 90);
    }

    #[test]
    fn defaults_match_keepass_stock_values() {
        // Confirms the manual Default impl matches the KeePass 2.x
        // factory-default values rather than Rust's all-zero integers.
        let m = Meta::default();
        assert_eq!(m.master_key_change_rec, -1);
        assert_eq!(m.master_key_change_force, -1);
        assert_eq!(m.history_max_items, 10);
        assert_eq!(m.history_max_size, 6 * 1024 * 1024);
        assert_eq!(m.maintenance_history_days, 365);
    }

    #[test]
    fn rejects_non_integer_history_setting() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <HistoryMaxItems>lots</HistoryMaxItems>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "HistoryMaxItems",
                ..
            }
        ));
    }

    #[test]
    fn parses_memory_protection_flags() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <MemoryProtection>
      <ProtectTitle>True</ProtectTitle>
      <ProtectUserName>False</ProtectUserName>
      <ProtectPassword>True</ProtectPassword>
      <ProtectURL>True</ProtectURL>
      <ProtectNotes>True</ProtectNotes>
    </MemoryProtection>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let mp = vault.meta.memory_protection;
        assert!(mp.protect_title);
        assert!(!mp.protect_username);
        assert!(mp.protect_password);
        assert!(mp.protect_url);
        assert!(mp.protect_notes);
    }

    #[test]
    fn missing_memory_protection_keeps_keepass_defaults() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let mp = vault.meta.memory_protection;
        assert!(!mp.protect_title);
        assert!(!mp.protect_username);
        assert!(mp.protect_password); // KeePass default
        assert!(!mp.protect_url);
        assert!(!mp.protect_notes);
    }

    #[test]
    fn unknown_memory_protection_children_are_ignored() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <MemoryProtection>
      <ProtectPassword>False</ProtectPassword>
      <FutureExtension>anything</FutureExtension>
    </MemoryProtection>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(!vault.meta.memory_protection.protect_password);
    }

    #[test]
    fn zero_recycle_bin_uuid_is_treated_as_none() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <RecycleBinEnabled>False</RecycleBinEnabled>
    <RecycleBinUUID>AAAAAAAAAAAAAAAAAAAAAA==</RecycleBinUUID>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(!vault.meta.recycle_bin_enabled);
        assert_eq!(vault.meta.recycle_bin_uuid, None);
    }

    // -----------------------------------------------------------------
    // <Tags> parsing
    // -----------------------------------------------------------------

    fn tags_fixture(tags_xml: &str) -> String {
        format!(
            r"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        {tags_xml}
      </Entry>
    </Group>
  </Root>
</KeePassFile>"
        )
    }

    #[test]
    fn parses_semicolon_separated_tags() {
        let vault =
            decode_vault(tags_fixture("<Tags>work;vpn;personal</Tags>").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.tags, vec!["work", "vpn", "personal"]);
    }

    #[test]
    fn parses_comma_separated_tags() {
        let vault =
            decode_vault(tags_fixture("<Tags>work,vpn,personal</Tags>").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.tags, vec!["work", "vpn", "personal"]);
    }

    #[test]
    fn parses_mixed_separator_tags() {
        // Some clients emit a mix when migrating between tools.
        let vault = decode_vault(tags_fixture("<Tags>a;b,c</Tags>").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.tags, vec!["a", "b", "c"]);
    }

    #[test]
    fn trims_whitespace_around_tag_values() {
        let vault =
            decode_vault(tags_fixture("<Tags>  work ;  vpn  ; personal </Tags>").as_bytes())
                .unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.tags, vec!["work", "vpn", "personal"]);
    }

    #[test]
    fn drops_empty_tag_segments() {
        let vault = decode_vault(tags_fixture("<Tags>;;work;;;vpn;</Tags>").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.tags, vec!["work", "vpn"]);
    }

    #[test]
    fn empty_tags_element_yields_empty_vec() {
        let vault = decode_vault(tags_fixture("<Tags></Tags>").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.tags.is_empty());
    }

    #[test]
    fn missing_tags_element_yields_empty_vec() {
        let vault = decode_vault(tags_fixture("").as_bytes()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.tags.is_empty());
    }

    // -----------------------------------------------------------------
    // <History>
    // -----------------------------------------------------------------

    #[test]
    fn history_snapshots_are_collected_in_order() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>Current</Value></String>
        <History>
          <Entry>
            <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
            <String><Key>Title</Key><Value>Oldest</Value></String>
          </Entry>
          <Entry>
            <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
            <String><Key>Title</Key><Value>Middle</Value></String>
          </Entry>
          <Entry>
            <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
            <String><Key>Title</Key><Value>Newest</Value></String>
          </Entry>
        </History>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.title, "Current");
        let hist_titles: Vec<_> = e.history.iter().map(|h| h.title.clone()).collect();
        assert_eq!(hist_titles, ["Oldest", "Middle", "Newest"]);
    }

    #[test]
    fn empty_history_yields_empty_vec() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <History/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.history.is_empty());
    }

    #[test]
    fn history_keeps_inner_stream_cipher_in_sync() {
        // Two protected values: one in a history snapshot, one on the
        // current entry that follows. If the decoder skipped the
        // snapshot's <Value>, the keystream would desynchronise and the
        // current entry's password would decrypt to garbage.
        use crate::crypto::InnerStreamCipher;
        use crate::format::InnerStreamAlgorithm;

        // Derive a known 64-byte keystream we can XOR against.
        let key = [0x33u8; 32];
        let mut stream = [0u8; 64];
        let mut ks = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        ks.process(&mut stream);

        let pw_hist = b"history-pw";
        let pw_current = b"current-pw";
        let (head, rest) = stream.split_at_mut(pw_hist.len());
        let hist_cipher = BASE64.encode(xor(pw_hist, head));
        let (mid, _) = rest.split_at_mut(pw_current.len());
        let cur_cipher = BASE64.encode(xor(pw_current, mid));

        let xml = format!(
            r#"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <History>
          <Entry>
            <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
            <String><Key>Title</Key><Value>T-old</Value></String>
            <String><Key>Password</Key><Value Protected="True">{hist_cipher}</Value></String>
          </Entry>
        </History>
        <String><Key>Password</Key><Value Protected="True">{cur_cipher}</Value></String>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#
        );
        let mut cipher = InnerStreamCipher::new(InnerStreamAlgorithm::Salsa20, &key).unwrap();
        let vault = decode_vault_with_cipher(xml.as_bytes(), &mut cipher).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.password, "current-pw");
        assert_eq!(e.history.len(), 1);
        assert_eq!(e.history[0].password, "history-pw");
    }

    fn xor(plain: &[u8], keystream: &[u8]) -> Vec<u8> {
        plain.iter().zip(keystream).map(|(p, k)| p ^ k).collect()
    }

    // -----------------------------------------------------------------
    // <Binary> attachment references
    // -----------------------------------------------------------------

    #[test]
    fn parses_binary_references_on_entry() {
        let xml = br#"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <Binary><Key>hello.txt</Key><Value Ref="0"/></Binary>
        <Binary><Key>image.png</Key><Value Ref="3"/></Binary>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.attachments.len(), 2);
        assert_eq!(e.attachments[0].name, "hello.txt");
        assert_eq!(e.attachments[0].ref_id, 0);
        assert_eq!(e.attachments[1].name, "image.png");
        assert_eq!(e.attachments[1].ref_id, 3);
    }

    #[test]
    fn binary_without_ref_attribute_is_silently_dropped() {
        // Some writers leave a stub <Binary/> behind when an attachment
        // is removed. Don't fail the whole decode over it.
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <Binary><Key>orphan</Key><Value/></Binary>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.attachments.is_empty());
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use std::io::Write as _;
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());
        gz.write_all(bytes).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn parses_kdbx3_binaries_pool_with_compressed_and_uncompressed() {
        let hello_raw = BASE64.encode(b"hello");
        let world_gz_b64 = BASE64.encode(gzip(b"world"));

        let xml = format!(
            r#"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <Binaries>
      <Binary ID="0" Compressed="False">{hello_raw}</Binary>
      <Binary ID="1" Compressed="True">{world_gz_b64}</Binary>
    </Binaries>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>"#
        );
        let vault = decode_vault(xml.as_bytes()).unwrap();
        assert_eq!(vault.binaries.len(), 2);
        assert_eq!(vault.binaries[0].data, b"hello");
        assert!(!vault.binaries[0].protected);
        assert_eq!(vault.binaries[1].data, b"world");
    }

    #[test]
    fn kdbx3_binaries_pool_handles_sparse_ids() {
        let xml = br#"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <Binaries>
      <Binary ID="2" Compressed="False">YWJj</Binary>
    </Binaries>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>"#;
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.binaries.len(), 3); // 0, 1 placeholders + 2
        assert!(vault.binaries[0].data.is_empty());
        assert!(vault.binaries[1].data.is_empty());
        assert_eq!(vault.binaries[2].data, b"abc");
    }

    #[test]
    fn binary_with_non_integer_ref_is_rejected() {
        let xml = br#"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <Binary><Key>bad</Key><Value Ref="not-a-number"/></Binary>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let err = decode_vault(xml).unwrap_err();
        assert!(matches!(
            err,
            XmlError::InvalidValue {
                element: "Value",
                ..
            }
        ));
    }

    // -----------------------------------------------------------------
    // <DeletedObjects>
    // -----------------------------------------------------------------

    #[test]
    fn parses_deleted_objects_in_source_order() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
    <DeletedObjects>
      <DeletedObject>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <DeletionTime>2026-04-21T10:00:00Z</DeletionTime>
      </DeletedObject>
      <DeletedObject>
        <UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>
        <DeletionTime>2026-04-22T11:00:00Z</DeletionTime>
      </DeletedObject>
    </DeletedObjects>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.deleted_objects.len(), 2);
        let mut expected_u1 = [0u8; 16];
        expected_u1[15] = 1;
        assert_eq!(vault.deleted_objects[0].uuid, Uuid::from_bytes(expected_u1));
        assert_eq!(
            vault.deleted_objects[0].deleted_at,
            Some(Utc.with_ymd_and_hms(2026, 4, 21, 10, 0, 0).unwrap())
        );
        let mut expected_u2 = [0u8; 16];
        expected_u2[15] = 2;
        assert_eq!(vault.deleted_objects[1].uuid, Uuid::from_bytes(expected_u2));
    }

    #[test]
    fn missing_deletion_time_is_tolerated() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
    <DeletedObjects>
      <DeletedObject>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
      </DeletedObject>
    </DeletedObjects>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.deleted_objects.len(), 1);
        assert_eq!(vault.deleted_objects[0].deleted_at, None);
    }

    #[test]
    fn deleted_object_without_uuid_is_skipped() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
    <DeletedObjects>
      <DeletedObject>
        <DeletionTime>2026-04-21T10:00:00Z</DeletionTime>
      </DeletedObject>
    </DeletedObjects>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(vault.deleted_objects.is_empty());
    }

    #[test]
    fn missing_deleted_objects_block_is_empty() {
        let vault = decode_vault(sample_xml()).unwrap();
        assert!(vault.deleted_objects.is_empty());
    }

    // -----------------------------------------------------------------
    // Group-level UI / auto-type / search fields
    // -----------------------------------------------------------------

    #[test]
    fn parses_group_ui_and_auto_type_fields() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Work</Name>
      <IsExpanded>False</IsExpanded>
      <DefaultAutoTypeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultAutoTypeSequence>
      <EnableAutoType>True</EnableAutoType>
      <EnableSearching>False</EnableSearching>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(!vault.root.is_expanded);
        assert_eq!(
            vault.root.default_auto_type_sequence,
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(vault.root.enable_auto_type, Some(true));
        assert_eq!(vault.root.enable_searching, Some(false));
    }

    #[test]
    fn missing_group_ui_fields_use_defaults() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Default</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert!(vault.root.is_expanded); // KeePass default: true
        assert!(vault.root.default_auto_type_sequence.is_empty());
        assert_eq!(vault.root.enable_auto_type, None);
        assert_eq!(vault.root.enable_searching, None);
    }

    // -----------------------------------------------------------------
    // Meta/CustomData
    // -----------------------------------------------------------------

    #[test]
    fn parses_meta_custom_data_items() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <CustomData>
      <Item>
        <Key>KPXC_DECRYPTION_TIME_PREFERENCE</Key>
        <Value>1000</Value>
        <LastModificationTime>2026-04-21T10:00:00Z</LastModificationTime>
      </Item>
      <Item>
        <Key>plugin.example.flag</Key>
        <Value>true</Value>
      </Item>
    </CustomData>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.custom_data.len(), 2);
        assert_eq!(
            vault.meta.custom_data[0].key,
            "KPXC_DECRYPTION_TIME_PREFERENCE"
        );
        assert_eq!(vault.meta.custom_data[0].value, "1000");
        assert_eq!(
            vault.meta.custom_data[0].last_modified,
            Some(Utc.with_ymd_and_hms(2026, 4, 21, 10, 0, 0).unwrap())
        );
        assert_eq!(vault.meta.custom_data[1].key, "plugin.example.flag");
        assert_eq!(vault.meta.custom_data[1].value, "true");
        assert_eq!(vault.meta.custom_data[1].last_modified, None);
    }

    #[test]
    fn incomplete_custom_data_item_is_dropped() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <CustomData>
      <Item><Key>orphan</Key></Item>
      <Item><Value>orphan</Value></Item>
      <Item>
        <Key>real</Key>
        <Value>v</Value>
      </Item>
    </CustomData>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.custom_data.len(), 1);
        assert_eq!(vault.meta.custom_data[0].key, "real");
    }

    #[test]
    fn missing_custom_data_is_empty() {
        let vault = decode_vault(sample_xml()).unwrap();
        assert!(vault.meta.custom_data.is_empty());
    }

    #[test]
    fn tristate_null_inherits() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <EnableAutoType>null</EnableAutoType>
      <EnableSearching>NULL</EnableSearching>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.root.enable_auto_type, None);
        assert_eq!(vault.root.enable_searching, None);
    }

    // -----------------------------------------------------------------
    // Entry: colours, override URL, custom icon
    // -----------------------------------------------------------------

    #[test]
    fn parses_entry_colors_override_url_and_custom_icon() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <ForegroundColor>#FF0000</ForegroundColor>
        <BackgroundColor>#00FFAA</BackgroundColor>
        <OverrideURL>cmd://firefox %1</OverrideURL>
        <CustomIconUUID>AAAAAAAAAAAAAAAAAAAAAg==</CustomIconUUID>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.foreground_color, "#FF0000");
        assert_eq!(e.background_color, "#00FFAA");
        assert_eq!(e.override_url, "cmd://firefox %1");
        let mut expected = [0u8; 16];
        expected[15] = 2;
        assert_eq!(e.custom_icon_uuid, Some(Uuid::from_bytes(expected)));
    }

    #[test]
    fn missing_entry_metadata_fields_are_empty_or_none() {
        let vault = decode_vault(sample_xml()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.foreground_color.is_empty());
        assert!(e.background_color.is_empty());
        assert!(e.override_url.is_empty());
        assert_eq!(e.custom_icon_uuid, None);
    }

    #[test]
    fn zero_custom_icon_uuid_is_treated_as_none() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <CustomIconUUID>AAAAAAAAAAAAAAAAAAAAAA==</CustomIconUUID>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.custom_icon_uuid, None);
    }

    #[test]
    fn empty_custom_icon_uuid_element_is_treated_as_none() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <CustomIconUUID/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.custom_icon_uuid, None);
    }

    // -----------------------------------------------------------------
    // Group + Entry CustomData
    // -----------------------------------------------------------------

    #[test]
    fn parses_group_custom_data() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <CustomData>
        <Item>
          <Key>plugin.group.flag</Key>
          <Value>enabled</Value>
        </Item>
      </CustomData>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.root.custom_data.len(), 1);
        assert_eq!(vault.root.custom_data[0].key, "plugin.group.flag");
        assert_eq!(vault.root.custom_data[0].value, "enabled");
    }

    #[test]
    fn parses_entry_custom_data() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <CustomData>
          <Item>
            <Key>plugin.entry.foo</Key>
            <Value>bar</Value>
            <LastModificationTime>2026-04-21T10:00:00Z</LastModificationTime>
          </Item>
          <Item>
            <Key>plugin.entry.baz</Key>
            <Value>qux</Value>
          </Item>
        </CustomData>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.custom_data.len(), 2);
        assert_eq!(e.custom_data[0].key, "plugin.entry.foo");
        assert_eq!(e.custom_data[0].value, "bar");
        assert_eq!(
            e.custom_data[0].last_modified,
            Some(Utc.with_ymd_and_hms(2026, 4, 21, 10, 0, 0).unwrap())
        );
        assert_eq!(e.custom_data[1].key, "plugin.entry.baz");
        assert_eq!(e.custom_data[1].last_modified, None);
    }

    #[test]
    fn missing_group_or_entry_custom_data_is_empty() {
        let vault = decode_vault(sample_xml()).unwrap();
        assert!(vault.root.custom_data.is_empty());
        let e = vault.iter_entries().next().unwrap();
        assert!(e.custom_data.is_empty());
    }

    // -----------------------------------------------------------------
    // QualityCheck + PreviousParentGroup + LastTopVisibleEntry
    // -----------------------------------------------------------------

    #[test]
    fn parses_entry_quality_check_and_previous_parent() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <QualityCheck>False</QualityCheck>
        <PreviousParentGroup>AAAAAAAAAAAAAAAAAAAAAg==</PreviousParentGroup>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(!e.quality_check);
        let mut expected = [0u8; 16];
        expected[15] = 2;
        assert_eq!(
            e.previous_parent_group,
            Some(GroupId(Uuid::from_bytes(expected)))
        );
    }

    #[test]
    fn missing_quality_check_defaults_to_true() {
        let vault = decode_vault(sample_xml()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.quality_check);
        assert_eq!(e.previous_parent_group, None);
    }

    #[test]
    fn parses_group_custom_icon_uuid() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <CustomIconUUID>AAAAAAAAAAAAAAAAAAAAAg==</CustomIconUUID>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let mut expected = [0u8; 16];
        expected[15] = 2;
        assert_eq!(
            vault.root.custom_icon_uuid,
            Some(Uuid::from_bytes(expected))
        );
    }

    #[test]
    fn parses_meta_color_and_header_hash() {
        let xml = br"<KeePassFile>
  <Meta>
    <Generator>G</Generator>
    <Color>#FF8800</Color>
    <HeaderHash>Zm9vYmFy</HeaderHash>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.meta.color, "#FF8800");
        assert_eq!(vault.meta.header_hash, "Zm9vYmFy");
    }

    #[test]
    fn parses_group_previous_parent_and_last_top_visible_entry() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <PreviousParentGroup>AAAAAAAAAAAAAAAAAAAAAw==</PreviousParentGroup>
      <LastTopVisibleEntry>AAAAAAAAAAAAAAAAAAAABA==</LastTopVisibleEntry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let mut expected_parent = [0u8; 16];
        expected_parent[15] = 3;
        assert_eq!(
            vault.root.previous_parent_group,
            Some(GroupId(Uuid::from_bytes(expected_parent)))
        );
        let mut expected_entry = [0u8; 16];
        expected_entry[15] = 4;
        assert_eq!(
            vault.root.last_top_visible_entry,
            Some(EntryId(Uuid::from_bytes(expected_entry)))
        );
    }

    #[test]
    fn nil_previous_parent_and_last_top_visible_are_none() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <PreviousParentGroup>AAAAAAAAAAAAAAAAAAAAAA==</PreviousParentGroup>
      <LastTopVisibleEntry></LastTopVisibleEntry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        assert_eq!(vault.root.previous_parent_group, None);
        assert_eq!(vault.root.last_top_visible_entry, None);
    }

    // -----------------------------------------------------------------
    // AutoType
    // -----------------------------------------------------------------

    #[test]
    fn parses_entry_auto_type_with_associations() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <AutoType>
          <Enabled>False</Enabled>
          <DataTransferObfuscation>1</DataTransferObfuscation>
          <DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
          <Association>
            <Window>Firefox - *</Window>
            <KeystrokeSequence>{PASSWORD}{ENTER}</KeystrokeSequence>
          </Association>
          <Association>
            <Window>Work VPN - *</Window>
            <KeystrokeSequence>{USERNAME}{TAB}{PASSWORD}</KeystrokeSequence>
          </Association>
        </AutoType>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(!e.auto_type.enabled);
        assert_eq!(e.auto_type.data_transfer_obfuscation, 1);
        assert_eq!(
            e.auto_type.default_sequence,
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(e.auto_type.associations.len(), 2);
        assert_eq!(e.auto_type.associations[0].window, "Firefox - *");
        assert_eq!(
            e.auto_type.associations[0].keystroke_sequence,
            "{PASSWORD}{ENTER}"
        );
        assert_eq!(e.auto_type.associations[1].window, "Work VPN - *");
    }

    #[test]
    fn missing_auto_type_block_gives_default() {
        let vault = decode_vault(sample_xml()).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert!(e.auto_type.enabled); // default: enabled
        assert_eq!(e.auto_type.data_transfer_obfuscation, 0);
        assert!(e.auto_type.default_sequence.is_empty());
        assert!(e.auto_type.associations.is_empty());
    }

    #[test]
    fn empty_auto_type_block_keeps_defaults() {
        let xml = br"<KeePassFile>
  <Meta><Generator>G</Generator></Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>R</Name>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>T</Value></String>
        <AutoType/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>";
        let vault = decode_vault(xml).unwrap();
        let e = vault.iter_entries().next().unwrap();
        assert_eq!(e.auto_type, crate::model::AutoType::default());
    }

    /// A self-closing `<Foo/>` unknown child must be captured in the
    /// parent's `unknown_xml` at each of the three supported container
    /// levels. The outer loop used to drop Empty events into the
    /// `_ => {}` catch-all, silently losing such elements on round-trip.
    #[test]
    fn self_closing_unknowns_are_captured_at_entry_group_and_meta() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<KeePassFile>
  <Meta>
    <Generator>KeePassXC</Generator>
    <MetaFlag/>
  </Meta>
  <Root>
    <Group>
      <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
      <Name>Passwords</Name>
      <GroupFlag/>
      <Entry>
        <UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID>
        <String><Key>Title</Key><Value>Gmail</Value></String>
        <EntryFlag/>
      </Entry>
    </Group>
  </Root>
</KeePassFile>"#;
        let vault = decode_vault(xml).unwrap();

        // Meta captured a self-closing unknown.
        let meta_tags: Vec<_> = vault.meta.unknown_xml.iter().map(|u| &u.tag).collect();
        assert_eq!(meta_tags, vec!["MetaFlag"]);
        let meta_raw = std::str::from_utf8(&vault.meta.unknown_xml[0].raw_xml).unwrap();
        assert!(
            meta_raw.contains("MetaFlag"),
            "meta fragment lost its tag: {meta_raw:?}"
        );

        // Root group captured a self-closing unknown.
        let group_tags: Vec<_> = vault.root.unknown_xml.iter().map(|u| &u.tag).collect();
        assert_eq!(group_tags, vec!["GroupFlag"]);

        // Entry captured a self-closing unknown.
        let entry = vault.iter_entries().next().unwrap();
        let entry_tags: Vec<_> = entry.unknown_xml.iter().map(|u| &u.tag).collect();
        assert_eq!(entry_tags, vec!["EntryFlag"]);
    }
}
