//! `Entry` and the value types referenced from inside it: `AutoType` +
//! `AutoTypeAssociation`, `Attachment`, `CustomField`.
//!
//! `Entry` and `CustomField` both have hand-rolled `Debug` impls that
//! redact credential material — see the impls below for the
//! rationale.

use uuid::Uuid;

use super::{CustomDataItem, EntryId, GroupId, Timestamps, UnknownElement};

/// A single credential record.
///
/// Fields beyond the "string-key/string-value" pairs that appear in every
/// KeePass entry (Title, UserName, Password, URL, Notes) are carried in
/// [`Self::custom_fields`] keyed by their `<Key>` name.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// Unique identifier.
    pub id: EntryId,
    /// Entry title (`<String><Key>Title</Key>...</String>`).
    pub title: String,
    /// Username (`<String><Key>UserName</Key>...</String>`).
    pub username: String,
    /// Password, **as stored in the XML** — may still be base64-encoded
    /// ciphertext if the corresponding `<Value>` element carried
    /// `Protected="True"`. Decrypting protected values is the job of a
    /// higher layer that knows the inner-stream cipher state.
    pub password: String,
    /// URL (`<String><Key>URL</Key>...</String>`).
    pub url: String,
    /// Notes (`<String><Key>Notes</Key>...</String>`).
    pub notes: String,
    /// All other `<String>` fields on the entry, keyed by their `<Key>`.
    ///
    /// The values here follow the same "may be base64 ciphertext"
    /// caveat as [`Self::password`].
    pub custom_fields: Vec<CustomField>,
    /// `<Tags>` — free-form labels. KeePass stores these as a single
    /// delimited string; the decoder splits on `;` and `,` so that
    /// writers from either convention are handled. Empty segments
    /// are dropped.
    pub tags: Vec<String>,
    /// `<History>` — older snapshots of this entry, in the order
    /// KeePass wrote them (typically oldest → newest). Each snapshot
    /// is itself a full [`Entry`]; its own `history` field is always
    /// empty (KeePass does not nest history).
    pub history: Vec<Entry>,
    /// Binary attachments referenced from this entry. Each attachment
    /// carries a user-visible filename and an index into
    /// [`super::Vault::binaries`] where the bytes live. Resolving the
    /// reference is a vault-level lookup — entries don't own their
    /// payload bytes, because KeePass deduplicates identical payloads
    /// across entries.
    pub attachments: Vec<Attachment>,
    /// `<ForegroundColor>` — user-chosen text colour for the entry,
    /// written as a hex `"#RRGGBB"` string. Empty when the entry uses
    /// the client's default colour.
    pub foreground_color: String,
    /// `<BackgroundColor>` — user-chosen row-background colour.
    /// Empty when the entry uses the client's default colour.
    pub background_color: String,
    /// `<OverrideURL>` — per-entry URL-scheme override. KeePass uses
    /// this for custom "open in browser X" or "launch via script"
    /// behaviour; empty means the URL field opens via the client's
    /// default handler.
    pub override_url: String,
    /// `<CustomIconUUID>` — reference to a custom icon in the
    /// [`super::Meta::custom_icons`] pool. `None` when the entry uses one of
    /// the built-in icons.
    pub custom_icon_uuid: Option<Uuid>,
    /// `<IconID>` — index into KeePass's built-in icon set (0–68 in
    /// KeePass 2.x, with `0` being the "Key" default). A separate
    /// [`Self::custom_icon_uuid`] overrides this when both are set;
    /// the field is still round-tripped so host clients that render
    /// by-id (rather than by-UUID) don't lose the user's choice.
    /// Missing `<IconID>` in the XML decodes to `0` (KeePass's own
    /// default for a fresh entry).
    pub icon_id: u32,
    /// `<CustomData>` — free-form plugin / client-specific key/value
    /// items attached to this entry. Same shape as
    /// [`super::Meta::custom_data`], just scoped to the entry.
    pub custom_data: Vec<CustomDataItem>,
    /// `<QualityCheck>` — whether this entry's password participates
    /// in the host client's password-quality audit (duplicate
    /// detection, strength meter, breach check). Defaults to `true`;
    /// users opt out per-entry for things like PINs and recovery
    /// codes where quality metrics don't apply.
    pub quality_check: bool,
    /// `<PreviousParentGroup>` — the group this entry was moved out
    /// of, used by KeePass to make "undo move" reversible across
    /// saves. `None` when the entry has never been moved (or the
    /// field wasn't written).
    pub previous_parent_group: Option<GroupId>,
    /// `<AutoType>` — auto-type configuration. Absent blocks
    /// deserialise to [`AutoType::default`] (enabled, no
    /// obfuscation, empty sequence, no per-window associations).
    pub auto_type: AutoType,
    /// `<Times>` block — creation, modification, expiry, etc. Absent
    /// blocks deserialise to [`Timestamps::default`].
    pub times: Timestamps,
    /// Unknown XML children captured verbatim so a foreign writer's
    /// additions (future KeePass fields, vendor extensions) survive a
    /// read → edit → save cycle. Each element is re-emitted at the end
    /// of `<Entry>`, after all canonical children; exact source
    /// position is not preserved. See [`UnknownElement`].
    pub unknown_xml: Vec<UnknownElement>,
}

impl Entry {
    /// Construct a minimal [`Entry`] with the given id and default
    /// everything else.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    ///
    /// `quality_check` defaults to `true`, matching KeePass's default
    /// for fresh entries.
    #[must_use]
    pub fn empty(id: EntryId) -> Self {
        Self {
            id,
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
            icon_id: 0,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: AutoType::default(),
            times: Timestamps::default(),
            unknown_xml: Vec::new(),
        }
    }
}

/// Manual `Debug` impl: redact the entry's `password` field unconditionally.
///
/// A derived `Debug` would dump plaintext passwords into any panic message
/// or log line that touches an `Entry`. The `password` field is *named for*
/// credential material — there is no per-entry "this isn't really a password"
/// signal at this layer, so the safest discipline is to redact every time.
/// `custom_fields` recurses through [`CustomField`]'s own redacting impl;
/// `history` recurses through this impl (history snapshots never nest, so
/// recursion terminates after one level).
impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("id", &self.id)
            .field("title", &self.title)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("url", &self.url)
            .field("notes", &self.notes)
            .field("custom_fields", &self.custom_fields)
            .field("tags", &self.tags)
            .field("history", &self.history)
            .field("attachments", &self.attachments)
            .field("foreground_color", &self.foreground_color)
            .field("background_color", &self.background_color)
            .field("override_url", &self.override_url)
            .field("custom_icon_uuid", &self.custom_icon_uuid)
            .field("icon_id", &self.icon_id)
            .field("custom_data", &self.custom_data)
            .field("quality_check", &self.quality_check)
            .field("previous_parent_group", &self.previous_parent_group)
            .field("auto_type", &self.auto_type)
            .field("times", &self.times)
            .field("unknown_xml", &self.unknown_xml)
            .finish()
    }
}

/// Auto-type configuration on an [`Entry`] — the macro framework
/// KeePass uses to type credentials into a target window.
///
/// The top-level `enabled` flag gates all auto-type for this entry.
/// `default_sequence` is the fallback macro used when no
/// [`AutoTypeAssociation`] matches the current foreground window;
/// associations override it per-window.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AutoType {
    /// `<Enabled>` — defaults to `true` when the block is absent or
    /// empty, matching KeePass's permissive convention.
    pub enabled: bool,
    /// `<DataTransferObfuscation>` — delivery method. `0` is
    /// "straight keystroke stream"; non-zero values are KeePass-
    /// specific obfuscation strategies (clipboard hops, randomised
    /// timing, etc.).
    pub data_transfer_obfuscation: u32,
    /// `<DefaultSequence>` — fallback macro when no association
    /// matches. Empty means "inherit from the group's
    /// [`super::Group::default_auto_type_sequence`]".
    pub default_sequence: String,
    /// `<Association>` — per-window override macros, in source order.
    pub associations: Vec<AutoTypeAssociation>,
}

impl Default for AutoType {
    fn default() -> Self {
        Self {
            enabled: true,
            data_transfer_obfuscation: 0,
            default_sequence: String::new(),
            associations: Vec::new(),
        }
    }
}

impl AutoType {
    /// Construct a fresh [`AutoType`] block — enabled, no obfuscation,
    /// no default sequence, no per-window associations.
    ///
    /// Provided as a constructor because [`AutoType`] is
    /// `#[non_exhaustive]`, so callers in downstream crates can't
    /// build one with a struct literal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// One `<Association>` inside an [`AutoType`] block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AutoTypeAssociation {
    /// `<Window>` — glob pattern matched against the foreground
    /// window's title (e.g. `"Firefox - *"`).
    pub window: String,
    /// `<KeystrokeSequence>` — macro to play for this window match.
    pub keystroke_sequence: String,
}

impl AutoTypeAssociation {
    /// Construct a per-window override.
    ///
    /// Provided as a constructor because [`AutoTypeAssociation`] is
    /// `#[non_exhaustive]`, so callers in downstream crates can't
    /// build one with a struct literal.
    #[must_use]
    pub fn new(window: impl Into<String>, keystroke_sequence: impl Into<String>) -> Self {
        Self {
            window: window.into(),
            keystroke_sequence: keystroke_sequence.into(),
        }
    }
}

/// Reference from an [`Entry`] to a binary in [`super::Vault::binaries`].
///
/// On disk, KeePass writes this as
/// `<Binary><Key>filename</Key><Value Ref="N"/></Binary>` inside the
/// entry's `<String>` children list. The decoder splits it out into
/// its own dedicated collection so that a caller can iterate an
/// entry's attachments without walking its custom fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Attachment {
    /// User-visible filename, from the `<Key>`.
    pub name: String,
    /// Index into [`super::Vault::binaries`].
    pub ref_id: u32,
}

impl Attachment {
    /// Construct an [`Attachment`] from its two required components.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates) — the
    /// natural companion to the type's `#[non_exhaustive]` marker,
    /// matching the constructor pattern on [`CustomField`] etc.
    #[must_use]
    pub fn new(name: impl Into<String>, ref_id: u32) -> Self {
        Self {
            name: name.into(),
            ref_id,
        }
    }
}

/// One custom string field on an [`Entry`].
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CustomField {
    /// The `<Key>` name.
    pub key: String,
    /// The `<Value>` content, as stored in the XML.
    pub value: String,
    /// `true` if the `<Value>` carried `Protected="True"` — the content
    /// is then a base64-encoded ciphertext under the inner-stream cipher.
    pub protected: bool,
}

impl CustomField {
    /// Construct a [`CustomField`] from its three required components.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn new(key: impl Into<String>, value: impl Into<String>, protected: bool) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            protected,
        }
    }
}

/// Manual `Debug` impl: redact `value` whenever `protected` is set.
///
/// The `protected` flag is the entry's own declaration that the field
/// carries credential material; a derived `Debug` would surface that
/// material into logs and panic messages. Non-protected values are shown
/// as-is — KeePass's own UI surfaces them in cleartext, so they're treated
/// as user-visible metadata at this layer.
impl std::fmt::Debug for CustomField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value: &dyn std::fmt::Debug = if self.protected {
            &"[REDACTED]"
        } else {
            &self.value
        };
        f.debug_struct("CustomField")
            .field("key", &self.key)
            .field("value", value)
            .field("protected", &self.protected)
            .finish()
    }
}
