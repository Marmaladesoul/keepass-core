//! Format-agnostic vault model.
//!
//! The types here describe a KeePass vault in memory without committing to
//! a particular on-disk version. The XML decoder in
//! [`crate::xml`] translates between these types and the KeePass inner
//! XML document; the writer (later) translates the other way.
//!
//! Every identifier type is a newtype — no naked `Uuid`s cross the API
//! boundary. This makes key-confusion bugs (e.g. passing an [`EntryId`]
//! where a [`GroupId`] is expected) into compile errors, not runtime
//! ones.
//!
//! The model is intentionally a **minimum viable slice** for now: core
//! fields, timestamps, and the group/entry hierarchy. History, custom
//! icons, binaries, deleted objects, and auto-type settings will land
//! in follow-up PRs.

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

pub mod clock;
pub mod entry_editor;
pub mod group_editor;
pub mod new_entry;
pub mod new_group;
pub mod portable;
pub use clock::{Clock, FixedClock, SystemClock};
pub use entry_editor::{CustomFieldValue, EntryEditor};
pub use group_editor::GroupEditor;
pub use new_entry::NewEntry;
pub use new_group::NewGroup;
pub use portable::PortableEntry;

// ---------------------------------------------------------------------------
// HistoryPolicy
// ---------------------------------------------------------------------------

/// Caller-supplied policy for whether (and when) an
/// `edit_entry` call snapshots the pre-edit [`Entry`] into its own
/// history.
///
/// The library does not impose a global default — different hosts
/// want different behaviour, and coalescing rapid saves is a
/// legitimate policy, so [`HistoryPolicy`] is a parameter on every
/// `edit_entry` call, not state on the `Kdbx`.
///
/// After a snapshot is taken the history list is truncated to
/// [`Meta::history_max_items`] entries (value < 0 means unlimited);
/// [`Meta::history_max_size`] is treated as an approximate soft
/// byte budget based on the serialised canonical-field lengths.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum HistoryPolicy {
    /// Always snapshot before the edit runs. The canonical KeePass
    /// behaviour.
    Snapshot,

    /// Never snapshot. Use for cosmetic fixups the caller doesn't
    /// want to appear in the entry's history — e.g. correcting a
    /// typo immediately after the original save, or a bulk re-
    /// encode after a model migration.
    NoSnapshot,

    /// Snapshot only if the most recent history entry is older than
    /// `since`. Implements "coalesce edits within a window" — e.g.
    /// `chrono::Duration::hours(24)` means at most one snapshot per
    /// day. If there is no prior history, always snapshots.
    ///
    /// **Window anchor.** The window is measured against the most
    /// recent history snapshot's *own* `times.last_modification_time`
    /// — i.e. *when the state inside that snapshot was last
    /// modified*, which in canonical KeePass usage is "when that
    /// snapshot was created" (the snapshot is a copy of the live
    /// entry's pre-edit state, including its timestamp).
    ///
    /// In linear-edit cases this is the same as "when the previous
    /// snapshot happened", but the two diverge for editing patterns
    /// like *burst → silence → burst*. Worked example with a 24h
    /// window:
    ///
    /// ```text
    /// t=00:00  edit + Snapshot      → history: [snap@00:00]
    /// t=00:05  edit + IfOlderThan   → last snapshot last-modified
    ///                                  was at 00:00; 5 min < 24h,
    ///                                  so SKIP. history unchanged.
    /// t=01:00  edit + IfOlderThan   → last snapshot still 00:00;
    ///                                  60 min < 24h, so SKIP.
    /// t=25:00  edit + IfOlderThan   → 25h ≥ 24h, SNAPSHOT.
    ///                                  history: [snap@00:00, snap@25:00]
    /// ```
    ///
    /// If the most recent history entry is missing
    /// `last_modification_time` it's treated as ancient — snapshot.
    SnapshotIfOlderThan(chrono::Duration),
}

// ---------------------------------------------------------------------------
// Mutation-API errors
// ---------------------------------------------------------------------------

/// Errors returned by the [`crate::kdbx::Kdbx`] mutation API.
///
/// Tree-level operations (add / delete / move) can fail for
/// well-defined, caller-visible reasons: a UUID isn't in the vault,
/// a move would create a cycle, the root group can't be deleted, etc.
/// These each get their own variant so callers can pattern-match
/// rather than string-match. Wrapped at the top level via
/// [`crate::error::Error::Model`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ModelError {
    /// The requested [`EntryId`] is not present anywhere in the vault.
    #[error("entry {0:?} not found")]
    EntryNotFound(EntryId),

    /// The requested [`GroupId`] is not present anywhere in the vault.
    #[error("group {0:?} not found")]
    GroupNotFound(GroupId),

    /// A `Kdbx::move_group` call would make `moving` a descendant
    /// of itself through `new_parent`.
    #[error(
        "move would create a cycle: group {moving:?} cannot become a descendant of itself via {new_parent:?}"
    )]
    CircularMove {
        /// The group being moved.
        moving: GroupId,
        /// The proposed new parent, which is itself in `moving`'s subtree.
        new_parent: GroupId,
    },

    /// A caller-supplied UUID collides with one already in the vault.
    ///
    /// Hit during `Kdbx::add_entry` / `Kdbx::add_group` when the
    /// builder's `with_uuid` is used and the chosen UUID is already
    /// taken.
    #[error("UUID {0} already in use in this vault")]
    DuplicateUuid(Uuid),

    /// The root group cannot be deleted — every vault has exactly one.
    #[error("cannot delete the root group")]
    CannotDeleteRoot,

    /// A [`crate::kdbx::Kdbx::restore_entry_from_history`] (or any
    /// future caller that indexes into [`Entry::history`]) was given
    /// an `index` outside the valid range `0..len`. `len` is the
    /// entry's history length at the time of the call; captured so
    /// the error message is self-diagnosing without re-inspecting
    /// vault state.
    #[error("entry {id:?} history index {index} out of range (len = {len})")]
    HistoryIndexOutOfRange {
        /// The entry whose history was indexed.
        id: EntryId,
        /// The index the caller supplied.
        index: usize,
        /// The entry's history length at the time the call was rejected.
        len: usize,
    },

    /// The configured [`crate::protector::FieldProtector`] failed during
    /// a mutation that re-wraps a protected field — currently only
    /// [`crate::kdbx::Kdbx::edit_entry`], which re-wraps any plaintext
    /// the editor wrote into protected slots so the wrapped side-table
    /// stays the source of truth.
    ///
    /// In practice production protectors don't fail on wrap; the
    /// variant exists so a contractually-fallible `wrap` call doesn't
    /// silently leave plaintext on the model.
    #[error("field protector failure during mutation: {0}")]
    Protector(#[from] crate::protector::ProtectorError),
}

// ---------------------------------------------------------------------------
// Newtype identifiers
// ---------------------------------------------------------------------------

/// Identifier of an [`Entry`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId(pub Uuid);

/// Identifier of a [`Group`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Timestamps attached to an [`Entry`] or [`Group`].
///
/// Fields mirror the KeePass `<Times>` block. All times are UTC; the
/// on-disk representation is either ISO-8601 (KDBX3) or base64 of a
/// little-endian `i64` tick count since `0001-01-01T00:00:00Z` with
/// 100-nanosecond resolution (KDBX4).
///
/// Every field is `Option` because KeePass writers are permissive:
/// old files, hand-crafted XML, and partial migrations may omit any
/// subset. A missing `<Times>` block produces [`Self::default`] (all
/// `None`, `expires == false`, `usage_count == 0`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Timestamps {
    /// `<CreationTime>` — when the record was first created.
    pub creation_time: Option<DateTime<Utc>>,
    /// `<LastModificationTime>` — last field edit.
    pub last_modification_time: Option<DateTime<Utc>>,
    /// `<LastAccessTime>` — last time the record was read (KeePass
    /// clients update this opportunistically; its value is of limited
    /// forensic use).
    pub last_access_time: Option<DateTime<Utc>>,
    /// `<LocationChanged>` — last time the record was moved between
    /// groups.
    pub location_changed: Option<DateTime<Utc>>,
    /// `<ExpiryTime>` — expiration timestamp. Only meaningful when
    /// [`Self::expires`] is `true`.
    pub expiry_time: Option<DateTime<Utc>>,
    /// `<Expires>` — whether this record has an expiration at all.
    pub expires: bool,
    /// `<UsageCount>` — number of times a password field has been
    /// copied / displayed. Writers often leave this at 0.
    pub usage_count: u64,
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// A single credential record.
///
/// Fields beyond the "string-key/string-value" pairs that appear in every
/// KeePass entry (Title, UserName, Password, URL, Notes) are carried in
/// [`Self::custom_fields`] keyed by their `<Key>` name.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// [`Vault::binaries`] where the bytes live. Resolving the
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
    /// [`Meta::custom_icons`] pool. `None` when the entry uses one of
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
    /// [`Meta::custom_data`], just scoped to the entry.
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
    /// [`Group::default_auto_type_sequence`]".
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

/// Reference from an [`Entry`] to a binary in [`Vault::binaries`].
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
    /// Index into [`Vault::binaries`].
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

// ---------------------------------------------------------------------------
// Group
// ---------------------------------------------------------------------------

/// A folder / group in the vault hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Group {
    /// Unique identifier.
    pub id: GroupId,
    /// Display name.
    pub name: String,
    /// Optional free-text notes.
    pub notes: String,
    /// Child groups, in the order they appeared in the XML.
    pub groups: Vec<Group>,
    /// Entries directly inside this group, in the order they appeared in
    /// the XML.
    pub entries: Vec<Entry>,
    /// `<IsExpanded>` — whether the group is shown expanded in the
    /// host client's tree view. UI state, preserved for round-trip.
    /// Missing elements default to `true` (KeePass 2.x convention).
    pub is_expanded: bool,
    /// `<DefaultAutoTypeSequence>` — client-specific auto-type macro
    /// inherited by entries in this group. Empty when the group uses
    /// the vault-wide default.
    pub default_auto_type_sequence: String,
    /// `<EnableAutoType>` — tri-state flag: `Some(true)` / `Some(false)`
    /// explicitly enables or disables auto-type for this group, `None`
    /// inherits from the parent.
    pub enable_auto_type: Option<bool>,
    /// `<EnableSearching>` — tri-state flag: `Some(true)` / `Some(false)`
    /// explicitly includes or excludes this group from searches, `None`
    /// inherits from the parent.
    pub enable_searching: Option<bool>,
    /// `<CustomData>` — free-form plugin / client-specific key/value
    /// items attached to this group. Same shape as
    /// [`Meta::custom_data`], just scoped to the group.
    pub custom_data: Vec<CustomDataItem>,
    /// `<PreviousParentGroup>` — the group this group was moved out
    /// of, for "undo move" symmetry with [`Entry::previous_parent_group`].
    /// `None` when the group has never been moved.
    pub previous_parent_group: Option<GroupId>,
    /// `<LastTopVisibleEntry>` — UI hint: the [`EntryId`] that was
    /// scrolled to the top of the entry list last time this group
    /// was viewed. `None` when no entry has been marked, or when
    /// the field was absent from the XML.
    pub last_top_visible_entry: Option<EntryId>,
    /// `<CustomIconUUID>` — reference to a custom icon in the
    /// [`Meta::custom_icons`] pool. Same semantics as
    /// [`Entry::custom_icon_uuid`], scoped to the group.
    pub custom_icon_uuid: Option<Uuid>,
    /// `<IconID>` — built-in icon index. Same semantics as
    /// [`Entry::icon_id`], scoped to the group. Missing element
    /// decodes to `0` (KeePass's "Folder" default for groups).
    pub icon_id: u32,
    /// `<Times>` block for the group itself.
    pub times: Timestamps,
    /// Unknown XML children on `<Group>` preserved verbatim for
    /// round-trip — see [`Entry::unknown_xml`] for the full semantics.
    /// Child `<Entry>` / `<Group>` elements are never captured here;
    /// the decoder always descends into them.
    pub unknown_xml: Vec<UnknownElement>,
}

impl Group {
    /// Total entry count under this group (recursive).
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.entries.len() + self.groups.iter().map(Group::total_entries).sum::<usize>()
    }

    /// Total group count under this group (recursive, not counting `self`).
    #[must_use]
    pub fn total_subgroups(&self) -> usize {
        self.groups.len()
            + self
                .groups
                .iter()
                .map(Group::total_subgroups)
                .sum::<usize>()
    }

    /// Iterate all entries anywhere under this group, depth-first.
    ///
    /// Returns an owned iterator yielding references — useful for
    /// searches, stats, and interop tests.
    pub fn iter_entries(&self) -> Box<dyn Iterator<Item = &Entry> + '_> {
        Box::new(
            self.entries
                .iter()
                .chain(self.groups.iter().flat_map(Group::iter_entries)),
        )
    }

    /// Collect every group reachable from this one's subtree (recursive
    /// descendants only — `self` is **not** included), depth-first.
    ///
    /// Useful for callers that need to validate a candidate move (the
    /// destination must not be a descendant of the moved group) or
    /// enumerate icon / entry refs across a whole subtree without
    /// touching `self`.
    #[must_use]
    pub fn all_subgroups(&self) -> Vec<&Group> {
        let mut out = Vec::with_capacity(self.total_subgroups());
        for child in &self.groups {
            out.push(child);
            out.extend(child.all_subgroups());
        }
        out
    }

    /// Construct a minimal [`Group`] with the given id and default
    /// everything else.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    ///
    /// `is_expanded` defaults to `true`, matching the KeePass 2.x
    /// convention for groups missing the `<IsExpanded>` element.
    #[must_use]
    pub fn empty(id: GroupId) -> Self {
        Self {
            id,
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
            icon_id: 0,
            times: Timestamps::default(),
            unknown_xml: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Vault
// ---------------------------------------------------------------------------

/// The root vault type (format-agnostic).
///
/// A vault has a single root [`Group`] containing everything and a
/// [`Meta`] block with database-level metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Vault {
    /// The root group of the vault tree. Contains all groups and entries.
    pub root: Group,
    /// `<Meta>` block — database-level metadata.
    pub meta: Meta,
    /// Binary payloads, indexed by the `Ref` attribute on
    /// `<Binary Ref="…"/>` references inside entries. KeePass
    /// deduplicates identical payloads across entries, so the same
    /// entry in [`Vault::binaries`] may be referenced by multiple
    /// attachments.
    pub binaries: Vec<Binary>,
    /// `<DeletedObjects>` — tombstones for deleted entries or groups,
    /// recorded so that merging against a peer replica can tell a
    /// never-seen record apart from one the local side has deleted.
    /// Preserved verbatim for lossless round-trip.
    pub deleted_objects: Vec<DeletedObject>,
}

/// A tombstone for a deleted entry or group, recorded under
/// `<Root><DeletedObjects>`.
///
/// The UUID is deliberately a raw [`Uuid`] rather than an [`EntryId`]
/// or [`GroupId`] — at the format layer we can't tell which kind of
/// object the tombstone refers to without cross-referencing another
/// replica. Downstream merge code is free to classify it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DeletedObject {
    /// The 16-byte UUID of the deleted entry or group.
    pub uuid: Uuid,
    /// `<DeletionTime>` — when the deletion was recorded.
    pub deleted_at: Option<DateTime<Utc>>,
}

impl DeletedObject {
    /// Construct a [`DeletedObject`] tombstone for the given uuid and
    /// optional deletion timestamp.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn new(uuid: Uuid, deleted_at: Option<DateTime<Utc>>) -> Self {
        Self { uuid, deleted_at }
    }
}

/// One binary payload — either an attachment or an embedded image.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Binary {
    /// The raw, fully-decoded payload bytes (decompressed on KDBX3 if
    /// the `Compressed="True"` attribute was set, decrypted on KDBX4
    /// if the inner-header flags byte had bit 0 set).
    pub data: Vec<u8>,
    /// `true` if this payload was stored encrypted under the
    /// inner-stream cipher on disk — i.e. the `flags & 0x01` bit on
    /// the KDBX4 inner-header binary record. Preserved for
    /// round-trip write-back.
    pub protected: bool,
}

impl Binary {
    /// Construct a [`Binary`] from its two required components.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates) — the
    /// natural companion to the type's `#[non_exhaustive]` marker,
    /// matching the constructor pattern on [`CustomField`] etc.
    #[must_use]
    pub fn new(data: Vec<u8>, protected: bool) -> Self {
        Self { data, protected }
    }
}

/// Contents of the KeePass `<Meta>` element.
///
/// Only fields present in the on-disk XML populate here; every field
/// is either a string (possibly empty) or an `Option`, so a minimal
/// document with just `<Generator>` round-trips cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Meta {
    /// `<Generator>` — identifies the writer (e.g. `"KeePassXC"`,
    /// `"KdbxWeb"`). Diagnostic only.
    pub generator: String,
    /// `<DatabaseName>` — user-visible vault name.
    pub database_name: String,
    /// `<DatabaseDescription>` — user-visible free-text description.
    pub database_description: String,
    /// `<DatabaseNameChanged>` — last time the name was edited.
    pub database_name_changed: Option<chrono::DateTime<Utc>>,
    /// `<DatabaseDescriptionChanged>` — last time the description was
    /// edited.
    pub database_description_changed: Option<chrono::DateTime<Utc>>,
    /// `<DefaultUserName>` — default username for new entries.
    pub default_username: String,
    /// `<DefaultUserNameChanged>` — last time the default username
    /// was edited.
    pub default_username_changed: Option<chrono::DateTime<Utc>>,
    /// `<RecycleBinEnabled>` — whether soft-delete is wired up. When
    /// true and [`Self::recycle_bin_uuid`] points to an existing
    /// group, KeePass writers move deleted entries into that group
    /// instead of removing them. Absent elements are treated as
    /// `false`.
    pub recycle_bin_enabled: bool,
    /// `<RecycleBinUUID>` — the [`GroupId`] of the recycle-bin
    /// group, or `None` if the document lists no recycle bin.
    /// Writers sometimes emit an all-zero UUID to mean "no recycle
    /// bin", which we surface as `None` for symmetry with the
    /// explicitly-absent case.
    pub recycle_bin_uuid: Option<GroupId>,
    /// `<RecycleBinChanged>` — last time the recycle-bin
    /// configuration was edited.
    pub recycle_bin_changed: Option<chrono::DateTime<Utc>>,
    /// `<MemoryProtection>` — which canonical entry fields the writer
    /// marks as in-memory-protected in the host KeePass client.
    /// Semantic hint only; entry-level `Protected` XML attributes are
    /// what actually matter on disk.
    pub memory_protection: MemoryProtection,
    /// `<CustomData>` — free-form key/value entries used by plugins
    /// and client-specific settings. Preserved verbatim for round-trip
    /// so writers that don't know a particular key don't drop it.
    pub custom_data: Vec<CustomDataItem>,
    /// `<SettingsChanged>` — last time any `<Meta>` setting was edited.
    /// Distinct from the per-field `*Changed` timestamps.
    pub settings_changed: Option<DateTime<Utc>>,
    /// `<MasterKeyChanged>` — last time the master key was replaced.
    /// Used by the recommendation / force policies below.
    pub master_key_changed: Option<DateTime<Utc>>,
    /// `<MasterKeyChangeRec>` — number of days between recommended
    /// master-key changes. `-1` disables the recommendation.
    pub master_key_change_rec: i64,
    /// `<MasterKeyChangeForce>` — number of days after which the
    /// client forces a master-key change. `-1` disables.
    pub master_key_change_force: i64,
    /// `<HistoryMaxItems>` — cap on entry-history length.
    /// `-1` means unlimited.
    pub history_max_items: i32,
    /// `<HistoryMaxSize>` — cap on entry-history byte size.
    /// `-1` means unlimited.
    pub history_max_size: i64,
    /// `<MaintenanceHistoryDays>` — how long to keep entry snapshots
    /// before the client prunes them.
    pub maintenance_history_days: u32,
    /// `<CustomIcons>` — pool of custom entry / group icons,
    /// referenced by [`Entry::custom_icon_uuid`] and
    /// [`Group::custom_icon_uuid`]. Each icon carries its own UUID
    /// plus the decoded image bytes.
    pub custom_icons: Vec<CustomIcon>,
    /// `<Color>` — hex colour (e.g. `"#FF0000"`) used by KeePass 2.x
    /// clients as the vault-level colour swatch. Empty when the
    /// vault uses the client's default colour.
    pub color: String,
    /// `<HeaderHash>` — SHA-256 of the outer header, written into
    /// KDBX3 inner XML as a belt-and-braces integrity check. KDBX4
    /// moves this to the binary header (`verify_header_hash`) and
    /// doesn't emit the XML element. Preserved verbatim as the
    /// base64-encoded string for lossless round-trip — we don't
    /// re-verify it here.
    pub header_hash: String,
    /// Unknown XML children on `<Meta>` preserved verbatim for
    /// round-trip — see [`Entry::unknown_xml`] for the full semantics.
    pub unknown_xml: Vec<UnknownElement>,
}

/// One icon in the vault's [`Meta::custom_icons`] pool.
///
/// KeePass stores custom icons as a base64-encoded image payload
/// (typically PNG, but the format doesn't constrain — a consumer is
/// free to hand the bytes to an image decoder and see what happens).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CustomIcon {
    /// Identifier referenced by [`Entry::custom_icon_uuid`].
    pub uuid: Uuid,
    /// Decoded image bytes, typically PNG.
    pub data: Vec<u8>,
    /// `<Name>` — optional human-readable label. Empty for icons
    /// that carry no name.
    pub name: String,
    /// `<LastModificationTime>` — when the icon was last edited.
    /// Many KDBX3 writers omit this element.
    pub last_modified: Option<DateTime<Utc>>,
}

impl Default for Meta {
    fn default() -> Self {
        // Values mirror KeePass 2.x's stock defaults where relevant,
        // so a `Meta::default()` round-trips cleanly back through the
        // writer without spurious diff churn.
        Self {
            generator: String::new(),
            database_name: String::new(),
            database_description: String::new(),
            database_name_changed: None,
            database_description_changed: None,
            default_username: String::new(),
            default_username_changed: None,
            recycle_bin_enabled: false,
            recycle_bin_uuid: None,
            recycle_bin_changed: None,
            memory_protection: MemoryProtection::default(),
            custom_data: Vec::new(),
            settings_changed: None,
            master_key_changed: None,
            master_key_change_rec: -1,
            master_key_change_force: -1,
            history_max_items: 10,
            history_max_size: 6 * 1024 * 1024,
            maintenance_history_days: 365,
            custom_icons: Vec::new(),
            color: String::new(),
            header_hash: String::new(),
            unknown_xml: Vec::new(),
        }
    }
}

/// An XML subtree the decoder didn't recognise, preserved verbatim so
/// writers from the future (new KeePass fields, vendor extensions)
/// don't have their additions silently stripped on read → save.
///
/// The payload is a pre-serialised XML fragment starting with the
/// element's opening tag and ending with its matching close — ready to
/// splice into the output stream. Byte-exact preservation is **not**
/// promised: the fragment was re-emitted by `quick-xml` on parse, so
/// attribute ordering, insignificant whitespace, and empty-element
/// shorthand (`<Foo/>` vs `<Foo></Foo>`) may differ from the source.
/// Structural (parse-back) equality is what round-trips.
///
/// The encoder emits captured elements at the end of the parent
/// container's canonical children — in particular, for `<Group>` this
/// is *after* the container's child `<Entry>` and nested `<Group>`
/// siblings, not interleaved among them. Original source position
/// relative to both canonical fields and structural children is not
/// preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UnknownElement {
    /// The element's local name, extracted from the captured opening
    /// tag. Diagnostic only — the encoder does not re-derive the tag
    /// from this, it re-emits [`Self::raw_xml`] verbatim.
    pub tag: String,
    /// The element and all of its descendants, serialised as XML bytes.
    /// Self-contained: a fragment can be written to any XML sink that
    /// accepts raw bytes.
    pub raw_xml: Vec<u8>,
}

/// One item in a `<CustomData>` collection.
///
/// KeePass stores plugin-specific and client-specific settings as
/// arbitrary string key/value pairs here. The decoder preserves them
/// verbatim for round-trip — we don't know what downstream plugins
/// care about, so we don't filter.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CustomDataItem {
    /// Opaque identifier — usually a reverse-DNS-ish plugin namespace
    /// (e.g. `KPXC_DECRYPTION_TIME_PREFERENCE`).
    pub key: String,
    /// Opaque string value.
    pub value: String,
    /// `<LastModificationTime>` — when the item was last edited.
    /// KDBX4 writers set this; KDBX3 writers typically don't.
    pub last_modified: Option<DateTime<Utc>>,
}

/// `<MemoryProtection>` flags — whether a given canonical entry
/// field should be kept in protected memory by the host KeePass
/// client (masked on screen, stored in a SecureString, etc.).
///
/// These are UI/memory-hygiene hints, **not** an on-disk encryption
/// signal. The actual "protect this value's bytes with the
/// inner-stream cipher" signal is the per-value `Protected="True"`
/// XML attribute on individual `<Value>` elements.
///
/// Defaults reflect the KeePass 2.x convention: only the Password
/// field is protected by default. Missing `<MemoryProtection>`
/// blocks in the XML round-trip to this default.
// The five booleans are dictated by the KeePass spec (one per canonical
// entry field), so collapsing into a bitflags or enum-set would just add
// indirection without meaningful benefit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryProtection {
    /// `<ProtectTitle>` — default `false`.
    pub protect_title: bool,
    /// `<ProtectUserName>` — default `false`.
    pub protect_username: bool,
    /// `<ProtectPassword>` — default `true`.
    pub protect_password: bool,
    /// `<ProtectURL>` — default `false`.
    pub protect_url: bool,
    /// `<ProtectNotes>` — default `false`.
    pub protect_notes: bool,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        }
    }
}

impl Vault {
    /// Total entry count across the whole vault.
    #[must_use]
    pub fn total_entries(&self) -> usize {
        self.root.total_entries()
    }

    /// Iterate every entry in the vault, depth-first through the group
    /// tree.
    pub fn iter_entries(&self) -> Box<dyn Iterator<Item = &Entry> + '_> {
        self.root.iter_entries()
    }

    /// Collect every entry in the vault, depth-first through the group
    /// tree.
    ///
    /// Convenience eager-collected mirror of [`Self::iter_entries`] for
    /// FFI surfaces that prefer a concrete `Vec` over a borrowed
    /// iterator. Includes entries in the recycle-bin group (if any) —
    /// callers that want to exclude them can filter using
    /// [`Self::recycle_bin_enabled`] and [`Meta::recycle_bin_uuid`].
    #[must_use]
    pub fn all_entries(&self) -> Vec<&Entry> {
        let mut out = Vec::with_capacity(self.root.total_entries());
        out.extend(self.root.iter_entries());
        out
    }

    /// Whether the recycle-bin feature is enabled on this vault's meta
    /// block.
    ///
    /// This is the raw flag — it does **not** check that
    /// [`Meta::recycle_bin_uuid`] actually points at an existing group.
    /// Both bits of state are written by the encoder verbatim, and
    /// downstream callers (e.g. an FFI consumer rendering a "Move to
    /// Recycle Bin" affordance) typically want both: enable-flag for
    /// the UI toggle, uuid for the destination.
    #[must_use]
    pub fn recycle_bin_enabled(&self) -> bool {
        self.meta.recycle_bin_enabled
    }

    /// Return the [`GroupId`] of the group that directly contains
    /// `child`. Returns `None` when `child` is the root group itself,
    /// or when no group with that id exists in the vault.
    ///
    /// Walks the tree from the root; cost is O(N) in the total group
    /// count. The model does not store parent links — parenthood is
    /// purely positional in the group tree — so this is a search rather
    /// than a field read.
    #[must_use]
    pub fn group_parent(&self, child: GroupId) -> Option<GroupId> {
        find_parent_group(&self.root, child)
    }

    /// Borrow the raw bytes for the custom icon identified by `id`.
    /// Returns `None` if no such icon is registered.
    ///
    /// Mirror of [`crate::kdbx::Kdbx::custom_icon`] for callers that
    /// hold a [`Vault`] directly (read-only walks, downstream FFI
    /// surfaces that expose the vault model without the mutating
    /// `Kdbx` wrapper). Bytes are opaque to the library — typically
    /// PNG, but whatever the writing client emitted.
    #[must_use]
    pub fn custom_icon(&self, id: Uuid) -> Option<&[u8]> {
        self.meta
            .custom_icons
            .iter()
            .find(|c| c.uuid == id)
            .map(|c| c.data.as_slice())
    }

    /// Construct a minimal [`Vault`] with the given root-group id, an
    /// empty root group, default [`Meta`], and no binaries or
    /// tombstones.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn empty(root_id: GroupId) -> Self {
        Self {
            root: Group::empty(root_id),
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        }
    }
}

/// Walk `root`'s subtree looking for the group with id `child`,
/// returning the id of its immediate parent group. Returns `None` if
/// `child == root.id` (the root has no parent) or if `child` is not
/// present in the tree at all.
fn find_parent_group(root: &Group, child: GroupId) -> Option<GroupId> {
    for g in &root.groups {
        if g.id == child {
            return Some(root.id);
        }
        if let Some(p) = find_parent_group(g, child) {
            return Some(p);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn entry_with(title: &str) -> Entry {
        Entry {
            id: EntryId(Uuid::nil()),
            title: title.to_owned(),
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
            icon_id: 0,
            unknown_xml: Vec::new(),
        }
    }

    fn group_with_name(name: &str) -> Group {
        Group {
            id: GroupId(Uuid::nil()),
            name: name.to_owned(),
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
            icon_id: 0,
            times: Timestamps::default(),
            unknown_xml: Vec::new(),
        }
    }

    #[test]
    fn total_entries_counts_nested() {
        let mut root = group_with_name("root");
        root.entries.push(entry_with("a"));
        let mut child = group_with_name("child");
        child.entries.push(entry_with("b"));
        child.entries.push(entry_with("c"));
        root.groups.push(child);
        assert_eq!(root.total_entries(), 3);
    }

    #[test]
    fn total_subgroups_is_recursive() {
        let mut root = group_with_name("root");
        let mut child = group_with_name("child");
        child.groups.push(group_with_name("grandchild"));
        root.groups.push(child);
        assert_eq!(root.total_subgroups(), 2);
    }

    #[test]
    fn iter_entries_visits_every_entry_once() {
        let mut root = group_with_name("root");
        root.entries.push(entry_with("a"));
        let mut child = group_with_name("child");
        child.entries.push(entry_with("b"));
        root.groups.push(child);
        let titles: Vec<_> = root.iter_entries().map(|e| e.title.clone()).collect();
        assert_eq!(titles, ["a", "b"]);
    }

    #[test]
    fn empty_group_has_zero_counts() {
        let g = group_with_name("empty");
        assert_eq!(g.total_entries(), 0);
        assert_eq!(g.total_subgroups(), 0);
        assert_eq!(g.iter_entries().count(), 0);
    }

    #[test]
    fn entry_empty_has_supplied_id_and_default_else() {
        let id = EntryId(Uuid::from_u128(0x42));
        let e = Entry::empty(id);
        assert_eq!(e.id, id);
        assert!(e.title.is_empty());
        assert!(e.username.is_empty());
        assert!(e.password.is_empty());
        assert!(e.url.is_empty());
        assert!(e.notes.is_empty());
        assert!(e.custom_fields.is_empty());
        assert!(e.tags.is_empty());
        assert!(e.history.is_empty());
        assert!(e.attachments.is_empty());
        assert!(e.custom_data.is_empty());
        assert!(e.unknown_xml.is_empty());
        assert!(e.custom_icon_uuid.is_none());
        assert!(e.previous_parent_group.is_none());
        assert_eq!(e.icon_id, 0);
        assert!(
            e.quality_check,
            "quality_check defaults to KeePass's default of true"
        );
        assert_eq!(e.times, Timestamps::default());
        assert_eq!(e.auto_type, AutoType::default());
    }

    #[test]
    fn group_empty_has_supplied_id_and_default_else() {
        let id = GroupId(Uuid::from_u128(0x99));
        let g = Group::empty(id);
        assert_eq!(g.id, id);
        assert!(g.name.is_empty());
        assert!(g.notes.is_empty());
        assert!(g.groups.is_empty());
        assert!(g.entries.is_empty());
        assert!(
            g.is_expanded,
            "is_expanded defaults to KeePass 2.x's default of true"
        );
        assert!(g.default_auto_type_sequence.is_empty());
        assert!(g.enable_auto_type.is_none());
        assert!(g.enable_searching.is_none());
        assert!(g.custom_data.is_empty());
        assert!(g.previous_parent_group.is_none());
        assert!(g.last_top_visible_entry.is_none());
        assert!(g.custom_icon_uuid.is_none());
        assert_eq!(g.icon_id, 0);
        assert_eq!(g.times, Timestamps::default());
        assert!(g.unknown_xml.is_empty());
    }

    #[test]
    fn vault_empty_has_supplied_root_id_and_defaults() {
        let root_id = GroupId(Uuid::from_u128(0xa));
        let v = Vault::empty(root_id);
        assert_eq!(v.root.id, root_id);
        assert_eq!(v.meta, Meta::default());
        assert!(v.binaries.is_empty());
        assert!(v.deleted_objects.is_empty());
        assert_eq!(v.total_entries(), 0);
    }

    #[test]
    fn custom_field_new_carries_all_three_components() {
        let f = CustomField::new("OTPSecret", "JBSWY3DPEHPK3PXP", true);
        assert_eq!(f.key, "OTPSecret");
        assert_eq!(f.value, "JBSWY3DPEHPK3PXP");
        assert!(f.protected);
    }

    #[test]
    fn deleted_object_new_carries_uuid_and_optional_time() {
        use chrono::TimeZone;
        let id = Uuid::from_u128(0xdead);
        let t = DeletedObject::new(id, None);
        assert_eq!(t.uuid, id);
        assert!(t.deleted_at.is_none());

        let when = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = DeletedObject::new(id, Some(when));
        assert_eq!(t2.deleted_at, Some(when));
    }
}
