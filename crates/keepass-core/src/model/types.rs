//! Cross-cutting model types: history policy, mutation-API errors,
//! newtype identifiers, timestamps, and the two "carried verbatim"
//! containers (`UnknownElement`, `CustomDataItem`) that appear on
//! `Entry`, `Group`, and `Meta` alike.
//!
//! Lives in its own file so the per-aggregate modules (`entry`,
//! `group`, `vault`, `meta`) can share these without one having to
//! depend on another for what is essentially scalar plumbing.

use chrono::{DateTime, Utc};
use thiserror::Error;
use uuid::Uuid;

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
///
/// [`Entry`]: super::Entry
/// [`Meta::history_max_items`]: super::Meta::history_max_items
/// [`Meta::history_max_size`]: super::Meta::history_max_size
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
    /// future caller that indexes into [`super::Entry::history`]) was given
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

/// Identifier of an [`super::Entry`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId(pub Uuid);

/// Identifier of a [`super::Group`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(pub Uuid);

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------

/// Timestamps attached to an [`super::Entry`] or [`super::Group`].
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
// UnknownElement
// ---------------------------------------------------------------------------

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

impl UnknownElement {
    /// Construct an [`UnknownElement`] from its tag name and raw XML
    /// fragment.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn new(tag: String, raw_xml: Vec<u8>) -> Self {
        Self { tag, raw_xml }
    }
}

// ---------------------------------------------------------------------------
// CustomDataItem
// ---------------------------------------------------------------------------

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

impl CustomDataItem {
    /// Construct a [`CustomDataItem`] from its required fields.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn new(key: String, value: String, last_modified: Option<DateTime<Utc>>) -> Self {
        Self {
            key,
            value,
            last_modified,
        }
    }
}
