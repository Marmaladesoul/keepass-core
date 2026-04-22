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
use uuid::Uuid;

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
    /// `<Times>` block — creation, modification, expiry, etc. Absent
    /// blocks deserialise to [`Timestamps::default`].
    pub times: Timestamps,
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
    /// `<Times>` block for the group itself.
    pub times: Timestamps,
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
}

/// Contents of the KeePass `<Meta>` element.
///
/// Only fields present in the on-disk XML populate here; every field
/// is either a string (possibly empty) or an `Option`, so a minimal
/// document with just `<Generator>` round-trips cleanly.
///
/// Fields beyond this set — memory-protection flags, custom icons,
/// custom data, header hash, history settings — land in follow-up
/// PRs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
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
            times: Timestamps::default(),
        }
    }

    fn group_with_name(name: &str) -> Group {
        Group {
            id: GroupId(Uuid::nil()),
            name: name.to_owned(),
            notes: String::new(),
            groups: Vec::new(),
            entries: Vec::new(),
            times: Timestamps::default(),
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
}
