//! `Group` — a folder in the vault hierarchy, with the recursive
//! walk helpers (`total_entries`, `total_subgroups`, `iter_entries`,
//! `all_subgroups`).

use uuid::Uuid;

use super::{CustomDataItem, Entry, EntryId, GroupId, Timestamps, UnknownElement};

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
    /// [`super::Meta::custom_data`], just scoped to the group.
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
    /// [`super::Meta::custom_icons`] pool. Same semantics as
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
