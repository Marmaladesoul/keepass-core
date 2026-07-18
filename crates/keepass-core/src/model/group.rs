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
    /// touching `self`. The `self`-**inclusive** walk is
    /// [`Self::iter_groups`], of which this is the `skip(1)`-ed collect —
    /// they share the one depth-first pre-order walker so the two
    /// conventions can't drift.
    #[must_use]
    pub fn all_subgroups(&self) -> Vec<&Group> {
        self.iter_groups().skip(1).collect()
    }

    // ---- By-id lookup ------------------------------------------------------
    //
    // The model stores no parent links and hands out `pub groups` /
    // `pub entries`, so before these methods every consumer (kdbx.rs, the
    // merge crate, tests) re-implemented the same `groups`/`entries` DFS by
    // hand. These are the one tested home for it. Every lookup returns
    // `Option` — never an in-band sentinel; callers that need a hard error
    // (e.g. `Kdbx`'s mutators) translate `None` into their own error type at
    // their policy boundary.

    /// Find the entry with `id` anywhere in this group's subtree,
    /// depth-first pre-order. `None` when no entry carries that id.
    ///
    /// Entry ids are unique across a well-formed vault, so the first match
    /// is the only match.
    #[must_use]
    pub fn entry(&self, id: EntryId) -> Option<&Entry> {
        self.iter_entries().find(|e| e.id == id)
    }

    /// Mutable twin of [`Self::entry`].
    #[must_use]
    pub fn entry_mut(&mut self, id: EntryId) -> Option<&mut Entry> {
        self.iter_entries_mut().find(|e| e.id == id)
    }

    /// Find the group with `id` in this subtree, **including `self`** (a
    /// match on `self.id` returns `self`), depth-first pre-order. `None`
    /// when no group carries that id.
    ///
    /// Self-inclusive by design: it answers "is this id anywhere in this
    /// subtree, root included?", which is what every containment /
    /// descendant / find-group check needs — `group(id).is_some()` is the
    /// canonical containment test. Contrast [`Self::all_subgroups`], which
    /// deliberately **excludes** `self`.
    #[must_use]
    pub fn group(&self, id: GroupId) -> Option<&Group> {
        if self.id == id {
            return Some(self);
        }
        self.groups.iter().find_map(|g| g.group(id))
    }

    /// Mutable twin of [`Self::group`], self-inclusive.
    ///
    /// Hand-written recursion rather than an iterator: a self-inclusive
    /// `&mut Group` iterator can't be expressed safely — the yielded node
    /// aliases the children it would recurse into.
    #[must_use]
    pub fn group_mut(&mut self, id: GroupId) -> Option<&mut Group> {
        if self.id == id {
            return Some(self);
        }
        self.groups.iter_mut().find_map(|g| g.group_mut(id))
    }

    // ---- Parent-of ---------------------------------------------------------

    /// Return the id of the group directly holding entry `id`, or `None`
    /// if no entry with that id exists in this subtree. The entry analogue
    /// of [`Self::group_parent`] / [`super::Vault::group_parent`].
    #[must_use]
    pub fn entry_parent(&self, id: EntryId) -> Option<GroupId> {
        if self.entries.iter().any(|e| e.id == id) {
            return Some(self.id);
        }
        self.groups.iter().find_map(|g| g.entry_parent(id))
    }

    /// Return the id of the group directly holding the child group
    /// `child`, or `None` if `child` is `self` (this walk's root has no
    /// parent) or is absent from this subtree.
    #[must_use]
    pub fn group_parent(&self, child: GroupId) -> Option<GroupId> {
        for g in &self.groups {
            if g.id == child {
                return Some(self.id);
            }
            if let Some(p) = g.group_parent(child) {
                return Some(p);
            }
        }
        None
    }

    // ---- Detach ------------------------------------------------------------

    /// Remove the entry with `id` from the group that holds it and return
    /// it paired with that group's id. `None` if no entry with `id` exists
    /// in this subtree.
    ///
    /// Removes the first match; under the tree-wide id-uniqueness
    /// invariant that is the only match. Bool callers use
    /// [`Option::is_some`]; entry-only callers use `.map(|(e, _)| e)`;
    /// callers recording the old parent take the pair.
    #[must_use]
    pub fn detach_entry(&mut self, id: EntryId) -> Option<(Entry, GroupId)> {
        if let Some(pos) = self.entries.iter().position(|e| e.id == id) {
            let entry = self.entries.remove(pos);
            return Some((entry, self.id));
        }
        self.groups.iter_mut().find_map(|g| g.detach_entry(id))
    }

    /// Remove the subtree rooted at group `id` from its parent and return
    /// it paired with the parent's id. `None` if no group with `id` exists
    /// strictly below `self`.
    ///
    /// This walk's root (`self`) is never removable — nothing holds it in
    /// a `groups` vec — so `id == self.id` returns `None` rather than
    /// detaching `self`. Group-only callers use `.map(|(g, _)| g)`.
    #[must_use]
    pub fn detach_group(&mut self, id: GroupId) -> Option<(Group, GroupId)> {
        if let Some(pos) = self.groups.iter().position(|g| g.id == id) {
            let group = self.groups.remove(pos);
            return Some((group, self.id));
        }
        self.groups.iter_mut().find_map(|g| g.detach_group(id))
    }

    // ---- Iteration ---------------------------------------------------------

    /// Mutable mirror of [`Self::iter_entries`]: every entry under this
    /// group, depth-first pre-order. Composes with `?` for fallible
    /// per-entry passes.
    pub fn iter_entries_mut(&mut self) -> Box<dyn Iterator<Item = &mut Entry> + '_> {
        Box::new(
            self.entries
                .iter_mut()
                .chain(self.groups.iter_mut().flat_map(Group::iter_entries_mut)),
        )
    }

    /// Iterate every group in this subtree **including `self`** (`self`
    /// first), depth-first pre-order. Self-inclusive to match
    /// [`Self::group`]; [`Self::all_subgroups`] is this `skip(1)`-ed.
    pub fn iter_groups(&self) -> Box<dyn Iterator<Item = &Group> + '_> {
        Box::new(std::iter::once(self).chain(self.groups.iter().flat_map(Group::iter_groups)))
    }

    /// Iterate every entry paired with the id of the group that directly
    /// holds it, depth-first pre-order. The whole-tree, batched form of
    /// [`Self::entry_parent`].
    #[must_use = "returns an iterator and does nothing unless consumed"]
    pub fn iter_entries_with_parent(&self) -> Box<dyn Iterator<Item = (&Entry, GroupId)> + '_> {
        let id = self.id;
        Box::new(
            self.entries
                .iter()
                .map(move |e| (e, id))
                .chain(self.groups.iter().flat_map(Group::iter_entries_with_parent)),
        )
    }

    /// Iterate every group (self included, `self` first) paired with its
    /// parent's id — `None` for `self`/root, `Some(owner)` for every
    /// descendant — depth-first pre-order. The batched form of
    /// [`Self::group_parent`].
    #[must_use = "returns an iterator and does nothing unless consumed"]
    pub fn iter_groups_with_parent(
        &self,
    ) -> Box<dyn Iterator<Item = (&Group, Option<GroupId>)> + '_> {
        self.groups_with_parent_from(None)
    }

    /// Recursion helper for [`Self::iter_groups_with_parent`], threading
    /// each group's parent id down the walk.
    fn groups_with_parent_from(
        &self,
        parent: Option<GroupId>,
    ) -> Box<dyn Iterator<Item = (&Group, Option<GroupId>)> + '_> {
        let id = self.id;
        Box::new(
            std::iter::once((self, parent)).chain(
                self.groups
                    .iter()
                    .flat_map(move |g| g.groups_with_parent_from(Some(id))),
            ),
        )
    }

    /// Visit every group in this subtree (self included, `self` first),
    /// depth-first pre-order, calling `f` on each. The mutable-visitor
    /// counterpart to [`Self::iter_groups`] — a closure rather than an
    /// iterator because a self-inclusive `&mut Group` iterator can't be
    /// expressed safely.
    pub fn for_each_group_mut(&mut self, f: &mut impl FnMut(&mut Group)) {
        f(self);
        for g in &mut self.groups {
            g.for_each_group_mut(f);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn gid(n: u128) -> GroupId {
        GroupId(Uuid::from_u128(n))
    }
    fn eid(n: u128) -> EntryId {
        EntryId(Uuid::from_u128(n))
    }

    // A fixed fixture tree with entries and groups at multiple depths, so
    // every lookup below exercises a NON-root hit (the shape that the old
    // hand-rolled shallow test walkers silently got wrong):
    //
    //   G0 (root)         entries: [E1]
    //   ├── G1            entries: [E2]
    //   │   └── G2        entries: [E3]
    //   └── G3            entries: []
    fn fixture() -> Group {
        let mut root = Group::empty(gid(0));
        root.entries.push(Entry::empty(eid(1)));

        let mut g1 = Group::empty(gid(1));
        g1.entries.push(Entry::empty(eid(2)));
        let mut g2 = Group::empty(gid(2));
        g2.entries.push(Entry::empty(eid(3)));
        g1.groups.push(g2);

        let g3 = Group::empty(gid(3));

        root.groups.push(g1);
        root.groups.push(g3);
        root
    }

    #[test]
    fn entry_finds_deep_and_misses_absent() {
        let root = fixture();
        assert_eq!(root.entry(eid(3)).map(|e| e.id), Some(eid(3)));
        assert_eq!(root.entry(eid(1)).map(|e| e.id), Some(eid(1)));
        assert!(root.entry(eid(99)).is_none());
    }

    #[test]
    fn entry_mut_reaches_a_deep_entry() {
        let mut root = fixture();
        root.entry_mut(eid(3)).unwrap().title = "renamed".to_string();
        assert_eq!(root.entry(eid(3)).unwrap().title, "renamed");
    }

    #[test]
    fn group_is_self_inclusive_and_finds_deep() {
        let root = fixture();
        // Self match returns self.
        assert_eq!(root.group(gid(0)).map(|g| g.id), Some(gid(0)));
        // Deep match.
        assert_eq!(root.group(gid(2)).map(|g| g.id), Some(gid(2)));
        assert!(root.group(gid(99)).is_none());
    }

    #[test]
    fn group_mut_reaches_a_deep_group() {
        let mut root = fixture();
        root.group_mut(gid(2)).unwrap().name = "deep".to_string();
        assert_eq!(root.group(gid(2)).unwrap().name, "deep");
    }

    #[test]
    fn entry_parent_reports_the_owning_group() {
        let root = fixture();
        assert_eq!(root.entry_parent(eid(1)), Some(gid(0)));
        assert_eq!(root.entry_parent(eid(2)), Some(gid(1)));
        assert_eq!(root.entry_parent(eid(3)), Some(gid(2)));
        assert!(root.entry_parent(eid(99)).is_none());
    }

    #[test]
    fn group_parent_reports_owner_and_none_for_self() {
        let root = fixture();
        assert_eq!(root.group_parent(gid(1)), Some(gid(0)));
        assert_eq!(root.group_parent(gid(2)), Some(gid(1)));
        assert_eq!(root.group_parent(gid(3)), Some(gid(0)));
        // The walk's root has no parent, and absent ids miss.
        assert!(root.group_parent(gid(0)).is_none());
        assert!(root.group_parent(gid(99)).is_none());
    }

    #[test]
    fn detach_entry_returns_entry_and_parent_then_is_gone() {
        let mut root = fixture();
        let (entry, parent) = root.detach_entry(eid(2)).unwrap();
        assert_eq!(entry.id, eid(2));
        assert_eq!(parent, gid(1));
        assert!(root.entry(eid(2)).is_none());
        assert!(root.detach_entry(eid(99)).is_none());
    }

    #[test]
    fn detach_group_returns_subtree_and_parent_but_never_root() {
        let mut root = fixture();
        let (sub, parent) = root.detach_group(gid(2)).unwrap();
        assert_eq!(sub.id, gid(2));
        assert_eq!(parent, gid(1));
        assert!(root.group(gid(2)).is_none());
        // Detaching an entry that rode along on the removed subtree also misses.
        assert!(root.entry(eid(3)).is_none());
        // The walk's root is never removable.
        assert!(root.detach_group(gid(0)).is_none());
    }

    #[test]
    fn iter_groups_is_self_inclusive_pre_order() {
        let root = fixture();
        let ids: Vec<GroupId> = root.iter_groups().map(|g| g.id).collect();
        assert_eq!(ids, vec![gid(0), gid(1), gid(2), gid(3)]);
    }

    #[test]
    fn all_subgroups_excludes_self_and_matches_iter_groups_skip_one() {
        let root = fixture();
        let via_all: Vec<GroupId> = root.all_subgroups().iter().map(|g| g.id).collect();
        assert_eq!(via_all, vec![gid(1), gid(2), gid(3)]);
        let via_skip: Vec<GroupId> = root.iter_groups().skip(1).map(|g| g.id).collect();
        assert_eq!(via_all, via_skip);
    }

    #[test]
    fn iter_entries_mut_touches_every_entry() {
        let mut root = fixture();
        for e in root.iter_entries_mut() {
            e.title = "x".to_string();
        }
        assert!(root.iter_entries().all(|e| e.title == "x"));
        assert_eq!(root.iter_entries().count(), 3);
    }

    #[test]
    fn iter_entries_with_parent_pairs_each_entry_to_owner() {
        let root = fixture();
        let pairs: Vec<(EntryId, GroupId)> = root
            .iter_entries_with_parent()
            .map(|(e, p)| (e.id, p))
            .collect();
        assert_eq!(
            pairs,
            vec![(eid(1), gid(0)), (eid(2), gid(1)), (eid(3), gid(2))]
        );
    }

    #[test]
    fn iter_groups_with_parent_pairs_each_group_to_parent() {
        let root = fixture();
        let pairs: Vec<(GroupId, Option<GroupId>)> = root
            .iter_groups_with_parent()
            .map(|(g, p)| (g.id, p))
            .collect();
        assert_eq!(
            pairs,
            vec![
                (gid(0), None),
                (gid(1), Some(gid(0))),
                (gid(2), Some(gid(1))),
                (gid(3), Some(gid(0))),
            ]
        );
    }

    #[test]
    fn for_each_group_mut_visits_every_group_including_root() {
        let mut root = fixture();
        let mut count = 0;
        root.for_each_group_mut(&mut |g| {
            g.name = "v".to_string();
            count += 1;
        });
        assert_eq!(count, 4);
        assert!(root.iter_groups().all(|g| g.name == "v"));
    }
}
