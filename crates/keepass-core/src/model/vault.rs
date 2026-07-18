//! `Vault` — the format-agnostic root container, plus the two value
//! types it owns: `DeletedObject` (tombstones) and `Binary`
//! (attachment payloads).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{Entry, Group, GroupId, Meta, UnknownElement};

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
        self.root.group_parent(child)
    }

    // ---- Tree-navigation delegates -----------------------------------------
    //
    // Thin delegates to the corresponding [`Group`] method on `self.root`,
    // so consumers holding a `Vault` (FFI surfaces, `kdbx.rs`, tests) reach
    // the navigation without threading through `.root`. The Group methods
    // carry the semantics (self-inclusive group lookup, remove-first detach,
    // depth-first pre-order); see [`Group`].

    /// Find the entry with `id` anywhere in the vault. `None` if absent.
    /// `entry(id).is_some()` is the contains-entry check.
    #[must_use]
    pub fn entry(&self, id: super::EntryId) -> Option<&Entry> {
        self.root.entry(id)
    }

    /// Mutable twin of [`Self::entry`].
    #[must_use]
    pub fn entry_mut(&mut self, id: super::EntryId) -> Option<&mut Entry> {
        self.root.entry_mut(id)
    }

    /// Find the group with `id` anywhere in the vault, **including the
    /// root** (a match on the root id returns the root). `None` if absent.
    /// `group(id).is_some()` is the contains-group check.
    #[must_use]
    pub fn group(&self, id: GroupId) -> Option<&Group> {
        self.root.group(id)
    }

    /// Mutable twin of [`Self::group`], root-inclusive.
    #[must_use]
    pub fn group_mut(&mut self, id: GroupId) -> Option<&mut Group> {
        self.root.group_mut(id)
    }

    /// Return the id of the group directly holding entry `id`, or `None`
    /// if `id` is absent. The entry analogue of [`Self::group_parent`].
    #[must_use]
    pub fn entry_parent(&self, id: super::EntryId) -> Option<GroupId> {
        self.root.entry_parent(id)
    }

    /// Remove the entry with `id` and return it paired with its former
    /// owning group's id. `None` if absent. See [`Group::detach_entry`].
    #[must_use]
    pub fn detach_entry(&mut self, id: super::EntryId) -> Option<(Entry, GroupId)> {
        self.root.detach_entry(id)
    }

    /// Remove the subtree rooted at group `id` and return it paired with
    /// its former parent's id. `None` if absent (or `id` is the root,
    /// which nothing holds). See [`Group::detach_group`].
    #[must_use]
    pub fn detach_group(&mut self, id: GroupId) -> Option<(Group, GroupId)> {
        self.root.detach_group(id)
    }

    /// Iterate every entry in the vault, mutably, depth-first pre-order.
    pub fn iter_entries_mut(&mut self) -> Box<dyn Iterator<Item = &mut Entry> + '_> {
        self.root.iter_entries_mut()
    }

    /// Iterate every group in the vault (root included, root first),
    /// depth-first pre-order.
    pub fn iter_groups(&self) -> Box<dyn Iterator<Item = &Group> + '_> {
        self.root.iter_groups()
    }

    /// Iterate every entry paired with the id of the group directly
    /// holding it, depth-first pre-order.
    #[must_use = "returns an iterator and does nothing unless consumed"]
    pub fn iter_entries_with_parent(&self) -> Box<dyn Iterator<Item = (&Entry, GroupId)> + '_> {
        self.root.iter_entries_with_parent()
    }

    /// Iterate every group (root included, root first) paired with its
    /// parent's id — `None` for the root — depth-first pre-order.
    #[must_use = "returns an iterator and does nothing unless consumed"]
    pub fn iter_groups_with_parent(
        &self,
    ) -> Box<dyn Iterator<Item = (&Group, Option<GroupId>)> + '_> {
        self.root.iter_groups_with_parent()
    }

    /// Visit every group in the vault (root included, root first),
    /// depth-first pre-order, calling `f` on each. See
    /// [`Group::for_each_group_mut`].
    pub fn for_each_group_mut(&mut self, f: &mut impl FnMut(&mut Group)) {
        self.root.for_each_group_mut(f);
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

/// A tombstone for a deleted entry or group, recorded under
/// `<Root><DeletedObjects>`.
///
/// The UUID is deliberately a raw [`Uuid`] rather than an [`super::EntryId`]
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
    /// Unknown XML children on `<DeletedObject>` preserved verbatim for
    /// round-trip — see [`super::Entry::unknown_xml`] for the full
    /// semantics.
    pub unknown_xml: Vec<UnknownElement>,
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
        Self {
            uuid,
            deleted_at,
            unknown_xml: Vec::new(),
        }
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
    /// matching the constructor pattern on [`super::CustomField`] etc.
    #[must_use]
    pub fn new(data: Vec<u8>, protected: bool) -> Self {
        Self { data, protected }
    }
}
