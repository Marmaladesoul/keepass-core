//! Format-agnostic vault model.
//!
//! The types in this module describe a KeePass vault in memory without
//! committing to a particular on-disk version. The [`crate::format`] module
//! knows how to translate between these types and the KDBX3 / KDBX4 wire
//! formats.
//!
//! Every identifier type is a newtype — no naked `Uuid`s cross the API
//! boundary. This makes key-confusion bugs (e.g. passing an [`EntryId`] where
//! a [`GroupId`] is expected) into compile errors rather than runtime ones.
//!
//! Implementation pending.

use uuid::Uuid;

/// Identifier of an [`Entry`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId(Uuid);

/// Identifier of a [`Group`] within a vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(Uuid);

/// A single credential record.
///
/// Implementation pending.
#[derive(Debug)]
#[non_exhaustive]
pub struct Entry {
    /// Unique identifier.
    pub id: EntryId,
}

/// A folder/group in the vault hierarchy.
///
/// Implementation pending.
#[derive(Debug)]
#[non_exhaustive]
pub struct Group {
    /// Unique identifier.
    pub id: GroupId,
}

/// The root vault type (format-agnostic).
///
/// Implementation pending.
#[derive(Debug)]
#[non_exhaustive]
pub struct Vault {
    /// The root group of the vault tree.
    pub root: Group,
}
