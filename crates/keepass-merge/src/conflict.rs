//! Conflict carriers surfaced by the merge algorithm.
//!
//! [`EntryConflict`] is the load-bearing type: when the same entry was
//! edited on both sides and the per-field three-way merge cannot
//! auto-resolve, the conflict is reported with both full sides plus a
//! pre-computed list of [`FieldDelta`]s that lets a caller drive a
//! resolution UI without re-diffing.
//!
//! [`GroupConflict`] is a v0.2 placeholder: the v0.1 algorithm reconciles
//! group structure by last-write-wins-by-timestamp and never populates
//! this bucket. The type exists in the v0.1 surface so the bucket on
//! [`crate::MergeOutcome`] is non-empty in shape; richer fields are
//! reserved by `#[non_exhaustive]`.

use keepass_core::model::{Entry, EntryId, GroupId};

/// Per-field difference between the two sides of an [`EntryConflict`].
///
/// One [`FieldDelta`] is emitted for every field key that differs between
/// `local` and `remote`. Fields identical on both sides are not surfaced.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FieldDelta {
    /// Field key (e.g. `Title`, `Password`, or a custom-field name).
    pub key: String,
    /// Which sides hold a value for this key.
    pub kind: FieldDeltaKind,
}

/// Classification of a [`FieldDelta`] by which sides hold the field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FieldDeltaKind {
    /// The field exists only on the local side.
    LocalOnly,
    /// The field exists only on the remote side.
    RemoteOnly,
    /// Both sides have the field but the values differ.
    BothDiffer,
}

/// An entry that was edited on both sides and could not be auto-merged.
///
/// Carries both pre-merge entry states in full plus the differing field
/// list. The ancestor (taken from the entry's `<History>` list during the
/// merge) is *not* surfaced — the existing Keys.app conflict-resolver UI
/// only displays both sides, and richer ancestor reporting is reserved
/// for a future slice via `#[non_exhaustive]`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EntryConflict {
    /// Identifier of the conflicted entry.
    pub entry_id: EntryId,
    /// Local side of the conflict, in full.
    pub local: Entry,
    /// Remote (incoming) side of the conflict, in full.
    pub remote: Entry,
    /// Pre-computed list of fields that differ between `local` and `remote`.
    pub field_deltas: Vec<FieldDelta>,
}

/// Placeholder for a future group structural conflict (v0.2).
///
/// The v0.1 merge algorithm never produces a [`GroupConflict`]; group
/// renames and moves are silently reconciled by last-write-wins on
/// timestamps. The type exists so [`crate::MergeOutcome::group_conflicts`]
/// has a meaningful element type today; v0.2 will populate sibling fields
/// such as `local: Group` / `remote: Group` without a semver break.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GroupConflict {
    /// Identifier of the group with diverging structure.
    pub group_id: GroupId,
}
