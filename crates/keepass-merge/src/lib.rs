//! # keepass-merge
//!
//! Three-way merge of two KeePass vaults using each entry's `<History>`
//! list as the per-entry common ancestor. Conflicting field-level changes
//! are surfaced for caller resolution; everything else is auto-merged.
//! Group structural conflicts are resolved by last-write-wins-by-timestamp
//! in v0.1; richer group-conflict reporting is reserved for v0.2.
//!
//! This crate exists separately from [`keepass_core`] because merge is a
//! distinct concern with its own test surface, and not every consumer of
//! `keepass-core` needs it (e.g. a read-only viewer or a format
//! converter).

#![doc(html_no_source)]
#![forbid(unsafe_code)]

pub mod conflict;
pub mod error;
pub mod field_conflict;
pub mod outcome;

pub mod prune;
pub mod resolution;
pub mod tombstone;

mod apply;
mod auto;
mod binary_pool;
mod entry_merge;
mod hash;
mod history_merge;
mod merge;

pub use crate::apply::{apply_merge, reconcile_timestamps};
pub use crate::auto::{ParkConflictsConfig, ParkedConflictsReport, apply_merge_park_conflicts};
pub use crate::conflict::{
    AttachmentDelta, AttachmentDeltaKind, EntryConflict, FieldDelta, FieldDeltaKind, GroupConflict,
    IconDelta,
};
pub use crate::error::MergeError;
pub use crate::field_conflict::{FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker};
pub use crate::merge::merge;
pub use crate::outcome::MergeOutcome;
pub use crate::prune::prune_history_with_tombstones;
pub use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
pub use crate::tombstone::{
    HistoryTombstone, TOMBSTONE_CUSTOM_DATA_KEY, TombstoneError, TombstoneReason,
    add_history_tombstone, parse_tombstones,
};
