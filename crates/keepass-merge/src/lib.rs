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
pub mod outcome;

pub mod resolution;

mod apply;
mod binary_pool;
mod entry_merge;
mod hash;
mod history_merge;
mod merge;

pub use crate::apply::{apply_merge, reconcile_timestamps};
pub use crate::conflict::{
    AttachmentDelta, AttachmentDeltaKind, EntryConflict, FieldDelta, FieldDeltaKind, GroupConflict,
};
pub use crate::error::MergeError;
pub use crate::merge::merge;
pub use crate::outcome::MergeOutcome;
pub use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
