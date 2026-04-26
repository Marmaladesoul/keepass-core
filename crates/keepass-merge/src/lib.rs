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

// Slice 2 introduces these private modules ahead of slice 3's vault
// walker (the only non-test consumer of `merge_entry`). The
// `dead_code` allow comes off once slice 3 wires the merge entry
// point into the public surface.
#[allow(dead_code)]
mod entry_merge;
#[allow(dead_code)]
mod hash;

pub use crate::conflict::{EntryConflict, FieldDelta, FieldDeltaKind, GroupConflict};
pub use crate::error::MergeError;
pub use crate::outcome::MergeOutcome;
