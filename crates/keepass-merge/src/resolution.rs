//! Caller-supplied resolution carrier for [`crate::apply_merge`].
//!
//! [`Resolution`] holds the choices a user (or the FFI consumer's UI)
//! has made for the conflict-bearing buckets in a [`crate::MergeOutcome`]:
//!
//! - per-field winners for every entry in
//!   [`crate::MergeOutcome::entry_conflicts`];
//! - keep-or-delete decisions for every entry in
//!   [`crate::MergeOutcome::delete_edit_conflicts`].
//!
//! `Resolution::default()` is empty (no choices recorded). When the
//! corresponding outcome buckets are also empty, that's the auto-apply
//! incantation — no caller input required:
//!
//! ```ignore
//! apply_merge(&mut local, &remote, &outcome, &Resolution::default())
//! ```
//!
//! Slice 5b adds the validation pass that maps missing or extra
//! entries in this carrier to error variants on
//! [`crate::MergeError`]. Slice 5a accepts any `Resolution` whose
//! caller-supplied maps are consistent with the no-conflict outcome
//! buckets it's set up to handle.

use std::collections::HashMap;

use keepass_core::model::EntryId;

/// Caller-supplied resolution for the conflict buckets of a
/// [`crate::MergeOutcome`]. See module docs.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct Resolution {
    /// Per-field winner for every conflicting field of every entry in
    /// [`crate::MergeOutcome::entry_conflicts`]. The inner map is
    /// keyed by the [`crate::FieldDelta::key`] reported by the merge.
    pub entry_field_choices: HashMap<EntryId, HashMap<String, ConflictSide>>,
    /// Per-entry decision for every entry in
    /// [`crate::MergeOutcome::delete_edit_conflicts`].
    pub delete_edit_choices: HashMap<EntryId, DeleteEditChoice>,
}

/// Which side a caller has chosen for a single conflicting field.
///
/// Public twin of the crate-private `Side` enum used by the entry
/// merger. They're deliberately separate types: `Side` carries
/// "absence" semantics (a `Local` choice for a field the local side
/// doesn't have means "keep absent") that's a footgun on a
/// caller-facing API. `ConflictSide` is purely "this side won".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConflictSide {
    /// Take the local side's value for this field.
    Local,
    /// Take the remote side's value for this field.
    Remote,
}

/// Caller's choice for a delete-vs-edit conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeleteEditChoice {
    /// Keep the locally-edited entry; drop the remote tombstone from
    /// the merged tombstone set so the entry isn't subsequently re-
    /// deleted by the format's own merge semantics.
    KeepLocal,
    /// Honour the remote deletion; remove the local entry and
    /// preserve the remote tombstone in the merged tombstone set.
    AcceptRemoteDelete,
}
