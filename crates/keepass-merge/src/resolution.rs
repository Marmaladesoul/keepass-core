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
    /// Per-attachment decision for every conflicting attachment of
    /// every entry in [`crate::MergeOutcome::entry_conflicts`]. The
    /// inner map is keyed by [`crate::AttachmentDelta::name`].
    pub entry_attachment_choices: HashMap<EntryId, HashMap<String, AttachmentChoice>>,
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

/// Caller's choice for a single conflicting attachment.
///
/// For [`crate::AttachmentDeltaKind::LocalOnly`] /
/// [`crate::AttachmentDeltaKind::RemoteOnly`] deltas:
/// [`Self::KeepLocal`] / [`Self::KeepRemote`] are the only meaningful
/// variants. [`Self::KeepBoth`] is validation-rejected for these
/// kinds — the absent side has no bytes to keep.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachmentChoice {
    /// Take local's bytes. For a `RemoteOnly` delta, this honours
    /// local's absent state — the attachment is dropped from the
    /// merged entry.
    KeepLocal,
    /// Take remote's bytes. For a `LocalOnly` delta, this honours
    /// remote's absent state — the attachment is dropped.
    KeepRemote,
    /// Both sides hold the attachment with different bytes; keep
    /// both. The merge layer installs local's attachment under its
    /// original name and remote's under a renamed slot to avoid the
    /// per-entry name collision KDBX disallows.
    ///
    /// `rename_override` lets the caller specify the renamed name.
    /// When `None`, the default pattern `"<stem> (remote).<ext>"` is
    /// used, with a counter suffix (`"<stem> (remote 2).<ext>"`, …)
    /// if that name is also already taken by another kept
    /// attachment on the merged entry.
    ///
    /// Validation rejects this variant for any delta whose kind isn't
    /// [`crate::AttachmentDeltaKind::BothDiffer`] — one side has no
    /// bytes to keep.
    KeepBoth {
        /// Override the default rename pattern; `None` uses the
        /// default with counter-suffix fallback.
        rename_override: Option<String>,
    },
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
