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
use uuid::Uuid;

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
    /// Pre-computed list of attachments that differ between `local`
    /// and `remote` and need caller resolution. Auto-resolvable
    /// attachment differences (byte-identical, or 3-way classifier
    /// has a clear winner against the LCA) ride through the merge's
    /// internal auto-resolution pipeline and apply silently; they do
    /// not appear here.
    pub attachment_deltas: Vec<AttachmentDelta>,
}

/// Per-attachment difference between the two sides of an [`EntryConflict`].
///
/// Mirrors [`FieldDelta`] for attachments. One [`AttachmentDelta`] is
/// emitted for every attachment name whose presence-or-content the
/// merge could not auto-resolve. Names whose payloads are
/// byte-identical on both sides — or where the 3-way classifier saw a
/// clear winner against the LCA — do not surface as deltas; they ride
/// the entry-level merge through `attachment_auto_resolutions`.
///
/// The `*_sha256` and `*_size` slots are populated from the relevant
/// side's [`keepass_core::model::Vault::binaries`] entry at
/// classification time so downstream resolver UIs can render content
/// metadata without re-dereferencing the binary pool.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AttachmentDelta {
    /// Attachment name (the `<Binary><Key>` value). For the
    /// [`AttachmentDeltaKind::BothDiffer`] kind, the name is shared
    /// across both sides; for the one-sided kinds, it's the name on
    /// the side that holds the attachment.
    pub name: String,
    /// Which side(s) hold the attachment under this name.
    pub kind: AttachmentDeltaKind,
    /// SHA-256 of the local-side payload, or `None` when local doesn't
    /// hold this attachment ([`AttachmentDeltaKind::RemoteOnly`]).
    pub local_sha256: Option<[u8; 32]>,
    /// SHA-256 of the remote-side payload, or `None` when remote
    /// doesn't hold it ([`AttachmentDeltaKind::LocalOnly`]).
    pub remote_sha256: Option<[u8; 32]>,
    /// Decoded payload size in bytes on the local side, or `None`
    /// when absent.
    pub local_size: Option<u64>,
    /// Decoded payload size in bytes on the remote side, or `None`
    /// when absent.
    pub remote_size: Option<u64>,
}

/// Classification of an [`AttachmentDelta`] by which side(s) hold the
/// attachment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AttachmentDeltaKind {
    /// The name exists only on the local side, and the LCA is either
    /// absent or carried a different payload — i.e. local edited an
    /// attachment that remote deleted, so the data alone can't decide.
    LocalOnly,
    /// The name exists only on the remote side, and the LCA is either
    /// absent or carried a different payload — i.e. remote edited an
    /// attachment that local deleted.
    RemoteOnly,
    /// Both sides hold the name but the bytes differ (SHA-256
    /// mismatch) and neither side's bytes match the LCA — concurrent
    /// edits to the same attachment slot.
    BothDiffer,
}

/// Per-entry icon difference between the two sides of an
/// [`EntryConflict`]. Surfaces only when the local and remote sides
/// hold different `custom_icon_uuid` values (or one side has one and
/// the other doesn't) **and** the 3-way classifier couldn't pick a
/// winner against the LCA. Base-icon-ID divergence is silently auto-
/// merged and does not surface here — see
/// `_localdocs/MERGE_ICON_CLASSIFIER.md`.
///
/// Currently `pub(crate)` — the classifier populates it on
/// [`crate::entry_merge::EntryMergeOutput`] but no routing or apply
/// consumes it yet. Promoted to `pub` and wired into
/// [`EntryConflict::icon_delta`] in PR I3.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields read by routing/apply in PR I2; resolution carrier in PR I3.
pub(crate) struct IconDelta {
    pub local_custom_icon_uuid: Option<Uuid>,
    pub remote_custom_icon_uuid: Option<Uuid>,
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
