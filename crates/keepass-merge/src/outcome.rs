//! The result of a merge run.
//!
//! [`MergeOutcome`] mirrors the `MergeResult` shape consumed by the
//! existing Keys.app conflict-resolver UI: seven entry-level buckets plus
//! a v0.2 placeholder for group structural conflicts. Every bucket
//! defaults to empty so the merge algorithm can build the outcome
//! incrementally as it walks the two vaults.

use std::collections::HashMap;

use keepass_core::model::{Entry, EntryId, GroupId};

use crate::conflict::{EntryConflict, GroupConflict};
use crate::entry_merge::{AttachmentAutoResolution, Side};

/// All entry- and group-level decisions produced by a merge run.
///
/// The seven entry buckets cover every classification a v0.1 merge can
/// produce; [`Self::group_conflicts`] is reserved for v0.2 and is always
/// empty in v0.1.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct MergeOutcome {
    /// Entries that changed only on the remote side and are safe to take.
    pub disk_only_changes: Vec<EntryId>,
    /// Entries that changed only locally; the remote copy is stale.
    pub local_only_changes: Vec<EntryId>,
    /// Entries edited on both sides that require caller resolution.
    pub entry_conflicts: Vec<EntryConflict>,
    /// Entries present only on the remote side and not in our tombstones.
    pub added_on_disk: Vec<Entry>,
    /// Entries present locally but tombstoned on the remote side.
    pub deleted_on_disk: Vec<EntryId>,
    /// Entries we tombstoned that are still alive on the remote side; the
    /// caller should write back to propagate our deletions.
    pub local_deletions_pending_sync: Vec<EntryId>,
    /// Entries that surfaced an edit-vs-delete conflict in either
    /// direction:
    /// * **Asymmetric (legacy)**: local edited the entry; remote
    ///   tombstoned it with `deleted_at < local.mtime`.
    /// * **Symmetric**: remote edited the entry; local tombstoned it
    ///   with `deleted_at < remote.mtime`. In this case local doesn't
    ///   actually hold the entry — the merge crate stashes remote's
    ///   pre-merge entry content in a crate-private sidecar
    ///   (`delete_edit_restore_from_remote`) so the apply step can
    ///   restore it under remote's parent group.
    ///
    /// The auto-park flow synthesises `DeleteEditChoice::KeepLocal`
    /// for both directions per spec §4 "edit wins"; the apply step
    /// detects which side the entry is on and restores accordingly.
    /// Tombstone retention is intentionally NOT preserved (see
    /// `apply::resolution::apply_delete_edit_resolutions` for the
    /// cross-client safety rationale) — the historical signal lives
    /// in `MergeEvent::EntryRestoredFromDeletion` instead.
    pub delete_edit_conflicts: Vec<EntryId>,
    /// Group structural conflicts. Always empty in v0.1; reserved for v0.2.
    pub group_conflicts: Vec<GroupConflict>,
    /// Entries whose per-entry 3-way merge found no shared ancestor
    /// (both sides' `<History>` lists either diverged past the LCA or
    /// were truncated beyond it). Per spec §3 these enter the merge's
    /// conservative-fallback path — every field that differs parks
    /// rather than auto-resolves — and the FFI layer is expected to
    /// surface a warn-severity log per spec §6 ("Entry 'X' had no
    /// shared history — manual review needed for all changed fields").
    /// Populated regardless of whether the entry ended up in
    /// `entry_conflicts`: an LCA-missing entry whose fields happened
    /// to agree is still worth knowing about.
    pub lca_missing_entries: Vec<EntryId>,
    /// Entries that tripped the spec §3 corruption signal: same UUID
    /// on both sides, no shared ancestor, no history on either side,
    /// both sides carry an mtime. Cannot arise from a normal sync flow.
    /// The merge still parks rather than auto-fixing; the caller is
    /// expected to surface a structured error log entry. Every entry
    /// in this list is also in `lca_missing_entries`.
    pub corruption_signals: Vec<EntryId>,
    /// Crate-private sidecar: per-entry attachment auto-resolutions
    /// produced by the classifier in [`crate::entry_merge::merge_entry`].
    /// Keyed by [`EntryId`] for every entry that ended up in
    /// `disk_only_changes`, `local_only_changes`, or `entry_conflicts`.
    /// Apply consumes this to drive per-attachment merge inside the
    /// entry-level merge. Attachment *conflicts* (where the classifier
    /// can't auto-decide) surface on
    /// [`EntryConflict::attachment_deltas`] and consume caller choices
    /// via [`crate::Resolution::entry_attachment_choices`].
    pub(crate) attachment_auto_resolutions_per_entry:
        HashMap<EntryId, Vec<AttachmentAutoResolution>>,
    /// Crate-private sidecar: per-entry field auto-resolutions produced
    /// by the classifier in [`crate::entry_merge::merge_entry`]. Keyed
    /// by [`EntryId`] for every entry that ended up in
    /// `disk_only_changes` or `local_only_changes`. Apply consumes this
    /// to overlay per-field winners on the bucket-level clone, so a
    /// mixed-side auto-resolution (e.g. local wins Title, remote wins
    /// UserName) doesn't silently lose one side's edit. Field
    /// *conflicts* (where the classifier can't auto-decide) surface on
    /// [`EntryConflict::field_deltas`] and consume caller choices via
    /// [`crate::Resolution::entry_field_choices`].
    pub(crate) field_auto_resolutions_per_entry: HashMap<EntryId, Vec<(String, Side)>>,
    /// Crate-private sidecar: per-entry icon auto-resolution produced
    /// by the classifier in [`crate::entry_merge::merge_entry`]. Keyed
    /// by [`EntryId`]; only present when the classifier had a clear
    /// answer against the LCA. Apply consumes this to overlay the
    /// chosen side's `custom_icon_uuid` on the bucket-winner clone.
    /// Icon *conflicts* (where the classifier can't auto-decide) will
    /// surface on [`EntryConflict::icon_delta`] in PR I3.
    pub(crate) icon_auto_resolutions_per_entry: HashMap<EntryId, Side>,
    /// Crate-private sidecar: for symmetric edit-vs-delete entries
    /// (local deleted, remote edited), holds the remote-side entry
    /// content and remote's parent-group id. Apply consumes both
    /// when restoring the entry under the spec §4 "edit wins" rule:
    /// the entry content lands at the parent (or root if the parent
    /// isn't present locally). Asymmetric delete-vs-edit (the legacy
    /// case where local was the editor) leaves this sidecar empty —
    /// the entry already exists on local.
    pub(crate) delete_edit_restore_from_remote: HashMap<EntryId, (Entry, GroupId)>,
    /// Crate-private sidecar: per-entry merged tag set produced by
    /// the tag classifier in [`crate::entry_merge::merge_entry`]. Tags
    /// merge as a pure set (per `internal design notes`)
    /// with no conflict cases; apply writes the merged set onto the
    /// merged entry. Stashed for every entry that landed in any
    /// non-empty bucket, including `entry_conflicts`.
    pub(crate) merged_tags_per_entry: HashMap<EntryId, std::collections::BTreeSet<String>>,
}

#[cfg(test)]
mod tests {
    use super::MergeOutcome;

    #[test]
    fn default_is_empty() {
        let outcome = MergeOutcome::default();
        assert!(outcome.disk_only_changes.is_empty());
        assert!(outcome.local_only_changes.is_empty());
        assert!(outcome.entry_conflicts.is_empty());
        assert!(outcome.added_on_disk.is_empty());
        assert!(outcome.deleted_on_disk.is_empty());
        assert!(outcome.local_deletions_pending_sync.is_empty());
        assert!(outcome.delete_edit_conflicts.is_empty());
        assert!(outcome.group_conflicts.is_empty());
        assert!(outcome.lca_missing_entries.is_empty());
        assert!(outcome.corruption_signals.is_empty());
    }
}
