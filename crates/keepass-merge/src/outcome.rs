//! The result of a merge run.
//!
//! [`MergeOutcome`] mirrors the `MergeResult` shape consumed by the
//! existing Keys.app conflict-resolver UI: seven entry-level buckets plus
//! a v0.2 placeholder for group structural conflicts. Every bucket
//! defaults to empty so the merge algorithm can build the outcome
//! incrementally as it walks the two vaults.

use std::collections::HashMap;

use keepass_core::model::{Entry, EntryId};

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
    /// Entries the remote side tombstoned that we had locally edited.
    pub delete_edit_conflicts: Vec<EntryId>,
    /// Group structural conflicts. Always empty in v0.1; reserved for v0.2.
    pub group_conflicts: Vec<GroupConflict>,
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
    /// Crate-private sidecar: per-entry merged tag set produced by
    /// the tag classifier in [`crate::entry_merge::merge_entry`]. Tags
    /// merge as a pure set (per `_localdocs/MERGE_TAGS_DESIGN.md`)
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
    }
}
