//! The result of a merge run.
//!
//! [`MergeOutcome`] mirrors the `MergeResult` shape consumed by the
//! existing Keys.app conflict-resolver UI: seven entry-level buckets plus
//! a v0.2 placeholder for group structural conflicts. Every bucket
//! defaults to empty so the merge algorithm can build the outcome
//! incrementally as it walks the two vaults.

use keepass_core::model::{Entry, EntryId};

use crate::conflict::{EntryConflict, GroupConflict};

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
