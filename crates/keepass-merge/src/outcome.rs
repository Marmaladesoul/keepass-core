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
    /// Crate-private sidecar: the per-entry auto-resolution facets the
    /// classifier in [`crate::entry_merge::merge_entry`] produced for
    /// every both-present entry, keyed by [`EntryId`]. One
    /// [`PerEntryPlan`] per entry rather than a parallel map per facet:
    /// the four facets are co-derived from a single `merge_entry` run
    /// and co-consumed by apply's re-join, so a per-facet map is a
    /// shredding that let the "mixed-side field wins" data-loss bug slip
    /// through once (apply overlaid the bucket winner but forgot one
    /// facet's map). Bundling them makes apply look each entry's decision
    /// up in one place. See [`PerEntryPlan`] for the per-facet contract.
    pub(crate) per_entry: HashMap<EntryId, PerEntryPlan>,
    /// Crate-private sidecar: for symmetric edit-vs-delete entries
    /// (local deleted, remote edited), holds the remote-side entry
    /// content and remote's parent-group id. Apply consumes both
    /// when restoring the entry under the spec §4 "edit wins" rule:
    /// the entry content lands at the parent (or root if the parent
    /// isn't present locally). Asymmetric delete-vs-edit (the legacy
    /// case where local was the editor) leaves this sidecar empty —
    /// the entry already exists on local.
    ///
    /// Kept separate from [`Self::per_entry`] deliberately: it is not a
    /// `merge_entry` auto-resolution facet — it's produced by the
    /// delete-vs-edit routing for a *disjoint* set of entries and
    /// consumed by a different apply path, so it shares neither the
    /// producer nor the lifecycle of the four bundled facets.
    pub(crate) delete_edit_restore_from_remote: HashMap<EntryId, (Entry, GroupId)>,
}

/// The auto-resolution facets [`crate::entry_merge::merge_entry`]
/// produced for one both-present entry — a slimmed projection of
/// `EntryMergeOutput` carrying only what apply needs to re-join.
///
/// Populated for every both-present entry (empty facets are the common
/// case); apply reads the relevant facet(s) for whichever bucket the
/// entry routed to. `Default` is all-empty.
#[derive(Debug, Default)]
pub(crate) struct PerEntryPlan {
    /// Per-attachment auto-resolutions. Apply drives per-attachment
    /// merge from these for entries in `disk_only_changes`,
    /// `local_only_changes`, or `entry_conflicts`. Attachment
    /// *conflicts* (no auto-decision) surface on
    /// [`EntryConflict::attachment_deltas`] and consume caller choices
    /// via [`crate::Resolution::entry_attachment_choices`].
    pub(crate) attachment_auto_resolutions: Vec<AttachmentAutoResolution>,
    /// Per-field auto-resolutions. Apply overlays these per-field
    /// winners on the bucket-level clone for `disk_only_changes` /
    /// `local_only_changes`, so a mixed-side auto-resolution (e.g. local
    /// wins Title, remote wins UserName) doesn't silently lose one
    /// side's edit. Field *conflicts* surface on
    /// [`EntryConflict::field_deltas`] and consume caller choices via
    /// [`crate::Resolution::entry_field_choices`].
    pub(crate) field_auto_resolutions: Vec<(String, Side)>,
    /// Icon auto-resolution; `Some` only when the classifier had a clear
    /// answer against the LCA. Apply overlays the chosen side's
    /// `custom_icon_uuid` on the bucket-winner clone. Icon *conflicts*
    /// will surface on [`EntryConflict::icon_delta`] in PR I3.
    pub(crate) icon_auto_resolution: Option<Side>,
    /// The merged tag set (a pure set merge — no conflict cases, per
    /// `internal design notes`). Apply writes it onto the merged entry.
    pub(crate) merged_tags: std::collections::BTreeSet<String>,
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
