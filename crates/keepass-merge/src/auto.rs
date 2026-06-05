//! Hold-open conflict handling for [`crate::apply_merge`].
//!
//! [`apply_merge_park_conflicts`] applies every non-conflicting change
//! from a merge outcome to the local vault and **holds open** every
//! genuine conflict the three-way classifier flagged: each side keeps
//! **its own** current value for the conflicting facet. No winner is
//! picked, and nothing is written into `<History>`.
//!
//! ## Why hold-open (not park-and-converge)
//!
//! The previous design picked an mtime/uuid winner and parked the
//! loser into history with a marker — but that (a) silently overwrote
//! one device's value, (b) chose by a rule meaningless to the user, and
//! (c) the marker didn't converge across peers. Hold-open instead leaves
//! both values live (each device shows its own), surfaces the conflict
//! via [`MergeOutcome::entry_conflicts`], and converges only when the
//! user explicitly resolves — a resolution then propagates as a
//! [`crate::conflict_resolution::ConflictResolution`] record. See
//! `_project-management/sync-conflict-state-redesign.md`.
//!
//! Because the divergence stays live in current state, "is this entry in
//! conflict?" is *derived* from the merge outcome each round — there is
//! no parked marker to store, and a re-merge of a held conflict writes
//! nothing (the loop-safety fixpoint).
//!
//! ## What this DOESN'T do
//!
//! It does **not** auto-resolve a genuine "both sides edited the same
//! field off a shared ancestor" conflict. The three-way merge still
//! auto-resolves the easy cases (one side changed); only true clashes
//! are held.

use keepass_core::model::{EntryId, Group, Vault};

use crate::apply::apply_merge;
use crate::conflict::{AttachmentDeltaKind, EntryConflict};
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
use crate::{MergeError, MergeOutcome};

/// Standard `<String>` field whose conflicts are flagged `sensitive` in
/// the activity-log event. Purely informational now (hold-open treats
/// every facet the same way); password clashes are worth surfacing
/// distinctly to the user.
const PASSWORD_FIELD: &str = "Password";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration knob for [`apply_merge_park_conflicts`].
///
/// Retained for API stability (callers construct it and the signature is
/// unchanged). `now` is no longer consumed — hold-open writes no
/// timestamped markers — but the field stays so existing call sites keep
/// compiling; it may carry future config.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParkConflictsConfig {
    /// Wall-clock stamp. Currently unused (no markers are written).
    pub now: chrono::DateTime<chrono::Utc>,
}

impl ParkConflictsConfig {
    /// Convenience constructor.
    #[must_use]
    pub fn with_now(now: chrono::DateTime<chrono::Utc>) -> Self {
        Self { now }
    }
}

/// Summary of what [`apply_merge_park_conflicts`] did, for downstream UX
/// ("we merged N changes; M entries have conflicts to review").
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ParkedConflictsReport {
    /// Entries currently holding a conflict (each side kept its own value
    /// for at least one facet). Surfaced as the vault-tile / entry badge.
    pub entries_with_parked_conflict: Vec<EntryId>,
    /// Entries the remote tombstoned but local had kept editing; the
    /// local edit was preserved (edit-wins).
    pub entries_restored_from_deletion: Vec<EntryId>,
    /// Entries with a both-differ attachment that rode the merge's
    /// non-destructive `KeepBoth` rename machinery (listed for telemetry).
    pub attachments_kept_both: Vec<EntryId>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Apply `outcome` to `local`, **holding open** every conflict: each
/// side keeps its own current value for the conflicting facet, the
/// conflict is surfaced in the returned report, and nothing is parked
/// into history. Non-conflicting changes apply as usual; delete-vs-edit
/// uses edit-wins.
///
/// Idempotent on a held conflict: re-running over an unchanged
/// `(local, remote)` keeps local's values again and writes nothing new —
/// the loop-safety fixpoint.
///
/// # Errors
///
/// Propagates whatever [`apply_merge`] returns. The synthesised
/// keep-local resolution is valid by construction.
pub fn apply_merge_park_conflicts(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    _config: &ParkConflictsConfig,
) -> Result<ParkedConflictsReport, MergeError> {
    // Spec §6 always-info: one event per held conflict for the activity
    // log + badge. Emitted before apply mutates the tree so the events
    // reference the pre-merge state.
    for conflict in &outcome.entry_conflicts {
        crate::events::emit(&crate::MergeEvent::ConflictParked {
            entry: conflict.entry_id,
            title: conflict.local.title.clone(),
            fields: conflict
                .field_deltas
                .iter()
                .map(|d| d.key.clone())
                .collect(),
            sensitive: is_sensitive_conflict(conflict),
        });
    }
    // Edit-wins on delete-vs-edit fires as its own event. Title comes from
    // whichever side carries the edit — local (asymmetric: local edited,
    // remote deleted) or remote (symmetric: local deleted, remote edited).
    for entry_id in &outcome.delete_edit_conflicts {
        let title = if let Some((remote_entry, _)) =
            outcome.delete_edit_restore_from_remote.get(entry_id)
        {
            remote_entry.title.clone()
        } else {
            find_entry_title(&local.root, *entry_id).unwrap_or_default()
        };
        crate::events::emit(&crate::MergeEvent::EntryRestoredFromDeletion {
            entry: *entry_id,
            title,
        });
    }

    // Hold-open: keep this side's value for every conflicting facet.
    let resolution = synthesize_keep_local_resolution(outcome);
    apply_merge(local, remote, outcome, &resolution)?;

    Ok(ParkedConflictsReport {
        entries_with_parked_conflict: outcome.entry_conflicts.iter().map(|c| c.entry_id).collect(),
        entries_restored_from_deletion: outcome.delete_edit_conflicts.clone(),
        attachments_kept_both: outcome
            .entry_conflicts
            .iter()
            .filter(|c| {
                c.attachment_deltas
                    .iter()
                    .any(|d| d.kind == AttachmentDeltaKind::BothDiffer)
            })
            .map(|c| c.entry_id)
            .collect(),
    })
}

/// Spec §5.1 (informational only now): a conflict is "sensitive" if it
/// touches the Password field or any custom field with `Protected="True"`
/// on either side. Used purely to flag the activity-log event — hold-open
/// treats every facet identically.
fn is_sensitive_conflict(conflict: &EntryConflict) -> bool {
    for delta in &conflict.field_deltas {
        if delta.key == PASSWORD_FIELD {
            return true;
        }
        let protected_either_side = conflict
            .local
            .custom_fields
            .iter()
            .any(|f| f.key == delta.key && f.protected)
            || conflict
                .remote
                .custom_fields
                .iter()
                .any(|f| f.key == delta.key && f.protected);
        if protected_either_side {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Keep-local resolution synthesis.
// ---------------------------------------------------------------------------

/// Build a [`Resolution`] that keeps **local's** value for every
/// conflicting field and icon (hold-open), keeps both files for a
/// both-differ attachment (non-destructive), and edit-wins for
/// delete-vs-edit. On peer A this keeps A's values; on peer B it keeps
/// B's — each device holds its own, symmetric and convergent in
/// *membership* (both surface the same conflict set).
fn synthesize_keep_local_resolution(outcome: &MergeOutcome) -> Resolution {
    let mut resolution = Resolution::default();

    for conflict in &outcome.entry_conflicts {
        if !conflict.field_deltas.is_empty() {
            let mut field_choices = std::collections::HashMap::new();
            for delta in &conflict.field_deltas {
                field_choices.insert(delta.key.clone(), ConflictSide::Local);
            }
            resolution
                .entry_field_choices
                .insert(conflict.entry_id, field_choices);
        }

        // Attachments are not a single-value facet: keep both differing
        // files (renamed) rather than holding, and keep the present side
        // for one-sided deltas. Non-destructive, so no data is lost and
        // there's nothing to "hold".
        if !conflict.attachment_deltas.is_empty() {
            let mut attachment_choices = std::collections::HashMap::new();
            for delta in &conflict.attachment_deltas {
                let choice = match delta.kind {
                    AttachmentDeltaKind::BothDiffer => AttachmentChoice::KeepBoth {
                        rename_override: None,
                    },
                    AttachmentDeltaKind::LocalOnly => AttachmentChoice::KeepLocal,
                    AttachmentDeltaKind::RemoteOnly => AttachmentChoice::KeepRemote,
                };
                attachment_choices.insert(delta.name.clone(), choice);
            }
            resolution
                .entry_attachment_choices
                .insert(conflict.entry_id, attachment_choices);
        }

        if conflict.icon_delta.is_some() {
            resolution
                .entry_icon_choices
                .insert(conflict.entry_id, ConflictSide::Local);
        }
    }

    for entry_id in &outcome.delete_edit_conflicts {
        resolution
            .delete_edit_choices
            .insert(*entry_id, DeleteEditChoice::KeepLocal);
    }

    resolution
}

/// Walk `group` looking for the entry with `id`; returns its title (a
/// clone) if found. Used by the delete-vs-edit restoration event.
fn find_entry_title(group: &Group, id: EntryId) -> Option<String> {
    for entry in &group.entries {
        if entry.id == id {
            return Some(entry.title.clone());
        }
    }
    for sub in &group.groups {
        if let Some(title) = find_entry_title(sub, id) {
            return Some(title);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Unit tests for the helpers. End-to-end hold-open behaviour lives in
// `tests/` (auto_merge.rs, icon_conflict_resolution.rs, …).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::EntryConflict;
    use keepass_core::model::Timestamps;
    use uuid::Uuid;

    fn entry_with_title(id: u128, title: &str) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
        e.title = title.into();
        e.times = Timestamps::default();
        e
    }

    use keepass_core::model::Entry;

    fn one_field_conflict(entry_id: EntryId, field_key: &str) -> MergeOutcome {
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local: entry_with_title(1, "L"),
            remote: entry_with_title(1, "R"),
            field_deltas: vec![crate::conflict::FieldDelta {
                key: field_key.into(),
                kind: crate::conflict::FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: vec![],
            icon_delta: None,
        });
        outcome
    }

    #[test]
    fn keep_local_resolution_keeps_local_for_every_field() {
        let id = EntryId(Uuid::from_u128(1));
        let outcome = one_field_conflict(id, "Title");
        let resolution = synthesize_keep_local_resolution(&outcome);
        assert_eq!(
            resolution.entry_field_choices[&id]["Title"],
            ConflictSide::Local,
            "hold-open keeps this side's own value — never the remote's",
        );
    }

    #[test]
    fn keep_local_resolution_keeps_local_for_password_too() {
        // No more sensitive-field special-casing of the *resolution* —
        // every facet is held the same way (keep local).
        let id = EntryId(Uuid::from_u128(1));
        let outcome = one_field_conflict(id, "Password");
        let resolution = synthesize_keep_local_resolution(&outcome);
        assert_eq!(
            resolution.entry_field_choices[&id]["Password"],
            ConflictSide::Local,
        );
    }

    #[test]
    fn keep_local_resolution_keeps_local_icon() {
        let id = EntryId(Uuid::from_u128(1));
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id: id,
            local: entry_with_title(1, "L"),
            remote: entry_with_title(1, "R"),
            field_deltas: vec![],
            attachment_deltas: vec![],
            icon_delta: Some(crate::conflict::IconDelta {
                local_custom_icon_uuid: Some(Uuid::from_u128(0x0a)),
                remote_custom_icon_uuid: Some(Uuid::from_u128(0x0b)),
            }),
        });
        let resolution = synthesize_keep_local_resolution(&outcome);
        assert_eq!(
            resolution.entry_icon_choices[&id],
            ConflictSide::Local,
            "icon conflict holds open — keep this side's icon, no uuid winner",
        );
    }

    #[test]
    fn sensitive_flag_fires_on_password_and_protected_fields() {
        let pw = one_field_conflict(EntryId(Uuid::from_u128(1)), "Password");
        assert!(is_sensitive_conflict(&pw.entry_conflicts[0]));

        let mut c = EntryConflict {
            entry_id: EntryId(Uuid::from_u128(1)),
            local: entry_with_title(1, "L"),
            remote: entry_with_title(1, "R"),
            field_deltas: vec![crate::conflict::FieldDelta {
                key: "ApiToken".into(),
                kind: crate::conflict::FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: vec![],
            icon_delta: None,
        };
        c.local
            .custom_fields
            .push(keepass_core::model::CustomField::new("ApiToken", "x", true));
        assert!(is_sensitive_conflict(&c));

        let plain = one_field_conflict(EntryId(Uuid::from_u128(1)), "Title");
        assert!(!is_sensitive_conflict(&plain.entry_conflicts[0]));
    }

    #[test]
    fn delete_edit_conflict_resolves_to_keep_local() {
        let entry_id = EntryId(Uuid::from_u128(7));
        let mut outcome = MergeOutcome::default();
        outcome.delete_edit_conflicts.push(entry_id);
        let resolution = synthesize_keep_local_resolution(&outcome);
        assert_eq!(
            resolution.delete_edit_choices.get(&entry_id).copied(),
            Some(DeleteEditChoice::KeepLocal),
        );
    }
}
