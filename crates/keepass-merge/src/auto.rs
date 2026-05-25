//! Non-blocking conflict-parking variant of [`crate::apply_merge`].
//!
//! [`apply_merge_park_conflicts`] applies every non-conflicting
//! change from a merge outcome to the local vault, and **parks** the
//! genuine conflicts that keepass-merge's three-way classifier
//! flagged for human review — by pushing a clone of the remote-side
//! entry into local's `<History>` with a [`FieldConflictMarker`]
//! tagged on its `custom_data`. Local's *current* state for the
//! conflicting entry is left untouched.
//!
//! Sync no longer blocks on a modal. Conflicting entries get parked
//! in the vault file itself, surface as a vault-tile warning via the
//! per-vault `entries_with_parked_conflict` query, and are resolved
//! when the user clicks into the resolver — at which point the user
//! picks per-field winners + the marker history record is tombstoned
//! to clear the badge.
//!
//! ## What this DOESN'T do
//!
//! It does **not** auto-resolve conflicts via LWW or any other
//! per-side picking rule. The existing three-way merge already
//! handles the "one side changed off the LCA" case (auto-resolves
//! silently). The cases this function parks are the cases the
//! merge crate correctly identified as needing human input —
//! genuine "both sides edited the same field off a shared
//! ancestor." Silently picking between two real user edits would
//! lose data; we don't do that.
//!
//! See `_project-management/conflict-resolution-rework.md` (Keys
//! repo) for the broader design rationale.

use chrono::{DateTime, Utc};
use keepass_core::model::{CustomDataItem, Entry, EntryId, Group, Vault};

use crate::apply::apply_merge;
use crate::conflict::AttachmentDeltaKind;
use crate::field_conflict::{FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker};
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
use crate::{MergeError, MergeOutcome};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration knobs for [`apply_merge_park_conflicts`]. Injected
/// rather than derived so the merge stays a pure function — tests
/// can pin the clock.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParkConflictsConfig {
    /// Wall-clock stamp written into every emitted
    /// [`FieldConflictMarker`]. Injected (not read from the system
    /// clock) so the merge stays pure and tests are reproducible.
    pub now: DateTime<Utc>,
}

impl ParkConflictsConfig {
    /// Convenience constructor stamping markers with the supplied time.
    #[must_use]
    pub fn with_now(now: DateTime<Utc>) -> Self {
        Self { now }
    }
}

/// Summary of what [`apply_merge_park_conflicts`] did. Lets a
/// downstream consumer render "we merged N changes, M had concurrent
/// edits and were parked for your review" UX without re-walking the
/// vault.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct ParkedConflictsReport {
    /// Entries whose conflict was parked — each one's `<History>`
    /// now carries a marked snapshot of the remote-side state.
    pub entries_with_parked_conflict: Vec<EntryId>,
    /// Entries that the remote side tombstoned but local had
    /// continued editing; we restored local's edit (edit-wins
    /// rule) and parked the remote-tombstone intent as a marker on
    /// the local-snapshot pushed by apply_merge's standard
    /// resolution path.
    pub entries_restored_from_deletion: Vec<EntryId>,
    /// Entries where the merge identified attachment-both-differ
    /// situations. These ride the merge's standard
    /// `KeepBoth { rename_override: None }` rename machinery and
    /// don't need parking — listed for telemetry / UX completeness.
    pub attachments_kept_both: Vec<EntryId>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Apply `outcome` to `local`, parking every genuine conflict the
/// merge identified. Returns a [`ParkedConflictsReport`] summarising
/// the per-bucket effects.
///
/// ## Behaviour per bucket
///
/// - **`disk_only_changes`, `local_only_changes`, `added_on_disk`,
///   `deleted_on_disk`, `local_deletions_pending_sync`**: applied
///   as-is by the underlying [`apply_merge`] call. These represent
///   non-conflicting changes the existing three-way classifier
///   auto-resolved.
/// - **`entry_conflicts`**: PARKED. Local's current state is left
///   untouched. A clone of `conflict.remote` is pushed into the
///   matching local entry's `<History>` with a `FieldConflictMarker`
///   tagged on its `custom_data`. The synthesised [`Resolution`] used
///   for `apply_merge` picks `ConflictSide::Local` for every
///   field / attachment / icon choice on these entries — so the
///   apply step is effectively a no-op for their main state, beyond
///   the standard local-snapshot push the apply path always does.
/// - **`delete_edit_conflicts`**: edit-wins rule —
///   `DeleteEditChoice::KeepLocal`. Local entry is preserved.
///   Reported in `entries_restored_from_deletion` for downstream UX
///   that wants to surface "we kept your edits across a remote
///   deletion."
///
/// ## What this does NOT do
///
/// It does **not** auto-resolve content in entries the existing
/// three-way merge flagged as conflicts. The merge's classification
/// is preserved bit-for-bit; the rework is purely about how
/// conflicts are *surfaced* (parked in history vs. blocking on a
/// modal), not how they're *resolved* (still up to the user).
///
/// # Errors
///
/// Propagates whatever [`apply_merge`] returns. The synthesised
/// resolution is guaranteed valid by construction.
pub fn apply_merge_park_conflicts(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    config: &ParkConflictsConfig,
) -> Result<ParkedConflictsReport, MergeError> {
    // Step 1: synthesise a Resolution that picks Local for every
    // conflict choice. apply_merge then leaves conflicting
    // entries' main fields unchanged.
    let resolution = synthesize_keep_local_resolution(outcome);

    // Step 2: standard apply with the synthesised Resolution.
    apply_merge(local, remote, outcome, &resolution)?;

    // Step 3: AFTER apply has settled the merged tree, push a
    // marked clone of each conflict's remote entry into local's
    // matching entry's history. Parking must happen post-apply
    // because `apply::resolution::build_resolved_entry`
    // reconstructs each conflicted entry from the captured
    // `conflict.local` snapshot — anything we'd injected
    // pre-apply would be wiped by the `replace_entry` call.
    park_conflict_snapshots(local, remote, outcome, config);

    // Step 4: assemble the report.
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

// ---------------------------------------------------------------------------
// Step 1 — park remote-side conflict entries as marked history records.
// ---------------------------------------------------------------------------

fn park_conflict_snapshots(
    local: &mut Vault,
    _remote: &Vault,
    outcome: &MergeOutcome,
    config: &ParkConflictsConfig,
) {
    if outcome.entry_conflicts.is_empty() {
        return;
    }
    // EntryConflict already carries `remote: Entry` in full — no
    // need to re-walk `_remote` to find it. We just need to find
    // each conflict's matching local entry and push a clone with
    // the marker.
    let marker_value = FieldConflictMarker { at: config.now }.to_value();
    let marker_now = Some(config.now);
    for conflict in &outcome.entry_conflicts {
        let Some(local_entry) = find_entry_mut(&mut local.root, conflict.entry_id) else {
            continue;
        };
        let mut parked = conflict.remote.clone();
        // KDBX history records never nest their own history.
        parked.history.clear();
        // Don't double-park if the same `(mtime, content)` snapshot
        // is already marker-tagged in local's history.
        if local_entry.history.iter().any(|h| {
            h.times.last_modification_time == parked.times.last_modification_time
                && h.custom_data
                    .iter()
                    .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
        }) {
            continue;
        }
        parked.custom_data.push(CustomDataItem::new(
            FIELD_CONFLICT_CUSTOM_DATA_KEY.to_string(),
            marker_value.clone(),
            marker_now,
        ));
        local_entry.history.push(parked);
    }
}

fn find_entry_mut(group: &mut Group, id: EntryId) -> Option<&mut Entry> {
    if let Some(idx) = group.entries.iter().position(|e| e.id == id) {
        return Some(&mut group.entries[idx]);
    }
    for sub in &mut group.groups {
        if let Some(e) = find_entry_mut(sub, id) {
            return Some(e);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Step 2 — synthesize a "keep local everywhere" Resolution.
// ---------------------------------------------------------------------------

fn synthesize_keep_local_resolution(outcome: &MergeOutcome) -> Resolution {
    let mut resolution = Resolution::default();

    for conflict in &outcome.entry_conflicts {
        // Per-field: every delta gets ConflictSide::Local. One-sided
        // deltas pin to their only meaningful side anyway (a
        // RemoteOnly field can't be "Local" — there's nothing to
        // take); apply's `set_field_from` handles those by treating
        // Local as "field stays absent."
        if !conflict.field_deltas.is_empty() {
            let mut field_choices = std::collections::HashMap::new();
            for delta in &conflict.field_deltas {
                field_choices.insert(delta.key.clone(), ConflictSide::Local);
            }
            resolution
                .entry_field_choices
                .insert(conflict.entry_id, field_choices);
        }

        // Per-attachment: pick the side that holds the attachment
        // for one-sided deltas; KeepBoth for both-differ (apply's
        // rename machinery handles the per-entry name collision).
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

        // Icon: pick Local.
        if conflict.icon_delta.is_some() {
            resolution
                .entry_icon_choices
                .insert(conflict.entry_id, ConflictSide::Local);
        }
    }

    // Delete-edit: edit-wins rule.
    for entry_id in &outcome.delete_edit_conflicts {
        resolution
            .delete_edit_choices
            .insert(*entry_id, DeleteEditChoice::KeepLocal);
    }

    resolution
}

// ---------------------------------------------------------------------------
// Unit tests for the helpers. End-to-end integration tests live in
// `tests/parked_conflicts.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::{AttachmentDelta, EntryConflict};
    use chrono::TimeZone;
    use keepass_core::model::Timestamps;
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn entry_with_title(id: u128, title: &str, ts: Timestamps) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
        e.title = title.into();
        e.times = ts;
        e
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 25, 12, 0, 0).unwrap()
    }

    #[test]
    fn keep_local_resolution_assigns_local_for_every_choice_bucket() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local: entry_with_title(1, "L", at(2026, 5)),
            remote: entry_with_title(1, "R", at(2026, 4)),
            field_deltas: vec![crate::conflict::FieldDelta {
                key: "Password".into(),
                kind: crate::conflict::FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: vec![AttachmentDelta {
                name: "att.pdf".into(),
                kind: AttachmentDeltaKind::BothDiffer,
                local_sha256: Some([0u8; 32]),
                remote_sha256: Some([1u8; 32]),
                local_size: Some(10),
                remote_size: Some(20),
            }],
            icon_delta: None,
        });
        let resolution = synthesize_keep_local_resolution(&outcome);
        assert_eq!(
            resolution.entry_field_choices[&entry_id]["Password"],
            ConflictSide::Local
        );
        assert!(matches!(
            resolution.entry_attachment_choices[&entry_id]["att.pdf"],
            AttachmentChoice::KeepBoth { .. }
        ));
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

    #[test]
    fn parking_pushes_remote_with_marker_into_local_history() {
        // Build a one-entry local + remote vault and a synthetic
        // outcome with a single entry_conflict pointing at that
        // entry. After parking, local's entry's history should
        // contain a remote-equivalent snapshot tagged with the
        // marker key.
        let entry_id = EntryId(Uuid::from_u128(1));
        let local_entry = entry_with_title(1, "local-title", at(2026, 5));
        let remote_entry = entry_with_title(1, "remote-title", at(2026, 4));

        let mut local = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        local.root.entries.push(local_entry.clone());
        let mut remote = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        remote.root.entries.push(remote_entry.clone());

        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local: local_entry,
            remote: remote_entry,
            field_deltas: vec![crate::conflict::FieldDelta {
                key: "Title".into(),
                kind: crate::conflict::FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: vec![],
            icon_delta: None,
        });

        park_conflict_snapshots(
            &mut local,
            &remote,
            &outcome,
            &ParkConflictsConfig::with_now(now()),
        );

        let entry = &local.root.entries[0];
        // Current state untouched.
        assert_eq!(entry.title, "local-title");
        // Exactly one history record, carrying the marker.
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].title, "remote-title");
        let marker = entry.history[0]
            .custom_data
            .iter()
            .find(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
            .expect("marker present on parked snapshot");
        let parsed = FieldConflictMarker::from_value(&marker.value).expect("marker JSON parses");
        assert_eq!(parsed.at, now());
    }

    #[test]
    fn parking_is_idempotent_on_repeat_call() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let local_entry = entry_with_title(1, "local", at(2026, 5));
        let remote_entry = entry_with_title(1, "remote", at(2026, 4));
        let mut local = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        local.root.entries.push(local_entry.clone());
        let mut remote = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        remote.root.entries.push(remote_entry.clone());
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local: local_entry,
            remote: remote_entry,
            field_deltas: vec![],
            attachment_deltas: vec![],
            icon_delta: None,
        });
        let config = ParkConflictsConfig::with_now(now());
        park_conflict_snapshots(&mut local, &remote, &outcome, &config);
        park_conflict_snapshots(&mut local, &remote, &outcome, &config);
        // Second call must not duplicate the marker — same
        // `(mtime, marker-key)` already present.
        assert_eq!(local.root.entries[0].history.len(), 1);
    }
}
