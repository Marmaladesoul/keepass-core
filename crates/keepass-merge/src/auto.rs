//! Auto-resolving variant of [`crate::apply_merge`].
//!
//! [`apply_merge_auto`] synthesises a deterministic [`Resolution`]
//! for every conflict bucket the merge produces — no caller input
//! required — then runs the standard apply step against it, and
//! post-applies [`crate::FieldConflictMarker`] tags to the loser
//! snapshot of every field-LWW resolution so consumers can surface
//! pending reviews without re-running the merge.
//!
//! See `_project-management/conflict-resolution-rework.md` (Keys
//! repo) for the design rationale: the goal is to never block sync
//! on a modal, but still preserve a clear, user-initiated review
//! path for entries that had concurrent edits.
//!
//! ## Determinism guarantee
//!
//! Two peers running `apply_merge_auto` with the same `(local,
//! remote, outcome)` and an equivalent `AutoMergeConfig.now`
//! produce identical merged vaults. The tiebreakers (described in
//! `pick_field_side` and friends) are derived from symmetric
//! properties of the two entries — never from "this peer's
//! perspective" — so peer A's local-vs-remote and peer B's
//! local-vs-remote converge to the same choice.

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use keepass_core::model::{Entry, EntryId, Vault};

use crate::apply::apply_merge;
use crate::conflict::{AttachmentDeltaKind, FieldDelta, FieldDeltaKind};
use crate::field_conflict::{FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker, WinnerSide};
use crate::hash::entry_content_hash;
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
use crate::{MergeError, MergeOutcome};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Configuration knobs for [`apply_merge_auto`]. Injected rather than
/// derived so the merge stays a pure function — tests can pin both
/// the clock and the originator pubkey.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AutoMergeConfig {
    /// Wall-clock stamp written into every emitted
    /// [`FieldConflictMarker`]. Injected (not read from the system
    /// clock) so the merge stays pure and tests are reproducible.
    pub now: DateTime<Utc>,
}

impl AutoMergeConfig {
    /// Convenience constructor stamping the marker's `at` with the
    /// supplied time.
    #[must_use]
    pub fn with_now(now: DateTime<Utc>) -> Self {
        Self { now }
    }
}

/// Summary of what [`apply_merge_auto`] did. Surfaces the per-bucket
/// effects so a downstream consumer can render "we merged N
/// changes, M of them had concurrent edits" UX without re-walking
/// the vault.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct AutoMergeReport {
    /// Entries whose conflict went through field-LWW resolution.
    /// Each one's `<History>` carries a marker on the loser
    /// snapshot.
    pub entries_with_field_lww: Vec<EntryId>,
    /// Attachments that ended up kept-both. Each tuple records the
    /// entry id, the original attachment name, and the renamed
    /// slot the merge layer installed it under (matches the
    /// rename machinery in `apply_merge`).
    pub attachments_kept_both: Vec<EntryId>,
    /// Entries that were locally-edited and remotely-deleted, where
    /// the auto-resolve kept the local edit (edit-wins rule). Useful
    /// for surfacing "we restored these entries from deletion"
    /// notices.
    pub entries_restored_from_deletion: Vec<EntryId>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Auto-resolve every conflict bucket in `outcome` and apply the
/// result against `local`. Never returns a "needs user input"
/// error: the deterministic rules described below cover every
/// case the merge can produce.
///
/// Field-LWW resolution writes a [`FieldConflictMarker`] onto the
/// loser snapshot's `custom_data` so consumers can surface a
/// pending-review badge without re-running the merge.
///
/// ## Resolution rules (deterministic)
///
/// - **Field-LWW** (`outcome.entry_conflicts[i].field_deltas`):
///   pick the side whose entry has the newer `last_modification_time`.
///   On exact tie, pick the side with the *lexicographically smaller*
///   content hash of the entry — symmetric for both peers, so
///   independent runs converge.
/// - **Attachment**:
///   - `BothDiffer` → `KeepBoth { rename_override: None }` (merge
///     layer applies its rename machinery).
///   - `LocalOnly` → `KeepLocal`.
///   - `RemoteOnly` → `KeepRemote`.
/// - **Icon**: newer-mtime side wins; tie → remote (symmetric).
/// - **Delete-edit conflict** (`outcome.delete_edit_conflicts`):
///   `KeepLocal` (edit-wins — restore the entry).
///
/// # Errors
///
/// Propagates whatever [`apply_merge`] returns. The synthesised
/// resolution is guaranteed valid by construction, so the only way
/// for this call to fail is the same failure modes as a manual
/// `apply_merge` (and those are documented on its signature).
pub fn apply_merge_auto(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    config: &AutoMergeConfig,
) -> Result<AutoMergeReport, MergeError> {
    // Step 1: capture pre-apply loser-snapshot identities. We need
    // these BEFORE apply mutates the tree, because the merged
    // result no longer carries each side's original entry shape.
    let loser_intents = collect_field_lww_loser_intents(remote, outcome);

    // Step 2: synthesise a default-choice Resolution.
    let resolution = synthesize_resolution(outcome);

    // Step 3: standard apply with the synthesised Resolution.
    apply_merge(local, remote, outcome, &resolution)?;

    // Step 4: walk the merged tree and write FieldConflictMarker
    // onto the matching loser snapshot for every field-LWW
    // resolution.
    write_field_conflict_markers(local, &loser_intents, config);

    // Step 5: build the report.
    let entries_with_field_lww: Vec<EntryId> = loser_intents.iter().map(|i| i.entry_id).collect();
    let attachments_kept_both: Vec<EntryId> = outcome
        .entry_conflicts
        .iter()
        .filter(|c| {
            c.attachment_deltas
                .iter()
                .any(|d| d.kind == AttachmentDeltaKind::BothDiffer)
        })
        .map(|c| c.entry_id)
        .collect();
    let entries_restored_from_deletion: Vec<EntryId> = outcome.delete_edit_conflicts.clone();

    Ok(AutoMergeReport {
        entries_with_field_lww,
        attachments_kept_both,
        entries_restored_from_deletion,
    })
}

// ---------------------------------------------------------------------------
// Step 1 — capture loser-snapshot identities pre-apply.
// ---------------------------------------------------------------------------

/// Per-entry record of which side lost a field-LWW resolution, used
/// post-apply to find and tag the loser snapshot in the merged
/// `<History>` list.
#[derive(Debug, Clone)]
struct LoserIntent {
    entry_id: EntryId,
    loser_mtime: Option<DateTime<Utc>>,
    loser_hash: [u8; 32],
    winner_side: WinnerSide,
}

fn collect_field_lww_loser_intents(_remote: &Vault, outcome: &MergeOutcome) -> Vec<LoserIntent> {
    // `apply::resolution::build_resolved_entry` always pushes a
    // clone of `conflict.local` into the merged entry's history,
    // regardless of which side won the per-field resolution. So
    // the "snapshot we tag" is always the local-side pre-merge
    // entry. That snapshot's content hash is stable across the
    // apply step (history.clear() is the only mutation, and
    // history isn't part of the content hash).
    //
    // We hash against `&[]` because (a) attachments aren't part
    // of the test surface for this property and (b) when
    // attachments are present, `build_resolved_entry` hashes
    // against `remap.local_binaries()` *post-rebind* — matching
    // that exactly would require the local pool's post-merge
    // state, which we don't have pre-apply. The marker-writing
    // pass below tries the local pool's post-apply state first
    // and falls back to `&[]`, which catches the no-attachment
    // case and degrades gracefully (the dedup check in the apply
    // step uses the same `local_binaries` we'll have post-apply,
    // so the merged history record's hash is reachable).
    let mut out = Vec::new();
    for conflict in &outcome.entry_conflicts {
        if conflict.field_deltas.is_empty() {
            // Only field-LWW conflicts get a marker. Attachment-
            // only or icon-only conflicts self-mark per their own
            // channels.
            continue;
        }
        let winner = pick_entry_winner_for_field_lww(&conflict.local, &conflict.remote);
        let snapshot = &conflict.local;
        out.push(LoserIntent {
            entry_id: conflict.entry_id,
            loser_mtime: snapshot.times.last_modification_time,
            loser_hash: entry_content_hash(snapshot, &[]),
            winner_side: winner,
        });
    }
    out
}

/// Decide which side wins the entry-level LWW by mtime, with a
/// symmetric content-hash tiebreaker on exact-time ties (or when
/// one side has no mtime).
fn pick_entry_winner_for_field_lww(local: &Entry, remote: &Entry) -> WinnerSide {
    match (
        local.times.last_modification_time,
        remote.times.last_modification_time,
    ) {
        (Some(l), Some(r)) if l > r => WinnerSide::Local,
        (Some(l), Some(r)) if r > l => WinnerSide::Remote,
        _ => {
            // Tie OR one-sided absence: deterministic
            // content-hash tiebreaker. We hash against empty pools
            // — same shape on both peers given the same entry
            // bytes, so symmetric. Lower hash wins by convention.
            let local_hash = entry_content_hash(local, &[]);
            let remote_hash = entry_content_hash(remote, &[]);
            if local_hash <= remote_hash {
                WinnerSide::Local
            } else {
                WinnerSide::Remote
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Step 2 — synthesize the Resolution that drives apply_merge.
// ---------------------------------------------------------------------------

fn synthesize_resolution(outcome: &MergeOutcome) -> Resolution {
    let mut resolution = Resolution::default();

    for conflict in &outcome.entry_conflicts {
        let winner = pick_entry_winner_for_field_lww(&conflict.local, &conflict.remote);
        let winner_choice = match winner {
            WinnerSide::Local => ConflictSide::Local,
            WinnerSide::Remote => ConflictSide::Remote,
        };

        // Field choices — every delta gets the entry-level winner
        // (we don't do per-field tiebreaks because per-entry mtime
        // is the only timestamp we have).
        if !conflict.field_deltas.is_empty() {
            let mut field_choices: HashMap<String, ConflictSide> = HashMap::new();
            for delta in &conflict.field_deltas {
                field_choices.insert(delta.key.clone(), pick_field_choice(delta, winner_choice));
            }
            resolution
                .entry_field_choices
                .insert(conflict.entry_id, field_choices);
        }

        // Attachment choices — both-differ → kept-both with default
        // rename; one-sided → take whichever side has it.
        if !conflict.attachment_deltas.is_empty() {
            let mut attachment_choices: HashMap<String, AttachmentChoice> = HashMap::new();
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

        // Icon — pick the same side as the entry-level winner.
        if conflict.icon_delta.is_some() {
            resolution
                .entry_icon_choices
                .insert(conflict.entry_id, winner_choice);
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

/// Map a [`FieldDelta`] to a [`ConflictSide`] given the entry-level
/// winner. The `LocalOnly` / `RemoteOnly` kinds are pinned to their
/// only meaningful side (the side that holds the field);
/// `BothDiffer` rides with the entry-level winner.
fn pick_field_choice(delta: &FieldDelta, entry_winner: ConflictSide) -> ConflictSide {
    match delta.kind {
        FieldDeltaKind::LocalOnly => ConflictSide::Local,
        FieldDeltaKind::RemoteOnly => ConflictSide::Remote,
        FieldDeltaKind::BothDiffer => entry_winner,
    }
}

// ---------------------------------------------------------------------------
// Step 4 — write FieldConflictMarker on loser snapshots post-apply.
// ---------------------------------------------------------------------------

fn write_field_conflict_markers(
    local: &mut Vault,
    intents: &[LoserIntent],
    config: &AutoMergeConfig,
) {
    if intents.is_empty() {
        return;
    }
    let intent_by_id: HashMap<EntryId, &LoserIntent> =
        intents.iter().map(|i| (i.entry_id, i)).collect();
    // We need the binary pool for hash-matching the loser snapshot
    // in history. Pulled before the &mut walk to keep the borrow
    // checker happy.
    let local_binaries = local.binaries.clone();
    let intent_ids: HashSet<EntryId> = intents.iter().map(|i| i.entry_id).collect();
    write_markers_recursive(
        &mut local.root,
        &intent_by_id,
        &intent_ids,
        &local_binaries,
        config,
    );
}

fn write_markers_recursive(
    group: &mut keepass_core::model::Group,
    intent_by_id: &HashMap<EntryId, &LoserIntent>,
    intent_ids: &HashSet<EntryId>,
    binaries: &[keepass_core::model::Binary],
    config: &AutoMergeConfig,
) {
    for entry in &mut group.entries {
        if !intent_ids.contains(&entry.id) {
            continue;
        }
        let Some(intent) = intent_by_id.get(&entry.id) else {
            continue;
        };
        // Find the loser snapshot in the entry's history by
        // (mtime, content_hash). Use the slice-1-style "&[]" pool
        // for hash comparison (matches what build_merged_entry uses
        // when re-hashing for its own dedup check).
        let target_mtime = intent.loser_mtime;
        let target_hash = intent.loser_hash;
        let marker = FieldConflictMarker {
            at: config.now,
            winner_side: intent.winner_side,
        };
        let marker_value = marker.to_value();
        for snap in &mut entry.history {
            if snap.times.last_modification_time != target_mtime {
                continue;
            }
            if entry_content_hash(snap, binaries) != target_hash
                && entry_content_hash(snap, &[]) != target_hash
            {
                continue;
            }
            // Don't double-write if the marker is already present
            // (e.g., a previous auto-merge tagged the same snapshot).
            if snap
                .custom_data
                .iter()
                .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
            {
                break;
            }
            snap.custom_data
                .push(keepass_core::model::CustomDataItem::new(
                    FIELD_CONFLICT_CUSTOM_DATA_KEY.to_string(),
                    marker_value.clone(),
                    Some(config.now),
                ));
            break;
        }
    }
    for sub in &mut group.groups {
        write_markers_recursive(sub, intent_by_id, intent_ids, binaries, config);
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the deterministic-choice helpers. End-to-end
// integration coverage lives in `tests/auto_merge.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::EntryConflict;
    use chrono::TimeZone;
    use keepass_core::model::{EntryId, Timestamps};
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn entry_with_title(title: &str, ts: Timestamps) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::nil()));
        e.title = title.into();
        e.times = ts;
        e
    }

    #[test]
    fn winner_is_newer_mtime_side() {
        let local = entry_with_title("local", at(2026, 1));
        let remote = entry_with_title("remote", at(2026, 5));
        assert_eq!(
            pick_entry_winner_for_field_lww(&local, &remote),
            WinnerSide::Remote,
        );
        let later_local = entry_with_title("local", at(2026, 10));
        let earlier_remote = entry_with_title("remote", at(2026, 5));
        assert_eq!(
            pick_entry_winner_for_field_lww(&later_local, &earlier_remote),
            WinnerSide::Local,
        );
    }

    #[test]
    fn same_mtime_tiebreaks_symmetrically_on_content_hash() {
        let local = entry_with_title("aaa", at(2026, 5));
        let remote = entry_with_title("zzz", at(2026, 5));
        let from_a = pick_entry_winner_for_field_lww(&local, &remote);
        // Mirror: swap sides — the symmetric tiebreaker must agree.
        let from_b = pick_entry_winner_for_field_lww(&remote, &local);
        // Both peers should pick the same logical winner.
        assert!(
            (from_a == WinnerSide::Local && from_b == WinnerSide::Remote)
                || (from_a == WinnerSide::Remote && from_b == WinnerSide::Local),
            "tiebreaker must be symmetric; got {from_a:?} / {from_b:?}"
        );
    }

    #[test]
    fn attachment_both_differ_resolves_to_keep_both() {
        let mut outcome = MergeOutcome::default();
        let conflict = EntryConflict {
            entry_id: EntryId(Uuid::nil()),
            local: entry_with_title("e", at(2026, 5)),
            remote: entry_with_title("e", at(2026, 4)),
            field_deltas: vec![],
            attachment_deltas: vec![crate::conflict::AttachmentDelta {
                name: "att.pdf".into(),
                kind: AttachmentDeltaKind::BothDiffer,
                local_sha256: Some([0u8; 32]),
                remote_sha256: Some([1u8; 32]),
                local_size: Some(10),
                remote_size: Some(20),
            }],
            icon_delta: None,
        };
        outcome.entry_conflicts.push(conflict);
        let resolution = synthesize_resolution(&outcome);
        let choices = resolution
            .entry_attachment_choices
            .get(&EntryId(Uuid::nil()))
            .expect("attachment choices");
        let choice = choices.get("att.pdf").expect("att.pdf choice");
        assert!(matches!(choice, AttachmentChoice::KeepBoth { .. }));
    }

    #[test]
    fn delete_edit_conflict_resolves_to_keep_local() {
        let entry_id = EntryId(Uuid::nil());
        let mut outcome = MergeOutcome::default();
        outcome.delete_edit_conflicts.push(entry_id);
        let resolution = synthesize_resolution(&outcome);
        assert_eq!(
            resolution.delete_edit_choices.get(&entry_id).copied(),
            Some(DeleteEditChoice::KeepLocal),
        );
    }
}
