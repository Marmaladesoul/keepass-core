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
use crate::conflict::{AttachmentDeltaKind, EntryConflict};
use crate::field_conflict::{FIELD_CONFLICT_CUSTOM_DATA_KEY, FieldConflictMarker};
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice, Resolution};
use crate::{MergeError, MergeOutcome};

/// Standard `<String>` field name that always parks on disagreement
/// per spec §5.1 — silent password reversion is the worst-case
/// outcome of getting a 3-way merge wrong, so for this field we
/// deliberately keep BOTH sides for the user to review.
const PASSWORD_FIELD: &str = "Password";

/// Per-entry parking decision, derived from `(mtime, sensitive-field?)`
/// before we synthesise the [`Resolution`] for `apply_merge`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParkingDecision {
    /// Local won by mtime (or tied — tie falls to local pending the
    /// pubkey tiebreaker). `apply_merge` keeps local's field values;
    /// remote's pre-merge clone is pushed to history with the marker.
    WinnerLocal,
    /// Remote won by mtime. `apply_merge` takes remote's field values;
    /// local's pre-merge snapshot (which `build_resolved_entry` is
    /// about to push anyway) is tagged with the marker in place.
    WinnerRemote,
    /// One or more conflicting fields is Password or has the
    /// `Protected="True"` bit set on either side. Neither side wins
    /// outright — `apply_merge` arbitrarily keeps local (deterministic
    /// across peers given the same `(local, remote)` pair) and BOTH
    /// sides are parked into history with markers so the user reviews
    /// on equal footing per spec §5.1.
    BothSidesSensitive,
}

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
/// - **`entry_conflicts`**: PARKED with the spec §5.2 mtime-based
///   winner. The side with the more recent `last_modification_time`
///   takes the merged current state; the loser is pushed into history
///   tagged with the `FieldConflictMarker`. For the Password field —
///   and any custom field whose `Protected="True"` bit is set on
///   either side — spec §5.1 overrides: neither side wins, local is
///   kept arbitrarily for the current state, and BOTH sides land in
///   history with markers so the user reviews on equal footing.
///   The resolver UI surfaces parked entries via the
///   `FIELD_CONFLICT_CUSTOM_DATA_KEY` badge regardless of which side
///   currently materialises on disk.
/// - **`delete_edit_conflicts`**: edit-wins rule —
///   `DeleteEditChoice::KeepLocal`. Local entry is preserved.
///   Reported in `entries_restored_from_deletion` for downstream UX
///   that wants to surface "we kept your edits across a remote
///   deletion."
///
/// ## Tied mtime
///
/// When both sides share the same sub-second-resolution
/// `last_modification_time` for a non-sensitive conflict, the spec
/// calls for a pubkey-based tiebreaker (per the rework spec §6).
/// **TODO(PR-4):** wire account-identity pubkeys through to here.
/// Until then, tied mtime falls back to Local — deterministic per
/// peer, but doesn't fully converge across peers in the rare tied
/// case. Convergence in that case requires the user to resolve via
/// the parked-conflict UI (each peer surfaces the conflict
/// independently); the resolution propagates via the standard
/// history-tombstone path.
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
    // Decide per-entry winner up front. The same decisions feed both
    // the Resolution we hand to apply_merge (who wins the current
    // state) and the post-apply parking step (whose pre-merge snapshot
    // gets the marker — and whether to park both sides for the
    // sensitive-field case).
    let decisions = parking_decisions(outcome);

    // Spec §6 always-info: one event per parked entry for the activity
    // log + badge. Emit before apply mutates the tree so the events
    // reference the pre-merge state.
    for conflict in &outcome.entry_conflicts {
        let sensitive = matches!(
            decisions.get(&conflict.entry_id),
            Some(ParkingDecision::BothSidesSensitive)
        );
        crate::events::emit(&crate::MergeEvent::ConflictParked {
            entry: conflict.entry_id,
            title: conflict.local.title.clone(),
            fields: conflict
                .field_deltas
                .iter()
                .map(|d| d.key.clone())
                .collect(),
            sensitive,
        });
    }
    // Edit-wins on delete-vs-edit fires as its own event. Title for
    // the prose comes from whichever side actually carries the edit —
    // local (asymmetric: local edited, remote deleted) or remote
    // (symmetric: local deleted, remote edited).
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

    // Step 1: synthesise a Resolution that picks the winner per
    // decision. apply_merge then materialises the winner's field
    // values onto the merged entry.
    let resolution = synthesize_mtime_based_resolution(outcome, &decisions);

    // Step 2: standard apply with the synthesised Resolution.
    apply_merge(local, remote, outcome, &resolution)?;

    // Step 3: AFTER apply has settled the merged tree, push or in-place
    // tag the loser-side snapshot(s) with the field-conflict marker.
    // Parking must happen post-apply because
    // `apply::resolution::build_resolved_entry` reconstructs each
    // conflicted entry from the captured `conflict.local` snapshot —
    // anything we'd injected pre-apply would be wiped by the
    // `replace_entry` call.
    park_conflict_snapshots(local, remote, outcome, &decisions, config);

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
// Parking decisions — mtime-based winner with sensitive-field detection.
// ---------------------------------------------------------------------------

fn parking_decisions(
    outcome: &MergeOutcome,
) -> std::collections::HashMap<EntryId, ParkingDecision> {
    outcome
        .entry_conflicts
        .iter()
        .map(|c| (c.entry_id, decide_one(c)))
        .collect()
}

fn decide_one(conflict: &EntryConflict) -> ParkingDecision {
    if is_sensitive_conflict(conflict) {
        return ParkingDecision::BothSidesSensitive;
    }
    match mtime_winner(&conflict.local, &conflict.remote) {
        ConflictSide::Local => ParkingDecision::WinnerLocal,
        ConflictSide::Remote => ParkingDecision::WinnerRemote,
    }
}

/// Spec §5.1: the Password field (and any custom field with
/// `Protected="True"` on either side) always parks BOTH sides instead
/// of picking a winner. Silent password reversion is the worst-case
/// outcome of getting the 3-way merge wrong; the cost of asking the
/// user to confirm is acceptable.
fn is_sensitive_conflict(conflict: &EntryConflict) -> bool {
    for delta in &conflict.field_deltas {
        if delta.key == PASSWORD_FIELD {
            return true;
        }
        // Custom field: check either side's `protected` bit. Either
        // side asserting protection is enough — the bit is the user's
        // signal that the value is sensitive.
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

/// Spec §5.2: winner = side with the more recent
/// `last_modification_time`. On a tie (sub-second equal), the spec
/// calls for a pubkey-based tiebreaker per the rework spec §6.
/// **TODO(PR-4):** wire account-identity pubkeys through to here.
/// Until then, tied-mtime falls back to Local — deterministic from
/// each peer's own perspective, even though it doesn't converge
/// across peers in the tied case. Convergence in that case requires
/// the user to resolve via the parked-conflict UI (which both peers
/// will surface independently); the resolution then propagates via
/// the standard history-tombstone path.
fn mtime_winner(local: &Entry, remote: &Entry) -> ConflictSide {
    let l = local.times.last_modification_time;
    let r = remote.times.last_modification_time;
    match (l, r) {
        (Some(l), Some(r)) if l > r => ConflictSide::Local,
        (Some(l), Some(r)) if r > l => ConflictSide::Remote,
        // Tied (sub-second-equal) → TODO(PR-4) pubkey tiebreaker. Local
        // falls out as the default. We also fold the
        // (Some/None) + (None/None) cases into this arm: any concrete
        // mtime is newer than unknown, so local wins when only local
        // has one and the both-None fallback also goes to local.
        (Some(_) | None, None) | (Some(_), Some(_)) => ConflictSide::Local,
        (None, Some(_)) => ConflictSide::Remote,
    }
}

// ---------------------------------------------------------------------------
// Step 1 — park remote-side conflict entries as marked history records.
// ---------------------------------------------------------------------------

fn park_conflict_snapshots(
    local: &mut Vault,
    _remote: &Vault,
    outcome: &MergeOutcome,
    decisions: &std::collections::HashMap<EntryId, ParkingDecision>,
    config: &ParkConflictsConfig,
) {
    if outcome.entry_conflicts.is_empty() {
        return;
    }
    // EntryConflict already carries both `local` and `remote: Entry`
    // in full — no need to re-walk `_remote`. The decision per entry
    // controls *which* snapshot(s) get the marker:
    //
    // - `WinnerLocal`: park the remote loser → push a fresh
    //   remote-clone with marker into local's history.
    // - `WinnerRemote`: park the local loser → `build_resolved_entry`
    //   already pushed a local-pre-merge snapshot into history without
    //   a marker; find it by mtime and tag in place. Avoids a duplicate
    //   `(mtime, content)` history record that the next round's
    //   `merge_histories` would dedup (and might lose the marker on).
    // - `BothSidesSensitive`: park both. `apply_merge` kept local
    //   arbitrarily; the local-snapshot it pushed gets the marker in
    //   place; a fresh remote-clone is pushed with marker too.
    let marker_value = FieldConflictMarker { at: config.now }.to_value();
    let marker_now = Some(config.now);
    for conflict in &outcome.entry_conflicts {
        let Some(local_entry) = find_entry_mut(&mut local.root, conflict.entry_id) else {
            continue;
        };
        let decision = decisions
            .get(&conflict.entry_id)
            .copied()
            .unwrap_or(ParkingDecision::WinnerLocal);
        match decision {
            ParkingDecision::WinnerLocal => {
                push_marker_clone(local_entry, &conflict.remote, &marker_value, marker_now);
            }
            ParkingDecision::WinnerRemote => {
                // The loser snapshot — local's pre-merge — was pushed
                // into history by `build_resolved_entry`. Tag it in
                // place. If the find-by-mtime probe misses (unlikely),
                // fall through to a fresh push as a defensive belt.
                if !tag_existing_snapshot_at_mtime(
                    local_entry,
                    conflict.local.times.last_modification_time,
                    &marker_value,
                    marker_now,
                ) {
                    push_marker_clone(local_entry, &conflict.local, &marker_value, marker_now);
                }
            }
            ParkingDecision::BothSidesSensitive => {
                // Tag the local snapshot pushed by `build_resolved_entry`
                // (or push a fresh local-clone if the probe misses,
                // again as a belt). Then push the remote-clone with
                // marker so both sides have a marked record.
                if !tag_existing_snapshot_at_mtime(
                    local_entry,
                    conflict.local.times.last_modification_time,
                    &marker_value,
                    marker_now,
                ) {
                    push_marker_clone(local_entry, &conflict.local, &marker_value, marker_now);
                }
                push_marker_clone(local_entry, &conflict.remote, &marker_value, marker_now);
            }
        }
    }
}

/// Push a marker-tagged clone of `source` into `entry.history`,
/// guarding against double-parking at the same mtime if a marker is
/// already present.
fn push_marker_clone(
    entry: &mut Entry,
    source: &Entry,
    marker_value: &str,
    marker_now: Option<DateTime<Utc>>,
) {
    let mtime = source.times.last_modification_time;
    // Idempotence: if a marker-tagged record already exists at this
    // mtime, the entry has already been parked this round.
    if entry.history.iter().any(|h| {
        h.times.last_modification_time == mtime
            && h.custom_data
                .iter()
                .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
    }) {
        return;
    }
    let mut parked = source.clone();
    // KDBX history records never nest their own history.
    parked.history.clear();
    parked.custom_data.push(CustomDataItem::new(
        FIELD_CONFLICT_CUSTOM_DATA_KEY.to_string(),
        marker_value.to_string(),
        marker_now,
    ));
    entry.history.push(parked);
}

/// Find an existing history record at `mtime` that doesn't already
/// carry the marker, and add the marker to its `custom_data`. Returns
/// `true` if a record was tagged; `false` if no candidate was found.
///
/// We match on mtime alone (no content-hash check) because the only
/// situation this is called for is the loser-side snapshot the apply
/// step just pushed: there's no other history record at that mtime in
/// practice. A future content-hash refinement would harden against the
/// pathological case of an unrelated history record with a colliding
/// mtime, but for entry-level conflicts that scenario isn't reachable
/// from the apply flow.
fn tag_existing_snapshot_at_mtime(
    entry: &mut Entry,
    mtime: Option<DateTime<Utc>>,
    marker_value: &str,
    marker_now: Option<DateTime<Utc>>,
) -> bool {
    let Some(target) = entry.history.iter_mut().find(|h| {
        h.times.last_modification_time == mtime
            && !h
                .custom_data
                .iter()
                .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
    }) else {
        return false;
    };
    target.custom_data.push(CustomDataItem::new(
        FIELD_CONFLICT_CUSTOM_DATA_KEY.to_string(),
        marker_value.to_string(),
        marker_now,
    ));
    true
}

/// Walk `group` looking for the entry with `id`; returns its title
/// (a clone) if found. Used by the activity-log emission for the
/// delete-vs-edit restoration prose.
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

fn synthesize_mtime_based_resolution(
    outcome: &MergeOutcome,
    decisions: &std::collections::HashMap<EntryId, ParkingDecision>,
) -> Resolution {
    let mut resolution = Resolution::default();

    for conflict in &outcome.entry_conflicts {
        let decision = decisions
            .get(&conflict.entry_id)
            .copied()
            .unwrap_or(ParkingDecision::WinnerLocal);
        // Per-field: pick the winner per the parking decision. For
        // `BothSidesSensitive` (Password / `Protected="True"`) we
        // arbitrarily keep local so the current state stays
        // deterministic across peers given the same `(local, remote)`
        // pair — the spec doesn't pick a winner here, but the file has
        // to have *some* value in it, so we pin one and rely on the
        // both-sides parking to surface the alternative for review.
        let side_for_fields = match decision {
            ParkingDecision::WinnerLocal | ParkingDecision::BothSidesSensitive => {
                ConflictSide::Local
            }
            ParkingDecision::WinnerRemote => ConflictSide::Remote,
        };
        if !conflict.field_deltas.is_empty() {
            let mut field_choices = std::collections::HashMap::new();
            for delta in &conflict.field_deltas {
                field_choices.insert(delta.key.clone(), side_for_fields);
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

    fn one_conflict(
        entry_id: EntryId,
        local: Entry,
        remote: Entry,
        field_key: &str,
    ) -> MergeOutcome {
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local,
            remote,
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
    fn mtime_winner_picks_newer_side() {
        let l = entry_with_title(1, "L", at(2026, 5));
        let r = entry_with_title(1, "R", at(2026, 4));
        assert_eq!(mtime_winner(&l, &r), ConflictSide::Local);
        assert_eq!(mtime_winner(&r, &l), ConflictSide::Remote);
    }

    #[test]
    fn mtime_winner_ties_fall_to_local_until_pubkey_tiebreaker_lands() {
        // TODO(PR-4): once account pubkeys are wired, replace this with
        // a pubkey-comparison check.
        let same = at(2026, 5);
        let l = entry_with_title(1, "L", same.clone());
        let r = entry_with_title(1, "R", same);
        assert_eq!(mtime_winner(&l, &r), ConflictSide::Local);
    }

    #[test]
    fn sensitive_detection_fires_on_password_field() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let outcome = one_conflict(
            entry_id,
            entry_with_title(1, "L", at(2026, 5)),
            entry_with_title(1, "R", at(2026, 4)),
            "Password",
        );
        assert!(matches!(
            decide_one(&outcome.entry_conflicts[0]),
            ParkingDecision::BothSidesSensitive
        ));
    }

    #[test]
    fn sensitive_detection_fires_on_protected_custom_field() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let mut local = entry_with_title(1, "L", at(2026, 5));
        let mut remote = entry_with_title(1, "R", at(2026, 4));
        // Custom field with Protected=true on local only — either-side
        // assertion is enough.
        local
            .custom_fields
            .push(keepass_core::model::CustomField::new(
                "ApiToken",
                "local-val",
                true,
            ));
        remote
            .custom_fields
            .push(keepass_core::model::CustomField::new(
                "ApiToken",
                "remote-val",
                false,
            ));
        let outcome = one_conflict(entry_id, local, remote, "ApiToken");
        assert!(matches!(
            decide_one(&outcome.entry_conflicts[0]),
            ParkingDecision::BothSidesSensitive
        ));
    }

    #[test]
    fn non_sensitive_field_decision_follows_mtime_winner() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let outcome = one_conflict(
            entry_id,
            entry_with_title(1, "L", at(2026, 5)),
            entry_with_title(1, "R", at(2026, 4)),
            "Title",
        );
        assert!(matches!(
            decide_one(&outcome.entry_conflicts[0]),
            ParkingDecision::WinnerLocal
        ));

        let outcome = one_conflict(
            entry_id,
            entry_with_title(1, "L", at(2026, 4)),
            entry_with_title(1, "R", at(2026, 5)),
            "Title",
        );
        assert!(matches!(
            decide_one(&outcome.entry_conflicts[0]),
            ParkingDecision::WinnerRemote
        ));
    }

    #[test]
    fn synthesized_resolution_uses_decided_winner_per_entry() {
        let entry_id = EntryId(Uuid::from_u128(1));
        // Remote newer → ConflictSide::Remote.
        let outcome = one_conflict(
            entry_id,
            entry_with_title(1, "L", at(2026, 4)),
            entry_with_title(1, "R", at(2026, 5)),
            "Title",
        );
        let decisions = parking_decisions(&outcome);
        let resolution = synthesize_mtime_based_resolution(&outcome, &decisions);
        assert_eq!(
            resolution.entry_field_choices[&entry_id]["Title"],
            ConflictSide::Remote
        );
    }

    #[test]
    fn sensitive_resolution_keeps_local_arbitrarily() {
        let entry_id = EntryId(Uuid::from_u128(1));
        // Remote newer, BUT Password field → arbitrary local + both
        // parked.
        let outcome = one_conflict(
            entry_id,
            entry_with_title(1, "L", at(2026, 4)),
            entry_with_title(1, "R", at(2026, 5)),
            "Password",
        );
        let decisions = parking_decisions(&outcome);
        let resolution = synthesize_mtime_based_resolution(&outcome, &decisions);
        assert_eq!(
            resolution.entry_field_choices[&entry_id]["Password"],
            ConflictSide::Local
        );
    }

    #[test]
    fn synthesized_resolution_keeps_local_when_local_newer() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(EntryConflict {
            entry_id,
            local: entry_with_title(1, "L", at(2026, 5)),
            remote: entry_with_title(1, "R", at(2026, 4)),
            field_deltas: vec![crate::conflict::FieldDelta {
                key: "Title".into(),
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
        let decisions = parking_decisions(&outcome);
        let resolution = synthesize_mtime_based_resolution(&outcome, &decisions);
        assert_eq!(
            resolution.entry_field_choices[&entry_id]["Title"],
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
        let decisions = parking_decisions(&outcome);
        let resolution = synthesize_mtime_based_resolution(&outcome, &decisions);
        assert_eq!(
            resolution.delete_edit_choices.get(&entry_id).copied(),
            Some(DeleteEditChoice::KeepLocal),
        );
    }

    #[test]
    fn parking_winner_local_pushes_remote_clone_with_marker() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let local_entry = entry_with_title(1, "local-title", at(2026, 5));
        let remote_entry = entry_with_title(1, "remote-title", at(2026, 4));

        let mut local = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        local.root.entries.push(local_entry.clone());
        let mut remote = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        remote.root.entries.push(remote_entry.clone());

        let outcome = one_conflict(entry_id, local_entry, remote_entry, "Title");
        let decisions = parking_decisions(&outcome);
        park_conflict_snapshots(
            &mut local,
            &remote,
            &outcome,
            &decisions,
            &ParkConflictsConfig::with_now(now()),
        );

        let entry = &local.root.entries[0];
        assert_eq!(entry.title, "local-title", "current state untouched");
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
    fn parking_winner_remote_tags_existing_local_snapshot_in_place() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let local_entry = entry_with_title(1, "local-title", at(2026, 4));
        let remote_entry = entry_with_title(1, "remote-title", at(2026, 5));

        // Simulate the post-apply state where `build_resolved_entry`
        // has overlaid remote's fields onto local and pushed a local-
        // pre-merge snapshot into history.
        let mut local_post_apply = local_entry.clone();
        local_post_apply.title = remote_entry.title.clone();
        // local-pre-merge snapshot (no marker yet) at local's mtime.
        local_post_apply.history.push(local_entry.clone());

        let mut local = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        local.root.entries.push(local_post_apply);
        let mut remote = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        remote.root.entries.push(remote_entry.clone());

        let outcome = one_conflict(entry_id, local_entry, remote_entry, "Title");
        let decisions = parking_decisions(&outcome);
        park_conflict_snapshots(
            &mut local,
            &remote,
            &outcome,
            &decisions,
            &ParkConflictsConfig::with_now(now()),
        );

        let entry = &local.root.entries[0];
        // Exactly one history record — the one apply pushed, now
        // tagged in place (no duplicate at the same mtime).
        assert_eq!(entry.history.len(), 1);
        assert_eq!(
            entry.history[0].title, "local-title",
            "tagged snapshot is local's pre-merge"
        );
        assert!(
            entry.history[0]
                .custom_data
                .iter()
                .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY),
            "marker added in place"
        );
    }

    #[test]
    fn parking_sensitive_marks_both_sides() {
        let entry_id = EntryId(Uuid::from_u128(1));
        let local_entry = entry_with_title(1, "local-title", at(2026, 4));
        let remote_entry = entry_with_title(1, "remote-title", at(2026, 5));

        // Sensitive path keeps local arbitrarily, so the post-apply
        // state is the local entry (no field overlay) but with the
        // local-pre-merge already in history (build_resolved_entry's
        // snapshot push). Apply could push it identical to current.
        let mut local_post_apply = local_entry.clone();
        local_post_apply.history.push(local_entry.clone());

        let mut local = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        local.root.entries.push(local_post_apply);
        let mut remote = Vault::empty(keepass_core::model::GroupId(Uuid::nil()));
        remote.root.entries.push(remote_entry.clone());

        let outcome = one_conflict(entry_id, local_entry, remote_entry, "Password");
        let decisions = parking_decisions(&outcome);
        park_conflict_snapshots(
            &mut local,
            &remote,
            &outcome,
            &decisions,
            &ParkConflictsConfig::with_now(now()),
        );

        let entry = &local.root.entries[0];
        // Local snapshot tagged in place + remote-clone pushed with
        // marker → two marker-tagged history records.
        let marker_count = entry
            .history
            .iter()
            .filter(|h| {
                h.custom_data
                    .iter()
                    .any(|cd| cd.key == FIELD_CONFLICT_CUSTOM_DATA_KEY)
            })
            .count();
        assert_eq!(
            marker_count, 2,
            "sensitive parking writes a marker on both sides"
        );
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
        let outcome = one_conflict(entry_id, local_entry, remote_entry, "Title");
        let decisions = parking_decisions(&outcome);
        let config = ParkConflictsConfig::with_now(now());
        park_conflict_snapshots(&mut local, &remote, &outcome, &decisions, &config);
        park_conflict_snapshots(&mut local, &remote, &outcome, &decisions, &config);
        // Second call must not duplicate the marker — same
        // `(mtime, marker-key)` already present.
        assert_eq!(local.root.entries[0].history.len(), 1);
    }
}
