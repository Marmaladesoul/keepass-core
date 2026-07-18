//! Caller-driven resolution-application helpers for `apply_merge`.
//!
//! Covers the conflict-resolution flow: validation of the
//! [`Resolution`] against the [`MergeOutcome`], then applying the
//! caller's per-entry / per-field / per-attachment / delete-edit
//! choices. The attachment-conflict path (which spans both the
//! caller-driven [`AttachmentChoice`] decisions and the
//! auto-resolution machinery from `entry_merge`) lives here too,
//! along with the small leaf helpers (`install_side`, `pick_rename`,
//! `rebind_history`) it relies on. Field-level read/copy/clear by KDBX
//! name lives in [`crate::field_access`].

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Binary, DeletedObject, Entry, EntryId, Group};
use uuid::Uuid;

use crate::binary_pool::BinaryPoolRemap;
use crate::conflict::{AttachmentDelta, AttachmentDeltaKind, EntryConflict, FieldDeltaKind};
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::field_access::{copy_field, remove_field};
use crate::hash::{entry_content_hash, sha256};
use crate::history_merge::merge_histories;
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice};
use crate::time::second_resolution;
use crate::tombstone::{
    parse_tombstones, tombstone_set, union_history_tombstones, write_tombstones_to_custom_data,
};
use crate::{MergeError, MergeOutcome, Resolution};

use super::{remove_entry, replace_entry};

/// Read-only walk of the resolution against the outcome. Returns the
/// first violation found (single-pass, first-violation-wins).
#[allow(clippy::too_many_lines)]
pub(super) fn validate_resolution(
    outcome: &MergeOutcome,
    resolution: &Resolution,
) -> Result<(), MergeError> {
    let conflict_ids: HashSet<EntryId> =
        outcome.entry_conflicts.iter().map(|c| c.entry_id).collect();
    let delete_edit_ids: HashSet<EntryId> = outcome.delete_edit_conflicts.iter().copied().collect();

    // 1. Every entry referenced in entry_field_choices must be in
    //    entry_conflicts; every key inside must be in that conflict's
    //    field_deltas.
    for (entry_id, field_choices) in &resolution.entry_field_choices {
        let Some(conflict) = outcome
            .entry_conflicts
            .iter()
            .find(|c| c.entry_id == *entry_id)
        else {
            return Err(MergeError::UnknownEntryInResolution { entry: *entry_id });
        };
        let known_fields: HashSet<&str> = conflict
            .field_deltas
            .iter()
            .map(|d| d.key.as_str())
            .collect();
        for field_key in field_choices.keys() {
            if !known_fields.contains(field_key.as_str()) {
                return Err(MergeError::UnknownFieldInResolution {
                    entry: *entry_id,
                    field: field_key.clone(),
                });
            }
        }
    }

    // 2. Every entry referenced in entry_attachment_choices must be
    //    in entry_conflicts; every attachment name inside must be in
    //    that conflict's attachment_deltas; KeepBoth choices must
    //    correspond to BothDiffer deltas.
    for (entry_id, attachment_choices) in &resolution.entry_attachment_choices {
        let Some(conflict) = outcome
            .entry_conflicts
            .iter()
            .find(|c| c.entry_id == *entry_id)
        else {
            return Err(MergeError::UnknownEntryInResolution { entry: *entry_id });
        };
        let known_atts: HashMap<&str, AttachmentDeltaKind> = conflict
            .attachment_deltas
            .iter()
            .map(|d| (d.name.as_str(), d.kind))
            .collect();
        for (name, choice) in attachment_choices {
            let Some(kind) = known_atts.get(name.as_str()).copied() else {
                return Err(MergeError::UnknownAttachmentInResolution {
                    entry: *entry_id,
                    attachment: name.clone(),
                });
            };
            if matches!(choice, AttachmentChoice::KeepBoth { .. })
                && kind != AttachmentDeltaKind::BothDiffer
            {
                return Err(MergeError::KeepBothNotPermittedForKind {
                    entry: *entry_id,
                    attachment: name.clone(),
                });
            }
        }
    }

    // 3. Every entry referenced in delete_edit_choices must be in
    //    delete_edit_conflicts.
    for entry_id in resolution.delete_edit_choices.keys() {
        if !delete_edit_ids.contains(entry_id) {
            return Err(MergeError::UnknownEntryInResolution { entry: *entry_id });
        }
    }

    // 3b. Every entry referenced in entry_icon_choices must be in
    //     entry_conflicts and carry an icon_delta.
    for entry_id in resolution.entry_icon_choices.keys() {
        let Some(conflict) = outcome
            .entry_conflicts
            .iter()
            .find(|c| c.entry_id == *entry_id)
        else {
            return Err(MergeError::UnknownEntryInResolution { entry: *entry_id });
        };
        if conflict.icon_delta.is_none() {
            return Err(MergeError::UnknownEntryInResolution { entry: *entry_id });
        }
    }

    // 4. Every conflict in either bucket must have a corresponding
    //    resolution entry. A conflict with field_deltas requires its
    //    entry in entry_field_choices (even an empty inner map — the
    //    caller's intent must be explicit). Same for attachment_deltas
    //    and entry_attachment_choices, and for icon_delta on
    //    entry_icon_choices.
    for conflict in &outcome.entry_conflicts {
        if !conflict.field_deltas.is_empty()
            && !resolution
                .entry_field_choices
                .contains_key(&conflict.entry_id)
        {
            return Err(MergeError::MissingResolutionForConflict {
                entry: conflict.entry_id,
            });
        }
        if !conflict.attachment_deltas.is_empty()
            && !resolution
                .entry_attachment_choices
                .contains_key(&conflict.entry_id)
        {
            return Err(MergeError::MissingResolutionForConflict {
                entry: conflict.entry_id,
            });
        }
        if conflict.icon_delta.is_some()
            && !resolution
                .entry_icon_choices
                .contains_key(&conflict.entry_id)
        {
            return Err(MergeError::MissingResolutionForConflict {
                entry: conflict.entry_id,
            });
        }
    }
    for id in &delete_edit_ids {
        if !resolution.delete_edit_choices.contains_key(id) {
            return Err(MergeError::MissingResolutionForConflict { entry: *id });
        }
    }

    // Discourage unused-variable warning when there are no field
    // conflicts but only attachment conflicts.
    let _ = conflict_ids;

    Ok(())
}

/// Apply each `delete_edit_conflicts` choice. Returns the set of
/// uuids whose remote tombstone the caller chose to drop (consumed
/// by the tombstone-union step).
///
/// Two-way handling per audit fix:
/// * **Asymmetric (legacy)**: local edited, remote deleted. The
///   entry is already on local; `KeepLocal` keeps it,
///   `AcceptRemoteDelete` removes it.
/// * **Symmetric (post-fix)**: local deleted, remote edited. The
///   entry is on remote and stashed in
///   `outcome.delete_edit_restore_from_remote`. `KeepLocal` (spec
///   default — "edit wins") restores the entry into local under
///   the remote-mirrored parent; `AcceptRemoteDelete` leaves the
///   deletion in place.
///
/// **Tombstone retention policy (deviates from spec §4 wording).**
/// In both branches we drop the local tombstone when restoring the
/// entry. The spec calls for retaining it as "historical signal,"
/// but that produces `entry alive + matching tombstone in
/// <DeletedObjects>` — a state that `keepass-core`'s own
/// `kdbx::import_entry_with_uuid` explicitly scrubs because
/// downstream sync (and other KDBX clients) can interpret the
/// tombstone as authoritative and re-delete the restored entry.
/// The historical signal is preserved via
/// `MergeEvent::EntryRestoredFromDeletion` (engine subscribes via
/// tracing) — it doesn't have to live on disk.
pub(super) fn apply_delete_edit_resolutions(
    local_root: &mut Group,
    local_tombstones: &mut Vec<DeletedObject>,
    outcome: &MergeOutcome,
    resolution: &Resolution,
) -> HashSet<Uuid> {
    let mut kept_local = HashSet::new();
    for id in &outcome.delete_edit_conflicts {
        // Validation guarantees the key is present.
        let choice = resolution.delete_edit_choices[id];
        let symmetric = outcome.delete_edit_restore_from_remote.get(id);
        match (choice, symmetric) {
            (DeleteEditChoice::KeepLocal, None) => {
                // Asymmetric: local has the entry; just retain it.
                kept_local.insert(id.0);
                local_tombstones.retain(|t| t.uuid != id.0);
            }
            (DeleteEditChoice::KeepLocal, Some((remote_entry, remote_parent))) => {
                // Symmetric: restore from remote. Insert under the
                // remote-mirrored parent if it exists locally; fall
                // back to root.
                match super::find_group_mut(local_root, *remote_parent) {
                    Some(parent) => parent.entries.push(remote_entry.clone()),
                    None => local_root.entries.push(remote_entry.clone()),
                }
                // Drop local's tombstone (see policy doc above).
                kept_local.insert(id.0);
                local_tombstones.retain(|t| t.uuid != id.0);
            }
            (DeleteEditChoice::AcceptRemoteDelete, None) => {
                // Asymmetric: drop local's entry; tombstone propagates
                // from remote via the standard tombstone-union path.
                remove_entry(local_root, *id);
            }
            (DeleteEditChoice::AcceptRemoteDelete, Some(_)) => {
                // Symmetric: the deletion is already in place on local;
                // honour it by not restoring. Local's tombstone stays.
            }
        }
    }
    kept_local
}

/// Apply each `entry_conflicts` resolution by per-field merge:
/// clone local as the base, then overwrite the fields the caller
/// chose `Remote` for. History merge + pre-merge snapshot per slice 5a.
pub(super) fn apply_entry_conflict_resolutions(
    local_root: &mut Group,
    outcome: &MergeOutcome,
    resolution: &Resolution,
    remap: &mut BinaryPoolRemap<'_>,
) {
    let empty_attachment_auto: Vec<AttachmentAutoResolution> = Vec::new();
    let empty_field_choices: HashMap<String, ConflictSide> = HashMap::new();
    let empty_attachment_choices: HashMap<String, AttachmentChoice> = HashMap::new();
    for conflict in &outcome.entry_conflicts {
        // Validation requires entries with non-empty deltas to have a
        // resolution entry; for empty deltas it allows the key to be
        // absent. Default to the empty map either way.
        let field_choices = resolution
            .entry_field_choices
            .get(&conflict.entry_id)
            .unwrap_or(&empty_field_choices);
        let attachment_choices = resolution
            .entry_attachment_choices
            .get(&conflict.entry_id)
            .unwrap_or(&empty_attachment_choices);
        let atts_auto = outcome
            .attachment_auto_resolutions_per_entry
            .get(&conflict.entry_id)
            .unwrap_or(&empty_attachment_auto);
        let icon_choice = resolution
            .entry_icon_choices
            .get(&conflict.entry_id)
            .copied();
        let mut merged = build_resolved_entry(
            conflict,
            field_choices,
            atts_auto,
            attachment_choices,
            icon_choice,
            remap,
        );
        apply_merged_tags(
            &mut merged,
            outcome,
            conflict.entry_id,
            &conflict.local,
            &conflict.remote,
        );
        apply_attachment_tombstones(
            &mut merged,
            &conflict.local,
            &conflict.remote,
            remap.local_binaries(),
        );
        replace_entry(local_root, conflict.entry_id, merged);
    }
}

/// Overwrite `merged.tags` with the per-entry merged tag set the
/// classifier stashed during `merge`, then run the
/// `keys.tag_state.v1` tombstone filter pass and persist the unioned
/// tag-state back onto `merged.custom_data`.
///
/// The classifier's merged set is the LCA-3-way outcome (see
/// `internal design notes`); the tombstone pass on top is
/// the kdbx-invisible "this tag was explicitly removed, do not
/// resurrect it" signal documented in the design notes §4.
/// For each tag in the merged set we look up its tombstone (if any)
/// and ask: is the most recent side that holds this tag carrying an
/// mtime newer than the tombstone's `at`? If yes, the tag was re-added
/// after the tombstone — keep it. If no (or only the tombstoned side
/// has it), drop. KDBX has no per-tag add-time so the holding entry's
/// `last_modification_time` is the spec-proxy add-time.
///
/// Apply runs only when the entry landed in some bucket, so the
/// no-stash branch is the omitted-entry case and we leave
/// `merged.tags` (and the persisted tag-state) alone.
pub(super) fn apply_merged_tags(
    merged: &mut Entry,
    outcome: &MergeOutcome,
    id: EntryId,
    local_entry: &Entry,
    remote_entry: &Entry,
) {
    let Some(set) = outcome.merged_tags_per_entry.get(&id) else {
        return;
    };

    // Parse + union both sides' tag-state tombstones. Parse failures
    // degrade silently to empty — a corrupt value mustn't crash the
    // merge; the unioned-and-reserialised list overwrites it below.
    let local_state =
        crate::tombstone::parse_tag_state(&local_entry.custom_data).unwrap_or_default();
    let remote_state =
        crate::tombstone::parse_tag_state(&remote_entry.custom_data).unwrap_or_default();
    let unioned = crate::tombstone::union_tag_states(&local_state, &remote_state);

    let local_set: std::collections::BTreeSet<&str> =
        local_entry.tags.iter().map(String::as_str).collect();
    let remote_set: std::collections::BTreeSet<&str> =
        remote_entry.tags.iter().map(String::as_str).collect();
    let local_mtime = local_entry.times.last_modification_time;
    let remote_mtime = remote_entry.times.last_modification_time;

    let mut filtered: Vec<String> = Vec::with_capacity(set.len());
    for tag in set {
        let kept = match unioned.remove.get(tag) {
            None => true,
            Some(rm) => {
                let local_add_time = local_set.contains(tag.as_str()).then_some(local_mtime);
                let remote_add_time = remote_set.contains(tag.as_str()).then_some(remote_mtime);
                let latest_add: Option<chrono::DateTime<chrono::Utc>> =
                    [local_add_time, remote_add_time]
                        .into_iter()
                        .flatten()
                        .flatten()
                        .max();
                // Re-add wins iff a concrete add-time is strictly newer
                // than the tombstone's `at`. An absent mtime on the
                // holding side can't beat a concrete tombstone time —
                // conservative: don't resurrect a tombstoned tag on
                // unknown provenance.
                latest_add.is_some_and(|t| t > rm.at)
            }
        };
        if kept {
            filtered.push(tag.clone());
        }
    }
    merged.tags = filtered;

    // Persist the unioned tag-state so the tombstones propagate to
    // peers on the next sync round. `None` for last_modified — apply
    // is pure.
    crate::tombstone::write_tag_state_to_custom_data(&mut merged.custom_data, &unioned, None);
}

/// Run the `keys.attachment_tombstones.v1` filter pass on top of the
/// merged entry's final attachment list, and persist the unioned
/// tombstones back onto `merged.custom_data`.
///
/// Mirrors `apply_merged_tags` in shape: parse both sides, union by
/// `(filename, hash)` with earliest `at` winning, then drop any
/// attachment whose `(filename, hash)` is tombstoned unless the
/// holding side's mtime is strictly newer than the tombstone's `at`
/// (the spec §4 re-add escape hatch). `binaries` is the local pool —
/// `remap` has already rebound any remote-sourced refs by the time
/// this runs, so every attachment on `merged` indexes into the local
/// pool.
pub(super) fn apply_attachment_tombstones(
    merged: &mut Entry,
    local_entry: &Entry,
    remote_entry: &Entry,
    binaries: &[Binary],
) {
    let local_ts =
        crate::tombstone::parse_attachment_tombstones(&local_entry.custom_data).unwrap_or_default();
    let remote_ts = crate::tombstone::parse_attachment_tombstones(&remote_entry.custom_data)
        .unwrap_or_default();
    if local_ts.is_empty() && remote_ts.is_empty() {
        return;
    }
    let unioned = crate::tombstone::union_attachment_tombstones(&local_ts, &remote_ts);
    let lookup: std::collections::HashMap<
        (String, [u8; 32]),
        &crate::tombstone::AttachmentTombstone,
    > = unioned
        .iter()
        .map(|t| ((t.filename.clone(), t.hash), t))
        .collect();

    let local_set: std::collections::HashMap<&str, [u8; 32]> = local_entry
        .attachments
        .iter()
        .filter_map(|a| {
            let bin = binaries.get(a.ref_id as usize)?;
            Some((a.name.as_str(), sha256(&bin.data)))
        })
        .collect();
    let remote_set: std::collections::HashMap<&str, [u8; 32]> = remote_entry
        .attachments
        .iter()
        .filter_map(|a| {
            let bin = binaries.get(a.ref_id as usize)?;
            Some((a.name.as_str(), sha256(&bin.data)))
        })
        .collect();
    let local_mtime = local_entry.times.last_modification_time;
    let remote_mtime = remote_entry.times.last_modification_time;

    merged.attachments.retain(|att| {
        let Some(bin) = binaries.get(att.ref_id as usize) else {
            // Corrupt ref — preserve, matches the conservative posture
            // elsewhere in the crate.
            return true;
        };
        let hash = sha256(&bin.data);
        let key = (att.name.clone(), hash);
        let Some(rm) = lookup.get(&key) else {
            return true;
        };
        // Re-attach wins iff a holding side carries this same
        // (filename, hash) with mtime strictly newer than the
        // tombstone's `at`. Unknown mtime conservatively loses to a
        // concrete tombstone — same posture as tag-state filtering.
        let local_add = local_set
            .get(att.name.as_str())
            .filter(|h| **h == hash)
            .and(local_mtime);
        let remote_add = remote_set
            .get(att.name.as_str())
            .filter(|h| **h == hash)
            .and(remote_mtime);
        let latest_add = [local_add, remote_add].into_iter().flatten().max();
        latest_add.is_some_and(|t| t > rm.at)
    });

    crate::tombstone::write_attachment_tombstones_to_custom_data(
        &mut merged.custom_data,
        &unioned,
        None,
    );
}

/// Build the post-resolution entry: clone the local side, apply each
/// `Remote`-chosen field from the conflict's `remote`, then stitch in
/// the combined history plus a pre-merge snapshot of local.
///
/// `remap` translates any history record sourced from `conflict.remote`
/// — its `Attachment::ref_id` values index into the remote vault's
/// binary pool and would be silently stale once installed into local
/// without translation. Current-side attachments are inherited from
/// `conflict.local` (per `<History>` is per-field, not per-attachment
/// in v0.1) and need no translation.
pub(super) fn build_resolved_entry(
    conflict: &EntryConflict,
    field_choices: &HashMap<String, ConflictSide>,
    attachment_resolutions: &[AttachmentAutoResolution],
    attachment_choices: &HashMap<String, AttachmentChoice>,
    icon_choice: Option<ConflictSide>,
    remap: &mut BinaryPoolRemap<'_>,
) -> Entry {
    let mut merged = conflict.local.clone();

    for delta in &conflict.field_deltas {
        let choice = field_choices
            .get(&delta.key)
            .copied()
            // Validation should prevent this, but be safe: default to
            // Local (no-op). A missing inner choice means "keep mine".
            .unwrap_or(ConflictSide::Local);
        if matches!(choice, ConflictSide::Local) {
            continue;
        }
        // ConflictSide::Remote — copy from conflict.remote per the
        // delta's kind.
        match delta.kind {
            FieldDeltaKind::LocalOnly => {
                // Remote chose: remove the field locally.
                remove_field(&mut merged, &delta.key);
            }
            FieldDeltaKind::RemoteOnly | FieldDeltaKind::BothDiffer => {
                // Take the remote's value (and protected bit for
                // custom fields).
                copy_field(&mut merged, &conflict.remote, &delta.key);
            }
        }
    }

    // Apply icon choice when the conflict carries an icon_delta.
    // `merged` started as a clone of local, so an absent icon_choice
    // (validation allows it to be Local-equivalent) defaults to the
    // local UUID already in place. Only flip when the caller picked
    // remote.
    if conflict.icon_delta.is_some() {
        if let Some(ConflictSide::Remote) = icon_choice {
            merged.custom_icon_uuid = conflict.remote.custom_icon_uuid;
        }
    }

    // Apply attachment auto-resolutions per-name. The entry-level
    // "ride along on local" carried local's whole attachment list
    // onto `merged` via the `.clone()` above; reconcile per-name now
    // for any name the classifier had a clear answer on.
    apply_attachment_resolutions(
        &mut merged,
        &conflict.local,
        &conflict.remote,
        attachment_resolutions,
        remap,
    );

    // Apply caller resolutions for each AttachmentDelta on this
    // conflict. KeepBoth installs both sides with the remote-side
    // renamed; KeepLocal / KeepRemote behaves like the auto-resolution
    // path with the chosen side.
    apply_caller_attachment_choices(
        &mut merged,
        &conflict.local,
        &conflict.remote,
        &conflict.attachment_deltas,
        attachment_choices,
        remap,
    );

    // History stitching mirrors slice 5a's `build_merged_entry` for
    // the auto-resolution paths. Rebind the remote-side history records
    // before merging so the combined result carries only local-pool
    // ref_ids.
    let rebound_remote_history = rebind_history(&conflict.remote.history, remap);
    // Rebind the remote *current* too (history cleared) so it can be added as
    // the rejected-side snapshot below in the local binary pool's ref space.
    let mut remote_current = conflict.remote.clone();
    remote_current.history.clear();
    let rebound_remote_current = rebind_history(std::slice::from_ref(&remote_current), remap)
        .pop()
        .unwrap_or(remote_current);
    // After rebinding we're done mutating the binary pool for this
    // entry; the rest of build_resolved_entry needs only a read-only
    // view of it for hashing + history dedup.
    let local_binaries: &[Binary] = remap.local_binaries();
    // Union the two sides' history tombstones — same shape as
    // `build_merged_entry` in tree.rs; parse failures degrade
    // silently to empty.
    let local_ts = parse_tombstones(&conflict.local.custom_data).unwrap_or_default();
    let remote_ts = parse_tombstones(&conflict.remote.custom_data).unwrap_or_default();
    let unioned_ts = union_history_tombstones(&local_ts, &remote_ts);
    let ts_set = tombstone_set(&unioned_ts);
    let mut combined = merge_histories(
        &conflict.local.history,
        &rebound_remote_history,
        local_binaries,
        &ts_set,
    );
    // Non-destructive resolution: preserve BOTH sides' pre-resolution current
    // states in `<History>`, EXCEPT whichever became the resolved value (that
    // side is the live entry, not history). So "keep ours" preserves *theirs*,
    // "keep theirs" preserves *ours*, and a per-field mix preserves both — and
    // there is never a redundant history copy of the chosen value. (Previously
    // only local's pre-state was snapshotted, which duplicated the current value
    // on a keep-ours resolution and silently dropped the rejected "theirs".)
    let merged_hash = entry_content_hash(&merged, local_binaries);
    let mut local_current = conflict.local.clone();
    local_current.history.clear();
    for snapshot in [local_current, rebound_remote_current] {
        let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
        // The side that became the resolved value lives as `merged`, not as a
        // history record — skip it (this is the redundant-copy fix).
        if snapshot_hash == merged_hash {
            continue;
        }
        // Second-resolution mtime comparison, matching `build_merged_entry`
        // and `merge_histories`: ms-stamped engine mtimes vs second-truncated
        // KDBX round-trips would otherwise push a pre-merge snapshot alongside
        // its already-merged twin (Bug A history bloat — see `the design notes`).
        let snapshot_mtime = second_resolution(snapshot.times.last_modification_time);
        if ts_set.contains(&(snapshot_mtime, snapshot_hash)) {
            continue;
        }
        let already_present = combined.iter().any(|h| {
            second_resolution(h.times.last_modification_time) == snapshot_mtime
                && entry_content_hash(h, local_binaries) == snapshot_hash
        });
        if !already_present {
            combined.push(snapshot);
        }
    }
    merged.history = combined;
    write_tombstones_to_custom_data(&mut merged.custom_data, &unioned_ts, None);
    merged
}

/// Reconcile `merged.attachments` against the per-name auto-resolutions
/// from the classifier. `merged` came in as a clone of the entry-level
/// winning side (local or remote); the resolutions describe what the
/// *attachment* classifier decided per name, which may diverge from
/// the entry-level winner for some names.
///
/// For each [`AttachmentAutoResolution`]:
///
/// - "winning side" for *this attachment* is `res.side`.
/// - the merged set should hold the name iff the winning side has it
///   for that name (presence semantics inherited from
///   `classify_three_way` / `Side`);
/// - when the winning side is `Remote`, its `ref_id` indexes into the
///   remote binary pool — translate via `remap`.
///
/// Attachment *conflicts* (not in `resolutions`) are left as-is: they
/// inherit the entry-level winner's bytes by virtue of the upstream
/// clone. The public conflict surface in a later slice will let the
/// caller override that per name.
pub(super) fn apply_attachment_resolutions(
    merged: &mut Entry,
    local_entry: &Entry,
    remote_entry: &Entry,
    resolutions: &[AttachmentAutoResolution],
    remap: &mut BinaryPoolRemap<'_>,
) {
    for res in resolutions {
        let winning_side_entry = match res.side {
            Side::Local => local_entry,
            Side::Remote => remote_entry,
        };
        let want = winning_side_entry
            .attachments
            .iter()
            .find(|a| a.name == res.name);

        match want {
            Some(chosen) => {
                let mut new_att = chosen.clone();
                // Remote-side refs index into the remote pool; rebind.
                if matches!(res.side, Side::Remote) {
                    remap.rebind(std::slice::from_mut(&mut new_att));
                }
                if let Some(pos) = merged.attachments.iter().position(|a| a.name == res.name) {
                    merged.attachments[pos] = new_att;
                } else {
                    merged.attachments.push(new_att);
                }
            }
            None => {
                // Winning side doesn't hold this name (e.g.
                // `HonourDeletion`). Strip from merged.
                merged.attachments.retain(|a| a.name != res.name);
            }
        }
    }
}

/// Apply caller resolutions for an [`EntryConflict`]'s attachment_deltas.
///
/// Each delta has an [`AttachmentChoice`] in `choices` (validated to
/// be present and kind-consistent by `validate_resolution`). For
/// `KeepLocal` / `KeepRemote`, the winning side's bytes go onto
/// `merged` (with binary-pool rebinding for remote-side wins). For
/// `KeepBoth`, both sides are kept — local under its original name,
/// remote renamed (defaulting to `"<stem> (remote).<ext>"`, with a
/// counter suffix on collision).
pub(super) fn apply_caller_attachment_choices(
    merged: &mut Entry,
    local_entry: &Entry,
    remote_entry: &Entry,
    deltas: &[AttachmentDelta],
    choices: &HashMap<String, AttachmentChoice>,
    remap: &mut BinaryPoolRemap<'_>,
) {
    for delta in deltas {
        // Validation ensures the delta has a choice and that
        // `KeepBoth` only appears for `BothDiffer` deltas. A missing
        // choice here would be a validation gap, not a user mistake;
        // default conservatively to `KeepLocal`.
        let choice = choices
            .get(&delta.name)
            .cloned()
            .unwrap_or(AttachmentChoice::KeepLocal);
        match choice {
            AttachmentChoice::KeepLocal => {
                install_side(merged, local_entry, &delta.name, Side::Local, remap);
            }
            AttachmentChoice::KeepRemote => {
                install_side(merged, remote_entry, &delta.name, Side::Remote, remap);
            }
            AttachmentChoice::KeepBoth { rename_override } => {
                // Local under its original name; remote under a
                // renamed slot that doesn't collide with any already-
                // present attachment.
                install_side(merged, local_entry, &delta.name, Side::Local, remap);
                let renamed =
                    pick_rename(rename_override.as_deref(), &delta.name, &merged.attachments);
                let Some(remote_att) = remote_entry
                    .attachments
                    .iter()
                    .find(|a| a.name == delta.name)
                else {
                    // Validation should have flagged this — KeepBoth
                    // only valid for BothDiffer where both sides hold
                    // the name. Defensive skip.
                    continue;
                };
                let mut new_att = remote_att.clone();
                new_att.name = renamed;
                remap.rebind(std::slice::from_mut(&mut new_att));
                merged.attachments.push(new_att);
            }
        }
    }
}

/// Install one side's view of an attachment named `name` onto
/// `merged`. Mirrors the `apply_attachment_resolutions` per-name
/// reconciliation but is keyed by an explicit side rather than a
/// classifier output.
pub(super) fn install_side(
    merged: &mut Entry,
    side_entry: &Entry,
    name: &str,
    side: Side,
    remap: &mut BinaryPoolRemap<'_>,
) {
    let want = side_entry.attachments.iter().find(|a| a.name == name);
    match want {
        Some(chosen) => {
            let mut new_att = chosen.clone();
            if matches!(side, Side::Remote) {
                remap.rebind(std::slice::from_mut(&mut new_att));
            }
            if let Some(pos) = merged.attachments.iter().position(|a| a.name == name) {
                merged.attachments[pos] = new_att;
            } else {
                merged.attachments.push(new_att);
            }
        }
        None => {
            // Chosen side doesn't have this name — drop from merged.
            merged.attachments.retain(|a| a.name != name);
        }
    }
}

/// Pick a rename for the remote-side attachment in a `KeepBoth`
/// resolution. When the caller supplied an override, use it verbatim
/// (no collision-counter applied — the caller is responsible for
/// picking a clean name). When no override, generate the default
/// pattern `"<stem> (remote).<ext>"` (or `"<name> (remote)"` for
/// extension-less names), then append a counter suffix until the
/// resulting name isn't already in `existing`.
pub(super) fn pick_rename(
    override_name: Option<&str>,
    original: &str,
    existing: &[keepass_core::model::Attachment],
) -> String {
    if let Some(n) = override_name {
        return n.to_owned();
    }
    let (stem, ext) = match original.rfind('.') {
        Some(dot) if dot > 0 => (&original[..dot], &original[dot..]),
        _ => (original, ""),
    };
    let mut candidate = format!("{stem} (remote){ext}");
    let mut counter: u32 = 2;
    while existing.iter().any(|a| a.name == candidate) {
        candidate = format!("{stem} (remote {counter}){ext}");
        counter = counter.saturating_add(1);
        // Practical bound: KDBX entries rarely carry thousands of
        // same-stem attachments; if they did, the counter would
        // saturate and the apply step would loop forever on its own
        // output. Break defensively at u32::MAX.
        if counter == u32::MAX {
            break;
        }
    }
    candidate
}

/// Clone every history record and rebind its top-level attachments
/// (history records themselves have no nested history per KDBX).
pub(super) fn rebind_history(history: &[Entry], remap: &mut BinaryPoolRemap<'_>) -> Vec<Entry> {
    history
        .iter()
        .map(|h| {
            let mut clone = h.clone();
            remap.rebind(&mut clone.attachments);
            clone
        })
        .collect()
}
