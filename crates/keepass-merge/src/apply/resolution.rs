//! Caller-driven resolution-application helpers for `apply_merge`.
//!
//! Covers the conflict-resolution flow: validation of the
//! [`Resolution`] against the [`MergeOutcome`], then applying the
//! caller's per-entry / per-field / per-attachment / delete-edit
//! choices. The attachment-conflict path (which spans both the
//! caller-driven [`AttachmentChoice`] decisions and the
//! auto-resolution machinery from `entry_merge`) lives here too,
//! along with the small leaf helpers (`install_side`, `pick_rename`,
//! `rebind_history`, `remove_field`, `set_field_from`) it relies on.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{Binary, CustomField, DeletedObject, Entry, EntryId, Group};
use uuid::Uuid;

use crate::binary_pool::BinaryPoolRemap;
use crate::conflict::{AttachmentDelta, AttachmentDeltaKind, EntryConflict, FieldDeltaKind};
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::hash::entry_content_hash;
use crate::history_merge::merge_histories;
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice};
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
        match choice {
            DeleteEditChoice::KeepLocal => {
                kept_local.insert(id.0);
                // Drop any local tombstone for this uuid too — the
                // local entry stays, so a tombstone for it would be
                // contradictory state.
                local_tombstones.retain(|t| t.uuid != id.0);
            }
            DeleteEditChoice::AcceptRemoteDelete => {
                remove_entry(local_root, *id);
                // The tombstone-union step will pull in the remote's
                // tombstone for this uuid via the standard path.
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
        apply_merged_tags(&mut merged, outcome, conflict.entry_id);
        replace_entry(local_root, conflict.entry_id, merged);
    }
}

/// Overwrite `merged.tags` with the per-entry merged tag set the
/// classifier stashed during `merge`. The merged set is the auto-
/// resolved union/honour-deletion outcome (see
/// `_localdocs/MERGE_TAGS_DESIGN.md`); when nothing changed for tags,
/// it's just `local.tags` re-sorted. Apply runs only when the entry
/// landed in some bucket, so the no-stash branch is the omitted-
/// entry case and we leave `merged.tags` alone.
pub(super) fn apply_merged_tags(merged: &mut Entry, outcome: &MergeOutcome, id: EntryId) {
    if let Some(set) = outcome.merged_tags_per_entry.get(&id) {
        merged.tags = set.iter().cloned().collect();
    }
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
                set_field_from(&mut merged, &conflict.remote, &delta.key);
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
    let mut snapshot = conflict.local.clone();
    snapshot.history.clear();
    let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
    let snapshot_mtime = snapshot.times.last_modification_time;
    let snapshot_is_tombstoned = ts_set.contains(&(snapshot_mtime, snapshot_hash));
    let already_present = combined.iter().any(|h| {
        h.times.last_modification_time == snapshot_mtime
            && entry_content_hash(h, local_binaries) == snapshot_hash
    });
    if !already_present && !snapshot_is_tombstoned {
        combined.push(snapshot);
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

pub(super) fn remove_field(entry: &mut Entry, key: &str) {
    match key {
        "Title" => entry.title.clear(),
        "UserName" => entry.username.clear(),
        "Password" => entry.password.clear(),
        "URL" => entry.url.clear(),
        "Notes" => entry.notes.clear(),
        _ => {
            entry.custom_fields.retain(|f| f.key != key);
        }
    }
}

pub(super) fn set_field_from(entry: &mut Entry, source: &Entry, key: &str) {
    match key {
        "Title" => entry.title.clone_from(&source.title),
        "UserName" => entry.username.clone_from(&source.username),
        "Password" => entry.password.clone_from(&source.password),
        "URL" => entry.url.clone_from(&source.url),
        "Notes" => entry.notes.clone_from(&source.notes),
        _ => {
            let from = source.custom_fields.iter().find(|f| f.key == key);
            match from {
                Some(src) => match entry.custom_fields.iter_mut().find(|f| f.key == key) {
                    Some(target) => {
                        target.value.clone_from(&src.value);
                        target.protected = src.protected;
                    }
                    None => entry.custom_fields.push(CustomField::new(
                        src.key.clone(),
                        src.value.clone(),
                        src.protected,
                    )),
                },
                None => entry.custom_fields.retain(|f| f.key != key),
            }
        }
    }
}
