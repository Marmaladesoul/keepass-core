//! Apply a [`MergeOutcome`] to a local [`Vault`], producing the merged state.
//!
//! Slice 5a covers every bucket the caller doesn't have to drive:
//!
//! - [`MergeOutcome::disk_only_changes`] — overwrite local entry with
//!   remote, preserving combined history plus a pre-merge local snapshot.
//! - [`MergeOutcome::local_only_changes`] — keep local content but
//!   absorb any history records the remote side has that we don't.
//! - [`MergeOutcome::added_on_disk`] — clone-insert remote entries,
//!   mirroring remote's parent-group path into local; falls back to
//!   local's root if the path doesn't exist locally.
//! - [`MergeOutcome::local_deletions_pending_sync`] — propagate local
//!   tombstones into remote (no-op on local; documented for completeness).
//! - [`MergeOutcome::deleted_on_disk`] — drop the local entry; the
//!   tombstone union below records the deletion.
//! - Tombstone union with exact `(uuid, deleted_at)` dedup.
//! - Group-tree LWW reconciliation (rename / move / metadata).
//!
//! [`reconcile_timestamps`] is a separate post-apply pass that takes
//! the later of each timestamp pair across both sides for every
//! entry-id and group-id present on both. Caller invokes after
//! `apply_merge`.
//!
//! Slice 5b adds the caller-driven buckets:
//!
//! - [`MergeOutcome::entry_conflicts`] — per-field resolution drives
//!   which side wins each conflicting field. Pre-merge local snapshot
//!   lands in history.
//! - [`MergeOutcome::delete_edit_conflicts`] — `KeepLocal` drops the
//!   remote tombstone (kept-local skip-set), `AcceptRemoteDelete`
//!   removes the local entry and the standard tombstone-union
//!   propagates the remote tombstone.
//!
//! Resolution validation runs first as a read-only single-pass walk
//! returning the first violation as one of `MergeError::
//! UnknownEntryInResolution` / `UnknownFieldInResolution` /
//! `MissingResolutionForConflict`. No mutation has occurred when an
//! error is returned; the caller can fix the resolution and retry.

use std::collections::{HashMap, HashSet};

use keepass_core::model::{
    Binary, CustomField, DeletedObject, Entry, EntryId, Group, GroupId, Vault,
};
use uuid::Uuid;

use crate::binary_pool::BinaryPoolRemap;
use crate::conflict::{AttachmentDelta, AttachmentDeltaKind, EntryConflict, FieldDeltaKind};
use crate::entry_merge::{AttachmentAutoResolution, Side};
use crate::hash::entry_content_hash;
use crate::history_merge::merge_histories;
use crate::resolution::{AttachmentChoice, ConflictSide, DeleteEditChoice};
use crate::{MergeError, MergeOutcome, Resolution};

/// Mutate `local` in place by applying `outcome` and `resolution`'s
/// caller-driven choices.
///
/// `remote` is consulted read-only for three purposes: to source the
/// added-entries and their parent-group paths, to drive group-tree
/// LWW reconciliation by timestamp, and to source the field values
/// that the resolution has the caller pulling across the merge.
///
/// Returns `Err` if the resolution doesn't cover the outcome's
/// conflict buckets — see the validation pass for the exact contract.
/// On `Err` no mutation has occurred and `local` is untouched.
///
/// `Resolution::default()` is the auto-apply incantation: when the
/// outcome's `entry_conflicts` and `delete_edit_conflicts` buckets
/// are empty, an empty resolution is sufficient.
pub fn apply_merge(
    local: &mut Vault,
    remote: &Vault,
    outcome: &MergeOutcome,
    resolution: &Resolution,
) -> Result<(), MergeError> {
    // Validation pass first — read-only, fail-fast. No mutation has
    // occurred when this returns Err; caller can fix and retry.
    validate_resolution(outcome, resolution)?;

    // Group-tree LWW first so any newly-added remote groups are in
    // place before `added_on_disk` looks for parent-group paths.
    apply_group_tree(local, remote);

    // Split-borrow Vault fields so `BinaryPoolRemap` can hold
    // `&mut local.binaries` while the entry-mutation steps work on
    // `&mut local.root`. The two fields are disjoint; the compiler
    // accepts the split when we name each field explicitly.
    let local_root = &mut local.root;
    let local_tombstones = &mut local.deleted_objects;
    let mut remap = BinaryPoolRemap::new(&mut local.binaries, &remote.binaries);

    // Conflict-driven mutations come *before* the auto-merge buckets:
    // conflict resolution is the most opinionated mutation, so we land
    // it first and then auto-merge against the resolved tree. Defends
    // against any future bucket-overlap refactor at zero cost.
    let kept_local =
        apply_delete_edit_resolutions(local_root, local_tombstones, outcome, resolution);
    apply_entry_conflict_resolutions(local_root, outcome, resolution, &mut remap);

    // Entry-level mutations. Order is "remove → modify → add" so a
    // remote-add with the same id as a local-tombstoned entry can't
    // confuse intermediate state.
    for id in &outcome.deleted_on_disk {
        remove_entry(local_root, *id);
    }

    let empty_attachment_resolutions: Vec<AttachmentAutoResolution> = Vec::new();
    let empty_field_resolutions: Vec<(String, Side)> = Vec::new();
    for id in &outcome.disk_only_changes {
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(local_root, *id) else {
            continue;
        };
        let atts = outcome
            .attachment_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_attachment_resolutions);
        let fields = outcome
            .field_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_field_resolutions);
        let icon = outcome.icon_auto_resolutions_per_entry.get(id).copied();
        let mut merged = build_merged_entry(
            local_entry,
            remote_entry,
            EntryWinner::Remote,
            atts,
            fields,
            icon,
            &mut remap,
        );
        apply_merged_tags(&mut merged, outcome, *id);
        replace_entry(local_root, *id, merged);
    }

    for id in &outcome.local_only_changes {
        // History-merge runs even though the local content stays put
        // — that's how a remote's intermediate snapshots reach local
        // when the remote's *current* state matches local's.
        let Some(remote_entry) = find_entry(&remote.root, *id) else {
            continue;
        };
        let Some(local_entry) = find_entry(local_root, *id) else {
            continue;
        };
        let atts = outcome
            .attachment_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_attachment_resolutions);
        let fields = outcome
            .field_auto_resolutions_per_entry
            .get(id)
            .unwrap_or(&empty_field_resolutions);
        let icon = outcome.icon_auto_resolutions_per_entry.get(id).copied();
        let mut merged = build_merged_entry(
            local_entry,
            remote_entry,
            EntryWinner::Local,
            atts,
            fields,
            icon,
            &mut remap,
        );
        apply_merged_tags(&mut merged, outcome, *id);
        replace_entry(local_root, *id, merged);
    }

    for new_entry in &outcome.added_on_disk {
        let target_parent = find_remote_parent(&remote.root, new_entry.id);
        let mut to_insert = new_entry.clone();
        // `new_entry` originates from `remote`; its current-state and
        // every history snapshot's `Attachment::ref_id` references
        // `remote.binaries`. Translate before install.
        remap.rebind(&mut to_insert.attachments);
        for hist in &mut to_insert.history {
            remap.rebind(&mut hist.attachments);
        }
        let inserted = target_parent
            .and_then(|gid| find_group_mut(local_root, gid))
            .map(|g| {
                g.entries.push(to_insert.clone());
            });
        if inserted.is_none() {
            local_root.entries.push(to_insert);
        }
    }

    // `local_deletions_pending_sync` is informational for the FFI
    // consumer — local already has the tombstone, no mutation
    // required. The bucket exists so the caller knows to schedule a
    // save-back, not because apply has work to do.
    let _ = &outcome.local_deletions_pending_sync;

    // Tombstone union: take everything remote has that local doesn't,
    // exact-tuple deduplicated by `(uuid, deleted_at)`. Skip uuids
    // covered by a `KeepLocal` delete-edit choice — those are the
    // "user said keep mine, drop the remote tombstone" path.
    union_tombstones(local_tombstones, &remote.deleted_objects, &kept_local);

    Ok(())
}

/// Read-only walk of the resolution against the outcome. Returns the
/// first violation found (single-pass, first-violation-wins).
#[allow(clippy::too_many_lines)]
fn validate_resolution(outcome: &MergeOutcome, resolution: &Resolution) -> Result<(), MergeError> {
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
fn apply_delete_edit_resolutions(
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
fn apply_entry_conflict_resolutions(
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
fn apply_merged_tags(merged: &mut Entry, outcome: &MergeOutcome, id: EntryId) {
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
fn build_resolved_entry(
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
    let mut combined = merge_histories(
        &conflict.local.history,
        &rebound_remote_history,
        local_binaries,
    );
    let mut snapshot = conflict.local.clone();
    snapshot.history.clear();
    let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
    let already_present = combined.iter().any(|h| {
        h.times.last_modification_time == snapshot.times.last_modification_time
            && entry_content_hash(h, local_binaries) == snapshot_hash
    });
    if !already_present {
        combined.push(snapshot);
    }
    merged.history = combined;
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
fn apply_attachment_resolutions(
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
fn apply_caller_attachment_choices(
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
fn install_side(
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
fn pick_rename(
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
fn rebind_history(history: &[Entry], remap: &mut BinaryPoolRemap<'_>) -> Vec<Entry> {
    history
        .iter()
        .map(|h| {
            let mut clone = h.clone();
            remap.rebind(&mut clone.attachments);
            clone
        })
        .collect()
}

fn remove_field(entry: &mut Entry, key: &str) {
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

fn set_field_from(entry: &mut Entry, source: &Entry, key: &str) {
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

/// Take the later of each timestamp pair across both vaults for every
/// entry and group present on both. Per-entry: `last_modification_time`,
/// `last_access_time`, `location_changed`. Per-group: same. Doesn't
/// touch content; only `times.*` fields.
///
/// Caller invokes after [`apply_merge`].
pub fn reconcile_timestamps(local: &mut Vault, remote: &Vault) {
    let remote_entries: HashMap<EntryId, &Entry> = {
        let mut out = HashMap::new();
        collect_entries(&remote.root, &mut out);
        out
    };
    reconcile_group_timestamps_recursive(&mut local.root, remote);
    reconcile_entry_timestamps_recursive(&mut local.root, &remote_entries);
}

// ---------------------------------------------------------------------------
// Group-tree LWW reconciliation
// ---------------------------------------------------------------------------

fn apply_group_tree(local: &mut Vault, remote: &Vault) {
    let local_tombstones: HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>> = local
        .deleted_objects
        .iter()
        .map(|t| (t.uuid, t.deleted_at))
        .collect();
    let remote_tombstones: HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>> = remote
        .deleted_objects
        .iter()
        .map(|t| (t.uuid, t.deleted_at))
        .collect();

    // Pass 1: take later-mtime metadata for every group present on both
    // sides. Recursive so nested groups are handled.
    take_later_group_metadata(&mut local.root, &remote.root);

    // Pass 2: drop any local group whose id is in remote's tombstones,
    // unless the local group's last_modification_time is later than
    // the tombstone's deleted_at (conservative: don't silently delete a
    // locally-edited group).
    drop_remotely_tombstoned_groups(&mut local.root, &remote_tombstones);

    // Pass 3: add any remote group not present locally and not in
    // local's tombstones. Insert under the resolved parent (matches
    // remote's path) or under local's root as fallback.
    add_remote_only_groups(local, remote, &local_tombstones);
}

fn take_later_group_metadata(local: &mut Group, remote: &Group) {
    // Walk both trees in lockstep where ids match.
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(remote, &mut remote_by_id);
    take_later_recursive(local, &remote_by_id);
}

fn take_later_recursive(local_group: &mut Group, remote_by_id: &HashMap<GroupId, &Group>) {
    if let Some(r) = remote_by_id.get(&local_group.id) {
        let local_t = local_group.times.last_modification_time;
        if let Some(rt) = r.times.last_modification_time {
            if local_t.is_none_or(|lt| rt > lt) {
                local_group.name = r.name.clone();
                local_group.notes = r.notes.clone();
                local_group.icon_id = r.icon_id;
                local_group.custom_icon_uuid = r.custom_icon_uuid;
                local_group.previous_parent_group = r.previous_parent_group;
                local_group.enable_auto_type = r.enable_auto_type;
                local_group.enable_searching = r.enable_searching;
                local_group.default_auto_type_sequence = r.default_auto_type_sequence.clone();
                local_group.is_expanded = r.is_expanded;
            }
        }
    }
    for sub in &mut local_group.groups {
        take_later_recursive(sub, remote_by_id);
    }
}

fn drop_remotely_tombstoned_groups(
    group: &mut Group,
    tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
) {
    group.groups.retain(|g| {
        let Some(deleted_at) = tombstones.get(&g.id.0) else {
            return true;
        };
        // Conservative keep: if the local group's mtime is later than
        // the tombstone's deleted_at (or either is missing), keep.
        match (g.times.last_modification_time, *deleted_at) {
            (Some(local_mt), Some(deleted)) => local_mt > deleted,
            _ => true,
        }
    });
    for sub in &mut group.groups {
        drop_remotely_tombstoned_groups(sub, tombstones);
    }
}

fn add_remote_only_groups(
    local: &mut Vault,
    remote: &Vault,
    local_tombstones: &HashMap<Uuid, Option<chrono::DateTime<chrono::Utc>>>,
) {
    let local_ids = collect_group_ids(&local.root);
    let remote_groups: Vec<(GroupId, GroupId, Group)> = {
        // (id, parent_id, cloned group with no children — children are
        // handled by their own recursion as we walk remote)
        let mut out = Vec::new();
        gather_remote_groups_with_parents(&remote.root, remote.root.id, &mut out);
        out
    };
    for (id, parent_id, group_meta) in remote_groups {
        if local_ids.contains(&id) {
            continue;
        }
        if local_tombstones.contains_key(&id.0) {
            continue;
        }
        // Insert a child copy with empty children — the children, if
        // any, are covered by their own iteration (we collected them
        // depth-first from remote with their own parent ids).
        let mut child = group_meta;
        child.groups.clear();
        child.entries.clear();
        match find_group_mut(&mut local.root, parent_id) {
            Some(parent) => parent.groups.push(child),
            None => local.root.groups.push(child),
        }
    }
}

fn gather_remote_groups_with_parents(
    group: &Group,
    parent_id: GroupId,
    out: &mut Vec<(GroupId, GroupId, Group)>,
) {
    // Skip the root itself — it's always present on local by
    // construction.
    if group.id != parent_id {
        out.push((group.id, parent_id, group.clone()));
    }
    for sub in &group.groups {
        gather_remote_groups_with_parents(sub, group.id, out);
    }
}

// ---------------------------------------------------------------------------
// Per-entry rebuild
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum EntryWinner {
    Local,
    Remote,
}

/// Build a merged entry by cloning the winning side and stitching
/// in the combined history plus a pre-merge snapshot of whichever
/// side is being overwritten.
///
/// `remap` translates remote-pool `Attachment::ref_id` values into
/// local-pool indices for every cloned piece sourced from `remote`:
/// the winner=Remote current-state clone, the winner=Local snapshot
/// of remote (when remote is the loser), and every remote-sourced
/// history record.
fn build_merged_entry(
    local: &Entry,
    remote: &Entry,
    winner: EntryWinner,
    attachment_resolutions: &[AttachmentAutoResolution],
    field_resolutions: &[(String, Side)],
    icon_resolution: Option<Side>,
    remap: &mut BinaryPoolRemap<'_>,
) -> Entry {
    // Rebind remote's history before merging so the combined output
    // carries only local-pool ref_ids regardless of which records win
    // the dedup. Slice 4's merge_histories handles dedup + ordering.
    let rebound_remote_history = rebind_history(&remote.history, remap);

    // Snapshot the loser's pre-merge state into history so a later
    // viewer can see what was overwritten. The snapshot has its
    // history field cleared (KDBX doesn't nest history). The
    // remote-side snapshot needs its attachment ref_ids translated
    // first; do that before we drop the mutable borrow on remap.
    let snapshot = match winner {
        EntryWinner::Remote => {
            let mut s = local.clone();
            s.history.clear();
            s
        }
        EntryWinner::Local => {
            let mut s = remote.clone();
            s.history.clear();
            remap.rebind(&mut s.attachments);
            s
        }
    };

    // Past this point we only need read-only access to the local
    // pool for hashing + history dedup.
    let local_binaries: &[Binary] = remap.local_binaries();
    let mut combined = merge_histories(&local.history, &rebound_remote_history, local_binaries);
    // Dedup the snapshot if a record at its mtime *and content* is
    // already present (avoids spurious duplication on a no-op merge).
    // Tightened in slice 5b per #R21 to use the slice-2 content hash
    // alongside the mtime, matching the slice-4 dedup discipline.
    let snapshot_hash = entry_content_hash(&snapshot, local_binaries);
    let already_present = combined.iter().any(|h| {
        h.times.last_modification_time == snapshot.times.last_modification_time
            && entry_content_hash(h, local_binaries) == snapshot_hash
    });
    if !already_present {
        combined.push(snapshot);
    }

    let mut merged = match winner {
        EntryWinner::Remote => {
            let mut e = remote.clone();
            remap.rebind(&mut e.attachments);
            e
        }
        EntryWinner::Local => local.clone(),
    };
    // Overlay per-field auto-resolutions whose side differs from the
    // bucket winner. Without this the wholesale clone above would
    // silently lose any field where the per-field classifier picked
    // the other side — the "mixed-side field wins" data-loss class.
    // `set_field_from` handles both "take value" (source has the
    // field) and "clear field" (source lacks it, for custom keys) the
    // same way `build_resolved_entry` does for the conflict path.
    let winner_side = match winner {
        EntryWinner::Local => Side::Local,
        EntryWinner::Remote => Side::Remote,
    };
    for (key, side) in field_resolutions {
        if *side == winner_side {
            continue;
        }
        let source = match side {
            Side::Local => local,
            Side::Remote => remote,
        };
        set_field_from(&mut merged, source, key);
    }
    // Overlay the icon auto-resolution if the classifier picked a
    // side different from the bucket winner. Mirrors the per-field
    // overlay above; base icon ID is intentionally untouched (rides
    // along with whichever side won the entry-level merge per spec
    // rule 4). `custom_icons` pool reconciliation is the FFI / write-
    // back layer's responsibility — out of scope for v0.1 merge.
    if let Some(side) = icon_resolution {
        if side != winner_side {
            let source = match side {
                Side::Local => local,
                Side::Remote => remote,
            };
            merged.custom_icon_uuid = source.custom_icon_uuid;
        }
    }
    // Apply per-attachment auto-resolutions on top of the entry-level
    // winner's clone, overriding the ride-along behaviour for the names
    // the classifier had a clear answer on.
    apply_attachment_resolutions(&mut merged, local, remote, attachment_resolutions, remap);
    merged.history = combined;
    merged
}

// ---------------------------------------------------------------------------
// Tombstone union
// ---------------------------------------------------------------------------

fn union_tombstones(
    local: &mut Vec<DeletedObject>,
    remote: &[DeletedObject],
    skip: &HashSet<Uuid>,
) {
    let existing: HashSet<(Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        local.iter().map(|t| (t.uuid, t.deleted_at)).collect();
    for t in remote {
        if skip.contains(&t.uuid) {
            // Caller chose KeepLocal for this uuid — drop the remote
            // tombstone from the union so the local entry isn't
            // re-deleted by the format's own merge semantics.
            continue;
        }
        let key = (t.uuid, t.deleted_at);
        if !existing.contains(&key) {
            local.push(DeletedObject::new(t.uuid, t.deleted_at));
        }
    }
}

// ---------------------------------------------------------------------------
// Timestamp reconciliation
// ---------------------------------------------------------------------------

fn reconcile_entry_timestamps_recursive(
    group: &mut Group,
    remote_entries: &HashMap<EntryId, &Entry>,
) {
    for entry in &mut group.entries {
        if let Some(r) = remote_entries.get(&entry.id) {
            take_later_opt(
                &mut entry.times.last_modification_time,
                r.times.last_modification_time,
            );
            take_later_opt(&mut entry.times.last_access_time, r.times.last_access_time);
            take_later_opt(&mut entry.times.location_changed, r.times.location_changed);
        }
    }
    for sub in &mut group.groups {
        reconcile_entry_timestamps_recursive(sub, remote_entries);
    }
}

fn reconcile_group_timestamps_recursive(group: &mut Group, remote: &Vault) {
    let mut remote_by_id: HashMap<GroupId, &Group> = HashMap::new();
    collect_groups(&remote.root, &mut remote_by_id);
    reconcile_group_timestamps_walk(group, &remote_by_id);
}

fn reconcile_group_timestamps_walk(group: &mut Group, remote_by_id: &HashMap<GroupId, &Group>) {
    if let Some(r) = remote_by_id.get(&group.id) {
        take_later_opt(
            &mut group.times.last_modification_time,
            r.times.last_modification_time,
        );
        take_later_opt(&mut group.times.last_access_time, r.times.last_access_time);
        take_later_opt(&mut group.times.location_changed, r.times.location_changed);
    }
    for sub in &mut group.groups {
        reconcile_group_timestamps_walk(sub, remote_by_id);
    }
}

fn take_later_opt(
    target: &mut Option<chrono::DateTime<chrono::Utc>>,
    candidate: Option<chrono::DateTime<chrono::Utc>>,
) {
    match (*target, candidate) {
        (None, Some(c)) => *target = Some(c),
        (Some(t), Some(c)) if c > t => *target = Some(c),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tree helpers
// ---------------------------------------------------------------------------

fn find_entry(group: &Group, id: EntryId) -> Option<&Entry> {
    if let Some(e) = group.entries.iter().find(|e| e.id == id) {
        return Some(e);
    }
    group.groups.iter().find_map(|g| find_entry(g, id))
}

fn replace_entry(group: &mut Group, id: EntryId, new: Entry) {
    if let Some(pos) = group.entries.iter().position(|e| e.id == id) {
        group.entries[pos] = new;
        return;
    }
    for sub in &mut group.groups {
        replace_entry(sub, id, new.clone());
    }
}

fn remove_entry(group: &mut Group, id: EntryId) -> bool {
    if let Some(pos) = group.entries.iter().position(|e| e.id == id) {
        group.entries.remove(pos);
        return true;
    }
    for sub in &mut group.groups {
        if remove_entry(sub, id) {
            return true;
        }
    }
    false
}

fn find_remote_parent(group: &Group, entry_id: EntryId) -> Option<GroupId> {
    if group.entries.iter().any(|e| e.id == entry_id) {
        return Some(group.id);
    }
    group
        .groups
        .iter()
        .find_map(|g| find_remote_parent(g, entry_id))
}

fn find_group_mut(group: &mut Group, id: GroupId) -> Option<&mut Group> {
    if group.id == id {
        return Some(group);
    }
    group.groups.iter_mut().find_map(|g| find_group_mut(g, id))
}

fn collect_entries<'a>(group: &'a Group, out: &mut HashMap<EntryId, &'a Entry>) {
    for e in &group.entries {
        out.insert(e.id, e);
    }
    for sub in &group.groups {
        collect_entries(sub, out);
    }
}

fn collect_groups<'a>(group: &'a Group, out: &mut HashMap<GroupId, &'a Group>) {
    out.insert(group.id, group);
    for sub in &group.groups {
        collect_groups(sub, out);
    }
}

fn collect_group_ids_walk(g: &Group, out: &mut std::collections::HashSet<GroupId>) {
    out.insert(g.id);
    for sub in &g.groups {
        collect_group_ids_walk(sub, out);
    }
}

fn collect_group_ids(group: &Group) -> std::collections::HashSet<GroupId> {
    let mut out = std::collections::HashSet::new();
    collect_group_ids_walk(group, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::{apply_merge, reconcile_timestamps};
    use crate::conflict::{EntryConflict, FieldDelta, FieldDeltaKind};
    use crate::resolution::{ConflictSide, DeleteEditChoice};
    use crate::{MergeError, MergeOutcome, Resolution, merge};
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{DeletedObject, Entry, EntryId, Group, GroupId, Timestamps, Vault};
    use std::collections::HashMap;
    use uuid::Uuid;

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn entry(id: u128, title: &str, ts: Timestamps) -> Entry {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
        e.title = title.into();
        e.times = ts;
        e
    }

    fn vault_with(entries: Vec<Entry>) -> Vault {
        let mut v = Vault::empty(GroupId(Uuid::nil()));
        v.root.entries = entries;
        v
    }

    #[test]
    fn auto_apply_disk_only_changes_overwrites_with_remote_and_keeps_history() {
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local_entry = entry(1, "A", at(2026, 1));
        local_entry.history = vec![ancestor.clone()];
        let mut remote_entry = entry(1, "B", at(2026, 2));
        remote_entry.history = vec![ancestor];

        let mut local = vault_with(vec![local_entry.clone()]);
        let remote = vault_with(vec![remote_entry]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.disk_only_changes.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        let merged = &local.root.entries[0];
        assert_eq!(merged.title, "B");
        // History contains: ancestor (deduped) + pre-merge local snapshot.
        assert!(merged.history.iter().any(|h| h.title == "A"
            && h.times.last_modification_time == at(2026, 1).last_modification_time));
    }

    #[test]
    fn auto_apply_local_only_changes_keeps_local_content() {
        let ancestor = entry(1, "A", at(2026, 1));
        let mut local_entry = entry(1, "B", at(2026, 2));
        local_entry.history = vec![ancestor.clone()];
        let mut remote_entry = entry(1, "A", at(2026, 1));
        remote_entry.history = vec![ancestor];

        let mut local = vault_with(vec![local_entry]);
        let remote = vault_with(vec![remote_entry]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.local_only_changes.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        // Local content stays.
        assert_eq!(local.root.entries[0].title, "B");
    }

    #[test]
    fn added_on_disk_inserts_under_local_root_when_remote_parent_missing() {
        let local = Vault::empty(GroupId(Uuid::nil()));
        let mut local = local;
        let remote_only = entry(7, "from-remote", at(2026, 1));
        let remote = vault_with(vec![remote_only.clone()]);
        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.added_on_disk.len(), 1);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(
            local
                .root
                .entries
                .iter()
                .any(|e| e.id == EntryId(Uuid::from_u128(7)))
        );
    }

    #[test]
    fn added_on_disk_mirrors_remote_subgroup_path() {
        // Remote has a subgroup "child" with an entry inside; local
        // already has the same subgroup id. Apply should insert the
        // entry into local's matching subgroup, not into root.
        let child_id = GroupId(Uuid::from_u128(0xc));
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local.root.groups.push(Group::empty(child_id));

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_child = Group::empty(child_id);
        remote_child.entries.push(entry(7, "in-child", at(2026, 1)));
        remote.root.groups.push(remote_child);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.entries.is_empty());
        assert_eq!(local.root.groups[0].entries.len(), 1);
        assert_eq!(local.root.groups[0].entries[0].title, "in-child");
    }

    #[test]
    fn deleted_on_disk_removes_local_entry_and_unions_tombstone() {
        let local_entry = entry(1, "doomed", at(2026, 1));
        let mut local = vault_with(vec![local_entry]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.deleted_on_disk, vec![EntryId(Uuid::from_u128(1))]);

        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.entries.is_empty());
        // Tombstone now in local.
        assert_eq!(local.deleted_objects.len(), 1);
        assert_eq!(local.deleted_objects[0].uuid, Uuid::from_u128(1));
    }

    #[test]
    fn tombstone_union_dedupes_by_exact_tuple() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let id = Uuid::from_u128(1);
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        local
            .deleted_objects
            .push(DeletedObject::new(id, Some(when)));
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        // Same uuid+deleted_at — dedup.
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(when)));
        // Same uuid, different deleted_at — both preserved.
        let other_when = Utc.with_ymd_and_hms(2026, 2, 1, 0, 0, 0).unwrap();
        remote
            .deleted_objects
            .push(DeletedObject::new(id, Some(other_when)));

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(
            local.deleted_objects.len(),
            2,
            "exact-tuple dedup must preserve same-uuid different-time"
        );
    }

    #[test]
    fn group_tree_lww_takes_later_metadata() {
        // Same group id on both sides; remote has a later mtime and a
        // different name. After apply, local takes remote's name.
        let id = GroupId(Uuid::from_u128(0xaa));
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let mut local_g = Group::empty(id);
        local_g.name = "old".into();
        local_g.times = at(2026, 1);
        local.root.groups.push(local_g);

        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_g = Group::empty(id);
        remote_g.name = "new".into();
        remote_g.times = at(2026, 5);
        remote.root.groups.push(remote_g);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert_eq!(local.root.groups[0].name, "new");
    }

    #[test]
    fn group_tree_lww_adds_remote_only_group() {
        let id = GroupId(Uuid::from_u128(0xbb));
        let local = Vault::empty(GroupId(Uuid::nil()));
        let mut local = local;
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        let mut remote_g = Group::empty(id);
        remote_g.name = "new-group".into();
        remote.root.groups.push(remote_g);

        let outcome = merge(&local, &remote).expect("merge");
        apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

        assert!(local.root.groups.iter().any(|g| g.id == id));
    }

    // ---------- slice 5b: validation + conflict-driven apply ----------

    fn make_entry_conflict(
        id: u128,
        local_title: &str,
        remote_title: &str,
        ts: Timestamps,
    ) -> EntryConflict {
        let l = entry(id, local_title, ts.clone());
        let r = entry(id, remote_title, ts);
        EntryConflict {
            entry_id: EntryId(Uuid::from_u128(id)),
            local: l,
            remote: r,
            field_deltas: vec![FieldDelta {
                key: "Title".into(),
                kind: FieldDeltaKind::BothDiffer,
            }],
            attachment_deltas: Vec::new(),
            icon_delta: None,
        }
    }

    #[test]
    fn validation_extra_entry_in_resolution_returns_unknown_entry() {
        let outcome = MergeOutcome::default();
        let mut resolution = Resolution::default();
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(99)), HashMap::new());
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let remote = Vault::empty(GroupId(Uuid::nil()));
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(err, MergeError::UnknownEntryInResolution { .. }));
    }

    #[test]
    fn validation_extra_field_key_returns_unknown_field() {
        let mut outcome = MergeOutcome::default();
        outcome
            .entry_conflicts
            .push(make_entry_conflict(1, "L", "R", at(2026, 1)));
        let mut resolution = Resolution::default();
        let mut fields = HashMap::new();
        fields.insert("Title".into(), ConflictSide::Local);
        fields.insert("BogusField".into(), ConflictSide::Local);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), fields);
        let mut local = vault_with(vec![entry(1, "L", at(2026, 1))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 1))]);
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(err, MergeError::UnknownFieldInResolution { .. }));
    }

    #[test]
    fn validation_missing_entry_conflict_returns_missing_resolution() {
        let mut outcome = MergeOutcome::default();
        outcome
            .entry_conflicts
            .push(make_entry_conflict(1, "L", "R", at(2026, 1)));
        let resolution = Resolution::default();
        let mut local = vault_with(vec![entry(1, "L", at(2026, 1))]);
        let remote = vault_with(vec![entry(1, "R", at(2026, 1))]);
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(
            err,
            MergeError::MissingResolutionForConflict { .. }
        ));
    }

    #[test]
    fn validation_missing_delete_edit_returns_missing_resolution() {
        let mut outcome = MergeOutcome::default();
        outcome
            .delete_edit_conflicts
            .push(EntryId(Uuid::from_u128(1)));
        let resolution = Resolution::default();
        let mut local = Vault::empty(GroupId(Uuid::nil()));
        let remote = Vault::empty(GroupId(Uuid::nil()));
        let err = apply_merge(&mut local, &remote, &outcome, &resolution).unwrap_err();
        assert!(matches!(
            err,
            MergeError::MissingResolutionForConflict { .. }
        ));
    }

    #[test]
    fn entry_conflict_apply_with_remote_choice_overwrites_field() {
        let mut local_e = entry(1, "L", at(2026, 1));
        local_e.username = "alice".into();
        let mut remote_e = entry(1, "R", at(2026, 1));
        remote_e.username = "bob".into();
        let conflict = EntryConflict {
            entry_id: EntryId(Uuid::from_u128(1)),
            local: local_e.clone(),
            remote: remote_e.clone(),
            field_deltas: vec![
                FieldDelta {
                    key: "Title".into(),
                    kind: FieldDeltaKind::BothDiffer,
                },
                FieldDelta {
                    key: "UserName".into(),
                    kind: FieldDeltaKind::BothDiffer,
                },
            ],
            attachment_deltas: Vec::new(),
            icon_delta: None,
        };
        let mut outcome = MergeOutcome::default();
        outcome.entry_conflicts.push(conflict);

        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        choices.insert("UserName".into(), ConflictSide::Local);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        let mut local = vault_with(vec![local_e]);
        let remote = vault_with(vec![remote_e]);
        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let merged = &local.root.entries[0];
        assert_eq!(merged.title, "R", "Title resolved Remote");
        assert_eq!(merged.username, "alice", "UserName resolved Local");
        // Pre-merge local snapshot landed in history.
        assert!(
            merged
                .history
                .iter()
                .any(|h| h.title == "L" && h.username == "alice")
        );
    }

    #[test]
    fn delete_edit_keep_local_drops_remote_tombstone_and_keeps_entry() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let mut local = vault_with(vec![entry(1, "kept", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));
        // Override: pretend local edited after the tombstone so the
        // bucket lands in delete_edit_conflicts.
        local.root.entries[0].times.last_modification_time =
            Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.delete_edit_conflicts.len(), 1);

        let mut resolution = Resolution::default();
        resolution
            .delete_edit_choices
            .insert(EntryId(Uuid::from_u128(1)), DeleteEditChoice::KeepLocal);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        assert!(
            local
                .root
                .entries
                .iter()
                .any(|e| e.id == EntryId(Uuid::from_u128(1)))
        );
        assert!(
            !local
                .deleted_objects
                .iter()
                .any(|t| t.uuid == Uuid::from_u128(1)),
            "KeepLocal must drop the remote tombstone"
        );
    }

    #[test]
    fn delete_edit_accept_remote_removes_entry_and_propagates_tombstone() {
        let when = Utc.with_ymd_and_hms(2026, 1, 5, 0, 0, 0).unwrap();
        let mut local = vault_with(vec![entry(1, "doomed", at(2026, 1))]);
        let mut remote = Vault::empty(GroupId(Uuid::nil()));
        remote
            .deleted_objects
            .push(DeletedObject::new(Uuid::from_u128(1), Some(when)));
        local.root.entries[0].times.last_modification_time =
            Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap());

        let outcome = merge(&local, &remote).expect("merge");
        let mut resolution = Resolution::default();
        resolution.delete_edit_choices.insert(
            EntryId(Uuid::from_u128(1)),
            DeleteEditChoice::AcceptRemoteDelete,
        );

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        assert!(local.root.entries.is_empty());
        assert!(
            local
                .deleted_objects
                .iter()
                .any(|t| t.uuid == Uuid::from_u128(1))
        );
    }

    #[test]
    fn applied_conflict_is_idempotent_under_remerge() {
        // Apply a resolution; re-merge the resulting vault against
        // the original remote; outcome should be conflict-free.
        let mut local_e = entry(1, "L", at(2026, 1));
        local_e.username = "alice".into();
        let mut remote_e = entry(1, "R", at(2026, 1));
        remote_e.username = "bob".into();

        let mut local = vault_with(vec![local_e.clone()]);
        let remote = vault_with(vec![remote_e.clone()]);

        let outcome = merge(&local, &remote).expect("merge");
        assert_eq!(outcome.entry_conflicts.len(), 1);

        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        choices.insert("UserName".into(), ConflictSide::Remote);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let outcome2 = merge(&local, &remote).expect("re-merge");
        assert!(
            outcome2.entry_conflicts.is_empty(),
            "second merge should produce no further conflicts"
        );
    }

    #[test]
    fn snapshot_dedup_uses_content_hash_at_same_mtime() {
        // Two entries share an mtime but differ in content; the
        // pre-merge local snapshot must be preserved (not collapsed
        // against an existing combined record at the same mtime
        // whose content differs).
        let ancestor = entry(1, "ancestor", at(2026, 1));
        let mut local_e = entry(1, "local-now", at(2026, 5));
        local_e.history = vec![ancestor.clone()];
        let mut remote_e = entry(1, "remote-now", at(2026, 5));
        // Insert a remote history record at the local-now mtime but
        // with different content. Without the content-hash check the
        // snapshot would collapse against this record.
        let mut decoy = entry(1, "decoy", at(2026, 5));
        decoy.history.clear();
        remote_e.history = vec![ancestor, decoy];

        let mut local = vault_with(vec![local_e.clone()]);
        let remote = vault_with(vec![remote_e]);
        let outcome = merge(&local, &remote).expect("merge");
        // Both local and remote share an mtime → conflict; resolve
        // remote so build_resolved_entry exercises the dedup path.
        let mut resolution = Resolution::default();
        let mut choices = HashMap::new();
        choices.insert("Title".into(), ConflictSide::Remote);
        resolution
            .entry_field_choices
            .insert(EntryId(Uuid::from_u128(1)), choices);

        apply_merge(&mut local, &remote, &outcome, &resolution).expect("apply");

        let merged = &local.root.entries[0];
        // Snapshot of pre-merge local ("local-now") must be present.
        assert!(
            merged.history.iter().any(|h| h.title == "local-now"),
            "snapshot of overwritten local content must be preserved despite mtime collision with decoy"
        );
    }

    #[test]
    fn reconcile_timestamps_takes_later_per_entry() {
        let mut local_entry = entry(1, "A", at(2026, 1));
        local_entry.times.last_access_time =
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap());

        let mut remote_entry = entry(1, "A", at(2026, 1));
        let later = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
        remote_entry.times.last_access_time = Some(later);

        let mut local = vault_with(vec![local_entry]);
        let remote = vault_with(vec![remote_entry]);

        reconcile_timestamps(&mut local, &remote);

        assert_eq!(local.root.entries[0].times.last_access_time, Some(later));
    }
}
