//! Entry CRUD verbs — insert, delete, move, the read-touch pair, the
//! history-bookkeeping verbs, and the two protector-threading mutators
//! (`edit_entry` / `restore_entry_from_history`).
//!
//! The "clean" half (insert, delete, move, read-touch, history
//! bookkeeping) collaborates only with the [`Vault`] tree and — where a
//! mutation stamps timestamps — an injected [`Clock`], so each is a free
//! fn over `&mut Vault` (+ `&dyn Clock` only where it stamps a time).
//!
//! `edit_entry` and `restore_entry_from_history` additionally thread the
//! field protector and its wrapped-field side-table. Following the same
//! injection idiom as [`reveal`](crate::vault_ops::reveal), they take
//! `protector: Option<&dyn FieldProtector>` and
//! `protected_fields: &mut ProtectedFieldMap` as explicit params rather
//! than reaching for state on the [`Vault`]. The wrap/unwrap-with-key
//! primitives themselves stay in [`crate::kdbx`]
//! ([`wrap_entry_with_key`](crate::kdbx::wrap_entry_with_key) /
//! [`unwrap_entry_with_key`](crate::kdbx::unwrap_entry_with_key)), which
//! these verbs call across a deliberate, minimal back-reference.
//!
//! [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps a thin delegating wrapper
//! for every verb here — the protector-threading pair destructures its
//! `Unlocked` state into the four disjoint borrows the free fn needs —
//! so the public API is byte-for-byte unchanged.

use crate::kdbx::{ProtectedFieldMap, unwrap_entry_with_key, wrap_entry_with_key};
use crate::model::{
    AutoType, Binary, Clock, DeletedObject, Entry, EntryEditor, EntryId, GroupId, HistoryPolicy,
    ModelError, NewEntry, Timestamps, Vault,
};
use crate::protector::FieldProtector;
use crate::vault_ops::binaries::{apply_pending_attaches, gc_binaries_pool};
use crate::vault_ops::history::{should_snapshot_now, truncate_history};
use crate::vault_ops::ids::{fresh_uuid, uuid_in_use};

/// Free-fn core of [`Kdbx::add_entry`](crate::kdbx::Kdbx::add_entry);
/// see the wrapper for the full contract.
pub(crate) fn add_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    parent: GroupId,
    template: NewEntry,
) -> Result<EntryId, ModelError> {
    let uuid = match template.uuid {
        Some(u) => {
            if uuid_in_use(vault, u) {
                return Err(ModelError::DuplicateUuid(u));
            }
            u
        }
        None => fresh_uuid(vault),
    };

    // Locate the target parent up front so we fail early.
    if vault.root.group(parent).is_none() {
        return Err(ModelError::GroupNotFound(parent));
    }

    let now = clock.now();
    let entry = Entry {
        id: EntryId(uuid),
        title: template.title,
        username: template.username,
        password: template.password,
        url: template.url,
        notes: template.notes,
        custom_fields: Vec::new(),
        tags: template.tags,
        history: Vec::new(),
        attachments: Vec::new(),
        foreground_color: String::new(),
        background_color: String::new(),
        override_url: String::new(),
        custom_icon_uuid: None,
        custom_data: Vec::new(),
        quality_check: true,
        previous_parent_group: None,
        auto_type: AutoType::default(),
        times: Timestamps {
            creation_time: Some(now),
            last_modification_time: Some(now),
            last_access_time: Some(now),
            location_changed: Some(now),
            expiry_time: None,
            expires: false,
            usage_count: 0,
        },
        icon_id: 0,
        unknown_xml: Vec::new(),
    };

    // Re-locate under &mut; infallible because we just checked.
    let target = vault
        .root
        .group_mut(parent)
        .expect("group existence checked above");
    target.entries.push(entry);
    Ok(EntryId(uuid))
}

/// Free-fn core of [`Kdbx::delete_entry`](crate::kdbx::Kdbx::delete_entry);
/// see the wrapper for the full contract.
pub(crate) fn delete_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: EntryId,
) -> Result<(), ModelError> {
    let (removed, _old_parent) = vault
        .root
        .detach_entry(id)
        .ok_or(ModelError::EntryNotFound(id))?;
    let now = clock.now();
    vault
        .deleted_objects
        .push(DeletedObject::new(removed.id.0, Some(now)));
    // The deleted entry may have been the last referent of one or
    // more pool binaries. Reap them now so the post-condition
    // "vault.binaries holds only bytes still reachable from a live
    // entry" holds for any caller reading the vault between
    // `delete_entry` and `save_to_bytes`.
    gc_binaries_pool(vault);
    Ok(())
}

/// Free-fn core of [`Kdbx::move_entry`](crate::kdbx::Kdbx::move_entry);
/// see the wrapper for the full contract.
pub(crate) fn move_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: EntryId,
    new_parent: GroupId,
) -> Result<(), ModelError> {
    // Check the destination first so a failure leaves the entry
    // where it was.
    if vault.root.group(new_parent).is_none() {
        return Err(ModelError::GroupNotFound(new_parent));
    }

    let (mut entry, old_parent) = vault
        .root
        .detach_entry(id)
        .ok_or(ModelError::EntryNotFound(id))?;

    entry.previous_parent_group = Some(old_parent);
    let now = clock.now();
    entry.times.location_changed = Some(now);

    let target = vault
        .root
        .group_mut(new_parent)
        .expect("destination existence checked above");
    target.entries.push(entry);
    Ok(())
}

/// Free-fn core of [`Kdbx::touch_entry`](crate::kdbx::Kdbx::touch_entry);
/// see the wrapper for the full contract.
pub(crate) fn touch_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: EntryId,
) -> Result<(), ModelError> {
    let now = clock.now();
    let entry = vault
        .root
        .entry_mut(id)
        .ok_or(ModelError::EntryNotFound(id))?;
    entry.times.last_access_time = Some(now);
    Ok(())
}

/// Free-fn core of [`Kdbx::clear_entry_last_access`](crate::kdbx::Kdbx::clear_entry_last_access);
/// see the wrapper for the full contract.
pub(crate) fn clear_entry_last_access(vault: &mut Vault, id: EntryId) -> Result<(), ModelError> {
    let entry = vault
        .root
        .entry_mut(id)
        .ok_or(ModelError::EntryNotFound(id))?;
    entry.times.last_access_time = None;
    Ok(())
}

/// Free-fn core of [`Kdbx::trim_entry_history`](crate::kdbx::Kdbx::trim_entry_history);
/// see the wrapper for the full contract.
pub(crate) fn trim_entry_history(vault: &mut Vault, id: EntryId) -> Result<u32, ModelError> {
    let history_max_items = vault.meta.history_max_items;
    let history_max_size = vault.meta.history_max_size;
    let entry = vault
        .root
        .entry_mut(id)
        .ok_or(ModelError::EntryNotFound(id))?;
    let before = entry.history.len();
    truncate_history(&mut entry.history, history_max_items, history_max_size);
    let removed = before - entry.history.len();
    // `before - after` is bounded by history length; `u32::MAX`
    // snapshots is many orders of magnitude past anything KeePass
    // emits in practice, so the cast is safe.
    Ok(u32::try_from(removed).unwrap_or(u32::MAX))
}

/// Free-fn core of [`Kdbx::prune_history_older_than`](crate::kdbx::Kdbx::prune_history_older_than);
/// see the wrapper for the full contract.
pub(crate) fn prune_history_older_than(
    vault: &mut Vault,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> usize {
    let mut removed = 0;
    for entry in vault.root.iter_entries_mut() {
        let before = entry.history.len();
        entry.history.retain(|snap| {
            snap.times
                .last_modification_time
                .is_some_and(|t| t >= cutoff)
        });
        removed += before - entry.history.len();
    }
    removed
}

/// Free-fn core of [`Kdbx::edit_entry`](crate::kdbx::Kdbx::edit_entry);
/// see the wrapper for the full contract.
///
/// Threads four pieces of state the clean verbs don't need: the field
/// `protector` and its `protected_fields` side-table (respectively
/// `None` / untouched on the no-protector path), alongside `vault` and
/// `clock`. With a protector configured the session key is acquired
/// exactly once per edit and reused for the pre-edit unwrap and the
/// post-edit re-wrap.
///
/// # Errors
///
/// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
/// - [`ModelError::Protector`] when a [`FieldProtector`] is configured
///   and acquiring the session key or re-wrapping the live protected
///   slots after the closure runs fails.
pub(crate) fn edit_entry<R>(
    vault: &mut Vault,
    clock: &dyn Clock,
    protector: Option<&dyn FieldProtector>,
    protected_fields: &mut ProtectedFieldMap,
    id: EntryId,
    policy: HistoryPolicy,
    f: impl FnOnce(&mut EntryEditor<'_>) -> R,
) -> Result<R, ModelError> {
    // Hoist everything we need off the vault before we take a
    // long-lived `&mut Entry` borrow — the borrow checker otherwise
    // forbids touching `clock` / meta through the rest of the fn.
    let now = clock.now();
    let history_max_items = vault.meta.history_max_items;
    let history_max_size = vault.meta.history_max_size;
    // Capture the pre-edit wrapped record so the editor closure can
    // operate on plaintext, then we re-wrap everything (live fields +
    // every history snapshot) once it returns. When no protector is
    // configured the unwrap/rewrap bookkeeping is skipped entirely.
    let old_record = protector.and_then(|_| protected_fields.get(&id).cloned());

    let entry = vault
        .root
        .entry_mut(id)
        .ok_or(ModelError::EntryNotFound(id))?;

    // Restore plaintext on the entry from the side-table so the
    // editor closure reads "current" values from `entry.password`
    // / protected custom fields, and any snapshot we clone next
    // captures the up-to-date plaintext for save-time use. This
    // mirror's the save pipeline's `unwrap_vault_protected_fields`
    // step on a single entry.
    // Per-edit key: acquired once if a protector is configured AND
    // this entry has wrapped fields. Used for both the pre-edit
    // unwrap and the post-edit re-wrap below so the editor pays
    // a single `acquire_session_key` call per edit cycle.
    let edit_key = match (protector, old_record.as_ref()) {
        (Some(p), Some(_)) => Some(p.acquire_session_key()?),
        _ => None,
    };
    if let (Some(rec), Some(k)) = (old_record.as_ref(), edit_key.as_ref()) {
        unwrap_entry_with_key(entry, rec, k)?;
    }

    let should_snapshot = should_snapshot_now(policy, &entry.history, now);

    if should_snapshot {
        let mut snap = entry.clone();
        // KeePass history entries never nest their own history.
        snap.history.clear();
        entry.history.push(snap);
        truncate_history(&mut entry.history, history_max_items, history_max_size);
    }

    // Scope the editor borrow so `entry` is freely usable again
    // when we stamp the last-modification timestamp below. Pull
    // any staged attach intents out of the editor before its
    // borrow drops — they get applied against the Vault's
    // shared binaries pool after the &mut Entry borrow ends.
    // Split-borrow: `entry` is &mut into `vault.root`; the binary
    // pool is a sibling field of the same Vault. Rust allows holding
    // both borrows simultaneously because they target disjoint fields.
    let binaries: &[Binary] = &vault.binaries;
    let (result, pending) = {
        let mut editor = EntryEditor::new(entry, binaries);
        let r = f(&mut editor);
        let p = editor.take_pending_binary_ops();
        (r, p)
    };

    entry.times.last_modification_time = Some(now);

    // Re-wrap the entry's protected fields (live + every history
    // snapshot) into a fresh side-table record so the canonical
    // "model holds empty plaintext, side-table holds wrapped
    // bytes" invariant is restored. Without this the save-time
    // unwrap step blindly restores the OLD wrapped bytes over
    // whatever the editor wrote and the edit is lost.
    let new_record = match (protector, edit_key.as_ref()) {
        (Some(_), Some(k)) => Some(wrap_entry_with_key(entry, k)?),
        (Some(p), None) => {
            // Edit on an entry that didn't have a wrapped record
            // before this edit (e.g. all protected fields were
            // empty). Acquire a key now to wrap the new state.
            let k = p.acquire_session_key()?;
            Some(wrap_entry_with_key(entry, &k)?)
        }
        _ => None,
    };

    // The &mut Entry borrow ends here; from this point on we
    // have &mut Vault available for pool-level work.
    let _ = entry;

    apply_pending_attaches(vault, id, pending);
    gc_binaries_pool(vault);

    if let Some(new_record) = new_record {
        protected_fields.insert(id, new_record);
    }

    Ok(result)
}

/// Free-fn core of
/// [`Kdbx::restore_entry_from_history`](crate::kdbx::Kdbx::restore_entry_from_history);
/// see the wrapper for the full contract.
///
/// Threads the same four pieces of state as [`edit_entry`]; with a
/// protector configured the session key is acquired exactly once per
/// restore and reused for the pre-restore unwrap and the post-restore
/// re-wrap.
///
/// # Errors
///
/// - [`ModelError::EntryNotFound`] if `id` is not in the vault.
/// - [`ModelError::HistoryIndexOutOfRange`] if `history_index` is
///   `>= entry.history.len()`.
/// - [`ModelError::Protector`] when a [`FieldProtector`] is configured
///   and acquiring the session key, unwrapping the pre-restore snapshot
///   plaintext, or re-wrapping the restored fields fails.
pub(crate) fn restore_entry_from_history(
    vault: &mut Vault,
    clock: &dyn Clock,
    protector: Option<&dyn FieldProtector>,
    protected_fields: &mut ProtectedFieldMap,
    id: EntryId,
    history_index: usize,
    policy: HistoryPolicy,
) -> Result<(), ModelError> {
    // Hoist off the vault before the `&mut Entry` borrow, same reason
    // as `edit_entry`.
    let now = clock.now();
    let history_max_items = vault.meta.history_max_items;
    let history_max_size = vault.meta.history_max_size;
    // Capture the pre-restore wrapped record so we can unwrap the live
    // entry (and its history snapshots) to plaintext before reading the
    // target snapshot, then re-wrap the restored entry into a fresh
    // side-table record afterwards. Mirror of `edit_entry`: with a
    // protector configured the model `String`s are blanked and the real
    // bytes live in the side-table, so a raw `snap.password` read would
    // see the empty post-wrap string and the side-table would still
    // point at the pre-restore ciphertext. When no protector is
    // configured all of this is skipped and the path is
    // behaviour-identical to before.
    let old_record = protector.and_then(|_| protected_fields.get(&id).cloned());

    let entry = vault
        .root
        .entry_mut(id)
        .ok_or(ModelError::EntryNotFound(id))?;

    if history_index >= entry.history.len() {
        return Err(ModelError::HistoryIndexOutOfRange {
            id,
            index: history_index,
            len: entry.history.len(),
        });
    }

    // Per-restore key: acquired once if a protector is configured
    // AND this entry has wrapped fields. Used for both the
    // pre-restore unwrap and the post-restore re-wrap so we pay a
    // single `acquire_session_key` call per restore.
    let restore_key = match (protector, old_record.as_ref()) {
        (Some(p), Some(_)) => Some(p.acquire_session_key()?),
        _ => None,
    };
    // Restore plaintext onto the live entry and every history
    // snapshot from the side-table, so the snapshot we clone next
    // carries real plaintext (not the blanked post-wrap string) and
    // any pre-restore snapshot we push captures live plaintext.
    if let (Some(rec), Some(k)) = (old_record.as_ref(), restore_key.as_ref()) {
        unwrap_entry_with_key(entry, rec, k)?;
    }

    // Clone the target snapshot out before mutating history — once
    // we push the pre-restore snapshot the index shifts.
    let snap = entry.history[history_index].clone();

    if should_snapshot_now(policy, &entry.history, now) {
        let mut pre_restore = entry.clone();
        // KeePass never nests history; the snapshot we're pushing
        // represents the live entry at call time, not "live + all
        // its prior history".
        pre_restore.history.clear();
        entry.history.push(pre_restore);
    }

    // ---- Restore content -----------------------------------------
    // Explicit field-by-field copy so the restore set is auditable
    // at this call site. Excluded fields are documented on the
    // method; if a new field lands on `Entry`, the reviewer sees
    // this block and decides its restore policy deliberately.
    entry.title = snap.title;
    entry.username = snap.username;
    entry.password = snap.password;
    entry.url = snap.url;
    entry.notes = snap.notes;
    entry.tags = snap.tags;
    entry.custom_fields = snap.custom_fields;
    entry.attachments = snap.attachments;
    entry.foreground_color = snap.foreground_color;
    entry.background_color = snap.background_color;
    entry.override_url = snap.override_url;
    entry.custom_icon_uuid = snap.custom_icon_uuid;
    entry.icon_id = snap.icon_id;
    entry.quality_check = snap.quality_check;
    entry.auto_type = snap.auto_type;
    // Expiry is wire-split into two fields, but semantically one —
    // the `set_expiry` setter unifies them at the API boundary and
    // we copy them atomically here so a stale `expires=false` can't
    // linger alongside a freshly-restored `expiry_time`.
    entry.times.expires = snap.times.expires;
    entry.times.expiry_time = snap.times.expiry_time;

    // Stamp the restore as an edit, so UIs that sort by
    // last-modification show this entry at the top.
    entry.times.last_modification_time = Some(now);

    truncate_history(&mut entry.history, history_max_items, history_max_size);

    // Re-wrap the restored entry (live protected fields + every
    // surviving history snapshot) into a fresh side-table record so
    // the canonical "model holds empty plaintext, side-table holds
    // wrapped bytes" invariant is restored around the new content.
    // Truncation ran first, so the record's history aligns
    // positionally with `entry.history`. Without this the save-time
    // unwrap step blindly overlays the OLD wrapped bytes over the
    // restored plaintext and the restore is lost on save. Mirror of
    // `edit_entry`'s post-edit re-wrap.
    let new_record = match (protector, restore_key.as_ref()) {
        (Some(_), Some(k)) => Some(wrap_entry_with_key(entry, k)?),
        (Some(p), None) => {
            // Restore on an entry that had no wrapped record before
            // (e.g. all protected fields were empty at unlock).
            // Acquire a key now to wrap the restored state.
            let k = p.acquire_session_key()?;
            Some(wrap_entry_with_key(entry, &k)?)
        }
        _ => None,
    };

    // End the entry borrow so the vault is accessible again for
    // pool GC.
    let _ = entry;
    gc_binaries_pool(vault);

    if let Some(new_record) = new_record {
        protected_fields.insert(id, new_record);
    }

    Ok(())
}
