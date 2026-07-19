//! Clean entry CRUD verbs — the ones whose only collaborators are the
//! [`Vault`] tree and (where a mutation stamps timestamps) an injected
//! [`Clock`].
//!
//! These are the "clean" half of the entry surface: insert, delete,
//! move, the read-touch pair, and the two history-bookkeeping verbs.
//! None of them need the field protector or its side-table, so each is
//! a free fn over `&mut Vault` (+ `&dyn Clock` only where it stamps a
//! time). The protector-threading verbs — `edit_entry` and
//! `restore_entry_from_history` — deliberately stay on
//! [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) because they also touch the
//! protector and the wrapped-field side-table.
//!
//! [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps a thin delegating wrapper
//! for every verb here, so the public API is byte-for-byte unchanged.

use crate::model::{
    AutoType, Clock, DeletedObject, Entry, EntryId, GroupId, ModelError, NewEntry, Timestamps,
    Vault,
};
use crate::vault_ops::binaries::gc_binaries_pool;
use crate::vault_ops::history::truncate_history;
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
