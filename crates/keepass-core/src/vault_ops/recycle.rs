//! Recycle-bin policy verbs — soft-delete into the bin, empty the bin,
//! and the lazy bin-creation helper they share.
//!
//! Mirrors [`entry_ops`](crate::vault_ops::entry_ops) and
//! [`group_ops`](crate::vault_ops::group_ops): every verb is a free fn
//! over `&mut Vault` (+ `&dyn Clock`), and
//! [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps a thin delegating wrapper
//! for the public ones ([`recycle_entry`], [`recycle_group`],
//! [`empty_recycle_bin`]) so the public API is byte-for-byte unchanged.
//!
//! This layer owns *policy only* — the relocate-into-bin and
//! permanent-delete mechanics are delegated to the already-extracted
//! entry / group verbs ([`move_entry`], [`move_group`], [`delete_entry`],
//! [`delete_group`]), and the settings stamp to
//! [`stamp_settings_changed`]. The bin-disabled fallback (both
//! `recycle_bin_enabled = false` **and** `recycle_bin_uuid` is `None`)
//! hard-deletes via the `delete_*` verbs; a bin that merely has
//! `enabled = false` is still honoured for soft-delete.

use crate::model::{Clock, EntryId, GroupId, ModelError, NewGroup, Vault};
use crate::vault_ops::entry_ops::{delete_entry, move_entry};
use crate::vault_ops::group_ops::{add_group, delete_group, move_group};
use crate::vault_ops::meta_settings::stamp_settings_changed;

/// Free-fn core of [`Kdbx::recycle_entry`](crate::kdbx::Kdbx::recycle_entry);
/// see the wrapper for the full contract.
pub(crate) fn recycle_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: EntryId,
) -> Result<Option<GroupId>, ModelError> {
    // Validate existence + get the entry's current parent group.
    let parent = vault
        .root
        .entry_parent(id)
        .ok_or(ModelError::EntryNotFound(id))?;

    // `recycle_bin_enabled = false` → hard delete, no bin.
    if !vault.meta.recycle_bin_enabled && vault.meta.recycle_bin_uuid.is_none() {
        // Only fall through to hard-delete when BOTH enabled is
        // false AND no bin exists. If a bin exists (even with
        // enabled=false), respect it — matches KeePassXC's
        // "bin exists, you can still use it" flexibility.
        delete_entry(vault, clock, id)?;
        return Ok(None);
    }

    // Already inside the bin? Walk ancestors from the parent
    // group up to root; any ancestor == bin → no-op.
    if let Some(bin_id) = vault.meta.recycle_bin_uuid {
        if vault
            .root
            .group(bin_id)
            .is_some_and(|bin| bin.group(parent).is_some())
        {
            return Ok(None);
        }
    }

    let bin_id = find_or_create_recycle_bin(vault, clock)?;
    move_entry(vault, clock, id, bin_id)?;
    Ok(Some(bin_id))
}

/// Free-fn core of [`Kdbx::recycle_group`](crate::kdbx::Kdbx::recycle_group);
/// see the wrapper for the full contract.
pub(crate) fn recycle_group(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
) -> Result<Option<GroupId>, ModelError> {
    if vault.root.group(id).is_none() {
        return Err(ModelError::GroupNotFound(id));
    }
    if id == vault.root.id {
        return Err(ModelError::CannotDeleteRoot);
    }

    // Same fallback logic as `recycle_entry`.
    if !vault.meta.recycle_bin_enabled && vault.meta.recycle_bin_uuid.is_none() {
        delete_group(vault, clock, id)?;
        return Ok(None);
    }

    // Is `id` the bin itself? → CircularMove.
    if let Some(bin_id) = vault.meta.recycle_bin_uuid {
        if bin_id == id && vault.root.group(bin_id).is_some() {
            return Err(ModelError::CircularMove {
                moving: id,
                new_parent: bin_id,
            });
        }
        // Already inside the bin?
        if vault
            .root
            .group(bin_id)
            .is_some_and(|bin| bin.group(id).is_some())
        {
            return Ok(None);
        }
    }

    let bin_id = find_or_create_recycle_bin(vault, clock)?;
    move_group(vault, clock, id, bin_id)?;
    Ok(Some(bin_id))
}

/// Free-fn core of [`Kdbx::empty_recycle_bin`](crate::kdbx::Kdbx::empty_recycle_bin);
/// see the wrapper for the full contract.
pub(crate) fn empty_recycle_bin(vault: &mut Vault, clock: &dyn Clock) -> Result<usize, ModelError> {
    let Some(bin_id) = vault.meta.recycle_bin_uuid else {
        return Ok(0);
    };
    // Snapshot direct-child ids BEFORE mutating — can't iterate
    // `&mut Vec` while calling `&mut self` delete methods. A
    // dangling `recycle_bin_uuid` resolves to `None` here and
    // we early-return 0.
    let Some(bin) = vault.root.group(bin_id) else {
        return Ok(0);
    };
    let entry_ids: Vec<EntryId> = bin.entries.iter().map(|e| e.id).collect();
    let group_ids: Vec<GroupId> = bin.groups.iter().map(|g| g.id).collect();
    let count = entry_ids.len() + group_ids.len();

    for eid in entry_ids {
        delete_entry(vault, clock, eid)?;
    }
    for gid in group_ids {
        delete_group(vault, clock, gid)?;
    }
    Ok(count)
}

/// Resolve the existing recycle bin group id, or create one
/// lazily under the root if none exists (or if the current
/// `recycle_bin_uuid` dangles). See [`recycle_entry`] for
/// the lazy-creation invariants.
pub(crate) fn find_or_create_recycle_bin(
    vault: &mut Vault,
    clock: &dyn Clock,
) -> Result<GroupId, ModelError> {
    if let Some(bin_id) = vault.meta.recycle_bin_uuid {
        if vault.root.group(bin_id).is_some() {
            return Ok(bin_id);
        }
        // Dangling — fall through and mint a fresh bin. The
        // stale `recycle_bin_uuid` is about to be overwritten
        // below.
    }
    let root = vault.root.id;
    let bin_id = add_group(
        vault,
        clock,
        root,
        NewGroup::new("Recycle Bin")
            .icon_id(43)
            .enable_auto_type(Some(false))
            .enable_searching(Some(false)),
    )?;
    let now = clock.now();
    vault.meta.recycle_bin_enabled = true;
    vault.meta.recycle_bin_uuid = Some(bin_id);
    vault.meta.recycle_bin_changed = Some(now);
    stamp_settings_changed(vault, clock);
    Ok(bin_id)
}
