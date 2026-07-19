//! Group CRUD verbs — insert, recursive delete, move / reorder, and the
//! closure-based field edit.
//!
//! Mirrors [`entry_ops`](crate::vault_ops::entry_ops): every verb is a
//! free fn over `&mut Vault` (+ `&dyn Clock` wherever it stamps a time),
//! and [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps a thin delegating
//! wrapper for each so the public API is byte-for-byte unchanged.
//!
//! The two movers — push-to-end ([`move_group`]) and clamped-insert
//! ([`move_group_to_position`]) — share one core, [`move_group_inner`],
//! which differs only in whether it pushes or inserts at a clamped index;
//! everything else (root guard, destination check, cycle rejection,
//! detach + re-attach, `location_changed` stamp) is identical.

use crate::model::{Clock, Group, GroupEditor, GroupId, ModelError, NewGroup, Timestamps, Vault};
use crate::vault_ops::binaries::gc_binaries_pool;
use crate::vault_ops::ids::{fresh_uuid, uuid_in_use};
use crate::vault_ops::tombstones::collect_subtree_tombstones;

/// Free-fn core of [`Kdbx::add_group`](crate::kdbx::Kdbx::add_group);
/// see the wrapper for the full contract.
pub(crate) fn add_group(
    vault: &mut Vault,
    clock: &dyn Clock,
    parent: GroupId,
    template: NewGroup,
) -> Result<GroupId, ModelError> {
    let uuid = match template.uuid {
        Some(u) => {
            if uuid_in_use(vault, u) {
                return Err(ModelError::DuplicateUuid(u));
            }
            u
        }
        None => fresh_uuid(vault),
    };

    if vault.root.group(parent).is_none() {
        return Err(ModelError::GroupNotFound(parent));
    }

    let now = clock.now();
    let group = Group {
        id: GroupId(uuid),
        name: template.name,
        notes: template.notes,
        groups: Vec::new(),
        entries: Vec::new(),
        is_expanded: true,
        default_auto_type_sequence: String::new(),
        enable_auto_type: template.enable_auto_type,
        enable_searching: template.enable_searching,
        custom_data: Vec::new(),
        previous_parent_group: None,
        last_top_visible_entry: None,
        custom_icon_uuid: None,
        times: Timestamps {
            creation_time: Some(now),
            last_modification_time: Some(now),
            last_access_time: Some(now),
            location_changed: Some(now),
            expiry_time: None,
            expires: false,
            usage_count: 0,
        },
        icon_id: template.icon_id,
        unknown_xml: Vec::new(),
    };

    let target = vault
        .root
        .group_mut(parent)
        .expect("parent existence checked above");
    target.groups.push(group);
    Ok(GroupId(uuid))
}

/// Free-fn core of [`Kdbx::delete_group`](crate::kdbx::Kdbx::delete_group);
/// see the wrapper for the full contract.
pub(crate) fn delete_group(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
) -> Result<(), ModelError> {
    if vault.root.id == id {
        return Err(ModelError::CannotDeleteRoot);
    }
    let now = clock.now();
    let removed = vault
        .root
        .detach_group(id)
        .map(|(g, _)| g)
        .ok_or(ModelError::GroupNotFound(id))?;
    // Tombstone every entry and subgroup recursively, in addition
    // to the group itself.
    let tombstones = collect_subtree_tombstones(&removed, now);
    vault.deleted_objects.extend(tombstones);
    // Same rationale as `delete_entry`: a whole subtree's worth of
    // attachments may have just lost their last referent, and the
    // worst case (delete a group full of attachments) is exactly
    // the situation where leaking orphan binaries to the next save
    // hurts most.
    gc_binaries_pool(vault);
    Ok(())
}

/// Free-fn core of [`Kdbx::move_group`](crate::kdbx::Kdbx::move_group);
/// see the wrapper for the full contract. Pushes the moved group to the
/// end of `new_parent`'s children.
pub(crate) fn move_group(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
    new_parent: GroupId,
) -> Result<(), ModelError> {
    move_group_inner(vault, clock, id, new_parent, None)
}

/// Free-fn core of
/// [`Kdbx::move_group_to_position`](crate::kdbx::Kdbx::move_group_to_position);
/// see the wrapper for the full contract. Inserts the moved group at
/// `position` among `new_parent`'s children, clamped to the end.
pub(crate) fn move_group_to_position(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
    new_parent: GroupId,
    position: usize,
) -> Result<(), ModelError> {
    move_group_inner(vault, clock, id, new_parent, Some(position))
}

/// Shared core of the two group movers: root guard → destination check →
/// cycle rejection → detach → `location_changed` stamp → re-attach.
///
/// The only behavioural knob is `position`:
/// - `None` pushes the moved group to the end of `new_parent`'s children
///   (the [`move_group`] contract).
/// - `Some(i)` inserts it at index `i`, clamped to the destination's
///   current child count so an out-of-range index appends (the
///   [`move_group_to_position`] contract).
///
/// Because the clamp point is measured *after* the source is detached,
/// `None` and `Some(i)` for any `i >=` the destination's post-detach
/// child count produce byte-identical trees.
fn move_group_inner(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
    new_parent: GroupId,
    position: Option<usize>,
) -> Result<(), ModelError> {
    if vault.root.id == id {
        // Root has no parent and reparenting it would orphan the
        // whole vault.
        return Err(ModelError::CannotDeleteRoot);
    }

    // Check the destination exists before touching anything.
    if vault.root.group(new_parent).is_none() {
        return Err(ModelError::GroupNotFound(new_parent));
    }

    // Cycle check: walk `id`'s subtree (including `id` itself)
    // and reject if `new_parent` lives inside it.
    let Some(source_subtree) = vault.root.group(id) else {
        return Err(ModelError::GroupNotFound(id));
    };
    if source_subtree.group(new_parent).is_some() {
        return Err(ModelError::CircularMove {
            moving: id,
            new_parent,
        });
    }

    let (mut group, old_parent) = vault
        .root
        .detach_group(id)
        .ok_or(ModelError::GroupNotFound(id))?;
    let now = clock.now();
    group.previous_parent_group = Some(old_parent);
    group.times.location_changed = Some(now);

    let target = vault
        .root
        .group_mut(new_parent)
        .expect("destination existence checked above");
    match position {
        None => target.groups.push(group),
        Some(pos) => {
            let clamped = pos.min(target.groups.len());
            target.groups.insert(clamped, group);
        }
    }
    Ok(())
}

/// Free-fn core of [`Kdbx::edit_group`](crate::kdbx::Kdbx::edit_group);
/// see the wrapper for the full contract.
pub(crate) fn edit_group<R>(
    vault: &mut Vault,
    clock: &dyn Clock,
    id: GroupId,
    f: impl FnOnce(&mut GroupEditor<'_>) -> R,
) -> Result<R, ModelError> {
    let now = clock.now();
    let group = vault
        .root
        .group_mut(id)
        .ok_or(ModelError::GroupNotFound(id))?;
    let result = {
        let mut editor = GroupEditor::new(group);
        f(&mut editor)
    };
    group.times.last_modification_time = Some(now);
    Ok(result)
}
