//! Portable cross-vault export / import verbs — snapshot an entry into a
//! self-contained [`PortableEntry`] carrier and re-insert it (into the same
//! or a different vault) with pool dedup and identity bookkeeping.
//!
//! Mirrors [`entry_ops`](crate::vault_ops::entry_ops) and
//! [`recycle`](crate::vault_ops::recycle): every verb is a free fn over the
//! [`Vault`] (`&Vault` for the read-only export, `&mut Vault` + `&dyn Clock`
//! for the mutating imports), and [`Kdbx<Unlocked>`](crate::kdbx::Kdbx) keeps
//! a thin delegating wrapper for each public one
//! ([`export_entry`], [`import_entry`], [`import_entry_with_uuid`]) so the
//! public API is byte-for-byte unchanged.
//!
//! Export is **read-only**: it clones the entry, every history snapshot, and
//! the full bytes of every referenced binary and custom icon into the
//! carrier, touching neither the pools nor any timestamp. Import threads the
//! carrier's binaries through the destination binary pool
//! ([`insert_or_dedup_binary`]) and its icons through the destination
//! custom-icon pool ([`add_custom_icon`] on the mint path), remaps the
//! entry's and every snapshot's `ref_id` / `custom_icon_uuid` to the
//! destination indices, and stamps the live entry's bookkeeping. Protected /
//! secret strings ride through the carrier as plain model values — the field
//! protector is never consulted on this path.

use std::collections::HashMap;

use crate::model::{Binary, Clock, Entry, EntryId, GroupId, ModelError, PortableEntry, Vault};
use crate::vault_ops::binaries::insert_or_dedup_binary;
use crate::vault_ops::icons::add_custom_icon;
use crate::vault_ops::ids::{fresh_uuid, uuid_in_use};

/// Free-fn core of [`Kdbx::export_entry`](crate::kdbx::Kdbx::export_entry);
/// see the wrapper for the full contract. Read-only over `&Vault`.
pub(crate) fn export_entry(vault: &Vault, id: EntryId) -> Result<PortableEntry, ModelError> {
    let entry = vault.root.entry(id).ok_or(ModelError::EntryNotFound(id))?;

    // Collect the set of binary ref_ids referenced by the entry
    // or any of its history snapshots. Same live+history walk the
    // binary-pool GC (`gc_binaries_pool`) does over the whole tree.
    let mut binary_refs: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for a in &entry.attachments {
        binary_refs.insert(a.ref_id);
    }
    for snap in &entry.history {
        for a in &snap.attachments {
            binary_refs.insert(a.ref_id);
        }
    }
    let mut binaries: Vec<(u32, Binary)> = binary_refs
        .into_iter()
        .filter_map(|r| vault.binaries.get(r as usize).map(|b| (r, b.clone())))
        .collect();
    binaries.sort_by_key(|(r, _)| *r);

    // Collect the set of custom-icon UUIDs referenced by live +
    // history, then clone the full CustomIcon record for each.
    let mut icon_refs: std::collections::HashSet<uuid::Uuid> = std::collections::HashSet::new();
    if let Some(u) = entry.custom_icon_uuid {
        icon_refs.insert(u);
    }
    for snap in &entry.history {
        if let Some(u) = snap.custom_icon_uuid {
            icon_refs.insert(u);
        }
    }
    let custom_icons: Vec<crate::model::CustomIcon> = vault
        .meta
        .custom_icons
        .iter()
        .filter(|c| icon_refs.contains(&c.uuid))
        .cloned()
        .collect();

    Ok(PortableEntry {
        entry: entry.clone(),
        binaries,
        custom_icons,
    })
}

/// Free-fn core of [`Kdbx::import_entry`](crate::kdbx::Kdbx::import_entry);
/// see the wrapper for the full contract.
pub(crate) fn import_entry(
    vault: &mut Vault,
    clock: &dyn Clock,
    parent: GroupId,
    mut entry: PortableEntry,
    mint_new_uuid: bool,
) -> Result<EntryId, ModelError> {
    if vault.root.group(parent).is_none() {
        return Err(ModelError::GroupNotFound(parent));
    }

    // Validate (or mint) UUIDs for the live entry + every
    // history snapshot before any destination mutation.
    // `DuplicateUuid` must fail cleanly.
    if mint_new_uuid {
        entry.entry.id = EntryId(fresh_uuid(vault));
        for snap in &mut entry.entry.history {
            snap.id = EntryId(fresh_uuid(vault));
        }
    } else {
        if uuid_in_use(vault, entry.entry.id.0) {
            return Err(ModelError::DuplicateUuid(entry.entry.id.0));
        }
        for snap in &entry.entry.history {
            if uuid_in_use(vault, snap.id.0) {
                return Err(ModelError::DuplicateUuid(snap.id.0));
            }
        }
    }

    // Binary-pool remap: content-hash dedup against
    // `vault.binaries`; insert misses, reuse hits.
    let mut binary_remap: HashMap<u32, u32> = HashMap::new();
    for (src_ref, bin) in entry.binaries.drain(..) {
        let dst_ref = insert_or_dedup_binary(vault, bin);
        binary_remap.insert(src_ref, dst_ref);
    }

    // Custom-icon pool remap: UUID-dedup on the mint_new_uuid=false
    // path, content-hash-dedup via `add_custom_icon` on the
    // mint_new_uuid=true path.
    let mut icon_remap: HashMap<uuid::Uuid, uuid::Uuid> = HashMap::new();
    if mint_new_uuid {
        for icon in entry.custom_icons.drain(..) {
            let dst_uuid = add_custom_icon(vault, clock, icon.data.clone());
            icon_remap.insert(icon.uuid, dst_uuid);
        }
    } else {
        for icon in entry.custom_icons.drain(..) {
            let src_uuid = icon.uuid;
            let already_present = vault.meta.custom_icons.iter().any(|c| c.uuid == src_uuid);
            if !already_present {
                vault.meta.custom_icons.push(icon);
                // No `settings_changed` stamp here — adding an
                // entry (and its referenced icons) is shaped
                // like `add_entry`, which doesn't stamp Meta.
            }
            icon_remap.insert(src_uuid, src_uuid);
        }
    }

    // Apply remaps to the live entry and every history snapshot.
    let now = clock.now();
    remap_entry_refs(&mut entry.entry, &binary_remap, &icon_remap);
    for snap in &mut entry.entry.history {
        remap_entry_refs(snap, &binary_remap, &icon_remap);
    }

    // Stamp live-entry bookkeeping per the design notes invariants.
    entry.entry.times.creation_time = Some(now);
    entry.entry.times.last_modification_time = Some(now);
    entry.entry.times.last_access_time = Some(now);
    entry.entry.times.location_changed = Some(now);
    entry.entry.times.usage_count = 0;
    entry.entry.previous_parent_group = None;

    let new_id = entry.entry.id;
    let target = vault
        .root
        .group_mut(parent)
        .expect("parent existence checked at the top of this method");
    target.entries.push(entry.entry);
    Ok(new_id)
}

/// Free-fn core of
/// [`Kdbx::import_entry_with_uuid`](crate::kdbx::Kdbx::import_entry_with_uuid);
/// see the wrapper for the full contract.
pub(crate) fn import_entry_with_uuid(
    vault: &mut Vault,
    clock: &dyn Clock,
    parent: GroupId,
    mut entry: PortableEntry,
    target_uuid: EntryId,
) -> Result<EntryId, ModelError> {
    // Override the live entry's UUID to the caller-specified one.
    // History snapshots get fresh UUIDs — see the doc comment.
    entry.entry.id = target_uuid;
    for snap in &mut entry.entry.history {
        snap.id = EntryId(fresh_uuid(vault));
    }

    // Forgive any matching tombstone before the import collision
    // check runs (uuid_in_use ignores tombstones, but downstream
    // sync would consume the tombstone as "delete this entry"
    // and undo the undo).
    vault.deleted_objects.retain(|t| t.uuid != target_uuid.0);

    // Delegate to import_entry with the preserve-UUID branch. Its
    // uuid_in_use check catches the case where target_uuid is
    // already live in the destination vault (legitimately a
    // bookkeeping error from the caller).
    import_entry(vault, clock, parent, entry, false)
}

/// Apply the binary + custom-icon remaps produced during
/// [`Kdbx::import_entry`](crate::kdbx::Kdbx::import_entry) to a single
/// [`Entry`]. Walks the entry's attachments and `custom_icon_uuid`;
/// callers invoke this once on the live imported entry and once per
/// history snapshot.
fn remap_entry_refs(
    entry: &mut Entry,
    binary_remap: &HashMap<u32, u32>,
    icon_remap: &HashMap<uuid::Uuid, uuid::Uuid>,
) {
    for a in &mut entry.attachments {
        if let Some(&new) = binary_remap.get(&a.ref_id) {
            a.ref_id = new;
        }
    }
    if let Some(u) = entry.custom_icon_uuid {
        if let Some(&new) = icon_remap.get(&u) {
            entry.custom_icon_uuid = Some(new);
        }
    }
}
