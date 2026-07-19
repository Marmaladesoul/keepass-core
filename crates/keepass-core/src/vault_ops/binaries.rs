//! Binary-attachment pool: attach application, refcount GC, and dedup insert.

use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::model::entry_editor::PendingBinaryOps;
use crate::model::{Attachment, Binary, EntryId, Vault};

/// Apply the attach intents staged inside an `edit_entry` closure to
/// the shared [`Vault::binaries`] pool, then push matching
/// [`Attachment`] references onto the target entry.
///
/// Dedup-by-content-hash: SHA-256 of the payload paired with the
/// `protected` flag is the dedup key. Identical-bytes-but-different-
/// flag attachments stay as separate pool entries because the
/// `protected` flag rides on the binary itself in the KDBX4 inner
/// header (and on the `Protected="True"` `<Value>` attribute on
/// KDBX3); coalescing them would silently flip the flag for one
/// caller.
pub(crate) fn apply_pending_attaches(vault: &mut Vault, id: EntryId, pending: PendingBinaryOps) {
    if pending.attaches.is_empty() {
        return;
    }
    // Index existing pool by (content hash, protected). Take the
    // earliest index on a collision so dedup is deterministic.
    let mut hash_to_idx: HashMap<([u8; 32], bool), u32> = HashMap::new();
    for (i, b) in vault.binaries.iter().enumerate() {
        let h: [u8; 32] = Sha256::digest(&b.data).into();
        hash_to_idx
            .entry((h, b.protected))
            .or_insert_with(|| u32::try_from(i).expect("pool idx fits u32"));
    }

    let mut new_attachments: Vec<Attachment> = Vec::with_capacity(pending.attaches.len());
    for att in pending.attaches {
        let h: [u8; 32] = Sha256::digest(&att.data).into();
        let key = (h, att.protected);
        let ref_id = if let Some(&idx) = hash_to_idx.get(&key) {
            idx
        } else {
            let idx = u32::try_from(vault.binaries.len()).expect("pool idx fits u32");
            vault.binaries.push(Binary {
                data: att.data,
                protected: att.protected,
            });
            hash_to_idx.insert(key, idx);
            idx
        };
        new_attachments.push(Attachment {
            name: att.name,
            ref_id,
        });
    }

    if let Some(e) = vault.entry_mut(id) {
        e.attachments.extend(new_attachments);
    }
}

/// Refcount-aware garbage collection of [`Vault::binaries`].
///
/// Walks every entry (and every history snapshot) in the vault to
/// build the set of `ref_id`s that are still in use, then drops any
/// pool entry not in that set and renumbers the surviving
/// references so the indexes stay contiguous from 0.
///
/// Called from every mutation that can orphan a binary —
/// `edit_entry` (after `detach`), `delete_entry`, `delete_group`,
/// `restore_history` — and once more inside `do_save` as defence in
/// depth. A `detach` shrinks the pool only when the very last
/// reference (in any entry, this one or another) is gone, so a binary
/// shared between two entries survives a detach from one of them.
pub(crate) fn gc_binaries_pool(vault: &mut Vault) {
    let mut in_use: HashSet<u32> = HashSet::new();
    for e in vault.iter_entries() {
        for a in &e.attachments {
            in_use.insert(a.ref_id);
        }
        // History snapshots are themselves `Entry` values that carry
        // their own attachment lists; dropping a pool entry a snapshot
        // still references would corrupt the saved file.
        for snap in &e.history {
            for a in &snap.attachments {
                in_use.insert(a.ref_id);
            }
        }
    }

    let n = vault.binaries.len();
    let n_u32 = u32::try_from(n).expect("pool size fits u32");
    if (0..n_u32).all(|i| in_use.contains(&i)) {
        return;
    }

    // Old-index → new-index mapping; `None` for dropped entries.
    let mut remap: Vec<Option<u32>> = Vec::with_capacity(n);
    let mut next: u32 = 0;
    for i in 0..n_u32 {
        if in_use.contains(&i) {
            remap.push(Some(next));
            next += 1;
        } else {
            remap.push(None);
        }
    }

    let kept: Vec<Binary> = vault
        .binaries
        .drain(..)
        .enumerate()
        .filter(|(i, _)| remap[*i].is_some())
        .map(|(_, b)| b)
        .collect();
    vault.binaries = kept;

    // Rewrite every attachment ref_id (live + history) through the
    // old->new index remap so the surviving references stay contiguous.
    for e in vault.iter_entries_mut() {
        for a in &mut e.attachments {
            if let Some(Some(new)) = remap.get(a.ref_id as usize) {
                a.ref_id = *new;
            }
        }
        for snap in &mut e.history {
            for a in &mut snap.attachments {
                if let Some(Some(new)) = remap.get(a.ref_id as usize) {
                    a.ref_id = *new;
                }
            }
        }
    }
}

/// Append `bin` to [`Vault::binaries`] if no existing binary has
/// identical `(data, protected)`; otherwise return the existing
/// slot's `ref_id`. Used by [`Kdbx::import_entry`](crate::kdbx::Kdbx::import_entry) to dedup
/// imported attachment bytes against the destination pool.
///
/// Content-hash comparison uses SHA-256 so a large shared
/// attachment (e.g. a company-logo PNG on many entries) imports
/// exactly once. The `protected` flag is part of the dedup key
/// because the same bytes with a different inner-stream encryption
/// flag are semantically different binaries (the on-disk
/// representation differs).
pub(crate) fn insert_or_dedup_binary(vault: &mut Vault, bin: Binary) -> u32 {
    let incoming: [u8; 32] = Sha256::digest(&bin.data).into();
    for (idx, existing) in vault.binaries.iter().enumerate() {
        if existing.protected == bin.protected {
            let h: [u8; 32] = Sha256::digest(&existing.data).into();
            if h == incoming {
                return u32::try_from(idx).expect("pool index fits u32");
            }
        }
    }
    let new_ref = u32::try_from(vault.binaries.len()).expect("pool index fits u32");
    vault.binaries.push(bin);
    new_ref
}
