//! Custom-icon pool: dedup insert, save-time GC, and the icon verbs.

use std::collections::HashSet;

use sha2::{Digest, Sha256};

use crate::model::{Clock, CustomIcon, Vault};
use crate::vault_ops::meta_settings::stamp_settings_changed;

/// Free-fn core of [`Kdbx::add_custom_icon`](crate::kdbx::Kdbx::add_custom_icon);
/// see the wrapper for the full contract.
pub(crate) fn add_custom_icon(vault: &mut Vault, clock: &dyn Clock, data: Vec<u8>) -> uuid::Uuid {
    let (uuid, inserted) = add_or_dedup_icon(vault, data);
    if inserted {
        stamp_settings_changed(vault, clock);
    }
    uuid
}

/// Free-fn core of [`Kdbx::remove_custom_icon`](crate::kdbx::Kdbx::remove_custom_icon);
/// see the wrapper for the full contract.
pub(crate) fn remove_custom_icon(vault: &mut Vault, clock: &dyn Clock, id: uuid::Uuid) -> bool {
    let before = vault.meta.custom_icons.len();
    vault.meta.custom_icons.retain(|c| c.uuid != id);
    if vault.meta.custom_icons.len() < before {
        stamp_settings_changed(vault, clock);
        true
    } else {
        false
    }
}

/// Free-fn core of [`Kdbx::custom_icon`](crate::kdbx::Kdbx::custom_icon);
/// see the wrapper for the full contract.
pub(crate) fn custom_icon(vault: &Vault, id: uuid::Uuid) -> Option<&[u8]> {
    vault
        .meta
        .custom_icons
        .iter()
        .find(|c| c.uuid == id)
        .map(|c| c.data.as_slice())
}

/// Insertion + content-hash dedup core for [`Kdbx::add_custom_icon`](crate::kdbx::Kdbx::add_custom_icon).
///
/// Returns `(uuid, inserted)`. When `inserted == true`, a fresh icon
/// was pushed and the caller should stamp
/// [`crate::model::Meta::settings_changed`]; when `false`, dedup hit
/// an existing icon and nothing about the pool has changed (so no
/// stamp).
///
/// Extracted from the public method so a unit test can assert the
/// load-bearing idempotence invariant directly — `name` and
/// `last_modified` on an existing icon must NOT be overwritten by a
/// same-bytes re-insertion. Neither field is on the public surface
/// yet, so crossing the integration-test boundary without an
/// `unsafe` pointer cast or a test-only accessor isn't possible.
fn add_or_dedup_icon(vault: &mut Vault, data: Vec<u8>) -> (uuid::Uuid, bool) {
    let incoming: [u8; 32] = Sha256::digest(&data).into();
    for existing in &vault.meta.custom_icons {
        let hash: [u8; 32] = Sha256::digest(&existing.data).into();
        if hash == incoming {
            return (existing.uuid, false);
        }
    }
    let uuid = fresh_icon_uuid(vault);
    vault.meta.custom_icons.push(CustomIcon {
        uuid,
        data,
        name: String::new(),
        last_modified: None,
    });
    (uuid, true)
}

/// Generate a fresh v4 UUID that doesn't collide with any existing
/// custom-icon UUID in [`Vault::meta::custom_icons`]. Entry/group
/// UUIDs live in a different semantic namespace (the wire format
/// doesn't cross-reference them), but `Uuid::new_v4()` is globally
/// unique anyway; the loop is belt-and-braces.
fn fresh_icon_uuid(vault: &Vault) -> uuid::Uuid {
    loop {
        let candidate = uuid::Uuid::new_v4();
        if !vault.meta.custom_icons.iter().any(|c| c.uuid == candidate) {
            return candidate;
        }
    }
}

/// Save-time refcount GC for [`Vault::meta::custom_icons`].
///
/// Walks every entry (live + every `history[]` snapshot) and every
/// group to collect the set of `custom_icon_uuid` values actually
/// referenced, prunes the pool to that set, and sweeps any surviving
/// reference that no longer resolves (e.g. because the caller ran
/// `remove_custom_icon(X)` without unsetting the field) back to
/// `None`. The on-disk invariant "every `<CustomIconUUID>` resolves
/// in `<CustomIcons>`" is restored before the bytes hit the wire.
///
/// **Rhythm divergence from `gc_binaries_pool`**: the binary-pool GC
/// runs inside every mutation that can orphan a binary
/// (`edit_entry`/`detach`, `delete_entry`, `delete_group`,
/// `restore_history`) so that `vault.binaries` reflects only
/// reachable bytes for any caller reading the vault between mutations
/// — the per-entry `attachments` accessor is part of the public
/// surface and callers can plausibly index into the pool. Icons
/// neither have a bulk accessor yet nor can they be orphaned by a
/// content edit (only by the explicit `remove_custom_icon`, whose
/// docstring already warns callers), so the icon GC runs only on
/// save. This keeps the hot `edit_entry` path from paying for a tree
/// walk it doesn't need.
pub(crate) fn gc_custom_icons_pool(vault: &mut Vault) {
    let mut in_use: HashSet<uuid::Uuid> = HashSet::new();
    // Group icons come from every group; entry icons come from every
    // entry plus each of its history snapshots (a snapshot carries its
    // own `custom_icon_uuid` that must keep its icon alive in the pool).
    for g in vault.iter_groups() {
        if let Some(u) = g.custom_icon_uuid {
            in_use.insert(u);
        }
    }
    for e in vault.iter_entries() {
        if let Some(u) = e.custom_icon_uuid {
            in_use.insert(u);
        }
        for snap in &e.history {
            if let Some(u) = snap.custom_icon_uuid {
                in_use.insert(u);
            }
        }
    }
    vault.meta.custom_icons.retain(|c| in_use.contains(&c.uuid));

    // Dangling-ref sweep: any entry/group custom_icon_uuid that
    // doesn't resolve in the post-prune pool gets reset to None.
    // Without this the wire format would carry an unresolvable
    // reference.
    let pool: HashSet<uuid::Uuid> = vault.meta.custom_icons.iter().map(|c| c.uuid).collect();
    vault.for_each_group_mut(&mut |g| {
        if let Some(u) = g.custom_icon_uuid {
            if !pool.contains(&u) {
                g.custom_icon_uuid = None;
            }
        }
        for e in &mut g.entries {
            if let Some(u) = e.custom_icon_uuid {
                if !pool.contains(&u) {
                    e.custom_icon_uuid = None;
                }
            }
            for snap in &mut e.history {
                if let Some(u) = snap.custom_icon_uuid {
                    if !pool.contains(&u) {
                        snap.custom_icon_uuid = None;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Timestamps;

    fn empty_vault() -> Vault {
        use crate::model::{Group, GroupId, Meta};
        Vault {
            root: Group {
                id: GroupId(uuid::Uuid::nil()),
                name: String::new(),
                notes: String::new(),
                groups: Vec::new(),
                entries: Vec::new(),
                is_expanded: true,
                default_auto_type_sequence: String::new(),
                enable_auto_type: None,
                enable_searching: None,
                custom_data: Vec::new(),
                previous_parent_group: None,
                last_top_visible_entry: None,
                custom_icon_uuid: None,
                icon_id: 0,
                times: Timestamps::default(),
                unknown_xml: Vec::new(),
            },
            meta: Meta::default(),
            binaries: Vec::new(),
            deleted_objects: Vec::new(),
        }
    }

    #[test]
    fn add_or_dedup_icon_dedup_preserves_existing_metadata() {
        // First insert establishes the icon, then we hand-label it
        // to simulate a caller that has previously named it. A
        // second insert with the same bytes must dedup back to the
        // same UUID AND leave `name` / `last_modified` alone —
        // otherwise any Keys "re-register this icon" flow would
        // silently wipe user-set labels.
        let mut vault = empty_vault();
        let (first, inserted) = add_or_dedup_icon(&mut vault, b"icon-bytes".to_vec());
        assert!(inserted);
        vault.meta.custom_icons[0].name = "My Label".to_owned();
        let marker_ts: chrono::DateTime<chrono::Utc> = "2024-05-06T07:08:09Z".parse().unwrap();
        vault.meta.custom_icons[0].last_modified = Some(marker_ts);

        let (second, inserted) = add_or_dedup_icon(&mut vault, b"icon-bytes".to_vec());
        assert_eq!(first, second, "dedup returns the existing UUID");
        assert!(!inserted, "dedup must not stamp settings_changed");
        assert_eq!(vault.meta.custom_icons.len(), 1);
        assert_eq!(vault.meta.custom_icons[0].name, "My Label");
        assert_eq!(vault.meta.custom_icons[0].last_modified, Some(marker_ts));
    }

    #[test]
    fn add_or_dedup_icon_different_bytes_mint_new_entry() {
        let mut vault = empty_vault();
        let (a, inserted_a) = add_or_dedup_icon(&mut vault, b"first".to_vec());
        let (b, inserted_b) = add_or_dedup_icon(&mut vault, b"second".to_vec());
        assert!(inserted_a && inserted_b);
        assert_ne!(a, b);
        assert_eq!(vault.meta.custom_icons.len(), 2);
    }
}
