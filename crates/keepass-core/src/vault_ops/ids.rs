//! UUID collision checks and fresh-UUID minting over a [`Vault`] tree.

use crate::model::{Group, Vault};

/// `true` if `candidate` matches any existing entry id, group id, or
/// the root group id. Used by [`Kdbx::add_entry`](crate::kdbx::Kdbx::add_entry) to reject
/// caller-supplied UUIDs that would collide.
pub(crate) fn uuid_in_use(vault: &Vault, candidate: uuid::Uuid) -> bool {
    group_uuid_in_use(&vault.root, candidate)
}

fn group_uuid_in_use(group: &Group, candidate: uuid::Uuid) -> bool {
    if group.id.0 == candidate {
        return true;
    }
    // Walk both the live entry ids AND every history snapshot's id.
    // Tree-wide UUID uniqueness on the wire includes history entries
    // — KeePass writers assign history snapshots their own `<UUID>`
    // element, and `import_entry(mint_new_uuid=false)`'s pre-mutation
    // collision check has to catch incoming UUIDs that collide with
    // a pre-existing history id (not just a live one). Also fixes a
    // latent hole on `add_entry`'s caller-supplied-UUID rejection
    // path, which uses the same helper.
    if group
        .entries
        .iter()
        .any(|e| e.id.0 == candidate || e.history.iter().any(|s| s.id.0 == candidate))
    {
        return true;
    }
    group.groups.iter().any(|g| group_uuid_in_use(g, candidate))
}

/// Generate a fresh v4 UUID that doesn't collide with any existing
/// entry or group in the vault. In practice `Uuid::new_v4()` is
/// globally unique and the loop is belt-and-braces, but the loop
/// makes the "never collide" invariant explicit.
pub(crate) fn fresh_uuid(vault: &Vault) -> uuid::Uuid {
    loop {
        let candidate = uuid::Uuid::new_v4();
        if !uuid_in_use(vault, candidate) {
            return candidate;
        }
    }
}
