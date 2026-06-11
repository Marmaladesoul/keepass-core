//! Whole-vault content digest for replica-convergence checks.
//!
//! [`vault_content_digest`] produces a SHA-256 over a canonical,
//! domain-tagged bytestream of a vault's *user-visible content*: the
//! group tree (identity, name, notes, icon, parentage) and every
//! entry's location, content hash, and icon. Two replicas that have
//! genuinely converged — same entries with the same fields, in the
//! same groups, with the same icons — produce the same digest
//! regardless of declaration order in the XML; any user-visible
//! divergence produces different digests.
//!
//! The driving consumer is sync convergence testing (keyhole's
//! two-process fuzz harness asserts `digest(A) == digest(B)` after a
//! bidirectional merge), but the definition is deliberately
//! client-agnostic.
//!
//! Per-entry content identity is the same canonicalisation the
//! history-LCA walker uses (`hash::entry_content_hash`), so "what
//! counts as the same entry content" has exactly one definition in
//! this crate. Two deliberate *additions* on top of it, because this
//! digest answers "are these replicas equal?" rather than "is this
//! the same entry version?":
//!
//! - **Location.** Each entry contributes its parent group id; a
//!   moved entry changes the digest even though its content hash is
//!   unchanged.
//! - **Icon.** Excluded from `entry_content_hash` for LCA-matching
//!   reasons (favicon writes don't push history snapshots), but two
//!   replicas that differ only in an entry's icon have *not*
//!   converged, so the digest hashes each entry's `icon_id` /
//!   `custom_icon_uuid` alongside its content hash.
//!
//! Excluded, deliberately:
//!
//! - **History.** Replica histories can legitimately differ in depth
//!   (e.g. one side pruned); convergence is about current state.
//! - **Timestamps.** Merge reconciliation aligns the winners, but
//!   access times and similar are noise for equality purposes.
//! - **Tombstones (`deleted_objects`).** A delete manifests as the
//!   *absence* of the entry, which the digest already sees; tombstone
//!   bookkeeping (deletion times in particular) is transport-level
//!   state, not user-visible content.
//! - **UI / client state**: `is_expanded`, auto-type config, custom
//!   data, and all `Meta` fields except the recycle-bin pointer (bin
//!   enablement and identity are user-visible vault behaviour).
//!
//! Stability contract: same as `hash::entry_content_hash` —
//! deterministic for a given `keepass-merge` build, **not** stable
//! across releases or implementations. Compare digests produced by
//! the same build; do not persist them.

use keepass_core::model::{Group, GroupId, Vault};
use sha2::{Digest, Sha256};

use crate::hash::entry_content_hash;

/// Domain tags for the digest's sections, disjoint from the
/// per-entry tags in `hash` (which occupy 0x01–0x04) so the two
/// canonical streams can never be confused.
const SECTION_GROUPS: u8 = 0x10;
const SECTION_ENTRIES: u8 = 0x11;
const SECTION_META: u8 = 0x12;

/// Digest a vault's user-visible content. See module docs for scope.
#[must_use]
pub fn vault_content_digest(vault: &Vault) -> [u8; 32] {
    let mut groups: Vec<(&Group, Option<GroupId>)> = Vec::new();
    collect_groups(&vault.root, None, &mut groups);
    groups.sort_by_key(|(g, _)| g.id.0.as_bytes().to_owned());

    let mut hasher = Sha256::new();

    hasher.update([SECTION_GROUPS]);
    for (group, parent) in &groups {
        hasher.update(group.id.0.as_bytes());
        update_optional_uuid(&mut hasher, parent.map(|p| p.0));
        update_len_prefixed(&mut hasher, group.name.as_bytes());
        update_len_prefixed(&mut hasher, group.notes.as_bytes());
        hasher.update(group.icon_id.to_le_bytes());
        update_optional_uuid(&mut hasher, group.custom_icon_uuid);
    }

    // Entries, sorted by uuid across the whole tree. The parent group
    // id makes the digest move-sensitive; the icon pair restores the
    // icon's contribution that `entry_content_hash` deliberately
    // omits.
    let mut entries: Vec<(&keepass_core::model::Entry, GroupId)> = Vec::new();
    for (group, _) in &groups {
        for entry in &group.entries {
            entries.push((entry, group.id));
        }
    }
    entries.sort_by_key(|(e, _)| e.id.0.as_bytes().to_owned());

    hasher.update([SECTION_ENTRIES]);
    for (entry, parent) in entries {
        hasher.update(entry.id.0.as_bytes());
        hasher.update(parent.0.as_bytes());
        hasher.update(entry_content_hash(entry, &vault.binaries));
        hasher.update(entry.icon_id.to_le_bytes());
        update_optional_uuid(&mut hasher, entry.custom_icon_uuid);
    }

    hasher.update([SECTION_META]);
    hasher.update([u8::from(vault.meta.recycle_bin_enabled)]);
    update_optional_uuid(&mut hasher, vault.meta.recycle_bin_uuid.map(|g| g.0));

    hasher.finalize().into()
}

/// Flatten the group tree into `(group, parent)` pairs, root included
/// (with `None` for its parent).
fn collect_groups<'v>(
    group: &'v Group,
    parent: Option<GroupId>,
    out: &mut Vec<(&'v Group, Option<GroupId>)>,
) {
    out.push((group, parent));
    for child in &group.groups {
        collect_groups(child, Some(group.id), out);
    }
}

/// Hash an optional UUID unambiguously: a presence byte, then the 16
/// raw bytes only when present. (A bare zeroed-UUID encoding would
/// collide "absent" with the nil UUID.)
fn update_optional_uuid(hasher: &mut Sha256, uuid: Option<uuid::Uuid>) {
    match uuid {
        Some(u) => {
            hasher.update([1u8]);
            hasher.update(u.as_bytes());
        }
        None => hasher.update([0u8]),
    }
}

/// Length-prefix (u32 LE) and write a byte slice, mirroring the
/// convention in `hash`.
fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    debug_assert!(
        u32::try_from(bytes.len()).is_ok(),
        "field bytes exceed u32::MAX — refusing to truncate length prefix",
    );
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u32;
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use keepass_core::model::{Entry, EntryId, Group, GroupId, Vault};
    use uuid::Uuid;

    use super::vault_content_digest;

    fn uuid(n: u8) -> Uuid {
        Uuid::from_bytes([n; 16])
    }

    fn group(n: u8, name: &str) -> Group {
        let mut g = Group::empty(GroupId(uuid(n)));
        g.name = name.to_owned();
        g
    }

    fn entry(n: u8, title: &str) -> Entry {
        let mut e = Entry::empty(EntryId(uuid(n)));
        e.title = title.to_owned();
        e
    }

    fn vault(root: Group) -> Vault {
        let mut v = Vault::empty(GroupId(uuid(1)));
        v.root = root;
        v
    }

    /// Two-group tree with one entry in each, children in the given
    /// order.
    fn two_group_vault(order_swapped: bool) -> Vault {
        let mut a = group(2, "alpha");
        a.entries.push(entry(10, "in-alpha"));
        let mut b = group(3, "beta");
        b.entries.push(entry(11, "in-beta"));

        let mut root = group(1, "root");
        if order_swapped {
            root.groups = vec![b, a];
        } else {
            root.groups = vec![a, b];
        }
        vault(root)
    }

    #[test]
    fn deterministic() {
        let v = two_group_vault(false);
        assert_eq!(vault_content_digest(&v), vault_content_digest(&v));
    }

    #[test]
    fn declaration_order_invariant() {
        // Same content, different sibling order in the tree — the
        // digest must not care how the XML happened to be written.
        assert_eq!(
            vault_content_digest(&two_group_vault(false)),
            vault_content_digest(&two_group_vault(true)),
        );
    }

    #[test]
    fn entry_field_change_diverges() {
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        v2.root.groups[0].entries[0].password = "changed".to_owned();
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v2));
    }

    #[test]
    fn entry_move_diverges() {
        // Same entry content, different parent group: NOT converged.
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        let moved = v2.root.groups[0].entries.remove(0);
        v2.root.groups[1].entries.push(moved);
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v2));
    }

    #[test]
    fn entry_icon_diverges() {
        // Icon is outside entry_content_hash (LCA reasons) but two
        // replicas differing only by icon have not converged.
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        v2.root.groups[0].entries[0].icon_id = 7;
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v2));

        let mut v3 = two_group_vault(false);
        v3.root.groups[0].entries[0].custom_icon_uuid = Some(uuid(9));
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v3));
    }

    #[test]
    fn group_rename_diverges() {
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        v2.root.groups[0].name = "renamed".to_owned();
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v2));
    }

    #[test]
    fn recycle_bin_meta_diverges() {
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        v2.meta.recycle_bin_enabled = true;
        assert_ne!(vault_content_digest(&v1), vault_content_digest(&v2));

        let mut v3 = two_group_vault(false);
        v3.meta.recycle_bin_enabled = true;
        v3.meta.recycle_bin_uuid = Some(GroupId(uuid(3)));
        assert_ne!(vault_content_digest(&v2), vault_content_digest(&v3));
    }

    #[test]
    fn history_and_timestamps_ignored() {
        // History depth and timestamps are replica bookkeeping, not
        // user-visible content — replicas may legitimately differ.
        let v1 = two_group_vault(false);
        let mut v2 = two_group_vault(false);
        let snapshot = v2.root.groups[0].entries[0].clone();
        v2.root.groups[0].entries[0].history.push(snapshot);
        assert_eq!(vault_content_digest(&v1), vault_content_digest(&v2));
    }
}
