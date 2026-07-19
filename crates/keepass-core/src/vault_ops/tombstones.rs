//! Subtree tombstone collection for group deletion.

use crate::model::{DeletedObject, Group};

/// Build a [`DeletedObject`] tombstone (stamped `at`) for the group
/// itself plus every entry and every subgroup recursively under it,
/// in depth-first order. Used by `delete_group` so a peer replica
/// merging against this vault can distinguish deleted records from
/// never-seen ones.
pub(crate) fn collect_subtree_tombstones(
    group: &Group,
    at: chrono::DateTime<chrono::Utc>,
) -> Vec<DeletedObject> {
    let mut out = Vec::new();
    push_subtree_tombstones(group, at, &mut out);
    out
}

fn push_subtree_tombstones(
    group: &Group,
    at: chrono::DateTime<chrono::Utc>,
    out: &mut Vec<DeletedObject>,
) {
    for e in &group.entries {
        out.push(DeletedObject::new(e.id.0, Some(at)));
    }
    for child in &group.groups {
        push_subtree_tombstones(child, at, out);
    }
    out.push(DeletedObject::new(group.id.0, Some(at)));
}
