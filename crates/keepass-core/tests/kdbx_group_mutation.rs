//! Slice 7 — `Kdbx::add_group` / `delete_group` / `move_group` /
//! `edit_group` + [`GroupEditor`].
//!
//! Per MUTATION.md §"Slicing plan" slice 7. Five concerns, one
//! integration test each:
//!
//! 1. **add + edit + save round-trip.** Insert a group, set its name
//!    and notes through `edit_group`, save, re-open, confirm both
//!    survived along with a `last_modification_time` stamp from the
//!    pinned clock.
//! 2. **delete is recursive + tombstones every descendant.** Delete a
//!    group with both a child entry and a child sub-group. After
//!    save → reload, the whole subtree is gone and a `DeletedObject`
//!    record exists for the group, the entry, and the sub-group.
//! 3. **move stamps `previous_parent_group` + `location_changed`.**
//!    Move a leaf group between two siblings; round-trip through save;
//!    confirm the bookkeeping survived.
//! 4. **cycle rejection.** A move that would make the source a
//!    descendant of itself (via its own subtree) returns
//!    `ModelError::CircularMove` and leaves the tree untouched.
//! 5. **root cannot be deleted or moved.** `delete_group(root)` and
//!    `move_group(root, _)` both return `CannotDeleteRoot`.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, ModelError, NewEntry, NewGroup};
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn kdbx4_basic() -> PathBuf {
    fixtures_root().join("kdbxweb/kdbx4-basic.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let sidecar = path.with_extension("json");
    let text = fs::read_to_string(sidecar).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

fn open(at: DateTime<Utc>) -> Kdbx<keepass_core::kdbx::Unlocked> {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap()
}

fn reopen(bytes: Vec<u8>) -> Kdbx<keepass_core::kdbx::Unlocked> {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap()
}

#[test]
fn add_then_edit_then_save_round_trips_name_and_notes() {
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root = kdbx.vault().root.id;

    let id = kdbx.add_group(root, NewGroup::new("Personal")).unwrap();
    kdbx.edit_group(id, |g| {
        g.set_name("Personal Vault");
        g.set_notes("only mine");
    })
    .unwrap();

    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = reopen(bytes);
    let g = reopened
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == id)
        .expect("group survives round-trip");
    assert_eq!(g.name, "Personal Vault");
    assert_eq!(g.notes, "only mine");
    assert_eq!(g.times.last_modification_time, Some(at));
}

#[test]
fn delete_group_tombstones_every_descendant_recursively() {
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root = kdbx.vault().root.id;

    let parent = kdbx.add_group(root, NewGroup::new("Parent")).unwrap();
    let child_group = kdbx
        .add_group(parent, NewGroup::new("Child Group"))
        .unwrap();
    let child_entry = kdbx
        .add_entry(parent, NewEntry::new("Child Entry"))
        .unwrap();

    let tombstones_before = kdbx.vault().deleted_objects.len();
    kdbx.delete_group(parent).unwrap();

    // Three new tombstones: parent, child group, child entry.
    let new_tombstones = &kdbx.vault().deleted_objects[tombstones_before..];
    let mut uuids: Vec<_> = new_tombstones.iter().map(|t| t.uuid).collect();
    uuids.sort();
    let mut expected = vec![parent.0, child_group.0, child_entry.0];
    expected.sort();
    assert_eq!(uuids, expected);
    for t in new_tombstones {
        assert_eq!(t.deleted_at, Some(at));
    }

    // Save round-trip preserves the tombstones and confirms the
    // subtree really is gone from the live tree.
    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = reopen(bytes);
    assert!(
        reopened.vault().root.groups.iter().all(|g| g.id != parent),
        "deleted group must not survive round-trip"
    );
    assert!(
        reopened.vault().iter_entries().all(|e| e.id != child_entry),
        "entry under deleted group must not survive round-trip"
    );
    let surviving_uuids: std::collections::HashSet<_> = reopened
        .vault()
        .deleted_objects
        .iter()
        .map(|t| t.uuid)
        .collect();
    for u in &expected {
        assert!(
            surviving_uuids.contains(u),
            "tombstone for {u} must survive round-trip"
        );
    }
}

#[test]
fn move_group_stamps_previous_parent_and_location_changed() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = open(t0);
    let root = kdbx.vault().root.id;

    let a = kdbx.add_group(root, NewGroup::new("A")).unwrap();
    let b = kdbx.add_group(root, NewGroup::new("B")).unwrap();
    let leaf = kdbx.add_group(a, NewGroup::new("Leaf")).unwrap();

    kdbx.move_group(leaf, b).unwrap();

    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = reopen(bytes);

    // After the move, `leaf` lives under `b`, not `a`.
    let b_after = reopened
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == b)
        .expect("b survives");
    let leaf_after = b_after
        .groups
        .iter()
        .find(|g| g.id == leaf)
        .expect("leaf moved under b");
    assert_eq!(leaf_after.previous_parent_group, Some(a));
    assert_eq!(leaf_after.times.location_changed, Some(t0));

    let a_after = reopened
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == a)
        .expect("a survives");
    assert!(
        a_after.groups.iter().all(|g| g.id != leaf),
        "leaf must not still live under a"
    );
}

#[test]
fn move_group_into_own_subtree_returns_circular_move_and_does_not_move() {
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root = kdbx.vault().root.id;

    let parent = kdbx.add_group(root, NewGroup::new("Parent")).unwrap();
    let middle = kdbx.add_group(parent, NewGroup::new("Middle")).unwrap();
    let leaf = kdbx.add_group(middle, NewGroup::new("Leaf")).unwrap();

    // Try to move `parent` underneath `leaf` — `leaf` is in `parent`'s
    // own subtree, so the result would be a cycle.
    let err = kdbx.move_group(parent, leaf).unwrap_err();
    match err {
        ModelError::CircularMove { moving, new_parent } => {
            assert_eq!(moving, parent);
            assert_eq!(new_parent, leaf);
        }
        other => panic!("expected CircularMove, got {other:?}"),
    }

    // Moving onto self is also a cycle.
    let err = kdbx.move_group(parent, parent).unwrap_err();
    assert!(matches!(err, ModelError::CircularMove { .. }));

    // The tree is unchanged: parent still lives under root, middle
    // under parent, leaf under middle.
    let p = kdbx
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent)
        .expect("parent untouched");
    let m = p.groups.iter().find(|g| g.id == middle).expect("middle");
    assert!(m.groups.iter().any(|g| g.id == leaf), "leaf");
}

#[test]
fn root_cannot_be_deleted_or_moved() {
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root = kdbx.vault().root.id;
    let other = kdbx.add_group(root, NewGroup::new("Other")).unwrap();

    let err = kdbx.delete_group(root).unwrap_err();
    assert!(matches!(err, ModelError::CannotDeleteRoot));
    let err = kdbx.move_group(root, other).unwrap_err();
    assert!(matches!(err, ModelError::CannotDeleteRoot));
}
