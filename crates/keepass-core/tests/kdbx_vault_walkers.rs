//! Slice 8I-E — additional surface on `Vault` / `Kdbx` for the
//! downstream FFI consumer.
//!
//! Three additions, with at least one integration test per concern:
//!
//! 1. `Vault::all_entries()` — eager flat walk of every entry in the
//!    vault, depth-first. Includes recycle-bin entries; FFI callers
//!    filter using `recycle_bin_enabled` + `meta.recycle_bin_uuid`.
//! 2. `Vault::recycle_bin_enabled()` — accessor for the meta flag.
//! 3. `Kdbx::move_group_to_position()` — variant of `move_group` that
//!    inserts the moved group at a chosen index among `new_parent`'s
//!    children. Out-of-range positions clamp to the end. Same parent
//!    is a sibling reorder.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, GroupId, NewEntry, NewGroup};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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
    serde_json::from_str::<serde_json::Value>(&text)
        .unwrap()
        .get("master_password")
        .and_then(|v| v.as_str())
        .map(ToOwned::to_owned)
        .unwrap()
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

// -----------------------------------------------------------------
// Vault::all_entries
// -----------------------------------------------------------------

#[test]
fn vault_all_entries_walks_recursively() {
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    // Baseline — fixture's pre-existing entry count.
    let baseline = kdbx.vault().all_entries().len();

    //   root
    //   ├── A           (+1 entry)
    //   │   └── A1      (+2 entries)
    //   └── B           (+1 entry)
    let a = kdbx.add_group(root_id, NewGroup::new("A")).unwrap();
    let a1 = kdbx.add_group(a, NewGroup::new("A1")).unwrap();
    let b = kdbx.add_group(root_id, NewGroup::new("B")).unwrap();

    kdbx.add_entry(a, NewEntry::new("a-entry")).unwrap();
    kdbx.add_entry(a1, NewEntry::new("a1-entry-1")).unwrap();
    kdbx.add_entry(a1, NewEntry::new("a1-entry-2")).unwrap();
    kdbx.add_entry(b, NewEntry::new("b-entry")).unwrap();

    let all = kdbx.vault().all_entries();
    assert_eq!(all.len(), baseline + 4);

    // Sanity: the count matches `iter_entries`, which is the spec for
    // what `all_entries` is — an eager mirror.
    assert_eq!(all.len(), kdbx.vault().iter_entries().count());

    // And every title we added shows up in the result.
    let titles: Vec<&str> = all.iter().map(|e| e.title.as_str()).collect();
    for needle in ["a-entry", "a1-entry-1", "a1-entry-2", "b-entry"] {
        assert!(
            titles.contains(&needle),
            "expected entry titled {needle:?} in all_entries",
        );
    }
}

#[test]
fn vault_all_entries_includes_recycle_bin_contents() {
    // Default behaviour: all_entries does NOT filter out the recycle
    // bin. FFI callers that want to hide deleted entries are expected
    // to filter using `recycle_bin_enabled` + `meta.recycle_bin_uuid`.
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    // Ensure the recycle-bin feature is on so `delete_entry` soft-deletes.
    kdbx.set_recycle_bin(true, None);

    let workspace = kdbx.add_group(root_id, NewGroup::new("Work")).unwrap();
    let doomed = kdbx.add_entry(workspace, NewEntry::new("doomed")).unwrap();

    // Soft-delete sends the entry to the recycle bin (auto-created on
    // first soft-recycle).
    kdbx.recycle_entry(doomed).unwrap();

    // Recycle bin should now exist and the entry should still be
    // reachable via the flat walker.
    assert!(kdbx.vault().recycle_bin_enabled());
    let titles: Vec<&str> = kdbx
        .vault()
        .all_entries()
        .iter()
        .map(|e| e.title.as_str())
        .collect();
    assert!(
        titles.contains(&"doomed"),
        "soft-deleted entry should still appear in all_entries",
    );
}

// -----------------------------------------------------------------
// Vault::recycle_bin_enabled
// -----------------------------------------------------------------

#[test]
fn vault_recycle_bin_enabled_returns_meta_flag() {
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);

    // Force-disable, then read.
    kdbx.set_recycle_bin(false, None);
    assert!(!kdbx.vault().recycle_bin_enabled());

    // Force-enable, then read.
    kdbx.set_recycle_bin(true, None);
    assert!(kdbx.vault().recycle_bin_enabled());
}

// -----------------------------------------------------------------
// Kdbx::move_group_to_position
// -----------------------------------------------------------------

#[test]
fn move_group_to_position_inserts_at_index() {
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    // Destination parent with three existing children.
    let parent = kdbx.add_group(root_id, NewGroup::new("Parent")).unwrap();
    let _c0 = kdbx.add_group(parent, NewGroup::new("c0")).unwrap();
    let _c1 = kdbx.add_group(parent, NewGroup::new("c1")).unwrap();
    let _c2 = kdbx.add_group(parent, NewGroup::new("c2")).unwrap();

    // Group to move, currently a child of root.
    let mover = kdbx.add_group(root_id, NewGroup::new("mover")).unwrap();

    kdbx.move_group_to_position(mover, parent, 1).unwrap();

    // The mover should now be at index 1 in parent's children.
    let parent_node = kdbx
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent)
        .expect("parent in tree");
    let names: Vec<&str> = parent_node.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["c0", "mover", "c1", "c2"]);
}

#[test]
fn move_group_to_position_clamps_out_of_range() {
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    let parent = kdbx.add_group(root_id, NewGroup::new("Parent")).unwrap();
    let _c0 = kdbx.add_group(parent, NewGroup::new("c0")).unwrap();
    let _c1 = kdbx.add_group(parent, NewGroup::new("c1")).unwrap();

    let mover = kdbx.add_group(root_id, NewGroup::new("mover")).unwrap();

    // Position larger than the destination's current child count
    // should clamp to a push at the end.
    kdbx.move_group_to_position(mover, parent, 999).unwrap();

    let parent_node = kdbx
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent)
        .expect("parent in tree");
    let names: Vec<&str> = parent_node.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["c0", "c1", "mover"]);
}

#[test]
fn move_group_to_position_same_parent_reorders_siblings() {
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    let parent = kdbx.add_group(root_id, NewGroup::new("Parent")).unwrap();
    let a = kdbx.add_group(parent, NewGroup::new("a")).unwrap();
    let _b = kdbx.add_group(parent, NewGroup::new("b")).unwrap();
    let _c = kdbx.add_group(parent, NewGroup::new("c")).unwrap();

    // Move `a` from index 0 to the end. After removal the remaining
    // siblings are [b, c]; inserting at index 2 (== len) appends.
    kdbx.move_group_to_position(a, parent, 2).unwrap();

    let parent_node = kdbx
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent)
        .expect("parent in tree");
    let names: Vec<&str> = parent_node.groups.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["b", "c", "a"]);
}

#[test]
fn move_group_equals_move_to_position_pushed_to_end() {
    // Guards the DRY merge of the two movers into one shared core:
    // `move_group(x, p)` must produce a byte-identical tree — same child
    // order, same `previous_parent_group`, same `location_changed` stamp —
    // as `move_group_to_position(x, p, n)` for any `n` at/past the
    // destination's post-detach child count (both append to the end).
    let at: DateTime<Utc> = "2026-05-12T10:00:00Z".parse().unwrap();

    // Pin UUIDs so the two independently-built vaults are structurally
    // identical, making a whole-subtree `assert_eq!` meaningful.
    let parent_uuid = Uuid::from_u128(0x0001);
    let c0_uuid = Uuid::from_u128(0x00c0);
    let c1_uuid = Uuid::from_u128(0x00c1);
    let mover_uuid = Uuid::from_u128(0x000f);

    let build = |kdbx: &mut Kdbx<keepass_core::kdbx::Unlocked>| -> (GroupId, GroupId) {
        let root_id = kdbx.vault().root.id;
        let parent = kdbx
            .add_group(root_id, NewGroup::new("Parent").with_uuid(parent_uuid))
            .unwrap();
        kdbx.add_group(parent, NewGroup::new("c0").with_uuid(c0_uuid))
            .unwrap();
        kdbx.add_group(parent, NewGroup::new("c1").with_uuid(c1_uuid))
            .unwrap();
        let mover = kdbx
            .add_group(root_id, NewGroup::new("mover").with_uuid(mover_uuid))
            .unwrap();
        (parent, mover)
    };

    let mut via_push = open(at);
    let (parent_a, mover_a) = build(&mut via_push);
    via_push.move_group(mover_a, parent_a).unwrap();

    let mut via_position = open(at);
    let (parent_b, mover_b) = build(&mut via_position);
    // After the mover detaches from root, `parent` has two children; any
    // position >= 2 appends, matching `move_group`'s push.
    via_position
        .move_group_to_position(mover_b, parent_b, 2)
        .unwrap();

    let dest_a = via_push
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent_a)
        .expect("parent survives in push variant");
    let dest_b = via_position
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == parent_b)
        .expect("parent survives in position variant");

    // Whole-subtree structural equality: child order, ids, and the moved
    // group's `previous_parent_group` + `location_changed` stamp all match.
    assert_eq!(dest_a, dest_b);
    // And the mover really landed at the end (push semantics).
    assert_eq!(
        dest_a.groups.last().map(|g| g.id),
        Some(mover_a),
        "mover appended to the end"
    );
}
