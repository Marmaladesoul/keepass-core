//! Slice 8I-D — small read-only accessors on `Vault` / `Group` used by
//! the downstream FFI consumer.
//!
//! Three additions, one integration test per concern:
//!
//! 1. `Vault::custom_icon(uuid)` — borrow the bytes of a pooled custom
//!    icon by UUID. `Some` for a known id, `None` for an unknown one.
//! 2. `Vault::group_parent(child)` — id of the group directly
//!    containing `child`. `None` for the root group and for unknown
//!    ids.
//! 3. `Group::all_subgroups()` — every descendant group, depth-first,
//!    not including `self`.
//!
//! Seeded programmatically against `kdbxweb/kdbx4-basic.kdbx` to stay
//! consistent with the rest of `crates/keepass-core/tests/`.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, NewGroup};
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

// -----------------------------------------------------------------
// Vault::custom_icon
// -----------------------------------------------------------------

#[test]
fn vault_custom_icon_returns_bytes_for_known_uuid() {
    let at: DateTime<Utc> = "2026-05-11T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);

    let icon_bytes = b"PNGbytes-not-really-but-opaque".to_vec();
    let uuid = kdbx.add_custom_icon(icon_bytes.clone());

    let got = kdbx
        .vault()
        .custom_icon(uuid)
        .expect("Vault::custom_icon returns Some for a known UUID");
    assert_eq!(got, icon_bytes.as_slice());
}

#[test]
fn vault_custom_icon_returns_none_for_unknown_uuid() {
    let at: DateTime<Utc> = "2026-05-11T10:00:00Z".parse().unwrap();
    let kdbx = open(at);

    let bogus = uuid::Uuid::from_u128(0xdead_beef_dead_beef_dead_beef_dead_beef);
    assert!(kdbx.vault().custom_icon(bogus).is_none());
}

// -----------------------------------------------------------------
// Vault::group_parent
// -----------------------------------------------------------------

#[test]
fn vault_group_parent_returns_parent_for_subgroup() {
    let at: DateTime<Utc> = "2026-05-11T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    let parent = kdbx.add_group(root_id, NewGroup::new("Parent")).unwrap();
    let child = kdbx.add_group(parent, NewGroup::new("Child")).unwrap();
    let grandchild = kdbx.add_group(child, NewGroup::new("Grandchild")).unwrap();

    assert_eq!(kdbx.vault().group_parent(parent), Some(root_id));
    assert_eq!(kdbx.vault().group_parent(child), Some(parent));
    assert_eq!(kdbx.vault().group_parent(grandchild), Some(child));
}

#[test]
fn vault_group_parent_returns_none_for_root_and_unknown() {
    let at: DateTime<Utc> = "2026-05-11T10:00:00Z".parse().unwrap();
    let kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    assert!(kdbx.vault().group_parent(root_id).is_none());

    let bogus = keepass_core::model::GroupId(uuid::Uuid::from_u128(0x1234_5678));
    assert!(kdbx.vault().group_parent(bogus).is_none());
}

// -----------------------------------------------------------------
// Group::all_subgroups
// -----------------------------------------------------------------

#[test]
fn group_all_subgroups_walks_recursively() {
    let at: DateTime<Utc> = "2026-05-11T10:00:00Z".parse().unwrap();
    let mut kdbx = open(at);
    let root_id = kdbx.vault().root.id;

    //   root
    //   ├── A
    //   │   └── A1
    //   └── B
    let a = kdbx.add_group(root_id, NewGroup::new("A")).unwrap();
    let a1 = kdbx.add_group(a, NewGroup::new("A1")).unwrap();
    let b = kdbx.add_group(root_id, NewGroup::new("B")).unwrap();

    // Locate group A in the tree so we can call all_subgroups on it.
    let a_node = kdbx
        .vault()
        .root
        .groups
        .iter()
        .find(|g| g.id == a)
        .expect("group A in tree");

    // Group A on its own should report exactly one descendant (A1).
    let a_descendants = a_node.all_subgroups();
    assert_eq!(a_descendants.len(), 1);
    assert_eq!(a_descendants[0].id, a1);

    // The root: every descendant we added (plus whatever the fixture
    // already had). Use a `contains`-style assertion rather than an
    // exact count to stay robust to the seed vault's pre-existing
    // groups.
    let from_root: Vec<_> = kdbx
        .vault()
        .root
        .all_subgroups()
        .into_iter()
        .map(|g| g.id)
        .collect();
    assert!(from_root.contains(&a));
    assert!(from_root.contains(&a1));
    assert!(from_root.contains(&b));
    // Root itself must NOT be in its own all_subgroups output.
    assert!(!from_root.contains(&root_id));
}
