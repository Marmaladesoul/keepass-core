//! Integration tests for the recycle-bin helpers on `Kdbx<Unlocked>`:
//! `recycle_entry`, `recycle_group`, `empty_recycle_bin`.
//!
//! Seeded programmatically against `kdbxweb/kdbx4-basic.kdbx` for
//! most cases. One test uses `pykeepass/recycle.kdbx` — a fixture
//! that already carries a populated recycle bin from a real writer
//! — to catch any divergence between "library-created bin" and
//! "foreign-writer-created bin" handling.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{Clock, EntryId, GroupId, ModelError, NewEntry, NewGroup};

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

fn recycle_fixture() -> PathBuf {
    fixtures_root().join("pykeepass/recycle.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let text = fs::read_to_string(path.with_extension("json")).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

#[derive(Debug, Clone)]
struct SharedClock(Arc<Mutex<DateTime<Utc>>>);
impl SharedClock {
    fn new(at: DateTime<Utc>) -> Self {
        Self(Arc::new(Mutex::new(at)))
    }
    fn set(&self, at: DateTime<Utc>) {
        *self.0.lock().unwrap() = at;
    }
}
impl Clock for SharedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

fn open_with_clock(path: &Path, t0: DateTime<Utc>) -> (Kdbx<Unlocked>, SharedClock) {
    let composite = CompositeKey::from_password(password_from_sidecar(path).as_bytes());
    let clock = SharedClock::new(t0);
    let handle = clock.clone();
    let kdbx = Kdbx::<Sealed>::open(path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();
    (kdbx, handle)
}

fn reopen_with_clock(path: &Path, bytes: Vec<u8>, at: DateTime<Utc>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(password_from_sidecar(path).as_bytes());
    Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(SharedClock::new(at)))
        .unwrap()
}

fn find_entry(kdbx: &Kdbx<Unlocked>, id: EntryId) -> Option<&keepass_core::model::Entry> {
    kdbx.vault().iter_entries().find(|e| e.id == id)
}

fn find_group(
    root: &keepass_core::model::Group,
    id: GroupId,
) -> Option<&keepass_core::model::Group> {
    if root.id == id {
        return Some(root);
    }
    for child in &root.groups {
        if let Some(g) = find_group(child, id) {
            return Some(g);
        }
    }
    None
}

// ---------------------------------------------------------------------
// recycle_entry
// ---------------------------------------------------------------------

#[test]
fn first_recycle_entry_creates_bin_canonically_and_stamps_meta() {
    let t_create: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t_recycle: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_with_clock(&kdbx4_basic(), t_create);
    // Normalise meta pre-state — the kdbxweb/kdbx4-basic fixture
    // ships with `recycle_bin_enabled = true` + a dangling UUID.
    // The test wants "user has recycling turned on, but no bin
    // group has been minted yet" — i.e. enabled=true, uuid=None —
    // so the lazy-creation path is unambiguously under test.
    kdbx.set_recycle_bin(true, None);
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("To Bin")).unwrap();
    let settings_before = kdbx.vault().meta.settings_changed;
    assert!(kdbx.vault().meta.recycle_bin_enabled);
    assert!(kdbx.vault().meta.recycle_bin_uuid.is_none());

    clock.set(t_recycle);
    let bin = kdbx.recycle_entry(id).unwrap().expect("bin minted");

    let bin_group = find_group(&kdbx.vault().root, bin).expect("bin registered at root");
    assert_eq!(bin_group.name, "Recycle Bin");
    assert_eq!(bin_group.icon_id, 43);
    assert_eq!(bin_group.enable_auto_type, Some(false));
    assert_eq!(bin_group.enable_searching, Some(false));
    assert_eq!(bin_group.times.creation_time, Some(t_recycle));
    // Root is the bin's parent.
    assert!(kdbx.vault().root.groups.iter().any(|g| g.id == bin));

    // Meta bookkeeping: enabled + uuid + changed + settings_changed.
    assert!(kdbx.vault().meta.recycle_bin_enabled);
    assert_eq!(kdbx.vault().meta.recycle_bin_uuid, Some(bin));
    assert_eq!(kdbx.vault().meta.recycle_bin_changed, Some(t_recycle));
    assert_ne!(
        kdbx.vault().meta.settings_changed,
        settings_before,
        "lazy bin creation stamps meta.settings_changed"
    );

    // Entry is now under the bin; its `times.location_changed` +
    // `previous_parent_group` were set by the composed `move_entry`.
    let e = find_entry(&kdbx, id).expect("entry still present");
    assert_eq!(e.previous_parent_group, Some(root));
    assert_eq!(e.times.location_changed, Some(t_recycle));

    // Lives in the bin, not the root.
    assert!(!kdbx.vault().root.entries.iter().any(|e| e.id == id));
    assert!(bin_group.entries.iter().any(|e| e.id == id));
}

#[test]
fn second_recycle_entry_reuses_bin_and_leaves_recycle_bin_changed_alone() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;
    let id_a = kdbx.add_entry(root, NewEntry::new("A")).unwrap();
    let id_b = kdbx.add_entry(root, NewEntry::new("B")).unwrap();

    clock.set(t0 + Duration::minutes(1));
    let bin_1 = kdbx.recycle_entry(id_a).unwrap().unwrap();
    let groups_after_first = kdbx.vault().root.groups.len();
    let changed_first = kdbx.vault().meta.recycle_bin_changed;

    clock.set(t0 + Duration::minutes(2));
    let bin_2 = kdbx.recycle_entry(id_b).unwrap().unwrap();

    assert_eq!(bin_1, bin_2, "reuse the existing bin");
    assert_eq!(
        kdbx.vault().root.groups.len(),
        groups_after_first,
        "second recycle must not mint another bin"
    );
    assert_eq!(
        kdbx.vault().meta.recycle_bin_changed,
        changed_first,
        "recycle_bin_changed is a bin-config stamp, not a per-move stamp"
    );
}

#[test]
fn recycle_entry_on_entry_already_in_bin_returns_ok_none_without_mutation() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("Twice-Recycled"))
        .unwrap();
    let bin = kdbx.recycle_entry(id).unwrap().unwrap();
    let changed_before = kdbx.vault().meta.recycle_bin_changed;
    let entries_in_bin = find_group(&kdbx.vault().root, bin).unwrap().entries.len();

    // Second recycle: already inside the bin → Ok(None).
    let result = kdbx.recycle_entry(id).unwrap();
    assert!(result.is_none(), "already-in-bin returns Ok(None)");
    assert_eq!(
        find_group(&kdbx.vault().root, bin).unwrap().entries.len(),
        entries_in_bin,
        "no mutation"
    );
    assert_eq!(kdbx.vault().meta.recycle_bin_changed, changed_before);
}

#[test]
fn recycle_entry_on_unknown_id_returns_entry_not_found() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let bogus = EntryId(uuid::Uuid::from_u128(0xDEAD));
    match kdbx.recycle_entry(bogus) {
        Err(ModelError::EntryNotFound(got)) => assert_eq!(got, bogus),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

#[test]
fn recycle_entry_hard_deletes_when_bin_disabled_and_no_bin_exists() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    // Normalise meta pre-state — the kdbxweb/kdbx4-basic fixture
    // ships with `recycle_bin_enabled = true` + a dangling UUID;
    // clear both so the "bin disabled, no bin exists" branch is
    // unambiguously under test.
    kdbx.set_recycle_bin(false, None);
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("Hard-Delete")).unwrap();
    assert!(!kdbx.vault().meta.recycle_bin_enabled);
    assert!(kdbx.vault().meta.recycle_bin_uuid.is_none());
    let tombstones_before = kdbx.vault().deleted_objects.len();

    let result = kdbx.recycle_entry(id).unwrap();
    assert!(result.is_none(), "hard-delete fallback returns Ok(None)");

    // Entry is gone; `DeletedObject` emitted.
    assert!(find_entry(&kdbx, id).is_none());
    assert_eq!(
        kdbx.vault().deleted_objects.len(),
        tombstones_before + 1,
        "hard-delete emits one tombstone"
    );
    // No bin was created.
    assert!(kdbx.vault().meta.recycle_bin_uuid.is_none());
}

// ---------------------------------------------------------------------
// recycle_group
// ---------------------------------------------------------------------

#[test]
fn recycle_group_moves_subtree_under_bin() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;

    // Build a small subtree: "Work" > "Subgroup" + entries.
    let work = kdbx.add_group(root, NewGroup::new("Work")).unwrap();
    let sub = kdbx.add_group(work, NewGroup::new("Subgroup")).unwrap();
    let entry_a = kdbx.add_entry(work, NewEntry::new("A")).unwrap();
    let entry_b = kdbx.add_entry(sub, NewEntry::new("B")).unwrap();

    let bin = kdbx.recycle_group(work).unwrap().unwrap();

    // The whole Work subtree now lives under the bin.
    let bin_group = find_group(&kdbx.vault().root, bin).unwrap();
    assert!(bin_group.groups.iter().any(|g| g.id == work));
    let work_under_bin = find_group(bin_group, work).unwrap();
    assert!(work_under_bin.groups.iter().any(|g| g.id == sub));
    assert!(work_under_bin.entries.iter().any(|e| e.id == entry_a));
    // Subgroup's own entries still travel with it.
    assert!(
        find_group(bin_group, sub)
            .unwrap()
            .entries
            .iter()
            .any(|e| e.id == entry_b)
    );
    // Work is no longer directly under root.
    assert!(!kdbx.vault().root.groups.iter().any(|g| g.id == work));
}

#[test]
fn recycle_group_on_root_returns_cannot_delete_root() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;
    match kdbx.recycle_group(root) {
        Err(ModelError::CannotDeleteRoot) => {}
        other => panic!("expected CannotDeleteRoot, got {other:?}"),
    }
}

/// The `group_is_descendant_of` branch in `recycle_group` —
/// short-circuit `Ok(None)` when the target is already nested
/// inside the bin — isn't otherwise exercised by the test suite.
/// `recycle_entry` has its equivalent (test #3); this closes the
/// symmetry gap for groups.
#[test]
fn recycle_group_on_group_already_nested_in_bin_returns_ok_none_without_mutation() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;

    // Set up a group under root, recycle it into the bin.
    let g = kdbx.add_group(root, NewGroup::new("Moving In")).unwrap();
    clock.set(t0 + Duration::minutes(1));
    let bin = kdbx.recycle_group(g).unwrap().expect("first recycle moves");
    let changed_after_first = kdbx.vault().meta.recycle_bin_changed;
    let bin_groups_before_retry = find_group(&kdbx.vault().root, bin).unwrap().groups.len();

    // Second recycle of the same group — now nested under the bin
    // already. Must short-circuit `Ok(None)`, no mutation.
    clock.set(t0 + Duration::minutes(2));
    let result = kdbx.recycle_group(g).unwrap();
    assert!(result.is_none(), "already-in-bin group returns Ok(None)");
    assert_eq!(
        kdbx.vault().meta.recycle_bin_changed,
        changed_after_first,
        "short-circuit must not re-stamp recycle_bin_changed"
    );
    assert_eq!(
        find_group(&kdbx.vault().root, bin).unwrap().groups.len(),
        bin_groups_before_retry,
        "short-circuit must not duplicate or re-move"
    );
}

#[test]
fn recycle_group_on_bin_itself_returns_circular_move() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("Trigger Bin")).unwrap();
    // Create the bin by recycling something first.
    let bin = kdbx.recycle_entry(id).unwrap().unwrap();

    match kdbx.recycle_group(bin) {
        Err(ModelError::CircularMove { moving, new_parent }) => {
            assert_eq!(moving, bin);
            assert_eq!(new_parent, bin);
        }
        other => panic!("expected CircularMove, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// empty_recycle_bin
// ---------------------------------------------------------------------

#[test]
fn empty_recycle_bin_returns_direct_child_count_and_emits_tombstones() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;

    // Set up: two loose entries + one group containing two entries,
    // all recycled into the bin. Direct children after recycle: 3
    // (two entries + one group). Recursive tombstones: 3 direct
    // items + 2 entries inside the recycled group = 5 total.
    let e1 = kdbx.add_entry(root, NewEntry::new("E1")).unwrap();
    let e2 = kdbx.add_entry(root, NewEntry::new("E2")).unwrap();
    let g = kdbx.add_group(root, NewGroup::new("G")).unwrap();
    kdbx.add_entry(g, NewEntry::new("G.1")).unwrap();
    kdbx.add_entry(g, NewEntry::new("G.2")).unwrap();

    kdbx.recycle_entry(e1).unwrap();
    kdbx.recycle_entry(e2).unwrap();
    kdbx.recycle_group(g).unwrap();

    let bin = kdbx.vault().meta.recycle_bin_uuid.unwrap();
    let tombstones_before = kdbx.vault().deleted_objects.len();

    let removed = kdbx.empty_recycle_bin().unwrap();
    assert_eq!(removed, 3, "direct-children count: 2 entries + 1 group");

    // Recursive cascade: 2 direct entries + 1 group itself + 2
    // nested entries inside G = 5 new tombstones.
    let tombstones_after = kdbx.vault().deleted_objects.len();
    assert_eq!(
        tombstones_after - tombstones_before,
        5,
        "recursive cascade emits one DeletedObject per entry and per subgroup"
    );

    // Bin group survives, empty.
    let bin_group = find_group(&kdbx.vault().root, bin).expect("bin still present");
    assert!(bin_group.entries.is_empty());
    assert!(bin_group.groups.is_empty());
    assert_eq!(kdbx.vault().meta.recycle_bin_uuid, Some(bin));
}

#[test]
fn empty_recycle_bin_with_no_bin_returns_zero() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    // Normalise — see the matching note on
    // `first_recycle_entry_creates_bin_canonically_and_stamps_meta`.
    kdbx.set_recycle_bin(false, None);
    assert!(kdbx.vault().meta.recycle_bin_uuid.is_none());
    let tombstones_before = kdbx.vault().deleted_objects.len();
    assert_eq!(kdbx.empty_recycle_bin().unwrap(), 0);
    assert_eq!(
        kdbx.vault().deleted_objects.len(),
        tombstones_before,
        "no-op must emit no tombstones"
    );
}

// ---------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------

#[test]
fn dangling_recycle_bin_uuid_is_treated_as_no_bin_and_fresh_bin_minted() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;

    // Point `recycle_bin_uuid` at a nonexistent group.
    let bogus = GroupId(uuid::Uuid::from_u128(0xABCD_EF01));
    kdbx.set_recycle_bin(true, Some(bogus));
    assert_eq!(kdbx.vault().meta.recycle_bin_uuid, Some(bogus));

    let id = kdbx
        .add_entry(root, NewEntry::new("Fresh Recycle"))
        .unwrap();
    let minted = kdbx.recycle_entry(id).unwrap().unwrap();
    assert_ne!(
        minted, bogus,
        "the dangling id was not resurrected; a fresh bin was minted"
    );
    assert_eq!(
        kdbx.vault().meta.recycle_bin_uuid,
        Some(minted),
        "meta.recycle_bin_uuid now points at the fresh bin"
    );
    assert!(find_group(&kdbx.vault().root, minted).is_some());
}

#[test]
fn full_round_trip_through_save_and_reopen_preserves_bin_and_contents() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&kdbx4_basic(), t0);
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("Round-trip")).unwrap();
    let bin = kdbx.recycle_entry(id).unwrap().unwrap();

    let reopened = reopen_with_clock(
        &kdbx4_basic(),
        kdbx.save_to_bytes().unwrap(),
        t0 + Duration::hours(1),
    );
    assert_eq!(reopened.vault().meta.recycle_bin_uuid, Some(bin));
    assert!(reopened.vault().meta.recycle_bin_enabled);
    let bin_group = find_group(&reopened.vault().root, bin).expect("bin survives reopen");
    assert_eq!(bin_group.name, "Recycle Bin");
    assert_eq!(bin_group.icon_id, 43);
    assert!(bin_group.entries.iter().any(|e| e.id == id));
}

#[test]
fn recycle_against_foreign_writer_fixture_moves_into_existing_bin() {
    // pykeepass/recycle.kdbx already carries a populated recycle
    // bin from a foreign writer. Our recycle helper must reuse that
    // bin rather than minting a new one.
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _) = open_with_clock(&recycle_fixture(), t0);
    let existing_bin = kdbx
        .vault()
        .meta
        .recycle_bin_uuid
        .expect("recycle.kdbx fixture carries a bin");
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("New In Bin")).unwrap();

    let returned = kdbx.recycle_entry(id).unwrap().unwrap();
    assert_eq!(
        returned, existing_bin,
        "reuses the foreign-writer-created bin"
    );
    let bin_group = find_group(&kdbx.vault().root, existing_bin).unwrap();
    assert!(bin_group.entries.iter().any(|e| e.id == id));
}
