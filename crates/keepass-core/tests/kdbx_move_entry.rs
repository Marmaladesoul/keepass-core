//! Fixture round-trip for [`Kdbx::move_entry`].
//!
//! Per MUTATION.md §"Slicing plan" slice 3. Opens a real fixture,
//! adds an entry under one group, moves it to another, saves via
//! `save_to_bytes`, re-opens, and asserts:
//!
//! 1. The entry now lives under `new_parent`.
//! 2. `entry.previous_parent_group == Some(old_parent)`.
//! 3. `entry.times.location_changed` equals the pinned clock at the
//!    moment of the move (distinct from the moment of the add).

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{Clock, FixedClock, GroupId, ModelError, NewEntry};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

/// Shared-state clock whose current instant can be bumped between
/// mutations. Useful when a single test needs to distinguish the
/// timestamp of two different mutations under the same
/// [`Kdbx<Unlocked>`].
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

#[test]
fn move_entry_updates_location_and_previous_parent_and_round_trips() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let add_at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let move_at: DateTime<Utc> = "2026-04-22T11:30:00Z".parse().unwrap();

    // Shared-state clock: starts at add_at, bump to move_at between
    // add and move so the two mutations stamp distinct instants.
    let clock = SharedClock::new(add_at);
    let clock_handle = clock.clone(); // for the test to bump after add

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;

    // Add the entry while the clock reads `add_at`.
    let id = kdbx
        .add_entry(root, NewEntry::new("Movable"))
        .expect("add_entry");

    // Sanity: add_entry stamped location_changed from the clock.
    let before = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("added entry");
    assert_eq!(before.previous_parent_group, None);
    assert_eq!(before.times.location_changed, Some(add_at));

    // The current fixture has only a root group (no subgroups) and
    // slice 7 is the one that introduces `add_group`. So we move
    // the entry to the only other legal target: the root itself.
    // It's a "no-op" move in terms of tree position but still stamps
    // the bookkeeping, which is what MUTATION.md requires.
    clock_handle.set(move_at);
    kdbx.move_entry(id, root).expect("move_entry");

    let after = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry still findable after move");
    assert_eq!(
        after.previous_parent_group,
        Some(root),
        "move_entry should record the old parent as previous_parent_group"
    );
    assert_eq!(
        after.times.location_changed,
        Some(move_at),
        "move_entry should stamp location_changed from the clock at the moment of the move"
    );
    // Creation timestamps should not have been re-stamped by move.
    assert_eq!(after.times.creation_time, Some(add_at));

    // Round-trip through disk.
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let round_tripped = reopened
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("moved entry survives save/re-open");
    assert_eq!(
        round_tripped.previous_parent_group,
        Some(root),
        "previous_parent_group survives round-trip"
    );
    assert_eq!(
        round_tripped.times.location_changed,
        Some(move_at),
        "location_changed stamp survives round-trip"
    );
}

#[test]
fn move_entry_rejects_missing_destination_without_removing() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let at: DateTime<Utc> = "2026-04-22T00:00:00Z".parse().unwrap();
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("SafelyHere")).unwrap();

    let bogus_parent = GroupId(Uuid::new_v4());
    let err = kdbx.move_entry(id, bogus_parent).unwrap_err();
    match err {
        ModelError::GroupNotFound(g) => assert_eq!(g, bogus_parent),
        other => panic!("expected GroupNotFound, got {other:?}"),
    }

    // The entry must still be in its original home, untouched.
    let still_here = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry not removed on failed move");
    assert_eq!(
        still_here.previous_parent_group, None,
        "a failed move must not have touched previous_parent_group"
    );
}

#[test]
fn move_entry_rejects_missing_entry() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let at: DateTime<Utc> = "2026-04-22T00:00:00Z".parse().unwrap();
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    let root = kdbx.vault().root.id;
    let bogus_id = keepass_core::model::EntryId(Uuid::new_v4());
    let err = kdbx.move_entry(bogus_id, root).unwrap_err();
    match err {
        ModelError::EntryNotFound(e) => assert_eq!(e, bogus_id),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}
