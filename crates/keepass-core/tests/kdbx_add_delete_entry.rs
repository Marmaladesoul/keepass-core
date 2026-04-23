//! Fixture round-trip for [`Kdbx::add_entry`] / [`Kdbx::delete_entry`].
//!
//! Per MUTATION.md §"Slicing plan" slice 2. Each test opens a real
//! fixture, applies the mutation, saves via `save_to_bytes`, re-opens,
//! and asserts the expected vault shape.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, ModelError, NewEntry};
use secrecy::SecretString;
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
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

fn pinned_clock() -> (DateTime<Utc>, Box<FixedClock>) {
    let at: DateTime<Utc> = "2026-04-22T01:02:03Z".parse().unwrap();
    (at, Box::new(FixedClock(at)))
}

#[test]
fn add_entry_round_trips_through_save_and_reopen_with_pinned_timestamps() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let (pinned_at, clock) = pinned_clock();

    // Unlock with the pinned clock so add_entry stamps a known instant.
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, clock)
        .unwrap();

    let root = kdbx.vault().root.id;
    let entries_before = kdbx.vault().total_entries();

    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("Gmail")
                .username("alice@example.com")
                .password(SecretString::from("hunter2"))
                .url("https://mail.google.com")
                .tags(vec!["email".into(), "personal".into()]),
        )
        .expect("add_entry under root");

    // In-memory: entry count went up, new entry is findable, timestamps
    // all equal the pinned clock.
    assert_eq!(kdbx.vault().total_entries(), entries_before + 1);
    let added = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("added entry visible in vault");
    assert_eq!(added.title, "Gmail");
    assert_eq!(added.username, "alice@example.com");
    assert_eq!(added.password, "hunter2");
    assert_eq!(added.url, "https://mail.google.com");
    assert_eq!(
        added.tags,
        vec!["email".to_string(), "personal".to_string()]
    );
    assert_eq!(added.previous_parent_group, None);
    assert_eq!(added.times.creation_time, Some(pinned_at));
    assert_eq!(added.times.last_modification_time, Some(pinned_at));
    assert_eq!(added.times.last_access_time, Some(pinned_at));
    assert_eq!(added.times.location_changed, Some(pinned_at));

    // Round-trip through disk.
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    let after = reopened
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("added entry still present after save/re-open");
    assert_eq!(after.title, "Gmail");
    assert_eq!(after.username, "alice@example.com");
    assert_eq!(after.password, "hunter2");
    assert_eq!(after.url, "https://mail.google.com");
    // Timestamps survive the round-trip (the encoder already supports
    // <Times> on entries — see encoder.rs).
    assert_eq!(after.times.creation_time, Some(pinned_at));
    assert_eq!(after.times.last_modification_time, Some(pinned_at));
}

#[test]
fn delete_entry_records_a_deletedobject_and_removes_from_tree() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let (pinned_at, clock) = pinned_clock();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, clock)
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(root, NewEntry::new("Ephemeral"))
        .expect("add_entry");
    assert!(kdbx.vault().iter_entries().any(|e| e.id == id));
    let entries_after_add = kdbx.vault().total_entries();
    let tombstones_before = kdbx.vault().deleted_objects.len();

    kdbx.delete_entry(id).expect("delete_entry");

    // In-memory assertions.
    assert_eq!(kdbx.vault().total_entries(), entries_after_add - 1);
    assert!(
        !kdbx.vault().iter_entries().any(|e| e.id == id),
        "deleted entry should no longer be in the tree"
    );
    let tombstones_after = &kdbx.vault().deleted_objects;
    assert_eq!(
        tombstones_after.len(),
        tombstones_before + 1,
        "delete_entry should append exactly one DeletedObject"
    );
    let tombstone = tombstones_after.last().unwrap();
    assert_eq!(tombstone.uuid, id.0);
    assert_eq!(tombstone.deleted_at, Some(pinned_at));

    // Round-trip through disk.
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    assert!(
        !reopened.vault().iter_entries().any(|e| e.id == id),
        "deleted entry should still be absent after save/re-open"
    );
    let survived_tombstone = reopened
        .vault()
        .deleted_objects
        .iter()
        .find(|o| o.uuid == id.0)
        .expect("tombstone survives save/re-open");
    assert_eq!(survived_tombstone.deleted_at, Some(pinned_at));
}

#[test]
fn add_entry_rejects_duplicate_uuid() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    // Pick a UUID already in use (an existing entry's id).
    let existing_uuid = kdbx.vault().iter_entries().next().unwrap().id.0;

    let err = kdbx
        .add_entry(
            kdbx.vault().root.id,
            NewEntry::new("Clash").with_uuid(existing_uuid),
        )
        .unwrap_err();
    match err {
        ModelError::DuplicateUuid(u) => assert_eq!(u, existing_uuid),
        other => panic!("expected DuplicateUuid, got {other:?}"),
    }
}

#[test]
fn add_entry_preserves_caller_supplied_uuid() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    let supplied = Uuid::new_v4();
    let id = kdbx
        .add_entry(
            kdbx.vault().root.id,
            NewEntry::new("Imported").with_uuid(supplied),
        )
        .unwrap();
    assert_eq!(id.0, supplied);
}

#[test]
fn add_entry_rejects_missing_parent_group() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    let bogus = keepass_core::model::GroupId(Uuid::new_v4());
    let err = kdbx.add_entry(bogus, NewEntry::new("Nowhere")).unwrap_err();
    match err {
        ModelError::GroupNotFound(g) => assert_eq!(g, bogus),
        other => panic!("expected GroupNotFound, got {other:?}"),
    }
}

#[test]
fn delete_entry_rejects_missing_id() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();

    let bogus = keepass_core::model::EntryId(Uuid::new_v4());
    let err = kdbx.delete_entry(bogus).unwrap_err();
    match err {
        ModelError::EntryNotFound(e) => assert_eq!(e, bogus),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}
