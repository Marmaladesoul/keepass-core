//! Invariant tests for the editor-exposed canonical fields: each
//! target field lands on the fixture with a non-default value; a test
//! opens the fixture, mutates a deliberately-unrelated field via
//! `edit_entry` or `edit_group`, saves, reopens, and asserts the
//! target field round-tripped unchanged.
//!
//! One small test per field — granular on purpose, so a regression
//! pinpoints the field that broke rather than a batch-level failure.
//! See `FFI_PHASE1.md` item 1 for the requirement this closes.
//!
//! Fixture: `tests/fixtures/pykeepass/editor-fields.kdbx` (see
//! `tests/fixtures/generate.py::gen_pykeepass_editor_fields`).

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{AutoType, AutoTypeAssociation, Entry, Group, HistoryPolicy};

const FIXTURE_PASSWORD: &str = "test-editor-107";

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/pykeepass/editor-fields.kdbx")
}

fn open_fixture() -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes());
    Kdbx::<Sealed>::open(fixture_path())
        .expect("open")
        .read_header()
        .expect("read header")
        .unlock(&composite)
        .expect("unlock")
}

fn reopen(bytes: Vec<u8>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes());
    Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("re-open")
        .read_header()
        .expect("re-read header")
        .unlock(&composite)
        .expect("re-unlock")
}

/// Locate the "Work" subgroup and its sole entry in the fixture vault.
fn work_group(kdbx: &Kdbx<Unlocked>) -> &Group {
    kdbx.vault()
        .root
        .groups
        .iter()
        .find(|g| g.name == "Work")
        .expect("Work group present in fixture")
}

fn work_entry(kdbx: &Kdbx<Unlocked>) -> &Entry {
    work_group(kdbx)
        .entries
        .first()
        .expect("Work group carries one entry in fixture")
}

/// Mutate the entry's title (deliberately *not* one of the targeted
/// fields) and round-trip through save + reopen. Returns the reopened
/// vault so each test can assert one specific untouched field.
fn round_trip_after_title_edit() -> Kdbx<Unlocked> {
    let mut kdbx = open_fixture();
    let entry_id = work_entry(&kdbx).id;
    kdbx.edit_entry(entry_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_title("touched-by-entry-test");
    })
    .expect("edit_entry");
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    reopen(bytes)
}

/// Counterpart for group invariant tests. Mutates the Work group's
/// notes (again, not one of the targets).
fn round_trip_after_group_notes_edit() -> Kdbx<Unlocked> {
    let mut kdbx = open_fixture();
    let gid = work_group(&kdbx).id;
    kdbx.edit_group(gid, |g| {
        g.set_notes("touched-by-group-test");
    })
    .expect("edit_group");
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    reopen(bytes)
}

// ---------------------------------------------------------------------
// Entry-level invariants
// ---------------------------------------------------------------------

#[test]
fn entry_icon_id_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    assert_eq!(work_entry(&kdbx).icon_id, 25);
}

#[test]
fn entry_custom_icon_uuid_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    let expected = uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-000000000011").unwrap();
    assert_eq!(work_entry(&kdbx).custom_icon_uuid, Some(expected));
}

#[test]
fn entry_override_url_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    assert_eq!(work_entry(&kdbx).override_url, "cmd://firefox %1");
}

#[test]
fn entry_foreground_color_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    assert_eq!(work_entry(&kdbx).foreground_color, "#FF0000");
}

#[test]
fn entry_background_color_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    assert_eq!(work_entry(&kdbx).background_color, "#00FFAA");
}

#[test]
fn entry_expiry_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    let e = work_entry(&kdbx);
    let expected: DateTime<Utc> = "2030-01-02T03:04:05Z".parse().unwrap();
    assert!(e.times.expires);
    assert_eq!(e.times.expiry_time, Some(expected));
}

#[test]
fn entry_quality_check_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    // Fixture carries an explicit `False`; the invariant is that an
    // unrelated edit doesn't silently restore it to the library's
    // `true` default.
    assert!(!work_entry(&kdbx).quality_check);
}

#[test]
fn entry_auto_type_survives_unrelated_edit() {
    let kdbx = round_trip_after_title_edit();
    let got = &work_entry(&kdbx).auto_type;
    // `AutoType` is `#[non_exhaustive]` so out-of-crate construction
    // goes through `::new()` + field assignment rather than a struct
    // literal.
    let mut expected = AutoType::new();
    expected.enabled = false;
    expected.data_transfer_obfuscation = 1;
    expected.default_sequence = "{USERNAME}{TAB}".to_owned();
    expected.associations = vec![AutoTypeAssociation::new("Firefox - *", "{PASSWORD}{ENTER}")];
    assert_eq!(got, &expected);
}

// ---------------------------------------------------------------------
// Group-level invariants
// ---------------------------------------------------------------------

#[test]
fn group_icon_id_survives_unrelated_edit() {
    let kdbx = round_trip_after_group_notes_edit();
    assert_eq!(work_group(&kdbx).icon_id, 43);
}

#[test]
fn group_custom_icon_uuid_survives_unrelated_edit() {
    let kdbx = round_trip_after_group_notes_edit();
    let expected = uuid::Uuid::parse_str("aaaaaaaa-bbbb-cccc-dddd-000000000012").unwrap();
    assert_eq!(work_group(&kdbx).custom_icon_uuid, Some(expected));
}

#[test]
fn group_default_auto_type_sequence_survives_unrelated_edit() {
    let kdbx = round_trip_after_group_notes_edit();
    assert_eq!(
        work_group(&kdbx).default_auto_type_sequence,
        "{TITLE}{ENTER}"
    );
}

#[test]
fn group_enable_auto_type_survives_unrelated_edit() {
    let kdbx = round_trip_after_group_notes_edit();
    // The fixture carries `<EnableAutoType>False</EnableAutoType>` —
    // an explicit tri-state `false`, distinct from "inherit".
    assert_eq!(work_group(&kdbx).enable_auto_type, Some(false));
}

#[test]
fn group_enable_searching_survives_unrelated_edit() {
    let kdbx = round_trip_after_group_notes_edit();
    assert_eq!(work_group(&kdbx).enable_searching, Some(false));
}

// ---------------------------------------------------------------------
// Setter smoke tests for the two fields this slice newly exposes.
// Preservation of an externally-set value is covered above; these
// tests additionally prove the new setters themselves round-trip
// through save + reopen.
// ---------------------------------------------------------------------

#[test]
fn entry_set_icon_id_round_trips_through_save() {
    let mut kdbx = open_fixture();
    let entry_id = work_entry(&kdbx).id;
    kdbx.edit_entry(entry_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_icon_id(7);
    })
    .expect("edit_entry");
    let reopened = reopen(kdbx.save_to_bytes().expect("save_to_bytes"));
    assert_eq!(work_entry(&reopened).icon_id, 7);
}

#[test]
fn group_set_icon_id_round_trips_through_save() {
    let mut kdbx = open_fixture();
    let gid = work_group(&kdbx).id;
    kdbx.edit_group(gid, |g| {
        g.set_icon_id(11);
    })
    .expect("edit_group");
    let reopened = reopen(kdbx.save_to_bytes().expect("save_to_bytes"));
    assert_eq!(work_group(&reopened).icon_id, 11);
}
