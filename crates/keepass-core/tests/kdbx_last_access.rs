//! Integration tests for `<LastAccessTime>` handling on entries:
//!
//! - [`EntryEditor::set_last_access_time`] — explicit setter that
//!   writes `Some(t)` or clears via `None`.
//! - [`Kdbx::touch_entry`] — leaf stamp `last_access_time = clock.now()`
//!   with no other bookkeeping side-effects.
//!
//! Also proves the **load-bearing invariant** that `edit_entry` does
//! NOT auto-stamp `last_access_time` under either snapshot policy.
//! FFI clock-ownership rule A says the library owns every
//! `*.times.*` stamp, but the corollary is that different stamps fire
//! under different operations — reading an entry's fields through
//! `vault().iter_entries()` (or mutating unrelated fields) is not an
//! access-touch, and a well-meaning "tidy up the bookkeeping into one
//! helper" refactor silently breaks this. The assertion is identity
//! comparison, not "older than now" — the value must be untouched,
//! not "re-touched with an earlier clock reading."
//!
//! Programmatic fixture seeding on `kdbxweb/kdbx4-basic.kdbx`, same
//! pattern as the other mutation-API integration tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{Clock, EntryId, HistoryPolicy, ModelError, NewEntry};

// ---------------------------------------------------------------------
// Fixture helpers (lifted from kdbx_history_restore.rs)
// ---------------------------------------------------------------------

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

fn open_basic_with_clock(t0: DateTime<Utc>) -> (Kdbx<Unlocked>, SharedClock) {
    let path = kdbx4_basic();
    let composite = CompositeKey::from_password(password_from_sidecar(&path).as_bytes());
    let clock = SharedClock::new(t0);
    let handle = clock.clone();
    let kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();
    (kdbx, handle)
}

fn reopen_with_clock(bytes: Vec<u8>, at: DateTime<Utc>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(password_from_sidecar(&kdbx4_basic()).as_bytes());
    Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(SharedClock::new(at)))
        .unwrap()
}

fn find_entry(kdbx: &Kdbx<Unlocked>, id: EntryId) -> &keepass_core::model::Entry {
    kdbx.vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry present")
}

fn add_one_entry(kdbx: &mut Kdbx<Unlocked>) -> EntryId {
    let root = kdbx.vault().root.id;
    kdbx.add_entry(root, NewEntry::new("Gmail")).unwrap()
}

// ---------------------------------------------------------------------
// EntryEditor::set_last_access_time
// ---------------------------------------------------------------------

#[test]
fn set_last_access_time_some_round_trips_through_save() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);

    let pinned: DateTime<Utc> = "2020-06-01T12:34:56Z".parse().unwrap();
    clock.set(t0 + Duration::minutes(1));
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_last_access_time(Some(pinned));
    })
    .unwrap();

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(2));
    assert_eq!(
        find_entry(&reopened, id).times.last_access_time,
        Some(pinned)
    );
}

#[test]
fn set_last_access_time_none_clears_and_round_trips_as_absent() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    // `add_entry` stamps `last_access_time = t0`; assert the starting
    // state so the clearing step is meaningful.
    assert_eq!(find_entry(&kdbx, id).times.last_access_time, Some(t0));

    clock.set(t0 + Duration::minutes(1));
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_last_access_time(None);
    })
    .unwrap();
    assert_eq!(find_entry(&kdbx, id).times.last_access_time, None);

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(2));
    assert_eq!(find_entry(&reopened, id).times.last_access_time, None);
}

// ---------------------------------------------------------------------
// Kdbx::touch_entry
// ---------------------------------------------------------------------

#[test]
fn touch_entry_stamps_last_access_time_from_clock() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    let before = find_entry(&kdbx, id).times.clone();

    let t_touch = t0 + Duration::hours(2);
    clock.set(t_touch);
    kdbx.touch_entry(id).unwrap();

    let after = &find_entry(&kdbx, id).times;
    assert_eq!(after.last_access_time, Some(t_touch));

    // Every other `times.*` field must be unchanged — `touch_entry`
    // is a leaf stamp, not an edit.
    assert_eq!(after.creation_time, before.creation_time);
    assert_eq!(after.last_modification_time, before.last_modification_time);
    assert_eq!(after.location_changed, before.location_changed);
    assert_eq!(after.expiry_time, before.expiry_time);
    assert_eq!(after.expires, before.expires);
    assert_eq!(after.usage_count, before.usage_count);
}

#[test]
fn touch_entry_with_unknown_id_returns_entry_not_found() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let bogus = EntryId(uuid::Uuid::from_u128(0xDEAD_BEEF));

    let err = kdbx.touch_entry(bogus).unwrap_err();
    match err {
        ModelError::EntryNotFound(got) => assert_eq!(got, bogus),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

#[test]
fn touch_entry_does_not_snapshot_history() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    let history_len_before = find_entry(&kdbx, id).history.len();
    assert_eq!(history_len_before, 0);

    clock.set(t0 + Duration::hours(1));
    kdbx.touch_entry(id).unwrap();
    assert_eq!(find_entry(&kdbx, id).history.len(), history_len_before);
}

#[test]
fn touch_entry_does_not_stamp_meta_settings_changed() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    let settings_before = kdbx.vault().meta.settings_changed;

    clock.set(t0 + Duration::hours(1));
    kdbx.touch_entry(id).unwrap();
    assert_eq!(kdbx.vault().meta.settings_changed, settings_before);
}

#[test]
fn touch_entry_does_not_stamp_last_modification_time() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    let lmt_before = find_entry(&kdbx, id).times.last_modification_time;

    clock.set(t0 + Duration::hours(1));
    kdbx.touch_entry(id).unwrap();
    assert_eq!(
        find_entry(&kdbx, id).times.last_modification_time,
        lmt_before,
        "touch is a read-access stamp, not a content edit"
    );
}

// ---------------------------------------------------------------------
// Load-bearing invariant: edit_entry does NOT auto-stamp last_access_time
// ---------------------------------------------------------------------

/// The library must never advance `last_access_time` from an edit.
/// Identity-checked across both `HistoryPolicy` variants — a refactor
/// that merges the stamping helpers would likely touch both paths at
/// once, so testing both together raises the cost of the bad refactor.
#[test]
fn edit_entry_does_not_auto_stamp_last_access_time_under_either_policy() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = add_one_entry(&mut kdbx);
    // `add_entry` stamped `last_access_time = t0`. Pin a different,
    // deliberately-ancient value so the assertion distinguishes
    // "untouched" from "re-stamped to the current clock".
    let pinned: DateTime<Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_last_access_time(Some(pinned));
    })
    .unwrap();
    assert_eq!(find_entry(&kdbx, id).times.last_access_time, Some(pinned));

    // Unrelated edit under NoSnapshot — must not advance last_access.
    clock.set(t0 + Duration::hours(1));
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_title("edit under NoSnapshot");
    })
    .unwrap();
    assert_eq!(
        find_entry(&kdbx, id).times.last_access_time,
        Some(pinned),
        "edit_entry(NoSnapshot) must not auto-stamp last_access_time"
    );

    // Unrelated edit under Snapshot — same invariant must hold.
    clock.set(t0 + Duration::hours(2));
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_title("edit under Snapshot");
    })
    .unwrap();
    assert_eq!(
        find_entry(&kdbx, id).times.last_access_time,
        Some(pinned),
        "edit_entry(Snapshot) must not auto-stamp last_access_time"
    );
}
