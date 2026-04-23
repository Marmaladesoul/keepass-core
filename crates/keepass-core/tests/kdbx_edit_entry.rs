//! Fixture round-trip for [`Kdbx::edit_entry`].
//!
//! Per MUTATION.md §"Slicing plan" slice 4. Covers all three
//! [`HistoryPolicy`] variants — `Snapshot`, `NoSnapshot`, and
//! `SnapshotIfOlderThan(window)` across both sides of the window
//! boundary — and asserts the expected history bookkeeping survives
//! `save_to_bytes → re-open`.

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{Clock, FixedClock, HistoryPolicy, ModelError, NewEntry};
use secrecy::SecretString;
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

/// Shared-state clock the test can advance between mutations.
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
fn edit_entry_snapshot_policy_records_pre_edit_state_and_round_trips() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t1: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();

    let clock = SharedClock::new(t0);
    let handle = clock.clone();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("Gmail")
                .username("alice@example.com")
                .password(SecretString::from("hunter2"))
                .url("https://mail.google.com"),
        )
        .unwrap();

    // Advance clock, then edit with Snapshot policy.
    handle.set(t1);
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("hunter3"));
        e.set_title("Gmail Work");
    })
    .unwrap();

    let edited = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry findable after edit");

    // New values applied.
    assert_eq!(edited.password, "hunter3");
    assert_eq!(edited.title, "Gmail Work");
    // last_modification_time stamped from t1.
    assert_eq!(edited.times.last_modification_time, Some(t1));
    // Exactly one history snapshot, carrying the pre-edit state.
    assert_eq!(edited.history.len(), 1);
    let snap = &edited.history[0];
    assert_eq!(snap.password, "hunter2");
    assert_eq!(snap.title, "Gmail");
    // Snapshot's own history is empty (KeePass never nests).
    assert!(snap.history.is_empty());

    // Round-trip.
    let bytes = kdbx.save_to_bytes().unwrap();
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
        .expect("entry survives round-trip");
    assert_eq!(after.password, "hunter3");
    assert_eq!(after.title, "Gmail Work");
    assert_eq!(after.history.len(), 1);
    assert_eq!(after.history[0].password, "hunter2");
    assert_eq!(after.history[0].title, "Gmail");
}

#[test]
fn edit_entry_no_snapshot_policy_skips_history_and_still_stamps_last_modified() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t1: DateTime<Utc> = "2026-04-22T10:05:00Z".parse().unwrap();

    let clock = SharedClock::new(t0);
    let handle = clock.clone();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("FixupMe")).unwrap();

    handle.set(t1);
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.set_title("Fixed");
    })
    .unwrap();

    let edited = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry");
    assert_eq!(edited.title, "Fixed");
    assert_eq!(edited.times.last_modification_time, Some(t1));
    assert!(
        edited.history.is_empty(),
        "NoSnapshot must not append to history"
    );
}

#[test]
fn snapshot_if_older_than_coalesces_within_the_window() {
    // Within the 24h window → second edit should coalesce (no new
    // snapshot).
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t1: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap(); // 1h after t0 → first edit snapshots
    let t2: DateTime<Utc> = "2026-04-22T13:00:00Z".parse().unwrap(); // 2h after t1 → WITHIN the 24h window → coalesce

    let clock = SharedClock::new(t0);
    let handle = clock.clone();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("Coalesce")).unwrap();

    // First edit: history empty → policy says always snapshot.
    handle.set(t1);
    kdbx.edit_entry(
        id,
        HistoryPolicy::SnapshotIfOlderThan(Duration::hours(24)),
        |e| {
            e.set_title("Coalesce v1");
        },
    )
    .unwrap();
    assert_eq!(
        kdbx.vault()
            .iter_entries()
            .find(|e| e.id == id)
            .unwrap()
            .history
            .len(),
        1,
        "first edit with empty history must snapshot"
    );

    // Second edit 2 hours later: last history entry's
    // last_modification_time is t1 (set by add_entry creating the
    // pre-edit state that got snapshotted). t2 - 24h = yesterday;
    // t1 > yesterday, so policy skips snapshot.
    handle.set(t2);
    kdbx.edit_entry(
        id,
        HistoryPolicy::SnapshotIfOlderThan(Duration::hours(24)),
        |e| {
            e.set_title("Coalesce v2");
        },
    )
    .unwrap();
    let after = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry");
    assert_eq!(after.title, "Coalesce v2");
    assert_eq!(
        after.history.len(),
        1,
        "second edit within the 24h window must not add another snapshot"
    );
    // last_modification_time still stamped from t2.
    assert_eq!(after.times.last_modification_time, Some(t2));
}

#[test]
fn snapshot_if_older_than_takes_new_snapshot_past_the_window() {
    // Past the 24h window → second edit should snapshot again.
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t1: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();
    // 25h after t1 → past the 24h window → snapshot again
    let t2: DateTime<Utc> = "2026-04-23T12:00:00Z".parse().unwrap();

    let clock = SharedClock::new(t0);
    let handle = clock.clone();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("WindowedV")).unwrap();

    handle.set(t1);
    kdbx.edit_entry(
        id,
        HistoryPolicy::SnapshotIfOlderThan(Duration::hours(24)),
        |e| {
            e.set_title("WindowedV v1");
        },
    )
    .unwrap();
    assert_eq!(
        kdbx.vault()
            .iter_entries()
            .find(|e| e.id == id)
            .unwrap()
            .history
            .len(),
        1
    );

    handle.set(t2);
    kdbx.edit_entry(
        id,
        HistoryPolicy::SnapshotIfOlderThan(Duration::hours(24)),
        |e| {
            e.set_title("WindowedV v2");
        },
    )
    .unwrap();
    let after = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry");
    assert_eq!(after.title, "WindowedV v2");
    assert_eq!(
        after.history.len(),
        2,
        "second edit past the 24h window must snapshot again"
    );
    // Oldest-first ordering: history[0] is the very-first snapshot.
    assert_eq!(after.history[0].title, "WindowedV");
    assert_eq!(after.history[1].title, "WindowedV v1");
}

/// Helper for the truncation test below: build N snapshots, assert
/// history length equals `cap` and the retained titles are the last
/// `cap` of `v0 .. v{EDITS-2}` (snapshot N captures the pre-edit
/// title, so snapshot 0 is "Truncate" and snapshots 1.. are
/// `v{N-1}`).
fn assert_truncates_to(cap: usize, edits: usize) {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    // Pin the cap via the public Meta setter (slice 8). The fixture's
    // stock default is 10; the caller drives both "match the default"
    // and "shrink below the default" through this same harness.
    let cap_i32 = i32::try_from(cap).expect("cap fits i32");
    kdbx.set_history_max_items(cap_i32);
    assert_eq!(kdbx.vault().meta.history_max_items, cap_i32);

    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new("Truncate")).unwrap();

    for i in 0..edits {
        kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
            e.set_title(format!("v{i}"));
        })
        .unwrap();
    }

    let e = kdbx.vault().iter_entries().find(|e| e.id == id).unwrap();
    assert_eq!(
        e.history.len(),
        cap,
        "history should be capped at meta.history_max_items ({cap})"
    );
    let titles: Vec<String> = e.history.iter().map(|h| h.title.clone()).collect();
    let expected: Vec<String> = (edits - cap - 1..edits - 1)
        .map(|i| format!("v{i}"))
        .collect();
    assert_eq!(titles, expected);
}

#[test]
fn edit_entry_truncates_history_to_max_items_default() {
    // Default cap of 10 — exercises the path where the truncation
    // policy was already in place from the fixture's stock Meta.
    assert_truncates_to(10, 15);
}

#[test]
fn edit_entry_truncates_history_to_max_items_shrunk_via_meta_setter() {
    // Shrink the cap to 4 via `set_history_max_items` and confirm
    // truncation honours the new ceiling. Closes the testing gap
    // PR #63's cleanup left for the (then-pending) Meta setter.
    assert_truncates_to(4, 15);
}

#[test]
fn edit_entry_rejects_missing_id() {
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
    let err = kdbx
        .edit_entry(bogus, HistoryPolicy::NoSnapshot, |_| ())
        .unwrap_err();
    match err {
        ModelError::EntryNotFound(e) => assert_eq!(e, bogus),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}
