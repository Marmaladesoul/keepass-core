//! Integration tests for `Meta::custom_icons` pool management:
//!
//! - [`Kdbx::add_custom_icon`] — UUID-minted insertion with
//!   content-hash dedup.
//! - [`Kdbx::remove_custom_icon`] — direct pool removal.
//! - [`Kdbx::custom_icon`] — byte-borrow accessor.
//!
//! Plus the save-time refcount GC:
//!
//! - orphans pruned;
//! - refs in live entries, live groups, and history snapshots
//!   keep their icons alive;
//! - dangling `custom_icon_uuid` refs swept to `None`.
//!
//! Seeded programmatically against `kdbxweb/kdbx4-basic.kdbx`, matching
//! the pattern in the other mutation-API tests.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{Clock, EntryId, HistoryPolicy, NewEntry};

// ---------------------------------------------------------------------
// Fixture helpers
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

fn add_entry_with_icon(
    kdbx: &mut Kdbx<Unlocked>,
    title: &str,
    icon: Option<uuid::Uuid>,
) -> EntryId {
    let root = kdbx.vault().root.id;
    let id = kdbx.add_entry(root, NewEntry::new(title)).unwrap();
    if let Some(u) = icon {
        kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
            e.set_custom_icon(Some(u));
        })
        .unwrap();
    }
    id
}

// ---------------------------------------------------------------------
// API-surface tests
// ---------------------------------------------------------------------

#[test]
fn add_custom_icon_returns_uuid_and_custom_icon_accessor_returns_bytes() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"icon-payload-v1".to_vec());
    assert_eq!(
        kdbx.custom_icon(uuid).map(<[u8]>::to_vec),
        Some(b"icon-payload-v1".to_vec())
    );

    // Reference the icon so the GC on save keeps it alive.
    let id = add_entry_with_icon(&mut kdbx, "With Icon", Some(uuid));
    assert_eq!(find_entry(&kdbx, id).custom_icon_uuid, Some(uuid));

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(1));
    assert_eq!(
        reopened.custom_icon(uuid).map(<[u8]>::to_vec),
        Some(b"icon-payload-v1".to_vec())
    );
}

#[test]
fn add_custom_icon_dedups_by_content_hash() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let bytes = b"identical-icon-bytes".to_vec();
    let first = kdbx.add_custom_icon(bytes.clone());
    let second = kdbx.add_custom_icon(bytes);
    assert_eq!(first, second, "dedup returns the existing UUID");
    assert_eq!(
        kdbx.vault().meta.custom_icons.len(),
        1,
        "dedup does not grow the pool"
    );
    // The "dedup doesn't clobber an existing icon's `name` /
    // `last_modified`" invariant is covered by the co-located unit
    // test `add_custom_icon_dedup_preserves_existing_metadata` in
    // `kdbx.rs` — that field isn't on the public surface yet, so
    // asserting it across the crate boundary would require reaching
    // through `unsafe` or adding a test-only accessor. The in-crate
    // test constructs `CustomIcon` directly.
}

#[test]
fn remove_custom_icon_returns_true_for_present_and_drops_from_pool() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"ephemeral".to_vec());
    assert!(kdbx.custom_icon(uuid).is_some());
    assert!(kdbx.remove_custom_icon(uuid));
    assert!(kdbx.custom_icon(uuid).is_none());
    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(1));
    assert!(reopened.custom_icon(uuid).is_none());
}

#[test]
fn remove_custom_icon_returns_false_for_absent_and_no_mutation() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let settings_before = kdbx.vault().meta.settings_changed;
    let bogus = uuid::Uuid::from_u128(0x1234_5678);
    assert!(!kdbx.remove_custom_icon(bogus));
    assert_eq!(kdbx.vault().meta.settings_changed, settings_before);
    assert!(kdbx.vault().meta.custom_icons.is_empty());
}

// ---------------------------------------------------------------------
// Save-time GC
// ---------------------------------------------------------------------

#[test]
fn save_gc_keeps_icon_referenced_only_by_a_live_entry() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"live-ref".to_vec());
    add_entry_with_icon(&mut kdbx, "Holder", Some(uuid));

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(1));
    assert_eq!(
        reopened.custom_icon(uuid).map(<[u8]>::to_vec),
        Some(b"live-ref".to_vec()),
        "icon referenced by a live entry must survive save-time GC"
    );
}

#[test]
fn save_gc_keeps_icon_referenced_only_by_a_history_snapshot() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"history-only".to_vec());

    // Live entry points at the icon; snapshot captures that state.
    let id = add_entry_with_icon(&mut kdbx, "Holder", Some(uuid));

    // Edit with Snapshot policy, clearing the icon on live — the
    // only remaining reference is now the history snapshot.
    clock.set(t0 + Duration::minutes(1));
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.set_custom_icon(None);
    })
    .unwrap();
    assert_eq!(find_entry(&kdbx, id).custom_icon_uuid, None);
    assert_eq!(find_entry(&kdbx, id).history.len(), 1);
    assert_eq!(
        find_entry(&kdbx, id).history[0].custom_icon_uuid,
        Some(uuid),
        "snapshot preserves the pre-edit reference"
    );

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(2));
    assert_eq!(
        reopened.custom_icon(uuid).map(<[u8]>::to_vec),
        Some(b"history-only".to_vec()),
        "icon referenced only by a history snapshot must survive GC"
    );
}

#[test]
fn save_gc_drops_orphaned_icon() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"orphan".to_vec());
    // Never referenced by any entry or group.

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(1));
    assert!(
        reopened.custom_icon(uuid).is_none(),
        "orphaned icon must be GC'd on save"
    );
}

#[test]
fn save_gc_clears_dangling_custom_icon_uuid_to_none() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, _clock) = open_basic_with_clock(t0);
    let uuid = kdbx.add_custom_icon(b"to-be-deleted".to_vec());
    let id = add_entry_with_icon(&mut kdbx, "Holder", Some(uuid));

    // Remove the icon from the pool WITHOUT unsetting the entry's
    // reference — exactly the dangling shape the GC is there to fix.
    assert!(kdbx.remove_custom_icon(uuid));
    assert_eq!(
        find_entry(&kdbx, id).custom_icon_uuid,
        Some(uuid),
        "in-memory ref intentionally dangles pre-save"
    );

    let reopened = reopen_with_clock(kdbx.save_to_bytes().unwrap(), t0 + Duration::minutes(1));
    assert_eq!(
        find_entry(&reopened, id).custom_icon_uuid,
        None,
        "dangling custom_icon_uuid must be reset to None on save"
    );
    assert!(reopened.custom_icon(uuid).is_none());
}

// ---------------------------------------------------------------------
// Settings-changed stamping contract
// ---------------------------------------------------------------------

#[test]
fn settings_changed_stamps_on_add_present_remove_only() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let settings_start = kdbx.vault().meta.settings_changed;

    // add_custom_icon stamps.
    clock.set(t0 + Duration::hours(1));
    let uuid = kdbx.add_custom_icon(b"stamping".to_vec());
    let after_add = kdbx.vault().meta.settings_changed;
    assert_ne!(after_add, settings_start, "add_custom_icon must stamp");

    // remove_custom_icon(absent) must NOT stamp.
    clock.set(t0 + Duration::hours(2));
    let bogus = uuid::Uuid::from_u128(0xDEAD);
    assert!(!kdbx.remove_custom_icon(bogus));
    assert_eq!(
        kdbx.vault().meta.settings_changed,
        after_add,
        "remove_custom_icon on an absent id must not stamp"
    );

    // remove_custom_icon(present) must stamp.
    clock.set(t0 + Duration::hours(3));
    assert!(kdbx.remove_custom_icon(uuid));
    assert_ne!(
        kdbx.vault().meta.settings_changed,
        after_add,
        "remove_custom_icon on a present id must stamp"
    );
}
