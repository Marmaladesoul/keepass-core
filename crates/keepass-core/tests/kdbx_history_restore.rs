//! Integration tests for history management on entries:
//!
//! - [`EntryEditor::remove_history_at`] / [`EntryEditor::clear_history`]
//!   (per-revision delete + clear-all).
//! - [`Kdbx::restore_entry_from_history`] (revert live content to a
//!   named prior snapshot).
//!
//! History surface is seeded programmatically via
//! `edit_entry(HistoryPolicy::Snapshot, ...)` against the standard
//! `kdbxweb/kdbx4-basic.kdbx` base rather than from a dedicated
//! history-pinned fixture — the test body then reads as the
//! specification of what's being exercised. One divergent case
//! (`unknown_xml` keep-live) can't be built through the public API
//! (`unknown_xml` has no setter), so it uses the small
//! `history-unknown-xml.kdbx` fixture whose generator bakes the
//! live-vs-snapshot divergence in directly.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{Clock, EntryId, HistoryPolicy, ModelError, NewEntry};
use secrecy::SecretString;

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

/// Shared-state clock — tests advance it between mutations so each
/// snapshot's `last_modification_time` is distinguishable.
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

/// Open the base fixture with a pinned [`SharedClock`] so the test
/// can advance time deterministically.
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

/// Add one entry, then edit it `revs.len()` times with
/// `HistoryPolicy::Snapshot` to build a predictable history. Advances
/// the injected clock by one minute per revision.
///
/// Each element of `revs` is the password the entry carries AFTER
/// that revision. At the end of the function the entry has:
///
/// - `password` = `revs.last()`, `title = "Gmail"`.
/// - `history.len()` = `revs.len() - 1` (the initial add isn't a
///   snapshot; every subsequent edit is).
/// - `history[i].password` = `revs[i]` (the pre-edit state at the
///   moment of the (i+1)-th edit, which is the i-th revision's
///   password).
fn seed_entry_with_history(
    kdbx: &mut Kdbx<Unlocked>,
    clock: &SharedClock,
    t0: DateTime<Utc>,
    revs: &[&str],
) -> EntryId {
    assert!(!revs.is_empty(), "at least one revision required");
    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("Gmail")
                .username("alice@example.com")
                .password(SecretString::from(revs[0]))
                .url("https://mail.google.com"),
        )
        .unwrap();

    for (i, pw) in revs.iter().enumerate().skip(1) {
        clock.set(t0 + Duration::minutes(i64::try_from(i).unwrap()));
        kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
            e.set_password(SecretString::from(*pw));
        })
        .unwrap();
    }
    id
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

// ---------------------------------------------------------------------
// EntryEditor::remove_history_at / clear_history
// ---------------------------------------------------------------------

#[test]
fn remove_history_at_valid_index_drops_that_entry_and_shifts_the_rest() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3", "v4"]);
    // history now carries [v1, v2, v3]; live password is v4.
    assert_eq!(find_entry(&kdbx, id).history.len(), 3);

    clock.set(t0 + Duration::minutes(10));
    let removed = kdbx
        .edit_entry(id, HistoryPolicy::NoSnapshot, |e| e.remove_history_at(1))
        .unwrap();
    assert!(removed);

    let hist = &find_entry(&kdbx, id).history;
    assert_eq!(hist.len(), 2);
    assert_eq!(hist[0].password, "v1");
    assert_eq!(hist[1].password, "v3");
}

#[test]
fn remove_history_at_out_of_range_returns_false_and_preserves_history() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2"]);
    assert_eq!(find_entry(&kdbx, id).history.len(), 1);

    clock.set(t0 + Duration::minutes(5));
    let removed = kdbx
        .edit_entry(id, HistoryPolicy::NoSnapshot, |e| e.remove_history_at(99))
        .unwrap();
    assert!(!removed);
    assert_eq!(find_entry(&kdbx, id).history.len(), 1);
}

#[test]
fn clear_history_drops_all_entries_and_returns_count() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3", "v4"]);
    assert_eq!(find_entry(&kdbx, id).history.len(), 3);

    clock.set(t0 + Duration::minutes(10));
    let dropped = kdbx
        // `clear_history` as a method pointer doesn't bridge the
        // higher-ranked lifetime on `EntryEditor<'_>`; keep the
        // closure even though clippy thinks it's redundant.
        .edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
            #[allow(clippy::redundant_closure_for_method_calls)]
            e.clear_history()
        })
        .unwrap();
    assert_eq!(dropped, 3);
    assert!(find_entry(&kdbx, id).history.is_empty());
}

#[test]
fn clear_history_on_empty_returns_zero_without_side_effects() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1"]);
    assert!(find_entry(&kdbx, id).history.is_empty());

    let dropped = kdbx
        // `clear_history` as a method pointer doesn't bridge the
        // higher-ranked lifetime on `EntryEditor<'_>`; keep the
        // closure even though clippy thinks it's redundant.
        .edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
            #[allow(clippy::redundant_closure_for_method_calls)]
            e.clear_history()
        })
        .unwrap();
    assert_eq!(dropped, 0);
    assert!(find_entry(&kdbx, id).history.is_empty());
}

// ---------------------------------------------------------------------
// Kdbx::restore_entry_from_history
// ---------------------------------------------------------------------

#[test]
fn restore_with_snapshot_policy_pushes_pre_restore_and_restores_content() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3"]);
    // history = [v1, v2]; live password = v3.

    // Restore `v1` (history[0]). Pre-restore live (v3) should land as
    // a new snapshot; live content should match v1; last_mod stamped
    // from the restore-time clock.
    let t_restore = t0 + Duration::hours(1);
    clock.set(t_restore);
    kdbx.restore_entry_from_history(id, 0, HistoryPolicy::Snapshot)
        .unwrap();

    let e = find_entry(&kdbx, id);
    assert_eq!(e.password, "v1", "live content restored from snapshot");
    // history now carries v1, v2, AND the pre-restore v3 snapshot.
    assert_eq!(e.history.len(), 3);
    assert_eq!(e.history[0].password, "v1");
    assert_eq!(e.history[1].password, "v2");
    assert_eq!(e.history[2].password, "v3");
    // The pushed pre-restore snapshot carries empty history (KeePass
    // never nests).
    assert!(e.history[2].history.is_empty());
    // last_modification_time advanced to the restore clock.
    assert_eq!(e.times.last_modification_time, Some(t_restore));
}

#[test]
fn restore_with_no_snapshot_policy_leaves_history_length_unchanged() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3"]);
    // history = [v1, v2]; live = v3.
    let hist_len_before = find_entry(&kdbx, id).history.len();
    assert_eq!(hist_len_before, 2);

    let t_restore = t0 + Duration::hours(1);
    clock.set(t_restore);
    kdbx.restore_entry_from_history(id, 1, HistoryPolicy::NoSnapshot)
        .unwrap();

    let e = find_entry(&kdbx, id);
    assert_eq!(e.password, "v2", "live content restored from snapshot");
    assert_eq!(e.history.len(), hist_len_before);
    assert_eq!(e.times.last_modification_time, Some(t_restore));
}

#[test]
fn restore_with_out_of_range_index_rejects_with_typed_error() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2"]);
    // history.len() == 1.

    clock.set(t0 + Duration::hours(1));
    let err = kdbx
        .restore_entry_from_history(id, 5, HistoryPolicy::NoSnapshot)
        .unwrap_err();
    match err {
        ModelError::HistoryIndexOutOfRange {
            id: err_id,
            index,
            len,
        } => {
            assert_eq!(err_id, id);
            assert_eq!(index, 5);
            assert_eq!(len, 1);
        }
        other => panic!("expected HistoryIndexOutOfRange, got {other:?}"),
    }

    // No mutation: content is still v2, history is still [v1].
    let e = find_entry(&kdbx, id);
    assert_eq!(e.password, "v2");
    assert_eq!(e.history.len(), 1);
}

#[test]
fn restore_keeps_live_unknown_xml_and_does_not_roll_back_to_snapshot_unknown_xml() {
    let path = fixtures_root().join("pykeepass/history-unknown-xml.kdbx");
    let composite = CompositeKey::from_password(password_from_sidecar(&path).as_bytes());
    let t_restore: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(SharedClock::new(t_restore)))
        .unwrap();

    // Sanity on the fixture shape before we do anything.
    let id = kdbx.vault().iter_entries().next().unwrap().id;
    {
        let e = find_entry(&kdbx, id);
        assert_eq!(e.title, "Current");
        assert_eq!(e.history.len(), 1);
        let live_tags: Vec<_> = e.unknown_xml.iter().map(|u| &u.tag).collect();
        let snap_tags: Vec<_> = e.history[0].unknown_xml.iter().map(|u| &u.tag).collect();
        assert_eq!(live_tags, vec!["FutureLive"]);
        assert_eq!(snap_tags, vec!["FutureSnap"]);
    }

    kdbx.restore_entry_from_history(id, 0, HistoryPolicy::NoSnapshot)
        .unwrap();

    let e = find_entry(&kdbx, id);
    // Content came from the snapshot.
    assert_eq!(e.title, "Original");
    // Unknown XML stayed on the live entry — NOT rolled back from snap.
    let live_tags: Vec<_> = e.unknown_xml.iter().map(|u| &u.tag).collect();
    assert_eq!(
        live_tags,
        vec!["FutureLive"],
        "live unknown_xml must not be overwritten from the snapshot's"
    );
    // And didn't acquire the snapshot's marker either.
    assert!(
        !e.unknown_xml.iter().any(|u| u.tag == "FutureSnap"),
        "restore must not import snapshot-only unknown_xml"
    );
}

#[test]
fn restore_preserves_attachment_refs_through_save_and_reopen() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1"]);

    // Attach a binary to the live entry, then snapshot by editing.
    clock.set(t0 + Duration::minutes(1));
    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("old-file.txt", b"hello-from-the-past".to_vec(), false);
    })
    .unwrap();

    // Snapshot this state (live carries the attachment), then remove
    // the attachment on live. After the next edit, the binary is
    // referenced only by the snapshot.
    clock.set(t0 + Duration::minutes(2));
    kdbx.edit_entry(id, HistoryPolicy::Snapshot, |e| {
        e.detach("old-file.txt");
    })
    .unwrap();
    {
        let e = find_entry(&kdbx, id);
        assert!(e.attachments.is_empty(), "live entry detached");
        assert_eq!(e.history.len(), 1);
        assert_eq!(
            e.history[0].attachments.len(),
            1,
            "snapshot still references the binary, keeping it in the pool"
        );
    }

    // Restore from history[0] — the attachment ref must come back.
    clock.set(t0 + Duration::minutes(3));
    kdbx.restore_entry_from_history(id, 0, HistoryPolicy::NoSnapshot)
        .unwrap();
    assert_eq!(find_entry(&kdbx, id).attachments.len(), 1);

    // Save and re-open; the binary bytes must still be there.
    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = reopen_with_clock(bytes, t0 + Duration::minutes(4));
    let e = find_entry(&reopened, id);
    assert_eq!(e.attachments.len(), 1);
    assert_eq!(e.attachments[0].name, "old-file.txt");
    let bin = &reopened.vault().binaries[e.attachments[0].ref_id as usize];
    assert_eq!(bin.data, b"hello-from-the-past");
}

#[test]
fn restore_under_snapshot_policy_truncates_per_history_max_items() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3"]);
    // history = [v1, v2]; live = v3.
    kdbx.set_history_max_items(2);

    clock.set(t0 + Duration::hours(1));
    kdbx.restore_entry_from_history(id, 0, HistoryPolicy::Snapshot)
        .unwrap();

    // Restore would have produced [v1, v2, pre-restore v3] = 3 entries;
    // max_items = 2 means the oldest (v1) is dropped post-push.
    let e = find_entry(&kdbx, id);
    assert_eq!(e.history.len(), 2);
    assert_eq!(e.history[0].password, "v2");
    assert_eq!(e.history[1].password, "v3");
    assert_eq!(e.password, "v1", "live content is still the restored v1");
}

#[test]
fn restore_round_trips_through_save_and_reopen() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut kdbx, clock) = open_basic_with_clock(t0);
    let id = seed_entry_with_history(&mut kdbx, &clock, t0, &["v1", "v2", "v3"]);

    let t_restore = t0 + Duration::hours(1);
    clock.set(t_restore);
    kdbx.restore_entry_from_history(id, 0, HistoryPolicy::Snapshot)
        .unwrap();

    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = reopen_with_clock(bytes, t_restore + Duration::minutes(1));
    let e = find_entry(&reopened, id);
    assert_eq!(e.password, "v1");
    assert_eq!(e.history.len(), 3);
    assert_eq!(e.history[2].password, "v3");
    assert_eq!(e.times.last_modification_time, Some(t_restore));
}
