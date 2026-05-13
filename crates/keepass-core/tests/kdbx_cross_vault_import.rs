//! Integration tests for [`Kdbx::export_entry`] + [`Kdbx::import_entry`]
//! (FFI_PHASE1 item 6).
//!
//! The test harness opens `kdbxweb/kdbx4-basic.kdbx` twice for "source"
//! and "destination" vaults — two independent unlock-sessions of the
//! same bytes. That's cheaper than minting a dedicated dst fixture
//! and keeps the cross-vault cases inline with the rest of the
//! slice 6 behaviour. One test reuses `pykeepass/unknown-xml.kdbx`
//! as source so the `unknown_xml`-preservation case has real
//! foreign-writer content without a public setter.
//!
//! Naming convention:
//!
//! - `src_*` helpers / locals operate on the source vault.
//! - `dst_*` / `to_*` operate on the destination vault.
//! - `portable` is the `PortableEntry` in flight.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{Clock, EntryId, GroupId, HistoryPolicy, ModelError, NewEntry};
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

fn unknown_xml_fixture() -> PathBuf {
    fixtures_root().join("pykeepass/unknown-xml.kdbx")
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

fn open_basic_pair(
    src_clock: DateTime<Utc>,
    dst_clock: DateTime<Utc>,
) -> ((Kdbx<Unlocked>, SharedClock), (Kdbx<Unlocked>, SharedClock)) {
    (
        open_with_clock(&kdbx4_basic(), src_clock),
        open_with_clock(&kdbx4_basic(), dst_clock),
    )
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

fn root_group(kdbx: &Kdbx<Unlocked>) -> GroupId {
    kdbx.vault().root.id
}

// ---------------------------------------------------------------------
// Error-surface tests
// ---------------------------------------------------------------------

#[test]
fn export_entry_with_unknown_id_returns_entry_not_found() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (src, _) = open_with_clock(&kdbx4_basic(), t0);
    let bogus = EntryId(uuid::Uuid::from_u128(0xDEAD));
    match src.export_entry(bogus) {
        Err(ModelError::EntryNotFound(got)) => assert_eq!(got, bogus),
        other => panic!("expected EntryNotFound, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// Round-trip: same-vault + cross-vault
// ---------------------------------------------------------------------

#[test]
fn same_vault_round_trip_with_mint_new_uuid() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut src, clock) = open_with_clock(&kdbx4_basic(), t0);
    let src_id = src
        .add_entry(
            root_group(&src),
            NewEntry::new("Gmail")
                .username("alice@example.com")
                .password(SecretString::from("v1"))
                .url("https://mail.google.com"),
        )
        .unwrap();

    let portable = src.export_entry(src_id).unwrap();
    clock.set(t0 + Duration::hours(1));
    let new_id = src
        .import_entry(root_group(&src), portable, /* mint_new_uuid */ true)
        .unwrap();

    assert_ne!(new_id, src_id, "mint_new_uuid must produce a fresh id");

    // Both live on in the source vault; content fields match.
    let original = find_entry(&src, src_id).expect("original kept");
    let imported = find_entry(&src, new_id).expect("imported present");
    assert_eq!(original.title, imported.title);
    assert_eq!(original.username, imported.username);
    assert_eq!(original.password, imported.password);
    assert_eq!(original.url, imported.url);
}

#[test]
fn cross_vault_round_trip_with_mint_new_uuid() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t_import: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t_import);
    let src_id = src
        .add_entry(
            root_group(&src),
            NewEntry::new("Work VPN")
                .username("bob")
                .password(SecretString::from("hunter2"))
                .url("https://vpn.example"),
        )
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();

    let new_id = dst
        .import_entry(root_group(&dst), portable, /* mint_new_uuid */ true)
        .unwrap();

    assert_ne!(new_id, src_id);
    let imported = find_entry(&dst, new_id).expect("in destination");
    assert_eq!(imported.title, "Work VPN");
    assert_eq!(imported.username, "bob");
    assert_eq!(imported.password, "hunter2");

    // Source still carries the original — export is read-only.
    assert!(find_entry(&src, src_id).is_some());
    assert!(find_entry(&dst, src_id).is_none());
}

#[test]
fn import_preserves_uuid_when_mint_new_uuid_is_false() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Keep UUID"))
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();
    let new_id = dst.import_entry(root_group(&dst), portable, false).unwrap();
    assert_eq!(new_id, src_id);
}

#[test]
fn import_duplicate_uuid_fails_cleanly_without_mutation() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);
    // Add an entry to src, import it into dst once successfully,
    // then try a second import with mint_new_uuid=false — must fail.
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("First"))
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();
    let _first = dst.import_entry(root_group(&dst), portable, false).unwrap();

    let dst_entry_count_before = dst.vault().total_entries();

    let portable2 = src.export_entry(src_id).unwrap();
    match dst.import_entry(root_group(&dst), portable2, false) {
        Err(ModelError::DuplicateUuid(uuid)) => assert_eq!(uuid, src_id.0),
        other => panic!("expected DuplicateUuid, got {other:?}"),
    }

    assert_eq!(
        dst.vault().total_entries(),
        dst_entry_count_before,
        "failed import must not mutate the destination"
    );
}

/// Regression guard for the `group_uuid_in_use` history-walk fix
/// (PR #79 review — reviewer's `#R5` finding).
///
/// Before the fix, `group_uuid_in_use` only walked live entry ids;
/// an incoming UUID colliding with an existing destination **history
/// snapshot** id slipped past the pre-mutation validation and the
/// import silently succeeded with a tree-wide UUID collision.
///
/// The test constructs exactly that state: destination holds an
/// entry whose `history[0].id` is a freshly-minted UUID distinct
/// from the live entry's id (courtesy of `import_entry(mint_new_uuid=
/// true)`'s own history re-minting). A second import with
/// `mint_new_uuid=false` carrying that history UUID as its live id
/// must now fail with `DuplicateUuid`.
#[test]
fn import_false_rejects_collision_with_destination_history_uuid() {
    use keepass_core::model::NewEntry;
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, src_clock), (mut dst, _)) = open_basic_pair(t0, t0);

    // Build src_with_history: an entry carrying one history snapshot.
    let src_with_hist = src
        .add_entry(
            root_group(&src),
            NewEntry::new("With History").password(SecretString::from("v1")),
        )
        .unwrap();
    src_clock.set(t0 + Duration::minutes(1));
    src.edit_entry(src_with_hist, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("v2"));
    })
    .unwrap();

    // Seed dst by importing with mint_new_uuid=true. The destination
    // entry's live id and its history[0].id are BOTH fresh UUIDs
    // distinct from each other under our import implementation —
    // `fresh_uuid` mints a new UUID per call, so live + history get
    // different values.
    let portable = src.export_entry(src_with_hist).unwrap();
    let dst_live = dst.import_entry(root_group(&dst), portable, true).unwrap();
    let dst_hist_id = {
        let dst_entry = find_entry(&dst, dst_live).expect("seeded entry present");
        assert_eq!(dst_entry.history.len(), 1);
        dst_entry.history[0].id
    };
    assert_ne!(
        dst_live, dst_hist_id,
        "history re-mint produced a distinct UUID — test premise intact"
    );

    // Now build a source entry whose live id deliberately collides
    // with the destination's history[0].id via `NewEntry::with_uuid`.
    // Import with mint_new_uuid=false must catch the history-side
    // collision BEFORE any mutation.
    let collision = dst_hist_id.0;
    let src_colliding = src
        .add_entry(
            root_group(&src),
            NewEntry::new("Collider").with_uuid(collision),
        )
        .unwrap();
    assert_eq!(src_colliding.0, collision);

    let portable2 = src.export_entry(src_colliding).unwrap();
    let dst_entries_before = dst.vault().total_entries();
    match dst.import_entry(root_group(&dst), portable2, /* mint_new_uuid */ false) {
        Err(ModelError::DuplicateUuid(uuid)) => assert_eq!(uuid, collision),
        other => panic!("expected DuplicateUuid for history-id collision, got {other:?}"),
    }
    assert_eq!(
        dst.vault().total_entries(),
        dst_entries_before,
        "rejected import must not mutate the destination"
    );
}

// ---------------------------------------------------------------------
// Binary pool remap
// ---------------------------------------------------------------------

#[test]
fn import_dedups_binaries_against_destination_pool_by_content_hash() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    // Source entry carries "shared.bin" → b"SHARED".
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Src With Attachment"))
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("shared.bin", b"SHARED".to_vec(), false);
    })
    .unwrap();

    // Destination already holds a binary with identical bytes (under
    // a different filename — dedup is by content, not name).
    let dst_holder = dst
        .add_entry(root_group(&dst), NewEntry::new("Dst Pre-populated"))
        .unwrap();
    dst.edit_entry(dst_holder, HistoryPolicy::NoSnapshot, |e| {
        e.attach("prior.bin", b"SHARED".to_vec(), false);
    })
    .unwrap();

    let dst_pool_size_before = dst.vault().binaries.len();

    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    assert_eq!(
        dst.vault().binaries.len(),
        dst_pool_size_before,
        "content-hash dedup must not grow the destination pool"
    );

    let imported_entry = find_entry(&dst, imported).unwrap();
    assert_eq!(imported_entry.attachments.len(), 1);
    let ref_id = imported_entry.attachments[0].ref_id;
    assert_eq!(dst.vault().binaries[ref_id as usize].data, b"SHARED");
}

#[test]
fn import_appends_new_binary_when_destination_has_no_match() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Unique Attachment"))
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("unique.bin", b"UNIQUE".to_vec(), false);
    })
    .unwrap();

    let dst_pool_size_before = dst.vault().binaries.len();
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    assert_eq!(dst.vault().binaries.len(), dst_pool_size_before + 1);
    let e = find_entry(&dst, imported).unwrap();
    let ref_id = e.attachments[0].ref_id;
    assert_eq!(dst.vault().binaries[ref_id as usize].data, b"UNIQUE");
}

// ---------------------------------------------------------------------
// Custom-icon pool remap
// ---------------------------------------------------------------------

#[test]
fn import_preserves_custom_icon_uuid_when_mint_new_uuid_is_false() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);
    let icon_uuid = src.add_custom_icon(b"icon-a".to_vec());
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Icon Entry"))
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_icon(Some(icon_uuid));
    })
    .unwrap();

    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, false).unwrap();

    let e = find_entry(&dst, imported).unwrap();
    assert_eq!(
        e.custom_icon_uuid,
        Some(icon_uuid),
        "mint_new_uuid=false preserves the source UUID"
    );
    assert!(dst.custom_icon(icon_uuid).is_some());
}

#[test]
fn import_content_hash_dedups_icons_when_mint_new_uuid_is_true() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    // Destination already has an icon with these bytes under UUID_dst.
    let dst_uuid = dst.add_custom_icon(b"shared-icon-bytes".to_vec());

    // Source has a different UUID for the same bytes.
    let src_uuid = src.add_custom_icon(b"shared-icon-bytes".to_vec());
    assert_ne!(src_uuid, dst_uuid);
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Icon Entry"))
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_icon(Some(src_uuid));
    })
    .unwrap();

    let dst_pool_size_before = dst.vault().meta.custom_icons.len();

    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let e = find_entry(&dst, imported).unwrap();
    assert_eq!(
        e.custom_icon_uuid,
        Some(dst_uuid),
        "content-hash dedup must remap to the destination's existing icon"
    );
    assert_eq!(
        dst.vault().meta.custom_icons.len(),
        dst_pool_size_before,
        "content-hash dedup must not grow the destination pool"
    );
}

#[test]
fn import_carries_new_icon_when_destination_has_no_match() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);
    let src_uuid = src.add_custom_icon(b"unique-icon".to_vec());
    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Icon Entry"))
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.set_custom_icon(Some(src_uuid));
    })
    .unwrap();

    let dst_pool_size_before = dst.vault().meta.custom_icons.len();
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let e = find_entry(&dst, imported).unwrap();
    let dst_uuid = e.custom_icon_uuid.expect("icon remapped to a UUID");
    assert_eq!(
        dst.vault().meta.custom_icons.len(),
        dst_pool_size_before + 1
    );
    assert_eq!(
        dst.custom_icon(dst_uuid).map(<[u8]>::to_vec),
        Some(b"unique-icon".to_vec())
    );
}

// ---------------------------------------------------------------------
// History travels
// ---------------------------------------------------------------------

#[test]
fn import_carries_history_snapshots_with_verbatim_timestamps() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut src, src_clock) = open_with_clock(&kdbx4_basic(), t0);

    // Build up history on the source entry: two Snapshot edits at
    // distinct clock points.
    let src_id = src
        .add_entry(
            root_group(&src),
            NewEntry::new("With History").password(SecretString::from("v1")),
        )
        .unwrap();
    src_clock.set(t0 + Duration::minutes(1));
    src.edit_entry(src_id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("v2"));
    })
    .unwrap();
    src_clock.set(t0 + Duration::minutes(2));
    src.edit_entry(src_id, HistoryPolicy::Snapshot, |e| {
        e.set_password(SecretString::from("v3"));
    })
    .unwrap();

    let src_entry = find_entry(&src, src_id).unwrap();
    assert_eq!(src_entry.history.len(), 2);
    let src_hist_times: Vec<_> = src_entry
        .history
        .iter()
        .map(|s| s.times.last_modification_time)
        .collect();

    // Open a destination with a DIFFERENT clock, so if import
    // accidentally re-stamps history timestamps, the test sees
    // the drift.
    let (mut dst, _) = open_with_clock(&kdbx4_basic(), t0 + Duration::days(30));
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let dst_entry = find_entry(&dst, imported).unwrap();
    assert_eq!(dst_entry.history.len(), 2);
    let dst_hist_times: Vec<_> = dst_entry
        .history
        .iter()
        .map(|s| s.times.last_modification_time)
        .collect();
    assert_eq!(src_hist_times, dst_hist_times);
    assert_eq!(dst_entry.history[0].password, "v1");
    assert_eq!(dst_entry.history[1].password, "v2");
    assert_eq!(dst_entry.password, "v3");
}

#[test]
fn import_carries_binary_referenced_only_by_history_snapshot() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut src, src_clock) = open_with_clock(&kdbx4_basic(), t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Detach Then Snapshot"))
        .unwrap();
    src_clock.set(t0 + Duration::minutes(1));
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("old.bin", b"OLD".to_vec(), false);
    })
    .unwrap();
    src_clock.set(t0 + Duration::minutes(2));
    // Snapshot captures the attach; detach afterwards — only the
    // snapshot now references the bytes.
    src.edit_entry(src_id, HistoryPolicy::Snapshot, |e| {
        e.detach("old.bin");
    })
    .unwrap();
    let src_entry = find_entry(&src, src_id).unwrap();
    assert!(src_entry.attachments.is_empty());
    assert_eq!(src_entry.history[0].attachments.len(), 1);

    let (mut dst, _) = open_with_clock(&kdbx4_basic(), t0);
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let dst_entry = find_entry(&dst, imported).unwrap();
    assert!(dst_entry.attachments.is_empty());
    assert_eq!(dst_entry.history.len(), 1);
    assert_eq!(dst_entry.history[0].attachments.len(), 1);
    let snap_ref = dst_entry.history[0].attachments[0].ref_id;
    assert_eq!(dst.vault().binaries[snap_ref as usize].data, b"OLD");
}

// ---------------------------------------------------------------------
// Stamping contract
// ---------------------------------------------------------------------

#[test]
fn import_stamps_live_entry_times_from_destination_clock() {
    let t_src: DateTime<Utc> = "2000-01-01T00:00:00Z".parse().unwrap();
    let t_dst: DateTime<Utc> = "2030-06-15T12:34:56Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t_src, t_dst);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Time-travel"))
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let e = find_entry(&dst, imported).unwrap();
    assert_eq!(e.times.creation_time, Some(t_dst));
    assert_eq!(e.times.last_modification_time, Some(t_dst));
    assert_eq!(e.times.last_access_time, Some(t_dst));
    assert_eq!(e.times.location_changed, Some(t_dst));
    // usage_count resets per the MUTATION.md invariant. Source's
    // was 0 anyway; pin the post-import value explicitly.
    assert_eq!(e.times.usage_count, 0);
    // previous_parent_group cleared to match `add_entry`.
    assert_eq!(e.previous_parent_group, None);
}

// ---------------------------------------------------------------------
// `unknown_xml` preservation
// ---------------------------------------------------------------------

#[test]
fn import_preserves_unknown_xml_from_source_entry() {
    // `pykeepass/unknown-xml.kdbx` has a single entry carrying
    // `<FutureEntryHint attr="x">payload</FutureEntryHint>` as an
    // unknown child — the slice-1 fixture. Re-use as the export
    // source; destination is the standard basic fixture.
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (src, _) = open_with_clock(&unknown_xml_fixture(), t0);
    let (mut dst, _) = open_with_clock(&kdbx4_basic(), t0);

    let src_id = src.vault().iter_entries().next().unwrap().id;
    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let e = find_entry(&dst, imported).unwrap();
    let tags: Vec<_> = e.unknown_xml.iter().map(|u| &u.tag).collect();
    assert_eq!(
        tags,
        vec!["FutureEntryHint"],
        "unknown_xml must travel through the export/import carrier"
    );
}

// ---------------------------------------------------------------------
// End-to-end: save destination + reopen
// ---------------------------------------------------------------------

#[test]
fn imported_entry_survives_save_and_reopen_with_binaries_and_icons() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_icon = src.add_custom_icon(b"roundtrip-icon".to_vec());
    let src_id = src
        .add_entry(
            root_group(&src),
            NewEntry::new("Full Shape")
                .username("alice")
                .password(SecretString::from("secret")),
        )
        .unwrap();
    src.edit_entry(src_id, HistoryPolicy::NoSnapshot, |e| {
        e.attach("blob.bin", b"content-bytes".to_vec(), false);
        e.set_custom_icon(Some(src_icon));
    })
    .unwrap();

    let portable = src.export_entry(src_id).unwrap();
    let imported = dst.import_entry(root_group(&dst), portable, true).unwrap();

    let reopened = reopen_with_clock(
        &kdbx4_basic(),
        dst.save_to_bytes().unwrap(),
        t0 + Duration::hours(1),
    );
    let e = find_entry(&reopened, imported).unwrap();
    assert_eq!(e.title, "Full Shape");
    assert_eq!(e.username, "alice");
    assert_eq!(e.password, "secret");
    assert_eq!(e.attachments.len(), 1);
    assert_eq!(e.attachments[0].name, "blob.bin");
    let ref_id = e.attachments[0].ref_id;
    assert_eq!(
        reopened.vault().binaries[ref_id as usize].data,
        b"content-bytes"
    );
    let icon = e.custom_icon_uuid.expect("icon ref survives");
    assert_eq!(
        reopened.custom_icon(icon).map(<[u8]>::to_vec),
        Some(b"roundtrip-icon".to_vec())
    );
}

// ---------------------------------------------------------------------
// import_entry_with_uuid — move-undo identity preservation
// ---------------------------------------------------------------------

#[test]
fn import_entry_with_uuid_preserves_caller_supplied_id() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Round-trip me"))
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();
    let dst_root = root_group(&dst);
    let returned = dst
        .import_entry_with_uuid(dst_root, portable, src_id)
        .unwrap();

    assert_eq!(returned, src_id, "method should return target_uuid");
    assert!(
        find_entry(&dst, src_id).is_some(),
        "destination should hold the entry under target_uuid",
    );
}

#[test]
fn import_entry_with_uuid_clears_matching_tombstone() {
    // Simulate a forward cross-vault move: source has the entry,
    // exports it, destination imports (under a different uuid for
    // this test — the cross-vault path), source deletes leaving a
    // tombstone. Undo brings the entry back under the original uuid.
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Will be moved"))
        .unwrap();
    let forward_portable = src.export_entry(src_id).unwrap();
    let dst_id = dst
        .import_entry(root_group(&dst), forward_portable, /*mint=*/ true)
        .unwrap();
    src.delete_entry(src_id).unwrap();
    assert!(
        src.vault()
            .deleted_objects
            .iter()
            .any(|t| t.uuid == src_id.0),
        "forward move should leave a tombstone on the source",
    );

    // Undo: export from dst, import-with-uuid on src under src_id.
    let undo_portable = dst.export_entry(dst_id).unwrap();
    let restored = src
        .import_entry_with_uuid(root_group(&src), undo_portable, src_id)
        .unwrap();
    assert_eq!(restored, src_id);
    assert!(
        find_entry(&src, src_id).is_some(),
        "source should hold the entry alive under the original uuid",
    );
    assert!(
        !src.vault()
            .deleted_objects
            .iter()
            .any(|t| t.uuid == src_id.0),
        "matching tombstone should have been cleared on import-with-uuid",
    );
}

#[test]
fn import_entry_with_uuid_returns_duplicate_uuid_when_live_collision() {
    // If target_uuid is already live in the destination vault, the
    // method must fail cleanly (and leave the destination untouched).
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, _), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("Exported"))
        .unwrap();

    // Plant a live entry in the destination using the same UUID via
    // a preserve-UUID import of one portable, then try a second
    // import-with-uuid pointing at the same target — that's the
    // collision the method must reject.
    let first_portable = src.export_entry(src_id).unwrap();
    dst.import_entry(root_group(&dst), first_portable, /*mint=*/ false)
        .unwrap();

    let second_portable = src.export_entry(src_id).unwrap();
    let err = dst
        .import_entry_with_uuid(root_group(&dst), second_portable, src_id)
        .unwrap_err();
    match err {
        ModelError::DuplicateUuid(got) => assert_eq!(got, src_id.0),
        other => panic!("expected DuplicateUuid, got {other:?}"),
    }
}

#[test]
fn import_entry_with_uuid_mints_fresh_history_snapshot_ids() {
    // History-snapshot ids should be regenerated even when the live
    // entry's id is caller-supplied.
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let ((mut src, src_clock), (mut dst, _)) = open_basic_pair(t0, t0);

    let src_id = src
        .add_entry(root_group(&src), NewEntry::new("With history"))
        .unwrap();
    // Generate one history snapshot by editing the entry.
    src_clock.set(t0 + Duration::hours(1));
    src.edit_entry(src_id, HistoryPolicy::Snapshot, |e| {
        e.set_title("With history — edited");
    })
    .unwrap();
    let src_snapshot_ids: Vec<_> = find_entry(&src, src_id)
        .unwrap()
        .history
        .iter()
        .map(|s| s.id)
        .collect();
    assert!(!src_snapshot_ids.is_empty(), "test setup: history present");

    let portable = src.export_entry(src_id).unwrap();
    let target_uuid = src_id;
    let restored = dst
        .import_entry_with_uuid(root_group(&dst), portable, target_uuid)
        .unwrap();
    let dst_entry = find_entry(&dst, restored).unwrap();
    let dst_snapshot_ids: Vec<_> = dst_entry.history.iter().map(|s| s.id).collect();

    assert_eq!(
        dst_snapshot_ids.len(),
        src_snapshot_ids.len(),
        "history snapshot count preserved",
    );
    for (src_snap, dst_snap) in src_snapshot_ids.iter().zip(dst_snapshot_ids.iter()) {
        assert_ne!(
            src_snap, dst_snap,
            "history-snapshot ids should be minted fresh, not carried over",
        );
    }
}

// ---------------------------------------------------------------------
// Debug redaction guard
// ---------------------------------------------------------------------

#[test]
fn debug_impl_does_not_leak_plaintext_password() {
    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let (mut src, _) = open_with_clock(&kdbx4_basic(), t0);
    let secret = "plaintext-password-never-in-debug-output";
    let src_id = src
        .add_entry(
            root_group(&src),
            NewEntry::new("Redaction Test").password(SecretString::from(secret)),
        )
        .unwrap();
    let portable = src.export_entry(src_id).unwrap();
    let debug = format!("{portable:?}");
    assert!(
        !debug.contains(secret),
        "Debug impl must redact the entry's plaintext password; got: {debug}"
    );
    assert!(
        debug.contains("[REDACTED]"),
        "Debug impl should mark the password field as redacted; got: {debug}"
    );
}
