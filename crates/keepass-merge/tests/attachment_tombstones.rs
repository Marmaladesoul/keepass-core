//! Integration tests for the attachment detach-tombstone mechanism
//! (`keys.attachment_tombstones.v1`).
//!
//! Spec: sync-merge-strategies.md §4 + history-tombstones.md.

use chrono::{TimeZone, Utc};
use keepass_core::model::{
    Attachment, Binary, CustomDataItem, Entry, EntryId, GroupId, Timestamps, Vault,
};
use keepass_merge::{
    ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY, AttachmentTombstone, Resolution, apply_merge, merge,
    parse_attachment_tombstones,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn timestamps_at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(ts(year, month, day));
    t
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn entry_with(id_byte: u8, mtime: (i32, u32, u32)) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(u128::from(id_byte))));
    e.title = format!("entry-{id_byte}");
    e.times = timestamps_at(mtime.0, mtime.1, mtime.2);
    e
}

fn vault_with(entry: Entry, binaries: Vec<Binary>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.binaries = binaries;
    v.root.entries.push(entry);
    v
}

fn write_attachment_tombstones(entry: &mut Entry, list: &[AttachmentTombstone]) {
    let json = serde_json::to_string(list).expect("serialize");
    entry.custom_data.push(CustomDataItem::new(
        ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
        json,
        None,
    ));
}

// ---------------------------------------------------------------------------

#[test]
fn attachment_tombstone_drops_payload_both_sides_still_hold() {
    // Both sides hold "scan.pdf" with the same content (no
    // attachment-classifier disagreement, so the entry routes
    // through the no-bucket pre-pass), but local has a tombstone
    // covering the (filename, hash). The pre-pass must drop the
    // attachment from local and persist the tombstone.
    let bytes = b"hello-pdf".to_vec();
    let hash = sha256_of(&bytes);

    let mut local_entry = entry_with(1, (2026, 4, 1));
    local_entry.attachments.push(Attachment::new("scan.pdf", 0));
    let mut local = vault_with(local_entry, vec![Binary::new(bytes.clone(), false)]);
    write_attachment_tombstones(
        &mut local.root.entries[0],
        &[AttachmentTombstone::new("scan.pdf", hash, ts(2026, 5, 15))],
    );

    let mut remote_entry = entry_with(1, (2026, 4, 1));
    remote_entry
        .attachments
        .push(Attachment::new("scan.pdf", 0));
    let remote = vault_with(remote_entry, vec![Binary::new(bytes, false)]);

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    assert!(
        local.root.entries[0].attachments.is_empty(),
        "tombstoned (filename, hash) must drop the attachment even when both sides hold it"
    );
    let merged_ts = parse_attachment_tombstones(&local.root.entries[0].custom_data).expect("parse");
    assert_eq!(merged_ts.len(), 1);
}

#[test]
fn reattach_with_newer_mtime_beats_tombstone() {
    // Local re-attached at a fresh mtime newer than the tombstone's
    // `at` — the spec §4 escape hatch: a deliberate re-attach wins.
    // Remote also holds it to avoid an attachment-classifier conflict.
    let bytes = b"hello-pdf".to_vec();
    let hash = sha256_of(&bytes);

    let mut local_entry = entry_with(1, (2026, 5, 1));
    local_entry.attachments.push(Attachment::new("scan.pdf", 0));
    let mut local = vault_with(local_entry, vec![Binary::new(bytes.clone(), false)]);
    write_attachment_tombstones(
        &mut local.root.entries[0],
        &[AttachmentTombstone::new("scan.pdf", hash, ts(2026, 3, 15))],
    );

    let mut remote_entry = entry_with(1, (2026, 5, 1));
    remote_entry
        .attachments
        .push(Attachment::new("scan.pdf", 0));
    let remote = vault_with(remote_entry, vec![Binary::new(bytes, false)]);

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    assert!(
        local.root.entries[0]
            .attachments
            .iter()
            .any(|a| a.name == "scan.pdf"),
        "re-attached payload with newer mtime must survive"
    );
}

#[test]
fn tombstone_does_not_block_reattach_of_different_content_under_same_name() {
    // Local holds "scan.pdf" with NEW bytes (different hash from the
    // tombstoned version). The tombstone is for the OLD bytes; the
    // new attachment must survive.
    let new_bytes = b"new".to_vec();
    let old_hash = [0xaau8; 32];

    let mut local_entry = entry_with(1, (2026, 5, 1));
    local_entry.attachments.push(Attachment::new("scan.pdf", 0));
    let mut local = vault_with(local_entry, vec![Binary::new(new_bytes.clone(), false)]);
    write_attachment_tombstones(
        &mut local.root.entries[0],
        &[AttachmentTombstone::new(
            "scan.pdf",
            old_hash,
            ts(2026, 3, 15),
        )],
    );

    let mut remote_entry = entry_with(1, (2026, 5, 1));
    remote_entry
        .attachments
        .push(Attachment::new("scan.pdf", 0));
    let remote = vault_with(remote_entry, vec![Binary::new(new_bytes, false)]);

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    assert_eq!(
        local.root.entries[0].attachments.len(),
        1,
        "different-content reattach must not be blocked by a (filename, old-hash) tombstone"
    );
}

#[test]
fn attachment_tombstones_union_across_both_sides() {
    let hash_a = [0x11u8; 32];
    let hash_b = [0x22u8; 32];

    let mut local = vault_with(entry_with(1, (2026, 4, 1)), vec![]);
    write_attachment_tombstones(
        &mut local.root.entries[0],
        &[AttachmentTombstone::new("a.pdf", hash_a, ts(2026, 2, 1))],
    );
    let mut remote = vault_with(entry_with(1, (2026, 4, 1)), vec![]);
    write_attachment_tombstones(
        &mut remote.root.entries[0],
        &[AttachmentTombstone::new("b.pdf", hash_b, ts(2026, 3, 1))],
    );

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    let merged = parse_attachment_tombstones(&local.root.entries[0].custom_data).expect("parse");
    let names: std::collections::HashSet<&str> =
        merged.iter().map(|t| t.filename.as_str()).collect();
    assert!(names.contains("a.pdf"));
    assert!(names.contains("b.pdf"));
}

#[test]
fn attachment_tombstones_propagate_through_no_bucket_path() {
    // Both sides identical, no attachments anywhere — but remote has
    // tombstone state. The pre-pass must carry it to local.
    let hash = [0x33u8; 32];

    let local = vault_with(entry_with(1, (2026, 4, 1)), vec![]);
    let mut remote = vault_with(entry_with(1, (2026, 4, 1)), vec![]);
    write_attachment_tombstones(
        &mut remote.root.entries[0],
        &[AttachmentTombstone::new("scan.pdf", hash, ts(2026, 3, 15))],
    );

    let mut local_mut = local;
    let outcome = merge(&local_mut, &remote).expect("merge");
    apply_merge(&mut local_mut, &remote, &outcome, &Resolution::default()).expect("apply");

    let merged =
        parse_attachment_tombstones(&local_mut.root.entries[0].custom_data).expect("parse");
    assert!(merged.iter().any(|t| t.filename == "scan.pdf"));
}
