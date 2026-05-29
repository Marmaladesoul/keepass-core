//! Cross-pass interaction tests: do the tombstone pre-passes and the
//! structural concurrent-move passes play nicely when they fire on
//! the same entry in the same merge round?
//!
//! Background: the apply pipeline runs structural passes
//! (`apply_group_tree` → group moves → entry moves) BEFORE the
//! tombstone pre-passes (history / tag / attachment). The intuition
//! says this is fine — the tombstone pre-pass walks `local.root` and
//! mutates each entry in place; an entry that was reparented by the
//! move pass earlier in the sequence still lives in `local.root`,
//! just under a different parent. But intuition isn't a test.

use chrono::{TimeZone, Utc};
use keepass_core::model::{
    Attachment, Binary, CustomDataItem, Entry, EntryId, Group, GroupId, Timestamps, Vault,
};
use keepass_merge::{
    ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY, AttachmentTombstone, Resolution,
    TAG_STATE_CUSTOM_DATA_KEY, TagRemoval, TagState, apply_merge, merge,
    parse_attachment_tombstones, parse_tag_state,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn ts(year: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, m, d, 0, 0, 0).unwrap()
}

fn timestamps(mtime: (i32, u32, u32), loc: Option<(i32, u32, u32)>) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(ts(mtime.0, mtime.1, mtime.2));
    if let Some((y, m, d)) = loc {
        t.location_changed = Some(ts(y, m, d));
    }
    t
}

fn empty_group(id_byte: u128, name: &str) -> Group {
    let mut g = Group::empty(GroupId(Uuid::from_u128(id_byte)));
    g.name = name.into();
    g
}

fn build_vault(root_groups: Vec<Group>, binaries: Vec<Binary>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.binaries = binaries;
    v.root.groups = root_groups;
    v
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

#[test]
fn tag_tombstone_survives_concurrent_entry_reparent() {
    // Local: entry-1 under G_A, tag "archive" tombstoned at 2026-03-15.
    // Remote: entry-1 under G_B (concurrent move, newer
    // `location_changed`), still holds "archive" in tags (stale-peer
    // case — remote never saw the tombstone).
    //
    // After merge:
    //   1. Move pass wins for remote → entry is now under G_B.
    //   2. Tag-tombstone pre-pass should still apply, dropping
    //      "archive" from the entry's tags, regardless of the
    //      reparent.
    let entry_id = EntryId(Uuid::from_u128(0x77));

    let mut entry_local = Entry::empty(entry_id);
    entry_local.title = "entry-1".into();
    entry_local.times = timestamps((2026, 3, 1), Some((2026, 3, 1)));
    entry_local.tags = vec!["archive".into(), "keep".into()];
    let mut tag_state = TagState::default();
    tag_state
        .remove
        .insert("archive".to_string(), TagRemoval::new(ts(2026, 3, 15)));
    entry_local.custom_data.push(CustomDataItem::new(
        TAG_STATE_CUSTOM_DATA_KEY.to_string(),
        serde_json::to_string(&tag_state).unwrap(),
        None,
    ));
    let mut g_a_local = empty_group(0x10, "A");
    g_a_local.entries.push(entry_local);
    let g_b_local = empty_group(0x20, "B");
    let mut local = build_vault(vec![g_a_local, g_b_local], vec![]);

    // Remote: entry-1 under G_B (newer location_changed), still has
    // "archive" in tags, no tombstone state.
    let mut entry_remote = Entry::empty(entry_id);
    entry_remote.title = "entry-1".into();
    entry_remote.times = timestamps((2026, 3, 1), Some((2026, 4, 1)));
    entry_remote.tags = vec!["archive".into(), "keep".into()];
    let g_a_remote = empty_group(0x10, "A");
    let mut g_b_remote = empty_group(0x20, "B");
    g_b_remote.entries.push(entry_remote);
    let remote = build_vault(vec![g_a_remote, g_b_remote], vec![]);

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    // Structural: entry now under G_B.
    let g_a = local.root.groups.iter().find(|g| g.name == "A").unwrap();
    assert!(
        g_a.entries.iter().all(|e| e.id != entry_id),
        "post-merge: G_A must no longer hold the moved entry"
    );
    let g_b = local.root.groups.iter().find(|g| g.name == "B").unwrap();
    let moved = g_b
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry now lives under G_B");

    // Tombstone applied: "archive" dropped from tags.
    assert!(
        !moved.tags.iter().any(|t| t == "archive"),
        "tag-state tombstone must propagate to the moved entry's tags (got {:?})",
        moved.tags
    );
    assert!(
        moved.tags.iter().any(|t| t == "keep"),
        "non-tombstoned tag must survive the move"
    );
    // Tombstone state persisted onto the moved entry for future syncs.
    let merged_state = parse_tag_state(&moved.custom_data).expect("parse");
    assert!(merged_state.remove.contains_key("archive"));
}

#[test]
fn attachment_tombstone_survives_concurrent_entry_reparent() {
    // Same shape as the tag test but for `keys.attachment_tombstones.v1`.
    // Local: entry-1 under G_A, holds "scan.pdf" with tombstone for
    //   its (filename, hash).
    // Remote: entry-1 under G_B (newer location_changed), also holds
    //   "scan.pdf" with the same bytes (so it survives the
    //   attachment-classifier check as a no-op), no tombstone.
    // After merge: entry now under G_B, "scan.pdf" dropped, tombstone
    //   persisted.
    let entry_id = EntryId(Uuid::from_u128(0x77));
    let bytes = b"the-bytes".to_vec();
    let hash = sha256(&bytes);

    let mut entry_local = Entry::empty(entry_id);
    entry_local.title = "entry-1".into();
    entry_local.times = timestamps((2026, 3, 1), Some((2026, 3, 1)));
    entry_local.attachments.push(Attachment::new("scan.pdf", 0));
    let tombstones = vec![AttachmentTombstone::new("scan.pdf", hash, ts(2026, 3, 15))];
    entry_local.custom_data.push(CustomDataItem::new(
        ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
        serde_json::to_string(&tombstones).unwrap(),
        None,
    ));
    let mut g_a_local = empty_group(0x10, "A");
    g_a_local.entries.push(entry_local);
    let g_b_local = empty_group(0x20, "B");
    let mut local = build_vault(
        vec![g_a_local, g_b_local],
        vec![Binary::new(bytes.clone(), false)],
    );

    let mut entry_remote = Entry::empty(entry_id);
    entry_remote.title = "entry-1".into();
    entry_remote.times = timestamps((2026, 3, 1), Some((2026, 4, 1)));
    entry_remote
        .attachments
        .push(Attachment::new("scan.pdf", 0));
    let g_a_remote = empty_group(0x10, "A");
    let mut g_b_remote = empty_group(0x20, "B");
    g_b_remote.entries.push(entry_remote);
    let remote = build_vault(
        vec![g_a_remote, g_b_remote],
        vec![Binary::new(bytes, false)],
    );

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    let g_b = local.root.groups.iter().find(|g| g.name == "B").unwrap();
    let moved = g_b
        .entries
        .iter()
        .find(|e| e.id == entry_id)
        .expect("entry now under G_B");
    assert!(
        moved.attachments.is_empty(),
        "attachment tombstone must propagate to the moved entry (got {:?})",
        moved
            .attachments
            .iter()
            .map(|a| &a.name)
            .collect::<Vec<_>>()
    );
    let merged_ts = parse_attachment_tombstones(&moved.custom_data).expect("parse");
    assert!(
        merged_ts.iter().any(|t| t.filename == "scan.pdf"),
        "attachment tombstone state must persist for future syncs"
    );
}
