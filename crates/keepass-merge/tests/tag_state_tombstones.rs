//! Integration tests for the tag remove-tombstone mechanism
//! (`keys.tag_state.v1`).
//!
//! Mirrors `history_tombstones.rs` in shape: build two-sided
//! scenarios that exercise the public `merge` + `apply_merge`
//! round-trip and verify the tombstone-driven outcome.
//!
//! Spec: sync-merge-strategies.md §4 (target spec, in the Keys
//! `_project-management` tree).

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomDataItem, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    Resolution, TAG_STATE_CUSTOM_DATA_KEY, TagRemoval, TagState, apply_merge, merge,
    parse_tag_state,
};
use uuid::Uuid;

fn ts(year: i32, month: u32, day: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
}

fn timestamps_at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(ts(year, month, day));
    t
}

fn entry_with_tags(id_byte: u8, mtime: (i32, u32, u32), tags: &[&str]) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(u128::from(id_byte))));
    e.title = format!("entry-{id_byte}");
    e.times = timestamps_at(mtime.0, mtime.1, mtime.2);
    e.tags = tags.iter().map(|s| (*s).to_string()).collect();
    e
}

fn vault_with(entry: Entry) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries.push(entry);
    v
}

fn write_tag_state(entry: &mut Entry, state: &TagState) {
    let json = serde_json::to_string(state).expect("TagState serializes");
    entry.custom_data.push(CustomDataItem::new(
        TAG_STATE_CUSTOM_DATA_KEY.to_string(),
        json,
        None,
    ));
}

fn rm_at(at: chrono::DateTime<Utc>) -> TagRemoval {
    TagRemoval::new(at)
}

// ---------------------------------------------------------------------------

#[test]
fn tag_tombstone_on_one_side_drops_tag_on_the_other() {
    // Local was edited 2026-03-01 with tag "archive" present.
    // Remote was edited 2026-04-01 having tombstoned "archive" at
    // 2026-03-15. Tombstone wins → merged entry has no "archive".
    let local = entry_with_tags(1, (2026, 3, 1), &["archive", "keep"]);
    let mut remote = entry_with_tags(1, (2026, 4, 1), &["keep"]);
    let mut state = TagState::default();
    state
        .remove
        .insert("archive".to_string(), rm_at(ts(2026, 3, 15)));
    write_tag_state(&mut remote, &state);

    let mut local_vault = vault_with(local);
    let remote_vault = vault_with(remote);
    let outcome = merge(&local_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut local_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = &local_vault.root.entries[0];
    assert!(
        !merged.tags.iter().any(|t| t == "archive"),
        "tombstoned tag must be dropped from merged entry"
    );
    assert!(merged.tags.iter().any(|t| t == "keep"));
    // Tombstone propagated to local for future sync rounds.
    let merged_state = parse_tag_state(&merged.custom_data).expect("parse");
    assert!(merged_state.remove.contains_key("archive"));
}

#[test]
fn re_add_after_tombstone_wins_when_holding_side_mtime_is_newer() {
    // Local re-added "archive" with a fresh mtime (2026-05-01) AFTER
    // the tombstone's `at` (2026-03-15). Spec §4: re-adding wins.
    let local = entry_with_tags(1, (2026, 5, 1), &["archive"]);
    let mut remote = entry_with_tags(1, (2026, 4, 1), &[]);
    let mut state = TagState::default();
    state
        .remove
        .insert("archive".to_string(), rm_at(ts(2026, 3, 15)));
    write_tag_state(&mut remote, &state);

    let mut local_vault = vault_with(local);
    let remote_vault = vault_with(remote);
    let outcome = merge(&local_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut local_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = &local_vault.root.entries[0];
    assert!(
        merged.tags.iter().any(|t| t == "archive"),
        "re-added tag with mtime newer than tombstone must survive"
    );
}

#[test]
fn tombstones_union_across_both_sides() {
    // Local tombstoned "old", remote tombstoned "archive". After
    // merge both must appear in the unioned state on local.
    let mut local = entry_with_tags(1, (2026, 4, 1), &[]);
    let mut remote = entry_with_tags(1, (2026, 4, 1), &[]);
    let mut a = TagState::default();
    a.remove.insert("old".to_string(), rm_at(ts(2026, 2, 1)));
    let mut b = TagState::default();
    b.remove
        .insert("archive".to_string(), rm_at(ts(2026, 3, 1)));
    write_tag_state(&mut local, &a);
    write_tag_state(&mut remote, &b);

    let mut local_vault = vault_with(local);
    let remote_vault = vault_with(remote);
    let outcome = merge(&local_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut local_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged_state = parse_tag_state(&local_vault.root.entries[0].custom_data).expect("parse");
    assert!(merged_state.remove.contains_key("old"));
    assert!(merged_state.remove.contains_key("archive"));
}

#[test]
fn tag_state_propagates_even_when_entry_routes_to_no_bucket() {
    // Both sides identical except for tag-state: local has no
    // tombstone, remote tombstoned "archive". Neither side currently
    // carries "archive" in `tags`, so the entry classifier sees no
    // difference and the entry routes to no bucket. The pre-pass
    // (`union_tag_states_across_entries`) must still carry the
    // tombstone over.
    let local = entry_with_tags(1, (2026, 4, 1), &["keep"]);
    let mut remote = entry_with_tags(1, (2026, 4, 1), &["keep"]);
    let mut state = TagState::default();
    state
        .remove
        .insert("archive".to_string(), rm_at(ts(2026, 3, 15)));
    write_tag_state(&mut remote, &state);

    let mut local_vault = vault_with(local);
    let remote_vault = vault_with(remote);
    let outcome = merge(&local_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut local_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged_state = parse_tag_state(&local_vault.root.entries[0].custom_data).expect("parse");
    assert!(
        merged_state.remove.contains_key("archive"),
        "tag-state must propagate via the pre-pass even when the entry routes to no bucket"
    );
}

#[test]
fn tombstone_does_not_drop_tag_when_no_concrete_holding_mtime() {
    // Edge case: local holds `archive` but `last_modification_time`
    // is None. Per the spec proxy, an unknown add-time can't beat the
    // tombstone's concrete `at` — drop conservatively.
    let mut local = Entry::empty(EntryId(Uuid::from_u128(1)));
    local.title = "entry-1".into();
    local.tags = vec!["archive".into()];
    // local.times stays default (all None) — the point of the test.
    let mut remote = entry_with_tags(1, (2026, 4, 1), &[]);
    remote.title = "entry-1".into();
    let mut state = TagState::default();
    state
        .remove
        .insert("archive".to_string(), rm_at(ts(2026, 3, 15)));
    write_tag_state(&mut remote, &state);

    let mut local_vault = vault_with(local);
    let remote_vault = vault_with(remote);
    let outcome = merge(&local_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut local_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = &local_vault.root.entries[0];
    assert!(
        !merged.tags.iter().any(|t| t == "archive"),
        "concrete tombstone wins over unknown add-time"
    );
}
