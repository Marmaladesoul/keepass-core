//! End-to-end tests for icon auto-resolution routing + apply (PR I2).
//!
//! Pre-fix, icon-only divergences were silently omitted (no bucket
//! routing — `auto_resolutions` empty, `attachment_auto_resolutions`
//! empty, no tag work). Post-fix, when the classifier has a clear
//! LCA-driven winner for `custom_icon_uuid`, the entry routes through
//! `disk_only_changes` / `local_only_changes` and `build_merged_entry`
//! overlays the chosen side's UUID on the bucket-winner clone.

use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
use uuid::Uuid;

fn at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time =
        Some(chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, year, month, day, 0, 0, 0).unwrap());
    t
}

fn entry(id: u128, ts: Timestamps) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.times = ts;
    e
}

fn vault(entries: Vec<Entry>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = entries;
    v
}

fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap_or_else(|| panic!("entry {id} not found"))
}

#[test]
fn remote_edited_icon_routes_to_disk_only_changes_and_takes_remote_uuid() {
    // Ancestor: icon=1. Local: icon=1 (unchanged). Remote: icon=2.
    // Pre-fix: icon-only divergences were silently omitted (no bucket
    // routing) → merged carried local's icon=1 → remote's icon edit
    // was lost. Post-fix: routes to disk_only_changes and apply
    // overlays remote's UUID.
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);

    let mut ancestor = entry(1, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(1, at(2026, 1, 1));
    local.custom_icon_uuid = Some(icon1);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(1, at(2026, 1, 2));
    remote.custom_icon_uuid = Some(icon2);
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    assert_eq!(
        outcome.disk_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "remote-side icon edit routes to disk_only_changes",
    );
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 1);
    assert_eq!(
        merged.custom_icon_uuid,
        Some(icon2),
        "remote's icon edit kept",
    );
}

#[test]
fn local_edited_icon_routes_to_local_only_changes_and_keeps_local_uuid() {
    // Symmetric: local edited icon, remote unchanged. Routes through
    // local_only_changes (so history-merge still runs); merged keeps
    // local's icon.
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);

    let mut ancestor = entry(2, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(2, at(2026, 1, 2));
    local.custom_icon_uuid = Some(icon2);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(2, at(2026, 1, 1));
    remote.custom_icon_uuid = Some(icon1);
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    assert_eq!(
        outcome.local_only_changes,
        vec![EntryId(Uuid::from_u128(2))],
        "local-side icon edit routes to local_only_changes",
    );
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 2);
    assert_eq!(merged.custom_icon_uuid, Some(icon2), "local's icon kept");
}

#[test]
fn mixed_side_field_remote_and_icon_local_preserves_both() {
    // Local edited Title (auto=Local), remote edited custom_icon_uuid
    // (auto=Remote). Bucket: disk_only_changes (any_remote_wins=true).
    // After the slice-9 mixed-side fix (PR #140) Title is overlaid;
    // this PR ensures icon is overlaid too on the auto-resolution
    // path. Pre-I2 the icon wouldn't have been classified at all and
    // would have been silently auto-merged via the entry-level clone.
    let icon1 = Uuid::from_u128(0x10);
    let icon2 = Uuid::from_u128(0x20);

    let mut ancestor = entry(3, at(2026, 1, 1));
    ancestor.title = "A".into();
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(3, at(2026, 1, 2));
    local.title = "L".into();
    local.custom_icon_uuid = Some(icon1);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(3, at(2026, 1, 3));
    remote.title = "A".into();
    remote.custom_icon_uuid = Some(icon2);
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 3);
    assert_eq!(merged.title, "L", "local's Title edit kept");
    assert_eq!(
        merged.custom_icon_uuid,
        Some(icon2),
        "remote's icon edit kept",
    );
}

#[test]
fn icon_only_conflict_still_omitted_until_pr_i3() {
    // Both sides diverge from LCA on icon — classifier produces
    // icon_conflict, no auto_resolution. PR I3 will route this to
    // entry_conflicts; for now (I2) it stays omitted, matching the
    // pre-existing posture. This test pins that contract so I3's
    // change is loud and intentional.
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);
    let icon3 = Uuid::from_u128(0x03);

    let mut ancestor = entry(4, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(4, at(2026, 1, 2));
    local.custom_icon_uuid = Some(icon2);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(4, at(2026, 1, 3));
    remote.custom_icon_uuid = Some(icon3);
    remote.history = vec![ancestor];

    let outcome = merge(&vault(vec![local]), &vault(vec![remote])).expect("merge");
    assert!(outcome.disk_only_changes.is_empty());
    assert!(outcome.local_only_changes.is_empty());
    assert!(outcome.entry_conflicts.is_empty());
}
