//! End-to-end tests for icon conflict resolution (PR I3).
//!
//! Icon-only conflicts (LCA missing, or both sides diverge from LCA)
//! now route through `entry_conflicts` with a populated `icon_delta`.
//! Callers resolve via `Resolution::entry_icon_choices`.

use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{ConflictSide, Resolution, apply_merge, merge};
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
fn icon_only_conflict_routes_to_entry_conflicts_with_icon_delta() {
    // Ancestor: icon=1. Local moved to icon=2. Remote moved to icon=3.
    // Both sides diverge from LCA → classifier can't auto-resolve → conflict.
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);
    let icon3 = Uuid::from_u128(0x03);

    let mut ancestor = entry(1, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(1, at(2026, 1, 2));
    local.custom_icon_uuid = Some(icon2);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(1, at(2026, 1, 3));
    remote.custom_icon_uuid = Some(icon3);
    remote.history = vec![ancestor];

    let outcome = merge(&vault(vec![local]), &vault(vec![remote])).expect("merge");
    assert_eq!(
        outcome.entry_conflicts.len(),
        1,
        "icon-only conflict routes to entry_conflicts",
    );
    let conflict = &outcome.entry_conflicts[0];
    let delta = conflict.icon_delta.as_ref().expect("icon_delta populated");
    assert_eq!(delta.local_custom_icon_uuid, Some(icon2));
    assert_eq!(delta.remote_custom_icon_uuid, Some(icon3));
    assert!(conflict.field_deltas.is_empty());
    assert!(conflict.attachment_deltas.is_empty());
}

#[test]
fn icon_conflict_resolution_with_local_choice_keeps_local() {
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);
    let icon3 = Uuid::from_u128(0x03);

    let mut ancestor = entry(2, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(2, at(2026, 1, 2));
    local.custom_icon_uuid = Some(icon2);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(2, at(2026, 1, 3));
    remote.custom_icon_uuid = Some(icon3);
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");

    let mut resolution = Resolution::default();
    resolution
        .entry_icon_choices
        .insert(EntryId(Uuid::from_u128(2)), ConflictSide::Local);
    apply_merge(&mut merged_vault, &remote_vault, &outcome, &resolution).expect("apply");

    let merged = find(&merged_vault, 2);
    assert_eq!(merged.custom_icon_uuid, Some(icon2), "local icon kept");
}

#[test]
fn icon_conflict_resolution_with_remote_choice_takes_remote() {
    let icon1 = Uuid::from_u128(0x01);
    let icon2 = Uuid::from_u128(0x02);
    let icon3 = Uuid::from_u128(0x03);

    let mut ancestor = entry(3, at(2026, 1, 1));
    ancestor.custom_icon_uuid = Some(icon1);

    let mut local = entry(3, at(2026, 1, 2));
    local.custom_icon_uuid = Some(icon2);
    local.history = vec![ancestor.clone()];

    let mut remote = entry(3, at(2026, 1, 3));
    remote.custom_icon_uuid = Some(icon3);
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");

    let mut resolution = Resolution::default();
    resolution
        .entry_icon_choices
        .insert(EntryId(Uuid::from_u128(3)), ConflictSide::Remote);
    apply_merge(&mut merged_vault, &remote_vault, &outcome, &resolution).expect("apply");

    let merged = find(&merged_vault, 3);
    assert_eq!(merged.custom_icon_uuid, Some(icon3), "remote icon kept");
}

#[test]
fn icon_conflict_missing_resolution_returns_error() {
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

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");

    let result = apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    );
    assert!(
        result.is_err(),
        "missing icon resolution must error out, not silently default",
    );
}

#[test]
fn one_sided_custom_icon_no_lca_is_conflict_with_icon_delta() {
    // No LCA, one side has a custom icon, the other doesn't → conflict.
    // Verifies the spec rule that "one side has, other doesn't" is
    // conflict-eligible when no LCA can decide.
    let icon1 = Uuid::from_u128(0x01);

    let mut local = entry(5, at(2026, 1, 1));
    local.custom_icon_uuid = Some(icon1);
    let remote = entry(5, at(2026, 1, 1));

    let outcome = merge(&vault(vec![local]), &vault(vec![remote])).expect("merge");
    assert_eq!(outcome.entry_conflicts.len(), 1);
    let delta = outcome.entry_conflicts[0]
        .icon_delta
        .as_ref()
        .expect("icon_delta populated");
    assert_eq!(delta.local_custom_icon_uuid, Some(icon1));
    assert_eq!(delta.remote_custom_icon_uuid, None);
}
