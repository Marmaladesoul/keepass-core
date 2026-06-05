//! Integration coverage for the vault-meta merge introduced in
//! PR-3.2d. Exercises the public `merge` / `apply_merge` pair so the
//! spec §2.1 rules are observable end-to-end.

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomDataItem, CustomIcon, GroupId, Vault};
use keepass_merge::{
    CONFLICT_RESOLUTION_CUSTOM_DATA_KEY, Resolution, apply_merge, merge, parse_conflict_resolutions,
};
use uuid::Uuid;

fn at(y: i32, m: u32, d: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
}

fn fresh_vault() -> Vault {
    Vault::empty(GroupId(Uuid::nil()))
}

#[test]
fn meta_merge_runs_via_apply_merge_for_disjoint_changes() {
    // Local picked a name on 2026-04-01; remote later picked a
    // description on 2026-05-01. Both changes must survive on local
    // after apply.
    let mut local = fresh_vault();
    local.meta.database_name = "Family".into();
    local.meta.database_name_changed = Some(at(2026, 4, 1));

    let mut remote = fresh_vault();
    remote.meta.database_description = "Shared vault".into();
    remote.meta.database_description_changed = Some(at(2026, 5, 1));

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    assert_eq!(local.meta.database_name, "Family");
    assert_eq!(local.meta.database_description, "Shared vault");
}

#[test]
fn conflict_resolutions_set_union_across_merge() {
    // Two peers each resolved a *different* conflict. Unlike ordinary
    // Meta custom_data (per-key LWW), the conflict-resolution list is a
    // CRDT set — both decisions must survive the merge, not clobber each
    // other. Records are written as raw JSON (the struct is
    // `#[non_exhaustive]`, so the test crate can't build it directly).
    let entry_a = Uuid::from_u128(0xa1).to_string();
    let entry_b = Uuid::from_u128(0xb2).to_string();

    let mut local = fresh_vault();
    local.meta.custom_data.push(CustomDataItem::new(
        CONFLICT_RESOLUTION_CUSTOM_DATA_KEY.to_string(),
        format!(
            r#"[{{"entry":"{entry_a}","kind":"field","key":"Password","resolved_at":"2026-06-01T00:00:00Z"}}]"#
        ),
        None,
    ));

    let mut remote = fresh_vault();
    remote.meta.custom_data.push(CustomDataItem::new(
        CONFLICT_RESOLUTION_CUSTOM_DATA_KEY.to_string(),
        format!(r#"[{{"entry":"{entry_b}","kind":"icon","resolved_at":"2026-06-02T00:00:00Z"}}]"#),
        None,
    ));

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    let resolutions = parse_conflict_resolutions(&local.meta.custom_data).expect("parse");
    assert_eq!(
        resolutions.len(),
        2,
        "both peers' independent resolutions survive the union: {resolutions:?}"
    );
    assert!(resolutions.iter().any(|r| r.entry.to_string() == entry_a));
    assert!(resolutions.iter().any(|r| r.entry.to_string() == entry_b));
}

#[test]
fn meta_merge_prefers_shorter_history_retention() {
    let mut local = fresh_vault();
    local.meta.history_max_items = 7;
    let mut remote = fresh_vault();
    remote.meta.history_max_items = 30;

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");
    assert_eq!(local.meta.history_max_items, 7);
}

#[test]
fn meta_merge_unions_custom_icon_pool_via_apply_merge() {
    let mut local = fresh_vault();
    local.meta.custom_icons.push(CustomIcon::new(
        Uuid::from_u128(1),
        b"A".to_vec(),
        "A".into(),
        None,
    ));
    let mut remote = fresh_vault();
    remote.meta.custom_icons.push(CustomIcon::new(
        Uuid::from_u128(2),
        b"B".to_vec(),
        "B".into(),
        None,
    ));

    let outcome = merge(&local, &remote).expect("merge");
    apply_merge(&mut local, &remote, &outcome, &Resolution::default()).expect("apply");

    let uuids: std::collections::HashSet<Uuid> =
        local.meta.custom_icons.iter().map(|i| i.uuid).collect();
    assert!(uuids.contains(&Uuid::from_u128(1)));
    assert!(uuids.contains(&Uuid::from_u128(2)));
}
