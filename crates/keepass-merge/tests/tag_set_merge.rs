//! End-to-end tests for tag set-merge (slice B6).
//!
//! Tags merge as a pure set — no public conflict surface; every cell
//! of the 3-way truth table auto-resolves. See
//! `_localdocs/MERGE_TAGS_DESIGN.md` for the full table and rationale.

use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
use std::collections::BTreeSet;
use uuid::Uuid;

fn at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time =
        Some(chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, year, month, day, 0, 0, 0).unwrap());
    t
}

fn entry(id: u128, title: &str, ts: Timestamps) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.title = title.into();
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
        .unwrap()
}

fn tag_set(e: &Entry) -> BTreeSet<&str> {
    e.tags.iter().map(String::as_str).collect()
}

// ---------------------------------------------------------------------
// Auto-resolution truth-table coverage
// ---------------------------------------------------------------------

#[test]
fn both_add_disjoint_tags_unions() {
    // No-LCA fallback: ancestor unknown, both sides have tags →
    // union. Local has {work}, remote has {important} → merged has
    // both.
    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.tags = vec!["work".into()];
    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.tags = vec!["important".into()];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["important", "work"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
        "union of both sides when no LCA is known",
    );
}

#[test]
fn local_added_tag_with_lca_keeps_it() {
    // Ancestor: {work}. Local: {work, important}. Remote: {work}.
    // Local added "important" — kept.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into()];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["work".into(), "important".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.tags = vec!["work".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["important", "work"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
    );
}

#[test]
fn remote_added_tag_with_lca_keeps_it() {
    // Symmetric: remote added the tag; merge keeps it.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into()];

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.tags = vec!["work".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["work".into(), "urgent".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(
        outcome.disk_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "remote's tag addition routes to disk_only_changes",
    );

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["urgent", "work"].into_iter().collect::<BTreeSet<&str>>(),
    );
}

#[test]
fn remote_deleted_tag_with_lca_honours_deletion() {
    // Ancestor: {work, stale}. Local: {work, stale} unchanged.
    // Remote: {work} — dropped "stale". Honour deletion.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into(), "stale".into()];

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.tags = vec!["work".into(), "stale".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["work".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["work"].into_iter().collect::<BTreeSet<&str>>()
    );
}

#[test]
fn local_deleted_tag_with_lca_honours_deletion() {
    // Symmetric: local dropped the tag; merge respects local's
    // deletion.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into(), "stale".into()];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["work".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.tags = vec!["work".into(), "stale".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["work"].into_iter().collect::<BTreeSet<&str>>()
    );
}

#[test]
fn both_added_same_tag_keeps_one() {
    // Ancestor: {}. Local: {urgent}. Remote: {urgent}. Both added
    // the same tag concurrently — set merge keeps one copy.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec![];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["urgent".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["urgent".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["urgent"].into_iter().collect::<BTreeSet<&str>>(),
    );
}

#[test]
fn both_added_different_tags_keeps_union() {
    // Ancestor: {work}. Local: {work, important}. Remote:
    // {work, urgent}. Both added different tags — set merge keeps
    // both additions, no conflict.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into()];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["work".into(), "important".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["work".into(), "urgent".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    // The entry has no field/attachment conflicts — only tags
    // differ. It must NOT land in entry_conflicts.
    assert!(
        outcome.entry_conflicts.is_empty(),
        "tag-only divergence must never produce a public conflict",
    );

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["important", "urgent", "work"]
            .into_iter()
            .collect::<BTreeSet<&str>>(),
    );
}

#[test]
fn both_deleted_same_tag_drops_it() {
    // Ancestor: {work, stale}. Both sides dropped "stale".
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into(), "stale".into()];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["work".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["work".into()];
    remote_e.history = vec![ancestor];

    let local = vault(vec![local_e]);
    let remote = vault(vec![remote_e]);
    let outcome = merge(&local, &remote).unwrap();

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        tag_set(&e),
        ["work"].into_iter().collect::<BTreeSet<&str>>()
    );
}

// ---------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------

#[test]
fn tag_only_remote_addition_routes_to_disk_only_changes() {
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into()];

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.tags = vec!["work".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["work".into(), "new".into()];
    remote_e.history = vec![ancestor];

    let outcome = merge(&vault(vec![local_e]), &vault(vec![remote_e])).unwrap();
    assert_eq!(
        outcome.disk_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "tag added remotely → local needs work → disk_only_changes",
    );
}

#[test]
fn tag_only_local_addition_routes_to_local_only_changes() {
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec!["work".into()];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["work".into(), "new".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.tags = vec!["work".into()];
    remote_e.history = vec![ancestor];

    let outcome = merge(&vault(vec![local_e]), &vault(vec![remote_e])).unwrap();
    assert_eq!(
        outcome.local_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "tag added locally → remote is stale → local_only_changes",
    );
}

#[test]
fn identical_tags_still_omitted() {
    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.tags = vec!["work".into(), "important".into()];
    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.tags = vec!["work".into(), "important".into()];

    let outcome = merge(&vault(vec![local_e]), &vault(vec![remote_e])).unwrap();
    assert!(outcome.disk_only_changes.is_empty());
    assert!(outcome.local_only_changes.is_empty());
    assert!(outcome.entry_conflicts.is_empty());
}

#[test]
fn tag_only_divergence_never_surfaces_as_conflict() {
    // Even when both sides diverge maximally on tags (different
    // additions, ancestor empty), the merge must NOT produce an
    // entry_conflicts entry. Tags are a pure auto-merge surface.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.tags = vec![];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.tags = vec!["L-only".into()];
    local_e.history = vec![ancestor.clone()];

    let mut remote_e = entry(1, "shared", at(2026, 2, 1));
    remote_e.tags = vec!["R-only".into()];
    remote_e.history = vec![ancestor];

    let outcome = merge(&vault(vec![local_e]), &vault(vec![remote_e])).unwrap();
    assert!(
        outcome.entry_conflicts.is_empty(),
        "tags must never produce a public conflict",
    );
}
