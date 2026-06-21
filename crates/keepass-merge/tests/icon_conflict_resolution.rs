//! End-to-end tests for icon conflict resolution (PR I3).
//!
//! Icon-only conflicts (LCA missing, or both sides diverge from LCA)
//! now route through `entry_conflicts` with a populated `icon_delta`.
//! Callers resolve via `Resolution::entry_icon_choices`.

use keepass_core::model::{Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    ConflictSide, ParkConflictsConfig, Resolution, apply_merge, apply_merge_park_conflicts, merge,
};
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

/// Hold-open (supersedes the #212 "converge via parking" behaviour): a
/// genuine two-different-present-icon conflict is **held open** — each
/// device keeps its *own* icon until the user resolves. No winner is
/// picked (the old smaller-uuid tiebreak was arbitrary to the user and
/// discarded "mine vs theirs"). Crucially the merge is still **loop-safe**:
/// each peer keeps its own icon and a re-merge writes nothing, so there's
/// no ping-pong — the conflict is simply a stable held state surfaced for
/// review. See `internal design notes`.
#[test]
fn icon_only_conflict_holds_open_each_side_keeps_own() {
    let ancestor_icon = Uuid::from_u128(0x01);
    let icon_a = Uuid::from_u128(0x0a);
    let icon_b = Uuid::from_u128(0x0b);

    let id = EntryId(Uuid::from_u128(0x42));

    // Common synced base: title set, ancestor icon, archived in history.
    let mut ancestor = Entry::empty(id);
    ancestor.title = "AAA BBB CCC".into();
    ancestor.custom_icon_uuid = Some(ancestor_icon);
    ancestor.times = at(2026, 1, 1);

    // A moved the icon to icon_a; B moved it to icon_b. Both diverge from
    // the LCA → genuine conflict, neither auto-resolvable.
    let mut a_entry = ancestor.clone();
    a_entry.custom_icon_uuid = Some(icon_a);
    a_entry.times = at(2026, 1, 2);
    a_entry.history = vec![ancestor.clone()];

    let mut b_entry = ancestor.clone();
    b_entry.custom_icon_uuid = Some(icon_b);
    b_entry.times = at(2026, 1, 3);
    b_entry.history = vec![ancestor.clone()];

    let mut a = vault(vec![a_entry]);
    let mut b = vault(vec![b_entry]);
    let cfg = ParkConflictsConfig::with_now(
        chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, 2026, 6, 4, 0, 0, 0).unwrap(),
    );

    // One round: each peer merges the OTHER's pre-merge state (concurrent).
    let a0 = a.clone();
    let b0 = b.clone();
    let out_ab = merge(&a0, &b0).expect("merge a<-b");
    assert!(
        out_ab
            .entry_conflicts
            .iter()
            .any(|c| c.icon_delta.is_some()),
        "both-diverged icons must surface as an icon conflict",
    );
    apply_merge_park_conflicts(&mut a, &b0, &out_ab, &cfg).expect("hold-open on A");
    let out_ba = merge(&b0, &a0).expect("merge b<-a");
    apply_merge_park_conflicts(&mut b, &a0, &out_ba, &cfg).expect("hold-open on B");

    // Hold-open: each peer keeps its OWN icon (no winner picked).
    assert_eq!(
        find(&a, 0x42).custom_icon_uuid,
        Some(icon_a),
        "A must keep its own icon under hold-open",
    );
    assert_eq!(
        find(&b, 0x42).custom_icon_uuid,
        Some(icon_b),
        "B must keep its own icon under hold-open",
    );

    // Loop-safety: re-merging the held state is a fixpoint — the conflict
    // is still surfaced (it's unresolved) but applying it writes nothing.
    let settle = merge(&a, &b).expect("settle merge");
    assert!(
        settle
            .entry_conflicts
            .iter()
            .any(|c| c.icon_delta.is_some()),
        "unresolved icon conflict stays surfaced until explicit resolution",
    );
    let a_before = a.clone();
    apply_merge_park_conflicts(&mut a, &b, &settle, &cfg).expect("re-apply on A");
    assert_eq!(
        find(&a, 0x42).custom_icon_uuid,
        find(&a_before, 0x42).custom_icon_uuid,
        "re-applying a held conflict must not change A's value (loop-safe fixpoint)",
    );
}

#[test]
fn one_sided_custom_icon_no_lca_auto_resolves_to_present_icon() {
    // No LCA, one side has a custom icon, the other doesn't. Absence is
    // the implicit base state, so the present icon wins (additive)
    // rather than parking a conflict — this is the transient
    // favicon-fetch race (one device fetched + assigned, the other
    // hasn't yet). The present icon must survive the merge.
    let icon1 = Uuid::from_u128(0x01);

    let mut local = entry(5, at(2026, 1, 1));
    local.custom_icon_uuid = Some(icon1);
    let remote = entry(5, at(2026, 1, 1));

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    assert!(
        outcome.entry_conflicts.is_empty(),
        "absence-vs-present must auto-resolve, not park a conflict",
    );

    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");
    assert_eq!(
        merged_vault.root.entries[0].custom_icon_uuid,
        Some(icon1),
        "the present icon survives the merge",
    );
}
