//! End-to-end coverage for resolution-record *adoption* (phase 1c):
//! a held conflict covered by a `keys.conflict_resolutions.v1` record is
//! adopted (converges to the resolving side) instead of held, so a
//! resolve on one peer clears the conflict on every peer.
//!
//! Resolution records are written as raw JSON because `ConflictResolution`
//! is `#[non_exhaustive]` (the test crate can't build it directly).

use chrono::{TimeZone, Utc};
use keepass_core::model::{CustomDataItem, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{ParkConflictsConfig, apply_merge_park_conflicts, merge};
use uuid::Uuid;

fn at(day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap());
    t
}

fn vault(entries: Vec<Entry>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = entries;
    v
}

fn find(v: &Vault, id: u128) -> &Entry {
    v.root
        .entries
        .iter()
        .find(|e| e.id == EntryId(Uuid::from_u128(id)))
        .expect("entry present")
}

fn cfg() -> ParkConflictsConfig {
    ParkConflictsConfig::with_now(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap())
}

/// Put a raw conflict-resolution record into a vault's Meta custom_data.
fn put_resolution(v: &mut Vault, json: &str) {
    v.meta.custom_data.push(CustomDataItem::new(
        "keys.conflict_resolutions.v1".to_string(),
        json.to_string(),
        None,
    ));
}

const ENTRY: u128 = 0x42;

/// Build the A/B icon-conflict pair: common ancestor icon, A→icon_a,
/// B→icon_b, both diverged off the LCA.
fn icon_conflict_pair(icon_a: Uuid, icon_b: Uuid) -> (Vault, Vault) {
    let id = EntryId(Uuid::from_u128(ENTRY));
    let mut ancestor = Entry::empty(id);
    ancestor.title = "Login".into();
    ancestor.custom_icon_uuid = Some(Uuid::from_u128(0x01));
    ancestor.times = at(1);

    let mut a = ancestor.clone();
    a.custom_icon_uuid = Some(icon_a);
    a.times = at(2);
    a.history = vec![ancestor.clone()];

    let mut b = ancestor.clone();
    b.custom_icon_uuid = Some(icon_b);
    b.times = at(3);
    b.history = vec![ancestor];

    (vault(vec![a]), vault(vec![b]))
}

#[test]
fn remote_resolution_is_adopted_and_clears_the_conflict() {
    let icon_a = Uuid::from_u128(0x0a);
    let icon_b = Uuid::from_u128(0x0b);
    let (mut a_vault, mut b_vault) = icon_conflict_pair(icon_a, icon_b);

    // A resolves the icon to its own value at a time AFTER both edits.
    let entry_uuid = Uuid::from_u128(ENTRY).to_string();
    put_resolution(
        &mut a_vault,
        &format!(
            r#"[{{"entry":"{entry_uuid}","kind":"icon","resolved_at":"2026-01-05T00:00:00Z"}}]"#
        ),
    );

    // B merges A. A (remote) carries the resolution B lacks → B adopts A's
    // icon and the conflict is no longer held.
    let out = merge(&b_vault, &a_vault).expect("merge b<-a");
    assert!(
        out.entry_conflicts.iter().any(|c| c.icon_delta.is_some()),
        "merge still detects the raw icon divergence",
    );
    let report = apply_merge_park_conflicts(&mut b_vault, &a_vault, &out, &cfg()).expect("apply");

    assert_eq!(
        find(&b_vault, ENTRY).custom_icon_uuid,
        Some(icon_a),
        "B adopts the resolving side's (A's) icon",
    );
    assert!(
        report.entries_with_parked_conflict.is_empty(),
        "an adopted conflict is no longer held: {:?}",
        report.entries_with_parked_conflict,
    );

    // And it stays converged: a re-merge surfaces no icon conflict
    // (both now hold icon_a; the resolution propagated via Meta union).
    let settle = merge(&b_vault, &a_vault).expect("settle");
    assert!(
        settle
            .entry_conflicts
            .iter()
            .all(|c| c.icon_delta.is_none()),
        "resolved icon stays converged on re-merge",
    );
}

#[test]
fn local_edit_after_resolution_supersedes_and_holds() {
    // A resolved the icon at T, but B then changed its icon at T2 > T.
    // B's later edit re-opens the conflict — the resolution must NOT be
    // adopted (the maintainer's supersession requirement).
    let icon_a = Uuid::from_u128(0x0a);
    let icon_b_new = Uuid::from_u128(0x0c);
    let (mut a_vault, mut b_vault) = icon_conflict_pair(icon_a, Uuid::from_u128(0x0b));

    // A resolved at 2026-01-05; B's entry was just edited later (day 10).
    let entry_uuid = Uuid::from_u128(ENTRY).to_string();
    put_resolution(
        &mut a_vault,
        &format!(
            r#"[{{"entry":"{entry_uuid}","kind":"icon","resolved_at":"2026-01-05T00:00:00Z"}}]"#
        ),
    );
    {
        let b_entry = b_vault.root.entries.get_mut(0).unwrap();
        b_entry.custom_icon_uuid = Some(icon_b_new);
        b_entry.times = at(10); // after the resolution
    }

    let out = merge(&b_vault, &a_vault).expect("merge b<-a");
    let report = apply_merge_park_conflicts(&mut b_vault, &a_vault, &out, &cfg()).expect("apply");

    assert_eq!(
        find(&b_vault, ENTRY).custom_icon_uuid,
        Some(icon_b_new),
        "B's post-resolution edit wins — the stale resolution is not adopted",
    );
    assert_eq!(
        report.entries_with_parked_conflict,
        vec![EntryId(Uuid::from_u128(ENTRY))],
        "the superseded conflict is held again for review",
    );
}

#[test]
fn no_resolution_holds_open() {
    // Sanity: with no resolution record anywhere, the icon conflict is
    // held (each side keeps its own) — plain hold-open.
    let icon_a = Uuid::from_u128(0x0a);
    let icon_b = Uuid::from_u128(0x0b);
    let (mut a_vault, b_vault) = icon_conflict_pair(icon_a, icon_b);

    let out = merge(&a_vault, &b_vault).expect("merge a<-b");
    let report = apply_merge_park_conflicts(&mut a_vault, &b_vault, &out, &cfg()).expect("apply");

    assert_eq!(
        find(&a_vault, ENTRY).custom_icon_uuid,
        Some(icon_a),
        "A keeps its own icon (hold-open)",
    );
    assert_eq!(
        report.entries_with_parked_conflict,
        vec![EntryId(Uuid::from_u128(ENTRY))],
        "unresolved conflict is held",
    );
}
