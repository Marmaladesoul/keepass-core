#![allow(clippy::similar_names)] // g_a_id / g_b_id reads more clearly than aliases

//! Focused reproductions for spec §2.3 / §4 convergence: concurrent
//! moves, symmetric edit-vs-delete. The symmetric edit-vs-delete
//! coverage pins the engine fix that surfaced from Tier 2.

use chrono::{TimeZone, Utc};
use keepass_core::model::{Entry, EntryId, Group, GroupId, Timestamps, Vault};
use keepass_merge::{ParkConflictsConfig, apply_merge_park_conflicts, merge};
use uuid::Uuid;

fn ts(year: i32, m: u32, d: u32, h: u32, min: u32, sec: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(year, m, d, h, min, sec).unwrap()
}

fn timestamps(mtime: chrono::DateTime<Utc>, loc: chrono::DateTime<Utc>) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time = Some(mtime);
    t.location_changed = Some(loc);
    t.creation_time = Some(mtime);
    t
}

fn entry_in(
    group: &mut Group,
    id: u128,
    title: &str,
    mtime: chrono::DateTime<Utc>,
    loc: chrono::DateTime<Utc>,
) {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.title = title.into();
    e.times = timestamps(mtime, loc);
    group.entries.push(e);
}

fn group_in<'a>(parent: &'a mut Group, id: u128, name: &str) -> &'a mut Group {
    let mut g = Group::empty(GroupId(Uuid::from_u128(id)));
    g.name = name.into();
    parent.groups.push(g);
    parent.groups.last_mut().unwrap()
}

fn cfg(at: chrono::DateTime<Utc>) -> ParkConflictsConfig {
    ParkConflictsConfig::with_now(at)
}

#[test]
fn concurrent_move_with_repeated_sync_converges_on_same_parent() {
    // Both peers hold the same entry. Peer-0 has it at root with
    // location_changed t1. Peer-1 has it under group G_B with
    // location_changed t2 > t1. After bidirectional sync_pairwise
    // they must converge on the same parent.
    let entry_id = 0x77u128;
    let g_a_id = 0x10u128;
    let g_b_id = 0x20u128;
    let t1 = ts(2026, 1, 1, 0, 1, 0);
    let t2 = ts(2026, 1, 1, 0, 2, 0);

    let mut peer0 = Vault::empty(GroupId(Uuid::nil()));
    let _ = group_in(&mut peer0.root, g_a_id, "A");
    let _ = group_in(&mut peer0.root, g_b_id, "B");
    entry_in(&mut peer0.root, entry_id, "e", t1, t1);

    let mut peer1 = Vault::empty(GroupId(Uuid::nil()));
    let _ = group_in(&mut peer1.root, g_a_id, "A");
    let g_b = group_in(&mut peer1.root, g_b_id, "B");
    entry_in(g_b, entry_id, "e", t2, t2);

    // Run sync_pairwise twice to mimic the chaos runner's repeated
    // sync_pairwise calls.
    for round in 1..=2 {
        let p0_snap = peer0.clone();
        let outcome = merge(&peer1, &p0_snap).expect("merge to peer1");
        apply_merge_park_conflicts(
            &mut peer1,
            &p0_snap,
            &outcome,
            &cfg(ts(2026, 1, 1, 0, 3, 0)),
        )
        .expect("apply to peer1");

        let p1_snap = peer1.clone();
        let outcome2 = merge(&peer0, &p1_snap).expect("merge to peer0");
        apply_merge_park_conflicts(
            &mut peer0,
            &p1_snap,
            &outcome2,
            &cfg(ts(2026, 1, 1, 0, 4, 0)),
        )
        .expect("apply to peer0");

        // After each round, both peers should have the entry under
        // group G_B (peer-1's location_changed t2 > peer-0's t1).
        let entry_id_t = EntryId(Uuid::from_u128(entry_id));
        let p0_parent = find_entry_parent(&peer0.root, entry_id_t);
        let p1_parent = find_entry_parent(&peer1.root, entry_id_t);
        assert_eq!(
            p0_parent, p1_parent,
            "round {round}: peers' parent for entry should agree (got peer-0={p0_parent:?}, peer-1={p1_parent:?})"
        );
    }
}

#[test]
fn symmetric_edit_vs_delete_local_deleted_remote_edited_converges() {
    // Peer-0 deletes entry X at t_del. Peer-1 edits entry X at t_edit
    // with t_edit > t_del. Per spec §4 edit wins: both peers should
    // converge to "entry X alive."
    let entry_id = 0x77u128;
    let t_init = ts(2026, 1, 1, 0, 1, 0);
    let t_del = ts(2026, 1, 1, 0, 2, 0);
    let t_edit = ts(2026, 1, 1, 0, 3, 0);

    // Both start with entry X under root.
    let mut peer0 = Vault::empty(GroupId(Uuid::nil()));
    entry_in(&mut peer0.root, entry_id, "original", t_init, t_init);
    let mut peer1 = peer0.clone();

    // Peer-0 deletes; peer-1 edits.
    peer0
        .root
        .entries
        .retain(|e| e.id != EntryId(Uuid::from_u128(entry_id)));
    peer0
        .deleted_objects
        .push(keepass_core::model::DeletedObject::new(
            Uuid::from_u128(entry_id),
            Some(t_del),
        ));
    let edited = peer1
        .root
        .entries
        .iter_mut()
        .find(|e| e.id == EntryId(Uuid::from_u128(entry_id)))
        .unwrap();
    edited.title = "edited".into();
    edited.times.last_modification_time = Some(t_edit);

    // Pairwise sync.
    let p0_snap = peer0.clone();
    let outcome = merge(&peer1, &p0_snap).expect("merge to peer1");
    apply_merge_park_conflicts(
        &mut peer1,
        &p0_snap,
        &outcome,
        &cfg(ts(2026, 1, 1, 0, 4, 0)),
    )
    .expect("apply to peer1");

    let p1_snap = peer1.clone();
    let outcome2 = merge(&peer0, &p1_snap).expect("merge to peer0");
    apply_merge_park_conflicts(
        &mut peer0,
        &p1_snap,
        &outcome2,
        &cfg(ts(2026, 1, 1, 0, 5, 0)),
    )
    .expect("apply to peer0");

    // Both peers should have the entry alive with the edited title.
    let entry_id_t = EntryId(Uuid::from_u128(entry_id));
    let p0_entry = find_entry(&peer0.root, entry_id_t);
    let p1_entry = find_entry(&peer1.root, entry_id_t);
    assert!(p0_entry.is_some(), "peer-0 should hold the restored entry");
    assert!(p1_entry.is_some(), "peer-1 should hold the restored entry");
    assert_eq!(p0_entry.unwrap().title, "edited");
    assert_eq!(p1_entry.unwrap().title, "edited");

    // Tombstone retention policy: both peers should NOT carry the
    // tombstone (current implementation drops it for cross-client
    // safety per the audit; see apply::resolution::apply_delete_edit_resolutions).
    assert!(
        !peer0
            .deleted_objects
            .iter()
            .any(|t| t.uuid == Uuid::from_u128(entry_id))
    );
    assert!(
        !peer1
            .deleted_objects
            .iter()
            .any(|t| t.uuid == Uuid::from_u128(entry_id))
    );
}

#[test]
fn symmetric_edit_vs_delete_with_no_edit_provenance_converges() {
    // Regression for the delete-vs-edit direction asymmetry: an alive
    // entry carrying NO `last_modification_time` (absent provenance)
    // faces a concrete tombstone `deleted_at` on the other peer.
    //
    // The conservative policy is "any missing timestamp ⇒ edit wins
    // (keep)", and it must hold from BOTH merge directions:
    //   - deletion-local  / alive-remote (`remote_edited_after`)
    //   - alive-local / deletion-remote (`local_edited_after`)
    // If only one direction keeps, the peers diverge — one drops the
    // entry the other retains. This test pins that both peers converge
    // to "entry alive".
    let entry_id = 0x77u128;
    let t_init = ts(2026, 1, 1, 0, 1, 0);
    let t_del = ts(2026, 1, 1, 0, 2, 0);

    // Both start with entry X under root.
    let mut peer0 = Vault::empty(GroupId(Uuid::nil()));
    entry_in(&mut peer0.root, entry_id, "original", t_init, t_init);
    let mut peer1 = peer0.clone();

    // Peer-0 deletes X at a concrete `deleted_at`.
    peer0
        .root
        .entries
        .retain(|e| e.id != EntryId(Uuid::from_u128(entry_id)));
    peer0
        .deleted_objects
        .push(keepass_core::model::DeletedObject::new(
            Uuid::from_u128(entry_id),
            Some(t_del),
        ));

    // Peer-1 edits X but the edit carries NO mtime (absent provenance).
    let edited = peer1
        .root
        .entries
        .iter_mut()
        .find(|e| e.id == EntryId(Uuid::from_u128(entry_id)))
        .unwrap();
    edited.title = "edited".into();
    edited.times.last_modification_time = None;

    // Pairwise sync, both directions.
    let p0_snap = peer0.clone();
    let outcome = merge(&peer1, &p0_snap).expect("merge to peer1");
    apply_merge_park_conflicts(
        &mut peer1,
        &p0_snap,
        &outcome,
        &cfg(ts(2026, 1, 1, 0, 4, 0)),
    )
    .expect("apply to peer1");

    let p1_snap = peer1.clone();
    let outcome2 = merge(&peer0, &p1_snap).expect("merge to peer0");
    apply_merge_park_conflicts(
        &mut peer0,
        &p1_snap,
        &outcome2,
        &cfg(ts(2026, 1, 1, 0, 5, 0)),
    )
    .expect("apply to peer0");

    // Both peers must retain the entry — convergence. Pre-fix, the
    // deletion-local / alive-remote direction dropped it on peer-0
    // while peer-1 kept it: silent divergence.
    let entry_id_t = EntryId(Uuid::from_u128(entry_id));
    assert!(
        find_entry(&peer0.root, entry_id_t).is_some(),
        "peer-0 (deletion-local) must keep the no-provenance edit"
    );
    assert!(
        find_entry(&peer1.root, entry_id_t).is_some(),
        "peer-1 (alive-local) must keep the no-provenance edit"
    );
}

fn find_entry(group: &Group, id: EntryId) -> Option<&Entry> {
    for e in &group.entries {
        if e.id == id {
            return Some(e);
        }
    }
    for sub in &group.groups {
        if let Some(e) = find_entry(sub, id) {
            return Some(e);
        }
    }
    None
}

fn find_entry_parent(group: &Group, id: EntryId) -> Option<GroupId> {
    if group.entries.iter().any(|e| e.id == id) {
        return Some(group.id);
    }
    for sub in &group.groups {
        if let Some(p) = find_entry_parent(sub, id) {
            return Some(p);
        }
    }
    None
}
