//! Scripted scenarios driven by the Tier 2 sim harness
//! (`common/sim.rs`). Each test sets up a deterministic series of
//! operations on two or more peers, drives a pairwise sync, and
//! asserts content convergence via [`Sim::assert_converged`].

mod common;

use common::sim::{Op, Sim};

#[test]
fn two_peers_disjoint_edits_converge() {
    // Peer-0 adds entry A; peer-1 adds entry B; sync; both should
    // have both entries.
    let mut sim = Sim::new(2, 1);
    let t0 = sim.next_clock();
    let t1 = sim.next_clock();
    sim.apply(
        0,
        Op::AddEntry {
            entry_id: 0xA,
            group_id: 0,
            title: "A".into(),
            password: "pa".into(),
            mtime: t0,
            creation_time: t0,
        },
    )
    .unwrap();
    sim.apply(
        1,
        Op::AddEntry {
            entry_id: 0xB,
            group_id: 0,
            title: "B".into(),
            password: "pb".into(),
            mtime: t1,
            creation_time: t1,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();
}

#[test]
fn two_peers_concurrent_password_edit_parks_both() {
    // Both peers edit the same Password concurrently — the Password
    // field always parks per spec §5.1. After sync, current state
    // converges (deterministic local-wins for sensitive) and history
    // carries both parked snapshots.
    let mut sim = Sim::new(2, 2);
    // Bootstrap entry on peer-0, sync to peer-1.
    let t0 = sim.next_clock();
    sim.apply(
        0,
        Op::AddEntry {
            entry_id: 0xA,
            group_id: 0,
            title: "Bank".into(),
            password: "original".into(),
            mtime: t0,
            creation_time: t0,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();

    // Concurrent password edits on both.
    let t_l = sim.next_clock();
    let t_r = sim.next_clock();
    sim.apply(
        0,
        Op::EditPassword {
            entry_id: 0xA,
            new_password: "local-new".into(),
            mtime: t_l,
        },
    )
    .unwrap();
    sim.apply(
        1,
        Op::EditPassword {
            entry_id: 0xA,
            new_password: "remote-new".into(),
            mtime: t_r,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();
}

#[test]
fn three_peers_chained_pairwise_converges() {
    // Three peers, pairwise sync chain. After (0↔1, 1↔2, 0↔2) all
    // three should be identical.
    let mut sim = Sim::new(3, 3);
    let t0 = sim.next_clock();
    sim.apply(
        0,
        Op::AddEntry {
            entry_id: 1,
            group_id: 0,
            title: "Shared".into(),
            password: "p".into(),
            mtime: t0,
            creation_time: t0,
        },
    )
    .unwrap();
    let t1 = sim.next_clock();
    sim.apply(
        1,
        Op::AddEntry {
            entry_id: 2,
            group_id: 0,
            title: "Only-1".into(),
            password: "p".into(),
            mtime: t1,
            creation_time: t1,
        },
    )
    .unwrap();
    let t2 = sim.next_clock();
    sim.apply(
        2,
        Op::AddEntry {
            entry_id: 3,
            group_id: 0,
            title: "Only-2".into(),
            password: "p".into(),
            mtime: t2,
            creation_time: t2,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.sync_pairwise(1, 2).unwrap();
    sim.sync_pairwise(0, 2).unwrap();
    sim.assert_converged().unwrap();
}

#[test]
fn tag_tombstone_propagates_through_sync() {
    // Peer-0 adds an entry with tag "archive", syncs to peer-1.
    // Peer-0 removes "archive" via tombstone. Sync. Peer-1's entry
    // should no longer carry "archive" and should hold the tombstone.
    let mut sim = Sim::new(2, 4);
    let t0 = sim.next_clock();
    sim.apply(
        0,
        Op::AddEntry {
            entry_id: 1,
            group_id: 0,
            title: "E".into(),
            password: "p".into(),
            mtime: t0,
            creation_time: t0,
        },
    )
    .unwrap();
    let t1 = sim.next_clock();
    sim.apply(
        0,
        Op::AddTag {
            entry_id: 1,
            tag: "archive".into(),
            mtime: t1,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();

    let t2 = sim.next_clock();
    sim.apply(
        0,
        Op::RemoveTag {
            entry_id: 1,
            tag: "archive".into(),
            at: t2,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();
}

#[test]
fn concurrent_move_lww_converges_across_peers() {
    // Peer-0 moves entry to group X; peer-1 moves same entry to
    // group Y. After sync, both peers agree on the winning group
    // (the one with the later location_changed).
    let mut sim = Sim::new(2, 5);
    let t0 = sim.next_clock();
    sim.apply(
        0,
        Op::AddEntry {
            entry_id: 1,
            group_id: 0,
            title: "E".into(),
            password: "p".into(),
            mtime: t0,
            creation_time: t0,
        },
    )
    .unwrap();
    let tg_x = sim.next_clock();
    sim.apply(
        0,
        Op::AddGroup {
            group_id: 0xa,
            parent_id: 0,
            name: "X".into(),
            mtime: tg_x,
            creation_time: tg_x,
        },
    )
    .unwrap();
    let tg_y = sim.next_clock();
    sim.apply(
        0,
        Op::AddGroup {
            group_id: 0xb,
            parent_id: 0,
            name: "Y".into(),
            mtime: tg_y,
            creation_time: tg_y,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();

    let t_lo = sim.next_clock();
    sim.apply(
        0,
        Op::MoveEntry {
            entry_id: 1,
            new_group_id: 0xa,
            location_changed: t_lo,
        },
    )
    .unwrap();
    let t_hi = sim.next_clock();
    sim.apply(
        1,
        Op::MoveEntry {
            entry_id: 1,
            new_group_id: 0xb,
            location_changed: t_hi,
        },
    )
    .unwrap();
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();
}

#[test]
fn camping_divergence_small_scale_converges() {
    // Spec's camping scenario at small scale: 20 entries created on
    // peer-0, 20 on peer-1, no concurrent edits to the same entry.
    // After sync, both peers carry all 40 entries.
    let mut sim = Sim::new(2, 6);
    for i in 0..20u128 {
        let t = sim.next_clock();
        sim.apply(
            0,
            Op::AddEntry {
                entry_id: 0x1000 | i,
                group_id: 0,
                title: format!("local-{i}"),
                password: format!("p{i}"),
                mtime: t,
                creation_time: t,
            },
        )
        .unwrap();
    }
    for i in 0..20u128 {
        let t = sim.next_clock();
        sim.apply(
            1,
            Op::AddEntry {
                entry_id: 0x2000 | i,
                group_id: 0,
                title: format!("remote-{i}"),
                password: format!("p{i}"),
                mtime: t,
                creation_time: t,
            },
        )
        .unwrap();
    }
    sim.sync_pairwise(0, 1).unwrap();
    sim.assert_converged().unwrap();
}
