//! P2P sync convergence properties for `keepass-merge`.
//!
//! Beyond the in-place properties in `properties.rs`, peer-to-peer
//! sync needs stronger guarantees:
//!
//! 1. **Two-peer convergence** — when peer A and peer B independently
//!    merge each other's vault and apply the result, A' and B' must
//!    agree (re-merging them is a no-op).
//!
//! 2. **Three-peer order-independence** — when three peers' vaults are
//!    merged in different orders (`(A+B)+C` vs `A+(B+C)`), the final
//!    vaults must agree.
//!
//! Together these underwrite the sync design's "everyone races, all
//! winners produce the same answer" claim — peers can independently
//! compute merges without coordination and still converge, which is
//! the cornerstone of leaderless P2P kdbx sync.
//!
//! Both properties only test the **auto-mergeable** path: when the
//! merge surfaces `entry_conflicts` or `delete_edit_conflicts`,
//! proptest can't synthesize a meaningful `Resolution` so we skip
//! those generations via `prop_assume!`. Real Keys handles those by
//! prompting the user; convergence in that case is a UX concern, not
//! a merge-algebra concern.

use chrono::{TimeZone, Utc};
use keepass_core::model::{DeletedObject, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{MergeOutcome, Resolution, apply_merge, merge};
use proptest::prelude::*;
use uuid::Uuid;

// Same strategy shape as `properties.rs`: small UUID domain to force
// frequent overlap, bounded entry/history/tombstone counts.

fn entry_strategy() -> impl Strategy<Value = Entry> {
    (
        0u8..6,
        ".{0,8}",
        0u32..40,
        prop::collection::vec((".{0,4}", ".{0,4}", any::<bool>()), 0..2),
        0u8..3,
    )
        .prop_map(|(id, title, mtime_day, customs, history_count)| {
            let mut e = Entry::empty(EntryId(Uuid::from_u128(u128::from(id))));
            e.title = title;
            let mut t = Timestamps::default();
            t.last_modification_time = Some(
                Utc.with_ymd_and_hms(2026, 1, mtime_day.clamp(1, 28), 0, 0, 0)
                    .unwrap(),
            );
            e.times = t;
            e.custom_fields = customs
                .into_iter()
                .map(|(k, v, p)| keepass_core::model::CustomField::new(k, v, p))
                .collect();
            for i in 0..history_count {
                let mut snap = e.clone();
                snap.history.clear();
                let mut ts = Timestamps::default();
                ts.last_modification_time = Some(
                    Utc.with_ymd_and_hms(2025, 12, u32::from(i + 1), 0, 0, 0)
                        .unwrap(),
                );
                snap.times = ts;
                snap.title = format!("hist-{i}");
                e.history.push(snap);
            }
            e
        })
}

fn tombstone_strategy() -> impl Strategy<Value = DeletedObject> {
    (0u8..6, 1u32..28).prop_map(|(id, day)| {
        DeletedObject::new(
            Uuid::from_u128(u128::from(id)),
            Some(Utc.with_ymd_and_hms(2026, 1, day, 0, 0, 0).unwrap()),
        )
    })
}

fn vault_strategy() -> impl Strategy<Value = Vault> {
    (
        prop::collection::vec(entry_strategy(), 0..5),
        prop::collection::vec(tombstone_strategy(), 0..3),
    )
        .prop_map(|(entries, tombstones)| {
            let mut v = Vault::empty(GroupId(Uuid::nil()));
            let mut by_id: std::collections::HashMap<EntryId, Entry> =
                std::collections::HashMap::new();
            for e in entries {
                by_id.insert(e.id, e);
            }
            v.root.entries = by_id.into_values().collect();
            v.deleted_objects = tombstones;
            v
        })
}

/// True when an outcome has no caller-driven buckets to resolve.
fn is_auto_mergeable(o: &MergeOutcome) -> bool {
    o.entry_conflicts.is_empty() && o.delete_edit_conflicts.is_empty()
}

/// True when an outcome has nothing left to do — both sides agree
/// on every entry and every tombstone. Two such vaults are considered
/// converged.
fn is_converged(o: &MergeOutcome) -> bool {
    o.entry_conflicts.is_empty()
        && o.delete_edit_conflicts.is_empty()
        && o.disk_only_changes.is_empty()
        && o.local_only_changes.is_empty()
        && o.added_on_disk.is_empty()
        && o.deleted_on_disk.is_empty()
        && o.local_deletions_pending_sync.is_empty()
}

proptest! {
    // Most generated `(a, b)` pairs surface caller-driven conflicts (which we
    // can't auto-resolve in a property test), so we'd burn through proptest's
    // default rejection budget at scale. Raise it generously: the budget is
    // about being able to FIND enough auto-mergeable cases, not about test
    // strength.
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_global_rejects: 200_000,
        ..ProptestConfig::default()
    })]

    /// Two peers, each independently merging the other's vault, must
    /// arrive at the same place.
    ///
    /// In the P2P sync model: peer A holds vault `a`, peer B holds
    /// `b`. A receives `b` and computes `merge(a, b)`; B receives `a`
    /// and computes `merge(b, a)`. Each applies its outcome to its
    /// local vault. If the resulting `a'` and `b'` don't converge,
    /// the gossip layer would see two different "new tip" hashes for
    /// the same logical reconciliation, and the swarm would churn
    /// indefinitely.
    #[test]
    fn two_peers_converge(a in vault_strategy(), b in vault_strategy()) {
        let outcome_ab = merge(&a, &b).expect("merge a<-b");
        let outcome_ba = merge(&b, &a).expect("merge b<-a");

        prop_assume!(is_auto_mergeable(&outcome_ab));
        prop_assume!(is_auto_mergeable(&outcome_ba));

        let mut a_prime = a.clone();
        apply_merge(&mut a_prime, &b, &outcome_ab, &Resolution::default())
            .expect("apply on peer A");

        let mut b_prime = b.clone();
        apply_merge(&mut b_prime, &a, &outcome_ba, &Resolution::default())
            .expect("apply on peer B");

        let convergence = merge(&a_prime, &b_prime).expect("convergence merge");
        prop_assert!(
            is_converged(&convergence),
            "two-peer convergence failed: a' and b' disagree after independent merges; \
             convergence outcome = {convergence:?}"
        );
    }

    /// Three peers' vaults merged in two different associativity
    /// orders must end at the same place.
    ///
    /// `((a + b) + c)` represents peer A receiving b first then c.
    /// `(a + (b + c))` represents peer A receiving an already-merged
    /// b+c (e.g. via a relay peer that fetched both before A came
    /// online). Sync would diverge if these produced different
    /// vaults.
    #[test]
    fn three_peer_merge_is_order_independent(
        a in vault_strategy(),
        b in vault_strategy(),
        c in vault_strategy(),
    ) {
        // Path 1: (a + b) + c
        let outcome_ab = merge(&a, &b).expect("ab");
        prop_assume!(is_auto_mergeable(&outcome_ab));
        let mut path1 = a.clone();
        apply_merge(&mut path1, &b, &outcome_ab, &Resolution::default())
            .expect("apply ab");
        let outcome_ab_c = merge(&path1, &c).expect("ab+c");
        prop_assume!(is_auto_mergeable(&outcome_ab_c));
        apply_merge(&mut path1, &c, &outcome_ab_c, &Resolution::default())
            .expect("apply ab+c");

        // Path 2: a + (b + c)
        let outcome_bc = merge(&b, &c).expect("bc");
        prop_assume!(is_auto_mergeable(&outcome_bc));
        let mut bc = b.clone();
        apply_merge(&mut bc, &c, &outcome_bc, &Resolution::default())
            .expect("apply bc");
        let outcome_a_bc = merge(&a, &bc).expect("a+bc");
        prop_assume!(is_auto_mergeable(&outcome_a_bc));
        let mut path2 = a.clone();
        apply_merge(&mut path2, &bc, &outcome_a_bc, &Resolution::default())
            .expect("apply a+bc");

        // Two paths must converge.
        let convergence = merge(&path1, &path2).expect("convergence");
        prop_assert!(
            is_converged(&convergence),
            "three-peer associativity failed: (a+b)+c and a+(b+c) disagree; \
             convergence outcome = {convergence:?}"
        );
    }
}
