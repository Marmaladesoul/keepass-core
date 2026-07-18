//! OR-set CRDT primitives shared by the `<CustomData>`-hosted merge
//! surfaces: history / attachment / tag tombstones ([`crate::tombstone`])
//! and conflict resolutions ([`crate::conflict_resolution`]).
//!
//! Each of those surfaces stores a set of self-describing records in a
//! KDBX `<CustomData>` slot and set-unions them on merge, keeping one
//! representative per identity key chosen by an issue-time tiebreak. The
//! parse/write plumbing and the union skeleton were four near-identical
//! hand-rolled copies; a copy silently drifting on the collision tiebreak
//! is a convergence bug — two peers keeping different survivors for the
//! same key diverge, which is data loss. Housing the slot plumbing, the
//! union skeleton, and the two tiebreak policies here makes that drift
//! structurally impossible: there is one place each behaviour lives.

use std::collections::HashMap;
use std::hash::Hash;

use chrono::{DateTime, Utc};
use keepass_core::model::CustomDataItem;
use serde::Serialize;
use serde::de::DeserializeOwned;

/// Read a JSON payload from the `<CustomData>` slot named `key`. Returns
/// `T::default()` when the slot is absent — the common case for
/// entries/vaults that never exercised the surface.
///
/// # Errors
///
/// Propagates the `serde_json` error when the slot exists but its value
/// isn't well-formed JSON for `T`. Each surface's public reader maps it
/// into that surface's error enum via `?`.
pub(crate) fn read_custom_data_slot<T: DeserializeOwned + Default>(
    custom_data: &[CustomDataItem],
    key: &str,
) -> Result<T, serde_json::Error> {
    match custom_data.iter().find(|i| i.key == key) {
        Some(item) => serde_json::from_str(&item.value),
        None => Ok(T::default()),
    }
}

/// Replace (or, when `payload_is_empty`, remove) the `<CustomData>` slot
/// named `key`. `last_modified` is stamped onto the written item when
/// `Some`; pass `None` from the pure merge-apply path where wall-clock
/// access is disallowed.
///
/// Removing the slot when the payload is empty keeps the KDBX free of
/// dead keys — the byte-stability invariant every surface's round-trip
/// test relies on.
pub(crate) fn write_custom_data_slot<T: Serialize + ?Sized>(
    custom_data: &mut Vec<CustomDataItem>,
    key: &str,
    payload: &T,
    payload_is_empty: bool,
    last_modified: Option<DateTime<Utc>>,
) {
    custom_data.retain(|item| item.key != key);
    if payload_is_empty {
        return;
    }
    let json = serde_json::to_string(payload)
        .expect("custom_data slot payload serialization is infallible");
    custom_data.push(CustomDataItem::new(key.to_string(), json, last_modified));
}

/// Set-union two slices into a fresh `Vec`, keeping one representative
/// per `key_fn` value chosen by `prefer`, sorted by `key_fn` for a
/// deterministic (per input pair) JSON representation.
///
/// `prefer(candidate, incumbent)` returns `true` when `candidate` should
/// displace the `incumbent` already held for that key. Supply a *strict*
/// comparison so an exact tie keeps the first-seen record (stable across
/// the `a`-then-`b` fold).
#[must_use]
pub(crate) fn union_by_key<T, K>(
    a: &[T],
    b: &[T],
    key_fn: impl Fn(&T) -> K,
    prefer: impl Fn(&T, &T) -> bool,
) -> Vec<T>
where
    T: Clone,
    K: Eq + Hash + Ord,
{
    let mut by_key: HashMap<K, T> = HashMap::new();
    for item in a.iter().chain(b.iter()) {
        by_key
            .entry(key_fn(item))
            .and_modify(|existing| {
                if prefer(item, existing) {
                    *existing = item.clone();
                }
            })
            .or_insert_with(|| item.clone());
    }
    let mut out: Vec<T> = by_key.into_values().collect();
    out.sort_by_cached_key(|t| key_fn(t));
    out
}

/// A record stored in an OR-set `<CustomData>` slot: it carries an issue
/// time and an optional originating device/user public key used only as
/// a deterministic tiebreaker on an exact issue-time tie.
pub(crate) trait OrSetMember {
    /// When the record was issued (`at` / `resolved_at`).
    fn issued_at(&self) -> DateTime<Utc>;
    /// Originating device/user public key, tiebreaker only.
    fn origin(&self) -> Option<[u8; 32]>;
}

/// Earliest-issued-wins collision policy (history / attachment / tag
/// tombstones): the earlier deletion event is the canonical one, so
/// deletion-time provenance reflects when the user intent first
/// occurred; an exact tie is broken by the lexicographically smaller
/// `origin`. Returns `true` when `candidate` should displace `incumbent`.
pub(crate) fn earliest_wins<T: OrSetMember>(candidate: &T, incumbent: &T) -> bool {
    candidate.issued_at() < incumbent.issued_at()
        || (candidate.issued_at() == incumbent.issued_at()
            && candidate.origin() < incumbent.origin())
}

/// Latest-issued-wins collision policy (conflict resolutions): the most
/// recent decision is the one every peer must adopt; an exact tie is
/// broken by the lexicographically larger `origin`. The mirror of
/// [`earliest_wins`], kept beside it so the two directions can't drift.
/// Returns `true` when `candidate` should displace `incumbent`.
pub(crate) fn latest_wins<T: OrSetMember>(candidate: &T, incumbent: &T) -> bool {
    candidate.issued_at() > incumbent.issued_at()
        || (candidate.issued_at() == incumbent.issued_at()
            && candidate.origin() > incumbent.origin())
}
