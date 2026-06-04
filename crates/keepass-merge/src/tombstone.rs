//! History tombstones — making history-record deletions stick across merge.
//!
//! Today's `merge_histories` (crate-private) is deliberately
//! additive: a record present on one side and absent on the other
//! survives the merge. That's correct when nothing is ever deleted
//! from history but defeats any user intent to actually delete a
//! historical record. Tombstones are the missing primitive: an
//! explicit "this `(mtime, hash)` is gone, do not resurrect it" signal
//! that propagates as set-union via KDBX `<CustomData>`.
//!
//! Algorithm credit: kdbxweb's `addHistoryTombstone` / OR-set CRDT
//! by Antelle (Dmitry Demidov, KeeWeb), commit `2b0140f` 2015-11-28,
//! citing Wuu & Bernstein 1984 and the Optimized OR-set 2012 paper.
//! kdbxweb keeps tombstones client-local; we put them in the file as
//! a Keys-specific custom_data extension so they propagate across an
//! arbitrary peer topology, not just hub-and-spoke.
//!
//! See `_project-management/history-tombstones.md` in the Keys repo
//! for the broader design rationale and use cases.

use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use keepass_core::model::{Binary, CustomDataItem, Entry};
use serde::{Deserialize, Serialize};

use crate::hash::entry_content_hash;

/// `<CustomData>` key under which the tombstone list lives on each entry.
/// Suffix `.v1` reserves room for schema migration.
pub const TOMBSTONE_CUSTOM_DATA_KEY: &str = "keys.history_tombstones.v1";

/// Why a history record was tombstoned. Mostly UX-flavoured: the
/// merge crate filters on the `(mtime, hash)` pair regardless. Other
/// kinds may be added; `#[non_exhaustive]` lets us do that safely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum TombstoneReason {
    /// The user explicitly deleted this history record (privacy /
    /// cleanup intent — the strongest form of "this should stay
    /// gone").
    UserDelete,
    /// Auto-merge resolved a field-LWW conflict; the loser snapshot
    /// is being cleaned up. See `conflict-resolution-rework.md`.
    ConflictCleanup,
    /// `Meta::HistoryMaxItems` truncation evicted this record.
    QuotaTrim,
    /// Anything else — preserves forward-compat for future code paths.
    Other,
}

/// One tombstoned history record.
///
/// Identified by `(mtime, hash)`: `mtime` alone is not a unique key
/// because `merge_histories` (crate-private) tolerates multiple
/// records sharing an mtime when their content differs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct HistoryTombstone {
    /// Last-modification-time of the tombstoned record.
    ///
    /// `None` is a legitimate value — KDBX permits history records
    /// without timestamps, and we tombstone them like any other.
    pub mtime: Option<DateTime<Utc>>,

    /// Content hash of the tombstoned record (computed via the
    /// merge crate's internal `entry_content_hash`).
    #[serde(with = "hex_array_32")]
    pub hash: [u8; 32],

    /// When this tombstone was issued. Used as the union tiebreaker
    /// when the same `(mtime, hash)` is tombstoned independently on
    /// two peers: we keep the earlier `at` so deletion-time
    /// provenance reflects when the user-intent first occurred.
    pub at: DateTime<Utc>,

    /// Optional originating user/device public key, hex-encoded on
    /// the wire. `None` is permitted for pre-P2P single-user contexts.
    #[serde(default, with = "hex_array_32_opt")]
    pub by: Option<[u8; 32]>,

    /// What kind of deletion this represents.
    pub reason: TombstoneReason,
}

/// Compact form of a tombstone list, suitable for the
/// [`crate::history_merge::merge_histories`] filter step.
pub(crate) type TombstoneSet = HashSet<(Option<DateTime<Utc>>, [u8; 32])>;

/// Errors that can occur while reading or modifying an entry's
/// tombstone list.
#[derive(Debug, thiserror::Error)]
pub enum TombstoneError {
    /// The entry's `keys.history_tombstones.v1` value couldn't be
    /// parsed as JSON. Indicates a corrupt or
    /// version-incompatible vault.
    #[error("failed to parse tombstone list: {0}")]
    Parse(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// Read / write the tombstone list on an entry's custom_data.
// ---------------------------------------------------------------------------

/// Read the tombstone list from an entry's `custom_data`. Returns
/// an empty `Vec` when the key is absent (the common case for
/// entries that have never had a history record deleted).
pub fn parse_tombstones(
    custom_data: &[CustomDataItem],
) -> Result<Vec<HistoryTombstone>, TombstoneError> {
    let Some(item) = custom_data
        .iter()
        .find(|i| i.key == TOMBSTONE_CUSTOM_DATA_KEY)
    else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_str(&item.value)?)
}

/// Replace (or, when `tombstones` is empty, remove) the tombstone
/// list on an entry's `custom_data`. `last_modified` is stamped onto
/// the underlying [`CustomDataItem::last_modified`] when `Some` so
/// KDBX writers that honour that field record an update time; pass
/// `None` from the pure merge apply path where wall-clock access is
/// disallowed.
pub(crate) fn write_tombstones_to_custom_data(
    custom_data: &mut Vec<CustomDataItem>,
    tombstones: &[HistoryTombstone],
    last_modified: Option<DateTime<Utc>>,
) {
    custom_data.retain(|item| item.key != TOMBSTONE_CUSTOM_DATA_KEY);
    if tombstones.is_empty() {
        return;
    }
    let json =
        serde_json::to_string(tombstones).expect("HistoryTombstone serialization is infallible");
    custom_data.push(CustomDataItem::new(
        TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
        json,
        last_modified,
    ));
}

// ---------------------------------------------------------------------------
// Set-union semantics.
// ---------------------------------------------------------------------------

/// Union two tombstone lists by `(mtime, hash)`. When the same pair
/// is present on both sides we keep the one with the earlier `at`
/// (the original deletion event), then the lexicographically smaller
/// `by` as a deterministic last-resort tiebreaker.
///
/// Output is sorted by `(mtime, hash)` so the JSON representation is
/// stable for property tests and visual diffing.
#[must_use]
pub(crate) fn union_history_tombstones(
    a: &[HistoryTombstone],
    b: &[HistoryTombstone],
) -> Vec<HistoryTombstone> {
    let mut by_key: HashMap<(Option<DateTime<Utc>>, [u8; 32]), HistoryTombstone> = HashMap::new();
    for t in a.iter().chain(b.iter()) {
        let key = (t.mtime, t.hash);
        by_key
            .entry(key)
            .and_modify(|existing| {
                if t.at < existing.at || (t.at == existing.at && t.by < existing.by) {
                    *existing = t.clone();
                }
            })
            .or_insert_with(|| t.clone());
    }
    let mut out: Vec<_> = by_key.into_values().collect();
    out.sort_by_key(|t| (t.mtime, t.hash));
    out
}

/// Compact a tombstone list into the `(mtime, hash)` lookup set used
/// by [`crate::history_merge::merge_histories`] to filter records.
///
/// The `mtime` component is truncated to whole-second resolution
/// ([`crate::time::second_resolution`]) so it matches the coarsened
/// dedup key the history paths look up with: a tombstone issued against
/// a millisecond-precise mtime must still fire against the same record
/// once the KDBX round-trip has truncated it to a whole second (and
/// vice-versa). See `sync-soak-bugs.md` Bug A.
#[must_use]
pub(crate) fn tombstone_set(tombstones: &[HistoryTombstone]) -> TombstoneSet {
    tombstones
        .iter()
        .map(|t| (crate::time::second_resolution(t.mtime), t.hash))
        .collect()
}

// ---------------------------------------------------------------------------
// Public action API.
// ---------------------------------------------------------------------------

/// Tombstone a history record.
///
/// Removes any record from `entry.history` matching
/// `(record_to_delete.mtime, hash_of_record_to_delete)` and adds a
/// corresponding [`HistoryTombstone`] to the entry's
/// `keys.history_tombstones.v1` custom_data.
///
/// Idempotent: if the same `(mtime, hash)` is already tombstoned on
/// the entry, the existing tombstone is preserved (we keep the
/// earlier `at`) and history is left as-is.
///
/// If `record_to_delete` is not present in `entry.history` (e.g.
/// already removed by a prior merge), the tombstone is still added.
/// This matters for replay safety and for the case where the loser
/// of a field-LWW conflict is being cleaned up but a stale peer's
/// view still holds it.
///
/// # Errors
///
/// Returns [`TombstoneError::Parse`] only if the entry already has
/// a malformed `keys.history_tombstones.v1` value. A fresh entry
/// (no prior tombstones) never errors.
pub fn add_history_tombstone(
    entry: &mut Entry,
    record_to_delete: &Entry,
    binaries: &[Binary],
    reason: TombstoneReason,
    by: Option<[u8; 32]>,
    now: DateTime<Utc>,
) -> Result<(), TombstoneError> {
    let hash = entry_content_hash(record_to_delete, binaries);
    let mtime = record_to_delete.times.last_modification_time;

    // Drop matching record from history (may be absent — that's fine).
    entry.history.retain(|h| {
        h.times.last_modification_time != mtime || entry_content_hash(h, binaries) != hash
    });

    // Merge into existing tombstone list.
    let mut existing = parse_tombstones(&entry.custom_data)?;
    let new_tombstone = HistoryTombstone {
        mtime,
        hash,
        at: now,
        by,
        reason,
    };
    let merged = union_history_tombstones(&existing, std::slice::from_ref(&new_tombstone));
    existing = merged;
    write_tombstones_to_custom_data(&mut entry.custom_data, &existing, Some(now));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tag remove-tombstones (`keys.tag_state.v1`).
//
// Per the sync-merge strategies spec §4, tag deletions need a
// kdbx-native-invisible tombstone surface so a `subtract` operation
// survives sync round-trips. Stored on the parent entry's
// `<CustomData>` as `keys.tag_state.v1` with a single `remove` map
// keyed by tag string.
//
// The same union semantics as history tombstones apply: set union
// across both sides, earliest `at` wins on collision. The apply step
// runs a filter pass over the merged tag set: for each tag the
// classifier produced, drop it if it's tombstoned and the latest
// add-time on either side is older than the tombstone's `at`. The
// add-time proxy is the holding entry's `last_modification_time` —
// kdbx doesn't track per-tag add-times, so a tag bumps the entry
// mtime on add (per spec). Re-adding a tombstoned tag with a fresh
// mtime overrides the tombstone for that round; future merges
// re-evaluate.
// ---------------------------------------------------------------------------

/// `<CustomData>` key under which the tag-state object lives on each entry.
/// Suffix `.v1` reserves room for schema migration.
pub const TAG_STATE_CUSTOM_DATA_KEY: &str = "keys.tag_state.v1";

/// One tag-removal record. The map key on [`TagState::remove`] is the
/// tag string; this struct carries the deletion provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TagRemoval {
    /// When the removal was issued. Used as the union tiebreaker:
    /// earlier `at` wins when the same tag is tombstoned independently
    /// on two peers (matches the history-tombstone semantics).
    pub at: DateTime<Utc>,

    /// Optional originating user/device public key, hex-encoded on
    /// the wire. `None` is permitted for pre-P2P single-user contexts.
    #[serde(default, with = "hex_array_32_opt")]
    pub by: Option<[u8; 32]>,

    /// What kind of deletion this represents. Tags only ever carry
    /// `UserDelete` or `Other` in practice — quota trim and conflict
    /// cleanup don't apply — but the variant is shared with the
    /// history-tombstone reason for cross-surface consistency.
    #[serde(default = "default_tag_reason")]
    pub reason: TombstoneReason,
}

fn default_tag_reason() -> TombstoneReason {
    TombstoneReason::UserDelete
}

impl TagRemoval {
    /// Construct a [`TagRemoval`] with the given deletion timestamp.
    /// Optional fields default to absent / `UserDelete` so adding
    /// future fields is non-breaking.
    #[must_use]
    pub fn new(at: DateTime<Utc>) -> Self {
        Self {
            at,
            by: None,
            reason: TombstoneReason::UserDelete,
        }
    }

    /// Stamp the originating pubkey on the record. Chainable.
    #[must_use]
    pub fn with_by(mut self, by: [u8; 32]) -> Self {
        self.by = Some(by);
        self
    }

    /// Override the deletion reason. Chainable.
    #[must_use]
    pub fn with_reason(mut self, reason: TombstoneReason) -> Self {
        self.reason = reason;
        self
    }
}

/// Wire shape of `keys.tag_state.v1` — currently a single `remove`
/// map keyed by tag string. The wrapper is intentional: a future
/// schema revision may add `add: {…}` for explicit per-tag add-times
/// without breaking the v1 deserialiser.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TagState {
    /// Tags that have been explicitly removed, keyed by tag string.
    /// Present tags are implicit (in `entry.tags`); absence here is
    /// the no-tombstone default.
    #[serde(default)]
    pub remove: BTreeMap<String, TagRemoval>,
}

impl TagState {
    /// `true` when no removals are recorded — used to short-circuit
    /// the persistence step and keep the kdbx `<CustomData>` free of
    /// the key for entries that have never had a tag tombstoned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remove.is_empty()
    }
}

/// Read the tag-state object from an entry's `custom_data`. Returns
/// an empty `TagState` when the key is absent (the common case).
///
/// # Errors
///
/// Returns [`TombstoneError::Parse`] when the value exists but is not
/// well-formed JSON / doesn't match the schema.
pub fn parse_tag_state(custom_data: &[CustomDataItem]) -> Result<TagState, TombstoneError> {
    let Some(item) = custom_data
        .iter()
        .find(|i| i.key == TAG_STATE_CUSTOM_DATA_KEY)
    else {
        return Ok(TagState::default());
    };
    Ok(serde_json::from_str(&item.value)?)
}

/// Replace (or, when `state` is empty, remove) the tag-state object
/// on an entry's `custom_data`. `last_modified` is stamped onto the
/// underlying [`CustomDataItem::last_modified`] when `Some`; pass
/// `None` from the pure merge apply path.
pub(crate) fn write_tag_state_to_custom_data(
    custom_data: &mut Vec<CustomDataItem>,
    state: &TagState,
    last_modified: Option<DateTime<Utc>>,
) {
    custom_data.retain(|item| item.key != TAG_STATE_CUSTOM_DATA_KEY);
    if state.is_empty() {
        return;
    }
    let json = serde_json::to_string(state).expect("TagState serialization is infallible");
    custom_data.push(CustomDataItem::new(
        TAG_STATE_CUSTOM_DATA_KEY.to_string(),
        json,
        last_modified,
    ));
}

/// Union two tag-state objects: set union over `remove`, earliest
/// `at` wins on per-key collision (lex-smallest `by` as the
/// last-resort tiebreaker — mirrors [`union_history_tombstones`]).
#[must_use]
pub(crate) fn union_tag_states(a: &TagState, b: &TagState) -> TagState {
    let mut out: BTreeMap<String, TagRemoval> = BTreeMap::new();
    for (tag, rm) in a.remove.iter().chain(b.remove.iter()) {
        out.entry(tag.clone())
            .and_modify(|existing| {
                if rm.at < existing.at || (rm.at == existing.at && rm.by < existing.by) {
                    *existing = rm.clone();
                }
            })
            .or_insert_with(|| rm.clone());
    }
    TagState { remove: out }
}

// ---------------------------------------------------------------------------
// Attachment detach-tombstones (`keys.attachment_tombstones.v1`).
//
// Per the sync-merge strategies spec §4 + history-tombstones.md, an
// attachment detach is tombstoned on `(filename, content_hash)` so a
// stale peer that still holds the bytes can't silently reattach them
// on the next sync round. The hash component distinguishes a re-attach
// of *different* content under the same filename (which the tombstone
// must NOT block) from a stale-peer reintroduction of the same bytes
// (which it must block).
//
// Storage shape mirrors `keys.history_tombstones.v1` — a JSON array
// of self-describing records. Union semantics: dedup by
// `(filename, sha256)`, earliest `at` wins on collision. The filter
// pass at apply time walks the merged entry's attachments and drops
// any whose `(filename, sha256)` is tombstoned, unless the holding
// side's `last_modification_time` is strictly newer than the
// tombstone's `at` — the re-attach-after-delete escape hatch matches
// the tag-state semantics.
// ---------------------------------------------------------------------------

/// `<CustomData>` key under which attachment detach-tombstones live
/// on each entry. Suffix `.v1` reserves room for schema migration.
pub const ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY: &str = "keys.attachment_tombstones.v1";

/// One detached-attachment tombstone, keyed by `(filename, hash)`.
///
/// The composite key is deliberate: tombstoning by filename alone
/// would block a legitimate re-attach of *different* content under
/// the same name; tombstoning by hash alone would block a legitimate
/// re-attach of identical bytes under a *different* name (e.g. a
/// user-driven rename). The merge crate filters by the full pair so
/// only a stale peer's reintroduction of the exact `(filename, hash)`
/// fires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct AttachmentTombstone {
    /// Original filename of the detached attachment.
    pub filename: String,

    /// SHA-256 of the attachment payload, hex-encoded on the wire.
    /// Matches the hash the merge crate computes during attachment
    /// classification (`entry_merge::AttachmentSnap::sha256`).
    #[serde(with = "hex_array_32")]
    pub hash: [u8; 32],

    /// When the detach was issued. Used as the union tiebreaker:
    /// earlier `at` wins per spec §4.
    pub at: DateTime<Utc>,

    /// Optional originating user/device public key, hex-encoded.
    #[serde(default, with = "hex_array_32_opt")]
    pub by: Option<[u8; 32]>,

    /// What kind of removal this represents. `UserDelete` is the
    /// common case (the user removed the attachment); `ConflictCleanup`
    /// can fire when the resolver picks a delete; `QuotaTrim` is not
    /// currently emitted for attachments but the shared enum keeps the
    /// surface uniform.
    #[serde(default = "default_attachment_reason")]
    pub reason: TombstoneReason,
}

fn default_attachment_reason() -> TombstoneReason {
    TombstoneReason::UserDelete
}

impl AttachmentTombstone {
    /// Construct an [`AttachmentTombstone`] with the required keys.
    /// Optional fields default to absent / `UserDelete` so adding
    /// future fields is non-breaking.
    #[must_use]
    pub fn new(filename: impl Into<String>, hash: [u8; 32], at: DateTime<Utc>) -> Self {
        Self {
            filename: filename.into(),
            hash,
            at,
            by: None,
            reason: TombstoneReason::UserDelete,
        }
    }

    /// Stamp the originating pubkey on the record. Chainable.
    #[must_use]
    pub fn with_by(mut self, by: [u8; 32]) -> Self {
        self.by = Some(by);
        self
    }

    /// Override the deletion reason. Chainable.
    #[must_use]
    pub fn with_reason(mut self, reason: TombstoneReason) -> Self {
        self.reason = reason;
        self
    }
}

/// Read the attachment-tombstone list from an entry's `custom_data`.
/// Returns an empty `Vec` when the key is absent (the common case).
///
/// # Errors
///
/// Returns [`TombstoneError::Parse`] when the value exists but isn't
/// well-formed JSON / doesn't match the schema.
pub fn parse_attachment_tombstones(
    custom_data: &[CustomDataItem],
) -> Result<Vec<AttachmentTombstone>, TombstoneError> {
    let Some(item) = custom_data
        .iter()
        .find(|i| i.key == ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY)
    else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_str(&item.value)?)
}

/// Replace (or, when `tombstones` is empty, remove) the attachment-
/// tombstone list on an entry's `custom_data`.
pub(crate) fn write_attachment_tombstones_to_custom_data(
    custom_data: &mut Vec<CustomDataItem>,
    tombstones: &[AttachmentTombstone],
    last_modified: Option<DateTime<Utc>>,
) {
    custom_data.retain(|item| item.key != ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY);
    if tombstones.is_empty() {
        return;
    }
    let json =
        serde_json::to_string(tombstones).expect("AttachmentTombstone serialization is infallible");
    custom_data.push(CustomDataItem::new(
        ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
        json,
        last_modified,
    ));
}

/// Union two attachment-tombstone lists by `(filename, hash)`. When
/// the same pair is present on both sides we keep the one with the
/// earlier `at`, then the lex-smaller `by` as the deterministic
/// last-resort tiebreaker (mirrors [`union_history_tombstones`]).
///
/// Output is sorted by `(filename, hash)` so the JSON representation
/// is stable for property tests and visual diffing.
#[must_use]
pub(crate) fn union_attachment_tombstones(
    a: &[AttachmentTombstone],
    b: &[AttachmentTombstone],
) -> Vec<AttachmentTombstone> {
    let mut by_key: HashMap<(String, [u8; 32]), AttachmentTombstone> = HashMap::new();
    for t in a.iter().chain(b.iter()) {
        let key = (t.filename.clone(), t.hash);
        by_key
            .entry(key)
            .and_modify(|existing| {
                if t.at < existing.at || (t.at == existing.at && t.by < existing.by) {
                    *existing = t.clone();
                }
            })
            .or_insert_with(|| t.clone());
    }
    let mut out: Vec<_> = by_key.into_values().collect();
    out.sort_by(|x, y| (x.filename.as_str(), &x.hash).cmp(&(y.filename.as_str(), &y.hash)));
    out
}

/// Compact an attachment-tombstone list into a `(filename, hash)`
/// lookup set for the apply-time filter pass.
pub(crate) type AttachmentTombstoneSet = HashSet<(String, [u8; 32])>;

#[must_use]
pub(crate) fn attachment_tombstone_set(
    tombstones: &[AttachmentTombstone],
) -> AttachmentTombstoneSet {
    tombstones
        .iter()
        .map(|t| (t.filename.clone(), t.hash))
        .collect()
}

// ---------------------------------------------------------------------------
// Hex serde helpers for the [u8; 32] fields.
// ---------------------------------------------------------------------------

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in bytes {
            // Lower-case hex; deterministic JSON output for property tests.
            write!(s, "{b:02x}").expect("write to String is infallible");
        }
        ser.serialize_str(&s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        decode_32(&s).map_err(serde::de::Error::custom)
    }

    pub(super) fn decode_32(s: &str) -> Result<[u8; 32], String> {
        if s.len() != 64 {
            return Err(format!("expected 64 hex chars, got {}", s.len()));
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
            out[i] = u8::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
        }
        Ok(out)
    }
}

mod hex_array_32_opt {
    use super::hex_array_32::decode_32;
    use serde::{Deserialize, Deserializer, Serializer};

    // Serde's `#[serde(with = "module")]` machinery dictates the
    // `&Option<T>` shape here — we can't switch to `Option<&T>` without
    // changing the call site contract.
    #[allow(clippy::ref_option)]
    pub(super) fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        ser: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => super::hex_array_32::serialize(b, ser),
            None => ser.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        de: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        let opt: Option<String> = Option::<String>::deserialize(de)?;
        match opt {
            None => Ok(None),
            Some(s) => decode_32(&s).map(Some).map_err(serde::de::Error::custom),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests for the in-crate helpers. Cross-module integration tests live
// in `tests/history_tombstones.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn fixed_hash(n: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = n;
        h
    }

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn roundtrip_json_through_custom_data() {
        let tombstones = vec![HistoryTombstone {
            mtime: Some(ts(2026, 1, 15)),
            hash: fixed_hash(0xab),
            at: ts(2026, 5, 24),
            by: Some(fixed_hash(0xff)),
            reason: TombstoneReason::UserDelete,
        }];
        let mut cd: Vec<CustomDataItem> = Vec::new();
        write_tombstones_to_custom_data(&mut cd, &tombstones, Some(ts(2026, 5, 24)));
        assert_eq!(cd.len(), 1);
        let parsed = parse_tombstones(&cd).unwrap();
        assert_eq!(parsed, tombstones);
    }

    #[test]
    fn empty_list_removes_the_key() {
        let mut cd = vec![CustomDataItem::new(
            TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
            "[]".to_string(),
            None,
        )];
        write_tombstones_to_custom_data(&mut cd, &[], Some(ts(2026, 5, 24)));
        assert!(
            cd.is_empty(),
            "empty tombstone list must remove the custom_data key"
        );
    }

    #[test]
    fn missing_key_parses_as_empty() {
        let cd: Vec<CustomDataItem> = vec![CustomDataItem::new(
            "some.other.key".to_string(),
            "irrelevant".to_string(),
            None,
        )];
        assert!(parse_tombstones(&cd).unwrap().is_empty());
    }

    #[test]
    fn union_prefers_earlier_at_when_keys_collide() {
        let early = HistoryTombstone {
            mtime: Some(ts(2026, 1, 1)),
            hash: fixed_hash(1),
            at: ts(2026, 2, 1),
            by: None,
            reason: TombstoneReason::UserDelete,
        };
        let later = HistoryTombstone {
            mtime: Some(ts(2026, 1, 1)),
            hash: fixed_hash(1),
            at: ts(2026, 3, 1),
            by: None,
            reason: TombstoneReason::ConflictCleanup,
        };
        let unioned =
            union_history_tombstones(std::slice::from_ref(&later), std::slice::from_ref(&early));
        assert_eq!(unioned.len(), 1);
        assert_eq!(unioned[0].at, ts(2026, 2, 1));
        assert_eq!(unioned[0].reason, TombstoneReason::UserDelete);
    }

    #[test]
    fn union_deduplicates_distinct_entries_then_sorts() {
        let a = HistoryTombstone {
            mtime: Some(ts(2026, 1, 1)),
            hash: fixed_hash(1),
            at: ts(2026, 2, 1),
            by: None,
            reason: TombstoneReason::UserDelete,
        };
        let b = HistoryTombstone {
            mtime: Some(ts(2026, 1, 2)),
            hash: fixed_hash(2),
            at: ts(2026, 2, 2),
            by: None,
            reason: TombstoneReason::UserDelete,
        };
        let unioned = union_history_tombstones(std::slice::from_ref(&b), std::slice::from_ref(&a));
        assert_eq!(unioned.len(), 2);
        assert_eq!(unioned[0].mtime, Some(ts(2026, 1, 1)));
        assert_eq!(unioned[1].mtime, Some(ts(2026, 1, 2)));
    }

    fn tag_rm(at: DateTime<Utc>) -> TagRemoval {
        TagRemoval {
            at,
            by: None,
            reason: TombstoneReason::UserDelete,
        }
    }

    #[test]
    fn tag_state_roundtrip_json_through_custom_data() {
        let mut state = TagState::default();
        state
            .remove
            .insert("archive".to_string(), tag_rm(ts(2026, 4, 1)));
        let mut cd: Vec<CustomDataItem> = Vec::new();
        write_tag_state_to_custom_data(&mut cd, &state, Some(ts(2026, 5, 24)));
        assert_eq!(cd.len(), 1);
        let parsed = parse_tag_state(&cd).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn tag_state_empty_removes_the_key() {
        let mut cd = vec![CustomDataItem::new(
            TAG_STATE_CUSTOM_DATA_KEY.to_string(),
            "{\"remove\":{}}".to_string(),
            None,
        )];
        write_tag_state_to_custom_data(&mut cd, &TagState::default(), None);
        assert!(
            cd.is_empty(),
            "empty TagState must remove the custom_data key"
        );
    }

    #[test]
    fn tag_state_missing_key_parses_as_empty() {
        let cd: Vec<CustomDataItem> = vec![CustomDataItem::new(
            "some.other.key".to_string(),
            "irrelevant".to_string(),
            None,
        )];
        assert!(parse_tag_state(&cd).unwrap().is_empty());
    }

    #[test]
    fn tag_state_union_prefers_earlier_at_on_collision() {
        let mut early = TagState::default();
        early
            .remove
            .insert("archive".to_string(), tag_rm(ts(2026, 2, 1)));
        let mut late = TagState::default();
        late.remove
            .insert("archive".to_string(), tag_rm(ts(2026, 3, 1)));
        let unioned = union_tag_states(&late, &early);
        assert_eq!(unioned.remove["archive"].at, ts(2026, 2, 1));
    }

    #[test]
    fn tag_state_union_keeps_disjoint_tags_from_both_sides() {
        let mut a = TagState::default();
        a.remove
            .insert("archive".to_string(), tag_rm(ts(2026, 2, 1)));
        let mut b = TagState::default();
        b.remove.insert("old".to_string(), tag_rm(ts(2026, 3, 1)));
        let unioned = union_tag_states(&a, &b);
        assert!(unioned.remove.contains_key("archive"));
        assert!(unioned.remove.contains_key("old"));
    }

    fn att_tomb(filename: &str, hash_byte: u8, at: DateTime<Utc>) -> AttachmentTombstone {
        AttachmentTombstone {
            filename: filename.to_string(),
            hash: fixed_hash(hash_byte),
            at,
            by: None,
            reason: TombstoneReason::UserDelete,
        }
    }

    #[test]
    fn attachment_tombstone_roundtrip_json_through_custom_data() {
        let tombstones = vec![att_tomb("scan.pdf", 0xab, ts(2026, 5, 24))];
        let mut cd: Vec<CustomDataItem> = Vec::new();
        write_attachment_tombstones_to_custom_data(&mut cd, &tombstones, Some(ts(2026, 5, 24)));
        assert_eq!(cd.len(), 1);
        let parsed = parse_attachment_tombstones(&cd).unwrap();
        assert_eq!(parsed, tombstones);
    }

    #[test]
    fn attachment_tombstones_empty_list_removes_the_key() {
        let mut cd = vec![CustomDataItem::new(
            ATTACHMENT_TOMBSTONE_CUSTOM_DATA_KEY.to_string(),
            "[]".to_string(),
            None,
        )];
        write_attachment_tombstones_to_custom_data(&mut cd, &[], None);
        assert!(cd.is_empty());
    }

    #[test]
    fn attachment_tombstone_union_prefers_earlier_at_on_filename_hash_collision() {
        let early = att_tomb("scan.pdf", 0xab, ts(2026, 2, 1));
        let later = att_tomb("scan.pdf", 0xab, ts(2026, 3, 1));
        let unioned =
            union_attachment_tombstones(std::slice::from_ref(&later), std::slice::from_ref(&early));
        assert_eq!(unioned.len(), 1);
        assert_eq!(unioned[0].at, ts(2026, 2, 1));
    }

    #[test]
    fn attachment_tombstone_union_keeps_distinct_by_name_or_hash() {
        // Same filename, different hash → two records.
        let a = att_tomb("scan.pdf", 0xab, ts(2026, 2, 1));
        let b = att_tomb("scan.pdf", 0xcd, ts(2026, 3, 1));
        // Different filename, same hash → two records.
        let c = att_tomb("scan2.pdf", 0xab, ts(2026, 4, 1));
        let unioned =
            union_attachment_tombstones(&[a.clone(), c.clone()], std::slice::from_ref(&b));
        assert_eq!(unioned.len(), 3);
    }

    #[test]
    fn null_mtime_round_trips() {
        let tombstones = vec![HistoryTombstone {
            mtime: None,
            hash: fixed_hash(0x33),
            at: ts(2026, 5, 24),
            by: None,
            reason: TombstoneReason::UserDelete,
        }];
        let mut cd: Vec<CustomDataItem> = Vec::new();
        write_tombstones_to_custom_data(&mut cd, &tombstones, Some(ts(2026, 5, 24)));
        let parsed = parse_tombstones(&cd).unwrap();
        assert_eq!(parsed[0].mtime, None);
    }
}
