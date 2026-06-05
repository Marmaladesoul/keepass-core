//! Conflict resolution records — the one piece of conflict state that
//! must converge across peers.
//!
//! Under the **hold-open** model (see
//! `_project-management/sync-conflict-state-redesign.md`), a conflicted
//! field is never auto-converged: each device keeps its own value until
//! the user explicitly resolves. "Is `(entry, field)` in conflict?" is
//! therefore *derived* at merge time from the live current-state
//! divergence and needs no synced representation.
//!
//! The **resolution** is the exception. When the user picks a value, every
//! peer must learn to stop holding and adopt it — so a resolution is
//! recorded as a vault-level (`<Meta><CustomData>`) entry under
//! [`CONFLICT_RESOLUTION_CUSTOM_DATA_KEY`], **set-unioned** on merge
//! (mirroring the history-tombstone CRDT in [`crate::tombstone`]).
//!
//! ## Secret-safety (hard constraint)
//!
//! A resolution record carries **no value and no value-hash** — only
//! `{entry, kind, key, resolved_at, by}`. KDBX does not stream-cipher the
//! `<CustomData>` map, and a bare hash of a password is an offline
//! brute-force oracle, so nothing value-derived about a secret goes here.
//! The chosen value rides as ordinary *protected* entry data (the
//! resolving side's current value, already present in the merge inputs);
//! the holding peer adopts that. See the design doc §4.2.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use keepass_core::model::CustomDataItem;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `<Meta><CustomData>` key under which the vault's conflict-resolution
/// list lives. Suffix `.v1` reserves room for schema migration.
pub const CONFLICT_RESOLUTION_CUSTOM_DATA_KEY: &str = "keys.conflict_resolutions.v1";

/// Which facet of an entry a resolution applies to. `#[non_exhaustive]`
/// leaves room for future conflict surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ConflictKind {
    /// A standard or custom string field, named by [`ConflictResolution::key`].
    Field,
    /// The entry's custom icon (`key` is `None`).
    Icon,
    /// A binary attachment, named by [`ConflictResolution::key`].
    Attachment,
}

/// One resolved conflict.
///
/// Identity for set-union is `(entry, kind, key)`. There is intentionally
/// **no chosen-value field** — see the module docs' secret-safety note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ConflictResolution {
    /// UUID of the entry whose conflict was resolved. Serialised as a
    /// hyphenated string (the `uuid` crate's `serde` feature isn't enabled
    /// in this crate, and we don't want to add it just for this).
    #[serde(with = "uuid_str")]
    pub entry: Uuid,

    /// Which facet of the entry this resolves.
    pub kind: ConflictKind,

    /// The field / attachment name, or `None` for [`ConflictKind::Icon`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// When the resolution was made. The union keeps the **latest**
    /// `resolved_at` per `(entry, kind, key)` — the most recent decision
    /// wins (unlike tombstones, which keep the earliest deletion event).
    pub resolved_at: DateTime<Utc>,

    /// Optional originating user/device public key, hex on the wire.
    /// `None` in pre-P2P single-user contexts. Used only as a
    /// deterministic tiebreaker on an exact `resolved_at` tie.
    #[serde(
        default,
        with = "crate::tombstone::hex_array_32_opt",
        skip_serializing_if = "Option::is_none"
    )]
    pub by: Option<[u8; 32]>,
}

impl ConflictResolution {
    /// Construct a resolution record.
    ///
    /// Public so downstream crates (keys-engine) can mint records when the
    /// user resolves a conflict — the `#[non_exhaustive]` attribute
    /// otherwise blocks struct-literal construction outside this crate.
    ///
    /// `key` must be `Some` for [`ConflictKind::Field`] /
    /// [`ConflictKind::Attachment`] and `None` for [`ConflictKind::Icon`];
    /// that pairing is a caller invariant, not enforced here.
    ///
    /// Per the secret-safety rule (module docs) there is deliberately no
    /// value parameter — the chosen value rides as ordinary protected entry
    /// data, never in the record.
    #[must_use]
    pub fn new(
        entry: Uuid,
        kind: ConflictKind,
        key: Option<String>,
        resolved_at: DateTime<Utc>,
        by: Option<[u8; 32]>,
    ) -> Self {
        Self {
            entry,
            kind,
            key,
            resolved_at,
            by,
        }
    }

    /// Identity tuple for set-union dedup.
    fn key_tuple(&self) -> (Uuid, ConflictKind, Option<&str>) {
        (self.entry, self.kind, self.key.as_deref())
    }
}

/// Errors reading the resolution list from a vault's Meta custom_data.
#[derive(Debug, thiserror::Error)]
pub enum ConflictResolutionError {
    /// The `keys.conflict_resolutions.v1` value wasn't valid JSON.
    #[error("failed to parse conflict-resolution list: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Read the resolution list from a vault's Meta `custom_data`. Empty when
/// the key is absent (the common case — most vaults never had a conflict).
pub fn parse_conflict_resolutions(
    custom_data: &[CustomDataItem],
) -> Result<Vec<ConflictResolution>, ConflictResolutionError> {
    let Some(item) = custom_data
        .iter()
        .find(|i| i.key == CONFLICT_RESOLUTION_CUSTOM_DATA_KEY)
    else {
        return Ok(Vec::new());
    };
    Ok(serde_json::from_str(&item.value)?)
}

/// Replace (or, when empty, remove) the resolution list on a vault's Meta
/// `custom_data`. `last_modified` is stamped when `Some`; pass `None` from
/// the pure merge-apply path.
pub(crate) fn write_conflict_resolutions_to_custom_data(
    custom_data: &mut Vec<CustomDataItem>,
    resolutions: &[ConflictResolution],
    last_modified: Option<DateTime<Utc>>,
) {
    custom_data.retain(|item| item.key != CONFLICT_RESOLUTION_CUSTOM_DATA_KEY);
    if resolutions.is_empty() {
        return;
    }
    let json =
        serde_json::to_string(resolutions).expect("ConflictResolution serialization is infallible");
    custom_data.push(CustomDataItem::new(
        CONFLICT_RESOLUTION_CUSTOM_DATA_KEY.to_string(),
        json,
        last_modified,
    ));
}

/// Union two resolution lists by `(entry, kind, key)`. When the same
/// conflict was resolved on two peers, keep the **later** `resolved_at`
/// (the most recent decision); break an exact tie by the larger `by`
/// (deterministic). Output is sorted for a stable JSON representation.
#[must_use]
pub(crate) fn union_conflict_resolutions(
    a: &[ConflictResolution],
    b: &[ConflictResolution],
) -> Vec<ConflictResolution> {
    let mut by_key: HashMap<(Uuid, ConflictKind, Option<String>), ConflictResolution> =
        HashMap::new();
    for r in a.iter().chain(b.iter()) {
        let (entry, kind, key) = r.key_tuple();
        let map_key = (entry, kind, key.map(str::to_owned));
        by_key
            .entry(map_key)
            .and_modify(|existing| {
                if r.resolved_at > existing.resolved_at
                    || (r.resolved_at == existing.resolved_at && r.by > existing.by)
                {
                    *existing = r.clone();
                }
            })
            .or_insert_with(|| r.clone());
    }
    let mut out: Vec<_> = by_key.into_values().collect();
    out.sort_by(|x, y| {
        x.entry
            .cmp(&y.entry)
            .then_with(|| (x.kind as u8).cmp(&(y.kind as u8)))
            .then_with(|| x.key.cmp(&y.key))
    });
    out
}

/// Add (or update) a conflict-resolution record on a vault's Meta
/// `custom_data`, set-unioned by `(entry, kind, key)` — the most recent
/// `resolved_at` wins (matching how the Meta merge unions the two sides).
///
/// This is the downstream write-path analogue of
/// [`crate::tombstone::add_history_tombstone`]: keys-engine calls it when
/// the user resolves a conflict, so the record propagates and every peer
/// adopts the resolving side's value and stops holding (design doc §5.3).
///
/// Idempotent: re-adding an identical record is a no-op; a newer
/// `resolved_at` for the same `(entry, kind, key)` supersedes the old one,
/// while an older one is ignored.
///
/// # Errors
///
/// Returns [`ConflictResolutionError::Parse`] only if the Meta already
/// holds a malformed `keys.conflict_resolutions.v1` value. A vault with no
/// prior resolutions never errors.
pub fn add_conflict_resolution(
    meta_custom_data: &mut Vec<CustomDataItem>,
    record: &ConflictResolution,
) -> Result<(), ConflictResolutionError> {
    let existing = parse_conflict_resolutions(meta_custom_data)?;
    let merged = union_conflict_resolutions(&existing, std::slice::from_ref(record));
    write_conflict_resolutions_to_custom_data(meta_custom_data, &merged, Some(record.resolved_at));
    Ok(())
}

/// Serialise `Uuid` as a hyphenated string for `#[serde(with = ...)]`.
mod uuid_str {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub(super) fn serialize<S: Serializer>(u: &Uuid, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&u.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Uuid, D::Error> {
        let s = String::deserialize(de)?;
        Uuid::parse_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, day, 0, 0, 0).unwrap()
    }

    fn res(entry: u128, kind: ConflictKind, key: Option<&str>, day: u32) -> ConflictResolution {
        ConflictResolution {
            entry: Uuid::from_u128(entry),
            kind,
            key: key.map(str::to_owned),
            resolved_at: at(day),
            by: None,
        }
    }

    #[test]
    fn round_trips_through_custom_data() {
        let list = vec![
            res(1, ConflictKind::Field, Some("Password"), 1),
            res(2, ConflictKind::Icon, None, 2),
        ];
        let mut cd = Vec::new();
        write_conflict_resolutions_to_custom_data(&mut cd, &list, None);
        assert_eq!(cd.len(), 1, "exactly one custom_data item written");
        let parsed = parse_conflict_resolutions(&cd).expect("parse");
        assert_eq!(parsed, list);
    }

    #[test]
    fn empty_list_removes_the_key() {
        let mut cd = vec![CustomDataItem::new(
            CONFLICT_RESOLUTION_CUSTOM_DATA_KEY.to_string(),
            "[]".to_string(),
            None,
        )];
        write_conflict_resolutions_to_custom_data(&mut cd, &[], None);
        assert!(cd.is_empty(), "empty list clears the key entirely");
    }

    #[test]
    fn absent_key_parses_as_empty() {
        assert!(parse_conflict_resolutions(&[]).expect("parse").is_empty());
    }

    #[test]
    fn union_keeps_latest_resolution_per_key() {
        // Same (entry, field) resolved on two peers at different times →
        // the later decision wins.
        let older = res(1, ConflictKind::Field, Some("Password"), 1);
        let newer = res(1, ConflictKind::Field, Some("Password"), 5);
        let out =
            union_conflict_resolutions(std::slice::from_ref(&older), std::slice::from_ref(&newer));
        assert_eq!(out.len(), 1, "same key collapses to one");
        assert_eq!(out[0].resolved_at, at(5), "latest decision wins");
    }

    #[test]
    fn union_keeps_distinct_keys() {
        let a = res(1, ConflictKind::Field, Some("Password"), 1);
        let b = res(1, ConflictKind::Field, Some("UserName"), 1);
        let c = res(1, ConflictKind::Icon, None, 1);
        let out = union_conflict_resolutions(&[a, b], std::slice::from_ref(&c));
        assert_eq!(out.len(), 3, "field/field/icon are distinct conflicts");
    }

    #[test]
    fn new_matches_struct_literal() {
        let made = ConflictResolution::new(
            Uuid::from_u128(7),
            ConflictKind::Field,
            Some("Password".to_string()),
            at(3),
            None,
        );
        assert_eq!(made, res(7, ConflictKind::Field, Some("Password"), 3));
    }

    #[test]
    fn add_conflict_resolution_appends_unions_and_supersedes() {
        let mut cd = Vec::new();

        // First resolution lands.
        add_conflict_resolution(&mut cd, &res(1, ConflictKind::Field, Some("Password"), 1))
            .expect("add");
        assert_eq!(parse_conflict_resolutions(&cd).unwrap().len(), 1);

        // A distinct facet adds a second record.
        add_conflict_resolution(&mut cd, &res(1, ConflictKind::Icon, None, 1)).expect("add");
        assert_eq!(parse_conflict_resolutions(&cd).unwrap().len(), 2);

        // A newer resolution for the same (entry, kind, key) supersedes, not appends.
        add_conflict_resolution(&mut cd, &res(1, ConflictKind::Field, Some("Password"), 5))
            .expect("add");
        let parsed = parse_conflict_resolutions(&cd).unwrap();
        assert_eq!(parsed.len(), 2, "same key supersedes rather than stacking");
        let pw = parsed
            .iter()
            .find(|r| r.kind == ConflictKind::Field)
            .expect("password resolution present");
        assert_eq!(pw.resolved_at, at(5), "latest decision wins");
    }

    #[test]
    fn add_conflict_resolution_is_idempotent_and_ignores_older() {
        let mut cd = Vec::new();
        let newer = res(1, ConflictKind::Field, Some("Password"), 5);
        add_conflict_resolution(&mut cd, &newer).expect("add");

        // Re-adding the same record changes nothing.
        add_conflict_resolution(&mut cd, &newer).expect("add");
        assert_eq!(
            parse_conflict_resolutions(&cd).unwrap(),
            vec![newer.clone()]
        );

        // An older resolution for the same key is ignored (union keeps latest).
        add_conflict_resolution(&mut cd, &res(1, ConflictKind::Field, Some("Password"), 2))
            .expect("add");
        assert_eq!(parse_conflict_resolutions(&cd).unwrap(), vec![newer]);
    }

    #[test]
    fn union_is_commutative_and_idempotent() {
        let a = vec![
            res(1, ConflictKind::Field, Some("Password"), 1),
            res(2, ConflictKind::Icon, None, 3),
        ];
        let b = vec![
            res(1, ConflictKind::Field, Some("Password"), 4), // newer dup
            res(3, ConflictKind::Field, Some("URL"), 2),
        ];
        let ab = union_conflict_resolutions(&a, &b);
        let ba = union_conflict_resolutions(&b, &a);
        assert_eq!(ab, ba, "commutative");
        let twice = union_conflict_resolutions(&ab, &ab);
        assert_eq!(ab, twice, "idempotent");
        // The newer Password resolution (day 4) survived.
        let pw = ab
            .iter()
            .find(|r| r.key.as_deref() == Some("Password"))
            .expect("password resolution present");
        assert_eq!(pw.resolved_at, at(4));
    }
}
