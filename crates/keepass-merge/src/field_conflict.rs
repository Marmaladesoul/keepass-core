//! Parked-conflict markers — the loser-snapshot tag the
//! conflict-resolver UI keys off.
//!
//! When `apply_merge_park_conflicts` decides not to auto-resolve a
//! genuine "both sides edited the same field off the LCA" conflict,
//! it parks the remote side by pushing a clone of remote's entry into
//! local's `<History>` and tagging that snapshot's `custom_data` with
//! a marker:
//!
//! ```text
//! parked_remote_snapshot.custom_data["keys.field_conflict.v1"] = json({
//!   at: <ISO8601>
//! })
//! ```
//!
//! The marker is what Keys-Mac (and any other consumer) checks to
//! decide whether an entry has a pending conflict review. The marker
//! is **on the parked remote snapshot**, not on the entry's
//! top-level custom_data, so the parked snapshot is identifiable
//! among the entry's history records, and so removing the marker
//! happens naturally when the history record is tombstoned via the
//! slice-2 mechanism (see `history-tombstones.md`).
//!
//! The marker carries only its timestamp — no winner / loser
//! semantics — because the conflict isn't auto-resolved. The user's
//! choice is captured later by the resolver UI; the marker just
//! says "this snapshot is the parked-remote alternative; review
//! against current state."
//!
//! See `_project-management/conflict-resolution-rework.md` (Keys
//! repo) for the broader design rationale.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `<CustomData>` key under which the parked-conflict marker lives
/// on the parked-remote history snapshot. Suffix `.v1` reserves room
/// for schema migration.
pub const FIELD_CONFLICT_CUSTOM_DATA_KEY: &str = "keys.field_conflict.v1";

/// The marker written into a parked-remote history snapshot's
/// `custom_data`.
///
/// Intentionally carries only its emission timestamp. There is no
/// winner / loser — the existing keepass-merge three-way merge
/// surfaced this as a genuine "both sides changed" conflict and the
/// rework chose to park it rather than silently LWW-resolve. The
/// resolver UI is the only thing that picks a side, and that's
/// recorded by editing the entry + tombstoning the marker snapshot,
/// not by writing into the marker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FieldConflictMarker {
    /// When the auto-merge parked this conflict. Stamped from
    /// [`crate::ParkConflictsConfig::now`] for deterministic
    /// testability.
    pub at: DateTime<Utc>,
}

impl FieldConflictMarker {
    /// Parse the marker from a `custom_data` value if present.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] if the value is
    /// not valid JSON or doesn't match the schema. A missing key is
    /// **not** an error — callers check key-presence at the
    /// [`keepass_core::model::CustomDataItem`] level.
    pub fn from_value(value: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(value)
    }

    /// Serialise the marker to its JSON wire form.
    ///
    /// # Panics
    ///
    /// Panics only if `serde_json` fails to serialise a fixed
    /// derive-generated representation, which is unreachable for
    /// this type's shape.
    #[must_use]
    pub fn to_value(&self) -> String {
        serde_json::to_string(self).expect("FieldConflictMarker serialisation is infallible")
    }
}
