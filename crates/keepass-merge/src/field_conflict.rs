//! Field-LWW conflict markers — the loser-snapshot tag the
//! conflict-resolver UI keys off.
//!
//! When `apply_merge_auto` auto-resolves an entry conflict via the
//! per-field LWW + tiebreaker policy, the *loser* snapshot — the
//! entry state we pushed into the merged entry's `<History>` as the
//! pre-merge record of the side that didn't win — gets a small
//! marker written into its own `custom_data`:
//!
//! ```text
//! loser_snapshot.custom_data["keys.field_conflict.v1"] = json({
//!   at:          <ISO8601>,
//!   winner_side: "local" | "remote"
//! })
//! ```
//!
//! That marker is what Keys-Mac (and any other consumer) checks to
//! decide whether an entry has a pending conflict review. The marker
//! is **on the loser snapshot**, not on the entry's top-level
//! custom_data: this co-locates the signal with the data it
//! describes, avoids same-mtime-collision identifier pain, and means
//! no ack flag is needed — once a history tombstone removes the
//! loser snapshot, the marker dies with it.
//!
//! See `_project-management/conflict-resolution-rework.md` (Keys
//! repo) for the broader design rationale.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `<CustomData>` key under which the field-LWW marker lives on a
/// loser history snapshot. Suffix `.v1` reserves room for schema
/// migration.
pub const FIELD_CONFLICT_CUSTOM_DATA_KEY: &str = "keys.field_conflict.v1";

/// Side of the field-LWW resolution that won. Diagnostic-only; the
/// resolver UI doesn't depend on it — both sides are reachable via
/// the entry's current state + the loser snapshot itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum WinnerSide {
    /// The locally-held entry's state won the LWW comparison.
    Local,
    /// The remote-side (incoming) entry's state won the LWW
    /// comparison.
    Remote,
}

/// The marker written into a loser snapshot's `custom_data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FieldConflictMarker {
    /// When the auto-merge ran. Stamped from
    /// [`crate::AutoMergeConfig::now`] for deterministic testability.
    pub at: DateTime<Utc>,
    /// Which side won the field-LWW resolution this marker belongs
    /// to.
    pub winner_side: WinnerSide,
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
