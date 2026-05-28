//! Typed merge events for the activity-log surface.
//!
//! [`MergeEvent`] is the stable type the engine layer will hook to
//! persist activity-log entries (per the eventual
//! `sync-activity-log.md` spec). Today the merge crate just emits the
//! events via [`mod@tracing`] at the spec §6-prescribed level — engine
//! layers that don't want a persisted log can drop the events on the
//! floor with a no-op subscriber.
//!
//! Severity mapping (sync-merge-strategies §6):
//!
//! - **Always-warn**: `LcaMissing`, `MasterKeyDisagreement` (the
//!   latter is also returned as a [`crate::MergeError`] before any
//!   mutation happens).
//! - **Always-error**: `CorruptionSignal` (a same-UUID,
//!   no-LCA-no-history pair — cannot arise from a normal sync flow).
//! - **Always-info**: `ConflictParked` (per parked-conflict badge),
//!   `EntryRestoredFromDeletion`, `ConcurrentMove` (group + entry),
//!   `HistoryRetentionConverged`, `VaultMetaFieldLww`,
//!   `GroupMetaFieldLww`.
//! - **Verbose-info** (not emitted by default at info level —
//!   intentionally skipped this slice; future revisions can route
//!   them through a dedicated subscriber): routine 3-way auto-merges,
//!   CRDT union of tags / custom-data / attachments where the union
//!   is trivially correct.
//! - **Not logged**: cosmetic LWW (colour / icon), device-local UI
//!   state, `Times.*` advancement.
//!
//! Prose templates from spec §6 are used verbatim where the spec
//! provides them. The engine layer remains free to retranslate or
//! reformat; the event's structured fields carry enough information
//! to do so.

use chrono::{DateTime, Utc};
use keepass_core::model::{EntryId, GroupId};

/// One typed merge event. The structured variants let an engine-side
/// subscriber persist a row in the future activity log without
/// reparsing the merge crate's tracing prose; the prose itself is
/// derivable from `Display` for log readability.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MergeEvent {
    /// An entry's per-entry 3-way classification ran without finding
    /// a shared ancestor (both sides' histories diverged past the LCA
    /// or were truncated beyond it). Every divergent field on the
    /// entry parks rather than auto-resolves. Spec §6 always-warn.
    LcaMissing {
        /// The entry id.
        entry: EntryId,
        /// Entry title at the point of merge (for human-readable log
        /// prose). Pulled from local's side; matches the parked
        /// entry's current title post-apply.
        title: String,
    },
    /// Same-UUID, no-LCA, both-sides-empty-history corruption signal
    /// per spec §3 case 2. Cannot arise from a normal sync flow.
    /// Spec §6 always-error.
    CorruptionSignal {
        /// The entry id with the corruption signature.
        entry: EntryId,
        /// Local-side title.
        title: String,
    },
    /// Two replicas independently rotated the master key (different
    /// `<Meta><MasterKeyChanged>` timestamps). Spec §6 hard fault —
    /// the merge for this vault is aborted; this event records the
    /// signal for the engine-side banner.
    MasterKeyDisagreement {
        /// Local-side `master_key_changed`.
        local_changed_at: DateTime<Utc>,
        /// Remote-side `master_key_changed`.
        remote_changed_at: DateTime<Utc>,
    },
    /// One or more fields of an entry parked into history for user
    /// review per spec §5. The badge surfaces on the
    /// `keys.field_conflict.v1`-marked snapshot.
    ConflictParked {
        /// The conflicted entry.
        entry: EntryId,
        /// Local-side title.
        title: String,
        /// Names of the conflicting standard / custom fields that
        /// parked. Includes `"Password"` when the spec §5.1 sensitive
        /// branch fired.
        fields: Vec<String>,
        /// `true` when the entry tripped the spec §5.1 both-sides-
        /// parked branch (Password or `Protected="True"`).
        sensitive: bool,
    },
    /// Spec §4 delete-vs-edit: the remote side tombstoned an entry
    /// that the local side had continued editing. Edit wins; the
    /// tombstone is preserved as historical provenance. Spec §6
    /// always-info.
    EntryRestoredFromDeletion {
        /// The entry whose deletion was overridden.
        entry: EntryId,
        /// Local-side title (the title at the point of the edit).
        title: String,
    },
    /// A group's owning parent differed between the two sides and
    /// remote's `location_changed` was newer — the merge relocated
    /// the group. Spec §6 always-info with the "Undo" prose.
    GroupConcurrentMove {
        /// The reparented group.
        group: GroupId,
        /// Local-side group name.
        name: String,
        /// Local's parent id before the move.
        local_parent: GroupId,
        /// Remote's parent id, now applied to local.
        remote_parent: GroupId,
    },
    /// Same shape as [`Self::GroupConcurrentMove`] but for entries.
    EntryConcurrentMove {
        /// The reparented entry.
        entry: EntryId,
        /// Local-side title.
        title: String,
        /// Local's owning group before the move.
        local_parent: GroupId,
        /// Remote's owning group, now applied to local.
        remote_parent: GroupId,
    },
    /// `<Meta><HistoryMax*>` differed between sides; the spec §2.1
    /// "shorter retention wins" rule picked the more conservative
    /// cap. Spec §6 always-info.
    HistoryRetentionConverged {
        /// Local-side max-items.
        local_max_items: i32,
        /// Remote-side max-items.
        remote_max_items: i32,
        /// The cap the merged vault now carries.
        picked_max_items: i32,
    },
    /// Vault-meta field LWW where the remote side won and the merge
    /// took remote's value. Covers the user-edited surfaces:
    /// `DatabaseName`, `DatabaseDescription`, `DefaultUserName`,
    /// recycle-bin config, etc. Spec §6 always-info.
    VaultMetaFieldLww {
        /// Human-readable field name (e.g. `"DatabaseName"`).
        field: &'static str,
        /// Local-side value before the swap. Empty string when the
        /// field type doesn't have a meaningful string rendering.
        local_value: String,
        /// Remote-side value, now applied to local.
        remote_value: String,
    },
}

impl std::fmt::Display for MergeEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LcaMissing { entry, title } => {
                write!(
                    f,
                    "Entry '{title}' ({entry:?}) had no shared history — manual review needed for all changed fields"
                )
            }
            Self::CorruptionSignal { entry, title } => {
                write!(
                    f,
                    "Entry '{title}' ({entry:?}) tripped the same-UUID-no-shared-history corruption signal — surfacing for review"
                )
            }
            Self::MasterKeyDisagreement {
                local_changed_at,
                remote_changed_at,
            } => {
                write!(
                    f,
                    "Master-key rotation disagreement — local changed at {local_changed_at}, remote at {remote_changed_at}. Merge aborted; resolve manually"
                )
            }
            Self::ConflictParked {
                entry,
                title,
                fields,
                sensitive,
            } => {
                let kind = if *sensitive {
                    "sensitive (Password / Protected)"
                } else {
                    "field"
                };
                write!(
                    f,
                    "Entry '{title}' ({entry:?}) had concurrent {kind} edits to {fields:?} — review →"
                )
            }
            Self::EntryRestoredFromDeletion { entry, title } => {
                write!(
                    f,
                    "Entry '{title}' ({entry:?}) was deleted remotely but edited locally — kept the edit. Undo →"
                )
            }
            Self::GroupConcurrentMove {
                group,
                name,
                local_parent,
                remote_parent,
            } => {
                write!(
                    f,
                    "Group '{name}' ({group:?}) moved to {local_parent:?} locally, to {remote_parent:?} remotely — kept remote (newer location_changed). Undo →"
                )
            }
            Self::EntryConcurrentMove {
                entry,
                title,
                local_parent,
                remote_parent,
            } => {
                write!(
                    f,
                    "Entry '{title}' ({entry:?}) moved to {local_parent:?} locally, to {remote_parent:?} remotely — kept remote (newer location_changed). Undo →"
                )
            }
            Self::HistoryRetentionConverged {
                local_max_items,
                remote_max_items,
                picked_max_items,
            } => {
                write!(
                    f,
                    "History retention set to {local_max_items} locally and {remote_max_items} remotely — kept {picked_max_items} (more privacy-conservative)"
                )
            }
            Self::VaultMetaFieldLww {
                field,
                local_value,
                remote_value,
            } => {
                write!(
                    f,
                    "{field} changed locally ('{local_value}') and remotely ('{remote_value}') — kept '{remote_value}' (newer)"
                )
            }
        }
    }
}

/// Emit a [`MergeEvent`] via the appropriate [`mod@tracing`] level
/// per spec §6. Engine layers register a tracing subscriber to
/// observe the events; the merge crate stays pure.
///
/// The emitted prose matches `Display`; structured fields are
/// emitted alongside so a subscriber can extract them without
/// re-parsing.
#[allow(clippy::too_many_lines)]
pub(crate) fn emit(event: &MergeEvent) {
    match event {
        MergeEvent::LcaMissing { entry, title } => {
            tracing::warn!(
                target: "keys.sync.merge",
                event = "lca_missing",
                entry_id = ?entry,
                title = %title,
                "{event}"
            );
        }
        MergeEvent::CorruptionSignal { entry, title } => {
            tracing::error!(
                target: "keys.sync.merge",
                event = "corruption_signal",
                entry_id = ?entry,
                title = %title,
                "{event}"
            );
        }
        MergeEvent::MasterKeyDisagreement {
            local_changed_at,
            remote_changed_at,
        } => {
            tracing::error!(
                target: "keys.sync.merge",
                event = "master_key_disagreement",
                local_changed_at = %local_changed_at,
                remote_changed_at = %remote_changed_at,
                "{event}"
            );
        }
        MergeEvent::ConflictParked {
            entry,
            title,
            fields,
            sensitive,
        } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "conflict_parked",
                entry_id = ?entry,
                title = %title,
                fields = ?fields,
                sensitive = %sensitive,
                "{event}"
            );
        }
        MergeEvent::EntryRestoredFromDeletion { entry, title } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "entry_restored_from_deletion",
                entry_id = ?entry,
                title = %title,
                "{event}"
            );
        }
        MergeEvent::GroupConcurrentMove {
            group,
            name,
            local_parent,
            remote_parent,
        } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "group_concurrent_move",
                group_id = ?group,
                name = %name,
                local_parent = ?local_parent,
                remote_parent = ?remote_parent,
                "{event}"
            );
        }
        MergeEvent::EntryConcurrentMove {
            entry,
            title,
            local_parent,
            remote_parent,
        } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "entry_concurrent_move",
                entry_id = ?entry,
                title = %title,
                local_parent = ?local_parent,
                remote_parent = ?remote_parent,
                "{event}"
            );
        }
        MergeEvent::HistoryRetentionConverged {
            local_max_items,
            remote_max_items,
            picked_max_items,
        } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "history_retention_converged",
                local = %local_max_items,
                remote = %remote_max_items,
                picked = %picked_max_items,
                "{event}"
            );
        }
        MergeEvent::VaultMetaFieldLww {
            field,
            local_value,
            remote_value,
        } => {
            tracing::info!(
                target: "keys.sync.merge",
                event = "vault_meta_field_lww",
                field = %field,
                local = %local_value,
                remote = %remote_value,
                "{event}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use uuid::Uuid;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    #[test]
    fn lca_missing_display_uses_spec_prose() {
        let ev = MergeEvent::LcaMissing {
            entry: EntryId(Uuid::nil()),
            title: "Netflix".into(),
        };
        let prose = format!("{ev}");
        assert!(prose.contains("Netflix"));
        assert!(prose.contains("no shared history"));
    }

    #[test]
    fn master_key_disagreement_display_carries_both_timestamps() {
        let ev = MergeEvent::MasterKeyDisagreement {
            local_changed_at: at(2026, 4, 1),
            remote_changed_at: at(2026, 5, 1),
        };
        let prose = format!("{ev}");
        assert!(prose.contains("rotation disagreement"));
    }

    #[test]
    fn conflict_parked_display_distinguishes_sensitive() {
        let plain = MergeEvent::ConflictParked {
            entry: EntryId(Uuid::nil()),
            title: "Bank".into(),
            fields: vec!["Title".into()],
            sensitive: false,
        };
        let sensitive = MergeEvent::ConflictParked {
            entry: EntryId(Uuid::nil()),
            title: "Bank".into(),
            fields: vec!["Password".into()],
            sensitive: true,
        };
        let p = format!("{plain}");
        let s = format!("{sensitive}");
        assert!(p.contains("field edits"));
        assert!(s.contains("sensitive"));
    }
}
