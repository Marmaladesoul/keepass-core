//! Error type for the merge crate.
//!
//! Per the workspace convention (see `keepass-core::error`) this top-level
//! enum is `#[non_exhaustive]` and transparently wraps upstream
//! [`keepass_core::Error`] via the [`MergeError::Model`] arm. Merge-specific
//! variants will be added in later slices as the merge algorithm grows.

/// Errors produced by the merge crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MergeError {
    /// An error originating from the underlying `keepass-core` model.
    #[error(transparent)]
    Model(#[from] keepass_core::Error),

    /// The caller's [`crate::Resolution`] referred to an entry that
    /// isn't present in any conflict bucket of the [`crate::MergeOutcome`]
    /// being applied. Usually a sign of a stale outcome (the resolution
    /// was constructed against a previous merge).
    #[error(
        "resolution refers to entry {entry:?} which is not in any conflict bucket of the outcome"
    )]
    UnknownEntryInResolution {
        /// The unexpected entry id.
        entry: keepass_core::model::EntryId,
    },

    /// The caller's [`crate::Resolution`] supplied a per-field choice for
    /// a key that isn't in the corresponding conflict's `field_deltas`.
    /// Usually a sign of a stale outcome or a typo'd field key.
    #[error(
        "resolution for entry {entry:?} refers to field {field:?} which is not in the conflict's field_deltas"
    )]
    UnknownFieldInResolution {
        /// The conflicted entry the bad field belongs to.
        entry: keepass_core::model::EntryId,
        /// The field key the caller supplied.
        field: String,
    },

    /// An entry in the [`crate::MergeOutcome`]'s `entry_conflicts` or
    /// `delete_edit_conflicts` bucket has no corresponding entry in the
    /// caller's [`crate::Resolution`]. The caller forgot to provide a
    /// choice for it.
    #[error("no resolution provided for conflict on entry {entry:?}")]
    MissingResolutionForConflict {
        /// The conflicted entry the resolution is missing.
        entry: keepass_core::model::EntryId,
    },

    /// The caller's [`crate::Resolution`] supplied a per-attachment
    /// choice for a name that isn't in the corresponding conflict's
    /// `attachment_deltas`. Usually a sign of a stale outcome or a
    /// typo'd attachment name.
    #[error(
        "resolution for entry {entry:?} refers to attachment {attachment:?} which is not in the conflict's attachment_deltas"
    )]
    UnknownAttachmentInResolution {
        /// The conflicted entry the bad attachment belongs to.
        entry: keepass_core::model::EntryId,
        /// The attachment name the caller supplied.
        attachment: String,
    },

    /// The caller chose [`crate::AttachmentChoice::KeepBoth`] for an
    /// attachment whose delta kind isn't
    /// [`crate::AttachmentDeltaKind::BothDiffer`]. The absent side has
    /// no bytes to keep — "keep both" is meaningless.
    #[error(
        "KeepBoth is not valid for attachment {attachment:?} on entry {entry:?}: only one side has the attachment"
    )]
    KeepBothNotPermittedForKind {
        /// The conflicted entry.
        entry: keepass_core::model::EntryId,
        /// The attachment name.
        attachment: String,
    },
}

#[cfg(test)]
mod tests {
    use super::MergeError;

    #[test]
    fn from_keepass_core_error_is_transparent() {
        // Build a `keepass_core::Error` via its own `From<std::io::Error>`
        // arm and verify our `#[from]` lights up. Doesn't depend on any
        // specific upstream variant being present.
        let io_err = std::io::Error::other("smoke");
        let core_err: keepass_core::Error = io_err.into();
        let merge_err: MergeError = core_err.into();
        assert!(matches!(merge_err, MergeError::Model(_)));
    }
}
