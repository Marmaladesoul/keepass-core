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
