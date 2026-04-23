//! [`NewGroup`] builder for [`crate::kdbx::Kdbx::add_group`].
//!
//! The shape mirrors [`crate::model::NewEntry`]: a staging type for
//! caller-provided fields, with library-owned fields (UUID timestamps,
//! `previous_parent_group`) filled in at insertion time.
//!
//! Groups don't carry history, so there is no `HistoryPolicy` parameter
//! on the corresponding `add_group` / `edit_group` methods.

use uuid::Uuid;

/// Minimal staging type for [`crate::kdbx::Kdbx::add_group`].
///
/// Only the user-visible string fields (Name, Notes) are supported in
/// this slice. UI-state and per-group auto-type / search overrides
/// land in follow-up slices via [`crate::model::GroupEditor`].
#[derive(Debug, Clone)]
pub struct NewGroup {
    pub(crate) name: String,
    pub(crate) notes: String,
    pub(crate) uuid: Option<Uuid>,
}

impl NewGroup {
    /// Start a new group with the given name. Notes default to empty;
    /// the library generates a fresh v4 UUID at `add_group` time.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            notes: String::new(),
            uuid: None,
        }
    }

    /// Set free-text notes for the group.
    #[must_use]
    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// Pre-set the UUID. The escape hatch for import flows that need
    /// to preserve a specific UUID (e.g. importing from another
    /// KeePass file). `add_group` returns
    /// [`crate::model::ModelError::DuplicateUuid`] if the supplied
    /// UUID is already in use anywhere in the vault.
    #[must_use]
    pub fn with_uuid(mut self, uuid: Uuid) -> Self {
        self.uuid = Some(uuid);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty_notes_no_uuid() {
        let g = NewGroup::new("Personal");
        assert_eq!(g.name, "Personal");
        assert!(g.notes.is_empty());
        assert!(g.uuid.is_none());
    }

    #[test]
    fn builder_methods_chain() {
        let g = NewGroup::new("Work")
            .notes("client logins")
            .with_uuid(Uuid::nil());
        assert_eq!(g.notes, "client logins");
        assert_eq!(g.uuid, Some(Uuid::nil()));
    }
}
