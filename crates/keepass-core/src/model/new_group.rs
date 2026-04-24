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
    pub(crate) icon_id: u32,
    pub(crate) enable_auto_type: Option<bool>,
    pub(crate) enable_searching: Option<bool>,
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
            icon_id: 0,
            enable_auto_type: None,
            enable_searching: None,
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

    /// Set the built-in icon index. Same semantics as
    /// [`crate::model::GroupEditor::set_icon_id`]; the library does
    /// not range-check.
    #[must_use]
    pub fn icon_id(mut self, id: u32) -> Self {
        self.icon_id = id;
        self
    }

    /// Set the tri-state auto-type override. `Some(false)` is the
    /// canonical shape for the recycle-bin group, which opts its
    /// contents out of auto-type; `Some(true)` forces on;
    /// `None` (the default) means "inherit from parent".
    #[must_use]
    pub fn enable_auto_type(mut self, enabled: Option<bool>) -> Self {
        self.enable_auto_type = enabled;
        self
    }

    /// Set the tri-state search-inclusion override. Same semantics
    /// as [`Self::enable_auto_type`].
    #[must_use]
    pub fn enable_searching(mut self, enabled: Option<bool>) -> Self {
        self.enable_searching = enabled;
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
