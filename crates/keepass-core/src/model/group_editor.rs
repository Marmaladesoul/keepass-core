//! [`GroupEditor`] for [`crate::kdbx::Kdbx::edit_group`].
//!
//! The editor parallels [`crate::model::EntryEditor`]: scoped mutable
//! access to a single [`Group`], exposing only the fields a caller may
//! legitimately change. Library-owned fields — `id`, `groups`,
//! `entries`, `times`, `previous_parent_group` — are not reachable
//! through this type.
//!
//! Unlike entries, groups don't carry history, so `edit_group` takes
//! no [`crate::model::HistoryPolicy`] parameter and no snapshot logic
//! runs around the closure. The single bookkeeping side-effect after
//! the closure returns is `times.last_modification_time = clock.now()`.

use uuid::Uuid;

use super::Group;

/// Scoped mutable view of a [`Group`] inside
/// [`crate::kdbx::Kdbx::edit_group`].
///
/// `#[non_exhaustive]` so new setter methods can be added without a
/// semver break for downstream callers.
#[derive(Debug)]
#[non_exhaustive]
pub struct GroupEditor<'a> {
    inner: &'a mut Group,
}

impl<'a> GroupEditor<'a> {
    /// Crate-internal constructor. Called by
    /// [`crate::kdbx::Kdbx::edit_group`] with a `&mut Group` freshly
    /// looked up under the target id.
    pub(crate) fn new(inner: &'a mut Group) -> Self {
        Self { inner }
    }

    /// Set the group's display name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.inner.name = name.into();
    }

    /// Set free-text notes for the group.
    pub fn set_notes(&mut self, notes: impl Into<String>) {
        self.inner.notes = notes.into();
    }

    /// Set the UI "expanded in tree view" flag.
    pub fn set_expanded(&mut self, expanded: bool) {
        self.inner.is_expanded = expanded;
    }

    /// Set the per-group default auto-type macro inherited by entries
    /// in the group. Empty string falls back to the vault-wide default.
    pub fn set_default_auto_type_sequence(&mut self, sequence: impl Into<String>) {
        self.inner.default_auto_type_sequence = sequence.into();
    }

    /// Set the tri-state auto-type override for this group.
    pub fn set_enable_auto_type(&mut self, enabled: Option<bool>) {
        self.inner.enable_auto_type = enabled;
    }

    /// Set the tri-state search-inclusion override for this group.
    pub fn set_enable_searching(&mut self, enabled: Option<bool>) {
        self.inner.enable_searching = enabled;
    }

    /// Point the group at a custom icon from
    /// [`crate::model::Meta::custom_icons`], or pass `None` to fall
    /// back to one of the built-in icons.
    pub fn set_custom_icon(&mut self, icon: Option<Uuid>) {
        self.inner.custom_icon_uuid = icon;
    }

    /// Set the group's built-in icon index. Same semantics and
    /// non-validation policy as [`crate::model::EntryEditor::set_icon_id`].
    pub fn set_icon_id(&mut self, id: u32) {
        self.inner.icon_id = id;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{GroupId, Timestamps};

    fn fresh_group() -> Group {
        Group {
            id: GroupId(Uuid::nil()),
            name: String::new(),
            notes: String::new(),
            groups: Vec::new(),
            entries: Vec::new(),
            is_expanded: true,
            default_auto_type_sequence: String::new(),
            enable_auto_type: None,
            enable_searching: None,
            custom_data: Vec::new(),
            previous_parent_group: None,
            last_top_visible_entry: None,
            custom_icon_uuid: None,
            icon_id: 0,
            times: Timestamps::default(),
            unknown_xml: Vec::new(),
        }
    }

    #[test]
    fn setters_assign_through() {
        let icon = Uuid::from_u128(0x00C0_FFEE);
        let mut g = fresh_group();
        {
            let mut editor = GroupEditor::new(&mut g);
            editor.set_name("Personal");
            editor.set_notes("private vault");
            editor.set_expanded(false);
            editor.set_default_auto_type_sequence("{USERNAME}{TAB}{PASSWORD}{ENTER}");
            editor.set_enable_auto_type(Some(false));
            editor.set_enable_searching(Some(true));
            editor.set_custom_icon(Some(icon));
        }
        assert_eq!(g.name, "Personal");
        assert_eq!(g.notes, "private vault");
        assert!(!g.is_expanded);
        assert_eq!(
            g.default_auto_type_sequence,
            "{USERNAME}{TAB}{PASSWORD}{ENTER}"
        );
        assert_eq!(g.enable_auto_type, Some(false));
        assert_eq!(g.enable_searching, Some(true));
        assert_eq!(g.custom_icon_uuid, Some(icon));
    }
}
