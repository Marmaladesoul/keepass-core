//! [`EntryEditor`] for [`crate::kdbx::Kdbx::edit_entry`].
//!
//! The editor is handed to the caller's closure inside `edit_entry`
//! and exposes *only* the fields the caller may legitimately change.
//! Fields the library owns — `id`, `history`, `times`,
//! `previous_parent_group` — are not reachable through this type.
//! Bookkeeping (history snapshot, `last_modification_time` stamp)
//! runs automatically in `edit_entry` after the closure returns.
//!
//! This slice (MUTATION.md §"Slicing plan" slice 4) exposes the five
//! canonical string fields (Title / UserName / Password / URL /
//! Notes) only. Custom fields, tags, colours, attachments, and the
//! rest of the entry surface land in follow-up slices.

use secrecy::{ExposeSecret, SecretString};

use super::Entry;

/// Scoped mutable view of an [`Entry`] inside
/// [`crate::kdbx::Kdbx::edit_entry`].
///
/// `#[non_exhaustive]` so new setter methods can be added in later
/// slices without a semver break for downstream callers who use the
/// editor through its methods (which every caller does — the struct
/// has no public fields).
#[derive(Debug)]
#[non_exhaustive]
pub struct EntryEditor<'a> {
    inner: &'a mut Entry,
}

impl<'a> EntryEditor<'a> {
    /// Crate-internal constructor. Called by
    /// [`crate::kdbx::Kdbx::edit_entry`] with a `&mut Entry` freshly
    /// looked up under the target id.
    pub(crate) fn new(inner: &'a mut Entry) -> Self {
        Self { inner }
    }

    /// Set the entry's title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.inner.title = title.into();
    }

    /// Set the entry's username.
    pub fn set_username(&mut self, username: impl Into<String>) {
        self.inner.username = username.into();
    }

    /// Set the entry's password. Takes a [`SecretString`] so the
    /// caller's copy is moved into the editor, not cloned — see the
    /// parallel note on [`crate::model::NewEntry::password`].
    //
    // `needless_pass_by_value` would have us take `&SecretString`,
    // but the move is a load-bearing part of the API contract per
    // MUTATION.md §"Secret hygiene at the boundary".
    #[allow(clippy::needless_pass_by_value)]
    pub fn set_password(&mut self, password: SecretString) {
        password
            .expose_secret()
            .clone_into(&mut self.inner.password);
    }

    /// Set the entry's URL.
    pub fn set_url(&mut self, url: impl Into<String>) {
        self.inner.url = url.into();
    }

    /// Set the entry's notes.
    pub fn set_notes(&mut self, notes: impl Into<String>) {
        self.inner.notes = notes.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AutoType, EntryId, Timestamps};
    use uuid::Uuid;

    fn fresh_entry() -> Entry {
        Entry {
            id: EntryId(Uuid::nil()),
            title: String::new(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            custom_fields: Vec::new(),
            tags: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            custom_icon_uuid: None,
            custom_data: Vec::new(),
            quality_check: true,
            previous_parent_group: None,
            auto_type: AutoType::default(),
            times: Timestamps::default(),
        }
    }

    #[test]
    fn setters_assign_fields() {
        let mut e = fresh_entry();
        {
            let mut editor = EntryEditor::new(&mut e);
            editor.set_title("Gmail");
            editor.set_username("alice@example.com");
            editor.set_password(SecretString::from("hunter2"));
            editor.set_url("https://mail.google.com");
            editor.set_notes("personal");
        }
        assert_eq!(e.title, "Gmail");
        assert_eq!(e.username, "alice@example.com");
        assert_eq!(e.password, "hunter2");
        assert_eq!(e.url, "https://mail.google.com");
        assert_eq!(e.notes, "personal");
    }
}
