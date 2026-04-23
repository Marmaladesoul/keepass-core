//! [`NewEntry`] builder for [`crate::kdbx::Kdbx::add_entry`].
//!
//! The builder is a staging area for a caller-supplied entry. The
//! library owns the fields the caller **must not** set directly:
//! UUID (usually — see [`NewEntry::with_uuid`] for the import escape
//! hatch), timestamps, and `previous_parent_group`. Calling
//! `add_entry` is what actually inserts the new entry into the vault
//! tree and stamps the bookkeeping.

use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

/// Minimal staging type for [`crate::kdbx::Kdbx::add_entry`].
///
/// Only the five canonical string fields (Title, UserName, Password,
/// URL, Notes), plus Tags, are supported in this first slice. Custom
/// fields, colours, attachments, auto-type, etc. land in follow-up
/// slices — the field-level `Kdbx::edit_entry` method ships in slice
/// 4.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub(crate) title: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) url: String,
    pub(crate) notes: String,
    pub(crate) tags: Vec<String>,
    pub(crate) uuid: Option<Uuid>,
}

impl NewEntry {
    /// Start a new entry with the given title. All other fields are
    /// empty strings / empty tags; the library will fill in UUID and
    /// timestamps at `add_entry` time.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            username: String::new(),
            password: String::new(),
            url: String::new(),
            notes: String::new(),
            tags: Vec::new(),
            uuid: None,
        }
    }

    /// Set the username.
    #[must_use]
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = username.into();
        self
    }

    /// Set the password. Takes a [`SecretString`] so callers can't
    /// leak the password through a cloned `String` or a `Debug`
    /// print. The library expands the secret into the stored plain
    /// `String` at insertion time; the inner-stream cipher protection
    /// happens at `save_to_bytes`.
    //
    // `SecretString` by value (not `&SecretString`) is deliberate per
    // MUTATION.md: it moves ownership of the secret out of the
    // caller, so they can't keep a cheap copy after the builder
    // consumes it. `clippy::needless_pass_by_value` would have us
    // take a reference, but the move is a load-bearing part of the
    // API contract.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn password(mut self, password: SecretString) -> Self {
        password.expose_secret().clone_into(&mut self.password);
        self
    }

    /// Set the URL.
    #[must_use]
    pub fn url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
    }

    /// Set the notes.
    #[must_use]
    pub fn notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = notes.into();
        self
    }

    /// Set the tag list. Replaces any previously-set tags.
    #[must_use]
    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Pre-set the UUID. Normally the library generates a fresh v4
    /// UUID at `add_entry` time; this escape hatch is for import
    /// flows that need to preserve a specific UUID (e.g. importing
    /// from another KeePass file).
    ///
    /// `add_entry` returns
    /// [`crate::model::ModelError::DuplicateUuid`] if the supplied
    /// UUID is already in use anywhere in the vault (including as a
    /// group UUID).
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
    fn default_is_empty_strings_and_no_uuid() {
        let e = NewEntry::new("Title");
        assert_eq!(e.title, "Title");
        assert!(e.username.is_empty());
        assert!(e.password.is_empty());
        assert!(e.url.is_empty());
        assert!(e.notes.is_empty());
        assert!(e.tags.is_empty());
        assert!(e.uuid.is_none());
    }

    #[test]
    fn builder_methods_chain_and_override() {
        let e = NewEntry::new("T")
            .username("alice")
            .password(SecretString::from("hunter2"))
            .url("https://example.com")
            .notes("n")
            .tags(vec!["a".into(), "b".into()])
            .with_uuid(Uuid::nil());
        assert_eq!(e.username, "alice");
        assert_eq!(e.password, "hunter2");
        assert_eq!(e.url, "https://example.com");
        assert_eq!(e.notes, "n");
        assert_eq!(e.tags, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(e.uuid, Some(Uuid::nil()));
    }
}
