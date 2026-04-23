//! [`EntryEditor`] for [`crate::kdbx::Kdbx::edit_entry`].
//!
//! The editor is handed to the caller's closure inside `edit_entry`
//! and exposes *only* the fields the caller may legitimately change.
//! Fields the library owns — `id`, `history`, `times`,
//! `previous_parent_group` — are not reachable through this type.
//! Bookkeeping (history snapshot, `last_modification_time` stamp)
//! runs automatically in `edit_entry` after the closure returns.
//!
//! Slice 4 (MUTATION.md §"Slicing plan") shipped the five canonical
//! string fields. Slice 5 extends the editor to cover custom fields
//! (with [`CustomFieldValue`] for protected/plain routing), tags,
//! foreground / background colour, override URL, custom icon UUID,
//! quality-check flag, expiry, and auto-type. Attachments land in
//! slice 6.

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

use super::{AutoType, CustomField, Entry};

/// Value supplied to [`EntryEditor::set_custom_field`].
///
/// Routes [`CustomField::protected`]: a [`Self::Plain`] payload writes
/// a public custom field; a [`Self::Protected`] payload takes a
/// [`SecretString`] so the secret cannot accidentally leak through a
/// `String` clone or `Debug` print, and the resulting [`CustomField`]
/// is flagged for inner-stream encryption at save time.
#[derive(Debug)]
#[non_exhaustive]
pub enum CustomFieldValue {
    /// Public value — written `<Value>...</Value>` with no
    /// `Protected` attribute.
    Plain(String),
    /// Protected value — written `<Value Protected="True">...</Value>`,
    /// XOR-encoded against the inner-stream cipher.
    Protected(SecretString),
}

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

    // -----------------------------------------------------------------
    // Canonical string fields
    // -----------------------------------------------------------------

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

    // -----------------------------------------------------------------
    // Tags
    // -----------------------------------------------------------------

    /// Replace the tag list.
    pub fn set_tags(&mut self, tags: Vec<String>) {
        self.inner.tags = tags;
    }

    /// Append a tag. Idempotent — adding a tag that already exists is
    /// a no-op so the encoder never emits a `<Tags>` value with
    /// duplicate segments.
    pub fn add_tag(&mut self, tag: impl Into<String>) {
        let tag = tag.into();
        if !self.inner.tags.iter().any(|t| t == &tag) {
            self.inner.tags.push(tag);
        }
    }

    /// Remove a tag by exact match. Returns `true` if a tag was
    /// removed, `false` if it was not present.
    pub fn remove_tag(&mut self, tag: &str) -> bool {
        let before = self.inner.tags.len();
        self.inner.tags.retain(|t| t != tag);
        self.inner.tags.len() != before
    }

    // -----------------------------------------------------------------
    // Custom fields
    // -----------------------------------------------------------------

    /// Set (or insert) a custom field by key.
    ///
    /// If a field with the same key already exists its value and
    /// `protected` flag are overwritten in place — preserving its
    /// position in the entry's custom-field list. Otherwise the new
    /// field is appended.
    ///
    /// Routes the secret-bearing variant of [`CustomFieldValue`] so
    /// protected payloads cross the API boundary as [`SecretString`].
    pub fn set_custom_field(&mut self, key: impl Into<String>, value: CustomFieldValue) {
        let key = key.into();
        let (text, protected) = match value {
            CustomFieldValue::Plain(s) => (s, false),
            CustomFieldValue::Protected(s) => (s.expose_secret().to_owned(), true),
        };
        if let Some(existing) = self.inner.custom_fields.iter_mut().find(|c| c.key == key) {
            existing.value = text;
            existing.protected = protected;
        } else {
            self.inner.custom_fields.push(CustomField {
                key,
                value: text,
                protected,
            });
        }
    }

    /// Remove a custom field by key. Returns `true` if a field was
    /// removed, `false` if no field with that key existed.
    pub fn remove_custom_field(&mut self, key: &str) -> bool {
        let before = self.inner.custom_fields.len();
        self.inner.custom_fields.retain(|c| c.key != key);
        self.inner.custom_fields.len() != before
    }

    // -----------------------------------------------------------------
    // Decorative / behavioural fields
    // -----------------------------------------------------------------

    /// Set the entry's foreground colour as a hex `"#RRGGBB"` string.
    /// Pass an empty string to clear the per-entry colour and inherit
    /// the client default.
    pub fn set_foreground_color(&mut self, hex: impl Into<String>) {
        self.inner.foreground_color = hex.into();
    }

    /// Set the entry's background (row) colour. Same shape as
    /// [`Self::set_foreground_color`].
    pub fn set_background_color(&mut self, hex: impl Into<String>) {
        self.inner.background_color = hex.into();
    }

    /// Set the per-entry URL-scheme override. Empty string clears it
    /// and the entry's `URL` opens via the client's default handler.
    pub fn set_override_url(&mut self, url: impl Into<String>) {
        self.inner.override_url = url.into();
    }

    /// Point the entry at a custom icon from
    /// [`crate::model::Meta::custom_icons`], or pass `None` to fall
    /// back to one of the built-in icons.
    pub fn set_custom_icon(&mut self, icon: Option<Uuid>) {
        self.inner.custom_icon_uuid = icon;
    }

    /// Toggle whether this entry's password participates in the host
    /// client's password-quality audit. Defaults to `true`; opt out
    /// for PINs, recovery codes, and other strings where a strength
    /// meter doesn't apply.
    pub fn set_quality_check(&mut self, enabled: bool) {
        self.inner.quality_check = enabled;
    }

    /// Set the entry's expiry. `Some(at)` enables expiry and stamps
    /// the deadline; `None` disables expiry entirely (clearing both
    /// the `Expires` flag and the stored `ExpiryTime`).
    pub fn set_expiry(&mut self, at: Option<DateTime<Utc>>) {
        if let Some(t) = at {
            self.inner.times.expires = true;
            self.inner.times.expiry_time = Some(t);
        } else {
            self.inner.times.expires = false;
            self.inner.times.expiry_time = None;
        }
    }

    /// Replace the entry's [`AutoType`] configuration outright.
    pub fn set_auto_type(&mut self, auto_type: AutoType) {
        self.inner.auto_type = auto_type;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AutoType, AutoTypeAssociation, EntryId, Timestamps};
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
    fn canonical_setters_assign_fields() {
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

    #[test]
    fn tag_setters_replace_add_and_remove_with_dedup() {
        let mut e = fresh_entry();
        {
            let mut editor = EntryEditor::new(&mut e);
            editor.set_tags(vec!["a".into(), "b".into()]);
            editor.add_tag("c");
            editor.add_tag("a"); // duplicate — should be a no-op
        }
        assert_eq!(e.tags, vec!["a".to_string(), "b".into(), "c".into()]);

        {
            let mut editor = EntryEditor::new(&mut e);
            assert!(editor.remove_tag("b"));
            assert!(!editor.remove_tag("nope"));
        }
        assert_eq!(e.tags, vec!["a".to_string(), "c".into()]);
    }

    #[test]
    fn custom_field_set_inserts_then_overwrites_in_place() {
        let mut e = fresh_entry();
        {
            let mut editor = EntryEditor::new(&mut e);
            editor.set_custom_field("Recovery", CustomFieldValue::Plain("ABC".into()));
            editor.set_custom_field(
                "TOTP",
                CustomFieldValue::Protected(SecretString::from("seed")),
            );
        }
        assert_eq!(e.custom_fields.len(), 2);
        assert_eq!(e.custom_fields[0].key, "Recovery");
        assert!(!e.custom_fields[0].protected);
        assert_eq!(e.custom_fields[1].key, "TOTP");
        assert!(e.custom_fields[1].protected);
        assert_eq!(e.custom_fields[1].value, "seed");

        // Overwrite preserves position and updates flag + value.
        {
            let mut editor = EntryEditor::new(&mut e);
            editor.set_custom_field(
                "Recovery",
                CustomFieldValue::Protected(SecretString::from("XYZ")),
            );
        }
        assert_eq!(e.custom_fields.len(), 2);
        assert_eq!(e.custom_fields[0].key, "Recovery");
        assert!(e.custom_fields[0].protected);
        assert_eq!(e.custom_fields[0].value, "XYZ");
    }

    #[test]
    fn custom_field_remove_returns_whether_anything_was_dropped() {
        let mut e = fresh_entry();
        e.custom_fields.push(CustomField {
            key: "PIN".into(),
            value: "1234".into(),
            protected: false,
        });
        let mut editor = EntryEditor::new(&mut e);
        assert!(editor.remove_custom_field("PIN"));
        assert!(!editor.remove_custom_field("PIN"));
    }

    #[test]
    fn decorative_setters_assign_through() {
        let icon = Uuid::from_u128(0xDEAD_BEEF);
        let mut e = fresh_entry();
        {
            let mut editor = EntryEditor::new(&mut e);
            editor.set_foreground_color("#FF0000");
            editor.set_background_color("#00FFAA");
            editor.set_override_url("cmd://firefox %1");
            editor.set_custom_icon(Some(icon));
            editor.set_quality_check(false);
        }
        assert_eq!(e.foreground_color, "#FF0000");
        assert_eq!(e.background_color, "#00FFAA");
        assert_eq!(e.override_url, "cmd://firefox %1");
        assert_eq!(e.custom_icon_uuid, Some(icon));
        assert!(!e.quality_check);

        // Clearing the custom icon round-trips back to None.
        EntryEditor::new(&mut e).set_custom_icon(None);
        assert_eq!(e.custom_icon_uuid, None);
    }

    #[test]
    fn set_expiry_toggles_expires_flag() {
        let mut e = fresh_entry();
        let at: DateTime<Utc> = "2030-01-02T03:04:05Z".parse().unwrap();
        EntryEditor::new(&mut e).set_expiry(Some(at));
        assert!(e.times.expires);
        assert_eq!(e.times.expiry_time, Some(at));

        EntryEditor::new(&mut e).set_expiry(None);
        assert!(!e.times.expires);
        assert_eq!(e.times.expiry_time, None);
    }

    #[test]
    fn set_auto_type_replaces_block() {
        let mut e = fresh_entry();
        let at = AutoType {
            enabled: false,
            data_transfer_obfuscation: 1,
            default_sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}".into(),
            associations: vec![AutoTypeAssociation {
                window: "Firefox - *".into(),
                keystroke_sequence: "{PASSWORD}{ENTER}".into(),
            }],
        };
        EntryEditor::new(&mut e).set_auto_type(at.clone());
        assert_eq!(e.auto_type, at);
    }
}
