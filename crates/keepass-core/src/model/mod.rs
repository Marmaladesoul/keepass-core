//! Format-agnostic vault model.
//!
//! The types here describe a KeePass vault in memory without committing to
//! a particular on-disk version. The XML decoder in
//! [`crate::xml`] translates between these types and the KeePass inner
//! XML document; the writer (later) translates the other way.
//!
//! Every identifier type is a newtype — no naked `Uuid`s cross the API
//! boundary. This makes key-confusion bugs (e.g. passing an [`EntryId`]
//! where a [`GroupId`] is expected) into compile errors, not runtime
//! ones.
//!
//! ## Layout
//!
//! The model is split across topical submodules so each file fits a
//! single concern in head:
//!
//! - [`types`] — `HistoryPolicy`, `ModelError`, the `EntryId` /
//!   `GroupId` newtypes, `Timestamps`, and the two "carried verbatim"
//!   containers (`UnknownElement`, `CustomDataItem`) that appear on
//!   `Entry`, `Group`, and `Meta` alike.
//! - [`entry`] — `Entry` plus its leaf value types (`AutoType`,
//!   `AutoTypeAssociation`, `Attachment`, `CustomField`). The
//!   hand-rolled redacting `Debug` impls for `Entry` and `CustomField`
//!   live here.
//! - [`group`] — `Group` and its recursive walk helpers.
//! - [`vault`] — `Vault` (the root container) plus `DeletedObject`
//!   tombstones and `Binary` payloads.
//! - [`meta`] — `Meta` plus the two value types it owns (`CustomIcon`,
//!   `MemoryProtection`).
//!
//! The pre-existing per-operation modules — [`entry_editor`],
//! [`group_editor`], [`new_entry`], [`new_group`], [`portable`],
//! [`clock`] — are unchanged.
//!
//! Every type is re-exported at this top-level path so existing
//! `use keepass_core::model::Foo;` call sites continue to work
//! unchanged.

pub mod clock;
pub mod entry;
pub mod entry_editor;
pub mod group;
pub mod group_editor;
pub mod meta;
pub mod new_entry;
pub mod new_group;
pub mod portable;
pub mod types;
pub mod uuid_source;
pub mod vault;

pub use clock::{Clock, FixedClock, SystemClock};
pub use uuid_source::{RandomUuids, SeededUuids, UuidSource};
pub use entry::{Attachment, AutoType, AutoTypeAssociation, CustomField, Entry};
pub use entry_editor::{CustomFieldValue, EntryEditor};
pub use group::Group;
pub use group_editor::GroupEditor;
pub use meta::{CustomIcon, MemoryProtection, Meta};
pub use new_entry::NewEntry;
pub use new_group::NewGroup;
pub use portable::PortableEntry;
pub use types::{
    CustomDataItem, EntryId, GroupId, HistoryPolicy, ModelError, Timestamps, UnknownElement,
};
pub use vault::{Binary, DeletedObject, Vault};

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn entry_with(title: &str) -> Entry {
        Entry {
            id: EntryId(Uuid::nil()),
            title: title.to_owned(),
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
            icon_id: 0,
            unknown_xml: Vec::new(),
        }
    }

    fn group_with_name(name: &str) -> Group {
        Group {
            id: GroupId(Uuid::nil()),
            name: name.to_owned(),
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
    fn total_entries_counts_nested() {
        let mut root = group_with_name("root");
        root.entries.push(entry_with("a"));
        let mut child = group_with_name("child");
        child.entries.push(entry_with("b"));
        child.entries.push(entry_with("c"));
        root.groups.push(child);
        assert_eq!(root.total_entries(), 3);
    }

    #[test]
    fn total_subgroups_is_recursive() {
        let mut root = group_with_name("root");
        let mut child = group_with_name("child");
        child.groups.push(group_with_name("grandchild"));
        root.groups.push(child);
        assert_eq!(root.total_subgroups(), 2);
    }

    #[test]
    fn iter_entries_visits_every_entry_once() {
        let mut root = group_with_name("root");
        root.entries.push(entry_with("a"));
        let mut child = group_with_name("child");
        child.entries.push(entry_with("b"));
        root.groups.push(child);
        let titles: Vec<_> = root.iter_entries().map(|e| e.title.clone()).collect();
        assert_eq!(titles, ["a", "b"]);
    }

    #[test]
    fn empty_group_has_zero_counts() {
        let g = group_with_name("empty");
        assert_eq!(g.total_entries(), 0);
        assert_eq!(g.total_subgroups(), 0);
        assert_eq!(g.iter_entries().count(), 0);
    }

    #[test]
    fn entry_empty_has_supplied_id_and_default_else() {
        let id = EntryId(Uuid::from_u128(0x42));
        let e = Entry::empty(id);
        assert_eq!(e.id, id);
        assert!(e.title.is_empty());
        assert!(e.username.is_empty());
        assert!(e.password.is_empty());
        assert!(e.url.is_empty());
        assert!(e.notes.is_empty());
        assert!(e.custom_fields.is_empty());
        assert!(e.tags.is_empty());
        assert!(e.history.is_empty());
        assert!(e.attachments.is_empty());
        assert!(e.custom_data.is_empty());
        assert!(e.unknown_xml.is_empty());
        assert!(e.custom_icon_uuid.is_none());
        assert!(e.previous_parent_group.is_none());
        assert_eq!(e.icon_id, 0);
        assert!(
            e.quality_check,
            "quality_check defaults to KeePass's default of true"
        );
        assert_eq!(e.times, Timestamps::default());
        assert_eq!(e.auto_type, AutoType::default());
    }

    #[test]
    fn group_empty_has_supplied_id_and_default_else() {
        let id = GroupId(Uuid::from_u128(0x99));
        let g = Group::empty(id);
        assert_eq!(g.id, id);
        assert!(g.name.is_empty());
        assert!(g.notes.is_empty());
        assert!(g.groups.is_empty());
        assert!(g.entries.is_empty());
        assert!(
            g.is_expanded,
            "is_expanded defaults to KeePass 2.x's default of true"
        );
        assert!(g.default_auto_type_sequence.is_empty());
        assert!(g.enable_auto_type.is_none());
        assert!(g.enable_searching.is_none());
        assert!(g.custom_data.is_empty());
        assert!(g.previous_parent_group.is_none());
        assert!(g.last_top_visible_entry.is_none());
        assert!(g.custom_icon_uuid.is_none());
        assert_eq!(g.icon_id, 0);
        assert_eq!(g.times, Timestamps::default());
        assert!(g.unknown_xml.is_empty());
    }

    #[test]
    fn vault_empty_has_supplied_root_id_and_defaults() {
        let root_id = GroupId(Uuid::from_u128(0xa));
        let v = Vault::empty(root_id);
        assert_eq!(v.root.id, root_id);
        assert_eq!(v.meta, Meta::default());
        assert!(v.binaries.is_empty());
        assert!(v.deleted_objects.is_empty());
        assert_eq!(v.total_entries(), 0);
    }

    #[test]
    fn custom_field_new_carries_all_three_components() {
        let f = CustomField::new("OTPSecret", "JBSWY3DPEHPK3PXP", true);
        assert_eq!(f.key, "OTPSecret");
        assert_eq!(f.value, "JBSWY3DPEHPK3PXP");
        assert!(f.protected);
    }

    #[test]
    fn deleted_object_new_carries_uuid_and_optional_time() {
        use chrono::TimeZone;
        let id = Uuid::from_u128(0xdead);
        let t = DeletedObject::new(id, None);
        assert_eq!(t.uuid, id);
        assert!(t.deleted_at.is_none());

        let when = chrono::Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        let t2 = DeletedObject::new(id, Some(when));
        assert_eq!(t2.deleted_at, Some(when));
    }

    // -----------------------------------------------------------------------
    // Debug-redaction tests (§4.8.7 — never leak credential material into
    // log/panic output, mirroring `PortableEntry`'s manual `Debug` impl).
    // -----------------------------------------------------------------------

    const SECRET: &str = "hunter2-CORRECT-HORSE-BATTERY-STAPLE";

    #[test]
    fn entry_debug_redacts_password() {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(1)));
        e.password = SECRET.to_owned();
        let rendered = format!("{e:?}");
        assert!(
            !rendered.contains(SECRET),
            "Entry Debug must never surface the password field; got: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "Entry Debug must explicitly mark the redaction; got: {rendered}"
        );
    }

    #[test]
    fn entry_debug_redacts_password_in_history_snapshots() {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(2)));
        let mut prior = Entry::empty(EntryId(Uuid::from_u128(3)));
        prior.password = SECRET.to_owned();
        e.history.push(prior);
        let rendered = format!("{e:?}");
        assert!(
            !rendered.contains(SECRET),
            "history snapshots must redact their passwords too; got: {rendered}"
        );
    }

    #[test]
    fn custom_field_debug_redacts_protected_value() {
        let f = CustomField::new("OTPSecret", SECRET, true);
        let rendered = format!("{f:?}");
        assert!(
            !rendered.contains(SECRET),
            "protected CustomField must redact its value; got: {rendered}"
        );
        assert!(
            rendered.contains("[REDACTED]"),
            "protected CustomField must mark the redaction; got: {rendered}"
        );
    }

    #[test]
    fn custom_field_debug_shows_non_protected_value() {
        let f = CustomField::new("Department", "Engineering", false);
        let rendered = format!("{f:?}");
        assert!(
            rendered.contains("Engineering"),
            "non-protected CustomField values are user-visible metadata and should debug as-is; got: {rendered}"
        );
    }

    #[test]
    fn entry_debug_redacts_protected_custom_field_via_cascade() {
        let mut e = Entry::empty(EntryId(Uuid::from_u128(4)));
        e.custom_fields
            .push(CustomField::new("OTPSecret", SECRET, true));
        let rendered = format!("{e:?}");
        assert!(
            !rendered.contains(SECRET),
            "Entry Debug must transitively redact protected custom fields via CustomField's impl; got: {rendered}"
        );
    }

    #[test]
    fn group_debug_redacts_nested_entry_password() {
        let mut g = group_with_name("Personal");
        let mut e = Entry::empty(EntryId(Uuid::from_u128(5)));
        e.password = SECRET.to_owned();
        g.entries.push(e);
        let rendered = format!("{g:?}");
        assert!(
            !rendered.contains(SECRET),
            "Group derives Debug, but its entries must use the redacted Entry impl; got: {rendered}"
        );
    }

    #[test]
    fn vault_debug_redacts_deeply_nested_entry_password() {
        let mut v = Vault::empty(GroupId(Uuid::from_u128(6)));
        let mut child = group_with_name("Banking");
        let mut e = Entry::empty(EntryId(Uuid::from_u128(7)));
        e.password = SECRET.to_owned();
        child.entries.push(e);
        v.root.groups.push(child);
        let rendered = format!("{v:?}");
        assert!(
            !rendered.contains(SECRET),
            "Vault Debug must redact passwords at any nesting depth; got: {rendered}"
        );
    }
}
