//! `Meta` — the contents of the KeePass `<Meta>` block — and the two
//! value types it owns: `CustomIcon` (icon-pool entries) and
//! `MemoryProtection` (per-field "keep this masked" UI hints).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{CustomDataItem, GroupId, UnknownElement};

/// Contents of the KeePass `<Meta>` element.
///
/// Only fields present in the on-disk XML populate here; every field
/// is either a string (possibly empty) or an `Option`, so a minimal
/// document with just `<Generator>` round-trips cleanly.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Meta {
    /// `<Generator>` — identifies the writer (e.g. `"KeePassXC"`,
    /// `"KdbxWeb"`). Diagnostic only.
    pub generator: String,
    /// `<DatabaseName>` — user-visible vault name.
    pub database_name: String,
    /// `<DatabaseDescription>` — user-visible free-text description.
    pub database_description: String,
    /// `<DatabaseNameChanged>` — last time the name was edited.
    pub database_name_changed: Option<chrono::DateTime<Utc>>,
    /// `<DatabaseDescriptionChanged>` — last time the description was
    /// edited.
    pub database_description_changed: Option<chrono::DateTime<Utc>>,
    /// `<DefaultUserName>` — default username for new entries.
    pub default_username: String,
    /// `<DefaultUserNameChanged>` — last time the default username
    /// was edited.
    pub default_username_changed: Option<chrono::DateTime<Utc>>,
    /// `<RecycleBinEnabled>` — whether soft-delete is wired up. When
    /// true and [`Self::recycle_bin_uuid`] points to an existing
    /// group, KeePass writers move deleted entries into that group
    /// instead of removing them. Absent elements are treated as
    /// `false`.
    pub recycle_bin_enabled: bool,
    /// `<RecycleBinUUID>` — the [`GroupId`] of the recycle-bin
    /// group, or `None` if the document lists no recycle bin.
    /// Writers sometimes emit an all-zero UUID to mean "no recycle
    /// bin", which we surface as `None` for symmetry with the
    /// explicitly-absent case.
    pub recycle_bin_uuid: Option<GroupId>,
    /// `<RecycleBinChanged>` — last time the recycle-bin
    /// configuration was edited.
    pub recycle_bin_changed: Option<chrono::DateTime<Utc>>,
    /// `<MemoryProtection>` — which canonical entry fields the writer
    /// marks as in-memory-protected in the host KeePass client.
    /// Semantic hint only; entry-level `Protected` XML attributes are
    /// what actually matter on disk.
    pub memory_protection: MemoryProtection,
    /// `<CustomData>` — free-form key/value entries used by plugins
    /// and client-specific settings. Preserved verbatim for round-trip
    /// so writers that don't know a particular key don't drop it.
    pub custom_data: Vec<CustomDataItem>,
    /// `<SettingsChanged>` — last time any `<Meta>` setting was edited.
    /// Distinct from the per-field `*Changed` timestamps.
    pub settings_changed: Option<DateTime<Utc>>,
    /// `<MasterKeyChanged>` — last time the master key was replaced.
    /// Used by the recommendation / force policies below.
    pub master_key_changed: Option<DateTime<Utc>>,
    /// `<MasterKeyChangeRec>` — number of days between recommended
    /// master-key changes. `-1` disables the recommendation.
    pub master_key_change_rec: i64,
    /// `<MasterKeyChangeForce>` — number of days after which the
    /// client forces a master-key change. `-1` disables.
    pub master_key_change_force: i64,
    /// `<HistoryMaxItems>` — cap on entry-history length.
    /// `-1` means unlimited.
    pub history_max_items: i32,
    /// `<HistoryMaxSize>` — cap on entry-history byte size.
    /// `-1` means unlimited.
    pub history_max_size: i64,
    /// `<MaintenanceHistoryDays>` — how long to keep entry snapshots
    /// before the client prunes them.
    pub maintenance_history_days: u32,
    /// `<CustomIcons>` — pool of custom entry / group icons,
    /// referenced by [`super::Entry::custom_icon_uuid`] and
    /// [`super::Group::custom_icon_uuid`]. Each icon carries its own UUID
    /// plus the decoded image bytes.
    pub custom_icons: Vec<CustomIcon>,
    /// `<Color>` — hex colour (e.g. `"#FF0000"`) used by KeePass 2.x
    /// clients as the vault-level colour swatch. Empty when the
    /// vault uses the client's default colour.
    pub color: String,
    /// `<HeaderHash>` — SHA-256 of the outer header, written into
    /// KDBX3 inner XML as a belt-and-braces integrity check. KDBX4
    /// moves this to the binary header (`verify_header_hash`) and
    /// doesn't emit the XML element. Preserved verbatim as the
    /// base64-encoded string for lossless round-trip — we don't
    /// re-verify it here.
    pub header_hash: String,
    /// Unknown XML children on `<Meta>` preserved verbatim for
    /// round-trip — see [`super::Entry::unknown_xml`] for the full semantics.
    pub unknown_xml: Vec<UnknownElement>,
}

impl Default for Meta {
    fn default() -> Self {
        // Values mirror KeePass 2.x's stock defaults where relevant,
        // so a `Meta::default()` round-trips cleanly back through the
        // writer without spurious diff churn.
        Self {
            generator: String::new(),
            database_name: String::new(),
            database_description: String::new(),
            database_name_changed: None,
            database_description_changed: None,
            default_username: String::new(),
            default_username_changed: None,
            recycle_bin_enabled: false,
            recycle_bin_uuid: None,
            recycle_bin_changed: None,
            memory_protection: MemoryProtection::default(),
            custom_data: Vec::new(),
            settings_changed: None,
            master_key_changed: None,
            master_key_change_rec: -1,
            master_key_change_force: -1,
            history_max_items: 10,
            history_max_size: 6 * 1024 * 1024,
            maintenance_history_days: 365,
            custom_icons: Vec::new(),
            color: String::new(),
            header_hash: String::new(),
            unknown_xml: Vec::new(),
        }
    }
}

/// One icon in the vault's [`Meta::custom_icons`] pool.
///
/// KeePass stores custom icons as a base64-encoded image payload
/// (typically PNG, but the format doesn't constrain — a consumer is
/// free to hand the bytes to an image decoder and see what happens).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CustomIcon {
    /// Identifier referenced by [`super::Entry::custom_icon_uuid`].
    pub uuid: Uuid,
    /// Decoded image bytes, typically PNG.
    pub data: Vec<u8>,
    /// `<Name>` — optional human-readable label. Empty for icons
    /// that carry no name.
    pub name: String,
    /// `<LastModificationTime>` — when the icon was last edited.
    /// Many KDBX3 writers omit this element.
    pub last_modified: Option<DateTime<Utc>>,
}

impl CustomIcon {
    /// Construct a [`CustomIcon`] from its required fields.
    ///
    /// Intended for in-memory model construction (test fixtures,
    /// format converters, downstream merge / diff crates). Newly-added
    /// fields default to whatever [`Default`] would produce; this
    /// constructor's behaviour is therefore stable across additions —
    /// the natural companion to the type's `#[non_exhaustive]` marker.
    #[must_use]
    pub fn new(
        uuid: Uuid,
        data: Vec<u8>,
        name: String,
        last_modified: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            uuid,
            data,
            name,
            last_modified,
        }
    }
}

/// `<MemoryProtection>` flags — whether a given canonical entry
/// field should be kept in protected memory by the host KeePass
/// client (masked on screen, stored in a SecureString, etc.).
///
/// These are UI/memory-hygiene hints, **not** an on-disk encryption
/// signal. The actual "protect this value's bytes with the
/// inner-stream cipher" signal is the per-value `Protected="True"`
/// XML attribute on individual `<Value>` elements.
///
/// Defaults reflect the KeePass 2.x convention: only the Password
/// field is protected by default. Missing `<MemoryProtection>`
/// blocks in the XML round-trip to this default.
// The five booleans are dictated by the KeePass spec (one per canonical
// entry field), so collapsing into a bitflags or enum-set would just add
// indirection without meaningful benefit.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemoryProtection {
    /// `<ProtectTitle>` — default `false`.
    pub protect_title: bool,
    /// `<ProtectUserName>` — default `false`.
    pub protect_username: bool,
    /// `<ProtectPassword>` — default `true`.
    pub protect_password: bool,
    /// `<ProtectURL>` — default `false`.
    pub protect_url: bool,
    /// `<ProtectNotes>` — default `false`.
    pub protect_notes: bool,
}

impl Default for MemoryProtection {
    fn default() -> Self {
        Self {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        }
    }
}
