//! Self-contained entry snapshot for cross-vault export / import.
//!
//! [`PortableEntry`] is the opaque carrier returned by
//! [`crate::kdbx::Kdbx::export_entry`] and consumed by
//! [`crate::kdbx::Kdbx::import_entry`]. It contains the entry, every
//! one of its history snapshots, the full decrypted bytes of every
//! referenced binary attachment, and every referenced [`CustomIcon`]
//! — enough state that the destination vault doesn't need to share
//! the source's binary or custom-icon pools.
//!
//! Callers don't inspect the carrier. They pass it from source to
//! destination, the destination deduplicates against its own pools,
//! and the public shape is purely `source.export_entry(id)` →
//! `destination.import_entry(parent, portable, mint_new_uuid)`.
//!
//! The type is `#[non_exhaustive]`; all fields are `pub(crate)` and
//! reachable only from inside the crate — integration tests that
//! genuinely need to introspect do so under `#[cfg(test)]
//! pub(crate)` accessors defined at the bottom of this module.

use super::{Binary, CustomIcon, Entry};

/// A self-contained snapshot of an entry suitable for importing into
/// a different (or the same) vault.
///
/// Opaque on the public surface — construct via
/// [`crate::kdbx::Kdbx::export_entry`], pass to
/// [`crate::kdbx::Kdbx::import_entry`], don't inspect in between.
///
/// `#[non_exhaustive]` so future fields (e.g. serialisation
/// versioning, referenced entry templates, external-cipher metadata)
/// can land without a semver break.
#[non_exhaustive]
pub struct PortableEntry {
    /// The entry itself, including `history`. Attachment `ref_id`s
    /// inside `entry` and `entry.history[..]` are **source-vault
    /// indexes** — they're only meaningful alongside
    /// [`Self::binaries`] below, and are remapped to destination
    /// indexes at import time.
    pub(crate) entry: Entry,
    /// Payload for every binary referenced by `entry` **or** any
    /// history snapshot's `attachments`, keyed by the source vault's
    /// `ref_id`. Stored as a sorted `Vec` rather than a `HashMap`
    /// because N is small (typically ≤ a handful per entry) and the
    /// linear scan beats hashing at that size.
    pub(crate) binaries: Vec<(u32, Binary)>,
    /// Every custom icon referenced by `entry` **or** any history
    /// snapshot's `custom_icon_uuid`. Carried as the full
    /// [`CustomIcon`] so UUID + bytes + name + last_modified all
    /// travel together. Destination dedups by UUID or by content
    /// hash depending on `mint_new_uuid`.
    pub(crate) custom_icons: Vec<CustomIcon>,
}

/// Manual `Debug` impl: redact the entry's password field and every
/// protected custom-field value, elide binary payload bytes down to
/// a length summary, and elide custom-icon bytes ditto.
///
/// A derived `#[derive(Debug)]` would dump plaintext passwords into
/// any panic message or log line that touches a `PortableEntry`;
/// the redaction discipline here matches what the other secret-
/// bearing types in the crate (e.g. `SecretString`) already do.
impl std::fmt::Debug for PortableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            entry,
            binaries,
            custom_icons,
        } = self;
        f.debug_struct("PortableEntry")
            .field("entry.id", &entry.id)
            .field("entry.title", &entry.title)
            .field("entry.username", &entry.username)
            .field("entry.password", &"[REDACTED]")
            .field("entry.url", &entry.url)
            .field("entry.history_len", &entry.history.len())
            .field("entry.attachments_len", &entry.attachments.len())
            .field("entry.custom_icon_uuid", &entry.custom_icon_uuid)
            .field("entry.unknown_xml_len", &entry.unknown_xml.len())
            .field(
                "binaries",
                &binaries
                    .iter()
                    .map(|(id, b)| (id, b.data.len(), b.protected))
                    .collect::<Vec<_>>(),
            )
            .field(
                "custom_icons",
                &custom_icons
                    .iter()
                    .map(|c| (c.uuid, c.data.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

// Test-only `pub(crate)` accessors intentionally omitted: the
// current slice-6 test suite verifies end-to-end via the imported
// entry in the destination vault (the way Keys will actually
// consume the API), so peeking inside the in-flight carrier isn't
// needed yet. Add `entry_for_test` / `binaries_for_test` /
// `custom_icons_for_test` here `#[cfg(test)] pub(crate)` if a
// future test genuinely needs to introspect.
