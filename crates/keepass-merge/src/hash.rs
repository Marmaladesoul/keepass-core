//! Content hashing for entry-level LCA matching.
//!
//! [`entry_content_hash`] produces a SHA-256 over a canonical,
//! length-prefixed bytestream of an entry's standard fields plus its
//! sorted custom fields. The hash is used by the history-LCA walker to
//! disambiguate two history records that share a `last_modification_time`
//! — see [`crate::entry_merge`].
//!
//! Stability contract: reflexive within a single process run. Hash
//! values are not stable across `keepass-merge` releases or across
//! KeePass implementations; do not persist them.
//!
//! Notable scope choices for v0.1 (mirroring the merge-comparator
//! itself):
//!
//! - Standard fields (`Title`, `UserName`, `Password`, `URL`, `Notes`)
//!   are hashed by their canonical KDBX names with `protected = 0`.
//! - Custom fields are hashed in stable-sort order by `key`. Duplicate
//!   keys (illegal per KDBX, but the upstream model does not enforce
//!   uniqueness) hash in stable-sort encounter order; the merge crate
//!   does not normalise.
//! - `tags`, `attachments`, `auto_type`, `unknown_xml`, and timestamps
//!   are *not* part of the content hash. The merge surface treats them
//!   as ride-along state per the v0.1 spec.

use keepass_core::model::Entry;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Canonical KDBX names of the standard string fields. The order here
/// is irrelevant — the hash sorts by name — but matching the KDBX XML
/// names keeps the canonicalisation human-recognisable.
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// Hash an entry's content for LCA matching. See module docs for scope.
pub(crate) fn entry_content_hash(entry: &Entry) -> [u8; 32] {
    // Collect (key, value, protected) tuples for every field, then
    // stable-sort by key so reordered custom_fields hash identically.
    let standard = STANDARD_FIELDS.iter().map(|name| {
        let value = match *name {
            "Title" => entry.title.as_str(),
            "UserName" => entry.username.as_str(),
            "Password" => entry.password.as_str(),
            "URL" => entry.url.as_str(),
            "Notes" => entry.notes.as_str(),
            _ => unreachable!("STANDARD_FIELDS is fixed"),
        };
        (*name, value, false)
    });
    let custom = entry
        .custom_fields
        .iter()
        .map(|f| (f.key.as_str(), f.value.as_str(), f.protected));

    let mut all: Vec<(&str, &str, bool)> = standard.chain(custom).collect();
    all.sort_by(|a, b| a.0.cmp(b.0));

    let mut hasher = Sha256::new();
    for (key, value, protected) in all {
        write_len_prefixed(&mut hasher, key.as_bytes());
        write_len_prefixed(&mut hasher, value.as_bytes());
        hasher.update([u8::from(protected)]);
    }
    hasher.finalize().into()
}

/// Length-prefix and write a byte slice into the hasher. Length goes in
/// as `u32` little-endian; we `debug_assert!` it fits — a single field
/// over 4 GiB is implausible for a password-manager record but the
/// assertion costs nothing and surfaces the bug if `value` ever holds
/// something it shouldn't.
fn write_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    debug_assert!(
        u32::try_from(bytes.len()).is_ok(),
        "field bytes exceed u32::MAX — refusing to truncate length prefix",
    );
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u32;
    hasher.update(len.to_le_bytes());
    hasher.update(bytes);
}

/// Constant-time compare of two SHA-256 digests. Inputs aren't secret
/// in this crate, but the workspace-wide rule (AGENTS.md) is to use
/// constant-time on every hash compare regardless.
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, entry_content_hash};
    use keepass_core::model::{CustomField, Entry, EntryId};
    use uuid::Uuid;

    fn entry() -> Entry {
        Entry::empty(EntryId(Uuid::nil()))
    }

    #[test]
    fn reflexive() {
        let mut e = entry();
        e.title = "Hello".into();
        assert_eq!(entry_content_hash(&e), entry_content_hash(&e));
    }

    #[test]
    fn custom_field_order_does_not_matter() {
        let mut a = entry();
        a.custom_fields = vec![
            CustomField::new("alpha", "1", false),
            CustomField::new("beta", "2", true),
        ];
        let mut b = entry();
        b.custom_fields = vec![
            CustomField::new("beta", "2", true),
            CustomField::new("alpha", "1", false),
        ];
        assert!(ct_eq(&entry_content_hash(&a), &entry_content_hash(&b)));
    }

    #[test]
    fn protected_flag_changes_hash() {
        let mut a = entry();
        a.custom_fields = vec![CustomField::new("x", "v", false)];
        let mut b = a.clone();
        b.custom_fields[0].protected = true;
        assert_ne!(entry_content_hash(&a), entry_content_hash(&b));
    }

    #[test]
    fn standard_field_change_changes_hash() {
        let a = entry();
        let mut b = entry();
        b.title = "different".into();
        assert_ne!(entry_content_hash(&a), entry_content_hash(&b));
    }

    #[test]
    fn tags_are_excluded_from_hash() {
        let a = entry();
        let mut b = entry();
        b.tags = vec!["work".into(), "important".into()];
        assert_eq!(entry_content_hash(&a), entry_content_hash(&b));
    }
}
