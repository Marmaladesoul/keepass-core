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
//! Scope (slice B5 expanded; see `_localdocs/MERGE_CONTENT_HASH_SCOPE.md`):
//!
//! - Standard string fields (`Title`, `UserName`, `Password`, `URL`,
//!   `Notes`) hashed by their canonical KDBX names with
//!   `protected = 0`.
//! - Custom fields hashed in stable-sort order by `key`. Duplicate
//!   keys (illegal per KDBX, but the upstream model does not enforce
//!   uniqueness) hash in encounter order; the merge crate does not
//!   normalise.
//! - **Attachments**: hashed in stable-sort order by name. Each
//!   attachment contributes `(name, sha256(payload), protected_flag)`.
//!   Duplicate names use first occurrence (matching the classifier's
//!   convention). Out-of-bounds `ref_id` values are skipped (also
//!   matching the classifier's posture — corrupt refs don't fail the
//!   hash, they just don't contribute).
//! - **Icon**: `(icon_id, custom_icon_uuid)` contributes a single
//!   tuple to the hash. The custom-icon UUID is the user-visible
//!   discriminator; the base icon ID rides for round-trip fidelity.
//! - **Tags**: alphabetised list contributes as one length-prefixed
//!   block. KDBX writers don't normalise tag order on disk; sorting
//!   makes the hash invariant under writer order.
//!
//! Still excluded — pure ride-along, not surfaced in any conflict UI:
//! `auto_type`, `unknown_xml`, and timestamps (the `mtime` half of
//! the LCA key is matched separately).

use keepass_core::model::{Binary, Entry};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Canonical KDBX names of the standard string fields. The order here
/// is irrelevant — the hash sorts by name — but matching the KDBX XML
/// names keeps the canonicalisation human-recognisable.
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// Domain tags written into the hasher before each section so that
/// the byte streams for attachments / icon / tags can't collide with
/// the field stream by accident. Single bytes are enough — there are
/// only a handful of sections.
const SECTION_FIELDS: u8 = 0x01;
const SECTION_ATTACHMENTS: u8 = 0x02;
const SECTION_ICON: u8 = 0x03;
const SECTION_TAGS: u8 = 0x04;

/// Hash an entry's content for LCA matching. See module docs for scope.
///
/// `binaries` is the binary pool of the vault the entry came from —
/// used to dereference `Attachment::ref_id` into the SHA-256 of the
/// payload. Pass `&local.binaries` for local-side entries (current
/// and history) and `&remote.binaries` for remote-side entries; the
/// LCA walker handles the per-side dispatch.
pub(crate) fn entry_content_hash(entry: &Entry, binaries: &[Binary]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // Section 1: fields (standard + custom).
    hasher.update([SECTION_FIELDS]);
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
    let mut fields: Vec<(&str, &str, bool)> = standard.chain(custom).collect();
    fields.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value, protected) in fields {
        write_len_prefixed(&mut hasher, key.as_bytes());
        write_len_prefixed(&mut hasher, value.as_bytes());
        hasher.update([u8::from(protected)]);
    }

    // Section 2: attachments. First occurrence per name wins (matches
    // the classifier's dedup); out-of-bounds ref_ids are skipped.
    hasher.update([SECTION_ATTACHMENTS]);
    let mut atts: Vec<(&str, [u8; 32], bool)> = Vec::with_capacity(entry.attachments.len());
    let mut seen_names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for att in &entry.attachments {
        if !seen_names.insert(att.name.as_str()) {
            continue;
        }
        let Some(bin) = binaries.get(att.ref_id as usize) else {
            // Corrupt ref — skip; the classifier treats it as absent
            // on this side, so the hash should too.
            continue;
        };
        let mut bh = Sha256::new();
        bh.update(&bin.data);
        let sha: [u8; 32] = bh.finalize().into();
        atts.push((att.name.as_str(), sha, bin.protected));
    }
    atts.sort_by(|a, b| a.0.cmp(b.0));
    for (name, sha, protected) in atts {
        write_len_prefixed(&mut hasher, name.as_bytes());
        hasher.update(sha);
        hasher.update([u8::from(protected)]);
    }

    // Section 3: icon. Custom-icon UUID is the user-visible
    // discriminator; base icon ID rides for round-trip fidelity.
    hasher.update([SECTION_ICON]);
    hasher.update(entry.icon_id.to_le_bytes());
    match entry.custom_icon_uuid {
        Some(uuid) => {
            hasher.update([1u8]); // present marker
            hasher.update(uuid.as_bytes());
        }
        None => hasher.update([0u8]),
    }

    // Section 4: tags, alphabetised so writer order doesn't change
    // the hash.
    hasher.update([SECTION_TAGS]);
    let mut sorted_tags: Vec<&str> = entry.tags.iter().map(String::as_str).collect();
    sorted_tags.sort_unstable();
    for tag in sorted_tags {
        write_len_prefixed(&mut hasher, tag.as_bytes());
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
    use keepass_core::model::{Attachment, Binary, CustomField, Entry, EntryId};
    use uuid::Uuid;

    fn entry() -> Entry {
        Entry::empty(EntryId(Uuid::nil()))
    }

    fn no_binaries() -> Vec<Binary> {
        Vec::new()
    }

    #[test]
    fn reflexive() {
        let mut e = entry();
        e.title = "Hello".into();
        let bins = no_binaries();
        assert_eq!(entry_content_hash(&e, &bins), entry_content_hash(&e, &bins));
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
        let bins = no_binaries();
        assert!(ct_eq(
            &entry_content_hash(&a, &bins),
            &entry_content_hash(&b, &bins),
        ));
    }

    #[test]
    fn protected_flag_changes_hash() {
        let mut a = entry();
        a.custom_fields = vec![CustomField::new("x", "v", false)];
        let mut b = a.clone();
        b.custom_fields[0].protected = true;
        let bins = no_binaries();
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn standard_field_change_changes_hash() {
        let a = entry();
        let mut b = entry();
        b.title = "different".into();
        let bins = no_binaries();
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    // ----- Slice B5: tags, attachments, icon now hashed -----

    #[test]
    fn tags_change_hash() {
        let a = entry();
        let mut b = entry();
        b.tags = vec!["work".into(), "important".into()];
        let bins = no_binaries();
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn tag_order_does_not_matter() {
        let mut a = entry();
        a.tags = vec!["alpha".into(), "beta".into(), "gamma".into()];
        let mut b = entry();
        b.tags = vec!["gamma".into(), "alpha".into(), "beta".into()];
        let bins = no_binaries();
        assert!(ct_eq(
            &entry_content_hash(&a, &bins),
            &entry_content_hash(&b, &bins),
        ));
    }

    #[test]
    fn attachment_payload_change_changes_hash() {
        let mut a = entry();
        a.attachments = vec![Attachment::new("note.txt", 0)];
        let bins_a = vec![Binary::new(b"v1".to_vec(), false)];

        let mut b = entry();
        b.attachments = vec![Attachment::new("note.txt", 0)];
        let bins_b = vec![Binary::new(b"v2".to_vec(), false)];

        assert_ne!(
            entry_content_hash(&a, &bins_a),
            entry_content_hash(&b, &bins_b),
        );
    }

    #[test]
    fn attachment_name_change_changes_hash() {
        let mut a = entry();
        a.attachments = vec![Attachment::new("a.txt", 0)];
        let mut b = entry();
        b.attachments = vec![Attachment::new("b.txt", 0)];
        let bins = vec![Binary::new(b"same".to_vec(), false)];
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn attachment_order_does_not_matter() {
        let mut a = entry();
        a.attachments = vec![Attachment::new("a.txt", 0), Attachment::new("b.txt", 1)];
        let mut b = entry();
        b.attachments = vec![Attachment::new("b.txt", 1), Attachment::new("a.txt", 0)];
        let bins = vec![
            Binary::new(b"contents-a".to_vec(), false),
            Binary::new(b"contents-b".to_vec(), false),
        ];
        assert!(ct_eq(
            &entry_content_hash(&a, &bins),
            &entry_content_hash(&b, &bins),
        ));
    }

    #[test]
    fn attachment_protected_flag_changes_hash() {
        let mut a = entry();
        a.attachments = vec![Attachment::new("x", 0)];
        let mut b = entry();
        b.attachments = vec![Attachment::new("x", 0)];
        let bins_a = vec![Binary::new(b"same".to_vec(), false)];
        let bins_b = vec![Binary::new(b"same".to_vec(), true)];
        assert_ne!(
            entry_content_hash(&a, &bins_a),
            entry_content_hash(&b, &bins_b),
        );
    }

    #[test]
    fn out_of_bounds_attachment_ref_is_skipped() {
        // Matches the classifier's posture: corrupt ref doesn't fail
        // the hash, it just doesn't contribute. The skipped entry
        // hashes the same as an entry that doesn't have that
        // attachment at all.
        let mut a = entry();
        a.attachments = vec![Attachment::new("ghost", 99)];
        let b = entry();
        let bins = no_binaries();
        assert_eq!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn icon_id_change_changes_hash() {
        let a = entry();
        let mut b = entry();
        b.icon_id = 42;
        let bins = no_binaries();
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn custom_icon_uuid_change_changes_hash() {
        let a = entry();
        let mut b = entry();
        b.custom_icon_uuid = Some(Uuid::from_u128(0xabcd_ef01));
        let bins = no_binaries();
        assert_ne!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }

    #[test]
    fn auto_type_change_does_not_affect_hash() {
        // Confirms `auto_type` stays ride-along.
        let a = entry();
        let mut b = entry();
        b.auto_type.enabled = !a.auto_type.enabled;
        let bins = no_binaries();
        assert_eq!(entry_content_hash(&a, &bins), entry_content_hash(&b, &bins),);
    }
}
