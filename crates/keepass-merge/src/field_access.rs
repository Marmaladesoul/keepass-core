//! Single source of truth for addressing an entry's fields *by KDBX name*.
//!
//! A KDBX entry stores five "standard" string fields — `Title`,
//! `UserName`, `Password`, `URL`, `Notes` — as named struct slots, and
//! everything else as keyed [`CustomField`]s. Merge classification,
//! content hashing, and conflict-apply all need to read a field by name,
//! clear it, or copy it from another entry, without pre-classifying it as
//! standard or custom.
//!
//! The name→slot mapping is therefore easy to duplicate: it previously
//! lived in several match statements across the classifier, the hasher,
//! and the apply layer, alongside two independent copies of the
//! standard-field name list. Adding a standard field, or changing one's
//! semantics (e.g. the `protected` bit), then meant editing every copy —
//! and missing one silently diverged the merge classifier from the
//! content hash its conflict detection depends on. The mapping lives here
//! now, declared once.

use keepass_core::model::{CustomField, Entry};

/// Canonical KDBX names of the standard string fields, in KDBX XML order.
/// The single source of truth for "which fields are standard"; every
/// name→slot accessor below matches exactly this set.
pub(crate) const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// Immutable slot for standard field `name`, or `None` if `name` is not a
/// standard field (i.e. it names a custom field or is otherwise unknown).
fn standard_slot<'a>(entry: &'a Entry, name: &str) -> Option<&'a String> {
    match name {
        "Title" => Some(&entry.title),
        "UserName" => Some(&entry.username),
        "Password" => Some(&entry.password),
        "URL" => Some(&entry.url),
        "Notes" => Some(&entry.notes),
        _ => None,
    }
}

/// Mutable slot for standard field `name`, or `None` if `name` is not a
/// standard field. Companion to [`standard_slot`]; these two matches are
/// the only place the standard-field name→slot mapping is written down.
fn standard_slot_mut<'a>(entry: &'a mut Entry, name: &str) -> Option<&'a mut String> {
    match name {
        "Title" => Some(&mut entry.title),
        "UserName" => Some(&mut entry.username),
        "Password" => Some(&mut entry.password),
        "URL" => Some(&mut entry.url),
        "Notes" => Some(&mut entry.notes),
        _ => None,
    }
}

/// Read standard field `name`. `name` must be one of [`STANDARD_FIELDS`]
/// (callers iterate that list); a non-standard name is a program error.
pub(crate) fn standard_value<'a>(entry: &'a Entry, name: &str) -> &'a str {
    match standard_slot(entry, name) {
        Some(slot) => slot.as_str(),
        None => unreachable!("STANDARD_FIELDS is fixed"),
    }
}

/// Copy field `key`'s value from `source` into `target` — a standard
/// field slot, a custom field (value + `protected` bit), or removal of a
/// custom field `source` no longer holds. Standard and custom keys are
/// handled the same way from the caller's side: it doesn't pre-classify.
pub(crate) fn copy_field(target: &mut Entry, source: &Entry, key: &str) {
    // `key` is standard for `target` iff it's standard for `source` (same
    // field set), so the `Some`/`None` sides always agree; `_` is the
    // custom path.
    match (standard_slot_mut(target, key), standard_slot(source, key)) {
        (Some(dst), Some(src)) => dst.clone_from(src),
        _ => copy_custom_field(target, source, key),
    }
}

/// Custom-field arm of [`copy_field`]: mirror `source`'s custom field
/// `key` into `target` — update in place, insert if absent, or remove
/// when `source` no longer holds it.
fn copy_custom_field(target: &mut Entry, source: &Entry, key: &str) {
    match source.custom_fields.iter().find(|f| f.key == key) {
        Some(src) => match target.custom_fields.iter_mut().find(|f| f.key == key) {
            Some(dst) => {
                dst.value.clone_from(&src.value);
                dst.protected = src.protected;
            }
            None => target.custom_fields.push(CustomField::new(
                src.key.clone(),
                src.value.clone(),
                src.protected,
            )),
        },
        None => target.custom_fields.retain(|f| f.key != key),
    }
}

/// Clear field `key`: empty a standard field slot in place, or drop the
/// custom field entirely.
pub(crate) fn remove_field(entry: &mut Entry, key: &str) {
    match standard_slot_mut(entry, key) {
        Some(slot) => slot.clear(),
        None => entry.custom_fields.retain(|f| f.key != key),
    }
}
