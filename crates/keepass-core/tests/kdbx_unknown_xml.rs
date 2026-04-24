//! Round-trip preservation of unknown XML children on `<Entry>`,
//! `<Group>`, and `<Meta>`.
//!
//! A future KeePass client (or a third-party writer) may emit elements
//! this library doesn't know about. The decoder captures each such
//! subtree as an [`UnknownElement`] under the parent's `unknown_xml`
//! field; the encoder re-emits them at the end of the parent's
//! canonical children on save. These tests prove the loop closes for:
//!
//! 1. parse → save → reparse — an untouched fixture round-trips.
//! 2. parse → edit-unrelated-field → save → reparse — a mutation on a
//!    canonical field does not clobber any sibling unknown child.
//!
//! Fidelity contract: structural equality, not byte equality. We
//! assert the captured element's tag and that its serialised payload
//! contains the original text content. See
//! `tests/fixtures/generate.py::gen_pykeepass_unknown_xml` for the
//! fixture construction.

use std::path::{Path, PathBuf};

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{HistoryPolicy, UnknownElement};
use secrecy::SecretString;

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures/pykeepass/unknown-xml.kdbx")
}

const FIXTURE_PASSWORD: &str = "test-unknown-106";

fn open_fixture() -> Kdbx<Unlocked> {
    let path = fixture_path();
    let composite = CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes());
    Kdbx::<Sealed>::open(&path)
        .expect("open fixture")
        .read_header()
        .expect("read header")
        .unlock(&composite)
        .expect("unlock")
}

fn reopen(bytes: Vec<u8>) -> Kdbx<Unlocked> {
    let composite = CompositeKey::from_password(FIXTURE_PASSWORD.as_bytes());
    Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("re-open")
        .read_header()
        .expect("re-read header")
        .unlock(&composite)
        .expect("re-unlock")
}

/// Structural equivalent of "the fragment preserves this tag and this
/// text content". Byte-level comparison would fail on quick-xml's
/// attribute-whitespace and empty-shorthand normalisation.
fn assert_captured(unknowns: &[UnknownElement], tag: &str, text: &str) {
    let hit = unknowns
        .iter()
        .find(|u| u.tag == tag)
        .unwrap_or_else(|| panic!("unknown element <{tag}> not captured; got {unknowns:?}"));
    let xml = std::str::from_utf8(&hit.raw_xml).expect("captured XML is UTF-8");
    assert!(
        xml.contains(&format!("<{tag}")),
        "fragment missing <{tag} in its serialised form: {xml:?}"
    );
    assert!(
        xml.contains(text),
        "fragment missing expected text {text:?}: {xml:?}"
    );
    assert!(
        xml.contains(&format!("</{tag}>")),
        "fragment missing closing </{tag}>: {xml:?}"
    );
}

fn assert_fixture_shape(kdbx: &Kdbx<Unlocked>) {
    let vault = kdbx.vault();
    assert_captured(&vault.meta.unknown_xml, "FuturePolicy", "strict");
    assert_captured(&vault.root.unknown_xml, "FutureGroupFlag", "yes");
    let entry = vault
        .iter_entries()
        .next()
        .expect("fixture has at least one entry");
    assert_captured(&entry.unknown_xml, "FutureEntryHint", "payload");
    // Attribute preserved too — structural assertion on the serialised
    // form, since quick-xml may have normalised quoting.
    let xml = std::str::from_utf8(&entry.unknown_xml[0].raw_xml).unwrap();
    assert!(
        xml.contains("attr=\"x\"") || xml.contains("attr='x'"),
        "FutureEntryHint lost its attr=\"x\": {xml}"
    );
}

#[test]
fn unknown_children_round_trip_through_parse_save_reparse() {
    let kdbx = open_fixture();
    assert_fixture_shape(&kdbx);

    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = reopen(bytes);
    assert_fixture_shape(&reopened);
}

#[test]
fn unknown_children_survive_edit_entry_on_canonical_field() {
    let mut kdbx = open_fixture();
    let entry_id = kdbx
        .vault()
        .iter_entries()
        .next()
        .expect("fixture entry")
        .id;

    kdbx.edit_entry(entry_id, HistoryPolicy::NoSnapshot, |e| {
        // Canonical field mutation; unknown_xml must survive.
        e.set_password(SecretString::from("rotated-password"));
    })
    .expect("edit_entry");

    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = reopen(bytes);
    assert_fixture_shape(&reopened);

    // And the canonical edit actually applied.
    let entry = reopened.vault().iter_entries().next().unwrap();
    assert_eq!(entry.password, "rotated-password");
}

#[test]
fn unknown_children_survive_edit_group_on_canonical_field() {
    let mut kdbx = open_fixture();
    let root_id = kdbx.vault().root.id;

    kdbx.edit_group(root_id, |g| {
        g.set_notes("re-noted by the test");
    })
    .expect("edit_group");

    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = reopen(bytes);
    assert_fixture_shape(&reopened);

    assert_eq!(reopened.vault().root.notes, "re-noted by the test");
}

#[test]
fn unknown_children_survive_snapshot_edit_on_both_live_and_history() {
    // Under HistoryPolicy::Snapshot, the library clones the live
    // entry into `entry.history` *before* the edit closure runs.
    // That snapshot is a full `Entry` — `unknown_xml` included — so
    // the captured foreign children must travel with it. The live
    // entry then runs the closure and must keep its own
    // `unknown_xml` untouched.
    //
    // FFI_PHASE1 confirmation checklist flags this exact path as
    // needing coverage; the other integration tests here all use
    // NoSnapshot, which never exercises the Clone.
    let mut kdbx = open_fixture();
    let entry_id = kdbx.vault().iter_entries().next().expect("entry").id;

    kdbx.edit_entry(
        entry_id,
        keepass_core::model::HistoryPolicy::Snapshot,
        |e| e.set_password(SecretString::from("post-snapshot")),
    )
    .expect("edit_entry");

    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = reopen(bytes);
    let entry = reopened
        .vault()
        .iter_entries()
        .next()
        .expect("entry after reopen");

    // Live entry: unknown_xml intact; the edit landed.
    assert_captured(&entry.unknown_xml, "FutureEntryHint", "payload");
    assert_eq!(entry.password, "post-snapshot");

    // History: exactly one pre-edit snapshot, carrying its own copy
    // of the unknown child. A derived Clone should propagate it, but
    // this is the kind of invariant that silently rots, so assert it.
    assert_eq!(entry.history.len(), 1);
    let snap = &entry.history[0];
    assert_captured(&snap.unknown_xml, "FutureEntryHint", "payload");
    // And the snapshot captures the pre-edit password, not the new one.
    assert_ne!(snap.password, "post-snapshot");
}

#[test]
fn unknown_children_survive_meta_setter() {
    let mut kdbx = open_fixture();
    kdbx.set_database_description("rebranded via mutation");

    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    let reopened = reopen(bytes);
    assert_fixture_shape(&reopened);

    assert_eq!(
        reopened.vault().meta.database_description,
        "rebranded via mutation"
    );
}
