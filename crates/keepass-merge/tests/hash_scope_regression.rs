//! Regression test for the LCA-blindness bug that slice B5 fixes.
//!
//! Pre-B5, `entry_content_hash` excluded attachments / icon / tags.
//! `find_common_ancestor` matched LCA candidates by `(mtime,
//! content_hash)`; when local edited *only* an attachment, local's
//! current state shared its content_hash with the pre-edit history
//! snapshot (attachments weren't in the hash), so the LCA walker
//! returned `local.current` as the LCA. The classifier then saw
//! `local.attachment == ancestor.attachment` (literally the same
//! Entry object) and auto-resolved the attachment to Remote —
//! silently overwriting local's edit with remote's stale bytes.
//!
//! Post-B5, attachments contribute to the hash, so local.current
//! and the pre-edit snapshot hash differently. The walker correctly
//! returns the pre-edit history record as the LCA, and the classifier
//! sees local's edit and auto-resolves to Local.

use keepass_core::model::{Attachment, Binary, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
use uuid::Uuid;

fn at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time =
        Some(chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, year, month, day, 0, 0, 0).unwrap());
    t
}

fn entry(id: u128, title: &str, ts: Timestamps) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.title = title.into();
    e.times = ts;
    e
}

fn vault(entries: Vec<Entry>, binaries: Vec<Binary>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = entries;
    v.binaries = binaries;
    v
}

fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap()
}

fn att_bytes<'a>(entry: &Entry, name: &str, pool: &'a [Binary]) -> Option<&'a [u8]> {
    let att = entry.attachments.iter().find(|a| a.name == name)?;
    pool.get(att.ref_id as usize).map(|b| b.data.as_slice())
}

#[test]
fn local_only_attachment_edit_no_field_change_preserved_after_merge() {
    // Setup: ancestor has attachment "note.txt" with bytes "v0";
    // local edited the attachment to "v1" but didn't touch any
    // field; remote is at the ancestor state. Same title, same
    // username, same everything — only the attachment bytes differ
    // between local.current and local.history[0].
    //
    // Pre-B5 LCA walker would have matched local.current with
    // remote.current by mtime + (attachment-blind) content_hash, and
    // the classifier would have auto-resolved local's edit to Remote
    // — silently losing the edit.
    //
    // Post-B5 the LCA walker uses the attachment-aware hash:
    // - local.current's content_hash includes "v1"
    // - local.history[0]'s content_hash includes "v0"
    // - remote.current's content_hash includes "v0"
    // The walker finds the LCA at local.history[0] (mtime matching
    // remote's history). Classifier sees local's edit. Auto: TakeLocal.

    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 1)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"v1".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.attachments = vec![Attachment::new("note.txt", 0)];
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![Binary::new(b"v0".to_vec(), false)]);

    let outcome = merge(&local, &remote).unwrap();
    // Routes through `local_only_changes` — local's attachment edit
    // wins; remote has nothing to contribute beyond agreeing with
    // history.
    assert_eq!(
        outcome.local_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "local's attachment-only edit must be detected as a local-side change",
    );

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"v1" as &[u8]),
        "local's edited attachment bytes must survive the merge",
    );
}

// Icon and tag regression tests are deliberately omitted from this
// slice. B5 only fixes `entry_content_hash`'s scope — the LCA walker
// can now *detect* icon-only and tag-only edits, but routing them
// through `disk_only_changes` / `local_only_changes` requires their
// own classifier extensions (parallel to the attachment classifier
// in B2/B3). Tag set-merge is the planned B6 slice; an icon
// classifier slice is unscheduled. When those land, the symmetric
// regression tests for icon and tags belong with their respective
// slices.
