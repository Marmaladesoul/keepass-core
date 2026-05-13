//! Integration tests for cross-vault binary-pool reconciliation.
//!
//! Before this slice, `apply_merge` never touched `Vault::binaries`.
//! Any cross-side attachment carry-over silently left
//! `Attachment::ref_id` values pointing into the *remote* vault's
//! binary pool, producing latent corruption for entries with
//! attachments coming from `remote` (out-of-bounds reads at best;
//! wrong-content reads at worst, depending on local pool size).
//!
//! These tests cover every entry-cloning path in `apply_merge`:
//!
//! - `added_on_disk` — entirely remote-sourced new entry.
//! - `disk_only_changes` — remote-wins overwrite carries remote
//!   current attachments.
//! - `local_only_changes` — local-wins keep but remote's history
//!   records ride along via `merge_histories`.
//! - `entry_conflicts` — resolution merges histories from both sides.
//!
//! Plus the dedup contract: an identical binary already in `local`
//! must not be re-imported under a fresh index.

use keepass_core::model::{Attachment, Binary, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{ConflictSide, Resolution, apply_merge, merge};
use std::collections::HashMap;
use uuid::Uuid;

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

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

/// Look up an entry in a flat root-only vault (every test below builds
/// its vaults that way) and return a clone for assertion.
fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap_or_else(|| panic!("entry {id} not in vault"))
}

/// Assert every attachment in `entry` (current + history) addresses a
/// valid index in `pool` and that the dereferenced bytes equal `want`.
fn assert_attachment_resolves(entry: &Entry, pool: &[Binary], name: &str, want: &[u8]) {
    let att = entry
        .attachments
        .iter()
        .find(|a| a.name == name)
        .unwrap_or_else(|| panic!("entry has no attachment named {name:?}"));
    let bin = pool.get(att.ref_id as usize).unwrap_or_else(|| {
        panic!(
            "ref_id {} out of bounds in pool of {}",
            att.ref_id,
            pool.len()
        )
    });
    assert_eq!(
        bin.data, want,
        "attachment {name:?} resolves to wrong bytes",
    );
}

// ---------------------------------------------------------------------
// added_on_disk
// ---------------------------------------------------------------------

#[test]
fn added_on_disk_remote_attachment_lands_in_local_pool() {
    // Local has nothing. Remote has one entry with one attachment.
    let local = Vault::empty(GroupId(Uuid::nil()));

    let mut remote_e = entry(1, "added", at(2026, 1, 1));
    remote_e.attachments = vec![Attachment::new("file.txt", 0)];
    let remote = vault(
        vec![remote_e],
        vec![Binary::new(b"REMOTE-BYTES".to_vec(), false)],
    );

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    assert_eq!(merged.binaries.len(), 1, "binary imported");
    let added = find(&merged, 1);
    assert_attachment_resolves(&added, &merged.binaries, "file.txt", b"REMOTE-BYTES");
}

#[test]
fn added_on_disk_history_attachments_also_rebind() {
    // Remote-only entry whose history record carries its own
    // attachment to a different remote binary. Both binaries must
    // import; both refs must resolve.
    let mut history_snapshot = entry(1, "old", at(2026, 1, 1));
    history_snapshot.attachments = vec![Attachment::new("v1.txt", 1)];
    let mut remote_e = entry(1, "new", at(2026, 2, 1));
    remote_e.attachments = vec![Attachment::new("v2.txt", 0)];
    remote_e.history = vec![history_snapshot];

    let remote = vault(
        vec![remote_e],
        vec![
            Binary::new(b"CURRENT".to_vec(), false),
            Binary::new(b"HISTORY".to_vec(), false),
        ],
    );
    let local = Vault::empty(GroupId(Uuid::nil()));

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    let added = find(&merged, 1);
    assert_attachment_resolves(&added, &merged.binaries, "v2.txt", b"CURRENT");

    let hist = added.history.iter().find(|h| h.title == "old").unwrap();
    let hist_att = &hist.attachments[0];
    let hist_bytes = &merged.binaries[hist_att.ref_id as usize].data;
    assert_eq!(hist_bytes, b"HISTORY");
}

// ---------------------------------------------------------------------
// disk_only_changes
// ---------------------------------------------------------------------

#[test]
fn disk_only_changes_brings_remote_attachment() {
    // Same entry on both sides. Remote is newer and has an attachment
    // local doesn't.
    let ancestor = entry(1, "shared", at(2026, 1, 1));

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.history = vec![ancestor.clone()];
    let local = vault(vec![local_e], vec![]);

    let mut remote_e = entry(1, "edited", at(2026, 2, 1));
    remote_e.attachments = vec![Attachment::new("notes.txt", 0)];
    remote_e.history = vec![ancestor];
    let remote = vault(
        vec![remote_e],
        vec![Binary::new(b"NEW-NOTES".to_vec(), false)],
    );

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    assert_eq!(merged.binaries.len(), 1);
    let e = find(&merged, 1);
    assert_attachment_resolves(&e, &merged.binaries, "notes.txt", b"NEW-NOTES");
}

// ---------------------------------------------------------------------
// local_only_changes (history-merge path)
// ---------------------------------------------------------------------

#[test]
fn local_only_changes_pulls_remote_history_attachment() {
    // One-sided local edit so the entry routes to `local_only_changes`
    // (remote unchanged from the LCA). Remote's history carries an
    // attachment-bearing snapshot local doesn't have; the snapshot
    // rides into local.history via merge_histories and its ref_id
    // must rebind to a local-pool index.
    let ancestor = entry(1, "v1", at(2026, 1, 1));

    let mut local_e = entry(1, "v2-local-edit", at(2026, 2, 1));
    local_e.history = vec![ancestor.clone()];
    let local = vault(vec![local_e], vec![]);

    // Remote = ancestor (unchanged) plus a separate history record
    // with an attachment.
    let mut remote_history_attached = entry(1, "extra-remote-snapshot", at(2026, 1, 15));
    remote_history_attached.attachments = vec![Attachment::new("draft.txt", 0)];
    let mut remote_e = entry(1, "v1", at(2026, 1, 1));
    remote_e.history = vec![remote_history_attached];
    let remote = vault(
        vec![remote_e],
        vec![Binary::new(b"DRAFT-BYTES".to_vec(), false)],
    );

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(
        outcome.local_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "test fixture must route through the local_only_changes bucket",
    );
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    let e = find(&merged, 1);
    // The remote-side history snapshot with the attachment landed in
    // merged.history; its ref_id must point into merged.binaries.
    let hist = e
        .history
        .iter()
        .find(|h| h.title == "extra-remote-snapshot")
        .expect("remote history snapshot must land in merged history");
    let att = &hist.attachments[0];
    let bytes = &merged.binaries[att.ref_id as usize].data;
    assert_eq!(bytes, b"DRAFT-BYTES");
}

// ---------------------------------------------------------------------
// Dedup contract
// ---------------------------------------------------------------------

#[test]
fn identical_binary_in_local_pool_is_reused_not_reappended() {
    // Local already has the bytes that remote is about to "bring in".
    // The merge should reuse the existing local index — no growth.
    let local_pool = vec![Binary::new(b"SAME-BYTES".to_vec(), false)];
    let local = vault(vec![], local_pool);

    let mut remote_e = entry(1, "added", at(2026, 1, 1));
    remote_e.attachments = vec![Attachment::new("same.txt", 0)];
    let remote = vault(
        vec![remote_e],
        vec![Binary::new(b"SAME-BYTES".to_vec(), false)],
    );

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    assert_eq!(
        merged.binaries.len(),
        1,
        "dedup must reuse existing local binary"
    );
    let e = find(&merged, 1);
    assert_eq!(e.attachments[0].ref_id, 0);
}

#[test]
fn multiple_refs_to_same_remote_binary_converge_on_one_local_index() {
    // Two remote entries each reference the same remote binary.
    // After merge, both should resolve to the same local index.
    let mut a = entry(1, "a", at(2026, 1, 1));
    a.attachments = vec![Attachment::new("shared.txt", 0)];
    let mut b = entry(2, "b", at(2026, 1, 1));
    b.attachments = vec![Attachment::new("shared.txt", 0)];

    let remote = vault(vec![a, b], vec![Binary::new(b"SHARED".to_vec(), false)]);
    let local = Vault::empty(GroupId(Uuid::nil()));

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();

    assert_eq!(merged.binaries.len(), 1, "single dedup across entries");
    let ea = find(&merged, 1);
    let eb = find(&merged, 2);
    assert_eq!(ea.attachments[0].ref_id, eb.attachments[0].ref_id);
}

// ---------------------------------------------------------------------
// entry_conflicts (resolution path)
// ---------------------------------------------------------------------

#[test]
fn entry_conflict_history_remote_attachments_rebind() {
    // Both sides edited the same entry. The conflict resolution path
    // calls merge_histories(local.history, remote.history); the remote
    // side's history records carry attachments referencing remote's
    // pool. Those must rebind regardless of which side the field
    // resolution picks.
    let ancestor = entry(1, "ancestor", at(2026, 1, 1));

    let mut local_e = entry(1, "L-title", at(2026, 1, 5));
    local_e.history = vec![ancestor.clone()];
    let local = vault(vec![local_e], vec![]);

    let mut remote_history = entry(1, "R-history-snap", at(2026, 1, 3));
    remote_history.attachments = vec![Attachment::new("snap.txt", 0)];
    let mut remote_e = entry(1, "R-title", at(2026, 1, 6));
    remote_e.history = vec![ancestor, remote_history];
    let remote = vault(
        vec![remote_e],
        vec![Binary::new(b"SNAPSHOT".to_vec(), false)],
    );

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("Title".into(), ConflictSide::Local); // user keeps local title
    resolution
        .entry_field_choices
        .insert(EntryId(Uuid::from_u128(1)), choices);

    let mut merged = local.clone();
    let outcome = merge(&local, &remote).unwrap();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();

    let e = find(&merged, 1);
    let snap = e
        .history
        .iter()
        .find(|h| !h.attachments.is_empty())
        .expect("remote history snapshot with attachment must land in merged history");
    let bytes = &merged.binaries[snap.attachments[0].ref_id as usize].data;
    assert_eq!(bytes, b"SNAPSHOT");
}
