//! End-to-end tests for the attachment-auto-resolution wiring.
//!
//! The classifier (added in slice B2) populates per-name
//! auto-resolutions inside `merge_entry`. This slice (B3) wires those
//! into routing in `merge.rs` and apply in `apply.rs`:
//!
//! - Routing now considers attachment auto-resolutions when deciding
//!   the entry's bucket — an entry whose only divergence is a
//!   per-name attachment auto-resolution no longer gets silently
//!   omitted from every bucket.
//! - Apply consumes the per-name auto-resolutions and reconciles the
//!   merged entry's attachment list per-name rather than blindly
//!   riding along with the entry-level winner.
//!
//! Attachment *conflicts* (no LCA-derived answer) still ride along
//! with the entry-level winner — the public resolution surface for
//! those lands in a later slice.

use keepass_core::model::{Attachment, Binary, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
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

fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap_or_else(|| panic!("entry {id} not in vault"))
}

fn attachment_bytes<'a>(entry: &Entry, name: &str, pool: &'a [Binary]) -> Option<&'a [u8]> {
    let att = entry.attachments.iter().find(|a| a.name == name)?;
    pool.get(att.ref_id as usize).map(|b| b.data.as_slice())
}

// ---------------------------------------------------------------------
// Routing: an entry whose only divergence is an attachment auto-
// resolution must not be silently omitted.
// ---------------------------------------------------------------------

#[test]
fn entry_with_only_attachment_remote_edit_routes_through_disk_only_changes() {
    // Field-identical entries. Local has the LCA's attachment bytes;
    // remote has edited it (and the LCA history record proves it was
    // a one-sided remote edit). Classifier auto: TakeRemote. Without
    // routing-extension, this entry would be silently omitted and the
    // local file would never receive remote's edited attachment.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)]; // ref into local-pool

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 0)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(vec![local_e], vec![Binary::new(b"L".to_vec(), false)]);

    let mut remote_e = entry(1, "shared", at(2026, 1, 1));
    remote_e.attachments = vec![Attachment::new("note.txt", 0)];
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![Binary::new(b"R".to_vec(), false)]);

    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(
        outcome.disk_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "remote-side attachment edit must route through disk_only_changes",
    );

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        attachment_bytes(&e, "note.txt", &merged.binaries),
        Some(b"R" as &[u8]),
        "merged entry must now hold remote's edited bytes",
    );
}

// NOTE: "local edits *only* an attachment" is not testable end-to-end
// in the current LCA model. `entry_content_hash` excludes attachments
// (slice-1 design choice), and `find_common_ancestor` returns the
// most-recent shared record by (mtime, content_hash). When local's
// only edit is an attachment, local.current shares both with the
// pre-edit state on remote → walker returns local.current as the LCA,
// and the classifier sees local-attachment == ancestor-attachment
// (because they're the same Entry). Auto-resolves to TakeRemote,
// which is semantically wrong but is a pre-existing limitation, not
// something B3 introduces. Documented in MERGE_ATTACHMENT_DESIGN.md.
// A test for the symmetric "remote edits only an attachment" case
// passes because the asymmetry of the LCA walker favours the local
// side.

// ---------------------------------------------------------------------
// Apply: per-attachment auto-resolution overrides ride-along.
// ---------------------------------------------------------------------

#[test]
fn per_attachment_override_beats_entry_level_winner() {
    // The core new capability of slice B3: an attachment can have a
    // different "winner" from the entry-level merge. Setup:
    //
    // - local edited a.txt (bumped mtime as KDBX writers do).
    // - remote edited b.txt (also bumped mtime, to a different value).
    // - The LCA — found via history — has the pre-edit bytes for both.
    //
    // Classifier:
    // - a.txt: l != r, ancestor matches r → auto TakeLocal.
    // - b.txt: l != r, ancestor matches l → auto TakeRemote.
    //
    // Routing: any_remote_wins (b.txt) → disk_only_changes.
    //
    // Apply: cloning remote would give us "a.txt-old + b.txt-new".
    // The per-attachment override for a.txt must kick in and replace
    // the clone's a.txt with local's "a.txt-new". Net result:
    // a.txt-new (from local), b.txt-new (from remote). Pre-B3 apply
    // would have lost local's a.txt edit silently.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![
        Attachment::new("a.txt", 0), // local-pool 0 = "a-old"
        Attachment::new("b.txt", 1), // local-pool 1 = "b-old"
    ];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![
        Attachment::new("a.txt", 2), // local-pool 2 = "a-new"
        Attachment::new("b.txt", 1),
    ];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"a-old".to_vec(), false),
            Binary::new(b"b-old".to_vec(), false),
            Binary::new(b"a-new".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    remote_e.attachments = vec![
        Attachment::new("a.txt", 0), // remote-pool 0 = "a-old"
        Attachment::new("b.txt", 2), // remote-pool 2 = "b-new"
    ];
    remote_e.history = vec![ancestor];
    let remote = vault(
        vec![remote_e],
        vec![
            Binary::new(b"a-old".to_vec(), false),
            Binary::new(b"b-old".to_vec(), false),
            Binary::new(b"b-new".to_vec(), false),
        ],
    );

    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(
        outcome.disk_only_changes,
        vec![EntryId(Uuid::from_u128(1))],
        "remote-wins on b.txt drives disk_only_changes",
    );

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        attachment_bytes(&e, "a.txt", &merged.binaries),
        Some(b"a-new" as &[u8]),
        "a.txt from local (per-attachment override beat the entry-level Remote winner)",
    );
    assert_eq!(
        attachment_bytes(&e, "b.txt", &merged.binaries),
        Some(b"b-new" as &[u8]),
        "b.txt from remote (entry-level winner agreed with classifier)",
    );
}

#[test]
fn honour_deletion_auto_resolution_strips_attachment_from_merged() {
    // Local had an attachment; remote dropped it (and bumped mtime
    // with a field edit so LCA walker uses ancestor not local.current);
    // ancestor matches local's bytes → remote initiated the deletion
    // with no concurrent local edit. Classifier auto-resolves to
    // Remote (the side that has it absent). The apply step should
    // strip the attachment from the merged entry.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("doomed.txt", 0)];

    let mut local_e = entry(1, "shared", at(2026, 1, 1));
    local_e.attachments = vec![Attachment::new("doomed.txt", 0)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(vec![local_e], vec![Binary::new(b"shared".to_vec(), false)]);

    let mut remote_e = entry(1, "remote-edit", at(2026, 2, 1));
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![]);

    let outcome = merge(&local, &remote).unwrap();
    // Title also differs, so disk_only_changes; the attachment
    // resolution still rides through.
    assert_eq!(outcome.disk_only_changes, vec![EntryId(Uuid::from_u128(1))]);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap();
    let e = find(&merged, 1);
    assert!(
        e.attachments.iter().all(|a| a.name != "doomed.txt"),
        "deletion must be honoured: attachment dropped from merged",
    );
}

#[test]
fn truly_identical_entry_still_omitted() {
    // Same content on both sides — no field diffs, no attachment
    // diffs. Should remain omitted from every bucket so callers
    // iterating `local_only_changes` don't see false positives.
    let mut e_local = entry(1, "same", at(2026, 1, 1));
    e_local.attachments = vec![Attachment::new("a.txt", 0)];
    let mut e_remote = entry(1, "same", at(2026, 1, 1));
    e_remote.attachments = vec![Attachment::new("a.txt", 0)];

    let local = vault(vec![e_local], vec![Binary::new(b"x".to_vec(), false)]);
    let remote = vault(vec![e_remote], vec![Binary::new(b"x".to_vec(), false)]);

    let outcome = merge(&local, &remote).unwrap();
    assert!(outcome.disk_only_changes.is_empty());
    assert!(outcome.local_only_changes.is_empty());
    assert!(outcome.entry_conflicts.is_empty());
}
