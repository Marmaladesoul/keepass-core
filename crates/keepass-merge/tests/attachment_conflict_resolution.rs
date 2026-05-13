//! End-to-end tests for the public attachment-conflict surface
//! introduced in slice B4.
//!
//! Slice B3 wired auto-resolvable attachment merges through routing
//! and apply. This slice surfaces the *conflict* cases on
//! `EntryConflict::attachment_deltas` and adds a per-attachment
//! caller-resolution carrier (`Resolution::entry_attachment_choices`,
//! `AttachmentChoice`). Routing now sends attachment-only conflicts
//! through `entry_conflicts` so the caller's resolver UI gets a
//! chance to see them.

use keepass_core::model::{Attachment, Binary, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{
    AttachmentChoice, AttachmentDeltaKind, MergeError, Resolution, apply_merge, merge,
};
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

fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap_or_else(|| panic!("entry {id} not in vault"))
}

fn att_bytes<'a>(entry: &Entry, name: &str, pool: &'a [Binary]) -> Option<&'a [u8]> {
    let att = entry.attachments.iter().find(|a| a.name == name)?;
    pool.get(att.ref_id as usize).map(|b| b.data.as_slice())
}

/// Set up the canonical "both edited the same attachment with
/// different bytes" `BothDiffer` conflict scenario. Returns the
/// constructed (local, remote) pair and the entry id.
fn both_differ_setup() -> (Vault, Vault, EntryId) {
    // Ancestor: shared bytes "v0" at idx 0 (local pool) / idx 0 (remote pool).
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)];

    // Local-pool: idx 0 = "v0"; idx 1 = local's edit "L".
    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 1)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"L".to_vec(), false),
        ],
    );

    // Remote-pool: idx 0 = "v0"; idx 1 = remote's edit "R".
    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    remote_e.attachments = vec![Attachment::new("note.txt", 1)];
    remote_e.history = vec![ancestor];
    let remote = vault(
        vec![remote_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"R".to_vec(), false),
        ],
    );

    (local, remote, EntryId(Uuid::from_u128(1)))
}

// ---------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------

#[test]
fn attachment_conflict_routes_to_entry_conflicts() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    assert_eq!(outcome.entry_conflicts.len(), 1);
    let conflict = &outcome.entry_conflicts[0];
    assert_eq!(conflict.entry_id, id);
    assert!(conflict.field_deltas.is_empty(), "field side identical");
    assert_eq!(conflict.attachment_deltas.len(), 1);
    let delta = &conflict.attachment_deltas[0];
    assert_eq!(delta.name, "note.txt");
    assert_eq!(delta.kind, AttachmentDeltaKind::BothDiffer);
    assert!(delta.local_sha256.is_some());
    assert!(delta.remote_sha256.is_some());
    assert_ne!(delta.local_sha256, delta.remote_sha256);
}

// ---------------------------------------------------------------------
// Apply with caller choices
// ---------------------------------------------------------------------

#[test]
fn keep_local_choice_takes_local_bytes() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("note.txt".into(), AttachmentChoice::KeepLocal);
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"L" as &[u8])
    );
}

#[test]
fn keep_remote_choice_takes_remote_bytes() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("note.txt".into(), AttachmentChoice::KeepRemote);
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"R" as &[u8])
    );
}

#[test]
fn keep_both_default_renames_remote_with_remote_suffix() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert(
        "note.txt".into(),
        AttachmentChoice::KeepBoth {
            rename_override: None,
        },
    );
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);

    // Both attachments present; local under its original name, remote
    // under the default rename.
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"L" as &[u8])
    );
    assert_eq!(
        att_bytes(&e, "note (remote).txt", &merged.binaries),
        Some(b"R" as &[u8]),
    );
}

#[test]
fn keep_both_override_uses_caller_supplied_name() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert(
        "note.txt".into(),
        AttachmentChoice::KeepBoth {
            rename_override: Some("note-from-laptop.txt".into()),
        },
    );
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);

    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"L" as &[u8])
    );
    assert_eq!(
        att_bytes(&e, "note-from-laptop.txt", &merged.binaries),
        Some(b"R" as &[u8]),
        "remote bytes installed under the caller-supplied rename",
    );
}

#[test]
fn keep_both_collision_appends_counter_suffix() {
    // Construct a scenario where the entry already has an attachment
    // named "note (remote).txt" — the default rename collides, so
    // the apply step must append a counter suffix.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![
        Attachment::new("note.txt", 0),
        Attachment::new("note (remote).txt", 1),
    ];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![
        Attachment::new("note.txt", 2), // edited
        Attachment::new("note (remote).txt", 1),
    ];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"PRE-RENAME".to_vec(), false),
            Binary::new(b"L".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    remote_e.attachments = vec![
        Attachment::new("note.txt", 2), // edited differently
        Attachment::new("note (remote).txt", 1),
    ];
    remote_e.history = vec![ancestor];
    let remote = vault(
        vec![remote_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"PRE-RENAME".to_vec(), false),
            Binary::new(b"R".to_vec(), false),
        ],
    );

    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(outcome.entry_conflicts.len(), 1);

    let id = EntryId(Uuid::from_u128(1));
    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert(
        "note.txt".into(),
        AttachmentChoice::KeepBoth {
            rename_override: None,
        },
    );
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);

    // "note (remote).txt" was already taken, so remote's lands at
    // "note (remote 2).txt".
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"L" as &[u8])
    );
    assert_eq!(
        att_bytes(&e, "note (remote).txt", &merged.binaries),
        Some(b"PRE-RENAME" as &[u8]),
        "pre-existing attachment under the default rename slot is preserved",
    );
    assert_eq!(
        att_bytes(&e, "note (remote 2).txt", &merged.binaries),
        Some(b"R" as &[u8]),
        "remote's edited bytes installed under the counter-suffixed rename",
    );
}

// ---------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------

#[test]
fn missing_attachment_resolution_errors() {
    let (local, remote, _id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    // Empty resolution — no choice for the attachment conflict.
    let mut merged = local.clone();
    let err = apply_merge(&mut merged, &remote, &outcome, &Resolution::default()).unwrap_err();
    assert!(matches!(
        err,
        MergeError::MissingResolutionForConflict { .. }
    ));
}

#[test]
fn unknown_attachment_name_errors() {
    let (local, remote, id) = both_differ_setup();
    let outcome = merge(&local, &remote).unwrap();

    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("note.txt".into(), AttachmentChoice::KeepLocal);
    choices.insert("bogus.txt".into(), AttachmentChoice::KeepLocal);
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    let err = apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap_err();
    assert!(matches!(
        err,
        MergeError::UnknownAttachmentInResolution { attachment, .. }
        if attachment == "bogus.txt"
    ));
}

#[test]
fn keep_both_rejected_for_one_sided_delta() {
    // Construct a LocalOnly delta scenario: local has an attachment,
    // remote doesn't, ancestor has it with different bytes (so
    // not auto-resolvable).
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)]; // local-pool 0 = ancestor bytes

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 1)]; // local-pool 1 = local's edit
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"L-edit".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    // remote has no attachment
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![]);

    let outcome = merge(&local, &remote).unwrap();
    assert_eq!(outcome.entry_conflicts.len(), 1);
    assert_eq!(
        outcome.entry_conflicts[0].attachment_deltas[0].kind,
        AttachmentDeltaKind::LocalOnly,
    );

    let id = EntryId(Uuid::from_u128(1));
    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert(
        "note.txt".into(),
        AttachmentChoice::KeepBoth {
            rename_override: None,
        },
    );
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    let err = apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap_err();
    assert!(matches!(
        err,
        MergeError::KeepBothNotPermittedForKind { attachment, .. }
        if attachment == "note.txt"
    ));
}

// ---------------------------------------------------------------------
// One-sided resolution
// ---------------------------------------------------------------------

#[test]
fn local_only_keep_local_preserves_attachment() {
    // LocalOnly delta (genuine conflict — ancestor differed from
    // local, so not auto-honoured). Caller picks KeepLocal: attachment
    // stays in the merged entry.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 1)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"L-edit".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![]);

    let outcome = merge(&local, &remote).unwrap();
    let id = EntryId(Uuid::from_u128(1));
    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("note.txt".into(), AttachmentChoice::KeepLocal);
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);
    assert_eq!(
        att_bytes(&e, "note.txt", &merged.binaries),
        Some(b"L-edit" as &[u8])
    );
}

#[test]
fn local_only_keep_remote_honours_deletion() {
    // Same setup; caller picks KeepRemote → honours remote's
    // (absent) state, dropping the attachment.
    let mut ancestor = entry(1, "shared", at(2026, 1, 1));
    ancestor.attachments = vec![Attachment::new("note.txt", 0)];

    let mut local_e = entry(1, "shared", at(2026, 2, 1));
    local_e.attachments = vec![Attachment::new("note.txt", 1)];
    local_e.history = vec![ancestor.clone()];
    let local = vault(
        vec![local_e],
        vec![
            Binary::new(b"v0".to_vec(), false),
            Binary::new(b"L-edit".to_vec(), false),
        ],
    );

    let mut remote_e = entry(1, "shared", at(2026, 3, 1));
    remote_e.history = vec![ancestor];
    let remote = vault(vec![remote_e], vec![]);

    let outcome = merge(&local, &remote).unwrap();
    let id = EntryId(Uuid::from_u128(1));
    let mut resolution = Resolution::default();
    let mut choices = HashMap::new();
    choices.insert("note.txt".into(), AttachmentChoice::KeepRemote);
    resolution.entry_attachment_choices.insert(id, choices);

    let mut merged = local.clone();
    apply_merge(&mut merged, &remote, &outcome, &resolution).unwrap();
    let e = find(&merged, 1);
    assert!(
        e.attachments.iter().all(|a| a.name != "note.txt"),
        "remote's deletion honoured: attachment stripped from merged",
    );
}
