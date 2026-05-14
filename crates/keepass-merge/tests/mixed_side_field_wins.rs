//! Regression tests for the "mixed-side field wins" data-loss class.
//!
//! Pre-fix, `route_both_present` classified an entry into
//! `disk_only_changes` or `local_only_changes` by an `any_remote_wins`
//! flag, and apply then cloned the bucket-level winner wholesale —
//! ignoring the per-field winner list. When a single entry's per-field
//! auto-resolutions split between sides (local wins Title, remote wins
//! UserName), one side's edit was silently lost. The fix stashes the
//! per-field auto-resolution list on `MergeOutcome` and overlays each
//! non-bucket-winner field onto the clone inside `build_merged_entry`.

use keepass_core::model::{CustomField, Entry, EntryId, GroupId, Timestamps, Vault};
use keepass_merge::{Resolution, apply_merge, merge};
use uuid::Uuid;

fn at(year: i32, month: u32, day: u32) -> Timestamps {
    let mut t = Timestamps::default();
    t.last_modification_time =
        Some(chrono::TimeZone::with_ymd_and_hms(&chrono::Utc, year, month, day, 0, 0, 0).unwrap());
    t
}

fn entry(id: u128, ts: Timestamps) -> Entry {
    let mut e = Entry::empty(EntryId(Uuid::from_u128(id)));
    e.times = ts;
    e
}

fn vault(entries: Vec<Entry>) -> Vault {
    let mut v = Vault::empty(GroupId(Uuid::nil()));
    v.root.entries = entries;
    v
}

fn find(v: &Vault, id: u128) -> Entry {
    let want = EntryId(Uuid::from_u128(id));
    v.root
        .entries
        .iter()
        .find(|e| e.id == want)
        .cloned()
        .unwrap_or_else(|| panic!("entry {id} not found"))
}

// ---------------------------------------------------------------------
// Standard-field mixed-side scenario
// ---------------------------------------------------------------------

#[test]
fn mixed_side_local_title_remote_username_preserves_both_edits() {
    // Ancestor: Title="A", UserName="U".
    // Local: Title="L", UserName="U"  (local edited Title)
    // Remote: Title="A", UserName="R" (remote edited UserName)
    //
    // Expected post-merge: Title="L" (local's edit kept) AND
    // UserName="R" (remote's edit kept). Pre-fix the entry routed to
    // `disk_only_changes` (remote wins UserName), apply cloned remote
    // wholesale, and Title="L" was silently lost.
    let mut ancestor = entry(1, at(2026, 1, 1));
    ancestor.title = "A".into();
    ancestor.username = "U".into();

    let mut local = entry(1, at(2026, 1, 2));
    local.title = "L".into();
    local.username = "U".into();
    local.history = vec![ancestor.clone()];

    let mut remote = entry(1, at(2026, 1, 3));
    remote.title = "A".into();
    remote.username = "R".into();
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 1);
    assert_eq!(merged.title, "L", "local's Title edit must survive");
    assert_eq!(merged.username, "R", "remote's UserName edit must survive");
}

#[test]
fn mixed_side_symmetric_local_bucket_preserves_remote_edit() {
    // Symmetric to the above but the *local* side wins the bucket
    // (any_remote_wins == false would not fire — but tag-only edits
    // can still route to local_only_changes; force the local-bucket
    // path by having local edit one field that auto-merges to local,
    // and remote edit one that auto-merges to remote, with overall
    // bucket = Local because there's also one local-side win.
    //
    // Simplest construction: local edits Notes (auto=Local), remote
    // edits URL (auto=Remote). any_remote_wins = true →
    // disk_only_changes. Apply clones remote → Notes is lost pre-fix.
    let mut ancestor = entry(2, at(2026, 1, 1));
    ancestor.notes = "n0".into();
    ancestor.url = "u0".into();

    let mut local = entry(2, at(2026, 1, 2));
    local.notes = "local-notes".into();
    local.url = "u0".into();
    local.history = vec![ancestor.clone()];

    let mut remote = entry(2, at(2026, 1, 3));
    remote.notes = "n0".into();
    remote.url = "remote-url".into();
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 2);
    assert_eq!(merged.notes, "local-notes", "local's Notes edit kept");
    assert_eq!(merged.url, "remote-url", "remote's URL edit kept");
}

// ---------------------------------------------------------------------
// Custom-field mixed-side scenario
// ---------------------------------------------------------------------

#[test]
fn mixed_side_custom_fields_preserves_both_edits() {
    // Ancestor: cf_a="A0", cf_b="B0".
    // Local: cf_a="A_local", cf_b="B0" (local edited cf_a).
    // Remote: cf_a="A0", cf_b="B_remote" (remote edited cf_b).
    let mut ancestor = entry(3, at(2026, 1, 1));
    ancestor
        .custom_fields
        .push(CustomField::new("cf_a", "A0", false));
    ancestor
        .custom_fields
        .push(CustomField::new("cf_b", "B0", false));

    let mut local = entry(3, at(2026, 1, 2));
    local
        .custom_fields
        .push(CustomField::new("cf_a", "A_local", false));
    local
        .custom_fields
        .push(CustomField::new("cf_b", "B0", false));
    local.history = vec![ancestor.clone()];

    let mut remote = entry(3, at(2026, 1, 3));
    remote
        .custom_fields
        .push(CustomField::new("cf_a", "A0", false));
    remote
        .custom_fields
        .push(CustomField::new("cf_b", "B_remote", false));
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 3);
    let cf_a = merged
        .custom_fields
        .iter()
        .find(|f| f.key == "cf_a")
        .expect("cf_a present");
    let cf_b = merged
        .custom_fields
        .iter()
        .find(|f| f.key == "cf_b")
        .expect("cf_b present");
    assert_eq!(cf_a.value, "A_local", "local's cf_a edit kept");
    assert_eq!(cf_b.value, "B_remote", "remote's cf_b edit kept");
}

#[test]
fn mixed_side_custom_field_addition_then_remote_edit_preserves_both() {
    // Ancestor: cf_a="A0" (no cf_b).
    // Local: cf_a="A0", cf_b="added_locally" (local added cf_b).
    // Remote: cf_a="A_remote" (remote edited cf_a; no cf_b).
    //
    // Local added cf_b → auto = Local. Remote edited cf_a → auto =
    // Remote. Bucket: disk_only_changes (any_remote_wins=true).
    // Pre-fix: apply clones remote → cf_b is silently lost.
    let mut ancestor = entry(4, at(2026, 1, 1));
    ancestor
        .custom_fields
        .push(CustomField::new("cf_a", "A0", false));

    let mut local = entry(4, at(2026, 1, 2));
    local
        .custom_fields
        .push(CustomField::new("cf_a", "A0", false));
    local
        .custom_fields
        .push(CustomField::new("cf_b", "added_locally", false));
    local.history = vec![ancestor.clone()];

    let mut remote = entry(4, at(2026, 1, 3));
    remote
        .custom_fields
        .push(CustomField::new("cf_a", "A_remote", false));
    remote.history = vec![ancestor];

    let mut merged_vault = vault(vec![local]);
    let remote_vault = vault(vec![remote]);
    let outcome = merge(&merged_vault, &remote_vault).expect("merge");
    apply_merge(
        &mut merged_vault,
        &remote_vault,
        &outcome,
        &Resolution::default(),
    )
    .expect("apply");

    let merged = find(&merged_vault, 4);
    let cf_a = merged
        .custom_fields
        .iter()
        .find(|f| f.key == "cf_a")
        .expect("cf_a present");
    let cf_b = merged.custom_fields.iter().find(|f| f.key == "cf_b");
    assert_eq!(cf_a.value, "A_remote", "remote's cf_a edit kept");
    assert!(cf_b.is_some(), "local's cf_b addition kept");
    assert_eq!(cf_b.unwrap().value, "added_locally");
}
