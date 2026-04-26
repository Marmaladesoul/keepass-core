//! Three-way field merge for a single entry.
//!
//! [`merge_entry`] takes the local and remote sides of an entry and
//! produces a per-field classification by walking the entry's
//! `<History>` list to find a common ancestor (the merge crate's
//! "LCA"). Auto-resolvable per-field edits (one side touched, the other
//! is unchanged from the ancestor) are bucketed into
//! [`EntryMergeOutput::auto_resolutions`]; field-level conflicts that
//! need user input are bucketed into [`EntryMergeOutput::conflicts`].
//!
//! ## Comparator asymmetry
//!
//! Standard `<String>` fields (`Title`, `UserName`, `Password`, `URL`,
//! `Notes`) on the upstream [`Entry`] type are bare strings with no
//! per-field `protected` bit. Memory-protection for those values is a
//! global concern (`Meta::MemoryProtection`) handled outside the merge
//! crate. Per-entry custom fields *do* carry a `protected` flag.
//!
//! The 3-way comparator therefore treats standard fields by value
//! alone and custom fields by `(value, protected)`. A custom field
//! whose `protected` bit flips with no value change is a conflict.
//!
//! ## v0.1 scope
//!
//! `tags`, `attachments`, `auto_type`, `unknown_xml`, custom-icon
//! references, group-membership, timestamps, and the entry's own
//! `<History>` are *not* part of the comparator. They ride along with
//! whichever side wins the entry-level merge in slice 5's apply step.
//! Per-attachment / per-tag conflict surface is logged in
//! `MERGE_BACKLOG.md` for v0.1.x.
//!
//! ## No-ancestor fallback
//!
//! When [`find_common_ancestor`] returns `None` (truncated histories
//! diverged on both sides, or one side has no history at all), every
//! field that differs between the two sides is classified as a
//! conflict — never as an auto-resolution. Conservative: never
//! overwrites a user edit silently.

use std::collections::{BTreeSet, HashMap};

use keepass_core::model::Entry;

use crate::conflict::{FieldDelta, FieldDeltaKind};
use crate::hash::{ct_eq, entry_content_hash};

/// Which side an auto-resolved field should be applied from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Side {
    /// Keep the local value (or absence, if local has no entry for the key).
    Local,
    /// Take the remote value (or absence, if remote has no entry for the key).
    Remote,
}

/// Output of a single-entry 3-way merge.
#[derive(Debug, Default)]
pub(crate) struct EntryMergeOutput {
    /// Field keys whose 3-way merge could not auto-resolve. Each entry
    /// becomes one [`FieldDelta`] in the surrounding [`crate::EntryConflict`].
    pub conflicts: Vec<FieldDelta>,
    /// Field keys whose 3-way merge has a clear answer. Slice 5's apply
    /// step copies the chosen side's value into the merged entry — or
    /// deletes the field if the chosen side has no value for it.
    pub auto_resolutions: Vec<(String, Side)>,
    /// `true` iff [`find_common_ancestor`] produced a hit. `false` means
    /// every conflicting field was classified conservatively (no
    /// auto-resolution attempted).
    ///
    /// Slice 3's vault walker doesn't read this directly — the
    /// per-field auto-resolution profile carries enough information
    /// for routing. Kept as a `pub(crate)` signal so a future slice
    /// can emit a `debug!` ("no LCA found, conservative fallback")
    /// if the FFI layer grows a tracing subscriber.
    #[allow(dead_code)]
    pub had_ancestor: bool,
}

/// Names of the standard `<String>` fields on an [`Entry`].
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// Run the 3-way field merge for one entry pair. See module docs.
pub(crate) fn merge_entry(local: &Entry, remote: &Entry) -> EntryMergeOutput {
    let ancestor = find_common_ancestor(local, remote);
    let mut out = EntryMergeOutput {
        conflicts: Vec::new(),
        auto_resolutions: Vec::new(),
        had_ancestor: ancestor.is_some(),
    };

    // Standard fields: always present on both sides; comparator is value-only.
    for &name in STANDARD_FIELDS {
        let l = standard_value(local, name);
        let r = standard_value(remote, name);
        if l == r {
            continue;
        }
        let resolution = ancestor.map(|a| {
            let av = standard_value(a, name);
            classify_three_way(Some(&l), Some(&r), Some(&av))
        });
        match resolution {
            Some(Resolution::Auto(side)) => out.auto_resolutions.push((name.into(), side)),
            // Standard fields always exist on both sides → BothDiffer.
            _ => out.conflicts.push(FieldDelta {
                key: name.into(),
                kind: FieldDeltaKind::BothDiffer,
            }),
        }
    }

    // Custom fields: presence matters; comparator is (value, protected).
    let local_custom = custom_map(local);
    let remote_custom = custom_map(remote);
    let ancestor_custom = ancestor.map(custom_map);

    let mut keys: BTreeSet<&str> = BTreeSet::new();
    keys.extend(local_custom.keys().copied());
    keys.extend(remote_custom.keys().copied());

    for key in keys {
        let l = local_custom.get(key).copied();
        let r = remote_custom.get(key).copied();
        if l == r {
            continue;
        }
        let resolution = ancestor_custom.as_ref().map(|a| {
            let av = a.get(key).copied();
            classify_three_way(l.as_ref(), r.as_ref(), av.as_ref())
        });
        let kind = match (l.is_some(), r.is_some()) {
            (true, true) => FieldDeltaKind::BothDiffer,
            (true, false) => FieldDeltaKind::LocalOnly,
            (false, true) => FieldDeltaKind::RemoteOnly,
            (false, false) => unreachable!("key collected from union of local + remote"),
        };
        match resolution {
            Some(Resolution::Auto(side)) => out.auto_resolutions.push((key.into(), side)),
            _ => out.conflicts.push(FieldDelta {
                key: key.into(),
                kind,
            }),
        }
    }

    out
}

/// Detect whether a local entry appears to have been edited after a
/// remote tombstone was recorded. Used by the vault-level walker to
/// classify the delete-vs-edit case.
///
/// When either timestamp is `None` we have no information; the
/// function returns `true` (conservative: surface as a conflict
/// rather than silently delete a possibly-edited entry). KDBX writers
/// fill these timestamps in practice, so the fallback fires rarely
/// — and false-positive conflict ("user clicks 'keep mine' once") is
/// strictly less harmful than false-negative silent delete ("user
/// loses an edit they never saw conflict on").
pub(crate) fn local_edited_after(
    entry: &Entry,
    cutoff: Option<chrono::DateTime<chrono::Utc>>,
) -> bool {
    match (entry.times.last_modification_time, cutoff) {
        (Some(local_mtime), Some(deleted_at)) => local_mtime > deleted_at,
        _ => true,
    }
}

/// Find the most-recent entry-history record present on both sides.
///
/// Match key is `last_modification_time` (primary). Records with no
/// timestamp are excluded — KDBX writers fill this and untimed records
/// carry no meaningful ancestry. On a timestamp collision the
/// content-hash decides.
pub(crate) fn find_common_ancestor<'a>(local: &'a Entry, remote: &'a Entry) -> Option<&'a Entry> {
    // Group remote history by mtime so a single mtime can map to multiple records.
    let mut remote_by_mtime: HashMap<chrono::DateTime<chrono::Utc>, Vec<&Entry>> = HashMap::new();
    for snap in &remote.history {
        if let Some(t) = snap.times.last_modification_time {
            remote_by_mtime.entry(t).or_default().push(snap);
        }
    }

    // Walk local history newest → oldest so the first content-matching
    // hit is the most recent shared record.
    let mut local_iter: Vec<&Entry> = local
        .history
        .iter()
        .filter(|e| e.times.last_modification_time.is_some())
        .collect();
    local_iter.sort_by_key(|e| std::cmp::Reverse(e.times.last_modification_time));

    for l in local_iter {
        let t = l.times.last_modification_time?;
        let Some(remotes) = remote_by_mtime.get(&t) else {
            continue;
        };
        let lh = entry_content_hash(l);
        for r in remotes {
            let rh = entry_content_hash(r);
            if ct_eq(&lh, &rh) {
                return Some(l);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Auto(Side),
    Conflict,
}

/// Classify one field's 3-way merge given local, remote, and ancestor
/// values. `Option<T>` here represents "field present" vs "field
/// absent" — for standard fields the ancestor always has *some* value
/// (possibly empty), but the function generalises so custom-field
/// presence/absence works through the same path.
fn classify_three_way<T: PartialEq>(
    local: Option<&T>,
    remote: Option<&T>,
    ancestor: Option<&T>,
) -> Resolution {
    if local == ancestor {
        Resolution::Auto(Side::Remote)
    } else if remote == ancestor {
        Resolution::Auto(Side::Local)
    } else {
        Resolution::Conflict
    }
}

fn standard_value<'a>(entry: &'a Entry, name: &str) -> &'a str {
    match name {
        "Title" => entry.title.as_str(),
        "UserName" => entry.username.as_str(),
        "Password" => entry.password.as_str(),
        "URL" => entry.url.as_str(),
        "Notes" => entry.notes.as_str(),
        _ => unreachable!("STANDARD_FIELDS is fixed"),
    }
}

fn custom_map(entry: &Entry) -> HashMap<&str, (&str, bool)> {
    entry
        .custom_fields
        .iter()
        .map(|f| (f.key.as_str(), (f.value.as_str(), f.protected)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{Side, find_common_ancestor, merge_entry};
    use crate::conflict::FieldDeltaKind;
    use chrono::{TimeZone, Utc};
    use keepass_core::model::{CustomField, Entry, EntryId, Timestamps};
    use uuid::Uuid;

    fn entry() -> Entry {
        Entry::empty(EntryId(Uuid::nil()))
    }

    fn at(year: i32, day: u32) -> Timestamps {
        let mut t = Timestamps::default();
        t.last_modification_time = Some(Utc.with_ymd_and_hms(year, 1, day, 0, 0, 0).unwrap());
        t
    }

    fn snapshot(title: &str, ts: Timestamps) -> Entry {
        let mut e = entry();
        e.title = title.into();
        e.times = ts;
        e
    }

    #[test]
    fn lca_found_by_mtime() {
        let mut local = entry();
        local.history = vec![snapshot("v1", at(2026, 1)), snapshot("v2", at(2026, 2))];
        let mut remote = entry();
        remote.history = vec![snapshot("v1", at(2026, 1)), snapshot("v3", at(2026, 3))];

        let lca = find_common_ancestor(&local, &remote).expect("LCA");
        assert_eq!(lca.title, "v1");
    }

    #[test]
    fn lca_collision_broken_by_content() {
        // Two history records share an mtime but differ in content; only the
        // matching-content one is the real ancestor.
        let mtime = at(2026, 1);
        let mut local = entry();
        local.history = vec![snapshot("shared", mtime.clone())];
        let mut remote = entry();
        remote.history = vec![snapshot("other", mtime.clone()), snapshot("shared", mtime)];

        let lca = find_common_ancestor(&local, &remote).expect("LCA");
        assert_eq!(lca.title, "shared");
    }

    #[test]
    fn lca_none_when_no_overlap() {
        let mut local = entry();
        local.history = vec![snapshot("v1", at(2026, 1))];
        let mut remote = entry();
        remote.history = vec![snapshot("v2", at(2026, 2))];

        assert!(find_common_ancestor(&local, &remote).is_none());
    }

    #[test]
    fn one_sided_edit_auto_resolves() {
        // Ancestor has Title="A". Local edited it to "B"; remote left it.
        let ancestor = snapshot("A", at(2026, 1));
        let mut local = entry();
        local.title = "B".into();
        local.history = vec![ancestor.clone()];
        let mut remote = entry();
        remote.title = "A".into();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote);
        assert!(out.had_ancestor);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions, vec![("Title".into(), Side::Local)]);
    }

    #[test]
    fn divergent_edits_conflict() {
        // Ancestor "A"; local → "B", remote → "C". True conflict.
        let ancestor = snapshot("A", at(2026, 1));
        let mut local = entry();
        local.title = "B".into();
        local.history = vec![ancestor.clone()];
        let mut remote = entry();
        remote.title = "C".into();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote);
        assert!(out.had_ancestor);
        assert!(out.auto_resolutions.is_empty());
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "Title");
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::BothDiffer);
    }

    #[test]
    fn no_ancestor_fallback_treats_every_diff_as_conflict() {
        // Identical entries with no history; one side edited Title.
        let mut local = entry();
        local.title = "A".into();
        let mut remote = entry();
        remote.title = "B".into();

        let out = merge_entry(&local, &remote);
        assert!(!out.had_ancestor);
        assert!(out.auto_resolutions.is_empty());
        assert_eq!(out.conflicts.len(), 1);
    }

    #[test]
    fn protected_flag_flip_is_a_conflict_without_ancestor() {
        let mut local = entry();
        local.custom_fields = vec![CustomField::new("x", "v", false)];
        let mut remote = entry();
        remote.custom_fields = vec![CustomField::new("x", "v", true)];

        let out = merge_entry(&local, &remote);
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "x");
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::BothDiffer);
    }

    #[test]
    fn local_only_custom_field_classified_as_local_only() {
        let mut local = entry();
        local.custom_fields = vec![CustomField::new("x", "v", false)];
        let remote = entry();

        let out = merge_entry(&local, &remote);
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::LocalOnly);
    }

    #[test]
    fn local_added_custom_field_with_ancestor_auto_resolves_local() {
        // Ancestor has no custom field; local added one; remote unchanged.
        let ancestor = entry(); // mtime = None — needs a timestamp for LCA hit
        let mut ancestor = ancestor;
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.custom_fields = vec![CustomField::new("x", "v", false)];
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote);
        assert!(out.had_ancestor);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions, vec![("x".into(), Side::Local)]);
    }
}
