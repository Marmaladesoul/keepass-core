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
//! ## Ancestor candidate set
//!
//! [`find_common_ancestor`] considers each side's *current* entry as
//! well as every `<History>` snapshot when searching for a shared
//! record. This matters for the asymmetric case where one side edited
//! and the other did not: the editor pushes the pre-edit version into
//! its own history, but the unedited side's current state IS that
//! same pre-edit version — and was never pushed into its own history,
//! because no edit was made. Treating current entries as ancestor
//! candidates recovers the real LCA in this case.
//!
//! ## No-ancestor fallback
//!
//! When [`find_common_ancestor`] returns `None` (truncated histories
//! diverged on both sides and neither current state matches the
//! other side's history), every field that differs between the two
//! sides is classified as a conflict — never as an auto-resolution.
//! Conservative: never overwrites a user edit silently.

use std::collections::{BTreeSet, HashMap};

use keepass_core::model::{Binary, Entry};
use sha2::{Digest, Sha256};

use crate::conflict::{AttachmentDelta, AttachmentDeltaKind, FieldDelta, FieldDeltaKind};
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
    /// Attachment names whose 3-way merge could not auto-resolve.
    /// Populated by the classifier added in slice B2; no consumer yet
    /// — routing in `merge.rs` and `apply.rs` will start reading this
    /// in slice B3 (per `_localdocs/MERGE_ATTACHMENT_DESIGN.md`).
    #[allow(dead_code)]
    pub attachment_conflicts: Vec<AttachmentDelta>,
    /// Attachment names whose 3-way merge has a clear answer. Same
    /// shape as `auto_resolutions` but keyed by attachment name. Also
    /// awaiting B3 wiring.
    #[allow(dead_code)]
    pub attachment_auto_resolutions: Vec<AttachmentAutoResolution>,
    /// The merged tag set after applying 3-way set semantics against
    /// the LCA (per `_localdocs/MERGE_TAGS_DESIGN.md`). Apply writes
    /// this onto the merged entry when the entry routes through any
    /// bucket. Always populated; identical to `local.tags` as a set
    /// when the merge had nothing to do for tags.
    pub merged_tags: std::collections::BTreeSet<String>,
    /// `true` when [`Self::merged_tags`] differs from `local.tags` as
    /// a set — i.e. local has tag-work to do after the merge.
    /// Contributes to the routing decision in `merge.rs`.
    pub tags_changed_from_local: bool,
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

/// One auto-resolved attachment decision. Companion to the field-level
/// `(String, Side)` entries in [`EntryMergeOutput::auto_resolutions`].
///
/// `side` says which side wins. Apply consumes the winner like field
/// merge does: ensure the merged entry's attachment list mirrors that
/// side's presence-or-absence for this name. When the winning side has
/// the attachment, take its bytes; when the winning side doesn't,
/// drop it from the merged entry.
#[derive(Debug, Clone)]
#[allow(dead_code)] // wired up in slice B3
pub(crate) struct AttachmentAutoResolution {
    pub name: String,
    pub side: Side,
}

/// Names of the standard `<String>` fields on an [`Entry`].
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// Run the 3-way field + attachment merge for one entry pair. See
/// module docs.
///
/// `local_binaries` / `remote_binaries` are the binary pools from each
/// side's enclosing [`keepass_core::model::Vault`] — used by the
/// attachment classifier to dereference [`keepass_core::model::Attachment::ref_id`]
/// values into payload SHA-256 hashes. The LCA is always taken from
/// the local side (see [`find_common_ancestor`]); its attachment
/// `ref_id` values therefore index into `local_binaries`.
pub(crate) fn merge_entry(
    local: &Entry,
    remote: &Entry,
    local_binaries: &[Binary],
    remote_binaries: &[Binary],
) -> EntryMergeOutput {
    let ancestor = find_common_ancestor(local, remote, local_binaries, remote_binaries);
    let merged_tags = classify_tags(local, remote, ancestor);
    let local_tag_set: std::collections::BTreeSet<&str> =
        local.tags.iter().map(String::as_str).collect();
    let merged_tag_set_view: std::collections::BTreeSet<&str> =
        merged_tags.iter().map(String::as_str).collect();
    let tags_changed_from_local = merged_tag_set_view != local_tag_set;
    let mut out = EntryMergeOutput {
        conflicts: Vec::new(),
        auto_resolutions: Vec::new(),
        attachment_conflicts: Vec::new(),
        attachment_auto_resolutions: Vec::new(),
        merged_tags,
        tags_changed_from_local,
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

    classify_attachments(
        local,
        remote,
        ancestor,
        local_binaries,
        remote_binaries,
        &mut out,
    );

    out
}

/// Bundle of one side's attachment metadata at a single name, used by
/// the 3-way classifier. `sha256` is `None` when the attachment is
/// absent on that side; the same `Option`-presence semantics that
/// drive [`classify_three_way`] for fields apply here.
#[derive(Clone, Copy, PartialEq, Eq)]
struct AttachmentSnap {
    sha256: Option<[u8; 32]>,
    size: Option<u64>,
}

impl AttachmentSnap {
    fn absent() -> Self {
        Self {
            sha256: None,
            size: None,
        }
    }
}

/// Walk the union of attachment names from local + remote (and the
/// LCA, if any) and bucket each into either an auto-resolution or a
/// conflict. Naming and 3-way classification mirror the custom-fields
/// pass above; the comparator is the payload SHA-256 from the
/// dereferenced binary pool.
fn classify_attachments(
    local: &Entry,
    remote: &Entry,
    ancestor: Option<&Entry>,
    local_binaries: &[Binary],
    remote_binaries: &[Binary],
    out: &mut EntryMergeOutput,
) {
    let local_map = attachment_map(local, local_binaries);
    let remote_map = attachment_map(remote, remote_binaries);
    // The LCA is sourced from local-side history (see
    // [`find_common_ancestor`]); its `ref_id`s therefore index into
    // `local_binaries`.
    let ancestor_map = ancestor.map(|a| attachment_map(a, local_binaries));

    let mut names: BTreeSet<&str> = BTreeSet::new();
    names.extend(local_map.keys().copied());
    names.extend(remote_map.keys().copied());

    for name in names {
        let l = local_map
            .get(name)
            .copied()
            .unwrap_or_else(AttachmentSnap::absent);
        let r = remote_map
            .get(name)
            .copied()
            .unwrap_or_else(AttachmentSnap::absent);
        if l == r {
            // Byte-identical (or absent on both, though absent-on-both
            // can't occur here — the name was collected from the union).
            continue;
        }
        let resolution = ancestor_map.as_ref().map(|a| {
            let av = a.get(name).copied().unwrap_or_else(AttachmentSnap::absent);
            classify_three_way(l.sha256.as_ref(), r.sha256.as_ref(), av.sha256.as_ref())
        });
        if let Some(Resolution::Auto(side)) = resolution {
            out.attachment_auto_resolutions
                .push(AttachmentAutoResolution {
                    name: name.into(),
                    side,
                });
        } else {
            let kind = match (l.sha256.is_some(), r.sha256.is_some()) {
                (true, true) => AttachmentDeltaKind::BothDiffer,
                (true, false) => AttachmentDeltaKind::LocalOnly,
                (false, true) => AttachmentDeltaKind::RemoteOnly,
                (false, false) => {
                    unreachable!("name collected from union of local + remote")
                }
            };
            out.attachment_conflicts.push(AttachmentDelta {
                name: name.into(),
                kind,
                local_sha256: l.sha256,
                remote_sha256: r.sha256,
                local_size: l.size,
                remote_size: r.size,
            });
        }
    }
}

/// Tag set merge against the (optional) LCA. See
/// `_localdocs/MERGE_TAGS_DESIGN.md`.
///
/// Tags carry presence/absence only — there's no slot/content
/// distinction that could produce a conflict between two writers.
/// Every cell of the 3-way truth table auto-resolves, so this
/// function returns a definitive merged tag set rather than buckets.
///
/// When `ancestor` is `Some`, deletions are honoured: a tag present
/// in the ancestor but absent on one side is dropped from the merged
/// set (the side without it actively removed it). When `ancestor` is
/// `None`, falls back to union (keep every tag from either side) —
/// conservative: never drops a tag without evidence the writer
/// intended to delete it.
fn classify_tags(
    local: &Entry,
    remote: &Entry,
    ancestor: Option<&Entry>,
) -> std::collections::BTreeSet<String> {
    use std::collections::BTreeSet;
    let local_tags: BTreeSet<&str> = local.tags.iter().map(String::as_str).collect();
    let remote_tags: BTreeSet<&str> = remote.tags.iter().map(String::as_str).collect();
    let ancestor_tags: Option<BTreeSet<&str>> =
        ancestor.map(|a| a.tags.iter().map(String::as_str).collect());

    let all_seen: BTreeSet<&str> = local_tags
        .iter()
        .chain(remote_tags.iter())
        .copied()
        .collect();

    let mut merged: BTreeSet<String> = BTreeSet::new();
    for tag in all_seen {
        let in_local = local_tags.contains(tag);
        let in_remote = remote_tags.contains(tag);
        let keep = if in_local && in_remote {
            // Present on both sides — no decision to make.
            true
        } else {
            // Exactly one side has it (since `all_seen` is the union
            // of local + remote, the both-absent case can't appear).
            // No LCA → conservative union, keep it. LCA present and
            // the ancestor had it → honour the deletion. LCA present
            // and the ancestor didn't → keep the addition.
            match &ancestor_tags {
                None => true,
                Some(anc) => !anc.contains(tag),
            }
        };
        if keep {
            merged.insert(tag.to_string());
        }
    }
    merged
}

/// Build a `name → AttachmentSnap` map for one side. Skips
/// attachments whose `ref_id` is out of bounds in `binaries` (matches
/// the conservative posture elsewhere in the crate: corrupt refs
/// don't block the merge — they're effectively absent from the
/// comparator). Duplicate names on the same side (illegal per KDBX
/// but the upstream model doesn't enforce uniqueness) collapse to
/// first-occurrence wins, same as the custom-field map.
fn attachment_map<'a>(entry: &'a Entry, binaries: &[Binary]) -> HashMap<&'a str, AttachmentSnap> {
    let mut out = HashMap::with_capacity(entry.attachments.len());
    for att in &entry.attachments {
        let Some(bin) = binaries.get(att.ref_id as usize) else {
            continue;
        };
        out.entry(att.name.as_str()).or_insert(AttachmentSnap {
            sha256: Some(sha256_of(&bin.data)),
            size: Some(bin.data.len() as u64),
        });
    }
    out
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
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
///
/// **Candidate set includes each side's *current* entry**, not just
/// `<History>` snapshots. The common case for LCA-by-current is:
///
/// 1. Both sides start in sync at state X (mtime T0).
/// 2. The remote writer edits the entry. KDBX semantics: the writer
///    pushes the pre-edit copy (still at content X, mtime T0) into
///    `remote.history`, then mutates the current to state Y at T1.
/// 3. The local writer hasn't touched the entry. `local.current` is
///    still (X, T0). Crucially, `local.history` does **not** contain
///    a snapshot of (X, T0) — local never edited, so no snapshot was
///    pushed.
///
/// Without considering current entries as candidates, the only shared
/// records would be older snapshots predating T0 — and from one of
/// those older ancestors, both sides look like edits, producing a
/// false-positive conflict. Including `local.current` in the candidate
/// pool lets us recognise (X, T0) as the genuine LCA, after which the
/// per-field 3-way classifier auto-resolves every difference to remote.
pub(crate) fn find_common_ancestor<'a>(
    local: &'a Entry,
    remote: &'a Entry,
    local_binaries: &[Binary],
    remote_binaries: &[Binary],
) -> Option<&'a Entry> {
    // Group remote candidates by mtime. Candidates = current + history.
    let mut remote_by_mtime: HashMap<chrono::DateTime<chrono::Utc>, Vec<&Entry>> = HashMap::new();
    for snap in std::iter::once(remote).chain(remote.history.iter()) {
        if let Some(t) = snap.times.last_modification_time {
            remote_by_mtime.entry(t).or_default().push(snap);
        }
    }

    // Walk local candidates (current + history) newest → oldest so the
    // first content-matching hit is the most recent shared record.
    let mut local_iter: Vec<&Entry> = std::iter::once(local)
        .chain(local.history.iter())
        .filter(|e| e.times.last_modification_time.is_some())
        .collect();
    local_iter.sort_by_key(|e| std::cmp::Reverse(e.times.last_modification_time));

    for l in local_iter {
        let t = l.times.last_modification_time?;
        let Some(remotes) = remote_by_mtime.get(&t) else {
            continue;
        };
        // Each side's entries reference their own pool's binaries.
        // After slice B5, attachments are part of the hash so the
        // pool argument matters per call.
        let lh = entry_content_hash(l, local_binaries);
        for r in remotes {
            let rh = entry_content_hash(r, remote_binaries);
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
    use crate::conflict::{AttachmentDeltaKind, FieldDeltaKind};
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

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
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

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
        assert_eq!(lca.title, "shared");
    }

    #[test]
    fn lca_none_when_no_overlap() {
        let mut local = entry();
        local.history = vec![snapshot("v1", at(2026, 1))];
        let mut remote = entry();
        remote.history = vec![snapshot("v2", at(2026, 2))];

        assert!(find_common_ancestor(&local, &remote, &[], &[]).is_none());
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

        let out = merge_entry(&local, &remote, &[], &[]);
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

        let out = merge_entry(&local, &remote, &[], &[]);
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

        let out = merge_entry(&local, &remote, &[], &[]);
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

        let out = merge_entry(&local, &remote, &[], &[]);
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "x");
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::BothDiffer);
    }

    #[test]
    fn local_only_custom_field_classified_as_local_only() {
        let mut local = entry();
        local.custom_fields = vec![CustomField::new("x", "v", false)];
        let remote = entry();

        let out = merge_entry(&local, &remote, &[], &[]);
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::LocalOnly);
    }

    #[test]
    fn remote_edit_pushed_pre_edit_into_history_local_unchanged_auto_resolves_remote() {
        // Reproduces the common external-edit pattern:
        // 1. Both sides start in sync at (Title="A", mtime=day1). Local
        //    has no history snapshot of this state — local was the
        //    creator and never edited.
        // 2. Remote writer edits the entry: pushes (A, day1) into
        //    remote.history, mutates current to (Title="B", mtime=day2).
        // 3. Local hasn't touched it: current is still (A, day1).
        //
        // The LCA *is* local.current itself (matches remote.history[0]
        // by mtime + content). With the broadened candidate set the
        // walker recognises this and the per-field 3-way classifier
        // sees local == ancestor → auto-resolves Title to Remote.
        let pre_edit = snapshot("A", at(2026, 1));

        let mut local = entry();
        local.title = "A".into();
        local.times = at(2026, 1);
        // No local.history — local never edited.

        let mut remote = entry();
        remote.title = "B".into();
        remote.times = at(2026, 2);
        remote.history = vec![pre_edit];

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA via local.current");
        assert_eq!(lca.title, "A");

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.had_ancestor);
        assert!(
            out.conflicts.is_empty(),
            "expected auto-resolve, got conflicts: {:?}",
            out.conflicts
        );
        assert_eq!(out.auto_resolutions, vec![("Title".into(), Side::Remote)]);
    }

    #[test]
    fn local_edit_pushed_pre_edit_into_history_remote_unchanged_auto_resolves_local() {
        // Symmetric: local edited (pushed pre-edit into local.history,
        // moved current forward). Remote.current is the unedited
        // pre-edit state with no history of its own. LCA is
        // remote.current.
        let pre_edit = snapshot("A", at(2026, 1));

        let mut local = entry();
        local.title = "B".into();
        local.times = at(2026, 2);
        local.history = vec![pre_edit];

        let mut remote = entry();
        remote.title = "A".into();
        remote.times = at(2026, 1);

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA via remote.current");
        assert_eq!(lca.title, "A");

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.had_ancestor);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions, vec![("Title".into(), Side::Local)]);
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

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.had_ancestor);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions, vec![("x".into(), Side::Local)]);
    }

    // -----------------------------------------------------------------
    // Attachment classifier (slice B2)
    // -----------------------------------------------------------------
    //
    // Coverage of the classification table in MERGE_ATTACHMENT_DESIGN.md.
    // The classifier output isn't read anywhere yet (consumer lands in
    // slice B3) so these tests assert directly on `out
    // .attachment_auto_resolutions` and `out.attachment_conflicts`.

    use keepass_core::model::{Attachment, Binary};

    fn bin(data: &[u8]) -> Binary {
        Binary::new(data.to_vec(), false)
    }

    fn att(name: &str, ref_id: u32) -> Attachment {
        Attachment::new(name, ref_id)
    }

    #[test]
    fn attachment_byte_identical_on_both_sides_is_silent() {
        // Same name, same bytes (independent pools each have idx 0 = b"x").
        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        let mut remote = entry();
        remote.attachments = vec![att("note.txt", 0)];

        let out = merge_entry(&local, &remote, &[bin(b"x")], &[bin(b"x")]);
        assert!(out.attachment_auto_resolutions.is_empty());
        assert!(out.attachment_conflicts.is_empty());
    }

    #[test]
    fn attachment_both_differ_no_ancestor_is_a_conflict() {
        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        let mut remote = entry();
        remote.attachments = vec![att("note.txt", 0)];

        let out = merge_entry(&local, &remote, &[bin(b"L")], &[bin(b"R")]);
        assert!(out.attachment_auto_resolutions.is_empty());
        assert_eq!(out.attachment_conflicts.len(), 1);
        let delta = &out.attachment_conflicts[0];
        assert_eq!(delta.name, "note.txt");
        assert_eq!(delta.kind, AttachmentDeltaKind::BothDiffer);
        assert!(delta.local_sha256.is_some());
        assert!(delta.remote_sha256.is_some());
        assert_eq!(delta.local_size, Some(1));
        assert_eq!(delta.remote_size, Some(1));
        assert_ne!(delta.local_sha256, delta.remote_sha256);
    }

    #[test]
    fn attachment_both_differ_ancestor_matches_local_auto_resolves_remote() {
        // Ancestor matches local's bytes → remote did the edit → take
        // remote. Both pools carry the ancestor bytes at idx 0; remote
        // has its edited copy at idx 1. After B5 the LCA hash covers
        // attachments, so both sides' ancestor records must dereference
        // to identical bytes for the LCA walker to match them.
        let mut ancestor = entry();
        ancestor.attachments = vec![att("note.txt", 0)];
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.attachments = vec![att("note.txt", 1)]; // remote's edit at idx 1
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[bin(b"L")], &[bin(b"L"), bin(b"R")]);
        assert!(out.attachment_conflicts.is_empty());
        assert_eq!(out.attachment_auto_resolutions.len(), 1);
        assert_eq!(out.attachment_auto_resolutions[0].name, "note.txt");
        assert_eq!(out.attachment_auto_resolutions[0].side, Side::Remote);
    }

    #[test]
    fn attachment_both_differ_ancestor_matches_remote_auto_resolves_local() {
        // Symmetric: ancestor matches remote's bytes → local edited.
        let mut ancestor = entry();
        ancestor.attachments = vec![att("note.txt", 0)];
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.attachments = vec![att("note.txt", 0)];
        remote.history = vec![ancestor];

        // local pool: idx 0 = the LCA bytes b"R" (ancestor matches remote);
        // idx 1 = local-current's edited bytes b"L". Re-point the
        // attachments so each refers to its appropriate slot.
        local.attachments = vec![att("note.txt", 1)];
        local.history[0].attachments = vec![att("note.txt", 0)];

        let out = merge_entry(&local, &remote, &[bin(b"R"), bin(b"L")], &[bin(b"R")]);
        assert!(out.attachment_conflicts.is_empty());
        assert_eq!(out.attachment_auto_resolutions.len(), 1);
        assert_eq!(out.attachment_auto_resolutions[0].side, Side::Local);
    }

    #[test]
    fn attachment_local_only_no_ancestor_auto_resolves_local() {
        // Local added an attachment; ancestor lacked it; remote unchanged.
        let mut ancestor = entry();
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.attachments = vec![att("added.txt", 0)];
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[bin(b"new")], &[]);
        assert!(out.attachment_conflicts.is_empty());
        assert_eq!(out.attachment_auto_resolutions.len(), 1);
        assert_eq!(out.attachment_auto_resolutions[0].name, "added.txt");
        assert_eq!(out.attachment_auto_resolutions[0].side, Side::Local);
    }

    #[test]
    fn attachment_local_only_ancestor_matched_remote_deleted_honours_deletion() {
        // Local has the attachment, remote dropped it. Ancestor had it
        // with the same bytes as local → remote initiated the deletion
        // and local didn't concurrently edit. Auto-honour by taking
        // remote (whose state for this name is "absent"). Both pools
        // must carry the ancestor's bytes at idx 0 for the LCA walker
        // to match the ancestor record across sides (B5 hash includes
        // attachments).
        let mut ancestor = entry();
        ancestor.attachments = vec![att("note.txt", 0)];
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[bin(b"shared")], &[bin(b"shared")]);
        assert!(out.attachment_conflicts.is_empty());
        assert_eq!(out.attachment_auto_resolutions.len(), 1);
        assert_eq!(out.attachment_auto_resolutions[0].side, Side::Remote);
    }

    #[test]
    fn attachment_local_only_ancestor_differed_is_delete_edit_conflict() {
        // Local has bytes X for "note.txt". Remote dropped it. Ancestor
        // had bytes Y for "note.txt" (i.e. local concurrently edited
        // the bytes while remote was deleting). Genuine conflict — the
        // user has to decide between local's edit and remote's delete.
        let mut ancestor = entry();
        ancestor.attachments = vec![att("note.txt", 0)]; // local-pool idx 0 = b"Y"
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.attachments = vec![att("note.txt", 1)]; // local-pool idx 1 = b"X"
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[bin(b"Y"), bin(b"X")], &[]);
        assert!(out.attachment_auto_resolutions.is_empty());
        assert_eq!(out.attachment_conflicts.len(), 1);
        assert_eq!(
            out.attachment_conflicts[0].kind,
            AttachmentDeltaKind::LocalOnly
        );
    }

    #[test]
    fn attachment_remote_only_no_ancestor_auto_resolves_remote() {
        // Remote added a new attachment; ancestor lacked it.
        let mut ancestor = entry();
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.history = vec![ancestor.clone()];

        let mut remote = entry();
        remote.attachments = vec![att("added.txt", 0)];
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[], &[bin(b"new")]);
        assert!(out.attachment_conflicts.is_empty());
        assert_eq!(out.attachment_auto_resolutions.len(), 1);
        assert_eq!(out.attachment_auto_resolutions[0].side, Side::Remote);
    }

    #[test]
    fn attachment_no_ancestor_fallback_conflicts_every_difference() {
        // No LCA at all — every attachment-level difference is a
        // conflict, never an auto-resolution. Mirrors the field-side
        // fallback that the module docs describe.
        let mut local = entry();
        local.attachments = vec![att("note.txt", 0)];
        let mut remote = entry();
        remote.attachments = vec![att("other.txt", 0)];

        let out = merge_entry(&local, &remote, &[bin(b"L")], &[bin(b"R")]);
        assert!(out.attachment_auto_resolutions.is_empty());
        assert_eq!(out.attachment_conflicts.len(), 2);
        let mut kinds: Vec<AttachmentDeltaKind> =
            out.attachment_conflicts.iter().map(|d| d.kind).collect();
        kinds.sort_by_key(|k| format!("{k:?}"));
        assert_eq!(
            kinds,
            vec![
                AttachmentDeltaKind::LocalOnly,
                AttachmentDeltaKind::RemoteOnly
            ]
        );
    }

    #[test]
    fn attachment_out_of_bounds_ref_id_is_treated_as_absent() {
        // Corrupt ref_id → classifier acts as if the attachment were
        // absent on that side. Mirrors the conservative posture
        // elsewhere in the crate (skip-malformed rather than fail-merge).
        let mut local = entry();
        local.attachments = vec![att("note.txt", 99)]; // out of bounds
        let mut remote = entry();
        remote.attachments = vec![att("note.txt", 0)];

        let out = merge_entry(&local, &remote, &[], &[bin(b"R")]);
        // Local-side appears absent → kind is RemoteOnly (one-sided),
        // ancestor missing → conflict.
        assert_eq!(out.attachment_conflicts.len(), 1);
        assert_eq!(
            out.attachment_conflicts[0].kind,
            AttachmentDeltaKind::RemoteOnly
        );
    }
}
