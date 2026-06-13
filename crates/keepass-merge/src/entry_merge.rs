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
//! other side's history), [`resolve_no_lca`] applies:
//! - a slot present on **one side only** is taken (additive — present
//!   beats absent), so a transient sync-race add (a new custom field, a
//!   freshly-fetched favicon) auto-resolves instead of parking a
//!   spurious conflict;
//! - a slot present on **both sides with differing values** is a
//!   `Conflict` (parked for the resolver UI) — we never silently pick a
//!   winner by mtime, so a genuine concurrent value edit (e.g. a
//!   password) is surfaced, not dropped.
//!
//! Standard fields are always present on both sides, so they only ever
//! hit the both-present branch → still conflict (unchanged). Attachments
//! deliberately stay conflict-only on no-LCA (see `classify_attachments`).

use std::collections::{BTreeSet, HashMap};

use keepass_core::model::{Binary, Entry};
use sha2::{Digest, Sha256};

use crate::conflict::{AttachmentDelta, AttachmentDeltaKind, FieldDelta, FieldDeltaKind};
use crate::hash::{ct_eq, entry_content_hash};
use crate::time::second_resolution;

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
    /// Icon-divergence delta when the classifier sees a genuine
    /// conflict: two *different* present `custom_icon_uuid`s that can't
    /// be 3-way auto-resolved. `None` when icons match or the classifier
    /// auto-resolved — including the no-LCA absence-vs-present case,
    /// where the present icon wins (absence is the implicit base; see
    /// `classify_icon`). Routed onto [`EntryConflict::icon_delta`] by
    /// `route_both_present`.
    pub icon_conflict: Option<crate::conflict::IconDelta>,
    /// Icon auto-resolution when the classifier had a clear answer
    /// (LCA matches one side; take the other). Mutually exclusive with
    /// `icon_conflict`. Consumed by `route_both_present` (routing) and
    /// `build_merged_entry` (apply overlay).
    pub icon_auto_resolution: Option<Side>,
    /// `true` iff [`find_common_ancestor`] produced a hit. `false` means
    /// every conflicting field was classified conservatively (no
    /// auto-resolution attempted).
    ///
    /// Read by [`crate::merge::merge`]'s routing pass: when `false` and
    /// the entry routes to a conflict bucket, the entry id is recorded
    /// in [`crate::MergeOutcome::lca_missing_entries`] so the FFI layer
    /// can surface the spec §6 warn-severity log ("Entry 'X' had no
    /// shared history — manual review needed for all changed fields").
    pub had_ancestor: bool,
    /// `true` when this entry's merge tripped the "independent
    /// same-UUID creation, no LCA, no shared history" corruption signal
    /// per spec §3 case 2: both sides hold the entry, both sides'
    /// `<History>` lists are empty, both sides carry a
    /// `last_modification_time`, and no shared ancestor was found.
    /// This combination cannot arise from a normal sync flow — UUIDs
    /// are random and unique — and is a stronger signal than a plain
    /// "histories truncated" no-LCA fall-through. The merge still
    /// routes the entry through the parking path (don't auto-fix) but
    /// the caller is expected to surface a structured error.
    pub corruption_signal: bool,
}

/// One auto-resolved attachment decision. Companion to the field-level
/// `(String, Side)` entries in [`EntryMergeOutput::auto_resolutions`].
///
/// `side` says which side wins. Apply consumes the winner like field
/// merge does: ensure the merged entry's attachment list mirrors that
/// side's presence-or-absence for this name. When the winning side has
/// the attachment, take its bytes; when the winning side doesn't,
/// drop it from the merged entry. [`classify`] surfaces the remote-side
/// winners as [`AttachmentChange`] instructions on
/// [`Classification::AutoMerged`].
#[derive(Debug, Clone)]
pub(crate) struct AttachmentAutoResolution {
    pub name: String,
    pub side: Side,
}

/// One attachment instruction accompanying
/// [`Classification::AutoMerged`] — the LCA-backed, *one-sided* peer
/// attachment changes the verdict adopted (5c: attachment
/// propagation through the pairwise owner-rows path).
///
/// Carried as explicit instructions, bytes included, rather than via
/// the merged [`Entry`]'s `attachments` list: that list's `ref_id`s
/// index a binary pool, and a merged entry mixing kept-local and
/// adopted-peer attachments would have to reference two pools at
/// once. The consumer applies these against its own storage instead
/// (content-addressed, so the bytes dedup on arrival).
#[derive(Clone)]
#[non_exhaustive]
pub enum AttachmentChange {
    /// Adopt the peer's bytes under `name` (add, or replace the local
    /// attachment of the same name).
    Take {
        /// Attachment name (the KDBX `<Binary><Key>`).
        name: String,
        /// The peer-side payload bytes.
        bytes: Vec<u8>,
    },
    /// Remove the local attachment under `name` — the peer deleted it
    /// after the shared ancestor, and local left it untouched.
    Drop {
        /// Attachment name.
        name: String,
    },
}

impl std::fmt::Debug for AttachmentChange {
    /// Manual impl: prints the byte *count*, never the bytes —
    /// attachment payloads are vault content and must not reach logs
    /// via a stray `{:?}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Take { name, bytes } => f
                .debug_struct("Take")
                .field("name", name)
                .field("bytes_len", &bytes.len())
                .finish(),
            Self::Drop { name } => f.debug_struct("Drop").field("name", name).finish(),
        }
    }
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
    let had_ancestor = ancestor.is_some();
    // Corruption signal per spec §3: same UUID seen on both sides, no
    // shared ancestor, and neither side has any history records. Real
    // edit divergence either produces a shared ancestor (LCA found) or
    // leaves at least one side with a non-empty history (the side that
    // did the editing). Two history-empty entries with the same UUID
    // and disjoint state can only arise from independent creation —
    // i.e. UUID collision, which kdbx UUIDs make vanishingly unlikely
    // — or a corruption bug elsewhere in the stack. Require both sides
    // to carry a `last_modification_time`: an empty-history entry with
    // an absent mtime is just a freshly-defaulted shell, not a
    // corruption signal.
    let corruption_signal = !had_ancestor
        && local.history.is_empty()
        && remote.history.is_empty()
        && local.times.last_modification_time.is_some()
        && remote.times.last_modification_time.is_some();

    let mut out = EntryMergeOutput {
        conflicts: Vec::new(),
        auto_resolutions: Vec::new(),
        attachment_conflicts: Vec::new(),
        attachment_auto_resolutions: Vec::new(),
        merged_tags,
        tags_changed_from_local,
        icon_conflict: None,
        icon_auto_resolution: None,
        had_ancestor,
        corruption_signal,
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
        // No LCA → standard fields are always present on both sides, so
        // `resolve_no_lca(true, true)` is `Conflict` (park) — same as the
        // pre-existing behaviour.
        let res = resolution.unwrap_or_else(|| resolve_no_lca(true, true));
        match res {
            Resolution::Auto(side) => out.auto_resolutions.push((name.into(), side)),
            Resolution::Conflict => out.conflicts.push(FieldDelta {
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
        // No LCA → present-wins for a key on one side only; both-present
        // differing → Conflict (park).
        let res = resolution.unwrap_or_else(|| resolve_no_lca(l.is_some(), r.is_some()));
        match res {
            Resolution::Auto(side) => out.auto_resolutions.push((key.into(), side)),
            Resolution::Conflict => out.conflicts.push(FieldDelta {
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

    classify_icon(local, remote, &mut out);

    out
}

/// Resolution for a single divergent slot when there is no shared
/// ancestor (see `merge_entry`'s no-LCA policy):
/// - present on one side only → take the present side (additive);
/// - present on both with differing values → `Conflict` (park it for
///   the resolver UI; we deliberately do NOT silently pick by mtime —
///   a genuine two-value clash is exactly what the conflict UI is for).
///
/// Both-absent can't reach here — equal slots are skipped by the caller.
fn resolve_no_lca(local_present: bool, remote_present: bool) -> Resolution {
    match (local_present, remote_present) {
        (true, false) => Resolution::Auto(Side::Local),
        (false, true) => Resolution::Auto(Side::Remote),
        _ => Resolution::Conflict,
    }
}

/// Classify `custom_icon_uuid` divergence between local and remote
/// against the (optional) LCA. See `_localdocs/MERGE_ICON_CLASSIFIER.md`.
///
/// Absence is the implicit base for icons: a present custom icon is an
/// *additive* change that wins over absence. This holds **uniformly**,
/// whether or not a content-LCA was found:
/// - exactly one side has an icon → take the present one (the absent
///   side is treated as never having had it, not as a deliberate
///   removal). The icon is no longer part of content identity (it's
///   excluded from `entry_content_hash`), so the content-LCA is matched
///   *ignoring* the icon — its icon value is therefore not a
///   trustworthy base against which to honour a "removal". The product
///   rule is that a fetched/assigned favicon must survive a merge
///   rather than be silently dropped, and present-wins is convergent
///   (the mirror side takes the present icon too);
/// - both sides carry a *differing* icon → resolve by **cross-side
///   history membership**, NOT the content-LCA. The icon is excluded
///   from `entry_content_hash`, so the matched content-LCA's icon is not
///   a reliable base (it can be one side's own current). Instead: if one
///   side's current icon is a value the *other* side has already moved
///   past (present in its prior versions), that side is behind → take the
///   side that advanced; two genuinely-new values (neither in the other's
///   history) → conflict. This is symmetric in `(local, remote)`, so both
///   peers reach the same result — convergent, unlike a direction-
///   dependent 3-way against a one-sided ancestor;
/// - identical icons → no row.
///
/// Base icon ID is not modelled here — per spec rule 4 it rides along
/// silently with the chosen icon side.
fn classify_icon(local: &Entry, remote: &Entry, out: &mut EntryMergeOutput) {
    let l = local.custom_icon_uuid;
    let r = remote.custom_icon_uuid;
    if l == r {
        return;
    }
    let resolution = match (l, r) {
        // Exactly one side present → additive present-wins (see docs).
        (Some(_), None) => Resolution::Auto(Side::Local),
        (None, Some(_)) => Resolution::Auto(Side::Remote),
        // Both present and differing → resolve by cross-side history
        // membership (the content-LCA's icon is unreliable; see fn docs).
        // If one side's current icon is a value the OTHER has already
        // moved past, that side is behind → take the side that advanced.
        // Two genuinely-new values → clash → park. Symmetric in
        // (local, remote) ⇒ both peers converge on the same result.
        (Some(_), Some(_)) => {
            let remote_behind = side_has_icon(local, r); // r is a prior local value
            let local_behind = side_has_icon(remote, l); // l is a prior remote value
            match (local_behind, remote_behind) {
                (false, true) => Resolution::Auto(Side::Local),
                (true, false) => Resolution::Auto(Side::Remote),
                _ => Resolution::Conflict,
            }
        }
        // `l == r` already returned above; (None, None) is unreachable.
        (None, None) => return,
    };
    match resolution {
        Resolution::Auto(side) => out.icon_auto_resolution = Some(side),
        Resolution::Conflict => {
            out.icon_conflict = Some(crate::conflict::IconDelta {
                local_custom_icon_uuid: l,
                remote_custom_icon_uuid: r,
            });
        }
    }
}

/// True when `icon` is present (as a `custom_icon_uuid`) on the entry's
/// current state or any of its history snapshots. Used by `classify_icon`
/// for cross-side staleness: an icon found in the *other* side's versions
/// means that side has already seen (and moved past) this value.
fn side_has_icon(entry: &Entry, icon: Option<uuid::Uuid>) -> bool {
    icon.is_some()
        && std::iter::once(entry)
            .chain(entry.history.iter())
            .any(|e| e.custom_icon_uuid == icon)
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
        // Attachments deliberately stay on the conservative no-LCA →
        // conflict path (unlike custom fields / icon): they have a
        // dedicated keep-local / keep-remote / keep-both resolver flow,
        // and a pre-existing cross-pool LCA-matching limitation means a
        // genuine delete-vs-edit often presents as no-LCA — present-wins
        // there would silently undo deletions and bypass that UI.
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

/// Find the most-recent entry version present on both sides — the
/// per-entry LCA for the 3-way classifiers.
///
/// **Matching runs in two passes.** Content alone is not a generation
/// identity: an edit that returns an entry to a previously-seen content
/// state (removing an attachment ⇒ back to the pre-add state; setting a
/// field back to an old value) makes the SAME hash recur at different
/// generations, and a content-only matcher can alias a new record to an
/// ancient shared snapshot. Against that wrong ancestor, the peer's
/// stale copy reads as a fresh one-sided change (the alias-er's newest
/// intent silently reverts), or a one-sided change reads as both-sided
/// (a facet divergence the verdict then swallows) — keyhole DESIGN.md
/// Finding #8.
///
/// **The winning pair maximises
/// `min(local generation rank, remote generation rank)`** (rank: oldest
/// history snapshot = 0, …, current = highest), tie-broken by the later
/// local mtime, then the later local rank. The fork point is by
/// definition a version BOTH lineages contain, with everything after it
/// on each side being that side's divergence — so the tightest ancestor
/// is the pair sitting latest in BOTH lineages, not the first content
/// match found walking one side. Mtime-first walking (the previous
/// rule) breaks inside a same-second burst, where an entry's CURRENT
/// record (e.g. just-removed-attachment, content equal to an ancient
/// state) ties on time with everything and matches an ancient remote
/// snapshot before the true latest shared generation is ever considered
/// — the dominant shape of the Finding-#8 fuzz failures. Rank ordering
/// also kills the cross-second variant (restoring an old value made the
/// restorer's current alias to the peer's ancient snapshot and silently
/// revert), because the true shared generation always out-ranks an
/// ancient recurrence on the min() side.
///
/// **Why mtime is a tie-break, not a match gate:** the same logical
/// generation does NOT carry the same mtime on both replicas — classify's
/// auto-merge adoption builds the advanced entry from a clone of the
/// LOCAL side, so an adopted change keeps the adopter's mtime (observed
/// live: identical content hashes one second apart). Gating pairs on
/// mtime equality therefore rejects genuine shared generations and
/// regresses to ancient pre-fork pairs — measured at 3× the failure
/// rate of content-only matching on the attachment fuzzer. A re-stamped
/// echo (same value, mtime seconds off — KDBX-3.1 truncation or a
/// round-trip re-stamp) must also still match, and does. (Residue: if
/// history quota-trimming has evicted the true shared generation, the
/// surviving pick is the best available guess, as before.)
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
    // Candidates per side in generation-RANK order: oldest history
    // snapshot = 0, …, current = highest (KDBX history is oldest-first
    // on disk). Each side dereferences its own binary pool. Constant-
    // time hash compare per the workspace rule (hashes aren't secret
    // here, but the convention holds regardless).
    type PairKey = (usize, Option<chrono::DateTime<chrono::Utc>>, usize);
    type Candidate<'e> = (
        &'e Entry,
        [u8; 32],
        Option<chrono::DateTime<chrono::Utc>>,
        usize,
    );
    let rank_candidates = |e: &'a Entry, binaries: &[Binary]| -> Vec<Candidate<'a>> {
        e.history
            .iter()
            .chain(std::iter::once(e))
            .enumerate()
            .map(|(rank, c)| {
                (
                    c,
                    entry_content_hash(c, binaries),
                    second_resolution(c.times.last_modification_time),
                    rank,
                )
            })
            .collect()
    };
    let locals = rank_candidates(local, local_binaries);
    let remotes = rank_candidates(remote, remote_binaries);

    // Best content-matching pair by (min rank, local mtime, local rank).
    let mut best: Option<(PairKey, &'a Entry)> = None;
    for (l, lh, lm, lrank) in &locals {
        for (_, rh, _, rrank) in &remotes {
            if !ct_eq(lh, rh) {
                continue;
            }
            let key = ((*lrank).min(*rrank), *lm, *lrank);
            if best.as_ref().is_none_or(|(k, _)| key > *k) {
                best = Some((key, l));
            }
        }
    }

    let chosen = best.map(|(_, l)| l);
    // `KEYS_DEBUG_LCA=1` diagnostics: dump every candidate pair-side and
    // the chosen ancestor. Same secret posture as keys-engine's
    // KEYS_DEBUG_ADOPTION — uuid + ranks + floored mtimes + attachment
    // COUNTS only, plus a 4-byte content-hash prefix to correlate
    // candidates across the two sides; never field values, names, or
    // full hashes (stderr may be captured into persistent logs). This
    // dump is what surfaced the auto-merge-keeps-adopter-mtime fact
    // that killed the (mtime, hash) compound-key fix candidate.
    if std::env::var_os("KEYS_DEBUG_LCA").is_some() {
        let dump = |tag: &str, cs: &[Candidate<'_>]| {
            for (c, h, m, r) in cs {
                eprintln!(
                    "LCA-DEBUG   {tag} rank={r} mtime={m:?} hash={:02x}{:02x}{:02x}{:02x} atts={}",
                    h[0],
                    h[1],
                    h[2],
                    h[3],
                    c.attachments.len()
                );
            }
        };
        eprintln!("LCA-DEBUG entry={}", local.id.0);
        dump("local ", &locals);
        dump("remote", &remotes);
        match &chosen {
            Some(c) => eprintln!(
                "LCA-DEBUG chosen mtime={:?} atts={}",
                c.times.last_modification_time,
                c.attachments.len()
            ),
            None => eprintln!("LCA-DEBUG chosen NONE"),
        }
    }
    chosen
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

// ───────────────────────────────────────────────────────────────────────────
// Public entry-pair classifier — the multi-peer owner-rows "brain".
//
// See `_project-management/sync-multipeer-store.md` §9 Phase 1. This is a
// purely additive public wrapper around [`find_common_ancestor`] +
// [`merge_entry`]; it changes no existing caller. The owner-rows store
// (keys-engine, Phase 2+) calls it per entry to decide, for one peer's
// version of an entry: advance our copy (`AutoMerged`), keep the peer's
// value as a conflict row (`Conflict`), or do nothing (`InSync`).
// ───────────────────────────────────────────────────────────────────────────

/// Granularity of the *both-sides-edited* conflict test (design doc §3).
///
/// Only affects the one case where each side moved a *different* facet off
/// the shared ancestor — everywhere else the verdict is identical. The knob
/// the design doc calls "the one real granularity knob"; kept as a parameter
/// so the call site (not the brain) owns the decision, to be settled on soak
/// feel rather than guesswork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Granularity {
    /// "I changed Title, you changed Notes" merges silently; only a genuine
    /// *same*-field (or icon) clash is a conflict. Matches the behaviour of
    /// the vault-level `merge` / [`crate::apply_merge`].
    Field,
    /// Any item both sides touched is flagged for the resolver, even when the
    /// edited fields don't overlap. Shown a touch more often than `Field`;
    /// identical resolver UX. The password-manager-leaning option per the
    /// design doc.
    Item,
}

/// Verdict of [`classify`] for one `(local, peer)` entry pair.
///
/// Mirrors the validated spike's `Outcome` (Agree / AutoResolved / Conflict)
/// over the real [`Entry`] type.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Classification {
    /// The two sides agree across every facet `classify` reconciles
    /// (standard + custom fields, icon, tags) — nothing to ingest.
    ///
    /// Facets `classify` deliberately does **not** examine — attachments,
    /// `<History>`, `custom_data`, timestamps — can still differ here: an
    /// entry that diverges *only* in one of those classifies `InSync`.
    /// Reconciling them is [`crate::apply_merge`]'s job (content pools land
    /// in a later phase); see [`Classification::AutoMerged`] for the same
    /// scope boundary.
    InSync,
    /// Every divergence auto-resolved against the LCA. `merged` is `local`
    /// advanced to the combined result — one-sided takes, plus (under
    /// [`Granularity::Field`]) both-sided edits of *different* fields. No
    /// user input required.
    ///
    /// When only the peer is behind (we moved a facet off the LCA, the peer
    /// didn't), `merged` equals `local` — there is nothing to fold in, but
    /// the sides still differ so this is not `InSync`.
    AutoMerged {
        /// `local` with the peer's non-conflicting field/icon changes folded
        /// in and tags 3-way-merged against the ancestor.
        ///
        /// **Scope.** `<History>`, `custom_data`, and timestamps are
        /// inherited from `local` **unchanged**. The merged entry's
        /// `attachments` list is also local's — adopted attachment
        /// changes travel as the explicit [`AttachmentChange`]
        /// instructions alongside, because a single entry cannot
        /// reference two binary pools at once (see `attachment_changes`).
        merged: Box<Entry>,
        /// LCA-backed one-sided peer attachment changes to apply after
        /// adopting `merged` (5c). Empty when attachments agree or only
        /// local moved them. Both-sided attachment divergence stays on
        /// the conservative conflict path (`classify_attachments`'s
        /// no-LCA posture included) and is **not** auto-applied — see
        /// the scope note on [`Classification::Conflict`].
        attachment_changes: Vec<AttachmentChange>,
    },
    /// At least one facet genuinely conflicts: both sides moved the same field
    /// or the icon off the LCA (any granularity), or — under
    /// [`Granularity::Item`] — both sides edited the item at all. Carries the
    /// full resolver payload, reusing the same [`crate::conflict::EntryConflict`]
    /// the vault-level merge produces so the FFI + resolver UI are unchanged.
    ///
    /// `field_deltas` / `icon_delta` are populated per granularity:
    /// `Field` surfaces only the facets needing user input (same as the
    /// vault merge); `Item` surfaces every differing field/icon so the
    /// resolver shows the full per-field picker. `attachment_deltas` is always
    /// empty here — attachments ride [`crate::apply_merge`], not `classify`.
    ///
    /// Like attachments, any 3-way-merged tag set is **not** folded in on the
    /// conflict path: tag reconciliation for a conflicted entry is deferred to
    /// resolve time, mirroring the `AutoMerged` scope boundary.
    Conflict {
        /// Both full sides plus the differing-facet deltas.
        conflict: Box<crate::conflict::EntryConflict>,
    },
}

/// Classify one peer's version of an entry against ours, using the entry's
/// `<History>` as the shared ancestor (LCA). The reusable per-entry brain
/// behind the multi-peer owner-rows store.
///
/// Purely additive: wraps the existing `find_common_ancestor` +
/// `merge_entry` and changes no existing caller. `local_binaries` /
/// `peer_binaries` are the two sides' [`keepass_core::model::Vault`] binary
/// pools, threaded through so the LCA is located with the same content hash
/// the production merge uses.
///
/// When the two sides share no ancestor (e.g. `<History>` trimmed past the
/// fork point), the wrapped classifier falls back conservatively — a
/// both-present field that differs is a `Conflict`, never a silent pick — so
/// `classify` returns `Conflict` rather than guessing. See [`Classification`]
/// for the verdict shape and [`Granularity`] for the both-sides-edited knob.
pub fn classify(
    local: &Entry,
    peer: &Entry,
    local_binaries: &[Binary],
    peer_binaries: &[Binary],
    granularity: Granularity,
) -> Classification {
    let out = merge_entry(local, peer, local_binaries, peer_binaries);

    // A genuine conflict = both sides moved the *same* field, or the icon,
    // off the LCA. Both-sided attachment divergence (and the deliberate
    // no-LCA-conflict posture in `classify_attachments`) stays OUT of the
    // verdict for now: surfacing it here would park entries the owner-rows
    // resolver cannot yet resolve (conflict rows don't store attachments) —
    // the remaining 5c slice. LCA-backed one-sided attachment changes DO
    // feed the verdict below, as auto-merges.
    let genuine_conflict = !out.conflicts.is_empty() || out.icon_conflict.is_some();

    // Which side(s) moved a field/icon/attachment off the shared ancestor.
    // A genuine conflict means both sides moved the same facet, so it
    // counts for both.
    let local_moved = genuine_conflict
        || out.auto_resolutions.iter().any(|(_, s)| *s == Side::Local)
        || out.icon_auto_resolution == Some(Side::Local)
        || out
            .attachment_auto_resolutions
            .iter()
            .any(|r| r.side == Side::Local);
    let peer_moved = genuine_conflict
        || out.auto_resolutions.iter().any(|(_, s)| *s == Side::Remote)
        || out.icon_auto_resolution == Some(Side::Remote)
        || out
            .attachment_auto_resolutions
            .iter()
            .any(|r| r.side == Side::Remote);

    if !local_moved && !peer_moved && !out.tags_changed_from_local {
        return Classification::InSync;
    }

    let is_conflict = match granularity {
        Granularity::Field => genuine_conflict,
        Granularity::Item => genuine_conflict || (local_moved && peer_moved),
    };

    if is_conflict {
        let (field_deltas, icon_delta) = match granularity {
            // Field-level: surface only the facets that need user input
            // (same as the vault-level merge's `EntryConflict`).
            Granularity::Field => (out.conflicts, out.icon_conflict),
            // Item-level: the whole item is flagged, so surface every
            // differing field/icon for the per-field picker (design doc §3).
            Granularity::Item => (
                differing_field_deltas(local, peer),
                icon_delta_if_differs(local, peer),
            ),
        };
        return Classification::Conflict {
            conflict: Box::new(crate::conflict::EntryConflict {
                entry_id: local.id,
                local: local.clone(),
                remote: peer.clone(),
                field_deltas,
                attachment_deltas: Vec::new(),
                icon_delta,
            }),
        };
    }

    // Auto-merge: advance `local` by the peer's one-sided field/icon changes
    // and the 3-way-merged tag set. Side::Local resolutions are already in
    // place (we started from a clone of `local`).
    let mut merged = local.clone();
    for (key, side) in &out.auto_resolutions {
        if *side == Side::Remote {
            take_field_from(&mut merged, peer, key);
        }
    }
    if out.icon_auto_resolution == Some(Side::Remote) {
        merged.custom_icon_uuid = peer.custom_icon_uuid;
    }
    merged.tags = out.merged_tags.into_iter().collect();

    // Remote-side attachment winners become explicit instructions:
    // the peer holding the name means "take its bytes" (dereferenced
    // from the peer pool here, where the pool is in scope); the peer
    // NOT holding it means its LCA-backed removal won — drop ours.
    // Side::Local winners need nothing: merged already is local.
    let attachment_changes = out
        .attachment_auto_resolutions
        .iter()
        .filter(|r| r.side == Side::Remote)
        .map(|r| {
            let peer_bytes = peer
                .attachments
                .iter()
                .find(|a| a.name == r.name)
                .and_then(|a| peer_binaries.get(a.ref_id as usize))
                .map(|b| b.data.clone());
            match peer_bytes {
                Some(bytes) => AttachmentChange::Take {
                    name: r.name.clone(),
                    bytes,
                },
                None => AttachmentChange::Drop {
                    name: r.name.clone(),
                },
            }
        })
        .collect();

    Classification::AutoMerged {
        merged: Box::new(merged),
        attachment_changes,
    }
}

/// Every standard or custom field whose value differs between the two sides,
/// classified by which side(s) hold it. Builds the item-level resolver
/// payload — every difference becomes a pickable row — where the field-level
/// path surfaces only the same-field clashes.
fn differing_field_deltas(local: &Entry, peer: &Entry) -> Vec<FieldDelta> {
    let mut deltas = Vec::new();
    for &name in STANDARD_FIELDS {
        if standard_value(local, name) != standard_value(peer, name) {
            // Standard fields are always present on both sides.
            deltas.push(FieldDelta {
                key: name.into(),
                kind: FieldDeltaKind::BothDiffer,
            });
        }
    }
    let local_custom = custom_map(local);
    let peer_custom = custom_map(peer);
    let mut keys: BTreeSet<&str> = BTreeSet::new();
    keys.extend(local_custom.keys().copied());
    keys.extend(peer_custom.keys().copied());
    for key in keys {
        let l = local_custom.get(key).copied();
        let p = peer_custom.get(key).copied();
        if l == p {
            continue;
        }
        let kind = match (l.is_some(), p.is_some()) {
            (true, true) => FieldDeltaKind::BothDiffer,
            (true, false) => FieldDeltaKind::LocalOnly,
            (false, true) => FieldDeltaKind::RemoteOnly,
            (false, false) => unreachable!("key collected from union of local + peer"),
        };
        deltas.push(FieldDelta {
            key: key.into(),
            kind,
        });
    }
    deltas
}

/// An [`crate::conflict::IconDelta`] iff the two sides' `custom_icon_uuid`
/// differ. The item-level companion to [`differing_field_deltas`].
fn icon_delta_if_differs(local: &Entry, peer: &Entry) -> Option<crate::conflict::IconDelta> {
    (local.custom_icon_uuid != peer.custom_icon_uuid).then_some(crate::conflict::IconDelta {
        local_custom_icon_uuid: local.custom_icon_uuid,
        remote_custom_icon_uuid: peer.custom_icon_uuid,
    })
}

/// Copy field `key`'s value from `source` into `target` — standard field,
/// custom field (value + `protected` bit), or removal of a custom field the
/// `source` no longer holds. Mirrors the apply layer's `set_field_from`; kept
/// local to the classifier so Phase 1 stays additive (no visibility change to
/// the apply internals). The two are small and stable; a future refactor can
/// unify them if a third caller appears.
fn take_field_from(target: &mut Entry, source: &Entry, key: &str) {
    match key {
        "Title" => target.title.clone_from(&source.title),
        "UserName" => target.username.clone_from(&source.username),
        "Password" => target.password.clone_from(&source.password),
        "URL" => target.url.clone_from(&source.url),
        "Notes" => target.notes.clone_from(&source.notes),
        _ => match source.custom_fields.iter().find(|f| f.key == key) {
            Some(src) => match target.custom_fields.iter_mut().find(|f| f.key == key) {
                Some(dst) => {
                    dst.value.clone_from(&src.value);
                    dst.protected = src.protected;
                }
                None => target
                    .custom_fields
                    .push(keepass_core::model::CustomField::new(
                        src.key.clone(),
                        src.value.clone(),
                        src.protected,
                    )),
            },
            None => target.custom_fields.retain(|f| f.key != key),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AttachmentChange, Classification, Granularity, Side, classify, find_common_ancestor,
        merge_entry,
    };
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
        // Distinct current titles: identical currents would themselves be
        // the (legitimate) latest shared version — see lca_none_when_no_overlap.
        let mut local = entry();
        local.title = "local-current".into();
        local.history = vec![snapshot("v1", at(2026, 1)), snapshot("v2", at(2026, 2))];
        let mut remote = entry();
        remote.title = "remote-current".into();
        remote.history = vec![snapshot("v1", at(2026, 1)), snapshot("v3", at(2026, 3))];

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
        assert_eq!(lca.title, "v1");
    }

    /// Finding #8, same-second alias: within one floored second mtimes
    /// cannot disambiguate generations, so pair selection must rank by
    /// GENERATION position. The old mtime-first walk left history
    /// oldest-first inside a tie, so an ancient snapshot whose content
    /// recurred matched before the true latest shared generation —
    /// turning a disjoint-field auto-merge into a spurious same-field
    /// conflict (and, facet-dependent, a silent divergence).
    #[test]
    fn lca_same_second_tie_prefers_newest_generation() {
        let t = at(2026, 1);
        // Shared lineage, all in one second: ("A","X") → ("B","X").
        let gen0 = {
            let mut e = snapshot("A", t.clone());
            e.notes = "X".into();
            e
        };
        let gen1 = {
            let mut e = snapshot("B", t.clone());
            e.notes = "X".into();
            e
        };
        // Remote edited title B→C; local edited notes X→Y. Disjoint.
        let mut remote = snapshot("C", t.clone());
        remote.notes = "X".into();
        remote.history = vec![gen0.clone(), gen1.clone()];
        let mut local = snapshot("B", t.clone());
        local.notes = "Y".into();
        local.history = vec![gen0, gen1];

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
        assert_eq!(
            (lca.title.as_str(), lca.notes.as_str()),
            ("B", "X"),
            "latest shared generation, not the ancient same-second recurrence",
        );
        match classify(&local, &remote, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(merged.title, "C", "remote's one-sided title lands");
                assert_eq!(merged.notes, "Y", "local's one-sided notes survive");
            }
            other => panic!("disjoint same-second edits must auto-merge, got {other:?}"),
        }
    }

    /// Finding #8, cross-second alias: an edit restoring a PREVIOUS value
    /// makes the restorer's current entry content-match the peer's
    /// ancient snapshot. Newest-local-first matching took that pair as
    /// the LCA, read the peer's stale copy as a fresh one-sided edit,
    /// and silently reverted the restore. Under min-rank pair selection
    /// the true shared generation (the pre-restore value, late in BOTH
    /// lineages) out-ranks the current↔ancient pair, and the restore —
    /// local's newest intent — survives.
    #[test]
    fn lca_replace_back_to_old_value_does_not_alias() {
        let gen0 = snapshot("old", at(2026, 1));
        let gen1 = snapshot("new", at(2026, 2));
        // Local restored "old" on day 3; remote still sits at "new".
        let mut local = snapshot("old", at(2026, 3));
        local.history = vec![gen0.clone(), gen1.clone()];
        let mut remote = snapshot("new", at(2026, 2));
        remote.history = vec![gen0];

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
        assert_eq!(
            (lca.title.as_str(), lca.times.last_modification_time),
            ("new", at(2026, 2).last_modification_time),
            "the pre-restore generation is the ancestor, not the aliased current/gen0 pair",
        );
        match classify(&local, &remote, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(merged.title, "old", "the restore must not silently revert");
            }
            other => panic!("one-sided restore must auto-merge keeping local, got {other:?}"),
        }
    }

    #[test]
    fn lca_collision_broken_by_content() {
        // Two history records share an mtime but differ in content; only the
        // matching-content one is the real ancestor. Distinct current titles
        // for the same reason as lca_found_by_mtime.
        let mtime = at(2026, 1);
        let mut local = entry();
        local.title = "local-current".into();
        local.history = vec![snapshot("shared", mtime.clone())];
        let mut remote = entry();
        remote.title = "remote-current".into();
        remote.history = vec![snapshot("other", mtime.clone()), snapshot("shared", mtime)];

        let lca = find_common_ancestor(&local, &remote, &[], &[]).expect("LCA");
        assert_eq!(lca.title, "shared");
    }

    #[test]
    fn lca_none_when_no_overlap() {
        // Distinct current titles too: matching is by content now, so two
        // *identical* currents (e.g. both empty) would legitimately be a
        // shared version. True no-overlap means no shared content anywhere.
        let mut local = entry();
        local.title = "local-current".into();
        local.history = vec![snapshot("v1", at(2026, 1))];
        let mut remote = entry();
        remote.title = "remote-current".into();
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
    fn local_only_custom_field_no_lca_takes_present() {
        // No LCA; a custom field present on one side only is additive →
        // take the present (local) side, not a conflict.
        let mut local = entry();
        local.custom_fields = vec![CustomField::new("x", "v", false)];
        let remote = entry();

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions.len(), 1);
        assert_eq!(out.auto_resolutions[0].0, "x");
        assert_eq!(out.auto_resolutions[0].1, Side::Local);
    }

    #[test]
    fn remote_only_custom_field_no_lca_takes_present() {
        // Symmetric: present on remote only → take Remote.
        let local = entry();
        let mut remote = entry();
        remote.custom_fields = vec![CustomField::new("x", "v", false)];

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.conflicts.is_empty());
        assert_eq!(out.auto_resolutions.len(), 1);
        assert_eq!(out.auto_resolutions[0].0, "x");
        assert_eq!(out.auto_resolutions[0].1, Side::Remote);
    }

    #[test]
    fn custom_field_both_present_differ_no_lca_parks_conflict() {
        // No LCA, same key on both sides with DIFFERENT values → park a
        // conflict; never silently pick one. This is the safety
        // guarantee for concurrent value edits (e.g. a password) — we
        // surface them in the resolver rather than LWW-dropping the loser.
        let mut local = entry();
        local.custom_fields = vec![CustomField::new("pw", "local-secret", true)];
        let mut remote = entry();
        remote.custom_fields = vec![CustomField::new("pw", "remote-secret", true)];

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.auto_resolutions.is_empty());
        assert_eq!(out.conflicts.len(), 1);
        assert_eq!(out.conflicts[0].key, "pw");
        assert_eq!(out.conflicts[0].kind, FieldDeltaKind::BothDiffer);
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

    // ----- Icon classifier (PR I1) -----

    fn icon(id: u128) -> Uuid {
        Uuid::from_u128(id)
    }

    #[test]
    fn icon_classifier_no_row_when_both_sides_match() {
        // Same custom_icon_uuid on both sides → no row, no auto-res.
        let same = Some(icon(1));
        let mut local = entry();
        local.custom_icon_uuid = same;
        let mut remote = entry();
        remote.custom_icon_uuid = same;

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert!(out.icon_auto_resolution.is_none());
    }

    #[test]
    fn icon_classifier_no_row_when_both_sides_have_no_custom_icon() {
        let local = entry();
        let remote = entry();
        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert!(out.icon_auto_resolution.is_none());
    }

    #[test]
    fn icon_classifier_conflict_when_differing_uuids_with_no_lca() {
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(1));
        let mut remote = entry();
        remote.custom_icon_uuid = Some(icon(2));

        let out = merge_entry(&local, &remote, &[], &[]);
        let delta = out.icon_conflict.expect("conflict expected");
        assert_eq!(delta.local_custom_icon_uuid, Some(icon(1)));
        assert_eq!(delta.remote_custom_icon_uuid, Some(icon(2)));
        assert!(out.icon_auto_resolution.is_none());
    }

    #[test]
    fn icon_classifier_auto_present_when_one_side_has_custom_other_doesnt_no_lca() {
        // No shared ancestor; local has a custom icon, remote has none.
        // Absence is the implicit base, so the present icon wins
        // (additive) instead of parking a conflict — this is the
        // transient favicon-fetch race: one device fetched + assigned
        // the favicon, the other hasn't yet.
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(1));
        let remote = entry(); // None

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(
            out.icon_conflict.is_none(),
            "absence-vs-present must not conflict with no LCA"
        );
        assert_eq!(out.icon_auto_resolution, Some(Side::Local));
    }

    #[test]
    fn icon_classifier_auto_present_remote_side_no_lca() {
        // Mirror of the above: remote has the icon, local has none.
        let local = entry(); // None
        let mut remote = entry();
        remote.custom_icon_uuid = Some(icon(1));

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert_eq!(out.icon_auto_resolution, Some(Side::Remote));
    }

    #[test]
    fn favicon_race_same_url_one_side_fetched_auto_resolves_no_lca() {
        // The real transient sync race: a fresh entry (no shared
        // history) where both sides have the same URL, but only one has
        // fetched + assigned the favicon yet. Must auto-resolve to the
        // fetched icon, not park a conflict that sticks after both
        // converge.
        let mut local = entry();
        local.url = "https://apple.com".into();
        local.custom_icon_uuid = Some(icon(42));
        let mut remote = entry();
        remote.url = "https://apple.com".into();
        // remote.custom_icon_uuid stays None (favicon not fetched yet)

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.conflicts.is_empty(), "url matches → no field conflict");
        assert!(
            out.icon_conflict.is_none(),
            "icon must auto-resolve, not conflict"
        );
        assert_eq!(out.icon_auto_resolution, Some(Side::Local));
    }

    #[test]
    fn title_edit_auto_resolves_when_icon_diverges_without_history() {
        // Regression for the favicon→spurious-conflict cascade. A
        // favicon was written into the entry (current *and* the
        // pre-edit history snapshot) without the remote side ever
        // fetching it. Then the title was edited locally. With the
        // icon excluded from the content hash, the icon-bearing local
        // history snapshot still matches the remote's icon-less current
        // by content — so the LCA is found and the title edit
        // auto-resolves. Before the fix the icon mismatch blocked LCA
        // discovery and the title parked as a whole-entry conflict.
        let mut ancestor = snapshot("old title", at(2026, 1));
        ancestor.custom_icon_uuid = Some(icon(7));

        let mut local = entry();
        local.title = "new title".into();
        local.times = at(2026, 2);
        local.custom_icon_uuid = Some(icon(7));
        local.history = vec![ancestor];

        // Remote never fetched the favicon and didn't touch the title.
        let mut remote = entry();
        remote.title = "old title".into();
        remote.times = at(2026, 1);

        assert!(
            find_common_ancestor(&local, &remote, &[], &[]).is_some(),
            "icon-only divergence must not block LCA discovery"
        );

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(
            out.conflicts.is_empty(),
            "title edit must auto-resolve, not park a conflict"
        );
        assert_eq!(
            out.auto_resolutions
                .iter()
                .find(|(k, _)| k == "Title")
                .map(|(_, side)| *side),
            Some(Side::Local),
            "local's new title wins (remote unchanged from the ancestor)"
        );
    }

    #[test]
    fn icon_classifier_auto_remote_when_lca_matches_local() {
        // Ancestor + local both icon=1; remote moved to icon=2.
        // → remote edited → auto-resolve to Remote.
        let mut ancestor = snapshot("v1", at(2026, 1));
        ancestor.custom_icon_uuid = Some(icon(1));
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(1));
        local.history = vec![ancestor.clone()];
        let mut remote = entry();
        remote.custom_icon_uuid = Some(icon(2));
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert_eq!(out.icon_auto_resolution, Some(Side::Remote));
    }

    #[test]
    fn icon_classifier_auto_local_when_lca_matches_remote() {
        let mut ancestor = snapshot("v1", at(2026, 1));
        ancestor.custom_icon_uuid = Some(icon(1));
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(2));
        local.history = vec![ancestor.clone()];
        let mut remote = entry();
        remote.custom_icon_uuid = Some(icon(1));
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert_eq!(out.icon_auto_resolution, Some(Side::Local));
    }

    #[test]
    fn icon_classifier_conflict_when_both_sides_diverge_from_lca() {
        let mut ancestor = snapshot("v1", at(2026, 1));
        ancestor.custom_icon_uuid = Some(icon(1));
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(2));
        local.history = vec![ancestor.clone()];
        let mut remote = entry();
        remote.custom_icon_uuid = Some(icon(3));
        remote.history = vec![ancestor];

        let out = merge_entry(&local, &remote, &[], &[]);
        let delta = out.icon_conflict.expect("conflict expected");
        assert_eq!(delta.local_custom_icon_uuid, Some(icon(2)));
        assert_eq!(delta.remote_custom_icon_uuid, Some(icon(3)));
        assert!(out.icon_auto_resolution.is_none());
    }

    #[test]
    fn icon_classifier_auto_local_when_lca_had_none_and_only_local_added() {
        // LCA had no custom icon; local added one; remote stayed nil.
        // 3-way classify: l != ancestor (None), r == ancestor → Auto(Local).
        let ancestor = snapshot("v1", at(2026, 1));
        let mut local = entry();
        local.custom_icon_uuid = Some(icon(1));
        local.history = vec![ancestor.clone()];
        let remote = {
            let mut e = entry();
            e.history = vec![ancestor];
            e
        };

        let out = merge_entry(&local, &remote, &[], &[]);
        assert!(out.icon_conflict.is_none());
        assert_eq!(out.icon_auto_resolution, Some(Side::Local));
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

    // -----------------------------------------------------------------
    // Public entry-pair classifier (Phase 1 — multi-peer owner-rows brain)
    // -----------------------------------------------------------------
    //
    // Mirrors the validated spike's scenarios
    // (`KeysCore/.../tests/multipeer_spike.rs`) over the real `Entry`:
    // one-sided auto-take, both-sided same-field conflict, the
    // field-vs-item granularity split, the no-shared-ancestor fallback,
    // plus icon + tag coverage the spike's 3-field model didn't carry.

    const C_BASE: (&str, &str, &str) = ("Title", "pw0", "notes");

    /// An entry whose CURRENT value is `current` and whose `<History>`
    /// holds one ancestor snapshot `base` stamped day `base_day` — the
    /// LCA both forks share. Mirrors the spike's `entry()` fixture.
    fn forked(base: (&str, &str, &str), base_day: u32, current: (&str, &str, &str)) -> Entry {
        let mut snap = entry();
        snap.title = base.0.into();
        snap.password = base.1.into();
        snap.notes = base.2.into();
        snap.times = at(2026, base_day);

        let mut e = entry();
        e.title = current.0.into();
        e.password = current.1.into();
        e.notes = current.2.into();
        e.history = vec![snap];
        e
    }

    /// Sorted field-delta keys from a `Conflict` verdict (panics otherwise).
    fn conflict_field_keys(c: &Classification) -> Vec<String> {
        match c {
            Classification::Conflict { conflict } => {
                let mut keys: Vec<String> = conflict
                    .field_deltas
                    .iter()
                    .map(|d| d.key.clone())
                    .collect();
                keys.sort();
                keys
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn classify_in_sync_when_identical() {
        let local = forked(C_BASE, 1, C_BASE);
        let peer = forked(C_BASE, 1, C_BASE);
        assert!(matches!(
            classify(&local, &peer, &[], &[], Granularity::Field),
            Classification::InSync
        ));
    }

    #[test]
    fn classify_one_sided_peer_edit_auto_merges() {
        // Peer changed the title; we never touched the entry → auto-take,
        // no conflict (the case that would be miserable if flagged).
        let local = forked(C_BASE, 1, C_BASE);
        let peer = forked(C_BASE, 1, ("Title-B", "pw0", "notes"));
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(merged.title, "Title-B", "peer's change adopted");
                assert_eq!(merged.password, "pw0", "untouched field kept");
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_both_sided_same_field_conflicts() {
        // Both moved Password off the LCA, differently → genuine conflict,
        // both values preserved on the carried sides.
        let local = forked(C_BASE, 1, ("Title", "pw-MINE", "notes"));
        let peer = forked(C_BASE, 1, ("Title", "pw-THEIRS", "notes"));
        let c = classify(&local, &peer, &[], &[], Granularity::Field);
        assert_eq!(conflict_field_keys(&c), vec!["Password".to_string()]);
        let Classification::Conflict { conflict } = c else {
            unreachable!()
        };
        assert_eq!(conflict.local.password, "pw-MINE");
        assert_eq!(conflict.remote.password, "pw-THEIRS");
        assert!(conflict.attachment_deltas.is_empty());
    }

    #[test]
    fn classify_both_sided_diff_fields_field_level_merges() {
        // I changed Title, peer changed Notes → field-level merges silently.
        let local = forked(C_BASE, 1, ("Title-MINE", "pw0", "notes"));
        let peer = forked(C_BASE, 1, ("Title", "pw0", "notes-THEIRS"));
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(merged.title, "Title-MINE", "my field kept");
                assert_eq!(merged.notes, "notes-THEIRS", "their field merged in");
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_both_sided_diff_fields_item_level_flags() {
        // Same inputs as above; item-level flags the item and surfaces every
        // differing field for the resolver picker (design doc §3).
        let local = forked(C_BASE, 1, ("Title-MINE", "pw0", "notes"));
        let peer = forked(C_BASE, 1, ("Title", "pw0", "notes-THEIRS"));
        let c = classify(&local, &peer, &[], &[], Granularity::Item);
        assert_eq!(
            conflict_field_keys(&c),
            vec!["Notes".to_string(), "Title".to_string()]
        );
    }

    #[test]
    fn classify_granularity_knob_flips_diff_field_verdict() {
        // The one-line knob: identical inputs, opposite verdicts.
        let local = forked(C_BASE, 1, ("Title-MINE", "pw0", "notes"));
        let peer = forked(C_BASE, 1, ("Title", "pw0", "notes-THEIRS"));
        assert!(matches!(
            classify(&local, &peer, &[], &[], Granularity::Field),
            Classification::AutoMerged { .. }
        ));
        assert!(matches!(
            classify(&local, &peer, &[], &[], Granularity::Item),
            Classification::Conflict { .. }
        ));
    }

    #[test]
    fn classify_no_shared_ancestor_falls_back_to_conflict() {
        // Disjoint histories + currents ⇒ no shared snapshot. A both-present
        // field that differs parks conservatively, never a silent pick.
        let local = forked(C_BASE, 1, ("Title", "pw-A", "notes"));
        let peer = forked(("X", "Y", "Z"), 9, ("Title", "pw-B", "notes"));
        assert!(
            find_common_ancestor(&local, &peer, &[], &[]).is_none(),
            "fixture must genuinely share no ancestor"
        );
        let c = classify(&local, &peer, &[], &[], Granularity::Field);
        assert_eq!(conflict_field_keys(&c), vec!["Password".to_string()]);
    }

    #[test]
    fn classify_tags_only_diff_auto_merges() {
        // Fields identical, peer added a tag → no conflict, tag merged in
        // (even under item granularity — tags never conflict).
        let local = forked(C_BASE, 1, C_BASE);
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.tags = vec!["work".into()];
        match classify(&local, &peer, &[], &[], Granularity::Item) {
            Classification::AutoMerged { merged, .. } => {
                assert!(
                    merged.tags.contains(&"work".to_string()),
                    "peer's tag merged in"
                );
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_icon_one_sided_auto_merges() {
        // Peer assigned a custom icon, we have none, no field change →
        // additive present-wins, no conflict.
        let local = forked(C_BASE, 1, C_BASE);
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.custom_icon_uuid = Some(icon(7));
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(
                    merged.custom_icon_uuid,
                    Some(icon(7)),
                    "peer's icon adopted"
                );
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_icon_both_diverge_conflicts() {
        // Both sides carry a different, genuinely-new custom icon → icon-only
        // conflict: no field deltas, an icon delta carrying both sides.
        let mut local = forked(C_BASE, 1, C_BASE);
        local.custom_icon_uuid = Some(icon(1));
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.custom_icon_uuid = Some(icon(2));
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::Conflict { conflict } => {
                assert!(conflict.field_deltas.is_empty(), "icon-only conflict");
                let d = conflict.icon_delta.expect("icon_delta present");
                assert_eq!(d.local_custom_icon_uuid, Some(icon(1)));
                assert_eq!(d.remote_custom_icon_uuid, Some(icon(2)));
            }
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn classify_peer_added_custom_field_auto_merges() {
        // Peer added a protected custom field; we have none → take it (value
        // and protected bit), no conflict.
        let local = forked(C_BASE, 1, C_BASE);
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.custom_fields = vec![CustomField::new("TOTP", "seed", true)];
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                let f = merged
                    .custom_fields
                    .iter()
                    .find(|f| f.key == "TOTP")
                    .expect("custom field merged in");
                assert_eq!(f.value, "seed");
                assert!(f.protected, "protected bit carried");
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_peer_removed_custom_field_auto_merges_drop() {
        // LCA had custom field X; we keep it unchanged; peer removed it off
        // the LCA → one-sided take, X dropped from the merged value (the
        // deletion is honoured, not silently resurrected).
        let mut ancestor = entry();
        ancestor.custom_fields = vec![CustomField::new("X", "v", false)];
        ancestor.times = at(2026, 1);

        let mut local = entry();
        local.custom_fields = vec![CustomField::new("X", "v", false)];
        local.history = vec![ancestor.clone()];

        let mut peer = entry();
        peer.history = vec![ancestor];

        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert!(
                    !merged.custom_fields.iter().any(|f| f.key == "X"),
                    "peer's deletion honoured — X dropped from merged"
                );
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_field_conflict_plus_one_sided_carries_full_sides() {
        // Password clashes (both moved it); Title is a one-sided peer edit.
        // Field-granularity Conflict surfaces only the clash, but carries both
        // full sides so the dropped one-sided change stays recoverable — the
        // hold-open "present, never auto-merge" guarantee (design doc §3).
        let local = forked(C_BASE, 1, ("Title", "pw-MINE", "notes"));
        let peer = forked(C_BASE, 1, ("Title-PEER", "pw-THEIRS", "notes"));
        let c = classify(&local, &peer, &[], &[], Granularity::Field);
        assert_eq!(
            conflict_field_keys(&c),
            vec!["Password".to_string()],
            "only the genuine clash is surfaced under Field granularity"
        );
        let Classification::Conflict { conflict } = c else {
            unreachable!()
        };
        assert_eq!(conflict.local.title, "Title");
        assert_eq!(
            conflict.remote.title, "Title-PEER",
            "peer's one-sided Title preserved on the carried side"
        );
        assert_eq!(conflict.local.password, "pw-MINE");
        assert_eq!(conflict.remote.password, "pw-THEIRS");
    }

    #[test]
    fn classify_item_same_field_clash_single_delta() {
        // Item granularity routes field_deltas through `differing_field_deltas`
        // (a different path from `out.conflicts`). A genuine same-field clash
        // must surface as exactly one BothDiffer delta.
        let local = forked(C_BASE, 1, ("Title", "pw-MINE", "notes"));
        let peer = forked(C_BASE, 1, ("Title", "pw-THEIRS", "notes"));
        let c = classify(&local, &peer, &[], &[], Granularity::Item);
        assert_eq!(conflict_field_keys(&c), vec!["Password".to_string()]);
        let Classification::Conflict { conflict } = c else {
            unreachable!()
        };
        assert_eq!(conflict.field_deltas.len(), 1);
        assert_eq!(conflict.field_deltas[0].kind, FieldDeltaKind::BothDiffer);
    }

    #[test]
    fn classify_auto_merges_icon_and_field_together() {
        // Peer made a one-sided Title edit AND assigned a one-sided icon; both
        // land in the merged value (exercises the icon overlay alongside a
        // field take, not in isolation).
        let local = forked(C_BASE, 1, C_BASE);
        let mut peer = forked(C_BASE, 1, ("Title-B", "pw0", "notes"));
        peer.custom_icon_uuid = Some(icon(9));
        match classify(&local, &peer, &[], &[], Granularity::Field) {
            Classification::AutoMerged { merged, .. } => {
                assert_eq!(merged.title, "Title-B", "field take folded in");
                assert_eq!(
                    merged.custom_icon_uuid,
                    Some(icon(9)),
                    "icon take folded in"
                );
            }
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_in_sync_with_shared_multi_snapshot_history() {
        // Identical current values + identical multi-snapshot history on both
        // sides → InSync (the verdict ignores the richer shared history).
        let mut local = forked(C_BASE, 1, C_BASE);
        local.history = vec![snapshot("v0", at(2026, 1)), snapshot("v1", at(2026, 2))];
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.history = vec![snapshot("v0", at(2026, 1)), snapshot("v1", at(2026, 2))];
        assert!(matches!(
            classify(&local, &peer, &[], &[], Granularity::Field),
            Classification::InSync
        ));
    }

    #[test]
    fn classify_peer_attachment_add_auto_merges_with_take() {
        // 5c: an LCA-backed, peer-only attachment add is an auto-merge
        // carrying an explicit Take instruction with the peer's bytes.
        // (This test previously pinned the opposite — attachment-only
        // divergence verdicting InSync — when attachments were outside
        // classify's scope.)
        let local = forked(C_BASE, 1, C_BASE);
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.attachments = vec![att("secret.txt", 0)];
        match classify(&local, &peer, &[], &[bin(b"data")], Granularity::Field) {
            Classification::AutoMerged {
                attachment_changes, ..
            } => match attachment_changes.as_slice() {
                [AttachmentChange::Take { name, bytes }] => {
                    assert_eq!(name, "secret.txt");
                    assert_eq!(bytes, b"data");
                }
                other => panic!("expected one Take, got {other:?}"),
            },
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_peer_attachment_remove_auto_merges_with_drop() {
        // The peer deleted an attachment local still holds. Local never
        // edited (its current IS the shared ancestor, attachment
        // included); the peer pushed a history snapshot of that
        // ancestor when it deleted. The LCA matcher pairs local-current
        // with peer-history by content hash, the 3-way sees the peer's
        // removal as the only change → Drop instruction.
        let mut local = forked(C_BASE, 1, C_BASE);
        local.history.clear();
        local.attachments = vec![att("stale.txt", 0)];

        let mut peer = forked(C_BASE, 1, C_BASE);
        if let Some(h) = peer.history.first_mut() {
            h.attachments = vec![att("stale.txt", 0)];
        }

        match classify(
            &local,
            &peer,
            &[bin(b"old-bytes")],
            &[bin(b"old-bytes")],
            Granularity::Field,
        ) {
            Classification::AutoMerged {
                attachment_changes, ..
            } => match attachment_changes.as_slice() {
                [AttachmentChange::Drop { name }] => assert_eq!(name, "stale.txt"),
                other => panic!("expected one Drop, got {other:?}"),
            },
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_local_attachment_add_no_instructions() {
        // Local-only attachment changes need nothing applied: merged IS
        // local. The verdict is AutoMerged (sides differ) with an empty
        // instruction list.
        let mut local = forked(C_BASE, 1, C_BASE);
        local.attachments = vec![att("mine.txt", 0)];
        let peer = forked(C_BASE, 1, C_BASE);
        match classify(&local, &peer, &[bin(b"mine")], &[], Granularity::Field) {
            Classification::AutoMerged {
                attachment_changes, ..
            } => assert!(attachment_changes.is_empty(), "nothing to apply locally"),
            other => panic!("expected AutoMerged, got {other:?}"),
        }
    }

    #[test]
    fn classify_no_lca_attachment_divergence_not_auto_adopted() {
        // No shared ancestor: classify_attachments deliberately stays
        // conservative (present-wins would silently undo deletions), so
        // a no-LCA attachment divergence must never produce adoption
        // instructions, whatever the entry-level verdict is.
        let mut local = forked(C_BASE, 1, C_BASE);
        local.history.clear();
        let mut peer = forked(C_BASE, 1, C_BASE);
        peer.history.clear();
        peer.attachments = vec![att("orphan.txt", 0)];
        if let Classification::AutoMerged {
            attachment_changes, ..
        } = classify(&local, &peer, &[], &[bin(b"x")], Granularity::Field)
        {
            assert!(
                attachment_changes.is_empty(),
                "no-LCA divergence must not auto-adopt"
            );
        }
        // Conflict / InSync are acceptable conservative verdicts; the
        // property under test is only that no adoption instruction is
        // fabricated without an LCA.
    }
}
