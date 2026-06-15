//! Vault-meta merge.
//!
//! The `<Meta>` block carries vault-level scalars (name, description,
//! recycle-bin pointer, history-retention caps, …), the
//! memory-protection flag set, the custom-icon pool, and the
//! vault-level custom-data map. Up until this slice, `apply_merge`
//! never touched `local.meta` — the merged vault carried whichever
//! `Meta` happened to ride along on `local`, silently dropping any
//! changes the user made on the remote side.
//!
//! Per the sync-merge-strategies spec §2.1, each Meta field has its
//! own merge strategy:
//!
//! * Per-field LWW with field-local "changed" timestamps for the
//!   user-edited surfaces (`DatabaseName`, `DatabaseDescription`,
//!   `DefaultUserName`, recycle-bin config).
//! * Per-field LWW arbitrated by `<SettingsChanged>` for everything
//!   that doesn't carry its own per-field timestamp (memory-protection
//!   flags, colour, recommendation policies, maintenance retention).
//! * Min-of-two for the privacy-conservative caps (`HistoryMaxItems`,
//!   `HistoryMaxSize`).
//! * Max-of-two for advancing-only provenance timestamps
//!   (`SettingsChanged` itself, `RecycleBinChanged`).
//! * Grow-only CRDT for the custom-icon pool, keyed by UUID; per-UUID
//!   collision picks the later `last_modified` so a renamed or
//!   replaced icon's most recent state wins.
//!
//! The vault-level `<Meta><CustomData>` map is intentionally NOT
//! merged per-key here — that's spec item 9 / PR-3.3 territory.
//! Today the vault-level custom-data still rides along on local
//! (matching the pre-slice behaviour); spec item 4b's
//! `keys.cd_tombstones.v1` will fold in once the per-key 3-way
//! foundation lands.
//!
//! `MasterKeyChanged` divergence already aborts the merge upstream
//! (`crate::merge::merge`'s pre-flight check, PR-3.2a). When this
//! function runs, the two sides' `master_key_changed` are either
//! equal or one is `None`; LWW on the `Option<DateTime<Utc>>` value
//! resolves cleanly.

use chrono::{DateTime, Utc};
use keepass_core::model::{CustomDataItem, CustomIcon, Meta};

/// Apply the spec §2.1 per-field rules to `local.meta`, taking
/// remote's values where the local-vs-remote arbitration falls to
/// remote. Pure mutation; no errors — `merge::merge`'s master-key
/// pre-flight rejects the hard-fault case before this can run.
pub(crate) fn merge_meta(local: &mut Meta, remote: &Meta) {
    // Scalar facets, split into `merge_meta_scalars` so a consumer that
    // reconciles the icon and custom-data pools separately (keys-engine's
    // owner-rows `ingest_peer`) can reuse the exact scalar LWW rules without
    // double-handling those pools.
    merge_meta_scalars(local, remote);

    // --- Custom-icon pool: grow-only set keyed by UUID. Per-UUID
    // collision keeps the later `last_modified` so a rename or
    // resave on one side propagates.
    local.custom_icons = union_custom_icons(&local.custom_icons, &remote.custom_icons);

    // --- Vault-level `<Meta><CustomData>`: per-key union with LWW
    // arbitration on the per-item `last_modified` timestamp. Spec
    // §2.1 names this "Per-key 3-way (§4)"; without a vault-level LCA
    // the 3-way collapses to "union by key, LWW per key on
    // collision". Audit item 4b's `keys.cd_tombstones.v1` filter will
    // plug in on top of this once it lands.
    local.custom_data = merge_meta_custom_data(&local.custom_data, &remote.custom_data);
}

/// Apply the spec §2.1 per-field rules to the **scalar** `Meta` facets only —
/// the user-edited surfaces (name / description / default-username /
/// recycle-bin config), the settings-arbitrated block, master-key provenance,
/// and the privacy-conservative history caps. Does NOT touch the custom-icon
/// pool or the vault-level custom-data map; `merge_meta` is this plus those
/// two.
///
/// Exposed so keys-engine's owner-rows `ingest_peer` can reuse the identical
/// scalar convergence (it reconciles the icon pool content-addressed and
/// threads resolution records through custom-data on its own path, so it wants
/// the scalars without the pool merges). Sharing one implementation keeps the
/// disk-reconcile and peer-sync paths from drifting on the LWW rules.
pub fn merge_meta_scalars(local: &mut Meta, remote: &Meta) {
    // --- User-edited scalars: per-field LWW on the field's own
    // "*_changed" timestamp. The spec calls for activity-log emission
    // when the remote side wins; that surface lands with audit item 10
    // (PR-3.3) — the merge crate just performs the LWW for now.
    if remote_wins(local.database_name_changed, remote.database_name_changed) {
        crate::events::emit(&crate::MergeEvent::VaultMetaFieldLww {
            field: "DatabaseName",
            local_value: local.database_name.clone(),
            remote_value: remote.database_name.clone(),
        });
        local.database_name.clone_from(&remote.database_name);
        local.database_name_changed = remote.database_name_changed;
    }
    if remote_wins(
        local.database_description_changed,
        remote.database_description_changed,
    ) {
        crate::events::emit(&crate::MergeEvent::VaultMetaFieldLww {
            field: "DatabaseDescription",
            local_value: local.database_description.clone(),
            remote_value: remote.database_description.clone(),
        });
        local
            .database_description
            .clone_from(&remote.database_description);
        local.database_description_changed = remote.database_description_changed;
    }
    if remote_wins(
        local.default_username_changed,
        remote.default_username_changed,
    ) {
        crate::events::emit(&crate::MergeEvent::VaultMetaFieldLww {
            field: "DefaultUserName",
            local_value: local.default_username.clone(),
            remote_value: remote.default_username.clone(),
        });
        local.default_username.clone_from(&remote.default_username);
        local.default_username_changed = remote.default_username_changed;
    }

    // --- Recycle bin: enable flag + UUID arbitrated by
    // `recycle_bin_changed`. Treated as a unit so the flag and the
    // pointer move together; otherwise we'd risk
    // `enabled=true, uuid=None` from a partial LWW.
    let recycle_changed_winner_remote =
        remote_wins(local.recycle_bin_changed, remote.recycle_bin_changed);
    if recycle_changed_winner_remote {
        local.recycle_bin_enabled = remote.recycle_bin_enabled;
        local.recycle_bin_uuid = remote.recycle_bin_uuid;
    }
    // RecycleBinChanged itself is max-of-two: it's a provenance
    // timestamp that should only advance.
    local.recycle_bin_changed = max_opt(local.recycle_bin_changed, remote.recycle_bin_changed);

    // --- Settings-arbitrated scalars: LWW on `settings_changed`,
    // which advances every time any other Meta setting is edited.
    let settings_remote_wins = remote_wins(local.settings_changed, remote.settings_changed);
    if settings_remote_wins {
        local.memory_protection = remote.memory_protection;
        local.color.clone_from(&remote.color);
        local.maintenance_history_days = remote.maintenance_history_days;
        // Master-key *policy* values (rec / force) — distinct from the
        // master-key disagreement check in `crate::merge::merge`.
        // Those are policy recommendations; LWW-ing them under
        // settings_changed matches their meaning. The actual key
        // material divergence is the spec §6 hard-fault, already
        // covered.
        local.master_key_change_rec = remote.master_key_change_rec;
        local.master_key_change_force = remote.master_key_change_force;
    }
    // SettingsChanged itself is max-of-two (advances).
    local.settings_changed = max_opt(local.settings_changed, remote.settings_changed);

    // --- MasterKeyChanged: spec §6 hard fault on disagreement is
    // upstream of this. If we got here, the two sides' values are
    // either equal or one is None; max-of-two preserves whichever is
    // concrete.
    local.master_key_changed = max_opt(local.master_key_changed, remote.master_key_changed);

    // --- Privacy-conservative caps: min-of-two with the "unlimited"
    // sentinel (`-1`) treated as "infinity". A side that prefers
    // shorter retention always wins so the merge can't silently expand
    // a user's chosen quota.
    let prev_max_items = local.history_max_items;
    local.history_max_items =
        min_with_unlimited_i32(local.history_max_items, remote.history_max_items);
    if prev_max_items != remote.history_max_items && prev_max_items != local.history_max_items {
        crate::events::emit(&crate::MergeEvent::HistoryRetentionConverged {
            local_max_items: prev_max_items,
            remote_max_items: remote.history_max_items,
            picked_max_items: local.history_max_items,
        });
    }
    local.history_max_size =
        min_with_unlimited_i64(local.history_max_size, remote.history_max_size);

    // NOTE: `generator`, `header_hash`, `unknown_xml` are not merged
    // per the spec. `generator` is overwritten by whichever writer
    // emits the next save; `header_hash` is KDBX3 belt-and-braces
    // that gets recomputed on write; `unknown_xml` is per-side
    // round-trip ballast. The custom-icon pool and vault-level
    // custom-data are merged by `merge_meta`, not here.
}

/// `true` when remote's `*_changed` timestamp is strictly newer than
/// local's. An absent local time loses to any concrete remote time
/// (the remote side has positively recorded a change; local hasn't).
/// An absent remote time can't win — no signal to swap on.
fn remote_wins(local: Option<DateTime<Utc>>, remote: Option<DateTime<Utc>>) -> bool {
    match (local, remote) {
        (Some(l), Some(r)) => r > l,
        (None, Some(_)) => true,
        _ => false,
    }
}

fn max_opt(a: Option<DateTime<Utc>>, b: Option<DateTime<Utc>>) -> Option<DateTime<Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x @ Some(_), None) | (None, x @ Some(_)) => x,
        (None, None) => None,
    }
}

/// `min` with `-1` (`HistoryMaxItems`'s "unlimited" sentinel) treated
/// as infinity. So `min(7, -1) = 7`, `min(-1, 30) = 30`, `min(7, 30) = 7`,
/// `min(-1, -1) = -1`.
fn min_with_unlimited_i32(a: i32, b: i32) -> i32 {
    match (a < 0, b < 0) {
        (true, true) => -1,
        (true, false) => b,
        (false, true) => a,
        (false, false) => a.min(b),
    }
}

fn min_with_unlimited_i64(a: i64, b: i64) -> i64 {
    match (a < 0, b < 0) {
        (true, true) => -1,
        (true, false) => b,
        (false, true) => a,
        (false, false) => a.min(b),
    }
}

/// Per-key union of two `<Meta><CustomData>` lists. Keys present on
/// either side land in the merged result; per-key value collisions
/// arbitrate by LWW on each item's `last_modified` field, with a
/// concrete `Some` always winning over `None` (a writer that set the
/// timestamp positively recorded the edit). Output is sorted by key
/// so the merge is deterministic.
fn merge_meta_custom_data(a: &[CustomDataItem], b: &[CustomDataItem]) -> Vec<CustomDataItem> {
    use std::collections::HashMap;

    use crate::conflict_resolution::CONFLICT_RESOLUTION_CUSTOM_DATA_KEY;

    let mut by_key: HashMap<&str, &CustomDataItem> = HashMap::new();
    for item in a.iter().chain(b.iter()) {
        // The conflict-resolution list is a CRDT set, not an LWW scalar —
        // two peers can resolve different conflicts independently and both
        // decisions must survive. Skip it here; it's set-unioned below.
        if item.key == CONFLICT_RESOLUTION_CUSTOM_DATA_KEY {
            continue;
        }
        match by_key.get(item.key.as_str()).copied() {
            None => {
                by_key.insert(item.key.as_str(), item);
            }
            Some(existing) if item.value == existing.value => {
                // Same value on both sides — pick the entry with the
                // later (or any concrete) `last_modified` so the
                // merged timestamp is the freshest one we've seen.
                if take_later_lm(existing.last_modified, item.last_modified) {
                    by_key.insert(item.key.as_str(), item);
                }
            }
            Some(existing) => {
                // Value disagreement — LWW on `last_modified`.
                if take_later_lm(existing.last_modified, item.last_modified) {
                    by_key.insert(item.key.as_str(), item);
                }
            }
        }
    }
    let mut out: Vec<CustomDataItem> = by_key.into_values().cloned().collect();

    // Set-union the conflict-resolution CRDT separately (skipped above).
    // Parse failures degrade to empty — a corrupt value must not crash a
    // merge; the unioned, re-serialised list overwrites it anyway.
    let res_a = crate::conflict_resolution::parse_conflict_resolutions(a).unwrap_or_default();
    let res_b = crate::conflict_resolution::parse_conflict_resolutions(b).unwrap_or_default();
    let unioned = crate::conflict_resolution::union_conflict_resolutions(&res_a, &res_b);
    crate::conflict_resolution::write_conflict_resolutions_to_custom_data(&mut out, &unioned, None);

    out.sort_by(|x, y| x.key.cmp(&y.key));
    out
}

/// `true` when the candidate's `last_modified` should beat the
/// incumbent's. Concrete `Some` beats `None`; among two `Some`s the
/// strictly-later one wins; among two `None`s the incumbent stays.
fn take_later_lm(incumbent: Option<DateTime<Utc>>, candidate: Option<DateTime<Utc>>) -> bool {
    match (incumbent, candidate) {
        (Some(i), Some(c)) => c > i,
        (None, Some(_)) => true,
        _ => false,
    }
}

/// Grow-only union of two custom-icon pools keyed by `uuid`. On
/// per-UUID collision the icon with the later `last_modified` wins
/// (so a user's most recent rename / image-replace propagates).
/// Output is sorted by UUID so the merge is deterministic per
/// `(local, remote)` pair.
fn union_custom_icons(a: &[CustomIcon], b: &[CustomIcon]) -> Vec<CustomIcon> {
    use std::collections::HashMap;
    let mut by_uuid: HashMap<uuid::Uuid, CustomIcon> = HashMap::new();
    for icon in a.iter().chain(b.iter()) {
        by_uuid
            .entry(icon.uuid)
            .and_modify(|existing| {
                let take_new = match (existing.last_modified, icon.last_modified) {
                    (Some(e), Some(i)) => i > e,
                    (None, Some(_)) => true,
                    _ => false,
                };
                if take_new {
                    *existing = icon.clone();
                }
            })
            .or_insert_with(|| icon.clone());
    }
    let mut out: Vec<CustomIcon> = by_uuid.into_values().collect();
    out.sort_by_key(|i| i.uuid);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    fn at(y: i32, m: u32, d: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
    }

    fn fresh() -> Meta {
        Meta::default()
    }

    #[test]
    fn database_name_lww_takes_newer_side() {
        let mut l = fresh();
        l.database_name = "Local".into();
        l.database_name_changed = Some(at(2026, 4, 1));
        let mut r = fresh();
        r.database_name = "Remote".into();
        r.database_name_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert_eq!(l.database_name, "Remote");
        assert_eq!(l.database_name_changed, Some(at(2026, 5, 1)));
    }

    #[test]
    fn database_name_lww_keeps_local_when_local_is_newer() {
        let mut l = fresh();
        l.database_name = "Local".into();
        l.database_name_changed = Some(at(2026, 5, 1));
        let mut r = fresh();
        r.database_name = "Remote".into();
        r.database_name_changed = Some(at(2026, 4, 1));
        merge_meta(&mut l, &r);
        assert_eq!(l.database_name, "Local");
    }

    #[test]
    fn absent_local_change_loses_to_concrete_remote_change() {
        let mut l = fresh();
        l.database_name = "Default".into();
        // local *_changed stays None
        let mut r = fresh();
        r.database_name = "Remote".into();
        r.database_name_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert_eq!(l.database_name, "Remote");
    }

    #[test]
    fn history_max_items_takes_min_preferring_concrete_over_unlimited() {
        let mut l = fresh();
        l.history_max_items = 7;
        let mut r = fresh();
        r.history_max_items = 30;
        merge_meta(&mut l, &r);
        assert_eq!(l.history_max_items, 7);

        let mut l = fresh();
        l.history_max_items = -1; // unlimited
        let mut r = fresh();
        r.history_max_items = 7;
        merge_meta(&mut l, &r);
        assert_eq!(l.history_max_items, 7);

        let mut l = fresh();
        l.history_max_items = -1;
        let mut r = fresh();
        r.history_max_items = -1;
        merge_meta(&mut l, &r);
        assert_eq!(l.history_max_items, -1);
    }

    #[test]
    fn settings_changed_advances_via_max() {
        let mut l = fresh();
        l.settings_changed = Some(at(2026, 4, 1));
        let mut r = fresh();
        r.settings_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert_eq!(l.settings_changed, Some(at(2026, 5, 1)));
    }

    #[test]
    fn settings_arbitrated_fields_swap_together_when_remote_wins() {
        let mut l = fresh();
        l.color = "#000000".into();
        l.maintenance_history_days = 365;
        l.settings_changed = Some(at(2026, 4, 1));
        let mut r = fresh();
        r.color = "#FF00FF".into();
        r.maintenance_history_days = 90;
        r.settings_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert_eq!(l.color, "#FF00FF");
        assert_eq!(l.maintenance_history_days, 90);
    }

    #[test]
    fn recycle_bin_flag_and_uuid_swap_together_via_recycle_bin_changed() {
        use keepass_core::model::GroupId;
        use uuid::Uuid;
        let mut l = fresh();
        l.recycle_bin_enabled = false;
        l.recycle_bin_uuid = None;
        l.recycle_bin_changed = Some(at(2026, 4, 1));
        let mut r = fresh();
        r.recycle_bin_enabled = true;
        r.recycle_bin_uuid = Some(GroupId(Uuid::from_u128(0x00c0_ffee)));
        r.recycle_bin_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert!(l.recycle_bin_enabled);
        assert_eq!(
            l.recycle_bin_uuid,
            Some(GroupId(Uuid::from_u128(0x00c0_ffee)))
        );
        assert_eq!(l.recycle_bin_changed, Some(at(2026, 5, 1)));
    }

    #[test]
    fn custom_icons_union_keeps_disjoint_uuids_from_both_sides() {
        use uuid::Uuid;
        let icon_a = CustomIcon::new(Uuid::from_u128(1), b"A".to_vec(), "A".into(), None);
        let icon_b = CustomIcon::new(Uuid::from_u128(2), b"B".to_vec(), "B".into(), None);
        let mut l = fresh();
        l.custom_icons.push(icon_a.clone());
        let mut r = fresh();
        r.custom_icons.push(icon_b.clone());
        merge_meta(&mut l, &r);
        let uuids: std::collections::HashSet<Uuid> =
            l.custom_icons.iter().map(|i| i.uuid).collect();
        assert!(uuids.contains(&icon_a.uuid));
        assert!(uuids.contains(&icon_b.uuid));
    }

    #[test]
    fn custom_icons_per_uuid_collision_takes_later_last_modified() {
        use uuid::Uuid;
        let uuid = Uuid::from_u128(1);
        let icon_old = CustomIcon::new(
            uuid,
            b"old".to_vec(),
            "old-name".into(),
            Some(at(2026, 4, 1)),
        );
        let icon_new = CustomIcon::new(
            uuid,
            b"new".to_vec(),
            "new-name".into(),
            Some(at(2026, 5, 1)),
        );
        let mut l = fresh();
        l.custom_icons.push(icon_old);
        let mut r = fresh();
        r.custom_icons.push(icon_new);
        merge_meta(&mut l, &r);
        assert_eq!(l.custom_icons.len(), 1);
        assert_eq!(l.custom_icons[0].name, "new-name");
    }

    fn cd(key: &str, value: &str, last_modified: Option<DateTime<Utc>>) -> CustomDataItem {
        CustomDataItem::new(key.to_string(), value.to_string(), last_modified)
    }

    #[test]
    fn meta_custom_data_unions_disjoint_keys_from_both_sides() {
        let mut l = fresh();
        l.custom_data
            .push(cd("plugin.a.setting", "L-only", Some(at(2026, 4, 1))));
        let mut r = fresh();
        r.custom_data
            .push(cd("plugin.b.setting", "R-only", Some(at(2026, 4, 1))));
        merge_meta(&mut l, &r);
        let keys: std::collections::HashSet<&str> =
            l.custom_data.iter().map(|i| i.key.as_str()).collect();
        assert!(keys.contains("plugin.a.setting"));
        assert!(keys.contains("plugin.b.setting"));
    }

    #[test]
    fn meta_custom_data_lww_picks_later_modified_on_key_collision() {
        let mut l = fresh();
        l.custom_data
            .push(cd("plugin.x", "old", Some(at(2026, 4, 1))));
        let mut r = fresh();
        r.custom_data
            .push(cd("plugin.x", "new", Some(at(2026, 5, 1))));
        merge_meta(&mut l, &r);
        assert_eq!(l.custom_data.len(), 1);
        assert_eq!(l.custom_data[0].value, "new");
    }

    #[test]
    fn meta_custom_data_concrete_modified_beats_none() {
        let mut l = fresh();
        l.custom_data.push(cd("plugin.x", "none-side", None));
        let mut r = fresh();
        r.custom_data
            .push(cd("plugin.x", "remote-wins", Some(at(2026, 4, 1))));
        merge_meta(&mut l, &r);
        assert_eq!(l.custom_data.len(), 1);
        assert_eq!(l.custom_data[0].value, "remote-wins");
    }

    #[test]
    fn memory_protection_swaps_when_remote_settings_changed_wins() {
        let mut l = fresh();
        l.memory_protection.protect_title = true;
        l.settings_changed = Some(at(2026, 4, 1));
        let mut r = fresh();
        r.memory_protection.protect_title = false;
        r.memory_protection.protect_url = true;
        r.settings_changed = Some(at(2026, 5, 1));
        merge_meta(&mut l, &r);
        assert!(!l.memory_protection.protect_title);
        assert!(l.memory_protection.protect_url);
    }
}
