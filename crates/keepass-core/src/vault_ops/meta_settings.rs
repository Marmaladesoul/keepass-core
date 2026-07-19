//! Vault-level meta setters, their shared settings-changed stamp, and
//! the whole-vault replace verb.
//!
//! Each setter writes one field on `vault.meta` and stamps
//! [`crate::model::Meta::settings_changed`] via
//! [`stamp_settings_changed`]. The high-level setter API deliberately
//! does not auto-stamp the per-field `*Changed` timestamps
//! (`database_name_changed` and friends) — those are KeePass's own
//! field-level edit-history hooks and are left for the caller to
//! manage. Encoder and decoder still round-trip them faithfully when
//! set in-model.

use crate::model::{Clock, GroupId, Vault};

/// Stamp [`crate::model::Meta::settings_changed`] from the injected
/// clock. Shared by every setter here so a single place owns the
/// side-effect.
pub(crate) fn stamp_settings_changed(vault: &mut Vault, clock: &dyn Clock) {
    vault.meta.settings_changed = Some(clock.now());
}

/// Free-fn core of [`Kdbx::set_database_name`](crate::kdbx::Kdbx::set_database_name).
pub(crate) fn set_database_name(vault: &mut Vault, clock: &dyn Clock, name: impl Into<String>) {
    vault.meta.database_name = name.into();
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_database_description`](crate::kdbx::Kdbx::set_database_description).
pub(crate) fn set_database_description(
    vault: &mut Vault,
    clock: &dyn Clock,
    description: impl Into<String>,
) {
    vault.meta.database_description = description.into();
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_default_username`](crate::kdbx::Kdbx::set_default_username).
pub(crate) fn set_default_username(
    vault: &mut Vault,
    clock: &dyn Clock,
    username: impl Into<String>,
) {
    vault.meta.default_username = username.into();
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_color`](crate::kdbx::Kdbx::set_color).
pub(crate) fn set_color(vault: &mut Vault, clock: &dyn Clock, hex: impl Into<String>) {
    vault.meta.color = hex.into();
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_recycle_bin`](crate::kdbx::Kdbx::set_recycle_bin).
pub(crate) fn set_recycle_bin(
    vault: &mut Vault,
    clock: &dyn Clock,
    enabled: bool,
    group: Option<GroupId>,
) {
    vault.meta.recycle_bin_enabled = enabled;
    vault.meta.recycle_bin_uuid = group;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_history_max_items`](crate::kdbx::Kdbx::set_history_max_items).
pub(crate) fn set_history_max_items(vault: &mut Vault, clock: &dyn Clock, max: i32) {
    vault.meta.history_max_items = max;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_history_max_size`](crate::kdbx::Kdbx::set_history_max_size).
pub(crate) fn set_history_max_size(vault: &mut Vault, clock: &dyn Clock, max: i64) {
    vault.meta.history_max_size = max;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_maintenance_history_days`](crate::kdbx::Kdbx::set_maintenance_history_days).
pub(crate) fn set_maintenance_history_days(vault: &mut Vault, clock: &dyn Clock, days: u32) {
    vault.meta.maintenance_history_days = days;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_master_key_change_rec`](crate::kdbx::Kdbx::set_master_key_change_rec).
pub(crate) fn set_master_key_change_rec(vault: &mut Vault, clock: &dyn Clock, days: i64) {
    vault.meta.master_key_change_rec = days;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::set_master_key_change_force`](crate::kdbx::Kdbx::set_master_key_change_force).
pub(crate) fn set_master_key_change_force(vault: &mut Vault, clock: &dyn Clock, days: i64) {
    vault.meta.master_key_change_force = days;
    stamp_settings_changed(vault, clock);
}

/// Free-fn core of [`Kdbx::replace_vault`](crate::kdbx::Kdbx::replace_vault).
pub(crate) fn replace_vault(vault: &mut Vault, replacement: Vault) {
    *vault = replacement;
}
