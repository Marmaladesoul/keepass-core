//! Slice 8 — `Kdbx<Unlocked>` Meta setters.
//!
//! Per MUTATION.md §"Slicing plan" slice 8. Every setter writes its
//! Meta field and stamps `Meta::settings_changed = clock.now()`.
//!
//! The integration test runs every setter through the round-trip
//! gauntlet: open a fixture, mutate every Meta field via its public
//! setter, save to bytes, re-open with the same composite key, and
//! assert each value (and the single `settings_changed` stamp)
//! survived. The save → re-open leg is what proves the encoder
//! actually persists each new field.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{FixedClock, NewGroup};
use std::fs;
use std::path::{Path, PathBuf};

fn fixtures_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

fn kdbx4_basic() -> PathBuf {
    fixtures_root().join("kdbxweb/kdbx4-basic.kdbx")
}

fn password_from_sidecar(path: &Path) -> String {
    let sidecar = path.with_extension("json");
    let text = fs::read_to_string(sidecar).unwrap();
    text.split("\"master_password\"")
        .nth(1)
        .and_then(|s| s.split('"').nth(1))
        .unwrap()
        .to_owned()
}

#[test]
fn every_meta_setter_round_trips_and_stamps_settings_changed() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());
    let at: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();

    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(FixedClock(at)))
        .unwrap();

    // Pre-condition: settings_changed is whatever the fixture wrote
    // (likely None or some stock timestamp, definitely not `at`).
    let pre = kdbx.vault().meta.settings_changed;
    assert_ne!(pre, Some(at), "fixture must not pre-stamp the clock");

    let root = kdbx.vault().root.id;
    let bin_group = kdbx.add_group(root, NewGroup::new("Recycle")).unwrap();

    kdbx.set_database_name("Renamed Vault");
    kdbx.set_database_description("post-edit description");
    kdbx.set_default_username("alice@example.com");
    kdbx.set_color("#336699");
    kdbx.set_recycle_bin(true, Some(bin_group));
    kdbx.set_history_max_items(7);
    kdbx.set_history_max_size(2 * 1024 * 1024);
    kdbx.set_maintenance_history_days(30);
    kdbx.set_master_key_change_rec(180);
    kdbx.set_master_key_change_force(365);

    // In-memory: every setter stamped settings_changed.
    assert_eq!(kdbx.vault().meta.settings_changed, Some(at));

    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let m = &reopened.vault().meta;

    assert_eq!(m.database_name, "Renamed Vault");
    assert_eq!(m.database_description, "post-edit description");
    assert_eq!(m.default_username, "alice@example.com");
    assert_eq!(m.color, "#336699");
    assert!(m.recycle_bin_enabled);
    assert_eq!(m.recycle_bin_uuid, Some(bin_group));
    assert_eq!(m.history_max_items, 7);
    assert_eq!(m.history_max_size, 2 * 1024 * 1024);
    assert_eq!(m.maintenance_history_days, 30);
    assert_eq!(m.master_key_change_rec, 180);
    assert_eq!(m.master_key_change_force, 365);
    assert_eq!(m.settings_changed, Some(at));
}
