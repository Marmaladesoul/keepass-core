//! Fixture round-trip for the slice-5 [`EntryEditor`] additions
//! (custom fields, tags, decorative fields, expiry, auto-type).
//!
//! Per MUTATION.md §"Slicing plan" slice 5. The integration test
//! opens a real fixture, applies one `edit_entry` closure that
//! exercises every new setter, saves to bytes, re-opens with the
//! same composite key, and asserts the values stuck — including the
//! protected custom field, which travels through the inner-stream
//! cipher in the round-trip.

use chrono::{DateTime, Utc};
use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use keepass_core::model::{
    AutoType, AutoTypeAssociation, Clock, CustomFieldValue, HistoryPolicy, NewEntry,
};
use secrecy::SecretString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct SharedClock(Arc<Mutex<DateTime<Utc>>>);
impl SharedClock {
    fn new(at: DateTime<Utc>) -> Self {
        Self(Arc::new(Mutex::new(at)))
    }
    fn set(&self, at: DateTime<Utc>) {
        *self.0.lock().unwrap() = at;
    }
}
impl Clock for SharedClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

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
fn edit_entry_extended_fields_round_trip_through_save() {
    let path = kdbx4_basic();
    let password = password_from_sidecar(&path);
    let composite = CompositeKey::from_password(password.as_bytes());

    let t0: DateTime<Utc> = "2026-04-22T10:00:00Z".parse().unwrap();
    let t1: DateTime<Utc> = "2026-04-22T11:00:00Z".parse().unwrap();
    let expiry: DateTime<Utc> = "2030-12-31T23:59:59Z".parse().unwrap();
    let icon = Uuid::from_u128(0xCAFE_F00D_DEAD_BEEF_0000_0000_0000_0001);

    let clock = SharedClock::new(t0);
    let handle = clock.clone();
    let mut kdbx = Kdbx::<Sealed>::open(&path)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock_with_clock(&composite, Box::new(clock))
        .unwrap();

    let root = kdbx.vault().root.id;
    let id = kdbx
        .add_entry(
            root,
            NewEntry::new("Extended")
                .username("alice@example.com")
                .password(SecretString::from("hunter2"))
                .url("https://example.com")
                .tags(vec!["personal".into()]),
        )
        .unwrap();

    // Advance clock so edit_entry's last_modification stamp is
    // distinguishable from add_entry's creation stamp.
    handle.set(t1);

    // Single edit closure exercises every new setter.
    let mut auto_type = AutoType::new();
    auto_type.data_transfer_obfuscation = 1;
    auto_type.default_sequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}".into();
    auto_type
        .associations
        .push(AutoTypeAssociation::new("Firefox - *", "{PASSWORD}{ENTER}"));
    let auto_type_for_check = auto_type.clone();

    kdbx.edit_entry(id, HistoryPolicy::NoSnapshot, |e| {
        e.add_tag("work");
        e.set_custom_field("Recovery", CustomFieldValue::Plain("ABC-DEF".into()));
        e.set_custom_field(
            "TOTP",
            CustomFieldValue::Protected(SecretString::from("JBSWY3DPEHPK3PXP")),
        );
        e.set_foreground_color("#FF0000");
        e.set_background_color("#00FFAA");
        e.set_override_url("cmd://firefox %1");
        e.set_custom_icon(Some(icon));
        e.set_quality_check(false);
        e.set_expiry(Some(expiry));
        e.set_auto_type(auto_type);
    })
    .unwrap();

    // Sanity-check in-memory before round-trip.
    let edited = kdbx
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry findable after edit");
    assert_eq!(edited.times.last_modification_time, Some(t1));
    assert_eq!(edited.tags, vec!["personal".to_string(), "work".into()]);
    assert!(!edited.quality_check);

    // Save → re-open → assert.
    let bytes = kdbx.save_to_bytes().unwrap();
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let after = reopened
        .vault()
        .iter_entries()
        .find(|e| e.id == id)
        .expect("entry survives round-trip");

    assert_eq!(after.tags, vec!["personal".to_string(), "work".into()]);
    assert_eq!(after.foreground_color, "#FF0000");
    assert_eq!(after.background_color, "#00FFAA");
    assert_eq!(after.override_url, "cmd://firefox %1");
    assert_eq!(after.custom_icon_uuid, Some(icon));
    assert!(!after.quality_check);
    assert!(after.times.expires);
    assert_eq!(after.times.expiry_time, Some(expiry));
    assert_eq!(after.auto_type, auto_type_for_check);

    // Custom fields: plain reads back as plain, protected reads back
    // protected (and decrypts to the original plaintext through the
    // inner-stream cipher).
    let plain = after
        .custom_fields
        .iter()
        .find(|c| c.key == "Recovery")
        .expect("plain custom field");
    assert_eq!(plain.value, "ABC-DEF");
    assert!(!plain.protected);
    let secret = after
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP")
        .expect("protected custom field");
    assert_eq!(secret.value, "JBSWY3DPEHPK3PXP");
    assert!(secret.protected);
}
