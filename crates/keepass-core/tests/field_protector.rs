//! Integration tests for the optional in-memory
//! [`FieldProtector`](keepass_core::protector::FieldProtector) wrap
//! layer over protected-field plaintext.
//!
//! Covers:
//! - Wrap on unlock: with a protector installed, the in-model
//!   `Entry::password` / `CustomField::value` strings are blanked,
//!   while reveal-side accessors recover the original plaintext.
//! - Round-trip via save: a wrapped-in-memory vault saves and
//!   reopens with byte-identical user-visible content.
//! - Legacy parity: omitting the protector preserves the
//!   pre-protector behaviour exactly (plaintext lives in the model).
//! - Failure propagation: a wrap error surfaces as
//!   [`Error::Protector`] from the unlock entry point.

use std::sync::{Arc, Mutex};

use keepass_core::CompositeKey;
use keepass_core::Error;
use keepass_core::kdbx::{Kdbx, Sealed, Unlocked};
use keepass_core::model::{CustomField, NewEntry};
use keepass_core::protector::{FieldProtector, ProtectorError, SessionKey};
use secrecy::SecretString;

/// Test-only protector: returns a 32-byte session key derived from a
/// single seed byte. keepass-core does its own AES-GCM seal/open
/// against the returned key. Two `XorProtector`s with the same seed
/// produce wrapped blobs that round-trip against each other.
///
/// (Name is historical — predates the switch to AES-GCM. Kept for
/// test continuity.)
#[derive(Debug)]
struct XorProtector {
    key: u8,
}

impl FieldProtector for XorProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Ok(SessionKey::from_bytes([self.key; 32]))
    }
}

/// Protector that fails every `acquire_session_key` call. Used to
/// assert the failure propagates through the unlock entry point.
#[derive(Debug)]
struct FailingWrapProtector;

impl FieldProtector for FailingWrapProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        Err(ProtectorError::KeyUnavailable(
            "synthetic key-unavailable failure".into(),
        ))
    }
}

/// Counts every `acquire_session_key` call so tests can assert how
/// often the protector was invoked. Post-rewrite the expectation is
/// "one acquire per bulk pass + one per single-field reveal", not
/// "one per protected field" — the cross-language hop is the cost we
/// were optimising away.
#[derive(Debug)]
struct CountingProtector {
    inner: XorProtector,
    acquires: Mutex<usize>,
}

impl CountingProtector {
    fn new(key: u8) -> Self {
        Self {
            inner: XorProtector { key },
            acquires: Mutex::new(0),
        }
    }
    fn acquires(&self) -> usize {
        *self.acquires.lock().unwrap()
    }
}

impl FieldProtector for CountingProtector {
    fn acquire_session_key(&self) -> Result<SessionKey, ProtectorError> {
        *self.acquires.lock().unwrap() += 1;
        self.inner.acquire_session_key()
    }
}

/// Build a fresh KDBX4 vault with one entry that carries a password
/// plus one protected and one non-protected custom field. Saves and
/// reopens via the regular path so subsequent tests exercise the
/// real unlock pipeline rather than `create_empty_v4` directly.
fn fixture_bytes_with_one_entry(composite: &CompositeKey) -> (Vec<u8>, String, String, String) {
    let mut kdbx =
        Kdbx::<Unlocked>::create_empty_v4(composite, "Protector Test").expect("create_empty_v4");
    let root = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root,
            NewEntry::new("login").password(SecretString::from("hunter2")),
        )
        .expect("add_entry");
    // Add custom fields via direct vault mutation — the editor APIs
    // are richer than this test needs.
    {
        let entry = kdbx
            .vault()
            .root
            .entries
            .iter()
            .find(|e| e.id == entry_id)
            .expect("entry just added")
            .clone();
        let mut new = entry.clone();
        new.custom_fields.push(CustomField::new(
            "TOTP Seed",
            "JBSWY3DPEHPK3PXP",
            true, // protected
        ));
        new.custom_fields.push(CustomField::new(
            "Recovery Code",
            "1234-5678",
            false, // not protected
        ));
        let mut vault = kdbx.vault().clone();
        for e in &mut vault.root.entries {
            if e.id == entry_id {
                *e = new.clone();
            }
        }
        kdbx.replace_vault(vault);
    }
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");
    (
        bytes,
        "hunter2".into(),
        "JBSWY3DPEHPK3PXP".into(),
        "1234-5678".into(),
    )
}

#[test]
fn field_protector_wraps_on_unlock_unwraps_on_reveal() {
    let composite = CompositeKey::from_password(b"test");
    let (bytes, password, totp, recovery) = fixture_bytes_with_one_entry(&composite);

    let protector = Arc::new(CountingProtector::new(0x5a));
    let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector.clone()))
        .expect("unlock_with_protector");

    // Post-rewrite: one `acquire_session_key` call for the whole
    // bulk wrap pass (covering password + every protected custom
    // field + every history snapshot). Reveal-side accessors add
    // one acquire per call below.
    assert_eq!(
        protector.acquires(),
        1,
        "bulk wrap pass should fetch the key exactly once"
    );

    // In-model strings are blanked for wrapped fields.
    let entry = unlocked.vault().root.entries.first().expect("one entry");
    assert!(entry.password.is_empty(), "password should be blanked");
    let totp_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .expect("totp field");
    assert!(
        totp_cf.value.is_empty(),
        "protected custom field should be blanked"
    );
    let recovery_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "Recovery Code")
        .expect("recovery field");
    assert_eq!(
        recovery_cf.value, recovery,
        "non-protected custom field stays plaintext on the model"
    );

    // Reveal recovers the plaintext.
    let id = entry.id;
    assert_eq!(unlocked.reveal_password(id).expect("reveal"), password);
    assert_eq!(
        unlocked
            .reveal_custom_field(id, "TOTP Seed")
            .expect("reveal cf"),
        Some(totp.clone()),
    );
    assert_eq!(
        unlocked
            .reveal_custom_field(id, "Recovery Code")
            .expect("reveal cf"),
        Some(recovery),
    );
    assert_eq!(
        unlocked
            .reveal_custom_field(id, "no such key")
            .expect("reveal missing"),
        None,
    );
}

#[test]
fn field_protector_round_trips_via_save() {
    let composite = CompositeKey::from_password(b"test");
    let (bytes, password, totp, recovery) = fixture_bytes_with_one_entry(&composite);

    let protector: Arc<dyn FieldProtector> = Arc::new(XorProtector { key: 0xa5 });
    let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector.clone()))
        .expect("unlock_with_protector");

    // Save while wrapped — encoder gets plaintext via the save-time
    // unwrap pass on a clone of the vault.
    let bytes2 = unlocked.save_to_bytes().expect("save_to_bytes");

    // Canonical in-memory state stays wrapped after save.
    let entry_after = unlocked.vault().root.entries.first().unwrap();
    assert!(entry_after.password.is_empty());

    // Reopen with no protector — plaintext recovered into the model.
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes2)
        .expect("reopen")
        .read_header()
        .expect("read_header")
        .unlock(&composite)
        .expect("unlock");
    let entry = reopened.vault().root.entries.first().expect("one entry");
    assert_eq!(entry.password, password);
    let totp_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp_cf.value, totp);
    let recovery_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "Recovery Code")
        .unwrap();
    assert_eq!(recovery_cf.value, recovery);
}

#[test]
fn no_protector_matches_legacy_behaviour() {
    let composite = CompositeKey::from_password(b"test");
    let (bytes, password, totp, _) = fixture_bytes_with_one_entry(&composite);

    let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock(&composite)
        .expect("unlock");

    // No protector → no side table; model strings carry plaintext.
    assert!(unlocked.field_protector().is_none());
    let entry = unlocked.vault().root.entries.first().unwrap();
    assert_eq!(entry.password, password);
    let totp_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp_cf.value, totp);

    // Reveal accessors still work — they pass the plaintext through
    // verbatim when no protector is configured.
    assert_eq!(unlocked.reveal_password(entry.id).unwrap(), password);
    assert_eq!(
        unlocked.reveal_custom_field(entry.id, "TOTP Seed").unwrap(),
        Some(totp),
    );
}

#[test]
fn protector_wrap_failure_propagates() {
    let composite = CompositeKey::from_password(b"test");
    let (bytes, _, _, _) = fixture_bytes_with_one_entry(&composite);

    let protector: Arc<dyn FieldProtector> = Arc::new(FailingWrapProtector);
    let err = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector))
        .expect_err("wrap failure should propagate");

    match err {
        Error::Protector(ProtectorError::KeyUnavailable(msg)) => {
            assert!(msg.contains("synthetic"), "got message {msg:?}");
        }
        other => panic!("expected Error::Protector(KeyUnavailable(_)), got {other:?}"),
    }
}

#[test]
fn vault_with_unwrapped_protected_returns_plaintext_clone() {
    // Regression for the merge-time empty-vs-plaintext bug: when a
    // protector is installed, downstream byte-level consumers (the
    // 3-way merger in particular) need a clone with plaintext spliced
    // back in. Mirrors what `do_save` already does internally.
    let composite = CompositeKey::from_password(b"test");
    let (bytes, password, totp, recovery) = fixture_bytes_with_one_entry(&composite);

    let protector: Arc<dyn FieldProtector> = Arc::new(XorProtector { key: 0xa5 });
    let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector))
        .expect("unlock_with_protector");

    // Canonical state is wrapped / blanked.
    let canonical_entry = unlocked.vault().root.entries.first().expect("one entry");
    assert!(
        canonical_entry.password.is_empty(),
        "canonical password blanked"
    );
    let canonical_totp = canonical_entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert!(
        canonical_totp.value.is_empty(),
        "canonical protected custom field blanked",
    );

    // Unwrapped clone carries plaintext on every protected slot.
    let unwrapped = unlocked
        .vault_with_unwrapped_protected()
        .expect("vault_with_unwrapped_protected");
    let entry = unwrapped.root.entries.first().expect("one entry");
    assert_eq!(entry.password, password);
    let totp_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp_cf.value, totp);
    let recovery_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "Recovery Code")
        .unwrap();
    assert_eq!(
        recovery_cf.value, recovery,
        "non-protected field rides through"
    );

    // Canonical state still wrapped after the unwrap call — the
    // clone is independent.
    let canonical_after = unlocked.vault().root.entries.first().unwrap();
    assert!(canonical_after.password.is_empty());
    let canonical_totp_after = canonical_after
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert!(canonical_totp_after.value.is_empty());
}

#[test]
fn vault_with_unwrapped_protected_no_protector_is_identity_clone() {
    // No protector → state.vault already carries plaintext; the
    // helper just returns a clone.
    let composite = CompositeKey::from_password(b"test");
    let (bytes, password, totp, _) = fixture_bytes_with_one_entry(&composite);

    let unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock(&composite)
        .expect("unlock");

    let unwrapped = unlocked
        .vault_with_unwrapped_protected()
        .expect("vault_with_unwrapped_protected");
    let entry = unwrapped.root.entries.first().unwrap();
    assert_eq!(entry.password, password);
    let totp_cf = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp_cf.value, totp);
}

#[test]
fn edit_entry_under_protector_persists_new_password_through_save() {
    // Regression: `edit_entry` mutates `entry.password` directly, but
    // the save pipeline's `unwrap_vault_protected_fields` used to
    // unconditionally overwrite that slot with the side-table's OLD
    // wrapped bytes — losing every protected-field edit on save.
    let composite = CompositeKey::from_password(b"test");
    let (bytes, _, _, _) = fixture_bytes_with_one_entry(&composite);

    let protector: Arc<dyn FieldProtector> = Arc::new(XorProtector { key: 0xa5 });
    let mut unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector.clone()))
        .expect("unlock_with_protector");
    let id = unlocked.vault().root.entries.first().unwrap().id;

    unlocked
        .edit_entry(id, keepass_core::model::HistoryPolicy::NoSnapshot, |e| {
            e.set_password(SecretString::from("rotated"));
            e.set_custom_field(
                "TOTP Seed",
                keepass_core::model::CustomFieldValue::Protected(SecretString::from("ZZZZ")),
            );
        })
        .expect("edit_entry");

    // Reveal sees the new plaintext immediately — the side-table is
    // the source of truth.
    assert_eq!(unlocked.reveal_password(id).unwrap(), "rotated");
    assert_eq!(
        unlocked.reveal_custom_field(id, "TOTP Seed").unwrap(),
        Some("ZZZZ".to_owned()),
    );

    // Canonical model still wrapped (the rewrap pass cleared the
    // plaintext the editor wrote).
    let entry_after = unlocked.vault().root.entries.first().unwrap();
    assert!(entry_after.password.is_empty(), "live password rewrapped");
    let totp_after = entry_after
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert!(totp_after.value.is_empty(), "live cf rewrapped");

    // The unwrapped clone (what the merger consumes) carries new
    // plaintext too.
    let unwrapped = unlocked.vault_with_unwrapped_protected().unwrap();
    let entry = unwrapped.root.entries.first().unwrap();
    assert_eq!(entry.password, "rotated");
    let totp = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp.value, "ZZZZ");

    // Save and reopen with no protector — the edit survives the
    // round-trip.
    let saved = unlocked.save_to_bytes().expect("save_to_bytes");
    let reopened = Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let entry = reopened.vault().root.entries.first().unwrap();
    assert_eq!(entry.password, "rotated");
    let totp = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp.value, "ZZZZ");
}

#[test]
fn edit_entry_under_protector_snapshot_carries_old_plaintext() {
    // Pre-edit snapshots taken inside `edit_entry` capture the entry
    // as it was *before* the closure ran — including the OLD
    // plaintext for protected fields. With a protector configured the
    // side-table has to grow a new entry alongside `entry.history`
    // carrying the OLD wrapped bytes, otherwise save would emit the
    // snapshot with an empty password.
    let composite = CompositeKey::from_password(b"test");
    let (bytes, original_password, original_totp, _) = fixture_bytes_with_one_entry(&composite);

    let protector: Arc<dyn FieldProtector> = Arc::new(XorProtector { key: 0xa5 });
    let mut unlocked = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open")
        .read_header()
        .expect("read_header")
        .unlock_with_protector(&composite, Some(protector.clone()))
        .expect("unlock_with_protector");
    let id = unlocked.vault().root.entries.first().unwrap().id;

    unlocked
        .edit_entry(id, keepass_core::model::HistoryPolicy::Snapshot, |e| {
            e.set_password(SecretString::from("rotated"));
            e.set_custom_field(
                "TOTP Seed",
                keepass_core::model::CustomFieldValue::Protected(SecretString::from("NEWSEED")),
            );
        })
        .expect("edit_entry");

    let saved = unlocked.save_to_bytes().expect("save_to_bytes");
    let reopened = Kdbx::<Sealed>::open_from_bytes(saved)
        .unwrap()
        .read_header()
        .unwrap()
        .unlock(&composite)
        .unwrap();
    let entry = reopened.vault().root.entries.first().unwrap();
    assert_eq!(entry.password, "rotated");
    let totp = entry
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(totp.value, "NEWSEED");

    // Exactly one history snapshot, carrying the pre-edit plaintext.
    assert_eq!(entry.history.len(), 1, "one snapshot from the edit");
    let snap = &entry.history[0];
    assert_eq!(
        snap.password, original_password,
        "snapshot preserves the OLD password"
    );
    let snap_totp = snap
        .custom_fields
        .iter()
        .find(|c| c.key == "TOTP Seed")
        .unwrap();
    assert_eq!(
        snap_totp.value, original_totp,
        "snapshot preserves the OLD protected cf"
    );
}

#[test]
fn create_empty_v4_with_protector_stores_protector() {
    let composite = CompositeKey::from_password(b"test");
    let protector: Arc<dyn FieldProtector> = Arc::new(XorProtector { key: 0x33 });
    let kdbx = Kdbx::<Unlocked>::create_empty_v4_with_protector(
        &composite,
        "Fresh",
        Some(protector.clone()),
    )
    .expect("create_empty_v4_with_protector");
    assert!(kdbx.field_protector().is_some());
}
