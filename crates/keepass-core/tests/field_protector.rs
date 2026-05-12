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
use keepass_core::protector::{FieldProtector, ProtectorError};
use secrecy::SecretString;

/// Test-only protector: XOR each byte with a fixed key and prepend a
/// magic marker so wrapped and plaintext are visually distinct.
///
/// Wraps deterministically — handy for byte-level assertions that
/// the in-memory side table actually holds the wrapped form.
#[derive(Debug)]
struct XorProtector {
    key: u8,
}

const WRAP_MARKER: &[u8] = b"WRP|";

impl FieldProtector for XorProtector {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        let mut out = Vec::with_capacity(plaintext.len() + WRAP_MARKER.len());
        out.extend_from_slice(WRAP_MARKER);
        out.extend(plaintext.iter().map(|b| b ^ self.key));
        Ok(out)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        if !wrapped.starts_with(WRAP_MARKER) {
            return Err(ProtectorError::Unwrap("missing magic marker".into()));
        }
        let body = &wrapped[WRAP_MARKER.len()..];
        Ok(body.iter().map(|b| b ^ self.key).collect())
    }
}

/// Protector that fails every wrap call. Used to assert that wrap
/// errors propagate through the unlock entry point.
#[derive(Debug)]
struct FailingWrapProtector;

impl FieldProtector for FailingWrapProtector {
    fn wrap(&self, _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Err(ProtectorError::Wrap("synthetic wrap failure".into()))
    }
    fn unwrap(&self, _: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        Err(ProtectorError::Unwrap(
            "not reachable in these tests".into(),
        ))
    }
}

/// Counts every wrap / unwrap call so tests can assert the
/// protector was actually invoked.
#[derive(Debug)]
struct CountingProtector {
    inner: XorProtector,
    wraps: Mutex<usize>,
    unwraps: Mutex<usize>,
}

impl CountingProtector {
    fn new(key: u8) -> Self {
        Self {
            inner: XorProtector { key },
            wraps: Mutex::new(0),
            unwraps: Mutex::new(0),
        }
    }
    fn wraps(&self) -> usize {
        *self.wraps.lock().unwrap()
    }
}

impl FieldProtector for CountingProtector {
    fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        *self.wraps.lock().unwrap() += 1;
        self.inner.wrap(plaintext)
    }
    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        *self.unwraps.lock().unwrap() += 1;
        self.inner.unwrap(wrapped)
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

    // Protector saw exactly two wrap calls: one password, one
    // protected custom field. The non-protected custom field is not
    // wrapped.
    assert_eq!(protector.wraps(), 2);

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
        Error::Protector(ProtectorError::Wrap(msg)) => {
            assert!(msg.contains("synthetic"), "got message {msg:?}");
        }
        other => panic!("expected Error::Protector(Wrap(_)), got {other:?}"),
    }
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
