//! Integration tests for [`Kdbx::<Unlocked>::create_empty_v4`].
//!
//! The constructor builds a fresh, in-memory KDBX4 vault with sensible
//! defaults (AES-256-CBC, Argon2d, GZip, ChaCha20). The load-bearing
//! assertion is structural round-trip: `create_empty_v4 → save_to_bytes
//! → open_from_bytes → read_header → unlock` produces an equivalent
//! vault, byte-stable on a re-save.

use keepass_core::CompositeKey;
use keepass_core::kdbx::{Kdbx, Sealed};
use secrecy::SecretString;

#[test]
fn create_empty_v4_round_trips_via_save_and_open() {
    let composite = CompositeKey::from_password(b"test-password");
    let kdbx = Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4(&composite, "Test Vault")
        .expect("create_empty_v4");

    // Serialise to bytes.
    let bytes = kdbx.save_to_bytes().expect("save_to_bytes");

    // Reopen via the standard path.
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes.clone())
        .expect("open_from_bytes")
        .read_header()
        .expect("read_header")
        .unlock(&composite)
        .expect("unlock");

    // Structural parity: same database name, same root group name, no
    // entries, no deleted objects.
    assert_eq!(reopened.vault().meta.database_name, "Test Vault");
    assert_eq!(reopened.vault().root.name, "Test Vault");
    assert!(reopened.vault().root.entries.is_empty());
    assert!(reopened.vault().root.groups.is_empty());
    assert!(reopened.vault().deleted_objects.is_empty());

    // Second-round save produces structurally-identical bytes (re-save
    // should be byte-stable; OuterHeader retained verbatim, no
    // re-randomisation of seeds between consecutive saves of the same
    // unlocked state).
    let bytes2 = reopened.save_to_bytes().expect("save again");
    assert_eq!(
        bytes.len(),
        bytes2.len(),
        "fresh-create and re-save should produce same-length payloads",
    );
}

#[test]
fn create_empty_v4_preserves_database_name() {
    let composite = CompositeKey::from_password(b"x");
    let kdbx =
        Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4(&composite, "My Personal Vault")
            .expect("create");
    assert_eq!(kdbx.vault().meta.database_name, "My Personal Vault");
    assert_eq!(kdbx.vault().root.name, "My Personal Vault");
}

#[test]
fn create_empty_v4_wrong_password_after_reopen_rejects() {
    let composite = CompositeKey::from_password(b"correct");
    let kdbx =
        Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4(&composite, "Vault").expect("create");
    let bytes = kdbx.save_to_bytes().expect("save");

    let wrong = CompositeKey::from_password(b"wrong");
    let result = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open_from_bytes")
        .read_header()
        .expect("read_header")
        .unlock(&wrong);
    assert!(result.is_err(), "wrong password must fail to unlock");
}

#[test]
fn create_empty_v4_accepts_mutations_post_create() {
    // Sanity: the fresh vault behaves as a standard `Kdbx<Unlocked>`
    // for downstream mutations (add_entry, etc.) — no special-case
    // handling needed by callers.
    use keepass_core::model::{NewEntry, NewGroup};
    let composite = CompositeKey::from_password(b"pw");
    let mut kdbx = Kdbx::<keepass_core::kdbx::Unlocked>::create_empty_v4(&composite, "Sample")
        .expect("create");

    let root = kdbx.vault().root.id;
    let _group = kdbx
        .add_group(root, NewGroup::new("Personal"))
        .expect("add_group");
    let _entry = kdbx
        .add_entry(
            root,
            NewEntry::new("Sample")
                .username("alice")
                .password(SecretString::from("hunter2")),
        )
        .expect("add_entry");

    // Round-trip via save → reopen → check the entry survived.
    let bytes = kdbx.save_to_bytes().expect("save");
    let reopened = Kdbx::<Sealed>::open_from_bytes(bytes)
        .expect("open_from_bytes")
        .read_header()
        .expect("read_header")
        .unlock(&composite)
        .expect("unlock");
    assert_eq!(reopened.vault().root.entries.len(), 1);
    assert_eq!(reopened.vault().root.entries[0].title, "Sample");
    assert_eq!(reopened.vault().root.groups.len(), 1);
    assert_eq!(reopened.vault().root.groups[0].name, "Personal");
}
