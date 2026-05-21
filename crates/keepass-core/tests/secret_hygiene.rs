//! Regression tests for secret-redaction discipline.
//!
//! Every key-bearing type in the crate hand-rolls its `Debug` impl to
//! elide raw bytes — a derived `#[derive(Debug)]` would dump
//! plaintext into any panic message or log line that touches the
//! value. The discipline is load-bearing for the threat model
//! (passwords on disk + in-memory), but easy to regress: a `Debug`
//! derive added by a future contributor would silently undo it.
//!
//! These tests construct each secret-bearing type with a recognisable
//! sentinel byte pattern and assert the sentinel doesn't appear in
//! the value's `Debug` output. They also pin the `Send + Sync`
//! bounds that `Arc<dyn FieldProtector>` and `Kdbx<Unlocked>` rely on
//! for cross-thread sharing — a future trait change that dropped
//! either bound would break downstream consumers silently at the
//! type level rather than loudly at the test.

use std::sync::Arc;

use keepass_core::CompositeKey;
use keepass_core::format::{
    EncryptionIv, MasterSeed, ProtectedStreamKey, StreamStartBytes, TransformSeed,
};
use keepass_core::kdbx::{Kdbx, Unlocked};
use keepass_core::model::{Entry, EntryId, NewEntry};
use keepass_core::protector::{FieldProtector, SessionKey};
use keepass_core::secret::{CipherKey, HmacBaseKey, TransformedKey};
use secrecy::SecretString;

/// A byte pattern that's vanishingly unlikely to appear in any of the
/// debug-impl scaffolding (struct names, field labels, length
/// numbers). Picked so a hex-encoded dump would contain the literal
/// bytes "deadbeef" — a derived Debug emits the array contents as
/// decimal integers but the value-laundering risk is the same shape,
/// so we check for both representations.
const SENTINEL_32: [u8; 32] = [0xDE; 32];
const SENTINEL_64: [u8; 64] = [0xBE; 64];

/// Hex / decimal representations of a single sentinel byte. We check
/// both — a Debug impl that printed `Vec<u8>` would emit decimals,
/// one that called a hex formatter would emit "de".
fn assert_no_sentinel(dbg: &str, byte: u8, ty: &str) {
    let dec = format!("{byte}");
    let hex = format!("{byte:02x}");
    let hex_upper = format!("{byte:02X}");
    assert!(
        // The "decimal byte" check is the weak one — small decimal
        // numbers like "222" can plausibly appear in length / count
        // fields. Require a run of at least three repetitions to
        // catch a Vec<u8>-style dump (", 222, 222, 222, …") without
        // false-positiving on incidental matches.
        !dbg.contains(&format!("{dec}, {dec}, {dec}")),
        "{ty} Debug leaks decimal-encoded sentinel byte {dec}: {dbg}"
    );
    assert!(
        !dbg.contains(&format!("{hex}{hex}{hex}")),
        "{ty} Debug leaks lowercase-hex sentinel byte {byte:#04x}: {dbg}"
    );
    assert!(
        !dbg.contains(&format!("{hex_upper}{hex_upper}{hex_upper}")),
        "{ty} Debug leaks uppercase-hex sentinel byte {byte:#04x}: {dbg}"
    );
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertions
// ---------------------------------------------------------------------------

/// Trait-bound check: forces the named type to be `Send + Sync` at
/// compile time. A future change that broke the bound would fail to
/// compile this test, before reaching the linker.
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn field_protector_arc_is_send_sync() {
    assert_send_sync::<Arc<dyn FieldProtector>>();
}

#[test]
fn kdbx_unlocked_is_send() {
    // Send so a vault can be moved across thread boundaries (the
    // downstream Keys app saves on a background thread). Sync is
    // not currently required and not asserted — keep this honest.
    fn assert_send<T: Send>() {}
    assert_send::<Kdbx<Unlocked>>();
}

#[test]
fn composite_key_is_send_sync() {
    assert_send_sync::<CompositeKey>();
}

#[test]
fn transformed_key_is_send_sync() {
    assert_send_sync::<TransformedKey>();
}

// ---------------------------------------------------------------------------
// Debug redaction on individual secret-bearing types
// ---------------------------------------------------------------------------

#[test]
fn composite_key_debug_redacts_bytes() {
    let key = CompositeKey::from_raw_bytes(SENTINEL_32);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xDE, "CompositeKey");
    // Sanity check that the redacted impl is doing *something* — it
    // should at least name the type.
    assert!(dbg.contains("CompositeKey"));
}

#[test]
fn transformed_key_debug_redacts_bytes() {
    let key = TransformedKey::from_raw_bytes(SENTINEL_32);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xDE, "TransformedKey");
    assert!(dbg.contains("TransformedKey"));
}

#[test]
fn cipher_key_debug_redacts_bytes() {
    let key = CipherKey::from_raw_bytes(SENTINEL_32);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xDE, "CipherKey");
    assert!(dbg.contains("CipherKey"));
}

#[test]
fn hmac_base_key_debug_redacts_bytes() {
    let key = HmacBaseKey::from_raw_bytes(SENTINEL_64);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xBE, "HmacBaseKey");
    assert!(dbg.contains("HmacBaseKey"));
}

#[test]
fn master_seed_debug_redacts_bytes() {
    let seed = MasterSeed(SENTINEL_32);
    let dbg = format!("{seed:?}");
    assert_no_sentinel(&dbg, 0xDE, "MasterSeed");
    assert!(dbg.contains("MasterSeed"));
}

#[test]
fn transform_seed_debug_redacts_bytes() {
    let seed = TransformSeed(SENTINEL_32);
    let dbg = format!("{seed:?}");
    assert_no_sentinel(&dbg, 0xDE, "TransformSeed");
    assert!(dbg.contains("TransformSeed"));
}

#[test]
fn protected_stream_key_debug_redacts_bytes() {
    let key = ProtectedStreamKey(SENTINEL_32);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xDE, "ProtectedStreamKey");
    assert!(dbg.contains("ProtectedStreamKey"));
}

#[test]
fn stream_start_bytes_debug_redacts_bytes() {
    let s = StreamStartBytes(SENTINEL_32);
    let dbg = format!("{s:?}");
    assert_no_sentinel(&dbg, 0xDE, "StreamStartBytes");
    assert!(dbg.contains("StreamStartBytes"));
}

#[test]
fn encryption_iv_debug_redacts_bytes() {
    let iv = EncryptionIv(SENTINEL_32.to_vec());
    let dbg = format!("{iv:?}");
    assert_no_sentinel(&dbg, 0xDE, "EncryptionIv");
    assert!(dbg.contains("EncryptionIv"));
}

#[test]
fn session_key_debug_redacts_bytes() {
    let key = SessionKey::from_bytes(SENTINEL_32);
    let dbg = format!("{key:?}");
    assert_no_sentinel(&dbg, 0xDE, "SessionKey");
    assert!(dbg.contains("SessionKey"));
}

// ---------------------------------------------------------------------------
// Entry / PortableEntry redaction
// ---------------------------------------------------------------------------

/// A distinctive password string that's very unlikely to appear as
/// part of any Debug-impl scaffolding (struct names, field labels).
const SENTINEL_PASSWORD: &str = "REDACTION-CANARY-7f3a9e1c";

#[test]
fn entry_debug_redacts_password() {
    let mut entry = Entry::empty(EntryId(uuid::Uuid::nil()));
    entry.title = "test".into();
    entry.password = SENTINEL_PASSWORD.into();
    let dbg = format!("{entry:?}");
    assert!(
        !dbg.contains(SENTINEL_PASSWORD),
        "Entry Debug leaks password: {dbg}"
    );
}

#[test]
fn portable_entry_debug_redacts_password() {
    // Build a minimal vault, add an entry with a sentinel password,
    // export it, and assert the export's Debug doesn't leak the
    // password. PortableEntry has its own hand-rolled Debug impl
    // separate from Entry's — both need to redact.
    let composite = CompositeKey::from_password(b"hygiene-test");
    let mut kdbx =
        Kdbx::<Unlocked>::create_empty_v4(&composite, "secret-hygiene").expect("create vault");
    let root_id = kdbx.vault().root.id;
    let entry_id = kdbx
        .add_entry(
            root_id,
            NewEntry::new("canary").password(SecretString::from(SENTINEL_PASSWORD)),
        )
        .expect("add entry");

    let portable = kdbx.export_entry(entry_id).expect("export");
    let dbg = format!("{portable:?}");
    assert!(
        !dbg.contains(SENTINEL_PASSWORD),
        "PortableEntry Debug leaks password: {dbg}"
    );
    // Positive: the entry is still recognisable by title / id.
    assert!(dbg.contains("PortableEntry"));
    assert!(dbg.contains("canary"));
}
