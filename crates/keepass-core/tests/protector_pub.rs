//! Integration tests proving that the AES-GCM seal/open helpers in
//! [`keepass_core::protector`] are reachable from outside the crate.
//!
//! Downstream consumers (e.g. keys-engine in the sibling Keys app)
//! need the canonical wrap implementation so the wire format stays
//! in lockstep with this crate's in-memory field protector. These
//! tests fail to compile if `seal_with_key` / `open_with_key` lose
//! their `pub` visibility.

use keepass_core::protector::{SessionKey, open_with_key, seal_with_key};

fn key(seed: u8) -> SessionKey {
    SessionKey::from_bytes([seed; 32])
}

#[test]
fn round_trip_empty() {
    let k = key(0x11);
    let sealed = seal_with_key(&k, b"").expect("seal");
    let opened = open_with_key(&k, &sealed).expect("open");
    assert_eq!(opened, b"");
    // Empty plaintext still yields nonce(12) + tag(16).
    assert_eq!(sealed.len(), 12 + 16);
}

#[test]
fn round_trip_single_byte() {
    let k = key(0x22);
    let sealed = seal_with_key(&k, b"x").expect("seal");
    let opened = open_with_key(&k, &sealed).expect("open");
    assert_eq!(opened, b"x");
}

#[test]
fn round_trip_one_kib_random() {
    // Deterministic pseudo-random payload so failures are reproducible
    // without pulling in a CSPRNG dependency for the test.
    let mut payload = vec![0u8; 1024];
    let mut x: u32 = 0x9E37_79B9;
    for slot in &mut payload {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *slot = u8::try_from((x >> 16) & 0xFF).expect("masked to byte");
    }

    let k = key(0x33);
    let sealed = seal_with_key(&k, &payload).expect("seal");
    let opened = open_with_key(&k, &sealed).expect("open");
    assert_eq!(opened, payload);
    // nonce(12) + ciphertext(1024) + tag(16)
    assert_eq!(sealed.len(), 12 + 1024 + 16);
}

#[test]
fn open_rejects_wrong_key() {
    let sealed = seal_with_key(&key(0x44), b"secret").expect("seal");
    assert!(open_with_key(&key(0x45), &sealed).is_err());
}
