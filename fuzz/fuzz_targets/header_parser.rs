//! Fuzz target for the KDBX outer-header pipeline.
//!
//! Feeds arbitrary bytes through `Kdbx::<Sealed>::open_from_bytes`
//! and `read_header`. Exercises:
//!
//! - File signature parsing.
//! - Version byte handling.
//! - TLV record decoding (KDBX3 u16 lengths + KDBX4 u32 lengths).
//! - VarDictionary parsing inside KDF / public-custom-data fields.
//! - Length-bound enforcement on declared field sizes.
//!
//! The pipeline must never panic on any input — all error paths
//! surface as `Result::Err`. A panic here is a real bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let bytes = data.to_vec();
    if let Ok(opened) = keepass_core::kdbx::Kdbx::<keepass_core::kdbx::Sealed>::open_from_bytes(bytes) {
        let _ = opened.read_header();
    }
});
