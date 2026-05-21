//! Fuzz target for the KDBX block-stream readers.
//!
//! Feeds arbitrary bytes to both `read_hmac_block_stream` (KDBX4,
//! per-block HMAC-SHA-256) and `read_hashed_block_stream` (KDBX3,
//! per-block SHA-256). Exercises:
//!
//! - Block-size bound enforcement (MAX_BLOCK_BYTES = 64 MiB).
//! - Truncation handling mid-block.
//! - End-marker detection.
//! - Per-block tag verification — must reject every bit-flip but
//!   must also not panic on any input shape.
//!
//! Each input is fed to both readers in turn (cheap because both
//! are O(n)). A panic from either is a real bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keepass_core::format::{hashed_block_stream, hmac_block_stream};
use keepass_core::secret::HmacBaseKey;

fuzz_target!(|data: &[u8]| {
    // KDBX3-style hashed block stream takes no key.
    let _ = hashed_block_stream::read_hashed_block_stream(data);

    // KDBX4-style HMAC block stream needs a key; fuzzing it with a
    // fixed zero key still exercises every parse path before the
    // HMAC verify (block-size bound, length parsing, truncation),
    // and the HMAC verify itself doesn't depend on key contents to
    // execute its constant-time compare.
    let base = HmacBaseKey::from_raw_bytes([0u8; 64]);
    let _ = hmac_block_stream::read_hmac_block_stream(data, &base);
});
