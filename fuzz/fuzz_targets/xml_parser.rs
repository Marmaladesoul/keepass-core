//! Fuzz target for the inner-XML decoder.
//!
//! Feeds arbitrary bytes to `decode_vault`, the entry point used at
//! every vault unlock. Exercises:
//!
//! - `quick-xml` event-loop handling of malformed input.
//! - Depth-bound enforcement on `<Group>` nesting.
//! - `unknown_xml` preservation on adversarial element ordering.
//! - Base64 + protected-value parsing.
//! - Timestamp / numeric value parsing in element bodies.
//!
//! Must never panic. All malformed input must surface as `XmlError`.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = keepass_core::xml::decode_vault(data);
});
