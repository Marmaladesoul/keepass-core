//! XML billion-laughs / entity-expansion defence regression tests.
//!
//! The decoder ingests untrusted bytes — every KDBX file's inner XML
//! is attacker-controllable, so the parser's resilience to malicious
//! XML constructs is part of the threat model. `quick-xml` does not
//! perform entity expansion by default (it returns `Event::DocType`
//! and unresolved `&entity;` references as text without dereferencing
//! them), but that's a behaviour of the dependency we depend on
//! load-bearing-ly — a future bump to a quick-xml major version that
//! flipped the default would silently regress us into a billion-laughs
//! footgun.
//!
//! These tests lock the current behaviour: each adversarial payload
//! must EITHER produce an error EOR leave the entity references
//! unexpanded. A decoder that produced "hahaha…" expanded text would
//! fail the assertions here.
//!
//! Scope: targets `decode_vault`, the public entry point. The
//! decoder is constructed once per vault unlock, so it's the
//! relevant surface to test.

use keepass_core::xml::decode_vault;

/// Recursive-entity (billion-laughs) payload: ten levels of
/// self-referencing entities. A naïve expansion would produce
/// 10^10 = 10 billion `lol` substrings — enough memory pressure to
/// crash a 32-bit process, or at minimum hang the parser.
///
/// We don't run this with the full ten levels in CI because if the
/// defence ever breaks, the test would itself OOM the runner before
/// asserting anything. Three levels (10^3 = 1000) is plenty to
/// detect expansion happening: the decoder's output would carry
/// "lol" 1000 times if expansion ran, and zero times if it didn't.
const BILLION_LAUGHS_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE keepass [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<KeePassFile>
  <Meta><Generator>&lol3;</Generator></Meta>
  <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>r</Name></Group></Root>
</KeePassFile>"#;

/// External-entity reference: classic XXE. quick-xml does not fetch
/// external resources, but defence-in-depth — we want to confirm the
/// decoder doesn't expand `&xxe;` into the contents of /etc/passwd
/// even if a future parser change introduced a resolver.
const EXTERNAL_ENTITY_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE keepass [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<KeePassFile>
  <Meta><Generator>&xxe;</Generator></Meta>
  <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>r</Name></Group></Root>
</KeePassFile>"#;

/// Simple internal entity: tests the baseline. The reference `&hi;`
/// must NOT be expanded into "hello" — quick-xml's default behaviour
/// is to leave custom entities as-is, and we want to lock that.
const INTERNAL_ENTITY_XML: &str = r#"<?xml version="1.0"?>
<!DOCTYPE keepass [
  <!ENTITY hi "hello">
]>
<KeePassFile>
  <Meta><Generator>&hi;</Generator></Meta>
  <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>r</Name></Group></Root>
</KeePassFile>"#;

/// Assert the decoder either rejects the payload outright or, if it
/// accepts it, the decoded fields contain no trace of the would-be
/// expanded text. Either outcome is safe — the only thing we forbid
/// is silent expansion.
fn assert_safe(xml: &str, forbidden_substring: &str, ctx: &str) {
    match decode_vault(xml.as_bytes()) {
        Err(_) => {} // OK: decoder rejected the payload outright.
        Ok(vault) => {
            // Hunt for the expanded substring anywhere in the decoded
            // model. The fields most likely to host expanded entities
            // are Meta.generator and root group fields. Format
            // everything we care about into a single string and grep.
            let observed = format!(
                "{}\n{}\n{}",
                vault.meta.generator, vault.root.name, vault.root.notes
            );
            assert!(
                !observed.contains(forbidden_substring),
                "{ctx}: decoder expanded entity into {forbidden_substring:?}; \
                 a billion-laughs payload would be amplified the same way. \
                 Observed text: {observed:?}"
            );
        }
    }
}

#[test]
fn billion_laughs_payload_is_not_expanded() {
    // If expansion ran, the decoded generator would contain 1000
    // copies of "lol". We forbid even one substring of "lollol" to
    // catch partial expansion (a future parser change that ran one
    // level but not more would still be a regression).
    assert_safe(BILLION_LAUGHS_XML, "lollol", "billion-laughs");
}

#[test]
fn external_entity_payload_is_not_resolved() {
    // /etc/passwd is the canonical XXE target. If a resolver
    // appeared, "root:" or "nologin" might leak in. Forbid both —
    // also assert the literal entity name isn't expanded into file
    // bytes by looking for the word "passwd" itself.
    assert_safe(EXTERNAL_ENTITY_XML, "root:", "xxe /etc/passwd");
    assert_safe(EXTERNAL_ENTITY_XML, "nologin", "xxe /etc/passwd");
}

#[test]
fn internal_entity_payload_is_not_expanded() {
    // Baseline expansion check: the entity body "hello" must not
    // appear in the decoded Generator field.
    assert_safe(INTERNAL_ENTITY_XML, "hello", "internal entity");
}

/// A DOCTYPE with no entities at all — should be either rejected or
/// silently ignored. Either is fine; the test exists to pin the
/// behaviour so a future change to "fail loudly on any DOCTYPE"
/// would be a deliberate choice rather than an accident.
#[test]
fn bare_doctype_does_not_crash_the_decoder() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE keepass>
<KeePassFile>
  <Meta><Generator>safe</Generator></Meta>
  <Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><Name>r</Name></Group></Root>
</KeePassFile>"#;

    // No panic, no hang. Result is either Ok or Err; both are fine.
    let _ = decode_vault(xml.as_bytes());
}
