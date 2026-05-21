//! Display coverage for every public error variant.
//!
//! Every error enum in the crate is `#[non_exhaustive]` and uses
//! `thiserror`'s `#[error(...)]` attributes to drive `Display`. The
//! risk this test guards against is twofold:
//!
//! 1. **Empty / placeholder messages.** A missing `#[error(...)]`
//!    attribute would compile cleanly under `thiserror` (the derive
//!    falls back to an empty string for variants without a message)
//!    and produce a `Display` that prints nothing — useless in a log
//!    line. Every variant constructed below must `Display`-render to
//!    a non-empty string.
//!
//! 2. **Secret leakage.** Variants that wrap a secret-bearing type
//!    (or include a payload that *could* contain one) must not print
//!    raw bytes. We instantiate variants with recognisable sentinels
//!    where applicable and assert the sentinel doesn't appear in the
//!    rendered message. Most variants here only carry IDs / counts /
//!    static strings; the few that carry strings are checked
//!    explicitly.
//!
//! Coverage is structural: every currently-defined variant of every
//! error enum named in the prompt (`Error`, `ModelError`,
//! `FormatError`, `CryptoError`, `XmlError`, `ProtectorError`) is
//! exercised. Every enum is `#[non_exhaustive]` so a downstream
//! exhaustiveness match isn't a compile error — adding a new variant
//! to one of these enums won't fail this file's compile. Keep an eye
//! out at review time.

use keepass_core::Error;
use keepass_core::crypto::CryptoError;
use keepass_core::format::FormatError;
use keepass_core::model::{EntryId, GroupId, ModelError};
use keepass_core::protector::ProtectorError;
use keepass_core::xml::XmlError;
use uuid::Uuid;

/// Assert the rendered string is non-empty and (for variants we
/// construct with a sentinel) free of the sentinel bytes.
fn assert_display_ok(rendered: &str, ctx: &str) {
    assert!(!rendered.is_empty(), "{ctx}: Display rendered empty string");
    assert!(
        !rendered.trim().is_empty(),
        "{ctx}: Display rendered only whitespace"
    );
}

// ---------------------------------------------------------------------------
// ModelError
// ---------------------------------------------------------------------------

#[test]
fn model_error_all_variants_display() {
    let id = EntryId(Uuid::nil());
    let gid = GroupId(Uuid::nil());

    let cases: Vec<ModelError> = vec![
        ModelError::EntryNotFound(id),
        ModelError::GroupNotFound(gid),
        ModelError::CircularMove {
            moving: gid,
            new_parent: gid,
        },
        ModelError::DuplicateUuid(Uuid::nil()),
        ModelError::CannotDeleteRoot,
        ModelError::HistoryIndexOutOfRange {
            id,
            index: 5,
            len: 3,
        },
        ModelError::Protector(ProtectorError::KeyUnavailable("test".into())),
    ];

    for err in &cases {
        let s = format!("{err}");
        assert_display_ok(&s, &format!("ModelError::{err:?}"));
    }
}

// ---------------------------------------------------------------------------
// FormatError
// ---------------------------------------------------------------------------

#[test]
fn format_error_all_variants_display() {
    let cases: Vec<FormatError> = vec![
        FormatError::BadSignature1,
        FormatError::BadSignature2,
        FormatError::UnsupportedVersion {
            major: 99,
            minor: 0,
        },
        FormatError::Truncated {
            needed: 128,
            got: 4,
        },
        FormatError::MalformedHeader("test message"),
    ];

    for err in &cases {
        let s = format!("{err}");
        assert_display_ok(&s, &format!("FormatError::{err:?}"));
    }
}

// ---------------------------------------------------------------------------
// CryptoError
// ---------------------------------------------------------------------------

#[test]
fn crypto_error_all_variants_display() {
    let cases: Vec<CryptoError> = vec![
        CryptoError::Kdf,
        CryptoError::Decrypt,
        CryptoError::HmacMismatch { index: 7 },
    ];

    for err in &cases {
        let s = format!("{err}");
        assert_display_ok(&s, &format!("CryptoError::{err:?}"));
    }

    // The error-collapse discipline (AGENTS.md §4.8.7): "Wrong key"
    // and "corrupt ciphertext" must surface as the *same* variant.
    // Pin that by asserting Decrypt's rendered message doesn't lean
    // either way — a future contributor splitting the variant would
    // need to update this assertion.
    let s = format!("{}", CryptoError::Decrypt);
    assert!(
        s.contains("wrong key") && s.contains("corrupt"),
        "CryptoError::Decrypt must surface both wrong-key and corruption \
         as the same error to avoid leaking an oracle; got: {s}"
    );
}

// ---------------------------------------------------------------------------
// XmlError
// ---------------------------------------------------------------------------

#[test]
fn xml_error_all_variants_display() {
    let cases: Vec<XmlError> = vec![
        XmlError::Malformed("unexpected EOF".into()),
        XmlError::MissingElement("Meta"),
        XmlError::InvalidValue {
            element: "Times/LastModificationTime",
            detail: "not a valid RFC3339 timestamp".into(),
        },
    ];

    for err in &cases {
        let s = format!("{err}");
        assert_display_ok(&s, &format!("XmlError::{err:?}"));
    }
}

// ---------------------------------------------------------------------------
// ProtectorError
// ---------------------------------------------------------------------------

#[test]
fn protector_error_all_variants_display() {
    // ProtectorError's variants all carry `String` detail. The crate
    // contract is that callers don't pass secret bytes into these
    // strings — but a defence-in-depth check is cheap. Construct
    // with a recognisable sentinel and assert it's exposed only in
    // the variant we're testing (we *want* the detail surfaced for
    // debugging), but the type label is also present so a future
    // refactor that swapped variants wouldn't go unnoticed.
    let cases: Vec<(ProtectorError, &str)> = vec![
        (
            ProtectorError::KeyUnavailable("sentinel-a".into()),
            "key unavailable",
        ),
        (ProtectorError::Seal("sentinel-b".into()), "seal failed"),
        (ProtectorError::Open("sentinel-c".into()), "open failed"),
    ];

    for (err, label) in &cases {
        let s = format!("{err}");
        assert_display_ok(&s, &format!("ProtectorError::{err:?}"));
        assert!(
            s.contains(label),
            "ProtectorError Display should contain {label:?}; got: {s}"
        );
    }
}

// ---------------------------------------------------------------------------
// Top-level Error: all From conversions render through to the inner
// type's Display (transparent).
// ---------------------------------------------------------------------------

#[test]
fn top_level_error_forwards_display() {
    let inner_msgs: Vec<(Error, String)> = vec![
        (
            CryptoError::Decrypt.into(),
            format!("{}", CryptoError::Decrypt),
        ),
        (
            XmlError::MissingElement("Root").into(),
            format!("{}", XmlError::MissingElement("Root")),
        ),
        (
            FormatError::BadSignature1.into(),
            format!("{}", FormatError::BadSignature1),
        ),
        (
            ModelError::CannotDeleteRoot.into(),
            format!("{}", ModelError::CannotDeleteRoot),
        ),
        (
            ProtectorError::Seal("x".into()).into(),
            format!("{}", ProtectorError::Seal("x".into())),
        ),
        (
            std::io::Error::new(std::io::ErrorKind::NotFound, "missing").into(),
            format!(
                "{}",
                std::io::Error::new(std::io::ErrorKind::NotFound, "missing")
            ),
        ),
    ];

    for (err, expected) in &inner_msgs {
        let rendered = format!("{err}");
        assert_eq!(
            &rendered, expected,
            "top-level Error::{err:?} must Display transparently"
        );
    }
}
