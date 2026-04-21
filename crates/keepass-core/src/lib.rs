//! # keepass-core
//!
//! Reference implementation of the KeePass (KDBX) password database format in
//! pure Rust. Full lossless round-trip read/write for KDBX3 and KDBX4,
//! preserving unknown XML elements for forward compatibility.
//!
//! ## Design principles
//!
//! - **Correctness over cleverness.** Illegal states are made unrepresentable
//!   via the type system rather than checked at runtime.
//! - **Memory-safe end to end.** `#![forbid(unsafe_code)]` at the crate root;
//!   every cryptographic primitive is a maintained `RustCrypto` crate.
//! - **Zero `unsafe`, zero panics on untrusted input.** The parser treats every
//!   byte as adversarial and returns errors instead of aborting.
//! - **Lossless round-trip.** Unknown XML elements are preserved verbatim so
//!   that files written by future KeePass versions survive a Rust edit cycle.
//! - **Layered architecture.** Each concern (crypto, compression, XML, model,
//!   format-version-specific framing) lives in its own module, independently
//!   testable and fuzzable.
//!
//! ## Module map
//!
//! - [`error`] — top-level [`Error`] and per-module error enums.
//! - [`secret`] — [`MasterKey`] and related types with `Drop`-based zeroing.
//! - [`crypto`] — [`Cipher`] trait and implementations (AES-256-CBC,
//!   ChaCha20, Salsa20), KDFs (Argon2, legacy AES-KDF), HMAC, hashing.
//! - [`xml`] — XML reading/writing helpers built on `quick-xml`, including the
//!   unknown-element preservation machinery.
//! - [`model`] — format-agnostic vault types ([`model::Entry`],
//!   [`model::Group`], [`model::Vault`]).
//! - [`format`] — version-specific framing: [`format::v3`] and
//!   [`format::v4`].
//! - [`kdbx`] — the [`kdbx::Kdbx`] typestate machine that ties everything
//!   together.
//!
//! ## Quick example
//!
//! ```no_run
//! // API sketch — pending implementation.
//! // use keepass_core::{Kdbx, MasterKey};
//! //
//! // let master = MasterKey::from_password("correct horse battery staple");
//! // let vault = Kdbx::open("vault.kdbx")?.unlock(&master)?;
//! // for entry in vault.entries() {
//! //     println!("{}", entry.title());
//! // }
//! // # Ok::<(), keepass_core::Error>(())
//! ```

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
// Crate-wide lints live in the workspace `Cargo.toml` so every crate in the
// workspace inherits them consistently.

pub mod crypto;
pub mod error;
pub mod format;
pub mod kdbx;
pub mod model;
pub mod secret;
pub mod xml;

// Re-export the headline types so consumers can write
// `use keepass_core::{Kdbx, MasterKey, Error};` without walking the module tree.
#[doc(inline)]
pub use crate::error::Error;
