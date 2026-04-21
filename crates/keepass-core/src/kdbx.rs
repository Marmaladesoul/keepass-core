//! The [`Kdbx`] typestate machine.
//!
//! A KDBX file passes through four distinct states on the way from bytes on
//! disk to a usable vault, and through three states on the way back out:
//!
//! ```text
//!  ┌────────┐  read_header   ┌────────────┐  unlock   ┌──────────┐  write
//!  │ Sealed │ ──────────────▶│ HeaderRead │ ─────────▶│ Unlocked │ ─────▶ bytes
//!  └────────┘                └────────────┘           └──────────┘
//! ```
//!
//! Each state is a distinct Rust type. Methods that only make sense in a
//! particular state exist only on the impl block for that state. The compiler
//! therefore statically prevents misuse: `vault.entries()` on a sealed vault
//! is a compile error, not a runtime one.
//!
//! This pattern is called the **typestate pattern** and is one of the
//! highest-leverage features of Rust's type system. It turns state-machine
//! invariants from "something we remember to check" into "something the type
//! system proves for us".
//!
//! ## Why each state exists
//!
//! - [`Sealed`] — the file has been read into memory but nothing has been
//!   parsed. The only legal operation is to inspect the magic bytes and begin
//!   header parsing.
//! - [`HeaderRead`] — the outer header has been parsed; we know the KDBX
//!   version, cipher, KDF parameters, and seeds. The master key has **not**
//!   yet been applied. The only legal operation is `unlock`.
//! - [`Unlocked`] — the master key has been derived, block HMACs verified
//!   (on KDBX4), payload decrypted, decompressed, and the inner XML parsed
//!   into the [`crate::model::Vault`] tree. Read and write operations are
//!   available.
//!
//! Implementation pending.

use std::marker::PhantomData;

// --- State types (zero-sized markers) -------------------------------------

/// Marker type: the file bytes are present but not yet parsed.
#[derive(Debug)]
pub struct Sealed {
    // `PhantomData` because the marker carries no runtime data; it only
    // exists in the type system to select the appropriate `impl` block.
    _private: PhantomData<()>,
}

/// Marker type: the outer header has been parsed; the payload is still
/// encrypted.
#[derive(Debug)]
pub struct HeaderRead {
    _private: PhantomData<()>,
}

/// Marker type: the vault has been fully decrypted and parsed. Read and
/// write operations are available.
#[derive(Debug)]
pub struct Unlocked {
    _private: PhantomData<()>,
}

// --- The typestate container ----------------------------------------------

/// A KeePass database in one of the lifecycle states [`Sealed`],
/// [`HeaderRead`], or [`Unlocked`].
///
/// Create a [`Kdbx<Sealed>`] by reading a file. Transition to
/// [`Kdbx<HeaderRead>`] by parsing the header, and to [`Kdbx<Unlocked>`] by
/// supplying a master key.
///
/// The type parameter is a zero-sized marker; at runtime all three variants
/// are the same size. All the state-machine enforcement happens at compile
/// time.
#[derive(Debug)]
pub struct Kdbx<State> {
    // The marker `state: State` field is held purely so that the type
    // parameter is constrained. Implementation fields will be added as
    // construction logic lands.
    #[allow(dead_code)] // populated when state transitions are implemented
    state: State,
}

// --- Sealed: only `read_header` is callable ------------------------------

impl Kdbx<Sealed> {
    // Construction and `read_header` land here.
}

// --- HeaderRead: only `unlock` is callable -------------------------------

impl Kdbx<HeaderRead> {
    // `unlock(master_key)` lands here.
}

// --- Unlocked: reads and writes are callable -----------------------------

impl Kdbx<Unlocked> {
    // `entries()`, `entry(id)`, `add_entry`, `write()`, etc. land here.
}
