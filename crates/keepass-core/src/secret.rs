//! Secret-handling types.
//!
//! All key material in this crate is wrapped in types that:
//!
//! - **Zero their memory on `Drop`** via the [`zeroize`] crate.
//! - **Refuse to be printed.** `Debug` is implemented manually to redact the
//!   bytes; `Display` is deliberately not implemented.
//! - **Box their buffers.** Keys are held in `Box<[u8; N]>` rather than
//!   `[u8; N]` directly so that moves do not leave stale copies on the stack.
//!
//! Callers pass these types across API boundaries rather than raw byte slices
//! so that key-confusion bugs (e.g. passing a header HMAC key where a master
//! key is expected) become compile errors.
//!
//! Implementation pending.

// Placeholder — zeroize + secrecy integration lands with the crypto module.
