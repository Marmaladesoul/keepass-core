//! KDBX 3.1 framing.
//!
//! - KDF: AES-KDF (repeated AES-256-ECB rounds).
//! - Outer cipher: AES-256-CBC or Twofish-CBC.
//! - Inner stream: Salsa20.
//! - No per-block HMAC tags (whole-file integrity comes from the outer cipher
//!   and a start-of-stream plaintext sentinel).
//!
//! Implementation pending.
