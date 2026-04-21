//! KDBX 4.x framing.
//!
//! - KDF: Argon2d (default) or Argon2id.
//! - Outer cipher: AES-256-CBC or ChaCha20.
//! - Inner stream: ChaCha20.
//! - Per-block HMAC-SHA-256 tags over 1 MiB blocks for integrity.
//! - Header is itself HMAC'd so tampering is detected before decryption.
//!
//! Implementation pending.
