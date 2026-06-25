//! Secret-handling types.
//!
//! Every type in this module that holds key material follows four rules:
//!
//! 1. **`Zeroize` on `Drop`** — when the value goes out of scope, its bytes
//!    are wiped. Implemented via the [`zeroize`] crate's derive macros so
//!    the compiler cannot optimise the wipe away.
//! 2. **Heap-boxed inner buffer** — keys are held in `Box<[u8; N]>` rather
//!    than `[u8; N]` on the stack, so `mem::take` / move semantics cannot
//!    leave stale copies behind.
//! 3. **Manually redacted `Debug`** — formatters expose only a length, never
//!    the bytes. `Display` is deliberately not implemented.
//! 4. **Domain-specific newtypes** — a `CompositeKey` cannot be silently
//!    substituted for a `TransformedKey` or a `MasterKey`; each stage of
//!    the KDF pipeline takes a type that only that stage can produce.
//!
//! The composite-key derivation at the end of this module is the first
//! real use of these types: it combines a password and optional keyfile
//! hash into the 32-byte composite key that feeds the KDF stage.

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// ---------------------------------------------------------------------------
// CompositeKey — SHA-256 chain over (password, keyfile_hash)
// ---------------------------------------------------------------------------

/// The 32-byte composite key derived from a password and/or keyfile.
///
/// Per the KeePass spec, the composite key is:
///
/// ```text
/// SHA-256( SHA-256(password) || SHA-256(keyfile_material) )
/// ```
///
/// If only one of password or keyfile is supplied, that component is used
/// on its own (wrapped in an outer `SHA-256` for uniformity). KDBX files
/// that have neither are not representable; at least one must be present.
///
/// The composite key is the input to the KDF (AES-KDF or Argon2), which
/// produces the transformed key — see the next pipeline layer.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CompositeKey(Box<[u8; 32]>);

impl CompositeKey {
    /// Derive a composite key from a password only.
    ///
    /// Computes `SHA-256(SHA-256(password))`. The password bytes are hashed
    /// inside this function and never retained.
    #[must_use]
    pub fn from_password(password: &[u8]) -> Self {
        let inner = Sha256::digest(password);
        let outer = Sha256::digest(inner);
        Self(Box::new(outer.into()))
    }

    /// Derive a composite key from a keyfile hash only.
    ///
    /// The keyfile must have already been reduced to its 32-byte key
    /// material per the KeePass keyfile formats (binary, hex, XML v1,
    /// XML v2, or "raw file SHA-256"). Parsing the keyfile is a separate
    /// concern; this function takes the resulting 32 bytes.
    ///
    /// Computes `SHA-256(keyfile_hash)` (one extra outer hash for
    /// uniformity with the password+keyfile path).
    #[must_use]
    pub fn from_keyfile_hash(keyfile_hash: &[u8; 32]) -> Self {
        let outer = Sha256::digest(keyfile_hash);
        Self(Box::new(outer.into()))
    }

    /// Derive a composite key from both a password and a keyfile hash.
    ///
    /// Computes `SHA-256(SHA-256(password) || keyfile_hash)` — the
    /// KeePass standard.
    #[must_use]
    pub fn from_password_and_keyfile_hash(password: &[u8], keyfile_hash: &[u8; 32]) -> Self {
        let pwd_hash = Sha256::digest(password);
        let mut hasher = Sha256::new();
        hasher.update(pwd_hash);
        hasher.update(keyfile_hash);
        Self(Box::new(hasher.finalize().into()))
    }

    /// Construct a composite key from pre-computed 32 bytes. Useful for
    /// round-trip tests and reserved for callers that know what they're
    /// doing — the [`Self::from_password`] / [`Self::from_keyfile_hash`]
    /// constructors should be preferred for production use.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte key as a slice reference.
    ///
    /// Callers should keep the borrow as short as possible and never copy
    /// the bytes into a longer-lived `Vec` / `String` — the whole point of
    /// `CompositeKey`'s `Drop` is that the bytes vanish when it goes out
    /// of scope.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CompositeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompositeKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// Keyfile hashing
// ---------------------------------------------------------------------------

/// Reduce raw KeePass keyfile bytes to the 32-byte hash that feeds into the
/// composite key derivation.
///
/// KeePass recognises several keyfile formats; the rule is **strictly
/// length-first, then content-sniffed**, per the reference implementation:
///
/// 1. **Exactly 32 bytes** — used verbatim as the keyfile hash. This is
///    the canonical "raw 32-byte keyfile" format.
/// 2. **Exactly 64 bytes, all ASCII hex digits** — parsed as 32 bytes of
///    hex-encoded key material.
/// 3. **XML keyfile** (KeyFile v1 / v2, e.g. `.keyx`) — v1 base64 `Data`,
///    or v2 hex `Data` with an optional `Hash` integrity attribute that is
///    verified when present. Input that *looks* like XML must parse as a
///    well-formed `<KeyFile>` document or fail closed — it never falls
///    through to case 4.
/// 4. **Any other byte sequence** — SHA-256 of the whole file.
///
/// # Errors
///
/// Returns a [`KeyFileError`] if the bytes look like an XML keyfile (start
/// with `<?xml` or `<KeyFile`) but are malformed, declare an unsupported
/// version, carry undecodable key data, or fail their v2 integrity
/// checksum. Never fails on raw binary input (cases 1, 2, 4).
pub fn keyfile_hash(bytes: &[u8]) -> Result<[u8; 32], KeyFileError> {
    // Case 1: exactly 32 bytes → use directly.
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Ok(out);
    }

    // Case 2: exactly 64 bytes, all hex digits.
    if bytes.len() == 64 && bytes.iter().all(u8::is_ascii_hexdigit) {
        let mut out = [0u8; 32];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_digit_value(pair[0]);
            let lo = hex_digit_value(pair[1]);
            out[i] = (hi << 4) | lo;
        }
        return Ok(out);
    }

    // Case 3: XML keyfile (KeePass KeyFile v1 / v2, e.g. `.keyx`). Anything
    // that *looks* like XML must parse as a well-formed `<KeyFile>` document
    // or fail closed — we never fall through to the Case-4 SHA-256 path for a
    // structurally-broken XML keyfile, which would derive a wrong composite
    // key and surface downstream as an opaque "wrong password".
    if looks_like_xml_keyfile(bytes) {
        return parse_xml_keyfile(bytes);
    }

    // Case 4: arbitrary bytes → SHA-256 of the whole file.
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn hex_digit_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => unreachable!("caller verified ASCII hex"),
    }
}

fn looks_like_xml_keyfile(bytes: &[u8]) -> bool {
    // Strip a UTF-8 BOM if present, then ASCII-skip whitespace, and look for
    // either `<?xml` or `<KeyFile`. A full parser would be overkill for this
    // sniff — it only routes likely-XML input into `parse_xml_keyfile`, which
    // does the real validation. (UTF-16-encoded keyfiles evade this sniff and
    // fall through to the Case-4 SHA-256 path; KeePassXC / KeePass 2 emit
    // UTF-8, which is caught.)
    let start = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        3
    } else {
        0
    };
    let trimmed = bytes[start..]
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .map_or(&[] as &[u8], |i| &bytes[start + i..]);
    trimmed.starts_with(b"<?xml") || trimmed.starts_with(b"<KeyFile")
}

/// Parse a KeePass XML keyfile (KeyFile v1 or v2 / `.keyx`) into its 32-byte
/// key material.
///
/// Both versions encode exactly 32 bytes:
///
/// * **v1** — `<Key><Data>` holds the 32 bytes base64-encoded; there is no
///   integrity field, so the bytes are decoded verbatim.
/// * **v2** (`.keyx`) — `<Key><Data>` holds the 32 bytes as whitespace-grouped
///   hex, and the `Data` element carries a `Hash` attribute equal to the
///   uppercase hex of the first four bytes of `SHA-256(key)`. When present the
///   hash is verified and a mismatch fails closed. It is a 4-byte integrity
///   checksum, **not** a MAC — it detects a corrupted/truncated keyfile, it
///   does not authenticate one against substitution.
///
/// The returned 32 bytes are the keyfile's contribution to the composite (used
/// directly as the `keyfile_hash` argument to
/// [`CompositeKey::from_password_and_keyfile_hash`], with no further hashing),
/// matching KeePassXC / KeePass 2 so a vault keyed by their keyfile opens here.
fn parse_xml_keyfile(bytes: &[u8]) -> Result<[u8; 32], KeyFileError> {
    use quick_xml::Reader;
    use quick_xml::events::Event;

    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(false);

    let mut buf = Vec::new();
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut root_is_keyfile = false;
    let mut version = String::new();
    let mut version_seen = false;
    let mut in_version = false;
    let mut data = String::new();
    let mut data_seen = false;
    let mut in_data = false;
    let mut data_hash: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = e.name().as_ref().to_vec();
                if stack.is_empty() {
                    root_is_keyfile = name == b"KeyFile";
                }
                if name == b"Version" && path_is(&stack, &[b"KeyFile", b"Meta"]) {
                    in_version = true;
                    version_seen = true;
                    version.clear();
                } else if name == b"Data" && path_is(&stack, &[b"KeyFile", b"Key"]) {
                    in_data = true;
                    data_seen = true;
                    data.clear();
                    data_hash = find_attr(&e, b"Hash");
                }
                stack.push(name);
            }
            Ok(Event::Empty(e)) if stack.is_empty() && e.name().as_ref() == b"KeyFile" => {
                root_is_keyfile = true;
            }
            Ok(Event::End(_)) => match stack.pop().as_deref() {
                Some(b"Version") => in_version = false,
                Some(b"Data") => in_data = false,
                _ => {}
            },
            Ok(Event::Text(t)) if in_version || in_data => {
                let decoded = t.decode().map_err(|_| KeyFileError::MalformedXml)?;
                if in_version {
                    version.push_str(&decoded);
                } else {
                    data.push_str(&decoded);
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return Err(KeyFileError::MalformedXml),
            _ => {}
        }
        buf.clear();
    }

    if !root_is_keyfile || !version_seen || !data_seen {
        return Err(KeyFileError::MalformedXml);
    }

    // Major-version dispatch: select on the leading digit, matching the
    // lenient reference clients ("2", "2.0", "2.00" all select v2). An
    // unrecognised major fails closed rather than guessing a decoder.
    match version.trim().as_bytes().first() {
        Some(b'1') => decode_keyfile_v1(&data),
        Some(b'2') => decode_keyfile_v2(&data, data_hash.as_deref()),
        _ => Err(KeyFileError::UnsupportedVersion(version.trim().to_owned())),
    }
}

/// True iff `stack` is exactly `path` (element-name for element-name).
fn path_is(stack: &[Vec<u8>], path: &[&[u8]]) -> bool {
    stack.len() == path.len() && stack.iter().zip(path).all(|(a, b)| a.as_slice() == *b)
}

/// The value of attribute `key` on `e`, as an owned string, if present.
fn find_attr(e: &quick_xml::events::BytesStart<'_>, key: &[u8]) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key)
        .map(|a| String::from_utf8_lossy(a.value.as_ref()).into_owned())
}

/// Decode a KeyFile **v1** `<Data>` payload: base64 of exactly 32 bytes.
fn decode_keyfile_v1(data: &str) -> Result<[u8; 32], KeyFileError> {
    use base64::Engine as _;
    let compact: Vec<u8> = data.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let mut decoded = base64::engine::general_purpose::STANDARD
        .decode(&compact)
        .map_err(|_| KeyFileError::InvalidKeyData)?;
    let result = <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| KeyFileError::InvalidKeyData);
    decoded.zeroize();
    result
}

/// Decode a KeyFile **v2** `<Data>` payload: whitespace-grouped hex of exactly
/// 32 bytes, with an optional `Hash` integrity checksum that is verified when
/// present.
fn decode_keyfile_v2(data: &str, hash: Option<&str>) -> Result<[u8; 32], KeyFileError> {
    let mut key = decode_hex_32(data).ok_or(KeyFileError::InvalidKeyData)?;
    if let Some(expected) = hash {
        // Hash = uppercase hex of SHA-256(key)[..4]. Verify-if-present /
        // accept-if-absent: a present-but-wrong hash means corruption and
        // fails closed; a foreign keyfile that omits the hash is still
        // accepted (interop with minters that don't write one).
        let digest = Sha256::digest(key);
        let actual = encode_hex_upper(&digest[..4]);
        if !expected.trim().eq_ignore_ascii_case(&actual) {
            // Wipe the recovered key on the reject path (matching the v1
            // decoder; the Ok path hands ownership to the caller verbatim).
            key.zeroize();
            return Err(KeyFileError::ChecksumMismatch);
        }
    }
    Ok(key)
}

/// Decode whitespace-separated hex into exactly 32 bytes, or `None` if the
/// non-whitespace content is not exactly 64 hex digits.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut nibbles = s.bytes().filter(|b| !b.is_ascii_whitespace());
    for byte in &mut out {
        let hi = nibbles.next().filter(u8::is_ascii_hexdigit)?;
        let lo = nibbles.next().filter(u8::is_ascii_hexdigit)?;
        *byte = (hex_digit_value(hi) << 4) | hex_digit_value(lo);
    }
    // Reject trailing content: anything left means more than 32 bytes.
    if nibbles.next().is_some() {
        return None;
    }
    Some(out)
}

/// Uppercase-hex-encode `bytes`.
fn encode_hex_upper(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut s, "{b:02X}").expect("writing to a String never fails");
    }
    s
}

/// Serialise 32 bytes of key material as a KeePass **KeyFile v2** (`.keyx`)
/// document — the modern, self-describing, integrity-checked keyfile format
/// that KeePassXC / KeePass 2 generate and prefer.
///
/// `Data` carries the 32 bytes as uppercase hex (grouped for readability) plus
/// a `Hash` attribute equal to the uppercase hex of the first four bytes of
/// `SHA-256(key)` (a corruption-detection checksum, not a MAC). [`keyfile_hash`]
/// round-trips the output back to `key`.
#[must_use]
pub fn keyfile_to_keyx_v2(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    let hash = encode_hex_upper(&digest[..4]);
    let mut hex = encode_hex_upper(key);
    // Group the 64 ASCII-hex chars into 8-char (4-byte) groups separated by
    // spaces. `hex` is ASCII, so byte-indexed chunking is char-aligned and
    // `b as char` is lossless (no panicking `from_utf8`).
    let mut data = String::with_capacity(hex.len() + hex.len() / 8);
    for (i, chunk) in hex.as_bytes().chunks(8).enumerate() {
        if i > 0 {
            data.push(' ');
        }
        data.extend(chunk.iter().map(|&b| b as char));
    }
    let doc = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<KeyFile>\n\
\t<Meta>\n\
\t\t<Version>2.0</Version>\n\
\t</Meta>\n\
\t<Key>\n\
\t\t<Data Hash=\"{hash}\">{data}</Data>\n\
\t</Key>\n\
</KeyFile>\n"
    );
    // Wipe the key-as-hex intermediates. The returned document still embeds the
    // key — its lifetime is the caller's, wrapped in `Zeroizing` on the mint
    // path (`generate_keyfile_keyx_v2`).
    hex.zeroize();
    data.zeroize();
    doc
}

/// Mint a fresh KeePass **KeyFile v2** (`.keyx`) document: 32 bytes from the OS
/// CSPRNG, serialised via [`keyfile_to_keyx_v2`]. The returned string is the
/// keyfile's file content; the caller owns where it is stored (OS keychain, a
/// sibling file, removable media). The raw key bytes are wiped before return —
/// only the serialised document (which embeds the key as hex) leaves here.
///
/// # Errors
///
/// Returns [`KeyFileError::RandomSource`] if the OS CSPRNG fails.
pub fn generate_keyfile_keyx_v2() -> Result<Zeroizing<String>, KeyFileError> {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| KeyFileError::RandomSource)?;
    let doc = keyfile_to_keyx_v2(&key);
    key.zeroize();
    Ok(Zeroizing::new(doc))
}

/// Error type for keyfile parsing / minting.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyFileError {
    /// The bytes looked like an XML keyfile but are not a well-formed
    /// `<KeyFile>` document (parse error, wrong root element, or a missing
    /// `Version` / `Data` element). Reported rather than silently hashing the
    /// raw bytes, which would derive a wrong composite key.
    #[error("malformed XML keyfile")]
    MalformedXml,

    /// The XML keyfile declares a major version this implementation does not
    /// recognise (only v1 and v2 are supported).
    #[error("unsupported XML keyfile version: {0}")]
    UnsupportedVersion(String),

    /// The XML keyfile's `Data` element did not decode to exactly 32 bytes of
    /// key material (bad base64 / hex, or the wrong length).
    #[error("invalid XML keyfile key data")]
    InvalidKeyData,

    /// A KeyFile v2 `Hash` attribute was present but did not match
    /// `SHA-256(key)[..4]`: the keyfile is corrupt or truncated. (The hash is
    /// a 4-byte integrity checksum, not a MAC — it detects corruption, not
    /// substitution.)
    #[error("XML keyfile checksum mismatch (corrupt key file)")]
    ChecksumMismatch,

    /// The OS cryptographically-secure RNG failed while minting a keyfile.
    #[error("secure random source failed")]
    RandomSource,
}

// ---------------------------------------------------------------------------
// TransformedKey — output of the KDF stage
// ---------------------------------------------------------------------------

/// The 32-byte transformed key — output of the KDF applied to a
/// [`CompositeKey`].
///
/// For KDBX3: AES-KDF of the composite key under `TransformSeed` for
/// `TransformRounds` rounds, then SHA-256 of the result.
///
/// For KDBX4: Argon2d / Argon2id of the composite key with the declared
/// parameters, direct 32-byte output.
///
/// This is the distinct-type reinforcement of §4.8.3's "newtype for every
/// semantic quantity" — a [`CompositeKey`] cannot be substituted for a
/// `TransformedKey` (or vice versa) even though they happen to share a
/// 32-byte width today.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct TransformedKey(Box<[u8; 32]>);

impl TransformedKey {
    /// Construct a transformed key from raw bytes. Intended for KDF
    /// implementations to emit their output; callers doing their own
    /// research may also use it.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte transformed key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TransformedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransformedKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// CipherKey — key handed to the outer AES-256 / ChaCha20 cipher
// ---------------------------------------------------------------------------

/// The 32-byte key handed to the outer payload cipher.
///
/// Derived as `SHA-256(master_seed || transformed_key)`. Used as-is by
/// AES-256-CBC (KDBX3 and KDBX4) and ChaCha20 (KDBX4 only).
///
/// Distinct type from [`TransformedKey`] even though both are 32 bytes:
/// substituting one for the other is a correctness bug, so the type
/// system prevents it.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct CipherKey(Box<[u8; 32]>);

impl CipherKey {
    /// Construct a cipher key from raw bytes. Intended for the derivation
    /// function to emit; prefer
    /// [`crate::crypto::derive_cipher_key`] for the standard path.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 32-byte cipher key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CipherKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherKey").field("len", &32).finish()
    }
}

// ---------------------------------------------------------------------------
// HmacKey — 64-byte base key for KDBX4 block HMAC verification
// ---------------------------------------------------------------------------

/// The 64-byte base key used to derive per-block HMAC keys in KDBX4.
///
/// Derived as `SHA-512(master_seed || transformed_key || 0x01)`. The
/// trailing 0x01 byte is KeePass's domain-separation marker.
///
/// Per-block HMAC keys are then computed as
/// `SHA-512(block_index_u64_le || base_key)` for each `u64` block
/// index. This module stores only the base; per-block derivation lives
/// with the block-verification logic.
///
/// KDBX3 has no HMAC step; this type is KDBX4-only.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct HmacBaseKey(Box<[u8; 64]>);

impl HmacBaseKey {
    /// Construct an HMAC base key from raw bytes. Intended for the
    /// derivation function; prefer [`crate::crypto::derive_hmac_base_key`]
    /// for the standard path.
    #[must_use]
    pub fn from_raw_bytes(bytes: [u8; 64]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the 64-byte base key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for HmacBaseKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacBaseKey").field("len", &64).finish()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: SHA-256 as a 32-byte array, for constructing reference values
    /// in tests.
    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&Sha256::digest(bytes));
        out
    }

    #[test]
    fn password_only_matches_double_sha256() {
        let pw = b"correct horse battery staple";
        let expected = sha256(&sha256(pw));
        let k = CompositeKey::from_password(pw);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn keyfile_only_hashes_once_externally() {
        // The external "keyfile_hash" parameter is already a single SHA-256
        // (or equivalent 32-byte key material). `from_keyfile_hash` wraps
        // it in one more SHA-256 pass for uniformity.
        let keyfile_hash = [0x42u8; 32];
        let expected = sha256(&keyfile_hash);
        let k = CompositeKey::from_keyfile_hash(&keyfile_hash);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn password_plus_keyfile_concatenates_then_hashes() {
        let pw = b"hunter2";
        let keyfile_hash = [0x99u8; 32];
        // Expected = SHA-256( SHA-256(pw) || keyfile_hash )
        let mut concat = Vec::with_capacity(64);
        concat.extend_from_slice(&sha256(pw));
        concat.extend_from_slice(&keyfile_hash);
        let expected = sha256(&concat);

        let k = CompositeKey::from_password_and_keyfile_hash(pw, &keyfile_hash);
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn different_inputs_produce_different_keys() {
        let k1 = CompositeKey::from_password(b"alpha");
        let k2 = CompositeKey::from_password(b"beta");
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn same_inputs_produce_identical_keys() {
        let k1 = CompositeKey::from_password(b"same");
        let k2 = CompositeKey::from_password(b"same");
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn password_and_keyfile_yields_different_key_than_password_alone() {
        let pw = b"same";
        let keyfile_hash = [0x11u8; 32];
        let with_kf = CompositeKey::from_password_and_keyfile_hash(pw, &keyfile_hash);
        let pw_only = CompositeKey::from_password(pw);
        assert_ne!(with_kf.as_bytes(), pw_only.as_bytes());
    }

    #[test]
    fn empty_password_is_legal() {
        // KeePass permits a blank password (usually when a keyfile is the
        // sole factor). The chain still runs.
        let k = CompositeKey::from_password(b"");
        // SHA-256(SHA-256(b"")) is a deterministic known value.
        let expected = sha256(&sha256(b""));
        assert_eq!(k.as_bytes(), &expected);
    }

    #[test]
    fn from_raw_bytes_stores_as_is() {
        let raw = [0xAA; 32];
        let k = CompositeKey::from_raw_bytes(raw);
        assert_eq!(k.as_bytes(), &raw);
    }

    #[test]
    fn debug_output_is_redacted() {
        let k = CompositeKey::from_password(b"secret value");
        let s = format!("{k:?}");
        assert!(
            !s.contains("secret"),
            "Debug should not leak the input: {s}"
        );
        // We don't assert absence of specific bytes (too risky given hash
        // output); the generic check is that the structure exposes only
        // a length.
        assert!(s.contains("len"));
        assert!(s.contains("32"));
    }

    #[test]
    fn clone_produces_equal_key() {
        let k = CompositeKey::from_password(b"clone me");
        let k2 = k.clone();
        assert_eq!(k.as_bytes(), k2.as_bytes());
    }

    // -----------------------------------------------------------------
    // keyfile_hash
    // -----------------------------------------------------------------

    #[test]
    fn keyfile_hash_uses_exact_32_bytes_verbatim() {
        let raw = [0xABu8; 32];
        assert_eq!(keyfile_hash(&raw).unwrap(), raw);
    }

    #[test]
    fn keyfile_hash_decodes_64_hex_chars() {
        let hex = b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let got = keyfile_hash(hex).unwrap();
        let expected: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        ];
        assert_eq!(got, expected);
    }

    #[test]
    fn keyfile_hash_hex_accepts_uppercase() {
        let hex = b"ABCDEFabcdef0123456789ABCDEFabcdef0123456789ABCDEFabcdef01234567";
        assert!(keyfile_hash(hex).is_ok());
    }

    #[test]
    fn keyfile_hash_rejects_64_non_hex_bytes_as_sha_of_file() {
        // 64 bytes that aren't hex → falls through to SHA-256(file).
        let mut bytes = [0u8; 64];
        bytes[0] = b'Z'; // non-hex byte
        let got = keyfile_hash(&bytes).unwrap();
        assert_eq!(got, sha256(&bytes));
    }

    #[test]
    fn keyfile_hash_falls_back_to_sha256_for_arbitrary_length() {
        for len in [0, 1, 31, 33, 63, 65, 128, 4096] {
            let bytes = vec![0x55u8; len];
            let got = keyfile_hash(&bytes).unwrap();
            assert_eq!(got, sha256(&bytes));
        }
    }

    // -----------------------------------------------------------------
    // XML keyfiles (KeyFile v1 / v2 / .keyx)
    // -----------------------------------------------------------------

    #[test]
    fn keyfile_hash_parses_keepassxc_v2_keyx_vector() {
        // A real KeePassXC `.keyx` (KeyFile v2) test vector — note the xmlns
        // attributes on the root element and the whitespace-grouped hex.
        let keyx = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<KeyFile xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">\n\
\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\
\t<Key>\n\t\t<Data Hash=\"FE2949B8\">\n\
\t\t\tA7007945 D07D54BA 28DF6434 1B4500FC\n\
\t\t\t9750DFB1 D36ADA2D 9C32DC19 4C7AB01B\n\
\t\t</Data>\n\t</Key>\n</KeyFile>";
        let expected: [u8; 32] = [
            0xA7, 0x00, 0x79, 0x45, 0xD0, 0x7D, 0x54, 0xBA, 0x28, 0xDF, 0x64, 0x34, 0x1B, 0x45,
            0x00, 0xFC, 0x97, 0x50, 0xDF, 0xB1, 0xD3, 0x6A, 0xDA, 0x2D, 0x9C, 0x32, 0xDC, 0x19,
            0x4C, 0x7A, 0xB0, 0x1B,
        ];
        assert_eq!(keyfile_hash(keyx).unwrap(), expected);
    }

    #[test]
    fn keyfile_hash_parses_keepassxc_v1_base64_vector() {
        use base64::Engine as _;
        let key_v1 = b"<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
<KeyFile>\n\t<Meta>\n\t\t<Version>1.00</Version>\n\t</Meta>\n\
\t<Key>\n\t\t<Data>nhNal+U9p6h1rWAAJ5YrNkMazMTZkIWLi3WC4JQv5jk=</Data>\n\t</Key>\n</KeyFile>";
        let expected = base64::engine::general_purpose::STANDARD
            .decode("nhNal+U9p6h1rWAAJ5YrNkMazMTZkIWLi3WC4JQv5jk=")
            .unwrap();
        assert_eq!(
            keyfile_hash(key_v1).unwrap().as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn mint_keyx_v2_roundtrips_and_self_verifies() {
        let doc = generate_keyfile_keyx_v2().unwrap();
        // The minted document parses back to 32 bytes and its embedded hash
        // verifies (no ChecksumMismatch).
        let parsed = keyfile_hash(doc.as_bytes()).unwrap();
        // Re-serialising those bytes reproduces a doc that parses identically.
        let doc2 = keyfile_to_keyx_v2(&parsed);
        assert_eq!(keyfile_hash(doc2.as_bytes()).unwrap(), parsed);
        // Two mints differ (fresh entropy).
        let other = generate_keyfile_keyx_v2().unwrap();
        assert_ne!(doc.as_str(), other.as_str());
    }

    #[test]
    fn keyfile_v2_rejects_a_corrupted_hash() {
        let key = [0x11u8; 32];
        let good = keyfile_to_keyx_v2(&key);
        // Swap the real Hash attribute for a wrong one of the same shape.
        let start = good.find("Hash=\"").unwrap() + 6;
        let end = start + good[start..].find('"').unwrap();
        let mut bad = good.clone();
        bad.replace_range(start..end, "DEADBEEF");
        assert!(matches!(
            keyfile_hash(bad.as_bytes()).unwrap_err(),
            KeyFileError::ChecksumMismatch
        ));
        // Sanity: the unmodified document still verifies and round-trips.
        assert_eq!(keyfile_hash(good.as_bytes()).unwrap(), key);
    }

    #[test]
    fn keyfile_v2_accepts_a_missing_hash() {
        // A v2 keyfile with no Hash attribute is accepted (foreign-tool interop).
        let doc = b"<KeyFile><Meta><Version>2.0</Version></Meta>\
<Key><Data>00112233 44556677 8899AABB CCDDEEFF 00112233 44556677 8899AABB CCDDEEFF</Data></Key></KeyFile>";
        let expected: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
            0xCC, 0xDD, 0xEE, 0xFF,
        ];
        assert_eq!(keyfile_hash(doc).unwrap(), expected);
    }

    #[test]
    fn keyfile_v2_rejects_non_hex_data() {
        let doc = b"<KeyFile><Meta><Version>2.0</Version></Meta>\
<Key><Data>ZZZZ</Data></Key></KeyFile>";
        assert!(matches!(
            keyfile_hash(doc).unwrap_err(),
            KeyFileError::InvalidKeyData
        ));
    }

    #[test]
    fn keyfile_rejects_unknown_version() {
        let doc = b"<KeyFile><Meta><Version>3.0</Version></Meta>\
<Key><Data>00</Data></Key></KeyFile>";
        assert!(matches!(
            keyfile_hash(doc).unwrap_err(),
            KeyFileError::UnsupportedVersion(_)
        ));
    }

    #[test]
    fn malformed_xml_keyfiles_fail_closed_not_silently_hashed() {
        // Looks like XML (so it must NOT fall through to the SHA-256 path) but
        // is not a well-formed KeyFile document.
        let no_version = b"<?xml version=\"1.0\"?><KeyFile><Key><Data>abc</Data></Key></KeyFile>";
        assert!(matches!(
            keyfile_hash(no_version).unwrap_err(),
            KeyFileError::MalformedXml
        ));

        let mut bom = vec![0xEF, 0xBB, 0xBF];
        bom.extend_from_slice(b"   \n<KeyFile/>");
        assert!(matches!(
            keyfile_hash(&bom).unwrap_err(),
            KeyFileError::MalformedXml
        ));
    }

    /// Reference vector — single-SHA of the empty string, for sanity.
    /// SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn sha256_helper_matches_known_vector() {
        let h = sha256(b"");
        assert_eq!(
            h,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ],
        );
    }
}
