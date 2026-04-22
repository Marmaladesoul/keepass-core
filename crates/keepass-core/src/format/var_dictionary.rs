//! Decoder for KDBX4's **VarDictionary** serialisation format.
//!
//! VarDictionary is the KeePass-specific key-value encoding used for the
//! KDBX4 `KdfParameters` header field (and optionally `PublicCustomData`).
//! Each entry is `(type, key_length_LE_i32, key_utf8, value_length_LE_i32,
//! value)`, and the stream is terminated by a single `0x00` type byte.
//!
//! The version prefix is a little-endian `u16`. Only the **major** version
//! is validated strictly; a newer minor version is tolerated (the KeePass
//! spec promises backward compatibility within a major version).
//!
//! ## On-disk layout
//!
//! ```text
//!   ┌──────────────┐
//!   │ version: u16 │
//!   ├──────────────┘
//!   │   ( type: u8
//!   │     key_len: i32 LE
//!   │     key: utf-8
//!   │     value_len: i32 LE
//!   │     value: bytes )*
//!   │
//!   │   end marker (type = 0x00)
//!   └──────────────
//! ```
//!
//! ## Value types
//!
//! | Byte | Rust type       | Notes                    |
//! |------|-----------------|--------------------------|
//! | 0x04 | [`Value::U32`]  | 4-byte little-endian u32 |
//! | 0x05 | [`Value::U64`]  | 8-byte little-endian u64 |
//! | 0x08 | [`Value::Bool`] | 1 byte (0 or 1)          |
//! | 0x0C | [`Value::I32`]  | 4-byte little-endian i32 |
//! | 0x0D | [`Value::I64`]  | 8-byte little-endian i64 |
//! | 0x18 | [`Value::String`] | UTF-8                 |
//! | 0x42 | [`Value::Bytes`]  | Raw bytes             |
//!
//! This module handles both decoding and encoding. The encoder
//! ([`VarDictionary::write`]) always emits entries in ASCII-sorted
//! key order (BTreeMap iteration order). Byte-exact round-trip of a
//! source blob therefore holds only when that source was already
//! sorted — KeePassXC is; kdbxweb is not. Typed round-trip
//! (parse → write → parse yields the same [`VarDictionary`]) always
//! holds.

use std::collections::BTreeMap;

use thiserror::Error;
use winnow::Parser;
use winnow::binary::{le_i32, le_i64, le_u8, le_u16, le_u32, le_u64};
use winnow::error::ContextError;
use winnow::token::take;

// Pin the winnow error type to `ContextError` so our wrapper function can
// infer the parser's error parameter without callers having to annotate.
type WResult<T> = winnow::ModalResult<T, ContextError>;

/// The current supported major version of VarDictionary.
pub const VERSION_MAJOR: u8 = 1;

// Type byte values defined by the KDBX4 spec.
const TYPE_END: u8 = 0x00;
const TYPE_U32: u8 = 0x04;
const TYPE_U64: u8 = 0x05;
const TYPE_BOOL: u8 = 0x08;
const TYPE_I32: u8 = 0x0C;
const TYPE_I64: u8 = 0x0D;
const TYPE_STRING: u8 = 0x18;
const TYPE_BYTES: u8 = 0x42;

/// One typed value stored in a VarDictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Unsigned 32-bit integer.
    U32(u32),
    /// Unsigned 64-bit integer.
    U64(u64),
    /// Boolean.
    Bool(bool),
    /// Signed 32-bit integer.
    I32(i32),
    /// Signed 64-bit integer.
    I64(i64),
    /// UTF-8 string.
    String(String),
    /// Raw bytes.
    Bytes(Vec<u8>),
}

/// A decoded VarDictionary.
///
/// Insertion order is not preserved — KeePass readers look values up by key,
/// not by position. The dictionary is backed by a [`BTreeMap`] so iteration
/// is deterministic (sorted by key) which aids reproducible test output.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VarDictionary {
    /// Major version from the on-disk version prefix.
    pub version_major: u8,
    /// Minor version from the on-disk version prefix.
    pub version_minor: u8,
    /// The key-value entries, sorted by key.
    pub entries: BTreeMap<String, Value>,
}

impl VarDictionary {
    /// Look up a value by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.get(key)
    }

    /// Convenience accessor: return the `u32` at `key`, if present and of
    /// the right type.
    #[must_use]
    pub fn get_u32(&self, key: &str) -> Option<u32> {
        if let Some(Value::U32(v)) = self.entries.get(key) {
            Some(*v)
        } else {
            None
        }
    }

    /// Convenience accessor: return the `u64` at `key`, if present and of
    /// the right type.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        if let Some(Value::U64(v)) = self.entries.get(key) {
            Some(*v)
        } else {
            None
        }
    }

    /// Convenience accessor: return the bytes at `key`, if present and of
    /// the right type.
    #[must_use]
    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        if let Some(Value::Bytes(v)) = self.entries.get(key) {
            Some(v.as_slice())
        } else {
            None
        }
    }

    /// Parse a VarDictionary from a byte buffer.
    ///
    /// The buffer must contain the entire encoded dictionary including the
    /// version prefix and terminator byte. Trailing bytes after the
    /// terminator are ignored and reported as remaining in the slice (use
    /// [`Self::parse_consuming`] if you want the whole buffer consumed).
    ///
    /// # Errors
    ///
    /// Returns [`VarDictionaryError::UnsupportedVersion`] for any major
    /// version other than [`VERSION_MAJOR`]. Returns
    /// [`VarDictionaryError::Truncated`] on a short read. Returns
    /// [`VarDictionaryError::UnknownType`] on an unknown value-type byte.
    /// Returns [`VarDictionaryError::InvalidLength`] on a negative
    /// length-field. Returns [`VarDictionaryError::InvalidUtf8`] on a
    /// key or string-value that is not valid UTF-8.
    /// Returns [`VarDictionaryError::InvalidBool`] if a boolean value byte
    /// is neither 0 nor 1.
    pub fn parse(mut input: &[u8]) -> Result<Self, VarDictionaryError> {
        let cursor = &mut input;
        parse_dictionary(cursor)
    }

    /// Serialise this dictionary to a byte buffer — the inverse of
    /// [`Self::parse`].
    ///
    /// Emits the version prefix (`[minor, major]`), then every entry in
    /// BTreeMap iteration order (sorted by key), then the `0x00`
    /// terminator. Round-trips any dictionary produced by
    /// [`Self::parse`] back to a byte-identical form *when the source
    /// bytes also listed entries in sorted key order*. Not every
    /// upstream writer does so — kdbxweb in particular emits entries
    /// in insertion order — so byte-exact round-trip of an arbitrary
    /// source blob is not guaranteed. Typed round-trip (parse-write-
    /// parse yields the same [`VarDictionary`]) always holds.
    ///
    /// # Errors
    ///
    /// Returns [`VarDictionaryWriteError::LengthOverflow`] if any key
    /// or value's byte length exceeds `i32::MAX`. Effectively
    /// unreachable — KeePass headers hold kilobytes of data, not
    /// gigabytes — but surfaced as a typed error rather than a panic.
    pub fn write(&self) -> Result<Vec<u8>, VarDictionaryWriteError> {
        // Pre-size: 2 bytes version + per-entry (1 type + 4 key-len +
        // key + 4 value-len + value) + 1 terminator.
        let approx: usize = 2
            + self
                .entries
                .iter()
                .map(|(k, v)| 1 + 4 + k.len() + 4 + value_byte_len(v))
                .sum::<usize>()
            + 1;
        let mut out = Vec::with_capacity(approx);

        // Version prefix: [minor, major], so u16::from_le_bytes reads
        // the minor byte as the low byte — matches the decoder.
        out.push(self.version_minor);
        out.push(self.version_major);

        for (key, value) in &self.entries {
            let ty = value_type_byte(value);
            let key_len =
                i32::try_from(key.len()).map_err(|_| VarDictionaryWriteError::LengthOverflow {
                    key: key.clone(),
                    field: Field::Key,
                    len: key.len(),
                })?;
            out.push(ty);
            out.extend_from_slice(&key_len.to_le_bytes());
            out.extend_from_slice(key.as_bytes());

            let value_bytes = encode_value_payload(value);
            let value_len = i32::try_from(value_bytes.len()).map_err(|_| {
                VarDictionaryWriteError::LengthOverflow {
                    key: key.clone(),
                    field: Field::Value,
                    len: value_bytes.len(),
                }
            })?;
            out.extend_from_slice(&value_len.to_le_bytes());
            out.extend_from_slice(&value_bytes);
        }

        out.push(TYPE_END);
        Ok(out)
    }

    /// Like [`Self::parse`], but asserts that the entire buffer is consumed.
    ///
    /// # Errors
    ///
    /// Same errors as [`Self::parse`], plus [`VarDictionaryError::TrailingBytes`]
    /// if there are unconsumed bytes after the terminator.
    pub fn parse_consuming(input: &[u8]) -> Result<Self, VarDictionaryError> {
        let mut cursor = input;
        let dict = parse_dictionary(&mut cursor)?;
        if !cursor.is_empty() {
            return Err(VarDictionaryError::TrailingBytes(cursor.len()));
        }
        Ok(dict)
    }
}

// ---------------------------------------------------------------------------
// Encoder helpers
// ---------------------------------------------------------------------------

/// The type byte that identifies this value's variant on disk.
const fn value_type_byte(v: &Value) -> u8 {
    match v {
        Value::U32(_) => TYPE_U32,
        Value::U64(_) => TYPE_U64,
        Value::Bool(_) => TYPE_BOOL,
        Value::I32(_) => TYPE_I32,
        Value::I64(_) => TYPE_I64,
        Value::String(_) => TYPE_STRING,
        Value::Bytes(_) => TYPE_BYTES,
    }
}

/// Byte length this value occupies in the payload section (after its
/// length prefix). Used for pre-sizing the output buffer.
fn value_byte_len(v: &Value) -> usize {
    match v {
        Value::U32(_) | Value::I32(_) => 4,
        Value::U64(_) | Value::I64(_) => 8,
        Value::Bool(_) => 1,
        Value::String(s) => s.len(),
        Value::Bytes(b) => b.len(),
    }
}

/// Encode the raw value payload (without type byte or length prefix).
fn encode_value_payload(v: &Value) -> Vec<u8> {
    match v {
        Value::U32(n) => n.to_le_bytes().to_vec(),
        Value::U64(n) => n.to_le_bytes().to_vec(),
        Value::Bool(b) => vec![u8::from(*b)],
        Value::I32(n) => n.to_le_bytes().to_vec(),
        Value::I64(n) => n.to_le_bytes().to_vec(),
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Bytes(b) => b.clone(),
    }
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Which side of a VarDictionary entry overflowed the length prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Field {
    /// The key string.
    Key,
    /// The value payload.
    Value,
}

impl std::fmt::Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key => f.write_str("key"),
            Self::Value => f.write_str("value"),
        }
    }
}

/// Errors that may arise while encoding a VarDictionary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VarDictionaryWriteError {
    /// A key or value exceeded the length that fits in the on-disk
    /// `i32` length prefix. Effectively unreachable for real headers.
    #[error("VarDictionary {field} for key {key:?} has length {len} which overflows i32")]
    LengthOverflow {
        /// The key whose entry overflowed.
        key: String,
        /// Whether the key or value field was too long.
        field: Field,
        /// The actual length in bytes.
        len: usize,
    },
}

/// Errors that may arise while decoding a VarDictionary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VarDictionaryError {
    /// The buffer ended before the decoder expected.
    #[error("unexpected end of VarDictionary input")]
    Truncated,

    /// The declared major version is not one this decoder supports.
    #[error("unsupported VarDictionary major version: {got}, supported: {supported}")]
    UnsupportedVersion {
        /// Major version byte from the file.
        got: u8,
        /// Major version this decoder was built for.
        supported: u8,
    },

    /// A value-type byte is not among the known type codes.
    #[error("unknown VarDictionary value type: 0x{0:02x}")]
    UnknownType(u8),

    /// A length field was negative, which the KDBX spec disallows.
    #[error("invalid VarDictionary length field: {0}")]
    InvalidLength(i32),

    /// A key or string value contained invalid UTF-8.
    #[error("invalid UTF-8 in VarDictionary {field}")]
    InvalidUtf8 {
        /// Whether the invalid UTF-8 was in a key or a value.
        field: &'static str,
    },

    /// A bool value byte was neither 0 nor 1.
    #[error("invalid VarDictionary bool value: {0}")]
    InvalidBool(u8),

    /// A value was the wrong length for its declared type.
    #[error("VarDictionary value for key {key:?} has wrong length: expected {expected}, got {got}")]
    ValueWrongLength {
        /// The key whose value was wrongly sized.
        key: String,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// A duplicate key was encountered — the spec says dictionaries have
    /// unique keys.
    #[error("duplicate VarDictionary key: {0:?}")]
    DuplicateKey(String),

    /// Bytes remained after the terminator. Reported only by
    /// [`VarDictionary::parse_consuming`].
    #[error("{0} trailing bytes after VarDictionary terminator")]
    TrailingBytes(usize),
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

fn parse_dictionary(input: &mut &[u8]) -> Result<VarDictionary, VarDictionaryError> {
    // Version prefix: u16 LE, packed as (minor, major) — the two bytes are
    // `[minor, major]` in the file so a `u16::from_le_bytes` reads the
    // *minor* byte as the low byte.
    let version = parse_u16_le(input)?;
    let version_minor = (version & 0xFF) as u8;
    let version_major = ((version >> 8) & 0xFF) as u8;

    if version_major != VERSION_MAJOR {
        return Err(VarDictionaryError::UnsupportedVersion {
            got: version_major,
            supported: VERSION_MAJOR,
        });
    }

    let mut entries: BTreeMap<String, Value> = BTreeMap::new();

    loop {
        let ty = parse_u8(input)?;
        if ty == TYPE_END {
            break;
        }
        let (key, value) = parse_entry(ty, input)?;
        if entries.insert(key.clone(), value).is_some() {
            return Err(VarDictionaryError::DuplicateKey(key));
        }
    }

    Ok(VarDictionary {
        version_major,
        version_minor,
        entries,
    })
}

fn parse_entry(ty: u8, input: &mut &[u8]) -> Result<(String, Value), VarDictionaryError> {
    let key_len_i = parse_i32_le(input)?;
    let key_len =
        usize::try_from(key_len_i).map_err(|_| VarDictionaryError::InvalidLength(key_len_i))?;
    let key_bytes = parse_take(input, key_len)?;
    let key = std::str::from_utf8(key_bytes)
        .map_err(|_| VarDictionaryError::InvalidUtf8 { field: "key" })?
        .to_owned();

    let value_len_i = parse_i32_le(input)?;
    let value_len =
        usize::try_from(value_len_i).map_err(|_| VarDictionaryError::InvalidLength(value_len_i))?;
    let value_bytes = parse_take(input, value_len)?;

    let value = decode_value(ty, &key, value_bytes)?;
    Ok((key, value))
}

fn decode_value(ty: u8, key: &str, bytes: &[u8]) -> Result<Value, VarDictionaryError> {
    match ty {
        TYPE_U32 => fixed_len::<4>(key, bytes).map(|arr| Value::U32(u32::from_le_bytes(arr))),
        TYPE_U64 => fixed_len::<8>(key, bytes).map(|arr| Value::U64(u64::from_le_bytes(arr))),
        TYPE_I32 => fixed_len::<4>(key, bytes).map(|arr| Value::I32(i32::from_le_bytes(arr))),
        TYPE_I64 => fixed_len::<8>(key, bytes).map(|arr| Value::I64(i64::from_le_bytes(arr))),
        TYPE_BOOL => {
            let [b] = fixed_len::<1>(key, bytes)?;
            match b {
                0 => Ok(Value::Bool(false)),
                1 => Ok(Value::Bool(true)),
                other => Err(VarDictionaryError::InvalidBool(other)),
            }
        }
        TYPE_STRING => {
            let s = std::str::from_utf8(bytes)
                .map_err(|_| VarDictionaryError::InvalidUtf8 {
                    field: "string value",
                })?
                .to_owned();
            Ok(Value::String(s))
        }
        TYPE_BYTES => Ok(Value::Bytes(bytes.to_vec())),
        other => Err(VarDictionaryError::UnknownType(other)),
    }
}

fn fixed_len<const N: usize>(key: &str, bytes: &[u8]) -> Result<[u8; N], VarDictionaryError> {
    bytes
        .try_into()
        .map_err(|_| VarDictionaryError::ValueWrongLength {
            key: key.to_owned(),
            expected: N,
            got: bytes.len(),
        })
}

// --- tiny winnow-backed primitives with VarDictionaryError mapping --------

fn parse_u8(input: &mut &[u8]) -> Result<u8, VarDictionaryError> {
    wrap::<u8>(le_u8.parse_next(input))
}
fn parse_u16_le(input: &mut &[u8]) -> Result<u16, VarDictionaryError> {
    wrap::<u16>(le_u16.parse_next(input))
}
fn parse_i32_le(input: &mut &[u8]) -> Result<i32, VarDictionaryError> {
    wrap::<i32>(le_i32.parse_next(input))
}
fn parse_take<'a>(input: &mut &'a [u8], n: usize) -> Result<&'a [u8], VarDictionaryError> {
    let r: WResult<&'a [u8]> = take(n).parse_next(input);
    wrap(r)
}

// `winnow` errors don't carry "why" here; all we know is "the cursor didn't
// have enough bytes for the parser we called". That is always a truncation
// in this module.
fn wrap<T>(r: WResult<T>) -> Result<T, VarDictionaryError> {
    r.map_err(|_| VarDictionaryError::Truncated)
}

// u64 / u32 / i64 parsers aren't used at the statement level currently (we
// decode their bytes by hand from a take()) but we expose them here so the
// decoder's primitives are complete for future code.
#[allow(dead_code)]
fn parse_u64_le(input: &mut &[u8]) -> Result<u64, VarDictionaryError> {
    wrap::<u64>(le_u64.parse_next(input))
}
#[allow(dead_code)]
fn parse_u32_le(input: &mut &[u8]) -> Result<u32, VarDictionaryError> {
    wrap::<u32>(le_u32.parse_next(input))
}
#[allow(dead_code)]
fn parse_i64_le(input: &mut &[u8]) -> Result<i64, VarDictionaryError> {
    wrap::<i64>(le_i64.parse_next(input))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Small helper: write a version prefix ([minor, major]) to `out`.
    fn push_version(out: &mut Vec<u8>, major: u8, minor: u8) {
        out.push(minor);
        out.push(major);
    }

    /// Encode one entry into `out` for test purposes.
    fn push_entry(out: &mut Vec<u8>, ty: u8, key: &str, value_bytes: &[u8]) {
        out.push(ty);
        out.extend_from_slice(&(i32::try_from(key.len()).unwrap()).to_le_bytes());
        out.extend_from_slice(key.as_bytes());
        out.extend_from_slice(&(i32::try_from(value_bytes.len()).unwrap()).to_le_bytes());
        out.extend_from_slice(value_bytes);
    }

    fn roundtrip_value(ty: u8, key: &str, value_bytes: &[u8]) -> Value {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, ty, key, value_bytes);
        buf.push(TYPE_END);
        let dict = VarDictionary::parse(&buf).unwrap();
        dict.entries.get(key).unwrap().clone()
    }

    #[test]
    fn parses_empty_dictionary() {
        let buf = [0x00u8, 0x01u8 /* minor=0 major=1 */, TYPE_END];
        let dict = VarDictionary::parse(&buf).unwrap();
        assert_eq!(dict.version_major, 1);
        assert_eq!(dict.version_minor, 0);
        assert!(dict.entries.is_empty());
    }

    #[test]
    fn parses_u32_value() {
        let v = roundtrip_value(TYPE_U32, "Iter", &42u32.to_le_bytes());
        assert_eq!(v, Value::U32(42));
    }

    #[test]
    fn parses_u64_value() {
        let v = roundtrip_value(TYPE_U64, "Mem", &(65_536u64).to_le_bytes());
        assert_eq!(v, Value::U64(65_536));
    }

    #[test]
    fn parses_bool_value() {
        let v_true = roundtrip_value(TYPE_BOOL, "Flag", &[1]);
        assert_eq!(v_true, Value::Bool(true));
        let v_false = roundtrip_value(TYPE_BOOL, "Flag", &[0]);
        assert_eq!(v_false, Value::Bool(false));
    }

    #[test]
    fn parses_i32_and_i64_values() {
        let v = roundtrip_value(TYPE_I32, "Neg", &(-7i32).to_le_bytes());
        assert_eq!(v, Value::I32(-7));
        let v = roundtrip_value(TYPE_I64, "Neg64", &(-100i64).to_le_bytes());
        assert_eq!(v, Value::I64(-100));
    }

    #[test]
    fn parses_string_value() {
        let v = roundtrip_value(TYPE_STRING, "Name", "Contoso".as_bytes());
        assert_eq!(v, Value::String("Contoso".to_owned()));
    }

    #[test]
    fn parses_bytes_value() {
        let v = roundtrip_value(TYPE_BYTES, "Salt", &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(v, Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]));
    }

    #[test]
    fn parses_realistic_argon2_params_blob() {
        // Keys commonly present in a real KDBX4 Argon2 KdfParameters:
        //   $UUID (bytes, 16), S (bytes, 32), R (u64), V (u32),
        //   I (u64), M (u64), P (u32)
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_BYTES, "$UUID", &[0xEFu8; 16]);
        push_entry(&mut buf, TYPE_BYTES, "S", &[0xAB; 32]);
        push_entry(&mut buf, TYPE_U64, "I", &2u64.to_le_bytes());
        push_entry(&mut buf, TYPE_U64, "M", &(65_536u64).to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "P", &1u32.to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "V", &19u32.to_le_bytes());
        buf.push(TYPE_END);

        let d = VarDictionary::parse(&buf).unwrap();
        assert_eq!(d.get_bytes("$UUID").unwrap().len(), 16);
        assert_eq!(d.get_bytes("S").unwrap().len(), 32);
        assert_eq!(d.get_u64("I"), Some(2));
        assert_eq!(d.get_u64("M"), Some(65_536));
        assert_eq!(d.get_u32("P"), Some(1));
        assert_eq!(d.get_u32("V"), Some(19));
        // Type-mismatched accessor returns None, not an error.
        assert_eq!(d.get_u32("$UUID"), None);
    }

    #[test]
    fn rejects_unsupported_major_version() {
        let buf = [0x00u8, 0x02u8 /* major=2 */, TYPE_END];
        let err = VarDictionary::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            VarDictionaryError::UnsupportedVersion {
                got: 2,
                supported: 1
            }
        ));
    }

    #[test]
    fn rejects_unknown_value_type() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, 0xFFu8 /* unknown type */, "X", &[1, 2, 3]);
        buf.push(TYPE_END);
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::UnknownType(0xFF)
        ));
    }

    #[test]
    fn rejects_truncation() {
        // Just the version, nothing else.
        let buf = [0x00u8, 0x01u8];
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::Truncated
        ));
    }

    #[test]
    fn rejects_negative_length() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        buf.push(TYPE_U32);
        buf.extend_from_slice(&(-1i32).to_le_bytes()); // key length -1
        let err = VarDictionary::parse(&buf).unwrap_err();
        assert!(matches!(err, VarDictionaryError::InvalidLength(-1)));
    }

    #[test]
    fn rejects_invalid_utf8_key() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        buf.push(TYPE_U32);
        buf.extend_from_slice(&2i32.to_le_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE]); // not valid UTF-8
        buf.extend_from_slice(&4i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.push(TYPE_END);
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::InvalidUtf8 { field: "key" }
        ));
    }

    #[test]
    fn rejects_value_of_wrong_length_for_type() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_U32, "X", &[1, 2, 3]); // should be 4 bytes
        buf.push(TYPE_END);
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::ValueWrongLength {
                expected: 4,
                got: 3,
                ..
            }
        ));
    }

    #[test]
    fn rejects_invalid_bool() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_BOOL, "X", &[2]); // only 0/1 valid
        buf.push(TYPE_END);
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::InvalidBool(2)
        ));
    }

    #[test]
    fn rejects_duplicate_keys() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_U32, "X", &1u32.to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "X", &2u32.to_le_bytes());
        buf.push(TYPE_END);
        assert!(matches!(
            VarDictionary::parse(&buf).unwrap_err(),
            VarDictionaryError::DuplicateKey(k) if k == "X"
        ));
    }

    #[test]
    fn parse_consuming_rejects_trailing_bytes() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        buf.push(TYPE_END);
        buf.extend_from_slice(b"garbage");
        assert!(matches!(
            VarDictionary::parse_consuming(&buf).unwrap_err(),
            VarDictionaryError::TrailingBytes(7)
        ));
    }

    #[test]
    fn parse_allows_trailing_bytes_by_default() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        buf.push(TYPE_END);
        buf.extend_from_slice(b"whatever");
        assert!(VarDictionary::parse(&buf).is_ok());
    }

    #[test]
    fn tolerates_newer_minor_version() {
        // Major=1, minor=99: decoder accepts.
        let buf = [99u8, 0x01, TYPE_END];
        let d = VarDictionary::parse(&buf).unwrap();
        assert_eq!(d.version_major, 1);
        assert_eq!(d.version_minor, 99);
    }

    #[test]
    fn entries_are_sorted_by_key() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_U32, "zeta", &0u32.to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "alpha", &1u32.to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "mu", &2u32.to_le_bytes());
        buf.push(TYPE_END);
        let d = VarDictionary::parse(&buf).unwrap();
        let keys: Vec<_> = d.entries.keys().collect();
        assert_eq!(keys, ["alpha", "mu", "zeta"]);
    }

    // -----------------------------------------------------------------------
    // Writer tests
    // -----------------------------------------------------------------------

    /// Build a dictionary by hand and confirm write/parse/write is stable.
    fn dict_from(entries: &[(&str, Value)], major: u8, minor: u8) -> VarDictionary {
        let mut d = VarDictionary {
            version_major: major,
            version_minor: minor,
            entries: BTreeMap::new(),
        };
        for (k, v) in entries {
            d.entries.insert((*k).to_owned(), v.clone());
        }
        d
    }

    #[test]
    fn writes_empty_dictionary() {
        let d = dict_from(&[], 1, 0);
        let bytes = d.write().unwrap();
        assert_eq!(bytes, vec![0x00, 0x01, TYPE_END]);
        let back = VarDictionary::parse_consuming(&bytes).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn round_trips_every_value_type() {
        let d = dict_from(
            &[
                ("b32", Value::U32(0xDEAD_BEEF)),
                ("b64", Value::U64(0x1234_5678_9ABC_DEF0)),
                ("flag", Value::Bool(true)),
                ("i32", Value::I32(-7)),
                ("i64", Value::I64(-1_000_000_000_000)),
                ("name", Value::String("Contoso".to_owned())),
                ("salt", Value::Bytes(vec![0xCA, 0xFE, 0xBA, 0xBE])),
            ],
            1,
            0,
        );
        let bytes = d.write().unwrap();
        let back = VarDictionary::parse_consuming(&bytes).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn byte_exact_round_trip_when_source_is_sorted() {
        // Build a byte stream in sorted-key order, parse it, re-emit,
        // and assert equality.
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_BYTES, "$UUID", &[0xEFu8; 16]);
        push_entry(&mut buf, TYPE_U64, "I", &2u64.to_le_bytes());
        push_entry(&mut buf, TYPE_U64, "M", &(65_536u64).to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "P", &1u32.to_le_bytes());
        push_entry(&mut buf, TYPE_BYTES, "S", &[0xAB; 32]);
        push_entry(&mut buf, TYPE_U32, "V", &19u32.to_le_bytes());
        buf.push(TYPE_END);

        let d = VarDictionary::parse_consuming(&buf).unwrap();
        let rewritten = d.write().unwrap();
        assert_eq!(rewritten, buf);
    }

    #[test]
    fn writer_sorts_unsorted_input() {
        // An unsorted source is normalised to sorted order by the writer
        // because the in-memory BTreeMap has no concept of "original
        // order". This is the documented behaviour.
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        push_entry(&mut buf, TYPE_U32, "zeta", &0u32.to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "alpha", &1u32.to_le_bytes());
        buf.push(TYPE_END);
        let d = VarDictionary::parse_consuming(&buf).unwrap();
        let rewritten = d.write().unwrap();
        // Parse the rewritten form via byte inspection: first entry after
        // the version prefix should be "alpha".
        assert_eq!(&rewritten[0..2], &[0x00, 0x01]);
        // type(1) + i32 key_len(4) = 5 bytes, then key bytes.
        assert_eq!(&rewritten[2..3], &[TYPE_U32]);
        assert_eq!(&rewritten[3..7], &5i32.to_le_bytes());
        assert_eq!(&rewritten[7..12], b"alpha");
    }

    #[test]
    fn version_bytes_are_minor_then_major() {
        let d = dict_from(&[], 1, 42);
        let bytes = d.write().unwrap();
        // [minor=42, major=1] per the KDBX VarDictionary layout.
        assert_eq!(bytes[0], 42);
        assert_eq!(bytes[1], 1);
    }

    #[test]
    fn string_values_are_not_null_terminated() {
        let d = dict_from(&[("Name", Value::String("abc".to_owned()))], 1, 0);
        let bytes = d.write().unwrap();
        // Find the value_len i32 for "Name": type(1) + keylen(4) + key(4) = 9 bytes in,
        // so the value length sits at offset 2+9 = 11.
        let vlen = i32::from_le_bytes([bytes[11], bytes[12], bytes[13], bytes[14]]);
        assert_eq!(
            vlen, 3,
            "string value length should be 3, no NUL terminator"
        );
    }

    #[test]
    fn bool_encodes_as_single_byte() {
        let d = dict_from(&[("T", Value::Bool(true))], 1, 0);
        let bytes = d.write().unwrap();
        let back = VarDictionary::parse_consuming(&bytes).unwrap();
        assert_eq!(back.entries.get("T"), Some(&Value::Bool(true)));
        // Terminator byte is the last.
        assert_eq!(*bytes.last().unwrap(), TYPE_END);
    }

    #[test]
    fn minor_version_is_preserved_on_round_trip() {
        let d = dict_from(&[("X", Value::U32(1))], 1, 99);
        let bytes = d.write().unwrap();
        let back = VarDictionary::parse_consuming(&bytes).unwrap();
        assert_eq!(back.version_major, 1);
        assert_eq!(back.version_minor, 99);
    }

    #[test]
    fn large_bytes_value_round_trips() {
        // 100 kB byte value — well within i32 range, exercises the large
        // allocation path.
        let payload = vec![0x77u8; 100_000];
        let d = dict_from(&[("big", Value::Bytes(payload.clone()))], 1, 0);
        let bytes = d.write().unwrap();
        let back = VarDictionary::parse_consuming(&bytes).unwrap();
        assert_eq!(back.entries.get("big"), Some(&Value::Bytes(payload)));
    }

    #[test]
    fn realistic_argon2_blob_round_trips_byte_exact() {
        let mut buf = Vec::new();
        push_version(&mut buf, 1, 0);
        // Sorted keys: $UUID, I, M, P, S, V (ASCII-sort order).
        push_entry(&mut buf, TYPE_BYTES, "$UUID", &[0xEFu8; 16]);
        push_entry(&mut buf, TYPE_U64, "I", &2u64.to_le_bytes());
        push_entry(&mut buf, TYPE_U64, "M", &(65_536u64).to_le_bytes());
        push_entry(&mut buf, TYPE_U32, "P", &1u32.to_le_bytes());
        push_entry(&mut buf, TYPE_BYTES, "S", &[0xAB; 32]);
        push_entry(&mut buf, TYPE_U32, "V", &19u32.to_le_bytes());
        buf.push(TYPE_END);
        let d = VarDictionary::parse_consuming(&buf).unwrap();
        assert_eq!(d.write().unwrap(), buf);
    }
}
