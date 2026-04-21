//! Type-length-value (TLV) reader for the KDBX outer header.
//!
//! Immediately after the 12-byte [`crate::format::FileSignature`], every KDBX
//! file carries a sequence of TLV records that describe the cipher, KDF,
//! seeds, and other framing metadata needed to decrypt the rest of the file.
//!
//! The length prefix of each record differs between format versions:
//!
//! | Version | Tag | Length          | Value |
//! |---------|-----|-----------------|-------|
//! | KDBX3   | `u8`| `u16` little-endian | `length` bytes |
//! | KDBX4   | `u8`| `u32` little-endian | `length` bytes |
//!
//! The sequence is terminated by a record with tag `0` (by convention called
//! the *end-of-header* sentinel). Its value — typically 4 bytes of `0x0D,
//! 0x0A, 0x0D, 0x0A`, the bytes `\r\n\r\n` — is not part of the semantic
//! header; we read it so the cursor advances past it but callers usually
//! ignore its contents.
//!
//! This module deliberately does **not** interpret individual tag values
//! (cipher UUID, master seed, KDF parameters, etc.). It returns the raw
//! records as borrowed slices of the input buffer; a higher layer will
//! decode the field-specific payloads. Keeping those concerns separate makes
//! the TLV loop itself trivial to test in isolation — and trivial to fuzz.

use winnow::Parser;
use winnow::binary::{le_u8, le_u16, le_u32};
use winnow::error::{ContextError, ErrMode};
use winnow::token::take;

use crate::format::FormatError;

/// One type-length-value record as it appears in the outer header.
///
/// The `value` slice borrows from the input buffer — no allocation happens
/// while parsing. Callers that need owned data can `.to_vec()` after the
/// fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlvField<'a> {
    /// The tag byte identifying which header field this record represents.
    /// Known tag values are specified by the KDBX format; see
    /// [`crate::format::v3`] and [`crate::format::v4`] for per-version tables.
    pub tag: u8,
    /// The raw value bytes, borrowed from the caller's input.
    pub value: &'a [u8],
}

impl TlvField<'_> {
    /// The tag value that marks the end of the header sequence.
    pub const END_OF_HEADER: u8 = 0;

    /// `true` if this record is the end-of-header sentinel.
    #[must_use]
    pub const fn is_end(&self) -> bool {
        self.tag == Self::END_OF_HEADER
    }
}

/// Length-prefix width used by a particular KDBX major version.
///
/// Made explicit as an enum (rather than a generic const parameter) because
/// callers typically dispatch on runtime [`crate::format::Version`] anyway,
/// and enums keep the public API free of const-generic ergonomics tax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LengthWidth {
    /// `u16` little-endian — used by KDBX3.
    U16,
    /// `u32` little-endian — used by KDBX4 and later.
    U32,
}

impl LengthWidth {
    /// Parse a length prefix of this width from the input, returning the
    /// length as a `usize`.
    #[inline]
    fn parse_length(self, input: &mut &[u8]) -> winnow::ModalResult<usize> {
        match self {
            Self::U16 => le_u16.parse_next(input).map(|n| n as usize),
            Self::U32 => le_u32
                .parse_next(input)
                .and_then(|n| usize::try_from(n).map_err(|_| ErrMode::Cut(ContextError::new()))),
        }
    }
}

/// Parse a single TLV record.
///
/// The `input` cursor advances past the record on success. On a short read,
/// returns an error containing no information beyond "incomplete"; the
/// caller should wrap winnow errors into a [`FormatError::Truncated`] with
/// the expected/actual byte counts.
#[inline]
fn parse_field<'a>(input: &mut &'a [u8], width: LengthWidth) -> winnow::ModalResult<TlvField<'a>> {
    let tag = le_u8.parse_next(input)?;
    let len = width.parse_length(input)?;
    let value = take(len).parse_next(input)?;
    Ok(TlvField { tag, value })
}

/// Read every TLV record from `input` up to and including the end-of-header
/// sentinel, returning the non-sentinel records and the trailing end-of-header
/// record as separate values.
///
/// The length prefix width is selected by `width`. After a successful call,
/// `input` points at the first byte past the end-of-header record — typically
/// the start of the encrypted payload (KDBX3) or the start of the header
/// HMAC + payload (KDBX4).
///
/// # Errors
///
/// Returns [`FormatError::Truncated`] if the input ends before a complete
/// record can be read, or before any end-of-header sentinel is encountered.
/// Returns [`FormatError::MalformedHeader`] if the tag/length parse yields
/// an otherwise-invalid record (e.g. a KDBX4 length that overflows
/// `usize` on a 32-bit target).
pub fn read_header_fields<'a>(
    input: &mut &'a [u8],
    width: LengthWidth,
) -> Result<(Vec<TlvField<'a>>, TlvField<'a>), FormatError> {
    let mut fields = Vec::new();
    loop {
        let before_len = input.len();
        let field = parse_field(input, width).map_err(|_| FormatError::Truncated {
            // Best-effort numbers: we know the header length prefix exists
            // (1 + {2,4} bytes) but can't know the full record size if the
            // length field itself was short.
            needed: before_len + 1,
            got: before_len,
        })?;
        if field.is_end() {
            return Ok((fields, field));
        }
        fields.push(field);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a KDBX3-style (u16 length) TLV stream from a list of (tag, value).
    fn pack_v3(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(tag, val) in records {
            out.push(tag);
            out.extend_from_slice(&(u16::try_from(val.len()).unwrap()).to_le_bytes());
            out.extend_from_slice(val);
        }
        out
    }

    /// Build a KDBX4-style (u32 length) TLV stream.
    fn pack_v4(records: &[(u8, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(tag, val) in records {
            out.push(tag);
            out.extend_from_slice(&(u32::try_from(val.len()).unwrap()).to_le_bytes());
            out.extend_from_slice(val);
        }
        out
    }

    #[test]
    fn parses_v3_single_record_plus_end() {
        // Tag 2, value "hi", then end-of-header with 4-byte value
        let buf = pack_v3(&[(2, b"hi"), (0, b"\r\n\r\n")]);
        let mut cursor: &[u8] = &buf;
        let (fields, end) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].tag, 2);
        assert_eq!(fields[0].value, b"hi");
        assert!(end.is_end());
        assert_eq!(end.value, b"\r\n\r\n");
        assert!(cursor.is_empty(), "cursor should be fully consumed");
    }

    #[test]
    fn parses_v4_multiple_records_plus_end() {
        let buf = pack_v4(&[
            (2, b"uuid"),
            (4, &[0x42; 32]),
            (11, b"kdf params"),
            (0, b"END!"),
        ]);
        let mut cursor: &[u8] = &buf;
        let (fields, end) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert_eq!(fields.iter().map(|f| f.tag).collect::<Vec<_>>(), [2, 4, 11]);
        assert_eq!(fields[0].value, b"uuid");
        assert_eq!(fields[1].value.len(), 32);
        assert_eq!(fields[2].value, b"kdf params");
        assert_eq!(end.tag, 0);
        assert_eq!(end.value, b"END!");
    }

    #[test]
    fn stops_at_first_end_marker() {
        // Two end markers back-to-back; we should consume only the first.
        let buf = pack_v3(&[(3, b"a"), (0, b"X"), (5, b"should-not-see")]);
        let mut cursor: &[u8] = &buf;
        let (fields, _end) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].tag, 3);
        // Remaining bytes begin with the not-seen record
        assert_eq!(cursor[0], 5);
    }

    #[test]
    fn errors_on_truncated_length_prefix() {
        // Tag byte then one length byte — missing one for u16.
        let buf = [2u8, 0x05];
        let mut cursor: &[u8] = &buf;
        let err = read_header_fields(&mut cursor, LengthWidth::U16).unwrap_err();
        assert!(matches!(err, FormatError::Truncated { .. }));
    }

    #[test]
    fn errors_on_truncated_value() {
        // Tag=2, length=10, but only 3 bytes of value present.
        let buf = [2u8, 0x0A, 0x00, b'a', b'b', b'c'];
        let mut cursor: &[u8] = &buf;
        let err = read_header_fields(&mut cursor, LengthWidth::U16).unwrap_err();
        assert!(matches!(err, FormatError::Truncated { .. }));
    }

    #[test]
    fn errors_on_empty_input() {
        let mut cursor: &[u8] = &[];
        let err = read_header_fields(&mut cursor, LengthWidth::U16).unwrap_err();
        assert!(matches!(err, FormatError::Truncated { .. }));
    }

    #[test]
    fn zero_length_records_are_allowed() {
        // Tag=7 with empty value (length=0), then end.
        let buf = pack_v3(&[(7, b""), (0, b"")]);
        let mut cursor: &[u8] = &buf;
        let (fields, _) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].tag, 7);
        assert_eq!(fields[0].value, b"");
    }

    #[test]
    fn end_marker_with_empty_value_is_allowed() {
        // Minimum legal header: just an end marker with a zero-length value.
        let buf = pack_v3(&[(0, b"")]);
        let mut cursor: &[u8] = &buf;
        let (fields, end) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert!(fields.is_empty());
        assert!(end.is_end());
        assert_eq!(end.value, b"");
    }

    #[test]
    fn v4_handles_large_length() {
        // A single record with a 100 000-byte value — fits in u32 but not u16.
        let payload = vec![0xABu8; 100_000];
        let buf = pack_v4(&[(5, &payload), (0, b"")]);
        let mut cursor: &[u8] = &buf;
        let (fields, _) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].tag, 5);
        assert_eq!(fields[0].value.len(), 100_000);
        assert_eq!(fields[0].value[0], 0xAB);
    }

    #[test]
    fn values_are_borrowed_not_copied() {
        // Confirm the returned slice points into the original buffer.
        let buf = pack_v3(&[(2, b"abc"), (0, b"")]);
        let mut cursor: &[u8] = &buf;
        let (fields, _) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        let v = fields[0].value.as_ptr();
        // The value bytes sit inside `buf` at offset 3 (tag=1 + len=2 bytes).
        let expected = buf.as_ptr().wrapping_add(3);
        assert_eq!(
            v, expected,
            "value slice should borrow from buf, not a copy"
        );
    }
}
