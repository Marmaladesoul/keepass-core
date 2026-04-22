//! Type-length-value (TLV) framing for the KDBX outer header — reader and writer.
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

use thiserror::Error;
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
// Writer
// ---------------------------------------------------------------------------

/// Error type for [`write_header_fields`].
///
/// The only failure mode is a record whose value is too long for the
/// configured [`LengthWidth`]. All other writes succeed.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum TlvWriteError {
    /// A record's value length did not fit the chosen length-prefix width.
    ///
    /// Emitted when the caller passes, for example, a 70 000-byte value
    /// alongside [`LengthWidth::U16`] (KDBX3), whose prefix tops out at
    /// `u16::MAX` = 65 535.
    #[error(
        "TLV record for tag {tag} has length {len} which exceeds maximum {max} for this version"
    )]
    LengthOverflow {
        /// The tag of the offending record.
        tag: u8,
        /// The actual value length in bytes.
        len: usize,
        /// The maximum length the chosen [`LengthWidth`] can encode.
        max: u64,
    },
}

/// Append a single TLV record to `out`.
///
/// The inverse of [`parse_field`]: emits tag, then the length as
/// little-endian bytes of the requested width, then the raw value.
#[inline]
fn write_field(
    out: &mut Vec<u8>,
    field: &TlvField<'_>,
    width: LengthWidth,
) -> Result<(), TlvWriteError> {
    match width {
        LengthWidth::U16 => {
            let len =
                u16::try_from(field.value.len()).map_err(|_| TlvWriteError::LengthOverflow {
                    tag: field.tag,
                    len: field.value.len(),
                    max: u64::from(u16::MAX),
                })?;
            out.push(field.tag);
            out.extend_from_slice(&len.to_le_bytes());
        }
        LengthWidth::U32 => {
            let len =
                u32::try_from(field.value.len()).map_err(|_| TlvWriteError::LengthOverflow {
                    tag: field.tag,
                    len: field.value.len(),
                    max: u64::from(u32::MAX),
                })?;
            out.push(field.tag);
            out.extend_from_slice(&len.to_le_bytes());
        }
    }
    out.extend_from_slice(field.value);
    Ok(())
}

/// Serialise a sequence of TLV records followed by an end-of-header sentinel.
///
/// The exact inverse of [`read_header_fields`]: feeding this function's
/// output back into the reader with the same [`LengthWidth`] yields the
/// original `fields` slice and an `end` record with identical tag and
/// value bytes.
///
/// Records are emitted in the order they appear in `fields` with no
/// reordering, deduplication, or other policy — this layer deals only
/// with framing; semantic validation lives in [`super::header::OuterHeader`].
///
/// The `end` record's value bytes are preserved verbatim. Real KeePass
/// writers conventionally emit tag `0` with value `\r\n\r\n`, but this
/// function lets callers round-trip whatever sentinel payload the reader
/// surfaced.
///
/// # Errors
///
/// Returns [`TlvWriteError::LengthOverflow`] if any record's value exceeds
/// the width's addressable range — 65 535 bytes for [`LengthWidth::U16`]
/// and `u32::MAX` for [`LengthWidth::U32`] on 64-bit targets. On 32-bit
/// targets a `U32` overflow is unreachable by construction, since
/// `usize::MAX == u32::MAX` and a `Vec<u8>` can never be longer.
pub fn write_header_fields(
    fields: &[TlvField<'_>],
    end: TlvField<'_>,
    width: LengthWidth,
) -> Result<Vec<u8>, TlvWriteError> {
    // Pre-size: 3 or 5 bytes header per record + sum of value lengths.
    let per_record_overhead = match width {
        LengthWidth::U16 => 3,
        LengthWidth::U32 => 5,
    };
    let total_values: usize = fields
        .iter()
        .map(|f| f.value.len())
        .chain(std::iter::once(end.value.len()))
        .sum();
    let mut out = Vec::with_capacity(per_record_overhead * (fields.len() + 1) + total_values);
    for field in fields {
        write_field(&mut out, field, width)?;
    }
    write_field(&mut out, &end, width)?;
    Ok(out)
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

    // -----------------------------------------------------------------------
    // Writer tests
    // -----------------------------------------------------------------------

    #[test]
    fn writes_v3_matches_pack_v3() {
        let records: &[(u8, &[u8])] = &[(2, b"hi"), (4, &[0x42; 32])];
        let end_val = b"\r\n\r\n";
        let expected = {
            let mut v = pack_v3(records);
            v.extend_from_slice(&pack_v3(&[(0, end_val)]));
            v
        };
        let fields: Vec<TlvField<'_>> = records
            .iter()
            .map(|&(tag, value)| TlvField { tag, value })
            .collect();
        let end = TlvField {
            tag: 0,
            value: end_val,
        };
        let out = write_header_fields(&fields, end, LengthWidth::U16).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn writes_v4_matches_pack_v4() {
        let records: &[(u8, &[u8])] = &[(2, b"uuid"), (4, &[0x42; 32]), (11, b"kdf params")];
        let end_val = b"END!";
        let expected = {
            let mut v = pack_v4(records);
            v.extend_from_slice(&pack_v4(&[(0, end_val)]));
            v
        };
        let fields: Vec<TlvField<'_>> = records
            .iter()
            .map(|&(tag, value)| TlvField { tag, value })
            .collect();
        let end = TlvField {
            tag: 0,
            value: end_val,
        };
        let out = write_header_fields(&fields, end, LengthWidth::U32).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn round_trip_v3() {
        let fields_in = vec![
            TlvField {
                tag: 2,
                value: b"hello",
            },
            TlvField {
                tag: 4,
                value: &[0xAA; 32],
            },
            TlvField {
                tag: 7,
                value: &[0x01; 16],
            },
        ];
        let end_in = TlvField {
            tag: 0,
            value: b"\r\n\r\n",
        };
        let bytes = write_header_fields(&fields_in, end_in, LengthWidth::U16).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields_out, end_out) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert!(cursor.is_empty());
        assert_eq!(fields_out.len(), fields_in.len());
        for (a, b) in fields_out.iter().zip(fields_in.iter()) {
            assert_eq!(a.tag, b.tag);
            assert_eq!(a.value, b.value);
        }
        assert_eq!(end_out.tag, 0);
        assert_eq!(end_out.value, b"\r\n\r\n");
    }

    #[test]
    fn round_trip_v4() {
        let fields_in = vec![
            TlvField {
                tag: 2,
                value: b"uuid-bytes-here!",
            },
            TlvField {
                tag: 11,
                value: b"variant dict payload",
            },
            TlvField {
                tag: 12,
                value: b"",
            },
        ];
        let end_in = TlvField {
            tag: 0,
            value: b"\r\n\r\n",
        };
        let bytes = write_header_fields(&fields_in, end_in, LengthWidth::U32).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields_out, end_out) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert!(cursor.is_empty());
        for (a, b) in fields_out.iter().zip(fields_in.iter()) {
            assert_eq!(a.tag, b.tag);
            assert_eq!(a.value, b.value);
        }
        assert_eq!(end_out.value, b"\r\n\r\n");
    }

    #[test]
    fn round_trip_v4_large_payload() {
        let payload = vec![0xCDu8; 100_000];
        let fields_in = vec![TlvField {
            tag: 5,
            value: &payload,
        }];
        let end_in = TlvField { tag: 0, value: b"" };
        let bytes = write_header_fields(&fields_in, end_in, LengthWidth::U32).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields_out, _end) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert_eq!(fields_out.len(), 1);
        assert_eq!(fields_out[0].tag, 5);
        assert_eq!(fields_out[0].value.len(), 100_000);
        assert_eq!(fields_out[0].value, payload.as_slice());
    }

    #[test]
    fn zero_length_value_round_trips() {
        let fields_in = vec![TlvField { tag: 7, value: b"" }];
        let end_in = TlvField { tag: 0, value: b"" };
        let bytes = write_header_fields(&fields_in, end_in, LengthWidth::U16).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields_out, end_out) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert_eq!(fields_out.len(), 1);
        assert_eq!(fields_out[0].tag, 7);
        assert_eq!(fields_out[0].value, b"");
        assert_eq!(end_out.value, b"");
    }

    #[test]
    fn end_sentinel_preserves_arbitrary_value() {
        // Non-canonical sentinel payload — the reader surfaces it, so the
        // writer must round-trip it byte-for-byte.
        let end_in = TlvField {
            tag: 0,
            value: b"END!",
        };
        let bytes = write_header_fields(&[], end_in, LengthWidth::U32).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields, end_out) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert!(fields.is_empty());
        assert_eq!(end_out.tag, 0);
        assert_eq!(end_out.value, b"END!");
    }

    #[test]
    fn rejects_overflow_for_u16_width() {
        let big = vec![0u8; 70_000];
        let fields = vec![TlvField {
            tag: 5,
            value: &big,
        }];
        let end = TlvField { tag: 0, value: b"" };
        let err = write_header_fields(&fields, end, LengthWidth::U16).unwrap_err();
        assert_eq!(
            err,
            TlvWriteError::LengthOverflow {
                tag: 5,
                len: 70_000,
                max: u64::from(u16::MAX),
            }
        );
    }

    #[test]
    fn empty_field_list_writes_just_end_sentinel() {
        let end_in = TlvField {
            tag: 0,
            value: b"\r\n\r\n",
        };
        let bytes = write_header_fields(&[], end_in, LengthWidth::U16).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields, end_out) = read_header_fields(&mut cursor, LengthWidth::U16).unwrap();
        assert!(fields.is_empty());
        assert_eq!(end_out.tag, 0);
        assert_eq!(end_out.value, b"\r\n\r\n");
        assert!(cursor.is_empty());
    }

    #[test]
    fn duplicate_tags_round_trip() {
        // Framing layer has no policy: duplicates pass through untouched
        // and in order. The typed-header layer is what rejects them.
        let fields_in = vec![
            TlvField {
                tag: 2,
                value: b"first",
            },
            TlvField {
                tag: 2,
                value: b"second",
            },
        ];
        let end_in = TlvField { tag: 0, value: b"" };
        let bytes = write_header_fields(&fields_in, end_in, LengthWidth::U32).unwrap();
        let mut cursor: &[u8] = &bytes;
        let (fields_out, _end) = read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert_eq!(fields_out.len(), 2);
        assert_eq!(fields_out[0].tag, 2);
        assert_eq!(fields_out[0].value, b"first");
        assert_eq!(fields_out[1].tag, 2);
        assert_eq!(fields_out[1].value, b"second");
    }
}
