//! KDBX4 inner header.
//!
//! KDBX4 splits metadata between an **outer header** (bound by the
//! header HMAC, available pre-decryption) and an **inner header** that
//! sits at the start of the decrypted, decompressed payload — just
//! before the XML. The inner header carries the runtime secrets that
//! should never be visible to passive filesystem observers:
//!
//! | Tag | Name                | Type           |
//! |----:|---------------------|----------------|
//! |  0  | End-of-header       | 0-byte sentinel|
//! |  1  | Inner random stream | `u32` LE       |
//! |  2  | Inner stream key    | bytes (32 typically) |
//! |  3  | Binary attachment   | 1 flags byte + raw bytes |
//!
//! Tag 3 may appear multiple times — each represents one binary
//! attachment in the binary-pool indexed by insertion order.
//!
//! KDBX3 has no inner header; its equivalent fields live in the outer
//! header and its attachments are embedded in the XML itself.
//!
//! The TLV framing is identical to the KDBX4 outer header: 1-byte tag,
//! 4-byte `u32` length, then the value. The caller passes the length
//! width explicitly via [`super::LengthWidth::U32`] for consistency
//! with the outer-header reader — though in practice KDBX4 is the only
//! version that has inner headers at all.

use thiserror::Error;

use super::{
    FormatError, InnerStreamAlgorithm, LengthWidth, TlvField, TlvWriteError, read_header_fields,
    write_header_fields,
};

// ---------------------------------------------------------------------------
// Tag constants
// ---------------------------------------------------------------------------

/// Canonical tag values for inner-header fields.
pub mod tag {
    /// End-of-header sentinel (value bytes are ignored).
    pub const END_OF_HEADER: u8 = 0;
    /// Inner random-stream algorithm identifier (`u32` LE).
    pub const INNER_RANDOM_STREAM_ID: u8 = 1;
    /// Inner-stream cipher key (bytes; 32 for Salsa20/ChaCha20,
    /// 64 for HC-256 — not supported).
    pub const INNER_STREAM_KEY: u8 = 2;
    /// Binary attachment: 1 flags byte followed by raw bytes.
    pub const BINARY_ATTACHMENT: u8 = 3;
}

/// Decode a 32-bit inner-stream algorithm identifier.
///
/// Kept as a module-local helper (rather than on [`InnerStreamAlgorithm`])
/// to avoid dragging this file's error type into the shared definition.
fn algorithm_from_u32(raw: u32) -> Result<InnerStreamAlgorithm, InnerHeaderError> {
    match raw {
        0 => Ok(InnerStreamAlgorithm::None),
        2 => Ok(InnerStreamAlgorithm::Salsa20),
        3 => Ok(InnerStreamAlgorithm::ChaCha20),
        other => Err(InnerHeaderError::UnknownInnerStreamAlgorithm(other)),
    }
}

// ---------------------------------------------------------------------------
// InnerHeader struct
// ---------------------------------------------------------------------------

/// Typed representation of the KDBX4 inner header.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InnerHeader {
    /// Which cipher to apply to protected `<Value>` XML fields.
    pub inner_stream_algorithm: InnerStreamAlgorithm,
    /// The inner-stream cipher key (typically 32 bytes for
    /// Salsa20/ChaCha20). Kept as owned bytes so the caller can
    /// consume or hand off to the cipher without holding a borrow on
    /// the decrypted-payload buffer.
    pub inner_stream_key: Vec<u8>,
    /// Binary attachments, in the order they appeared in the header.
    /// The first element's XML reference is `Ref="0"`, the second
    /// `Ref="1"`, and so on.
    pub binaries: Vec<InnerBinary>,
    /// Number of bytes consumed from the input. The caller uses this
    /// to slice past the inner header and reach the XML payload.
    pub consumed_bytes: usize,
}

/// One binary attachment from the KDBX4 inner header.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InnerBinary {
    /// The single flags byte: bit 0 = "protected" (applies inner-stream
    /// cipher), upper bits reserved.
    pub flags: u8,
    /// The raw attachment bytes — decompressed but still cipher-wrapped
    /// if `flags & 1 != 0`.
    pub data: Vec<u8>,
}

impl InnerBinary {
    /// `true` if the attachment's bytes are protected by the
    /// inner-stream cipher. A flags byte with bit 0 set.
    #[must_use]
    pub fn is_protected(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

impl InnerHeader {
    /// Parse a KDBX4 inner header from the start of `input`.
    ///
    /// On success, returns the typed [`InnerHeader`] with
    /// [`InnerHeader::consumed_bytes`] set to the number of bytes
    /// consumed — the XML payload begins at `input[consumed..]`.
    ///
    /// # Errors
    ///
    /// Returns [`InnerHeaderError`] on any parse failure: truncation,
    /// unknown tag, wrong-length value, duplicate key fields, etc.
    pub fn parse(input: &[u8]) -> Result<Self, InnerHeaderError> {
        let mut cursor = input;
        let start_len = cursor.len();
        let (fields, _end) = read_header_fields(&mut cursor, LengthWidth::U32)?;
        let consumed_bytes = start_len - cursor.len();

        let mut algorithm: Option<InnerStreamAlgorithm> = None;
        let mut key: Option<Vec<u8>> = None;
        let mut binaries: Vec<InnerBinary> = Vec::new();

        for field in &fields {
            match field.tag {
                tag::INNER_RANDOM_STREAM_ID => {
                    reject_duplicate(algorithm.is_some(), field.tag)?;
                    let raw = read_u32_le(field)?;
                    algorithm = Some(algorithm_from_u32(raw)?);
                }
                tag::INNER_STREAM_KEY => {
                    reject_duplicate(key.is_some(), field.tag)?;
                    if field.value.is_empty() {
                        return Err(InnerHeaderError::EmptyInnerStreamKey);
                    }
                    key = Some(field.value.to_vec());
                }
                tag::BINARY_ATTACHMENT => {
                    if field.value.is_empty() {
                        return Err(InnerHeaderError::EmptyBinary);
                    }
                    let flags = field.value[0];
                    let data = field.value[1..].to_vec();
                    binaries.push(InnerBinary { flags, data });
                }
                other => return Err(InnerHeaderError::UnknownTag(other)),
            }
        }

        let inner_stream_algorithm =
            algorithm.ok_or(InnerHeaderError::Missing(tag::INNER_RANDOM_STREAM_ID))?;
        let inner_stream_key = key.ok_or(InnerHeaderError::Missing(tag::INNER_STREAM_KEY))?;

        Ok(Self {
            inner_stream_algorithm,
            inner_stream_key,
            binaries,
            consumed_bytes,
        })
    }

    /// Serialise this inner header back to bytes — the inverse of
    /// [`Self::parse`].
    ///
    /// Emits tags in fixed order: `INNER_RANDOM_STREAM_ID` (1),
    /// `INNER_STREAM_KEY` (2), then each binary attachment as a
    /// `BINARY_ATTACHMENT` (3) in insertion order, and finally an
    /// end-of-header sentinel with an empty value (matching what
    /// KeePassXC and kdbxweb emit; the decoder accepts any value
    /// bytes for the sentinel but empty is canonical for the inner
    /// header).
    ///
    /// The byte output is suitable for placement at the start of the
    /// decompressed, decrypted KDBX4 payload, immediately before the
    /// XML document.
    ///
    /// # Errors
    ///
    /// Returns [`InnerHeaderWriteError::EmptyInnerStreamKey`] if the
    /// inner-stream key is empty — the spec forbids this, and the
    /// decoder already rejects it on read.
    ///
    /// Returns [`InnerHeaderWriteError::Tlv`] wrapping
    /// [`TlvWriteError::LengthOverflow`] if a binary attachment
    /// exceeds `u32::MAX` bytes. Effectively unreachable for any
    /// real attachment.
    pub fn write(&self) -> Result<Vec<u8>, InnerHeaderWriteError> {
        if self.inner_stream_key.is_empty() {
            return Err(InnerHeaderWriteError::EmptyInnerStreamKey);
        }

        let algo_bytes: [u8; 4] = match self.inner_stream_algorithm {
            InnerStreamAlgorithm::None => 0u32,
            InnerStreamAlgorithm::Salsa20 => 2u32,
            InnerStreamAlgorithm::ChaCha20 => 3u32,
        }
        .to_le_bytes();

        // Pre-compose each binary's TLV payload (flags byte + data)
        // into an owned buffer, so the borrowed TlvField slice below
        // has somewhere to point.
        let binary_payloads: Vec<Vec<u8>> = self
            .binaries
            .iter()
            .map(|b| {
                let mut v = Vec::with_capacity(1 + b.data.len());
                v.push(b.flags);
                v.extend_from_slice(&b.data);
                v
            })
            .collect();

        let mut fields: Vec<TlvField<'_>> = Vec::with_capacity(2 + binary_payloads.len());
        fields.push(TlvField {
            tag: tag::INNER_RANDOM_STREAM_ID,
            value: &algo_bytes,
        });
        fields.push(TlvField {
            tag: tag::INNER_STREAM_KEY,
            value: &self.inner_stream_key,
        });
        for payload in &binary_payloads {
            fields.push(TlvField {
                tag: tag::BINARY_ATTACHMENT,
                value: payload,
            });
        }

        let end = TlvField {
            tag: tag::END_OF_HEADER,
            value: &[],
        };
        write_header_fields(&fields, end, LengthWidth::U32).map_err(InnerHeaderWriteError::Tlv)
    }
}

/// Error type for [`InnerHeader::write`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InnerHeaderWriteError {
    /// The inner-stream key is empty. Spec-forbidden; the decoder
    /// rejects this on read too, so an in-memory header that trips
    /// this error was built manually and incompletely.
    #[error("inner-stream key is empty")]
    EmptyInnerStreamKey,

    /// A binary attachment's length exceeded the on-disk `u32` length
    /// prefix. Effectively unreachable.
    #[error(transparent)]
    Tlv(#[from] TlvWriteError),
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Error type for [`InnerHeader::parse`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum InnerHeaderError {
    /// Propagated TLV-level error (truncation, etc.).
    #[error(transparent)]
    Format(#[from] FormatError),

    /// A mandatory tag was not present.
    #[error("missing mandatory inner-header field (tag {0})")]
    Missing(u8),

    /// A tag appeared more than once where the spec requires a single
    /// occurrence.
    #[error("duplicate inner-header field (tag {0})")]
    Duplicate(u8),

    /// A field had the wrong length for its tag.
    #[error("inner-header field (tag {tag}) has wrong length: expected {expected}, got {got}")]
    WrongLength {
        /// The tag whose value was wrongly sized.
        tag: u8,
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// A tag number outside the known set was encountered.
    #[error("unknown inner-header tag {0}")]
    UnknownTag(u8),

    /// The inner random-stream algorithm identifier was unknown.
    #[error("unknown inner random-stream algorithm: {0}")]
    UnknownInnerStreamAlgorithm(u32),

    /// The inner-stream key field was zero-length. Spec-forbidden.
    #[error("inner-stream key is empty")]
    EmptyInnerStreamKey,

    /// A binary attachment field was zero-length (not even a flags byte).
    #[error("binary attachment is empty (no flags byte)")]
    EmptyBinary,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn reject_duplicate(already_set: bool, tag: u8) -> Result<(), InnerHeaderError> {
    if already_set {
        Err(InnerHeaderError::Duplicate(tag))
    } else {
        Ok(())
    }
}

fn read_u32_le(field: &TlvField<'_>) -> Result<u32, InnerHeaderError> {
    let bytes: [u8; 4] = field
        .value
        .try_into()
        .map_err(|_| InnerHeaderError::WrongLength {
            tag: field.tag,
            expected: 4,
            got: field.value.len(),
        })?;
    Ok(u32::from_le_bytes(bytes))
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a single TLV record (tag, u32 LE length, value bytes).
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + value.len());
        out.push(tag);
        out.extend_from_slice(&(u32::try_from(value.len()).unwrap()).to_le_bytes());
        out.extend_from_slice(value);
        out
    }

    /// Encode an end-of-header record (empty value).
    fn end_record() -> Vec<u8> {
        tlv(tag::END_OF_HEADER, &[])
    }

    #[test]
    fn parses_minimal_inner_header() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0x42u8; 64]));
        buf.extend_from_slice(&end_record());
        buf.extend_from_slice(b"EXTRA XML PAYLOAD");

        let header = InnerHeader::parse(&buf).unwrap();
        assert_eq!(
            header.inner_stream_algorithm,
            InnerStreamAlgorithm::ChaCha20
        );
        assert_eq!(header.inner_stream_key.len(), 64);
        assert!(header.binaries.is_empty());
        // Consumed should equal everything up to (and including) the end record.
        assert_eq!(&buf[header.consumed_bytes..], b"EXTRA XML PAYLOAD");
    }

    #[test]
    fn parses_inner_header_with_binaries() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &2u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0x11u8; 32]));
        // Two binaries: first protected (flags bit 0 set), second not.
        let mut bin0 = vec![0x01u8];
        bin0.extend_from_slice(b"protected-bytes");
        buf.extend_from_slice(&tlv(tag::BINARY_ATTACHMENT, &bin0));
        let mut bin1 = vec![0x00u8];
        bin1.extend_from_slice(b"plain-bytes");
        buf.extend_from_slice(&tlv(tag::BINARY_ATTACHMENT, &bin1));
        buf.extend_from_slice(&end_record());

        let header = InnerHeader::parse(&buf).unwrap();
        assert_eq!(header.inner_stream_algorithm, InnerStreamAlgorithm::Salsa20);
        assert_eq!(header.binaries.len(), 2);
        assert!(header.binaries[0].is_protected());
        assert_eq!(header.binaries[0].data, b"protected-bytes");
        assert!(!header.binaries[1].is_protected());
        assert_eq!(header.binaries[1].data, b"plain-bytes");
    }

    #[test]
    fn rejects_missing_inner_stream_algorithm() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            InnerHeaderError::Missing(tag::INNER_RANDOM_STREAM_ID)
        ));
    }

    #[test]
    fn rejects_missing_inner_stream_key() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            InnerHeaderError::Missing(tag::INNER_STREAM_KEY)
        ));
    }

    #[test]
    fn rejects_duplicate_algorithm_field() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &2u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            InnerHeaderError::Duplicate(tag::INNER_RANDOM_STREAM_ID)
        ));
    }

    #[test]
    fn rejects_unknown_tag() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&tlv(0x99, b"garbage"));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, InnerHeaderError::UnknownTag(0x99)));
    }

    #[test]
    fn rejects_unknown_algorithm_value() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &42u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(
            err,
            InnerHeaderError::UnknownInnerStreamAlgorithm(42)
        ));
    }

    #[test]
    fn rejects_empty_inner_stream_key() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[]));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, InnerHeaderError::EmptyInnerStreamKey));
    }

    #[test]
    fn rejects_empty_binary_attachment() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&tlv(tag::BINARY_ATTACHMENT, &[]));
        buf.extend_from_slice(&end_record());
        let err = InnerHeader::parse(&buf).unwrap_err();
        assert!(matches!(err, InnerHeaderError::EmptyBinary));
    }

    #[test]
    fn multiple_binaries_preserve_insertion_order() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        for i in 0u8..5 {
            let mut v = vec![0u8];
            v.push(i);
            v.push(0xAA);
            buf.extend_from_slice(&tlv(tag::BINARY_ATTACHMENT, &v));
        }
        buf.extend_from_slice(&end_record());
        let header = InnerHeader::parse(&buf).unwrap();
        assert_eq!(header.binaries.len(), 5);
        for (i, b) in header.binaries.iter().enumerate() {
            assert_eq!(b.data[0], u8::try_from(i).unwrap());
        }
    }

    #[test]
    fn binary_flags_decoded_correctly() {
        let test_cases = [
            (0x00, false), // unprotected
            (0x01, true),  // protected
            (0x02, false), // unknown upper bit, not the protected bit
            (0x03, true),  // protected + something else
        ];
        for (flags, expected_protected) in test_cases {
            let mut buf = Vec::new();
            buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
            buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
            let mut bin = vec![flags];
            bin.push(0xCD);
            buf.extend_from_slice(&tlv(tag::BINARY_ATTACHMENT, &bin));
            buf.extend_from_slice(&end_record());
            let header = InnerHeader::parse(&buf).unwrap();
            assert_eq!(
                header.binaries[0].is_protected(),
                expected_protected,
                "flags=0x{flags:02x}"
            );
        }
    }

    #[test]
    fn consumed_bytes_matches_content_length() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(tag::INNER_RANDOM_STREAM_ID, &3u32.to_le_bytes()));
        buf.extend_from_slice(&tlv(tag::INNER_STREAM_KEY, &[0u8; 32]));
        buf.extend_from_slice(&end_record());
        let header_len = buf.len();
        buf.extend_from_slice(b"trailing XML goes here");

        let header = InnerHeader::parse(&buf).unwrap();
        assert_eq!(header.consumed_bytes, header_len);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(InnerHeader::parse(&[]).is_err());
    }

    // -----------------------------------------------------------------------
    // Writer tests
    // -----------------------------------------------------------------------

    fn minimal_inner() -> InnerHeader {
        InnerHeader {
            inner_stream_algorithm: InnerStreamAlgorithm::ChaCha20,
            inner_stream_key: vec![0x42u8; 64],
            binaries: Vec::new(),
            consumed_bytes: 0, // unused by write()
        }
    }

    /// Assert that write + parse round-trips every typed field.
    fn assert_roundtrip(h: &InnerHeader) {
        let bytes = h.write().expect("write succeeds");
        let back = InnerHeader::parse(&bytes).expect("re-parse succeeds");
        assert_eq!(back.inner_stream_algorithm, h.inner_stream_algorithm);
        assert_eq!(back.inner_stream_key, h.inner_stream_key);
        assert_eq!(back.binaries.len(), h.binaries.len());
        for (a, b) in back.binaries.iter().zip(h.binaries.iter()) {
            assert_eq!(a.flags, b.flags);
            assert_eq!(a.data, b.data);
        }
        assert_eq!(back.consumed_bytes, bytes.len());
    }

    #[test]
    fn round_trips_minimal_inner_header() {
        assert_roundtrip(&minimal_inner());
    }

    #[test]
    fn round_trips_with_salsa20_algorithm() {
        let mut h = minimal_inner();
        h.inner_stream_algorithm = InnerStreamAlgorithm::Salsa20;
        h.inner_stream_key = vec![0x11u8; 32];
        assert_roundtrip(&h);
    }

    #[test]
    fn round_trips_with_none_algorithm() {
        let mut h = minimal_inner();
        h.inner_stream_algorithm = InnerStreamAlgorithm::None;
        h.inner_stream_key = vec![0x22u8; 32];
        assert_roundtrip(&h);
    }

    #[test]
    fn round_trips_with_binaries() {
        let mut h = minimal_inner();
        h.binaries = vec![
            InnerBinary {
                flags: 0x01,
                data: b"protected attachment".to_vec(),
            },
            InnerBinary {
                flags: 0x00,
                data: b"plain attachment".to_vec(),
            },
            InnerBinary {
                flags: 0x03,
                data: vec![0xCDu8; 4096],
            },
        ];
        assert_roundtrip(&h);
    }

    #[test]
    fn empty_inner_stream_key_errors() {
        let mut h = minimal_inner();
        h.inner_stream_key = Vec::new();
        assert!(matches!(
            h.write().unwrap_err(),
            InnerHeaderWriteError::EmptyInnerStreamKey
        ));
    }

    #[test]
    fn writes_tags_in_canonical_order() {
        let mut h = minimal_inner();
        h.binaries = vec![InnerBinary {
            flags: 0,
            data: b"x".to_vec(),
        }];
        let bytes = h.write().unwrap();
        // tag(1) + len(4) = 5 bytes of header per record; first byte
        // of each record is the tag. Expected order: 1, 2, 3, 0.
        assert_eq!(bytes[0], tag::INNER_RANDOM_STREAM_ID);
        // algorithm value: 4 bytes → next record at offset 5 + 4 = 9
        assert_eq!(bytes[9], tag::INNER_STREAM_KEY);
    }

    #[test]
    fn end_sentinel_has_empty_value() {
        let h = minimal_inner();
        let bytes = h.write().unwrap();
        // Parse and confirm the trailing end record has no value bytes.
        let mut cursor: &[u8] = &bytes;
        let (fields, end) = super::read_header_fields(&mut cursor, LengthWidth::U32).unwrap();
        assert_eq!(fields.len(), 2); // algorithm + key
        assert_eq!(end.tag, tag::END_OF_HEADER);
        assert_eq!(end.value, b"");
    }

    #[test]
    fn empty_binary_data_is_allowed_by_writer() {
        // data=[] gives a 1-byte payload (just the flags byte), which
        // the reader accepts — rejection is for zero-byte value (no
        // flags byte at all).
        let mut h = minimal_inner();
        h.binaries = vec![InnerBinary {
            flags: 0x01,
            data: Vec::new(),
        }];
        assert_roundtrip(&h);
    }

    #[test]
    fn many_binaries_round_trip_in_order() {
        let mut h = minimal_inner();
        h.binaries = (0..32u8)
            .map(|i| InnerBinary {
                flags: i & 0x01,
                data: vec![i; 16],
            })
            .collect();
        assert_roundtrip(&h);
    }
}
