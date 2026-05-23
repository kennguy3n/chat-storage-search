//! Thin facade over [`ciborium`] for CBOR encode / decode.
//!
//! The crate previously used `serde_cbor 0.11`, which has been
//! unmaintained since 2021 (`RUSTSEC-2021-0127`). `ciborium` is the
//! actively-maintained successor maintained by the RustCrypto org.
//!
//! Concentrating the dependency here keeps:
//!
//! * the choice of CBOR backend in one place — every call site goes
//!   through [`to_vec`] / [`from_slice`] / [`Value`] rather than
//!   referring to `ciborium::*` directly, so the next swap (if any)
//!   touches one file;
//! * the encode / decode error types out of every call site — both
//!   helpers return concrete aliases (`EncodeError` / `DecodeError`)
//!   that paper over `ciborium::ser::Error<io::Error>` /
//!   `ciborium::de::Error<io::Error>`.
//!
//! ## Wire-format compatibility
//!
//! Both `serde_cbor` and `ciborium` implement the canonical CBOR data
//! model from RFC 8949. For the structs in [`crate::formats`] (which
//! use `#[serde(with = "serde_bytes")]` on every byte array so they
//! land as CBOR byte strings, not arrays of integers) the encodings
//! are bit-identical. The `serde_cbor::to_vec` ↔ `ciborium::from_reader`
//! and `ciborium::into_writer` ↔ `serde_cbor::from_slice` round-trips
//! are exercised by every existing roundtrip test in `formats::*`,
//! and by the e2e demo (`crates/core/tests/e2e_demo.rs`).
//!
//! ## Trailing-byte semantics
//!
//! [`from_slice`] is **strict**: it returns an error if the input
//! contains bytes after the first complete CBOR value. This matches
//! the contract of the legacy `serde_cbor::from_slice`, where every
//! call site implicitly relied on "the entire buffer is one CBOR
//! value" — e.g. manifest decoding, on-disk EP-benchmark cache,
//! archive segment frame parsing. The naked `ciborium::from_reader`
//! consumes one value and silently ignores trailing data, which would
//! mask buffer-truncation or framing bugs in those call sites. The
//! strict wrapper preserves the historical guarantee.

pub use ciborium::value::Integer;
pub use ciborium::value::Value;

/// Result of [`to_vec`]. Concretely `ciborium::ser::Error<io::Error>`,
/// but the alias keeps call-site signatures terse.
pub type EncodeError = ciborium::ser::Error<std::io::Error>;

/// Result of [`from_slice`]. Concretely `ciborium::de::Error<io::Error>`.
pub type DecodeError = ciborium::de::Error<std::io::Error>;

/// Encode `value` to a freshly-allocated CBOR byte vector.
///
/// Matches the shape of the old `serde_cbor::to_vec` so call sites
/// stayed unchanged when this module was introduced (only the
/// `serde_cbor::` prefix moves to `crate::cbor::`).
pub fn to_vec<T: serde::Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Decode a value of type `T` from a CBOR byte slice.
///
/// Matches the shape **and the strict trailing-byte semantics** of
/// the legacy `serde_cbor::from_slice`: the entire input must be
/// consumed by exactly one CBOR value. Trailing bytes return
/// [`ciborium::de::Error::Semantic`] with the byte offset of the
/// first unread byte and a human-readable message.
///
/// Callers that need lenient "decode one value, ignore the rest"
/// behaviour (e.g. parsers reading a stream of independent frames)
/// can use [`ciborium::from_reader`] directly with a `Cursor` they
/// own, advancing the cursor between calls.
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut cursor = std::io::Cursor::new(bytes);
    let value: T = ciborium::from_reader(&mut cursor)?;
    let consumed = cursor.position() as usize;
    if consumed < bytes.len() {
        return Err(ciborium::de::Error::Semantic(
            Some(consumed),
            format!(
                "trailing bytes after CBOR value: {} byte(s) unread at offset {}",
                bytes.len() - consumed,
                consumed,
            ),
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Sample {
        magic: [u8; 4],
        n: u32,
        msg: String,
    }

    #[test]
    fn roundtrip_struct() {
        let s = Sample {
            magic: *b"CBOR",
            n: 42,
            msg: "hello".into(),
        };
        let bytes = to_vec(&s).expect("encode");
        let back: Sample = from_slice(&bytes).expect("decode");
        assert_eq!(s, back);
    }

    #[test]
    fn value_roundtrip_array() {
        let value = Value::Array(vec![
            Value::Text("a".into()),
            Value::Integer(Integer::from(7_i64)),
        ]);
        let bytes = to_vec(&value).expect("encode");
        let back: Value = from_slice(&bytes).expect("decode");
        assert_eq!(value, back);
    }

    #[test]
    fn from_slice_rejects_trailing_bytes() {
        // Encode one valid CBOR value, then append junk. The strict
        // wrapper must surface a `Semantic` error pointing at the
        // first trailing byte rather than silently returning the
        // first value (the default `ciborium::from_reader`
        // behaviour).
        let mut bytes = to_vec(&42u32).expect("encode");
        let valid_len = bytes.len();
        bytes.extend_from_slice(&[0xff, 0xff, 0xff]);

        let err = from_slice::<u32>(&bytes).expect_err("strict decode must reject trailing bytes");
        match err {
            ciborium::de::Error::Semantic(Some(offset), msg) => {
                assert_eq!(
                    offset, valid_len,
                    "offset should point at first trailing byte"
                );
                assert!(
                    msg.contains("trailing bytes"),
                    "error message should mention trailing bytes, got: {msg}"
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn from_slice_accepts_exact_input() {
        // The complementary check — a buffer with exactly one CBOR
        // value and no trailing bytes still decodes successfully.
        let bytes = to_vec(&"hello").expect("encode");
        let decoded: String = from_slice(&bytes).expect("decode");
        assert_eq!(decoded, "hello");
    }
}
