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
/// Matches the shape of the old `serde_cbor::from_slice`.
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    ciborium::from_reader(bytes)
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
}
