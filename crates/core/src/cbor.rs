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

    // -----------------------------------------------------------------
    // Wire-format golden vector.
    //
    // The manifest chain (`crate::formats::manifest::compute_manifest_hash`)
    // and the signing payload (`canonical_signing_payload`) re-encode
    // structs to CBOR and operate on the resulting bytes. If a future
    // `ciborium` upgrade changes its struct-as-map encoding by even a
    // single byte (e.g. flipped to indefinite-length maps, alternate
    // text-string encoding, key reordering), pre-existing manifest chains
    // would fail signature verification on upgrade — silently, with no
    // compile-time signal.
    //
    // This test locks the wire format to today's encoding using a
    // struct that mirrors the production manifest shape: a `serde_bytes`-
    // tagged fixed-size byte field (the BLAKE3 anchor), an integer field
    // (the chain sequence), and a UTF-8 string field (the device id).
    // The expected bytes were captured from `ciborium 0.2.2` and pinned
    // here so any future ciborium release that breaks byte-equivalence
    // fails this test instead of silently breaking the manifest chain
    // for every user on upgrade.
    //
    // If this test ever fails after a `ciborium` bump:
    //
    //   * VERIFY that the encoding change is intentional and harmless
    //     (e.g. the bump fixes a real bug in encoding, not just a
    //     stylistic reorder of fields).
    //   * If so, regenerate `EXPECTED` with `to_vec(&ManifestShape::sample())`
    //     and ship a one-time chain rewrite migration alongside the
    //     ciborium upgrade — do NOT just update the constant blindly.
    //   * If the change is unintentional / a regression, pin to the last
    //     known-good ciborium version and file a ciborium issue.
    // -----------------------------------------------------------------

    /// Shape that mirrors the production manifest fields exercised by
    /// `crate::formats::manifest`: a fixed-size byte array (CBOR byte
    /// string via `serde_bytes`), a u64 sequence counter, and a UTF-8
    /// device-id string.
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ManifestShape {
        #[serde(with = "serde_bytes")]
        anchor_hash: [u8; 4],
        sequence: u64,
        device_id: String,
    }

    impl ManifestShape {
        fn sample() -> Self {
            Self {
                anchor_hash: *b"BLK3",
                sequence: 0x0102_0304,
                device_id: "device-1".into(),
            }
        }
    }

    #[test]
    fn manifest_shape_encodes_to_golden_bytes() {
        // Golden vector captured from ciborium 0.2.2 on 2026-05-23.
        // See module-level comment above for the regeneration protocol.
        //
        // Decoded:
        //   A3                                  # map(3)
        //     6B 61 6E 63 68 6F 72 5F 68 61 73  # text(11) "anchor_hash"
        //     68
        //     44 42 4C 4B 33                    # bytes(4) b"BLK3"
        //     68 73 65 71 75 65 6E 63 65        # text(8) "sequence"
        //     1A 01 02 03 04                    # unsigned(0x01020304)
        //     69 64 65 76 69 63 65 5F 69 64     # text(9) "device_id"
        //     68 64 65 76 69 63 65 2D 31        # text(8) "device-1"
        const EXPECTED: &[u8] = &[
            0xa3, // map(3)
            0x6b, b'a', b'n', b'c', b'h', b'o', b'r', b'_', b'h', b'a', b's', b'h', //
            0x44, b'B', b'L', b'K', b'3', //
            0x68, b's', b'e', b'q', b'u', b'e', b'n', b'c', b'e', //
            0x1a, 0x01, 0x02, 0x03, 0x04, //
            0x69, b'd', b'e', b'v', b'i', b'c', b'e', b'_', b'i', b'd', //
            0x68, b'd', b'e', b'v', b'i', b'c', b'e', b'-', b'1', //
        ];

        let actual = to_vec(&ManifestShape::sample()).expect("encode");
        assert_eq!(
            actual, EXPECTED,
            "ciborium struct-as-map encoding drifted; manifest chain hashes \
             would silently change on upgrade. Read the module-level comment \
             above this test before regenerating the golden vector."
        );

        // Round-trip — the golden bytes decode back to the same value.
        let decoded: ManifestShape = from_slice(EXPECTED).expect("decode golden");
        assert_eq!(decoded, ManifestShape::sample());
    }

    // -----------------------------------------------------------------
    // Extended wire-format golden vector — covers the remaining serde
    // shape axes that production manifest / archive frames depend on
    // and which the simpler `ManifestShape` test above does not
    // exercise. This is the recommendation from the Devin Review pass
    // on PR #50 turned into defence-in-depth, while keeping the test
    // struct *synthetic* (not the real `BackupManifest`) so the test
    // does not break every time the manifest schema gains or renames
    // a field. The encoder axes — not the production schema — are
    // what we want to pin.
    //
    // Axes covered here that `ManifestShape` does not:
    //
    //   1. `Uuid` — `uuid::serde` ships as a 16-byte CBOR byte string
    //      (major type 2, len 16). A future uuid release that flipped
    //      to a 36-byte text string would silently break every chain.
    //   2. `Vec<NestedStruct>` — exercises array-of-map encoding,
    //      which the manifest's `segments` / `shards` / `media_refs`
    //      vectors rely on for verbatim hash equivalence.
    //   3. `Option<T>` — both `Some` (encoded as the inner value
    //      verbatim) and `None` (encoded as CBOR `null` = 0xF6).
    //   4. `enum` unit variant — `ChildKind::Events` ↔ text string
    //      "Events" (major type 3). Production: `SegmentType`,
    //      `IndexType`.
    //   5. `#[serde(default, with = "serde_bytes")]` empty `Vec<u8>` —
    //      encoded as a zero-length byte string (`0x40`), not omitted
    //      from the map. Matters for `pqc_signature` round-trip.
    //   6. `u32` and `u64` width-specific integer encoding (short
    //      unsigned vs 4-byte unsigned with 0x1A prefix).
    //
    // The accompanying production-shape integration tests in
    // `crates/core/src/formats/manifest.rs` keep verifying that
    // *decoded* manifests round-trip — together they form the full
    // cross-library wire-format invariant.
    // -----------------------------------------------------------------

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    enum ChildKind {
        Events,
        MessageDelta,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ChildRef {
        id: uuid::Uuid,
        kind: ChildKind,
        #[serde(with = "serde_bytes")]
        hash: [u8; 4],
        size: u64,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct ExtendedShape {
        magic: String,
        version: u32,
        manifest_id: uuid::Uuid,
        generation: u64,
        #[serde(with = "serde_bytes")]
        previous_manifest_hash: [u8; 4],
        children: Vec<ChildRef>,
        note: Option<String>,
        note_absent: Option<String>,
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
        #[serde(default, with = "serde_bytes")]
        pqc_signature: Vec<u8>,
    }

    impl ExtendedShape {
        fn sample() -> Self {
            Self {
                magic: "BMAN".into(),
                version: 1,
                // Deterministic UUIDs so the golden vector stays
                // stable. Production code uses `Uuid::now_v7()` —
                // which is also a 16-byte value — but a fixed
                // value here is necessary for byte-equality.
                manifest_id: uuid::Uuid::parse_str("01010101-0101-7101-8101-010101010101")
                    .expect("static uuid"),
                generation: 0x0102_0304,
                previous_manifest_hash: [0xAA, 0xBB, 0xCC, 0xDD],
                children: vec![ChildRef {
                    id: uuid::Uuid::parse_str("02020202-0202-7202-8202-020202020202")
                        .expect("static uuid"),
                    kind: ChildKind::Events,
                    hash: [0x11, 0x22, 0x33, 0x44],
                    size: 4096,
                }],
                note: Some("hi".into()),
                note_absent: None,
                signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
                pqc_signature: vec![],
            }
        }
    }

    #[test]
    fn extended_shape_encodes_to_golden_bytes() {
        // Captured from ciborium 0.2.2 + uuid 1.x on 2026-05-23.
        // Regeneration protocol: see the module-level wire-format
        // comment above `manifest_shape_encodes_to_golden_bytes`.
        // The annotated CBOR decode (one field per logical line):
        //
        //   AA                                          # map(10)
        //   65 magic                                    # text "magic"
        //   64 BMAN                                     # text "BMAN"
        //   67 version                                  # text "version"
        //   01                                          # unsigned 1
        //   6B manifest_id                              # text "manifest_id"
        //   50 01..01                                   # bytes(16) UUID
        //   6A generation                               # text "generation"
        //   1A 01 02 03 04                              # unsigned 0x01020304
        //   76 previous_manifest_hash                   # text(22)
        //   44 AA BB CC DD                              # bytes(4)
        //   68 children                                 # text "children"
        //   81                                          # array(1)
        //     A4                                        # map(4)
        //     62 id    50 02..02                        # uuid bytes(16)
        //     64 kind  66 Events                        # text(6) "Events"
        //     64 hash  44 11 22 33 44                   # bytes(4)
        //     64 size  19 10 00                         # unsigned 4096
        //   64 note   62 hi                             # text(2) "hi"
        //   6B note_absent  F6                          # null
        //   69 signature   44 DE AD BE EF               # bytes(4)
        //   6D pqc_signature  40                        # bytes(0)
        const EXPECTED: &[u8] = &[
            0xaa, 0x65, 0x6d, 0x61, 0x67, 0x69, 0x63, 0x64, 0x42, 0x4d, 0x41, 0x4e, 0x67, 0x76,
            0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x01, 0x6b, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65,
            0x73, 0x74, 0x5f, 0x69, 0x64, 0x50, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x71, 0x01,
            0x81, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x6a, 0x67, 0x65, 0x6e, 0x65, 0x72,
            0x61, 0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x01, 0x02, 0x03, 0x04, 0x76, 0x70, 0x72, 0x65,
            0x76, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x6d, 0x61, 0x6e, 0x69, 0x66, 0x65, 0x73, 0x74,
            0x5f, 0x68, 0x61, 0x73, 0x68, 0x44, 0xaa, 0xbb, 0xcc, 0xdd, 0x68, 0x63, 0x68, 0x69,
            0x6c, 0x64, 0x72, 0x65, 0x6e, 0x81, 0xa4, 0x62, 0x69, 0x64, 0x50, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x72, 0x02, 0x82, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x64,
            0x6b, 0x69, 0x6e, 0x64, 0x66, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x73, 0x64, 0x68, 0x61,
            0x73, 0x68, 0x44, 0x11, 0x22, 0x33, 0x44, 0x64, 0x73, 0x69, 0x7a, 0x65, 0x19, 0x10,
            0x00, 0x64, 0x6e, 0x6f, 0x74, 0x65, 0x62, 0x68, 0x69, 0x6b, 0x6e, 0x6f, 0x74, 0x65,
            0x5f, 0x61, 0x62, 0x73, 0x65, 0x6e, 0x74, 0xf6, 0x69, 0x73, 0x69, 0x67, 0x6e, 0x61,
            0x74, 0x75, 0x72, 0x65, 0x44, 0xde, 0xad, 0xbe, 0xef, 0x6d, 0x70, 0x71, 0x63, 0x5f,
            0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x40,
        ];

        let actual = to_vec(&ExtendedShape::sample()).expect("encode");
        assert_eq!(
            actual, EXPECTED,
            "ciborium encoding drifted for one of: Uuid (uuid 1.x serde \
             feature ⇒ 16-byte CBOR byte string), Vec<NestedStruct> \
             (array-of-map), Option<T> (Some inline / None ⇒ 0xF6), enum \
             unit variant (text string), or `#[serde(default, with = \
             \"serde_bytes\")]` empty Vec<u8> (zero-length byte string). \
             See module-level wire-format comment before regenerating."
        );

        // Round-trip the golden vector back through `from_slice` so a
        // future ciborium that *encodes* identically but *decodes*
        // differently (e.g. a bug in field discovery on `default`
        // fields) is caught here too.
        let decoded: ExtendedShape = from_slice(EXPECTED).expect("decode golden");
        assert_eq!(decoded, ExtendedShape::sample());
    }
}
