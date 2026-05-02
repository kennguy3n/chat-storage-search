//! BLAKE3 content hashing.
//!
//! BLAKE3 is the canonical content hash for KChat: it feeds Pattern
//! C convergent DEK derivation (`docs/PROPOSAL.md §3.14`,
//! `§8.4`) and the per-blob Merkle root in the KChat-internal AAD
//! construction (`§8.3`). One-shot and streaming variants produce
//! the same digest on equivalent inputs.

use std::io::{self, Read};

/// Length of a BLAKE3 digest in bytes.
pub const HASH_LEN: usize = 32;

/// Compute the BLAKE3 hash of `data` in one shot.
pub fn content_hash(data: &[u8]) -> [u8; HASH_LEN] {
    blake3::hash(data).into()
}

/// Compute the BLAKE3 hash of an `io::Read` source by streaming
/// 64 KiB at a time. Equivalent to [`content_hash`] for the
/// concatenated bytes the reader yields.
pub fn content_hash_streaming<R: Read>(mut reader: R) -> io::Result<[u8; HASH_LEN]> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known BLAKE3 vectors verified against the upstream `b3sum`
    /// reference (`b3sum 1.8.5`). 32-byte default digest length.
    const VECTORS: &[(&[u8], &str)] = &[
        (
            b"",
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        // Single byte 0x00.
        (
            &[0x00],
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            b"abc",
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        ),
        (
            b"IETF",
            "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2",
        ),
    ];

    #[test]
    fn known_vectors_match_blake3_reference() {
        for (input, want_hex) in VECTORS {
            let want = hex::decode(want_hex).unwrap();
            let got = content_hash(input);
            assert_eq!(got.as_slice(), want.as_slice(), "input = {input:?}");
        }
    }

    #[test]
    fn streaming_matches_one_shot_small() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one_shot = content_hash(data);
        let streamed = content_hash_streaming(&data[..]).unwrap();
        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn streaming_matches_one_shot_multi_buffer() {
        // Larger than the 64 KiB streaming buffer to exercise the
        // multi-read path.
        let data = vec![0xAB; 64 * 1024 * 3 + 17];
        let one_shot = content_hash(&data);
        let streamed = content_hash_streaming(&data[..]).unwrap();
        assert_eq!(one_shot, streamed);
    }

    #[test]
    fn distinct_inputs_produce_distinct_hashes() {
        let a = content_hash(b"hello");
        let b = content_hash(b"world");
        assert_ne!(a, b);
    }
}
