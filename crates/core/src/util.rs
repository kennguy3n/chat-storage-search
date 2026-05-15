//! Tiny cross-module helpers that don't earn a dedicated module.
//!
//! Kept deliberately small: anything that grows past a handful of
//! helpers (or pulls in a new dependency tree) should graduate to
//! its own module under `crate::crypto`, `crate::search`, etc.

/// URL-safe base64 (no padding) encoding of a byte slice.
///
/// Implements RFC 4648 §5 with `=` padding stripped. Matches the
/// wire shape the transport surface expects in the
/// `conversation_hash` parameter and is the canonical encoder for
/// any keyed-hash-bytes-to-URL conversion in the core crate.
///
/// Centralised here so [`crate::core_impl::CoreImpl::upload_search_shards`]
/// (write path) and
/// [`crate::search::cold_shard_source::TransportColdShardSource`]
/// (read path) cannot drift in alphabet or padding strategy — a
/// silent mismatch would manifest as a "shard not found" on every
/// cold lookup.
pub fn base64_urlsafe_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let n = chunk.len();
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if n >= 2 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if n >= 3 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_test_vectors_url_safe_no_padding() {
        // RFC 4648 §10 standard test vectors, transformed to the
        // url-safe alphabet (`+` -> `-`, `/` -> `_`) and stripped
        // of `=` padding. Adapted from the RFC text.
        assert_eq!(base64_urlsafe_encode(b""), "");
        assert_eq!(base64_urlsafe_encode(b"f"), "Zg");
        assert_eq!(base64_urlsafe_encode(b"fo"), "Zm8");
        assert_eq!(base64_urlsafe_encode(b"foo"), "Zm9v");
        assert_eq!(base64_urlsafe_encode(b"foob"), "Zm9vYg");
        assert_eq!(base64_urlsafe_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(base64_urlsafe_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn uses_url_safe_alphabet_for_high_bit_bytes() {
        // 0xFB / 0xFF combinations are the canonical way to flush
        // out `+` / `/` leaking through. Url-safe must emit `-`
        // and `_` instead.
        let encoded = base64_urlsafe_encode(&[0xFB, 0xFF, 0xBF]);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[test]
    fn output_length_matches_div_ceil_formula() {
        // The Vec preallocation in the encoder rounds up to the
        // nearest 4-byte boundary; the actual output is
        // `4 * ceil(n / 3) - pad`, where `pad` is the number of
        // stripped `=` characters.
        for n in 0..32usize {
            let bytes = vec![0xA5u8; n];
            let encoded = base64_urlsafe_encode(&bytes);
            let expected_unpadded = match n % 3 {
                0 => 4 * (n / 3),
                1 => 4 * (n / 3) + 2,
                2 => 4 * (n / 3) + 3,
                _ => unreachable!(),
            };
            assert_eq!(encoded.len(), expected_unpadded, "n = {n}");
        }
    }
}
