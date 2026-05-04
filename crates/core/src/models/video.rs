//! On-device video keyframe-sampling seam — Phase 6, Task 3 of
//! the 2026-05-04 batch.
//!
//! `docs/PROPOSAL.md §7.6` describes the video-search pipeline:
//! decode a video attachment into a small set of representative
//! keyframes, embed each via [`crate::models::clip::ImageEmbedder`]
//! (MobileCLIP-S2), and write the best embedding into
//! `search_vector` so the existing semantic-search engine
//! (`crates/core/src/search/semantic_search.rs`) can rank video
//! attachments alongside text and image messages.
//!
//! The actual decoding runs in the platform layer (AVFoundation
//! on iOS / macOS, MediaCodec on Android, Media Foundation /
//! ffmpeg on Windows / Linux). This module is the object-safe
//! Rust seam the platform glue plugs into.
//!
//! Like every other Phase 6 ML seam (`TextEmbedder`,
//! `ImageEmbedder`, `OcrBridge`, `WhisperTranscriber`,
//! `DocumentExtractor`), the trait is intentionally stateless
//! and synchronous so the same instance can be shared across
//! `send_media` calls without a `&mut self` restriction.

use crate::Result;

/// One sampled keyframe returned by
/// [`VideoKeyframeSampler::extract_keyframes`].
///
/// `timestamp_ms` is the wall-clock-relative position in
/// milliseconds from the start of the video buffer; `image_data`
/// is an encoded image (PNG / JPEG / HEIC) ready to feed into
/// [`crate::models::clip::ImageEmbedder::embed_image`];
/// `mime_type` is the encoded image MIME type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keyframe {
    /// Position of the keyframe in milliseconds, relative to
    /// the start of the source video buffer.
    pub timestamp_ms: u64,
    /// Encoded image bytes (PNG / JPEG / HEIC).
    pub image_data: Vec<u8>,
    /// MIME type of `image_data` (`"image/png"` /
    /// `"image/jpeg"` / `"image/heic"`).
    pub mime_type: String,
}

/// On-device video keyframe-sampling seam used by media ingest
/// (`docs/PROPOSAL.md §7.6`, Phase 6).
///
/// Object-safe + `Send + Sync` so [`crate::core_impl::CoreImpl`]
/// can stash a real platform sampler inside
/// `Mutex<Option<Box<dyn VideoKeyframeSampler>>>` and reuse the
/// same instance across `send_media` calls. Implementations
/// SHOULD reject non-video MIME types with
/// [`crate::Error::Model`] rather than returning a degenerate
/// keyframe vector.
///
/// `max_frames` is an upper bound; implementations MUST return
/// at most `max_frames` keyframes but MAY return fewer (e.g.,
/// for very short videos or videos with limited scene
/// variation).
pub trait VideoKeyframeSampler: std::fmt::Debug + Send + Sync {
    /// Extract up to `max_frames` keyframes from the video
    /// buffer. The returned vector SHOULD be ordered by
    /// `timestamp_ms` ascending so the caller can pick the
    /// "first" / "best" keyframe deterministically.
    fn extract_keyframes(
        &self,
        video_data: &[u8],
        mime_type: &str,
        max_frames: usize,
    ) -> Result<Vec<Keyframe>>;
}

/// Always-`NotImplemented` [`VideoKeyframeSampler`] for builds
/// without a real platform sampler wired in.
///
/// `extract_keyframes` returns
/// [`crate::Error::NotImplemented("video_keyframe_sampler")`](crate::Error::NotImplemented).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopVideoKeyframeSampler;

impl VideoKeyframeSampler for NoopVideoKeyframeSampler {
    fn extract_keyframes(
        &self,
        _video_data: &[u8],
        _mime_type: &str,
        _max_frames: usize,
    ) -> Result<Vec<Keyframe>> {
        Err(crate::Error::NotImplemented("video_keyframe_sampler"))
    }
}

/// Deterministic test [`VideoKeyframeSampler`] that derives a
/// reproducible set of synthetic keyframes from a BLAKE3 hash
/// of `(mime_type, video_data)`.
///
/// Used by the Phase 6 unit / integration tests to stand in for
/// a real AVFoundation / MediaCodec / ffmpeg sampler. The
/// "image" payload of each keyframe is the BLAKE3 hash of
/// `(input_hash, frame_index)` — small, deterministic, and
/// shaped roughly like a PNG header so downstream embedder
/// stubs can pretend to decode it.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockVideoKeyframeSampler;

impl VideoKeyframeSampler for MockVideoKeyframeSampler {
    fn extract_keyframes(
        &self,
        video_data: &[u8],
        mime_type: &str,
        max_frames: usize,
    ) -> Result<Vec<Keyframe>> {
        if !mime_type.starts_with("video/") {
            return Err(crate::Error::Model(format!(
                "MockVideoKeyframeSampler rejects non-video mime_type: {mime_type}"
            )));
        }
        if max_frames == 0 {
            return Ok(Vec::new());
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(mime_type.as_bytes());
        hasher.update(&[0]);
        hasher.update(video_data);
        let input_hash = hasher.finalize();

        // Emit min(max_frames, 5) frames so the mock matches
        // the PROPOSAL §7.6 default fan-out without overshooting
        // when the caller asks for a smaller cap.
        let count = max_frames.min(5);
        let span_ms = (video_data.len() as u64).saturating_mul(10).max(40);
        let step_ms = span_ms / count.max(1) as u64;

        let mut frames = Vec::with_capacity(count);
        for i in 0..count {
            let mut frame_hasher = blake3::Hasher::new();
            frame_hasher.update(input_hash.as_bytes());
            frame_hasher.update(&(i as u64).to_le_bytes());
            let frame_hash = frame_hasher.finalize();
            // Build a synthetic "PNG-ish" payload: 8-byte PNG
            // signature followed by the 32-byte hash twice.
            // Total = 72 bytes — small enough for tests, large
            // enough to differentiate.
            let mut image = Vec::with_capacity(72);
            image.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
            image.extend_from_slice(frame_hash.as_bytes());
            image.extend_from_slice(frame_hash.as_bytes());
            frames.push(Keyframe {
                timestamp_ms: (i as u64) * step_ms,
                image_data: image,
                mime_type: "image/png".to_string(),
            });
        }
        Ok(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_video_sampler_returns_not_implemented() {
        let s = NoopVideoKeyframeSampler;
        let err = s
            .extract_keyframes(b"video-bytes", "video/mp4", 5)
            .unwrap_err();
        assert!(matches!(
            err,
            crate::Error::NotImplemented("video_keyframe_sampler")
        ));
    }

    #[test]
    fn mock_video_sampler_returns_deterministic_keyframes() {
        let s = MockVideoKeyframeSampler;
        let a = s
            .extract_keyframes(b"hello-vid", "video/mp4", 5)
            .expect("a");
        let b = s
            .extract_keyframes(b"hello-vid", "video/mp4", 5)
            .expect("b");
        assert_eq!(a, b, "deterministic keyframes for identical inputs");

        let c = s
            .extract_keyframes(b"different-vid", "video/mp4", 5)
            .expect("c");
        assert_ne!(a, c, "distinct inputs produce distinct keyframes");

        // Frame count is bounded by max_frames and floor by mock.
        assert_eq!(a.len(), 5);
        // Frames are sorted by timestamp ascending.
        for w in a.windows(2) {
            assert!(w[0].timestamp_ms <= w[1].timestamp_ms);
        }
        // PNG signature is preserved at the head of each
        // synthetic image.
        assert_eq!(
            &a[0].image_data[..8],
            &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
        );
        assert_eq!(a[0].mime_type, "image/png");
    }

    #[test]
    fn mock_video_sampler_respects_max_frames() {
        let s = MockVideoKeyframeSampler;
        let frames = s
            .extract_keyframes(b"v", "video/quicktime", 2)
            .expect("frames");
        assert_eq!(frames.len(), 2);
        let none = s.extract_keyframes(b"v", "video/mp4", 0).expect("zero");
        assert!(none.is_empty());
    }

    #[test]
    fn mock_video_sampler_rejects_non_video_mime() {
        let s = MockVideoKeyframeSampler;
        let err = s.extract_keyframes(b"unused", "image/png", 5).unwrap_err();
        assert!(matches!(err, crate::Error::Model(_)));
    }

    #[test]
    fn video_keyframe_sampler_trait_is_object_safe() {
        // Compile-time + runtime sanity.
        let mock = MockVideoKeyframeSampler;
        let dynref: &dyn VideoKeyframeSampler = &mock;
        let frames = dynref.extract_keyframes(b"X", "video/mp4", 3).unwrap();
        assert!(!frames.is_empty());
    }
}
