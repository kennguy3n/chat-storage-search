//! Thumbnail generation for the media pipeline.
//!
//! `docs/DESIGN.md §3.2` lists the `thumbnail_only` and
//! `original_local` slots in the [`crate::local_store::state_machines::MediaState`]
//! lifecycle. [`process_media`](crate::media::processor::process_media)
//! produces the AEAD-sealed original; [`ThumbnailGenerator`] produces
//! the small, low-fidelity preview that the timeline can render before
//! the original has been (or even instead of being) downloaded /
//! decrypted.
//!
//! Keeps the surface deliberately narrow:
//!
//! * Image inputs (PNG / JPEG, decoded via the lean
//!   [`image`](https://docs.rs/image) crate with
//!   `default-features = false`) are decoded, resized down to fit
//!   inside `max_dimension`, and re-encoded as PNG so the thumbnail
//!   is **always** a deterministic PNG regardless of the input MIME.
//! * Non-image MIME types return [`Error::Message`]; full
//!   video / document / audio thumbnailing lands later in
//!   alongside the on-device vision and OCR models (see
//!   ).
//!
//! The returned [`ThumbnailResult::thumbnail_bytes`] is the PNG
//! payload that the caller feeds into
//! [`crate::media::processor::process_media`] (or
//! [`crate::media::chunker::chunk_and_encrypt`] directly) to produce
//! a sealed thumbnail asset that ships through MLS alongside the
//! original `MediaDescriptor`.

use std::io::Cursor;

use image::imageops::FilterType;
use image::{ImageFormat, ImageReader};

use crate::Error;

/// MIME type emitted for every successfully generated thumbnail.
///
/// The thumbnail format is normalized to PNG regardless of the input
/// MIME so the renderer side has a single decoder path.
pub const THUMBNAIL_MIME_TYPE: &str = "image/png";

/// Default upper bound on the long edge of a generated thumbnail.
///
/// 256 px is what `docs/DESIGN.md §3.2` calls out for the
/// `thumbnail_only` body state — it keeps the encoded blob small
/// enough to fit in a single AEAD chunk without hurting timeline
/// fidelity at common DPRs.
pub const DEFAULT_MAX_DIMENSION: u32 = 256;

/// Output of [`ThumbnailGenerator::generate_thumbnail`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThumbnailResult {
    /// Encoded thumbnail bytes ready to feed into
    /// [`crate::media::processor::process_media`] or
    /// [`crate::media::chunker::chunk_and_encrypt`].
    pub thumbnail_bytes: Vec<u8>,
    /// Pixel width of the encoded thumbnail.
    pub width: u32,
    /// Pixel height of the encoded thumbnail.
    pub height: u32,
    /// MIME type of [`Self::thumbnail_bytes`]. Always
    /// [`THUMBNAIL_MIME_TYPE`] for
    pub mime_type: String,
}

/// thumbnail generator.
///
/// The generator is currently stateless — it carries no
/// configuration of its own — but the type is kept around so the
/// public surface is identical to what will plug in (which
/// will hold the vision / OCR pipelines and the codec selection
/// logic).
#[derive(Debug, Default, Clone, Copy)]
pub struct ThumbnailGenerator;

impl ThumbnailGenerator {
    /// Construct a new thumbnail generator. has no
    /// configuration so this is just `Self`.
    pub fn new() -> Self {
        Self
    }

    /// Generate a thumbnail from `plaintext` for the given
    /// `mime_type`.
    ///
    /// `max_dimension` caps the long edge of the output (in pixels).
    /// The aspect ratio is preserved.
    ///
    /// Returns [`Error::Message`] when:
    ///
    /// * `plaintext` is empty,
    /// * `max_dimension` is `0`,
    /// * `mime_type` is not one of the supported image types
    ///   (`image/png`, `image/jpeg`),
    /// * the input bytes fail to decode as an image of the declared
    ///   format.
    pub fn generate_thumbnail(
        &self,
        plaintext: &[u8],
        mime_type: &str,
        max_dimension: u32,
    ) -> Result<ThumbnailResult, Error> {
        if plaintext.is_empty() {
            return Err(Error::Message(
                "thumbnail generation requires non-empty input"
                    .to_string()
                    .into(),
            ));
        }
        if max_dimension == 0 {
            return Err(Error::Message(
                "thumbnail max_dimension must be > 0".to_string().into(),
            ));
        }

        let format = image_format_for_mime(mime_type)?;

        let mut reader = ImageReader::new(Cursor::new(plaintext));
        reader.set_format(format);
        let img = reader.decode().map_err(|e| {
            Error::Message(crate::message::MessageError::ImageCodec {
                op: "decode",
                detail: e.to_string(),
            })
        })?;

        let resized = img.resize(max_dimension, max_dimension, FilterType::Triangle);
        let (width, height) = (resized.width(), resized.height());

        let mut out = Vec::new();
        resized
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .map_err(|e| {
                Error::Message(crate::message::MessageError::ImageCodec {
                    op: "encode_thumbnail",
                    detail: e.to_string(),
                })
            })?;

        Ok(ThumbnailResult {
            thumbnail_bytes: out,
            width,
            height,
            mime_type: THUMBNAIL_MIME_TYPE.to_string(),
        })
    }
}

/// Map a MIME type to the `image::ImageFormat` that decodes it, or
/// return [`Error::Message`] for unsupported types. only
/// supports PNG and JPEG inputs.
fn image_format_for_mime(mime_type: &str) -> Result<ImageFormat, Error> {
    match mime_type {
        "image/png" => Ok(ImageFormat::Png),
        "image/jpeg" | "image/jpg" => Ok(ImageFormat::Jpeg),
        other => Err(Error::Message(crate::message::MessageError::ImageCodec {
            op: "select_format",
            detail: format!("thumbnail generation not supported for mime_type {other:?}"),
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    /// Build an in-memory PNG of `width × height` filled with a
    /// gradient so the PNG encoder produces a non-trivial, varied
    /// payload (uniform-colour PNGs compress to under 100 bytes and
    /// don't exercise the resize path well).
    fn make_test_png(width: u32, height: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(width, height, |x, y| {
            let r = ((x * 255) / width.max(1)) as u8;
            let g = ((y * 255) / height.max(1)) as u8;
            let b = ((x ^ y) & 0xFF) as u8;
            Rgba([r, g, b, 0xFF])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .expect("encode test png");
        out
    }

    fn make_test_jpeg(width: u32, height: u32) -> Vec<u8> {
        let img = ImageBuffer::from_fn(width, height, |x, y| {
            let r = ((x * 255) / width.max(1)) as u8;
            let g = ((y * 255) / height.max(1)) as u8;
            let b = ((x ^ y) & 0xFF) as u8;
            image::Rgb([r, g, b])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Jpeg)
            .expect("encode test jpeg");
        out
    }

    #[test]
    fn thumbnail_from_valid_image_produces_smaller_output() {
        let big = make_test_png(1024, 768);
        let gen = ThumbnailGenerator::new();
        let out = gen
            .generate_thumbnail(&big, "image/png", 128)
            .expect("thumbnail");
        assert_eq!(out.mime_type, THUMBNAIL_MIME_TYPE);
        // Long edge respected (1024 → 128, height scaled
        // proportionally to 96).
        assert_eq!(out.width, 128);
        assert_eq!(out.height, 96);
        // PNG byte count for a 128 × 96 gradient is well under the
        // 1024 × 768 source.
        assert!(
            out.thumbnail_bytes.len() < big.len(),
            "thumbnail ({} bytes) must be smaller than original ({} bytes)",
            out.thumbnail_bytes.len(),
            big.len(),
        );
        // PNG magic bytes.
        assert_eq!(&out.thumbnail_bytes[..8], b"\x89PNG\r\n\x1A\n");
    }

    #[test]
    fn thumbnail_respects_max_dimension() {
        let big = make_test_png(800, 600);
        let gen = ThumbnailGenerator::new();
        for max in [16, 64, 256, 800] {
            let out = gen.generate_thumbnail(&big, "image/png", max).unwrap();
            assert!(out.width <= max);
            assert!(out.height <= max);
        }
    }

    #[test]
    fn thumbnail_preserves_aspect_ratio_for_portrait() {
        let portrait = make_test_png(300, 600);
        let gen = ThumbnailGenerator::new();
        let out = gen.generate_thumbnail(&portrait, "image/png", 200).unwrap();
        // Long edge clamped to 200; short edge half of that.
        assert_eq!(out.height, 200);
        assert_eq!(out.width, 100);
    }

    #[test]
    fn thumbnail_supports_jpeg_input() {
        let jpeg = make_test_jpeg(640, 480);
        let gen = ThumbnailGenerator::new();
        let out = gen.generate_thumbnail(&jpeg, "image/jpeg", 128).unwrap();
        assert_eq!(out.width, 128);
        assert_eq!(out.height, 96);
        // Output is always PNG.
        assert_eq!(out.mime_type, THUMBNAIL_MIME_TYPE);
        assert_eq!(&out.thumbnail_bytes[..8], b"\x89PNG\r\n\x1A\n");
    }

    #[test]
    fn unsupported_mime_type_returns_error() {
        let gen = ThumbnailGenerator::new();
        for mime in [
            "video/mp4",
            "application/pdf",
            "audio/ogg",
            "image/webp", // not in the supported MIME set
            "image/gif",
            "text/plain",
        ] {
            let err = gen
                .generate_thumbnail(b"\x00\x01\x02\x03", mime, 64)
                .expect_err("should error");
            assert!(matches!(err, Error::Message(_)), "got {err:?}");
            let s = err.to_string();
            assert!(
                s.contains("not supported") && s.contains(mime),
                "unexpected error: {s}"
            );
        }
    }

    #[test]
    fn empty_input_returns_error() {
        let gen = ThumbnailGenerator::new();
        let err = gen
            .generate_thumbnail(&[], "image/png", 64)
            .expect_err("should error");
        let s = err.to_string();
        assert!(s.contains("non-empty"), "unexpected error: {s}");
    }

    #[test]
    fn zero_max_dimension_returns_error() {
        let gen = ThumbnailGenerator::new();
        let png = make_test_png(64, 64);
        let err = gen
            .generate_thumbnail(&png, "image/png", 0)
            .expect_err("should error");
        let s = err.to_string();
        assert!(s.contains("max_dimension"), "unexpected error: {s}");
    }

    #[test]
    fn corrupt_image_returns_error() {
        let gen = ThumbnailGenerator::new();
        let err = gen
            .generate_thumbnail(b"not a real png at all", "image/png", 64)
            .expect_err("should error");
        let s = err.to_string();
        assert!(s.contains("decode"), "unexpected error: {s}");
    }

    #[test]
    fn default_max_dimension_constant_matches_proposal() {
        // Sanity check that the `DEFAULT_MAX_DIMENSION` constant
        // matches `docs/DESIGN.md §3.2` (256 px long edge).
        assert_eq!(DEFAULT_MAX_DIMENSION, 256);
    }
}
