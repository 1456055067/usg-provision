//! Input bounds for the M2 operator API and the signed manifests.
//!
//! These are project limits chosen for input validation (SI-10). They are
//! **not** the product limits that `specs/os-images.md` REQ-IMG-002 and
//! OPEN-IMG-L1 leave open. A value over a limit is refused with a reason
//! that states the limit; nothing is ever truncated silently (plan WU-4).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every text,
//   list and size in an API body or manifest is bounded.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - parse sizes are
//   capped before any allocation proportional to input.
// - SPEC: specs/os-images.md#REQ-IMG-002 (lengths enforced and reported;
//   values are project limits, the product limits stay OPEN)
// - SPEC: specs/os-images.md#REQ-IMG-033 (file names with spaces)

/// Longest display name (images, PE kits, packages), in Unicode scalar
/// values.
pub const MAX_DISPLAY_NAME_CHARS: usize = 128;

/// Longest package description, in Unicode scalar values.
pub const MAX_DESCRIPTION_CHARS: usize = 1024;

/// Longest uploaded file name, in bytes of UTF-8.
pub const MAX_FILE_NAME_BYTES: usize = 255;

/// Default cap on a JSON request body (plan section 3.2). The server may
/// configure `api.max_json_bytes`; [`crate::api::parse_request`] takes the
/// effective cap as an argument.
pub const DEFAULT_MAX_JSON_BYTES: usize = 64 * 1024;

/// Size of one content chunk for per-chunk digests (8 MiB, plan section
/// 1.1, "Content store").
pub const CHUNK_SIZE: u64 = 8 * 1024 * 1024;

/// Largest content size a signed content manifest may describe (1 TiB).
///
/// This is a parse ceiling for manifests, so the chunk list is bounded
/// (at most 131 072 entries). The server's configured
/// `content.max_upload_bytes` must not exceed it.
pub const MAX_CONTENT_BYTES: u64 = 1024 * 1024 * 1024 * 1024;

/// Most chunk digests a content manifest can hold
/// (`MAX_CONTENT_BYTES / CHUNK_SIZE`).
pub const MAX_CHUNKS: u64 = MAX_CONTENT_BYTES / CHUNK_SIZE;

/// Most images (editions) a WIM summary in a manifest may list. Matches
/// the `WimLimits::max_images` default of plan section 3.1.
pub const MAX_IMAGES: u32 = 1024;

/// Longest WIM edition name or description carried in a manifest or view,
/// in Unicode scalar values. Matches `WimLimits::max_name_chars`.
pub const MAX_WIM_TEXT_CHARS: usize = 1024;

/// Largest manifest payload (the signed JSON bytes).
pub const MAX_MANIFEST_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Largest signed envelope text (base64 payload plus signatures).
pub const MAX_ENVELOPE_BYTES: usize = 48 * 1024 * 1024;

/// Most signatures one envelope may carry.
pub const MAX_SIGNATURES: usize = 8;

/// Largest signature value accepted from an envelope, in bytes. An ASN.1
/// DER ECDSA P-384 signature is at most 104 bytes; the cap leaves room for
/// later algorithms without allowing unbounded input.
pub const MAX_SIGNATURE_BYTES: usize = 512;

/// Longest operator-facing message in an error or reason, in Unicode
/// scalar values.
pub const MAX_MESSAGE_CHARS: usize = 2048;

/// Longest error or reason code, in bytes.
pub const MAX_ERROR_CODE_BYTES: usize = 128;
