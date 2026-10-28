//! Input bounds for the M2 operator API, the signed manifests and the M3
//! device session, job plan, progress and boot-policy types.
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
// - SPEC: specs/disk.md#REQ-DISK-001 (disk descriptors, bounded)
// - SPEC: specs/progress.md#REQ-JOB-007, #REQ-JOB-011 (bounded retries
//   and timeouts; values OPEN-JOB-4)

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

// ---------------------------------------------------------------------------
// M3: device session, job plan, progress, boot policy (plan WU-2, section 3)
// ---------------------------------------------------------------------------

/// Largest device API request body (plan section 3.1: 64 KiB).
pub const MAX_DEVICE_JSON_BYTES: usize = 64 * 1024;

/// Largest `POST .../confirm` response the agent parses: two envelopes
/// (plan and content manifest) plus the job id and JSON framing.
pub const MAX_CONFIRM_RESPONSE_BYTES: usize = 2 * MAX_ENVELOPE_BYTES + 4096;

/// Most network hardware addresses a device reports (plan section 3.1).
pub const MAX_MACS: usize = 16;

/// Longest agent version string, in bytes of printable ASCII (project
/// limit; the plan does not state one).
pub const MAX_AGENT_VERSION_BYTES: usize = 64;

/// Longest disk model or serial number, in characters of printable ASCII
/// (plan section 3.1).
pub const MAX_DISK_TEXT_CHARS: usize = 64;

/// Longest partition label, in Unicode scalar values (plan section 3.1).
pub const MAX_PARTITION_LABEL_CHARS: usize = 32;

/// Most partitions in a disk descriptor or layout report (plan section
/// 3.1; a GPT holds 128 entries, `specs/standards/gpt.md`).
pub const MAX_PARTITIONS: usize = 128;

/// Most refused disks listed when a session ends (plan section 3.1).
pub const MAX_REFUSED_DISKS: usize = 32;

/// Most packages offered to one device (the boot-service assignment
/// limit of plan section 3.5).
pub const MAX_OFFERED_PACKAGES: usize = 256;

/// Most packages assigned to one boot service (plan section 3.5).
pub const MAX_BOOT_SERVICE_PACKAGES: usize = 256;

/// Most served subnets of one boot service (plan section 3.8).
pub const MAX_SERVED_SUBNETS: usize = 64;

/// Most files named in one failure report (plan section 3.4).
pub const MAX_FAILED_FILES: usize = 32;

/// Longest file name or role text in a progress item or failure, in
/// Unicode scalar values (project limit).
pub const MAX_ITEM_NAME_CHARS: usize = 255;

/// Most stops in one boot-policy list (plan section 3.6).
pub const MAX_BOOT_STOPS: usize = 100_000;

/// Longest operator note on an issued code or a refused session, in
/// Unicode scalar values (plan section 3.8: `note` at most 200).
pub const MAX_NOTE_CHARS: usize = 200;

/// Longest raw text accepted for an operator-issued code before
/// normalisation (10 symbols plus optional hyphens; project limit).
pub const MAX_AUTH_CODE_INPUT_BYTES: usize = 32;

/// Longest step timeout in a job plan, in seconds (7 days). Windows PE
/// restarts by itself after 240 hours (`specs/standards/winpe.md` §6), so
/// any longer value could never take effect (REQ-JOB-011).
pub const MAX_STEP_TIMEOUT_S: u32 = 7 * 24 * 3600;

/// Most retry attempts a job plan may ask for (project limit;
/// REQ-JOB-007 requires a bound, the values are OPEN-JOB-4).
pub const MAX_RETRY_ATTEMPTS: u32 = 100;

/// Longest retry delay in a job plan, in milliseconds (1 hour).
pub const MAX_RETRY_DELAY_MS: u32 = 3_600_000;

/// Longest report interval in a job plan, in seconds (1 hour).
pub const MAX_REPORT_INTERVAL_S: u32 = 3600;

/// Most failed attempts reported for one step (project limit).
pub const MAX_REPORTED_ATTEMPTS: u32 = 10_000;
