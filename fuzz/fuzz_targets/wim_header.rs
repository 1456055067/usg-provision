//! Fuzz target `wim_header`: arbitrary bytes as the start of an uploaded
//! WIM file.
//!
//! Every input goes through `parse_header`; a parsed header goes through
//! `classify_flags` and `check_header`. Invariants (plan WU-9, §10):
//!
//! - no panic, and every refusal carries a listed reason code;
//! - `parse_header` accepts only a 208-byte header with the signature and
//!   `cbSize` 208, and every field equals an independent little-endian
//!   read at its offset (the resource headers re-encode byte for byte);
//! - `check_header` accepts only a header whose image count is 1 to the
//!   limit, whose boot index is at most the image count, and whose
//!   offset-20 field is 32768 when the file is XPRESS; it never accepts
//!   what `classify_flags` refuses, and agrees with it on the compression;
//! - `check_within` never accepts a range that starts before the header or
//!   ends past the file, including on u64 overflow.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/os-images.md#REQ-IMG-037 (check before ready),
//   #REQ-IMG-022 (each refusal names its reason)
// - SPEC: specs/standards/wim.md §2 (header)
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

use libfuzzer_sys::fuzz_target;
use usgp_image::wim::header::{
    Compression, HEADER_LEN, HEADER_LEN_U64, MAGIC, WimHeader, check_header, classify_flags,
    parse_header,
};
use usgp_image::wim::reshdr::{RESHDR_LEN, ResourceHeader};
use usgp_image::{WimError, WimLimits};

fn assert_listed(e: &WimError) {
    let code = e.reason_code();
    assert!(
        WimError::REASON_CODES.contains(&code),
        "unlisted reason code {code}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator message");
}

fn le_u16(b: &[u8], at: usize) -> u16 {
    let mut a = [0u8; 2];
    a.copy_from_slice(&b[at..at + 2]);
    u16::from_le_bytes(a)
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    a.copy_from_slice(&b[at..at + 4]);
    u32::from_le_bytes(a)
}

/// The resource header at `at` re-encodes to the same 24 bytes.
fn assert_reshdr(b: &[u8], at: usize, rh: &ResourceHeader) {
    let raw = &b[at..at + RESHDR_LEN];
    assert_eq!(&rh.to_bytes()[..], raw, "resource header at {at} differs");
    assert_eq!(ResourceHeader::parse(raw).as_ref(), Some(rh));
    assert!(rh.stored_size < 1 << 56, "stored size over 56 bits");
}

fn check_fields(b: &[u8], h: &WimHeader) {
    assert!(b.len() >= HEADER_LEN, "accepted a short header");
    assert_eq!(&b[..MAGIC.len()], &MAGIC[..]);
    assert_eq!(h.cb_size, 208);
    assert_eq!(h.version, le_u32(b, 12));
    assert_eq!(h.flags, le_u32(b, 16));
    assert_eq!(h.field_20, le_u32(b, 20));
    assert_eq!(&h.guid[..], &b[24..40]);
    assert_eq!(h.part_number, le_u16(b, 40));
    assert_eq!(h.total_parts, le_u16(b, 42));
    assert_eq!(h.image_count, le_u32(b, 44));
    assert_reshdr(b, 48, &h.lookup);
    assert_reshdr(b, 72, &h.xml);
    assert_reshdr(b, 96, &h.boot_metadata);
    assert_eq!(h.boot_index, le_u32(b, 120));
    assert_reshdr(b, 124, &h.integrity);
}

fn check_range(rh: &ResourceHeader, file_len: u64) {
    match rh.check_within(HEADER_LEN_U64, file_len, "fuzz") {
        Ok(end) => {
            assert!(rh.offset >= HEADER_LEN_U64, "range starts in the header");
            assert_eq!(rh.offset.checked_add(rh.stored_size), Some(end));
            assert!(end <= file_len, "range ends past the file");
        }
        Err(e) => {
            assert!(matches!(e, WimError::OutOfBounds { .. }), "{e:?}");
            assert_listed(&e);
        }
    }
}

fn check_values(h: &WimHeader, max_images: u32) {
    let classified = classify_flags(h);
    match check_header(h, max_images) {
        Ok(c) => {
            assert_eq!(classified.as_ref().ok(), Some(&c), "classify disagrees");
            assert!(h.image_count >= 1, "accepted no images");
            assert!(h.image_count <= max_images, "accepted over the limit");
            assert!(h.boot_index <= h.image_count, "accepted a bad boot index");
            assert_eq!(h.total_parts, 1, "accepted a split part");
            assert_eq!(h.part_number, 1, "accepted a split part");
            if c == Compression::Xpress {
                assert_eq!(h.field_20, 32768, "accepted a bad chunk size");
            }
        }
        Err(e) => {
            assert_listed(&e);
            if let Err(ce) = classified {
                // Flags are checked first: the same refusal.
                assert_eq!(ce, e, "check_header and classify_flags differ");
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    match parse_header(data) {
        Ok(h) => {
            check_fields(data, &h);
            check_values(&h, WimLimits::DEFAULT.max_images);
            check_values(&h, 3);
            let file_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
            for rh in [&h.lookup, &h.xml, &h.boot_metadata, &h.integrity] {
                check_range(rh, file_len);
                check_range(rh, u64::MAX);
            }
        }
        Err(e) => {
            assert_listed(&e);
            assert!(
                matches!(
                    e,
                    WimError::TooShort | WimError::NotWim | WimError::HeaderSize { .. }
                ),
                "parse_header refused with {e:?}"
            );
        }
    }
});
