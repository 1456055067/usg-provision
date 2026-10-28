//! Fuzz target `wim_check`: arbitrary bytes as a whole uploaded WIM file.
//!
//! The file is checked in memory by `check_wim` with the default limits
//! and the FIPS provider (SHA-1 for the format hashes only). Invariants
//! (plan WU-9, §10):
//!
//! - no panic, and every refusal carries a listed reason code (REQ-IMG-022)
//!   with non-empty operator text;
//! - the progress callback never stops the check, so `wim_check_stalled`
//!   never appears; when a second run stops at the first callback, the
//!   check ends with `wim_check_stalled`, or with the refusal the first
//!   run reached before its first report; it never accepts;
//! - an accepted file has 1 to the image limit images, one edition per
//!   image with indexes 1 to N in order, a boot index of at most N, and
//!   `check_pe` either picks an index in 1 to N or refuses with a listed
//!   reason code;
//! - bounded work (SEC-003, BOOT-001): the bytes read through the progress
//!   hook never exceed twice the file length plus the header (each
//!   resource read at most once, a metadata entry repeating the lookup
//!   entry directly before it (OBS-018) included, plus the integrity
//!   range), and an accepted file's distinct metadata original sizes
//!   (each such repeat counted once) sum to at most
//!   `METADATA_EXPANSION_LIMIT` times the file length and the configured
//!   total.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity), SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038, #REQ-IMG-022
// - SPEC: specs/preinstall-env.md#REQ-PE-004
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md,
//   docs/decisions/0014-m2-wim-compression-scope.md

use std::io::Cursor;
use std::ops::ControlFlow;

use libfuzzer_sys::fuzz_target;
use usgp_image::limits::METADATA_EXPANSION_LIMIT;
use usgp_image::wim::header::parse_header;
use usgp_image::wim::lookup::LookupEntry;
use usgp_image::{WimError, WimLimits, check_pe, check_wim};

/// Sum of the original sizes of the metadata entries, read straight from
/// the bytes of an accepted file; an entry equal to the lookup entry
/// directly before it, which is not itself such a repeat, names the same
/// resource (OBS-018) and is counted once.
fn metadata_total(data: &[u8]) -> u64 {
    let h = parse_header(data).expect("accepted file has a header");
    let start = h.lookup.offset as usize;
    let end = start + h.lookup.stored_size as usize;
    let mut previous: Option<(LookupEntry, bool)> = None;
    let mut total = 0u64;
    for e in data[start..end]
        .chunks(50)
        .map(|raw| LookupEntry::parse(raw).expect("entry"))
    {
        let repeat = e.reshdr.is_metadata() && matches!(previous, Some((p, false)) if p == e);
        if e.reshdr.is_metadata() && !repeat {
            total += e.reshdr.original_size;
        }
        previous = Some((e, repeat));
    }
    total
}

fn assert_listed(e: &WimError) {
    let code = e.reason_code();
    assert!(
        WimError::REASON_CODES.contains(&code),
        "unlisted reason code {code}"
    );
    assert!(!e.operator_message().is_empty(), "empty operator message");
}

fuzz_target!(|data: &[u8]| {
    let file_len = data.len() as u64;
    let limits = WimLimits::DEFAULT;
    let mut calls: u64 = 0;
    let mut read: u64 = 0;
    let mut progress = |n: u64| {
        calls += 1;
        read += n;
        ControlFlow::Continue(())
    };
    let result = check_wim(
        &mut Cursor::new(data),
        file_len,
        &limits,
        usgp_crypto::provider(),
        &mut progress,
    );
    assert!(
        read <= 2 * file_len + 208,
        "read {read} bytes of a {file_len}-byte file"
    );
    // Stop at the first progress report: the check must end there.
    let mut stop = |_: u64| ControlFlow::Break(());
    let stopped = check_wim(
        &mut Cursor::new(data),
        file_len,
        &limits,
        usgp_crypto::provider(),
        &mut stop,
    );
    match &stopped {
        Ok(_) => assert_eq!(calls, 0, "accepted after a stop"),
        Err(WimError::Stalled) => assert!(calls >= 1, "stalled with no read"),
        Err(e) => {
            // Refused before the first report: the same refusal.
            assert_eq!(result.as_ref().err(), Some(e), "stopped run differs");
        }
    }
    match result {
        Ok(s) => {
            assert!(s.image_count >= 1, "accepted no images");
            assert!(s.image_count <= limits.max_images, "over the image limit");
            assert_eq!(s.editions.len(), s.image_count as usize, "editions");
            assert_eq!(s.xml_images.len(), s.image_count as usize, "xml images");
            for (want, e) in (1u32..).zip(&s.editions) {
                assert_eq!(e.index, want, "edition indexes not 1..=N");
                assert!(s.xml_image(want).is_some(), "no XML for index {want}");
            }
            assert!(s.boot_index <= s.image_count, "bad boot index accepted");
            let total = metadata_total(data);
            assert!(
                total <= file_len.saturating_mul(METADATA_EXPANSION_LIMIT)
                    && total <= limits.max_metadata_total_bytes,
                "metadata total {total} over budget"
            );
            match check_pe(&s) {
                Ok(i) => assert!((1..=s.image_count).contains(&i), "PE index {i}"),
                Err(e) => {
                    assert!(matches!(e, WimError::PeNoUsableImage { .. }), "{e:?}");
                    assert_listed(&e);
                }
            }
        }
        Err(e) => {
            assert!(!matches!(e, WimError::Stalled), "stalled without a stop");
            assert_listed(&e);
        }
    }
});
