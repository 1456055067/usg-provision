//! Fuzz target `inflate_diff`: our RFC 1951 inflater
//! (`usgp-wincfg` `archive::inflate::inflate_slice`) against the
//! `miniz_oxide` reference inflater.
//!
//! Octet 0 selects (bit 0); the rest is the input:
//!
//! - 0, differential: the rest is a raw DEFLATE stream, decoded by both
//!   with a 1 MiB output budget;
//! - 1, round trip: octet 1 is a compression level (modulo 11) and the
//!   rest is content, compressed raw by `miniz_oxide` and decoded by ours.
//!
//! Invariants:
//!
//! - no panic; every refusal is `bad_deflate` or `malformed` (data after
//!   the final block);
//! - our decoder accepts exactly when the reference finishes the stream
//!   within the budget having consumed all of the input, and then both
//!   produce the same bytes;
//! - our `OutputLimit` only when the reference also needs more than the
//!   budget; our "data after final block" only when the reference
//!   finishes before the end of the input;
//! - round trip: our decoder returns the content the reference encoder
//!   was given, for every level.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/drivers.md#REQ-DRV-001 (ZIP Deflate, CAB MSZIP)
// - RFC 1951 (DEFLATE)

use libfuzzer_sys::fuzz_target;
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use usgp_wincfg::ArchiveError;
use usgp_wincfg::archive::inflate::{InflateError, inflate_slice};

const BUDGET: usize = 1 << 20;

fn differential(stream: &[u8]) {
    let ours = inflate_slice(stream, BUDGET as u64);
    let mut out = vec![0u8; BUDGET];
    let mut r = DecompressorOxide::new();
    let (status, consumed, written) = decompress(
        &mut r,
        stream,
        &mut out,
        0,
        inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF,
    );
    let reference_done = status == TINFLStatus::Done;
    match ours {
        Ok(v) => {
            assert!(reference_done, "we accept, reference says {status:?}");
            assert_eq!(consumed, stream.len(), "we accept, reference stops early");
            assert_eq!(Some(v.as_slice()), out.get(..written), "outputs differ");
        }
        Err(ArchiveError::Inflate(InflateError::OutputLimit)) => {
            assert_eq!(
                status,
                TINFLStatus::HasMoreOutput,
                "budget refusal, reference {status:?}"
            );
        }
        Err(ArchiveError::Malformed(_)) => {
            assert!(
                reference_done && consumed < stream.len(),
                "trailing-data refusal disagrees"
            );
        }
        Err(ArchiveError::Inflate(e)) => {
            assert!(
                !(reference_done && consumed == stream.len()),
                "we refuse ({e:?}) a stream the reference decodes"
            );
        }
        Err(e) => panic!("unexpected refusal {e:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 1 == 0 {
        differential(rest);
    } else {
        let Some((&level, content)) = rest.split_first() else {
            return;
        };
        let stream = miniz_oxide::deflate::compress_to_vec(content, level % 11);
        let back = inflate_slice(&stream, content.len() as u64).expect("own stream decodes");
        assert_eq!(back, content, "round trip differs");
    }
});
