//! Fuzz target `xpress_chunk`: one XPRESS (LZ77 + Huffman) chunk.
//!
//! Input format (defined here; seeds from `fuzz/examples/gen_seeds.rs`):
//!
//! - octet 0 even: **decode**. Octets 1 and 2 are `n` (little-endian);
//!   the expected output length is `n + 1` (1 to 65536). The rest is the
//!   compressed chunk.
//! - octet 0 odd: **round trip**. The rest (at most 65536 octets, at
//!   least 1) is compressed with our test encoder, with and without
//!   matches, and decoded.
//!
//! Invariants (plan WU-9, §10; `specs/standards/wim-compression.md` §6):
//!
//! - no panic, and every error has a non-empty reason code;
//! - the decoder never writes past the expected length: it gets a slice
//!   of exactly that length inside a larger buffer whose tail is a
//!   sentinel, checked after every call;
//! - exact output length: a chunk that decodes to `n` bytes fails for
//!   `n - 1` and for `n + 1`;
//! - one reused `XpressDecoder` (kept across inputs) and a fresh
//!   `decode_xpress_chunk` give the same result and the same output;
//! - the round trip returns the original bytes.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/standards/wim-compression.md §3, §6 (decoder bounds)
// - SPEC: specs/os-images.md#REQ-IMG-037
// - DECISION: docs/decisions/0014-m2-wim-compression-scope.md

use std::cell::RefCell;

use libfuzzer_sys::fuzz_target;
use usgp_image::codec::{CodecError, XpressDecoder, decode_xpress_chunk};
use usgp_image::testkit::xpress_enc;

const MAX_OUT: usize = 65536;
const SENTINEL: u8 = 0xa5;
const SENTINEL_LEN: usize = 64;

thread_local! {
    static DECODER: RefCell<XpressDecoder> = RefCell::new(XpressDecoder::new());
}

/// Decodes into a slice of exactly `expected` bytes followed by a
/// sentinel, and checks that the sentinel is untouched.
fn decode_guarded(input: &[u8], expected: usize, reuse: bool) -> (Result<(), CodecError>, Vec<u8>) {
    let mut buf = vec![SENTINEL; expected + SENTINEL_LEN];
    let (out, tail) = buf.split_at_mut(expected);
    let r = if reuse {
        DECODER.with(|d| d.borrow_mut().decode_chunk(input, out))
    } else {
        decode_xpress_chunk(input, out)
    };
    assert!(
        tail.iter().all(|&b| b == SENTINEL),
        "decoder wrote past the expected length"
    );
    if let Err(e) = &r {
        assert!(!e.reason_code().is_empty(), "empty reason code");
        assert!(!e.to_string().is_empty(), "empty error text");
    }
    buf.truncate(expected);
    (r, buf)
}

fn decode_mode(input: &[u8], expected: usize) {
    let (fresh, fresh_out) = decode_guarded(input, expected, false);
    let (reused, reused_out) = decode_guarded(input, expected, true);
    assert_eq!(fresh, reused, "reused decoder result differs");
    if fresh.is_ok() {
        assert_eq!(fresh_out, reused_out, "reused decoder output differs");
        if expected > 0 {
            let (shorter, _) = decode_guarded(input, expected - 1, false);
            assert!(shorter.is_err(), "decoded into one byte less");
        }
        let (longer, _) = decode_guarded(input, expected + 1, false);
        assert!(longer.is_err(), "decoded into one byte more");
    }
}

fn round_trip(data: &[u8]) {
    for enc in [
        xpress_enc::compress(data),
        xpress_enc::compress_literals(data),
    ] {
        let (r, out) = decode_guarded(&enc, data.len(), false);
        assert_eq!(r, Ok(()), "own encoder output refused");
        assert_eq!(out, data, "round trip differs");
        let (r, out) = decode_guarded(&enc, data.len(), true);
        assert_eq!(r, Ok(()), "own encoder output refused (reused decoder)");
        assert_eq!(out, data, "round trip differs (reused decoder)");
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let Some((len, input)) = rest.split_at_checked(2) else {
            return;
        };
        let n = usize::from(u16::from_le_bytes([len[0], len[1]]));
        decode_mode(input, n + 1);
    } else {
        let data = &rest[..rest.len().min(MAX_OUT)];
        if !data.is_empty() {
            round_trip(data);
        }
    }
});
