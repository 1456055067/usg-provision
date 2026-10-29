//! Fuzz target `agent_http_head`: the pre-boot agent's HTTP/1.1 response
//! head parser (`usgp_preboot_agent::http::parse_head`, which reads
//! `Content-Length` through the private `parse_length`). The bytes come
//! from the server over TLS, so a hostile or broken server controls them.
//!
//! Input (our design, NIST-011): octet 0 selects (modulo 2):
//!
//! - 0: the rest is a response head as received;
//! - 1: the rest is the value of the one `Content-Length` header in an
//!   otherwise valid head (`HTTP/1.1 200 OK`), to reach `parse_length`.
//!
//! Invariants:
//!
//! - no panic; the same input gives the same answer twice;
//! - an accepted head has a status of 200 to 599, `head_len` within the
//!   input, the same result when parsed from its first `head_len` octets
//!   alone, and no result one octet short of that; its content type, if
//!   any, is lower-case ASCII with no surrounding white space and at most
//!   128 octets;
//! - mode 1, for a value of visible ASCII octets only: the head is
//!   accepted exactly when the value is 1 to 19 decimal digits, and then
//!   `content_length` is that number (a model written here, not the
//!   parser's code).

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11
// - SPEC: specs/preinstall-env.md#REQ-PE-015 (the agent's server channel)
// - RFC 9112 §2, §6.3 (message framing, Content-Length); RFC 9110 §8.6

use libfuzzer_sys::fuzz_target;
use usgp_preboot_agent::http::{Head, HttpError, parse_head};

/// Longest content type the parser keeps (`http.rs` `MAX_CONTENT_TYPE`).
const MAX_CONTENT_TYPE: usize = 128;

fn same(a: &Result<Option<Head>, HttpError>, b: &Result<Option<Head>, HttpError>) -> bool {
    match (a, b) {
        (Ok(x), Ok(y)) => x == y,
        (Err(x), Err(y)) => format!("{x:?}") == format!("{y:?}"),
        _ => false,
    }
}

fn check(buf: &[u8]) -> Result<Option<Head>, HttpError> {
    let r = parse_head(buf);
    assert!(same(&r, &parse_head(buf)), "not deterministic");
    if let Ok(Some(h)) = &r {
        assert!((200..=599).contains(&h.status));
        assert!(h.head_len > 0 && h.head_len <= buf.len());
        let head = buf.get(..h.head_len).expect("head_len within input");
        assert!(
            same(&r, &parse_head(head)),
            "the head alone parses differently"
        );
        let short = buf.get(..h.head_len - 1).expect("shorter prefix");
        assert!(
            !matches!(parse_head(short), Ok(Some(_))),
            "a head completed without its last octet"
        );
        if let Some(t) = &h.content_type {
            assert!(t.len() <= MAX_CONTENT_TYPE && t.is_ascii());
            assert_eq!(t, &t.to_ascii_lowercase());
            assert_eq!(t, t.trim());
        }
    }
    r
}

/// Model of the `Content-Length` rule: 1 to 19 ASCII digits.
fn length_model(v: &[u8]) -> Option<u64> {
    if v.is_empty() || v.len() > 19 || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let mut n: u64 = 0;
    for d in v {
        n = n * 10 + u64::from(d - b'0');
    }
    Some(n)
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel % 2 == 0 {
        let _ = check(rest);
        return;
    }
    let mut head = b"HTTP/1.1 200 OK\r\nContent-Length: ".to_vec();
    head.extend_from_slice(rest);
    head.extend_from_slice(b"\r\n\r\n");
    let r = check(&head);
    if rest.iter().all(|b| (0x21..=0x7e).contains(b)) {
        match (length_model(rest), &r) {
            (Some(n), Ok(Some(h))) => assert_eq!(h.content_length, n),
            (None, Err(_)) => {}
            (m, r) => panic!("model {m:?} but parser {r:?}"),
        }
    }
});
