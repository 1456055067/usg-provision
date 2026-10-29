//! Fuzz target `relay_feed_url`: arbitrary text as the relay's
//! `[server_feed] url` (`usgp-relay` `config::FeedUrl::parse`).
//!
//! The whole input, if UTF-8, is the URL.
//!
//! Invariants (M3 plan §3.6; impl-notes-wu11 "WU-14"):
//!
//! - no panic; the result equals a reference model of the documented form
//!   `https://host[:port][/]` (1 to 512 characters, lower-case scheme, no
//!   path, query, fragment or user information; host a DNS name of LDH
//!   labels that is not all digits and dots, a dotted-quad IPv4 address,
//!   or an IPv6 literal in brackets; port 1 to 65535, 443 by default);
//! - `authority()` (the `Host` header value) parses back to the same URL;
//! - an accepted feed URL is also accepted, with the same host and port,
//!   by the agent's `parse_server_url`, which documents the same
//!   `https://host[:port]` form.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings), SI-10 (Information Input
//   Validation), SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-067
// - RFC 3986 §3.2 (authority), RFC 9110 §7.2 (Host), RFC 1123 §2.1

use std::net::{Ipv4Addr, Ipv6Addr};

use libfuzzer_sys::fuzz_target;
use usgp_proto::agent_config::parse_server_url;
use usgp_relay::config::FeedUrl;

fn dns_or_ipv4(h: &str) -> bool {
    h.parse::<Ipv4Addr>().is_ok()
        || (h.len() <= 253
            && h.split('.').all(|l| {
                (1..=63).contains(&l.len())
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !l.starts_with('-')
                    && !l.ends_with('-')
            })
            && !h.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
}

fn port(p: Option<&str>) -> Option<u16> {
    match p {
        None => Some(443),
        Some(p) if (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) => {
            p.parse::<u16>().ok().filter(|&n| n != 0)
        }
        Some(_) => None,
    }
}

/// The documented form, written independently of the crate.
fn model(text: &str) -> Option<(String, u16)> {
    if text.is_empty() || text.len() > FeedUrl::MAX_LEN {
        return None;
    }
    let rest = text.strip_prefix("https://")?;
    let auth = rest.strip_suffix('/').unwrap_or(rest);
    if auth.is_empty()
        || !auth
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
    {
        return None;
    }
    if let Some(v6) = auth.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        h.parse::<Ipv6Addr>().ok()?;
        if h.contains('[') || h.contains(']') || h.is_empty() {
            return None;
        }
        let p = match after {
            "" => None,
            a => Some(a.strip_prefix(':')?),
        };
        return Some((h.to_owned(), port(p)?));
    }
    let (h, p) = match auth.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (auth, None),
    };
    if h.is_empty() || h.contains('[') || h.contains(']') || !dns_or_ipv4(h) {
        return None;
    }
    Some((h.to_owned(), port(p)?))
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let got = FeedUrl::parse(text);
    if let Err(reason) = &got {
        assert!(!reason.is_empty());
    }
    let pair = got.as_ref().ok().map(|u| (u.host.clone(), u.port));
    assert_eq!(
        pair,
        model(text),
        "FeedUrl differs from the reference model"
    );
    let Ok(u) = got else { return };
    let again = FeedUrl::parse(&format!("https://{}", u.authority()));
    assert_eq!(again.as_ref(), Ok(&u), "authority does not parse back");
    assert_eq!(
        parse_server_url(text),
        Ok((u.host.clone(), u.port)),
        "agent URL parser disagrees on a feed URL"
    );
});
