//! Fuzz target `agent_config`: arbitrary text as the pre-boot agent's
//! `agent.toml` (`usgp-proto` `AgentConfigFile::from_toml`), and as a
//! server URL for `parse_server_url`.
//!
//! Octet 0 selects (modulo 2): 0, the rest (UTF-8) is the file; 1, the
//! rest is a URL.
//!
//! Invariants (M3 plan §3.9; decision 0020; impl-notes-integration
//! item 7):
//!
//! - no panic; every refusal has operator text, and an `Invalid` refusal
//!   names one of the file's keys;
//! - an accepted file has settings: an `https` server with a host that is
//!   an IP literal or a DNS name of 1 to 63-character LDH labels (at most
//!   253 characters), a port 1 to 65535 (443 by default), a valid server
//!   name, `network_wait_s` 10 to 600 (default 120), `connect_timeout_s`
//!   1 to 120 (default 15), and non-empty file names; `to_toml` parses
//!   back to the same file;
//! - an accepted URL re-built from its host and port parses back to the
//!   same host and port.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-6 (Configuration Settings), SI-10 (Information Input
//   Validation), SA-11
// - SPEC: specs/preinstall-env.md#REQ-PE-015
// - DECISION: docs/decisions/0020 (public configuration, no secret)
// - RFC 3986 §3.2 (authority), RFC 1123 §2.1 (host names)

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use usgp_proto::agent_config::{
    AgentConfigError, AgentConfigFile, CONNECT_TIMEOUT_S, MAX_CONFIG_BYTES, NETWORK_WAIT_S,
    check_host, parse_server_url,
};

const KEYS: [&str; 7] = [
    "server_url",
    "server_name",
    "trust_anchors",
    "plan_key_pub",
    "content_key_pub",
    "network_wait_s",
    "connect_timeout_s",
];

/// Host rule, written independently: an IP literal, or LDH labels.
fn host_model(h: &str) -> bool {
    h.parse::<IpAddr>().is_ok()
        || (!h.is_empty()
            && h.len() <= 253
            && h.split('.').all(|l| {
                (1..=63).contains(&l.len())
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !l.starts_with('-')
                    && !l.ends_with('-')
            }))
}

fn url(u: &str) {
    let Ok((host, port)) = parse_server_url(u) else {
        return;
    };
    assert!(
        u.get(..8)
            .is_some_and(|s| s.eq_ignore_ascii_case("https://")),
        "scheme"
    );
    assert_ne!(port, 0, "port 0");
    if host.contains(':') {
        assert!(
            matches!(host.parse::<IpAddr>(), Ok(IpAddr::V6(_))),
            "colon in a host that is not IPv6"
        );
    } else {
        assert!(host_model(&host), "host {host:?} breaks the rule");
        assert!(check_host(&host).is_ok());
    }
    assert!(
        !host.contains(['@', '?', '#', '/', '[', ']']),
        "authority characters in host"
    );
    let rebuilt = if host.contains(':') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    };
    assert_eq!(
        parse_server_url(&rebuilt),
        Ok((host.clone(), port)),
        "rebuilt URL differs"
    );
    if port == 443 {
        // The default port: the URL without one is the same server.
        let bare = rebuilt.trim_end_matches(":443").to_owned();
        assert_eq!(parse_server_url(&bare), Ok((host, 443)));
    }
}

fn file(text: &str) {
    let f = match AgentConfigFile::from_toml(text) {
        Ok(f) => f,
        Err(e) => {
            assert!(!e.to_string().is_empty(), "empty refusal text");
            match e {
                AgentConfigError::TooLarge => assert!(text.len() > MAX_CONFIG_BYTES),
                AgentConfigError::Invalid { key, reason } => {
                    assert!(KEYS.contains(&key), "unknown key {key}");
                    assert!(!reason.is_empty());
                }
                _ => {}
            }
            return;
        }
    };
    assert!(text.len() <= MAX_CONFIG_BYTES, "over the size limit");
    let s = f.settings().expect("accepted file has settings");
    assert_eq!(
        parse_server_url(&f.server_url),
        Ok((s.host.clone(), s.port))
    );
    match &f.server_name {
        Some(n) => {
            assert_eq!(&s.server_name, n);
            assert!(host_model(n), "server_name breaks the host rule");
        }
        None => assert_eq!(s.server_name, s.host, "default server name"),
    }
    let (wmin, wmax, wdef) = NETWORK_WAIT_S;
    let (cmin, cmax, cdef) = CONNECT_TIMEOUT_S;
    assert!(
        (wmin..=wmax).contains(&s.network_wait_s),
        "network_wait_s range"
    );
    assert!(
        (cmin..=cmax).contains(&s.connect_timeout_s),
        "connect_timeout_s range"
    );
    assert_eq!(s.network_wait_s, f.network_wait_s.unwrap_or(wdef));
    assert_eq!(s.connect_timeout_s, f.connect_timeout_s.unwrap_or(cdef));
    for p in [&f.trust_anchors, &f.plan_key_pub, &f.content_key_pub] {
        assert!(!p.as_os_str().is_empty(), "empty file name");
    }
    let out = f.to_toml().expect("accepted file writes");
    match AgentConfigFile::from_toml(&out) {
        Ok(again) => assert_eq!(again, f, "to_toml does not round-trip"),
        Err(e) => panic!("own agent.toml refused: {e}"),
    }
    url(&f.server_url);
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(rest) else {
        return;
    };
    if sel % 2 == 0 {
        file(text);
    } else {
        url(text);
    }
});
