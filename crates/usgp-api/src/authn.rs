//! Operator identity from the TLS client certificate (decision 0007).
//!
//! The TLS layer has already validated the certificate path, revocation
//! and policy (`usgp_crypto::tls::ServerTls`). Here the end-entity
//! certificate's SHA-256 is looked up: exactly one enrolled, active
//! operator must be bound to it. No certificate, an unknown certificate,
//! or a disabled operator is 401 with an audit record. The lookup runs on
//! every request, so disabling an operator takes effect at once.
//!
//! Unauthenticated audit volume is capped ([`UnauthLimiter`]); refusals
//! over a cap are still refused, counted per reason, and summarised. Two
//! budgets keep noise from hiding the use of a real credential (findings
//! NIST-001, SEC-012 / NIST-014). The split is by whether the attempt
//! involved a certificate **issued by our PKI**, not by failure class,
//! because anyone can mint a certificate that fails as `untrusted`,
//! `expired` or `bad_eku`:
//!
//! - **anonymous**: no client certificate, TLS protocol failure, handshake
//!   timeout, and any refused certificate that does **not** chain to a
//!   configured trust anchor (self-made, foreign issuer, unparsable);
//! - **credential**: a certificate that chains to a configured trust
//!   anchor (`usgp_crypto::tls::RefusedHandshake::chained_to_trust_anchor`):
//!   revoked, expired, wrong purpose, policy, ... at the handshake, and
//!   unknown certificate or disabled operator after it. Chaining is decided
//!   before the client proves key possession, so anyone holding a copy of
//!   a public certificate from our PKI (a trust anchor, an intermediate,
//!   or an operator certificate) can draw on this budget too (findings
//!   SEC-016, NIST-017; POAM-28).
//!
//! A refused certificate from our PKI whose client did not send the
//! intermediate certificates cannot be shown to chain and is counted on
//! the anonymous budget (its record, when admitted, still names it and
//! says `trust_anchor: not_chained`).
//!
//! A source is an IPv4 address (/32) or an IPv6 /64 ([`source_key`]), so
//! rotating addresses inside one IPv6 subnet does not multiply the budget
//! (finding SEC-004). Each budget also has a global per-minute ceiling;
//! beyond it only the summary counters grow.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-2 (Identification and Authentication), IA-5(2)
//   (PKI-Based Authentication) - certificate validated by the TLS layer;
//   fingerprint bound to one operator.
// - NIST 800-53: AC-2 (Account Management) - disabled operators refused
//   on every request.
// - NIST 800-53: AU-2, AU-12, AC-7 - unauthenticated attempts audited;
//   attempts with a certificate from our PKI on a budget that anonymous
//   traffic and self-made certificates cannot use up.
// - NIST 800-53: AU-4, AU-5, SC-5 - their audit volume capped per source
//   (IPv4 /32, IPv6 /64) and globally per minute; the excess is counted
//   and summarised.
// - SPEC: specs/operator-access.md#REQ-RBAC-005, #REQ-AUD-001
// - RFC 9110 §15.5.2 (401), §11.6.1 (WWW-Authenticate)

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use usgp_audit::Actor;
use usgp_crypto::PeerCertificate;
use usgp_db::{Operator, OperatorStatus, RepoTx, Store};

/// An authenticated operator for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The operator record.
    pub operator: Operator,
}

impl Principal {
    /// The audit actor: operator id; label = display name and certificate
    /// SHA-256 (plan section 7).
    #[must_use]
    pub fn actor(&self) -> Actor {
        let op = &self.operator;
        Actor::operator(
            &op.id.to_string(),
            &format!(
                "{} (cert sha256 {})",
                op.display_name.as_str(),
                op.cert_sha256.to_hex()
            ),
        )
    }
}

/// Why a request was not authenticated (all 401).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthnFailure {
    /// No client certificate was presented.
    NoCertificate,
    /// A valid certificate that no operator is bound to.
    UnknownCertificate {
        /// What was presented (fingerprint, subject, issuer).
        presented: String,
    },
    /// The bound operator is disabled.
    Disabled {
        /// What was presented.
        presented: String,
        /// The operator id.
        operator: String,
    },
}

impl AuthnFailure {
    /// The audit event (plan section 7).
    #[must_use]
    pub const fn event(&self) -> &'static str {
        match self {
            Self::NoCertificate => "auth.unauthenticated",
            Self::UnknownCertificate { .. } => "auth.unknown_certificate",
            Self::Disabled { .. } => "auth.operator_disabled",
        }
    }

    /// The audit reason.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::NoCertificate => "no_client_certificate",
            Self::UnknownCertificate { .. } => "unknown_certificate",
            Self::Disabled { .. } => "operator_disabled",
        }
    }

    /// The audit actor ("unauthenticated" with what was presented).
    #[must_use]
    pub fn actor(&self) -> Actor {
        match self {
            Self::NoCertificate => Actor::unauthenticated(None),
            Self::UnknownCertificate { presented } | Self::Disabled { presented, .. } => {
                Actor::unauthenticated(Some(presented))
            }
        }
    }
}

/// Public facts about a presented certificate, for the audit record.
#[must_use]
pub fn presented(cert: &PeerCertificate) -> String {
    format!(
        "cert sha256 {}; subject {}; issuer {}; serial {}",
        cert.sha256.to_hex(),
        cert.subject,
        cert.issuer,
        cert.serial
    )
}

/// Resolves the operator for a request.
///
/// # Errors
///
/// `Ok(Err(AuthnFailure))` for a 401; `Err(DbError)` if the lookup failed
/// (the router answers 500 and nothing is served: fail closed).
pub async fn authenticate<S: Store>(
    store: &S,
    peer: Option<&PeerCertificate>,
) -> Result<Result<Principal, AuthnFailure>, usgp_db::DbError> {
    let Some(cert) = peer else {
        return Ok(Err(AuthnFailure::NoCertificate));
    };
    let mut tx = store.begin().await?;
    let op = tx.operator_by_cert(&cert.sha256).await;
    tx.rollback().await;
    Ok(match op? {
        None => Err(AuthnFailure::UnknownCertificate {
            presented: presented(cert),
        }),
        Some(o) if o.status == OperatorStatus::Disabled => Err(AuthnFailure::Disabled {
            presented: presented(cert),
            operator: o.id.to_string(),
        }),
        Some(o) => Ok(Principal { operator: o }),
    })
}

/// The source an address belongs to for caps: the IPv4 address itself
/// (/32), or the IPv6 /64 prefix (one subnet's worth of addresses is one
/// source). IPv4-mapped IPv6 addresses count as their IPv4 address.
#[must_use]
pub fn source_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return IpAddr::V4(v4);
            }
            let [a, b, c, d, ..] = v6.segments();
            IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
    }
}

/// Which audit budget a refused attempt draws on (findings NIST-001,
/// SEC-012 / NIST-014).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthClass {
    /// No credential from our PKI: no client certificate, a TLS protocol
    /// failure, a handshake timeout, or a certificate that does not chain
    /// to a configured trust anchor.
    Anonymous,
    /// A certificate that chains to a configured trust anchor: refused at
    /// the handshake (revoked, expired, ...), or valid but unknown or
    /// bound to a disabled operator.
    Credential,
}

impl AuthClass {
    /// The budget for an HTTP-level refusal ([`AuthnFailure`]): no
    /// certificate is anonymous; an unknown certificate or a disabled
    /// operator passed path validation, so it chains to our anchors.
    #[must_use]
    pub const fn of_http(failure: &AuthnFailure) -> Self {
        match failure {
            AuthnFailure::NoCertificate => Self::Anonymous,
            AuthnFailure::UnknownCertificate { .. } | AuthnFailure::Disabled { .. } => {
                Self::Credential
            }
        }
    }

    /// The budget for a refused handshake: credential only if the
    /// presented certificate chains to a configured trust anchor.
    #[must_use]
    pub const fn of_handshake(chained_to_trust_anchor: bool) -> Self {
        if chained_to_trust_anchor {
            Self::Credential
        } else {
            Self::Anonymous
        }
    }
}

/// Caps for [`UnauthLimiter`] (records per minute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnauthCaps {
    /// Anonymous records per source.
    pub anonymous_per_source: u32,
    /// Anonymous records in total.
    pub anonymous_global: u32,
    /// Credential records per source.
    pub credential_per_source: u32,
    /// Credential records in total.
    pub credential_global: u32,
}

impl Default for UnauthCaps {
    fn default() -> Self {
        Self {
            anonymous_per_source: 10,
            anonymous_global: 300,
            credential_per_source: 60,
            credential_global: 600,
        }
    }
}

/// Most sources tracked at once per budget. Beyond it, new sources share
/// one overflow bucket, so memory stays bounded under a spoofed-address
/// flood.
pub const MAX_TRACKED_SOURCES: usize = 4096;

/// The per-minute window.
const WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
struct Bucket {
    start: Instant,
    count: u32,
}

impl Bucket {
    const fn new(now: Instant) -> Self {
        Self {
            start: now,
            count: 0,
        }
    }

    /// True if one more fits under `cap` in the current window (and
    /// counts it).
    fn take(&mut self, now: Instant, cap: u32) -> bool {
        if now.saturating_duration_since(self.start) >= WINDOW {
            self.start = now;
            self.count = 0;
        }
        if self.count < cap {
            self.count = self.count.saturating_add(1);
            true
        } else {
            false
        }
    }

    /// True if one more fits, without counting it.
    fn has_room(&self, now: Instant, cap: u32) -> bool {
        now.saturating_duration_since(self.start) >= WINDOW || self.count < cap
    }
}

#[derive(Debug)]
struct Budget {
    per_source: u32,
    global_cap: u32,
    buckets: HashMap<IpAddr, Bucket>,
    overflow: Option<Bucket>,
    global: Option<Bucket>,
}

impl Budget {
    fn new(per_source: u32, global_cap: u32) -> Self {
        Self {
            per_source,
            global_cap,
            buckets: HashMap::new(),
            overflow: None,
            global: None,
        }
    }

    /// True if a record for `key` may be written now: both the source's
    /// bucket and the global bucket have room. Only an admitted record is
    /// counted, so a source over its own cap does not use up the global
    /// ceiling.
    fn admit(&mut self, key: IpAddr, now: Instant) -> bool {
        if !self.buckets.contains_key(&key) && self.buckets.len() >= MAX_TRACKED_SOURCES {
            // Drop expired buckets before falling back to the overflow.
            self.buckets
                .retain(|_, b| now.saturating_duration_since(b.start) < WINDOW);
        }
        let global_cap = self.global_cap;
        let global_room = self
            .global
            .get_or_insert(Bucket::new(now))
            .has_room(now, global_cap);
        let tracked = self.buckets.contains_key(&key) || self.buckets.len() < MAX_TRACKED_SOURCES;
        let per = self.per_source;
        let bucket = if tracked {
            self.buckets.entry(key).or_insert(Bucket::new(now))
        } else {
            self.overflow.get_or_insert(Bucket::new(now))
        };
        if !global_room || !bucket.has_room(now, per) {
            return false;
        }
        let _ = bucket.take(now, per);
        self.global
            .get_or_insert(Bucket::new(now))
            .take(now, global_cap)
    }
}

#[derive(Debug)]
struct LimiterState {
    anonymous: Budget,
    credential: Budget,
    suppressed: u64,
    by_reason: BTreeMap<&'static str, u64>,
    suppressed_sources: HashSet<IpAddr>,
    overflow_suppressed: bool,
}

/// Caps unauthenticated audit records per source and globally, in two
/// budgets ([`AuthClass`]; plan section 3.2, findings SEC-004 and
/// NIST-001).
#[derive(Debug)]
pub struct UnauthLimiter {
    state: Mutex<LimiterState>,
}

/// Refusals not recorded individually since the last summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnauthSummary {
    /// Refusals over a cap.
    pub suppressed: u64,
    /// Distinct sources among them (overflow counted as one).
    pub sources: u64,
    /// Count per refusal reason (event reason or TLS class).
    pub by_reason: Vec<(&'static str, u64)>,
}

impl UnauthLimiter {
    /// A limiter with `caps`.
    #[must_use]
    pub fn new(caps: UnauthCaps) -> Self {
        Self {
            state: Mutex::new(LimiterState {
                anonymous: Budget::new(caps.anonymous_per_source, caps.anonymous_global),
                credential: Budget::new(caps.credential_per_source, caps.credential_global),
                suppressed: 0,
                by_reason: BTreeMap::new(),
                suppressed_sources: HashSet::new(),
                overflow_suppressed: false,
            }),
        }
    }

    /// True if a record of a refusal with `reason` from `ip`, on the
    /// `class` budget, may be written now; otherwise the refusal is
    /// counted for the next summary.
    pub fn admit(&self, ip: IpAddr, reason: &'static str, class: AuthClass, now: Instant) -> bool {
        let key = source_key(ip);
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let admitted = match class {
            AuthClass::Anonymous => s.anonymous.admit(key, now),
            AuthClass::Credential => s.credential.admit(key, now),
        };
        if !admitted {
            s.suppressed = s.suppressed.saturating_add(1);
            let n = s.by_reason.entry(reason).or_insert(0);
            *n = n.saturating_add(1);
            if s.suppressed_sources.len() < MAX_TRACKED_SOURCES {
                s.suppressed_sources.insert(key);
            } else {
                s.overflow_suppressed = true;
            }
        }
        admitted
    }

    /// Takes the counts since the last call, if any refusal was
    /// suppressed.
    pub fn take_summary(&self) -> Option<UnauthSummary> {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if s.suppressed == 0 {
            return None;
        }
        let sources = u64::try_from(s.suppressed_sources.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(s.overflow_suppressed));
        let out = UnauthSummary {
            suppressed: s.suppressed,
            sources,
            by_reason: std::mem::take(&mut s.by_reason).into_iter().collect(),
        };
        s.suppressed = 0;
        s.suppressed_sources.clear();
        s.overflow_suppressed = false;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn caps(anon: u32, cred: u32) -> UnauthCaps {
        UnauthCaps {
            anonymous_per_source: anon,
            anonymous_global: 10_000,
            credential_per_source: cred,
            credential_global: 10_000,
        }
    }

    #[test]
    fn caps_per_source_and_summarises() {
        let l = UnauthLimiter::new(caps(3, 3));
        let t = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!((0..3).all(|_| l.admit(a, "no_client_certificate", AuthClass::Anonymous, t)));
        assert!(!l.admit(a, "no_client_certificate", AuthClass::Anonymous, t));
        assert!(!l.admit(a, "protocol", AuthClass::Anonymous, t));
        assert!(
            l.admit(b, "no_client_certificate", AuthClass::Anonymous, t),
            "other sources are not affected"
        );
        assert_eq!(
            l.take_summary(),
            Some(UnauthSummary {
                suppressed: 2,
                sources: 1,
                by_reason: vec![("no_client_certificate", 1), ("protocol", 1)],
            })
        );
        assert_eq!(l.take_summary(), None);
        // A new window admits again.
        assert!(l.admit(a, "no_client_certificate", AuthClass::Anonymous, t + WINDOW));
    }

    /// NIST-001: anonymous noise up to (and past) its cap does not use up
    /// the credential budget.
    #[test]
    fn anonymous_noise_does_not_hide_credential_failures() {
        let l = UnauthLimiter::new(caps(2, 2));
        let t = Instant::now();
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
        for _ in 0..50 {
            let _ = l.admit(a, "no_client_certificate", AuthClass::Anonymous, t);
            let _ = l.admit(a, "handshake_timeout", AuthClass::Anonymous, t);
        }
        assert!(l.admit(a, "revoked", AuthClass::Credential, t));
        assert!(l.admit(a, "unknown_certificate", AuthClass::Credential, t));
        assert!(
            !l.admit(a, "operator_disabled", AuthClass::Credential, t),
            "its own cap applies"
        );
        let s = l.take_summary().unwrap();
        assert!(s.by_reason.contains(&("operator_disabled", 1)), "{s:?}");
    }

    /// SEC-012 / NIST-014: self-made certificates from many sources use
    /// the anonymous budget; a revoked certificate from our PKI is still
    /// recorded individually.
    #[test]
    fn self_made_certificates_cannot_use_up_the_credential_budget() {
        let l = UnauthLimiter::new(UnauthCaps {
            anonymous_per_source: 10,
            anonymous_global: 20,
            credential_per_source: 2,
            credential_global: 2,
        });
        let t = Instant::now();
        for i in 0..1000u32 {
            let ip = IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i));
            for reason in ["untrusted", "bad_certificate", "expired", "bad_eku"] {
                let _ = l.admit(ip, reason, AuthClass::of_handshake(false), t);
            }
        }
        let victim = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
        assert!(l.admit(victim, "revoked", AuthClass::of_handshake(true), t));
        let s = l.take_summary().unwrap();
        assert_eq!(s.suppressed, 4000 - 20);
        assert!(!s.by_reason.iter().any(|(r, _)| *r == "revoked"), "{s:?}");
    }

    #[test]
    fn http_refusals_classified() {
        assert_eq!(
            AuthClass::of_http(&AuthnFailure::NoCertificate),
            AuthClass::Anonymous
        );
        assert_eq!(
            AuthClass::of_http(&AuthnFailure::UnknownCertificate {
                presented: String::new()
            }),
            AuthClass::Credential
        );
    }

    /// SEC-004: every address in one IPv6 /64 is one source; another /64
    /// is another source.
    #[test]
    fn ipv6_counted_per_64() {
        let l = UnauthLimiter::new(caps(2, 2));
        let t = Instant::now();
        let mut admitted = 0;
        for i in 0..100u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, i, i, 0, i));
            if l.admit(ip, "no_client_certificate", AuthClass::Anonymous, t) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 2);
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 3, 0, 0, 0, 1));
        assert!(l.admit(other, "no_client_certificate", AuthClass::Anonymous, t));
        let s = l.take_summary().unwrap();
        assert_eq!(s.suppressed, 98);
        assert_eq!(s.sources, 1);
    }

    #[test]
    fn source_keys() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(source_key(v4), v4);
        let mapped = IpAddr::V6(Ipv4Addr::new(10, 1, 2, 3).to_ipv6_mapped());
        assert_eq!(source_key(mapped), v4);
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 5, 6, 7, 8, 9, 10));
        assert_eq!(
            source_key(v6),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 5, 6, 0, 0, 0, 0))
        );
    }

    /// SEC-004: a global ceiling per minute, whatever the number of
    /// sources; only the counters grow beyond it.
    #[test]
    fn global_ceiling() {
        let l = UnauthLimiter::new(UnauthCaps {
            anonymous_per_source: 10,
            anonymous_global: 25,
            credential_per_source: 10,
            credential_global: 5,
        });
        let t = Instant::now();
        let mut admitted = 0;
        for i in 0..1000u32 {
            if l.admit(
                IpAddr::V4(Ipv4Addr::from(i)),
                "protocol",
                AuthClass::Anonymous,
                t,
            ) {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 25);
        let cred = (0..100u32)
            .filter(|&i| {
                l.admit(
                    IpAddr::V4(Ipv4Addr::from(i)),
                    "revoked",
                    AuthClass::Credential,
                    t,
                )
            })
            .count();
        assert_eq!(cred, 5, "separate global ceiling");
        let s = l.take_summary().unwrap();
        assert_eq!(s.suppressed, 975 + 95);
        // The next minute admits again.
        assert!(l.admit(
            IpAddr::V4(Ipv4Addr::from(1u32)),
            "protocol",
            AuthClass::Anonymous,
            t + WINDOW
        ));
    }

    #[test]
    fn bounded_under_many_sources() {
        let l = UnauthLimiter::new(caps(1, 1));
        let t = Instant::now();
        for i in 0..(u32::try_from(MAX_TRACKED_SOURCES).unwrap() + 100) {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let _ = l.admit(ip, "protocol", AuthClass::Anonymous, t);
        }
        let s = l.state.lock().unwrap();
        assert!(s.anonymous.buckets.len() <= MAX_TRACKED_SOURCES);
    }
}
