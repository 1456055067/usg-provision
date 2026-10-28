//! ProxyDHCP service: classification through `usgp-dhcp`, the relay's
//! [`BootPolicy`], rate limits and audit events.
//!
//! [`DhcpService::handle`] is synchronous and performs no I/O; the socket
//! tasks in `lib.rs` feed it datagrams and send what it returns. Replies
//! are built only by `usgp_dhcp`, whose reply type has no address field,
//! so the relay can never assign an address (REQ-BOOT-010; decision 0003).
//!
//! Relayed requests are accepted from any relay agent (REQ-BOOT-002 as
//! written; owner answer Q-1). There is no relay-agent allowlist in M1.
//!
//! Every request is classified by where it came from ([`Origin`]), using
//! the UDP source and the receiving interface's subnet as well as
//! `giaddr`. Only requests from the boot segment itself use the
//! same-segment budget or can cause a broadcast there. A request with
//! `giaddr` = 0 sent to port 67 from another subnet is charged to the
//! routed budget when its `ciaddr` is its UDP source (the reply is then a
//! unicast to `ciaddr`:68, never a broadcast) and is otherwise dropped
//! (`off_segment_source`); one sent to port 4011 from another subnet is
//! charged to the routed budget (SC-5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - malformed input is
//   dropped silently (usgp-dhcp parser).
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - per-chaddr,
//   per-routed-source budgets, and separate global budgets for
//   same-segment and routed requests, classified by UDP source and
//   interface subnet; off-segment requests to 67 without giaddr dropped
//   unless they can be answered by unicast to their own source;
//   aggregated drop counters.
// - NIST 800-53: CM-7 (Least Functionality) - PXE clients only, one
//   architecture, never a lease.
// - NIST 800-53: AU-2 / AU-3 / AU-12 - every reply is an event; drops are
//   summarised.
// - NIST 800-53: IA-3 - NOT MET on TB-1: PXE devices are unauthenticated
//   by the standard; chaddr and GUID are logged as claimed labels only.
//   See docs/compliance/POAM.md (IA-3 on TB-1).
// - SPEC: specs/boot-network.md#REQ-BOOT-001, -002, -004, -005, -006,
//   -007, -010, -020, -021, -022, -044, -050, -051, -052, -070
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md

// POAM: SC-8 (Transmission Confidentiality and Integrity) - DHCP/PXE
// messages are cleartext and unauthenticated by the standard; nothing on
// TB-1 can be protected in transit. Integrity of what is served rests on
// SI-7 verification and device Secure Boot.
// POAM: SC-5 - (1) a sender that rotates chaddr can use up a global reply
// budget while the flood lasts: on the boot segment, the same-segment
// budget; off-segment, by rotating its source address (relayed with any
// giaddr, or to 4011), the routed budget. (2) giaddr is claimed: a host
// on the boot segment can set a non-local giaddr and use up the routed
// budget, and replies go to that giaddr (REQ-BOOT-002 Q-1). (3) A spoofed
// source address inside the interface's subnet counts as same-segment.
// Network mitigation: DHCP snooping / port security / IP source guard on
// the boot segment and ACLs on UDP 67/4011 that admit only known relay
// agents (docs/operations/relay.md).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use usgp_common::event::AuditEvent;
use usgp_dhcp::packet::is_unicast_host;
use usgp_dhcp::{
    BootPolicy, ClientArch, Decision, Destination, DropReason, Guid, ListenPort, MacAddr,
    ParseError, ReplyKind, ResponderContext, parse_request, respond,
};

use crate::config::{InterfaceConfig, Limits};
use crate::content::ContentStore;
use crate::events::{self, COMPONENT, Outcome};
use crate::limits::{BucketSpec, BucketTable, Counters, TokenBucket};
use crate::lock;
use crate::suppress::{FeedGate, Suppression, SuppressionList, Verdict};

/// How often a suppressed device is logged at most (plan section 7).
pub const SUPPRESSED_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// A datagram to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// Where to send it.
    pub destination: Destination,
    /// The encoded BOOTREPLY.
    pub bytes: Vec<u8>,
}

impl Outbound {
    /// The destination socket address.
    #[must_use]
    pub fn addr(&self) -> SocketAddrV4 {
        self.destination.addr()
    }
}

/// The relay's boot policy for one request.
struct Policy<'a> {
    program: Option<&'a [u8]>,
    list: &'a SuppressionList,
    feed: &'a FeedGate,
    locals: &'a [Ipv4Addr],
}

impl BootPolicy for Policy<'_> {
    fn boot_program(&self, arch: ClientArch) -> Option<&[u8]> {
        // Architecture 7 only in M1 (DEC-0004, REQ-BOOT-003/005).
        if arch == ClientArch::X64_UEFI {
            self.program
        } else {
            None
        }
    }

    fn is_suppressed(&self, mac: MacAddr, guid: Option<Guid>) -> bool {
        // The suppression file and the boot-policy stop list together
        // (REQ-BOOT-051, REQ-BOOT-067).
        Verdict::of(self.list, self.feed, mac, guid) != Verdict::Serve
    }

    fn is_local_address(&self, addr: Ipv4Addr) -> bool {
        self.locals.contains(&addr)
    }
}

/// Where a request came from, decided from how it arrived (UDP source,
/// receiving interface and port), not from `giaddr` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Not relayed, and sent from 0.0.0.0 or from an address in the
    /// receiving interface's subnet.
    SameSegment,
    /// Relayed (`giaddr` set), or sent from another subnet to port 4011,
    /// or to port 67 with `ciaddr` equal to the UDP source.
    Routed,
}

impl Origin {
    /// Stable label for audit events.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SameSegment => "same_segment",
            Self::Routed => "routed",
        }
    }
}

/// Classifies a request. `None` means drop it (`off_segment_source`).
///
/// For `giaddr` = 0 on port 67 from a source outside the interface's
/// subnet: if `ciaddr` is non-zero, a unicast host address and equal to
/// the UDP source, the request is `Routed`. Such a client already has an
/// address on another subnet (for example a follow-up REQUEST after an
/// offer that reached it through a relay agent, or a client on a
/// secondary subnet of the boot segment), and the reply is a unicast to
/// `ciaddr`:68 (pxe-dhcp.md §9 step 2, with the source check of
/// `usgp_dhcp`'s responder), so it cannot cause a broadcast. Which port
/// such a client uses for its follow-up to a proxy that answered on 67 is
/// an open point (proxy-dhcp.md §9), so port 67 is not refused for it.
/// Any other off-subnet giaddr-0 request on 67 is dropped: answering it
/// would mean a broadcast on the boot segment for a sender that is not on
/// it (project rule for SC-5, not a statement of pxe-dhcp.md §9).
///
/// A 0.0.0.0 source is a host that has no address yet; RFC 1122
/// §3.2.1.3 allows that source only while a host learns its address, so
/// it is taken as same-segment. With no known prefix
/// (`InterfaceConfig::prefix_len` = `None`) no other source is
/// same-segment (fail closed).
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection), SC-7 (Boundary
//   Protection) - the boot segment's budget and broadcasts are reserved
//   for senders on that segment.
// - SPEC: specs/boot-network.md#REQ-BOOT-001, #REQ-BOOT-002, #REQ-BOOT-044
#[must_use]
pub fn classify(
    iface: &InterfaceConfig,
    port: ListenPort,
    src: SocketAddrV4,
    giaddr: Ipv4Addr,
    ciaddr: Ipv4Addr,
) -> Option<Origin> {
    if !giaddr.is_unspecified() {
        return Some(Origin::Routed);
    }
    let ip = *src.ip();
    if ip.is_unspecified() || iface.on_segment(ip) {
        return Some(Origin::SameSegment);
    }
    match port {
        ListenPort::BootServer4011 => Some(Origin::Routed),
        ListenPort::Dhcp67 if ciaddr == ip && is_unicast_host(ip) => Some(Origin::Routed),
        ListenPort::Dhcp67 => None,
    }
}

#[derive(Debug)]
struct DhcpLimits {
    clients: BucketTable<MacAddr>,
    /// Routed requests, per UDP source (relay agent or routed client).
    relays: BucketTable<Ipv4Addr>,
    /// Same-segment requests, every interface.
    global: TokenBucket,
    /// Routed requests, every source.
    relayed_global: TokenBucket,
    suppressed_log: BucketTable<MacAddr>,
}

/// The ProxyDHCP service shared by every interface's DHCP sockets.
#[derive(Debug)]
pub struct DhcpService {
    content: Arc<ContentStore>,
    suppression: Arc<Suppression>,
    locals: Vec<Ipv4Addr>,
    limits: Mutex<DhcpLimits>,
    drops: Mutex<Counters>,
    shed: Arc<Mutex<Counters>>,
}

impl DhcpService {
    /// A service answering on `locals` (every configured interface
    /// address). `shed` collects `limits.shed` counts.
    #[must_use]
    pub fn new(
        content: Arc<ContentStore>,
        suppression: Arc<Suppression>,
        locals: Vec<Ipv4Addr>,
        limits: &Limits,
        shed: Arc<Mutex<Counters>>,
        now: Instant,
    ) -> Self {
        let per_sec = |n: u32| Duration::from_nanos(1_000_000_000 / u64::from(n.max(1)));
        let state = DhcpLimits {
            clients: BucketTable::new(
                BucketSpec {
                    burst: limits.dhcp_client_burst,
                    per_token: limits.dhcp_client_refill,
                },
                limits.tracked_clients,
            ),
            relays: BucketTable::new(
                BucketSpec {
                    burst: limits.dhcp_relay_burst,
                    per_token: per_sec(limits.dhcp_relay_per_sec),
                },
                limits.tracked_clients,
            ),
            global: TokenBucket::per_second(
                limits.dhcp_global_per_sec,
                limits.dhcp_global_per_sec,
                now,
            ),
            relayed_global: TokenBucket::per_second(
                limits.dhcp_relayed_global_per_sec,
                limits.dhcp_relayed_global_per_sec,
                now,
            ),
            suppressed_log: BucketTable::new(
                BucketSpec {
                    burst: 1,
                    per_token: SUPPRESSED_LOG_INTERVAL,
                },
                limits.tracked_clients,
            ),
        };
        Self {
            content,
            suppression,
            locals,
            limits: Mutex::new(state),
            drops: Mutex::new(Counters::default()),
            shed,
        }
    }

    /// Handles one datagram received on `iface` at `port` from `src`.
    /// Returns the reply to send, or `None` (silent drop).
    pub fn handle(
        &self,
        iface: &InterfaceConfig,
        port: ListenPort,
        src: SocketAddrV4,
        buf: &[u8],
        now: Instant,
    ) -> Option<Outbound> {
        let req = match parse_request(buf) {
            Ok(r) => r,
            Err(e) => {
                // Below the 300-octet BOOTP minimum: discarded and counted
                // on its own (pxe-dhcp.md §3.2; RFC 1542 §2.1).
                let label = match e {
                    ParseError::ShortMessage { .. } => e.label(),
                    _ => "malformed",
                };
                lock(&self.drops).bump(label);
                return None;
            }
        };
        let Some(origin) = classify(iface, port, src, req.giaddr, req.ciaddr) else {
            lock(&self.drops).bump("off_segment_source");
            return None;
        };
        let list = self.suppression.current();
        let feed = self.suppression.feed();
        let program = self.content.offerable_program();
        let policy = Policy {
            program: program.map(|p| p.as_bytes()),
            list: &list,
            feed: &feed,
            locals: &self.locals,
        };
        let ctx = ResponderContext {
            server_addr: iface.address,
            port,
            source: src,
        };
        let reply = match respond(&req, &ctx, &policy) {
            Decision::Reply(r) => r,
            Decision::Drop(reason) => {
                if reason == DropReason::Suppressed {
                    match Verdict::of(&list, &feed, req.chaddr, req.guid) {
                        Verdict::Stopped(job) => {
                            lock(&self.drops).bump("boot_stopped");
                            self.log_stopped(
                                iface,
                                src,
                                (req.chaddr, req.guid),
                                (job, feed.generation()),
                                now,
                            );
                        }
                        Verdict::PolicyUnavailable => {
                            lock(&self.drops).bump("boot_policy_unavailable");
                        }
                        Verdict::Suppressed | Verdict::Serve => {
                            lock(&self.drops).bump(reason.label());
                            self.log_suppressed(iface, src, req.chaddr, req.guid, now);
                        }
                    }
                } else {
                    lock(&self.drops).bump(reason.label());
                }
                return None;
            }
        };

        // Budgets are charged only for messages that would be answered, so
        // ordinary (non-PXE) DHCP traffic through a relay agent cannot use
        // up the PXE clients' budget. Routed and same-segment requests draw
        // on separate global budgets, chosen by `classify` from the UDP
        // source and the interface subnet, so senders on other subnets
        // cannot use up the boot segment's budget. The reverse direction is
        // not closed: a host on the segment can claim a giaddr (POAM SC-5
        // above).
        let relayed = !req.giaddr.is_unspecified();
        let routed = origin == Origin::Routed;
        {
            let mut l = lock(&self.limits);
            let shed = if routed && !l.relays.try_take(src.ip(), now) {
                Some("dhcp_relay_source")
            } else if !l.clients.try_take(&req.chaddr, now) {
                Some("dhcp_client")
            } else if routed && !l.relayed_global.try_take(now) {
                Some("dhcp_relayed_global")
            } else if !routed && !l.global.try_take(now) {
                Some("dhcp_global")
            } else {
                None
            };
            if let Some(label) = shed {
                drop(l);
                lock(&self.shed).bump(label);
                return None;
            }
        }

        let file = program.map(|p| p.as_str().to_owned()).unwrap_or_default();
        let mut detail = vec![
            ("xid", format!("{:#010x}", req.xid)),
            ("arch", reply.arch.0.to_string()),
            ("file", file),
            ("destination", reply.destination.label().to_owned()),
            ("destination_addr", reply.destination.addr().to_string()),
            ("listen_port", listen_port_label(port).to_owned()),
            ("relay_info_echoed", reply.relay_info_echoed.to_string()),
            ("yiaddr", reply_yiaddr(&reply.bytes)),
            ("origin", origin.label().to_owned()),
        ];
        if relayed {
            detail.push(("giaddr", req.giaddr.to_string()));
        }
        let name = match reply.kind {
            ReplyKind::Offer => events::DHCP_OFFER_SENT,
            ReplyKind::Ack => events::DHCP_ACK_SENT,
        };
        events::emit(AuditEvent {
            interface: Some(&iface.name),
            local_addr: Some(SocketAddr::V4(SocketAddrV4::new(
                iface.address,
                listen_port_number(port),
            ))),
            peer: Some(SocketAddr::V4(src)),
            claimed_mac: Some(req.chaddr.to_string()),
            claimed_guid: req.guid.map(|g| g.to_string()),
            detail: &detail,
            ..AuditEvent::new(name, Outcome::Success, COMPONENT)
        });
        Some(Outbound {
            destination: reply.destination,
            bytes: reply.bytes,
        })
    }

    fn log_suppressed(
        &self,
        iface: &InterfaceConfig,
        src: SocketAddrV4,
        mac: MacAddr,
        guid: Option<Guid>,
        now: Instant,
    ) {
        if !lock(&self.limits).suppressed_log.try_take(&mac, now) {
            return;
        }
        let detail = [("action", "no reply".to_owned())];
        events::emit(AuditEvent {
            interface: Some(&iface.name),
            peer: Some(SocketAddr::V4(src)),
            claimed_mac: Some(mac.to_string()),
            claimed_guid: guid.map(|g| g.to_string()),
            detail: &detail,
            ..AuditEvent::new(events::DHCP_SUPPRESSED, Outcome::Dropped, COMPONENT)
        });
    }

    /// `boot.device.stopped`, throttled per device like `dhcp.suppressed`
    /// (REQ-BOOT-067; plan section 7).
    fn log_stopped(
        &self,
        iface: &InterfaceConfig,
        src: SocketAddrV4,
        (mac, guid): (MacAddr, Option<Guid>),
        (job, generation): (usgp_proto::ids::JobId, Option<u64>),
        now: Instant,
    ) {
        if !lock(&self.limits).suppressed_log.try_take(&mac, now) {
            return;
        }
        let detail = [
            ("action", "no reply".to_owned()),
            ("job_id", job.to_string()),
            (
                "generation",
                generation.map_or_else(String::new, |g| g.to_string()),
            ),
        ];
        events::emit(AuditEvent {
            interface: Some(&iface.name),
            peer: Some(SocketAddr::V4(src)),
            claimed_mac: Some(mac.to_string()),
            claimed_guid: guid.map(|g| g.to_string()),
            detail: &detail,
            ..AuditEvent::new(events::BOOT_DEVICE_STOPPED, Outcome::Dropped, COMPONENT)
        });
    }

    /// Returns and clears the drop counts (for `dhcp.drop.summary`).
    pub fn take_drop_counts(&self) -> Vec<(&'static str, u64)> {
        lock(&self.drops).drain()
    }

    /// Current drop count for a [`DropReason`] label (tests, status).
    #[must_use]
    pub fn drop_count(&self, label: &str) -> u64 {
        lock(&self.drops).get(label)
    }
}

/// `yiaddr` as encoded in a BOOTREPLY (octets 16..20, RFC 2131 §2), read
/// from the bytes actually sent so the audit record shows what went on
/// the wire; `"unreadable"` if the reply is too short.
#[must_use]
pub fn reply_yiaddr(bytes: &[u8]) -> String {
    bytes
        .get(16..20)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
        .map_or_else(
            || "unreadable".to_owned(),
            |o| Ipv4Addr::from(o).to_string(),
        )
}

/// Stable label of a listening port.
#[must_use]
pub const fn listen_port_label(port: ListenPort) -> &'static str {
    match port {
        ListenPort::Dhcp67 => "67",
        ListenPort::BootServer4011 => "4011",
    }
}

/// UDP port number of a listening port.
#[must_use]
pub const fn listen_port_number(port: ListenPort) -> u16 {
    match port {
        ListenPort::Dhcp67 => usgp_dhcp::responder::SERVER_PORT,
        ListenPort::BootServer4011 => usgp_dhcp::responder::BOOT_SERVER_PORT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(prefix_len: Option<u8>) -> InterfaceConfig {
        InterfaceConfig {
            name: "relay0".to_owned(),
            address: Ipv4Addr::new(10, 20, 1, 2),
            prefix_len,
        }
    }

    #[test]
    fn classify_by_source_and_subnet() {
        let i = iface(Some(24));
        let s = |a: [u8; 4], p: u16| SocketAddrV4::new(Ipv4Addr::from(a), p);
        let none = Ipv4Addr::UNSPECIFIED;
        let agent = Ipv4Addr::new(10, 20, 2, 1);
        use ListenPort::{BootServer4011 as P4011, Dhcp67 as P67};
        // giaddr set: routed whatever the source.
        for src in [s([10, 20, 1, 9], 67), s([192, 0, 2, 1], 67), s([0; 4], 68)] {
            assert_eq!(classify(&i, P67, src, agent, none), Some(Origin::Routed));
        }
        // giaddr 0 from 0.0.0.0 or the subnet: same segment, both ports.
        for port in [P67, P4011] {
            assert_eq!(
                classify(&i, port, s([0; 4], 68), none, none),
                Some(Origin::SameSegment)
            );
            assert_eq!(
                classify(&i, port, s([10, 20, 1, 200], 68), none, none),
                Some(Origin::SameSegment)
            );
        }
        // giaddr 0 from another subnet: on 67 routed only when ciaddr is
        // the source (unicast reply to ciaddr:68), otherwise dropped; on
        // 4011 always routed.
        for src in [s([10, 20, 2, 50], 68), s([192, 0, 2, 9], 68)] {
            assert_eq!(classify(&i, P67, src, none, none), None);
            let other = Ipv4Addr::new(10, 20, 2, 99);
            assert_eq!(classify(&i, P67, src, none, other), None);
            assert_eq!(
                classify(&i, P67, src, none, *src.ip()),
                Some(Origin::Routed)
            );
            assert_eq!(classify(&i, P4011, src, none, none), Some(Origin::Routed));
        }
        // Never for a source that is not a unicast host address.
        for a in [[127, 0, 0, 1], [224, 0, 0, 1], [255, 255, 255, 255]] {
            let ip = Ipv4Addr::from(a);
            assert_eq!(classify(&i, P67, s(a, 68), none, ip), None);
        }
        // Prefix unknown: only 0.0.0.0 is same segment (fail closed).
        let u = iface(None);
        assert_eq!(
            classify(&u, P67, s([0; 4], 68), none, none),
            Some(Origin::SameSegment)
        );
        assert_eq!(classify(&u, P67, s([10, 20, 1, 200], 68), none, none), None);
        let own = Ipv4Addr::new(10, 20, 1, 200);
        assert_eq!(
            classify(&u, P67, s([10, 20, 1, 200], 68), none, own),
            Some(Origin::Routed)
        );
        assert_eq!(
            classify(&u, P4011, s([10, 20, 1, 200], 68), none, none),
            Some(Origin::Routed)
        );
    }

    #[test]
    fn yiaddr_read_from_reply_bytes() {
        let mut b = vec![0u8; 300];
        assert_eq!(reply_yiaddr(&b), "0.0.0.0");
        if let Some(y) = b.get_mut(16..20) {
            y.copy_from_slice(&[10, 20, 1, 77]);
        }
        assert_eq!(reply_yiaddr(&b), "10.20.1.77");
        assert_eq!(reply_yiaddr(&[0u8; 19]), "unreadable");
        assert_eq!(reply_yiaddr(&[]), "unreadable");
    }
}
