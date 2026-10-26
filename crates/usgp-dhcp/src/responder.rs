//! ProxyDHCP decision logic: classify a parsed request, decide whether it
//! is for this server, build the reply, and choose where to send it.
//!
//! Sans-IO: the caller supplies the receiving port, the source address and
//! a [`BootPolicy`]; this module returns a [`Decision`] and never touches a
//! socket.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - hops, giaddr and
//   source checks; silent drop on every failure.
// - NIST 800-53: CM-7 (Least Functionality) - answers PXE clients of a
//   supported architecture only; never assigns addresses.
// - SPEC: specs/boot-network.md#REQ-BOOT-001, #REQ-BOOT-002, #REQ-BOOT-003,
//   #REQ-BOOT-004, #REQ-BOOT-005, #REQ-BOOT-006, #REQ-BOOT-010,
//   #REQ-BOOT-012, #REQ-BOOT-020, #REQ-BOOT-021, #REQ-BOOT-022,
//   #REQ-BOOT-051, #REQ-BOOT-052
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md, 0004 (arch 7 only)
// - RFC 2131 §4.1 - reply addressing; RFC 1542 §4.1.1 (hops), §5.4 (flags)
// - draft-henry-remote-boot-protocol-00 §3.3.1, §3.3.2 - boot-server
//   requests and the tag-71 reply

use core::net::{Ipv4Addr, SocketAddrV4};

use crate::error::ParseError;
use crate::ident::{ClientArch, Guid, MacAddr};
use crate::packet::{BootItem, MAX_HOPS, MessageType, Request, is_unicast_host};
use crate::reply::{BuildError, ProxyReply, ReplyKind, reply_size_limit};

/// DHCP server port (RFC 2131 §4.1).
pub const SERVER_PORT: u16 = 67;
/// DHCP client port (RFC 2131 §4.1).
pub const CLIENT_PORT: u16 = 68;
/// PXE boot-server / ProxyDHCP alternate port (draft-henry §3.3.1).
pub const BOOT_SERVER_PORT: u16 = 4011;

/// The port a request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenPort {
    /// UDP 67.
    Dhcp67,
    /// UDP 4011.
    BootServer4011,
}

/// Facts about where a request arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponderContext {
    /// The receiving interface's configured address (becomes `siaddr` and
    /// option 54; REQ-BOOT-022).
    pub server_addr: Ipv4Addr,
    /// Receiving port.
    pub port: ListenPort,
    /// UDP source of the datagram.
    pub source: SocketAddrV4,
}

/// The relay's view of content, suppression and its own addresses.
pub trait BootPolicy {
    /// The verified boot program name for `arch`, or `None` if the content
    /// is missing (REQ-BOOT-052: no offer for missing content).
    fn boot_program(&self, arch: ClientArch) -> Option<&[u8]>;

    /// Whether the operator suppressed this device (REQ-BOOT-050). The
    /// identifiers are claimed, not authenticated (REQ-BOOT-045).
    fn is_suppressed(&self, mac: MacAddr, guid: Option<Guid>) -> bool;

    /// Whether `addr` is one of this relay's own interface addresses. A
    /// relayed request whose `giaddr` is ours is dropped (plan §6).
    fn is_local_address(&self, addr: Ipv4Addr) -> bool;
}

/// Where to send a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// The relay agent: `giaddr`, port 67.
    RelayAgent(SocketAddrV4),
    /// A unicast address: `ciaddr`:68, or the 4011 request's source.
    Unicast(SocketAddrV4),
    /// Limited broadcast 255.255.255.255, port 68.
    Broadcast68,
}

impl Destination {
    /// The socket address to send to.
    #[must_use]
    pub fn addr(&self) -> SocketAddrV4 {
        match self {
            Self::RelayAgent(a) | Self::Unicast(a) => *a,
            Self::Broadcast68 => SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT),
        }
    }

    /// Stable label for audit events.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::RelayAgent(_) => "relay_agent",
            Self::Unicast(_) => "unicast",
            Self::Broadcast68 => "broadcast",
        }
    }
}

/// A reply to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// Where to send it.
    pub destination: Destination,
    /// The encoded DHCP message.
    pub bytes: Vec<u8>,
    /// OFFER or ACK.
    pub kind: ReplyKind,
    /// The architecture the boot program was chosen for.
    pub arch: ClientArch,
    /// Whether option 82 was echoed.
    pub relay_info_echoed: bool,
}

/// Why a request got no reply. Every drop is silent (REQ-BOOT-006).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DropReason {
    /// The message failed parsing (set by callers of
    /// [`crate::parse_request`]; see also [`handle`]).
    Malformed(ParseError),
    /// Option 60 does not identify a PXE client (REQ-BOOT-004).
    NotPxeClient,
    /// No listed architecture is supported (REQ-BOOT-005).
    UnsupportedArch,
    /// The device is suppressed (REQ-BOOT-051).
    Suppressed,
    /// No verified boot program for the architecture (REQ-BOOT-052).
    MissingContent,
    /// A REQUEST that is not addressed to this server (site lease
    /// exchange, or a renewal).
    ForOtherServer,
    /// A tag-71 boot item other than type 0, layer 0, no credentials.
    UnsupportedBootItem,
    /// `giaddr` is not a unicast address, or is one of ours.
    BadGiaddr,
    /// `hops` above 16 (RFC 1542 §4.1.1).
    TooManyHops,
    /// A DISCOVER arrived on port 4011, where only REQUESTs are expected.
    DiscoverOnBootServerPort,
    /// The UDP source of a 4011 request cannot be replied to (not a unicast
    /// host address, or port 0).
    BadSource,
    /// The reply could not be built within the size limit.
    ReplyUnbuildable(BuildError),
}

impl DropReason {
    /// Stable, low-cardinality label for drop counters (`dhcp.drop.summary`).
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Malformed(_) => "malformed",
            Self::NotPxeClient => "not_pxe_client",
            Self::UnsupportedArch => "unsupported_arch",
            Self::Suppressed => "suppressed",
            Self::MissingContent => "missing_content",
            Self::ForOtherServer => "for_other_server",
            Self::UnsupportedBootItem => "unsupported_boot_item",
            Self::BadGiaddr => "bad_giaddr",
            Self::TooManyHops => "too_many_hops",
            Self::DiscoverOnBootServerPort => "discover_on_4011",
            Self::BadSource => "bad_source",
            Self::ReplyUnbuildable(_) => "reply_unbuildable",
        }
    }
}

/// The outcome for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Send this reply.
    Reply(Reply),
    /// Send nothing.
    Drop(DropReason),
}

/// Parses `buf` and decides on it in one step.
#[must_use]
pub fn handle(buf: &[u8], ctx: &ResponderContext, policy: &impl BootPolicy) -> Decision {
    match crate::packet::parse_request(buf) {
        Ok(req) => respond(&req, ctx, policy),
        Err(e) => Decision::Drop(DropReason::Malformed(e)),
    }
}

/// Decides how to answer a parsed request.
///
/// Order of checks: hops; giaddr; PXE vendor class; architecture; message
/// type and boot item; "is this REQUEST for us"; suppression; content;
/// reply addressing; reply encoding.
#[must_use]
pub fn respond(req: &Request<'_>, ctx: &ResponderContext, policy: &impl BootPolicy) -> Decision {
    match decide(req, ctx, policy) {
        Ok(r) => Decision::Reply(r),
        Err(d) => Decision::Drop(d),
    }
}

fn decide(
    req: &Request<'_>,
    ctx: &ResponderContext,
    policy: &impl BootPolicy,
) -> Result<Reply, DropReason> {
    if req.hops > MAX_HOPS {
        return Err(DropReason::TooManyHops);
    }
    let relayed = !req.giaddr.is_unspecified();
    if relayed && (!is_unicast_host(req.giaddr) || policy.is_local_address(req.giaddr)) {
        return Err(DropReason::BadGiaddr);
    }
    if req.giaddr == ctx.server_addr {
        return Err(DropReason::BadGiaddr);
    }
    if !req.is_pxe_client() {
        return Err(DropReason::NotPxeClient);
    }
    let arch = req
        .arch
        .first_supported()
        .ok_or(DropReason::UnsupportedArch)?;

    let (kind, boot_item) = match req.msg_type {
        MessageType::Discover => {
            if ctx.port == ListenPort::BootServer4011 {
                return Err(DropReason::DiscoverOnBootServerPort);
            }
            (ReplyKind::Offer, None)
        }
        MessageType::Request => {
            let item = req.boot_item;
            if item.is_some_and(|i| i != BootItem::DEFAULT) {
                return Err(DropReason::UnsupportedBootItem);
            }
            if !request_is_for_us(req, ctx) {
                return Err(DropReason::ForOtherServer);
            }
            (ReplyKind::Ack, item)
        }
    };

    if policy.is_suppressed(req.chaddr, req.guid) {
        return Err(DropReason::Suppressed);
    }
    let boot_file = policy
        .boot_program(arch)
        .ok_or(DropReason::MissingContent)?;
    let destination = destination(req, ctx)?;

    let encoded = ProxyReply {
        kind,
        xid: req.xid,
        flags: req.flags,
        giaddr: req.giaddr,
        chaddr: req.chaddr,
        server_addr: ctx.server_addr,
        boot_file,
        arch,
        client_ndi: req.ndi,
        client_guid: req.guid,
        boot_item,
        relay_info: req.relay_info.as_deref(),
    }
    .encode(reply_size_limit(req.max_message_size))
    .map_err(DropReason::ReplyUnbuildable)?;

    Ok(Reply {
        destination,
        bytes: encoded.bytes,
        kind,
        arch,
        relay_info_echoed: encoded.relay_info_echoed,
    })
}

/// A REQUEST is for us if it arrived on 4011, names us in option 54, or
/// (naming no server) carries an acceptable tag 71. A REQUEST naming
/// another server is the site lease exchange (plan §1.1).
fn request_is_for_us(req: &Request<'_>, ctx: &ResponderContext) -> bool {
    if ctx.port == ListenPort::BootServer4011 {
        return true;
    }
    match req.server_id {
        Some(id) => id == ctx.server_addr,
        None => req.boot_item.is_some(),
    }
}

/// Reply addressing (pxe-dhcp.md §9; RFC 2131 §4.1). There is no `yiaddr`
/// case: a proxy reply never carries an address.
///
/// `ciaddr` is a claimed header field. A same-segment request on 67 is
/// answered at `ciaddr`:68 only when `ciaddr` is also the datagram's UDP
/// source address. Otherwise the reply is broadcast to port 68, where the
/// client still receives it (it matches on xid and chaddr). This is a
/// deliberate security departure from pxe-dhcp.md §9 step 2, which says to
/// unicast to any non-zero `ciaddr`: it stops a requester aiming replies at
/// a third host (SC-5). It is not the step 4 fallback, which covers only
/// the `yiaddr`/`chaddr` unicast. Relayed replies still go to `giaddr`,
/// which has no such check (REQ-BOOT-002 Q-1).
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - no reflection to a
//   claimed address; SI-10 (Information Input Validation)
// - SPEC: specs/boot-network.md#REQ-BOOT-020
// - RFC 2131 §4.1; specs/standards/pxe-dhcp.md §9 steps 1 and 3 followed;
//   step 2 departed from as described above (recorded deviation)
fn destination(req: &Request<'_>, ctx: &ResponderContext) -> Result<Destination, DropReason> {
    if ctx.port == ListenPort::BootServer4011 {
        let src = ctx.source;
        if !is_unicast_host(*src.ip()) || src.port() == 0 {
            return Err(DropReason::BadSource);
        }
        return Ok(Destination::Unicast(src));
    }
    if !req.giaddr.is_unspecified() {
        return Ok(Destination::RelayAgent(SocketAddrV4::new(
            req.giaddr,
            SERVER_PORT,
        )));
    }
    // Departure from pxe-dhcp.md §9 step 2 for SC-5: unicast to ciaddr
    // only when it is the UDP source; otherwise broadcast (port 68 still
    // reaches the client).
    if !req.ciaddr.is_unspecified() && req.ciaddr == *ctx.source.ip() {
        return Ok(Destination::Unicast(SocketAddrV4::new(
            req.ciaddr,
            CLIENT_PORT,
        )));
    }
    Ok(Destination::Broadcast68)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::craft::RequestBuilder;
    use crate::packet::{FLAG_BROADCAST, parse_request};
    use crate::reply::inspect_reply;

    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);
    const OTHER_LOCAL: Ipv4Addr = Ipv4Addr::new(10, 20, 9, 2);

    struct Policy {
        program: Option<&'static [u8]>,
        suppressed_mac: Option<MacAddr>,
        suppressed_guid: Option<Guid>,
    }

    impl Default for Policy {
        fn default() -> Self {
            Self {
                program: Some(b"usgp-test-payload.efi"),
                suppressed_mac: None,
                suppressed_guid: None,
            }
        }
    }

    impl BootPolicy for Policy {
        fn boot_program(&self, arch: ClientArch) -> Option<&[u8]> {
            if arch == ClientArch::X64_UEFI {
                self.program
            } else {
                None
            }
        }
        fn is_suppressed(&self, mac: MacAddr, guid: Option<Guid>) -> bool {
            self.suppressed_mac == Some(mac) || (guid.is_some() && self.suppressed_guid == guid)
        }
        fn is_local_address(&self, addr: Ipv4Addr) -> bool {
            addr == SERVER || addr == OTHER_LOCAL
        }
    }

    fn ctx67() -> ResponderContext {
        ResponderContext {
            server_addr: SERVER,
            port: ListenPort::Dhcp67,
            source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
        }
    }

    fn ctx4011(src: SocketAddrV4) -> ResponderContext {
        ResponderContext {
            server_addr: SERVER,
            port: ListenPort::BootServer4011,
            source: src,
        }
    }

    fn run(b: &RequestBuilder, ctx: &ResponderContext, p: &Policy) -> Decision {
        let bytes = b.build();
        let req = parse_request(&bytes).unwrap();
        respond(&req, ctx, p)
    }

    fn reply(d: Decision) -> Reply {
        match d {
            Decision::Reply(r) => r,
            Decision::Drop(why) => panic!("dropped: {why:?}"),
        }
    }

    fn dropped(d: Decision) -> DropReason {
        match d {
            Decision::Drop(why) => why,
            Decision::Reply(r) => panic!("replied: {r:?}"),
        }
    }

    #[test]
    fn discover_same_segment_broadcast() {
        let r = reply(run(
            &RequestBuilder::pxe_discover(),
            &ctx67(),
            &Policy::default(),
        ));
        assert_eq!(r.destination, Destination::Broadcast68);
        assert_eq!(
            r.destination.addr(),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 68)
        );
        assert_eq!(r.kind, ReplyKind::Offer);
        assert_eq!(r.arch, ClientArch::X64_UEFI);
    }

    #[test]
    fn discover_offer_without_address() {
        let r = reply(run(
            &RequestBuilder::pxe_discover(),
            &ctx67(),
            &Policy::default(),
        ));
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(v.msg_type, Some(2));
    }

    #[test]
    fn arch7_gets_program() {
        let r = reply(run(
            &RequestBuilder::pxe_discover(),
            &ctx67(),
            &Policy::default(),
        ));
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.file, b"usgp-test-payload.efi");
    }

    #[test]
    fn siaddr_equals_interface_address() {
        let r = reply(run(
            &RequestBuilder::pxe_discover(),
            &ctx67(),
            &Policy::default(),
        ));
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.siaddr, SERVER);
        assert_eq!(v.server_id, Some(SERVER));
    }

    #[test]
    fn relayed_reply_to_giaddr_67() {
        let gi = Ipv4Addr::new(10, 20, 2, 1);
        let b = RequestBuilder::pxe_discover().giaddr(gi).hops(1);
        let r = reply(run(&b, &ctx67(), &Policy::default()));
        assert_eq!(
            r.destination,
            Destination::RelayAgent(SocketAddrV4::new(gi, 67))
        );
        assert_eq!(inspect_reply(&r.bytes).unwrap().giaddr, gi);
    }

    fn ctx67_from(src: SocketAddrV4) -> ResponderContext {
        ResponderContext {
            source: src,
            ..ctx67()
        }
    }

    #[test]
    fn ciaddr_unicast_68() {
        let ci = Ipv4Addr::new(10, 20, 1, 50);
        let b = RequestBuilder::pxe_discover().ciaddr(ci);
        let r = reply(run(
            &b,
            &ctx67_from(SocketAddrV4::new(ci, 68)),
            &Policy::default(),
        ));
        assert_eq!(
            r.destination,
            Destination::Unicast(SocketAddrV4::new(ci, 68))
        );
        // The source port does not matter, only the address.
        let r = reply(run(
            &b,
            &ctx67_from(SocketAddrV4::new(ci, 40000)),
            &Policy::default(),
        ));
        assert_eq!(
            r.destination,
            Destination::Unicast(SocketAddrV4::new(ci, 68))
        );
    }

    #[test]
    fn ciaddr_not_source_broadcast() {
        // A ciaddr that is not the sender's own address is never
        // used as a unicast target.
        let victim = Ipv4Addr::new(10, 20, 1, 50);
        for src in [
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
            SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 51), 68),
            SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 68),
        ] {
            for b in [
                RequestBuilder::pxe_discover().ciaddr(victim),
                RequestBuilder::pxe_request()
                    .ciaddr(victim)
                    .set_option(54, SERVER.octets().to_vec()),
            ] {
                let r = reply(run(&b, &ctx67_from(src), &Policy::default()));
                assert_eq!(r.destination, Destination::Broadcast68, "{src}");
                assert_eq!(r.destination.label(), "broadcast");
            }
        }
    }

    #[test]
    fn giaddr_wins_over_ciaddr_source_match() {
        let gi = Ipv4Addr::new(10, 20, 2, 1);
        let ci = Ipv4Addr::new(10, 20, 2, 50);
        let b = RequestBuilder::pxe_discover().giaddr(gi).hops(1).ciaddr(ci);
        let r = reply(run(
            &b,
            &ctx67_from(SocketAddrV4::new(ci, 68)),
            &Policy::default(),
        ));
        assert_eq!(
            r.destination,
            Destination::RelayAgent(SocketAddrV4::new(gi, 67))
        );
    }

    #[test]
    fn broadcast_flag_preserved() {
        for flags in [0u16, FLAG_BROADCAST] {
            let b = RequestBuilder::pxe_discover()
                .flags(flags)
                .giaddr(Ipv4Addr::new(10, 20, 2, 1));
            let r = reply(run(&b, &ctx67(), &Policy::default()));
            assert_eq!(inspect_reply(&r.bytes).unwrap().flags, flags);
        }
    }

    #[test]
    fn non_pxe_vendor_class_dropped() {
        // An arbitrary non-PXE class string (RFC 2132 §9.13).
        let b = RequestBuilder::pxe_discover().set_option(60, b"usgp-non-pxe-client".to_vec());
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::NotPxeClient
        );
    }

    #[test]
    fn missing_option60_dropped() {
        let b = RequestBuilder::pxe_discover().without(60);
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::NotPxeClient
        );
    }

    #[test]
    fn arch_list_without_7_dropped() {
        let b = RequestBuilder::pxe_discover()
            .set_option(60, b"PXEClient:Arch:00000:UNDI:002001".to_vec())
            .set_option(93, vec![0, 0]);
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::UnsupportedArch
        );
        let b = RequestBuilder::pxe_discover()
            .without(93)
            .set_option(60, b"PXEClient".to_vec());
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::UnsupportedArch
        );
    }

    #[test]
    fn multi_arch_with_7_served() {
        let b = RequestBuilder::pxe_discover().set_option(93, vec![0, 0, 0, 7, 0, 11]);
        let r = reply(run(&b, &ctx67(), &Policy::default()));
        assert_eq!(r.arch, ClientArch::X64_UEFI);
        let v = inspect_reply(&r.bytes).unwrap();
        assert!(v.codes.contains(93));
    }

    #[test]
    fn suppressed_no_reply() {
        let base = RequestBuilder::pxe_discover();
        let bytes = base.build();
        let req = parse_request(&bytes).unwrap();
        let by_mac = Policy {
            suppressed_mac: Some(req.chaddr),
            ..Policy::default()
        };
        assert_eq!(
            dropped(respond(&req, &ctx67(), &by_mac)),
            DropReason::Suppressed
        );
        let by_guid = Policy {
            suppressed_guid: req.guid,
            ..Policy::default()
        };
        assert_eq!(
            dropped(respond(&req, &ctx67(), &by_guid)),
            DropReason::Suppressed
        );
    }

    #[test]
    fn missing_content_no_offer() {
        let p = Policy {
            program: None,
            ..Policy::default()
        };
        assert_eq!(
            dropped(run(&RequestBuilder::pxe_discover(), &ctx67(), &p)),
            DropReason::MissingContent
        );
    }

    #[test]
    fn request_naming_us_gets_ack() {
        let b = RequestBuilder::pxe_request().set_option(54, SERVER.octets().to_vec());
        let r = reply(run(&b, &ctx67(), &Policy::default()));
        assert_eq!(r.kind, ReplyKind::Ack);
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.msg_type, Some(5));
        assert_eq!(v.vendor_specific, None);
    }

    #[test]
    fn request_naming_other_server_ignored() {
        let b = RequestBuilder::pxe_request().set_option(54, vec![10, 20, 1, 3]);
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::ForOtherServer
        );
        // No server id, no tag 71 (e.g. a renewal) on 67: not for us.
        let b = RequestBuilder::pxe_request();
        assert_eq!(
            dropped(run(&b, &ctx67(), &Policy::default())),
            DropReason::ForOtherServer
        );
    }

    #[test]
    fn tag71_request_gets_ack_with_tag71() {
        let b = RequestBuilder::pxe_request().option(43, vec![71, 4, 0, 0, 0, 0, 255]);
        let r = reply(run(&b, &ctx67(), &Policy::default()));
        let v = inspect_reply(&r.bytes).unwrap();
        assert_eq!(v.msg_type, Some(5));
        assert_eq!(v.vendor_specific, Some(&[71, 4, 0, 0, 0, 0, 255][..]));
    }

    #[test]
    fn tag71_unsupported_items_dropped() {
        for item in [[0u8, 1, 0, 0], [0, 0, 0, 1], [0, 0, 0x80, 0]] {
            let mut d = vec![71, 4];
            d.extend_from_slice(&item);
            d.push(255);
            let b = RequestBuilder::pxe_request().option(43, d);
            assert_eq!(
                dropped(run(&b, &ctx67(), &Policy::default())),
                DropReason::UnsupportedBootItem
            );
        }
    }

    #[test]
    fn request_on_4011_answered_to_source() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 77), 4011);
        let b = RequestBuilder::pxe_request().ciaddr(Ipv4Addr::new(10, 20, 2, 77));
        let r = reply(run(&b, &ctx4011(src), &Policy::default()));
        assert_eq!(r.destination, Destination::Unicast(src));
        assert_eq!(r.kind, ReplyKind::Ack);
    }

    #[test]
    fn request_on_4011_bad_source_dropped() {
        for src in [
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
            SocketAddrV4::new(Ipv4Addr::BROADCAST, 68),
            SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 77), 0),
        ] {
            let b = RequestBuilder::pxe_request();
            assert_eq!(
                dropped(run(&b, &ctx4011(src), &Policy::default())),
                DropReason::BadSource
            );
        }
    }

    #[test]
    fn discover_on_4011_dropped() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 77), 68);
        assert_eq!(
            dropped(run(
                &RequestBuilder::pxe_discover(),
                &ctx4011(src),
                &Policy::default()
            )),
            DropReason::DiscoverOnBootServerPort
        );
    }

    #[test]
    fn hops_limit() {
        let gi = Ipv4Addr::new(10, 20, 2, 1);
        let ok = RequestBuilder::pxe_discover().giaddr(gi).hops(16);
        reply(run(&ok, &ctx67(), &Policy::default()));
        let bad = RequestBuilder::pxe_discover().giaddr(gi).hops(17);
        assert_eq!(
            dropped(run(&bad, &ctx67(), &Policy::default())),
            DropReason::TooManyHops
        );
    }

    #[test]
    fn giaddr_rules() {
        for gi in [
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::LOCALHOST,
            SERVER,
            OTHER_LOCAL,
        ] {
            let b = RequestBuilder::pxe_discover().giaddr(gi);
            assert_eq!(
                dropped(run(&b, &ctx67(), &Policy::default())),
                DropReason::BadGiaddr,
                "{gi}"
            );
        }
    }

    #[test]
    fn handle_maps_parse_errors() {
        assert_eq!(
            handle(&[], &ctx67(), &Policy::default()),
            Decision::Drop(DropReason::Malformed(ParseError::TooShort { len: 0 }))
        );
    }

    #[test]
    fn labels_are_distinct() {
        let all = [
            DropReason::Malformed(ParseError::MissingEnd),
            DropReason::NotPxeClient,
            DropReason::UnsupportedArch,
            DropReason::Suppressed,
            DropReason::MissingContent,
            DropReason::ForOtherServer,
            DropReason::UnsupportedBootItem,
            DropReason::BadGiaddr,
            DropReason::TooManyHops,
            DropReason::DiscoverOnBootServerPort,
            DropReason::BadSource,
            DropReason::ReplyUnbuildable(BuildError::TooLarge),
        ];
        let mut labels: Vec<_> = all.iter().map(DropReason::label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), all.len());
    }
}
