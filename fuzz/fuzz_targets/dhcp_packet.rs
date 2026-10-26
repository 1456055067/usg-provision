//! Fuzz target `dhcp_packet`: arbitrary bytes as an incoming DHCP/PXE
//! message.
//!
//! Every input goes through `parse_request`; a parsed request is answered
//! by `respond` under a fixed policy in three receive contexts (port 67
//! broadcast, port 67 from a relay agent, port 4011 unicast). Every reply
//! must hold the ProxyDHCP invariants (plan §10.4): it re-parses as a
//! BOOTREPLY, `yiaddr` is 0, no lease, router or subnet option, xid and
//! chaddr echoed, size within the client's limit, option 82 echoed
//! byte-for-byte or not at all.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-006 (drop malformed, never panic),
//   #REQ-BOOT-010 (never offer an address or lease options),
//   #REQ-BOOT-022 (siaddr and option 54 are this server)
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md
// - RFC 2131 §4.1 - reply addressing; RFC 3046 §2.2 - option 82 echo

use std::net::{Ipv4Addr, SocketAddrV4};

use libfuzzer_sys::fuzz_target;
use usgp_dhcp::reply::{FORBIDDEN_REPLY_OPTIONS, inspect_reply, reply_size_limit};
use usgp_dhcp::{
    BootPolicy, ClientArch, Decision, Destination, DropReason, Guid, ListenPort, MacAddr,
    ReplyKind, Request, ResponderContext, handle, parse_request, respond,
};

const SERVER: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);
const OTHER_LOCAL: Ipv4Addr = Ipv4Addr::new(10, 20, 9, 2);
const BOOT_FILE: &[u8] = b"usgp-test-payload.efi";

/// Fixed policy: content for x64 UEFI only, nothing suppressed, two local
/// addresses.
struct Policy;

impl BootPolicy for Policy {
    fn boot_program(&self, arch: ClientArch) -> Option<&[u8]> {
        (arch == ClientArch::X64_UEFI).then_some(BOOT_FILE)
    }
    fn is_suppressed(&self, _mac: MacAddr, _guid: Option<Guid>) -> bool {
        false
    }
    fn is_local_address(&self, addr: Ipv4Addr) -> bool {
        addr == SERVER || addr == OTHER_LOCAL
    }
}

const CONTEXTS: [ResponderContext; 3] = [
    ResponderContext {
        server_addr: SERVER,
        port: ListenPort::Dhcp67,
        source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
    },
    ResponderContext {
        server_addr: SERVER,
        port: ListenPort::Dhcp67,
        source: SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 1), 67),
    },
    ResponderContext {
        server_addr: SERVER,
        port: ListenPort::BootServer4011,
        source: SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 50), 68),
    },
];

fn check_reply(req: &Request<'_>, ctx: &ResponderContext, d: &Decision) {
    let Decision::Reply(r) = d else { return };
    let v = match inspect_reply(&r.bytes) {
        Ok(v) => v,
        Err(e) => panic!("reply does not re-parse as BOOTREPLY: {e:?}"),
    };
    // REQ-BOOT-010 / decision 0003: never an address, never lease options.
    assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED, "yiaddr not 0");
    for c in FORBIDDEN_REPLY_OPTIONS {
        assert!(!v.codes.contains(c), "forbidden option {c} in reply");
    }
    // Echoed identity.
    assert_eq!(v.xid, req.xid, "xid not echoed");
    assert_eq!(v.chaddr, req.chaddr.octets(), "chaddr not echoed");
    // Size limit.
    let limit = reply_size_limit(req.max_message_size);
    assert!(
        r.bytes.len() <= limit,
        "reply {} > limit {limit}",
        r.bytes.len()
    );
    // Message type matches the reply kind.
    let want = match r.kind {
        ReplyKind::Offer => 2,
        ReplyKind::Ack => 5,
    };
    assert_eq!(v.msg_type, Some(want), "option 53 does not match kind");
    // REQ-BOOT-022: the server is this interface.
    assert_eq!(v.siaddr, ctx.server_addr, "siaddr not this server");
    assert_eq!(
        v.server_id,
        Some(ctx.server_addr),
        "option 54 not this server"
    );
    // Option 82: byte-identical echo or absent; never invented.
    match (req.relay_info.as_deref(), v.relay_info) {
        (Some(a), Some(b)) => assert_eq!(a, b, "option 82 altered"),
        (None, Some(_)) => panic!("option 82 in reply but not in request"),
        _ => {}
    }
    assert_eq!(
        r.relay_info_echoed,
        v.relay_info.is_some(),
        "relay_info_echoed flag disagrees with reply"
    );
    // Addressing (RFC 2131 §4.1): a unicast destination is never a
    // broadcast, multicast or unspecified address.
    match r.destination {
        Destination::Broadcast68 => {
            assert_eq!(ctx.port, ListenPort::Dhcp67, "broadcast reply on 4011");
            assert!(req.giaddr.is_unspecified(), "broadcast for relayed request");
        }
        Destination::RelayAgent(a) | Destination::Unicast(a) => {
            let ip = *a.ip();
            assert!(
                !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast(),
                "unicast reply to {ip}"
            );
            assert_ne!(a.port(), 0, "reply to port 0");
        }
    }
    if ctx.port == ListenPort::Dhcp67 && !req.giaddr.is_unspecified() {
        assert_eq!(
            r.destination,
            Destination::RelayAgent(SocketAddrV4::new(req.giaddr, 67)),
            "relayed request not answered to the relay agent"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let parsed = parse_request(data);
    let Some(first) = CONTEXTS.first() else {
        return;
    };
    let via_handle = handle(data, first, &Policy);
    let req = match parsed {
        Ok(req) => req,
        Err(e) => {
            assert_eq!(via_handle, Decision::Drop(DropReason::Malformed(e)));
            return;
        }
    };
    for ctx in &CONTEXTS {
        let d = respond(&req, ctx, &Policy);
        check_reply(&req, ctx, &d);
    }
    assert_eq!(
        via_handle,
        respond(&req, first, &Policy),
        "handle != respond"
    );
});
