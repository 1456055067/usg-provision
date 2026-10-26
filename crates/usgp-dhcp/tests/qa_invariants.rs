//! QA gap tests (qa-engineer, M1): reply invariants stronger than the
//! forbidden-option list.
//!
//! The negative suite and the fuzz target check that options 1, 3, 51, 58
//! and 59 never appear. These tests check the positive form of
//! REQ-BOOT-010: a ProxyDHCP reply carries only the option codes the
//! design allows, and no header field that could hand the device an
//! address or point it at another server. They also check that a
//! suppressed device gets no decision other than `Drop(Suppressed)` on any
//! message type or port (REQ-BOOT-051), and that suppression wins over
//! every reply path.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11, SI-10, CM-7
// - SPEC: specs/boot-network.md#REQ-BOOT-010, #REQ-BOOT-021,
//   #REQ-BOOT-022, #REQ-BOOT-051
// - DECISION: docs/decisions/0003-proxy-dhcp-only.md

#[cfg(test)]
mod qa {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use usgp_dhcp::craft::{RequestBuilder, SAMPLE_MAC};
    use usgp_dhcp::reply::inspect_reply;
    use usgp_dhcp::{
        BootPolicy, ClientArch, Decision, DropReason, Guid, ListenPort, MacAddr, ResponderContext,
        parse_request, respond,
    };

    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 20, 1, 2);
    const AGENT: Ipv4Addr = Ipv4Addr::new(10, 20, 2, 1);
    const PROGRAM: &[u8] = b"usgp-test-payload.efi";

    /// 43 (ACK echo of tag 71), 53, 54, 60, 82 (echo), 93, 94, 97.
    const ALLOWED: [u8; 8] = [43, 53, 54, 60, 82, 93, 94, 97];

    struct Policy {
        suppress_all: bool,
    }

    impl BootPolicy for Policy {
        fn boot_program(&self, arch: ClientArch) -> Option<&[u8]> {
            (arch == ClientArch::X64_UEFI).then_some(PROGRAM)
        }
        fn is_suppressed(&self, _mac: MacAddr, _guid: Option<Guid>) -> bool {
            self.suppress_all
        }
        fn is_local_address(&self, addr: Ipv4Addr) -> bool {
            addr == SERVER
        }
    }

    fn contexts() -> [ResponderContext; 3] {
        [
            ResponderContext {
                server_addr: SERVER,
                port: ListenPort::Dhcp67,
                source: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
            },
            ResponderContext {
                server_addr: SERVER,
                port: ListenPort::Dhcp67,
                source: SocketAddrV4::new(AGENT, 67),
            },
            ResponderContext {
                server_addr: SERVER,
                port: ListenPort::BootServer4011,
                source: SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 50), 68),
            },
        ]
    }

    fn seeds() -> Vec<Vec<u8>> {
        let ask_lease = |b: RequestBuilder| {
            b.option(50, vec![10, 20, 1, 77])
                .set_option(55, vec![1, 3, 6, 15, 28, 42, 51, 58, 59, 66, 67])
        };
        vec![
            RequestBuilder::pxe_discover().build(),
            ask_lease(RequestBuilder::pxe_discover()).build(),
            RequestBuilder::pxe_discover()
                .giaddr(AGENT)
                .hops(1)
                .option(82, vec![1, 3, b'a', b'b', b'c'])
                .build(),
            RequestBuilder::pxe_request()
                .option(54, SERVER.octets().to_vec())
                .build(),
            ask_lease(RequestBuilder::pxe_request().option(43, vec![71, 4, 0, 0, 0, 0, 255]))
                .build(),
            RequestBuilder::pxe_request()
                .ciaddr(Ipv4Addr::new(10, 20, 1, 50))
                .build(),
        ]
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    fn check_reply(buf: &[u8], reply: &[u8]) {
        let req = parse_request(buf).unwrap();
        let v = inspect_reply(reply).unwrap();
        assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED, "REQ-BOOT-010");
        assert_eq!(v.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(v.siaddr, SERVER, "REQ-BOOT-022");
        assert_eq!(v.server_id, Some(SERVER));
        assert_eq!(v.file, PROGRAM);
        // hops is 0 in a server reply; sname (octets 44..108) is empty.
        assert_eq!(reply[3], 0, "hops");
        assert!(reply[44..108].iter().all(|b| *b == 0), "sname");
        for code in 1..=254u8 {
            if v.codes.contains(code) {
                assert!(ALLOWED.contains(&code), "option {code} in a proxy reply");
            }
        }
        // Option 82 only ever appears as an unchanged echo (REQ-BOOT-021).
        match (req.relay_info.as_deref(), v.relay_info) {
            (_, None) => {}
            (Some(a), Some(b)) => assert_eq!(a, b),
            (None, Some(_)) => panic!("option 82 invented"),
        }
        if v.relay_info.is_some() {
            assert_eq!(v.last_code, Some(82), "82 is the last option");
        }
    }

    /// Every reply produced from mutated valid requests, on all three
    /// listening contexts, carries only allowed options.
    #[test]
    fn replies_carry_only_allowed_options_under_mutation() {
        let mut rng = XorShift(0x0bad_cafe_f00d_d00d);
        let policy = Policy {
            suppress_all: false,
        };
        let mut replies = 0u32;
        for seed in seeds() {
            for _ in 0..4000 {
                let mut b = seed.clone();
                for _ in 0..(rng.next() % 4) {
                    let at = usize::try_from(rng.next()).unwrap() % b.len();
                    b[at] = rng.next().to_le_bytes()[0];
                }
                let Ok(req) = parse_request(&b) else { continue };
                for ctx in contexts() {
                    if let Decision::Reply(r) = respond(&req, &ctx, &policy) {
                        replies += 1;
                        check_reply(&b, &r.bytes);
                    }
                }
            }
        }
        // The sweep must actually exercise the reply path.
        assert!(replies > 5000, "only {replies} replies");
    }

    /// REQ-BOOT-051: with the device suppressed, no request that would
    /// otherwise be answered gets a reply, on any port or message type,
    /// and the reason is always `Suppressed` (not a refusal message).
    #[test]
    fn suppression_wins_over_every_reply_path() {
        let open = Policy {
            suppress_all: false,
        };
        let shut = Policy { suppress_all: true };
        let mut checked = 0u32;
        for seed in seeds() {
            let req = parse_request(&seed).unwrap();
            assert_eq!(req.chaddr, MacAddr::new(SAMPLE_MAC).unwrap());
            for ctx in contexts() {
                if let Decision::Reply(_) = respond(&req, &ctx, &open) {
                    checked += 1;
                    assert_eq!(
                        respond(&req, &ctx, &shut),
                        Decision::Drop(DropReason::Suppressed),
                        "{ctx:?}"
                    );
                }
            }
        }
        assert!(checked >= 6, "{checked}");
    }
}
