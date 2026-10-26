//! ProxyDHCP service tests: crafted packets through `DhcpService` for the
//! same-segment, relayed and port-4011 paths, suppression, missing
//! content, rate limits, flood recovery, and the never-an-address
//! invariant on every reply.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-10, SC-5, CM-7, SA-11
//! - SPEC: specs/boot-network.md#REQ-BOOT-001, -002, -004, -005, -006,
//!   -007, -010, -020, -021, -022, -044, -050, -051, -052, -070
//! - DECISION: docs/decisions/0003-proxy-dhcp-only.md

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod dhcp {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use usgp_dhcp::craft::{RequestBuilder, SAMPLE_GUID_WIRE, SAMPLE_MAC};
    use usgp_dhcp::reply::FORBIDDEN_REPLY_OPTIONS;
    use usgp_dhcp::{Destination, Guid, ListenPort, MacAddr, inspect_reply};
    use usgp_relay::config::RelayConfig;
    use usgp_relay::content::ContentStore;
    use usgp_relay::dhcp::{DhcpService, Outbound};
    use usgp_relay::limits::Counters;
    use usgp_relay::suppress::{Suppression, SuppressionList};

    use crate::common::{IFACE_ADDR, PROGRAM, Scratch, bytes, config, content, iface};

    struct Rig {
        s: Scratch,
        svc: DhcpService,
        content: Arc<ContentStore>,
        suppression: Arc<Suppression>,
        shed: Arc<Mutex<Counters>>,
        t0: Instant,
        data: Vec<u8>,
    }

    async fn rig_with(tag: &str, tweak: impl FnOnce(&mut RelayConfig)) -> Rig {
        let s = Scratch::new(tag);
        let data = bytes(4096, 5);
        s.publish(&[(PROGRAM, &data)]);
        let mut cfg = config(&s);
        tweak(&mut cfg);
        let content = content(&cfg).await;
        let suppression = Arc::new(Suppression::disabled());
        let shed = Arc::new(Mutex::new(Counters::default()));
        let t0 = Instant::now();
        let svc = DhcpService::new(
            Arc::clone(&content),
            Arc::clone(&suppression),
            cfg.local_addresses(),
            &cfg.limits,
            Arc::clone(&shed),
            t0,
        );
        Rig {
            s,
            svc,
            content,
            suppression,
            shed,
            t0,
            data,
        }
    }

    async fn rig(tag: &str) -> Rig {
        rig_with(tag, |_| {}).await
    }

    const BROADCAST_SRC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    const AGENT: Ipv4Addr = Ipv4Addr::new(10, 20, 2, 1);

    impl Rig {
        fn send(&self, port: ListenPort, src: SocketAddrV4, pkt: &[u8]) -> Option<Outbound> {
            self.svc.handle(&iface(), port, src, pkt, self.t0)
        }

        fn send_at(&self, src: SocketAddrV4, pkt: &[u8], at: Instant) -> Option<Outbound> {
            self.svc.handle(&iface(), ListenPort::Dhcp67, src, pkt, at)
        }

        fn discover(&self, b: &RequestBuilder) -> Option<Outbound> {
            self.send(ListenPort::Dhcp67, BROADCAST_SRC, &b.build())
        }
    }

    /// The REQ-BOOT-010 invariant and the offer content (plan section 1.1).
    fn check_reply(out: &Outbound, req: &RequestBuilder) {
        let v = inspect_reply(&out.bytes).unwrap();
        assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED, "never an address");
        for code in FORBIDDEN_REPLY_OPTIONS {
            assert!(!v.codes.contains(code), "option {code} in a proxy reply");
        }
        assert_eq!(v.xid, req.xid);
        assert_eq!(v.chaddr, req.chaddr);
        assert_eq!(v.siaddr, IFACE_ADDR, "REQ-BOOT-022: siaddr = interface");
        assert_eq!(v.server_id, Some(IFACE_ADDR));
        assert_eq!(v.file, PROGRAM.as_bytes());
        assert_eq!(v.arch, Some(&[0u8, 7][..]));
    }

    #[tokio::test]
    async fn same_segment_offer() {
        let r = rig("same-seg").await;
        let req = RequestBuilder::pxe_discover();
        let out = r.discover(&req).expect("offer");
        assert_eq!(out.destination, Destination::Broadcast68);
        check_reply(&out, &req);
        let v = inspect_reply(&out.bytes).unwrap();
        assert_eq!(v.msg_type, Some(2));
        // BROADCAST flag preserved (RFC 1542 §5.4).
        assert_eq!(v.flags, req.flags);
    }

    #[tokio::test]
    async fn relayed_any_source_default() {
        let r = rig("relayed").await;
        // Owner answer Q-1: any relay agent is accepted.
        for agent in [AGENT, Ipv4Addr::new(192, 168, 77, 1)] {
            let req = RequestBuilder::pxe_discover()
                .giaddr(agent)
                .hops(1)
                .chaddr([0x52, 0x54, 0, 0, 2, agent.octets()[3]])
                .option(82, vec![1, 4, b'r', b't', b'B', b'0']);
            let out = r
                .send(
                    ListenPort::Dhcp67,
                    SocketAddrV4::new(agent, 67),
                    &req.build(),
                )
                .expect("offer through the relay agent");
            assert_eq!(
                out.destination,
                Destination::RelayAgent(SocketAddrV4::new(agent, 67)),
                "REQ-BOOT-020"
            );
            check_reply(&out, &req);
            let v = inspect_reply(&out.bytes).unwrap();
            assert_eq!(v.giaddr, agent);
            // REQ-BOOT-021: option 82 echoed unchanged, last.
            assert_eq!(v.relay_info, Some(&[1u8, 4, b'r', b't', b'B', b'0'][..]));
            assert_eq!(v.last_code, Some(82));
        }
    }

    #[tokio::test]
    async fn request_on_4011_answered_to_source() {
        let r = rig("4011").await;
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 50), 68);
        let req = RequestBuilder::pxe_request().ciaddr(*src.ip());
        let out = r
            .send(ListenPort::BootServer4011, src, &req.build())
            .expect("ack");
        assert_eq!(out.destination, Destination::Unicast(src));
        check_reply(&out, &req);
        assert_eq!(inspect_reply(&out.bytes).unwrap().msg_type, Some(5));
    }

    #[tokio::test]
    async fn request_naming_us_on_67_acked() {
        let r = rig("req-us").await;
        let req = RequestBuilder::pxe_request().option(54, IFACE_ADDR.octets().to_vec());
        let out = r.discover(&req).expect("ack");
        check_reply(&out, &req);
    }

    #[tokio::test]
    async fn request_for_other_server_ignored() {
        let r = rig("req-other").await;
        let req = RequestBuilder::pxe_request().option(54, vec![10, 20, 1, 3]);
        assert!(r.discover(&req).is_none());
        assert_eq!(r.svc.drop_count("for_other_server"), 1);
    }

    #[tokio::test]
    async fn non_pxe_client_gets_nothing() {
        let r = rig("non-pxe").await;
        let req = RequestBuilder::pxe_discover().set_option(60, b"usgp-non-pxe-client".to_vec());
        assert!(r.discover(&req).is_none());
        let req = RequestBuilder::pxe_discover().without(60);
        assert!(r.discover(&req).is_none());
        assert_eq!(r.svc.drop_count("not_pxe_client"), 2);
    }

    #[tokio::test]
    async fn unsupported_arch_gets_nothing() {
        let r = rig("arch").await;
        let req = RequestBuilder::pxe_discover()
            .set_option(60, b"PXEClient:Arch:00000:UNDI:002001".to_vec())
            .set_option(93, vec![0, 0]);
        assert!(r.discover(&req).is_none());
        assert_eq!(r.svc.drop_count("unsupported_arch"), 1);
    }

    #[tokio::test]
    async fn own_address_as_giaddr_dropped() {
        let r = rig("own-giaddr").await;
        let req = RequestBuilder::pxe_discover().giaddr(IFACE_ADDR);
        assert!(
            r.send(
                ListenPort::Dhcp67,
                SocketAddrV4::new(AGENT, 67),
                &req.build()
            )
            .is_none()
        );
        assert_eq!(r.svc.drop_count("bad_giaddr"), 1);
    }

    #[tokio::test]
    async fn suppress_by_mac_and_lift_without_restart() {
        let r = rig("supp-mac").await;
        let req = RequestBuilder::pxe_discover();
        assert!(r.discover(&req).is_some());
        let mac = MacAddr::new(SAMPLE_MAC).unwrap();
        r.suppression
            .set(SuppressionList::from_ids(&[mac], &[]).unwrap());
        // REQ-BOOT-051: no reply at all.
        assert!(r.discover(&req).is_none());
        assert_eq!(r.svc.drop_count("suppressed"), 1);
        // Another device is unaffected.
        let other = RequestBuilder::pxe_discover().chaddr([0x52, 0x54, 0, 0, 9, 9]);
        assert!(r.discover(&other).is_some());
        // REQ-BOOT-050: lifting applies to the next attempt.
        r.suppression.set(SuppressionList::empty());
        assert!(r.discover(&req).is_some());
    }

    #[tokio::test]
    async fn suppress_by_guid() {
        let r = rig("supp-guid").await;
        let guid = Guid::from_wire(SAMPLE_GUID_WIRE);
        r.suppression
            .set(SuppressionList::from_ids(&[], &[guid]).unwrap());
        let req = RequestBuilder::pxe_discover();
        assert!(r.discover(&req).is_none());
        // Same GUID on another adapter (other MAC): still suppressed.
        let other_nic = RequestBuilder::pxe_discover().chaddr([0x52, 0x54, 0, 0, 7, 7]);
        assert!(r.discover(&other_nic).is_none());
        // A device that sends no GUID is matched by MAC only.
        let no_guid = RequestBuilder::pxe_discover().without(97);
        assert!(r.discover(&no_guid).is_some());
    }

    #[tokio::test]
    async fn missing_content_no_offer_then_recovers() {
        let r = rig("missing").await;
        let req = RequestBuilder::pxe_discover();
        assert!(r.discover(&req).is_some());
        let mut bad = r.data.clone();
        bad[0] ^= 0xff;
        r.s.write_boot_file(PROGRAM, &bad);
        r.content.recheck_all("recheck").await;
        assert!(r.discover(&req).is_none(), "REQ-BOOT-052");
        assert_eq!(r.svc.drop_count("missing_content"), 1);
        r.s.write_boot_file(PROGRAM, &r.data);
        r.content.recheck_all("recheck").await;
        assert!(r.discover(&req).is_some());
    }

    #[tokio::test]
    async fn per_client_rate_limit_and_refill() {
        let r = rig("rate-client").await;
        let req = RequestBuilder::pxe_discover().build();
        let mut answered = 0;
        for _ in 0..20 {
            if r.send_at(BROADCAST_SRC, &req, r.t0).is_some() {
                answered += 1;
            }
        }
        // Default burst 8.
        assert_eq!(answered, 8);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_client"), 12);
        // One token per 2000 ms.
        assert!(
            r.send_at(BROADCAST_SRC, &req, r.t0 + Duration::from_millis(1999))
                .is_none()
        );
        assert!(
            r.send_at(BROADCAST_SRC, &req, r.t0 + Duration::from_millis(2000))
                .is_some()
        );
        // Another client is unaffected.
        let other = RequestBuilder::pxe_discover()
            .chaddr([0x52, 0x54, 0, 0, 3, 3])
            .build();
        assert!(r.send_at(BROADCAST_SRC, &other, r.t0).is_some());
    }

    #[tokio::test]
    async fn relay_source_rate_limit() {
        let r = rig_with("rate-relay", |cfg| cfg.limits.dhcp_relay_burst = 5).await;
        let src = SocketAddrV4::new(AGENT, 67);
        let mut answered = 0;
        for n in 0..10u8 {
            let req = RequestBuilder::pxe_discover()
                .giaddr(AGENT)
                .chaddr([0x52, 0x54, 0, 0, 4, n])
                .build();
            if r.send_at(src, &req, r.t0).is_some() {
                answered += 1;
            }
        }
        assert_eq!(answered, 5);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_relay_source"), 5);
        // Same-segment clients do not use the relay budget.
        let local = RequestBuilder::pxe_discover()
            .chaddr([0x52, 0x54, 0, 0, 5, 1])
            .build();
        assert!(r.send_at(BROADCAST_SRC, &local, r.t0).is_some());
    }

    #[tokio::test]
    async fn non_pxe_relayed_traffic_does_not_use_budget() {
        let r = rig_with("rate-nonpxe", |cfg| cfg.limits.dhcp_relay_burst = 1).await;
        let src = SocketAddrV4::new(AGENT, 67);
        for n in 0..50u8 {
            let req = RequestBuilder::pxe_discover()
                .giaddr(AGENT)
                .chaddr([0x52, 0x54, 0, 0, 6, n])
                .set_option(60, b"usgp-non-pxe-client".to_vec())
                .build();
            assert!(r.send_at(src, &req, r.t0).is_none());
        }
        let pxe = RequestBuilder::pxe_discover().giaddr(AGENT).build();
        assert!(r.send_at(src, &pxe, r.t0).is_some());
    }

    /// SEC-002: relayed requests have their own global budget, so a
    /// routed flood (many relay sources, rotating chaddr) cannot use up
    /// the same-segment budget, nor the other way round.
    #[tokio::test]
    async fn relayed_and_local_global_budgets_are_separate() {
        let r = rig_with("rate-split", |cfg| {
            cfg.limits.dhcp_global_per_sec = 10;
            cfg.limits.dhcp_relayed_global_per_sec = 5;
        })
        .await;
        let mut relayed = 0;
        for n in 0..40u8 {
            // A different routed source each time defeats the per-source
            // bucket; only the relayed global budget applies.
            let src = SocketAddrV4::new(Ipv4Addr::new(10, 99, 0, n.saturating_add(1)), 67);
            let req = RequestBuilder::pxe_discover()
                .giaddr(AGENT)
                .chaddr([0x52, 0x54, 0, 0, 9, n])
                .build();
            if r.send_at(src, &req, r.t0).is_some() {
                relayed += 1;
            }
        }
        assert_eq!(relayed, 5);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_relayed_global"), 35);
        // The same-segment budget is untouched.
        let mut local = 0;
        for n in 0..12u8 {
            let req = RequestBuilder::pxe_discover()
                .chaddr([0x52, 0x54, 0, 0, 10, n])
                .build();
            if r.send_at(BROADCAST_SRC, &req, r.t0).is_some() {
                local += 1;
            }
        }
        assert_eq!(local, 10);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 2);
    }

    /// SEC-002 (round 2): same-segment vs routed is decided from the UDP
    /// source and the interface subnet, not from giaddr alone. giaddr-0
    /// requests on 67 from another subnet whose ciaddr is not their
    /// source are dropped: they use no same-segment budget and cause no
    /// broadcast on the boot segment. On 4011 they are routed clients and
    /// use the routed budget.
    #[tokio::test]
    async fn off_segment_sources_never_use_same_segment_budget() {
        let r = rig_with("rate-origin", |cfg| {
            cfg.limits.dhcp_global_per_sec = 3;
            cfg.limits.dhcp_relayed_global_per_sec = 2;
        })
        .await;
        for n in 0..50u8 {
            let src = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, n.saturating_add(1)), 68);
            let req = RequestBuilder::pxe_request()
                .ciaddr(Ipv4Addr::new(10, 20, 1, 77))
                .option(54, IFACE_ADDR.octets().to_vec())
                .chaddr([0x52, 0x54, 0, 0, 0x11, n])
                .build();
            assert!(r.send(ListenPort::Dhcp67, src, &req).is_none(), "{src}");
            let disc = RequestBuilder::pxe_discover()
                .chaddr([0x52, 0x54, 0, 0, 0x12, n])
                .build();
            assert!(r.send(ListenPort::Dhcp67, src, &disc).is_none(), "{src}");
        }
        assert_eq!(r.svc.drop_count("off_segment_source"), 100);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 0);
        // The same-segment budget is intact: 3 broadcast offers, from
        // 0.0.0.0 and from a host in 10.20.1.0/24.
        let mut local = 0;
        for (n, src) in [
            BROADCAST_SRC,
            SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 50), 68),
            BROADCAST_SRC,
            BROADCAST_SRC,
        ]
        .into_iter()
        .enumerate()
        {
            let req = RequestBuilder::pxe_discover()
                .chaddr([0x52, 0x54, 0, 0, 0x13, u8::try_from(n).unwrap()])
                .build();
            if let Some(out) = r.send(ListenPort::Dhcp67, src, &req) {
                assert_eq!(out.destination, Destination::Broadcast68);
                local += 1;
            }
        }
        assert_eq!(local, 3);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 1);
        // Routed clients on 4011 draw on the routed budget (2), not on the
        // exhausted same-segment one.
        let mut routed = 0;
        for n in 0..4u8 {
            let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 50 + n), 68);
            let req = RequestBuilder::pxe_request()
                .ciaddr(*src.ip())
                .chaddr([0x52, 0x54, 0, 0, 0x14, n])
                .build();
            if let Some(out) = r.send(ListenPort::BootServer4011, src, &req) {
                assert_eq!(out.destination, Destination::Unicast(src));
                routed += 1;
            }
        }
        assert_eq!(routed, 2);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_relayed_global"), 2);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 1);
    }

    /// BOOT-011: a giaddr-0 request on 67 from another subnet whose ciaddr
    /// is its UDP source (a client that already has an address, for
    /// example a follow-up after a relayed offer) is answered by unicast
    /// to ciaddr:68 and charged to the routed budget, never to the
    /// same-segment one, and never broadcast.
    #[tokio::test]
    async fn off_segment_ciaddr_source_on_67_routed_unicast() {
        let r = rig_with("off-seg-ciaddr", |cfg| {
            cfg.limits.dhcp_relayed_global_per_sec = 2;
        })
        .await;
        let mut answered = 0;
        for n in 0..4u8 {
            let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 60 + n), 68);
            let req = RequestBuilder::pxe_request()
                .ciaddr(*src.ip())
                .option(54, IFACE_ADDR.octets().to_vec())
                .chaddr([0x52, 0x54, 0, 0, 0x15, n])
                .build();
            if let Some(out) = r.send(ListenPort::Dhcp67, src, &req) {
                assert_eq!(out.destination, Destination::Unicast(src), "{src}");
                answered += 1;
            }
        }
        assert_eq!(answered, 2);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_relayed_global"), 2);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 0);
        assert_eq!(r.svc.drop_count("off_segment_source"), 0);
        // The same request with a ciaddr that is not the source is dropped.
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 70), 68);
        let req = RequestBuilder::pxe_request()
            .ciaddr(Ipv4Addr::new(10, 20, 2, 71))
            .option(54, IFACE_ADDR.octets().to_vec())
            .build();
        assert!(r.send(ListenPort::Dhcp67, src, &req).is_none());
        assert_eq!(r.svc.drop_count("off_segment_source"), 1);
    }

    /// SEC-002: with no known prefix, only a 0.0.0.0 source is taken as
    /// same-segment (fail closed).
    #[tokio::test]
    async fn unknown_prefix_fails_closed() {
        let r = rig("no-prefix").await;
        let mut i = iface();
        i.prefix_len = None;
        let on_seg = SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 50), 68);
        let req = RequestBuilder::pxe_discover().build();
        let at = r.t0;
        assert!(
            r.svc
                .handle(&i, ListenPort::Dhcp67, on_seg, &req, at)
                .is_none()
        );
        assert_eq!(r.svc.drop_count("off_segment_source"), 1);
        assert!(
            r.svc
                .handle(&i, ListenPort::Dhcp67, BROADCAST_SRC, &req, at)
                .is_some()
        );
    }

    /// BOOT-008: requests below the 300-octet BOOTP minimum are dropped
    /// silently and counted as `short_message` (pxe-dhcp.md §3.2).
    #[tokio::test]
    async fn short_requests_dropped_and_counted() {
        let r = rig("short").await;
        let mut b = RequestBuilder::pxe_discover().without(55).without(97);
        b.pad_to = 0;
        let short = b.build();
        assert!(short.len() < 300);
        assert!(r.send(ListenPort::Dhcp67, BROADCAST_SRC, &short).is_none());
        assert_eq!(r.svc.drop_count("short_message"), 1);
        b.pad_to = 300;
        assert!(
            r.send(ListenPort::Dhcp67, BROADCAST_SRC, &b.build())
                .is_some()
        );
        assert_eq!(r.svc.take_drop_counts(), vec![("short_message", 1)]);
    }

    #[tokio::test]
    async fn global_reply_budget() {
        let r = rig_with("rate-global", |cfg| cfg.limits.dhcp_global_per_sec = 10).await;
        let mut answered = 0;
        for n in 0..30u8 {
            let req = RequestBuilder::pxe_discover()
                .chaddr([0x52, 0x54, 0, 0, 8, n])
                .build();
            if r.send_at(BROADCAST_SRC, &req, r.t0).is_some() {
                answered += 1;
            }
        }
        assert_eq!(answered, 10);
        assert_eq!(r.shed.lock().unwrap().get("dhcp_global"), 20);
        let req = RequestBuilder::pxe_discover()
            .chaddr([0x52, 0x54, 0, 0, 8, 200])
            .build();
        assert!(
            r.send_at(BROADCAST_SRC, &req, r.t0 + Duration::from_millis(100))
                .is_some()
        );
    }

    /// Deterministic xorshift for the flood.
    fn xorshift(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[tokio::test]
    async fn flood_bounded_then_recovers() {
        let r = rig("flood").await;
        let good = RequestBuilder::pxe_discover().build();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut replies = 0usize;
        for i in 0..20_000usize {
            let pkt = if i % 2 == 0 {
                // Random bytes of random length (0 to 1600).
                let len = usize::try_from(xorshift(&mut seed) % 1601).unwrap();
                (0..len)
                    .map(|_| xorshift(&mut seed).to_le_bytes()[0])
                    .collect::<Vec<u8>>()
            } else {
                // Mutations of a valid DISCOVER: flip a few bytes.
                let mut p = good.clone();
                for _ in 0..3 {
                    let at = usize::try_from(xorshift(&mut seed)).unwrap() % p.len();
                    p[at] ^= xorshift(&mut seed).to_le_bytes()[0] | 1;
                }
                p
            };
            if let Some(out) = r.send_at(BROADCAST_SRC, &pkt, r.t0) {
                // Whatever is answered still satisfies the invariant.
                let v = inspect_reply(&out.bytes).unwrap();
                assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED);
                for code in FORBIDDEN_REPLY_OPTIONS {
                    assert!(!v.codes.contains(code));
                }
                replies += 1;
            }
        }
        // Bounded by the global budgets within one instant: 200 for
        // same-segment requests plus 200 for those whose mutated giaddr
        // makes them relayed (separate budgets, SEC-002).
        assert!(replies <= 400, "{replies}");
        assert!(r.svc.drop_count("malformed") > 9_000);
        // Service continues once the flood stops.
        let fresh = RequestBuilder::pxe_discover()
            .chaddr([0x52, 0x54, 0, 0, 0x0a, 1])
            .build();
        assert!(
            r.send_at(BROADCAST_SRC, &fresh, r.t0 + Duration::from_secs(2))
                .is_some()
        );
    }

    #[tokio::test]
    async fn drop_counts_drain_for_summary() {
        let r = rig("summary").await;
        assert!(
            r.send(ListenPort::Dhcp67, BROADCAST_SRC, &[0u8; 10])
                .is_none()
        );
        assert!(
            r.send(ListenPort::Dhcp67, BROADCAST_SRC, &[1u8; 300])
                .is_none()
        );
        assert_eq!(r.svc.take_drop_counts(), vec![("malformed", 2)]);
        assert!(r.svc.take_drop_counts().is_empty());
    }

    #[tokio::test]
    async fn reply_latency_under_50ms() {
        let r = rig("latency").await;
        let req = RequestBuilder::pxe_discover().build();
        let start = Instant::now();
        let out = r.send(ListenPort::Dhcp67, BROADCAST_SRC, &req);
        let elapsed = start.elapsed();
        assert!(out.is_some());
        // REQ-BOOT-070: far inside the 4 s client retry window.
        assert!(elapsed < Duration::from_millis(50), "{elapsed:?}");
    }
}
