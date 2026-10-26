//! QA gap tests for milestone M1 (qa-engineer, SA-11 / CA-2 evidence).
//!
//! These tests drive the relay's public service objects (`DhcpService`,
//! `TftpListener`, `ContentStore`, `Suppression`) end to end with
//! in-memory sockets, and capture the audit events the relay emits on the
//! `audit` tracing target with a test-only subscriber. They cover:
//!
//! - audit events and their AU-3 fields on success and on failure;
//! - the exit-2 chain: a tampered file found by an RRQ stops DHCP offers,
//!   and a re-check after restoring it resumes them;
//! - no reply of any kind to a suppressed device on every DHCP path;
//! - no lease data in any reply, even when the request asks for it;
//! - relay-agent information echoed or dropped, with the audit flag;
//! - nothing host-specific (paths, digests) in boot-network traffic;
//! - nil GUID refused in a suppression file; GUID case-insensitivity.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, CA-2, AU-2, AU-3, AU-12, SI-7, SI-10, SI-11, SC-5
//! - SPEC: specs/boot-network.md#REQ-BOOT-007, -010, -021, -033, -040,
//!   -041, -043, -050, -051, -052
//! - DECISION: docs/decisions/0003-proxy-dhcp-only.md,
//!   docs/decisions/0004-m1-boot-scope-and-suppression.md

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod qa {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use usgp_dhcp::craft::{RequestBuilder, SAMPLE_GUID_WIRE, SAMPLE_MAC};
    use usgp_dhcp::{Destination, Guid, ListenPort, MacAddr, inspect_reply};
    use usgp_relay::content::ContentStore;
    use usgp_relay::dhcp::{DhcpService, Outbound};
    use usgp_relay::limits::Counters;
    use usgp_relay::state::ServiceState;
    use usgp_relay::suppress::{ReloadOutcome, Suppression, SuppressionList};
    use usgp_relay::tftp::{Disposition, TftpListener, TftpShared};
    use usgp_tftp::{Opcode, Packet, encode_ack, encode_request, parse};

    use crate::common::{
        IFACE, IFACE_ADDR, MemFactory, MemNet, MemSocket, PROGRAM, Scratch, bytes, config, content,
        iface, set_mode, trust,
    };

    // -----------------------------------------------------------------
    // Audit capture: a minimal tracing subscriber that records every
    // event on the `audit` target as a field map. Installed per test with
    // `tracing::subscriber::set_default` (thread-local); every test here
    // runs on the current-thread runtime, so spawned tasks emit on the
    // same thread.
    // -----------------------------------------------------------------

    type Record = HashMap<String, String>;

    #[derive(Clone, Default)]
    struct Capture {
        events: Arc<Mutex<Vec<Record>>>,
    }

    struct Visitor<'a>(&'a mut Record);

    impl tracing::field::Visit for Visitor<'_> {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.0.insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    impl tracing::Subscriber for Capture {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != usgp_common::event::AUDIT_TARGET {
                return;
            }
            let mut r = Record::new();
            event.record(&mut Visitor(&mut r));
            self.events.lock().unwrap().push(r);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    impl Capture {
        fn install() -> (Self, tracing::subscriber::DefaultGuard) {
            let c = Self::default();
            let guard = tracing::subscriber::set_default(c.clone());
            (c, guard)
        }

        fn all(&self) -> Vec<Record> {
            self.events.lock().unwrap().clone()
        }

        fn named(&self, name: &str) -> Vec<Record> {
            self.all()
                .into_iter()
                .filter(|r| r.get("event").map(String::as_str) == Some(name))
                .collect()
        }

        fn clear(&self) {
            self.events.lock().unwrap().clear();
        }
    }

    /// `detail` is a JSON object text; checks it contains `"key":"value"`.
    fn detail_has(r: &Record, key: &str, value: &str) -> bool {
        r.get("detail")
            .is_some_and(|d| d.contains(&format!("\"{key}\":\"{value}\"")))
    }

    fn field<'a>(r: &'a Record, k: &str) -> &'a str {
        r.get(k).map_or("<absent>", String::as_str)
    }

    /// The AU-3 fields every relay event carries.
    fn assert_au3(r: &Record, outcome: &str) {
        assert_eq!(field(r, "component"), "usgp-relay", "{r:?}");
        assert_eq!(field(r, "outcome"), outcome, "{r:?}");
        assert!(r.contains_key("detail"), "{r:?}");
    }

    // -----------------------------------------------------------------
    // Rigs
    // -----------------------------------------------------------------

    struct DhcpRig {
        s: Scratch,
        svc: DhcpService,
        content: Arc<ContentStore>,
        suppression: Arc<Suppression>,
        t0: Instant,
        data: Vec<u8>,
    }

    async fn dhcp_rig(tag: &str) -> DhcpRig {
        let s = Scratch::new(tag);
        let data = bytes(4096, 21);
        s.publish(&[(PROGRAM, &data)]);
        let cfg = config(&s);
        let content = content(&cfg).await;
        let suppression = Arc::new(Suppression::disabled());
        let t0 = Instant::now();
        let svc = DhcpService::new(
            Arc::clone(&content),
            Arc::clone(&suppression),
            cfg.local_addresses(),
            &cfg.limits,
            Arc::new(Mutex::new(Counters::default())),
            t0,
        );
        DhcpRig {
            s,
            svc,
            content,
            suppression,
            t0,
            data,
        }
    }

    const BCAST_SRC: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
    const AGENT: Ipv4Addr = Ipv4Addr::new(10, 20, 2, 1);

    impl DhcpRig {
        fn send(&self, port: ListenPort, src: SocketAddrV4, pkt: &[u8]) -> Option<Outbound> {
            self.svc.handle(&iface(), port, src, pkt, self.t0)
        }
    }

    fn tftp_listener(
        s: &Scratch,
        c: &Arc<ContentStore>,
        net: &Arc<MemNet>,
    ) -> Arc<TftpListener<MemFactory>> {
        let cfg = config(s);
        let shared = TftpShared::new(
            &cfg.limits,
            Arc::new(Mutex::new(Counters::default())),
            tokio::time::Instant::now().into_std(),
        );
        TftpListener::new(
            iface(),
            Arc::clone(c),
            cfg.tftp_listener_config(),
            MemFactory {
                net: Arc::clone(net),
                ip: IpAddr::V4(IFACE_ADDR),
            },
            shared,
        )
    }

    fn client_ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 20, 1, n))
    }

    fn rrq(name: &[u8], mode: &[u8], options: &[(&[u8], &[u8])]) -> Vec<u8> {
        encode_request(Opcode::Rrq, name, mode, options)
    }

    /// Lock-step download at the default 512-octet block size.
    async fn download(c: &MemSocket) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let (pkt, from) = c.recv().await;
            match parse(&pkt).unwrap() {
                Packet::Oack(_) => c.send(from, &encode_ack(0)),
                Packet::Data { block, data } => {
                    out.extend_from_slice(data);
                    c.send(from, &encode_ack(block));
                    if data.len() < 512 {
                        return out;
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    async fn wait_idle(l: &TftpListener<MemFactory>) {
        tokio::time::timeout(Duration::from_secs(30), async {
            while l.shared().active() != (0, 0) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("transfer slots released");
    }

    /// Lets spawned refusal/transfer tasks run to completion.
    async fn settle() {
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // -----------------------------------------------------------------
    // REQ-BOOT-010 (decision 0003): never an address, never lease data
    // -----------------------------------------------------------------

    /// Option codes a ProxyDHCP reply may carry (plan section 1.1 offer
    /// content; pxe-dhcp.md section 5.5): 43 (ACK with tag 71 only), 53,
    /// 54, 60, 82 (echo), 93, 94, 97. Anything else, and in particular any
    /// lease, router, subnet, DNS, renewal or rebinding option, is a
    /// REQ-BOOT-010 violation.
    const ALLOWED_REPLY_OPTIONS: [u8; 8] = [43, 53, 54, 60, 82, 93, 94, 97];

    fn assert_lease_free(out: &Outbound) {
        let v = inspect_reply(&out.bytes).unwrap();
        assert_eq!(v.yiaddr, Ipv4Addr::UNSPECIFIED, "REQ-BOOT-010 yiaddr");
        assert_eq!(v.ciaddr, Ipv4Addr::UNSPECIFIED, "no address echoed");
        for code in 0..=255u8 {
            if code == 0 || code == 255 {
                continue;
            }
            if v.codes.contains(code) {
                assert!(
                    ALLOWED_REPLY_OPTIONS.contains(&code),
                    "option {code} in a proxy reply"
                );
            }
        }
    }

    /// A request that explicitly asks for an address and every lease
    /// setting (option 50 requested address, option 51 lease time, and a
    /// parameter request list naming 1, 3, 6, 15, 28, 51, 58, 59) still
    /// gets a reply with yiaddr 0 and none of them, on every reply path.
    #[tokio::test(flavor = "current_thread")]
    async fn lease_request_never_honoured_on_any_path() {
        let r = dhcp_rig("qa-lease").await;
        let ask = |b: RequestBuilder| {
            b.option(50, vec![10, 20, 1, 77])
                .option(51, 3600u32.to_be_bytes().to_vec())
                .set_option(
                    55,
                    vec![1, 3, 6, 15, 28, 51, 54, 58, 59, 60, 66, 67, 93, 97],
                )
        };
        let paths: Vec<(&str, ListenPort, SocketAddrV4, RequestBuilder)> = vec![
            (
                "discover-broadcast",
                ListenPort::Dhcp67,
                BCAST_SRC,
                ask(RequestBuilder::pxe_discover()),
            ),
            (
                "discover-relayed",
                ListenPort::Dhcp67,
                SocketAddrV4::new(AGENT, 67),
                ask(RequestBuilder::pxe_discover().giaddr(AGENT).hops(1)),
            ),
            (
                "request-67-ciaddr",
                ListenPort::Dhcp67,
                SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 77), 68),
                ask(RequestBuilder::pxe_request()
                    .ciaddr(Ipv4Addr::new(10, 20, 1, 77))
                    .option(54, IFACE_ADDR.octets().to_vec())),
            ),
            (
                "request-67-tag71",
                ListenPort::Dhcp67,
                BCAST_SRC,
                ask(RequestBuilder::pxe_request().option(43, vec![71, 4, 0, 0, 0, 0, 255])),
            ),
            (
                "request-4011",
                ListenPort::BootServer4011,
                SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 77), 68),
                ask(RequestBuilder::pxe_request().ciaddr(Ipv4Addr::new(10, 20, 1, 77))),
            ),
        ];
        for (label, port, src, b) in paths {
            let out = r
                .send(port, src, &b.build())
                .unwrap_or_else(|| panic!("{label}: expected a reply"));
            assert_lease_free(&out);
        }
    }

    // -----------------------------------------------------------------
    // REQ-BOOT-051: a suppressed device gets no reply at all
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn suppressed_device_gets_nothing_on_every_path_and_one_event() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-supp").await;
        let mac = MacAddr::new(SAMPLE_MAC).unwrap();
        r.suppression
            .set(SuppressionList::from_ids(&[mac], &[]).unwrap());
        cap.clear();
        let ciaddr = Ipv4Addr::new(10, 20, 1, 77);
        let attempts: Vec<(ListenPort, SocketAddrV4, RequestBuilder)> = vec![
            (
                ListenPort::Dhcp67,
                BCAST_SRC,
                RequestBuilder::pxe_discover(),
            ),
            (
                ListenPort::Dhcp67,
                SocketAddrV4::new(AGENT, 67),
                RequestBuilder::pxe_discover().giaddr(AGENT).hops(1),
            ),
            (
                ListenPort::Dhcp67,
                BCAST_SRC,
                RequestBuilder::pxe_request().option(54, IFACE_ADDR.octets().to_vec()),
            ),
            (
                ListenPort::Dhcp67,
                BCAST_SRC,
                RequestBuilder::pxe_request().option(43, vec![71, 4, 0, 0, 0, 0, 255]),
            ),
            (
                ListenPort::BootServer4011,
                SocketAddrV4::new(ciaddr, 68),
                RequestBuilder::pxe_request().ciaddr(ciaddr),
            ),
        ];
        // Repeat each path a few times: still nothing, and the event is
        // throttled to one per device per minute (plan section 7).
        for _ in 0..3 {
            for (port, src, b) in &attempts {
                assert!(
                    r.send(*port, *src, &b.build()).is_none(),
                    "REQ-BOOT-051: suppressed device got a reply ({port:?})"
                );
            }
        }
        assert_eq!(r.svc.drop_count("suppressed"), 15);
        let ev = cap.named("dhcp.suppressed");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        assert_au3(&ev[0], "dropped");
        assert_eq!(field(&ev[0], "claimed_mac"), "52:54:00:00:01:01");
        assert_eq!(field(&ev[0], "interface"), IFACE);
        assert!(cap.named("dhcp.offer.sent").is_empty());
        assert!(cap.named("dhcp.ack.sent").is_empty());
    }

    /// A suppression file naming the nil GUID is refused at reload (the
    /// nil GUID means "no value" and would match every device that sends
    /// it; uefi-guid-text.md section 2). The previous list stays in force
    /// and `suppression.rejected` is emitted.
    #[tokio::test(flavor = "current_thread")]
    async fn suppression_file_with_nil_guid_rejected_previous_kept() {
        let (cap, _g) = Capture::install();
        let s = Scratch::new("qa-nil");
        let path = s.dir.join("suppress.toml");
        let write = |text: &str| {
            std::fs::write(&path, text).unwrap();
            set_mode(&path, 0o644);
        };
        write("schema_version = 1\n[[device]]\nmac = \"52:54:00:00:01:01\"\n");
        let h = Suppression::load_initial(&path, trust()).unwrap();
        let mac = MacAddr::new(SAMPLE_MAC).unwrap();
        assert!(h.current().contains(mac, None));
        for nil in [
            "00000000-0000-0000-0000-000000000000",
            "{00000000-0000-0000-0000-000000000000}",
        ] {
            write(&format!(
                "schema_version = 1\n[[device]]\nguid = \"{nil}\"\n"
            ));
            assert_eq!(h.reload(), ReloadOutcome::Rejected, "{nil}");
            assert!(h.current().contains(mac, None), "previous list kept");
        }
        let rej = cap.named("suppression.rejected");
        assert!(!rej.is_empty(), "{:?}", cap.all());
        // Outcome::Refused: refused by validation (usgp_common::event).
        assert_au3(&rej[0], "refused");
        assert!(detail_has(&rej[0], "action", "previous list kept"));
        // And a device that sends the nil GUID is not suppressed by an
        // unrelated list.
        let nil = Guid::from_wire([0; 16]);
        let other = MacAddr::new([0x52, 0x54, 0, 0, 9, 9]).unwrap();
        assert!(!h.current().contains(other, Some(nil)));
    }

    /// REQ-BOOT-007 operator part: the GUID text form is case-insensitive
    /// (uefi-guid-text.md section 2), so an operator who copies an
    /// upper-case GUID still suppresses the device that sends it.
    #[tokio::test(flavor = "current_thread")]
    async fn suppression_guid_text_is_case_insensitive() {
        let r = dhcp_rig("qa-guid-case").await;
        let g = Guid::from_wire(SAMPLE_GUID_WIRE);
        let upper = g.to_string().to_uppercase();
        let path = r.s.dir.join("suppress.toml");
        std::fs::write(
            &path,
            format!("schema_version = 1\n[[device]]\nguid = \"{upper}\"\n"),
        )
        .unwrap();
        set_mode(&path, 0o644);
        let h = Suppression::load_initial(&path, trust()).unwrap();
        r.suppression.set((*h.current()).clone());
        let other_nic = RequestBuilder::pxe_discover().chaddr([0x52, 0x54, 0, 0, 7, 7]);
        assert!(
            r.send(ListenPort::Dhcp67, BCAST_SRC, &other_nic.build())
                .is_none()
        );
    }

    // -----------------------------------------------------------------
    // Exit criterion 2 end to end: tamper -> RRQ refused -> offers stop ->
    // restore + re-check -> offers resume. With audit evidence.
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn rrq_tamper_stops_offers_and_audits_then_recovers() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-exit2").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        let discover = RequestBuilder::pxe_discover().build();
        assert!(r.send(ListenPort::Dhcp67, BCAST_SRC, &discover).is_some());

        // One byte changes in the boot root while the relay runs.
        let mut bad = r.data.clone();
        bad[2048] = bad[2048].wrapping_add(1);
        r.s.write_boot_file(PROGRAM, &bad);
        cap.clear();

        let c = net.bind(client_ip(60));
        assert_eq!(
            listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[])),
            Disposition::Started
        );
        let (pkt, _) = c.recv().await;
        assert!(
            matches!(parse(&pkt), Ok(Packet::Error { code: 1, .. })),
            "{pkt:?}"
        );
        assert!(c.recv_within(Duration::from_millis(100)).await.is_none());
        wait_idle(&listener).await;

        // Offers stop for the architecture (REQ-BOOT-052).
        assert_eq!(
            r.content.state().current(),
            ServiceState::RunningMissingContent
        );
        assert!(r.send(ListenPort::Dhcp67, BCAST_SRC, &discover).is_none());
        assert_eq!(r.svc.drop_count("missing_content"), 1);

        // Audit evidence (AU-2/AU-3): integrity failure with both digests,
        // the state change, and the refusal with the code sent.
        let fail = cap.named("boot.file.integrity_failed");
        assert_eq!(fail.len(), 1, "{:?}", cap.all());
        assert_au3(&fail[0], "failure");
        let expected = usgp_crypto::sha256(&r.data).to_hex();
        let actual = usgp_crypto::sha256(&bad).to_hex();
        assert!(
            detail_has(&fail[0], "expected_sha256", &expected),
            "{fail:?}"
        );
        assert!(detail_has(&fail[0], "actual_sha256", &actual), "{fail:?}");
        assert!(detail_has(&fail[0], "reason", "digest_mismatch"));
        assert!(detail_has(&fail[0], "cause", "rrq"));
        assert!(detail_has(&fail[0], "file", PROGRAM));
        let st = cap.named("relay.state.changed");
        assert_eq!(st.len(), 1, "{st:?}");
        assert_au3(&st[0], "failure");
        assert!(detail_has(&st[0], "to", "running_missing_content"));
        assert!(detail_has(&st[0], "uefi_x64", "missing_content"));
        let refused = cap.named("tftp.request.refused");
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_au3(&refused[0], "refused");
        assert!(detail_has(&refused[0], "reason", "integrity_failed"));
        assert!(detail_has(&refused[0], "code_sent", "1"));
        assert_eq!(field(&refused[0], "peer"), c.addr.to_string());
        assert!(cap.named("tftp.transfer.started").is_empty());
        assert!(cap.named("dhcp.offer.sent").is_empty());

        // Restore and re-check: back to Running, offers resume.
        cap.clear();
        r.s.write_boot_file(PROGRAM, &r.data);
        r.content.recheck_all("recheck").await;
        assert_eq!(r.content.state().current(), ServiceState::Running);
        let st = cap.named("relay.state.changed");
        assert_eq!(st.len(), 1, "{st:?}");
        assert_au3(&st[0], "success");
        assert!(detail_has(&st[0], "to", "running"));
        assert!(r.send(ListenPort::Dhcp67, BCAST_SRC, &discover).is_some());
        let c2 = net.bind(client_ip(61));
        listener.handle_request(c2.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        assert_eq!(download(&c2).await, r.data);
    }

    /// A file that is replaced by one of the same size (digest differs)
    /// while one transfer is running: the running transfer keeps serving
    /// the bytes it verified (no mixed content), and the next request is
    /// refused.
    #[tokio::test(flavor = "current_thread")]
    async fn swap_during_transfer_never_mixes_content() {
        let r = dhcp_rig("qa-swap").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        let c = net.bind(client_ip(62));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        let (pkt, from) = c.recv().await;
        let mut got = match parse(&pkt).unwrap() {
            Packet::Data { block: 1, data } => data.to_vec(),
            other => panic!("{other:?}"),
        };
        // Swap the file mid-transfer.
        r.s.write_boot_file(PROGRAM, &bytes(4096, 99));
        c.send(from, &encode_ack(1));
        loop {
            let (pkt, from) = c.recv().await;
            match parse(&pkt).unwrap() {
                Packet::Data { block, data } => {
                    got.extend_from_slice(data);
                    c.send(from, &encode_ack(block));
                    if data.len() < 512 {
                        break;
                    }
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, r.data, "served bytes are exactly the verified bytes");
        wait_idle(&listener).await;
        let c2 = net.bind(client_ip(63));
        listener.handle_request(c2.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        let (pkt, _) = c2.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Error { code: 1, .. })));
    }

    // -----------------------------------------------------------------
    // Audit events on success paths
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn offer_and_ack_events_carry_au3_fields() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-offer-ev").await;
        cap.clear();
        let out = r
            .send(
                ListenPort::Dhcp67,
                BCAST_SRC,
                &RequestBuilder::pxe_discover().build(),
            )
            .unwrap();
        assert_eq!(out.destination, Destination::Broadcast68);
        let ev = cap.named("dhcp.offer.sent");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        let e = &ev[0];
        assert_au3(e, "success");
        assert_eq!(field(e, "interface"), IFACE);
        assert_eq!(field(e, "local_addr"), "10.20.1.2:67");
        assert_eq!(field(e, "peer"), "0.0.0.0:68");
        assert_eq!(field(e, "claimed_mac"), "52:54:00:00:01:01");
        assert_eq!(
            field(e, "claimed_guid"),
            Guid::from_wire(SAMPLE_GUID_WIRE).to_string()
        );
        // yiaddr in the event is read from the encoded reply (NIST-010),
        // and the reply on the wire assigns nothing (REQ-BOOT-010).
        let wire_yiaddr = Ipv4Addr::new(out.bytes[16], out.bytes[17], out.bytes[18], out.bytes[19]);
        assert_eq!(
            wire_yiaddr,
            Ipv4Addr::UNSPECIFIED,
            "REQ-BOOT-010 on the wire"
        );
        assert!(detail_has(e, "yiaddr", &wire_yiaddr.to_string()));
        assert!(detail_has(e, "xid", "0x12345678"));
        assert!(detail_has(e, "arch", "7"));
        assert!(detail_has(e, "file", PROGRAM));
        assert!(detail_has(e, "destination", "broadcast"), "{e:?}");
        assert!(detail_has(e, "listen_port", "67"));

        // Relayed ACK on 4011 path: dhcp.ack.sent, peer is the source.
        cap.clear();
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 20, 2, 50), 68);
        r.send(
            ListenPort::BootServer4011,
            src,
            &RequestBuilder::pxe_request().ciaddr(*src.ip()).build(),
        )
        .unwrap();
        let ev = cap.named("dhcp.ack.sent");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        assert_au3(&ev[0], "success");
        assert_eq!(field(&ev[0], "local_addr"), "10.20.1.2:4011");
        assert_eq!(field(&ev[0], "peer"), src.to_string());
        assert!(detail_has(&ev[0], "listen_port", "4011"));
    }

    /// Malformed and non-PXE traffic produces no per-packet audit line
    /// (log volume stays bounded under a flood; drops are counted for the
    /// periodic summary instead).
    #[tokio::test(flavor = "current_thread")]
    async fn drops_are_counted_not_logged_per_packet() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-drop-ev").await;
        cap.clear();
        for i in 0..500u64 {
            let len = usize::try_from(i % 600).unwrap();
            let _ = r.send(ListenPort::Dhcp67, BCAST_SRC, &bytes(len, i + 1));
        }
        for _ in 0..50 {
            let b = RequestBuilder::pxe_discover().set_option(60, b"usgp-non-pxe-client".to_vec());
            assert!(r.send(ListenPort::Dhcp67, BCAST_SRC, &b.build()).is_none());
        }
        assert!(cap.all().is_empty(), "{:?}", cap.all());
        assert!(r.svc.drop_count("malformed") >= 400);
        assert_eq!(r.svc.drop_count("not_pxe_client"), 50);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tftp_completed_transfer_events() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-tftp-ev").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        cap.clear();
        let c = net.bind(client_ip(70));
        listener.handle_request(
            c.addr,
            &rrq(PROGRAM.as_bytes(), b"octet", &[(b"tsize", b"0")]),
        );
        assert_eq!(download(&c).await, r.data);
        wait_idle(&listener).await;
        settle().await;
        let st = cap.named("tftp.transfer.started");
        assert_eq!(st.len(), 1, "{:?}", cap.all());
        assert_au3(&st[0], "success");
        assert_eq!(field(&st[0], "peer"), c.addr.to_string());
        assert_eq!(field(&st[0], "interface"), IFACE);
        assert!(detail_has(&st[0], "verified_sha256", "true"));
        assert!(detail_has(&st[0], "tsize", "4096"));
        assert!(detail_has(&st[0], "oack", "true"));
        let done = cap.named("tftp.transfer.completed");
        assert_eq!(done.len(), 1, "{:?}", cap.all());
        assert_au3(&done[0], "success");
        assert!(detail_has(&done[0], "file", PROGRAM));
        assert!(detail_has(&done[0], "size", "4096"));
        assert!(detail_has(&done[0], "last_block", "9"));
        assert!(cap.named("tftp.transfer.failed").is_empty());
    }

    // -----------------------------------------------------------------
    // Audit events on failure paths
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn tftp_retry_cap_emits_failed_event() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-tftp-fail").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        cap.clear();
        let c = net.bind(client_ip(71));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        // Established (first ACK), then silent: the retry cap ends it.
        let (_, tid) = c.recv().await;
        c.send(tid, &encode_ack(1));
        while c.recv_within(Duration::from_secs(120)).await.is_some() {}
        wait_idle(&listener).await;
        let failed = cap.named("tftp.transfer.failed");
        assert_eq!(failed.len(), 1, "{:?}", cap.all());
        assert_au3(&failed[0], "failure");
        assert!(detail_has(&failed[0], "reason", "retry_cap"), "{failed:?}");
        assert!(cap.named("tftp.transfer.completed").is_empty());
    }

    /// SEC-001: a request that never gets a first ACK ends at the
    /// handshake timeout, with its own reason; NIST-011: the started and
    /// failed events carry the SHA-256 of the served file.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn tftp_handshake_timeout_emits_failed_event_with_digest() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-tftp-hs").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        cap.clear();
        let c = net.bind(client_ip(72));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        while c.recv_within(Duration::from_secs(120)).await.is_some() {}
        wait_idle(&listener).await;
        let digest = r
            .content
            .manifest()
            .get(PROGRAM.as_bytes())
            .unwrap()
            .sha256
            .to_hex();
        let started = cap.named("tftp.transfer.started");
        assert_eq!(started.len(), 1, "{:?}", cap.all());
        assert!(detail_has(&started[0], "sha256", &digest), "{started:?}");
        let failed = cap.named("tftp.transfer.failed");
        assert_eq!(failed.len(), 1, "{:?}", cap.all());
        assert!(
            detail_has(&failed[0], "reason", "handshake_timeout"),
            "{failed:?}"
        );
        assert!(detail_has(&failed[0], "sha256", &digest), "{failed:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn tftp_client_abort_emits_event() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-tftp-abort").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        cap.clear();
        let c = net.bind(client_ip(72));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        let (_, from) = c.recv().await;
        c.send(
            from,
            &usgp_tftp::encode_error(usgp_tftp::ErrorCode::NotDefined, "user abort"),
        );
        wait_idle(&listener).await;
        settle().await;
        let ev = cap.named("tftp.transfer.aborted_by_client");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        assert_au3(&ev[0], "failure");
        assert!(detail_has(&ev[0], "client_error_code", "0"));
    }

    /// Every refusal path: WRQ (ERROR 2), traversal / absolute / unknown
    /// names (ERROR 1), a mode other than octet (ERROR 4), and a file too
    /// large for 16-bit block numbers (ERROR 3, before any OACK or DATA,
    /// REQ-BOOT-035). Each is audited with the code sent; none of the
    /// ERROR packets carries a host path or digest (SI-11, REQ-BOOT-043).
    #[tokio::test(flavor = "current_thread")]
    async fn every_tftp_refusal_audited_and_discloses_nothing() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-refuse").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        let root = r.s.root().display().to_string();
        let manifest = r.s.manifest_path().display().to_string();
        let digest = usgp_crypto::sha256(&r.data).to_hex();
        cap.clear();

        let wrq = encode_request(Opcode::Wrq, PROGRAM.as_bytes(), b"octet", &[]);
        let cases: Vec<(Vec<u8>, u16, &str)> = vec![
            (wrq, 2, "write_request"),
            (
                rrq(b"../usgp-test-payload.efi", b"octet", &[]),
                1,
                "not_published",
            ),
            (rrq(b"/etc/passwd", b"octet", &[]), 1, "not_published"),
            (rrq(root.as_bytes(), b"octet", &[]), 1, "not_published"),
            (
                rrq(format!("{root}/{PROGRAM}").as_bytes(), b"octet", &[]),
                1,
                "not_published",
            ),
            (
                rrq(b"./usgp-test-payload.efi", b"octet", &[]),
                1,
                "not_published",
            ),
            (
                rrq(b"USGP-TEST-PAYLOAD.EFI", b"octet", &[]),
                1,
                "not_published",
            ),
            (
                rrq(b"usgp-test-payload.efi ", b"octet", &[]),
                1,
                "not_published",
            ),
            (
                rrq(b"..\\usgp-test-payload.efi", b"octet", &[]),
                1,
                "not_published",
            ),
            (
                rrq(PROGRAM.as_bytes(), b"netascii", &[]),
                4,
                "unsupported_mode",
            ),
            (rrq(PROGRAM.as_bytes(), b"mail", &[]), 4, "unsupported_mode"),
        ];
        for (i, (pkt, code, reason)) in cases.iter().enumerate() {
            let c = net.bind(client_ip(100 + u8::try_from(i).unwrap()));
            assert_eq!(
                listener.handle_request(c.addr, pkt),
                Disposition::Refused(reason),
                "case {i}"
            );
            let (reply, from) = c.recv().await;
            match parse(&reply) {
                Ok(Packet::Error { code: got, message }) => {
                    assert_eq!(got, *code, "case {i}");
                    let text = String::from_utf8_lossy(message);
                    assert!(
                        [
                            "file not found",
                            "read-only server",
                            "only octet mode is supported"
                        ]
                        .contains(&text.as_ref()),
                        "case {i}: unexpected ERROR text {text:?}"
                    );
                }
                other => panic!("case {i}: {other:?}"),
            }
            assert_ne!(from.port(), 69, "refusal from a new TID");
            for secret in [&root, &manifest, &digest] {
                assert!(
                    !reply.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "case {i}: ERROR discloses {secret}"
                );
            }
            assert!(c.recv_within(Duration::from_millis(50)).await.is_none());
        }
        settle().await;
        let refused = cap.named("tftp.request.refused");
        assert_eq!(refused.len(), cases.len(), "{:?}", cap.all());
        for (e, (_, code, reason)) in refused.iter().zip(&cases) {
            assert_au3(e, "refused");
            assert!(detail_has(e, "reason", reason), "{e:?}");
            assert!(detail_has(e, "code_sent", &code.to_string()), "{e:?}");
        }
        // Refusals never touch the content state.
        assert_eq!(r.content.state().current(), ServiceState::Running);
        assert!(cap.named("relay.state.changed").is_empty());
    }

    /// REQ-BOOT-035 at the relay with negotiation: a file needing 65536
    /// blocks at the 512 default, requested with tsize, gets ERROR 3 as
    /// the very first packet (no OACK, no DATA), is audited, and does not
    /// mark content missing.
    #[tokio::test(flavor = "current_thread")]
    async fn too_many_blocks_with_options_refused_before_oack() {
        let (cap, _g) = Capture::install();
        let s = Scratch::new("qa-035");
        let data = bytes(65_535 * 512, 3);
        s.publish(&[(PROGRAM, &data)]);
        let c_store = content(&config(&s)).await;
        let net = MemNet::new();
        let listener = tftp_listener(&s, &c_store, &net);
        cap.clear();
        let c = net.bind(client_ip(80));
        listener.handle_request(
            c.addr,
            &rrq(
                PROGRAM.as_bytes(),
                b"octet",
                &[(b"tsize", b"0"), (b"blksize", b"512")],
            ),
        );
        let (pkt, _) = c.recv().await;
        assert!(
            matches!(parse(&pkt), Ok(Packet::Error { code: 3, .. })),
            "first packet must be ERROR 3, got {pkt:?}"
        );
        assert!(c.recv_within(Duration::from_millis(100)).await.is_none());
        wait_idle(&listener).await;
        settle().await;
        let refused = cap.named("tftp.request.refused");
        assert_eq!(refused.len(), 1, "{:?}", cap.all());
        assert!(detail_has(&refused[0], "code_sent", "3"));
        assert!(cap.named("tftp.transfer.started").is_empty());
        assert_eq!(c_store.state().current(), ServiceState::Running);
        // The refusal is a transfer limit, not missing content: offers go on.
        assert!(c_store.offerable_program().is_some());
    }

    // -----------------------------------------------------------------
    // REQ-BOOT-021: relay agent information at the service level
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn option82_echo_and_drop_recorded_in_audit() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-82").await;
        let agent_src = SocketAddrV4::new(AGENT, 67);
        let small = vec![1, 4, b'r', b't', b'B', b'0', 2, 3, 1, 2, 3];
        cap.clear();
        let req = RequestBuilder::pxe_discover()
            .giaddr(AGENT)
            .hops(1)
            .option(82, small.clone());
        let out = r.send(ListenPort::Dhcp67, agent_src, &req.build()).unwrap();
        let v = inspect_reply(&out.bytes).unwrap();
        assert_eq!(v.relay_info, Some(&small[..]));
        assert_eq!(v.last_code, Some(82));
        let ev = cap.named("dhcp.offer.sent");
        assert!(detail_has(&ev[0], "relay_info_echoed", "true"));
        assert!(detail_has(&ev[0], "giaddr", "10.20.2.1"));

        // A 255-octet option 82 does not fit an ACK that also echoes tag
        // 71 at the 548 default: the reply is still sent, without 82
        // (RFC 3046 section 2.2), and the audit flag says so.
        cap.clear();
        let big = vec![0x5a; 255];
        let req = RequestBuilder::pxe_request()
            .giaddr(AGENT)
            .hops(1)
            .without(57)
            .option(43, vec![71, 4, 0, 0, 0, 0, 255])
            .option(82, big);
        let out = r
            .send(ListenPort::Dhcp67, agent_src, &req.build())
            .expect("reply without option 82");
        let v = inspect_reply(&out.bytes).unwrap();
        assert!(v.relay_info.is_none());
        assert!(out.bytes.len() <= 548);
        let ev = cap.named("dhcp.ack.sent");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        assert!(detail_has(&ev[0], "relay_info_echoed", "false"));

        // A request with no option 82 never gets one.
        let out = r
            .send(
                ListenPort::Dhcp67,
                agent_src,
                &RequestBuilder::pxe_discover()
                    .giaddr(AGENT)
                    .hops(1)
                    .chaddr([0x52, 0x54, 0, 0, 3, 3])
                    .build(),
            )
            .unwrap();
        assert!(inspect_reply(&out.bytes).unwrap().relay_info.is_none());
    }

    // -----------------------------------------------------------------
    // REQ-BOOT-043: nothing host-specific in boot-network traffic
    // -----------------------------------------------------------------

    #[tokio::test(flavor = "current_thread")]
    async fn dhcp_replies_carry_no_host_data() {
        let r = dhcp_rig("qa-043").await;
        let root = r.s.root().display().to_string();
        let manifest = r.s.manifest_path().display().to_string();
        let digest = usgp_crypto::sha256(&r.data).to_hex();
        let out = r
            .send(
                ListenPort::Dhcp67,
                BCAST_SRC,
                &RequestBuilder::pxe_discover().build(),
            )
            .unwrap();
        for secret in [&root, &manifest, &digest, &r.s.dir.display().to_string()] {
            assert!(
                !out.bytes
                    .windows(secret.len())
                    .any(|w| w == secret.as_bytes()),
                "reply discloses {secret}"
            );
        }
        // sname is all zero; file is the published name only.
        assert!(out.bytes[44..108].iter().all(|b| *b == 0), "sname empty");
        let v = inspect_reply(&out.bytes).unwrap();
        assert_eq!(v.file, PROGRAM.as_bytes());
        // Served TFTP payload is the published file and nothing else.
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        let c = net.bind(client_ip(90));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        assert_eq!(download(&c).await, r.data);
    }

    // -----------------------------------------------------------------
    // Re-verify round 1 (fixes-round-1-a/-b)
    // -----------------------------------------------------------------

    /// BOOT-005 through the relay: an ERROR from the client's TID that is
    /// not NUL-terminated still ends the transfer, releases the slot and
    /// is audited as `tftp.transfer.aborted_by_client` with the client's
    /// code. A 3-octet opcode-5 datagram is still ignored (transfer goes
    /// on), and the same sloppy ERROR from a foreign TID (same IP, other
    /// port) does not end the transfer (RFC 1350 §4: ERROR 5 to the
    /// intruder).
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn sloppy_client_error_ends_relay_transfer_only_from_client_tid() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-r1-sloppy").await;
        let net = MemNet::new();
        let listener = tftp_listener(&r.s, &r.content, &net);
        cap.clear();
        let c = net.bind(client_ip(73));
        listener.handle_request(c.addr, &rrq(PROGRAM.as_bytes(), b"octet", &[]));
        let (pkt, tid) = c.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })));

        // Too short to be an ERROR: ignored, the transfer continues.
        c.send(tid, &[0, 5, 0]);
        c.send(tid, &encode_ack(1));
        let block2 = loop {
            let (pkt, from) = c.recv().await;
            assert_eq!(from, tid);
            match parse(&pkt) {
                Ok(Packet::Data { block: 2, .. }) => break true,
                Ok(Packet::Data { block: 1, .. }) => {}
                other => panic!("unexpected {other:?}"),
            }
        };
        assert!(block2);

        // Unterminated ERROR from a foreign port: ERROR 5 to it, transfer
        // still alive.
        let intruder = net.bind(client_ip(73));
        intruder.send(tid, &[0, 5, 0, 3, b'x']);
        let (pkt, from) = intruder.recv().await;
        assert_eq!(from, tid);
        assert!(
            matches!(parse(&pkt), Ok(Packet::Error { code: 5, .. })),
            "{pkt:?}"
        );
        let (pending, active) = listener.shared().active();
        assert_eq!(pending + active, 1, "transfer still holds its slot");
        assert!(cap.named("tftp.transfer.aborted_by_client").is_empty());

        // Unterminated ERROR (code 3, no NUL) from the client TID ends it.
        c.send(tid, &[0, 5, 0, 3, b'x']);
        wait_idle(&listener).await;
        settle().await;
        let ev = cap.named("tftp.transfer.aborted_by_client");
        assert_eq!(ev.len(), 1, "{:?}", cap.all());
        assert_au3(&ev[0], "failure");
        assert!(detail_has(&ev[0], "client_error_code", "3"), "{ev:?}");
        assert!(cap.named("tftp.transfer.completed").is_empty());
        assert!(cap.named("tftp.transfer.failed").is_empty());
        // Nothing more is sent to the client (no retransmission).
        while let Some((pkt, _)) = c.recv_within(Duration::from_secs(30)).await {
            assert!(
                !matches!(parse(&pkt), Ok(Packet::Data { block: 3.., .. })),
                "DATA after abort: {pkt:?}"
            );
        }
        assert_eq!(listener.shared().active(), (0, 0));
    }

    /// SEC-003 through the relay: on port 67 with giaddr 0, a ciaddr that
    /// is not the UDP source address is never used as a unicast target
    /// (the reply is broadcast and the audit event says so); a matching
    /// ciaddr gets unicast to ciaddr:68.
    #[tokio::test(flavor = "current_thread")]
    async fn spoofed_ciaddr_not_used_as_unicast_target() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-r1-ciaddr").await;
        let victim = Ipv4Addr::new(10, 20, 1, 77);
        let req = || {
            RequestBuilder::pxe_request()
                .ciaddr(victim)
                .option(54, IFACE_ADDR.octets().to_vec())
                .build()
        };
        // SEC-002 (round 2): a giaddr-0 request on 67 from another subnet
        // is dropped, so it can neither be reflected nor broadcast.
        cap.clear();
        let off = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 9), 68);
        assert!(r.send(ListenPort::Dhcp67, off, &req()).is_none());
        assert_eq!(r.svc.drop_count("off_segment_source"), 1);
        assert!(cap.named("dhcp.ack.sent").is_empty(), "{:?}", cap.all());
        for src in [
            SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 99), 68),
            BCAST_SRC,
        ] {
            cap.clear();
            let out = r
                .send(ListenPort::Dhcp67, src, &req())
                .unwrap_or_else(|| panic!("{src}: expected a reply"));
            assert_eq!(out.destination, Destination::Broadcast68, "{src}");
            let ev = cap.named("dhcp.ack.sent");
            assert_eq!(ev.len(), 1, "{:?}", cap.all());
            assert!(detail_has(&ev[0], "destination", "broadcast"), "{ev:?}");
        }
        cap.clear();
        let out = r
            .send(ListenPort::Dhcp67, SocketAddrV4::new(victim, 68), &req())
            .unwrap();
        assert_eq!(
            out.destination,
            Destination::Unicast(SocketAddrV4::new(victim, 68))
        );
        let ev = cap.named("dhcp.ack.sent");
        assert!(detail_has(&ev[0], "destination", "unicast"), "{ev:?}");
    }

    /// NIST-010: the yiaddr in the offer/ack event is the value encoded in
    /// the reply, on every reply path (not a constant).
    #[tokio::test(flavor = "current_thread")]
    async fn event_yiaddr_matches_wire_on_every_path() {
        let (cap, _g) = Capture::install();
        let r = dhcp_rig("qa-r1-yiaddr").await;
        let paths: Vec<(ListenPort, SocketAddrV4, Vec<u8>, &str)> = vec![
            (
                ListenPort::Dhcp67,
                BCAST_SRC,
                RequestBuilder::pxe_discover().build(),
                "dhcp.offer.sent",
            ),
            (
                ListenPort::Dhcp67,
                SocketAddrV4::new(AGENT, 67),
                RequestBuilder::pxe_discover().giaddr(AGENT).hops(1).build(),
                "dhcp.offer.sent",
            ),
            (
                ListenPort::BootServer4011,
                SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 77), 68),
                RequestBuilder::pxe_request()
                    .ciaddr(Ipv4Addr::new(10, 20, 1, 77))
                    .build(),
                "dhcp.ack.sent",
            ),
        ];
        for (port, src, pkt, name) in paths {
            cap.clear();
            let out = r.send(port, src, &pkt).expect("reply");
            let wire = usgp_relay::dhcp::reply_yiaddr(&out.bytes);
            assert_eq!(wire, "0.0.0.0");
            let ev = cap.named(name);
            assert_eq!(ev.len(), 1, "{:?}", cap.all());
            assert!(detail_has(&ev[0], "yiaddr", &wire), "{ev:?}");
        }
    }
}
