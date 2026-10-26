//! QA gap tests for M1 fix rounds 2 and 3 (qa-engineer, SA-11 / CA-2
//! evidence, final pass).
//!
//! The coders' tests prove the round-2/3 behaviours. These add the parts
//! no test asserted:
//!
//! - the `origin` field of `dhcp.offer.sent` / `dhcp.ack.sent` on every
//!   classification path, and that an `off_segment_source` drop produces
//!   no per-packet audit line (AU-3, SC-5);
//! - the AU-3 fields of `boot.file.verify_slow` emitted from the real TFTP
//!   timeout path, and its per-file rate limit with the suppressed count
//!   (AU-2, SC-5; BOOT-012);
//! - prefix boundaries for same-segment classification (network and
//!   broadcast addresses of the subnet, neighbours just outside, /8 and
//!   /31) (SC-5, SEC-002);
//! - the boot-root trust check applies to the symbolic link's target, not
//!   the link (SEC-010, CM-5).
//!
//! All fixtures are generated in temp dirs at test time.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, CA-2, AU-2, AU-3, SC-5, CM-5, SI-7
//! - SPEC: specs/boot-network.md#REQ-BOOT-002, -034, -041, -044

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod qa {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use usgp_common::config::{ConfigError, TrustRule};
    use usgp_dhcp::craft::RequestBuilder;
    use usgp_dhcp::{Destination, ListenPort};
    use usgp_relay::config::{ConfigLoadError, InterfaceConfig, load};
    use usgp_relay::content::{FILE_VERIFY_SLOW, SLOW_REPORT_INTERVAL};
    use usgp_relay::dhcp::{DhcpService, Origin, classify};
    use usgp_relay::limits::Counters;
    use usgp_relay::suppress::Suppression;
    use usgp_relay::tftp::{Disposition, TftpListener, TftpShared};
    use usgp_tftp::{Opcode, encode_request};

    use crate::common::{
        IFACE_ADDR, MemFactory, MemNet, PROGRAM, Scratch, bytes, config, content, iface, set_mode,
        trust, write_config_toml,
    };

    // -----------------------------------------------------------------
    // Audit capture (same design as qa_m1.rs): thread-local subscriber
    // recording `audit`-target events; tests run on current-thread
    // runtimes so spawned tasks emit on this thread.
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

    fn field<'a>(r: &'a Record, k: &str) -> &'a str {
        r.get(k).map_or("<absent>", String::as_str)
    }

    /// `detail` is a JSON object text; checks it contains `"key":"value"`.
    fn detail_has(r: &Record, key: &str, value: &str) -> bool {
        r.get("detail")
            .is_some_and(|d| d.contains(&format!("\"{key}\":\"{value}\"")))
    }

    // -----------------------------------------------------------------
    // SEC-002 / BOOT-011: `origin` in DHCP audit events
    // -----------------------------------------------------------------

    /// (what, port, source, packet, event name, expected origin).
    type OriginCase = (
        &'static str,
        ListenPort,
        SocketAddrV4,
        Vec<u8>,
        &'static str,
        &'static str,
    );

    /// Every answered path records how the request was classified, and an
    /// `off_segment_source` drop is counted, not logged per packet.
    #[tokio::test(flavor = "current_thread")]
    async fn origin_recorded_in_dhcp_events_on_every_path() {
        let (cap, _g) = Capture::install();
        let s = Scratch::new("qa3-origin");
        s.publish(&[(PROGRAM, &bytes(512, 3))]);
        let cfg = config(&s);
        let c = content(&cfg).await;
        let t0 = Instant::now();
        let svc = DhcpService::new(
            Arc::clone(&c),
            Arc::new(Suppression::disabled()),
            cfg.local_addresses(),
            &cfg.limits,
            Arc::new(Mutex::new(Counters::default())),
            t0,
        );
        let i = iface();
        let agent = Ipv4Addr::new(10, 20, 2, 1);
        let routed_client = SocketAddrV4::new(Ipv4Addr::new(10, 20, 3, 40), 68);
        let cases: [OriginCase; 5] = [
            (
                "broadcast discover from 0.0.0.0",
                ListenPort::Dhcp67,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68),
                RequestBuilder::pxe_discover()
                    .chaddr([2, 0, 0, 0, 0, 1])
                    .build(),
                "dhcp.offer.sent",
                "same_segment",
            ),
            (
                "giaddr-0 request from inside the subnet",
                ListenPort::Dhcp67,
                SocketAddrV4::new(Ipv4Addr::new(10, 20, 1, 77), 68),
                RequestBuilder::pxe_discover()
                    .chaddr([2, 0, 0, 0, 0, 2])
                    .build(),
                "dhcp.offer.sent",
                "same_segment",
            ),
            (
                "relayed discover (giaddr set)",
                ListenPort::Dhcp67,
                SocketAddrV4::new(agent, 67),
                RequestBuilder::pxe_discover()
                    .giaddr(agent)
                    .chaddr([2, 0, 0, 0, 0, 3])
                    .build(),
                "dhcp.offer.sent",
                "routed",
            ),
            (
                "off-subnet request on 67 with ciaddr = source",
                ListenPort::Dhcp67,
                routed_client,
                RequestBuilder::pxe_request()
                    .ciaddr(*routed_client.ip())
                    .option(54, IFACE_ADDR.octets().to_vec())
                    .chaddr([2, 0, 0, 0, 0, 4])
                    .build(),
                "dhcp.ack.sent",
                "routed",
            ),
            (
                "off-subnet request on 4011",
                ListenPort::BootServer4011,
                routed_client,
                RequestBuilder::pxe_request()
                    .ciaddr(*routed_client.ip())
                    .chaddr([2, 0, 0, 0, 0, 5])
                    .build(),
                "dhcp.ack.sent",
                "routed",
            ),
        ];
        for (what, port, src, pkt, event, origin) in cases {
            cap.clear();
            let out = svc
                .handle(&i, port, src, &pkt, t0)
                .unwrap_or_else(|| panic!("{what}: no reply"));
            if origin == "routed" && src.ip() != &agent {
                assert_eq!(out.destination, Destination::Unicast(src), "{what}");
            }
            let ev = cap.named(event);
            assert_eq!(ev.len(), 1, "{what}: {:?}", cap.all());
            assert_eq!(field(&ev[0], "outcome"), "success", "{what}");
            assert!(detail_has(&ev[0], "origin", origin), "{what}: {:?}", ev[0]);
            assert_eq!(field(&ev[0], "peer"), src.to_string(), "{what}");
        }

        // Off-subnet giaddr-0 on 67 without ciaddr = source: dropped,
        // counted, and no audit line per packet.
        cap.clear();
        for n in 0..20u8 {
            let src = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, n + 1), 68);
            let pkt = RequestBuilder::pxe_discover()
                .chaddr([2, 0, 0, 0, 1, n])
                .build();
            assert!(svc.handle(&i, ListenPort::Dhcp67, src, &pkt, t0).is_none());
        }
        assert!(cap.all().is_empty(), "{:?}", cap.all());
        assert_eq!(svc.drop_count("off_segment_source"), 20);
    }

    // -----------------------------------------------------------------
    // SEC-002: prefix boundaries
    // -----------------------------------------------------------------

    /// (interface address, prefix length, inside, outside).
    type BoundaryCase = ([u8; 4], u8, &'static [[u8; 4]], &'static [[u8; 4]]);

    fn iface_at(addr: [u8; 4], len: u8) -> InterfaceConfig {
        InterfaceConfig {
            name: "relay0".to_owned(),
            address: Ipv4Addr::from(addr),
            prefix_len: Some(len),
        }
    }

    /// Known-answer boundaries: the first and last address of the subnet
    /// are same-segment, the neighbours just outside are not, on /8, /24
    /// and /31; the classification follows on port 67 with giaddr 0.
    #[test]
    fn same_segment_prefix_boundaries() {
        let none = Ipv4Addr::UNSPECIFIED;
        let cases: [BoundaryCase; 4] = [
            (
                [10, 20, 1, 2],
                24,
                &[[10, 20, 1, 0], [10, 20, 1, 1], [10, 20, 1, 255]],
                &[[10, 20, 0, 255], [10, 20, 2, 0], [10, 21, 1, 2]],
            ),
            (
                [10, 20, 1, 2],
                31,
                &[[10, 20, 1, 2], [10, 20, 1, 3]],
                &[[10, 20, 1, 1], [10, 20, 1, 4]],
            ),
            (
                [10, 200, 3, 4],
                8,
                &[[10, 0, 0, 1], [10, 255, 255, 254]],
                &[[9, 255, 255, 255], [11, 0, 0, 0]],
            ),
            (
                [172, 16, 5, 9],
                20,
                &[[172, 16, 0, 1], [172, 16, 15, 254]],
                &[[172, 15, 255, 254], [172, 16, 16, 1]],
            ),
        ];
        for (addr, len, inside, outside) in cases {
            let i = iface_at(addr, len);
            for a in inside {
                let ip = Ipv4Addr::from(*a);
                assert!(i.on_segment(ip), "{ip} in /{len} of {:?}", addr);
                assert_eq!(
                    classify(
                        &i,
                        ListenPort::Dhcp67,
                        SocketAddrV4::new(ip, 68),
                        none,
                        none
                    ),
                    Some(Origin::SameSegment),
                    "{ip} /{len}"
                );
            }
            for a in outside {
                let ip = Ipv4Addr::from(*a);
                assert!(!i.on_segment(ip), "{ip} outside /{len} of {:?}", addr);
                let src = SocketAddrV4::new(ip, 68);
                assert_eq!(
                    classify(&i, ListenPort::Dhcp67, src, none, none),
                    None,
                    "{ip} /{len}"
                );
                assert_eq!(
                    classify(&i, ListenPort::Dhcp67, src, none, ip),
                    Some(Origin::Routed),
                    "{ip} /{len} ciaddr = source"
                );
                assert_eq!(
                    classify(&i, ListenPort::BootServer4011, src, none, none),
                    Some(Origin::Routed),
                    "{ip} /{len} on 4011"
                );
            }
        }
    }

    // -----------------------------------------------------------------
    // BOOT-012 / SEC-008: boot.file.verify_slow from the TFTP path
    // -----------------------------------------------------------------

    /// With the only blocking thread held, every RRQ's verification
    /// times out at the handshake deadline. The first timeout emits
    /// `boot.file.verify_slow` with outcome `dropped` and the AU-3 detail
    /// fields; timeouts within the next 60 s emit nothing; the first one
    /// after 60 s emits again with `suppressed_since_last` equal to the
    /// number swallowed. No client-supplied name is ever reported.
    #[test]
    fn verify_slow_event_fields_and_rate_limit_from_tftp_path() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .max_blocking_threads(1)
            .build()
            .unwrap();
        rt.block_on(async {
            let (cap, _g) = Capture::install();
            let s = Scratch::new("qa3-slow");
            let data = bytes(1000, 7);
            s.publish(&[(PROGRAM, &data)]);
            let cfg = config(&s);
            let c = content(&cfg).await;
            let shed = Arc::new(Mutex::new(Counters::default()));
            let shared = TftpShared::new(
                &cfg.limits,
                Arc::clone(&shed),
                tokio::time::Instant::now().into_std(),
            );
            let net = MemNet::new();
            let listener = TftpListener::new(
                iface(),
                Arc::clone(&c),
                cfg.tftp_listener_config(),
                MemFactory {
                    net: Arc::clone(&net),
                    ip: IpAddr::V4(IFACE_ADDR),
                },
                Arc::clone(&shared),
            );
            let timeout = cfg.tftp_listener_config().handshake_timeout;
            let limit_ms = timeout.as_millis().to_string();
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = wait.recv();
            });
            cap.clear();
            let rrq = encode_request(Opcode::Rrq, PROGRAM.as_bytes(), b"octet", &[]);
            let fire = |n: u8| {
                let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 100 + n)), 3000);
                assert_eq!(listener.handle_request(src, &rrq), Disposition::Started);
            };
            let pass_deadline = || async {
                tokio::time::advance(timeout + Duration::from_millis(5)).await;
                for _ in 0..20 {
                    tokio::task::yield_now().await;
                }
            };

            fire(1);
            pass_deadline().await;
            let ev = cap.named(FILE_VERIFY_SLOW);
            assert_eq!(ev.len(), 1, "{:?}", cap.all());
            let e = &ev[0];
            assert_eq!(field(e, "component"), "usgp-relay", "{e:?}");
            assert_eq!(field(e, "outcome"), "dropped", "{e:?}");
            assert!(detail_has(e, "file", PROGRAM), "{e:?}");
            assert!(detail_has(e, "size", &data.len().to_string()), "{e:?}");
            assert!(detail_has(e, "limit_ms", &limit_ms), "{e:?}");
            assert!(detail_has(e, "suppressed_since_last", "0"), "{e:?}");
            let detail = field(e, "detail");
            let elapsed: u128 = detail
                .split("\"elapsed_ms\":\"")
                .nth(1)
                .and_then(|t| t.split('"').next())
                .and_then(|v| v.parse().ok())
                .unwrap_or_else(|| panic!("elapsed_ms missing: {detail}"));
            assert!(
                elapsed >= timeout.as_millis() && elapsed <= timeout.as_millis() + 10,
                "elapsed_ms {elapsed} vs limit {limit_ms}"
            );
            assert!(!detail.contains(&s.dir.display().to_string()), "{detail}");

            // Two more timeouts inside the interval: counted, not logged.
            cap.clear();
            fire(2);
            pass_deadline().await;
            fire(3);
            pass_deadline().await;
            assert!(cap.named(FILE_VERIFY_SLOW).is_empty(), "{:?}", cap.all());
            assert_eq!(shed.lock().unwrap().get("tftp_verify_timeout"), 3);

            // After the interval: one event carrying the swallowed count.
            tokio::time::advance(SLOW_REPORT_INTERVAL).await;
            fire(4);
            pass_deadline().await;
            let ev = cap.named(FILE_VERIFY_SLOW);
            assert_eq!(ev.len(), 1, "{:?}", cap.all());
            assert!(
                detail_has(&ev[0], "suppressed_since_last", "2"),
                "{:?}",
                ev[0]
            );
            assert_eq!(shared.active(), (0, 0));

            release.send(()).unwrap();
            blocker.await.unwrap();
        });
    }

    // -----------------------------------------------------------------
    // SEC-010: the trust check is applied to the canonical boot root
    // -----------------------------------------------------------------

    fn untrusted_rule(e: &ConfigLoadError) -> Option<TrustRule> {
        match e {
            ConfigLoadError::File(ConfigError::Untrusted { rule, .. }) => Some(*rule),
            _ => None,
        }
    }

    /// A boot root configured through a trusted-looking symbolic link to
    /// a world-writable directory is refused at load: the check runs on
    /// the link's target. A link to a regular file is refused as not a
    /// directory, and a dangling link is refused.
    #[test]
    fn boot_root_symlink_target_is_what_gets_trust_checked() {
        let s = Scratch::new("qa3-root-target");
        s.publish(&[(PROGRAM, b"payload")]);
        let open = s.dir.join("open");
        std::fs::create_dir(&open).unwrap();
        set_mode(&open, 0o777);
        let link = s.dir.join("root-link");
        let base = std::fs::read_to_string(write_config_toml(&s, "")).unwrap();
        let p = s.dir.join("relay.toml");
        let point_root_at_link = || {
            let text = base.replace(
                &format!("root = \"{}\"", s.root().display()),
                &format!("root = \"{}\"", link.display()),
            );
            assert_ne!(text, base);
            std::fs::write(&p, text).unwrap();
            set_mode(&p, 0o644);
        };

        std::os::unix::fs::symlink(&open, &link).unwrap();
        point_root_at_link();
        let e = load(&p, trust()).unwrap_err();
        assert_eq!(untrusted_rule(&e), Some(TrustRule::WorldWritable), "{e:?}");

        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(s.manifest_path(), &link).unwrap();
        let e = load(&p, trust()).unwrap_err();
        assert_eq!(e.field(), "boot.root", "{e:?}");

        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(s.dir.join("nowhere"), &link).unwrap();
        assert!(load(&p, trust()).is_err());

        // Control: the same link to the trusted root loads and stores the
        // canonical path.
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(s.root(), &link).unwrap();
        let cfg = load(&p, trust()).unwrap().config;
        assert_eq!(cfg.boot.root, std::fs::canonicalize(s.root()).unwrap());
    }
}
