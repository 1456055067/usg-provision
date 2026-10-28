//! TFTP service tests through `TftpListener` with in-memory sockets:
//! downloads with and without options, retries, caps, rate limits, foreign
//! TIDs, refusals, and many concurrent clients with one stalled.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SC-5, CM-7, SI-10, SI-11, SA-11
//! - SPEC: specs/boot-network.md#REQ-BOOT-030..035, #REQ-BOOT-040,
//!   #REQ-BOOT-041, #REQ-BOOT-044
//! - RFC 1350 §4 (TIDs, ERROR 5), §6; RFC 1123 §4.2.3.1; RFC 2347/2348/2349

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod tftp {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use usgp_relay::config::{InterfaceConfig, RelayConfig};
    use usgp_relay::limits::Counters;
    use usgp_relay::tftp::{Disposition, TftpListener, TftpShared};
    use usgp_tftp::{Opcode, Packet, encode_ack, encode_data, encode_error, encode_request, parse};

    use crate::common::{
        IFACE_ADDR, MemFactory, MemNet, MemSocket, PROGRAM, Scratch, bytes, config, content, iface,
    };

    struct Rig {
        _s: Scratch,
        net: Arc<MemNet>,
        listener: Arc<TftpListener<MemFactory>>,
        data: Vec<u8>,
    }

    async fn rig_with(tag: &str, size: usize, tweak: impl FnOnce(&mut RelayConfig)) -> Rig {
        let s = Scratch::new(tag);
        let data = bytes(size, 11);
        s.publish(&[(PROGRAM, &data)]);
        let mut cfg = config(&s);
        tweak(&mut cfg);
        let c = content(&cfg).await;
        let net = MemNet::new();
        let shed = Arc::new(Mutex::new(Counters::default()));
        let shared = TftpShared::new(&cfg.limits, shed, tokio::time::Instant::now().into_std());
        let listener = TftpListener::new(
            iface(),
            c,
            cfg.tftp_listener_config(),
            MemFactory {
                net: Arc::clone(&net),
                ip: IpAddr::V4(IFACE_ADDR),
            },
            shared,
        );
        Rig {
            _s: s,
            net,
            listener,
            data,
        }
    }

    async fn rig(tag: &str, size: usize) -> Rig {
        rig_with(tag, size, |_| {}).await
    }

    fn client_ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 20, 1, n))
    }

    fn rrq(name: &[u8], options: &[(&[u8], &[u8])]) -> Vec<u8> {
        encode_request(Opcode::Rrq, name, b"octet", options)
    }

    /// Lock-step client: ACKs OACK with 0 and each DATA with its number.
    /// Returns the file and the server TID.
    async fn download(c: &MemSocket, block_size: usize) -> (Vec<u8>, SocketAddr) {
        let mut out = Vec::new();
        let mut expected: u16 = 1;
        loop {
            let (pkt, from) = c.recv().await;
            match parse(&pkt).unwrap() {
                Packet::Oack(_) => c.send(from, &encode_ack(0)),
                Packet::Data { block, data } => {
                    if block == expected {
                        out.extend_from_slice(data);
                        expected = expected.wrapping_add(1);
                    }
                    c.send(from, &encode_ack(block));
                    if block == expected.wrapping_sub(1) && data.len() < block_size {
                        return (out, from);
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

    async fn expect_error(c: &MemSocket, code: u16) -> SocketAddr {
        let (pkt, from) = c.recv().await;
        match parse(&pkt) {
            Ok(Packet::Error { code: got, .. }) => assert_eq!(got, code, "{pkt:?}"),
            other => panic!("expected ERROR {code}, got {other:?}"),
        }
        from
    }

    #[tokio::test]
    async fn octet_rrq_full_download_no_options() {
        let r = rig("full", 5000).await;
        let c = r.net.bind(client_ip(50));
        assert_eq!(
            r.listener
                .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[])),
            Disposition::Started
        );
        let (got, tid) = download(&c, 512).await;
        assert_eq!(got, r.data);
        // Replies come from a new TID, not port 69 (RFC 1350 §4).
        assert_ne!(tid.port(), 69);
        assert_eq!(tid.ip(), IpAddr::V4(IFACE_ADDR));
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn exact_multiple_sends_final_empty_block() {
        let r = rig("multiple", 1024).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let mut sizes = Vec::new();
        loop {
            let (pkt, from) = c.recv().await;
            let Ok(Packet::Data { block, data }) = parse(&pkt) else {
                panic!("{pkt:?}");
            };
            sizes.push(data.len());
            c.send(from, &encode_ack(block));
            if data.len() < 512 {
                break;
            }
        }
        assert_eq!(sizes, vec![512, 512, 0]);
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn empty_file_one_empty_block() {
        let r = rig("empty", 0).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (got, _) = download(&c, 512).await;
        assert!(got.is_empty());
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn blksize_tsize_oack_download() {
        let r = rig("oack", 5000).await;
        let c = r.net.bind(client_ip(50));
        r.listener.handle_request(
            c.addr,
            &rrq(
                PROGRAM.as_bytes(),
                &[(b"blksize", b"1468"), (b"tsize", b"0")],
            ),
        );
        let (pkt, from) = c.recv().await;
        let Ok(Packet::Oack(list)) = parse(&pkt) else {
            panic!("{pkt:?}");
        };
        let opts: Vec<(Vec<u8>, Vec<u8>)> =
            list.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect();
        assert!(
            opts.contains(&(b"blksize".to_vec(), b"1468".to_vec())),
            "{opts:?}"
        );
        assert!(
            opts.contains(&(b"tsize".to_vec(), b"5000".to_vec())),
            "{opts:?}"
        );
        c.send(from, &encode_ack(0));
        let mut got = Vec::new();
        loop {
            let (pkt, from) = c.recv().await;
            let Ok(Packet::Data { block, data }) = parse(&pkt) else {
                panic!("{pkt:?}");
            };
            assert!(data.len() <= 1468);
            got.extend_from_slice(data);
            c.send(from, &encode_ack(block));
            if data.len() < 1468 {
                break;
            }
        }
        assert_eq!(got, r.data);
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn timeout_option_not_acknowledged() {
        let r = rig("timeout-opt", 100).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[(b"timeout", b"5")]));
        // No supported option: plain DATA 1 (RFC 2347; tftp.md §6).
        let (pkt, _) = c.recv().await;
        assert!(
            matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })),
            "{pkt:?}"
        );
    }

    #[tokio::test]
    async fn tsize_probe_abort_releases_slot() {
        let r = rig("probe", 5000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[(b"tsize", b"0")]));
        let (pkt, from) = c.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Oack(_))));
        // The client only wanted the size (UEFI §24.3.10) and aborts.
        c.send(
            from,
            &encode_error(usgp_tftp::ErrorCode::DiskFull, "size only"),
        );
        wait_idle(&r.listener).await;
        assert!(c.recv_within(Duration::from_millis(200)).await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn retry_cap_releases_slot() {
        let r = rig("retry", 5000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let mut arrivals = Vec::new();
        while let Some((pkt, _)) = c.recv_within(Duration::from_secs(120)).await {
            assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })));
            arrivals.push(tokio::time::Instant::now());
        }
        // First send plus handshake_retries (default 1) resend after the
        // initial RTO (1 s).
        assert_eq!(arrivals.len(), 2, "{arrivals:?}");
        let gap1 = arrivals[1] - arrivals[0];
        assert!(gap1 >= Duration::from_millis(1000), "{gap1:?}");
        wait_idle(&r.listener).await;
    }

    /// SEC-001: before the first ACK a transfer holds its pending slot at
    /// most `tftp.handshake_timeout_ms` (default 2 s), even when the RTO
    /// schedule would wait longer.
    #[tokio::test(start_paused = true)]
    async fn handshake_timeout_releases_pending_slot() {
        let r = rig_with("hs-timeout", 5000, |cfg| {
            cfg.tftp.handshake_retries = 5;
        })
        .await;
        let c = r.net.bind(client_ip(50));
        let t0 = tokio::time::Instant::now();
        assert_eq!(
            r.listener
                .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[])),
            Disposition::Started
        );
        let mut arrivals = 0;
        while c.recv_within(Duration::from_secs(60)).await.is_some() {
            arrivals += 1;
        }
        // Sent at 0 s and resent at 1 s; the next resend would be at 3 s,
        // after the 2 s handshake timeout.
        assert_eq!(arrivals, 2);
        wait_idle(&r.listener).await;
        let held = tokio::time::Instant::now() - t0;
        assert!(
            held < Duration::from_secs(60) + Duration::from_secs(3),
            "{held:?}"
        );
        assert_eq!(r.listener.shared().active(), (0, 0));
    }

    /// SEC-001: a steady trickle of spoofed RRQs (new source address each
    /// time, nobody ever ACKs) does not hold the pending cap: real clients
    /// are served throughout, and once the trickle stops every pending
    /// slot is released within the handshake timeout. With the previous
    /// defaults (16 pending slots held about 7 s) about 2.3 such requests
    /// per second blocked every boot; this sends 20 per second.
    #[tokio::test(start_paused = true)]
    async fn spoofed_rrq_trickle_does_not_block_real_clients() {
        let r = rig("spoof-trickle", 3000).await;
        let req = rrq(PROGRAM.as_bytes(), &[]);
        let listener = Arc::clone(&r.listener);
        let spoof_req = req.clone();
        let spoofer = tokio::spawn(async move {
            let mut dispositions = Vec::new();
            for i in 0..400u16 {
                // Unbound addresses: replies vanish, no ACK ever comes.
                let [hi, lo] = i.to_be_bytes();
                let ip = Ipv4Addr::new(10, 21, hi, lo.max(1));
                let src = SocketAddr::new(IpAddr::V4(ip), 2000 + i);
                dispositions.push(listener.handle_request(src, &spoof_req));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            dispositions
        });
        let mut max_pending = 0;
        for n in 0..8u8 {
            tokio::time::sleep(Duration::from_millis(2300)).await;
            let (pending, _) = r.listener.shared().active();
            max_pending = max_pending.max(pending);
            let c = r.net.bind(client_ip(50 + n));
            assert_eq!(
                r.listener.handle_request(c.addr, &req),
                Disposition::Started,
                "real client {n} during the trickle"
            );
            let (got, _) = download(&c, 512).await;
            assert_eq!(got, r.data);
        }
        let dispositions = spoofer.await.unwrap();
        // Every spoofed request was within the global admission rate and
        // found a pending slot: the cap was never the limit.
        assert!(
            dispositions.iter().all(|d| *d == Disposition::Started),
            "{dispositions:?}"
        );
        // At most rate x handshake lifetime (20/s x 2 s) are pending.
        assert!(max_pending <= 45, "{max_pending}");
        // Recovery: after the trickle stops, the pending slots drain within
        // the handshake timeout and a new client is served.
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(r.listener.shared().active(), (0, 0));
        let c = r.net.bind(client_ip(99));
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Started
        );
        let (got, _) = download(&c, 512).await;
        assert_eq!(got, r.data);
    }

    /// Control for the test above: with the previous settings (16 pending
    /// slots, two handshake resends, no handshake timeout or global
    /// bucket to speak of) the same trickle blocks a real client within
    /// two seconds.
    #[tokio::test(start_paused = true)]
    async fn spoofed_rrq_trickle_blocked_previous_settings() {
        let r = rig_with("spoof-old", 3000, |cfg| {
            cfg.limits.tftp_max_pending = 16;
            cfg.limits.tftp_rrq_global_burst = 10_000;
            cfg.limits.tftp_rrq_global_per_sec = 10_000;
            cfg.tftp.handshake_retries = 2;
            cfg.tftp.handshake_timeout = Duration::from_secs(60);
        })
        .await;
        let req = rrq(PROGRAM.as_bytes(), &[]);
        for i in 0..40u8 {
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 21, 0, i + 1)), 2000);
            r.listener.handle_request(src, &req);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let c = r.net.bind(client_ip(50));
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Shed("tftp_pending")
        );
    }

    /// SEC-001: the global admission bucket bounds how many requests per
    /// second reach file verification, whatever their claimed sources.
    #[tokio::test(start_paused = true)]
    async fn global_rrq_admission_bucket() {
        let r = rig_with("rrq-global", 100, |cfg| {
            cfg.limits.tftp_rrq_global_burst = 3;
            cfg.limits.tftp_rrq_global_per_sec = 1;
        })
        .await;
        let req = rrq(PROGRAM.as_bytes(), &[]);
        let mut got = Vec::new();
        for n in 0..4u8 {
            let c = r.net.bind(client_ip(60 + n));
            got.push(r.listener.handle_request(c.addr, &req));
        }
        assert_eq!(
            got,
            vec![
                Disposition::Started,
                Disposition::Started,
                Disposition::Started,
                Disposition::Shed("tftp_rrq_global"),
            ]
        );
        // Requests that need no slot (refusals) do not use the budget.
        let c = r.net.bind(client_ip(70));
        assert_eq!(
            r.listener.handle_request(c.addr, &rrq(b"nope", &[])),
            Disposition::Refused("not_published")
        );
        tokio::time::sleep(Duration::from_millis(1000)).await;
        let c = r.net.bind(client_ip(71));
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Started
        );
    }

    /// SEC-001 (round 2): the admission budget is per interface, so a
    /// flood that empties one interface's budget sheds nothing on another
    /// interface sharing the same caps.
    #[tokio::test(start_paused = true)]
    async fn rrq_flood_on_one_interface_does_not_shed_another() {
        let s = Scratch::new("rrq-per-iface");
        let data = bytes(100, 11);
        s.publish(&[(PROGRAM, &data)]);
        let mut cfg = config(&s);
        cfg.limits.tftp_rrq_global_burst = 3;
        cfg.limits.tftp_rrq_global_per_sec = 1;
        let c = content(&cfg).await;
        let net = MemNet::new();
        let shed = Arc::new(Mutex::new(Counters::default()));
        let shared = TftpShared::new(
            &cfg.limits,
            Arc::clone(&shed),
            tokio::time::Instant::now().into_std(),
        );
        let other_addr = Ipv4Addr::new(10, 20, 9, 2);
        let listener = |iface: InterfaceConfig| {
            let ip = IpAddr::V4(iface.address);
            TftpListener::new(
                iface,
                Arc::clone(&c),
                cfg.tftp_listener_config(),
                MemFactory {
                    net: Arc::clone(&net),
                    ip,
                },
                Arc::clone(&shared),
            )
        };
        let flooded = listener(iface());
        let quiet = listener(InterfaceConfig {
            name: "relay1".to_owned(),
            address: other_addr,
            prefix_len: Some(24),
        });
        let req = rrq(PROGRAM.as_bytes(), &[]);
        // Spoofed flood on the first interface, a new source each time.
        let mut flood = Vec::new();
        for n in 0..50u8 {
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 21, 0, n + 1)), 2000);
            flood.push(flooded.handle_request(src, &req));
        }
        assert_eq!(
            flood.iter().filter(|d| **d == Disposition::Started).count(),
            3
        );
        assert_eq!(shed.lock().unwrap().get("tftp_rrq_global"), 47);
        // A genuine client on the other interface is admitted and served.
        let client = net.bind(IpAddr::V4(Ipv4Addr::new(10, 20, 9, 50)));
        assert_eq!(
            quiet.handle_request(client.addr, &req),
            Disposition::Started
        );
        let (got, _) = download(&client, 512).await;
        assert_eq!(got, data);
        assert_eq!(shed.lock().unwrap().get("tftp_rrq_global"), 47);
        // The flooded interface is still shed until its bucket refills.
        let late = net.bind(client_ip(80));
        assert_eq!(
            flooded.handle_request(late.addr, &req),
            Disposition::Shed("tftp_rrq_global")
        );
    }

    /// SEC-008: the pending slot's lifetime starts when it is reserved and
    /// covers the wait for content verification. A request whose
    /// verification cannot start (here: the only blocking thread is busy)
    /// gives its slot back after `handshake_timeout`, silently, counted as
    /// `tftp_verify_timeout`, and names the file in a rate-limited
    /// `boot.file.verify_slow` event.
    #[test]
    fn verification_wait_bounded_by_handshake_timeout() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .max_blocking_threads(1)
            .build()
            .unwrap();
        rt.block_on(async {
            let s = Scratch::new("verify-wait");
            let data = bytes(100, 11);
            s.publish(&[(PROGRAM, &data)]);
            let cfg = config(&s);
            let c = content(&cfg).await;
            let net = MemNet::new();
            let shed = Arc::new(Mutex::new(Counters::default()));
            let shared = TftpShared::new(
                &cfg.limits,
                Arc::clone(&shed),
                tokio::time::Instant::now().into_std(),
            );
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
            // Occupy the single blocking thread so no file read can run.
            let (release, wait) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = wait.recv();
            });
            let client = net.bind(client_ip(50));
            assert_eq!(
                listener.handle_request(client.addr, &rrq(PROGRAM.as_bytes(), &[])),
                Disposition::Started
            );
            tokio::task::yield_now().await;
            assert_eq!(shared.active(), (1, 0));
            let timeout = cfg.tftp_listener_config().handshake_timeout;
            tokio::time::advance(timeout - Duration::from_millis(1)).await;
            tokio::task::yield_now().await;
            assert_eq!(shared.active(), (1, 0), "held until the deadline");
            tokio::time::advance(Duration::from_millis(2)).await;
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
            assert_eq!(shared.active(), (0, 0), "slot released at the deadline");
            assert_eq!(shed.lock().unwrap().get("tftp_verify_timeout"), 1);
            // BOOT-012: the timeout named the file in boot.file.verify_slow,
            // so another report within the same minute is rate-limited.
            let at = tokio::time::Instant::now().into_std();
            assert!(!c.report_verify_slow(PROGRAM.as_bytes(), timeout, timeout, at));
            // Let the queued read run (its result is discarded); nothing
            // is ever sent to the client.
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert!(
                client
                    .recv_within(Duration::from_millis(500))
                    .await
                    .is_none()
            );
            assert_eq!(shared.active(), (0, 0));
        });
    }

    /// QA-001: requests from multicast, broadcast, 0/8, loopback or port 0
    /// are dropped before any bucket, slot or reply.
    #[tokio::test]
    async fn bad_sources_dropped_before_any_slot() {
        let r = rig("bad-src", 100).await;
        let req = rrq(PROGRAM.as_bytes(), &[]);
        let wrq = encode_request(Opcode::Wrq, PROGRAM.as_bytes(), b"octet", &[]);
        let sources = [
            "224.0.0.1:1069",
            "239.1.2.3:1069",
            "255.255.255.255:1069",
            "0.0.0.0:1069",
            "0.1.2.3:1069",
            "127.0.0.1:1069",
            "240.0.0.1:1069",
            "10.20.1.50:0",
        ];
        for src in sources {
            let src: SocketAddr = src.parse().unwrap();
            assert_eq!(
                r.listener.handle_request(src, &req),
                Disposition::Dropped("bad_source"),
                "{src}"
            );
            assert_eq!(
                r.listener.handle_request(src, &wrq),
                Disposition::Dropped("bad_source"),
                "{src}"
            );
        }
        assert_eq!(r.listener.shared().active(), (0, 0));
        let n = u64::try_from(sources.len() * 2).unwrap();
        assert_eq!(r.listener.shared().drop_count("bad_source"), n);
        // An ordinary client is still served.
        let c = r.net.bind(client_ip(50));
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Started
        );
    }

    #[tokio::test(start_paused = true)]
    async fn established_retry_cap() {
        let r = rig("retry-est", 5000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (pkt, from) = c.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })));
        c.send(from, &encode_ack(1));
        let mut copies = 0;
        while let Some((pkt, _)) = c.recv_within(Duration::from_secs(300)).await {
            assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 2, .. })));
            copies += 1;
        }
        // First send plus max_retries (default 5).
        assert_eq!(copies, 6);
        wait_idle(&r.listener).await;
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_ack_never_resends() {
        let r = rig("dup-ack", 5000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (_, from) = c.recv().await;
        c.send(from, &encode_ack(1));
        c.send(from, &encode_ack(1));
        c.send(from, &encode_ack(1));
        let (pkt, _) = c.recv().await;
        let sent = tokio::time::Instant::now();
        assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 2, .. })));
        // Any further DATA 2 is a timer resend: it comes no sooner than the
        // RTO floor (250 ms), never straight after the duplicate ACKs.
        let (again, _) = c.recv().await;
        assert!(matches!(parse(&again), Ok(Packet::Data { block: 2, .. })));
        let gap = tokio::time::Instant::now() - sent;
        assert!(gap >= Duration::from_millis(250), "{gap:?}");
    }

    #[tokio::test]
    async fn foreign_tid_gets_error5_and_transfer_continues() {
        let r = rig("foreign", 2000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (pkt, tid) = c.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Data { block: 1, .. })));
        let intruder = r.net.bind(client_ip(66));
        intruder.send(tid, &encode_ack(1));
        let from = expect_error(&intruder, 5).await;
        assert_eq!(from, tid);
        // Same IP, other port: also foreign.
        let same_ip = r.net.bind(client_ip(50));
        same_ip.send(tid, &encode_ack(1));
        expect_error(&same_ip, 5).await;
        // The real client finishes normally.
        let mut got = match parse(&pkt).unwrap() {
            Packet::Data { data, .. } => data.to_vec(),
            _ => unreachable!(),
        };
        c.send(tid, &encode_ack(1));
        loop {
            let (pkt, from) = c.recv().await;
            let Ok(Packet::Data { block, data }) = parse(&pkt) else {
                panic!("{pkt:?}");
            };
            got.extend_from_slice(data);
            c.send(from, &encode_ack(block));
            if data.len() < 512 {
                break;
            }
        }
        assert_eq!(got, r.data);
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn client_data_during_read_is_illegal() {
        let r = rig("client-data", 2000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (_, tid) = c.recv().await;
        c.send(tid, &encode_data(1, b"x"));
        expect_error(&c, 4).await;
        wait_idle(&r.listener).await;
    }

    #[tokio::test]
    async fn client_error_ends_transfer() {
        let r = rig("client-error", 2000).await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        let (_, tid) = c.recv().await;
        c.send(tid, &encode_error(usgp_tftp::ErrorCode::NotDefined, "stop"));
        wait_idle(&r.listener).await;
        assert!(c.recv_within(Duration::from_millis(200)).await.is_none());
    }

    #[tokio::test]
    async fn wrq_error2_no_fs_access() {
        let r = rig("wrq", 100).await;
        let c = r.net.bind(client_ip(50));
        let wrq = encode_request(Opcode::Wrq, PROGRAM.as_bytes(), b"octet", &[]);
        assert_eq!(
            r.listener.handle_request(c.addr, &wrq),
            Disposition::Refused("write_request")
        );
        let from = expect_error(&c, 2).await;
        assert_ne!(from.port(), 69);
        // No slot was taken and nothing else arrives.
        assert_eq!(r.listener.shared().active(), (0, 0));
        assert!(c.recv_within(Duration::from_millis(200)).await.is_none());
    }

    #[tokio::test]
    async fn unknown_name_error1() {
        let r = rig("unknown", 100).await;
        let c = r.net.bind(client_ip(50));
        assert_eq!(
            r.listener.handle_request(c.addr, &rrq(b"nope.efi", &[])),
            Disposition::Refused("not_published")
        );
        expect_error(&c, 1).await;
    }

    #[tokio::test]
    async fn traversal_names_error1() {
        let r = rig_with("traversal", 100, |cfg| {
            cfg.limits.tftp_rrq_burst = 100;
            cfg.limits.tftp_error_per_sec = 1000;
        })
        .await;
        let long = vec![b'a'; 200];
        let names: Vec<&[u8]> = vec![
            b"../x",
            b"/etc/passwd",
            b"a/../b",
            b"\\x",
            b"%2e%2e",
            &long,
            "caf\u{e9}.efi".as_bytes(),
            b"./usgp-test-payload.efi",
            // M3: one leading separator is dropped and case is ignored
            // (`backslash_and_case_normalised`), but not twice, and not
            // past the allow-list.
            b"//usgp-test-payload.efi",
            b"\\\\usgp-test-payload.efi",
            b"USGP-TEST-PAYLOAD.EF",
            b"usgp-test-payload.efi/",
            b"root/usgp-test-payload.efi",
            b"../root/usgp-test-payload.efi",
        ];
        for (i, name) in names.iter().enumerate() {
            let c = r.net.bind(client_ip(50));
            assert_eq!(
                r.listener.handle_request(c.addr, &rrq(name, &[])),
                Disposition::Refused("not_published"),
                "case {i}"
            );
            expect_error(&c, 1).await;
        }
    }

    #[tokio::test]
    async fn embedded_nul_never_served() {
        let r = rig("nul", 100).await;
        let c = r.net.bind(client_ip(50));
        // "usgp-test-payload.efi\0x" cannot be a filename on the wire: the
        // NUL ends it, so the request reads as filename + mode "x" + ...
        let mut pkt = vec![0, 1];
        pkt.extend_from_slice(b"usgp-test-payload.efi\0x\0octet\0");
        let d = r.listener.handle_request(c.addr, &pkt);
        assert_ne!(d, Disposition::Started, "{d:?}");
        if let Some((p, _)) = c.recv_within(Duration::from_millis(200)).await {
            assert!(matches!(parse(&p), Ok(Packet::Error { .. })), "{p:?}");
        }
    }

    #[tokio::test]
    async fn netascii_refused_error4() {
        let r = rig("netascii", 100).await;
        let c = r.net.bind(client_ip(50));
        let req = encode_request(Opcode::Rrq, PROGRAM.as_bytes(), b"netascii", &[]);
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Refused("unsupported_mode")
        );
        expect_error(&c, 4).await;
    }

    #[tokio::test]
    async fn malformed_and_non_requests_dropped_silently() {
        let r = rig("malformed", 100).await;
        let c = r.net.bind(client_ip(50));
        for pkt in [
            vec![],
            vec![0],
            vec![0, 1],
            vec![0, 9, 0, 0],
            vec![0, 1, b'a'],
        ] {
            assert_eq!(
                r.listener.handle_request(c.addr, &pkt),
                Disposition::Dropped("malformed"),
                "{pkt:?}"
            );
        }
        assert_eq!(
            r.listener.handle_request(c.addr, &encode_ack(1)),
            Disposition::Dropped("not_a_request")
        );
        assert_eq!(
            r.listener.handle_request(c.addr, &encode_data(1, b"x")),
            Disposition::Dropped("not_a_request")
        );
        assert!(c.recv_within(Duration::from_millis(200)).await.is_none());
        assert_eq!(r.listener.shared().drop_count("malformed"), 5);
    }

    #[tokio::test]
    async fn block_count_limit_refused_before_data() {
        // 65535 * 512 octets needs 65536 DATA packets at the default block
        // size (the final one empty): with `block_wrap = "off"` (the M1
        // behaviour, still available) refused with ERROR 3
        // (REQ-BOOT-035). The M3 default wraps instead
        // (`wrap_default_serves_more_than_65535_blocks`).
        let r = rig_with("blocks", 65_535 * 512, |cfg| {
            cfg.tftp.block_wrap = usgp_tftp::BlockWrap::Off;
        })
        .await;
        let c = r.net.bind(client_ip(50));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[]));
        expect_error(&c, 3).await;
        wait_idle(&r.listener).await;
        // With a larger block size the same file is served.
        let c2 = r.net.bind(client_ip(51));
        r.listener
            .handle_request(c2.addr, &rrq(PROGRAM.as_bytes(), &[(b"blksize", b"1024")]));
        let (pkt, _) = c2.recv().await;
        assert!(matches!(parse(&pkt), Ok(Packet::Oack(_))), "{pkt:?}");
    }

    #[tokio::test]
    async fn pending_cap() {
        let r = rig_with("pending", 1000, |cfg| cfg.limits.tftp_max_pending = 2).await;
        let a = r.net.bind(client_ip(50));
        let b = r.net.bind(client_ip(51));
        let c = r.net.bind(client_ip(52));
        let req = rrq(PROGRAM.as_bytes(), &[]);
        assert_eq!(
            r.listener.handle_request(a.addr, &req),
            Disposition::Started
        );
        assert_eq!(
            r.listener.handle_request(b.addr, &req),
            Disposition::Started
        );
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Shed("tftp_pending")
        );
        // Shedding is silent.
        assert!(c.recv_within(Duration::from_millis(200)).await.is_none());
        // Once a's transfer is established, a pending slot frees up.
        let (_, tid) = a.recv().await;
        a.send(tid, &encode_ack(1));
        let _ = a.recv().await;
        assert_eq!(r.listener.shared().active(), (1, 1));
        assert_eq!(
            r.listener.handle_request(c.addr, &req),
            Disposition::Started
        );
    }

    #[tokio::test]
    async fn per_client_cap() {
        let r = rig_with("per-client", 1000, |cfg| {
            cfg.limits.tftp_per_client_transfers = 1;
        })
        .await;
        let a = r.net.bind(client_ip(50));
        let a2 = r.net.bind(client_ip(50));
        let req = rrq(PROGRAM.as_bytes(), &[]);
        assert_eq!(
            r.listener.handle_request(a.addr, &req),
            Disposition::Started
        );
        assert_eq!(
            r.listener.handle_request(a2.addr, &req),
            Disposition::Shed("tftp_per_client")
        );
        let other = r.net.bind(client_ip(51));
        assert_eq!(
            r.listener.handle_request(other.addr, &req),
            Disposition::Started
        );
    }

    #[tokio::test]
    async fn established_cap() {
        let r = rig_with("est-cap", 1000, |cfg| cfg.limits.tftp_max_transfers = 1).await;
        let a = r.net.bind(client_ip(50));
        let b = r.net.bind(client_ip(51));
        let req = rrq(PROGRAM.as_bytes(), &[]);
        r.listener.handle_request(a.addr, &req);
        let (_, tid) = a.recv().await;
        a.send(tid, &encode_ack(1));
        let _ = a.recv().await;
        assert_eq!(r.listener.shared().active(), (0, 1));
        assert_eq!(
            r.listener.handle_request(b.addr, &req),
            Disposition::Shed("tftp_transfers")
        );
    }

    #[tokio::test]
    async fn request_rate_per_source() {
        let r = rig("rrq-rate", 100).await;
        let c = r.net.bind(client_ip(50));
        // Default burst 8 per source IP; unknown names hold no slot.
        for _ in 0..8 {
            assert_eq!(
                r.listener.handle_request(c.addr, &rrq(b"nope", &[])),
                Disposition::Refused("not_published")
            );
        }
        assert_eq!(
            r.listener.handle_request(c.addr, &rrq(b"nope", &[])),
            Disposition::Shed("tftp_request_source")
        );
        // Another source is unaffected.
        let d = r.net.bind(client_ip(51));
        assert_eq!(
            r.listener.handle_request(d.addr, &rrq(b"nope", &[])),
            Disposition::Refused("not_published")
        );
    }

    #[tokio::test]
    async fn error_rate_cap() {
        let r = rig_with("err-rate", 100, |cfg| cfg.limits.tftp_error_per_sec = 2).await;
        let mut dispositions = Vec::new();
        for n in 0..5u8 {
            let c = r.net.bind(client_ip(100 + n));
            dispositions.push(r.listener.handle_request(c.addr, &rrq(b"nope", &[])));
        }
        assert_eq!(
            dispositions,
            vec![
                Disposition::Refused("not_published"),
                Disposition::Refused("not_published"),
                Disposition::Shed("tftp_error"),
                Disposition::Shed("tftp_error"),
                Disposition::Shed("tftp_error"),
            ]
        );
    }

    /// REQ-BOOT-034: one stalled client does not delay 50 others.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stalled_client_does_not_delay_50_others() {
        let r = rig_with("many", 8000, |cfg| {
            cfg.limits.tftp_max_pending = 64;
            cfg.limits.tftp_max_transfers = 64;
        })
        .await;
        let req = rrq(PROGRAM.as_bytes(), &[]);
        let stalled = r.net.bind(client_ip(2));
        assert_eq!(
            r.listener.handle_request(stalled.addr, &req),
            Disposition::Started
        );
        let (_, stalled_tid) = stalled.recv().await;
        // Established, then silent.
        stalled.send(stalled_tid, &encode_ack(1));

        let started = tokio::time::Instant::now();
        let mut tasks = Vec::new();
        for n in 0..50u8 {
            let c = r.net.bind(client_ip(100 + n));
            assert_eq!(
                r.listener.handle_request(c.addr, &req),
                Disposition::Started
            );
            tasks.push(tokio::spawn(async move { download(&c, 512).await.0 }));
        }
        for t in tasks {
            let got = tokio::time::timeout(Duration::from_secs(20), t)
                .await
                .expect("download finished")
                .unwrap();
            assert_eq!(got, r.data);
        }
        let elapsed = started.elapsed();
        // Well under the stalled transfer's retry window (1 s initial RTO,
        // 5 retries with doubling).
        assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
        // The 50 finished transfers release their slots; the stalled one
        // is still holding its own.
        tokio::time::timeout(Duration::from_secs(2), async {
            while r.listener.shared().active() != (0, 1) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("only the stalled transfer remains");
    }

    // -----------------------------------------------------------------
    // M3 (plan WU-11): request names, windowsize, wraparound, PE kit
    // -----------------------------------------------------------------

    /// A rig serving `files` (name, bytes) with `program` as the boot
    /// program and `kit` (TOML text, possibly empty) appended to the
    /// manifest.
    async fn kit_rig(
        tag: &str,
        files: &[(&str, &[u8])],
        program: &str,
        kit: &str,
    ) -> (Rig, Arc<usgp_relay::content::ContentStore>) {
        let s = Scratch::new(tag);
        s.publish(files);
        if !kit.is_empty() {
            let mut text = std::fs::read_to_string(s.manifest_path()).unwrap();
            text.push('\n');
            text.push_str(kit);
            std::fs::write(s.manifest_path(), text).unwrap();
        }
        let mut cfg = config(&s);
        cfg.boot.uefi_x64_program = usgp_proto::BootFileName::try_from(program).unwrap();
        let c = content(&cfg).await;
        let net = MemNet::new();
        let shed = Arc::new(Mutex::new(Counters::default()));
        let shared = TftpShared::new(&cfg.limits, shed, tokio::time::Instant::now().into_std());
        let listener = TftpListener::new(
            iface(),
            Arc::clone(&c),
            cfg.tftp_listener_config(),
            MemFactory {
                net: Arc::clone(&net),
                ip: IpAddr::V4(IFACE_ADDR),
            },
            shared,
        );
        (
            Rig {
                _s: s,
                net,
                listener,
                data: Vec::new(),
            },
            c,
        )
    }

    /// RFC 7440 client: ACKs after `window` in-order blocks or the short
    /// final block; wire numbers wrap 65535 -> 0. Returns the file and the
    /// number of wraps seen.
    async fn windowed_download(c: &MemSocket, block_size: usize, window: usize) -> (Vec<u8>, u64) {
        let mut out = Vec::new();
        let mut next: u64 = 1;
        let mut since_ack = 0usize;
        let mut wraps = 0u64;
        loop {
            let (pkt, from) = c.recv().await;
            match parse(&pkt).unwrap() {
                Packet::Oack(o) => {
                    assert_eq!(
                        o.get(b"windowsize"),
                        Some(window.to_string().as_bytes()),
                        "windowsize acknowledged"
                    );
                    c.send(from, &encode_ack(0));
                }
                Packet::Data { block, data } => {
                    let want = u16::try_from(next & 0xffff).unwrap();
                    if block != want {
                        continue;
                    }
                    if want == 0 {
                        wraps += 1;
                    }
                    out.extend_from_slice(data);
                    next += 1;
                    since_ack += 1;
                    let last = data.len() < block_size;
                    if last || since_ack == window {
                        c.send(from, &encode_ack(block));
                        since_ack = 0;
                    }
                    if last {
                        return (out, wraps);
                    }
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    /// REQ-BOOT-035 / REQ-BOOT-064 / DEC-0018 item 2: with the M3 defaults
    /// a file needing more than 65535 blocks is served in full, the block
    /// number wrapping to 0, in windows of the negotiated size.
    #[tokio::test]
    async fn wrap_default_serves_more_than_65535_blocks() {
        // 65,540 blocks of 8 bytes plus a short final block.
        let size = 65_540 * 8 + 3;
        let r = rig("wrap", size).await;
        let c = r.net.bind(client_ip(60));
        assert_eq!(
            r.listener.handle_request(
                c.addr,
                &rrq(
                    PROGRAM.as_bytes(),
                    &[(b"blksize", b"8"), (b"windowsize", b"8"), (b"tsize", b"0")],
                ),
            ),
            Disposition::Started
        );
        let (got, wraps) = windowed_download(&c, 8, 8).await;
        assert_eq!(wraps, 1);
        assert_eq!(got.len(), r.data.len());
        assert!(got == r.data, "reassembled bytes differ");
        wait_idle(&r.listener).await;
    }

    /// RFC 7440: the window granted is capped by `tftp.max_window_size`.
    #[tokio::test]
    async fn windowsize_capped_by_config() {
        let r = rig_with("wincap", 20_000, |cfg| cfg.tftp.max_window_size = 4).await;
        let c = r.net.bind(client_ip(61));
        r.listener
            .handle_request(c.addr, &rrq(PROGRAM.as_bytes(), &[(b"windowsize", b"16")]));
        let (got, wraps) = windowed_download(&c, 512, 4).await;
        assert_eq!(wraps, 0);
        assert!(got == r.data);
        wait_idle(&r.listener).await;
    }

    /// REQ-BOOT-063: Microsoft-style names (backslashes, a leading
    /// separator, other letter case) reach the published file; the matched
    /// manifest name is what is read.
    #[tokio::test]
    async fn backslash_and_case_normalised() {
        let bcd = bytes(3000, 21);
        let prog = bytes(700, 22);
        let (r, _) = kit_rig(
            "names",
            &[(PROGRAM, &prog), ("Boot/BCD", &bcd)],
            PROGRAM,
            "",
        )
        .await;
        for (i, (name, want)) in [
            (&b"\\Boot\\BCD"[..], &bcd),
            (b"/boot/bcd", &bcd),
            (b"Boot\\bcd", &bcd),
            (b"/USGP-TEST-PAYLOAD.EFI", &prog),
            (b"Usgp-Test-Payload.efi", &prog),
        ]
        .into_iter()
        .enumerate()
        {
            let c = r.net.bind(client_ip(70 + u8::try_from(i).unwrap()));
            assert_eq!(
                r.listener.handle_request(c.addr, &rrq(name, &[])),
                Disposition::Started,
                "case {i}"
            );
            let (got, _) = download(&c, 512).await;
            assert!(got == *want, "case {i}");
        }
        wait_idle(&r.listener).await;
    }

    /// Names that differ only in case make a case-insensitive match
    /// ambiguous: the manifest is refused at load (exit 78).
    #[tokio::test]
    async fn collision_manifest_refused() {
        let s = Scratch::new("collide");
        s.publish(&[(PROGRAM, b"p"), ("Boot/BCD", b"a"), ("boot/bcd", b"b")]);
        let cfg = config(&s);
        let e = usgp_relay::content::ContentStore::load(
            &cfg.boot.manifest,
            &cfg.boot.root,
            &cfg.boot.uefi_x64_program,
            cfg.tftp.max_file_size,
            cfg.limits.verify_concurrency,
            &cfg.trust,
        )
        .unwrap_err();
        assert!(
            matches!(
                e,
                usgp_relay::content::ContentLoadError::NameCollision { .. }
            ),
            "{e}"
        );
    }

    const KIT_FILES: [&str; 5] = [
        "bootmgfw.efi",
        "Boot/BCD",
        "Boot/boot.sdi",
        "Boot/boot.wim",
        "Boot/Fonts/wgl4_boot.ttf",
    ];

    fn kit_section(wim_sha: &str, fonts: &str) -> String {
        format!(
            "[pe_kit]\nboot_program = \"bootmgfw.efi\"\nbcd = \"Boot/BCD\"\n\
             sdi = \"Boot/boot.sdi\"\nwim = \"Boot/boot.wim\"\nfonts = [{fonts}]\n\
             pe_content_sha256 = \"{wim_sha}\"\n"
        )
    }

    /// REQ-BOOT-063 / REQ-PE-011/012: a complete kit is offered and every
    /// file the boot manager asks for (BCD, SDI, WIM, fonts) is served
    /// byte for byte under its Microsoft-style name.
    #[tokio::test]
    async fn pe_kit_files_served() {
        let contents: Vec<Vec<u8>> = (0..5u64)
            .map(|i| bytes(1000 + 777 * i as usize, 30 + i))
            .collect();
        let files: Vec<(&str, &[u8])> = KIT_FILES
            .iter()
            .zip(&contents)
            .map(|(n, c)| (*n, c.as_slice()))
            .collect();
        let wim_sha = usgp_crypto::sha256(&contents[3]).to_hex();
        let (r, c) = kit_rig(
            "kit-ok",
            &files,
            "bootmgfw.efi",
            &kit_section(&wim_sha, "\"Boot/Fonts/wgl4_boot.ttf\""),
        )
        .await;
        assert_eq!(
            c.state().current(),
            usgp_relay::state::ServiceState::Running
        );
        assert_eq!(
            c.offerable_program().map(|p| p.as_str()),
            Some("bootmgfw.efi")
        );
        assert!(c.pe_kit().is_some());
        for (i, name) in [
            &b"bootmgfw.efi"[..],
            b"\\Boot\\BCD",
            b"\\Boot\\boot.sdi",
            b"\\Boot\\boot.wim",
            b"\\Boot\\Fonts\\wgl4_boot.ttf",
        ]
        .into_iter()
        .enumerate()
        {
            let cl = r.net.bind(client_ip(80 + u8::try_from(i).unwrap()));
            assert_eq!(
                r.listener.handle_request(cl.addr, &rrq(name, &[])),
                Disposition::Started,
                "file {i}"
            );
            let (got, _) = download(&cl, 512).await;
            assert!(got == contents[i], "file {i}");
        }
        wait_idle(&r.listener).await;
    }

    /// REQ-PE-012 / REQ-BOOT-052: a kit naming a file that is not
    /// published is incomplete, which is missing content: no boot program
    /// is offered, and the kit's status says why.
    #[tokio::test]
    async fn incomplete_kit_is_missing_content() {
        let contents: Vec<Vec<u8>> = (0..4u64).map(|i| bytes(500, 40 + i)).collect();
        let files: Vec<(&str, &[u8])> = KIT_FILES[..4]
            .iter()
            .zip(&contents)
            .map(|(n, c)| (*n, c.as_slice()))
            .collect();
        let wim_sha = usgp_crypto::sha256(&contents[3]).to_hex();
        let (_r, c) = kit_rig(
            "kit-incomplete",
            &files,
            "bootmgfw.efi",
            &kit_section(&wim_sha, "\"Boot/Fonts/absent.ttf\""),
        )
        .await;
        assert_eq!(
            c.state().current(),
            usgp_relay::state::ServiceState::RunningMissingContent
        );
        assert!(c.offerable_program().is_none());
        let kit_status = c
            .state()
            .files()
            .into_iter()
            .find(|(n, _)| n == usgp_relay::pe_kit::KIT_STATUS_NAME)
            .map(|(_, s)| s);
        assert_eq!(kit_status, Some(usgp_relay::state::FileStatus::Missing));
    }

    /// REQ-PE-012 ("matches the imported environment"): a WIM whose
    /// digest is not the imported PE's, or a kit whose boot program is not
    /// the configured one, is missing content too.
    #[tokio::test]
    async fn mismatched_kit_is_missing_content() {
        let contents: Vec<Vec<u8>> = (0..4u64).map(|i| bytes(500, 50 + i)).collect();
        let files: Vec<(&str, &[u8])> = KIT_FILES[..4]
            .iter()
            .zip(&contents)
            .map(|(n, c)| (*n, c.as_slice()))
            .collect();
        let other_sha = usgp_crypto::sha256(b"another pe").to_hex();
        let (_r, c) = kit_rig(
            "kit-digest",
            &files,
            "bootmgfw.efi",
            &kit_section(&other_sha, ""),
        )
        .await;
        assert!(c.offerable_program().is_none());
        let wim_sha = usgp_crypto::sha256(&contents[3]).to_hex();
        let (_r2, c2) = kit_rig(
            "kit-prog",
            &files,
            "Boot/boot.sdi",
            &kit_section(&wim_sha, ""),
        )
        .await;
        assert!(c2.offerable_program().is_none());
        for store in [&c, &c2] {
            let kit_status = store
                .state()
                .files()
                .into_iter()
                .find(|(n, _)| n == usgp_relay::pe_kit::KIT_STATUS_NAME)
                .map(|(_, s)| s);
            assert_eq!(
                kit_status,
                Some(usgp_relay::state::FileStatus::IntegrityFailed)
            );
        }
    }
}
