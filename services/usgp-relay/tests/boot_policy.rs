//! BOOT-5 stop (REQ-BOOT-067; decision 0021): the signed boot-policy list
//! pulled over mTLS from a local test server built on `usgp-crypto`'s
//! test PKI, its verification (signature, boot service, generation), the
//! union with the suppression file at the DHCP responder, the cache file,
//! and the fail-safe behaviour when the server cannot be reached.
//!
//! No real server, device or network interface is used: the test server
//! listens on 127.0.0.1 and answers with fixed HTTP/1.1 responses.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SI-7(6), SC-23, SC-8, IA-3, SI-17, AU-2, AU-12, SA-11
//! - SPEC: specs/boot-network.md#REQ-BOOT-051, #REQ-BOOT-067
//! - DECISION: docs/decisions/0021 items 2 and 3

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod boot_policy {
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use usgp_crypto::test_pki::TestPki;
    use usgp_crypto::tls::{ServerTls, TlsMinVersion};
    use usgp_crypto::{SigningKey, sign_typed};
    use usgp_dhcp::craft::RequestBuilder;
    use usgp_dhcp::{ListenPort, MacAddr};
    use usgp_proto::device::MacAddress;
    use usgp_proto::envelope::{PayloadType, SignatureAlg, SignatureV1, SignedEnvelopeV1};
    use usgp_proto::ids::{BootServiceId, JobId, UnixMicros};
    use usgp_proto::{BootPolicyV1, BootStopEntryV1};
    use usgp_relay::config::{FeedUrl, ServerFeedConfig};
    use usgp_relay::dhcp::DhcpService;
    use usgp_relay::feed::{
        Applied, BootPolicyFeed, FetchError, PollOutcome, Rejection, Source, load_material,
    };
    use usgp_relay::files::FileError;
    use usgp_relay::limits::Counters;
    use usgp_relay::suppress::{FeedGate, Suppression, SuppressionList};

    use crate::common::{PROGRAM, Scratch, bytes, config, content, iface, set_mode, trust};

    // -----------------------------------------------------------------
    // Event capture (audit target only)
    // -----------------------------------------------------------------

    type Record = BTreeMap<String, String>;

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

        fn named(&self, name: &str) -> Vec<Record> {
            self.events
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.get("event").map(String::as_str) == Some(name))
                .cloned()
                .collect()
        }

        fn clear(&self) {
            self.events.lock().unwrap().clear();
        }
    }

    fn detail_has(r: &Record, key: &str, value: &str) -> bool {
        r.get("detail")
            .is_some_and(|d| d.contains(&format!("\"{key}\":\"{value}\"")))
    }

    // -----------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------

    const SERVICE: &str = "6f1c2a3b-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    const OTHER_SERVICE: &str = "11111111-2222-4333-8444-555555555555";
    const STOPPED_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x0a, 0x01];
    const OTHER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x0a, 0x02];

    fn service() -> BootServiceId {
        BootServiceId::parse(SERVICE).unwrap()
    }

    fn job(n: u8) -> JobId {
        JobId::from_random_bytes([n; 16])
    }

    fn policy(
        key: &SigningKey,
        svc: BootServiceId,
        generation: u64,
        macs: &[[u8; 6]],
    ) -> BootPolicyV1 {
        BootPolicyV1 {
            schema: 1,
            boot_service_id: svc,
            generation,
            issued_at_us: UnixMicros::new(1_793_000_000_000_000).unwrap(),
            key_id: key.key_id().0,
            stops: macs
                .iter()
                .enumerate()
                .map(|(i, m)| BootStopEntryV1 {
                    mac: MacAddress::new(*m).unwrap(),
                    job_id: job(u8::try_from(i + 1).unwrap()),
                })
                .collect(),
        }
    }

    /// The envelope JSON the server would send, signed with `key`.
    fn seal(key: &SigningKey, p: &BootPolicyV1) -> Vec<u8> {
        let payload = p.to_payload().unwrap();
        seal_payload(key, payload)
    }

    fn seal_payload(key: &SigningKey, payload: Vec<u8>) -> Vec<u8> {
        let ty = PayloadType::BootPolicyV1;
        let sig = sign_typed(key, ty.as_str(), &payload).unwrap();
        let s = SignatureV1::new(key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig).unwrap();
        SignedEnvelopeV1::new(ty, payload, vec![s])
            .unwrap()
            .to_json()
            .unwrap()
    }

    struct Keys {
        pki: TestPki,
        policy_key: SigningKey,
    }

    impl Keys {
        fn new() -> Self {
            Self {
                pki: TestPki::generate().unwrap(),
                policy_key: SigningKey::generate().unwrap(),
            }
        }
    }

    fn write(path: &Path, data: &[u8], mode: u32) {
        std::fs::write(path, data).unwrap();
        set_mode(path, mode);
    }

    /// Writes the feed files into `s` and returns the configuration for a
    /// server at `addr`.
    fn feed_config(s: &Scratch, k: &Keys, addr: SocketAddr, cache: bool) -> ServerFeedConfig {
        let dir = s.dir.join("feed");
        std::fs::create_dir_all(&dir).unwrap();
        set_mode(&dir, 0o755);
        let p = |n: &str| dir.join(n);
        write(
            &p("ca.pem"),
            k.pki.root.cert_pem().unwrap().as_bytes(),
            0o644,
        );
        write(&p("relay.pem"), &k.pki.client.chain_pem(), 0o644);
        write(&p("relay.key"), &k.pki.client.key_pem().unwrap(), 0o600);
        write(
            &p("policy.pub.pem"),
            k.policy_key
                .verifying_key()
                .to_spki_pem()
                .unwrap()
                .as_bytes(),
            0o644,
        );
        ServerFeedConfig {
            url: FeedUrl::parse(&format!("https://{addr}")).unwrap(),
            server_name: "localhost".to_owned(),
            trust_anchors: p("ca.pem"),
            client_cert: p("relay.pem"),
            client_key: p("relay.key"),
            boot_policy_key_pub: p("policy.pub.pem"),
            boot_service_id: service(),
            poll_interval: Duration::from_secs(30),
            cache_file: cache.then(|| p("boot-policy.json")),
        }
    }

    fn new_feed(cfg: ServerFeedConfig, suppression: &Arc<Suppression>) -> Arc<BootPolicyFeed> {
        let material = load_material(&cfg, &trust()).unwrap();
        BootPolicyFeed::new(cfg, material, Arc::clone(suppression))
    }

    /// An address nothing listens on (a bound then dropped listener).
    async fn closed_addr() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        a
    }

    // -----------------------------------------------------------------
    // Local test server (mTLS, fixed HTTP/1.1 answers)
    // -----------------------------------------------------------------

    /// What the test server saw and serves.
    #[derive(Default)]
    struct ServerState {
        /// Current list (generation, envelope JSON).
        current: Option<(u64, Vec<u8>)>,
        /// Request lines received.
        requests: Vec<String>,
        /// SHA-256 of the client certificate presented, per request.
        client_certs: Vec<Option<String>>,
    }

    struct TestServer {
        addr: SocketAddr,
        state: Arc<Mutex<ServerState>>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// Serves `GET /v1/relay/boot-policy?have=<g>`: 304 when `g` is the
    /// current generation, 200 with the envelope otherwise, 503 without a
    /// list. TLS with `tls` (client certificates validated by
    /// `usgp-crypto`).
    async fn serve(tls: ServerTls) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(ServerState::default()));
        let st = Arc::clone(&state);
        let task = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let Ok((mut stream, peer)) = tls.accept(tcp).await else {
                    continue;
                };
                let mut head = Vec::new();
                let mut buf = [0u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let line = text.lines().next().unwrap_or_default().to_owned();
                let have: Option<u64> = line
                    .split_once("have=")
                    .and_then(|(_, r)| r.split(' ').next())
                    .and_then(|g| g.parse().ok());
                let response = {
                    let mut s = st.lock().unwrap();
                    s.requests.push(line.clone());
                    s.client_certs
                        .push(peer.as_ref().map(|p| p.sha256.to_hex()));
                    match &s.current {
                        _ if peer.is_none() => {
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                .to_vec()
                        }
                        Some((g, _)) if have == Some(*g) => {
                            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec()
                        }
                        Some((_, body)) => {
                            let mut r = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            )
                            .into_bytes();
                            r.extend_from_slice(body);
                            r
                        }
                        None => b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec(),
                    }
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            }
        });
        TestServer { addr, state, task }
    }

    fn server_tls(pki: &TestPki) -> ServerTls {
        let settings = pki
            .server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls12)
            .unwrap();
        ServerTls::new(&settings).unwrap()
    }

    // -----------------------------------------------------------------
    // DHCP rig
    // -----------------------------------------------------------------

    struct DhcpRig {
        _s: Scratch,
        svc: DhcpService,
        t0: Instant,
    }

    async fn dhcp_rig(tag: &str, suppression: &Arc<Suppression>) -> DhcpRig {
        let s = Scratch::new(tag);
        s.publish(&[(PROGRAM, &bytes(2048, 9))]);
        let cfg = config(&s);
        let c = content(&cfg).await;
        let t0 = Instant::now();
        let svc = DhcpService::new(
            c,
            Arc::clone(suppression),
            cfg.local_addresses(),
            &cfg.limits,
            Arc::new(Mutex::new(Counters::default())),
            t0,
        );
        DhcpRig { _s: s, svc, t0 }
    }

    impl DhcpRig {
        fn discover(&self, mac: [u8; 6]) -> bool {
            let req = RequestBuilder::pxe_discover().chaddr(mac);
            let src = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 68);
            self.svc
                .handle(&iface(), ListenPort::Dhcp67, src, &req.build(), self.t0)
                .is_some()
        }
    }

    // -----------------------------------------------------------------
    // Tests: verification and the stop at the responder
    // -----------------------------------------------------------------

    /// Fail closed: with the feed enabled and no list applied yet, no
    /// device is offered a boot program, so a stopped device cannot be
    /// served because the server was not reachable.
    #[tokio::test(flavor = "current_thread")]
    async fn no_policy_yet_offers_nothing() {
        let k = Keys::new();
        let s = Scratch::new("bp-await");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        assert_eq!(feed.gate(), FeedGate::Awaiting);
        let r = dhcp_rig("bp-await-dhcp", &supp).await;
        assert!(!r.discover(OTHER_MAC));
        assert!(!r.discover(STOPPED_MAC));
        assert_eq!(r.svc.drop_count("boot_policy_unavailable"), 2);
        // The server cannot be reached: still nothing offered.
        assert!(matches!(
            feed.poll_once().await,
            PollOutcome::FetchFailed(FetchError::Connect(_))
        ));
        assert!(!r.discover(OTHER_MAC));
    }

    /// REQ-BOOT-067: a device on the applied stop list gets no reply
    /// (REQ-BOOT-051) and `boot.device.stopped` names the job; others are
    /// offered as before.
    #[tokio::test(flavor = "current_thread")]
    async fn stopped_device_gets_no_reply() {
        let (cap, _g) = Capture::install();
        let k = Keys::new();
        let s = Scratch::new("bp-stop");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let p = policy(&k.policy_key, service(), 1, &[STOPPED_MAC]);
        assert_eq!(
            feed.apply_bytes(&seal(&k.policy_key, &p), Source::Server),
            Ok(Applied::New { generation: 1 })
        );
        let applied = cap.named("boot_policy.applied");
        assert_eq!(applied.len(), 1);
        assert!(detail_has(&applied[0], "generation", "1"));
        assert!(detail_has(&applied[0], "stops", "1"));
        assert!(detail_has(&applied[0], "boot_service_id", SERVICE));
        assert_eq!(
            applied[0].get("outcome").map(String::as_str),
            Some("success")
        );

        let r = dhcp_rig("bp-stop-dhcp", &supp).await;
        cap.clear();
        assert!(!r.discover(STOPPED_MAC), "stopped device answered");
        assert!(r.discover(OTHER_MAC), "other device not answered");
        assert_eq!(r.svc.drop_count("boot_stopped"), 1);
        assert_eq!(r.svc.drop_count("suppressed"), 0);
        let stopped = cap.named("boot.device.stopped");
        assert_eq!(stopped.len(), 1);
        assert!(detail_has(&stopped[0], "job_id", &job(1).to_string()));
        assert!(detail_has(&stopped[0], "generation", "1"));
        assert_eq!(
            stopped[0].get("claimed_mac").map(String::as_str),
            Some(MacAddr::new(STOPPED_MAC).unwrap().to_string().as_str())
        );
        // A later generation without the device makes it eligible again
        // (the server's audited `boot-stop clear`).
        let p2 = policy(&k.policy_key, service(), 2, &[]);
        assert!(
            feed.apply_bytes(&seal(&k.policy_key, &p2), Source::Server)
                .is_ok()
        );
        assert!(r.discover(STOPPED_MAC));
    }

    /// The stop list and the suppression file act together (union).
    #[tokio::test(flavor = "current_thread")]
    async fn union_with_suppression_file() {
        let k = Keys::new();
        let s = Scratch::new("bp-union");
        let local = SuppressionList::from_ids(&[MacAddr::new(OTHER_MAC).unwrap()], &[]).unwrap();
        let supp = Arc::new(Suppression::with_list(None, local));
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let p = policy(&k.policy_key, service(), 1, &[STOPPED_MAC]);
        feed.apply_bytes(&seal(&k.policy_key, &p), Source::Server)
            .unwrap();
        let r = dhcp_rig("bp-union-dhcp", &supp).await;
        assert!(!r.discover(STOPPED_MAC));
        assert!(!r.discover(OTHER_MAC));
        assert!(r.discover([0x52, 0x54, 0x00, 0x00, 0x0a, 0x03]));
        assert_eq!(r.svc.drop_count("boot_stopped"), 1);
        assert_eq!(r.svc.drop_count("suppressed"), 1);
    }

    /// SC-23: a lower generation is refused and the applied list stays;
    /// the refusal is audited.
    #[tokio::test(flavor = "current_thread")]
    async fn rollback_refused() {
        let (cap, _g) = Capture::install();
        let k = Keys::new();
        let s = Scratch::new("bp-rollback");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let p5 = policy(&k.policy_key, service(), 5, &[STOPPED_MAC]);
        feed.apply_bytes(&seal(&k.policy_key, &p5), Source::Server)
            .unwrap();
        // An older, validly signed list that would un-stop the device.
        let p4 = policy(&k.policy_key, service(), 4, &[]);
        assert_eq!(
            feed.apply_bytes(&seal(&k.policy_key, &p4), Source::Server),
            Err(Rejection::Rollback { have: 5, got: 4 })
        );
        assert_eq!(feed.gate().generation(), Some(5));
        assert!(matches!(
            supp.verdict(MacAddr::new(STOPPED_MAC).unwrap(), None),
            usgp_relay::suppress::Verdict::Stopped(_)
        ));
        let rej = cap.named("boot_policy.rejected");
        assert_eq!(rej.len(), 1);
        assert!(detail_has(&rej[0], "reason", "rollback"));
        assert!(detail_has(&rej[0], "generation_in_effect", "5"));
        assert_eq!(rej[0].get("outcome").map(String::as_str), Some("refused"));
    }

    /// Same generation: identical bytes change nothing (no event); other
    /// content under a used generation is refused.
    #[tokio::test(flavor = "current_thread")]
    async fn equal_generation_rules() {
        let (cap, _g) = Capture::install();
        let k = Keys::new();
        let s = Scratch::new("bp-equal");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let env = seal(
            &k.policy_key,
            &policy(&k.policy_key, service(), 3, &[STOPPED_MAC]),
        );
        feed.apply_bytes(&env, Source::Server).unwrap();
        cap.clear();
        assert_eq!(
            feed.apply_bytes(&env, Source::Server),
            Ok(Applied::Unchanged)
        );
        assert!(cap.named("boot_policy.applied").is_empty());
        let other = seal(&k.policy_key, &policy(&k.policy_key, service(), 3, &[]));
        assert_eq!(
            feed.apply_bytes(&other, Source::Server),
            Err(Rejection::GenerationReused(3))
        );
        assert!(matches!(
            supp.verdict(MacAddr::new(STOPPED_MAC).unwrap(), None),
            usgp_relay::suppress::Verdict::Stopped(_)
        ));
    }

    /// SI-7(6): a list signed with another key, a tampered payload, the
    /// wrong payload type, or garbage is refused before parsing and the
    /// previous list stays.
    #[tokio::test(flavor = "current_thread")]
    async fn bad_signature_keeps_previous() {
        let k = Keys::new();
        let s = Scratch::new("bp-sig");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        feed.apply_bytes(
            &seal(
                &k.policy_key,
                &policy(&k.policy_key, service(), 1, &[STOPPED_MAC]),
            ),
            Source::Server,
        )
        .unwrap();

        // Another key (its own key_id).
        let rogue = SigningKey::generate().unwrap();
        let forged = seal(&rogue, &policy(&rogue, service(), 9, &[]));
        assert_eq!(
            feed.apply_bytes(&forged, Source::Server),
            Err(Rejection::Signature)
        );

        // Tampered payload under the real signature.
        let good = policy(&k.policy_key, service(), 9, &[STOPPED_MAC]);
        let payload = good.to_payload().unwrap();
        let sig = sign_typed(&k.policy_key, PayloadType::BootPolicyV1.as_str(), &payload).unwrap();
        let mut tampered = payload.clone();
        let at = tampered.len() / 2;
        tampered[at] ^= 0x01;
        let env = SignedEnvelopeV1::new(
            PayloadType::BootPolicyV1,
            tampered,
            vec![
                SignatureV1::new(k.policy_key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig)
                    .unwrap(),
            ],
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            feed.apply_bytes(&env, Source::Server),
            Err(Rejection::Signature)
        );

        // A payload type swap (a content manifest signature cannot pass).
        let sig = sign_typed(&k.policy_key, PayloadType::JobPlanV1.as_str(), &payload).unwrap();
        let env = SignedEnvelopeV1::new(
            PayloadType::JobPlanV1,
            payload,
            vec![
                SignatureV1::new(k.policy_key.key_id().0, SignatureAlg::EcdsaP384Sha384, sig)
                    .unwrap(),
            ],
        )
        .unwrap()
        .to_json()
        .unwrap();
        assert_eq!(
            feed.apply_bytes(&env, Source::Server),
            Err(Rejection::Signature)
        );

        for junk in [&b""[..], b"{}", b"not json", &[0xff; 64]] {
            assert_eq!(
                feed.apply_bytes(junk, Source::Server),
                Err(Rejection::Envelope)
            );
        }
        assert_eq!(feed.gate().generation(), Some(1));
        assert!(!dhcp_rig("bp-sig-dhcp", &supp).await.discover(STOPPED_MAC));
    }

    /// A signed list for another boot service is refused.
    #[tokio::test(flavor = "current_thread")]
    async fn wrong_boot_service_refused() {
        let k = Keys::new();
        let s = Scratch::new("bp-svc");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let other = BootServiceId::parse(OTHER_SERVICE).unwrap();
        let env = seal(&k.policy_key, &policy(&k.policy_key, other, 1, &[]));
        assert_eq!(
            feed.apply_bytes(&env, Source::Server),
            Err(Rejection::WrongBootService)
        );
        assert_eq!(feed.gate(), FeedGate::Awaiting);
    }

    /// A payload that verifies but is not a valid v1 list (duplicate MAC)
    /// is refused after the signature check.
    #[tokio::test(flavor = "current_thread")]
    async fn invalid_signed_payload_refused() {
        let k = Keys::new();
        let s = Scratch::new("bp-invalid");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, closed_addr().await, false), &supp);
        let p = policy(&k.policy_key, service(), 1, &[STOPPED_MAC]);
        let text = String::from_utf8(p.to_payload().unwrap()).unwrap();
        // Duplicate the single stop entry.
        let start = text.find("[{").unwrap() + 1;
        let end = text.rfind("}]").unwrap() + 1;
        let entry = text[start..end].to_owned();
        let dup = format!("{}{entry},{entry}{}", &text[..start], &text[end..]);
        let env = seal_payload(&k.policy_key, dup.into_bytes());
        assert!(matches!(
            feed.apply_bytes(&env, Source::Server),
            Err(Rejection::Invalid(_))
        ));
        assert_eq!(feed.gate(), FeedGate::Awaiting);
    }

    // -----------------------------------------------------------------
    // Tests: the pull over mTLS
    // -----------------------------------------------------------------

    /// The relay pulls over mTLS with its client certificate, applies the
    /// list, then asks with `have=<generation>` and gets 304; a new
    /// generation is applied on the next pull.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mtls_pull_applies_then_not_modified() {
        let k = Keys::new();
        let server = serve(server_tls(&k.pki)).await;
        let p1 = policy(&k.policy_key, service(), 1, &[STOPPED_MAC]);
        server.state.lock().unwrap().current = Some((1, seal(&k.policy_key, &p1)));
        let s = Scratch::new("bp-pull");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, server.addr, false), &supp);

        assert_eq!(
            feed.poll_once().await,
            PollOutcome::Applied(Applied::New { generation: 1 })
        );
        assert_eq!(feed.poll_once().await, PollOutcome::NotModified);
        let p2 = policy(&k.policy_key, service(), 2, &[STOPPED_MAC, OTHER_MAC]);
        server.state.lock().unwrap().current = Some((2, seal(&k.policy_key, &p2)));
        assert_eq!(
            feed.poll_once().await,
            PollOutcome::Applied(Applied::New { generation: 2 })
        );
        match feed.gate() {
            FeedGate::Applied(stops) => assert_eq!(stops.len(), 2),
            other => panic!("{other:?}"),
        }
        let st = server.state.lock().unwrap();
        assert_eq!(
            st.requests,
            vec![
                "GET /v1/relay/boot-policy?have=0 HTTP/1.1".to_owned(),
                "GET /v1/relay/boot-policy?have=1 HTTP/1.1".to_owned(),
                "GET /v1/relay/boot-policy?have=1 HTTP/1.1".to_owned(),
            ]
        );
        // The relay presented its enrolled client certificate every time.
        let want = usgp_crypto::sha256(k.pki.client.cert_der()).to_hex();
        assert!(
            st.client_certs
                .iter()
                .all(|c| c.as_deref() == Some(want.as_str()))
        );
    }

    /// Fail safe: when the server stops answering, the last good list
    /// stays in effect (the stopped device is still not served) and
    /// `boot_policy.fetch_failed` is emitted once per reason, not on every
    /// poll.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_unreachable_keeps_last_good() {
        let (cap, _g) = Capture::install();
        let k = Keys::new();
        let server = serve(server_tls(&k.pki)).await;
        let p = policy(&k.policy_key, service(), 4, &[STOPPED_MAC]);
        server.state.lock().unwrap().current = Some((4, seal(&k.policy_key, &p)));
        let s = Scratch::new("bp-down");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, server.addr, false), &supp);
        assert!(matches!(feed.poll_once().await, PollOutcome::Applied(_)));
        drop(server);
        tokio::time::sleep(Duration::from_millis(50)).await;
        for _ in 0..3 {
            assert!(matches!(
                feed.poll_once().await,
                PollOutcome::FetchFailed(_)
            ));
        }
        assert_eq!(feed.gate().generation(), Some(4));
        let r = dhcp_rig("bp-down-dhcp", &supp).await;
        assert!(!r.discover(STOPPED_MAC));
        assert!(r.discover(OTHER_MAC));
        let failed = cap.named("boot_policy.fetch_failed");
        assert_eq!(failed.len(), 1, "rate-limited per reason");
        assert!(detail_has(&failed[0], "generation_in_effect", "4"));
        assert!(detail_has(&failed[0], "action", "last good list kept"));
    }

    /// The relay verifies the server: a server certificate from another
    /// PKI is refused (TLS), and nothing is applied.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn untrusted_server_refused() {
        let k = Keys::new();
        let rogue_pki = TestPki::generate().unwrap();
        let server = serve(server_tls(&rogue_pki)).await;
        let p = policy(&k.policy_key, service(), 1, &[]);
        server.state.lock().unwrap().current = Some((1, seal(&k.policy_key, &p)));
        let s = Scratch::new("bp-rogue");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, server.addr, false), &supp);
        assert!(matches!(
            feed.poll_once().await,
            PollOutcome::FetchFailed(FetchError::Tls(_))
        ));
        assert_eq!(feed.gate(), FeedGate::Awaiting);
    }

    /// A non-200/304 answer is a fetch failure; the list is kept.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_error_status_is_fetch_failure() {
        let k = Keys::new();
        let server = serve(server_tls(&k.pki)).await;
        let s = Scratch::new("bp-503");
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(feed_config(&s, &k, server.addr, false), &supp);
        assert_eq!(
            feed.poll_once().await,
            PollOutcome::FetchFailed(FetchError::Status(503))
        );
        assert_eq!(feed.gate(), FeedGate::Awaiting);
    }

    // -----------------------------------------------------------------
    // Tests: cache file and start-up material
    // -----------------------------------------------------------------

    /// A list from the server is cached (0600, atomic); a new feed (a
    /// restart) applies the cache after verifying it; a tampered or
    /// rolled-back cache is refused and the relay stays without a list.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_written_and_verified_on_start() {
        use std::os::unix::fs::PermissionsExt;

        let k = Keys::new();
        let server = serve(server_tls(&k.pki)).await;
        let p = policy(&k.policy_key, service(), 7, &[STOPPED_MAC]);
        let env = seal(&k.policy_key, &p);
        server.state.lock().unwrap().current = Some((7, env.clone()));
        let s = Scratch::new("bp-cache");
        let cfg = feed_config(&s, &k, server.addr, true);
        let cache: PathBuf = cfg.cache_file.clone().unwrap();
        let supp = Arc::new(Suppression::disabled());
        let feed = new_feed(cfg.clone(), &supp);
        assert!(matches!(feed.poll_once().await, PollOutcome::Applied(_)));
        assert_eq!(std::fs::read(&cache).unwrap(), env);
        let mode = std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Restart: the cache is applied before any pull.
        let supp2 = Arc::new(Suppression::disabled());
        let feed2 = new_feed(cfg.clone(), &supp2);
        assert_eq!(feed2.load_cache(), Some(Ok(Applied::New { generation: 7 })));
        assert!(
            !dhcp_rig("bp-cache-dhcp", &supp2)
                .await
                .discover(STOPPED_MAC)
        );

        // A tampered cache is refused: no list, no offers.
        let mut bad = env.clone();
        let at = bad.len() / 2;
        bad[at] = if bad[at] == b'A' { b'B' } else { b'A' };
        std::fs::write(&cache, &bad).unwrap();
        let supp3 = Arc::new(Suppression::disabled());
        let feed3 = new_feed(cfg.clone(), &supp3);
        assert!(matches!(feed3.load_cache(), Some(Err(_))));
        assert_eq!(feed3.gate(), FeedGate::Awaiting);

        // A world-writable cache is refused.
        std::fs::write(&cache, &env).unwrap();
        set_mode(&cache, 0o666);
        let feed4 = new_feed(cfg.clone(), &Arc::new(Suppression::disabled()));
        assert!(matches!(feed4.load_cache(), Some(Err(_))));

        // No cache file yet is normal.
        std::fs::remove_file(&cache).unwrap();
        let feed5 = new_feed(cfg, &Arc::new(Suppression::disabled()));
        assert_eq!(feed5.load_cache(), None);
    }

    /// SC-12: the relay's private key must not be readable by others; a
    /// world-readable key refuses start-up (exit 78 via `RelayError::Feed`).
    #[tokio::test(flavor = "current_thread")]
    async fn readable_client_key_refused() {
        let k = Keys::new();
        let s = Scratch::new("bp-keymode");
        let cfg = feed_config(&s, &k, closed_addr().await, false);
        set_mode(&cfg.client_key, 0o644);
        let e = load_material(&cfg, &trust()).unwrap_err();
        assert!(
            matches!(
                e,
                usgp_relay::feed::FeedSetupError::File {
                    field: "client_key",
                    source: FileError::Readable { .. }
                }
            ),
            "{e}"
        );
        let re = usgp_relay::RelayError::from(e);
        assert_eq!(re.exit_code(), usgp_relay::EXIT_CONFIG);
        assert_eq!(re.field(), "server_feed.client_key");
        // The error never contains key bytes.
        let pem = String::from_utf8(k.pki.client.key_pem().unwrap().to_vec()).unwrap();
        let body = pem.lines().nth(1).unwrap();
        assert!(!re.to_string().contains(body));
    }

    /// The pinned key must be a usable public key.
    #[tokio::test(flavor = "current_thread")]
    async fn bad_pinned_key_refused() {
        let k = Keys::new();
        let s = Scratch::new("bp-badkey");
        let cfg = feed_config(&s, &k, closed_addr().await, false);
        write(&cfg.boot_policy_key_pub, b"not a key", 0o644);
        assert!(matches!(
            load_material(&cfg, &trust()),
            Err(usgp_relay::feed::FeedSetupError::Key(_))
        ));
    }
}
