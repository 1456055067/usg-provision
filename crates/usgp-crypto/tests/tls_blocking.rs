//! Blocking TLS client for the pre-boot agent (plan M3 WU-1, section 5
//! "Agent TLS client"; REQ-PE-015, decision 0020).
//!
//! Each test runs a real loopback TCP connection against a test
//! `ServerTls` (`test_pki::accept_blocking`) on its own thread.
#![cfg(feature = "test-pki")]

#[cfg(test)]
mod blocking {
    use std::io::{BufRead, BufReader, Cursor, ErrorKind, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use usgp_crypto::test_pki::{
        BlockingTestServerStream, LeafSpec, TestPki, Window, accept_blocking,
    };
    use usgp_crypto::tls::{
        BlockingClientStream, BlockingClientTls, ClientAlpn, ClientTlsSettings, ServerTls,
        ServerTlsSettings, TlsFailure, TlsFailureClass, TlsMinVersion, TlsProtocol,
    };
    use usgp_crypto::{CryptoError, PeerCertificate};

    const TIMEOUT: Duration = Duration::from_secs(10);

    type ServerOutcome = Result<Option<PeerCertificate>, TlsFailure>;

    fn server_tls(pki: &TestPki) -> ServerTls {
        let settings = pki
            .server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls12)
            .unwrap();
        ServerTls::new(&settings).unwrap()
    }

    fn agent_settings(pki: &TestPki) -> ClientTlsSettings {
        // The agent: trust anchors only, no client certificate.
        pki.client_settings(None, TlsMinVersion::Tls12).unwrap()
    }

    fn listen() -> (TcpListener, std::net::SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    fn dial(addr: std::net::SocketAddr) -> TcpStream {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(TIMEOUT)).unwrap();
        s.set_write_timeout(Some(TIMEOUT)).unwrap();
        s
    }

    /// A server that accepts one connection, runs `then` on the established
    /// stream, and reports the handshake outcome.
    fn serve_one<F>(server: ServerTls, listener: TcpListener, then: F) -> JoinHandle<ServerOutcome>
    where
        F: FnOnce(BlockingTestServerStream) + Send + 'static,
    {
        thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
            tcp.set_write_timeout(Some(TIMEOUT)).unwrap();
            let (stream, peer) = accept_blocking(&server, tcp)?;
            then(stream);
            Ok(peer)
        })
    }

    /// Echo one line back, then close cleanly.
    fn echo_line(stream: BlockingTestServerStream) {
        let mut r = BufReader::new(stream);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let mut stream = r.into_inner();
        stream.write_all(line.as_bytes()).unwrap();
        stream.flush().unwrap();
        stream.close().unwrap();
    }

    fn client_failure(
        settings: &ClientTlsSettings,
        server: ServerTls,
        name: &str,
    ) -> (TlsFailure, JoinHandle<ServerOutcome>) {
        let (l, addr) = listen();
        let h = serve_one(server, l, |_| {});
        let client = BlockingClientTls::new(settings).unwrap();
        let err = client.connect(dial(addr), name).unwrap_err();
        (err, h)
    }

    #[test]
    fn round_trip_over_tls13_with_http11_alpn() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = serve_one(server_tls(&pki), l, echo_line);
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        assert!(client.is_fips());
        let mut s: BlockingClientStream = client.connect(dial(addr), "localhost").unwrap();
        assert_eq!(s.protocol(), Some(TlsProtocol::Tls13));
        assert_eq!(s.alpn(), Some(&b"http/1.1"[..]));
        assert!(!s.resumed());
        let suite = s.cipher_suite().unwrap();
        assert!(
            ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256"].contains(&suite),
            "{suite}"
        );
        assert!(s.io().peer_addr().is_ok());
        s.write_all(b"hello agent\n").unwrap();
        s.flush().unwrap();
        let mut back = Vec::new();
        // Clean close_notify from the server: read_to_end ends with Ok.
        s.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"hello agent\n");
        s.close().unwrap();
        // No client certificate presented (the agent carries no secret).
        assert!(matches!(h.join().unwrap(), Ok(None)));
    }

    #[test]
    fn ip_literal_server_name_accepted() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = serve_one(server_tls(&pki), l, echo_line);
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        let mut s = client.connect(dial(addr), "127.0.0.1").unwrap();
        s.write_all(b"x\n").unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        assert_eq!(back, b"x\n");
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn tls13_only_client_connects() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = serve_one(server_tls(&pki), l, echo_line);
        let mut settings = agent_settings(&pki);
        settings.min_version = TlsMinVersion::Tls13;
        let client = BlockingClientTls::new(&settings).unwrap();
        let mut s = client.connect(dial(addr), "localhost").unwrap();
        assert_eq!(s.protocol(), Some(TlsProtocol::Tls13));
        s.write_all(b"y\n").unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn wrong_trust_anchor_refused() {
        let pki = TestPki::generate().unwrap();
        let settings = ClientTlsSettings {
            trust_anchors_pem: pki.untrusted_root.cert_pem().unwrap().into_bytes(),
            client_cert_chain_pem: None,
            client_key_pem: None,
            min_version: TlsMinVersion::Tls12,
            alpn: ClientAlpn::Http11,
        };
        let (err, h) = client_failure(&settings, server_tls(&pki), "localhost");
        assert_eq!(err.class, TlsFailureClass::Untrusted, "{err}");
        assert!(!err.class.is_time_related());
        // The server sees the client's alert, never an application byte.
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn wrong_server_name_refused() {
        let pki = TestPki::generate().unwrap();
        for name in ["example.invalid", "127.0.0.2", "localhost.localdomain"] {
            let (err, h) = client_failure(&agent_settings(&pki), server_tls(&pki), name);
            assert_eq!(err.class, TlsFailureClass::BadCertificate, "{name}: {err}");
            assert!(h.join().unwrap().is_err(), "{name}");
        }
    }

    #[test]
    fn expired_server_certificate_is_a_time_failure() {
        let pki = TestPki::generate().unwrap();
        let expired = pki
            .intermediate
            .issue(&LeafSpec {
                window: Window::Expired,
                ..LeafSpec::server("localhost")
            })
            .unwrap();
        let settings = ServerTlsSettings {
            cert_chain_pem: expired.chain_pem(),
            private_key_pem: expired.key_pem().unwrap(),
            min_version: TlsMinVersion::Tls12,
            client_trust_anchors_pem: pki.root.cert_pem().unwrap().into_bytes(),
            client_crls: pki.current_crls().unwrap(),
            acceptable_policy_oids: vec![],
        };
        let server = ServerTls::new(&settings).unwrap();
        let (err, h) = client_failure(&agent_settings(&pki), server, "localhost");
        assert_eq!(err.class, TlsFailureClass::Expired, "{err}");
        assert!(err.class.is_time_related());
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn not_yet_valid_server_certificate_is_a_time_failure() {
        let pki = TestPki::generate().unwrap();
        let future = pki
            .intermediate
            .issue(&LeafSpec {
                window: Window::NotYetValid,
                ..LeafSpec::server("localhost")
            })
            .unwrap();
        let settings = ServerTlsSettings {
            cert_chain_pem: future.chain_pem(),
            private_key_pem: future.key_pem().unwrap(),
            min_version: TlsMinVersion::Tls12,
            client_trust_anchors_pem: pki.root.cert_pem().unwrap().into_bytes(),
            client_crls: pki.current_crls().unwrap(),
            acceptable_policy_oids: vec![],
        };
        let server = ServerTls::new(&settings).unwrap();
        let (err, h) = client_failure(&agent_settings(&pki), server, "localhost");
        assert_eq!(err.class, TlsFailureClass::NotYetValid, "{err}");
        assert!(err.class.is_time_related());
        assert!(h.join().unwrap().is_err());
    }

    #[test]
    fn invalid_server_name_refused_before_any_io() {
        let pki = TestPki::generate().unwrap();
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        for name in ["", "bad name", "a..b", "-"] {
            let err = client
                .connect(Cursor::new(Vec::<u8>::new()), name)
                .unwrap_err();
            assert_eq!(err.class, TlsFailureClass::Protocol, "{name:?}");
        }
    }

    #[test]
    fn peer_closing_during_handshake_fails_closed() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = thread::spawn(move || {
            let (tcp, _) = l.accept().unwrap();
            drop(tcp);
        });
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        let err = client.connect(dial(addr), "localhost").unwrap_err();
        assert_eq!(err.class, TlsFailureClass::Protocol, "{err}");
        h.join().unwrap();
    }

    #[test]
    fn non_tls_peer_fails_closed() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = thread::spawn(move || {
            let (mut tcp, _) = l.accept().unwrap();
            tcp.set_read_timeout(Some(TIMEOUT)).unwrap();
            let mut buf = [0u8; 512];
            let _ = tcp.read(&mut buf);
            let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            let _ = tcp.shutdown(Shutdown::Both);
        });
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        let err = client.connect(dial(addr), "localhost").unwrap_err();
        assert_eq!(err.class, TlsFailureClass::Protocol, "{err}");
        h.join().unwrap();
    }

    #[test]
    fn silent_peer_times_out() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let (done_tx, done_rx) = mpsc::channel::<()>();
        let h = thread::spawn(move || {
            let (_tcp, _) = l.accept().unwrap();
            // Hold the connection open, say nothing.
            let _ = done_rx.recv_timeout(TIMEOUT);
        });
        let tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        let err = client.connect(tcp, "localhost").unwrap_err();
        assert_eq!(err.class, TlsFailureClass::Protocol, "{err}");
        done_tx.send(()).unwrap();
        h.join().unwrap();
    }

    #[test]
    fn truncation_is_an_error_not_end_of_data() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = serve_one(server_tls(&pki), l, |mut s| {
            s.write_all(b"partial").unwrap();
            s.flush().unwrap();
            // Cut the TCP connection without close_notify.
            let tcp = s.into_socket();
            tcp.shutdown(Shutdown::Both).unwrap();
        });
        let client = BlockingClientTls::new(&agent_settings(&pki)).unwrap();
        let mut s = client.connect(dial(addr), "localhost").unwrap();
        let mut back = Vec::new();
        let err = s.read_to_end(&mut back).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof, "{err}");
        assert_eq!(back, b"partial");
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn client_certificate_presented_when_configured() {
        let pki = TestPki::generate().unwrap();
        let (l, addr) = listen();
        let h = serve_one(server_tls(&pki), l, echo_line);
        let settings = pki
            .client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap();
        let client = BlockingClientTls::new(&settings).unwrap();
        let mut s = client.connect(dial(addr), "localhost").unwrap();
        s.write_all(b"z\n").unwrap();
        let mut back = Vec::new();
        s.read_to_end(&mut back).unwrap();
        let peer = h.join().unwrap().unwrap().unwrap();
        assert!(peer.subject.contains("CN=operator one"), "{}", peer.subject);
    }

    #[test]
    fn bad_settings_refused_at_build() {
        let pki = TestPki::generate().unwrap();
        // No anchors.
        let mut s = agent_settings(&pki);
        s.trust_anchors_pem = Vec::new();
        assert!(matches!(
            BlockingClientTls::new(&s),
            Err(CryptoError::Pem { .. })
        ));
        // Garbage anchors.
        s.trust_anchors_pem = b"not pem".to_vec();
        assert!(BlockingClientTls::new(&s).is_err());
        // Certificate without key.
        let mut s = agent_settings(&pki);
        s.client_cert_chain_pem = Some(pki.client.chain_pem());
        assert!(matches!(
            BlockingClientTls::new(&s),
            Err(CryptoError::TlsConfig { .. })
        ));
        // Key that does not match the certificate.
        let mut s = pki
            .client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap();
        s.client_key_pem = Some(pki.client_expired.key_pem().unwrap());
        assert!(BlockingClientTls::new(&s).is_err());
    }

    #[test]
    fn debug_shows_no_secrets() {
        let pki = TestPki::generate().unwrap();
        let settings = pki
            .client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap();
        let client = BlockingClientTls::new(&settings).unwrap();
        let text = format!("{client:?}");
        assert!(text.contains("fips: true"), "{text}");
        assert!(!text.contains("BEGIN"), "{text}");
    }
}
