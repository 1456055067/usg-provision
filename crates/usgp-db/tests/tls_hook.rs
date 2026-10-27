//! The PostgreSQL TLS hook and the certificate-only rule, against local
//! stand-in servers (no database; runs everywhere).
//!
//! - TLS handshake through `usgp-crypto`: client certificate presented, no
//!   ALPN, no channel binding.
//! - Wrong server name or untrusted server → refused with the TLS class.
//! - A server that does not offer TLS (`N` to the SSLRequest) → refused;
//!   no startup message is ever sent in plaintext.
//! - A server that asks for a password (cleartext, MD5 or SCRAM) after the
//!   TLS handshake → `auth_method_refused`; the driver has no password, so
//!   no hash is computed (decision 0012, plan section 5.5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1), IA-5(2), SC-13
// - Decision 0012

// Helpers and tests in one `cfg(test)` module so the workspace's
// test-only clippy allowances apply (same convention as usgp-audit).
#[cfg(test)]
mod t {

    use std::io::{Read, Write};
    use std::net::TcpListener as StdListener;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_postgres::tls::{MakeTlsConnect, TlsConnect, TlsStream};
    use usgp_crypto::test_pki::TestPki;
    use usgp_crypto::tls::{ClientAlpn, ClientTls, ServerTls, TlsFailureClass, TlsMinVersion};
    use usgp_db::{ConnectFailure, DbError, DbSettings, PgStore, PgTls};
    use zeroize::Zeroizing;

    const SSL_REQUEST: [u8; 8] = [0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f];

    fn pki() -> TestPki {
        TestPki::generate().unwrap()
    }

    fn client_tls(pki: &TestPki) -> ClientTls {
        let mut s = pki
            .client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap();
        s.alpn = ClientAlpn::None;
        ClientTls::new(&s).unwrap()
    }

    fn server_tls(pki: &TestPki) -> ServerTls {
        let s = pki
            .server_settings(
                pki.current_crls().unwrap(),
                Vec::new(),
                TlsMinVersion::Tls12,
            )
            .unwrap();
        ServerTls::new(&s).unwrap()
    }

    fn settings(port: u16) -> DbSettings {
        DbSettings {
            host: "127.0.0.1".into(),
            port,
            dbname: "usgp".into(),
            user: "usgp_app".into(),
            server_name: Some("localhost".into()),
            server_ca_pem: b"unused: connector supplied".to_vec(),
            client_cert_pem: b"unused: connector supplied".to_vec(),
            client_key_pem: Zeroizing::new(b"unused: connector supplied".to_vec()),
            min_tls: TlsMinVersion::Tls12,
            pool_size: 1,
            connect_timeout: Duration::from_secs(10),
            application_name: "usgp-db-test".into(),
        }
    }

    #[tokio::test]
    async fn handshake_presents_client_cert_without_alpn_or_channel_binding() {
        let pki = pki();
        let server = server_tls(&pki);
        let mut hook = PgTls::from_client(client_tls(&pki), "localhost").unwrap();
        assert!(hook.is_fips());
        let (c, s) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(async move { server.accept(s).await.map(|(_, peer)| peer) });
        let connect = <PgTls as MakeTlsConnect<tokio::io::DuplexStream>>::make_tls_connect(
            &mut hook, "ignored",
        )
        .unwrap();
        let stream = connect.connect(c).await.unwrap();
        assert!(stream.session().alpn().is_none());
        assert!(stream.session().protocol().is_some());
        // `channel_binding()` returns `ChannelBinding::none()` by construction
        // (src/tls.rs); tokio-postgres gives the value no accessor to assert on.
        // The SCRAM tests below show no password exchange can start.
        let _none = stream.channel_binding();
        let peer = srv.await.unwrap().unwrap().expect("client certificate");
        assert_eq!(peer.sha256, pki.client.peer_certificate().unwrap().sha256);
    }

    #[tokio::test]
    async fn wrong_server_name_refused() {
        let pki = pki();
        let server = server_tls(&pki);
        let mut hook = PgTls::from_client(client_tls(&pki), "db.example").unwrap();
        let (c, s) = tokio::io::duplex(64 * 1024);
        let _srv = tokio::spawn(async move { server.accept(s).await.map(|_| ()) });
        let connect = <PgTls as MakeTlsConnect<tokio::io::DuplexStream>>::make_tls_connect(
            &mut hook,
            "localhost",
        )
        .unwrap();
        let err = connect.connect(c).await.unwrap_err();
        assert_eq!(err.class(), TlsFailureClass::BadCertificate);
    }

    #[tokio::test]
    async fn untrusted_server_refused() {
        let pki = pki();
        let other = TestPki::generate().unwrap();
        let server = server_tls(&other);
        let mut hook = PgTls::from_client(client_tls(&pki), "localhost").unwrap();
        let (c, s) = tokio::io::duplex(64 * 1024);
        let _srv = tokio::spawn(async move { server.accept(s).await.map(|_| ()) });
        let connect = <PgTls as MakeTlsConnect<tokio::io::DuplexStream>>::make_tls_connect(
            &mut hook,
            "localhost",
        )
        .unwrap();
        let err = connect.connect(c).await.unwrap_err();
        assert_eq!(err.class(), TlsFailureClass::Untrusted);
    }

    #[test]
    fn invalid_tls_inputs_refused() {
        let mut s = settings(5432);
        s.server_ca_pem = b"not pem".to_vec();
        s.client_cert_pem = b"not pem".to_vec();
        let err = PgStore::connect(&s).unwrap_err();
        assert!(matches!(err, DbError::Connect { .. }), "{err:?}");
    }

    /// A server that answers `N` (no TLS): the client must give up, and must
    /// not send its startup message (user name, database) in plaintext.
    #[tokio::test]
    async fn server_without_tls_refused_no_plaintext() {
        let listener = StdListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut req = [0u8; 8];
            sock.read_exact(&mut req).unwrap();
            assert_eq!(req, SSL_REQUEST);
            sock.write_all(b"N").unwrap();
            let mut rest = Vec::new();
            // The client closes; anything it sent after `N` is captured.
            let _ = sock.read_to_end(&mut rest);
            rest
        });
        let pki = pki();
        let hook = PgTls::from_client(client_tls(&pki), "localhost").unwrap();
        let store = PgStore::with_tls(&settings(port), hook).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::TlsNotOffered,
                    ..
                }
            ),
            "{err:?}"
        );
        store.close();
        let after = server.join().unwrap();
        assert!(
            after.is_empty(),
            "client sent {} plaintext bytes",
            after.len()
        );
    }

    /// After TLS, the server sends one authentication request; returns what
    /// the server saw.
    async fn password_server(listener: TcpListener, server: ServerTls, auth: Vec<u8>) -> bool {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut req = [0u8; 8];
        sock.read_exact(&mut req).await.unwrap();
        assert_eq!(req, SSL_REQUEST);
        sock.write_all(b"S").await.unwrap();
        let (mut tls, peer) = server.accept(sock).await.unwrap();
        // Startup message: length (incl. itself), then the body.
        let mut len = [0u8; 4];
        tls.read_exact(&mut len).await.unwrap();
        let len = usize::try_from(u32::from_be_bytes(len)).unwrap();
        let mut body = vec![0u8; len.checked_sub(4).unwrap()];
        tls.read_exact(&mut body).await.unwrap();
        let text = String::from_utf8_lossy(&body).to_string();
        assert!(text.contains("usgp_app"), "explicit user sent");
        tls.write_all(&auth).await.unwrap();
        tls.flush().await.unwrap();
        // The client must close without answering with a password message.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut rest)).await;
        assert!(
            !rest.first().is_some_and(|b| *b == b'p'),
            "client sent a password/SASL response"
        );
        peer.is_some()
    }

    fn auth_request(code: u32, extra: &[u8]) -> Vec<u8> {
        let len = u32::try_from(4 + 4 + extra.len()).unwrap();
        let mut m = vec![b'R'];
        m.extend_from_slice(&len.to_be_bytes());
        m.extend_from_slice(&code.to_be_bytes());
        m.extend_from_slice(extra);
        m
    }

    async fn expect_auth_method_refused(auth: Vec<u8>) {
        let pki = pki();
        let server = server_tls(&pki);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let srv = tokio::spawn(password_server(listener, server, auth));
        let hook = PgTls::from_client(client_tls(&pki), "localhost").unwrap();
        let store = PgStore::with_tls(&settings(port), hook).unwrap();
        let err = store.ping().await.unwrap_err();
        assert!(
            matches!(
                err,
                DbError::Connect {
                    class: ConnectFailure::AuthMethodRefused,
                    ..
                }
            ),
            "{err:?}"
        );
        store.close();
        assert!(srv.await.unwrap(), "client certificate was presented");
    }

    #[tokio::test]
    async fn scram_request_refused() {
        expect_auth_method_refused(auth_request(10, b"SCRAM-SHA-256\0\0")).await;
    }

    #[tokio::test]
    async fn md5_request_refused() {
        expect_auth_method_refused(auth_request(5, &[1, 2, 3, 4])).await;
    }

    #[tokio::test]
    async fn cleartext_request_refused() {
        expect_auth_method_refused(auth_request(3, &[])).await;
    }
}
