//! Device-listener TLS (server authentication only; decision 0020) and
//! the operator listener's unchanged client-certificate rules.
//!
//! Handshakes run through the real async accept paths over an in-memory
//! duplex pipe.
#![cfg(feature = "test-pki")]

#[cfg(test)]
mod device {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use usgp_crypto::CryptoError;
    use usgp_crypto::test_pki::TestPki;
    use usgp_crypto::tls::{
        ClientTls, DeviceServerTls, DeviceServerTlsSettings, ServerTls, TlsMinVersion, TlsProtocol,
    };

    fn device_settings(pki: &TestPki, min: TlsMinVersion) -> DeviceServerTlsSettings {
        DeviceServerTlsSettings {
            cert_chain_pem: pki.server.chain_pem(),
            private_key_pem: pki.server.key_pem().unwrap(),
            min_version: min,
        }
    }

    #[tokio::test]
    async fn client_without_certificate_connects() {
        let pki = TestPki::generate().unwrap();
        let server = DeviceServerTls::new(&device_settings(&pki, TlsMinVersion::Tls12)).unwrap();
        assert!(server.is_fips());
        let client =
            ClientTls::new(&pki.client_settings(None, TlsMinVersion::Tls12).unwrap()).unwrap();
        let (a, b) = duplex(64 * 1024);
        let srv = async move {
            let mut s = server.accept(a).await.unwrap();
            assert_eq!(s.protocol(), Some(TlsProtocol::Tls13));
            assert_eq!(s.alpn(), Some(&b"http/1.1"[..]));
            assert!(!s.resumed());
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            s.write_all(&buf).await.unwrap();
            s.shutdown().await.unwrap();
        };
        let cli = async move {
            let mut c = client.connect(b, "localhost").await.unwrap();
            c.write_all(b"hello").await.unwrap();
            let mut back = Vec::new();
            c.read_to_end(&mut back).await.unwrap();
            assert_eq!(back, b"hello");
        };
        tokio::join!(srv, cli);
    }

    #[tokio::test]
    async fn tls13_floor_is_honoured() {
        let pki = TestPki::generate().unwrap();
        let server = DeviceServerTls::new(&device_settings(&pki, TlsMinVersion::Tls13)).unwrap();
        let client =
            ClientTls::new(&pki.client_settings(None, TlsMinVersion::Tls12).unwrap()).unwrap();
        let (a, b) = duplex(64 * 1024);
        let (s, c) = tokio::join!(server.accept(a), client.connect(b, "localhost"));
        assert_eq!(s.unwrap().protocol(), Some(TlsProtocol::Tls13));
        assert!(c.is_ok());
    }

    #[tokio::test]
    async fn untrusting_client_is_refused_by_its_own_check() {
        // The server side is still authenticated: a device whose anchors
        // do not cover the server certificate refuses the connection.
        let pki = TestPki::generate().unwrap();
        let server = DeviceServerTls::new(&device_settings(&pki, TlsMinVersion::Tls12)).unwrap();
        let mut settings = pki.client_settings(None, TlsMinVersion::Tls12).unwrap();
        settings.trust_anchors_pem = pki.untrusted_root.cert_pem().unwrap().into_bytes();
        let client = ClientTls::new(&settings).unwrap();
        let (a, b) = duplex(64 * 1024);
        let (s, c) = tokio::join!(server.accept(a), client.connect(b, "localhost"));
        assert!(c.is_err());
        assert!(s.is_err());
    }

    #[test]
    fn bad_device_settings_refused() {
        let pki = TestPki::generate().unwrap();
        // No certificate.
        let mut s = device_settings(&pki, TlsMinVersion::Tls12);
        s.cert_chain_pem = Vec::new();
        assert!(matches!(
            DeviceServerTls::new(&s),
            Err(CryptoError::Pem { .. })
        ));
        // Key from another certificate.
        let mut s = device_settings(&pki, TlsMinVersion::Tls12);
        s.private_key_pem = pki.client.key_pem().unwrap();
        assert!(matches!(
            DeviceServerTls::new(&s),
            Err(CryptoError::TlsConfig { .. })
        ));
        // Not a private key.
        let mut s = device_settings(&pki, TlsMinVersion::Tls12);
        s.private_key_pem = zeroize::Zeroizing::new(pki.server.chain_pem());
        assert!(DeviceServerTls::new(&s).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let pki = TestPki::generate().unwrap();
        let settings = device_settings(&pki, TlsMinVersion::Tls12);
        let text = format!("{settings:?}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(!text.contains("BEGIN"), "{text}");
        let server = DeviceServerTls::new(&settings).unwrap();
        let text = format!("{server:?}");
        assert!(text.contains("fips: true"), "{text}");
    }

    // Operator listener: unchanged by the device constructor.

    #[test]
    fn operator_constructor_still_requires_client_anchors_and_crls() {
        let pki = TestPki::generate().unwrap();
        let mut s = pki
            .server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls12)
            .unwrap();
        s.client_trust_anchors_pem = Vec::new();
        assert!(ServerTls::new(&s).is_err());
        let s = pki
            .server_settings(Vec::new(), vec![], TlsMinVersion::Tls12)
            .unwrap();
        assert!(matches!(
            ServerTls::new(&s),
            Err(CryptoError::TlsConfig { .. })
        ));
    }

    #[tokio::test]
    async fn operator_listener_gives_no_identity_to_a_client_without_certificate() {
        // M2 design (server.rs): the certificate is optional at the TLS
        // layer, so the handshake completes with no identity and the HTTP
        // layer answers 401. The device listener did not change this.
        let pki = TestPki::generate().unwrap();
        let server = ServerTls::new(
            &pki.server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        let client =
            ClientTls::new(&pki.client_settings(None, TlsMinVersion::Tls12).unwrap()).unwrap();
        let (a, b) = duplex(64 * 1024);
        let (s, c) = tokio::join!(server.accept(a), client.connect(b, "localhost"));
        let (_stream, identity) = s.unwrap();
        assert!(identity.is_none());
        assert!(c.is_ok());
    }
}
