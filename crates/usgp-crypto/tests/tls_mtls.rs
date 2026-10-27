//! Operator mTLS: client-certificate validation outcomes (plan M2 section
//! 5.4 and section 10 "mTLS"; REQ-RBAC-005, REQ-IMG-053).
//!
//! Handshakes run in memory through the production server configuration,
//! verifier and identity step (`test_pki::memory_handshake`).
#![cfg(feature = "test-pki")]

#[cfg(test)]
mod mtls {
    use usgp_crypto::test_pki::{
        MemoryHandshake, POLICY_ACCEPTED, TestCert, TestPki, client_tls_without_local_checks,
        memory_handshake,
    };
    use usgp_crypto::tls::{ClientTls, ServerTls, TlsFailureClass, TlsMinVersion, TlsProtocol};
    use usgp_crypto::{CryptoError, PeerCertificate, sha256};

    struct Fixture {
        pki: TestPki,
        server: ServerTls,
    }

    fn fixture_with(crls: impl Fn(&TestPki) -> Vec<Vec<u8>>, policies: Vec<String>) -> Fixture {
        let pki = TestPki::generate().unwrap();
        let settings = pki
            .server_settings(crls(&pki), policies, TlsMinVersion::Tls12)
            .unwrap();
        let server = ServerTls::new(&settings).unwrap();
        Fixture { pki, server }
    }

    fn fixture() -> Fixture {
        fixture_with(|p| p.current_crls().unwrap(), vec![])
    }

    fn connect(f: &Fixture, cert: Option<&TestCert>) -> MemoryHandshake {
        let client =
            ClientTls::new(&f.pki.client_settings(cert, TlsMinVersion::Tls12).unwrap()).unwrap();
        memory_handshake(&f.server, &client, "localhost").unwrap()
    }

    fn refused_class(h: &MemoryHandshake) -> TlsFailureClass {
        match &h.server {
            Err(e) => e.class,
            Ok(v) => panic!("expected refusal, got {v:?}"),
        }
    }

    #[test]
    fn valid_certificate_gives_identity() {
        let f = fixture();
        let h = connect(&f, Some(&f.pki.client));
        let peer = h.server.as_ref().unwrap().as_ref().unwrap();
        assert_eq!(peer.sha256, sha256(f.pki.client.cert_der()));
        assert_eq!(peer.der, f.pki.client.cert_der());
        assert!(peer.subject.contains("CN=operator one"), "{}", peer.subject);
        assert!(
            peer.issuer.contains("CN=usgp test operator ca"),
            "{}",
            peer.issuer
        );
        assert_eq!(peer.policies, vec![POLICY_ACCEPTED.to_string()]);
        assert!(!peer.serial.is_empty());
        assert!(peer.not_before < peer.not_after);
        assert!(h.client_error.is_none());
        assert!(!h.resumed);
    }

    #[test]
    fn no_certificate_reaches_http_as_none() {
        let f = fixture();
        let h = connect(&f, None);
        assert!(matches!(h.server, Ok(None)), "{:?}", h.server);
        assert!(h.client_error.is_none());
    }

    #[test]
    fn untrusted_issuer_refused() {
        let f = fixture();
        let h = connect(&f, Some(&f.pki.client_untrusted));
        assert_eq!(refused_class(&h), TlsFailureClass::Untrusted);
        assert!(h.client_error.is_some(), "client sees the alert");
    }

    /// SEC-012 / NIST-014: a refusal says whether the presented
    /// certificate chains to a configured anchor. Everything our PKI
    /// issued does, whatever the failure; a foreign or self-made
    /// certificate does not, even one that copies our CA names.
    #[test]
    fn refusal_records_whether_the_certificate_chains_to_an_anchor() {
        let f = fixture_with(
            |p| p.current_crls().unwrap(),
            vec![POLICY_ACCEPTED.to_string()],
        );
        let pki = &f.pki;
        let raw = |cert: &TestCert| {
            let client = client_tls_without_local_checks(pki, cert).unwrap();
            memory_handshake(&f.server, &client, "localhost").unwrap()
        };
        for cert in [
            &pki.client_revoked,
            &pki.client_under_revoked,
            &pki.client_expired,
            &pki.client_not_yet_valid,
            &pki.client_server_eku,
            &pki.client_no_eku,
            &pki.client_critical_ext,
            &pki.client_other_policy,
        ] {
            let h = raw(cert);
            let class = refused_class(&h);
            assert!(h.chained, "{class:?} from our PKI must count as chained");
        }
        assert!(!raw(&pki.client_untrusted).chained);

        // Same names as our hierarchy, different keys.
        let fake_root = usgp_crypto::test_pki::TestCa::root("usgp test root").unwrap();
        let fake_ca = fake_root.intermediate("usgp test operator ca").unwrap();
        let forged = fake_ca
            .issue(&usgp_crypto::test_pki::LeafSpec::client("operator one"))
            .unwrap();
        let h = raw(&forged);
        assert_eq!(refused_class(&h), TlsFailureClass::Untrusted);
        assert!(!h.chained, "name match without signature is not a chain");
        // Self-signed-style: the foreign root presenting a leaf it issued
        // directly.
        let selfmade = fake_root
            .issue(&usgp_crypto::test_pki::LeafSpec::client("self made"))
            .unwrap();
        assert!(!raw(&selfmade).chained);
        // Success and no certificate: nothing refused, nothing chained.
        assert!(!connect(&f, Some(&pki.client)).chained);
        assert!(!connect(&f, None).chained);
    }

    /// SEC-007: CRL facts (issuer, number) for rollback checks.
    #[test]
    fn crl_facts_name_issuer_and_number() {
        let pki = TestPki::generate().unwrap();
        let der = pki.intermediate.crl_numbered(&[], false, 300).unwrap();
        let facts = usgp_crypto::crl_facts(&der).unwrap();
        assert_eq!(facts.len(), 1);
        assert!(
            facts[0].issuer.contains("usgp test operator ca"),
            "{}",
            facts[0].issuer
        );
        let n300 = facts[0].number.clone().unwrap();
        let pem =
            usgp_crypto::test_pki::crl_pem(&pki.intermediate.crl(&[], false).unwrap()).unwrap();
        let n1 = usgp_crypto::crl_facts(pem.as_bytes()).unwrap()[0]
            .number
            .clone()
            .unwrap();
        assert!(n1 < n300);
        assert_eq!(n300.to_string(), "012c");
        assert!(usgp_crypto::crl_facts(b"not a crl").is_err());
    }

    #[test]
    fn expired_refused() {
        let f = fixture();
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_expired))),
            TlsFailureClass::Expired
        );
    }

    #[test]
    fn not_yet_valid_refused() {
        let f = fixture();
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_not_yet_valid))),
            TlsFailureClass::NotYetValid
        );
    }

    #[test]
    fn revoked_end_entity_refused() {
        let f = fixture();
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_revoked))),
            TlsFailureClass::Revoked
        );
    }

    #[test]
    fn revoked_intermediate_refused() {
        // The end entity itself is not revoked; its issuer is on the root CRL.
        let f = fixture();
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_under_revoked))),
            TlsFailureClass::Revoked
        );
    }

    #[test]
    fn stale_crl_refused_fail_closed() {
        let f = fixture_with(|p| p.crls_with_stale_intermediate().unwrap(), vec![]);
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client))),
            TlsFailureClass::CrlStale
        );
    }

    #[test]
    fn missing_crl_for_an_issuer_is_unknown_status_refused() {
        // Only the root's CRL: the intermediate-issued end entity has no CRL.
        let f = fixture_with(
            |p| {
                vec![
                    p.root
                        .crl(&[p.revoked_intermediate.serial()], false)
                        .unwrap(),
                ]
            },
            vec![],
        );
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client))),
            TlsFailureClass::RevocationUnknown
        );
    }

    #[test]
    fn missing_client_auth_eku_refused() {
        let f = fixture();
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_server_eku))),
            TlsFailureClass::BadEku
        );
    }

    #[test]
    fn absent_eku_extension_refused() {
        // SEC-006: stricter than RFC 5280 §4.2.1.12 (absent EKU = any
        // purpose); an operator certificate must list id-kp-clientAuth.
        let f = fixture();
        let h = connect(&f, Some(&f.pki.client_no_eku));
        assert_eq!(refused_class(&h), TlsFailureClass::BadEku);
        // The refusal still names the presented certificate (NIST-005).
        let p = h.presented.as_ref().expect("presented certificate");
        assert_eq!(p.sha256, sha256(f.pki.client_no_eku.cert_der()));
        assert!(p.subject.contains("CN=operator no eku"), "{}", p.subject);
        assert_eq!(p.extended_key_usage, None);
        assert!(!p.permits_client_auth());
        assert!(p.require_client_auth_eku().is_err());
    }

    #[test]
    fn enrolment_helper_matches_the_handshake_rule() {
        let pki = TestPki::generate().unwrap();
        let ok = PeerCertificate::from_der(pki.client.cert_der()).unwrap();
        assert!(ok.permits_client_auth());
        assert!(ok.require_client_auth_eku().is_ok());
        for bad in [&pki.client_no_eku, &pki.client_server_eku] {
            let c = PeerCertificate::from_der(bad.cert_der()).unwrap();
            assert!(!c.permits_client_auth());
            assert!(matches!(
                c.require_client_auth_eku(),
                Err(CryptoError::Certificate { .. })
            ));
        }
    }

    #[test]
    fn refusal_names_presented_certificate_and_success_does_not() {
        let f = fixture();
        for cert in [
            &f.pki.client_revoked,
            &f.pki.client_expired,
            &f.pki.client_untrusted,
            &f.pki.client_server_eku,
        ] {
            let h = connect(&f, Some(cert));
            assert!(h.server.is_err());
            let p = h.presented.as_ref().expect("presented certificate");
            assert_eq!(p.sha256, sha256(cert.cert_der()));
            assert!(!p.serial.is_empty());
            assert!(!p.issuer.is_empty());
        }
        assert!(connect(&f, Some(&f.pki.client)).presented.is_none());
        assert!(connect(&f, None).presented.is_none());
    }

    #[test]
    fn unknown_critical_extension_refused() {
        let f = fixture();
        let client = client_tls_without_local_checks(&f.pki, &f.pki.client_critical_ext).unwrap();
        let h = memory_handshake(&f.server, &client, "localhost").unwrap();
        assert_eq!(refused_class(&h), TlsFailureClass::UnknownCriticalExt);
    }

    #[test]
    fn policy_mismatch_refused_when_policies_configured() {
        let f = fixture_with(
            |p| p.current_crls().unwrap(),
            vec![POLICY_ACCEPTED.to_string()],
        );
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_other_policy))),
            TlsFailureClass::Policy
        );
        // A certificate with no policies at all is refused too.
        assert_eq!(
            refused_class(&connect(&f, Some(&f.pki.client_without_policy()))),
            TlsFailureClass::Policy
        );
        // The good certificate asserts the accepted policy.
        assert!(matches!(
            connect(&f, Some(&f.pki.client)).server,
            Ok(Some(_))
        ));
    }

    #[test]
    fn policies_ignored_when_list_empty() {
        let f = fixture();
        assert!(matches!(
            connect(&f, Some(&f.pki.client_other_policy)).server,
            Ok(Some(_))
        ));
    }

    #[test]
    fn negotiated_version_suite_and_alpn_in_allowed_set() {
        let f = fixture();
        let h = connect(&f, Some(&f.pki.client));
        assert_eq!(h.protocol, Some(TlsProtocol::Tls13));
        let suite = h.cipher_suite.unwrap();
        assert!(
            ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256"].contains(&suite.as_str()),
            "{suite}"
        );
        assert_eq!(h.alpn.as_deref(), Some(&b"http/1.1"[..]));
    }

    #[test]
    fn configs_are_fips() {
        let f = fixture();
        assert!(f.server.is_fips());
        let client = ClientTls::new(
            &f.pki
                .client_settings(Some(&f.pki.client), TlsMinVersion::Tls13)
                .unwrap(),
        )
        .unwrap();
        assert!(client.is_fips());
    }

    #[test]
    fn no_resumption_across_connections() {
        let f = fixture();
        let client = ClientTls::new(
            &f.pki
                .client_settings(Some(&f.pki.client), TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        for _ in 0..3 {
            let h = memory_handshake(&f.server, &client, "localhost").unwrap();
            assert!(matches!(h.server, Ok(Some(_))));
            assert!(!h.resumed);
        }
    }

    #[test]
    fn client_refuses_wrong_server_name() {
        let f = fixture();
        let client =
            ClientTls::new(&f.pki.client_settings(None, TlsMinVersion::Tls12).unwrap()).unwrap();
        let h = memory_handshake(&f.server, &client, "not-the-server.example").unwrap();
        assert!(h.client_error.is_some());
    }

    #[test]
    fn server_requires_at_least_one_crl() {
        let pki = TestPki::generate().unwrap();
        let settings = pki
            .server_settings(vec![], vec![], TlsMinVersion::Tls12)
            .unwrap();
        assert!(matches!(
            ServerTls::new(&settings),
            Err(CryptoError::TlsConfig { .. })
        ));
    }

    #[test]
    fn server_rejects_bad_policy_oid_and_bad_crl() {
        let pki = TestPki::generate().unwrap();
        let settings = pki
            .server_settings(
                pki.current_crls().unwrap(),
                vec!["x.y".into()],
                TlsMinVersion::Tls12,
            )
            .unwrap();
        assert!(matches!(
            ServerTls::new(&settings),
            Err(CryptoError::PolicyOid { index: 0 })
        ));
        let settings = pki
            .server_settings(vec![vec![0x30, 0x00]], vec![], TlsMinVersion::Tls12)
            .unwrap();
        assert!(ServerTls::new(&settings).is_err());
    }

    #[test]
    fn crls_accepted_as_pem_too() {
        let pki = TestPki::generate().unwrap();
        let pem_crls: Vec<Vec<u8>> = pki
            .current_crls()
            .unwrap()
            .iter()
            .map(|d| usgp_crypto::test_pki::crl_pem(d).unwrap().into_bytes())
            .collect();
        let server = ServerTls::new(
            &pki.server_settings(pem_crls, vec![], TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        let client = ClientTls::new(
            &pki.client_settings(Some(&pki.client_revoked), TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap();
        let h = memory_handshake(&server, &client, "localhost").unwrap();
        assert_eq!(refused_class(&h), TlsFailureClass::Revoked);
    }

    #[test]
    fn client_key_without_cert_is_a_config_error() {
        let pki = TestPki::generate().unwrap();
        let mut s = pki
            .client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap();
        s.client_cert_chain_pem = None;
        assert!(matches!(
            ClientTls::new(&s),
            Err(CryptoError::TlsConfig { .. })
        ));
    }

    #[test]
    fn failure_detail_has_no_key_material() {
        let f = fixture();
        let key_pem = f.pki.client_revoked.key_pem().unwrap();
        let body = std::str::from_utf8(&key_pem)
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .to_string();
        let h = connect(&f, Some(&f.pki.client_revoked));
        let text = format!("{:?}", h.server);
        assert!(!text.contains(&body));
        assert!(!text.contains("PRIVATE KEY"));
    }

    trait PkiExt {
        /// A current operator certificate with no certificatePolicies
        /// extension.
        fn client_without_policy(&self) -> TestCert;
    }

    impl PkiExt for TestPki {
        fn client_without_policy(&self) -> TestCert {
            self.intermediate
                .issue(&usgp_crypto::test_pki::LeafSpec {
                    policies: vec![],
                    ..usgp_crypto::test_pki::LeafSpec::client("operator no policy")
                })
                .unwrap()
        }
    }
}

/// The same outcomes over real async streams (`tokio::io::duplex`),
/// through `ServerTls::accept` and `ClientTls::connect`.
#[cfg(test)]
mod duplex {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use usgp_crypto::test_pki::{
        POLICY_ACCEPTED, TestCert, TestPki, client_tls_without_local_checks,
    };
    use usgp_crypto::tls::{
        ClientTls, ServerTls, TlsFailure, TlsFailureClass, TlsMinVersion, TlsProtocol,
    };
    use usgp_crypto::{PeerCertificate, sha256};

    fn server(pki: &TestPki, crls: Vec<Vec<u8>>, policies: Vec<String>) -> ServerTls {
        ServerTls::new(
            &pki.server_settings(crls, policies, TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap()
    }

    fn client(pki: &TestPki, cert: Option<&TestCert>) -> ClientTls {
        ClientTls::new(&pki.client_settings(cert, TlsMinVersion::Tls12).unwrap()).unwrap()
    }

    /// Handshake both sides; on success exchange one message each way.
    async fn run(
        server: &ServerTls,
        client: &ClientTls,
        name: &str,
    ) -> (Result<Option<PeerCertificate>, TlsFailure>, bool) {
        let (c_io, s_io) = duplex(64 * 1024);
        let (s, c) = tokio::join!(server.accept(s_io), client.connect(c_io, name));
        match (s, c) {
            (Ok((mut s, peer)), Ok(mut c)) => {
                assert_eq!(s.alpn(), Some(&b"http/1.1"[..]));
                assert_eq!(c.alpn(), Some(&b"http/1.1"[..]));
                assert!(!s.resumed() && !c.resumed());
                let suite = s.cipher_suite().unwrap();
                match s.protocol().unwrap() {
                    TlsProtocol::Tls13 => assert!(
                        ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256"].contains(&suite)
                    ),
                    TlsProtocol::Tls12 => assert!(suite.contains("_GCM_"), "{suite}"),
                }
                c.write_all(b"ping").await.unwrap();
                c.flush().await.unwrap();
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                s.write_all(b"pong").await.unwrap();
                s.flush().await.unwrap();
                c.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"pong");
                (Ok(peer), true)
            }
            (Ok((_, peer)), Err(_)) => (Ok(peer), false),
            (Err(e), c) => {
                // In TLS 1.3 the client may finish before the server
                // refuses; then its first read must fail.
                if let Ok(mut c) = c {
                    let mut buf = [0u8; 1];
                    assert!(c.read(&mut buf).await.map(|n| n == 0).unwrap_or(true));
                }
                (Err(e), false)
            }
        }
    }

    fn class(r: &Result<Option<PeerCertificate>, TlsFailure>) -> TlsFailureClass {
        match r {
            Err(e) => e.class,
            Ok(v) => panic!("expected refusal, got {v:?}"),
        }
    }

    #[tokio::test]
    async fn valid_certificate_identity_and_data() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let (r, ok) = run(&s, &client(&pki, Some(&pki.client)), "localhost").await;
        assert!(ok);
        let peer = r.unwrap().unwrap();
        assert_eq!(peer.sha256, sha256(pki.client.cert_der()));
    }

    #[tokio::test]
    async fn no_certificate_is_none_and_data_flows() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let (r, ok) = run(&s, &client(&pki, None), "localhost").await;
        assert!(ok);
        assert!(matches!(r, Ok(None)));
    }

    #[tokio::test]
    async fn negative_cases_refused_with_class() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let cases = [
            (&pki.client_untrusted, TlsFailureClass::Untrusted),
            (&pki.client_expired, TlsFailureClass::Expired),
            (&pki.client_revoked, TlsFailureClass::Revoked),
            (&pki.client_under_revoked, TlsFailureClass::Revoked),
            (&pki.client_server_eku, TlsFailureClass::BadEku),
            (&pki.client_no_eku, TlsFailureClass::BadEku),
        ];
        for (cert, want) in cases {
            let (r, ok) = run(&s, &client(&pki, Some(cert)), "localhost").await;
            assert!(!ok);
            assert_eq!(class(&r), want);
        }
        let c = client_tls_without_local_checks(&pki, &pki.client_critical_ext).unwrap();
        let (r, _) = run(&s, &c, "localhost").await;
        assert_eq!(class(&r), TlsFailureClass::UnknownCriticalExt);
    }

    #[tokio::test]
    async fn accept_with_presented_names_the_refused_certificate() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        for (cert, want) in [
            (&pki.client_revoked, TlsFailureClass::Revoked),
            (&pki.client_no_eku, TlsFailureClass::BadEku),
        ] {
            let c = client(&pki, Some(cert));
            let (c_io, s_io) = duplex(64 * 1024);
            let (r, _) = tokio::join!(s.accept_with_presented(s_io), c.connect(c_io, "localhost"));
            let Err(refused) = r else {
                panic!("expected refusal")
            };
            assert_eq!(refused.failure().class, want);
            assert_eq!(refused.presented_sha256(), Some(&sha256(cert.cert_der())));
            assert!(refused.chained_to_trust_anchor(), "issued by our PKI");
            let p = refused.presented().expect("parsed");
            assert_eq!(p.der, cert.cert_der());
            assert_eq!(refused.into_failure().class, want);
        }
        // No certificate: nothing presented, reaches HTTP as None.
        let c = client(&pki, None);
        let (c_io, s_io) = duplex(64 * 1024);
        let (r, _) = tokio::join!(s.accept_with_presented(s_io), c.connect(c_io, "localhost"));
        assert!(matches!(r, Ok((_, None))));
        // A protocol failure before any certificate: nothing presented.
        let (c_io, s_io) = duplex(1024);
        drop(c_io);
        let refused = s.accept_with_presented(s_io).await.unwrap_err();
        assert_eq!(refused.failure().class, TlsFailureClass::Protocol);
        assert!(refused.presented().is_none() && refused.presented_sha256().is_none());
        assert!(!refused.chained_to_trust_anchor());
        // A foreign issuer over the network path: not chained.
        let c = client(&pki, Some(&pki.client_untrusted));
        let (c_io, s_io) = duplex(64 * 1024);
        let (r, _) = tokio::join!(s.accept_with_presented(s_io), c.connect(c_io, "localhost"));
        let Err(refused) = r else {
            panic!("expected refusal")
        };
        assert_eq!(refused.failure().class, TlsFailureClass::Untrusted);
        assert!(refused.presented().is_some());
        assert!(!refused.chained_to_trust_anchor());
    }

    #[tokio::test]
    async fn stale_crl_refused() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.crls_with_stale_intermediate().unwrap(), vec![]);
        let (r, _) = run(&s, &client(&pki, Some(&pki.client)), "localhost").await;
        assert_eq!(class(&r), TlsFailureClass::CrlStale);
    }

    #[tokio::test]
    async fn policy_mismatch_refused() {
        let pki = TestPki::generate().unwrap();
        let s = server(
            &pki,
            pki.current_crls().unwrap(),
            vec![POLICY_ACCEPTED.to_string()],
        );
        let (r, _) = run(
            &s,
            &client(&pki, Some(&pki.client_other_policy)),
            "localhost",
        )
        .await;
        assert_eq!(class(&r), TlsFailureClass::Policy);
        let (r, ok) = run(&s, &client(&pki, Some(&pki.client)), "localhost").await;
        assert!(ok && matches!(r, Ok(Some(_))));
    }

    #[tokio::test]
    async fn tls13_only_server_and_client() {
        let pki = TestPki::generate().unwrap();
        let s = ServerTls::new(
            &pki.server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls13)
                .unwrap(),
        )
        .unwrap();
        let c = ClientTls::new(
            &pki.client_settings(Some(&pki.client), TlsMinVersion::Tls13)
                .unwrap(),
        )
        .unwrap();
        let (c_io, s_io) = duplex(64 * 1024);
        let (s, c) = tokio::join!(s.accept(s_io), c.connect(c_io, "localhost"));
        let (s, _) = s.unwrap();
        assert_eq!(s.protocol(), Some(TlsProtocol::Tls13));
        assert_eq!(c.unwrap().protocol(), Some(TlsProtocol::Tls13));
    }

    #[tokio::test]
    async fn client_refuses_wrong_name_and_bad_name() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let c = client(&pki, None);
        let (c_io, s_io) = duplex(64 * 1024);
        let (_, r) = tokio::join!(s.accept(s_io), c.connect(c_io, "other.example"));
        assert_eq!(r.unwrap_err().class, TlsFailureClass::BadCertificate);
        let (c_io, _s_io) = duplex(1024);
        let r = c.connect(c_io, "not a name!").await;
        assert_eq!(r.unwrap_err().class, TlsFailureClass::Protocol);
    }

    #[tokio::test]
    async fn peer_closing_mid_handshake_is_protocol() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let (c_io, s_io) = duplex(1024);
        drop(c_io);
        let err = s.accept(s_io).await.unwrap_err();
        assert_eq!(err.class, TlsFailureClass::Protocol);
    }

    #[tokio::test]
    async fn garbage_client_hello_is_refused_not_panic() {
        let pki = TestPki::generate().unwrap();
        let s = server(&pki, pki.current_crls().unwrap(), vec![]);
        let (mut c_io, s_io) = duplex(1024);
        c_io.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let err = s.accept(s_io).await.unwrap_err();
        assert_eq!(err.class, TlsFailureClass::Protocol);
    }
}
