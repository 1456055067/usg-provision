//! Unit tests that need raw rustls clients (version pinning, resumption).
//! The operator-facing outcomes are tested in `tests/tls_mtls.rs`.

use std::sync::Arc;

use rustls::client::Resumption;
use rustls::{CipherSuite, ClientConfig, HandshakeKind, RootCertStore};

use super::memory::handshake;
use super::*;
use crate::test_pki::TestPki;

fn pki() -> TestPki {
    TestPki::generate().unwrap()
}

fn server(pki: &TestPki, min: TlsMinVersion) -> ServerTls {
    ServerTls::new(
        &pki.server_settings(pki.current_crls().unwrap(), vec![], min)
            .unwrap(),
    )
    .unwrap()
}

/// A raw client on our restricted provider with chosen versions, client
/// certificate `pki.client`, and resumption as given.
fn raw_client(
    pki: &TestPki,
    versions: &[&'static SupportedProtocolVersion],
    resumption: bool,
) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for c in crate::pem::certificates(pki.root.cert_pem().unwrap().as_bytes(), "root").unwrap() {
        roots.add(c).unwrap();
    }
    let chain = crate::pem::certificates(&pki.client.chain_pem(), "chain").unwrap();
    let key_der = crate::pem::decode_secret(
        &pki.client.key_pem().unwrap(),
        crate::pem::LABEL_PRIVATE_KEY,
        "key",
    )
    .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.to_vec().into());
    let mut cfg = ClientConfig::builder_with_provider(tls_provider().unwrap())
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(chain, key)
        .unwrap();
    if !resumption {
        cfg.resumption = Resumption::disabled();
    }
    cfg.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
    Arc::new(cfg)
}

fn name() -> rustls::pki_types::ServerName<'static> {
    ClientTls::server_name("localhost").unwrap()
}

const ALLOWED_TLS13: &[CipherSuite] = &[
    CipherSuite::TLS13_AES_256_GCM_SHA384,
    CipherSuite::TLS13_AES_128_GCM_SHA256,
];
const ALLOWED_TLS12: &[CipherSuite] = &[
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
];

#[test]
fn tls13_negotiated_with_allowed_suite() {
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls12);
    let out = handshake(
        &s,
        raw_client(&pki, &[&rustls::version::TLS13], false),
        name(),
    )
    .unwrap();
    assert!(out.server.as_ref().unwrap().is_some());
    assert_eq!(out.protocol, Some(TlsProtocol::Tls13));
    assert!(ALLOWED_TLS13.contains(&out.cipher_suite.unwrap()));
    assert_eq!(out.alpn.as_deref(), Some(ALPN_HTTP11));
}

#[test]
fn tls12_negotiated_with_allowed_suite_when_min_is_12() {
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls12);
    let out = handshake(
        &s,
        raw_client(&pki, &[&rustls::version::TLS12], false),
        name(),
    )
    .unwrap();
    let peer = out.server.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(peer.sha256, crate::sha256(pki.client.cert_der()));
    assert_eq!(out.protocol, Some(TlsProtocol::Tls12));
    assert!(ALLOWED_TLS12.contains(&out.cipher_suite.unwrap()));
}

#[test]
fn tls12_client_refused_when_min_is_13() {
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls13);
    let out = handshake(
        &s,
        raw_client(&pki, &[&rustls::version::TLS12], false),
        name(),
    )
    .unwrap();
    let err = out.server.unwrap_err();
    assert_eq!(err.class, TlsFailureClass::Protocol);
}

#[test]
fn server_never_resumes_even_if_client_offers() {
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls12);
    for versions in [
        &[&rustls::version::TLS13][..],
        &[&rustls::version::TLS12][..],
    ] {
        let client = raw_client(&pki, versions, true);
        for _ in 0..3 {
            let out = handshake(&s, Arc::clone(&client), name()).unwrap();
            assert!(out.server.is_ok());
            assert!(matches!(
                out.server_kind,
                Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
            ));
            assert!(!matches!(out.client_kind, Some(HandshakeKind::Resumed)));
        }
    }
}

#[test]
fn built_configs_are_fips_and_ticketless() {
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls12);
    assert!(s.is_fips());
    let cfg = s.config();
    assert!(cfg.fips());
    assert_eq!(cfg.send_tls13_tickets, 0);
    assert_eq!(cfg.max_early_data_size, 0);
    assert!(!cfg.ticketer.enabled());
    assert_eq!(cfg.alpn_protocols, vec![ALPN_HTTP11.to_vec()]);
    // Per-connection configurations (presented-certificate capture) keep
    // every setting.
    let slot = Arc::new(super::server::PresentedSlot::default());
    let conn = s.connection_config(&slot).unwrap();
    assert!(conn.fips());
    assert_eq!(conn.send_tls13_tickets, 0);
    assert_eq!(conn.max_early_data_size, 0);
    assert!(!conn.ticketer.enabled());
    assert_eq!(conn.alpn_protocols, vec![ALPN_HTTP11.to_vec()]);
    let c = ClientTls::new(
        &pki.client_settings(Some(&pki.client), TlsMinVersion::Tls12)
            .unwrap(),
    )
    .unwrap();
    assert!(c.is_fips());
    assert!(c.config().fips());
}

#[test]
fn unknown_critical_extension_text_mapping_is_pinned() {
    // If webpki changes how it reports this error, the class mapping in
    // `classify` must be updated; this test fails first.
    let pki = pki();
    let s = server(&pki, TlsMinVersion::Tls12);
    // rustls refuses to load such a certificate on the client side.
    let settings = pki
        .client_settings(Some(&pki.client_critical_ext), TlsMinVersion::Tls12)
        .unwrap();
    assert!(ClientTls::new(&settings).is_err());
    let c =
        crate::test_pki::client_tls_without_local_checks(&pki, &pki.client_critical_ext).unwrap();
    let out = handshake(&s, c.config(), name()).unwrap();
    assert_eq!(
        out.server.unwrap_err().class,
        TlsFailureClass::UnknownCriticalExt
    );
}

#[test]
fn classify_maps_rustls_errors() {
    let e = rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked);
    assert_eq!(classify(&e), TlsFailureClass::Revoked);
    let e = rustls::Error::General("x".into());
    assert_eq!(classify(&e), TlsFailureClass::Protocol);
}
