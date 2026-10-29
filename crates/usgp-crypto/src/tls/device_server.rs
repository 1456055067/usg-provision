//! TLS server configuration for the device listener: server
//! authentication only.
//!
//! Devices in the pre-installation environment carry no secret and no
//! certificate (decision 0020). The device listener therefore never sends
//! a CertificateRequest; the device session is authorised later by an
//! operator-issued code or by operator approval (decision 0018 item 1),
//! not by TLS.
//!
//! This is a separate type from the operator listener's
//! [`super::ServerTls`] on purpose. It takes its own settings type with
//! no client-anchor or CRL field, and nothing here can switch operator
//! mTLS off. A [`DeviceServerTls`] never yields an operator identity.
//!
//! Everything else matches the operator listener (plan M3 section 5,
//! "Device listener TLS"): the same restricted FIPS provider, protocol
//! versions, suites and groups; no session tickets, no stateful
//! resumption, no 0-RTT; ALPN `http/1.1`; `ServerConfig::fips()` asserted
//! at build time.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and
//   Integrity) - device traffic only inside TLS 1.2/1.3 with AEAD suites.
// - NIST 800-53: SC-8, SC-23 (Session Authenticity), IA-11
//   (Re-authentication) - the server authenticates to the device by
//   certificate, and the device's session token (and the authorisation
//   it carries) travels only inside this TLS. The device is not
//   authenticated by TLS: no client certificate is asked for (decision
//   0020 items 2-3). No IA-2 or IA-3 claim here; IA-3 is partial
//   server-side (POAM: IA-3 (TB-2), usgp-api `device/auth.rs`).
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS provider;
//   `ServerConfig::fips()` asserted; fail closed.
// - NIST 800-53: SC-23 (Session Authenticity) - no resumption; every
//   connection is a full handshake.
// - NIST 800-53: SC-12 - the private key is decoded into a zeroized
//   buffer and handed to the module.
// - SPEC: specs/preinstall-env.md#REQ-PE-015;
//   specs/targeting.md#REQ-TGT-012; plan M3 section 3.1 ("Transport"),
//   section 5; decisions 0001, 0018 item 1, 0020.
// - RFC 8446 §4.3.2 (no CertificateRequest sent); RFC 5246 §7.4.4.

use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::NoServerSessionStorage;
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use tokio::io::{AsyncRead, AsyncWrite};

use super::settings::DeviceServerTlsSettings;
use super::stream::ServerTlsStream;
use super::{ALPN_HTTP11, TlsFailure, config_err, protocol_versions};
use crate::CryptoError;
use crate::pem;

/// A built device-listener TLS configuration (server authentication only;
/// no client certificate is ever requested).
#[derive(Clone)]
pub struct DeviceServerTls {
    config: Arc<ServerConfig>,
}

impl std::fmt::Debug for DeviceServerTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceServerTls")
            .field("fips", &self.config.fips())
            .finish_non_exhaustive()
    }
}

impl DeviceServerTls {
    /// Builds the device-listener configuration.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::FipsModeInactive`] if FIPS mode is off or the
    ///   built configuration does not report `fips()`;
    /// - [`CryptoError::Pem`] / [`CryptoError::InputTooLarge`] for bad
    ///   inputs;
    /// - [`CryptoError::TlsConfig`] if the key does not match the
    ///   certificate.
    pub fn new(settings: &DeviceServerTlsSettings) -> Result<Self, CryptoError> {
        let provider = super::tls_provider()?;
        let chain = pem::certificates(&settings.cert_chain_pem, "server certificate chain")?;
        let mut key_der = pem::decode_secret(
            &settings.private_key_pem,
            pem::LABEL_PRIVATE_KEY,
            "server private key",
        )?;
        // rustls wraps the key in its own zeroizing buffer when loading it.
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key_der)));
        drop(key_der);
        // Loads the key in the FIPS module and checks it matches the
        // certificate.
        let certified =
            Arc::new(CertifiedKey::from_der(chain, key, &provider).map_err(config_err)?);
        let mut config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(protocol_versions(settings.min_version))
            .map_err(config_err)?
            // Decision 0020: devices hold no certificate; never ask.
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
        config.session_storage = Arc::new(NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        config.max_early_data_size = 0;
        config.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        if !config.fips() {
            return Err(CryptoError::FipsModeInactive {
                component: "tls device server config",
            });
        }
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// True if the built configuration uses only FIPS-approved algorithms
    /// from the validated module (always true for a value that
    /// [`Self::new`] returned).
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.config.fips()
    }

    /// Runs the TLS handshake on `io`. The caller applies the handshake
    /// timeout. There is no peer identity: the device is authorised by
    /// the session protocol, never by TLS.
    ///
    /// # Errors
    ///
    /// [`TlsFailure`] if the handshake fails.
    pub async fn accept<IO>(&self, io: IO) -> Result<ServerTlsStream<IO>, TlsFailure>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.config));
        let stream = acceptor
            .accept(io)
            .await
            .map_err(|e| TlsFailure::from_io(&e))?;
        Ok(ServerTlsStream::new(stream))
    }
}

#[cfg(test)]
#[cfg(feature = "test-pki")]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustls::client::ResolvesClientCert;
    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, Connection, ServerConnection, SignatureScheme};

    use super::*;
    use crate::test_pki::TestPki;
    use crate::tls::{ClientTls, ServerTls, TlsMinVersion};

    fn device(pki: &TestPki, min: TlsMinVersion) -> DeviceServerTls {
        DeviceServerTls::new(&DeviceServerTlsSettings {
            cert_chain_pem: pki.server.chain_pem(),
            private_key_pem: pki.server.key_pem().unwrap(),
            min_version: min,
        })
        .unwrap()
    }

    fn operator(pki: &TestPki) -> ServerTls {
        ServerTls::new(
            &pki.server_settings(pki.current_crls().unwrap(), vec![], TlsMinVersion::Tls12)
                .unwrap(),
        )
        .unwrap()
    }

    /// Records whether the server asked for a client certificate
    /// (rustls calls `resolve` only on a CertificateRequest). Presents
    /// nothing.
    #[derive(Debug, Default)]
    struct AskedProbe(AtomicBool);

    impl ResolvesClientCert for AskedProbe {
        fn resolve(
            &self,
            _hints: &[&[u8]],
            _schemes: &[SignatureScheme],
        ) -> Option<Arc<CertifiedKey>> {
            self.0.store(true, Ordering::SeqCst);
            None
        }

        fn has_certs(&self) -> bool {
            true
        }
    }

    /// Moves pending records from `from` to `to`; true if any moved.
    fn pump(from: &mut Connection, to: &mut Connection) -> bool {
        let mut buf = Vec::new();
        while from.wants_write() {
            if from.write_tls(&mut buf).unwrap() == 0 {
                break;
            }
        }
        let mut rd = buf.as_slice();
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets().unwrap();
        }
        !buf.is_empty()
    }

    /// Runs both sides until neither has anything to send.
    fn run(server: &mut Connection, client: &mut Connection) {
        for _ in 0..64 {
            let a = pump(client, server);
            let b = pump(server, client);
            if !a && !b {
                break;
            }
        }
    }

    /// Handshakes `server_config` with a probing client; returns whether
    /// a certificate was requested and whether the handshake finished.
    fn asked_for_certificate(pki: &TestPki, server_config: Arc<ServerConfig>) -> (bool, bool) {
        let probe = Arc::new(AskedProbe::default());
        let base = ClientTls::new(&pki.client_settings(None, TlsMinVersion::Tls12).unwrap())
            .unwrap()
            .config();
        let mut roots = rustls::RootCertStore::empty();
        for c in pem::certificates(pki.root.cert_pem().unwrap().as_bytes(), "root").unwrap() {
            roots.add(c).unwrap();
        }
        let mut cfg = ClientConfig::builder_with_provider(Arc::clone(base.crypto_provider()))
            .with_protocol_versions(protocol_versions(TlsMinVersion::Tls12))
            .unwrap()
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::clone(&probe) as Arc<dyn ResolvesClientCert>);
        cfg.alpn_protocols = vec![ALPN_HTTP11.to_vec()];
        let name = ServerName::try_from("localhost").unwrap();
        let mut client = Connection::Client(ClientConnection::new(Arc::new(cfg), name).unwrap());
        let mut server = Connection::Server(ServerConnection::new(server_config).unwrap());
        run(&mut server, &mut client);
        let done = !server.is_handshaking() && !client.is_handshaking();
        (probe.0.load(Ordering::SeqCst), done)
    }

    #[test]
    fn device_listener_never_requests_a_client_certificate() {
        let pki = TestPki::generate().unwrap();
        let d = device(&pki, TlsMinVersion::Tls12);
        let (asked, done) = asked_for_certificate(&pki, Arc::clone(&d.config));
        assert!(!asked, "device listener sent a CertificateRequest");
        assert!(done);
    }

    #[test]
    fn operator_listener_still_requests_a_client_certificate() {
        let pki = TestPki::generate().unwrap();
        let (asked, _) = asked_for_certificate(&pki, operator(&pki).config());
        assert!(asked, "operator listener must send a CertificateRequest");
    }

    #[test]
    fn same_hardening_as_operator_listener() {
        let pki = TestPki::generate().unwrap();
        let d = device(&pki, TlsMinVersion::Tls12);
        let op = operator(&pki);
        let (dc, oc) = (&d.config, op.config());
        assert!(dc.fips());
        assert!(d.is_fips());
        assert_eq!(dc.send_tls13_tickets, 0);
        assert_eq!(dc.max_early_data_size, 0);
        assert!(!dc.session_storage.can_cache());
        assert_eq!(dc.alpn_protocols, oc.alpn_protocols);
        let names = |c: &ServerConfig| -> Vec<_> {
            c.crypto_provider()
                .cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect()
        };
        assert_eq!(names(dc), names(&oc));
        let groups = |c: &ServerConfig| -> Vec<_> {
            c.crypto_provider()
                .kx_groups
                .iter()
                .map(|g| g.name())
                .collect()
        };
        assert_eq!(groups(dc), groups(&oc));
    }
}
