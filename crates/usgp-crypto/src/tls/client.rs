//! TLS client configuration (operator CLI to the API; server to PostgreSQL).
//!
//! The server certificate is validated against the configured trust
//! anchors and the server name is verified (verify-full). A client
//! certificate is presented when configured. Resumption is off, matching
//! the server side.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) - TLS on the CLI and database channels.
// - NIST 800-53: IA-5(2) (Public Key-Based Authentication) - server
//   identity verified by its chain to the configured anchors and by name
//   (with SC-8 above); client certificate for database login (0012).
// - NIST 800-53: SC-13 - `ClientConfig::fips()` asserted at build time.
// - SPEC: plan M2 section 5.4 ("PostgreSQL client TLS"), section 3.5.
// POAM: the server certificate's revocation is not checked by clients
// (no CRL input on the client side in M2).

use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::Resumption;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

use tokio::io::{AsyncRead, AsyncWrite};

use super::settings::{ClientAlpn, ClientTlsSettings};
use super::stream::ClientTlsStream;
use super::{ALPN_HTTP11, config_err, protocol_versions, root_store};
use super::{TlsFailure, TlsFailureClass};
use crate::CryptoError;
use crate::pem;

/// A built TLS client configuration.
#[derive(Clone)]
pub struct ClientTls {
    config: Arc<ClientConfig>,
}

impl std::fmt::Debug for ClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTls")
            .field("fips", &self.config.fips())
            .field(
                "client_auth",
                &self.config.client_auth_cert_resolver.has_certs(),
            )
            .finish_non_exhaustive()
    }
}

impl ClientTls {
    /// Builds the client configuration.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::FipsModeInactive`] if FIPS mode is off or the
    ///   built configuration does not report `fips()`;
    /// - [`CryptoError::Pem`] / [`CryptoError::InputTooLarge`] for bad
    ///   inputs;
    /// - [`CryptoError::TlsConfig`] if only one of certificate and key is
    ///   set, or the key does not match the certificate.
    pub fn new(settings: &ClientTlsSettings) -> Result<Self, CryptoError> {
        let provider = super::tls_provider()?;
        let roots = root_store(&settings.trust_anchors_pem, "server trust anchors")?;
        let builder = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(protocol_versions(settings.min_version))
            .map_err(config_err)?
            .with_root_certificates(roots);
        let mut config = match (&settings.client_cert_chain_pem, &settings.client_key_pem) {
            (Some(chain_pem), Some(key_pem)) => {
                let chain = pem::certificates(chain_pem, "client certificate chain")?;
                let mut key_der =
                    pem::decode_secret(key_pem, pem::LABEL_PRIVATE_KEY, "client private key")?;
                // rustls wraps the key in its own zeroizing buffer.
                let key =
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(std::mem::take(&mut *key_der)));
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(config_err)?
            }
            (None, None) => builder.with_no_client_auth(),
            _ => {
                return Err(CryptoError::TlsConfig {
                    reason: "client certificate and key must be set together".to_string(),
                });
            }
        };
        config.resumption = Resumption::disabled();
        config.enable_early_data = false;
        config.alpn_protocols = match settings.alpn {
            ClientAlpn::Http11 => vec![ALPN_HTTP11.to_vec()],
            ClientAlpn::None => Vec::new(),
        };
        if !config.fips() {
            return Err(CryptoError::FipsModeInactive {
                component: "tls client config",
            });
        }
        Ok(Self {
            config: Arc::new(config),
        })
    }

    /// True if the built configuration uses only FIPS-approved
    /// algorithms from the validated module.
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.config.fips()
    }

    /// Checks that `name` is usable as a server name (DNS name or IP
    /// address literal).
    ///
    /// # Errors
    ///
    /// [`CryptoError::TlsConfig`] if it is not.
    pub fn check_server_name(name: &str) -> Result<(), CryptoError> {
        Self::server_name(name).map(|_| ())
    }

    /// Runs the TLS handshake on `io` to `server_name` (DNS name or IP
    /// literal), verifying the server certificate and name.
    ///
    /// The caller applies the connect timeout.
    ///
    /// # Errors
    ///
    /// [`TlsFailure`] if the name is invalid (class `protocol`) or the
    /// handshake fails (for example `untrusted` for an unknown server CA,
    /// `bad_certificate` for a name mismatch).
    pub async fn connect<IO>(
        &self,
        io: IO,
        server_name: &str,
    ) -> Result<ClientTlsStream<IO>, TlsFailure>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let name = Self::server_name(server_name).map_err(|e| TlsFailure {
            class: TlsFailureClass::Protocol,
            detail: e.to_string(),
        })?;
        let connector = tokio_rustls::TlsConnector::from(self.config());
        let stream = connector
            .connect(name, io)
            .await
            .map_err(|e| TlsFailure::from_io(&e))?;
        Ok(ClientTlsStream::new(stream))
    }

    pub(crate) fn server_name(name: &str) -> Result<ServerName<'static>, CryptoError> {
        ServerName::try_from(name.to_string()).map_err(|_| CryptoError::TlsConfig {
            reason: "server name is not a valid DNS name or IP address".to_string(),
        })
    }

    pub(crate) fn config(&self) -> Arc<ClientConfig> {
        Arc::clone(&self.config)
    }

    /// Wraps an already-built configuration (test PKI only).
    #[cfg(feature = "test-pki")]
    pub(crate) fn from_config(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}
