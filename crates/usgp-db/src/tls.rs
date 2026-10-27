//! tokio-postgres TLS hook over the `usgp-crypto` client connector
//! (decisions 0001, 0008, 0012; plan sections 5.4 and 5.5).
//!
//! - Every connection is TLS: [`PgTls`] always performs the handshake and
//!   never hands back a plaintext stream, and the driver configuration
//!   requires TLS ([`crate::config::pg_config`]), so `sslmode` is in effect
//!   verify-full.
//! - The server name verified is the configured one
//!   ([`crate::config::DbSettings::tls_server_name`]), not whatever host
//!   string the driver passes.
//! - The client presents its certificate; no ALPN is offered (PostgreSQL
//!   negotiates TLS in-band after the SSLRequest).
//! - [`TlsStream::channel_binding`] returns none: no password is used, so
//!   SCRAM channel binding has nothing to protect (plan section 5.5).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and
//   Integrity) - TLS 1.2/1.3 with the FIPS provider to the database.
// - NIST 800-53: SC-13 (Cryptographic Protection) - all TLS through
//   `usgp-crypto` (decision 0001).
// - NIST 800-53: IA-5(2) - client certificate login.
// - RFC 8446, RFC 5246 (via usgp-crypto)

// POAM: the database server certificate is not checked for revocation
// (usgp-crypto clients take no CRL input in M2; see tls/client.rs).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};
use usgp_crypto::tls::{
    ClientAlpn, ClientTls, ClientTlsSettings, ClientTlsStream, TlsFailure, TlsFailureClass,
};
use zeroize::Zeroizing;

use crate::config::DbSettings;
use crate::error::DbError;

/// A TLS handshake failure in the hook. Carries the `usgp-crypto` class
/// and its public detail (certificates and protocol state, never keys).
#[derive(Debug, Clone, thiserror::Error)]
#[error("database TLS handshake failed: {}", .0.class.as_str())]
pub struct TlsHookError(TlsFailure);

impl TlsHookError {
    /// The failure class.
    #[must_use]
    pub const fn class(&self) -> TlsFailureClass {
        self.0.class
    }
}

/// The `MakeTlsConnect` implementation handed to tokio-postgres and the
/// pool. Cheap to clone.
#[derive(Clone)]
pub struct PgTls {
    tls: Arc<ClientTls>,
    server_name: Arc<str>,
}

impl std::fmt::Debug for PgTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTls")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl PgTls {
    /// Builds the connector from the settings: trust anchors =
    /// `server_ca_pem`, client certificate and key, no ALPN.
    ///
    /// # Errors
    ///
    /// [`DbError::Connect`] with class `bad_certificate` if `usgp-crypto`
    /// refuses the inputs (unparsable PEM, unsupported key, FIPS not
    /// active).
    pub fn new(s: &DbSettings) -> Result<Self, DbError> {
        let settings = ClientTlsSettings {
            trust_anchors_pem: s.server_ca_pem.clone(),
            client_cert_chain_pem: Some(s.client_cert_pem.clone()),
            client_key_pem: Some(Zeroizing::new(s.client_key_pem.to_vec())),
            min_version: s.min_tls,
            alpn: ClientAlpn::None,
        };
        let tls = ClientTls::new(&settings).map_err(|e| DbError::Connect {
            class: crate::error::ConnectFailure::Tls(TlsFailureClass::BadCertificate),
            source: Some(Box::new(e)),
        })?;
        Self::from_client(tls, s.tls_server_name())
    }

    /// Wraps an existing connector (tests build one from test PKI).
    ///
    /// # Errors
    ///
    /// [`DbError::Connect`] with class `protocol` for an invalid server
    /// name.
    pub fn from_client(tls: ClientTls, server_name: &str) -> Result<Self, DbError> {
        ClientTls::check_server_name(server_name).map_err(|e| DbError::Connect {
            class: crate::error::ConnectFailure::Tls(TlsFailureClass::Protocol),
            source: Some(Box::new(e)),
        })?;
        Ok(Self {
            tls: Arc::new(tls),
            server_name: Arc::from(server_name),
        })
    }

    /// True if the underlying client configuration runs on the FIPS
    /// provider.
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.tls.is_fips()
    }
}

impl<S> MakeTlsConnect<S> for PgTls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PgTlsStream<S>;
    type TlsConnect = PgTlsConnect;
    type Error = TlsHookError;

    fn make_tls_connect(&mut self, _domain: &str) -> Result<PgTlsConnect, TlsHookError> {
        // The configured name is verified, never the driver's host string.
        Ok(PgTlsConnect {
            tls: Arc::clone(&self.tls),
            server_name: Arc::clone(&self.server_name),
        })
    }
}

/// One pending handshake.
#[derive(Clone)]
pub struct PgTlsConnect {
    tls: Arc<ClientTls>,
    server_name: Arc<str>,
}

impl std::fmt::Debug for PgTlsConnect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgTlsConnect")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

/// The handshake future.
pub type PgTlsFuture<S> =
    Pin<Box<dyn Future<Output = Result<PgTlsStream<S>, TlsHookError>> + Send>>;

impl<S> TlsConnect<S> for PgTlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PgTlsStream<S>;
    type Error = TlsHookError;
    type Future = PgTlsFuture<S>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let s = self
                .tls
                .connect(stream, &self.server_name)
                .await
                .map_err(TlsHookError)?;
            Ok(PgTlsStream(s))
        })
    }
}

/// An established TLS session to the database.
#[derive(Debug)]
pub struct PgTlsStream<S>(ClientTlsStream<S>);

impl<S> PgTlsStream<S> {
    /// The negotiated session (protocol, cipher suite, ALPN).
    #[must_use]
    pub const fn session(&self) -> &ClientTlsStream<S> {
        &self.0
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for PgTlsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for PgTlsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for PgTlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        // No password is ever used (decision 0012), so there is no SCRAM
        // exchange to bind to the channel.
        ChannelBinding::none()
    }
}
