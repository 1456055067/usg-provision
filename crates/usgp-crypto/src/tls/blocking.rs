//! Blocking TLS client for the pre-boot agent.
//!
//! The agent in the pre-installation environment is a plain `std::io`
//! program with no async runtime (plan M3 WU-1, section 5 "Agent TLS
//! client"). [`BlockingClientTls`] builds the same FIPS client
//! configuration as [`ClientTls`] and runs the handshake on any blocking
//! `Read + Write` transport, normally a [`std::net::TcpStream`]. No rustls
//! type appears in the public API.
//!
//! Rules (decision 0020; REQ-PE-015):
//!
//! - the server certificate must chain to the trust anchors in the
//!   settings, and only those (no operating-system store);
//! - the server name is verified (DNS name or IP literal);
//! - the configuration and every connection assert `fips()`; fail closed;
//! - the handshake completes inside [`BlockingClientTls::connect`], so a
//!   refused server is an error before any application byte is sent;
//! - a peer that closes without `close_notify` is reported as an error on
//!   read (truncation is never mistaken for end of data).
//!
//! Timeouts are the caller's: set them on the socket
//! (`TcpStream::set_read_timeout`, `set_write_timeout`) before calling
//! [`BlockingClientTls::connect`]. A timeout during the handshake is a
//! [`TlsFailureClass::Protocol`] failure.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) (Transmission Confidentiality and
//   Integrity) - every byte between the agent and the server is inside
//   TLS 1.2/1.3 with AEAD suites.
// - NIST 800-53: IA-3 (Device Identification and Authentication) - the
//   server is authenticated by its certificate chain to the configured
//   anchors and by name.
// - NIST 800-53: SC-13 (Cryptographic Protection) - FIPS provider;
//   `ClientConfig::fips()` asserted at build time and per connection.
// - NIST 800-53: SC-23 (Session Authenticity) - no resumption; every
//   connection is a full handshake.
// - SPEC: specs/preinstall-env.md#REQ-PE-015;
//   specs/targeting.md#REQ-TGT-012; plan M3 section 5 ("Agent TLS
//   client"), WU-1; decisions 0001, 0011, 0018, 0020.
// - RFC 8446 (TLS 1.3); RFC 5246 (TLS 1.2); RFC 6125 §6 (server name
//   check, through the TLS stack).
// POAM: the server certificate's revocation is not checked by the agent
// (no CRL input on the device; same gap as the M2 client in client.rs).

use std::io::{self, Read, Write};
use std::net::TcpStream;

use rustls::{ClientConnection, StreamOwned};

use super::settings::ClientTlsSettings;
use super::{ClientTls, TlsFailure, TlsFailureClass, TlsProtocol};
use crate::CryptoError;

/// Most `complete_io` rounds a handshake may take. A TLS 1.2 or 1.3 full
/// handshake needs a handful; the bound stops a peer that keeps a
/// handshake alive forever with tiny records.
const MAX_HANDSHAKE_ROUNDS: usize = 256;

/// A built blocking TLS client configuration.
#[derive(Clone)]
pub struct BlockingClientTls {
    inner: ClientTls,
}

impl std::fmt::Debug for BlockingClientTls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingClientTls")
            .field("inner", &self.inner)
            .finish()
    }
}

impl BlockingClientTls {
    /// Builds the client configuration (see [`ClientTls::new`]).
    ///
    /// # Errors
    ///
    /// As [`ClientTls::new`]: [`CryptoError::FipsModeInactive`],
    /// [`CryptoError::Pem`], [`CryptoError::InputTooLarge`] or
    /// [`CryptoError::TlsConfig`].
    pub fn new(settings: &ClientTlsSettings) -> Result<Self, CryptoError> {
        let inner = ClientTls::new(settings)?;
        if !inner.is_fips() {
            return Err(CryptoError::FipsModeInactive {
                component: "tls client config",
            });
        }
        Ok(Self { inner })
    }

    /// True if the built configuration uses only FIPS-approved algorithms
    /// from the validated module.
    #[must_use]
    pub fn is_fips(&self) -> bool {
        self.inner.is_fips()
    }

    /// Runs the TLS handshake on `io` to `server_name` (DNS name or IP
    /// literal) and returns the established stream.
    ///
    /// # Errors
    ///
    /// [`TlsFailure`]:
    ///
    /// - class `protocol` for an invalid server name, a configuration that
    ///   is not FIPS, a transport error or timeout, or a peer that closes
    ///   during the handshake;
    /// - `untrusted` if the server does not chain to the anchors;
    /// - `bad_certificate` for a name mismatch;
    /// - `expired` or `not_yet_valid` for certificate time errors (see
    ///   [`TlsFailureClass::is_time_related`]).
    pub fn connect<IO>(
        &self,
        mut io: IO,
        server_name: &str,
    ) -> Result<BlockingClientStream<IO>, TlsFailure>
    where
        IO: Read + Write,
    {
        let protocol = |detail: String| TlsFailure {
            class: TlsFailureClass::Protocol,
            detail,
        };
        let name = ClientTls::server_name(server_name).map_err(|e| protocol(e.to_string()))?;
        let config = self.inner.config();
        if !config.fips() {
            return Err(protocol(
                CryptoError::FipsModeInactive {
                    component: "tls client config",
                }
                .to_string(),
            ));
        }
        let mut conn =
            ClientConnection::new(config, name).map_err(|e| TlsFailure::from_rustls(&e))?;
        drive_handshake(&mut conn, &mut io)?;
        Ok(BlockingClientStream(StreamOwned::new(conn, io)))
    }
}

/// Runs `complete_io` until the handshake is done, failing closed on a
/// peer that stops making progress.
fn drive_handshake<IO: Read + Write>(
    conn: &mut ClientConnection,
    io: &mut IO,
) -> Result<(), TlsFailure> {
    let protocol = |detail: &str| TlsFailure {
        class: TlsFailureClass::Protocol,
        detail: detail.to_string(),
    };
    for _ in 0..MAX_HANDSHAKE_ROUNDS {
        if !conn.is_handshaking() {
            return Ok(());
        }
        let (read, written) = conn.complete_io(io).map_err(|e| TlsFailure::from_io(&e))?;
        if read == 0 && written == 0 && conn.is_handshaking() {
            return Err(protocol("connection closed during handshake"));
        }
    }
    if conn.is_handshaking() {
        return Err(protocol("handshake did not complete"));
    }
    Ok(())
}

/// The client side of an established blocking TLS connection.
///
/// Implements [`Read`] and [`Write`]; all bytes pass through TLS. `Debug`
/// shows only the negotiated parameters.
pub struct BlockingClientStream<IO: Read + Write = TcpStream>(StreamOwned<ClientConnection, IO>);

impl<IO: Read + Write> BlockingClientStream<IO> {
    /// The underlying transport, read-only (for example, to set socket
    /// timeouts or read the peer address). Writing to it directly would
    /// bypass TLS, so no mutable access is offered.
    pub fn io(&self) -> &IO {
        self.0.get_ref()
    }

    /// Negotiated protocol version.
    pub fn protocol(&self) -> Option<TlsProtocol> {
        self.0
            .conn
            .protocol_version()
            .and_then(TlsProtocol::from_rustls)
    }

    /// Negotiated cipher suite (IANA name).
    pub fn cipher_suite(&self) -> Option<&'static str> {
        self.0
            .conn
            .negotiated_cipher_suite()
            .and_then(|s| s.suite().as_str())
    }

    /// Negotiated ALPN protocol id.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.0.conn.alpn_protocol()
    }

    /// True if the handshake resumed an earlier session (never expected:
    /// resumption is disabled).
    pub fn resumed(&self) -> bool {
        matches!(
            self.0.conn.handshake_kind(),
            Some(rustls::HandshakeKind::Resumed)
        )
    }

    /// Sends `close_notify` and flushes it to the transport.
    ///
    /// # Errors
    ///
    /// The transport's write error.
    pub fn close(mut self) -> io::Result<()> {
        self.0.conn.send_close_notify();
        while self.0.conn.wants_write() {
            if self.0.conn.write_tls(&mut self.0.sock)? == 0 {
                break;
            }
        }
        self.0.sock.flush()
    }
}

impl<IO: Read + Write> std::fmt::Debug for BlockingClientStream<IO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingClientStream")
            .field("protocol", &self.protocol())
            .field("cipher_suite", &self.cipher_suite())
            .finish_non_exhaustive()
    }
}

impl<IO: Read + Write> Read for BlockingClientStream<IO> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<IO: Read + Write> Write for BlockingClientStream<IO> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
