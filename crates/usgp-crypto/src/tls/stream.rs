//! TLS stream newtypes so no rustls or tokio-rustls type leaves the crate.
//!
//! Both implement tokio's `AsyncRead` and `AsyncWrite`, so they plug into
//! hyper (through `hyper_util::rt::TokioIo`) and tokio-postgres.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1) - all application bytes pass through TLS.
// - SPEC: plan M2 WU-1 ("stream newtypes so no rustls type leaks").

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::TlsProtocol;

fn suite_name(c: &rustls::CommonState) -> Option<&'static str> {
    c.negotiated_cipher_suite().and_then(|s| s.suite().as_str())
}

fn resumed(c: &rustls::CommonState) -> bool {
    matches!(c.handshake_kind(), Some(rustls::HandshakeKind::Resumed))
}

macro_rules! tls_stream {
    ($name:ident, $inner:ty, $doc:literal) => {
        #[doc = $doc]
        pub struct $name<IO>($inner);

        impl<IO> $name<IO> {
            /// The underlying transport (for example, to read the peer
            /// address).
            pub fn io(&self) -> &IO {
                self.0.get_ref().0
            }

            /// Negotiated protocol version.
            pub fn protocol(&self) -> Option<TlsProtocol> {
                self.0
                    .get_ref()
                    .1
                    .protocol_version()
                    .and_then(TlsProtocol::from_rustls)
            }

            /// Negotiated cipher suite (IANA name).
            pub fn cipher_suite(&self) -> Option<&'static str> {
                suite_name(self.0.get_ref().1)
            }

            /// Negotiated ALPN protocol id.
            pub fn alpn(&self) -> Option<&[u8]> {
                self.0.get_ref().1.alpn_protocol()
            }

            /// True if the handshake resumed an earlier session (never
            /// expected: resumption is disabled on both sides).
            pub fn resumed(&self) -> bool {
                resumed(self.0.get_ref().1)
            }
        }

        impl<IO> std::fmt::Debug for $name<IO> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("protocol", &self.protocol())
                    .field("cipher_suite", &self.cipher_suite())
                    .finish_non_exhaustive()
            }
        }

        impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncRead for $name<IO> {
            fn poll_read(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }

        impl<IO: AsyncRead + AsyncWrite + Unpin> AsyncWrite for $name<IO> {
            fn poll_write(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
            }

            fn poll_write_vectored(
                self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bufs: &[io::IoSlice<'_>],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write_vectored(cx, bufs)
            }

            fn is_write_vectored(&self) -> bool {
                self.0.is_write_vectored()
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
            }
        }
    };
}

tls_stream!(
    ServerTlsStream,
    tokio_rustls::server::TlsStream<IO>,
    "Server side of an established TLS connection."
);
tls_stream!(
    ClientTlsStream,
    tokio_rustls::client::TlsStream<IO>,
    "Client side of an established TLS connection."
);

impl<IO> ServerTlsStream<IO> {
    pub(crate) fn new(inner: tokio_rustls::server::TlsStream<IO>) -> Self {
        Self(inner)
    }
}

impl<IO> ClientTlsStream<IO> {
    pub(crate) fn new(inner: tokio_rustls::client::TlsStream<IO>) -> Self {
        Self(inner)
    }
}
