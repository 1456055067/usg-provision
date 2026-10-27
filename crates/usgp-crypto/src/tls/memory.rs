//! In-memory TLS handshake between our server and a client configuration.
//!
//! Test support only (unit tests and the `test-pki` feature). It drives
//! the same `ServerConfig`, verifier and post-handshake identity step that
//! the network acceptor uses, over byte buffers instead of sockets.

use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, Connection, HandshakeKind, ServerConnection};

use super::server::{Presented, PresentedSlot, RefusedHandshake};
use super::{ServerTls, TlsFailure, TlsFailureClass, TlsProtocol};
use crate::x509::PeerCertificate;

/// Result of one in-memory handshake.
pub(crate) struct Outcome {
    pub server: Result<Option<PeerCertificate>, TlsFailure>,
    /// On refusal: the presented end entity's facts, as
    /// [`ServerTls::accept_with_presented`] reports them.
    pub presented: Option<PeerCertificate>,
    /// On refusal: [`RefusedHandshake::chained_to_trust_anchor`].
    pub chained: bool,
    pub client_error: Option<rustls::Error>,
    pub protocol: Option<TlsProtocol>,
    pub cipher_suite: Option<rustls::CipherSuite>,
    pub alpn: Option<Vec<u8>>,
    pub server_kind: Option<HandshakeKind>,
    pub client_kind: Option<HandshakeKind>,
}

/// Moves pending TLS records from `from` to `to`. Returns whether any
/// bytes moved and the receiver's processing result.
fn pump(from: &mut Connection, to: &mut Connection) -> (bool, Result<(), rustls::Error>) {
    let mut buf = Vec::new();
    while from.wants_write() {
        match from.write_tls(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
    if buf.is_empty() {
        return (false, Ok(()));
    }
    let mut rd = buf.as_slice();
    while !rd.is_empty() {
        match to.read_tls(&mut rd) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if let Err(e) = to.process_new_packets() {
            return (true, Err(e));
        }
    }
    (true, Ok(()))
}

pub(crate) fn handshake(
    server_tls: &ServerTls,
    client: Arc<ClientConfig>,
    name: ServerName<'static>,
) -> Result<Outcome, rustls::Error> {
    let slot = Arc::new(PresentedSlot::default());
    let config = server_tls
        .connection_config(&slot)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut server = Connection::Server(ServerConnection::new(config)?);
    let mut client = Connection::Client(ClientConnection::new(client, name)?);
    let mut server_err = None;
    let mut client_err = None;
    for _ in 0..64 {
        let (m1, r1) = pump(&mut client, &mut server);
        if let Err(e) = r1 {
            server_err.get_or_insert(e);
        }
        let (m2, r2) = pump(&mut server, &mut client);
        if let Err(e) = r2 {
            client_err.get_or_insert(e);
        }
        if !m1 && !m2 {
            break;
        }
    }
    let server_result = match (&server_err, &server) {
        (Some(e), _) => Err(TlsFailure::from_rustls(e)),
        (None, c) if c.is_handshaking() => Err(TlsFailure {
            class: TlsFailureClass::Protocol,
            detail: "handshake did not complete".to_string(),
        }),
        (None, c) => server_tls.peer_identity(c.peer_certificates()),
    };
    let (presented, chained) = match &server_result {
        Ok(_) => (None, false),
        Err(f) => {
            let p = slot.take().or_else(|| {
                // Refused after the verifier accepted the path.
                server
                    .peer_certificates()
                    .and_then(<[_]>::first)
                    .map(|c| Presented {
                        der: c.clone().into_owned(),
                        chained: true,
                    })
            });
            let refused = RefusedHandshake::new(f.clone(), p);
            (
                refused.presented().cloned(),
                refused.chained_to_trust_anchor(),
            )
        }
    };
    Ok(Outcome {
        server: server_result,
        presented,
        chained,
        client_error: client_err,
        protocol: server.protocol_version().and_then(TlsProtocol::from_rustls),
        cipher_suite: server.negotiated_cipher_suite().map(|s| s.suite()),
        alpn: server.alpn_protocol().map(<[u8]>::to_vec),
        server_kind: server.handshake_kind(),
        client_kind: client.handshake_kind(),
    })
}
