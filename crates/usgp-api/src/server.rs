//! The listener: TLS accept (mTLS, `usgp-crypto`), HTTP/1.1 over it with
//! hyper, connection caps and timeouts, and the periodic maintenance the
//! API needs (plan M2 sections 1.1, 3.2 and 5.4).
//!
//! A presented certificate that fails validation fails the handshake;
//! that is audited here as `auth.tls.failed` with its class, since there
//! is no HTTP exchange to audit it in. A connection without a certificate
//! reaches HTTP and gets 401 there. CRLs are reloaded by swapping the
//! acceptor ([`TlsAcceptorHandle::replace`]); each new connection uses the
//! current one, and no session is resumed, so every connection is checked
//! against the current CRLs. Connections accepted under an older acceptor
//! are closed gracefully after a replacement (the request in progress, if
//! any, completes first), and no connection lives longer than
//! `api.max_connection_age_s` (findings SEC-007, NIST-010).
//!
//! Connection slots (finding SEC-001):
//!
//! - at most `api.max_connections` in total, taken at TCP accept;
//! - at most `api.max_connections_per_source` connections and
//!   `api.max_handshakes_per_source` handshakes in progress per source
//!   (IPv4 address or IPv6 /64, [`crate::authn::source_key`]);
//! - `api.reserved_cert_connections` slots are kept for connections whose
//!   client certificate validated: a connection without a certificate that
//!   finds the other slots taken is closed after the handshake;
//! - a 401 closes its connection (`Connection: close`).
//!
//! Over-cap connections are closed without a response.
//!
//! The handshake timeout (`api.handshake_timeout_s`, default 5 s) bounds
//! how long an unauthenticated peer holds a slot before it is known
//! whether it has a certificate.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1), SC-13 (Transmission Confidentiality and
//   Integrity; Cryptographic Protection) - TLS 1.2/1.3 on the FIPS
//   provider only (usgp-crypto).
// - NIST 800-53: IA-2, IA-5(2) - client certificate validated at the
//   handshake.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - connection caps
//   (total, per source, handshakes per source, slots reserved for
//   certificate holders); handshake, header and idle timeouts; header
//   count and size limits.
// - NIST 800-53: SC-23 (Session Authenticity), AC-12 (Session
//   Termination) - no resumption; connection lifetime cap; connections
//   from before a CRL reload are closed.
// - NIST 800-53: AU-2, AU-12 - refused handshakes audited with class
//   (rate-capped per source and globally; credential classes on their
//   own budget).
// - NIST 800-53: CM-7 (Least Functionality) - HTTP/1.1 only.
// - SPEC: specs/os-images.md#REQ-IMG-053; specs/operator-access.md
//   #REQ-RBAC-005, #REQ-AUD-001
// - RFC 8446 §4.3.2 (CertificateRequest), RFC 9112 (HTTP/1.1)
// POAM: SC-5 - before authentication every connection holds one of the
// `api.max_connections` global slots for up to `api.handshake_timeout_s`.
// Per-source caps (handshakes per IPv4 address or IPv6 /64) bound one
// peer, but a few addresses together can still fill every global slot
// with slow handshakes (for example 8 IPv4 addresses x 8 handshakes = 64)
// and keep new operator logins out while established connections age out
// (`api.max_connection_age_s`). Reserved certificate slots protect only
// connections whose handshake completed. Mitigated, not closed, by the
// short default handshake timeout; a network-level control (firewall,
// source allow-list for the API port) is the deployment's duty.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::task::Poll;
use std::time::{Duration, Instant};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use usgp_audit::{Actor, AuditDraft, Detail, Interface, Outcome};
use usgp_crypto::tls::{ServerTls, TlsFailure};
use usgp_db::Store;

use crate::authn::{AuthClass, presented as presented_facts, source_key};
use crate::context::Api;
use crate::idle::IdleIo;
use crate::router::{ConnInfo, handle};

/// The current TLS acceptor; replaced when CRLs are reloaded. Each
/// replacement starts a new generation; connections of older generations
/// are closed gracefully.
#[derive(Debug)]
pub struct TlsAcceptorHandle {
    current: RwLock<Arc<ServerTls>>,
    generation: watch::Sender<u64>,
}

impl TlsAcceptorHandle {
    /// A handle on `tls`.
    #[must_use]
    pub fn new(tls: ServerTls) -> Self {
        Self {
            current: RwLock::new(Arc::new(tls)),
            generation: watch::Sender::new(0),
        }
    }

    /// Replaces the acceptor. New connections use it; established
    /// connections are told to close once their request in progress (if
    /// any) completes, so every operator is checked against the new CRLs.
    pub fn replace(&self, tls: ServerTls) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(tls);
        self.generation.send_modify(|g| *g = g.wrapping_add(1));
    }

    /// The current acceptor.
    #[must_use]
    pub fn current(&self) -> Arc<ServerTls> {
        Arc::clone(&self.current.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// The current generation (increases with each [`Self::replace`]).
    #[must_use]
    pub fn generation(&self) -> u64 {
        *self.generation.borrow()
    }

    fn subscribe(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }
}

/// How often maintenance runs (unauthenticated summary, upload expiry,
/// checkpoint timer).
pub const MAINTENANCE_EVERY: Duration = Duration::from_secs(60);

impl<S: Store + 'static> Api<S> {
    /// One maintenance pass: summary of capped unauthenticated refusals,
    /// expired upload sessions, and a checkpoint if one is due.
    pub async fn maintenance(&self) {
        self.flush_unauthenticated_summary().await;
        let _ = self.expire_uploads().await;
        self.checkpoint(false).await;
    }

    /// Audits a refused handshake (`auth.tls.failed`, plan section 7),
    /// subject to the cap of its budget: credential only if the presented
    /// certificate chains to a configured trust anchor, whatever the
    /// failure class; `protocol`, `handshake_timeout` and self-made or
    /// foreign certificates are anonymous ([`AuthClass`]; findings
    /// SEC-012, NIST-014). The record's detail carries `trust_anchor`
    /// (`chained` or `not_chained`).
    ///
    /// `presented` is what the client presented, if anything (facts of
    /// the end-entity certificate, or only its SHA-256 when it does not
    /// parse); it is a claim, not an identity (AU-3; finding NIST-005).
    pub async fn audit_tls_failure(
        &self,
        remote: SocketAddr,
        class: &'static str,
        detail: &str,
        presented: Option<&str>,
        chained_to_trust_anchor: bool,
    ) {
        let budget = AuthClass::of_handshake(chained_to_trust_anchor);
        if !self
            .inner
            .unauth
            .admit(remote.ip(), class, budget, Instant::now())
        {
            return;
        }
        let anchor = if chained_to_trust_anchor {
            "chained"
        } else {
            "not_chained"
        };
        let d = AuditDraft::new(
            "auth.tls.failed",
            Outcome::Refused,
            Actor::unauthenticated(presented),
            Interface::Api,
        )
        .source(&remote.to_string())
        .reason(class)
        .detail(
            Detail::new()
                .with("class", class)
                .with("detail", detail)
                .with("trust_anchor", anchor),
        );
        self.record_refusal(&d).await;
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct SourceCount {
    open: usize,
    handshaking: usize,
}

/// Connections and handshakes in progress per source (finding SEC-001).
/// Entries exist only while a source has a connection, so the map holds
/// at most `max_connections` entries.
#[derive(Debug)]
struct SourceTable {
    max_open: usize,
    max_handshaking: usize,
    counts: Mutex<HashMap<IpAddr, SourceCount>>,
}

impl SourceTable {
    fn new(max_open: usize, max_handshaking: usize) -> Arc<Self> {
        Arc::new(Self {
            max_open,
            max_handshaking,
            counts: Mutex::new(HashMap::new()),
        })
    }

    /// A slot for a new connection from `ip` (in handshake), or `None` if
    /// its source is at a cap.
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<SourceSlot> {
        let key = source_key(ip);
        let mut m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let c = m.entry(key).or_default();
        if c.open >= self.max_open || c.handshaking >= self.max_handshaking {
            if c.open == 0 {
                m.remove(&key);
            }
            return None;
        }
        c.open = c.open.saturating_add(1);
        c.handshaking = c.handshaking.saturating_add(1);
        Some(SourceSlot {
            table: Arc::clone(self),
            key,
            handshaking: true,
        })
    }

    #[cfg(test)]
    fn count(&self, ip: IpAddr) -> (usize, usize) {
        let m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        m.get(&source_key(ip))
            .map_or((0, 0), |c| (c.open, c.handshaking))
    }
}

/// One connection's place in its source's counts; released on drop.
#[derive(Debug)]
struct SourceSlot {
    table: Arc<SourceTable>,
    key: IpAddr,
    handshaking: bool,
}

impl SourceSlot {
    /// The handshake ended (either way).
    fn handshake_done(&mut self) {
        if std::mem::take(&mut self.handshaking) {
            let mut m = self
                .table
                .counts
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(c) = m.get_mut(&self.key) {
                c.handshaking = c.handshaking.saturating_sub(1);
            }
        }
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut m = self
            .table
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(c) = m.get_mut(&self.key) {
            c.open = c.open.saturating_sub(1);
            if self.handshaking {
                c.handshaking = c.handshaking.saturating_sub(1);
            }
            if c.open == 0 {
                m.remove(&self.key);
            }
        }
    }
}

/// Everything a connection task needs besides the API.
struct Slots {
    sources: Arc<SourceTable>,
    /// Slots a connection without a validated certificate may hold.
    uncertified: Arc<Semaphore>,
}

/// Serves the API on `listener` until `shutdown` completes.
///
/// Connections over a cap (module documentation) are closed at once.
/// Maintenance runs every [`MAINTENANCE_EVERY`]. On shutdown, no new
/// connection is accepted; connections in progress are left to finish on
/// the runtime. The server forces a final audit checkpoint afterwards
/// ([`Api::checkpoint`] with `force`).
///
/// # Errors
///
/// Never at present; the type leaves room for listener errors.
pub async fn serve<S: Store + 'static>(
    api: Api<S>,
    listener: TcpListener,
    tls: Arc<TlsAcceptorHandle>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let limits = &api.config().limits;
    let all = Arc::new(Semaphore::new(limits.max_connections));
    let slots = Arc::new(Slots {
        sources: SourceTable::new(
            limits.max_connections_per_source,
            limits.max_handshakes_per_source,
        ),
        uncertified: Arc::new(Semaphore::new(
            limits
                .max_connections
                .saturating_sub(limits.reserved_cert_connections)
                .max(1),
        )),
    });
    let m_api = api.clone();
    let maintenance = tokio::spawn(async move {
        loop {
            tokio::time::sleep(MAINTENANCE_EVERY).await;
            m_api.maintenance().await;
        }
    });
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let accept = std::pin::pin!(listener.accept());
        let accepted = match race(shutdown.as_mut(), accept).await {
            Either::Left(()) => break,
            Either::Right(a) => a,
        };
        let Ok((tcp, remote)) = accepted else {
            // Transient accept errors (for example EMFILE): pause briefly
            // instead of spinning.
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(source) = slots.sources.admit(remote.ip()) else {
            drop(tcp);
            continue;
        };
        let Ok(permit) = Arc::clone(&all).try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        tokio::spawn(connection(
            api.clone(),
            Arc::clone(&tls),
            tcp,
            remote,
            Held {
                _all: permit,
                source,
                _uncertified: None,
            },
            Arc::clone(&slots),
        ));
    }
    maintenance.abort();
    Ok(())
}

/// What one connection holds until it ends.
struct Held {
    _all: OwnedSemaphorePermit,
    source: SourceSlot,
    _uncertified: Option<OwnedSemaphorePermit>,
}

enum Either<A, B> {
    Left(A),
    Right(B),
}

/// The output of whichever future finishes first (`a` is polled first).
async fn race<A: Future, B: Future>(
    mut a: Pin<&mut A>,
    mut b: Pin<&mut B>,
) -> Either<A::Output, B::Output> {
    std::future::poll_fn(|cx| {
        if let Poll::Ready(x) = a.as_mut().poll(cx) {
            return Poll::Ready(Either::Left(x));
        }
        if let Poll::Ready(y) = b.as_mut().poll(cx) {
            return Poll::Ready(Either::Right(y));
        }
        Poll::Pending
    })
    .await
}

async fn connection<S: Store + 'static>(
    api: Api<S>,
    handle_tls: Arc<TlsAcceptorHandle>,
    tcp: TcpStream,
    remote: SocketAddr,
    mut held: Held,
    slots: Arc<Slots>,
) {
    let limits = api.config().limits.clone();
    // Subscribe before taking the acceptor, so a replacement between the
    // two is seen as a change.
    let mut generation = handle_tls.subscribe();
    let _ = generation.borrow_and_update();
    let tls = handle_tls.current();
    let accepted =
        tokio::time::timeout(limits.handshake_timeout, tls.accept_with_presented(tcp)).await;
    held.source.handshake_done();
    let (stream, peer) = match accepted {
        Ok(Ok(v)) => v,
        Ok(Err(refused)) => {
            let TlsFailure { class, detail } = refused.failure();
            let presented = match (refused.presented(), refused.presented_sha256()) {
                (Some(cert), _) => Some(presented_facts(cert)),
                (None, Some(sha)) => Some(format!("cert sha256 {}; unparsable", sha.to_hex())),
                (None, None) => None,
            };
            api.audit_tls_failure(
                remote,
                class.as_str(),
                detail,
                presented.as_deref(),
                refused.chained_to_trust_anchor(),
            )
            .await;
            return;
        }
        Err(_) => {
            api.audit_tls_failure(
                remote,
                "handshake_timeout",
                "the TLS handshake timed out",
                None,
                false,
            )
            .await;
            return;
        }
    };
    if peer.is_none() {
        // No certificate: only the unreserved slots (SEC-001).
        match Arc::clone(&slots.uncertified).try_acquire_owned() {
            Ok(p) => held._uncertified = Some(p),
            Err(_) => return,
        }
    }
    let conn = Arc::new(ConnInfo { peer, remote });
    let io = TokioIo::new(IdleIo::new(stream, limits.idle_timeout));
    let svc_api = api.clone();
    let svc = service_fn(move |req| handle(svc_api.clone(), Arc::clone(&conn), req));
    let http = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .max_headers(limits.max_headers)
        .max_header_size(limits.max_header_bytes)
        .keep_alive(true)
        .serve_connection(io, svc);
    let mut http = std::pin::pin!(http);
    let mut aged = std::pin::pin!(tokio::time::sleep(limits.max_connection_age));
    let mut reloaded = std::pin::pin!(generation.changed());
    let mut closing = false;
    std::future::poll_fn(|cx| {
        if http.as_mut().poll(cx).is_ready() {
            return Poll::Ready(());
        }
        if !closing {
            let old_age = aged.as_mut().poll(cx).is_ready();
            // `Err` (the handle is gone) also ends the connection.
            let old_generation = reloaded.as_mut().poll(cx).is_ready();
            if old_age || old_generation {
                closing = true;
                http.as_mut().graceful_shutdown();
                if http.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
            }
        }
        Poll::Pending
    })
    .await;
    drop(held);
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn source_caps_open_and_handshakes() {
        let t = SourceTable::new(3, 2);
        let a = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut s1 = t.admit(a).unwrap();
        let s2 = t.admit(a).unwrap();
        assert!(t.admit(a).is_none(), "two handshakes in progress");
        s1.handshake_done();
        let s3 = t.admit(a).unwrap();
        assert_eq!(t.count(a), (3, 2));
        assert!(t.admit(a).is_none(), "three open");
        drop(s2);
        assert_eq!(t.count(a), (2, 1));
        drop((s1, s3));
        assert_eq!(t.count(a), (0, 0));
        assert!(t.counts.lock().unwrap().is_empty(), "no entry left behind");
    }

    #[test]
    fn ipv6_slots_per_64() {
        let t = SourceTable::new(2, 2);
        let mut held = Vec::new();
        for i in 0..10u16 {
            let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, i, 0, 0, 1));
            if let Some(s) = t.admit(ip) {
                held.push(s);
            }
        }
        assert_eq!(held.len(), 2);
        let other = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1));
        assert!(t.admit(other).is_some());
    }
}
