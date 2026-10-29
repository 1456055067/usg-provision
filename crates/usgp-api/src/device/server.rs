//! The device listener's accept loop: TLS with server authentication only
//! (`DeviceServerTls`, FIPS provider; no certificate is requested from
//! the device, decision 0020), HTTP/1.1 with hyper, connection caps and
//! timeouts (plan M3 sections 3.1, 3.9 and 6).
//!
//! - a connection is admitted only from a source an active boot service
//!   serves, by the cached served-subnet table
//!   ([`super::admission`]; finding SEC-001); other sources are closed at
//!   once and audited as `device.connection.refused` under the anonymous
//!   per-source cap;
//! - at most `device_api.max_connections_per_boot_service` connections
//!   from the sources of one boot service;
//! - at most `device_api.max_connections` connections in total, taken at
//!   TCP accept;
//! - at most `device_api.max_connections_per_source` connections and
//!   `device_api.max_handshakes_per_source` handshakes in progress per
//!   source (IPv4 address or IPv6 /64);
//! - handshake, header and idle timeouts; header count and size limits.
//!
//! Over-cap connections are closed without a response. A failed handshake
//! is audited as `auth.tls.failed` under the per-source cap (anonymous
//! budget: a device has no credential at the TLS layer).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-8, SC-8(1), SC-13 - TLS 1.2/1.3 on the FIPS provider
//   only (usgp-crypto `DeviceServerTls`).
// - NIST 800-53: SC-5 - connections only from served subnets; caps per
//   boot service, per source, handshakes per source and in total;
//   handshake, header and idle timeouts (finding SEC-001).
// - NIST 800-53: SC-23 - no session resumption (usgp-crypto).
// - NIST 800-53: CM-7 - HTTP/1.1 only; the listener is off unless enabled.
// - NIST 800-53: AU-2, AU-12 - failed handshakes audited (capped).
// - SPEC: specs/targeting.md#REQ-TGT-012; specs/preinstall-env.md
//   #REQ-PE-015
// - Decisions 0001, 0020
// - RFC 8446, RFC 9112

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use usgp_audit::{Actor, AuditDraft, Detail, Interface, Outcome};
use usgp_crypto::tls::{DeviceServerTls, TlsFailure};
use usgp_db::Store;

use super::admission::Admission;
use super::router::{DeviceConn, device_ip, handle_device};
use crate::authn::AuthClass;
use crate::context::Api;
use crate::idle::IdleIo;
use crate::server::{Either, SourceSlot, SourceTable, race};

/// Serves the device routes on `listener` until `shutdown` completes.
///
/// # Errors
///
/// An [`std::io::Error`] of kind `InvalidInput`, before accepting
/// anything, if the device listener is not enabled in the configuration
/// or the provisioning keys are missing (fail closed).
pub async fn serve_device<S: Store + 'static>(
    api: Api<S>,
    listener: TcpListener,
    tls: Arc<DeviceServerTls>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let c = api.config().device.clone();
    if !c.enabled {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "device_api.enabled is false",
        ));
    }
    if api.provisioning_keys().is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the plan, boot-policy and code keys are not configured",
        ));
    }
    let all = Arc::new(Semaphore::new(c.max_connections));
    let sources = SourceTable::new(c.max_connections_per_source, c.max_handshakes_per_source);
    // Finding SEC-001: the served-subnet table, loaded now (a failure
    // admits nothing until a later load succeeds) and refreshed.
    let _ = api.refresh_device_boot_services().await;
    let refresher = {
        let api = api.clone();
        let every = c.boot_service_refresh;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(every).await;
                let _ = api.refresh_device_boot_services().await;
            }
        })
    };
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let accept = std::pin::pin!(listener.accept());
        let accepted = match race(shutdown.as_mut(), accept).await {
            Either::Left(()) => break,
            Either::Right(a) => a,
        };
        let Ok((tcp, remote)) = accepted else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        let Some(source) = sources.admit(remote.ip()) else {
            drop(tcp);
            continue;
        };
        let Ok(permit) = Arc::clone(&all).try_acquire_owned() else {
            drop(tcp);
            continue;
        };
        tokio::spawn(admit_then_serve(
            api.clone(),
            Arc::clone(&tls),
            tcp,
            remote,
            permit,
            source,
        ));
    }
    refresher.abort();
    Ok(())
}

/// Admits the connection by its source's boot service (finding SEC-001),
/// takes a per-boot-service slot, then serves it. A cached lookup; the
/// total and per-source slots taken at accept are held only for it.
async fn admit_then_serve<S: Store + 'static>(
    api: Api<S>,
    tls: Arc<DeviceServerTls>,
    tcp: TcpStream,
    remote: SocketAddr,
    permit: OwnedSemaphorePermit,
    source: SourceSlot,
) {
    let ip = device_ip(remote);
    let service = match api.device_admission(ip).await {
        Admission::Served(id) => id,
        refused => {
            drop((tcp, permit, source));
            api.audit_connection_refused(remote, refused.reason()).await;
            return;
        }
    };
    let max = api.config().device.max_connections_per_boot_service;
    let Some(slot) = api.inner.device.connections.take(service, max) else {
        // Over the boot service's cap: closed without a response, as the
        // other caps.
        return;
    };
    connection(api, tls, tcp, remote, permit, source).await;
    drop(slot);
}

impl<S: Store + 'static> Api<S> {
    /// Audits a connection refused at accept (anonymous budget; over the
    /// cap it is counted in `auth.unauthenticated.summary`).
    async fn audit_connection_refused(&self, remote: SocketAddr, reason: &'static str) {
        let ip = device_ip(remote);
        if !self
            .inner
            .unauth
            .admit(ip, reason, AuthClass::Anonymous, Instant::now())
        {
            return;
        }
        let d = AuditDraft::new(
            "device.connection.refused",
            Outcome::Refused,
            Actor::unauthenticated(Some("device")),
            Interface::DeviceApi,
        )
        .source(&remote.to_string())
        .reason(reason)
        .detail(
            Detail::new()
                .with("listener", "device_api")
                .with("source_ip", &ip.to_string()),
        );
        self.record_refusal(&d).await;
    }
}

async fn connection<S: Store + 'static>(
    api: Api<S>,
    tls: Arc<DeviceServerTls>,
    tcp: TcpStream,
    remote: SocketAddr,
    permit: OwnedSemaphorePermit,
    mut source: SourceSlot,
) {
    let c = api.config().device.clone();
    let accepted = tokio::time::timeout(c.handshake_timeout, tls.accept(tcp)).await;
    source.handshake_done();
    let stream = match accepted {
        Ok(Ok(s)) => s,
        Ok(Err(TlsFailure { class, detail })) => {
            api.audit_tls_failure_on(
                Interface::DeviceApi,
                remote,
                class.as_str(),
                &detail,
                None,
                false,
            )
            .await;
            return;
        }
        Err(_) => {
            api.audit_tls_failure_on(
                Interface::DeviceApi,
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
    let conn = Arc::new(DeviceConn { remote });
    let io = TokioIo::new(IdleIo::new(stream, c.idle_timeout));
    let svc_api = api.clone();
    let svc = service_fn(move |req| handle_device(svc_api.clone(), Arc::clone(&conn), req));
    let _ = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(c.header_timeout)
        .max_headers(c.max_headers)
        .max_header_size(c.max_header_bytes)
        .keep_alive(true)
        .serve_connection(io, svc)
        .await;
    drop((permit, source));
}
