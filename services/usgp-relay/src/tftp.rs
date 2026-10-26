//! Read-only TFTP service: request admission, caps and rate limits, and
//! the per-transfer task driving `usgp_tftp::ReadTransfer`.
//!
//! - Port 69 receives requests only. A malformed datagram, or any opcode
//!   other than RRQ/WRQ, is dropped silently, as is any request whose
//!   source is not a unicast host address with a non-zero port.
//! - A WRQ gets ERROR 2 before any file access (REQ-BOOT-040).
//! - An RRQ name is matched byte for byte against the manifest. An
//!   unpublished name gets ERROR 1 without any file access
//!   (REQ-BOOT-033/041).
//! - A published file is read and verified on every request (SI-7); a
//!   failure gets ERROR 1.
//! - Each transfer runs on its own new-TID socket in its own task, so a
//!   slow or stalled client never delays another (REQ-BOOT-034). Packets
//!   from a foreign TID get ERROR 5 and the transfer carries on
//!   (RFC 1350 §4).
//! - Admission to a transfer slot is limited per source and per interface
//!   (`tftp_rrq_global_per_sec` / `_burst`, one budget for each
//!   interface), so a flood on one segment does not shed requests on
//!   another. A pending slot is held at most `tftp.handshake_timeout_ms`
//!   from the moment it is reserved: the wait for content verification
//!   and the wait for the first ACK share that one deadline, and a request
//!   still waiting for verification when it passes is dropped
//!   (`tftp_verify_timeout`, plus a `boot.file.verify_slow` event naming
//!   the file, at most once a minute per file). A verification cut short
//!   this way keeps its read permit until its read returns, so at most
//!   `verify_concurrency` reads run at once. A sender that spoofs source addresses and
//!   never ACKs therefore holds at most (interfaces x rate x timeout)
//!   pending slots, however slow verification is; with the defaults that
//!   is about 100 per interface against `tftp_max_pending` 256 (SC-5).
//!
//! Every reply, including refusals, is sent from a new TID socket bound to
//! the interface address (plan section 3.2).

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality) - read-only, octet only.
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - per-source and
//   global request buckets, separate pending/established caps, short
//   pre-first-ACK lifetime, per-client cap, global ERROR budget, maximum
//   transfer duration, aggregated counters.
// - NIST 800-53: SI-10 - requests from non-unicast, loopback, 0/8 or
//   port-0 sources are dropped before any slot is reserved.
// - NIST 800-53: SI-7 - only verified bytes are served.
// - NIST 800-53: SI-10 - malformed input dropped (usgp-tftp parser).
// - NIST 800-53: SI-11 (Error Handling) - fixed, generic ERROR texts.
// - NIST 800-53: AU-2 / AU-12 - transfer start/end and refusals are events.
// - SPEC: specs/boot-network.md#REQ-BOOT-030..035, #REQ-BOOT-040..042,
//   #REQ-BOOT-044
// - RFC 1350 §4 - new TID per transfer, ERROR 5 for foreign TIDs

// POAM: SC-8 (Transmission Confidentiality and Integrity) - TFTP is
// cleartext and unauthenticated by the standard; the boot program can be
// read or altered in transit on TB-1. Integrity rests on SI-7 here and on
// device Secure Boot (the firmware verifies the program's signature).
// POAM: SC-5 - a flood of spoofed RRQs above `tftp_rrq_global_per_sec`
// on one interface uses up that interface's admission budget while it
// lasts, so genuine requests on the same segment are shed (other
// interfaces keep their own budgets; recovery is immediate when it
// stops). With several interfaces flooded at once, the shared
// `tftp_max_pending` cap can still be reached. Network mitigation: IP
// source guard / DHCP snooping on the boot segment
// (docs/operations/relay.md).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use usgp_common::event::AuditEvent;
use usgp_tftp::{
    Admission, ErrorCode, Mode, Outcome as TransferOutcome, Packet, Phase, ReadTransfer,
    ServerConfig, Step, admit_read, encode_error, foreign_tid_error, parse,
};

use crate::config::{InterfaceConfig, Limits};
use crate::content::{ContentError, ContentStore};
use crate::events::{self, COMPONENT, Outcome};
use crate::limits::{BucketSpec, BucketTable, Counters, TokenBucket};
use crate::lock;
use usgp_dhcp::packet::is_unicast_host;

/// Fixed ERROR texts (SI-11: nothing about paths, names or digests).
const MSG_NOT_FOUND: &str = "file not found";
const MSG_READ_ONLY: &str = "read-only server";
const MSG_MODE: &str = "only octet mode is supported";

/// Receive buffer for client datagrams on a transfer socket. ACK and
/// ERROR packets are far smaller; anything longer is truncated and then
/// fails to parse, which is ignored.
const TRANSFER_RECV_BUF: usize = 1024;

/// An unconnected UDP socket for one transfer (one server TID).
///
/// Implemented by `tokio::net::UdpSocket` for the service and by in-memory
/// sockets in tests.
pub trait TransferSocket: Send + Sync + 'static {
    /// Sends `buf` to `dst`.
    fn send_to(
        &self,
        buf: &[u8],
        dst: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send;
    /// Receives one datagram.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
    /// The local address (the server TID).
    ///
    /// # Errors
    ///
    /// The socket's error.
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

impl TransferSocket for tokio::net::UdpSocket {
    fn send_to(
        &self,
        buf: &[u8],
        dst: SocketAddr,
    ) -> impl Future<Output = io::Result<usize>> + Send {
        tokio::net::UdpSocket::send_to(self, buf, dst)
    }

    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send {
        tokio::net::UdpSocket::recv_from(self, buf)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        tokio::net::UdpSocket::local_addr(self)
    }
}

/// Opens a new server TID socket for one transfer or refusal.
pub trait SocketFactory: Send + Sync + 'static {
    /// The socket type.
    type Socket: TransferSocket;
    /// Opens a socket bound to the interface address, port 0.
    ///
    /// # Errors
    ///
    /// The bind error.
    fn open_tid(&self) -> io::Result<Self::Socket>;
}

#[derive(Debug, Default)]
struct Slots {
    pending: usize,
    established: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Parameters of a [`TftpListener`]: the sans-IO transfer settings plus the
/// relay's own limit on the pre-first-ACK phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerConfig {
    /// The `usgp_tftp` transfer settings.
    pub server: ServerConfig,
    /// Longest time a transfer waits for its first ACK before it is
    /// dropped and its pending slot released (relay side; SC-5).
    pub handshake_timeout: Duration,
}

/// TFTP state shared by every interface: caps, per-source buckets, the
/// ERROR budget and counters. The admission budget is per interface
/// ([`TftpListener`]).
#[derive(Debug)]
pub struct TftpShared {
    limits: Limits,
    slots: Mutex<Slots>,
    requests: Mutex<BucketTable<IpAddr>>,
    errors: Mutex<TokenBucket>,
    drops: Mutex<Counters>,
    shed: Arc<Mutex<Counters>>,
}

impl TftpShared {
    /// Shared state for `limits`; `shed` collects `limits.shed` counts.
    #[must_use]
    pub fn new(limits: &Limits, shed: Arc<Mutex<Counters>>, now: Instant) -> Arc<Self> {
        Arc::new(Self {
            limits: *limits,
            slots: Mutex::new(Slots::default()),
            requests: Mutex::new(BucketTable::new(
                BucketSpec {
                    burst: limits.tftp_rrq_burst,
                    per_token: limits.tftp_rrq_refill,
                },
                limits.tracked_clients,
            )),
            errors: Mutex::new(TokenBucket::per_second(
                limits.tftp_error_per_sec,
                limits.tftp_error_per_sec,
                now,
            )),
            drops: Mutex::new(Counters::default()),
            shed,
        })
    }

    /// Transfers before their first ACK, and established transfers.
    #[must_use]
    pub fn active(&self) -> (usize, usize) {
        let s = lock(&self.slots);
        (s.pending, s.established)
    }

    /// Returns and clears the drop counts (for `tftp.drop.summary`).
    pub fn take_drop_counts(&self) -> Vec<(&'static str, u64)> {
        lock(&self.drops).drain()
    }

    /// Current drop count for `label`.
    #[must_use]
    pub fn drop_count(&self, label: &str) -> u64 {
        lock(&self.drops).get(label)
    }

    fn shed(&self, label: &'static str) {
        lock(&self.shed).bump(label);
    }

    fn try_reserve(self: &Arc<Self>, ip: IpAddr) -> Result<SlotGuard, &'static str> {
        let mut s = lock(&self.slots);
        if s.per_ip.get(&ip).copied().unwrap_or(0) >= self.limits.tftp_per_client_transfers {
            return Err("tftp_per_client");
        }
        if s.pending >= self.limits.tftp_max_pending {
            return Err("tftp_pending");
        }
        if s.established >= self.limits.tftp_max_transfers {
            return Err("tftp_transfers");
        }
        s.pending += 1;
        *s.per_ip.entry(ip).or_insert(0) += 1;
        Ok(SlotGuard {
            shared: Arc::clone(self),
            ip,
            established: false,
        })
    }

    /// Takes one token from the global ERROR budget.
    fn allow_error(&self, now: Instant) -> bool {
        if lock(&self.errors).try_take(now) {
            true
        } else {
            self.shed("tftp_error");
            false
        }
    }
}

/// A transfer's claim on the pending or established cap; released on drop
/// whatever way the transfer ends.
#[derive(Debug)]
struct SlotGuard {
    shared: Arc<TftpShared>,
    ip: IpAddr,
    established: bool,
}

impl SlotGuard {
    /// Moves from the pending to the established cap.
    fn promote(&mut self) -> bool {
        if self.established {
            return true;
        }
        let mut s = lock(&self.shared.slots);
        if s.established >= self.shared.limits.tftp_max_transfers {
            return false;
        }
        s.pending = s.pending.saturating_sub(1);
        s.established += 1;
        self.established = true;
        true
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut s = lock(&self.shared.slots);
        if self.established {
            s.established = s.established.saturating_sub(1);
        } else {
            s.pending = s.pending.saturating_sub(1);
        }
        if let Some(n) = s.per_ip.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                s.per_ip.remove(&self.ip);
            }
        }
    }
}

/// What [`TftpListener::handle_request`] did with a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Dropped silently (malformed or not a request).
    Dropped(&'static str),
    /// Dropped silently by a rate limit or cap.
    Shed(&'static str),
    /// An ERROR refusal is being sent.
    Refused(&'static str),
    /// A transfer task was started (it may still refuse after verifying).
    Started,
}

/// The TFTP listener of one interface.
#[derive(Debug)]
pub struct TftpListener<F: SocketFactory> {
    iface: InterfaceConfig,
    content: Arc<ContentStore>,
    cfg: ServerConfig,
    handshake_timeout: Duration,
    factory: Arc<F>,
    shared: Arc<TftpShared>,
    /// Read requests admitted to a slot on this interface, all sources
    /// together (`tftp_rrq_global_per_sec` / `_burst`; SC-5).
    admission: Mutex<TokenBucket>,
}

/// Current time for the sans-IO state machine. Under a paused tokio clock
/// (tests) this follows the virtual clock.
fn now() -> Instant {
    tokio::time::Instant::now().into_std()
}

impl<F: SocketFactory> TftpListener<F> {
    /// A listener for `iface`, with its own admission budget.
    #[must_use]
    pub fn new(
        iface: InterfaceConfig,
        content: Arc<ContentStore>,
        cfg: ListenerConfig,
        factory: F,
        shared: Arc<TftpShared>,
    ) -> Arc<Self> {
        let admission = TokenBucket::per_second(
            shared.limits.tftp_rrq_global_burst,
            shared.limits.tftp_rrq_global_per_sec,
            now(),
        );
        Arc::new(Self {
            iface,
            content,
            cfg: cfg.server,
            handshake_timeout: cfg.handshake_timeout,
            factory: Arc::new(factory),
            shared,
            admission: Mutex::new(admission),
        })
    }

    /// The shared caps and counters.
    #[must_use]
    pub fn shared(&self) -> &Arc<TftpShared> {
        &self.shared
    }

    /// Handles one datagram received on port 69 from `src`. Must be called
    /// inside a tokio runtime: refusals and transfers run as tasks.
    pub fn handle_request(self: &Arc<Self>, src: SocketAddr, buf: &[u8]) -> Disposition {
        let t = now();
        let packet = match parse(buf) {
            Ok(p) => p,
            Err(_) => return self.drop_silently("malformed"),
        };
        let req = match packet {
            Packet::Rrq(r) | Packet::Wrq(r) => r,
            _ => return self.drop_silently("not_a_request"),
        };
        // No reply, slot or bucket entry for a source that cannot be a
        // TFTP client (same rule as the DHCP 4011 path).
        if !is_client_source(src) {
            return self.drop_silently("bad_source");
        }
        if !lock(&self.shared.requests).try_take(&src.ip(), t) {
            self.shared.shed("tftp_request_source");
            return Disposition::Shed("tftp_request_source");
        }
        if matches!(packet, Packet::Wrq(_)) {
            // No file access of any kind for a write request.
            return self.refuse(
                src,
                ErrorCode::AccessViolation,
                MSG_READ_ONLY,
                "write_request",
                None,
                t,
            );
        }
        let name = String::from_utf8_lossy(req.filename).into_owned();
        if !self.content.is_published(req.filename) {
            return self.refuse(
                src,
                ErrorCode::FileNotFound,
                MSG_NOT_FOUND,
                "not_published",
                Some(name),
                t,
            );
        }
        if req.mode_kind() != Mode::Octet {
            return self.refuse(
                src,
                ErrorCode::IllegalOperation,
                MSG_MODE,
                "unsupported_mode",
                Some(name),
                t,
            );
        }
        if !lock(&self.admission).try_take(t) {
            self.shared.shed("tftp_rrq_global");
            return Disposition::Shed("tftp_rrq_global");
        }
        let slot = match self.shared.try_reserve(src.ip()) {
            Ok(s) => s,
            Err(label) => {
                self.shared.shed(label);
                return Disposition::Shed(label);
            }
        };
        // SC-5: the pending-slot lifetime starts now, at reservation,
        // and covers the verification wait as well as the first ACK.
        let deadline = t.checked_add(self.handshake_timeout);
        let me = Arc::clone(self);
        let request = buf.to_vec();
        tokio::spawn(async move { me.serve(src, request, slot, deadline).await });
        Disposition::Started
    }

    fn drop_silently(&self, label: &'static str) -> Disposition {
        lock(&self.shared.drops).bump(label);
        Disposition::Dropped(label)
    }

    /// Sends an ERROR refusal from a new TID (subject to the ERROR budget)
    /// and emits `tftp.request.refused`.
    fn refuse(
        self: &Arc<Self>,
        src: SocketAddr,
        code: ErrorCode,
        msg: &'static str,
        reason: &'static str,
        file: Option<String>,
        t: Instant,
    ) -> Disposition {
        if !self.shared.allow_error(t) {
            return Disposition::Shed("tftp_error");
        }
        self.emit_refused(src, code, reason, file);
        let me = Arc::clone(self);
        let packet = encode_error(code, msg);
        tokio::spawn(async move { me.send_once(src, &packet).await });
        Disposition::Refused(reason)
    }

    async fn send_once(&self, dst: SocketAddr, packet: &[u8]) {
        match self.factory.open_tid() {
            Ok(sock) => {
                if sock.send_to(packet, dst).await.is_err() {
                    lock(&self.shared.drops).bump("send_failed");
                }
            }
            Err(_) => lock(&self.shared.drops).bump("tid_open_failed"),
        }
    }

    fn emit_refused(&self, src: SocketAddr, code: ErrorCode, reason: &str, file: Option<String>) {
        let mut detail = vec![
            ("reason", reason.to_owned()),
            ("code_sent", code.code().to_string()),
        ];
        if let Some(f) = file {
            detail.push(("file", f));
        }
        events::emit(AuditEvent {
            interface: Some(&self.iface.name),
            peer: Some(src),
            detail: &detail,
            ..AuditEvent::new(events::TFTP_REQUEST_REFUSED, Outcome::Refused, COMPONENT)
        });
    }

    /// Verifies the file, admits the request, and runs the transfer.
    /// `deadline` bounds how long the pending slot is held before the
    /// first ACK, counted from reservation (`None`: no bound).
    async fn serve(
        self: Arc<Self>,
        client: SocketAddr,
        request: Vec<u8>,
        mut slot: SlotGuard,
        deadline: Option<Instant>,
    ) {
        let Ok(Packet::Rrq(req)) = parse(&request) else {
            return;
        };
        let name = String::from_utf8_lossy(req.filename).into_owned();
        let verified = match deadline {
            Some(d) => {
                let at = tokio::time::Instant::from_std(d);
                match tokio::time::timeout_at(at, self.content.get_verified(req.filename)).await {
                    Ok(r) => r,
                    Err(_) => {
                        // Verification did not finish within the slot's
                        // lifetime (queued behind other reads, or a file
                        // too slow to read and hash): release the slot and
                        // drop silently, like any other load-shedding
                        // decision (SC-5). A read already running keeps
                        // its verify permit until it returns (content.rs),
                        // so the bound on concurrent reads holds. The file
                        // is named in a rate-limited event so a file that
                        // can never be verified in time is visible.
                        drop(slot);
                        self.shared.shed("tftp_verify_timeout");
                        let t = now();
                        let reserved = d.checked_sub(self.handshake_timeout).unwrap_or(d);
                        let _ = self.content.report_verify_slow(
                            req.filename,
                            t.saturating_duration_since(reserved),
                            self.handshake_timeout,
                            t,
                        );
                        return;
                    }
                }
            }
            None => self.content.get_verified(req.filename).await,
        };
        let data = match verified {
            Ok(d) => d,
            Err(e) => {
                let reason = match e {
                    ContentError::NotPublished => "not_published",
                    ContentError::Missing => "missing",
                    ContentError::IntegrityFailed => "integrity_failed",
                    ContentError::Unavailable => "verify_unavailable",
                };
                drop(slot);
                let _ = self.refuse(
                    client,
                    ErrorCode::FileNotFound,
                    MSG_NOT_FOUND,
                    reason,
                    Some(name),
                    now(),
                );
                return;
            }
        };
        let started = now();
        let (mut transfer, first) = match admit_read(&req, &data, &self.cfg, started) {
            Admission::Accept { transfer, first } => (transfer, first),
            Admission::Refuse { error, reason } => {
                drop(slot);
                if self.shared.allow_error(now()) {
                    let code = match reason {
                        usgp_tftp::RefuseReason::UnsupportedMode => ErrorCode::IllegalOperation,
                        _ => ErrorCode::DiskFull,
                    };
                    self.emit_refused(client, code, reason.label(), Some(name));
                    self.send_once(client, &error).await;
                }
                return;
            }
        };
        let sha256 = self
            .content
            .manifest()
            .get(req.filename)
            .map_or_else(String::new, |e| e.sha256.to_hex());
        let socket = match self.factory.open_tid() {
            Ok(s) => s,
            Err(_) => {
                lock(&self.shared.drops).bump("tid_open_failed");
                let detail = [
                    ("file", name),
                    ("sha256", sha256),
                    ("reason", "tid_open_failed".to_owned()),
                ];
                events::emit(AuditEvent {
                    interface: Some(&self.iface.name),
                    peer: Some(client),
                    detail: &detail,
                    ..AuditEvent::new(events::TFTP_FAILED, Outcome::Failure, COMPONENT)
                });
                return;
            }
        };
        let local = socket.local_addr().ok();
        let start_detail = [
            ("file", name.clone()),
            ("sha256", sha256.clone()),
            ("size", transfer.file_len().to_string()),
            ("blksize", transfer.block_size().to_string()),
            ("tsize", opt_u64(transfer.tsize())),
            ("oack", transfer.sent_oack().to_string()),
            ("verified_sha256", "true".to_owned()),
        ];
        events::emit(AuditEvent {
            interface: Some(&self.iface.name),
            local_addr: local,
            peer: Some(client),
            detail: &start_detail,
            ..AuditEvent::new(events::TFTP_STARTED, Outcome::Success, COMPONENT)
        });
        if socket.send_to(&first, client).await.is_err() {
            lock(&self.shared.drops).bump("send_failed");
        }
        let end = self
            .run_transfer(&socket, client, &mut transfer, &data, &mut slot, deadline)
            .await;
        self.emit_end(client, local, (&name, &sha256), &transfer, end, started);
    }

    /// Drives one transfer until it ends. Returns how it ended.
    async fn run_transfer(
        &self,
        socket: &F::Socket,
        client: SocketAddr,
        transfer: &mut ReadTransfer,
        data: &[u8],
        slot: &mut SlotGuard,
        handshake_deadline: Option<Instant>,
    ) -> End {
        let mut buf = vec![0u8; TRANSFER_RECV_BUF];
        // The pending slot is held at most until this deadline, set when
        // the slot was reserved (SC-5).
        loop {
            let mut deadline = transfer.deadline();
            if transfer.phase() == Phase::Handshake
                && let Some(h) = handshake_deadline
            {
                if now() >= h {
                    return End::HandshakeTimeout;
                }
                deadline = deadline.min(h);
            }
            let deadline = tokio::time::Instant::from_std(deadline);
            let step = tokio::select! {
                r = socket.recv_from(&mut buf) => match r {
                    Ok((n, from)) => {
                        if from != client {
                            // Foreign TID: ERROR 5 to it; carry on (RFC 1350 §4).
                            if self.shared.allow_error(now())
                                && socket.send_to(&foreign_tid_error(), from).await.is_err()
                            {
                                lock(&self.shared.drops).bump("send_failed");
                            }
                            continue;
                        }
                        let pkt = buf.get(..n).unwrap_or(&[]);
                        transfer.on_packet(pkt, data, now())
                    }
                    // A receive error (for example a reported ICMP error)
                    // does not end the transfer; the timer still runs.
                    Err(_) => Step::Wait,
                },
                () = tokio::time::sleep_until(deadline) => transfer.on_timeout(data, now()),
            };
            // Move to the established cap as soon as the first ACK is
            // accepted, before anything else is sent.
            if transfer.phase() == Phase::Established && !slot.promote() {
                self.shared.shed("tftp_transfers");
                return End::EstablishedCap;
            }
            match step {
                Step::Send(p) => {
                    if socket.send_to(&p, client).await.is_err() {
                        lock(&self.shared.drops).bump("send_failed");
                    }
                }
                Step::Wait => {}
                Step::Abort { error, outcome } => {
                    if socket.send_to(&error, client).await.is_err() {
                        lock(&self.shared.drops).bump("send_failed");
                    }
                    return End::Transfer(outcome);
                }
                Step::Done(o) => return End::Transfer(o),
            }
        }
    }

    fn emit_end(
        &self,
        client: SocketAddr,
        local: Option<SocketAddr>,
        (name, sha256): (&str, &str),
        transfer: &ReadTransfer,
        end: End,
        started: Instant,
    ) {
        let elapsed = now().saturating_duration_since(started);
        let mut detail = vec![
            ("file", name.to_owned()),
            ("sha256", sha256.to_owned()),
            ("size", transfer.file_len().to_string()),
            ("blksize", transfer.block_size().to_string()),
            ("tsize", opt_u64(transfer.tsize())),
            ("retries", transfer.retransmits().to_string()),
            ("duration_ms", duration_ms(elapsed)),
            ("last_block", transfer.current_block().to_string()),
        ];
        let (event, outcome) = match end {
            End::Transfer(TransferOutcome::Completed) => (events::TFTP_COMPLETED, Outcome::Success),
            End::Transfer(o @ TransferOutcome::AbortedByClient { code }) => {
                detail.push(("reason", o.label().to_owned()));
                detail.push(("client_error_code", code.to_string()));
                (events::TFTP_ABORTED_BY_CLIENT, Outcome::Failure)
            }
            End::Transfer(o @ TransferOutcome::Failed(_)) => {
                detail.push(("reason", o.label().to_owned()));
                (events::TFTP_FAILED, Outcome::Failure)
            }
            End::EstablishedCap => {
                detail.push(("reason", "established_cap".to_owned()));
                (events::TFTP_FAILED, Outcome::Failure)
            }
            End::HandshakeTimeout => {
                detail.push(("reason", "handshake_timeout".to_owned()));
                (events::TFTP_FAILED, Outcome::Failure)
            }
        };
        events::emit(AuditEvent {
            interface: Some(&self.iface.name),
            local_addr: local,
            peer: Some(client),
            detail: &detail,
            ..AuditEvent::new(event, outcome, COMPONENT)
        });
    }
}

/// How a transfer task ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum End {
    /// The state machine's own outcome.
    Transfer(TransferOutcome),
    /// No established slot was free when the first ACK arrived.
    EstablishedCap,
    /// No first ACK within the handshake timeout.
    HandshakeTimeout,
}

/// Whether `src` can be a TFTP client: a unicast IPv4 host address (not
/// 0/8, loopback, multicast, 240/4 or limited broadcast) and a non-zero
/// port. Subnet-directed broadcast cannot be told apart without the
/// prefix; the kernel does not deliver such sources on a unicast-bound
/// socket anyway (plan section 3.2).
#[must_use]
pub fn is_client_source(src: SocketAddr) -> bool {
    match src {
        SocketAddr::V4(v4) => v4.port() != 0 && is_unicast_host(*v4.ip()),
        // The listeners are bound to IPv4 addresses only (DEC-0004).
        SocketAddr::V6(_) => false,
    }
}

fn opt_u64(v: Option<u64>) -> String {
    v.map_or_else(|| "none".to_owned(), |n| n.to_string())
}

fn duration_ms(d: Duration) -> String {
    d.as_millis().to_string()
}
