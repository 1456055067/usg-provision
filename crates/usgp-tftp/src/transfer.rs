//! Read-transfer admission and the lock-step sender state machine.
//!
//! Sans-IO: the caller passes every received packet, every timer expiry,
//! the current time, and the verified file bytes; the state machine returns
//! what to send. It owns no file buffer and no socket. Foreign-TID packets
//! are the caller's job (it answers them with [`foreign_tid_error`] and
//! does not pass them here; RFC 1350 §4).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - retry caps (shorter
//   before the first ACK), maximum transfer duration, no resend on
//   duplicate ACK.
// - NIST 800-53: CM-7 (Least Functionality) - read-only, octet mode only.
// - NIST 800-53: SI-11 (Error Handling) - fixed, generic error text.
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-031,
//   #REQ-BOOT-032, #REQ-BOOT-035 (AUDITED part: never a truncated file)
// - RFC 1350 §2, §4, §6, §7 - lock-step, TIDs, normal and premature end
// - RFC 1123 §4.2.3.1 - Sorcerer's Apprentice fix; §4.2.3.2 adaptive RTO
// - RFC 2347 - OACK then ACK 0; RFC 2348 - final short block; RFC 2349

use core::time::Duration;
use std::time::Instant;

use crate::options::{Negotiated, negotiate};
use crate::packet::{
    ErrorCode, Mode, Opcode, Packet, ReadRequest, encode_data, encode_error, encode_oack, parse,
};
use crate::rto::Rto;

/// Largest number of DATA packets in one transfer: block numbers are 16
/// bits and never wrap (REQ-BOOT-035; plan §1.1).
pub const MAX_BLOCKS: u64 = 65535;

/// Server limits. Values are project design (OPEN-BOOT-L1), not product
/// behaviour; the relay config validates and supplies them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerConfig {
    /// Largest block size granted (clamped to 8..=65464).
    pub max_block_size: u16,
    /// RTO before any RTT sample.
    pub initial_rto: Duration,
    /// RTO floor.
    pub min_rto: Duration,
    /// RTO ceiling.
    pub max_rto: Duration,
    /// Resends of one packet after the first ACK before giving up.
    pub max_retries: u8,
    /// Resends of the first packet (OACK or DATA 1) before giving up.
    pub handshake_retries: u8,
    /// Hard limit on a transfer's total duration.
    pub max_duration: Duration,
    /// Largest file served.
    pub max_file_size: u64,
}

impl Default for ServerConfig {
    /// Plan §3.4 defaults.
    fn default() -> Self {
        Self {
            max_block_size: 1468,
            initial_rto: Duration::from_millis(1000),
            min_rto: Duration::from_millis(250),
            max_rto: Duration::from_millis(8000),
            max_retries: 5,
            handshake_retries: 2,
            max_duration: Duration::from_secs(600),
            max_file_size: 64 * 1024 * 1024,
        }
    }
}

/// Why a read request was refused before any OACK or DATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// Mode other than `octet`.
    UnsupportedMode,
    /// The file is larger than `max_file_size`.
    FileTooLarge,
    /// The file needs more than 65535 DATA packets at the negotiated block
    /// size (REQ-BOOT-035).
    TooManyBlocks,
}

impl RefuseReason {
    /// Stable label for audit events.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::UnsupportedMode => "unsupported_mode",
            Self::FileTooLarge => "file_too_large",
            Self::TooManyBlocks => "too_many_blocks",
        }
    }
}

/// Result of [`admit_read`].
#[derive(Debug)]
pub enum Admission {
    /// Start the transfer: send `first` (OACK or DATA 1) from a new TID.
    Accept {
        /// The transfer state.
        transfer: Box<ReadTransfer>,
        /// The first packet to send.
        first: Vec<u8>,
    },
    /// Send `error` and do not start a transfer.
    Refuse {
        /// The ERROR packet.
        error: Vec<u8>,
        /// Why.
        reason: RefuseReason,
    },
}

/// How a transfer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The final block was acknowledged.
    Completed,
    /// The client sent an ERROR (for example after reading `tsize`, or
    /// ERROR 8 rejecting the OACK).
    AbortedByClient {
        /// The client's error code.
        code: u16,
    },
    /// The server gave up.
    Failed(FailReason),
}

/// Why the server gave up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    /// The retry cap was reached (REQ-BOOT-032).
    RetryCapReached,
    /// The transfer ran past `max_duration`.
    MaxDurationExceeded,
    /// The client sent a packet that is illegal during a read transfer.
    IllegalOperation,
    /// The caller passed file bytes whose length differs from admission.
    DataMismatch,
}

impl Outcome {
    /// Stable label for audit events.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::AbortedByClient { .. } => "aborted_by_client",
            Self::Failed(FailReason::RetryCapReached) => "retry_cap",
            Self::Failed(FailReason::MaxDurationExceeded) => "max_duration",
            Self::Failed(FailReason::IllegalOperation) => "illegal_operation",
            Self::Failed(FailReason::DataMismatch) => "data_mismatch",
        }
    }
}

/// What the caller does next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Send this packet to the client TID, then wait until
    /// [`ReadTransfer::deadline`].
    Send(Vec<u8>),
    /// Send nothing; keep waiting until [`ReadTransfer::deadline`].
    Wait,
    /// Send this ERROR and end the transfer with `outcome`.
    Abort {
        /// The ERROR packet.
        error: Vec<u8>,
        /// The final outcome.
        outcome: Outcome,
    },
    /// The transfer is over; send nothing. Returned again on every later
    /// call (final).
    Done(Outcome),
}

/// Transfer phase, for separate pending/established caps (plan §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// No ACK yet for the first packet.
    Handshake,
    /// At least one valid ACK received.
    Established,
    /// Ended.
    Finished,
}

/// Fixed error texts (SI-11: nothing about paths, names or digests).
const MSG_MODE: &str = "only octet mode is supported";
const MSG_TOO_LARGE: &str = "file too large";
const MSG_ILLEGAL: &str = "illegal TFTP operation";
const MSG_UNKNOWN_TID: &str = "unknown transfer ID";

/// The ERROR 5 packet for a datagram from a foreign TID. The transfer in
/// progress carries on (RFC 1350 §4).
#[must_use]
pub fn foreign_tid_error() -> Vec<u8> {
    encode_error(ErrorCode::UnknownTransferId, MSG_UNKNOWN_TID)
}

/// The error code of a client ERROR on a transfer socket, read leniently:
/// any datagram of at least 4 octets with opcode 5 counts, whatever follows
/// the code (missing NUL, embedded NULs, no message at all). Used only for
/// packets from the client's own TID, never on port 69 and never by
/// [`parse`], which stays strict (finding BOOT-005).
///
// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - a client abort ends
//   the transfer at once instead of after the retry cap.
// - RFC 1350 §5 (ERROR layout), §7 (an ERROR ends the transfer)
fn lenient_error_code(pkt: &[u8]) -> Option<u16> {
    let [op_hi, op_lo, code_hi, code_lo, ..] = *pkt else {
        return None;
    };
    (u16::from_be_bytes([op_hi, op_lo]) == Opcode::Error.code())
        .then(|| u16::from_be_bytes([code_hi, code_lo]))
}

fn after(now: Instant, d: Duration) -> Instant {
    now.checked_add(d).unwrap_or(now)
}

/// Decides whether to start a read transfer of `data`, the verified file
/// bytes (the same slice must be passed to every later call).
///
/// Checks, in order: mode is `octet` (else ERROR 4); `file_len` is at most
/// `max_file_size` (else ERROR 3); option negotiation; the DATA packet
/// count `file_len / block_size + 1` is at most 65535 (else ERROR 3, before
/// any OACK or DATA; REQ-BOOT-035). The `+ 1` is the final short block,
/// which is empty when the size is an exact multiple (RFC 2348).
///
/// The caller has already matched the filename to a published, verified
/// file; WRQ is refused by the caller with ERROR 2 before any file access.
#[must_use]
pub fn admit_read(
    req: &ReadRequest<'_>,
    data: &[u8],
    cfg: &ServerConfig,
    now: Instant,
) -> Admission {
    let file_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
    if req.mode_kind() != Mode::Octet {
        return Admission::Refuse {
            error: encode_error(ErrorCode::IllegalOperation, MSG_MODE),
            reason: RefuseReason::UnsupportedMode,
        };
    }
    let too_large = |reason| Admission::Refuse {
        error: encode_error(ErrorCode::DiskFull, MSG_TOO_LARGE),
        reason,
    };
    if file_len > cfg.max_file_size {
        return too_large(RefuseReason::FileTooLarge);
    }
    let neg = negotiate(&req.options, file_len, cfg.max_block_size);
    let blocks = file_len / u64::from(neg.block_size) + 1;
    let Ok(last_block) = u16::try_from(blocks) else {
        return too_large(RefuseReason::TooManyBlocks);
    };
    if u64::from(last_block) > MAX_BLOCKS {
        return too_large(RefuseReason::TooManyBlocks);
    }
    let mut t = ReadTransfer {
        neg,
        file_len,
        last_block,
        current: if neg.needs_oack() { 0 } else { 1 },
        established: false,
        retries: 0,
        total_retransmits: 0,
        rto: Rto::new(cfg.initial_rto, cfg.min_rto, cfg.max_rto),
        sent_at: now,
        resent: false,
        next_timeout: now,
        hard_deadline: after(now, cfg.max_duration),
        max_retries: cfg.max_retries,
        handshake_retries: cfg.handshake_retries,
        outcome: None,
    };
    let first = match t.send_current(data, now) {
        Step::Send(p) => p,
        // Unreachable for a consistent slice; fail closed with a refusal.
        _ => return too_large(RefuseReason::FileTooLarge),
    };
    Admission::Accept {
        transfer: Box::new(t),
        first,
    }
}

/// One read transfer in progress.
#[derive(Debug, Clone)]
pub struct ReadTransfer {
    neg: Negotiated,
    file_len: u64,
    /// Number of the final DATA block (1..=65535).
    last_block: u16,
    /// Packet outstanding: 0 = OACK, n = DATA n.
    current: u16,
    established: bool,
    /// Resends of the current packet.
    retries: u8,
    total_retransmits: u32,
    rto: Rto,
    sent_at: Instant,
    /// Karn's rule: no RTT sample from a resent packet.
    resent: bool,
    next_timeout: Instant,
    hard_deadline: Instant,
    max_retries: u8,
    handshake_retries: u8,
    outcome: Option<Outcome>,
}

impl ReadTransfer {
    fn oack(&self) -> Vec<u8> {
        let pairs = self.neg.oack_pairs();
        let refs: Vec<(&[u8], &[u8])> = pairs.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        encode_oack(&refs)
    }

    fn data_matches(&self, data: &[u8]) -> bool {
        u64::try_from(data.len()).is_ok_and(|l| l == self.file_len)
    }

    /// The packet for `block` (0 = OACK).
    fn packet(&self, block: u16, data: &[u8]) -> Option<Vec<u8>> {
        if block == 0 {
            return Some(self.oack());
        }
        let bs = u64::from(self.neg.block_size);
        let start = u64::from(block - 1).checked_mul(bs)?;
        let end = start.checked_add(bs)?.min(self.file_len);
        let start = usize::try_from(start).ok()?;
        let end = usize::try_from(end).ok()?;
        Some(encode_data(block, data.get(start..end)?))
    }

    fn finish(&mut self, o: Outcome) -> Step {
        self.outcome = Some(o);
        Step::Done(o)
    }

    fn send_current(&mut self, data: &[u8], now: Instant) -> Step {
        match self.packet(self.current, data) {
            Some(p) => {
                self.sent_at = now;
                self.next_timeout = after(now, self.rto.current());
                Step::Send(p)
            }
            None => self.finish(Outcome::Failed(FailReason::DataMismatch)),
        }
    }

    /// Handles a datagram from the client's TID.
    ///
    /// - ERROR (opcode 5 and at least 4 octets, even if the message is not
    ///   NUL-terminated): ends the transfer without a reply. The framing is
    ///   not checked here because the datagram already comes from the
    ///   client's TID (BOOT-005);
    /// - otherwise malformed: ignored ([`Step::Wait`]);
    /// - ACK of the outstanding packet: next block, or [`Outcome::Completed`]
    ///   after the final block;
    /// - any other ACK (duplicate or future): ignored. A duplicate ACK
    ///   never causes a resend (RFC 1123 §4.2.3.1);
    /// - DATA, RRQ, WRQ or OACK: ERROR 4 and abort.
    pub fn on_packet(&mut self, pkt: &[u8], data: &[u8], now: Instant) -> Step {
        if let Some(o) = self.outcome {
            return Step::Done(o);
        }
        if !self.data_matches(data) {
            return self.finish(Outcome::Failed(FailReason::DataMismatch));
        }
        if let Some(code) = lenient_error_code(pkt) {
            return self.finish(Outcome::AbortedByClient { code });
        }
        let Ok(p) = parse(pkt) else {
            return Step::Wait;
        };
        match p {
            Packet::Ack { block } => self.on_ack(block, data, now),
            Packet::Error { code, .. } => self.finish(Outcome::AbortedByClient { code }),
            Packet::Data { .. } | Packet::Rrq(_) | Packet::Wrq(_) | Packet::Oack(_) => {
                let outcome = Outcome::Failed(FailReason::IllegalOperation);
                self.outcome = Some(outcome);
                Step::Abort {
                    error: encode_error(ErrorCode::IllegalOperation, MSG_ILLEGAL),
                    outcome,
                }
            }
        }
    }

    fn on_ack(&mut self, block: u16, data: &[u8], now: Instant) -> Step {
        if block != self.current {
            return Step::Wait;
        }
        if !self.resent {
            self.rto.sample(now.saturating_duration_since(self.sent_at));
        }
        self.established = true;
        if block == self.last_block {
            return self.finish(Outcome::Completed);
        }
        let Some(next) = block.checked_add(1) else {
            return self.finish(Outcome::Failed(FailReason::DataMismatch));
        };
        self.current = next;
        self.retries = 0;
        self.resent = false;
        self.send_current(data, now)
    }

    /// Handles the timer. Before [`Self::deadline`] this is a no-op
    /// ([`Step::Wait`]). After it: give up at the hard deadline or the
    /// retry cap, otherwise back off and resend the outstanding packet.
    pub fn on_timeout(&mut self, data: &[u8], now: Instant) -> Step {
        if let Some(o) = self.outcome {
            return Step::Done(o);
        }
        if !self.data_matches(data) {
            return self.finish(Outcome::Failed(FailReason::DataMismatch));
        }
        if now >= self.hard_deadline {
            return self.finish(Outcome::Failed(FailReason::MaxDurationExceeded));
        }
        if now < self.next_timeout {
            return Step::Wait;
        }
        let cap = if self.established {
            self.max_retries
        } else {
            self.handshake_retries
        };
        if self.retries >= cap {
            return self.finish(Outcome::Failed(FailReason::RetryCapReached));
        }
        self.retries = self.retries.saturating_add(1);
        self.total_retransmits = self.total_retransmits.saturating_add(1);
        self.resent = true;
        self.rto.backoff();
        self.send_current(data, now)
    }

    /// When the caller must next call [`Self::on_timeout`]: the earlier of
    /// the retransmit timer and the hard deadline.
    #[must_use]
    pub fn deadline(&self) -> Instant {
        self.next_timeout.min(self.hard_deadline)
    }

    /// Final outcome, once ended.
    #[must_use]
    pub fn outcome(&self) -> Option<Outcome> {
        self.outcome
    }

    /// Current phase.
    #[must_use]
    pub fn phase(&self) -> Phase {
        if self.outcome.is_some() {
            Phase::Finished
        } else if self.established {
            Phase::Established
        } else {
            Phase::Handshake
        }
    }

    /// Negotiated block size.
    #[must_use]
    pub fn block_size(&self) -> u16 {
        self.neg.block_size
    }

    /// The `tsize` value acknowledged in the OACK, if any.
    #[must_use]
    pub fn tsize(&self) -> Option<u64> {
        self.neg.tsize
    }

    /// Whether an OACK was sent.
    #[must_use]
    pub fn sent_oack(&self) -> bool {
        self.neg.needs_oack()
    }

    /// Number of the final DATA block.
    #[must_use]
    pub fn last_block(&self) -> u16 {
        self.last_block
    }

    /// Number of the packet currently outstanding (0 = OACK).
    #[must_use]
    pub fn current_block(&self) -> u16 {
        self.current
    }

    /// Total resends over the whole transfer.
    #[must_use]
    pub fn retransmits(&self) -> u32 {
        self.total_retransmits
    }

    /// Resends of the packet currently outstanding.
    #[must_use]
    pub fn current_retries(&self) -> u8 {
        self.retries
    }

    /// The file length admitted.
    #[must_use]
    pub fn file_len(&self) -> u64 {
        self.file_len
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{Opcode, encode_ack, encode_request};

    fn rrq(opts: &[(&[u8], &[u8])]) -> Vec<u8> {
        encode_request(Opcode::Rrq, b"usgp-test-payload.efi", b"octet", opts)
    }

    fn admit(pkt: &[u8], data: &[u8], cfg: &ServerConfig, now: Instant) -> Admission {
        let Ok(Packet::Rrq(r)) = parse(pkt) else {
            panic!("not an RRQ")
        };
        admit_read(&r, data, cfg, now)
    }

    fn accept(pkt: &[u8], data: &[u8], now: Instant) -> (Box<ReadTransfer>, Vec<u8>) {
        match admit(pkt, data, &ServerConfig::default(), now) {
            Admission::Accept { transfer, first } => (transfer, first),
            Admission::Refuse { reason, .. } => panic!("refused: {reason:?}"),
        }
    }

    fn file(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    /// Drives a whole transfer with immediate ACKs; returns the
    /// reassembled bytes.
    fn download(t: &mut ReadTransfer, first: Vec<u8>, data: &[u8], now: Instant) -> Vec<u8> {
        let mut out = Vec::new();
        let mut pkt = first;
        loop {
            let block = match parse(&pkt).unwrap() {
                Packet::Oack(_) => 0,
                Packet::Data { block, data: d } => {
                    out.extend_from_slice(d);
                    block
                }
                other => panic!("unexpected {other:?}"),
            };
            match t.on_packet(&encode_ack(block), data, now) {
                Step::Send(p) => pkt = p,
                Step::Done(Outcome::Completed) => return out,
                other => panic!("unexpected step {other:?}"),
            }
        }
    }

    #[test]
    fn octet_rrq_full_download() {
        let data = file(5632);
        let now = Instant::now();
        let (mut t, first) = accept(&rrq(&[(b"blksize", b"1468"), (b"tsize", b"0")]), &data, now);
        assert_eq!(download(&mut t, first, &data, now), data);
        assert_eq!(t.phase(), Phase::Finished);
        assert_eq!(
            t.on_packet(&encode_ack(4), &data, now),
            Step::Done(Outcome::Completed)
        );
    }

    #[test]
    fn rrq_no_options_data1_512() {
        let data = file(1000);
        let now = Instant::now();
        let (mut t, first) = accept(&rrq(&[]), &data, now);
        assert!(!t.sent_oack());
        assert_eq!(
            parse(&first),
            Ok(Packet::Data {
                block: 1,
                data: data.get(..512).unwrap()
            })
        );
        assert_eq!(download(&mut t, first, &data, now), data);
    }

    #[test]
    fn rrq_blksize_tsize_oack() {
        let data = file(5632);
        let (t, first) = accept(
            &rrq(&[(b"tsize", b"0"), (b"blksize", b"1428")]),
            &data,
            Instant::now(),
        );
        let Ok(Packet::Oack(l)) = parse(&first) else {
            panic!("no OACK")
        };
        assert_eq!(l.get(b"blksize"), Some(&b"1428"[..]));
        assert_eq!(l.get(b"tsize"), Some(&b"5632"[..]));
        assert_eq!(t.block_size(), 1428);
        assert_eq!(t.tsize(), Some(5632));
        assert_eq!(t.current_block(), 0);
    }

    #[test]
    fn unknown_option_ignored() {
        let data = file(10);
        let (t, first) = accept(&rrq(&[(b"x-vendor", b"1")]), &data, Instant::now());
        assert!(!t.sent_oack());
        assert!(matches!(parse(&first), Ok(Packet::Data { block: 1, .. })));
    }

    #[test]
    fn timeout_option_not_acked() {
        let data = file(10);
        let (_, first) = accept(
            &rrq(&[(b"timeout", b"5"), (b"tsize", b"0")]),
            &data,
            Instant::now(),
        );
        let Ok(Packet::Oack(l)) = parse(&first) else {
            panic!("no OACK")
        };
        assert_eq!(l.get(b"timeout"), None);
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn netascii_refused() {
        let pkt = encode_request(Opcode::Rrq, b"f", b"netascii", &[]);
        match admit(&pkt, &file(1), &ServerConfig::default(), Instant::now()) {
            Admission::Refuse { error, reason } => {
                assert_eq!(reason, RefuseReason::UnsupportedMode);
                assert!(matches!(parse(&error), Ok(Packet::Error { code: 4, .. })));
            }
            Admission::Accept { .. } => panic!("accepted netascii"),
        }
    }

    #[test]
    fn block_count_65535_ok_65536_refused() {
        let cfg = ServerConfig {
            max_file_size: u64::MAX,
            max_block_size: 1468,
            ..ServerConfig::default()
        };
        for (bs, opts) in [
            (512usize, vec![]),
            (1468, vec![(&b"blksize"[..], &b"1468"[..])]),
        ] {
            let pkt = rrq(&opts);
            let ok = vec![0u8; 65535 * bs - 1];
            match admit(&pkt, &ok, &cfg, Instant::now()) {
                Admission::Accept { transfer, .. } => assert_eq!(transfer.last_block(), 65535),
                Admission::Refuse { reason, .. } => panic!("refused {bs}: {reason:?}"),
            }
            let too_many = vec![0u8; 65535 * bs];
            match admit(&pkt, &too_many, &cfg, Instant::now()) {
                Admission::Refuse { error, reason } => {
                    assert_eq!(reason, RefuseReason::TooManyBlocks);
                    // refused_before_oack: the only packet is an ERROR.
                    assert!(matches!(parse(&error), Ok(Packet::Error { code: 3, .. })));
                }
                Admission::Accept { .. } => panic!("accepted 65536 blocks at {bs}"),
            }
        }
    }

    #[test]
    fn refused_before_oack() {
        let cfg = ServerConfig {
            max_file_size: u64::MAX,
            ..ServerConfig::default()
        };
        let pkt = rrq(&[(b"tsize", b"0")]);
        let data = vec![0u8; 65535 * 512];
        assert!(matches!(
            admit(&pkt, &data, &cfg, Instant::now()),
            Admission::Refuse {
                reason: RefuseReason::TooManyBlocks,
                ..
            }
        ));
    }

    #[test]
    fn retry_cap_aborts() {
        let data = file(2000);
        let t0 = Instant::now();
        let (mut t, _first) = accept(&rrq(&[]), &data, t0);
        // Handshake: 2 resends allowed, then give up (3 sends total).
        let mut now;
        let mut sends = 1;
        loop {
            now = t.deadline();
            match t.on_timeout(&data, now) {
                Step::Send(_) => sends += 1,
                Step::Done(o) => {
                    assert_eq!(o, Outcome::Failed(FailReason::RetryCapReached));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(sends, 3);
        assert_eq!(
            t.on_timeout(&data, now),
            Step::Done(Outcome::Failed(FailReason::RetryCapReached))
        );
    }

    #[test]
    fn retry_cap_after_established_uses_max_retries() {
        let data = file(2000);
        let t0 = Instant::now();
        let (mut t, _) = accept(&rrq(&[]), &data, t0);
        assert!(matches!(
            t.on_packet(&encode_ack(1), &data, t0),
            Step::Send(_)
        ));
        assert_eq!(t.phase(), Phase::Established);
        let mut resends = 0;
        loop {
            let now = t.deadline();
            match t.on_timeout(&data, now) {
                Step::Send(_) => resends += 1,
                Step::Done(_) => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(resends, 5);
        assert_eq!(t.retransmits(), 5);
    }

    #[test]
    fn karn_skip_retransmitted() {
        let data = file(2000);
        let t0 = Instant::now();
        let (mut t, _) = accept(&rrq(&[]), &data, t0);
        let rto0 = t.rto.current();
        let late = t.deadline();
        assert!(matches!(t.on_timeout(&data, late), Step::Send(_)));
        let backed_off = t.rto.current();
        assert_eq!(backed_off, rto0 * 2);
        // ACK of a resent packet: no RTT sample, RTO unchanged.
        let ack_at = late + Duration::from_millis(5);
        assert!(matches!(
            t.on_packet(&encode_ack(1), &data, ack_at),
            Step::Send(_)
        ));
        assert_eq!(t.rto.srtt(), None);
        assert_eq!(t.rto.current(), backed_off);
        // ACK of a packet sent once: sampled.
        let ack2 = ack_at + Duration::from_millis(40);
        assert!(matches!(
            t.on_packet(&encode_ack(2), &data, ack2),
            Step::Send(_)
        ));
        assert_eq!(t.rto.srtt(), Some(Duration::from_millis(40)));
    }

    #[test]
    fn early_timer_is_noop() {
        let data = file(10);
        let t0 = Instant::now();
        let (mut t, _) = accept(&rrq(&[]), &data, t0);
        assert_eq!(t.on_timeout(&data, t0), Step::Wait);
        assert_eq!(t.current_retries(), 0);
    }

    #[test]
    fn max_duration_ends_transfer() {
        let data = file(10_000);
        let t0 = Instant::now();
        let cfg = ServerConfig {
            max_duration: Duration::from_secs(10),
            ..ServerConfig::default()
        };
        let Admission::Accept { mut transfer, .. } = admit(&rrq(&[]), &data, &cfg, t0) else {
            panic!("refused")
        };
        let late = t0 + Duration::from_secs(11);
        assert_eq!(
            transfer.on_timeout(&data, late),
            Step::Done(Outcome::Failed(FailReason::MaxDurationExceeded))
        );
    }

    #[test]
    fn wrong_data_slice_fails_closed() {
        let data = file(100);
        let (mut t, _) = accept(&rrq(&[]), &data, Instant::now());
        assert_eq!(
            t.on_packet(&encode_ack(1), data.get(..99).unwrap(), Instant::now()),
            Step::Done(Outcome::Failed(FailReason::DataMismatch))
        );
    }

    #[test]
    fn unterminated_client_error_ends_transfer() {
        // BOOT-005: a client abort without the terminating NUL (or with a
        // stray NUL inside) still ends the transfer, after OACK and after
        // DATA, and does not wait for the retry cap.
        let data = file(2000);
        for (pkt, code) in [
            (&[0u8, 5, 0, 0][..], 0u16),
            (&[0, 5, 0, 8, b'x'], 8),
            (&[0, 5, 0, 1, b'a', 0, b'b'], 1),
            (&[0, 5, 0, 0, 0], 0),
        ] {
            let now = Instant::now();
            let (mut t, _) = accept(&rrq(&[(b"tsize", b"0")]), &data, now);
            assert!(t.sent_oack());
            assert_eq!(
                t.on_packet(pkt, &data, now),
                Step::Done(Outcome::AbortedByClient { code })
            );
            assert_eq!(t.phase(), Phase::Finished);
            assert_eq!(
                t.on_timeout(&data, now),
                Step::Done(Outcome::AbortedByClient { code })
            );

            let (mut t, _) = accept(&rrq(&[]), &data, now);
            assert!(matches!(
                t.on_packet(&encode_ack(1), &data, now),
                Step::Send(_)
            ));
            assert_eq!(
                t.on_packet(pkt, &data, now),
                Step::Done(Outcome::AbortedByClient { code })
            );
        }
    }

    #[test]
    fn short_or_other_malformed_still_ignored() {
        // Fewer than 4 octets, or another opcode, stays "malformed, ignore".
        let data = file(2000);
        let now = Instant::now();
        let (mut t, _) = accept(&rrq(&[]), &data, now);
        for pkt in [&[0u8, 5][..], &[0, 5, 0], &[0, 4, 0], &[0, 4, 0, 1, 2], &[]] {
            assert_eq!(t.on_packet(pkt, &data, now), Step::Wait, "{pkt:?}");
        }
        assert_eq!(t.phase(), Phase::Handshake);
    }

    #[test]
    fn strict_parse_unchanged_for_unterminated_error() {
        // Port 69 and the fuzz round trip keep the strict parser.
        assert!(parse(&[0, 5, 0, 0]).is_err());
        assert!(parse(&[0, 5, 0, 1, b'a', 0, b'b']).is_err());
    }
}
