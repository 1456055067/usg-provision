//! Fuzz target `tftp_window`: the windowed read transfer (RFC 7440) with
//! block-number wraparound (`usgp-tftp` `admit_read_with`, `ReadTransfer`),
//! driven by arbitrary ACKs, timer calls and window draining.
//!
//! Script (our design, WU-14):
//!
//! ```text
//! [0..3]  file length, u24 little-endian, at most MAX_FILE (file bytes
//!         are i % 251)
//! [3..5]  max_window_size, u16 little-endian (any value; clamped by the
//!         crate)
//! [5]     bits 0-1 wrap (0 zero, 1 one, 2 off, 3 zero); bits 2-4
//!         max_retries; bits 5-6 handshake_retries; bit 7 set:
//!         max_file_size = file length - 1 (else 1 GiB)
//! [6]     bits 0-2 index into BLOCK_SIZE_CAPS (max_block_size); bits 3-7
//!         max_duration in units of 20 s
//! [7]     n = RRQ length, then n octets parsed as the RRQ
//! ops     one octet each: low 3 bits = op, high 5 bits = arg
//!         0 drain: timer calls while blocks of the window are pending
//!         1 ACK the highest block sent              (time += arg ms)
//!         2 ACK block acked + 1 + arg (modulo the blocks in flight)
//!         3 ACK the wire number in the next 2 octets (big-endian)
//!         4 timer at the transfer deadline
//!         5 timer at now + arg * 100 ms (may be early)
//!         6 run: (arg + 1) * 64 rounds of drain + ACK the highest block
//!           (or ACK 0 while the OACK is outstanding)
//!         7 arg < 16: client ERROR with code arg; else ACK of the stale
//!           block acked - (arg - 16)
//! ```
//!
//! Invariants (impl-notes-wu6 "For WU-14"):
//!
//! - no panic; admission refuses exactly the non-octet modes, files over
//!   `min(max_file_size, 4 GiB - 1)` and, without wraparound, files of
//!   more than 65535 blocks; the final block index is `len / bs + 1`;
//! - every DATA block's wire number is `block_wrap().wire(index)` for an
//!   index in the current window (`acked + 1 ..= acked + window`), never
//!   past the final block and never leaving a gap; its payload is the
//!   file slice for that index (full blocks, then one short final block);
//! - blocks in flight never exceed the window: `sent - acked <= window
//!   <= 64`; `acked_index` never decreases;
//! - an ACK that does not raise `acked_index` produces no `Send` (except
//!   ACK 0 of the OACK); a timer call before the deadline with nothing
//!   pending is `Wait`; retries stay within the cap of the phase;
//! - `wraps()` is `block_wrap().wraps_by(highest sent)`;
//! - `Done` is final; `Completed` only after the final block is
//!   acknowledged, and the reassembled payload equals the file.

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SC-5
//   (Denial-of-Service Protection), SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-032,
//   #REQ-BOOT-035, #REQ-BOOT-064
// - RFC 7440 §3, §4 - windowsize; RFC 1350 §2, §6; RFC 1123 §4.2.3.1;
//   RFC 2348 - final short block; specs/standards/tftp.md §8 (wraparound)

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use usgp_tftp::{
    Admission, BlockWrap, MAX_BLOCKS, MAX_FILE_SIZE_CEILING, MAX_WINDOW_SIZE, Mode, Outcome,
    Packet, Phase, ReadTransfer, RefuseReason, ServerConfig, Step, WindowConfig, admit_read_with,
    encode_ack, parse,
};

/// Largest file a script can ask for: room for two wraps at 8-byte blocks.
const MAX_FILE: usize = (1 << 20) + 64;

/// `max_block_size` values the script can select (8 reaches a wrap
/// quickly).
const BLOCK_SIZE_CAPS: [u16; 8] = [8, 512, 1468, 16, 65464, 0, 64, 1024];

/// Upper bound on script operations per input.
const MAX_OPS: usize = 1024;

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.0.len() {
            return None;
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Some(a)
    }
}

fn file(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

fn slice(data: &[u8], index: u64, bs: u16) -> &[u8] {
    let bs = u64::from(bs);
    let start = index.saturating_sub(1).saturating_mul(bs);
    let end = start
        .saturating_add(bs)
        .min(u64::try_from(data.len()).unwrap_or(u64::MAX));
    let (s, e) = (
        usize::try_from(start).unwrap_or(usize::MAX),
        usize::try_from(end).unwrap_or(usize::MAX),
    );
    data.get(s..e).unwrap_or(&[])
}

/// What the client side has seen.
struct Model<'a> {
    data: &'a [u8],
    first: Vec<u8>,
    bs: u16,
    wrap: BlockWrap,
    last: u64,
    window: u64,
    max_retries: u8,
    handshake_retries: u8,
    /// Highest DATA index sent.
    sent_hi: u64,
    received: Vec<u8>,
    done: Option<Outcome>,
}

impl Model<'_> {
    /// Checks one DATA packet; returns its index.
    fn data(&mut self, t: &ReadTransfer, pkt: &[u8]) -> u64 {
        let Ok(Packet::Data { block, data: d }) = parse(pkt) else {
            panic!("sent packet is not DATA");
        };
        let acked = t.acked_index();
        let hi = acked.saturating_add(self.window).min(self.last);
        let Some(i) = (acked + 1..=hi).find(|&i| self.wrap.wire(i) == block) else {
            panic!("DATA {block} outside the window after {acked}");
        };
        assert!(
            i <= self.sent_hi + 1,
            "DATA {i} leaves a gap after {}",
            self.sent_hi
        );
        assert_eq!(d, slice(self.data, i, self.bs), "DATA {i} payload differs");
        if i < self.last {
            assert_eq!(d.len(), usize::from(self.bs), "short non-final block");
        } else {
            assert!(d.len() < usize::from(self.bs), "final block not short");
        }
        if i == self.sent_hi + 1 {
            self.received.extend_from_slice(d);
            self.sent_hi = i;
        }
        assert!(
            self.sent_hi - acked <= self.window,
            "more blocks in flight than the window"
        );
        i
    }

    /// Checks the step `s` of the call described by `c`.
    fn step(&mut self, t: &ReadTransfer, s: &Step, c: &Call) {
        let Call {
            acked_before,
            oack_before,
            ack,
            timer,
            quiet,
        } = *c;
        if let Some(o) = self.done {
            assert_eq!(*s, Step::Done(o), "Done is not final");
            assert_eq!(t.phase(), Phase::Finished);
            return;
        }
        let acked = t.acked_index();
        assert!(acked >= acked_before, "acked_index went back");
        assert!(acked <= self.sent_hi, "ACK of a block never sent accepted");
        match s {
            Step::Send(p) => {
                if oack_before && timer {
                    assert_eq!(*p, self.first, "OACK resend differs");
                } else {
                    if let Some(b) = ack
                        && acked == acked_before
                    {
                        assert!(oack_before && b == 0, "Send on an ACK that did not advance");
                    }
                    self.data(t, p);
                }
            }
            Step::Wait => {}
            Step::Abort { .. } => panic!("Abort without an illegal packet"),
            Step::Done(o) => {
                if *o == Outcome::Completed {
                    assert_eq!(acked, self.last, "completed before the final ACK");
                    assert_eq!(self.sent_hi, self.last, "completed before the final DATA");
                    assert_eq!(self.received, self.data, "reassembled payload differs");
                }
                self.done = Some(*o);
            }
        }
        if timer && quiet {
            assert_eq!(*s, Step::Wait, "timer before the deadline did something");
        }
        if self.done.is_none() {
            let cap = match t.phase() {
                Phase::Established => self.max_retries,
                _ => self.handshake_retries,
            };
            assert!(t.current_retries() <= cap, "retries over the cap");
            assert_eq!(t.wraps(), self.wrap.wraps_by(self.sent_hi), "wraps");
            if !(t.sent_oack() && t.current_index() == 0) {
                assert_eq!(t.current_block(), self.wrap.wire(t.current_index()));
            }
        } else {
            assert_eq!(t.phase(), Phase::Finished);
            assert_eq!(t.outcome(), self.done);
        }
    }
}

/// One call into the transfer, as seen before it was made.
#[derive(Clone, Copy)]
struct Call {
    /// `acked_index()` before the call.
    acked_before: u64,
    /// The OACK was outstanding.
    oack_before: bool,
    /// The wire number ACKed, if the call delivered an ACK.
    ack: Option<u16>,
    /// A timer call.
    timer: bool,
    /// A timer call before the deadline with nothing pending.
    quiet: bool,
}

struct Run<'a> {
    t: Box<ReadTransfer>,
    m: Model<'a>,
    data: &'a [u8],
    now: Instant,
}

impl Run<'_> {
    fn oack_outstanding(&self) -> bool {
        self.t.sent_oack() && self.t.current_index() == 0 && self.t.outcome().is_none()
    }

    fn call(&self, ack: Option<u16>, timer: bool) -> Call {
        Call {
            acked_before: self.t.acked_index(),
            oack_before: self.oack_outstanding(),
            ack,
            timer,
            quiet: timer
                && !self.t.pending_sends()
                && self.t.outcome().is_none()
                && self.now < self.t.deadline(),
        }
    }

    fn ack(&mut self, block: u16) {
        let c = self.call(Some(block), false);
        let s = self.t.on_packet(&encode_ack(block), self.data, self.now);
        self.m.step(&self.t, &s, &c);
    }

    fn packet(&mut self, pkt: &[u8]) -> Step {
        let c = self.call(None, false);
        let s = self.t.on_packet(pkt, self.data, self.now);
        self.m.step(&self.t, &s, &c);
        s
    }

    fn timer(&mut self, at: Instant) {
        self.now = self.now.max(at);
        let c = self.call(None, true);
        let s = self.t.on_timeout(self.data, self.now);
        self.m.step(&self.t, &s, &c);
    }

    fn drain(&mut self) {
        for _ in 0..=MAX_WINDOW_SIZE {
            if !self.t.pending_sends() {
                break;
            }
            self.timer(self.now);
        }
    }

    fn highest(&self) -> u16 {
        self.m.wrap.wire(self.m.sent_hi)
    }
}

fn admit_ok(req_mode: Mode, len: u64, cfg: &ServerConfig, wrap: BlockWrap, a: &Admission) -> bool {
    match a {
        Admission::Refuse { error, reason } => {
            assert!(
                matches!(parse(error), Ok(Packet::Error { .. })),
                "refusal not ERROR"
            );
            match reason {
                RefuseReason::UnsupportedMode => assert_ne!(req_mode, Mode::Octet),
                RefuseReason::FileTooLarge => {
                    assert!(
                        len > cfg.max_file_size.min(MAX_FILE_SIZE_CEILING),
                        "too large"
                    );
                }
                RefuseReason::TooManyBlocks => assert_eq!(wrap, BlockWrap::Off),
            }
            false
        }
        Admission::Accept { transfer, .. } => {
            assert_eq!(req_mode, Mode::Octet, "non-octet mode accepted");
            assert!(
                len <= cfg.max_file_size.min(MAX_FILE_SIZE_CEILING),
                "file too large"
            );
            let last = transfer.last_index();
            assert_eq!(
                last,
                len / u64::from(transfer.block_size()) + 1,
                "final index"
            );
            if wrap == BlockWrap::Off {
                assert!(last <= MAX_BLOCKS, "more than 65535 blocks without wrap");
            }
            true
        }
    }
}

fuzz_target!(|script: &[u8]| {
    let mut c = Cursor(script);
    let (Some(l0), Some(l1), Some(l2), Some(w0), Some(w1), Some(a), Some(b), Some(n)) = (
        c.u8(),
        c.u8(),
        c.u8(),
        c.u8(),
        c.u8(),
        c.u8(),
        c.u8(),
        c.u8(),
    ) else {
        return;
    };
    let Some(rrq) = c.take(usize::from(n)) else {
        return;
    };
    let Ok(Packet::Rrq(req)) = parse(rrq) else {
        return;
    };
    let len = usize::try_from(u32::from_le_bytes([l0, l1, l2, 0])).unwrap_or(0) % (MAX_FILE + 1);
    let data = file(len);
    let len64 = u64::try_from(len).unwrap_or(u64::MAX);
    let wrap = match a & 3 {
        1 => BlockWrap::One,
        2 => BlockWrap::Off,
        _ => BlockWrap::Zero,
    };
    let cfg = ServerConfig {
        max_block_size: BLOCK_SIZE_CAPS[usize::from(b & 7)],
        max_retries: (a >> 2) & 7,
        handshake_retries: (a >> 5) & 3,
        max_duration: Duration::from_secs(u64::from(b >> 3) * 20),
        max_file_size: if a & 0x80 != 0 {
            len64.saturating_sub(1)
        } else {
            1 << 30
        },
        ..ServerConfig::default()
    };
    let win = WindowConfig {
        max_window_size: u16::from_le_bytes([w0, w1]),
        block_wrap: wrap,
    };
    let t0 = Instant::now();
    let adm = admit_read_with(&req, &data, &cfg, &win, t0);
    if !admit_ok(req.mode_kind(), len64, &cfg, wrap, &adm) {
        return;
    }
    let Admission::Accept { transfer, first } = adm else {
        return;
    };
    let window = u64::from(transfer.window_size());
    assert!(
        (1..=u64::from(MAX_WINDOW_SIZE)).contains(&window),
        "window {window}"
    );
    assert!(
        window <= u64::from(win.max_window_size.clamp(1, MAX_WINDOW_SIZE)),
        "window over the configured maximum"
    );
    assert_eq!(transfer.block_wrap(), wrap);
    let bs = transfer.block_size();
    assert!((8..=65464).contains(&bs), "block size {bs}");
    let mut m = Model {
        data: &data,
        first: first.clone(),
        bs,
        wrap,
        last: transfer.last_index(),
        window,
        max_retries: cfg.max_retries,
        handshake_retries: cfg.handshake_retries,
        sent_hi: 0,
        received: Vec::new(),
        done: None,
    };
    if transfer.sent_oack() {
        assert!(
            matches!(parse(&first), Ok(Packet::Oack(_))),
            "first is not OACK"
        );
    } else {
        assert_eq!(m.data(&transfer, &first), 1, "first DATA is not block 1");
    }
    let mut r = Run {
        t: transfer,
        m,
        data: &data,
        now: t0,
    };
    for _ in 0..MAX_OPS {
        let Some(op) = c.u8() else { break };
        let arg = op >> 3;
        match op & 7 {
            0 => r.drain(),
            1 => {
                r.now += Duration::from_millis(u64::from(arg));
                let h = r.highest();
                r.ack(h);
            }
            2 => {
                let acked = r.t.acked_index();
                let span = r.m.sent_hi.saturating_sub(acked).max(1);
                let i = acked + 1 + u64::from(arg) % span;
                r.now += Duration::from_millis(1);
                r.ack(r.m.wrap.wire(i));
            }
            3 => {
                let (Some(hi), Some(lo)) = (c.u8(), c.u8()) else {
                    break;
                };
                r.ack(u16::from_be_bytes([hi, lo]));
            }
            4 => {
                let d = r.t.deadline();
                r.timer(d);
            }
            5 => {
                let at = r.now + Duration::from_millis(u64::from(arg) * 100);
                r.timer(at);
            }
            6 => {
                for _ in 0..(usize::from(arg) + 1) * 64 {
                    if r.t.outcome().is_some() {
                        break;
                    }
                    if r.oack_outstanding() {
                        r.ack(0);
                        continue;
                    }
                    r.drain();
                    let h = r.highest();
                    r.ack(h);
                }
            }
            _ => {
                if arg < 16 {
                    let was_done = r.m.done.is_some();
                    let s = r.packet(&[0, 5, 0, arg, b'x', 0]);
                    if !was_done {
                        assert_eq!(
                            s,
                            Step::Done(Outcome::AbortedByClient {
                                code: u16::from(arg)
                            }),
                            "client ERROR did not end the transfer"
                        );
                    }
                } else {
                    let back = u64::from(arg - 16);
                    let i = r.t.acked_index().saturating_sub(back);
                    r.ack(r.m.wrap.wire(i));
                }
            }
        }
    }
});
