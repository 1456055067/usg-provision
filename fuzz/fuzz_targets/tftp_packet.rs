//! Fuzz target `tftp_packet`: TFTP packet parsing and the read-transfer
//! state machine.
//!
//! The first input byte is a selector. Even: the rest is one packet for
//! `parse`; a parsed packet must round-trip through `Packet::encode`.
//! Odd: the rest is a transfer script (format below) that drives
//! `admit_read` and a `ReadTransfer` with packets and timer expiries.
//!
//! Transfer script (our design, WU-8):
//!
//! ```text
//! [0..2]  file length, u16 little-endian (file bytes are i % 251)
//! [2]     bits 0-2 max_retries, bits 3-4 handshake_retries,
//!         bits 5-7 index into BLOCK_SIZE_CAPS (max_block_size)
//! [3]     bit 0 set: max_file_size = file length - 1 (else default);
//!         bits 1-7 max_duration in seconds
//! [4]     n = RRQ length, then n octets parsed as the RRQ
//! ops     one octet each: low 3 bits = op, high 5 bits = arg
//!         0 ACK the outstanding block        (time += arg ms)
//!         1 ACK the outstanding block - 1    (time += arg ms)
//!         2 ACK the outstanding block + 1    (time += arg ms)
//!         3 ACK the block in the next 2 octets (big-endian)
//!         4 timer at the transfer deadline
//!         5 timer at now + arg * 100 ms (may be early)
//!         6 time += arg * 10 ms; next octet m, then m raw octets to on_packet
//!         7 arg < 16: client ERROR with code arg; else a wrong file slice
//! ```
//!
//! Invariants (plan §10.4): no panic; DATA block numbers increase strictly
//! (a timer resend repeats the outstanding block) and never exceed the
//! final block (at most 65535); a duplicate or other non-matching ACK never
//! produces `Send`; retries stay within the cap of the phase; `Done` (and
//! the outcome of `Abort`) is final. Every DATA payload equals the file
//! slice for its block (REQ-BOOT-035: never a corrupt or truncated file).

#![no_main]

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SC-5
//   (Denial-of-Service Protection), SA-11 (Developer Testing and
//   Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-031,
//   #REQ-BOOT-032, #REQ-BOOT-035
// - RFC 1350 §2, §6 - lock-step, block numbers; RFC 1123 §4.2.3.1 -
//   no resend on duplicate ACK; RFC 2347, RFC 2348 - OACK, block size

use std::time::{Duration, Instant};

use libfuzzer_sys::fuzz_target;
use usgp_tftp::{
    Admission, FailReason, MAX_BLOCKS, Outcome, Packet, Phase, ReadTransfer, ServerConfig, Step,
    admit_read, encode_ack, parse,
};

/// `max_block_size` values the script can select, including values outside
/// the 8..=65464 clamp range.
const BLOCK_SIZE_CAPS: [u16; 8] = [512, 1468, 8, 65464, 1024, 0, 7, 65535];

/// Upper bound on script operations per input.
const MAX_OPS: usize = 4096;

fuzz_target!(|input: &[u8]| {
    let Some((&selector, rest)) = input.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        round_trip(rest);
    } else {
        transfer(rest);
    }
});

fn round_trip(buf: &[u8]) {
    let Ok(p) = parse(buf) else { return };
    let enc = p.encode();
    let again = parse(&enc);
    assert_eq!(again, Ok(p), "parse(encode(p)) != p");
    if let Ok(q) = again {
        assert_eq!(q.encode(), enc, "encoding not stable");
    }
}

/// Byte cursor over the script.
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
    fn u16_le(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes([self.u8()?, self.u8()?]))
    }
    fn u16_be(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }
}

fn file(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect()
}

/// The bytes block `block` must carry.
fn expected_slice(data: &[u8], block: u16, bs: u16) -> &[u8] {
    let bs = usize::from(bs);
    let start = usize::from(block).saturating_sub(1).saturating_mul(bs);
    let end = start.saturating_add(bs).min(data.len());
    data.get(start..end).unwrap_or(&[])
}

/// Model of what the transfer has sent, checked against every `Step`.
struct Model<'a> {
    data: &'a [u8],
    first: Vec<u8>,
    block_size: u16,
    last_block: u16,
    max_retries: u8,
    handshake_retries: u8,
    /// Highest DATA block sent so far (0 = none).
    highest: u16,
    done: Option<Outcome>,
}

impl Model<'_> {
    fn check_data(&self, pkt: &[u8]) -> u16 {
        let Ok(Packet::Data { block, data: d }) = parse(pkt) else {
            panic!("sent packet is not DATA");
        };
        assert!(block >= 1, "DATA block 0");
        assert!(block <= self.last_block, "DATA {block} past final block");
        assert_eq!(
            d,
            expected_slice(self.data, block, self.block_size),
            "DATA {block} payload differs from the file"
        );
        if block < self.last_block {
            assert_eq!(
                d.len(),
                usize::from(self.block_size),
                "short non-final block"
            );
        } else {
            assert!(
                d.len() < usize::from(self.block_size),
                "final block not short"
            );
        }
        block
    }

    /// `prev` is the outstanding block before the call; `acked` is the
    /// block of the ACK delivered (None for timer calls and non-ACKs).
    fn check(&mut self, t: &ReadTransfer, step: &Step, prev: u16, acked: Option<u16>, timer: bool) {
        if let Some(o) = self.done {
            assert_eq!(*step, Step::Done(o), "Done is not final");
            assert_eq!(t.phase(), Phase::Finished);
            assert_eq!(t.outcome(), Some(o));
            return;
        }
        match step {
            Step::Send(p) if timer => {
                // A resend of the outstanding packet.
                if prev == 0 {
                    assert_eq!(*p, self.first, "timer resend differs from OACK");
                } else {
                    let b = self.check_data(p);
                    assert_eq!(b, prev, "timer resent a different block");
                }
                assert_eq!(t.current_block(), prev);
            }
            Step::Send(p) => {
                assert_eq!(
                    acked,
                    Some(prev),
                    "Send without an ACK of the outstanding block"
                );
                let b = self.check_data(p);
                assert_eq!(Some(b), prev.checked_add(1), "block did not advance by one");
                assert!(b > self.highest, "block numbers not strictly increasing");
                self.highest = b;
                assert_eq!(t.current_block(), b);
                assert_eq!(t.current_retries(), 0, "retries not reset on new block");
            }
            Step::Wait => {
                assert_eq!(t.current_block(), prev, "Wait moved the block");
            }
            Step::Abort { error, outcome } => {
                assert_eq!(*outcome, Outcome::Failed(FailReason::IllegalOperation));
                assert!(
                    matches!(parse(error), Ok(Packet::Error { code: 4, .. })),
                    "Abort without ERROR 4"
                );
                self.done = Some(*outcome);
            }
            Step::Done(o) => {
                if *o == Outcome::Completed {
                    assert_eq!(acked, Some(self.last_block), "completed without final ACK");
                    assert_eq!(prev, self.last_block);
                }
                self.done = Some(*o);
            }
        }
        if let Some(o) = self.done {
            assert_eq!(t.phase(), Phase::Finished);
            assert_eq!(t.outcome(), Some(o));
        } else {
            let cap = match t.phase() {
                Phase::Established => self.max_retries,
                _ => self.handshake_retries,
            };
            assert!(t.current_retries() <= cap, "retries over the cap");
        }
    }
}

fn transfer(script: &[u8]) {
    let mut c = Cursor(script);
    let (Some(len), Some(a), Some(b), Some(n)) = (c.u16_le(), c.u8(), c.u8(), c.u8()) else {
        return;
    };
    let Some(rrq) = c.take(usize::from(n)) else {
        return;
    };
    let Ok(Packet::Rrq(req)) = parse(rrq) else {
        return;
    };
    let data = file(usize::from(len));
    let mut wrong = data.clone();
    wrong.push(0);

    let caps_idx = usize::from(a >> 5);
    let cfg = ServerConfig {
        max_block_size: BLOCK_SIZE_CAPS.get(caps_idx).copied().unwrap_or(512),
        max_retries: a & 7,
        handshake_retries: (a >> 3) & 3,
        max_duration: Duration::from_secs(u64::from(b >> 1)),
        max_file_size: if b & 1 == 1 {
            u64::from(len).saturating_sub(1)
        } else {
            ServerConfig::default().max_file_size
        },
        ..ServerConfig::default()
    };

    let t0 = Instant::now();
    let (mut t, first) = match admit_read(&req, &data, &cfg, t0) {
        Admission::Refuse { error, .. } => {
            assert!(
                matches!(parse(&error), Ok(Packet::Error { .. })),
                "refusal is not an ERROR packet"
            );
            return;
        }
        Admission::Accept { transfer, first } => (transfer, first),
    };

    let bs = t.block_size();
    assert!(
        (8..=65464).contains(&bs),
        "block size {bs} outside RFC 2348 range"
    );
    let last = t.last_block();
    assert!(
        last >= 1 && u64::from(last) <= MAX_BLOCKS,
        "final block {last}"
    );
    assert_eq!(
        usize::from(last),
        data.len() / usize::from(bs) + 1,
        "final block number does not match the file length"
    );
    let mut m = Model {
        data: &data,
        first: first.clone(),
        block_size: bs,
        last_block: last,
        max_retries: cfg.max_retries,
        handshake_retries: cfg.handshake_retries,
        highest: 0,
        done: None,
    };
    if t.sent_oack() {
        assert!(
            matches!(parse(&first), Ok(Packet::Oack(_))),
            "first is not OACK"
        );
        assert_eq!(t.current_block(), 0);
    } else {
        assert_eq!(m.check_data(&first), 1, "first DATA is not block 1");
        m.highest = 1;
        assert_eq!(t.current_block(), 1);
    }
    assert_eq!(t.phase(), Phase::Handshake);

    let mut now = t0;
    for _ in 0..MAX_OPS {
        let Some(op) = c.u8() else { break };
        let arg = op >> 3;
        let prev = t.current_block();
        let ack = |blk: u16| (encode_ack(blk), Some(blk));
        let (step, acked, timer) = match op & 7 {
            0..=2 => {
                now += Duration::from_millis(u64::from(arg));
                let blk = match op & 7 {
                    0 => prev,
                    1 => prev.wrapping_sub(1),
                    _ => prev.wrapping_add(1),
                };
                let (pkt, acked) = ack(blk);
                (t.on_packet(&pkt, &data, now), acked, false)
            }
            3 => {
                let Some(blk) = c.u16_be() else { break };
                let (pkt, acked) = ack(blk);
                (t.on_packet(&pkt, &data, now), acked, false)
            }
            4 => {
                now = now.max(t.deadline());
                (t.on_timeout(&data, now), None, true)
            }
            5 => {
                now += Duration::from_millis(u64::from(arg) * 100);
                (t.on_timeout(&data, now), None, true)
            }
            6 => {
                now += Duration::from_millis(u64::from(arg) * 10);
                let Some(k) = c.u8() else { break };
                let Some(raw) = c.take(usize::from(k)) else {
                    break;
                };
                let acked = match parse(raw) {
                    Ok(Packet::Ack { block }) => Some(block),
                    _ => None,
                };
                let s = t.on_packet(raw, &data, now);
                // BOOT-005: any opcode-5 datagram of 4+ octets from the
                // client TID ends the transfer, framed or not.
                if let [0, 5, hi, lo, ..] = *raw
                    && m.done.is_none()
                {
                    assert_eq!(
                        s,
                        Step::Done(Outcome::AbortedByClient {
                            code: u16::from_be_bytes([hi, lo])
                        }),
                        "client ERROR did not end the transfer"
                    );
                }
                (s, acked, false)
            }
            _ => {
                if arg < 16 {
                    let pkt = [0, 5, 0, arg, 0];
                    let s = t.on_packet(&pkt, &data, now);
                    if m.done.is_none() {
                        assert_eq!(
                            s,
                            Step::Done(Outcome::AbortedByClient {
                                code: u16::from(arg)
                            }),
                            "client ERROR did not end the transfer"
                        );
                    }
                    (s, None, false)
                } else {
                    let s = t.on_packet(&encode_ack(prev), &wrong, now);
                    if m.done.is_none() {
                        assert_eq!(s, Step::Done(Outcome::Failed(FailReason::DataMismatch)));
                    }
                    (s, None, false)
                }
            }
        };
        if acked.is_some_and(|blk| blk != prev) {
            assert!(
                !matches!(step, Step::Send(_)),
                "Send on a duplicate or non-matching ACK"
            );
        }
        m.check(&t, &step, prev, acked, timer);
    }
}
