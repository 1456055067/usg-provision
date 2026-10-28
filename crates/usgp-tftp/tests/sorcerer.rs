//! Sorcerer's Apprentice Syndrome: a duplicate ACK never triggers a resend
//! (RFC 1123 §4.2.3.1; REQ-BOOT-032), in lock-step and per window
//! (RFC 7440 §4; M3 plan WU-6).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection), SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-032, #REQ-BOOT-064
// - RFC 1123 §4.2.3.1; RFC 7440 §4

use std::time::Instant;

use usgp_tftp::{
    Admission, Opcode, Outcome, Packet, ServerConfig, Step, admit_read, encode_ack, encode_request,
    parse,
};

fn start(data: &[u8], now: Instant) -> Option<Box<usgp_tftp::ReadTransfer>> {
    let pkt = encode_request(Opcode::Rrq, b"f", b"octet", &[]);
    let Ok(Packet::Rrq(r)) = parse(&pkt) else {
        return None;
    };
    match admit_read(&r, data, &ServerConfig::default(), now) {
        Admission::Accept { transfer, .. } => Some(transfer),
        Admission::Refuse { .. } => None,
    }
}

#[test]
fn dup_ack_no_resend() {
    let data = vec![1u8; 512 * 4 + 7];
    let now = Instant::now();
    let mut t = start(&data, now).unwrap();
    assert!(matches!(
        t.on_packet(&encode_ack(1), &data, now),
        Step::Send(_)
    ));
    for _ in 0..10 {
        assert_eq!(t.on_packet(&encode_ack(1), &data, now), Step::Wait);
    }
    assert_eq!(t.current_block(), 2);
    assert_eq!(t.retransmits(), 0);
}

#[test]
fn delayed_ack_does_not_double_the_stream() {
    // Block n times out and is resent; then both ACK n arrive. The first
    // advances, the second is a duplicate and sends nothing. Every block is
    // sent once apart from the single timer-driven resend.
    let data = vec![2u8; 512 * 6 + 1];
    let t0 = Instant::now();
    let mut t = start(&data, t0).unwrap();
    let mut data_sends = 1; // DATA 1 from admission
    let mut now = t0;
    for block in 1..=t.last_block() {
        if block == 3 {
            now = t.deadline();
            assert!(matches!(t.on_timeout(&data, now), Step::Send(_)));
            data_sends += 1;
        }
        match t.on_packet(&encode_ack(block), &data, now) {
            Step::Send(p) => {
                assert!(matches!(parse(&p), Ok(Packet::Data { block: b, .. }) if b == block + 1));
                data_sends += 1;
            }
            Step::Done(Outcome::Completed) => assert_eq!(block, t.last_block()),
            other => panic!("{other:?}"),
        }
        // The duplicate of every ACK, delayed.
        let dup = t.on_packet(&encode_ack(block), &data, now);
        assert!(
            !matches!(dup, Step::Send(_)),
            "resend on duplicate ACK {block}"
        );
    }
    assert_eq!(data_sends, usize::from(t.last_block()) + 1);
}

#[test]
fn block_numbers_strictly_increase() {
    let data = vec![3u8; 512 * 20];
    let now = Instant::now();
    let mut t = start(&data, now).unwrap();
    let mut last = 1u16;
    loop {
        match t.on_packet(&encode_ack(last), &data, now) {
            Step::Send(p) => match parse(&p) {
                Ok(Packet::Data { block, .. }) => {
                    assert_eq!(block, last + 1);
                    last = block;
                }
                other => panic!("{other:?}"),
            },
            Step::Done(Outcome::Completed) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(last, 21);
}

// ---- Windowed (RFC 7440) ------------------------------------------------

#[cfg(test)]
mod windowed {
    use std::time::Instant;

    use usgp_tftp::{
        Admission, BlockWrap, Opcode, Outcome, Packet, ReadTransfer, ServerConfig, Step,
        WindowConfig, admit_read_with, encode_ack, encode_request, parse,
    };

    fn start_windowed(
        data: &[u8],
        window: &[u8],
        wrap: BlockWrap,
        now: Instant,
    ) -> Box<ReadTransfer> {
        let pkt = encode_request(
            Opcode::Rrq,
            b"f",
            b"octet",
            &[(b"windowsize", window), (b"blksize", b"8")],
        );
        let Ok(Packet::Rrq(r)) = parse(&pkt) else {
            panic!("bad RRQ");
        };
        let cfg = ServerConfig {
            max_file_size: u64::MAX,
            ..ServerConfig::default()
        };
        let win = WindowConfig {
            max_window_size: 64,
            block_wrap: wrap,
        };
        match admit_read_with(&r, data, &cfg, &win, now) {
            Admission::Accept { transfer, .. } => transfer,
            Admission::Refuse { reason, .. } => panic!("{reason:?}"),
        }
    }

    /// Sends the rest of the current window; returns the wire numbers sent,
    /// starting with `first`.
    fn rest_of_window(t: &mut ReadTransfer, first: Step, data: &[u8], now: Instant) -> Vec<u16> {
        let mut out = Vec::new();
        let mut step = first;
        loop {
            match step {
                Step::Send(p) => match parse(&p) {
                    Ok(Packet::Data { block, .. }) => out.push(block),
                    other => panic!("{other:?}"),
                },
                other => panic!("{other:?}"),
            }
            if !t.pending_sends() {
                return out;
            }
            step = t.on_timeout(data, now);
        }
    }

    #[test]
    fn window_dup_ack_no_resend() {
        let data = vec![1u8; 8 * 40];
        let now = Instant::now();
        let mut t = start_windowed(&data, b"8", BlockWrap::Zero, now);
        let s = t.on_packet(&encode_ack(0), &data, now);
        assert_eq!(rest_of_window(&mut t, s, &data, now).len(), 8);
        let s = t.on_packet(&encode_ack(8), &data, now);
        assert_eq!(
            rest_of_window(&mut t, s, &data, now),
            (9..=16).collect::<Vec<_>>()
        );
        // Duplicates of the window ACK, of ACK 0 and of earlier blocks: no
        // send, no queued window, no retransmit count.
        for b in [8u16, 8, 0, 3, 7, 8] {
            assert_eq!(
                t.on_packet(&encode_ack(b), &data, now),
                Step::Wait,
                "ACK {b}"
            );
            assert!(!t.pending_sends());
        }
        assert_eq!(t.retransmits(), 0);
        assert_eq!(t.acked_index(), 8);
    }

    #[test]
    fn delayed_window_ack_does_not_double_the_stream() {
        // A window times out and is resent; then the delayed ACK for it and the
        // ACK for the resent copy both arrive. The first opens the next window,
        // the second is a duplicate and sends nothing. Only the timer resends.
        for wrap in [BlockWrap::Zero, BlockWrap::One] {
            let data = vec![2u8; 8 * 24 + 1];
            let t0 = Instant::now();
            let mut t = start_windowed(&data, b"4", wrap, t0);
            let mut sends = 0usize;
            let s = t.on_packet(&encode_ack(0), &data, t0);
            sends += rest_of_window(&mut t, s, &data, t0).len();
            let mut now = t0;
            loop {
                let end = t.acked_index() + 4;
                if end == 8 {
                    // Timer-driven resend of window 5..=8.
                    now = t.deadline();
                    let s = t.on_timeout(&data, now);
                    sends += rest_of_window(&mut t, s, &data, now).len();
                }
                let end = end.min(t.last_index());
                match t.on_packet(&encode_ack(wrap.wire(end)), &data, now) {
                    Step::Send(p) => {
                        sends += rest_of_window(&mut t, Step::Send(p), &data, now).len();
                    }
                    Step::Done(Outcome::Completed) => break,
                    other => panic!("{other:?}"),
                }
                let dup = t.on_packet(&encode_ack(wrap.wire(end)), &data, now);
                assert_eq!(dup, Step::Wait, "resend on duplicate window ACK {end}");
            }
            let last = usize::try_from(t.last_index()).unwrap();
            assert_eq!(sends, last + 4, "only the one timed-out window is resent");
            assert_eq!(t.retransmits(), 1);
        }
    }
}
