//! Sorcerer's Apprentice Syndrome: a duplicate ACK never triggers a resend
//! (RFC 1123 §4.2.3.1; REQ-BOOT-032).

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection), SA-11
// - SPEC: specs/boot-network.md#REQ-BOOT-032
// - RFC 1123 §4.2.3.1

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
