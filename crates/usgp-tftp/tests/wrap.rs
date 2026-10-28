//! M3 WU-6: RFC 7440 windowsize and block-number wraparound
//! (REQ-BOOT-035, REQ-BOOT-064, DEC-0018 item 2).
//!
//! A test receiver follows RFC 7440 §4 and `specs/standards/tftp.md` §10:
//! it accepts only the next block in sequence, ACKs the last block of each
//! window and the short final block, ACKs the last in-sequence block once
//! on a gap (again whenever a block it already has arrives, which means its
//! ACK was lost), and re-ACKs the final block if it sees DATA after the
//! end.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10, SC-5
// - SPEC: specs/boot-network.md#REQ-BOOT-035, #REQ-BOOT-064
// - RFC 1350 §5, §6; RFC 1123 §4.2.3.1; RFC 2347; RFC 2348; RFC 7440 §3, §4

#[cfg(test)]
mod wrap {
    use std::time::{Duration, Instant};

    use usgp_tftp::{
        Admission, BlockWrap, FailReason, MAX_WINDOW_SIZE, Opcode, Outcome, Packet, ReadTransfer,
        RefuseReason, ServerConfig, Step, WindowConfig, admit_read_with, encode_ack, encode_error,
        encode_request, parse,
    };

    const NAME: &[u8] = b"usgp-test-payload.efi";

    fn file(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251).to_le_bytes()[0]).collect()
    }

    fn big_cfg() -> ServerConfig {
        ServerConfig {
            max_file_size: u64::MAX,
            max_retries: 60,
            max_duration: Duration::from_secs(7200),
            ..ServerConfig::default()
        }
    }

    fn win(max_window_size: u16, block_wrap: BlockWrap) -> WindowConfig {
        WindowConfig {
            max_window_size,
            block_wrap,
        }
    }

    fn admit(
        opts: &[(&[u8], &[u8])],
        data: &[u8],
        cfg: &ServerConfig,
        w: &WindowConfig,
        now: Instant,
    ) -> Admission {
        let pkt = encode_request(Opcode::Rrq, NAME, b"octet", opts);
        let Ok(Packet::Rrq(r)) = parse(&pkt) else {
            panic!("bad RRQ");
        };
        admit_read_with(&r, data, cfg, w, now)
    }

    fn accept(
        opts: &[(&[u8], &[u8])],
        data: &[u8],
        cfg: &ServerConfig,
        w: &WindowConfig,
        now: Instant,
    ) -> (Box<ReadTransfer>, Vec<u8>) {
        match admit(opts, data, cfg, w, now) {
            Admission::Accept { transfer, first } => (transfer, first),
            Admission::Refuse { reason, .. } => panic!("refused: {reason:?}"),
        }
    }

    fn oack_pairs(first: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        match parse(first) {
            Ok(Packet::Oack(l)) => l.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect(),
            other => panic!("not an OACK: {other:?}"),
        }
    }

    fn data_block(p: &[u8]) -> (u16, usize) {
        match parse(p) {
            Ok(Packet::Data { block, data }) => (block, data.len()),
            other => panic!("not DATA: {other:?}"),
        }
    }

    /// Sends every queued block of the current window; returns their wire
    /// numbers.
    fn drain(t: &mut ReadTransfer, first: Option<Vec<u8>>, data: &[u8], now: Instant) -> Vec<u16> {
        let mut out: Vec<u16> = first.iter().map(|p| data_block(p).0).collect();
        while t.pending_sends() {
            assert!(t.deadline() <= now, "pending block but timer not due");
            match t.on_timeout(data, now) {
                Step::Send(p) => out.push(data_block(&p).0),
                other => panic!("{other:?}"),
            }
        }
        out
    }

    fn send_of(step: Step) -> Vec<u8> {
        match step {
            Step::Send(p) => p,
            other => panic!("expected Send, got {other:?}"),
        }
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// True with probability `per_mille` / 1000.
        fn chance(&mut self, per_mille: u64) -> bool {
            self.next() % 1000 < per_mille
        }
    }

    /// An RFC 7440 receiver.
    struct Receiver {
        wrap: BlockWrap,
        window: u64,
        block_size: usize,
        /// Absolute index of the next block expected.
        expected: u64,
        since_ack: u64,
        gap_acked: bool,
        done: bool,
        out: Vec<u8>,
    }

    impl Receiver {
        fn new(wrap: BlockWrap, window: u16, block_size: u16) -> Self {
            Self {
                wrap,
                window: u64::from(window),
                block_size: usize::from(block_size),
                expected: 1,
                since_ack: 0,
                gap_acked: false,
                done: false,
                out: Vec::new(),
            }
        }

        /// Takes one DATA packet; returns the ACK to send, if any.
        fn on_data(&mut self, p: &[u8]) -> Option<u16> {
            let Ok(Packet::Data { block, data }) = parse(p) else {
                panic!("server sent non-DATA {p:?}");
            };
            let last_in_seq = self.wrap.wire(self.expected - 1);
            if self.done {
                // Dally: re-ACK the final block (RFC 1350 §6).
                return Some(last_in_seq);
            }
            if block != self.wrap.wire(self.expected) {
                // A block received before means the sender restarted (our ACK
                // was lost): ACK again. Otherwise ACK a gap only once.
                let old = (1..=64u64)
                    .filter_map(|k| self.expected.checked_sub(k))
                    .any(|i| i >= 1 && self.wrap.wire(i) == block);
                if self.gap_acked && !old {
                    return None;
                }
                self.gap_acked = true;
                self.since_ack = 0;
                return Some(last_in_seq);
            }
            assert!(data.len() <= self.block_size, "oversized block");
            self.out.extend_from_slice(data);
            self.gap_acked = false;
            self.since_ack += 1;
            let ack = self.wrap.wire(self.expected);
            self.expected += 1;
            if data.len() < self.block_size {
                self.done = true;
                return Some(ack);
            }
            if self.since_ack >= self.window {
                self.since_ack = 0;
                return Some(ack);
            }
            None
        }
    }

    /// Runs a whole transfer over a lossy, duplicating channel; returns the
    /// reassembled bytes and the transfer.
    fn lossy_transfer(
        data: &[u8],
        block_size: u16,
        window: u16,
        wrap: BlockWrap,
        rng: &mut XorShift,
        loss_per_mille: u64,
    ) -> (Vec<u8>, Box<ReadTransfer>) {
        let bs = block_size.to_string();
        let ws = window.to_string();
        let opts: Vec<(&[u8], &[u8])> =
            vec![(b"blksize", bs.as_bytes()), (b"windowsize", ws.as_bytes())];
        let mut now = Instant::now();
        let (mut t, first) = accept(&opts, data, &big_cfg(), &win(MAX_WINDOW_SIZE, wrap), now);
        assert_eq!(t.window_size(), window);
        assert_eq!(t.block_size(), block_size);
        assert!(matches!(parse(&first), Ok(Packet::Oack(_))));
        let mut rx = Receiver::new(wrap, window, block_size);
        // Packets in flight from the server; ACKs in flight to the server.
        let mut to_client: Vec<Vec<u8>> = Vec::new();
        let mut to_server: Vec<u16> = Vec::new();
        let mut oack_pending = Some(first);
        let mut steps = 0u64;
        loop {
            steps += 1;
            assert!(steps < 50_000_000, "transfer does not converge");
            if let Some(o) = oack_pending.take() {
                // The client confirms the OACK with ACK 0 (RFC 2347), unless lost.
                assert!(matches!(parse(&o), Ok(Packet::Oack(_))));
                if !rng.chance(loss_per_mille) {
                    to_server.push(0);
                }
            }
            for p in to_client.drain(..) {
                if rng.chance(loss_per_mille) {
                    continue;
                }
                if let Some(a) = rx.on_data(&p)
                    && !rng.chance(loss_per_mille)
                {
                    to_server.push(a);
                }
            }
            let acks: Vec<u16> = std::mem::take(&mut to_server);
            for a in acks {
                let step = t.on_packet(&encode_ack(a), data, now);
                let dup_step = if rng.chance(100) {
                    // A duplicate of the same ACK must never cause a send.
                    let d = t.on_packet(&encode_ack(a), data, now);
                    assert!(!matches!(d, Step::Send(_)), "send on duplicate ACK {a}");
                    Some(d)
                } else {
                    None
                };
                match step {
                    Step::Send(p) => to_client.push(p),
                    Step::Wait => {}
                    Step::Done(Outcome::Completed) => return (rx.out, t),
                    other => panic!("{other:?}"),
                }
                if let Some(Step::Done(Outcome::Completed)) = dup_step {
                    return (rx.out, t);
                }
            }
            if !to_client.is_empty() {
                continue;
            }
            // Nothing in flight: run the timer.
            now = now.max(t.deadline());
            match t.on_timeout(data, now) {
                Step::Send(p) => {
                    if t.current_index() == 0 {
                        oack_pending = Some(p);
                    } else {
                        to_client.push(p);
                    }
                }
                Step::Wait => {}
                other => panic!("timer: {other:?}"),
            }
        }
    }

    // ---- Wraparound over a whole file -------------------------------------

    #[test]
    fn wrap_zero_200k_blocks_intact() {
        // 200,000 DATA packets at blksize 8: the number wraps three times.
        let blocks: usize = 200_000;
        let data = file(blocks * 8 - 3);
        let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
        let (out, t) = lossy_transfer(&data, 8, 8, BlockWrap::Zero, &mut rng, 0);
        assert!(out == data, "reassembled bytes differ");
        assert_eq!(t.last_index(), 200_000);
        assert_eq!(t.wraps(), 3);
        assert_eq!(t.last_block(), BlockWrap::Zero.wire(200_000));
        assert_eq!(t.outcome(), Some(Outcome::Completed));
    }

    #[test]
    fn wrap_zero_sequence_at_65535() {
        // Lock-step (no windowsize) still wraps: ... 65534, 65535, 0, 1 ...
        let data = file(65537 * 8);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"blksize", b"8")],
            &data,
            &big_cfg(),
            &win(8, BlockWrap::Zero),
            now,
        );
        assert_eq!(t.window_size(), 1);
        let mut wires = Vec::new();
        let mut step = t.on_packet(&encode_ack(0), &data, now);
        loop {
            match step {
                Step::Send(p) => {
                    let (b, _) = data_block(&p);
                    if t.current_index() >= 65533 {
                        wires.push(b);
                    }
                    step = t.on_packet(&encode_ack(b), &data, now);
                }
                Step::Done(Outcome::Completed) => break,
                other => panic!("{other:?}"),
            }
        }
        // 65537 * 8 octets: 65537 full blocks and an empty final block.
        assert_eq!(wires, vec![65533, 65534, 65535, 0, 1, 2]);
        assert_eq!(t.last_index(), 65538);
        assert_eq!(t.wraps(), 1);
    }

    #[test]
    fn wrap_one() {
        let data = file(65537 * 8);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"blksize", b"8")],
            &data,
            &big_cfg(),
            &win(8, BlockWrap::One),
            now,
        );
        let mut wires = Vec::new();
        let mut out = Vec::new();
        let mut step = t.on_packet(&encode_ack(0), &data, now);
        loop {
            match step {
                Step::Send(p) => {
                    let Ok(Packet::Data { block, data: d }) = parse(&p) else {
                        panic!("not DATA");
                    };
                    out.extend_from_slice(d);
                    assert_ne!(block, 0, "wrap to 1 never sends block 0");
                    if t.current_index() >= 65533 {
                        wires.push(block);
                    }
                    step = t.on_packet(&encode_ack(block), &data, now);
                }
                Step::Done(Outcome::Completed) => break,
                other => panic!("{other:?}"),
            }
        }
        assert!(out == data);
        assert_eq!(wires, vec![65533, 65534, 65535, 1, 2, 3]);
        assert_eq!(t.wraps(), 1);
    }

    #[test]
    fn off_refuses_too_many_blocks() {
        let now = Instant::now();
        for w in [win(8, BlockWrap::Off), WindowConfig::LOCKSTEP] {
            // 65535 blocks: accepted.
            match admit(
                &[(b"blksize", b"8")],
                &file(65535 * 8 - 1),
                &big_cfg(),
                &w,
                now,
            ) {
                Admission::Accept { transfer, .. } => assert_eq!(transfer.last_index(), 65535),
                Admission::Refuse { reason, .. } => panic!("{reason:?}"),
            }
            // 65536 blocks: ERROR 3, before any OACK or DATA.
            match admit(
                &[(b"blksize", b"8"), (b"windowsize", b"4")],
                &file(65535 * 8),
                &big_cfg(),
                &w,
                now,
            ) {
                Admission::Refuse { error, reason } => {
                    assert_eq!(reason, RefuseReason::TooManyBlocks);
                    assert!(matches!(parse(&error), Ok(Packet::Error { code: 3, .. })));
                }
                Admission::Accept { .. } => panic!("off accepted 65536 blocks"),
            }
        }
        // The same file is accepted when wrapping.
        for wrap in [BlockWrap::Zero, BlockWrap::One] {
            assert!(matches!(
                admit(
                    &[(b"blksize", b"8")],
                    &file(65535 * 8),
                    &big_cfg(),
                    &win(8, wrap),
                    now
                ),
                Admission::Accept { .. }
            ));
        }
    }

    #[test]
    fn max_file_size_still_applies_with_wrap() {
        let cfg = ServerConfig {
            max_file_size: 4096,
            ..big_cfg()
        };
        match admit(
            &[],
            &file(4097),
            &cfg,
            &WindowConfig::default(),
            Instant::now(),
        ) {
            Admission::Refuse { error, reason } => {
                assert_eq!(reason, RefuseReason::FileTooLarge);
                assert!(matches!(parse(&error), Ok(Packet::Error { code: 3, .. })));
            }
            Admission::Accept { .. } => panic!("accepted"),
        }
    }

    // ---- Window and ACK interplay ------------------------------------------

    #[test]
    fn window_sends_burst_then_waits_for_last_ack() {
        let data = file(512 * 10 + 5); // 11 blocks
        let now = Instant::now();
        let (mut t, first) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        assert_eq!(
            oack_pairs(&first),
            vec![(b"windowsize".to_vec(), b"4".to_vec())]
        );
        assert!(!t.pending_sends(), "nothing sent before ACK 0");
        let p = send_of(t.on_packet(&encode_ack(0), &data, now));
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![1, 2, 3, 4]);
        // Window sent: the timer is armed, not due.
        assert!(t.deadline() > now);
        assert_eq!(t.on_timeout(&data, now), Step::Wait);
        // ACKs inside the window that are not the last block still restart
        // after them; ACK 4 opens the next window.
        let p = send_of(t.on_packet(&encode_ack(4), &data, now));
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![5, 6, 7, 8]);
        let p = send_of(t.on_packet(&encode_ack(8), &data, now));
        // Final window holds 3 blocks, the last one short.
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![9, 10, 11]);
        assert_eq!(
            t.on_packet(&encode_ack(11), &data, now),
            Step::Done(Outcome::Completed)
        );
        assert_eq!(t.retransmits(), 0);
    }

    #[test]
    fn partial_ack_restarts_after_it() {
        let data = file(512 * 20);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        let p = send_of(t.on_packet(&encode_ack(0), &data, now));
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![1, 2, 3, 4]);
        // Block 3 lost: the receiver ACKs 2 (RFC 7440 §4).
        let p = send_of(t.on_packet(&encode_ack(2), &data, now));
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![3, 4, 5, 6]);
        assert_eq!(t.acked_index(), 2);
        // A stale ACK 1 and a repeated ACK 2 are ignored.
        assert_eq!(t.on_packet(&encode_ack(1), &data, now), Step::Wait);
        assert_eq!(t.on_packet(&encode_ack(2), &data, now), Step::Wait);
        // An ACK for a block not yet sent is ignored.
        assert_eq!(t.on_packet(&encode_ack(7), &data, now), Step::Wait);
        assert_eq!(t.retransmits(), 0);
    }

    #[test]
    fn ack_while_window_still_queued_restarts() {
        let data = file(512 * 20);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"8")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        let _ = send_of(t.on_packet(&encode_ack(0), &data, now));
        let _ = send_of(t.on_timeout(&data, now)); // block 2
        assert!(t.pending_sends());
        // An early ACK 1 moves the window to 2..=9.
        let p = send_of(t.on_packet(&encode_ack(1), &data, now));
        assert_eq!(
            drain(&mut t, Some(p), &data, now),
            vec![2, 3, 4, 5, 6, 7, 8, 9]
        );
    }

    #[test]
    fn timeout_resends_window_from_after_last_ack() {
        let data = file(512 * 20);
        let t0 = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            t0,
        );
        let p = send_of(t.on_packet(&encode_ack(0), &data, t0));
        drain(&mut t, Some(p), &data, t0);
        let p = send_of(t.on_packet(&encode_ack(4), &data, t0));
        drain(&mut t, Some(p), &data, t0);
        let late = t.deadline();
        let p = send_of(t.on_timeout(&data, late));
        assert_eq!(drain(&mut t, Some(p), &data, late), vec![5, 6, 7, 8]);
        assert_eq!((t.retransmits(), t.current_retries()), (1, 1));
        // The resend does not repeat itself before the backed-off timer.
        assert_eq!(t.on_timeout(&data, late), Step::Wait);
        // Progress resets the per-window retry count.
        let p = send_of(t.on_packet(&encode_ack(8), &data, late));
        drain(&mut t, Some(p), &data, late);
        assert_eq!((t.retransmits(), t.current_retries()), (1, 0));
    }

    #[test]
    fn retry_cap_per_window() {
        let data = file(512 * 20);
        let t0 = Instant::now();
        let cfg = ServerConfig {
            max_retries: 3,
            ..big_cfg()
        };
        let (mut t, _) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &cfg,
            &WindowConfig::default(),
            t0,
        );
        let p = send_of(t.on_packet(&encode_ack(0), &data, t0));
        drain(&mut t, Some(p), &data, t0);
        let mut resends = 0;
        loop {
            let now = t.deadline();
            match t.on_timeout(&data, now) {
                Step::Send(p) => {
                    resends += 1;
                    drain(&mut t, Some(p), &data, now);
                }
                Step::Done(o) => {
                    assert_eq!(o, Outcome::Failed(FailReason::RetryCapReached));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(resends, 3);
    }

    #[test]
    fn window_acks_across_wrap() {
        // Window of 8 straddling 65535 → wrap value, for both wrap modes.
        for wrap in [BlockWrap::Zero, BlockWrap::One] {
            let data = file(65560 * 8 + 3);
            let now = Instant::now();
            let (mut t, _) = accept(
                &[(b"blksize", b"8"), (b"windowsize", b"8")],
                &data,
                &big_cfg(),
                &win(8, wrap),
                now,
            );
            assert_eq!(t.window_size(), 8);
            // Walk forward in whole windows to acked = 65533.
            let mut step = t.on_packet(&encode_ack(0), &data, now);
            while t.acked_index() < 65528 {
                let p = send_of(step);
                drain(&mut t, Some(p), &data, now);
                let last = wrap.wire(t.acked_index() + 8);
                step = t.on_packet(&encode_ack(last), &data, now);
            }
            assert_eq!(t.acked_index(), 65528);
            drain(&mut t, Some(send_of(step)), &data, now);
            // Partial ACK of 65533 opens 65534..=65541.
            let p = send_of(t.on_packet(&encode_ack(65533), &data, now));
            let wires = drain(&mut t, Some(p), &data, now);
            let want: Vec<u16> = (65534..=65541).map(|i| wrap.wire(i)).collect();
            assert_eq!(wires, want);
            assert_eq!(t.wraps(), 1);
            // A duplicate ACK 65533 is ignored after the wrap.
            assert_eq!(t.on_packet(&encode_ack(65533), &data, now), Step::Wait);
            // ACK of 65537 (after the wrap) maps inside the window.
            let p = send_of(t.on_packet(&encode_ack(wrap.wire(65537)), &data, now));
            assert_eq!(t.acked_index(), 65537);
            let wires = drain(&mut t, Some(p), &data, now);
            let want: Vec<u16> = (65538..=65545).map(|i| wrap.wire(i)).collect();
            assert_eq!(wires, want);
            // The stale pre-wrap number 65535 (index 65535) is a duplicate now.
            assert_eq!(t.on_packet(&encode_ack(65535), &data, now), Step::Wait);
            // So is the wire number of the old window's start.
            assert_eq!(
                t.on_packet(&encode_ack(wrap.wire(65536)), &data, now),
                Step::Wait
            );
            assert_eq!(t.retransmits(), 0);
        }
    }

    #[test]
    fn exact_multiple_with_full_final_window() {
        // 7 full blocks + empty final block = 8 = one full window of 4 twice.
        // The end is the short (empty) block, not a short window.
        let data = file(512 * 7);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        assert_eq!(t.last_index(), 8);
        let p = send_of(t.on_packet(&encode_ack(0), &data, now));
        drain(&mut t, Some(p), &data, now);
        let p = send_of(t.on_packet(&encode_ack(4), &data, now));
        let mut lens = Vec::new();
        lens.push(data_block(&p).1);
        while t.pending_sends() {
            lens.push(data_block(&send_of(t.on_timeout(&data, now))).1);
        }
        assert_eq!(lens, vec![512, 512, 512, 0]);
        assert_eq!(
            t.on_packet(&encode_ack(8), &data, now),
            Step::Done(Outcome::Completed)
        );
    }

    #[test]
    fn file_smaller_than_one_window() {
        let data = file(100);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"8")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        let p = send_of(t.on_packet(&encode_ack(0), &data, now));
        assert_eq!(drain(&mut t, Some(p), &data, now), vec![1]);
        assert_eq!(
            t.on_packet(&encode_ack(1), &data, now),
            Step::Done(Outcome::Completed)
        );
    }

    #[test]
    fn lossy_transfers_reassemble_for_each_window_and_wrap() {
        // Property sweep (M3 plan §10.1): random loss and duplicate ACKs, for
        // several window sizes and every wrap mode, around the wrap point.
        let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
        for wrap in [BlockWrap::Zero, BlockWrap::One, BlockWrap::Off] {
            for window in [1u16, 4, 8, 64] {
                let sizes: &[usize] = if wrap == BlockWrap::Off {
                    &[0, 7, 8, 9, 65535 * 8 - 1]
                } else {
                    &[0, 15, 65535 * 8 - 1, 65535 * 8, 65537 * 8 + 1, 131_074 * 8]
                };
                for &len in sizes {
                    let data = file(len);
                    let (out, t) = lossy_transfer(&data, 8, window, wrap, &mut rng, 20);
                    assert!(
                        out == data,
                        "mismatch: wrap {wrap:?} window {window} len {len}"
                    );
                    assert_eq!(t.outcome(), Some(Outcome::Completed));
                }
            }
        }
    }

    // ---- Option negotiation (RFC 2347, RFC 2348, RFC 7440) -----------------

    #[test]
    fn blksize_and_windowsize_negotiated_rfc() {
        let data = file(10_000);
        let now = Instant::now();
        let cfg = ServerConfig {
            max_block_size: 16384,
            ..big_cfg()
        };
        // The values Microsoft documents as the boot manager defaults
        // (winpe-network-boot.md §5): 1432 and 4. Both granted as asked.
        let (t, first) = accept(
            &[
                (b"blksize", b"1432"),
                (b"windowsize", b"4"),
                (b"tsize", b"0"),
            ],
            &data,
            &cfg,
            &WindowConfig::default(),
            now,
        );
        assert_eq!(
            oack_pairs(&first),
            vec![
                (b"blksize".to_vec(), b"1432".to_vec()),
                (b"tsize".to_vec(), b"10000".to_vec()),
                (b"windowsize".to_vec(), b"4".to_vec()),
            ]
        );
        assert_eq!((t.block_size(), t.window_size()), (1432, 4));
        assert!(t.windowsize_acked());
        // Larger requests are answered with the server's limits, never more
        // than asked (RFC 2348; RFC 7440 §3).
        let (t, first) = accept(
            &[(b"BLKSIZE", b"65464"), (b"WindowSize", b"65535")],
            &data,
            &cfg,
            &WindowConfig::default(),
            now,
        );
        assert_eq!(
            oack_pairs(&first),
            vec![
                (b"blksize".to_vec(), b"16384".to_vec()),
                (b"windowsize".to_vec(), b"8".to_vec()),
            ]
        );
        assert_eq!((t.block_size(), t.window_size()), (16384, 8));
    }

    #[test]
    fn windowsize_invalid_values_ignored() {
        let data = file(2000);
        let now = Instant::now();
        for bad in [
            &b"0"[..],
            b"65536",
            b"-1",
            b"4x",
            b"",
            b"99999999999999999999",
        ] {
            let (t, first) = accept(
                &[(b"windowsize", bad)],
                &data,
                &big_cfg(),
                &WindowConfig::default(),
                now,
            );
            // Nothing acceptable: no OACK, lock-step DATA 1 (RFC 2347).
            assert!(!t.sent_oack(), "{bad:?}");
            assert_eq!(data_block(&first).0, 1, "{bad:?}");
            assert_eq!(t.window_size(), 1);
            let (t, first) = accept(
                &[(b"windowsize", bad), (b"tsize", b"0")],
                &data,
                &big_cfg(),
                &WindowConfig::default(),
                now,
            );
            assert_eq!(
                oack_pairs(&first),
                vec![(b"tsize".to_vec(), b"2000".to_vec())],
                "{bad:?}"
            );
            assert_eq!(t.window_size(), 1);
        }
    }

    #[test]
    fn windowsize_not_acknowledged_when_lockstep() {
        let data = file(2000);
        let now = Instant::now();
        for w in [
            WindowConfig::LOCKSTEP,
            win(1, BlockWrap::Zero),
            win(0, BlockWrap::Zero),
        ] {
            let (t, first) = accept(&[(b"windowsize", b"8")], &data, &big_cfg(), &w, now);
            assert!(!t.sent_oack());
            assert_eq!(data_block(&first).0, 1);
            assert_eq!(t.window_size(), 1);
        }
    }

    #[test]
    fn windowsize_capped_at_64_whatever_the_config() {
        let data = file(2000);
        let (t, first) = accept(
            &[(b"windowsize", b"1000")],
            &data,
            &big_cfg(),
            &win(u16::MAX, BlockWrap::Zero),
            Instant::now(),
        );
        assert_eq!(
            oack_pairs(&first),
            vec![(b"windowsize".to_vec(), b"64".to_vec())]
        );
        assert_eq!(t.window_size(), MAX_WINDOW_SIZE);
    }

    #[test]
    fn client_error_8_rejects_windowsize_oack() {
        let data = file(2000);
        let now = Instant::now();
        let (mut t, first) = accept(
            &[(b"windowsize", b"8")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        assert!(matches!(parse(&first), Ok(Packet::Oack(_))));
        let err = encode_error(usgp_tftp::ErrorCode::OptionNegotiation, "no");
        assert_eq!(
            t.on_packet(&err, &data, now),
            Step::Done(Outcome::AbortedByClient { code: 8 })
        );
        assert_eq!(
            t.on_timeout(&data, t.deadline()),
            Step::Done(Outcome::AbortedByClient { code: 8 })
        );
    }

    #[test]
    fn oack_handshake_ignores_nonzero_ack_and_retries() {
        let data = file(2000);
        let t0 = Instant::now();
        let (mut t, first) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            t0,
        );
        for b in [1u16, 2, 65535] {
            assert_eq!(t.on_packet(&encode_ack(b), &data, t0), Step::Wait);
        }
        assert_eq!(t.current_block(), 0);
        // The handshake resend is the OACK again.
        let late = t.deadline();
        let p = send_of(t.on_timeout(&data, late));
        assert_eq!(p, first);
        assert!(!t.pending_sends());
    }

    #[test]
    fn data_from_client_during_window_aborts() {
        let data = file(5000);
        let now = Instant::now();
        let (mut t, _) = accept(
            &[(b"windowsize", b"4")],
            &data,
            &big_cfg(),
            &WindowConfig::default(),
            now,
        );
        let _ = send_of(t.on_packet(&encode_ack(0), &data, now));
        match t.on_packet(&usgp_tftp::encode_data(1, b"x"), &data, now) {
            Step::Abort { error, outcome } => {
                assert_eq!(outcome, Outcome::Failed(FailReason::IllegalOperation));
                assert!(matches!(parse(&error), Ok(Packet::Error { code: 4, .. })));
            }
            other => panic!("{other:?}"),
        }
        assert!(!t.pending_sends());
    }
}
