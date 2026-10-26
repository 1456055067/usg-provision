//! Negative tests: every RFC length and option limit for TFTP (plan §10.2,
//! TFTP list).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SA-11 (Developer
//   Testing and Evaluation)
// - SPEC: specs/boot-network.md#REQ-BOOT-030, #REQ-BOOT-031,
//   #REQ-BOOT-035, #REQ-BOOT-040, #REQ-BOOT-041
// - RFC 1350 §5; RFC 2347; RFC 2348; RFC 2349

use std::time::Instant;

use usgp_tftp::{
    Admission, ErrorCode, FailReason, Opcode, Outcome, Packet, ParseError, ReadTransfer,
    RefuseReason, ServerConfig, Step, admit_read, encode_ack, encode_data, encode_error,
    encode_request, foreign_tid_error, parse,
};

const NAME: &[u8] = b"usgp-test-payload.efi";

fn rrq_with(mode: &[u8], opts: &[(&[u8], &[u8])]) -> Vec<u8> {
    encode_request(Opcode::Rrq, NAME, mode, opts)
}

fn rrq(opts: &[(&[u8], &[u8])]) -> Vec<u8> {
    rrq_with(b"octet", opts)
}

fn admit(pkt: &[u8], data: &[u8], cfg: &ServerConfig) -> Option<Admission> {
    match parse(pkt) {
        Ok(Packet::Rrq(r)) => Some(admit_read(&r, data, cfg, Instant::now())),
        _ => None,
    }
}

fn accept(pkt: &[u8], data: &[u8]) -> Option<(Box<ReadTransfer>, Vec<u8>)> {
    match admit(pkt, data, &ServerConfig::default())? {
        Admission::Accept { transfer, first } => Some((transfer, first)),
        Admission::Refuse { .. } => None,
    }
}

fn refuse_reason(pkt: &[u8], data: &[u8], cfg: &ServerConfig) -> Option<(RefuseReason, u16)> {
    match admit(pkt, data, cfg)? {
        Admission::Refuse { error, reason } => match parse(&error) {
            Ok(Packet::Error { code, .. }) => Some((reason, code)),
            _ => None,
        },
        Admission::Accept { .. } => None,
    }
}

type Pairs = Vec<(Vec<u8>, Vec<u8>)>;

/// `Some(Some(pairs))` for an OACK, `Some(None)` for DATA 1, `None` for
/// anything else.
fn oack_of(first: &[u8]) -> Option<Option<Pairs>> {
    match parse(first) {
        Ok(Packet::Oack(l)) => Some(Some(
            l.iter().map(|(n, v)| (n.to_vec(), v.to_vec())).collect(),
        )),
        Ok(Packet::Data { block: 1, .. }) => Some(None),
        _ => None,
    }
}

fn file(len: usize) -> Vec<u8> {
    vec![0xa5; len]
}

// ---- Packet length and opcode -----------------------------------------

#[test]
fn length_0() {
    assert_eq!(parse(&[]), Err(ParseError::TooShort { len: 0 }));
}

#[test]
fn length_1() {
    assert_eq!(parse(&[0]), Err(ParseError::TooShort { len: 1 }));
}

#[test]
fn length_3() {
    assert_eq!(parse(&[0, 4, 0]), Err(ParseError::BadAckLength { len: 3 }));
    assert_eq!(parse(&[0, 3, 0]), Err(ParseError::TooShort { len: 3 }));
    assert_eq!(parse(&[0, 5, 0]), Err(ParseError::TooShort { len: 3 }));
    assert_eq!(parse(&[0, 1, 0]), Err(ParseError::EmptyFilename));
}

#[test]
fn opcode_0() {
    assert_eq!(
        parse(&[0, 0, 0, 0]),
        Err(ParseError::UnknownOpcode { opcode: 0 })
    );
}

#[test]
fn opcodes_7_to_65535() {
    for op in 7..=u16::MAX {
        let [a, b] = op.to_be_bytes();
        assert_eq!(
            parse(&[a, b, 0, 1, 0]),
            Err(ParseError::UnknownOpcode { opcode: op })
        );
    }
}

// ---- RRQ framing ------------------------------------------------------

#[test]
fn rrq_missing_first_nul() {
    assert_eq!(
        parse(b"\x00\x01filename"),
        Err(ParseError::FilenameUnterminated)
    );
}

#[test]
fn rrq_missing_second_nul() {
    assert_eq!(
        parse(b"\x00\x01file\x00octet"),
        Err(ParseError::ModeUnterminated)
    );
}

#[test]
fn rrq_empty_filename() {
    assert_eq!(
        parse(b"\x00\x01\x00octet\x00"),
        Err(ParseError::EmptyFilename)
    );
}

#[test]
fn rrq_empty_mode() {
    assert_eq!(parse(b"\x00\x01file\x00\x00"), Err(ParseError::EmptyMode));
}

#[test]
fn rrq_513_octets() {
    let mut name = vec![b'a'; 512 - 2 - 1 - 6];
    let ok = encode_request(Opcode::Rrq, &name, b"octet", &[]);
    assert_eq!(ok.len(), 512);
    assert!(parse(&ok).is_ok());
    name.push(b'a');
    let long = encode_request(Opcode::Rrq, &name, b"octet", &[]);
    assert_eq!(long.len(), 513);
    assert_eq!(parse(&long), Err(ParseError::RequestTooLong { len: 513 }));
    let wrq = encode_request(Opcode::Wrq, &name, b"octet", &[]);
    assert_eq!(parse(&wrq), Err(ParseError::RequestTooLong { len: 513 }));
}

#[test]
fn wrq_parses_for_refusal() {
    // The server refuses WRQ with ERROR 2 before any file access; the
    // parser only has to recognise it.
    let p = encode_request(Opcode::Wrq, b"x", b"octet", &[]);
    assert!(matches!(parse(&p), Ok(Packet::Wrq(_))));
    let e = encode_error(ErrorCode::AccessViolation, "access violation");
    assert!(matches!(parse(&e), Ok(Packet::Error { code: 2, .. })));
}

// ---- Mode -------------------------------------------------------------

#[test]
fn mode_octet_upper_case_accepted() {
    let (_, first) = accept(&rrq_with(b"OCTET", &[]), &file(10)).unwrap();
    assert_eq!(oack_of(&first), Some(None));
}

#[test]
fn mode_netascii_refused() {
    let r = refuse_reason(
        &rrq_with(b"netascii", &[]),
        &file(10),
        &ServerConfig::default(),
    );
    assert_eq!(r, Some((RefuseReason::UnsupportedMode, 4)));
}

#[test]
fn mode_mail_refused() {
    let r = refuse_reason(&rrq_with(b"mail", &[]), &file(10), &ServerConfig::default());
    assert_eq!(r, Some((RefuseReason::UnsupportedMode, 4)));
}

#[test]
fn mode_unknown_refused() {
    let r = refuse_reason(
        &rrq_with(b"binary", &[]),
        &file(10),
        &ServerConfig::default(),
    );
    assert_eq!(r, Some((RefuseReason::UnsupportedMode, 4)));
}

// ---- Option framing ---------------------------------------------------

#[test]
fn option_without_value() {
    assert_eq!(
        parse(b"\x00\x01f\x00octet\x00blksize\x00"),
        Err(ParseError::OptionWithoutValue)
    );
    assert_eq!(
        parse(b"\x00\x01f\x00octet\x00blksize\x00512"),
        Err(ParseError::OptionWithoutValue)
    );
    assert_eq!(
        parse(b"\x00\x01f\x00octet\x00blksize"),
        Err(ParseError::OptionUnterminated)
    );
}

#[test]
fn option_empty_name() {
    assert_eq!(
        parse(b"\x00\x01f\x00octet\x00\x00512\x00"),
        Err(ParseError::EmptyOptionName)
    );
}

#[test]
fn option_duplicate_blksize() {
    let p = rrq(&[(b"blksize", b"512"), (b"blksize", b"1024")]);
    assert_eq!(parse(&p), Err(ParseError::DuplicateOption));
}

#[test]
fn option_duplicate_differs_only_in_case() {
    let p = rrq(&[(b"tsize", b"0"), (b"TSize", b"0")]);
    assert_eq!(parse(&p), Err(ParseError::DuplicateOption));
}

// ---- blksize values ---------------------------------------------------

fn blksize_reply(v: &[u8]) -> Option<Pairs> {
    let first = accept(&rrq(&[(b"blksize", v)]), &file(5000)).map(|(_, f)| f);
    first.as_deref().and_then(oack_of).unwrap_or_default()
}

#[test]
fn blksize_7_ignored() {
    assert_eq!(blksize_reply(b"7"), None);
}

#[test]
fn blksize_65465_ignored() {
    assert_eq!(blksize_reply(b"65465"), None);
}

#[test]
fn blksize_8_accepted() {
    assert_eq!(
        blksize_reply(b"8"),
        Some(vec![(b"blksize".to_vec(), b"8".to_vec())])
    );
}

#[test]
fn blksize_65464_capped_to_config() {
    assert_eq!(
        blksize_reply(b"65464"),
        Some(vec![(b"blksize".to_vec(), b"1468".to_vec())])
    );
}

#[test]
fn blksize_leading_zeros() {
    assert_eq!(
        blksize_reply(b"00512"),
        Some(vec![(b"blksize".to_vec(), b"512".to_vec())])
    );
}

#[test]
fn blksize_20_digits_ignored() {
    assert_eq!(blksize_reply(b"99999999999999999999"), None);
}

#[test]
fn blksize_non_digits_ignored() {
    assert_eq!(blksize_reply(b"1k"), None);
    assert_eq!(blksize_reply(b"-512"), None);
    assert_eq!(blksize_reply(b""), None);
}

// ---- tsize ------------------------------------------------------------

#[test]
fn tsize_0_returns_size() {
    let (_, first) = accept(&rrq(&[(b"tsize", b"0")]), &file(5632)).unwrap();
    assert_eq!(
        oack_of(&first),
        Some(Some(vec![(b"tsize".to_vec(), b"5632".to_vec())]))
    );
}

#[test]
fn tsize_5_ignored() {
    let (_, first) = accept(&rrq(&[(b"tsize", b"5")]), &file(5632)).unwrap();
    assert_eq!(oack_of(&first), Some(None));
}

#[test]
fn tsize_non_numeric_ignored() {
    let (_, first) = accept(&rrq(&[(b"tsize", b"zero")]), &file(5632)).unwrap();
    assert_eq!(oack_of(&first), Some(None));
}

// ---- Other options ----------------------------------------------------

#[test]
fn timeout_5_not_acknowledged() {
    let (_, first) = accept(&rrq(&[(b"timeout", b"5")]), &file(10)).unwrap();
    assert_eq!(oack_of(&first), Some(None));
}

#[test]
fn windowsize_not_acknowledged() {
    let (_, first) = accept(&rrq(&[(b"windowsize", b"8"), (b"tsize", b"0")]), &file(10)).unwrap();
    assert_eq!(
        oack_of(&first),
        Some(Some(vec![(b"tsize".to_vec(), b"10".to_vec())]))
    );
}

#[test]
fn unknown_option_ignored() {
    let (_, first) = accept(&rrq(&[(b"multicast", b"")]), &file(10)).unwrap();
    assert_eq!(oack_of(&first), Some(None));
}

// ---- ACK handling -----------------------------------------------------

#[test]
fn ack_length_3_and_5_ignored() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    let now = Instant::now();
    assert_eq!(t.on_packet(&[0, 4, 0], &data, now), Step::Wait);
    assert_eq!(t.on_packet(&[0, 4, 0, 1, 0], &data, now), Step::Wait);
    assert_eq!(t.current_block(), 1, "malformed ACKs do not advance");
}

#[test]
fn ack_for_future_block_ignored() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    assert_eq!(
        t.on_packet(&encode_ack(3), &data, Instant::now()),
        Step::Wait
    );
    assert_eq!(t.current_block(), 1);
}

#[test]
fn ack_0_without_oack_ignored() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    assert!(!t.sent_oack());
    assert_eq!(
        t.on_packet(&encode_ack(0), &data, Instant::now()),
        Step::Wait
    );
    assert_eq!(t.current_block(), 1);
}

#[test]
fn ack_0_after_oack_starts_data() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[(b"tsize", b"0")]), &data).unwrap();
    match t.on_packet(&encode_ack(0), &data, Instant::now()) {
        Step::Send(p) => assert!(matches!(parse(&p), Ok(Packet::Data { block: 1, .. }))),
        other => panic!("{other:?}"),
    }
}

// ---- Client packets during a transfer ---------------------------------

#[test]
fn error_8_after_oack_ends_transfer() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[(b"blksize", b"1468")]), &data).unwrap();
    let e = encode_error(ErrorCode::OptionNegotiation, "no");
    let now = Instant::now();
    assert_eq!(
        t.on_packet(&e, &data, now),
        Step::Done(Outcome::AbortedByClient { code: 8 })
    );
    assert_eq!(
        t.on_timeout(&data, t.deadline()),
        Step::Done(Outcome::AbortedByClient { code: 8 })
    );
}

#[test]
fn tsize_probe_abort() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[(b"tsize", b"0")]), &data).unwrap();
    let e = encode_error(ErrorCode::DiskFull, "");
    assert_eq!(
        t.on_packet(&e, &data, Instant::now()),
        Step::Done(Outcome::AbortedByClient { code: 3 })
    );
}

#[test]
fn data_from_client_error_4_and_abort() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    match t.on_packet(&encode_data(1, b"x"), &data, Instant::now()) {
        Step::Abort { error, outcome } => {
            assert_eq!(outcome, Outcome::Failed(FailReason::IllegalOperation));
            assert!(matches!(parse(&error), Ok(Packet::Error { code: 4, .. })));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        t.on_packet(&encode_ack(1), &data, Instant::now()),
        Step::Done(_)
    ));
}

#[test]
fn rrq_on_transfer_socket_error_4() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    assert!(matches!(
        t.on_packet(&rrq(&[]), &data, Instant::now()),
        Step::Abort {
            outcome: Outcome::Failed(FailReason::IllegalOperation),
            ..
        }
    ));
}

#[test]
fn foreign_tid_error_5_transfer_continues() {
    let data = file(2000);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    // The caller answers a foreign TID with ERROR 5 and does not feed the
    // datagram to this transfer.
    assert!(matches!(
        parse(&foreign_tid_error()),
        Ok(Packet::Error { code: 5, .. })
    ));
    assert!(matches!(
        t.on_packet(&encode_ack(1), &data, Instant::now()),
        Step::Send(_)
    ));
    assert_eq!(t.current_block(), 2);
}

// ---- File sizes -------------------------------------------------------

#[test]
fn zero_byte_file_one_empty_data() {
    let data = file(0);
    let (mut t, first) = accept(&rrq(&[]), &data).unwrap();
    assert_eq!(
        parse(&first),
        Ok(Packet::Data {
            block: 1,
            data: &[]
        })
    );
    assert_eq!(
        t.on_packet(&encode_ack(1), &data, Instant::now()),
        Step::Done(Outcome::Completed)
    );
}

#[test]
fn exact_multiple_ends_with_empty_data() {
    let data = file(1024);
    let (mut t, _) = accept(&rrq(&[]), &data).unwrap();
    assert_eq!(t.last_block(), 3);
    let now = Instant::now();
    assert!(matches!(
        t.on_packet(&encode_ack(1), &data, now),
        Step::Send(_)
    ));
    match t.on_packet(&encode_ack(2), &data, now) {
        Step::Send(p) => assert_eq!(
            parse(&p),
            Ok(Packet::Data {
                block: 3,
                data: &[]
            })
        ),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        t.on_packet(&encode_ack(3), &data, now),
        Step::Done(Outcome::Completed)
    );
}

fn big_cfg() -> ServerConfig {
    ServerConfig {
        max_file_size: u64::MAX,
        ..ServerConfig::default()
    }
}

#[test]
fn blocks_65535_ok_65536_refused() {
    // blksize 8 keeps the buffers small; 512 and 1468 are covered by the
    // unit test `transfer::tests::block_count_65535_ok_65536_refused`.
    let pkt = rrq(&[(b"blksize", b"8")]);
    match admit(&pkt, &file(65535 * 8 - 1), &big_cfg()).unwrap() {
        Admission::Accept { transfer, .. } => assert_eq!(transfer.last_block(), 65535),
        Admission::Refuse { reason, .. } => panic!("{reason:?}"),
    }
    assert_eq!(
        refuse_reason(&pkt, &file(65535 * 8), &big_cfg()),
        Some((RefuseReason::TooManyBlocks, 3))
    );
}

#[test]
fn blocks_65536_refused_at_512() {
    assert_eq!(
        refuse_reason(&rrq(&[]), &file(65535 * 512), &big_cfg()),
        Some((RefuseReason::TooManyBlocks, 3))
    );
}

#[test]
fn blocks_65536_refused_at_1468() {
    assert_eq!(
        refuse_reason(
            &rrq(&[(b"blksize", b"1468")]),
            &file(65535 * 1468),
            &big_cfg()
        ),
        Some((RefuseReason::TooManyBlocks, 3))
    );
}

#[test]
fn max_file_size_plus_one_refused() {
    let cfg = ServerConfig {
        max_file_size: 4096,
        ..ServerConfig::default()
    };
    assert!(matches!(
        admit(&rrq(&[]), &file(4096), &cfg),
        Some(Admission::Accept { .. })
    ));
    assert_eq!(
        refuse_reason(&rrq(&[]), &file(4097), &cfg),
        Some((RefuseReason::FileTooLarge, 3))
    );
}

// ---- Filenames (REQ-BOOT-041) -----------------------------------------

#[test]
fn traversal_names_passed_through_verbatim() {
    // The parser never decodes or normalises names; the relay matches them
    // byte for byte against the manifest, so none of these can reach a path.
    let long = vec![b'a'; 200];
    let names: [&[u8]; 8] = [
        b"../x",
        b"/etc/passwd",
        b"a/../b",
        b"\\x",
        b"%2e%2e",
        "caf\u{e9}.efi".as_bytes(),
        b"./usgp-test-payload.efi",
        &long,
    ];
    for name in names {
        let p = encode_request(Opcode::Rrq, name, b"octet", &[]);
        match parse(&p) {
            Ok(Packet::Rrq(r)) => assert_eq!(r.filename, name),
            other => panic!("{other:?}"),
        }
    }
}

#[test]
fn embedded_nul_ends_filename() {
    // "a\0b\0octet\0": the name is "a" and the mode is "b"; the leftover
    // "octet" is an unterminated option name, so the packet is malformed.
    assert_eq!(
        parse(b"\x00\x01a\x00b\x00octet"),
        Err(ParseError::OptionUnterminated)
    );
    // With a terminator the name is still only "a", never "a\0b".
    match parse(b"\x00\x01a\x00b\x00") {
        Ok(Packet::Rrq(r)) => assert_eq!(r.filename, b"a"),
        other => panic!("{other:?}"),
    }
}

// ---- Deterministic random sweep (fuzz invariants, plan §10.4) ---------

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn random_packets_parse_and_roundtrip() {
    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    for _ in 0..100_000 {
        let len = usize::try_from(rng.next() % 600).unwrap();
        let mut b: Vec<u8> = (0..len).map(|_| rng.next().to_le_bytes()[0]).collect();
        if let Some(op) = b.get_mut(1) {
            *op %= 8;
        }
        if let Some(op) = b.get_mut(0) {
            *op = 0;
        }
        if let Ok(p) = parse(&b) {
            assert_eq!(parse(&p.encode()), Ok(p));
        }
    }
}

#[test]
fn random_transfer_scripts_hold_invariants() {
    use std::time::Duration;
    let mut rng = XorShift(0x0123_4567_89ab_cdef);
    for _ in 0..2_000 {
        let data = file(usize::try_from(rng.next() % 6000).unwrap());
        let opts: &[(&[u8], &[u8])] = match rng.next() % 3 {
            0 => &[],
            1 => &[(b"blksize", b"700"), (b"tsize", b"0")],
            _ => &[(b"blksize", b"8")],
        };
        let t0 = Instant::now();
        let Some((mut t, _)) = accept(&rrq(opts), &data) else {
            continue;
        };
        let mut now = t0;
        let mut highest = t.current_block();
        let mut done = None;
        for _ in 0..400 {
            let r = rng.next();
            let step = if r.is_multiple_of(5) {
                now = t.deadline();
                t.on_timeout(&data, now)
            } else {
                now += Duration::from_millis(r % 50);
                let cur = t.current_block();
                let block = match r % 4 {
                    0 => cur.saturating_sub(1),
                    1 => cur.wrapping_add(1),
                    _ => cur,
                };
                let dup = block < cur;
                let s = t.on_packet(&encode_ack(block), &data, now);
                if dup {
                    assert!(!matches!(s, Step::Send(_)), "send on duplicate ACK");
                }
                s
            };
            if let Some(d) = done {
                assert_eq!(step, Step::Done(d), "Done is final");
            }
            match step {
                Step::Send(p) => {
                    if let Ok(Packet::Data { block, .. }) = parse(&p) {
                        assert!(block >= highest && block <= t.last_block());
                        highest = block;
                    }
                }
                Step::Done(o) | Step::Abort { outcome: o, .. } => done = Some(o),
                Step::Wait => {}
            }
            assert!(t.current_retries() <= 5);
        }
    }
}
