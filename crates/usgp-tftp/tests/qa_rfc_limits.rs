//! QA gap tests (qa-engineer, M1): RFC 2347/2348/2349 negotiation
//! properties and the 16-bit block-number limit driven to its end.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11, SI-10
//! - SPEC: specs/boot-network.md#REQ-BOOT-031, #REQ-BOOT-035
//! - RFC 1350 §5 (16-bit block numbers); RFC 2347 (option names are
//!   case-insensitive; the OACK holds only options the client asked for);
//!   RFC 2348 (8..=65464, never more than requested); RFC 2349 (tsize 0
//!   in an RRQ asks for the size)

#[cfg(test)]
mod qa {
    use std::time::Instant;

    use usgp_tftp::{
        Admission, Opcode, Outcome, Packet, ServerConfig, Step, admit_read, encode_ack,
        encode_request, parse,
    };

    const NAME: &[u8] = b"usgp-test-payload.efi";

    fn admit(opts: &[(&[u8], &[u8])], data: &[u8], cfg: &ServerConfig) -> Admission {
        let pkt = encode_request(Opcode::Rrq, NAME, b"octet", opts);
        let Ok(Packet::Rrq(r)) = parse(&pkt) else {
            panic!("bad RRQ");
        };
        admit_read(&r, data, cfg, Instant::now())
    }

    fn big_cfg() -> ServerConfig {
        ServerConfig {
            max_file_size: u64::MAX,
            ..ServerConfig::default()
        }
    }

    /// REQ-BOOT-035 at the very top of the range: a file that needs
    /// exactly 65535 DATA packets (blksize 8) is delivered completely and
    /// byte-exact; block numbers rise by one each time, the last is 65535,
    /// and no number ever wraps to 0.
    #[test]
    fn full_65535_block_transfer_never_wraps() {
        let data: Vec<u8> = (0..65535usize * 8 - 1)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect();
        let Admission::Accept {
            mut transfer,
            first,
        } = admit(&[(b"blksize", b"8")], &data, &big_cfg())
        else {
            panic!("refused");
        };
        assert!(matches!(parse(&first), Ok(Packet::Oack(_))));
        let mut out = Vec::with_capacity(data.len());
        let mut ack: u16 = 0;
        let mut prev: u16 = 0;
        let now = Instant::now();
        loop {
            match transfer.on_packet(&encode_ack(ack), &data, now) {
                Step::Send(p) => match parse(&p) {
                    Ok(Packet::Data { block, data: d }) => {
                        assert_eq!(block, prev.checked_add(1).unwrap(), "strictly +1");
                        assert!(d.len() <= 8);
                        out.extend_from_slice(d);
                        prev = block;
                        ack = block;
                    }
                    other => panic!("{other:?}"),
                },
                Step::Done(Outcome::Completed) => break,
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(prev, 65535);
        assert_eq!(out, data);
    }

    /// One octet more needs 65536 packets: refused with ERROR 3 before any
    /// OACK or DATA, at several negotiated sizes (8, 1024, 1468).
    #[test]
    fn one_octet_over_refused_at_each_block_size() {
        for (bs, text) in [(8usize, &b"8"[..]), (1024, b"1024"), (1468, b"1468")] {
            let ok = vec![0u8; 65535 * bs - 1];
            assert!(
                matches!(
                    admit(&[(b"blksize", text)], &ok, &big_cfg()),
                    Admission::Accept { .. }
                ),
                "bs {bs}"
            );
            drop(ok);
            let over = vec![0u8; 65535 * bs];
            match admit(&[(b"blksize", text), (b"tsize", b"0")], &over, &big_cfg()) {
                Admission::Refuse { error, .. } => {
                    assert!(
                        matches!(parse(&error), Ok(Packet::Error { code: 3, .. })),
                        "bs {bs}"
                    );
                }
                Admission::Accept { .. } => panic!("bs {bs}: accepted a file needing 65536 blocks"),
            }
        }
    }

    /// RFC 2347: option names are case-insensitive.
    #[test]
    fn option_names_case_insensitive() {
        let data = vec![7u8; 3000];
        let Admission::Accept { transfer, first } = admit(
            &[(b"BlkSize", b"1024"), (b"TSIZE", b"0")],
            &data,
            &ServerConfig::default(),
        ) else {
            panic!("refused");
        };
        assert_eq!(transfer.block_size(), 1024);
        assert_eq!(transfer.tsize(), Some(3000));
        let Ok(Packet::Oack(list)) = parse(&first) else {
            panic!("no OACK");
        };
        let names: Vec<Vec<u8>> = list.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        assert!(names.contains(&b"blksize".to_vec()));
        assert!(names.contains(&b"tsize".to_vec()));
    }

    struct XorShift(u64);

    impl XorShift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    /// Property over random option sets: the OACK only holds options the
    /// client requested; blksize is in 8..=min(requested, configured);
    /// tsize equals the file size and is sent only for a request of "0";
    /// every DATA payload is at most the negotiated size; timeout and
    /// windowsize are never acknowledged (tftp.md sections 6 and 7).
    #[test]
    fn negotiation_properties_hold_for_random_option_sets() {
        let names: [&[u8]; 6] = [
            b"blksize",
            b"tsize",
            b"timeout",
            b"windowsize",
            b"x-other",
            b"BLKSIZE",
        ];
        let values: [&[u8]; 12] = [
            b"0",
            b"1",
            b"7",
            b"8",
            b"9",
            b"512",
            b"1468",
            b"1469",
            b"65464",
            b"65465",
            b"99999999999999999999",
            b"12a",
        ];
        let mut rng = XorShift(0x1234_5678_9abc_def1);
        let mut oacks = 0u32;
        for _ in 0..20_000 {
            let n = usize::try_from(rng.next() % 4).unwrap();
            let mut opts: Vec<(&[u8], &[u8])> = Vec::new();
            for _ in 0..n {
                let name = names[usize::try_from(rng.next()).unwrap() % names.len()];
                let value = values[usize::try_from(rng.next()).unwrap() % values.len()];
                if opts.iter().any(|(o, _)| o.eq_ignore_ascii_case(name)) {
                    continue; // duplicates are covered by the negative suite
                }
                opts.push((name, value));
            }
            let len = usize::try_from(rng.next() % 5000).unwrap();
            let data = vec![0x5au8; len];
            let cfg_max = [512u16, 1468, 8192][usize::try_from(rng.next() % 3).unwrap()];
            let cfg = ServerConfig {
                max_block_size: cfg_max,
                ..ServerConfig::default()
            };
            let Admission::Accept {
                mut transfer,
                first,
            } = admit(&opts, &data, &cfg)
            else {
                continue;
            };
            let requested = |want: &[u8]| {
                opts.iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(want))
                    .map(|(_, v)| *v)
            };
            let bs = usize::from(transfer.block_size());
            match parse(&first) {
                Ok(Packet::Oack(list)) => {
                    oacks += 1;
                    for (name, value) in list.iter() {
                        let asked = requested(name).unwrap_or_else(|| {
                            panic!("OACK option {name:?} was not requested: {opts:?}")
                        });
                        let lname = name.to_ascii_lowercase();
                        assert!(
                            lname == b"blksize" || lname == b"tsize",
                            "acknowledged {name:?}"
                        );
                        let v: u64 = std::str::from_utf8(value).unwrap().parse().unwrap();
                        if lname == b"blksize" {
                            let req: u64 = std::str::from_utf8(asked).unwrap().parse().unwrap();
                            assert!(v >= 8 && v <= req && v <= u64::from(cfg_max), "{v}");
                            assert_eq!(usize::try_from(v).unwrap(), bs);
                        } else {
                            assert_eq!(asked, b"0", "tsize only for a request of 0");
                            assert_eq!(v, u64::try_from(len).unwrap());
                        }
                    }
                }
                Ok(Packet::Data { block: 1, data: d }) => {
                    assert_eq!(bs, 512, "no OACK means the 512 default");
                    assert!(d.len() <= 512);
                }
                other => panic!("{other:?}"),
            }
            // Drive to completion; every DATA fits the negotiated size.
            let mut ack = 0u16;
            let now = Instant::now();
            loop {
                match transfer.on_packet(&encode_ack(ack), &data, now) {
                    Step::Send(p) => {
                        if let Ok(Packet::Data { block, data: d }) = parse(&p) {
                            assert!(d.len() <= bs);
                            ack = block;
                        }
                    }
                    Step::Done(Outcome::Completed) => break,
                    Step::Wait if ack == 0 => ack = 1, // DATA 1 already sent
                    other => panic!("{other:?}"),
                }
            }
        }
        assert!(oacks > 1000, "only {oacks} OACKs");
    }
}
