//! XPRESS LZ77+Huffman decoder vectors (plan §10, "XPRESS" row; WU-X).
//!
//! Every vector is made by our own test encoder (decision 0006: no
//! third-party vectors). Proves: round trip, exact output length, symbol
//! 256 handling, and that each bound of wim-compression.md §6 yields an
//! error rather than a panic, without writing past the expected size.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10
//   (Information Input Validation)
// - SPEC: specs/os-images.md#REQ-IMG-037
// - SPEC: specs/standards/wim-compression.md §3, §6

// The encoder is the crate's test encoder (feature `testkit`).
#![cfg(feature = "testkit")]

#[cfg(test)]
mod vectors {
    use usgp_image::codec::{CodecError, XpressDecoder, decode_xpress_chunk};
    use usgp_image::testkit::xpress_enc::{
        BLOCK_OUTPUT_BYTES, Block, EncodeError, MAX_CODE_LEN, MAX_MATCH, SYMBOLS, Token,
        blocks_for, compress, compress_literals, encode_blocks, huffman_lengths,
    };

    /// WIM chunk size (wim.md §4).
    const CHUNK: usize = 32768;
    const SENTINEL: u8 = 0xA5;

    /// Small deterministic generator (xorshift64*), so vectors are
    /// reproducible without a dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next().to_le_bytes()[0]).collect()
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % u64::try_from(n).unwrap()).unwrap()
        }
    }

    /// Decodes into a buffer of exactly `expected` bytes followed by a
    /// sentinel region, and checks the sentinel region is untouched.
    fn decode(input: &[u8], expected: usize) -> Result<Vec<u8>, CodecError> {
        let mut buf = vec![SENTINEL; expected + 64];
        let r = decode_xpress_chunk(input, &mut buf[..expected]);
        assert!(
            buf[expected..].iter().all(|&b| b == SENTINEL),
            "decoder wrote past the expected output length"
        );
        r.map(|()| buf[..expected].to_vec())
    }

    fn text(n: usize) -> Vec<u8> {
        let phrase = b"The quick brown fox jumps over the lazy dog. 0123456789\n";
        phrase.iter().copied().cycle().take(n).collect()
    }

    fn samples() -> Vec<(&'static str, Vec<u8>)> {
        let mut rng = Rng(0x0123_4567_89AB_CDEF);
        let mut mixed = text(10_000);
        mixed.extend(rng.bytes(10_000));
        mixed.extend(vec![0u8; 12_768]);
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x42]),
            ("two bytes", vec![1, 2]),
            ("text 1000", text(1000)),
            ("zeros chunk", vec![0; CHUNK]),
            ("random chunk", rng.bytes(CHUNK)),
            ("text chunk", text(CHUNK)),
            ("mixed chunk", mixed),
            ("last chunk 1234", rng.bytes(1234)),
            ("chunk minus one", text(CHUNK - 1)),
            ("one block exact", text(BLOCK_OUTPUT_BYTES)),
            ("multi block", text(150_000)),
            ("multi block random", rng.bytes(140_000)),
        ]
    }

    #[test]
    fn round_trip_with_matches() {
        for (name, data) in samples() {
            let enc = compress(&data);
            let dec = decode(&enc, data.len()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(dec, data, "{name}");
        }
    }

    #[test]
    fn round_trip_literals_only() {
        for (name, data) in samples() {
            let enc = compress_literals(&data);
            let dec = decode(&enc, data.len()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(dec, data, "{name}");
        }
    }

    #[test]
    fn random_round_trips() {
        let mut rng = Rng(42);
        for _ in 0..200 {
            let len = rng.below(3000);
            // Low-entropy data so matches of every kind appear.
            let alphabet = 1 + rng.below(6);
            let data: Vec<u8> = (0..len)
                .map(|_| u8::try_from(rng.below(alphabet)).unwrap())
                .collect();
            let enc = compress(&data);
            assert_eq!(decode(&enc, data.len()).unwrap(), data);
        }
    }

    #[test]
    fn matches_actually_compress() {
        let data = vec![0u8; CHUNK];
        let enc = compress(&data);
        assert!(enc.len() < 400, "zeros compressed to {} bytes", enc.len());
    }

    #[test]
    fn exact_output_length_is_required() {
        let data = text(5000);
        let enc = compress(&data);
        // One byte short: the stream needs more room.
        assert!(decode(&enc, data.len() - 1).is_err());
        // One byte long: never succeeds.
        assert!(decode(&enc, data.len() + 1).is_err());
        assert_eq!(decode(&enc, data.len()).unwrap(), data);
    }

    #[test]
    fn decoder_reuse_across_chunks() {
        let mut d = XpressDecoder::new();
        for (_, data) in samples() {
            let enc = compress(&data);
            let mut out = vec![0u8; data.len()];
            d.decode_chunk(&enc, &mut out).unwrap();
            assert_eq!(out, data);
            // A bad chunk in between does not poison the next one.
            assert!(d.decode_chunk(&[0u8; 300], &mut out).is_err());
        }
    }

    // ---- symbol 256 (wim-compression.md §3.6) ----

    #[test]
    fn end_symbol_mid_stream_is_a_match() {
        // 256 before the end is length 3, offset 1.
        let block = Block::with_optimal_lengths(vec![
            Token::Literal(b'x'),
            Token::End,
            Token::Literal(b'y'),
            Token::End,
        ]);
        let enc = encode_blocks(&[block]).unwrap();
        assert_eq!(decode(&enc, 5).unwrap(), b"xxxxy");
    }

    #[test]
    fn stream_without_end_symbol_and_output_full_is_overrun() {
        // FORMAT: derived - per the reference, decoding continues inside
        // the block after the expected size and only symbol 256 at the
        // end of the input stops it. Here the padding decodes as a
        // further literal, which would write past the expected size.
        let block = Block::with_optimal_lengths(vec![Token::Literal(b'a'), Token::Literal(b'b')]);
        let enc = encode_blocks(&[block]).unwrap();
        assert_eq!(decode(&enc, 2), Err(CodecError::OutputOverrun));
    }

    #[test]
    fn full_block_needs_no_end_symbol() {
        // §3.6: after a full block, input too short for another table
        // ends the data.
        let data = text(BLOCK_OUTPUT_BYTES);
        let tokens: Vec<Token> = data.iter().map(|&b| Token::Literal(b)).collect();
        let enc = encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap();
        assert_eq!(decode(&enc, data.len()).unwrap(), data);
    }

    // ---- table bounds (§3.2) ----

    fn lengths(pairs: &[(usize, u8)]) -> [u8; SYMBOLS] {
        let mut l = [0u8; SYMBOLS];
        for &(s, n) in pairs {
            l[s] = n;
        }
        l
    }

    fn table_only(l: [u8; SYMBOLS]) -> Vec<u8> {
        let mut enc = encode_blocks(&[Block {
            lengths: l,
            tokens: Vec::new(),
        }])
        .unwrap();
        enc.extend_from_slice(&[0; 8]);
        enc
    }

    #[test]
    fn overfull_tables_rejected() {
        let all_one = [1u8; SYMBOLS];
        assert_eq!(
            decode(&table_only(all_one), 10),
            Err(CodecError::HuffmanTableOverfull)
        );
        let three = lengths(&[(0, 1), (1, 1), (2, 2)]);
        assert_eq!(
            decode(&table_only(three), 10),
            Err(CodecError::HuffmanTableOverfull)
        );
        // Lengths 1, 2, 3, 3 fill the code space exactly; one more 15-bit
        // code overfills it by a single entry.
        let mut deep = [0u8; SYMBOLS];
        deep[0] = 1;
        deep[1] = 2;
        deep[2] = 3;
        deep[3] = 3;
        deep[4] = MAX_CODE_LEN;
        assert_eq!(
            decode(&table_only(deep), 10),
            Err(CodecError::HuffmanTableOverfull)
        );
    }

    #[test]
    fn underfull_tables_rejected() {
        for l in [
            [0u8; SYMBOLS],
            lengths(&[(65, 1)]),
            lengths(&[(0, 2), (1, 2), (2, 2)]),
            [MAX_CODE_LEN; SYMBOLS],
            lengths(&[(0, 1), (1, 2), (2, 3), (3, 4), (4, 15)]),
        ] {
            assert_eq!(
                decode(&table_only(l), 10),
                Err(CodecError::HuffmanTableIncomplete)
            );
        }
    }

    #[test]
    fn deepest_complete_code_decodes() {
        // Lengths 1..=14 then two 15s: a complete code using every depth.
        let mut l = [0u8; SYMBOLS];
        for (s, n) in (1u8..=15).enumerate() {
            l[s] = n;
        }
        l[15] = MAX_CODE_LEN;
        // Use the two deepest symbols (14 and 15) and symbol 0.
        let tokens = vec![
            Token::Literal(14),
            Token::Literal(15),
            Token::Literal(0),
            Token::Literal(15),
        ];
        let enc = encode_blocks(&[Block { lengths: l, tokens }]).unwrap();
        // No end symbol in this code, so ask for exactly 4 bytes and
        // expect the padding to overrun (as above), proving the four
        // literals decoded first.
        let mut out = vec![0u8; 4];
        let r = decode_xpress_chunk(&enc, &mut out);
        assert_eq!(out, [14, 15, 0, 15]);
        assert!(r.is_err());
    }

    // ---- extended length (§3.4) ----

    fn ext_len_stream(length_bytes: Vec<u8>) -> Vec<u8> {
        // Literal 'q', then a match symbol with header 15 and 0 offset
        // bits (offset 1), then the end symbol.
        let tokens = vec![
            Token::Literal(b'q'),
            Token::Raw {
                symbol: 256 + 15,
                length_bytes,
                offset_bits: 0,
            },
            Token::End,
        ];
        encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap()
    }

    #[test]
    fn extended_length_below_15_rejected() {
        for v in 0u16..15 {
            let [lo, hi] = v.to_le_bytes();
            assert_eq!(
                decode(&ext_len_stream(vec![255, lo, hi]), 1 + 18),
                Err(CodecError::ExtendedLengthTooSmall),
                "v = {v}"
            );
        }
    }

    #[test]
    fn extended_length_boundaries() {
        // v = 15 is the smallest valid 16-bit length: 15 + 3 = 18.
        let enc = ext_len_stream(vec![255, 15, 0]);
        assert_eq!(decode(&enc, 1 + 18).unwrap(), vec![b'q'; 19]);
        // One byte 0: 0 + 15 + 3 = 18.
        let enc = ext_len_stream(vec![0]);
        assert_eq!(decode(&enc, 19).unwrap(), vec![b'q'; 19]);
        // One byte 254: 254 + 18 = 272.
        let enc = ext_len_stream(vec![254]);
        assert_eq!(decode(&enc, 273).unwrap(), vec![b'q'; 273]);
        // Through the encoder (one literal, then one match of n - 1):
        // n = 19 is the first one-byte form, n = 274 the first 16-bit form.
        for n in [17usize, 18, 19, 272, 273, 274, 275, 1000, 40_000] {
            let data = vec![7u8; n];
            assert_eq!(decode(&compress(&data), n).unwrap(), data, "n = {n}");
        }
    }

    #[test]
    fn longest_match_may_cross_the_block_end() {
        // §3.6: the block ends once 65536 bytes are produced; a match is
        // copied whole first. 1 + 65538 bytes in one block.
        let tokens = vec![
            Token::Literal(9),
            Token::Match {
                length: MAX_MATCH,
                offset: 1,
            },
        ];
        let enc = encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap();
        let n = 1 + usize::try_from(MAX_MATCH).unwrap();
        assert_eq!(decode(&enc, n).unwrap(), vec![9u8; n]);
        // The next block starts where the previous one ended.
        let mut blocks = vec![Block::with_optimal_lengths(vec![
            Token::Literal(1),
            Token::Match {
                length: 65_537,
                offset: 1,
            },
        ])];
        blocks.push(Block::with_optimal_lengths(vec![
            Token::Literal(2),
            Token::Match {
                length: 5,
                offset: 65_535,
            },
            Token::End,
        ]));
        let enc = encode_blocks(&blocks).unwrap();
        let mut want = vec![1u8; 65_538];
        want.push(2);
        let start = want.len() - 65_535;
        let copied: Vec<u8> = want[start..start + 5].to_vec();
        want.extend(copied);
        assert_eq!(decode(&enc, want.len()).unwrap(), want);
    }

    // ---- offsets (§3.5) ----

    #[test]
    fn offset_before_output_start_rejected() {
        let cases = vec![
            vec![Token::Match {
                length: 3,
                offset: 1,
            }],
            vec![
                Token::Literal(1),
                Token::Match {
                    length: 3,
                    offset: 2,
                },
            ],
            vec![
                Token::Literal(1),
                Token::Literal(2),
                Token::Match {
                    length: 4,
                    offset: 65_535,
                },
            ],
        ];
        for mut tokens in cases {
            tokens.push(Token::End);
            let enc = encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap();
            assert_eq!(decode(&enc, 100), Err(CodecError::OffsetBeforeStart));
        }
    }

    #[test]
    fn every_offset_width_round_trips() {
        // Offsets 2^n and 2^(n+1) - 1 for n = 0..=15.
        let mut rng = Rng(7);
        let prefix = rng.bytes(65_535);
        for n in 0u32..16 {
            for offset in [1u32 << n, (1u32 << (n + 1)) - 1] {
                let mut tokens: Vec<Token> = prefix.iter().map(|&b| Token::Literal(b)).collect();
                tokens.push(Token::Match { length: 4, offset });
                tokens.push(Token::End);
                // Fit in one block: 65535 + 4 crosses 65536, which is
                // allowed (the match is copied whole).
                let enc = encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap();
                let mut want = prefix.clone();
                let start = want.len() - usize::try_from(offset).unwrap();
                for i in 0..4 {
                    want.push(want[start + i]);
                }
                let mut out = vec![0u8; want.len()];
                let r = decode_xpress_chunk(&enc, &mut out);
                // The block ends inside the match; the end symbol is then
                // left unread and fewer than 256 bytes remain.
                assert_eq!(r, Ok(()), "offset {offset}");
                assert_eq!(out, want, "offset {offset}");
            }
        }
    }

    // ---- input exhaustion and output bounds (§3.6, §6) ----

    #[test]
    fn every_truncation_is_an_error() {
        // BOOT-002: a refill past the end of the input is InputExhausted at
        // once (wim-compression.md §3.6, §6), so no proper prefix of a
        // valid chunk decodes, not even one missing only zero padding.
        for data in [text(700), vec![0u8; 2000], Rng(3).bytes(600)] {
            let enc = compress(&data);
            assert_eq!(decode(&enc, data.len()), Ok(data.clone()));
            for cut in 0..enc.len() {
                assert!(decode(&enc[..cut], data.len()).is_err(), "cut {cut}");
            }
            // The last two bytes (one 16-bit unit) removed: refused as
            // exhausted input, not accepted with zero bits put in.
            assert_eq!(
                decode(&enc[..enc.len() - 2], data.len()),
                Err(CodecError::InputExhausted)
            );
        }
    }

    #[test]
    fn truncated_mid_stream_is_input_exhausted() {
        let data = Rng(11).bytes(4000);
        let enc = compress_literals(&data);
        // Keep the table and half the bits.
        let cut = 256 + (enc.len() - 256) / 2;
        assert_eq!(
            decode(&enc[..cut], data.len()),
            Err(CodecError::InputExhausted)
        );
    }

    #[test]
    fn missing_extra_length_byte_is_input_exhausted() {
        // Three short codes: all bits fit in the first two units, so the
        // stream is table, two units, then the extra length byte.
        let enc = ext_len_stream(vec![254]);
        assert_eq!(enc.len(), 256 + 4 + 1);
        assert_eq!(decode(&enc[..260], 273), Err(CodecError::InputExhausted));
        assert_eq!(decode(&enc, 273).unwrap(), vec![b'q'; 273]);
    }

    #[test]
    fn short_output_when_input_ends_at_a_block_boundary() {
        let data = text(BLOCK_OUTPUT_BYTES);
        let tokens: Vec<Token> = data.iter().map(|&b| Token::Literal(b)).collect();
        let enc = encode_blocks(&[Block::with_optimal_lengths(tokens)]).unwrap();
        assert_eq!(decode(&enc, data.len() + 10), Err(CodecError::ShortOutput));
        assert_eq!(decode(&[0u8; 255], 1), Err(CodecError::ShortOutput));
    }

    #[test]
    fn output_overrun_never_writes_past_expected_size() {
        let data = text(3000);
        for expected in [0usize, 1, 2, 3, 100, 2999] {
            assert_eq!(
                decode(&compress(&data), expected),
                Err(CodecError::OutputOverrun),
                "expected {expected}"
            );
            assert_eq!(
                decode(&compress_literals(&data), expected),
                Err(CodecError::OutputOverrun),
                "expected {expected}"
            );
        }
        // A single long match that would cross the end.
        let zeros = vec![0u8; 5000];
        assert_eq!(
            decode(&compress(&zeros), 4000),
            Err(CodecError::OutputOverrun)
        );
    }

    // ---- robustness ----

    #[test]
    fn random_input_never_panics() {
        let mut rng = Rng(0xDEAD_BEEF);
        for _ in 0..2000 {
            let len = rng.below(1200);
            let input = rng.bytes(len);
            let expected = rng.below(CHUNK + 1);
            let _ = decode(&input, expected);
        }
    }

    #[test]
    fn random_valid_table_with_random_bits_never_panics() {
        // A valid table followed by noise reaches the match paths.
        let mut rng = Rng(99);
        let mut freq = [1u64; SYMBOLS];
        for f in freq.iter_mut() {
            *f = 1 + rng.next() % 1000;
        }
        let l = huffman_lengths(&freq);
        let table = encode_blocks(&[Block {
            lengths: l,
            tokens: Vec::new(),
        }])
        .unwrap();
        for _ in 0..2000 {
            let mut input = table[..256].to_vec();
            let len = rng.below(600);
            input.extend(rng.bytes(len));
            let expected = rng.below(CHUNK + 1);
            let _ = decode(&input, expected);
        }
    }

    #[test]
    fn mutated_streams_never_panic() {
        let data = text(CHUNK);
        let enc = compress(&data);
        let mut rng = Rng(5);
        for _ in 0..500 {
            let mut m = enc.clone();
            for _ in 0..1 + rng.below(4) {
                let i = rng.below(m.len());
                m[i] ^= 1 << rng.below(8);
            }
            if let Ok(out) = decode(&m, data.len()) {
                assert_eq!(out.len(), data.len());
            }
        }
    }

    // ---- encoder self-checks ----

    #[test]
    fn encoder_refuses_symbol_without_code() {
        let block = Block {
            lengths: lengths(&[(0, 1), (1, 1)]),
            tokens: vec![Token::Literal(2)],
        };
        assert_eq!(
            encode_blocks(&[block]),
            Err(EncodeError::NoCode { symbol: 2 })
        );
        assert_eq!(
            EncodeError::NoCode { symbol: 2 }.to_string(),
            "symbol 2 has no code"
        );
        let bad = Block {
            lengths: [16; SYMBOLS],
            tokens: Vec::new(),
        };
        assert_eq!(encode_blocks(&[bad]), Err(EncodeError::BadSymbol));
        let block = Block::with_optimal_lengths(vec![Token::Match {
            length: 2,
            offset: 1,
        }]);
        assert_eq!(encode_blocks(&[block]), Err(EncodeError::BadMatch));
    }

    #[test]
    fn encoder_blocks_split_at_block_size() {
        let blocks = blocks_for(&text(150_000), true);
        assert_eq!(blocks.len(), 3);
        assert!(blocks.last().unwrap().tokens.ends_with(&[Token::End]));
    }

    #[test]
    fn codec_error_text_is_fixed() {
        for e in [
            CodecError::HuffmanTableOverfull,
            CodecError::HuffmanTableIncomplete,
            CodecError::ExtendedLengthTooSmall,
            CodecError::OffsetBeforeStart,
            CodecError::InputExhausted,
            CodecError::OutputOverrun,
            CodecError::ShortOutput,
        ] {
            assert!(!e.to_string().is_empty());
            assert!(
                e.reason_code()
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b == b'_')
            );
        }
    }
}
