//! Test-only XPRESS LZ77+Huffman encoder (feature `testkit`).
//!
//! Our own encoder, written from the decoder rules in
//! `specs/standards/wim-compression.md` §3, used only to make test vectors
//! and fuzz seeds. It is not used by the product and is not tuned for
//! ratio or speed: greedy matches against the last position with the same
//! three bytes, one Huffman table per 65536-byte block.
//!
//! [`encode_blocks`] writes any token sequence under any code-length table,
//! including invalid ones, so tests can build each malformed case of
//! wim-compression.md §6 directly.
//!
//! This file depends only on `std`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/standards/wim-compression.md §3, §6
//
// FORMAT: OBS-012, OBS-013 - stream layout follows the decoder in
// `codec/xpress.rs`: one table per chunk, ending with symbol 256 read
// exactly at the end of the input, as DISM's chunks do in run R1.

use std::collections::HashMap;
use std::fmt;

/// Output bytes per Huffman block (wim-compression.md §3.1).
pub const BLOCK_OUTPUT_BYTES: usize = 65536;
/// Symbols in the alphabet (§3.1).
pub const SYMBOLS: usize = 512;
/// Longest code (§3.1).
pub const MAX_CODE_LEN: u8 = 15;
/// End-of-data symbol (§3.6).
pub const END_SYMBOL: u16 = 256;
/// Shortest match (§3.4).
pub const MIN_MATCH: u32 = 3;
/// Longest match the length encoding can express: 16-bit value + 3 (§3.4).
pub const MAX_MATCH: u32 = 0xffff + MIN_MATCH;
/// Largest offset (§3.5).
pub const MAX_OFFSET: u32 = 0xffff;

/// One item of the encoded stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A literal byte (symbols 0 to 255).
    Literal(u8),
    /// A match, `MIN_MATCH..=MAX_MATCH` bytes copied from `offset`
    /// (1 to 65535) bytes back.
    Match {
        /// Bytes to copy.
        length: u32,
        /// Distance back.
        offset: u32,
    },
    /// Symbol 256 with no extra data (§3.6).
    End,
    /// Any symbol, followed by the given bytes written at the decoder's
    /// input position and then `offset_bits` written as the symbol's
    /// `(symbol - 256) / 16` extra offset bits. For building invalid
    /// streams.
    Raw {
        /// Symbol 0 to 511.
        symbol: u16,
        /// Extra length bytes, written as is.
        length_bytes: Vec<u8>,
        /// Extra offset bits value (only the low `n` bits are written).
        offset_bits: u16,
    },
}

/// One Huffman block: its code lengths and its tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Code length (0 to 15) of each of the 512 symbols.
    pub lengths: [u8; SYMBOLS],
    /// Tokens in order.
    pub tokens: Vec<Token>,
}

impl Block {
    /// A block whose code lengths are computed from its own tokens.
    #[must_use]
    pub fn with_optimal_lengths(tokens: Vec<Token>) -> Self {
        let mut freq = [0u64; SYMBOLS];
        for t in &tokens {
            if let Some(f) = token_symbol(t).and_then(|s| freq.get_mut(usize::from(s))) {
                *f = f.saturating_add(1);
            }
        }
        Self {
            lengths: huffman_lengths(&freq),
            tokens,
        }
    }
}

/// Why [`encode_blocks`] could not write a token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// A token's symbol has code length 0 in its block.
    NoCode {
        /// The symbol.
        symbol: u16,
    },
    /// A symbol over 511 or a code length over 15.
    BadSymbol,
    /// A match length or offset outside the encodable range.
    BadMatch,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCode { symbol } => write!(f, "symbol {symbol} has no code"),
            Self::BadSymbol => f.write_str("symbol or code length out of range"),
            Self::BadMatch => f.write_str("match length or offset out of range"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Compresses `data` with literals and greedy matches, appending the end
/// symbol (§3.6 recommends it).
#[must_use]
pub fn compress(data: &[u8]) -> Vec<u8> {
    encode_or_empty(&blocks_for(data, true))
}

/// Compresses `data` with literals only, appending the end symbol.
#[must_use]
pub fn compress_literals(data: &[u8]) -> Vec<u8> {
    encode_or_empty(&blocks_for(data, false))
}

/// Token blocks for `data`: one per 65536 output bytes, no match crossing
/// a block boundary, `End` in the last block.
#[must_use]
pub fn blocks_for(data: &[u8], use_matches: bool) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut tokens = Vec::new();
    let mut block_start: usize = 0;
    let mut pos: usize = 0;
    let mut last_seen: HashMap<[u8; 3], usize> = HashMap::new();
    while pos < data.len() {
        let block_end = block_start.saturating_add(BLOCK_OUTPUT_BYTES);
        let found = if use_matches {
            find_match(data, pos, block_end, &last_seen)
        } else {
            None
        };
        let advance = match found {
            Some((length, offset)) => {
                tokens.push(Token::Match {
                    length: u32::try_from(length).unwrap_or(MIN_MATCH),
                    offset: u32::try_from(offset).unwrap_or(1),
                });
                length
            }
            None => {
                tokens.push(Token::Literal(data.get(pos).copied().unwrap_or(0)));
                1
            }
        };
        let next = pos.saturating_add(advance);
        if use_matches {
            for p in pos..next {
                if let Some(key) = key_at(data, p) {
                    last_seen.insert(key, p);
                }
            }
        }
        pos = next;
        if pos >= block_end && pos < data.len() {
            blocks.push(Block::with_optimal_lengths(std::mem::take(&mut tokens)));
            block_start = block_end;
        }
    }
    tokens.push(Token::End);
    blocks.push(Block::with_optimal_lengths(tokens));
    blocks
}

fn encode_or_empty(blocks: &[Block]) -> Vec<u8> {
    // Blocks built by `blocks_for` always encode.
    encode_blocks(blocks).unwrap_or_default()
}

fn key_at(data: &[u8], p: usize) -> Option<[u8; 3]> {
    let s = data.get(p..p.checked_add(3)?)?;
    <[u8; 3]>::try_from(s).ok()
}

/// Longest match at `pos` against the last position with the same three
/// bytes, limited to the block and the encodable ranges.
fn find_match(
    data: &[u8],
    pos: usize,
    block_end: usize,
    last_seen: &HashMap<[u8; 3], usize>,
) -> Option<(usize, usize)> {
    let cand = *last_seen.get(&key_at(data, pos)?)?;
    let offset = pos.checked_sub(cand)?;
    if offset == 0 || offset > usize::try_from(MAX_OFFSET).ok()? {
        return None;
    }
    let limit = block_end
        .min(data.len())
        .checked_sub(pos)?
        .min(usize::try_from(MAX_MATCH).ok()?);
    let mut length = 0usize;
    while length < limit {
        let a = data.get(cand.checked_add(length)?)?;
        let b = data.get(pos.checked_add(length)?)?;
        if a != b {
            break;
        }
        length = length.checked_add(1)?;
    }
    (length >= usize::try_from(MIN_MATCH).ok()?).then_some((length, offset))
}

/// The symbol a token is coded with, if it has a valid one.
#[must_use]
pub fn token_symbol(t: &Token) -> Option<u16> {
    match t {
        Token::Literal(b) => Some(u16::from(*b)),
        Token::End => Some(END_SYMBOL),
        Token::Raw { symbol, .. } => Some(*symbol),
        Token::Match { length, offset } => match_parts(*length, *offset).ok().map(|m| m.symbol),
    }
}

struct MatchParts {
    symbol: u16,
    length_bytes: Vec<u8>,
    offset_bits: u16,
}

/// Splits a match into its symbol, extra length bytes and offset bits
/// (§3.4, §3.5).
fn match_parts(length: u32, offset: u32) -> Result<MatchParts, EncodeError> {
    if !(MIN_MATCH..=MAX_MATCH).contains(&length) || !(1..=MAX_OFFSET).contains(&offset) {
        return Err(EncodeError::BadMatch);
    }
    let l = length - MIN_MATCH;
    let (header, length_bytes) = if l < 15 {
        (l, Vec::new())
    } else if l - 15 < 255 {
        (
            15,
            vec![u8::try_from(l - 15).map_err(|_| EncodeError::BadMatch)?],
        )
    } else {
        let v = u16::try_from(l).map_err(|_| EncodeError::BadMatch)?;
        let [lo, hi] = v.to_le_bytes();
        (15, vec![255, lo, hi])
    };
    let n = 31 - offset.leading_zeros();
    let offset_bits = u16::try_from(offset - (1u32 << n)).map_err(|_| EncodeError::BadMatch)?;
    let symbol = u16::try_from(256 + n * 16 + header).map_err(|_| EncodeError::BadMatch)?;
    Ok(MatchParts {
        symbol,
        length_bytes,
        offset_bits,
    })
}

/// Encodes blocks into one compressed stream.
///
/// Each block is the 256-byte packed table, then its 16-bit units with any
/// extra length bytes placed where the decoder's input position will be
/// when it reads them (§3.3). Each block is padded with zero units so that
/// it ends exactly where the decoder's input position will be when the
/// block's last token has been read.
///
/// # Errors
///
/// [`EncodeError`] if a token cannot be written under its block's table.
pub fn encode_blocks(blocks: &[Block]) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    for block in blocks {
        encode_block(block, &mut out)?;
    }
    Ok(out)
}

fn encode_block(block: &Block, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    for [even, odd] in block.lengths.as_chunks::<2>().0 {
        if *even > MAX_CODE_LEN || *odd > MAX_CODE_LEN {
            return Err(EncodeError::BadSymbol);
        }
        out.push(even | (odd << 4));
    }
    let codes = canonical_codes(&block.lengths);
    let mut w = BlockWriter::default();
    for t in &block.tokens {
        let (symbol, length_bytes, offset_bits) = match t {
            Token::Literal(b) => (u16::from(*b), Vec::new(), 0),
            Token::End => (END_SYMBOL, Vec::new(), 0),
            Token::Raw {
                symbol,
                length_bytes,
                offset_bits,
            } => (*symbol, length_bytes.clone(), *offset_bits),
            Token::Match { length, offset } => {
                let m = match_parts(*length, *offset)?;
                (m.symbol, m.length_bytes, m.offset_bits)
            }
        };
        let &(code, len) = codes
            .get(usize::from(symbol))
            .ok_or(EncodeError::BadSymbol)?;
        if len == 0 {
            return Err(EncodeError::NoCode { symbol });
        }
        w.bits(code, u32::from(len));
        for b in length_bytes {
            w.byte(b);
        }
        if symbol >= END_SYMBOL {
            let n = u32::from((symbol - END_SYMBOL) >> 4);
            let mask = (1u32 << n) - 1;
            w.bits(u32::from(offset_bits) & mask, n);
        }
    }
    w.finish(out);
    Ok(())
}

/// Canonical (code, length) per symbol: by length, then by symbol (§3.1).
fn canonical_codes(lengths: &[u8; SYMBOLS]) -> Vec<(u32, u8)> {
    let mut count = [0u32; 16];
    for &l in lengths {
        if let Some(c) = count.get_mut(usize::from(l)) {
            *c = c.saturating_add(1);
        }
    }
    if let Some(c) = count.get_mut(0) {
        *c = 0;
    }
    let mut next = [0u32; 16];
    let mut code = 0u32;
    for bits in 1..16usize {
        let prev = count.get(bits - 1).copied().unwrap_or(0);
        code = code.wrapping_add(prev).wrapping_shl(1);
        if let Some(n) = next.get_mut(bits) {
            *n = code;
        }
    }
    lengths
        .iter()
        .map(|&l| {
            if l == 0 {
                return (0, 0);
            }
            match next.get_mut(usize::from(l)) {
                Some(n) => {
                    let c = *n;
                    *n = n.wrapping_add(1);
                    (c & ((1u32 << l) - 1), l)
                }
                None => (0, 0),
            }
        })
        .collect()
}

/// Bits and bytes of one block, and where each byte must go.
#[derive(Default)]
struct BlockWriter {
    acc: u64,
    acc_bits: u32,
    units: Vec<u16>,
    /// Total bits written: equals the bits the decoder will have consumed.
    consumed: u64,
    /// (units loaded by the decoder when it reads this byte, byte).
    bytes: Vec<(u64, u8)>,
}

impl BlockWriter {
    /// Units the decoder has loaded after consuming `c` bits: two at the
    /// block start, then one more each time fewer than 16 unread bits
    /// remain (the [MS-XCA] refill rule, §3.3).
    fn loaded(c: u64) -> u64 {
        if c <= 16 { 2 } else { 1 + c.div_ceil(16) }
    }

    fn bits(&mut self, value: u32, n: u32) {
        if n == 0 {
            return;
        }
        let mask = (1u64 << n) - 1;
        self.acc = (self.acc << n) | (u64::from(value) & mask);
        self.acc_bits += n;
        self.consumed += u64::from(n);
        while self.acc_bits >= 16 {
            self.acc_bits -= 16;
            let unit = (self.acc >> self.acc_bits) & 0xffff;
            self.units.push(u16::try_from(unit).unwrap_or(0));
            self.acc &= (1u64 << self.acc_bits) - 1;
        }
    }

    fn byte(&mut self, b: u8) {
        self.bytes.push((Self::loaded(self.consumed), b));
    }

    fn finish(mut self, out: &mut Vec<u8>) {
        if self.acc_bits > 0 {
            let unit = (self.acc << (16 - self.acc_bits)) & 0xffff;
            self.units.push(u16::try_from(unit).unwrap_or(0));
        }
        let target = Self::loaded(self.consumed);
        while u64::try_from(self.units.len()).unwrap_or(u64::MAX) < target {
            self.units.push(0);
        }
        let mut pending = self.bytes.iter().peekable();
        for (i, unit) in (1u64..).zip(&self.units) {
            out.extend_from_slice(&unit.to_le_bytes());
            while let Some(&&(at, b)) = pending.peek() {
                if at != i {
                    break;
                }
                out.push(b);
                pending.next();
            }
        }
    }
}

/// Length-limited (15) Huffman code lengths for the given frequencies.
///
/// Always gives a complete code: if fewer than two symbols are used, the
/// end symbol and symbol 0 are added with frequency 1. If the optimal code
/// is deeper than 15, frequencies are halved (keeping them non-zero) until
/// it fits.
#[must_use]
pub fn huffman_lengths(freq: &[u64; SYMBOLS]) -> [u8; SYMBOLS] {
    let mut f = *freq;
    let used = f.iter().filter(|&&x| x > 0).count();
    if used < 2 {
        for s in [0usize, usize::from(END_SYMBOL)] {
            if let Some(x) = f.get_mut(s)
                && *x == 0
            {
                *x = 1;
            }
        }
    }
    loop {
        let lengths = huffman_depths(&f);
        if lengths.iter().all(|&l| l <= MAX_CODE_LEN) {
            return lengths;
        }
        for x in f.iter_mut().filter(|x| **x > 0) {
            *x = (*x / 2).max(1);
        }
    }
}

/// Unlimited Huffman depths (saturated at 255) for symbols with non-zero
/// frequency.
fn huffman_depths(freq: &[u64; SYMBOLS]) -> [u8; SYMBOLS] {
    use std::cmp::Reverse;
    use std::collections::BinaryHeap;

    // Nodes 0..SYMBOLS are leaves; internal nodes follow.
    let mut parent: Vec<Option<usize>> = vec![None; SYMBOLS];
    let mut heap: BinaryHeap<Reverse<(u64, usize)>> = freq
        .iter()
        .enumerate()
        .filter(|(_, f)| **f > 0)
        .map(|(s, f)| Reverse((*f, s)))
        .collect();
    while heap.len() > 1 {
        let (Some(Reverse((fa, a))), Some(Reverse((fb, b)))) = (heap.pop(), heap.pop()) else {
            break;
        };
        let node = parent.len();
        parent.push(None);
        for child in [a, b] {
            if let Some(p) = parent.get_mut(child) {
                *p = Some(node);
            }
        }
        heap.push(Reverse((fa.saturating_add(fb), node)));
    }
    let mut lengths = [0u8; SYMBOLS];
    for (s, l) in lengths.iter_mut().enumerate() {
        if freq.get(s).copied().unwrap_or(0) == 0 {
            continue;
        }
        let mut depth = 0u8;
        let mut at = s;
        while let Some(Some(p)) = parent.get(at) {
            depth = depth.saturating_add(1);
            at = *p;
        }
        *l = depth;
    }
    lengths
}
