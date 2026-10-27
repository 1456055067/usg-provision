//! XPRESS LZ77+Huffman decoder ([MS-XCA] §2.2.4, "Processing").
//!
//! Our own implementation from Microsoft's published [MS-XCA] as
//! summarised in `specs/standards/wim-compression.md` §3. The decoder
//! never panics on input: every read goes through `get`, every write is
//! checked against the expected output size before it happens, and all
//! arithmetic on input-derived values is checked or provably bounded.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - each bound in
//   wim-compression.md §6 is a distinct `CodecError`.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   decoded output feeds the per-resource SHA-1 check (WU-5).
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038
// - SPEC: specs/standards/wim-compression.md §3, §6
// - [MS-XCA] §2.2.4 - LZ77+Huffman decompression
//
// FORMAT: OBS-012 - WIM's XPRESS (header flag 0x00020000) is [MS-XCA]
// LZ77+Huffman, applied to each 32 KiB chunk on its own with one Huffman
// table per chunk; the 65536-byte block rule never splits a WIM chunk
// (OPEN-WIMC-1 parts 1 and 2, run R1).
// FORMAT: OBS-013 - every DISM chunk ends with symbol 256, read exactly
// when all of the chunk's stored bytes are consumed; this decoder's rules
// 2 and 3 (impl-notes-wux.md) accepted all 369 R1 chunk instances
// (OPEN-WIMC-1 part 3, run R1).

use super::CodecError;

/// Output bytes produced per Huffman block (wim-compression.md §3.1).
pub const BLOCK_OUTPUT_BYTES: usize = 65536;
/// Bytes of packed code lengths at the start of each block (§3.1).
pub const TABLE_BYTES: usize = 256;
/// Size of the symbol alphabet (§3.1).
pub const SYMBOLS: usize = 512;
/// Longest Huffman code (§3.1).
pub const MAX_CODE_LEN: u32 = 15;
/// The symbol that may mark the end of the data (§3.6).
pub const END_SYMBOL: u16 = 256;
/// Shortest match (§3.4).
pub const MIN_MATCH: u32 = 3;

/// Entries in the reference decoding table: 2^15 (§3.2).
const DECODE_TABLE_LEN: usize = 1 << MAX_CODE_LEN;

/// Decodes one compressed chunk into `out`.
///
/// `out.len()` is the exact expected decompressed size; the decoder never
/// writes past it and fails if the data does not produce exactly that many
/// bytes. On error the contents of `out` are unspecified and must not be
/// used.
///
/// Allocates one 64 KiB decoding table; use [`XpressDecoder`] to reuse it
/// across chunks.
///
/// # Errors
///
/// Any [`CodecError`]; each is one bound of wim-compression.md §6.
pub fn decode_chunk(input: &[u8], out: &mut [u8]) -> Result<(), CodecError> {
    XpressDecoder::new().decode_chunk(input, out)
}

/// A reusable XPRESS decoder: holds the decoding table between chunks.
pub struct XpressDecoder {
    /// Symbol for every 15-bit prefix (§3.2).
    table: Box<[u16]>,
    /// Code length of every symbol in the current block.
    lengths: [u8; SYMBOLS],
}

impl Default for XpressDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for XpressDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XpressDecoder").finish_non_exhaustive()
    }
}

impl XpressDecoder {
    /// A decoder with an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            table: vec![0u16; DECODE_TABLE_LEN].into_boxed_slice(),
            lengths: [0; SYMBOLS],
        }
    }

    /// Decodes one compressed chunk into `out`; see [`decode_chunk`].
    ///
    /// # Errors
    ///
    /// Any [`CodecError`]; each is one bound of wim-compression.md §6.
    pub fn decode_chunk(&mut self, input: &[u8], out: &mut [u8]) -> Result<(), CodecError> {
        let mut in_pos: usize = 0;
        let mut out_pos: usize = 0;
        // Every pass of this loop consumes at least TABLE_BYTES of input
        // or returns, so it ends.
        loop {
            // §3.6: before each block the remaining input must hold a
            // table; if it cannot, the data ends here.
            let remaining = input.len().saturating_sub(in_pos);
            if remaining < TABLE_BYTES {
                return if out_pos == out.len() {
                    Ok(())
                } else {
                    Err(CodecError::ShortOutput)
                };
            }
            let table_end = in_pos
                .checked_add(TABLE_BYTES)
                .ok_or(CodecError::InputExhausted)?;
            let table_bytes = input
                .get(in_pos..table_end)
                .ok_or(CodecError::InputExhausted)?;
            self.build_table(table_bytes)?;

            let mut bits = BitReader::new(input, table_end)?;
            let block_end = out_pos.saturating_add(BLOCK_OUTPUT_BYTES);
            // Every pass writes at least one byte or returns, and writes
            // are bounded by `out.len()`, so this loop ends.
            while out_pos < block_end {
                let symbol = self.decode_symbol(&mut bits)?;
                if let Ok(literal) = u8::try_from(symbol) {
                    let slot = out.get_mut(out_pos).ok_or(CodecError::OutputOverrun)?;
                    *slot = literal;
                    out_pos = out_pos.checked_add(1).ok_or(CodecError::OutputOverrun)?;
                    continue;
                }
                // §3.6: symbol 256 ends the data only when all input has
                // been read and the expected size has been written;
                // otherwise it is an ordinary match (length 3, offset 1).
                if symbol == END_SYMBOL && bits.all_input_read() && out_pos == out.len() {
                    return Ok(());
                }
                out_pos = decode_match(symbol, &mut bits, out, out_pos)?;
            }
            in_pos = bits.position();
        }
    }

    /// Builds the decoding table from the 256 packed code-length bytes
    /// exactly as the reference method does (§3.2): for each length 1 to
    /// 15, for each symbol with that length in ascending order, fill
    /// `2^(15 - length)` consecutive entries.
    fn build_table(&mut self, packed: &[u8]) -> Result<(), CodecError> {
        // §3.1: even symbol in the low nibble, odd symbol in the high one.
        for ([even, odd], byte) in self.lengths.as_chunks_mut::<2>().0.iter_mut().zip(packed) {
            *even = byte & 0x0f;
            *odd = byte >> 4;
        }
        let mut filled: usize = 0;
        for len in 1..=MAX_CODE_LEN {
            let span = 1usize << (MAX_CODE_LEN - len);
            for (symbol, &sym_len) in (0u16..).zip(self.lengths.iter()) {
                if u32::from(sym_len) != len {
                    continue;
                }
                let end = filled
                    .checked_add(span)
                    .filter(|&e| e <= DECODE_TABLE_LEN)
                    .ok_or(CodecError::HuffmanTableOverfull)?;
                self.table
                    .get_mut(filled..end)
                    .ok_or(CodecError::HuffmanTableOverfull)?
                    .fill(symbol);
                filled = end;
            }
        }
        if filled == DECODE_TABLE_LEN {
            Ok(())
        } else {
            Err(CodecError::HuffmanTableIncomplete)
        }
    }

    /// Decodes one Huffman symbol from the top 15 bits of the register
    /// and consumes its code length (§3.3).
    fn decode_symbol(&self, bits: &mut BitReader<'_>) -> Result<u16, CodecError> {
        let index = usize::try_from(bits.peek15()).map_err(|_| CodecError::InputExhausted)?;
        // A complete table (checked in `build_table`) maps every index.
        let symbol = *self
            .table
            .get(index)
            .ok_or(CodecError::HuffmanTableIncomplete)?;
        let len = *self
            .lengths
            .get(usize::from(symbol))
            .ok_or(CodecError::HuffmanTableIncomplete)?;
        bits.consume(u32::from(len))?;
        Ok(symbol)
    }
}

/// Decodes the rest of a match whose symbol (256 to 511) has been read,
/// copies it, and returns the new output position (§3.1, §3.4, §3.5).
fn decode_match(
    symbol: u16,
    bits: &mut BitReader<'_>,
    out: &mut [u8],
    out_pos: usize,
) -> Result<usize, CodecError> {
    let s = symbol.saturating_sub(END_SYMBOL);
    let header = u32::from(s & 0x0f);
    let offset_bits = u32::from(s >> 4);

    // §3.4: the extra length bytes come straight from the input position,
    // after the symbol's bits and before the offset bits.
    let length = if header < 15 {
        header + MIN_MATCH
    } else {
        let b = bits.read_byte()?;
        if b < 255 {
            u32::from(b) + 15 + MIN_MATCH
        } else {
            let v = bits.read_u16_le()?;
            if v < 15 {
                return Err(CodecError::ExtendedLengthTooSmall);
            }
            u32::from(v) + MIN_MATCH
        }
    };

    // §3.5: offset = 2^n + the next n bits; 1 to 65535.
    let offset = (1u32 << offset_bits) + bits.take(offset_bits)?;

    let length = usize::try_from(length).map_err(|_| CodecError::OutputOverrun)?;
    let offset = usize::try_from(offset).map_err(|_| CodecError::OffsetBeforeStart)?;
    let mut src = out_pos
        .checked_sub(offset)
        .ok_or(CodecError::OffsetBeforeStart)?;
    let end = out_pos
        .checked_add(length)
        .filter(|&e| e <= out.len())
        .ok_or(CodecError::OutputOverrun)?;
    // Byte by byte: the length may exceed the offset (overlapping copy).
    for dst in out_pos..end {
        let byte = *out.get(src).ok_or(CodecError::OffsetBeforeStart)?;
        *out.get_mut(dst).ok_or(CodecError::OutputOverrun)? = byte;
        src = src.checked_add(1).ok_or(CodecError::OutputOverrun)?;
    }
    Ok(end)
}

/// The [MS-XCA] bit register (§3.3): 32 bits, the next unread bit at the
/// top, refilled with one little-endian 16-bit unit whenever fewer than 16
/// unread bits remain after a read.
///
/// The refill schedule follows wim-compression.md §3.3 exactly, because
/// extra length bytes are read from the input position the schedule
/// leaves behind.
///
/// A refill (or the two-unit load at the start of a block) that would
/// need bytes past the end of the input is `InputExhausted` at once: §3.6
/// and §6 require an error on any read outside the input buffer. The
/// reader never touches memory outside the input.
///
/// FORMAT: OBS-013 (c) - no refill in any R1 chunk needed bytes beyond the
/// stored size, so this rule refuses none of DISM's R1 chunks (BOOT-002;
/// checked again on every compressed resource by `tests/dism_samples.rs`).
struct BitReader<'a> {
    input: &'a [u8],
    /// Next input byte to load or read.
    pos: usize,
    /// Register; the next unread bit is bit 31.
    next_bits: u32,
    /// Unread bits in the register beyond the 16 that §3.3 says it always
    /// holds. 0 to 16 between reads.
    extra: i32,
}

impl<'a> BitReader<'a> {
    /// Loads two 16-bit units (§3.3: at the start of each block).
    fn new(input: &'a [u8], pos: usize) -> Result<Self, CodecError> {
        let mut r = Self {
            input,
            pos,
            next_bits: 0,
            extra: 16,
        };
        let hi = r.load_unit()?;
        let lo = r.load_unit()?;
        r.next_bits = (hi << 16) | lo;
        Ok(r)
    }

    /// Next 16-bit little-endian unit; `InputExhausted` past the end of
    /// the input.
    fn load_unit(&mut self) -> Result<u32, CodecError> {
        let p1 = self.pos.checked_add(1).ok_or(CodecError::InputExhausted)?;
        let lo = *self.input.get(self.pos).ok_or(CodecError::InputExhausted)?;
        let hi = *self.input.get(p1).ok_or(CodecError::InputExhausted)?;
        self.pos = self.pos.checked_add(2).ok_or(CodecError::InputExhausted)?;
        Ok(u32::from(u16::from_le_bytes([lo, hi])))
    }

    /// The top 15 bits of the register.
    fn peek15(&self) -> u32 {
        self.next_bits >> (32 - MAX_CODE_LEN)
    }

    /// Discards `n` (0 to 15) bits and refills per §3.3.
    fn consume(&mut self, n: u32) -> Result<(), CodecError> {
        if n == 0 {
            return Ok(());
        }
        if n > MAX_CODE_LEN {
            return Err(CodecError::InputExhausted);
        }
        let n_i = i32::try_from(n).map_err(|_| CodecError::InputExhausted)?;
        self.next_bits <<= n;
        self.extra -= n_i;
        if self.extra < 0 {
            let shift = u32::try_from(-self.extra).map_err(|_| CodecError::InputExhausted)?;
            let unit = self.load_unit()?;
            self.next_bits |= unit << shift;
            self.extra += 16;
        }
        Ok(())
    }

    /// Reads `n` (0 to 15) bits as a number, most significant first.
    fn take(&mut self, n: u32) -> Result<u32, CodecError> {
        if n == 0 {
            return Ok(0);
        }
        let value = self
            .next_bits
            .checked_shr(32 - n)
            .ok_or(CodecError::InputExhausted)?;
        self.consume(n)?;
        Ok(value)
    }

    /// Reads one byte straight from the input position (§3.3, §3.4).
    fn read_byte(&mut self) -> Result<u8, CodecError> {
        let b = *self.input.get(self.pos).ok_or(CodecError::InputExhausted)?;
        self.pos = self.pos.checked_add(1).ok_or(CodecError::InputExhausted)?;
        Ok(b)
    }

    /// Reads a little-endian 16-bit value straight from the input
    /// position (§3.4).
    fn read_u16_le(&mut self) -> Result<u16, CodecError> {
        let lo = self.read_byte()?;
        let hi = self.read_byte()?;
        Ok(u16::from_le_bytes([lo, hi]))
    }

    /// True once every input byte has been loaded or read (§3.6).
    fn all_input_read(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Input position after the units and bytes read so far; the next
    /// block's table starts here (§3.6).
    fn position(&self) -> usize {
        self.pos
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with(lengths: &[(usize, u8)]) -> Vec<u8> {
        let mut nibbles = [0u8; SYMBOLS];
        for &(s, l) in lengths {
            if let Some(n) = nibbles.get_mut(s) {
                *n = l;
            }
        }
        nibbles
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[even, odd]| even | (odd << 4))
            .collect()
    }

    #[test]
    fn all_zero_table_is_incomplete() {
        let mut input = vec![0u8; TABLE_BYTES];
        input.extend_from_slice(&[0; 4]);
        let mut out = [0u8; 1];
        assert_eq!(
            decode_chunk(&input, &mut out),
            Err(CodecError::HuffmanTableIncomplete)
        );
    }

    #[test]
    fn spec_nibble_example_packs_low_then_high() {
        // §3.1 example: lengths 5, 6, 7, 8 for symbols 0..3 give 0x65 0x87.
        let t = table_with(&[(0, 5), (1, 6), (2, 7), (3, 8)]);
        assert_eq!(t.get(..2), Some(&[0x65u8, 0x87][..]));
    }

    #[test]
    fn two_symbol_literal_stream() {
        // Symbols 'A' (code 0) and 256 (code 1), each one bit.
        let mut input = table_with(&[(usize::from(b'A'), 1), (256, 1)]);
        // Bits: A A A then END (1), padded: 0001_0000_0000_0000.
        input.extend_from_slice(&0x1000u16.to_le_bytes());
        input.extend_from_slice(&0u16.to_le_bytes());
        let mut out = [0u8; 3];
        assert_eq!(decode_chunk(&input, &mut out), Ok(()));
        assert_eq!(&out, b"AAA");
    }

    #[test]
    fn empty_input_and_empty_output_succeeds() {
        let mut out = [0u8; 0];
        assert_eq!(decode_chunk(&[], &mut out), Ok(()));
        let mut out = [0u8; 1];
        assert_eq!(decode_chunk(&[], &mut out), Err(CodecError::ShortOutput));
    }

    #[test]
    fn decoder_is_reusable_after_error() {
        let mut d = XpressDecoder::new();
        let mut out = [0u8; 1];
        assert!(d.decode_chunk(&[0u8; 300], &mut out).is_err());
        let mut input = table_with(&[(usize::from(b'Z'), 1), (256, 1)]);
        input.extend_from_slice(&0x4000u16.to_le_bytes());
        input.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(d.decode_chunk(&input, &mut out), Ok(()));
        assert_eq!(out, [b'Z']);
    }
}
