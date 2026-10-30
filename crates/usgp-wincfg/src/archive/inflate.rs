//! RFC 1951 DEFLATE decoder (plan §1.5 "Inflate").
//!
//! Our own decoder, shared by ZIP method 8 and CAB MSZIP. The 32 KiB history
//! [`Window`] is owned by the caller, so MSZIP can keep it across blocks
//! (`specs/standards/zip-cab.md` §B.6) while ZIP uses a fresh one per entry.
//!
//! Decoding is canonical-Huffman, one bit at a time: no lookup tables, so
//! every access is a checked `get`. Output is bounded by a caller budget.
//! Code-length sets are validated: over-subscribed sets are refused, and an
//! incomplete set is accepted only when every used code has length 1 (at
//! most one code; RFC 1951 §3.2.7 allows a single distance code). The
//! code-length code itself must be complete.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/drivers.md#REQ-DRV-009
// - RFC 1951 §3.2 - DEFLATE block format (specs/standards/zip-cab.md Part C)

use super::ArchiveError;

/// Size of the DEFLATE history window (RFC 1951 §3.2.5: distances up to
/// 32,768).
pub const WINDOW_SIZE: usize = 32 * 1024;

/// Errors in a DEFLATE stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InflateError {
    /// The compressed data ended before the final block did.
    #[error("compressed data ends early")]
    Truncated,
    /// Block type 11 (RFC 1951 §3.2.3).
    #[error("reserved block type")]
    ReservedBlockType,
    /// A stored block's length and its complement disagree.
    #[error("stored block length check failed")]
    StoredLength,
    /// Huffman code lengths are over-subscribed, incomplete or otherwise
    /// invalid.
    #[error("invalid Huffman code lengths")]
    BadCodeLengths,
    /// A code that decodes to no symbol, or to an invalid symbol.
    #[error("invalid symbol")]
    BadSymbol,
    /// A distance that reaches before the start of the history.
    #[error("distance beyond history")]
    DistanceTooFar,
    /// More output than the caller's budget.
    #[error("output budget exceeded")]
    OutputLimit,
}

/// A source of compressed bytes.
pub trait ByteSource {
    /// The next byte, or `None` at the end of the input.
    fn next_byte(&mut self) -> Result<Option<u8>, ArchiveError>;
}

/// A [`ByteSource`] over a slice.
#[derive(Debug)]
pub struct SliceSource<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceSource<'a> {
    /// Reads `data` from the start.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
}

impl ByteSource for SliceSource<'_> {
    fn next_byte(&mut self) -> Result<Option<u8>, ArchiveError> {
        let b = self.data.get(self.pos).copied();
        if b.is_some() {
            self.pos = self.pos.saturating_add(1);
        }
        Ok(b)
    }
}

/// The caller-owned 32 KiB history.
#[derive(Debug, Clone)]
pub struct Window {
    buf: Vec<u8>,
    pos: usize,
    filled: usize,
}

impl Default for Window {
    fn default() -> Self {
        Self::new()
    }
}

impl Window {
    /// An empty history.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0; WINDOW_SIZE],
            pos: 0,
            filled: 0,
        }
    }

    /// Forgets all history.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.filled = 0;
    }
}

/// FORMAT: RFC 1951 §3.2.5 - length base values for codes 257..285.
const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
/// FORMAT: RFC 1951 §3.2.5 - length extra bits.
const LEXT: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
/// FORMAT: RFC 1951 §3.2.5 - distance base values for codes 0..29.
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
/// FORMAT: RFC 1951 §3.2.5 - distance extra bits.
const DEXT: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
/// FORMAT: RFC 1951 §3.2.7 - order of code-length code lengths.
const CL_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
/// Longest code (RFC 1951 §3.2.7).
const MAX_BITS: usize = 15;

fn ierr(e: InflateError) -> ArchiveError {
    ArchiveError::Inflate(e)
}

/// A canonical Huffman code: counts per length and symbols in code order.
#[derive(Debug)]
struct Huffman {
    count: [u16; MAX_BITS + 1],
    symbol: Vec<u16>,
}

impl Huffman {
    /// Builds the code. Returns it and the number of unused codes at the
    /// longest length (0 = complete). Over-subscribed sets are refused.
    fn build(lengths: &[u8]) -> Result<(Self, i32), ArchiveError> {
        let mut count = [0u16; MAX_BITS + 1];
        for &l in lengths {
            let c = count
                .get_mut(usize::from(l))
                .ok_or(ierr(InflateError::BadCodeLengths))?;
            *c = c.saturating_add(1);
        }
        let mut left: i32 = 1;
        for len in 1..=MAX_BITS {
            left <<= 1;
            left -= i32::from(*count.get(len).unwrap_or(&0));
            if left < 0 {
                return Err(ierr(InflateError::BadCodeLengths));
            }
        }
        let mut offs = [0u16; MAX_BITS + 2];
        for len in 1..=MAX_BITS {
            let o = offs.get(len).copied().unwrap_or(0);
            let c = count.get(len).copied().unwrap_or(0);
            if let Some(n) = offs.get_mut(len + 1) {
                *n = o.saturating_add(c);
            }
        }
        let mut symbol = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l == 0 {
                continue;
            }
            let o = offs
                .get_mut(usize::from(l))
                .ok_or(ierr(InflateError::BadCodeLengths))?;
            let slot = symbol
                .get_mut(usize::from(*o))
                .ok_or(ierr(InflateError::BadCodeLengths))?;
            *slot = u16::try_from(sym).map_err(|_| ierr(InflateError::BadCodeLengths))?;
            *o = o.saturating_add(1);
        }
        Ok((Self { count, symbol }, left))
    }

    /// Builds a literal/length or distance code, applying the completeness
    /// rule from the module comment.
    fn build_checked(lengths: &[u8]) -> Result<Self, ArchiveError> {
        let (h, left) = Self::build(lengths)?;
        if left > 0 {
            let used = lengths.iter().filter(|&&l| l != 0).count();
            let ones = usize::from(h.count.get(1).copied().unwrap_or(0));
            if used != ones || used > 1 {
                return Err(ierr(InflateError::BadCodeLengths));
            }
        }
        Ok(h)
    }
}

/// LSB-first bit reader (RFC 1951 §3.1.1).
struct Bits<'s> {
    src: &'s mut dyn ByteSource,
    buf: u64,
    cnt: u32,
}

impl Bits<'_> {
    fn need(&mut self, n: u32) -> Result<(), ArchiveError> {
        while self.cnt < n {
            let b = self.src.next_byte()?.ok_or(ierr(InflateError::Truncated))?;
            self.buf |= u64::from(b) << self.cnt;
            self.cnt += 8;
        }
        Ok(())
    }

    /// Reads `n` (at most 16) bits, least significant first.
    fn bits(&mut self, n: u32) -> Result<u32, ArchiveError> {
        if n == 0 {
            return Ok(0);
        }
        self.need(n)?;
        let mask = (1u64 << n) - 1;
        let v = u32::try_from(self.buf & mask).map_err(|_| ierr(InflateError::BadSymbol))?;
        self.buf >>= n;
        self.cnt -= n;
        Ok(v)
    }

    /// Drops bits up to the next byte boundary.
    fn align(&mut self) {
        let r = self.cnt % 8;
        self.buf >>= r;
        self.cnt -= r;
    }

    /// Decodes one symbol, reading the code most significant bit first.
    fn decode(&mut self, h: &Huffman) -> Result<u16, ArchiveError> {
        let mut code: i32 = 0;
        let mut first: i32 = 0;
        let mut index: i32 = 0;
        for len in 1..=MAX_BITS {
            code |= i32::try_from(self.bits(1)?).map_err(|_| ierr(InflateError::BadSymbol))?;
            let count = i32::from(h.count.get(len).copied().unwrap_or(0));
            if code - count < first {
                let i = usize::try_from(index + (code - first))
                    .map_err(|_| ierr(InflateError::BadSymbol))?;
                return h
                    .symbol
                    .get(i)
                    .copied()
                    .ok_or(ierr(InflateError::BadSymbol));
            }
            index += count;
            first += count;
            first <<= 1;
            code <<= 1;
        }
        Err(ierr(InflateError::BadSymbol))
    }
}

/// Output callback: receives decoded bytes in order.
pub type OutFn<'a> = dyn FnMut(&[u8]) -> Result<(), ArchiveError> + 'a;

/// Decodes one DEFLATE stream (up to and including its final block).
pub struct Inflater<'w> {
    win: &'w mut Window,
}

struct Run<'w, 's, 'o, 'f> {
    win: &'w mut Window,
    bits: Bits<'s>,
    out: &'o mut OutFn<'f>,
    budget: u64,
    produced: u64,
    flush_from: usize,
}

impl<'w> Inflater<'w> {
    /// A decoder that reads and extends `window`.
    pub fn new(window: &'w mut Window) -> Self {
        Self { win: window }
    }

    /// Decodes from `src` until the final block ends, passing output to
    /// `out`. More than `budget` output bytes is an error. Returns the
    /// number of bytes produced. Bytes after the final block are left in
    /// `src` (except bits of the last partly used byte).
    pub fn inflate(
        &mut self,
        src: &mut dyn ByteSource,
        budget: u64,
        out: &mut OutFn<'_>,
    ) -> Result<u64, ArchiveError> {
        let flush_from = self.win.pos;
        let mut run = Run {
            win: self.win,
            bits: Bits {
                src,
                buf: 0,
                cnt: 0,
            },
            out,
            budget,
            produced: 0,
            flush_from,
        };
        loop {
            let last = run.bits.bits(1)?;
            match run.bits.bits(2)? {
                0 => run.stored()?,
                1 => {
                    let (lit, dist) = fixed_codes()?;
                    run.codes(&lit, &dist)?;
                }
                2 => {
                    let (lit, dist) = run.dynamic_codes()?;
                    run.codes(&lit, &dist)?;
                }
                _ => return Err(ierr(InflateError::ReservedBlockType)),
            }
            if last == 1 {
                break;
            }
        }
        run.flush()?;
        Ok(run.produced)
    }
}

/// FORMAT: RFC 1951 §3.2.6 - fixed Huffman code lengths.
fn fixed_codes() -> Result<(Huffman, Huffman), ArchiveError> {
    let mut lit = [0u8; 288];
    for (i, l) in lit.iter_mut().enumerate() {
        *l = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    let (lit, _) = Huffman::build(&lit)?;
    // 30 distance codes of length 5; codes 30 and 31 decode to nothing.
    let (dist, _) = Huffman::build(&[5u8; 30])?;
    Ok((lit, dist))
}

impl Run<'_, '_, '_, '_> {
    fn flush(&mut self) -> Result<(), ArchiveError> {
        let seg = self
            .win
            .buf
            .get(self.flush_from..self.win.pos)
            .ok_or(ierr(InflateError::OutputLimit))?;
        if !seg.is_empty() {
            (self.out)(seg)?;
        }
        self.flush_from = self.win.pos;
        Ok(())
    }

    fn put(&mut self, b: u8) -> Result<(), ArchiveError> {
        if self.produced >= self.budget {
            return Err(ierr(InflateError::OutputLimit));
        }
        if let Some(slot) = self.win.buf.get_mut(self.win.pos) {
            *slot = b;
        }
        self.win.pos += 1;
        if self.win.filled < WINDOW_SIZE {
            self.win.filled += 1;
        }
        self.produced += 1;
        if self.win.pos >= WINDOW_SIZE {
            self.flush()?;
            self.win.pos = 0;
            self.flush_from = 0;
        }
        Ok(())
    }

    fn stored(&mut self) -> Result<(), ArchiveError> {
        self.bits.align();
        let len = self.bits.bits(16)?;
        let nlen = self.bits.bits(16)?;
        if len != (!nlen & 0xFFFF) {
            return Err(ierr(InflateError::StoredLength));
        }
        for _ in 0..len {
            let b = u8::try_from(self.bits.bits(8)?).map_err(|_| ierr(InflateError::BadSymbol))?;
            self.put(b)?;
        }
        Ok(())
    }

    fn dynamic_codes(&mut self) -> Result<(Huffman, Huffman), ArchiveError> {
        let bad = || ierr(InflateError::BadCodeLengths);
        let nlen = usize::try_from(self.bits.bits(5)?).map_err(|_| bad())? + 257;
        let ndist = usize::try_from(self.bits.bits(5)?).map_err(|_| bad())? + 1;
        let ncode = usize::try_from(self.bits.bits(4)?).map_err(|_| bad())? + 4;
        if nlen > 286 || ndist > 30 {
            return Err(bad());
        }
        let mut cl = [0u8; 19];
        for &idx in CL_ORDER.iter().take(ncode) {
            let v = u8::try_from(self.bits.bits(3)?).map_err(|_| bad())?;
            *cl.get_mut(idx).ok_or_else(bad)? = v;
        }
        let (clcode, left) = Huffman::build(&cl)?;
        if left != 0 {
            return Err(bad());
        }
        let total = nlen + ndist;
        let mut lengths = vec![0u8; total];
        let mut i = 0usize;
        while i < total {
            let sym = self.bits.decode(&clcode)?;
            if sym < 16 {
                *lengths.get_mut(i).ok_or_else(bad)? = u8::try_from(sym).map_err(|_| bad())?;
                i += 1;
                continue;
            }
            let (val, rep) = match sym {
                16 => {
                    let prev = *lengths
                        .get(i.checked_sub(1).ok_or_else(bad)?)
                        .ok_or_else(bad)?;
                    (prev, 3 + self.bits.bits(2)?)
                }
                17 => (0, 3 + self.bits.bits(3)?),
                18 => (0, 11 + self.bits.bits(7)?),
                _ => return Err(bad()),
            };
            let rep = usize::try_from(rep).map_err(|_| bad())?;
            if i + rep > total {
                return Err(bad());
            }
            for slot in lengths.get_mut(i..i + rep).ok_or_else(bad)? {
                *slot = val;
            }
            i += rep;
        }
        if lengths.get(256).copied().unwrap_or(0) == 0 {
            return Err(bad());
        }
        let lit = Huffman::build_checked(lengths.get(..nlen).ok_or_else(bad)?)?;
        let dist = Huffman::build_checked(lengths.get(nlen..).ok_or_else(bad)?)?;
        Ok((lit, dist))
    }

    fn codes(&mut self, lit: &Huffman, dist: &Huffman) -> Result<(), ArchiveError> {
        let bad = || ierr(InflateError::BadSymbol);
        loop {
            let sym = self.bits.decode(lit)?;
            if sym < 256 {
                self.put(u8::try_from(sym).map_err(|_| bad())?)?;
                continue;
            }
            if sym == 256 {
                return Ok(());
            }
            let li = usize::from(sym - 257);
            let base = *LBASE.get(li).ok_or_else(bad)?;
            let ext = *LEXT.get(li).ok_or_else(bad)?;
            let len = u32::from(base) + self.bits.bits(u32::from(ext))?;
            let di = usize::from(self.bits.decode(dist)?);
            let dbase = *DBASE.get(di).ok_or_else(bad)?;
            let dext = *DEXT.get(di).ok_or_else(bad)?;
            let d = usize::try_from(u32::from(dbase) + self.bits.bits(u32::from(dext))?)
                .map_err(|_| bad())?;
            if d > self.win.filled {
                return Err(ierr(InflateError::DistanceTooFar));
            }
            for _ in 0..len {
                let from = (self.win.pos + WINDOW_SIZE - d) % WINDOW_SIZE;
                let b = *self.win.buf.get(from).ok_or_else(bad)?;
                self.put(b)?;
            }
        }
    }
}

/// Inflates a whole slice into a vector (tests and fuzzing). The stream must
/// end exactly at the end of `data`, apart from padding bits.
pub fn inflate_slice(data: &[u8], budget: u64) -> Result<Vec<u8>, ArchiveError> {
    let mut win = Window::new();
    let mut src = SliceSource::new(data);
    let mut out = Vec::new();
    Inflater::new(&mut win).inflate(&mut src, budget, &mut |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    })?;
    if src.remaining() != 0 {
        return Err(ArchiveError::Malformed("data after final deflate block"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stored_block() {
        // final, type 00; LEN=3, NLEN=!3; "abc".
        let d = [0x01, 0x03, 0x00, 0xFC, 0xFF, b'a', b'b', b'c'];
        assert_eq!(inflate_slice(&d, 100).unwrap(), b"abc");
        let bad = [0x01, 0x03, 0x00, 0xFC, 0xFE, b'a', b'b', b'c'];
        assert!(matches!(
            inflate_slice(&bad, 100),
            Err(ArchiveError::Inflate(InflateError::StoredLength))
        ));
    }

    #[test]
    fn fixed_block_empty_and_reserved() {
        // final, fixed, end-of-block (code 0000000): bits 1,10,0000000.
        assert_eq!(inflate_slice(&[0x03, 0x00], 10).unwrap(), b"");
        // final, type 11.
        assert!(matches!(
            inflate_slice(&[0x07], 10),
            Err(ArchiveError::Inflate(InflateError::ReservedBlockType))
        ));
        assert!(matches!(
            inflate_slice(&[], 10),
            Err(ArchiveError::Inflate(InflateError::Truncated))
        ));
    }

    #[test]
    fn budget_enforced() {
        let d = [0x01, 0x03, 0x00, 0xFC, 0xFF, b'a', b'b', b'c'];
        assert!(matches!(
            inflate_slice(&d, 2),
            Err(ArchiveError::Inflate(InflateError::OutputLimit))
        ));
    }

    #[test]
    fn oversubscribed_refused() {
        assert!(Huffman::build(&[1, 1, 1]).is_err());
        assert!(Huffman::build_checked(&[1]).is_ok());
        assert!(Huffman::build_checked(&[0, 0]).is_ok());
        assert!(Huffman::build_checked(&[2, 2, 2]).is_err());
    }
}
