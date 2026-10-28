//! Bounds-checked little-endian field access for on-disk structures.
//!
//! Every read returns `None` past the end of the buffer; every write
//! returns `false`. Nothing here indexes or slices without `get`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - UEFI 2.10 §1.9.1 - little-endian byte order (specs/standards/gpt.md §1)

/// `len` bytes at `off`, or `None` if out of range.
pub(crate) fn field(buf: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    let end = off.checked_add(len)?;
    buf.get(off..end)
}

/// Fixed-size array at `off`.
pub(crate) fn array<const N: usize>(buf: &[u8], off: usize) -> Option<[u8; N]> {
    field(buf, off, N)?.try_into().ok()
}

pub(crate) fn le_u16(buf: &[u8], off: usize) -> Option<u16> {
    array::<2>(buf, off).map(u16::from_le_bytes)
}

pub(crate) fn le_u32(buf: &[u8], off: usize) -> Option<u32> {
    array::<4>(buf, off).map(u32::from_le_bytes)
}

pub(crate) fn le_u64(buf: &[u8], off: usize) -> Option<u64> {
    array::<8>(buf, off).map(u64::from_le_bytes)
}

/// Copies `src` into `buf` at `off`; `false` if it does not fit.
pub(crate) fn put(buf: &mut [u8], off: usize, src: &[u8]) -> bool {
    let Some(end) = off.checked_add(src.len()) else {
        return false;
    };
    match buf.get_mut(off..end) {
        Some(dst) => {
            dst.copy_from_slice(src);
            true
        }
        None => false,
    }
}

/// `true` if every byte of `buf` from `off` to the end is zero (an empty or
/// out-of-range tail counts as zero).
pub(crate) fn zero_from(buf: &[u8], off: usize) -> bool {
    buf.get(off..).is_none_or(|t| t.iter().all(|&b| b == 0))
}
