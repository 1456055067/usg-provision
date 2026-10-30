//! Cabinet reader (`specs/standards/zip-cab.md` Part B, plan §1.5 "CAB").
//!
//! Accepted: version 1.3, a single cabinet, folders with compression type 0
//! (none) or 1 (MSZIP). Every other compression value is refused as
//! `cab_compression_unsupported` with the raw value; this covers LZX and
//! Quantum without depending on their encoding (OPEN-ARC-1, decision 0025
//! item 3). Previous/next cabinet flags and continued folders are refused
//! as `multi_cabinet`. Attribute 0x40 ("run after extraction") is ignored.
//!
//! FORMAT: byte offsets and the three reserved header fields follow the
//! public Microsoft Cabinet Format document (SRC-055); the topic 25 summary
//! lists the fields but not their offsets. The checksum's handling of 1 to
//! 3 leftover bytes also follows SRC-055 (see `checksum`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity), CM-7 (Least Functionality)
// - SPEC: specs/drivers.md#REQ-DRV-009; specs/standards/zip-cab.md#part-b-cabinet-src-055-src-185-src-186
// - Microsoft Cabinet Format (SRC-055); [MS-MCI] §2 MSZIP (SRC-185)

use super::inflate::{Inflater, SliceSource, Window};
use super::names::{self, Flavor};
use super::{
    ArchiveError, ArchiveKind, ArchiveLimits, ArchiveMode, ArchiveReport, Collector, ExtractSink,
    Input, Le, Listed, RelPath, check_listing,
};

const HEADER_LEN: usize = 36;
const FLAG_PREV: u16 = 0x0001;
const FLAG_NEXT: u16 = 0x0002;
const FLAG_RESERVE: u16 = 0x0004;
const MAX_HEADER_RESERVE: u16 = 60_000;
const FOLDER_CONTINUED_MIN: u16 = 0xFFFD;
const ATTR_UTF8: u16 = 0x80;
/// Uncompressed bytes per data block (all but the last of a folder).
const BLOCK_UNCOMP: u16 = 32_768;
/// MSZIP compressed block bound: 32 KiB + 12 (SRC-185 §2).
const MSZIP_MAX: u16 = 32_768 + 12;
const COMP_NONE: u16 = 0;
const COMP_MSZIP: u16 = 1;

struct Folder {
    first_block: u64,
    blocks: u16,
    compression: u16,
    /// Filled from the block walk.
    total: u64,
}

struct File {
    path: RelPath,
    size: u64,
    offset: u64,
    folder: u16,
}

/// The data-block checksum (topic 25 §B.5): little-endian 32-bit words XORed
/// into the seed. FORMAT: SRC-055 - a trailing 1 to 3 bytes form one final
/// word with the first leftover byte most significant.
pub(crate) fn checksum(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let (words, rem) = data.as_chunks::<4>();
    for w in words {
        sum ^= u32::from_le_bytes(*w);
    }
    let tail = rem.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    sum ^ tail
}

/// Reads a NUL-terminated name at `off`, at most `max` bytes before the NUL.
fn read_name(input: &Input<'_>, off: u64, max: usize) -> Result<(Vec<u8>, u64), ArchiveError> {
    let avail = input.len().saturating_sub(off);
    let n = usize::try_from(avail.min(u64::try_from(max.saturating_add(1)).unwrap_or(u64::MAX)))
        .map_err(|_| ArchiveError::Truncated)?;
    let buf = input.read_vec(off, n)?;
    let nul = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or(ArchiveError::BadName {
            reason: "name_too_long",
        })?;
    if nul > max {
        return Err(ArchiveError::BadName {
            reason: "name_too_long",
        });
    }
    let name = buf.get(..nul).ok_or(ArchiveError::Truncated)?.to_vec();
    Ok((
        name,
        off + u64::try_from(nul).map_err(|_| ArchiveError::Truncated)? + 1,
    ))
}

pub(crate) fn extract(
    input: &Input<'_>,
    lim: &ArchiveLimits,
    mode: ArchiveMode,
    sink: &mut dyn ExtractSink,
) -> Result<ArchiveReport, ArchiveError> {
    let mut h = [0u8; HEADER_LEN];
    input.read(0, &mut h)?;
    let mut le = Le::new(&h);
    let _sig = le.u32()?;
    let _reserved1 = le.u32()?;
    let cb_cabinet = le.u32()?;
    let _reserved2 = le.u32()?;
    let coff_files = u64::from(le.u32()?);
    let _reserved3 = le.u32()?;
    let minor = le.u8()?;
    let major = le.u8()?;
    let n_folders = le.u16()?;
    let n_files = le.u16()?;
    let flags = le.u16()?;
    let _set_id = le.u16()?;
    let _index = le.u16()?;
    if (major, minor) != (1, 3) {
        return Err(ArchiveError::CabVersionUnsupported);
    }
    if flags & (FLAG_PREV | FLAG_NEXT) != 0 {
        return Err(ArchiveError::MultiCabinet);
    }
    if flags & !FLAG_RESERVE != 0 {
        return Err(ArchiveError::Malformed("reserved cabinet flags"));
    }
    if u64::from(cb_cabinet) != input.len() {
        return Err(ArchiveError::Malformed("cabinet size field"));
    }
    if u32::from(n_files) > lim.max_entries {
        return Err(ArchiveError::LimitExceeded("entries"));
    }
    let mut pos = HEADER_LEN as u64;
    let (mut folder_res, mut data_res) = (0u64, 0u64);
    if flags & FLAG_RESERVE != 0 {
        let mut r = [0u8; 4];
        input.read(pos, &mut r)?;
        let mut le = Le::new(&r);
        let header_res = le.u16()?;
        folder_res = u64::from(le.u8()?);
        data_res = u64::from(le.u8()?);
        if header_res > MAX_HEADER_RESERVE {
            return Err(ArchiveError::Malformed("header reserve size"));
        }
        pos += 4 + u64::from(header_res);
    }

    // Folder records.
    let mut folders = Vec::with_capacity(usize::from(n_folders));
    for _ in 0..n_folders {
        let mut r = [0u8; 8];
        input.read(pos, &mut r)?;
        let mut le = Le::new(&r);
        let first_block = u64::from(le.u32()?);
        let blocks = le.u16()?;
        let compression = le.u16()?;
        if compression != COMP_NONE && compression != COMP_MSZIP {
            return Err(ArchiveError::CabCompressionUnsupported {
                type_value: compression,
            });
        }
        folders.push(Folder {
            first_block,
            blocks,
            compression,
            total: 0,
        });
        pos += 8 + folder_res;
    }
    // Regions that must not overlap: header + folders, files, data blocks.
    let mut ranges: Vec<(u64, u64)> = vec![(0, pos)];
    if pos > input.len() {
        return Err(ArchiveError::Truncated);
    }

    // File records.
    let mut files = Vec::with_capacity(usize::from(n_files));
    let mut fpos = coff_files;
    for _ in 0..n_files {
        let mut r = [0u8; 16];
        input.read(fpos, &mut r)?;
        let mut le = Le::new(&r);
        let size = u64::from(le.u32()?);
        let offset = u64::from(le.u32()?);
        let folder = le.u16()?;
        let _date = le.u16()?;
        let _time = le.u16()?;
        let attrs = le.u16()?;
        if folder >= FOLDER_CONTINUED_MIN {
            return Err(ArchiveError::MultiCabinet);
        }
        if folder >= n_folders {
            return Err(ArchiveError::Malformed("folder index"));
        }
        let (raw, next) = read_name(input, fpos + 16, lim.max_name_bytes)?;
        fpos = next;
        if attrs & ATTR_UTF8 == 0 && !raw.is_ascii() {
            return Err(ArchiveError::BadName {
                reason: "non_ascii",
            });
        }
        let s = std::str::from_utf8(&raw).map_err(|_| ArchiveError::BadName {
            reason: "invalid_utf8",
        })?;
        let (path, _) = names::validate(s, Flavor::Cab, lim)?;
        files.push(File {
            path,
            size,
            offset,
            folder,
        });
    }
    if n_files > 0 {
        ranges.push((coff_files, fpos));
    }

    // Walk data-block headers to get each folder's uncompressed total.
    for f in &mut folders {
        let mut b = f.first_block;
        for i in 0..f.blocks {
            let mut r = [0u8; 8];
            input.read(b, &mut r)?;
            let mut le = Le::new(&r);
            let _csum = le.u32()?;
            let cb_data = le.u16()?;
            let cb_uncomp = le.u16()?;
            if cb_uncomp == 0 {
                // A block split across cabinets (topic 25 §B.5).
                return Err(ArchiveError::MultiCabinet);
            }
            let last = i + 1 == f.blocks;
            if cb_uncomp > BLOCK_UNCOMP || (!last && cb_uncomp != BLOCK_UNCOMP) {
                return Err(ArchiveError::Malformed("data block size"));
            }
            let ok = match f.compression {
                COMP_NONE => cb_data == cb_uncomp,
                _ => (2..=MSZIP_MAX).contains(&cb_data),
            };
            if !ok {
                return Err(ArchiveError::Malformed("data block compressed size"));
            }
            let end = b + 8 + data_res + u64::from(cb_data);
            if end > input.len() {
                return Err(ArchiveError::Truncated);
            }
            ranges.push((b, end));
            b = end;
            f.total += u64::from(cb_uncomp);
        }
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if let [a, b] = pair
            && b.0 < a.1
        {
            return Err(ArchiveError::Overlap);
        }
    }

    // Files: ordered by folder then offset, inside their folder, no overlap.
    let mut prev: Option<(u16, u64)> = None;
    for f in &files {
        let end = f
            .offset
            .checked_add(f.size)
            .ok_or(ArchiveError::Malformed("file range"))?;
        let total = folders.get(usize::from(f.folder)).map_or(0, |fo| fo.total);
        if end > total {
            return Err(ArchiveError::Malformed("file outside folder"));
        }
        if let Some((pf, pend)) = prev
            && (f.folder < pf || (f.folder == pf && f.offset < pend))
        {
            return Err(ArchiveError::Overlap);
        }
        prev = Some((f.folder, end));
    }
    let listed: Vec<Listed> = files
        .iter()
        .map(|f| Listed {
            path: f.path.clone(),
            is_dir: false,
            size: f.size,
        })
        .collect();
    let names = check_listing(&listed, input.len(), lim)?;

    let mut col = Collector::new(sink, names, lim, mode);
    let mut window = Window::new();
    let mut next_file = 0usize;
    for (fi, folder) in folders.iter().enumerate() {
        let fi = u16::try_from(fi).map_err(|_| ArchiveError::Malformed("folder index"))?;
        window.reset();
        let mut d = Dispatch {
            files: &files,
            cur: next_file,
            folder: fi,
            started: false,
            pos: 0,
        };
        let mut b = folder.first_block;
        for _ in 0..folder.blocks {
            let mut r = [0u8; 8];
            input.read(b, &mut r)?;
            let mut le = Le::new(&r);
            let csum = le.u32()?;
            let cb_data = le.u16()?;
            let cb_uncomp = le.u16()?;
            let data_off = b + 8 + data_res;
            let data = input.read_vec(data_off, usize::from(cb_data))?;
            if csum != 0 {
                let seed = checksum(&data, 0);
                let hdr = r.get(4..8).ok_or(ArchiveError::Truncated)?;
                if checksum(hdr, seed) != csum {
                    return Err(ArchiveError::CabChecksum);
                }
            }
            let block = if folder.compression == COMP_NONE {
                data
            } else {
                mszip_block(&data, &mut window, cb_uncomp)?
            };
            d.feed(&block, &mut col)?;
            b = data_off + u64::from(cb_data);
        }
        d.feed(&[], &mut col)?;
        if d.started || d.files.get(d.cur).is_some_and(|f| f.folder == fi) {
            return Err(ArchiveError::Malformed("file outside folder"));
        }
        next_file = d.cur;
    }
    if next_file != files.len() {
        return Err(ArchiveError::Malformed("file outside folder"));
    }
    col.finish(ArchiveKind::Cab)
}

/// Decodes one MSZIP block (SRC-185 §2): `CK`, then a DEFLATE stream ending
/// in a final block, decoding to exactly `cb_uncomp` bytes and using all
/// the input. History in `window` carries over between blocks.
fn mszip_block(data: &[u8], window: &mut Window, cb_uncomp: u16) -> Result<Vec<u8>, ArchiveError> {
    let body = data
        .strip_prefix(b"CK")
        .ok_or(ArchiveError::Malformed("MSZIP signature"))?;
    let mut src = SliceSource::new(body);
    let mut out = Vec::with_capacity(usize::from(cb_uncomp));
    let n = Inflater::new(window).inflate(&mut src, u64::from(cb_uncomp), &mut |b: &[u8]| {
        out.extend_from_slice(b);
        Ok(())
    })?;
    if n != u64::from(cb_uncomp) {
        return Err(ArchiveError::SizeMismatch);
    }
    if src.remaining() != 0 {
        return Err(ArchiveError::Malformed("data after final deflate block"));
    }
    Ok(out)
}

/// Routes a folder's uncompressed stream to its files in order.
struct Dispatch<'f> {
    files: &'f [File],
    cur: usize,
    folder: u16,
    started: bool,
    /// Folder offset of the next byte to arrive.
    pos: u64,
}

impl Dispatch<'_> {
    /// Feeds the next block of the folder. An empty block marks the end.
    fn feed(&mut self, block: &[u8], col: &mut Collector<'_>) -> Result<(), ArchiveError> {
        let block_start = self.pos;
        let block_end =
            block_start + u64::try_from(block.len()).map_err(|_| ArchiveError::Truncated)?;
        let mut pos = block_start;
        while let Some(f) = self.files.get(self.cur) {
            if f.folder != self.folder {
                break;
            }
            let f_end = f.offset + f.size;
            if !self.started {
                if f.offset > block_end || (f.offset == block_end && f.size > 0) {
                    break;
                }
                pos = pos.max(f.offset);
                col.begin(&f.path, f.size)?;
                self.started = true;
            }
            let take_end = f_end.min(block_end);
            if take_end > pos {
                let a = usize::try_from(pos - block_start).map_err(|_| ArchiveError::Truncated)?;
                let z =
                    usize::try_from(take_end - block_start).map_err(|_| ArchiveError::Truncated)?;
                col.write(block.get(a..z).ok_or(ArchiveError::Truncated)?)?;
                pos = take_end;
            }
            if pos == f_end {
                col.end()?;
                self.started = false;
                self.cur += 1;
            } else {
                break;
            }
        }
        self.pos = block_end;
        Ok(())
    }
}
