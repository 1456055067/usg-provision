//! ZIP reader (`specs/standards/zip-cab.md` Part A, plan §1.5 "ZIP").
//!
//! Accepted: methods 0 (stored) and 8 (Deflate), data descriptors (flag 3),
//! Zip64 records and extra fields, UTF-8 names (flag 11) or ASCII names.
//! Refused by name: encryption, multi-disk, patched data, every other
//! method. The central directory is authoritative; every local header must
//! agree with it, data ranges must not overlap, and the central directory
//! must end exactly where the end records begin.
//!
//! FORMAT: byte offsets and field widths follow PKWARE APPNOTE 6.3.10
//! §4.3.7, §4.3.9, §4.3.12, §4.3.14 to §4.3.16 and §4.5.3 (SRC-183); the
//! topic 25 summary gives the field order but not every width.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-7 (Software,
//   Firmware, and Information Integrity)
// - SPEC: specs/drivers.md#REQ-DRV-009; specs/standards/zip-cab.md#part-a-zip-src-183
// - PKWARE APPNOTE §4.3, §4.4.4, §4.4.5, §4.4.7, §4.5.3

use usgp_common::crc32::Crc32;

use super::inflate::{Inflater, Window};
use super::names::{self, Flavor};
use super::{
    ArchiveError, ArchiveKind, ArchiveLimits, ArchiveReport, Collector, ExtractSink, Input, Le,
    Listed, RangeReader, RelPath, check_listing,
};

const SIG_LOCAL: u32 = 0x0403_4b50;
const SIG_CENTRAL: u32 = 0x0201_4b50;
const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_Z64_EOCD: u32 = 0x0606_4b50;
const SIG_Z64_LOC: u32 = 0x0706_4b50;
const SIG_DESCRIPTOR: u32 = 0x0807_4b50;

const EOCD_LEN: u64 = 22;
const Z64_LOC_LEN: u64 = 20;
const Z64_EOCD_MIN: u64 = 56;
const CENTRAL_LEN: usize = 46;
const LOCAL_LEN: usize = 30;

/// Flag bits (§4.4.4).
const F_ENCRYPTED: u16 = 1 << 0;
const F_DESCRIPTOR: u16 = 1 << 3;
const F_PATCHED: u16 = 1 << 5;
const F_STRONG: u16 = 1 << 6;
const F_UTF8: u16 = 1 << 11;
const F_MASKED_CD: u16 = 1 << 13;
/// Flags we understand and accept: 1 and 2 (method options), 3, 11.
const F_ACCEPTED: u16 = (1 << 1) | (1 << 2) | F_DESCRIPTOR | F_UTF8;

const SAT16: u16 = 0xFFFF;
const SAT32: u32 = 0xFFFF_FFFF;

/// Host system value for Unix in "version made by" (§4.4.2).
const HOST_UNIX: u8 = 3;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFDIR: u32 = 0o040_000;

struct Entry {
    path: RelPath,
    is_dir: bool,
    raw_name: Vec<u8>,
    flags: u16,
    method: u16,
    crc: u32,
    csize: u64,
    usize: u64,
    local: u64,
    zip64: bool,
    data_start: u64,
}

/// Directory location from the end records.
struct Directory {
    entries: u64,
    offset: u64,
    size: u64,
    /// Where the central directory must end (the first end record).
    end: u64,
}

fn method_check(method: u16) -> Result<(), ArchiveError> {
    let name = match method {
        0 | 8 => return Ok(()),
        99 => return Err(ArchiveError::Encrypted),
        1..=6 => "legacy",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstandard",
        95 => "xz",
        98 => "ppmd",
        _ => "unknown",
    };
    Err(ArchiveError::ZipMethodUnsupported { method, name })
}

fn flags_check(flags: u16) -> Result<(), ArchiveError> {
    if flags & (F_ENCRYPTED | F_STRONG | F_MASKED_CD) != 0 {
        return Err(ArchiveError::Encrypted);
    }
    if flags & F_PATCHED != 0 {
        return Err(ArchiveError::PatchedData);
    }
    if flags & !F_ACCEPTED != 0 {
        return Err(ArchiveError::Malformed("unsupported ZIP flags"));
    }
    Ok(())
}

/// Finds the end record by searching backwards (§4.3.16, topic 25 §A.1).
/// The comment must run exactly to the end of the file.
fn find_directory(input: &Input<'_>) -> Result<Directory, ArchiveError> {
    let len = input.len();
    if len < EOCD_LEN {
        return Err(ArchiveError::Truncated);
    }
    let span = len.min(EOCD_LEN + 0xFFFF);
    let start = len - span;
    let tail = input.read_vec(
        start,
        usize::try_from(span).map_err(|_| ArchiveError::Truncated)?,
    )?;
    let mut found = None;
    let last = tail.len().saturating_sub(22);
    for i in (0..=last).rev() {
        let mut le = Le::new(tail.get(i..).unwrap_or(&[]));
        if le.u32()? != SIG_EOCD {
            continue;
        }
        // Comment length is the last fixed field (bytes 20..22).
        let _fixed = le.take(16)?;
        let clen = usize::from(le.u16()?);
        if i.checked_add(22 + clen) == Some(tail.len()) {
            found = Some(i);
            break;
        }
    }
    let i = found.ok_or(ArchiveError::Malformed("no end of central directory"))?;
    let eocd_off = start + u64::try_from(i).map_err(|_| ArchiveError::Truncated)?;
    let mut le = Le::new(tail.get(i + 4..).unwrap_or(&[]));
    let disk = le.u16()?;
    let cd_disk = le.u16()?;
    let n_disk = le.u16()?;
    let n_total = le.u16()?;
    let cd_size = le.u32()?;
    let cd_off = le.u32()?;

    // Zip64 locator immediately before the end record (§4.3.15).
    let loc = eocd_off
        .checked_sub(Z64_LOC_LEN)
        .map(|o| -> Result<_, ArchiveError> {
            let mut b = [0u8; 20];
            input.read(o, &mut b)?;
            Ok((o, b))
        })
        .transpose()?
        .filter(|(_, b)| b.starts_with(&SIG_Z64_LOC.to_le_bytes()));
    let saturated = disk == SAT16
        || cd_disk == SAT16
        || n_disk == SAT16
        || n_total == SAT16
        || cd_size == SAT32
        || cd_off == SAT32;

    let Some((loc_off, b)) = loc else {
        if saturated {
            return Err(ArchiveError::Malformed("Zip64 locator missing"));
        }
        if disk != 0 || cd_disk != 0 || n_disk != n_total {
            return Err(ArchiveError::MultiDisk);
        }
        return Ok(Directory {
            entries: u64::from(n_total),
            offset: u64::from(cd_off),
            size: u64::from(cd_size),
            end: eocd_off,
        });
    };
    let mut le = Le::new(b.get(4..).unwrap_or(&[]));
    let z_disk = le.u32()?;
    let z_off = le.u64()?;
    let total_disks = le.u32()?;
    if z_disk != 0 || total_disks != 1 {
        return Err(ArchiveError::MultiDisk);
    }
    // Non-saturated 16-bit disk fields must still say "single disk".
    if (disk != SAT16 && disk != 0) || (cd_disk != SAT16 && cd_disk != 0) {
        return Err(ArchiveError::MultiDisk);
    }
    if z_off.checked_add(Z64_EOCD_MIN).is_none_or(|e| e > loc_off) {
        return Err(ArchiveError::Malformed("Zip64 end record position"));
    }
    let mut r = [0u8; 56];
    input.read(z_off, &mut r)?;
    let mut le = Le::new(&r);
    if le.u32()? != SIG_Z64_EOCD {
        return Err(ArchiveError::Malformed("Zip64 end record signature"));
    }
    let rec_size = le.u64()?;
    // The size field excludes the first 12 bytes (§4.3.14).
    if rec_size
        .checked_add(12)
        .is_none_or(|e| z_off.checked_add(e) != Some(loc_off))
    {
        return Err(ArchiveError::Malformed("Zip64 end record size"));
    }
    let _made_by = le.u16()?;
    let _needed = le.u16()?;
    let d = le.u32()?;
    let cd_d = le.u32()?;
    let nd = le.u64()?;
    let nt = le.u64()?;
    let size = le.u64()?;
    let offset = le.u64()?;
    if d != 0 || cd_d != 0 || nd != nt {
        return Err(ArchiveError::MultiDisk);
    }
    if (n_total != SAT16 && u64::from(n_total) != nt)
        || (cd_size != SAT32 && u64::from(cd_size) != size)
        || (cd_off != SAT32 && u64::from(cd_off) != offset)
    {
        return Err(ArchiveError::Malformed("Zip64 and end record disagree"));
    }
    Ok(Directory {
        entries: nt,
        offset,
        size,
        end: z_off,
    })
}

/// Values from a Zip64 extended-information extra field (§4.5.3).
#[derive(Default)]
struct Z64 {
    usize: Option<u64>,
    csize: Option<u64>,
    local: Option<u64>,
    disk: Option<u32>,
}

/// Walks extra fields; reads 0x0001 for the fields that are saturated.
fn parse_extra(
    extra: &[u8],
    want_u: bool,
    want_c: bool,
    want_off: bool,
    want_disk: bool,
) -> Result<Option<Z64>, ArchiveError> {
    let mut le = Le::new(extra);
    let mut found: Option<Z64> = None;
    while !le.rest().is_empty() {
        let id = le.u16()?;
        let n = le.u16()?;
        let body = le.take(usize::from(n))?;
        if id != 0x0001 {
            continue;
        }
        if found.is_some() {
            return Err(ArchiveError::Malformed("duplicate Zip64 extra field"));
        }
        let mut b = Le::new(body);
        let mut z = Z64::default();
        if want_u {
            z.usize = Some(b.u64()?);
        }
        if want_c {
            z.csize = Some(b.u64()?);
        }
        if want_off {
            z.local = Some(b.u64()?);
        }
        if want_disk {
            z.disk = Some(b.u32()?);
        }
        found = Some(z);
    }
    Ok(found)
}

fn decode_name(
    raw: &[u8],
    flags: u16,
    lim: &ArchiveLimits,
) -> Result<(RelPath, bool), ArchiveError> {
    if raw.len() > lim.max_name_bytes {
        return Err(ArchiveError::BadName {
            reason: "name_too_long",
        });
    }
    if flags & F_UTF8 == 0 && !raw.is_ascii() {
        // Code page 437 high bytes are refused (plan §1.5).
        return Err(ArchiveError::BadName {
            reason: "non_ascii",
        });
    }
    let s = std::str::from_utf8(raw).map_err(|_| ArchiveError::BadName {
        reason: "invalid_utf8",
    })?;
    names::validate(s, Flavor::Zip, lim)
}

fn read_central(
    input: &Input<'_>,
    dir: &Directory,
    lim: &ArchiveLimits,
) -> Result<Vec<Entry>, ArchiveError> {
    if dir.entries > u64::from(lim.max_entries) {
        return Err(ArchiveError::LimitExceeded("entries"));
    }
    let cd_end = dir
        .offset
        .checked_add(dir.size)
        .ok_or(ArchiveError::Malformed("central directory range"))?;
    if cd_end != dir.end {
        return Err(ArchiveError::Malformed(
            "central directory does not meet end record",
        ));
    }
    let min = dir.entries.saturating_mul(CENTRAL_LEN as u64);
    if dir.size < min {
        return Err(ArchiveError::Malformed("central directory too small"));
    }
    let mut rd = RangeReader::new(input, dir.offset, cd_end);
    let mut out = Vec::new();
    for _ in 0..dir.entries {
        let mut h = [0u8; CENTRAL_LEN];
        rd.read_exact(&mut h)?;
        let mut le = Le::new(&h);
        if le.u32()? != SIG_CENTRAL {
            return Err(ArchiveError::Malformed("central header signature"));
        }
        let made_by = le.u16()?;
        let _needed = le.u16()?;
        let flags = le.u16()?;
        let method = le.u16()?;
        let _time = le.u16()?;
        let _date = le.u16()?;
        let crc = le.u32()?;
        let csize32 = le.u32()?;
        let usize32 = le.u32()?;
        let nlen = usize::from(le.u16()?);
        let xlen = usize::from(le.u16()?);
        let clen = usize::from(le.u16()?);
        let disk16 = le.u16()?;
        let _internal = le.u16()?;
        let external = le.u32()?;
        let local32 = le.u32()?;
        flags_check(flags)?;
        method_check(method)?;
        if nlen > lim.max_name_bytes {
            return Err(ArchiveError::BadName {
                reason: "name_too_long",
            });
        }
        let mut raw_name = vec![0u8; nlen];
        rd.read_exact(&mut raw_name)?;
        let mut extra = vec![0u8; xlen];
        rd.read_exact(&mut extra)?;
        let mut comment = vec![0u8; clen];
        rd.read_exact(&mut comment)?;

        let z = parse_extra(
            &extra,
            usize32 == SAT32,
            csize32 == SAT32,
            local32 == SAT32,
            disk16 == SAT16,
        )?;
        let any_sat = usize32 == SAT32 || csize32 == SAT32 || local32 == SAT32 || disk16 == SAT16;
        if any_sat && z.is_none() {
            return Err(ArchiveError::Malformed("Zip64 extra field missing"));
        }
        let z = z.unwrap_or_default();
        let usize_ = z.usize.unwrap_or(u64::from(usize32));
        let csize = z.csize.unwrap_or(u64::from(csize32));
        let local = z.local.unwrap_or(u64::from(local32));
        let disk = z.disk.unwrap_or(u32::from(disk16));
        if disk != 0 {
            return Err(ArchiveError::MultiDisk);
        }

        let (path, is_dir) = decode_name(&raw_name, flags, lim)?;
        if made_by >> 8 == u16::from(HOST_UNIX) {
            let kind = (external >> 16) & S_IFMT;
            if kind != 0 && kind != S_IFREG && kind != S_IFDIR {
                return Err(ArchiveError::SpecialEntry);
            }
            if (kind == S_IFDIR) != is_dir && kind != 0 {
                return Err(ArchiveError::Malformed(
                    "directory attribute and name disagree",
                ));
            }
        }
        if is_dir && (usize_ != 0 || csize > 2) {
            return Err(ArchiveError::Malformed("directory with data"));
        }
        if method == 0 && csize != usize_ {
            return Err(ArchiveError::Malformed("stored sizes differ"));
        }
        if !is_dir && usize_ > csize.saturating_mul(lim.max_ratio_entry) {
            return Err(ArchiveError::LimitExceeded("entry_ratio"));
        }
        out.push(Entry {
            path,
            is_dir,
            raw_name,
            flags,
            method,
            crc,
            csize,
            usize: usize_,
            local,
            zip64: z.usize.is_some() || z.csize.is_some(),
            data_start: 0,
        });
    }
    if rd.remaining() != 0 {
        return Err(ArchiveError::Malformed("central directory size"));
    }
    Ok(out)
}

/// Checks a local header against its central entry; returns the byte range
/// `[local, end)` the entry occupies, including any data descriptor.
fn check_local(
    input: &Input<'_>,
    e: &mut Entry,
    data_limit: u64,
) -> Result<(u64, u64), ArchiveError> {
    let mut h = [0u8; LOCAL_LEN];
    input.read(e.local, &mut h)?;
    let mut le = Le::new(&h);
    if le.u32()? != SIG_LOCAL {
        return Err(ArchiveError::Mismatch("local header signature"));
    }
    let _needed = le.u16()?;
    let flags = le.u16()?;
    let method = le.u16()?;
    let _time = le.u16()?;
    let _date = le.u16()?;
    let crc = le.u32()?;
    let csize32 = le.u32()?;
    let usize32 = le.u32()?;
    let nlen = le.u16()?;
    let xlen = le.u16()?;
    flags_check(flags)?;
    if flags != e.flags {
        return Err(ArchiveError::Mismatch("flags"));
    }
    if method != e.method {
        return Err(ArchiveError::Mismatch("method"));
    }
    let name_off = e.local + LOCAL_LEN as u64;
    let name = input.read_vec(name_off, usize::from(nlen))?;
    if name != e.raw_name {
        return Err(ArchiveError::Mismatch("name"));
    }
    let extra_off = name_off + u64::from(nlen);
    let extra = input.read_vec(extra_off, usize::from(xlen))?;
    e.data_start = extra_off + u64::from(xlen);
    if flags & F_DESCRIPTOR == 0 {
        let z = parse_extra(&extra, usize32 == SAT32, csize32 == SAT32, false, false)?;
        if (usize32 == SAT32 || csize32 == SAT32) && z.is_none() {
            return Err(ArchiveError::Malformed("local Zip64 extra field missing"));
        }
        let z = z.unwrap_or_default();
        let lu = z.usize.unwrap_or(u64::from(usize32));
        let lc = z.csize.unwrap_or(u64::from(csize32));
        if crc != e.crc || lu != e.usize || lc != e.csize {
            return Err(ArchiveError::Mismatch("crc or sizes"));
        }
    } else {
        // Extra fields must still be well formed.
        parse_extra(&extra, false, false, false, false)?;
    }
    let data_end = e
        .data_start
        .checked_add(e.csize)
        .ok_or(ArchiveError::Malformed("data range"))?;
    if data_end > data_limit {
        return Err(ArchiveError::Overlap);
    }
    let mut end = data_end;
    if flags & F_DESCRIPTOR != 0 {
        end = check_descriptor(input, e, data_end, data_limit)?;
    }
    Ok((e.local, end))
}

/// Reads the data descriptor (§4.3.9), with or without its signature.
fn check_descriptor(
    input: &Input<'_>,
    e: &Entry,
    at: u64,
    limit: u64,
) -> Result<u64, ArchiveError> {
    let w: u64 = if e.zip64 { 8 } else { 4 };
    let body = 4 + 2 * w;
    let try_at = |off: u64| -> Result<Option<u64>, ArchiveError> {
        let Some(end) = off.checked_add(body).filter(|&x| x <= limit) else {
            return Ok(None);
        };
        let b = input.read_vec(
            off,
            usize::try_from(body).map_err(|_| ArchiveError::Truncated)?,
        )?;
        let mut le = Le::new(&b);
        let crc = le.u32()?;
        let (c, u) = if e.zip64 {
            (le.u64()?, le.u64()?)
        } else {
            (u64::from(le.u32()?), u64::from(le.u32()?))
        };
        Ok((crc == e.crc && c == e.csize && u == e.usize).then_some(end))
    };
    let mut sig = [0u8; 4];
    if at.checked_add(4).is_some_and(|x| x <= limit) {
        input.read(at, &mut sig)?;
        if u32::from_le_bytes(sig) == SIG_DESCRIPTOR
            && let Some(end) = try_at(at + 4)?
        {
            return Ok(end);
        }
    }
    try_at(at)?.ok_or(ArchiveError::Mismatch("data descriptor"))
}

pub(crate) fn extract(
    input: &Input<'_>,
    lim: &ArchiveLimits,
    sink: &mut dyn ExtractSink,
) -> Result<ArchiveReport, ArchiveError> {
    let dir = find_directory(input)?;
    let mut entries = read_central(input, &dir, lim)?;
    let listed: Vec<Listed> = entries
        .iter()
        .map(|e| Listed {
            path: e.path.clone(),
            is_dir: e.is_dir,
            size: e.usize,
        })
        .collect();
    let names = check_listing(&listed, input.len(), lim)?;

    let mut ranges = Vec::with_capacity(entries.len());
    for e in &mut entries {
        ranges.push(check_local(input, e, dir.offset)?);
    }
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if let [a, b] = pair
            && b.0 < a.1
        {
            return Err(ArchiveError::Overlap);
        }
    }

    let mut col = Collector::new(sink, names, lim);
    let mut window = Window::new();
    for e in &entries {
        if e.is_dir {
            col.dir(&e.path)?;
            continue;
        }
        col.begin(&e.path, e.usize)?;
        let data_end = e.data_start + e.csize;
        let mut rd = RangeReader::new(input, e.data_start, data_end);
        let mut crc = Crc32::new();
        if e.method == 0 {
            loop {
                let c = rd.chunk(64 * 1024)?;
                if c.is_empty() {
                    break;
                }
                crc.update(c);
                col.write(c)?;
            }
        } else {
            window.reset();
            let produced =
                Inflater::new(&mut window).inflate(&mut rd, e.usize, &mut |b: &[u8]| {
                    crc.update(b);
                    col.write(b)
                })?;
            if produced != e.usize {
                return Err(ArchiveError::SizeMismatch);
            }
            if rd.remaining() != 0 {
                return Err(ArchiveError::Malformed("data after final deflate block"));
            }
        }
        if crc.finish() != e.crc {
            return Err(ArchiveError::Crc);
        }
        col.end()?;
    }
    col.finish(ArchiveKind::Zip)
}
