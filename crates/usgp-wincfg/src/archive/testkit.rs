//! Test-only ZIP and cabinet writers (plan WU-2 "testkit builders").
//!
//! These write the subset the reader accepts, plus knobs to produce the
//! malformed shapes the negative tests need. They are not a production
//! writer: no input validation, and sizes are assumed to fit.

use usgp_common::crc32::crc32;

use super::cab::checksum;

/// One ZIP entry to write. Every field is public so tests can corrupt it.
#[derive(Debug, Clone)]
pub struct ZipEntrySpec {
    /// Stored name bytes.
    pub name: Vec<u8>,
    /// Bytes as stored (already compressed for method 8).
    pub data: Vec<u8>,
    /// Compression method.
    pub method: u16,
    /// CRC-32 of the uncompressed content.
    pub crc: u32,
    /// Uncompressed size.
    pub usize: u64,
    /// General-purpose flags (both headers unless `local_flags` is set).
    pub flags: u16,
    /// Override of the local header flags.
    pub local_flags: Option<u16>,
    /// Override of the local header name.
    pub local_name: Option<Vec<u8>>,
    /// Override of the local header CRC.
    pub local_crc: Option<u32>,
    /// "Version made by" (host in the high byte).
    pub made_by: u16,
    /// External attributes.
    pub external: u32,
    /// Write sizes and offset through a Zip64 extra field.
    pub zip64: bool,
    /// Write a data descriptor (sets flag 3) with its signature.
    pub descriptor: bool,
    /// Override the local header offset in the central directory.
    pub local_offset: Option<u64>,
}

impl ZipEntrySpec {
    /// A stored file.
    #[must_use]
    pub fn stored(name: &str, content: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: content.to_vec(),
            method: 0,
            crc: crc32(content),
            usize: content.len() as u64,
            flags: 0,
            local_flags: None,
            local_name: None,
            local_crc: None,
            made_by: 20,
            external: 0,
            zip64: false,
            descriptor: false,
            local_offset: None,
        }
    }

    /// A method-8 file with the given raw DEFLATE stream.
    #[must_use]
    pub fn deflated(name: &str, content: &[u8], stream: Vec<u8>) -> Self {
        let mut s = Self::stored(name, content);
        s.method = 8;
        s.data = stream;
        s
    }
}

/// Builds a ZIP file.
#[derive(Debug, Clone, Default)]
pub struct ZipBuilder {
    /// Entries in order.
    pub entries: Vec<ZipEntrySpec>,
    /// Write Zip64 end records.
    pub zip64_end: bool,
    /// Archive comment.
    pub comment: Vec<u8>,
    /// Disk number to write in the end record.
    pub disk: u16,
}

fn p16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn p32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn p64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}

impl ZipBuilder {
    /// Adds an entry.
    #[must_use]
    pub fn entry(mut self, e: ZipEntrySpec) -> Self {
        self.entries.push(e);
        self
    }

    /// Writes the archive.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut offsets = Vec::new();
        for e in &self.entries {
            offsets.push(out.len() as u64);
            let flags = e.flags | if e.descriptor { 1 << 3 } else { 0 };
            let csize = e.data.len() as u64;
            p32(&mut out, 0x0403_4b50);
            p16(&mut out, 45);
            p16(&mut out, e.local_flags.unwrap_or(flags));
            p16(&mut out, e.method);
            p16(&mut out, 0);
            p16(&mut out, 0x21);
            let name = e.local_name.clone().unwrap_or_else(|| e.name.clone());
            let mut extra = Vec::new();
            if e.descriptor {
                p32(&mut out, 0);
                p32(&mut out, 0);
                p32(&mut out, 0);
            } else if e.zip64 {
                p32(&mut out, e.local_crc.unwrap_or(e.crc));
                p32(&mut out, u32::MAX);
                p32(&mut out, u32::MAX);
                p16(&mut extra, 1);
                p16(&mut extra, 16);
                p64(&mut extra, e.usize);
                p64(&mut extra, csize);
            } else {
                p32(&mut out, e.local_crc.unwrap_or(e.crc));
                p32(&mut out, csize as u32);
                p32(&mut out, e.usize as u32);
            }
            p16(&mut out, name.len() as u16);
            p16(&mut out, extra.len() as u16);
            out.extend_from_slice(&name);
            out.extend_from_slice(&extra);
            out.extend_from_slice(&e.data);
            if e.descriptor {
                p32(&mut out, 0x0807_4b50);
                p32(&mut out, e.crc);
                if e.zip64 {
                    p64(&mut out, csize);
                    p64(&mut out, e.usize);
                } else {
                    p32(&mut out, csize as u32);
                    p32(&mut out, e.usize as u32);
                }
            }
        }
        let cd_start = out.len() as u64;
        for (e, &off) in self.entries.iter().zip(&offsets) {
            let flags = e.flags | if e.descriptor { 1 << 3 } else { 0 };
            let off = e.local_offset.unwrap_or(off);
            let csize = e.data.len() as u64;
            p32(&mut out, 0x0201_4b50);
            p16(&mut out, e.made_by);
            p16(&mut out, 45);
            p16(&mut out, flags);
            p16(&mut out, e.method);
            p16(&mut out, 0);
            p16(&mut out, 0x21);
            p32(&mut out, e.crc);
            let mut extra = Vec::new();
            if e.zip64 {
                p32(&mut out, u32::MAX);
                p32(&mut out, u32::MAX);
                p16(&mut extra, 1);
                p16(&mut extra, 24);
                p64(&mut extra, e.usize);
                p64(&mut extra, csize);
                p64(&mut extra, off);
            } else {
                p32(&mut out, csize as u32);
                p32(&mut out, e.usize as u32);
            }
            p16(&mut out, e.name.len() as u16);
            p16(&mut out, extra.len() as u16);
            p16(&mut out, 0);
            p16(&mut out, 0);
            p16(&mut out, 0);
            p32(&mut out, e.external);
            p32(&mut out, if e.zip64 { u32::MAX } else { off as u32 });
            out.extend_from_slice(&e.name);
            out.extend_from_slice(&extra);
        }
        let cd_end = out.len() as u64;
        let n = self.entries.len() as u64;
        if self.zip64_end {
            let z = out.len() as u64;
            p32(&mut out, 0x0606_4b50);
            p64(&mut out, 44);
            p16(&mut out, 45);
            p16(&mut out, 45);
            p32(&mut out, 0);
            p32(&mut out, 0);
            p64(&mut out, n);
            p64(&mut out, n);
            p64(&mut out, cd_end - cd_start);
            p64(&mut out, cd_start);
            p32(&mut out, 0x0706_4b50);
            p32(&mut out, 0);
            p64(&mut out, z);
            p32(&mut out, 1);
        }
        p32(&mut out, 0x0605_4b50);
        p16(&mut out, self.disk);
        p16(&mut out, 0);
        let (n16, sz, of) = if self.zip64_end {
            (u16::MAX, u32::MAX, u32::MAX)
        } else {
            (n as u16, (cd_end - cd_start) as u32, cd_start as u32)
        };
        p16(&mut out, n16);
        p16(&mut out, n16);
        p32(&mut out, sz);
        p32(&mut out, of);
        p16(&mut out, self.comment.len() as u16);
        out.extend_from_slice(&self.comment);
        out
    }
}

/// A DEFLATE stream of stored blocks (RFC 1951 §3.2.4) holding `data`.
#[must_use]
pub fn deflate_stored(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let chunks: Vec<&[u8]> = if data.is_empty() {
        vec![&[]]
    } else {
        data.chunks(65_535).collect()
    };
    let last = chunks.len() - 1;
    for (i, c) in chunks.iter().enumerate() {
        out.push(u8::from(i == last));
        p16(&mut out, c.len() as u16);
        p16(&mut out, !(c.len() as u16));
        out.extend_from_slice(c);
    }
    out
}

/// A symbol for [`deflate_fixed`].
#[derive(Debug, Clone, Copy)]
pub enum Op {
    /// A literal byte.
    Lit(u8),
    /// A back-reference (length 3..=258, distance 1..=32768).
    Match(u16, u16),
}

struct BitW {
    out: Vec<u8>,
    acc: u32,
    n: u32,
}

impl BitW {
    fn bits(&mut self, v: u32, n: u32) {
        for i in 0..n {
            self.acc |= ((v >> i) & 1) << self.n;
            self.n += 1;
            if self.n == 8 {
                self.out.push(self.acc as u8);
                self.acc = 0;
                self.n = 0;
            }
        }
    }
    /// Huffman codes go most significant bit first.
    fn code(&mut self, code: u32, len: u32) {
        for i in (0..len).rev() {
            self.bits((code >> i) & 1, 1);
        }
    }
    fn lit(&mut self, sym: u32) {
        match sym {
            0..=143 => self.code(0x30 + sym, 8),
            144..=255 => self.code(0x190 + sym - 144, 9),
            256..=279 => self.code(sym - 256, 7),
            _ => self.code(0xC0 + sym - 280, 8),
        }
    }
}

const LBASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LEXT: [u32; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DBASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DEXT: [u32; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// One final fixed-Huffman block (RFC 1951 §3.2.6) encoding `ops`.
#[must_use]
pub fn deflate_fixed(ops: &[Op]) -> Vec<u8> {
    let mut w = BitW {
        out: Vec::new(),
        acc: 0,
        n: 0,
    };
    w.bits(1, 1);
    w.bits(1, 2);
    for op in ops {
        match *op {
            Op::Lit(b) => w.lit(u32::from(b)),
            Op::Match(len, dist) => {
                let li = LBASE.iter().rposition(|&b| b <= len).unwrap_or(0);
                w.lit(257 + li as u32);
                w.bits(
                    u32::from(len - LBASE.get(li).copied().unwrap_or(3)),
                    LEXT.get(li).copied().unwrap_or(0),
                );
                let di = DBASE.iter().rposition(|&b| b <= dist).unwrap_or(0);
                w.code(di as u32, 5);
                w.bits(
                    u32::from(dist - DBASE.get(di).copied().unwrap_or(1)),
                    DEXT.get(di).copied().unwrap_or(0),
                );
            }
        }
    }
    w.lit(256);
    if w.n > 0 {
        w.out.push(w.acc as u8);
    }
    w.out
}

/// One cabinet file record to write.
#[derive(Debug, Clone)]
pub struct CabFileSpec {
    /// Name bytes (no NUL).
    pub name: Vec<u8>,
    /// Content.
    pub data: Vec<u8>,
    /// Attributes.
    pub attrs: u16,
}

/// Builds a single-folder cabinet.
#[derive(Debug, Clone, Default)]
pub struct CabBuilder {
    /// Files in order; all in folder 0.
    pub files: Vec<CabFileSpec>,
    /// Folder compression type field.
    pub compression: u16,
    /// Pre-encoded MSZIP block bodies (after `CK`), one per 32 KiB of the
    /// concatenated content; stored DEFLATE blocks are used when `None`.
    pub mszip_blocks: Option<Vec<Vec<u8>>>,
    /// Header flags to OR in.
    pub extra_flags: u16,
    /// Write data-block checksums.
    pub checksums: bool,
    /// Reserve sizes (header, folder, data); written when any is non-zero.
    pub reserve: (u16, u8, u8),
    /// Version (major, minor).
    pub version: Option<(u8, u8)>,
    /// Override the folder index of every file.
    pub folder_index: Option<u16>,
}

impl CabBuilder {
    /// Adds a file.
    #[must_use]
    pub fn file(mut self, name: &str, data: &[u8]) -> Self {
        self.files.push(CabFileSpec {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            attrs: 0x20,
        });
        self
    }

    /// Writes the cabinet.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let content: Vec<u8> = self.files.iter().flat_map(|f| f.data.clone()).collect();
        let chunks: Vec<&[u8]> = content.chunks(32_768).collect();
        let blocks: Vec<(Vec<u8>, u16)> = chunks
            .iter()
            .enumerate()
            .map(|(i, c)| {
                let body = match self.compression {
                    0 => c.to_vec(),
                    _ => {
                        let mut b = b"CK".to_vec();
                        match &self.mszip_blocks {
                            Some(v) => b.extend_from_slice(v.get(i).map_or(&[][..], Vec::as_slice)),
                            None => b.extend_from_slice(&deflate_stored(c)),
                        }
                        b
                    }
                };
                (body, c.len() as u16)
            })
            .collect();
        let has_reserve = self.reserve != (0, 0, 0);
        let mut hdr_len = 36
            + if has_reserve {
                4 + self.reserve.0 as usize
            } else {
                0
            };
        let folder_len = 8 + self.reserve.1 as usize;
        let coff_files = hdr_len + folder_len;
        let files_len: usize = self.files.iter().map(|f| 16 + f.name.len() + 1).sum();
        let first_block = coff_files + files_len;
        let data_len: usize = blocks
            .iter()
            .map(|(b, _)| 8 + self.reserve.2 as usize + b.len())
            .sum();
        let total = first_block + data_len;

        let mut out = Vec::new();
        out.extend_from_slice(b"MSCF");
        p32(&mut out, 0);
        p32(&mut out, total as u32);
        p32(&mut out, 0);
        p32(&mut out, coff_files as u32);
        p32(&mut out, 0);
        let (maj, min) = self.version.unwrap_or((1, 3));
        out.push(min);
        out.push(maj);
        p16(&mut out, 1);
        p16(&mut out, self.files.len() as u16);
        p16(&mut out, self.extra_flags | if has_reserve { 4 } else { 0 });
        p16(&mut out, 0x1234);
        p16(&mut out, 0);
        if has_reserve {
            p16(&mut out, self.reserve.0);
            out.push(self.reserve.1);
            out.push(self.reserve.2);
            out.extend(std::iter::repeat_n(0xAA, self.reserve.0 as usize));
        }
        hdr_len = out.len();
        let _ = hdr_len;
        p32(&mut out, first_block as u32);
        p16(&mut out, blocks.len() as u16);
        p16(&mut out, self.compression);
        out.extend(std::iter::repeat_n(0xBB, self.reserve.1 as usize));
        let mut off = 0u32;
        for f in &self.files {
            p32(&mut out, f.data.len() as u32);
            p32(&mut out, off);
            p16(&mut out, self.folder_index.unwrap_or(0));
            p16(&mut out, 0x21);
            p16(&mut out, 0);
            p16(&mut out, f.attrs);
            out.extend_from_slice(&f.name);
            out.push(0);
            off += f.data.len() as u32;
        }
        for (body, unc) in &blocks {
            let mut hdr = Vec::new();
            p16(&mut hdr, body.len() as u16);
            p16(&mut hdr, *unc);
            let csum = if self.checksums {
                checksum(&hdr, checksum(body, 0))
            } else {
                0
            };
            p32(&mut out, csum);
            out.extend_from_slice(&hdr);
            out.extend(std::iter::repeat_n(0xCC, self.reserve.2 as usize));
            out.extend_from_slice(body);
        }
        out
    }
}
