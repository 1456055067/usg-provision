//! Test-only WIM writer (feature `testkit`).
//!
//! Writes uncompressed and XPRESS WIM files with N images, an optional
//! integrity table and boot index, and controllable corruptions, laid out
//! the way our DISM samples are (docs/formats/wim-observed.md):
//!
//! - header fields and flags as DISM writes them (OBS-001, OBS-003,
//!   OBS-004, OBS-005, OBS-007);
//! - file resources from offset 208, unaligned, identical content stored
//!   once with a reference count (OBS-008); resources that do not shrink
//!   stored raw with flag 0x04 clear, also in XPRESS files (OBS-010);
//! - per image, its new file resources then its metadata resource, so
//!   metadata offsets rise with the image index (as in S04, OBS-009);
//! - optionally, the two serviced layouts DISM wrote in run R2: one
//!   metadata resource named by two equal adjacent entries (S11A,
//!   S11B; OBS-018), or image 1's metadata written again after every
//!   other resource with the old copy left in place (S12A; OBS-021,
//!   OBS-022);
//! - then the lookup table directly after the last metadata, with the
//!   metadata entries first (OBS-009), the XML directly after the lookup
//!   table with the element order DISM uses (OBS-014), and the integrity
//!   table last (OBS-007, OBS-015).
//!
//! `tests/dism_samples.rs` (`builder_matches_dism`) checks these points
//! against S01, S02, S04 (12 images) and S05. Not compared: the order of
//! file resources within one image, and reference counts beyond "some
//! resource is shared by every image" (the source trees differ).
//!
//! The metadata resources are opaque synthetic bytes, not a directory
//! tree: the M2 check only decodes and hashes them (OPEN-WIM-7 is not
//! needed until images are applied in M3).
//!
//! A "zero file" of any size can be added to image 1. It is written by
//! seeking past it, so on filesystems with holes a multi-gigabyte fixture
//! costs no disk space (plan WU-5, the 10.5 GiB large-upload fixture).

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/standards/wim.md §2 to §8 (layout written)
// - DECISION: docs/decisions/0006 item 4 (test files only from this
//   builder or our own DISM samples)

use std::collections::HashMap;
use std::io::{self, Read, Seek, SeekFrom, Write};

use usgp_crypto::LegacySha1Hasher;
use usgp_crypto::digest::legacy_sha1;

use super::xpress_enc;
use crate::wim::header::{
    CHUNK_SIZE, Compression, FLAG_COMPRESS_XPRESS, FLAG_COMPRESSION, FLAG_RP_FIX, HEADER_LEN, MAGIC,
};
use crate::wim::lookup::{LookupEntry, chunk_entry_width};
use crate::wim::reshdr::{RESHDR_FLAG_COMPRESSED, RESHDR_FLAG_METADATA, ResourceHeader};
use crate::wim::xml::encode_utf16;

/// Version DISM wrote in every R1 `.wim` (OBS-003).
pub const DISM_VERSION: u32 = 0x0001_0d00;
/// Integrity chunk size DISM wrote (OBS-015).
pub const INTEGRITY_CHUNK: u32 = 10 * 1024 * 1024;
/// Creation and modification time halves written into the XML (fixed so
/// the output is deterministic).
const TIME_HIGH: &str = "0x01DD662B";
const TIME_LOW: &str = "0x861D7446";

/// One image to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageSpec {
    /// `NAME`.
    pub name: String,
    /// `DESCRIPTION` (omitted from the XML when `None`).
    pub description: Option<String>,
    /// File contents; empty files get no resource (OBS-008).
    pub files: Vec<Vec<u8>>,
}

/// Where the builder put things, for tests that patch bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildInfo {
    /// File length.
    pub len: u64,
    /// The lookup table.
    pub lookup: ResourceHeader,
    /// The XML data.
    pub xml: ResourceHeader,
    /// The integrity table, if written.
    pub integrity: Option<ResourceHeader>,
    /// Metadata resource of each image, by index order.
    pub metadata: Vec<ResourceHeader>,
    /// File resources in file order.
    pub files: Vec<ResourceHeader>,
    /// Metadata written but named by no entry (the superseded copy left
    /// by [`WimBuilder::move_first_metadata`]).
    pub stale: Vec<ResourceHeader>,
}

/// Builder for test WIM files.
#[derive(Debug, Clone)]
pub struct WimBuilder {
    compression: Compression,
    images: Vec<ImageSpec>,
    boot_index: u32,
    integrity: bool,
    flags: Option<u32>,
    version: u32,
    field_20: Option<u32>,
    image_count: Option<u32>,
    part: (u16, u16),
    xml: Option<Vec<u8>>,
    zero_file: Option<u64>,
    bad_metadata_hash: Option<u32>,
    identical_metadata: bool,
    reuse_metadata: bool,
    move_first_metadata: bool,
    guid: [u8; 16],
}

impl WimBuilder {
    /// An empty builder for `compression`.
    #[must_use]
    pub fn new(compression: Compression) -> Self {
        Self {
            compression,
            images: Vec::new(),
            boot_index: 0,
            integrity: false,
            flags: None,
            version: DISM_VERSION,
            field_20: None,
            image_count: None,
            part: (1, 1),
            xml: None,
            zero_file: None,
            bad_metadata_hash: None,
            identical_metadata: false,
            reuse_metadata: false,
            move_first_metadata: false,
            guid: *b"usgp-test-guid-1",
        }
    }

    /// Adds an image with deterministic default files: a text file over
    /// two chunks, a small file, a pseudorandom (incompressible) file, a
    /// file shared by every image, and an empty file.
    #[must_use]
    pub fn image(mut self, name: &str, description: &str) -> Self {
        let n = u64::try_from(self.images.len())
            .unwrap_or(0)
            .saturating_add(1);
        self.images.push(ImageSpec {
            name: name.to_owned(),
            description: Some(description.to_owned()),
            files: default_files(n),
        });
        self
    }

    /// Adds an image exactly as given.
    #[must_use]
    pub fn image_spec(mut self, spec: ImageSpec) -> Self {
        self.images.push(spec);
        self
    }

    /// Sets the header's boot index (the boot metadata header then points
    /// at that image's metadata; derived, not observed).
    #[must_use]
    pub fn boot_index(mut self, index: u32) -> Self {
        self.boot_index = index;
        self
    }

    /// Writes an integrity table.
    #[must_use]
    pub fn integrity(mut self, on: bool) -> Self {
        self.integrity = on;
        self
    }

    /// Overrides the header flags.
    #[must_use]
    pub fn header_flags(mut self, flags: u32) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Overrides the version field.
    #[must_use]
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Overrides the field at offset 20.
    #[must_use]
    pub fn field_20(mut self, value: u32) -> Self {
        self.field_20 = Some(value);
        self
    }

    /// Overrides the header's image count.
    #[must_use]
    pub fn image_count(mut self, count: u32) -> Self {
        self.image_count = Some(count);
        self
    }

    /// Sets the part number and total parts.
    #[must_use]
    pub fn part(mut self, number: u16, total: u16) -> Self {
        self.part = (number, total);
        self
    }

    /// Replaces the XML document (encoded as BOM + UTF-16LE).
    #[must_use]
    pub fn xml_text(mut self, text: &str) -> Self {
        self.xml = Some(encode_utf16(text));
        self
    }

    /// Replaces the XML resource bytes exactly.
    #[must_use]
    pub fn xml_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.xml = Some(bytes);
        self
    }

    /// Adds a file of `len` zero bytes to image 1, written sparsely.
    #[must_use]
    pub fn zero_file(mut self, len: u64) -> Self {
        self.zero_file = Some(len);
        self
    }

    /// Writes a wrong SHA-1 for image `index`'s metadata entry.
    #[must_use]
    pub fn bad_metadata_hash(mut self, index: u32) -> Self {
        self.bad_metadata_hash = Some(index);
        self
    }

    /// Writes every image's metadata content as image 1's would be. With
    /// identical files, images then have identical metadata (same bytes,
    /// same SHA-1), each written at its own range (BOOT-011; DISM wrote
    /// one shared range instead in S11, see [`Self::reuse_metadata`]).
    #[must_use]
    pub fn identical_metadata(mut self, on: bool) -> Self {
        self.identical_metadata = on;
        self
    }

    /// Pairs images: image 2k names image 2k - 1's metadata with the same
    /// 50-byte lookup entry, directly after it, and no new metadata is
    /// written for it, as DISM did for the two images of S11A and S11B
    /// (OBS-018; only pairs were observed, so a resource is never named
    /// three times). Meant for images with identical files.
    #[must_use]
    pub fn reuse_metadata(mut self, on: bool) -> Self {
        self.reuse_metadata = on;
        self
    }

    /// After every other resource, writes image 1's metadata again and
    /// points lookup entry 1 at the new copy, leaving the old copy in
    /// place and unnamed, as DISM did when committing index 1 of S12A
    /// (OBS-021, OBS-022). The old copy is reported in
    /// [`BuildInfo::stale`].
    #[must_use]
    pub fn move_first_metadata(mut self, on: bool) -> Self {
        self.move_first_metadata = on;
        self
    }

    /// Builds into memory.
    ///
    /// # Errors
    ///
    /// Only if a size overflows (never for test-sized input).
    pub fn build(&self) -> io::Result<(Vec<u8>, BuildInfo)> {
        let mut c = io::Cursor::new(Vec::new());
        let info = self.write_to(&mut c)?;
        Ok((c.into_inner(), info))
    }

    /// Writes the file to `w` from offset 0. `w` must be readable so the
    /// integrity table can hash what was written.
    ///
    /// # Errors
    ///
    /// I/O errors from `w`, or `InvalidInput` on size overflow.
    pub fn write_to<W: Read + Write + Seek>(&self, w: &mut W) -> io::Result<BuildInfo> {
        w.seek(SeekFrom::Start(0))?;
        w.write_all(&[0u8; HEADER_LEN])?;
        let mut pos = u64::try_from(HEADER_LEN).map_err(|_| overflow())?;

        // File resources, deduplicated by SHA-1 (OBS-008).
        let mut files: Vec<LookupEntry> = Vec::new();
        let mut by_hash: HashMap<[u8; 20], usize> = HashMap::new();
        let mut metadata: Vec<LookupEntry> = Vec::new();
        let mut first_blob: Option<(Vec<u8>, usize, bool)> = None;
        for ((i, img), index) in self.images.iter().enumerate().zip(1u32..) {
            let mut hashes = Vec::new();
            for data in img.files.iter().filter(|d| !d.is_empty()) {
                let sha1 = legacy_sha1(data).0;
                hashes.push(sha1);
                if let Some(e) = by_hash.get(&sha1).and_then(|&k| files.get_mut(k)) {
                    e.ref_count = e.ref_count.saturating_add(1);
                    continue;
                }
                let (bytes, compressed) = self.encode(data);
                let reshdr = write_resource(w, &mut pos, &bytes, data.len(), compressed, 0)?;
                by_hash.insert(sha1, files.len());
                files.push(entry(reshdr, sha1));
            }
            if i == 0
                && let Some(len) = self.zero_file
            {
                let sha1 = zero_sha1(len);
                hashes.push(sha1);
                let reshdr = ResourceHeader {
                    stored_size: len,
                    flags: 0,
                    offset: pos,
                    original_size: len,
                };
                w.seek(SeekFrom::Current(
                    i64::try_from(len).map_err(|_| overflow())?,
                ))?;
                pos = pos.checked_add(len).ok_or_else(overflow)?;
                files.push(entry(reshdr, sha1));
            }

            // OBS-018: one resource, named again by an equal entry.
            if self.reuse_metadata
                && !i.is_multiple_of(2)
                && let Some(previous) = metadata.last().copied()
            {
                metadata.push(previous);
                continue;
            }

            // This image's metadata, right after its new files.
            let blob = metadata_blob(if self.identical_metadata { 1 } else { index }, &hashes);
            let mut sha1 = legacy_sha1(&blob).0;
            if self.bad_metadata_hash == Some(index)
                && let Some(b) = sha1.first_mut()
            {
                *b ^= 0xff;
            }
            let (bytes, compressed) = self.encode(&blob);
            let reshdr = write_resource(
                w,
                &mut pos,
                &bytes,
                blob.len(),
                compressed,
                RESHDR_FLAG_METADATA,
            )?;
            metadata.push(entry(reshdr, sha1));
            if i == 0 {
                first_blob = Some((bytes, blob.len(), compressed));
            }
        }

        // OBS-021: image 1's metadata written again after everything else.
        let mut stale = Vec::new();
        if self.move_first_metadata
            && let (Some((bytes, len, compressed)), Some(first)) =
                (first_blob, metadata.first_mut())
        {
            stale.push(first.reshdr);
            first.reshdr =
                write_resource(w, &mut pos, &bytes, len, compressed, RESHDR_FLAG_METADATA)?;
        }

        // Lookup table: metadata entries first (OBS-009).
        let mut table = Vec::new();
        for e in metadata.iter().chain(files.iter()) {
            table.extend_from_slice(&e.to_bytes());
        }
        let lookup = header_resource(pos, table.len())?;
        w.write_all(&table)?;
        pos = pos.checked_add(lookup.stored_size).ok_or_else(overflow)?;

        // XML directly after the lookup table (OBS-007), TOTALBYTES = its
        // own offset (OBS-014).
        let xml_bytes = match &self.xml {
            Some(x) => x.clone(),
            None => encode_utf16(&self.xml_document(pos)),
        };
        let xml = header_resource(pos, xml_bytes.len())?;
        w.write_all(&xml_bytes)?;
        pos = pos.checked_add(xml.stored_size).ok_or_else(overflow)?;

        // Integrity table over [208, end of lookup) (OBS-015).
        let integrity = if self.integrity {
            let start = u64::try_from(HEADER_LEN).map_err(|_| overflow())?;
            let end = lookup
                .offset
                .checked_add(lookup.stored_size)
                .ok_or_else(overflow)?;
            let t = integrity_table(w, start, end)?;
            w.seek(SeekFrom::Start(pos))?;
            let rh = ResourceHeader {
                stored_size: u64::try_from(t.len()).map_err(|_| overflow())?,
                flags: 0,
                offset: pos,
                original_size: u64::try_from(t.len()).map_err(|_| overflow())?,
            };
            w.write_all(&t)?;
            pos = pos.checked_add(rh.stored_size).ok_or_else(overflow)?;
            Some(rh)
        } else {
            None
        };

        let boot_metadata = usize::try_from(self.boot_index)
            .ok()
            .and_then(|b| b.checked_sub(1))
            .and_then(|k| metadata.get(k))
            .map(|e| e.reshdr)
            .unwrap_or_default();
        let header = self.header_bytes(&lookup, &xml, &boot_metadata, integrity.as_ref())?;
        w.seek(SeekFrom::Start(0))?;
        w.write_all(&header)?;
        w.seek(SeekFrom::Start(pos))?;
        w.flush()?;

        Ok(BuildInfo {
            len: pos,
            lookup,
            xml,
            integrity,
            metadata: metadata.iter().map(|e| e.reshdr).collect(),
            files: files.iter().map(|e| e.reshdr).collect(),
            stale,
        })
    }

    /// Stored bytes of a resource and whether they are compressed.
    fn encode(&self, data: &[u8]) -> (Vec<u8>, bool) {
        if self.compression == Compression::None {
            return (data.to_vec(), false);
        }
        compress_resource(data).map_or_else(|| (data.to_vec(), false), |b| (b, true))
    }

    fn xml_document(&self, xml_offset: u64) -> String {
        let mut s = format!("<WIM><TOTALBYTES>{xml_offset}</TOTALBYTES>");
        for (index, img) in (1u32..).zip(self.images.iter()) {
            let total: usize = img.files.iter().map(Vec::len).sum();
            let total = u64::try_from(total)
                .unwrap_or(u64::MAX)
                .saturating_add(if index == 1 {
                    self.zero_file.unwrap_or(0)
                } else {
                    0
                });
            let count = img
                .files
                .len()
                .saturating_add(usize::from(index == 1 && self.zero_file.is_some()));
            s.push_str(&format!(
                "<IMAGE INDEX=\"{index}\"><DIRCOUNT>1</DIRCOUNT>\
                 <FILECOUNT>{count}</FILECOUNT><TOTALBYTES>{total}</TOTALBYTES>\
                 <HARDLINKBYTES>0</HARDLINKBYTES>\
                 <CREATIONTIME><HIGHPART>{TIME_HIGH}</HIGHPART><LOWPART>{TIME_LOW}</LOWPART></CREATIONTIME>\
                 <LASTMODIFICATIONTIME><HIGHPART>{TIME_HIGH}</HIGHPART><LOWPART>{TIME_LOW}</LOWPART></LASTMODIFICATIONTIME>\
                 <WIMBOOT>0</WIMBOOT><NAME>{}</NAME>",
                escape(&img.name)
            ));
            if let Some(d) = &img.description {
                s.push_str(&format!("<DESCRIPTION>{}</DESCRIPTION>", escape(d)));
            }
            s.push_str("</IMAGE>");
        }
        s.push_str("</WIM>");
        s
    }

    fn header_bytes(
        &self,
        lookup: &ResourceHeader,
        xml: &ResourceHeader,
        boot: &ResourceHeader,
        integrity: Option<&ResourceHeader>,
    ) -> io::Result<[u8; HEADER_LEN]> {
        let (flags, field_20) = match self.compression {
            // OBS-005: none writes 0x80; fast writes 0x00020082. OBS-004:
            // offset 20 holds 0 or 32768.
            Compression::None => (FLAG_RP_FIX, 0),
            Compression::Xpress => (
                FLAG_COMPRESSION | FLAG_RP_FIX | FLAG_COMPRESS_XPRESS,
                CHUNK_SIZE,
            ),
        };
        let image_count = match self.image_count {
            Some(n) => n,
            None => u32::try_from(self.images.len()).map_err(|_| overflow())?,
        };
        let mut h = [0u8; HEADER_LEN];
        let fields: [(usize, &[u8]); 13] = [
            (0, &MAGIC),
            (8, &208u32.to_le_bytes()),
            (12, &self.version.to_le_bytes()),
            (16, &self.flags.unwrap_or(flags).to_le_bytes()),
            (20, &self.field_20.unwrap_or(field_20).to_le_bytes()),
            (24, &self.guid),
            (40, &self.part.0.to_le_bytes()),
            (42, &self.part.1.to_le_bytes()),
            (44, &image_count.to_le_bytes()),
            (48, &lookup.to_bytes()),
            (72, &xml.to_bytes()),
            (96, &boot.to_bytes()),
            (120, &self.boot_index.to_le_bytes()),
        ];
        for (at, bytes) in fields {
            put(&mut h, at, bytes)?;
        }
        if let Some(rh) = integrity {
            put(&mut h, 124, &rh.to_bytes())?;
        }
        Ok(h)
    }
}

fn overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "size overflow")
}

fn put(h: &mut [u8], at: usize, bytes: &[u8]) -> io::Result<()> {
    let end = at.checked_add(bytes.len()).ok_or_else(overflow)?;
    h.get_mut(at..end)
        .ok_or_else(overflow)?
        .copy_from_slice(bytes);
    Ok(())
}

fn entry(reshdr: ResourceHeader, sha1: [u8; 20]) -> LookupEntry {
    LookupEntry {
        reshdr,
        part_number: 1,
        ref_count: 1,
        sha1,
    }
}

/// Lookup and XML resource headers carry flag 0x02 (OBS-007).
fn header_resource(offset: u64, len: usize) -> io::Result<ResourceHeader> {
    let len = u64::try_from(len).map_err(|_| overflow())?;
    Ok(ResourceHeader {
        stored_size: len,
        flags: RESHDR_FLAG_METADATA,
        offset,
        original_size: len,
    })
}

fn write_resource<W: Write>(
    w: &mut W,
    pos: &mut u64,
    bytes: &[u8],
    original: usize,
    compressed: bool,
    extra_flags: u8,
) -> io::Result<ResourceHeader> {
    let stored = u64::try_from(bytes.len()).map_err(|_| overflow())?;
    let rh = ResourceHeader {
        stored_size: stored,
        flags: extra_flags
            | if compressed {
                RESHDR_FLAG_COMPRESSED
            } else {
                0
            },
        offset: *pos,
        original_size: u64::try_from(original).map_err(|_| overflow())?,
    };
    w.write_all(bytes)?;
    *pos = pos.checked_add(stored).ok_or_else(overflow)?;
    Ok(rh)
}

/// Chunk table + XPRESS chunks, or `None` if the resource would not
/// shrink or any chunk would not shrink (then it is stored raw, as DISM
/// does for whole resources, OBS-010; a raw chunk inside a compressed
/// resource is OPEN-WIM-5).
#[must_use]
pub fn compress_resource(data: &[u8]) -> Option<Vec<u8>> {
    let original = u64::try_from(data.len()).ok()?;
    if original == 0 {
        return None;
    }
    let chunk = usize::try_from(CHUNK_SIZE).ok()?;
    let width = chunk_entry_width(original);
    let mut table = Vec::new();
    let mut body = Vec::new();
    let pieces: Vec<&[u8]> = data.chunks(chunk).collect();
    let last = pieces.len().checked_sub(1)?;
    for (i, piece) in pieces.iter().enumerate() {
        let c = xpress_enc::compress(piece);
        if c.len() >= piece.len() {
            return None;
        }
        body.extend_from_slice(&c);
        if i < last {
            let end = u64::try_from(body.len()).ok()?;
            if width == 8 {
                table.extend_from_slice(&end.to_le_bytes());
            } else {
                table.extend_from_slice(&u32::try_from(end).ok()?.to_le_bytes());
            }
        }
    }
    table.extend_from_slice(&body);
    (table.len() < data.len()).then_some(table)
}

/// The synthetic metadata of image `index`: a marker, the index and the
/// hashes of its files, padded with text so it spans three chunks.
fn metadata_blob(index: u32, hashes: &[[u8; 20]]) -> Vec<u8> {
    let mut b = b"USGP-TEST-METADATA\0".to_vec();
    b.extend_from_slice(&index.to_le_bytes());
    for h in hashes {
        b.extend_from_slice(h);
    }
    let mut line: u32 = 0;
    while b.len() < 70_000 {
        b.extend_from_slice(format!("entry {line} of image {index};\n").as_bytes());
        line = line.saturating_add(1);
    }
    b
}

/// Default files for image `n`.
fn default_files(n: u64) -> Vec<Vec<u8>> {
    let mut text = Vec::new();
    let mut i: u64 = 0;
    while text.len() < 40_000 {
        text.extend_from_slice(format!("image {n} line {i} lorem ipsum dolor\n").as_bytes());
        i = i.saturating_add(1);
    }
    vec![
        text,
        format!("small file of image {n}\n").into_bytes(),
        pseudorandom(3000, n),
        b"shared by every image\n".repeat(100),
        Vec::new(),
    ]
}

/// Deterministic incompressible bytes (xorshift64*).
#[must_use]
pub fn pseudorandom(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..len)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            u8::try_from(s.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56).unwrap_or(0)
        })
        .collect()
}

fn zero_sha1(len: u64) -> [u8; 20] {
    let zeros = vec![0u8; 1 << 20];
    let mut h = LegacySha1Hasher::new();
    let mut left = len;
    while left > 0 {
        let n = usize::try_from(left).map_or(zeros.len(), |l| l.min(zeros.len()));
        h.update(zeros.get(..n).unwrap_or(&[]));
        left = left.saturating_sub(u64::try_from(n).unwrap_or(left));
    }
    h.finish().0
}

/// Reads back `[start, end)` of what was written and builds the integrity
/// table: table size, entry count, chunk size, then one SHA-1 per
/// 10 MiB chunk (`wim.md` §8; OBS-015).
fn integrity_table<W: Read + Seek>(w: &mut W, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let chunk = u64::from(INTEGRITY_CHUNK);
    let count = end.saturating_sub(start).div_ceil(chunk);
    let count32 = u32::try_from(count).map_err(|_| overflow())?;
    let size = count32
        .checked_mul(20)
        .and_then(|n| n.checked_add(12))
        .ok_or_else(overflow)?;
    let mut t = Vec::new();
    t.extend_from_slice(&size.to_le_bytes());
    t.extend_from_slice(&count32.to_le_bytes());
    t.extend_from_slice(&INTEGRITY_CHUNK.to_le_bytes());
    let mut buf = vec![0u8; 1 << 16];
    let mut at = start;
    while at < end {
        let chunk_end = at.saturating_add(chunk).min(end);
        let mut h = LegacySha1Hasher::new();
        w.seek(SeekFrom::Start(at))?;
        let mut left = chunk_end.saturating_sub(at);
        while left > 0 {
            let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
            let piece = buf.get_mut(..n).ok_or_else(overflow)?;
            w.read_exact(piece)?;
            h.update(piece);
            left = left.saturating_sub(u64::try_from(n).map_err(|_| overflow())?);
        }
        t.extend_from_slice(&h.finish().0);
        at = chunk_end;
    }
    Ok(t)
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}
