//! The lookup table (`wim.md` §5): one 50-byte entry per resource,
//! streamed and checked entry by entry.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every entry's
//   location is checked against the file; the table is streamed.
// - SPEC: specs/os-images.md#REQ-IMG-037 (locations within the file; the
//   number of images agrees), #REQ-IMG-038 (split parts refused)
// - SPEC: specs/standards/wim.md §3, §4, §5

use std::io::{Read, Seek};

use super::header::{CHUNK_SIZE, Compression, HEADER_LEN_U64};
use super::reshdr::{
    RESHDR_FLAG_COMPRESSED, RESHDR_FLAG_METADATA, RESHDR_FLAG_SPANNED, RESHDR_LEN, ResourceHeader,
    le_u16, le_u32,
};
use super::source::Source;
use crate::error::WimError;

/// Size of one lookup entry.
// FORMAT: OBS-008 - 50 packed bytes: resource header (24), part number
// (2), reference count (4), SHA-1 (20); every R1 table size is a multiple
// of 50 (OPEN-WIM-6 part 1 settled).
pub const ENTRY_LEN: usize = 50;

/// [`ENTRY_LEN`] as a u64.
pub const ENTRY_LEN_U64: u64 = 50;

/// Entries read per I/O.
const ENTRIES_PER_READ: usize = 1310;

/// Resource flag 0x10, which the WIM paper does not define.
// FORMAT: OBS-006 - DISM's recovery (.esd) output sets 0x10 on 18 lookup
// entries; that output is refused as an undocumented compression.
pub const RESHDR_FLAG_RECOVERY_UNDEFINED: u8 = 0x10;

/// One lookup table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LookupEntry {
    /// Where the resource is.
    pub reshdr: ResourceHeader,
    /// Part number in a split set.
    pub part_number: u16,
    /// Uses across all images.
    pub ref_count: u32,
    /// SHA-1 of the uncompressed content (OBS-008).
    pub sha1: [u8; 20],
}

impl LookupEntry {
    /// Parses one 50-byte entry. Returns `None` if `b` is shorter.
    #[must_use]
    pub fn parse(b: &[u8]) -> Option<Self> {
        let reshdr = ResourceHeader::parse(b.get(..RESHDR_LEN)?)?;
        let sha1: [u8; 20] = b.get(30..50)?.try_into().ok()?;
        Some(Self {
            reshdr,
            part_number: le_u16(b, 24)?,
            ref_count: le_u32(b, 26)?,
            sha1,
        })
    }

    /// The 50-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; ENTRY_LEN] {
        let mut out = [0u8; ENTRY_LEN];
        let fields = self
            .reshdr
            .to_bytes()
            .into_iter()
            .chain(self.part_number.to_le_bytes())
            .chain(self.ref_count.to_le_bytes())
            .chain(self.sha1);
        for (o, f) in out.iter_mut().zip(fields) {
            *o = f;
        }
        out
    }
}

/// Number of chunks of a compressed resource (`wim.md` §4).
#[must_use]
pub fn chunk_count(original_size: u64) -> u64 {
    original_size.div_ceil(u64::from(CHUNK_SIZE))
}

/// Width of one chunk-table entry for a resource of `original_size`.
// FORMAT: derived, unconfirmed - OPEN-WIM-10. wim.md §4: 8 bytes "if the
// original size is over 4 GB", read here as original_size > 2^32 - 1.
// OBS-011 confirms 4 bytes below 2^32; the threshold needs sample S08.
#[must_use]
pub fn chunk_entry_width(original_size: u64) -> u64 {
    if original_size > u64::from(u32::MAX) {
        8
    } else {
        4
    }
}

/// Size of the chunk table of a compressed resource:
/// `(ceil(original / 32768) - 1) * width` (`wim.md` §4; OBS-011).
#[must_use]
pub fn chunk_table_len(original_size: u64) -> Option<u64> {
    chunk_count(original_size)
        .checked_sub(1)?
        .checked_mul(chunk_entry_width(original_size))
}

/// Checks one entry on its own and against the file.
///
/// # Errors
///
/// [`WimError::Spanned`] for a split-set entry, [`WimError::Malformed`]
/// for undefined flags or inconsistent sizes, [`WimError::OutOfBounds`]
/// if the resource lies outside the file.
pub fn check_entry(
    e: &LookupEntry,
    compression: Compression,
    file_len: u64,
) -> Result<(), WimError> {
    let flags = e.reshdr.flags;
    // FORMAT: OBS-017 - in split parts every entry carries its part's
    // number; resource flag 0x08 was never seen but means spanned
    // (wim.md §3). Either is refused as split.
    if flags & RESHDR_FLAG_SPANNED != 0 || e.part_number != 1 {
        return Err(WimError::Spanned);
    }
    // BOOT-008: 0x10 is what the recovery (.esd) output writes; name it as
    // an unsupported compression rather than as damage.
    if flags & RESHDR_FLAG_RECOVERY_UNDEFINED != 0 {
        return Err(WimError::CompressionNotSupported);
    }
    // Only metadata and compressed are accepted. Free (0x01) and undefined
    // bits are unspecified for a reader; fail closed.
    if flags & !(RESHDR_FLAG_METADATA | RESHDR_FLAG_COMPRESSED) != 0 {
        return Err(WimError::Malformed {
            what: "resource flags",
        });
    }
    e.reshdr
        .check_within(HEADER_LEN_U64, file_len, "resource")?;
    if e.reshdr.is_compressed() {
        if compression == Compression::None {
            return Err(WimError::Malformed {
                what: "compressed resource in an uncompressed file",
            });
        }
        let table = chunk_table_len(e.reshdr.original_size).ok_or(WimError::Malformed {
            what: "compressed resource size",
        })?;
        // Each chunk needs at least one stored byte.
        let min = table
            .checked_add(chunk_count(e.reshdr.original_size))
            .ok_or(WimError::OutOfBounds {
                what: "chunk table",
            })?;
        if e.reshdr.stored_size < min {
            return Err(WimError::OutOfBounds {
                what: "chunk table",
            });
        }
    } else if e.reshdr.stored_size != e.reshdr.original_size {
        // FORMAT: OBS-010 - uncompressed resources (flag 0x04 clear) have
        // stored size == original size, also inside XPRESS files.
        return Err(WimError::Malformed {
            what: "resource sizes",
        });
    }
    Ok(())
}

/// Metadata entries in lookup order, with the file's resource count.
///
/// The metadata entries are private: one resource may be named by two
/// images (OBS-018), so per-resource work (reading, decoding, hashing,
/// budgeting) must go through [`LookupScan::distinct_metadata`];
/// [`LookupScan::image_metadata`] is for per-image lookups only (SEC-002).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LookupScan {
    /// Entries with the metadata flag, in lookup-table order. The k-th
    /// (0-based) belongs to image index k + 1 (OBS-009, OBS-021).
    metadata: Vec<LookupEntry>,
    /// Per entry of `metadata`: true if it repeats the lookup entry
    /// directly before it (OBS-018) and so names no new resource.
    repeats: Vec<bool>,
    /// Number of entries in the table.
    pub entries: u64,
    /// Compressed file (non-metadata) resources, sorted by offset, for the
    /// chunk-table pass (REQ-IMG-037 bullet 2; BOOT-007).
    pub compressed_files: Vec<ResourceHeader>,
}

impl LookupScan {
    /// The metadata entry of every image, in index order (entry k - 1 is
    /// image index k). Two images may name one resource (OBS-018): use
    /// this to find an image's entry, never to drive per-resource work.
    #[must_use]
    pub fn image_metadata(&self) -> &[LookupEntry] {
        &self.metadata
    }

    /// Each metadata resource once, with the image index of its first
    /// use: an entry that repeats the lookup entry directly before it
    /// (OBS-018) names the same bytes with the same hash, so it is
    /// skipped. The whole-table checks have already refused any other
    /// sharing, so these resources' ranges are disjoint and reading each
    /// once reads at most the file length (SEC-003).
    pub fn distinct_metadata(&self) -> impl Iterator<Item = (u32, &LookupEntry)> {
        (1u32..)
            .zip(self.metadata.iter().zip(&self.repeats))
            .filter(|(_, (_, repeat))| !**repeat)
            .map(|(index, (e, _))| (index, e))
    }
}

/// Most header resources added to the overlap check (lookup table, XML,
/// integrity table).
const MAX_HEADER_RESOURCES: usize = 3;

/// The refusal for a failed reservation: memory for the whole-table
/// checks is not available.
const fn no_memory() -> WimError {
    WimError::LimitExceeded {
        what: "lookup table",
    }
}

/// Entries kept while a table is walked, for the whole-table checks.
struct Collector {
    scan: LookupScan,
    /// Every entry's location, with room for the header's own resources
    /// so that [`Collector::finish`] never grows it (SEC-014).
    ranges: Vec<ResourceHeader>,
    /// The hash of every file (non-metadata) entry (BOOT-011).
    hashes: Vec<[u8; 20]>,
    /// Highest end offset of every entry except the first metadata entry
    /// (for the serviced-file order rule, OBS-021).
    end_of_others: u64,
    /// The lookup entry visited last, and whether it was itself a repeat
    /// (OBS-018 reuse rule).
    previous: Option<(LookupEntry, bool)>,
}

impl Collector {
    fn new(expected_entries: u64) -> Result<Self, WimError> {
        let n = usize::try_from(expected_entries).map_err(|_| no_memory())?;
        let with_header = n.checked_add(MAX_HEADER_RESOURCES).ok_or_else(no_memory)?;
        let mut ranges = Vec::new();
        let mut hashes = Vec::new();
        // Fail closed (no abort) if the memory is not available. Both
        // vectors are reserved in full here, so the walk and the
        // whole-table checks never reallocate them (SEC-014).
        ranges
            .try_reserve_exact(with_header)
            .and_then(|()| hashes.try_reserve_exact(n))
            .map_err(|_| no_memory())?;
        Ok(Self {
            scan: LookupScan {
                metadata: Vec::new(),
                repeats: Vec::new(),
                entries: 0,
                compressed_files: Vec::new(),
            },
            ranges,
            hashes,
            end_of_others: 0,
            previous: None,
        })
    }

    fn visit(
        &mut self,
        raw: &[u8],
        compression: Compression,
        file_len: u64,
        max_images: u32,
    ) -> Result<(), WimError> {
        let e = LookupEntry::parse(raw).ok_or(WimError::TooShort)?;
        check_entry(&e, compression, file_len)?;
        self.scan.entries = self.scan.entries.saturating_add(1);
        let first_metadata = e.reshdr.is_metadata() && self.scan.metadata.is_empty();
        if !first_metadata {
            let end = e.reshdr.offset.saturating_add(e.reshdr.stored_size);
            self.end_of_others = self.end_of_others.max(end);
        }
        if e.reshdr.is_metadata() {
            let n = u32::try_from(self.scan.metadata.len()).unwrap_or(u32::MAX);
            if n >= max_images {
                return Err(WimError::LimitExceeded { what: "images" });
            }
            // FORMAT: OBS-018 - in S11A and S11B (two images with
            // identical metadata, by append and by export) DISM wrote two
            // metadata entries next to each other in the lookup table,
            // equal in all 50 bytes (offset, sizes, flags, part, count,
            // SHA-1): one resource used by two images (wim.md §5, §13
            // S11). Only an entry equal to the lookup entry directly
            // before it, which is not itself a repeat, is taken as a
            // reuse: exactly two equal adjacent entries, as observed. Its
            // range is recorded once, so the overlap rule below does not
            // see it twice. Any other entry naming the same bytes (other
            // size, hash, flags or count, a file entry between the two,
            // or a third equal entry) keeps its own range and is refused
            // as an overlap.
            let repeat = matches!(self.previous, Some((p, false)) if p == e);
            self.previous = Some((e, repeat));
            self.scan.metadata.push(e);
            self.scan.repeats.push(repeat);
            if repeat {
                return Ok(());
            }
        } else {
            self.previous = Some((e, false));
            self.hashes.push(e.sha1);
        }
        self.ranges.push(e.reshdr);
        Ok(())
    }

    /// The whole-table checks, in this order: repeated hash among file
    /// resources, overlapping ranges (including `extra`, the header's own
    /// resources), metadata order. `extra`, when not empty, starts with
    /// the lookup table itself.
    ///
    /// Allocates nothing that can abort: `ranges` was reserved with room
    /// for `extra`, and the compressed-file list is reserved fallibly.
    // COMPLIANCE MAPPING:
    // - NIST 800-53: SC-5 (Denial of Service Protection), SI-10 - with no
    //   two resources sharing bytes (a reused metadata entry is one
    //   resource, read once through `distinct_metadata`), every resource
    //   range is read at most once, so the check's reads stay within the
    //   file length (SEC-003, BOOT-001).
    // - SPEC: specs/standards/wim.md §5, §13 S11 and S12
    // - SPEC: specs/os-images.md#REQ-IMG-037 (bounded time and memory)
    fn finish(mut self, extra: &[ResourceHeader]) -> Result<LookupScan, WimError> {
        // FORMAT: OBS-008 - DISM stores identical file content once, so
        // two file entries with one hash do not occur in DISM files;
        // refused. Metadata entries are left out (BOOT-011): two images
        // may have identical metadata, each is mapped to its index by
        // position, not by hash, and the overlap check below still
        // bounds the work to one read per range (OBS-018: DISM then
        // writes one range, named by two equal entries).
        self.hashes.sort_unstable();
        if self.hashes.windows(2).any(|w| w.first() == w.get(1)) {
            return Err(WimError::DuplicateResource);
        }
        drop(self.hashes);

        // FORMAT: OBS-008 - no two resources share bytes in any R1 file;
        // OBS-018 - the one sharing seen since (S11) is a reused metadata
        // entry, whose range `visit` recorded once. Gaps are allowed:
        // DISM leaves superseded lookup tables, XML and metadata in place
        // (OBS-020, OBS-022). Empty ranges share no byte.
        let mut ranges = self.ranges;
        // No-op when `extra` fits the room reserved in `new` (always, from
        // `scan` and `parse_table`); otherwise a refusal, never an abort.
        ranges.try_reserve(extra.len()).map_err(|_| no_memory())?;
        ranges.extend(extra.iter().copied());
        ranges.sort_unstable_by_key(|r| (r.offset, r.stored_size));
        let mut end_so_far: u64 = 0;
        for r in ranges.iter().filter(|r| r.stored_size != 0) {
            if r.offset < end_so_far {
                return Err(WimError::ResourceOverlap);
            }
            end_so_far = r.offset.saturating_add(r.stored_size);
        }

        // Metadata order (wim.md §5, §13 S11 and S12; OPEN-WIM-6).
        // FORMAT: OBS-009, OBS-023 - in S04 and S12B metadata offsets rise
        // with lookup order. FORMAT: OBS-018 - in S11A and S11B two
        // adjacent entries are equal (one reused resource).
        // FORMAT: OBS-021 - in S12A (S04 with index 1 mounted, changed
        // and committed) the first metadata entry names a new resource
        // written after every other resource of the table and ending
        // where the lookup table starts (so before the XML too); the
        // others keep rising offsets, and lookup order (not offset
        // order) names the index (wim.md §5 "Commit", §13 OPEN-WIM-6).
        // Only these three shapes are accepted: the first entry may lie
        // after every other entry's range and end exactly at the lookup
        // table, before every other header resource (then no reuse is
        // accepted in the same table, a combination not observed);
        // otherwise offsets rise strictly, or an entry repeats the one
        // before it. Any other order is refused (BOOT-003, BOOT-012); the
        // operator remedy is to export each image to a new file.
        // `parse_table` has no header resources; `check_wim` always
        // passes them.
        let m = &self.scan.metadata;
        let first_relocated = match (m.first(), m.get(1)) {
            (Some(a), Some(b)) => {
                let end = a.reshdr.offset.saturating_add(a.reshdr.stored_size);
                let before_header = extra.first().is_none_or(|lookup| lookup.offset == end)
                    && extra
                        .iter()
                        .filter(|r| r.stored_size != 0)
                        .all(|r| end <= r.offset);
                a.reshdr.offset > b.reshdr.offset
                    && a.reshdr.offset >= self.end_of_others
                    && before_header
            }
            _ => false,
        };
        let skip = usize::from(first_relocated);
        let rest = m.get(skip..).unwrap_or(&[]);
        let rest_repeats = self.scan.repeats.get(skip..).unwrap_or(&[]);
        let in_order = rest
            .iter()
            .zip(rest.iter().skip(1).zip(rest_repeats.iter().skip(1)))
            .all(|(a, (b, b_repeat))| {
                a.reshdr.offset < b.reshdr.offset || (!first_relocated && *b_repeat)
            });
        if !in_order {
            return Err(WimError::MetadataOrderNotSupported);
        }

        let wanted = |r: &&ResourceHeader| r.is_compressed() && !r.is_metadata();
        let count = ranges.iter().filter(wanted).count();
        let mut files = Vec::new();
        files.try_reserve_exact(count).map_err(|_| no_memory())?;
        files.extend(ranges.iter().filter(wanted).copied());
        drop(ranges);
        self.scan.compressed_files = files;
        Ok(self.scan)
    }
}

/// Parses and checks a whole in-memory lookup table (for fuzzing and
/// tests; [`scan`] streams the same checks and also checks the entries
/// against the header's own resources). Without those resources the
/// OBS-021 bounds on a moved first entry (ending at the lookup table,
/// before the XML and integrity table) are not checked, so use
/// [`crate::check_wim`] to check a file (finding BOOT-009).
///
/// # Errors
///
/// As [`check_entry`]; [`WimError::Malformed`] if the length is not a
/// multiple of 50; [`WimError::LimitExceeded`] if there are more than
/// `max_images` metadata entries; then [`WimError::DuplicateResource`],
/// [`WimError::ResourceOverlap`] (a reused metadata entry, OBS-018, is not
/// an overlap) and [`WimError::MetadataOrderNotSupported`] (orders other
/// than those of OBS-009, OBS-018 and OBS-021) from the whole-table checks.
pub fn parse_table(
    table: &[u8],
    compression: Compression,
    file_len: u64,
    max_images: u32,
) -> Result<LookupScan, WimError> {
    let (entries, rest) = table.as_chunks::<ENTRY_LEN>();
    if !rest.is_empty() {
        return Err(WimError::Malformed {
            what: "lookup table size",
        });
    }
    let count = u64::try_from(entries.len()).unwrap_or(u64::MAX);
    let mut c = Collector::new(count)?;
    for raw in entries {
        c.visit(raw, compression, file_len, max_images)?;
    }
    c.finish(&[])
}

/// Streams the lookup table at `table` (already bounds-checked and within
/// `max_lookup_bytes`) and checks every entry, then the whole table
/// against itself and against `header_resources` (the lookup table, XML
/// and integrity table).
pub(crate) fn scan<R: Read + Seek>(
    src: &mut Source<'_, R>,
    table: &ResourceHeader,
    header_resources: &[ResourceHeader],
    compression: Compression,
    file_len: u64,
    max_images: u32,
) -> Result<LookupScan, WimError> {
    let mut c = Collector::new(table.stored_size / ENTRY_LEN_U64)?;
    let mut buf = vec![0u8; ENTRY_LEN.saturating_mul(ENTRIES_PER_READ)];
    let mut done: u64 = 0;
    while done < table.stored_size {
        let left = table.stored_size.saturating_sub(done);
        let n = usize::try_from(left).map_or(buf.len(), |l| l.min(buf.len()));
        let piece = buf.get_mut(..n).ok_or(WimError::Malformed {
            what: "lookup table size",
        })?;
        let at = table
            .offset
            .checked_add(done)
            .ok_or(WimError::OutOfBounds {
                what: "lookup table",
            })?;
        src.read_at(at, piece)?;
        let (entries, rest) = piece.as_chunks::<ENTRY_LEN>();
        if !rest.is_empty() {
            return Err(WimError::Malformed {
                what: "lookup table size",
            });
        }
        for raw in entries {
            c.visit(raw, compression, file_len, max_images)?;
        }
        done = done.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
    }
    c.finish(header_resources)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obs_008_entry() {
        // S01 entry 1 (OBS-008): stored 1, flags 0, offset 208, original
        // 1, part 1, count 1, SHA-1 of a one-byte file.
        let mut b = [0u8; 50];
        let fields: [(usize, u8); 6] = [(0, 1), (8, 0xd0), (16, 1), (24, 1), (26, 1), (30, 0x30)];
        for (at, v) in fields {
            if let Some(s) = b.get_mut(at) {
                *s = v;
            }
        }
        let e = LookupEntry::parse(&b).unwrap();
        assert_eq!(e.reshdr.stored_size, 1);
        assert_eq!(e.reshdr.offset, 208);
        assert_eq!(e.part_number, 1);
        assert_eq!(e.ref_count, 1);
        assert_eq!(e.to_bytes(), b);
        assert_eq!(check_entry(&e, Compression::None, 209), Ok(()));
        assert!(check_entry(&e, Compression::None, 208).is_err());
    }

    #[test]
    fn chunk_math() {
        // OBS-011: 367034 bytes -> 12 chunks, 11 four-byte entries.
        assert_eq!(chunk_count(367_034), 12);
        assert_eq!(chunk_table_len(367_034), Some(44));
        assert_eq!(chunk_table_len(32768), Some(0));
        assert_eq!(chunk_table_len(0), None);
        assert_eq!(chunk_entry_width(u64::from(u32::MAX)), 4);
        assert_eq!(chunk_entry_width(1 << 32), 8);
        assert_eq!(
            chunk_table_len(u64::MAX),
            Some((u64::MAX.div_ceil(32768) - 1) * 8)
        );
    }

    fn entry_at(offset: u64, flags: u8, sha1: u8) -> [u8; ENTRY_LEN] {
        LookupEntry {
            reshdr: ResourceHeader {
                stored_size: 10,
                flags,
                offset,
                original_size: 10,
            },
            part_number: 1,
            ref_count: 1,
            sha1: [sha1; 20],
        }
        .to_bytes()
    }

    fn table(entries: &[[u8; ENTRY_LEN]]) -> Vec<u8> {
        entries.iter().flatten().copied().collect()
    }

    #[test]
    fn repeated_hash_refused_for_files_only() {
        // BOOT-011: two metadata entries with one hash at distinct ranges
        // are accepted; two file entries with one hash are refused.
        let m = RESHDR_FLAG_METADATA;
        let t = table(&[
            entry_at(208, m, 1),
            entry_at(218, m, 1),
            entry_at(228, 0, 2),
        ]);
        let scan = parse_table(&t, Compression::None, 1000, 4).unwrap();
        assert_eq!(scan.metadata.len(), 2);
        let t = table(&[
            entry_at(208, m, 1),
            entry_at(218, 0, 2),
            entry_at(228, 0, 2),
        ]);
        assert_eq!(
            parse_table(&t, Compression::None, 1000, 4),
            Err(WimError::DuplicateResource)
        );
        // Two file entries with one hash and one range: refused (the
        // reuse rule of OBS-018 is for metadata only).
        let t = table(&[entry_at(208, 0, 2), entry_at(208, 0, 2)]);
        assert_eq!(
            parse_table(&t, Compression::None, 1000, 4),
            Err(WimError::DuplicateResource)
        );
    }

    fn with(e: [u8; ENTRY_LEN], f: impl FnOnce(&mut LookupEntry)) -> [u8; ENTRY_LEN] {
        let mut x = LookupEntry::parse(&e).unwrap();
        f(&mut x);
        x.to_bytes()
    }

    fn scan_of(entries: &[[u8; ENTRY_LEN]]) -> Result<LookupScan, WimError> {
        parse_table(&table(entries), Compression::None, 1000, 8)
    }

    #[test]
    fn reused_metadata_entry_accepted_once() {
        // OBS-018 (S11A, S11B): two adjacent lookup entries equal in all
        // 50 bytes are one resource used twice; it is listed once.
        let m = RESHDR_FLAG_METADATA;
        let a = entry_at(208, m, 1);
        let s = scan_of(&[a, a, entry_at(218, 0, 2)]).unwrap();
        assert_eq!(s.image_metadata().len(), 2);
        assert_eq!(s.repeats, [false, true]);
        let d: Vec<u32> = s.distinct_metadata().map(|(i, _)| i).collect();
        assert_eq!(d, [1]);
        // Distinct entries keep their own indexes; two pairs are fine.
        let b = entry_at(218, m, 3);
        let s = scan_of(&[a, a, b, b, entry_at(228, 0, 2)]).unwrap();
        let d: Vec<u32> = s.distinct_metadata().map(|(i, _)| i).collect();
        assert_eq!(d, [1, 3]);
        // Only one repeat (BOOT-001): a third equal entry is an overlap.
        for uses in [3usize, 4] {
            let mut t = vec![a; uses];
            t.push(entry_at(218, 0, 2));
            assert_eq!(scan_of(&t), Err(WimError::ResourceOverlap), "{uses}");
        }
    }

    #[test]
    fn shared_metadata_range_must_match_in_every_field() {
        // Anything short of an exact repeat is an overlap (OBS-018 is the
        // only sharing observed).
        let m = RESHDR_FLAG_METADATA;
        let a = entry_at(208, m, 1);
        let variants = [
            with(a, |e| e.sha1 = [9; 20]),
            with(a, |e| {
                e.reshdr.stored_size = 11;
                e.reshdr.original_size = 11;
            }),
            with(a, |e| {
                e.reshdr.stored_size = 9;
                e.reshdr.original_size = 9;
            }),
            with(a, |e| e.ref_count = 2),
            // Partial overlap: starts inside the first range.
            with(a, |e| e.reshdr.offset = 213),
        ];
        for b in variants {
            assert_eq!(
                scan_of(&[a, b, entry_at(300, 0, 2)]),
                Err(WimError::ResourceOverlap),
                "{:?}",
                LookupEntry::parse(&b)
            );
        }
        // A repeat that is not adjacent to its twin keeps its own range:
        // another metadata entry, or a file entry, between them
        // (BOOT-004, SEC-001).
        assert_eq!(
            scan_of(&[a, entry_at(218, m, 3), a]),
            Err(WimError::ResourceOverlap)
        );
        assert_eq!(
            scan_of(&[a, entry_at(218, 0, 3), a]),
            Err(WimError::ResourceOverlap)
        );
        // A metadata entry repeating a file entry's range.
        assert_eq!(
            scan_of(&[entry_at(218, 0, 2), entry_at(218, m, 2)]),
            Err(WimError::ResourceOverlap)
        );
    }

    #[test]
    fn serviced_order_only_in_observed_shape() {
        // OBS-021 (S12A): the first metadata entry names a resource after
        // every other entry's range; the rest rise. Accepted.
        let m = RESHDR_FLAG_METADATA;
        let f = entry_at(228, 0, 9);
        let s = scan_of(&[
            entry_at(300, m, 1),
            entry_at(208, m, 2),
            entry_at(218, m, 3),
            f,
        ])
        .unwrap();
        let offsets: Vec<u64> = s.metadata.iter().map(|e| e.reshdr.offset).collect();
        assert_eq!(offsets, [300, 208, 218]);
        // Directly after the last other range is enough.
        assert!(
            scan_of(&[
                entry_at(238, m, 1),
                entry_at(208, m, 2),
                entry_at(218, m, 3),
                f
            ])
            .is_ok()
        );
        let refused = [
            // A file resource lies after the moved entry.
            vec![
                entry_at(300, m, 1),
                entry_at(208, m, 2),
                entry_at(310, 0, 9),
            ],
            // The moved entry ends before another metadata range ends.
            vec![
                entry_at(220, m, 1),
                entry_at(208, m, 2),
                entry_at(232, m, 3),
            ],
            // Not the first entry that moved.
            vec![
                entry_at(208, m, 1),
                entry_at(300, m, 2),
                entry_at(218, m, 3),
                f,
            ],
            // Two entries out of order.
            vec![
                entry_at(300, m, 1),
                entry_at(218, m, 2),
                entry_at(208, m, 3),
                f,
            ],
            // Reverse order of three (with two, a reversed pair is the
            // OBS-021 shape and is accepted).
            vec![
                entry_at(228, m, 1),
                entry_at(218, m, 2),
                entry_at(208, m, 3),
            ],
            // Moved first entry combined with a reused entry (unobserved).
            vec![
                entry_at(300, m, 1),
                entry_at(208, m, 2),
                entry_at(208, m, 2),
                f,
            ],
            // Reused first entry then a lower offset.
            vec![
                entry_at(300, m, 1),
                entry_at(300, m, 1),
                entry_at(208, m, 2),
            ],
        ];
        for t in refused {
            assert_eq!(
                scan_of(&t),
                Err(WimError::MetadataOrderNotSupported),
                "{:?}",
                t.iter()
                    .map(|e| LookupEntry::parse(e).unwrap().reshdr.offset)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn collector_reserves_room_for_header_resources() {
        // SEC-014: `finish` must not grow `ranges`.
        let mut c = Collector::new(4).unwrap();
        assert!(c.ranges.capacity() >= 4 + MAX_HEADER_RESOURCES);
        let before = c.ranges.capacity();
        for k in 0..4u64 {
            c.visit(
                &entry_at(208 + 10 * k, 0, 9 - u8::try_from(k).unwrap()),
                Compression::None,
                1000,
                4,
            )
            .unwrap();
        }
        assert_eq!(c.ranges.capacity(), before);
        let extra = [ResourceHeader {
            stored_size: 10,
            flags: RESHDR_FLAG_METADATA,
            offset: 300,
            original_size: 10,
        }; MAX_HEADER_RESOURCES];
        // Three overlapping extras: refused by the overlap rule, after the
        // extend that must fit the reservation.
        assert_eq!(c.finish(&extra), Err(WimError::ResourceOverlap));
        assert_eq!(
            Collector::new(u64::MAX).err(),
            Some(WimError::LimitExceeded {
                what: "lookup table"
            })
        );
    }

    #[test]
    fn table_size_not_multiple() {
        assert_eq!(
            parse_table(&[0u8; 49], Compression::None, 1000, 1),
            Err(WimError::Malformed {
                what: "lookup table size"
            })
        );
    }

    fn finish_with_header(
        entries: &[[u8; ENTRY_LEN]],
        header: &[ResourceHeader],
    ) -> Result<LookupScan, WimError> {
        let mut c = Collector::new(u64::try_from(entries.len()).unwrap()).unwrap();
        for e in entries {
            c.visit(e, Compression::None, 1000, 8).unwrap();
        }
        c.finish(header)
    }

    #[test]
    fn moved_entry_must_end_at_the_lookup_table() {
        // OBS-021 (BOOT-003): the moved first entry ends where the lookup
        // table starts, before the XML and integrity table.
        let m = RESHDR_FLAG_METADATA;
        let t = [
            entry_at(300, m, 1),
            entry_at(208, m, 2),
            entry_at(218, m, 3),
        ];
        let rh = |offset: u64, size: u64| ResourceHeader {
            stored_size: size,
            flags: m,
            offset,
            original_size: size,
        };
        // Lookup at 310, XML at 460, integrity at 500: accepted.
        assert!(finish_with_header(&t, &[rh(310, 150), rh(460, 20), rh(500, 20)]).is_ok());
        // A gap between the moved entry and the lookup table.
        assert_eq!(
            finish_with_header(&t, &[rh(320, 150), rh(470, 20)]),
            Err(WimError::MetadataOrderNotSupported)
        );
        // Moved entry after the lookup table and XML.
        assert_eq!(
            finish_with_header(&t, &[rh(228, 50), rh(278, 22)]),
            Err(WimError::MetadataOrderNotSupported)
        );
        // Lookup directly after it, but the XML lies before it.
        assert_eq!(
            finish_with_header(&t, &[rh(310, 150), rh(228, 20)]),
            Err(WimError::MetadataOrderNotSupported)
        );
        // Rising order needs none of this.
        let t = [entry_at(208, m, 1), entry_at(218, m, 2)];
        assert!(finish_with_header(&t, &[rh(600, 100), rh(228, 20)]).is_ok());
    }
}
