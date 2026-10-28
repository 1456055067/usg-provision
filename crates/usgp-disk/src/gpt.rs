//! GUID Partition Table: model, encoder and strict read-back parser.
//!
//! [`GptPlan`] is a complete table for one disk. [`GptPlan::writes`] gives
//! the blocks to write in the order UEFI requires for an update: backup
//! array and header first, then the primary array and header, then the
//! protective MBR at LBA 0 (`gpt.md` §7; plan §1.2(c)).
//!
//! [`parse_gpt`] reads a table back and applies every UEFI §5.3.2 check to
//! **both** headers and arrays, then checks that the backup mirrors the
//! primary and that every used entry lies in the usable range without
//! overlap. It reads only LBA 0, the two headers and the two entry arrays:
//! partition structures, never partition contents (REQ-DISK-016).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounded, strict parse
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   CRC and read-back before formatting
// - SPEC: specs/disk.md#REQ-DISK-009, #REQ-DISK-010, #REQ-DISK-016
// - UEFI 2.10 §5.3.1 to §5.3.3 (specs/standards/gpt.md §2, §4 to §7)

use crate::bytes;
use crate::crc32::{Crc32, crc32};
use crate::device::BlockDevice;
use crate::error::{GptCopy, GptError};
use crate::guid::Guid;
use crate::mbr;

/// FORMAT: gpt.md §4 - header signature, ASCII `EFI PART`.
pub const SIGNATURE: [u8; 8] = *b"EFI PART";
/// FORMAT: gpt.md §4 - revision 1.0.
pub const REVISION: u32 = 0x0001_0000;
/// FORMAT: gpt.md §4 - HeaderSize we write (the minimum, 92).
pub const HEADER_SIZE: u32 = 92;
/// FORMAT: gpt.md §4 - SizeOfPartitionEntry we write (128 × 2^0).
pub const ENTRY_SIZE: u32 = 128;
/// FORMAT: gpt.md §5 - the size every entry must be a power-of-two
/// multiple of (128 × 2^n).
const ENTRY_SIZE_UNIT: u32 = 128;
/// FORMAT: gpt.md §2, §10 and REQ-DISK-009 - entries we write: 128 × 128 =
/// 16,384 bytes, the minimum array size; Windows allows 128 partitions.
pub const ENTRY_COUNT: u32 = 128;
/// FORMAT: gpt.md §2 - the entry array must reserve at least 16,384 bytes.
pub const MIN_ARRAY_BYTES: u64 = 16_384;
/// FORMAT: gpt.md §2 - the primary header is at LBA 1.
pub const PRIMARY_HEADER_LBA: u64 = 1;
/// FORMAT: gpt.md §2 - our primary entry array starts right after the
/// primary header, at LBA 2.
pub const PRIMARY_ARRAY_LBA: u64 = 2;

// Header field offsets (gpt.md §4, UEFI Table 5.5).
/// FORMAT: gpt.md §4 - Signature at 0.
const H_SIGNATURE: usize = 0;
/// FORMAT: gpt.md §4 - Revision at 8.
const H_REVISION: usize = 8;
/// FORMAT: gpt.md §4 - HeaderSize at 12.
const H_HEADER_SIZE: usize = 12;
/// FORMAT: gpt.md §4 - HeaderCRC32 at 16.
const H_HEADER_CRC: usize = 16;
/// FORMAT: gpt.md §4 - Reserved (zero) at 20, 4 bytes.
const H_RESERVED: usize = 20;
/// FORMAT: gpt.md §4 - MyLBA at 24.
const H_MY_LBA: usize = 24;
/// FORMAT: gpt.md §4 - AlternateLBA at 32.
const H_ALT_LBA: usize = 32;
/// FORMAT: gpt.md §4 - FirstUsableLBA at 40.
const H_FIRST_USABLE: usize = 40;
/// FORMAT: gpt.md §4 - LastUsableLBA at 48.
const H_LAST_USABLE: usize = 48;
/// FORMAT: gpt.md §4 - DiskGUID at 56.
const H_DISK_GUID: usize = 56;
/// FORMAT: gpt.md §4 - PartitionEntryLBA at 72.
const H_ARRAY_LBA: usize = 72;
/// FORMAT: gpt.md §4 - NumberOfPartitionEntries at 80.
const H_ENTRY_COUNT: usize = 80;
/// FORMAT: gpt.md §4 - SizeOfPartitionEntry at 84.
const H_ENTRY_SIZE: usize = 84;
/// FORMAT: gpt.md §4 - PartitionEntryArrayCRC32 at 88.
const H_ARRAY_CRC: usize = 88;

// Entry field offsets (gpt.md §5, UEFI Table 5.6).
/// FORMAT: gpt.md §5 - PartitionTypeGUID at 0.
const E_TYPE: usize = 0;
/// FORMAT: gpt.md §5 - UniquePartitionGUID at 16.
const E_UNIQUE: usize = 16;
/// FORMAT: gpt.md §5 - StartingLBA at 32.
const E_FIRST: usize = 32;
/// FORMAT: gpt.md §5 - EndingLBA (inclusive) at 40.
const E_LAST: usize = 40;
/// FORMAT: gpt.md §5 - Attributes at 48.
const E_ATTRS: usize = 48;
/// FORMAT: gpt.md §5 - PartitionName at 56.
const E_NAME: usize = 56;
/// FORMAT: gpt.md §5 - PartitionName is 36 UTF-16 code units.
pub const NAME_UNITS: usize = 36;
/// FORMAT: gpt.md §5 - reserved bytes start at 128 within an entry.
const E_RESERVED: usize = 128;

/// FORMAT: gpt.md §5 (UEFI Table 5.8) - attribute bits 3 to 47 are
/// undefined and must be zero.
pub const ATTR_UNDEFINED_MASK: u64 = ((1u64 << 48) - 1) & !0b111;

/// FORMAT: gpt.md §4, §1 - the logical block sizes this crate handles
/// (512 and 4096; any other is refused, `windows-storage-firmware-api.md`
/// §3.3, OPEN-DISK-5(b) fail closed).
pub const SUPPORTED_BLOCK_SIZES: [u32; 2] = [512, 4096];

/// One partition entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartitionEntry {
    /// PartitionTypeGUID (nil = unused).
    pub type_guid: Guid,
    /// UniquePartitionGUID.
    pub unique_guid: Guid,
    /// StartingLBA.
    pub first_lba: u64,
    /// EndingLBA, inclusive.
    pub last_lba: u64,
    /// Attributes.
    pub attributes: u64,
    /// PartitionName, UTF-16 code units, NUL-padded.
    pub name: [u16; NAME_UNITS],
}

impl PartitionEntry {
    /// Size in LBAs (`last - first + 1`), or `None` if inverted.
    #[must_use]
    pub fn len_lbas(&self) -> Option<u64> {
        self.last_lba
            .checked_sub(self.first_lba)
            .and_then(|d| d.checked_add(1))
    }

    /// The name up to the first NUL, with invalid UTF-16 replaced (display
    /// only).
    #[must_use]
    pub fn name_lossy(&self) -> String {
        let end = self.name.iter().position(|&u| u == 0).unwrap_or(NAME_UNITS);
        char::decode_utf16(self.name.iter().take(end).copied())
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    fn encode(&self, out: &mut [u8]) -> bool {
        let mut name = [0u8; NAME_UNITS * 2];
        let (pairs, _) = name.as_chunks_mut::<2>();
        for (dst, u) in pairs.iter_mut().zip(self.name.iter()) {
            *dst = u.to_le_bytes();
        }
        bytes::put(out, E_TYPE, &self.type_guid.0)
            && bytes::put(out, E_UNIQUE, &self.unique_guid.0)
            && bytes::put(out, E_FIRST, &self.first_lba.to_le_bytes())
            && bytes::put(out, E_LAST, &self.last_lba.to_le_bytes())
            && bytes::put(out, E_ATTRS, &self.attributes.to_le_bytes())
            && bytes::put(out, E_NAME, &name)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        let mut name = [0u16; NAME_UNITS];
        let name_bytes = bytes::field(raw, E_NAME, NAME_UNITS * 2)?;
        let (pairs, _) = name_bytes.as_chunks::<2>();
        for (dst, pair) in name.iter_mut().zip(pairs) {
            *dst = u16::from_le_bytes(*pair);
        }
        Some(Self {
            type_guid: Guid(bytes::array(raw, E_TYPE)?),
            unique_guid: Guid(bytes::array(raw, E_UNIQUE)?),
            first_lba: bytes::le_u64(raw, E_FIRST)?,
            last_lba: bytes::le_u64(raw, E_LAST)?,
            attributes: bytes::le_u64(raw, E_ATTRS)?,
            name,
        })
    }
}

/// Upper bounds applied when parsing a GPT from a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptLimits {
    /// Largest NumberOfPartitionEntries accepted.
    pub max_entries: u32,
    /// Largest SizeOfPartitionEntry accepted.
    pub max_entry_size: u32,
    /// Largest entry array (count × size) read into memory.
    pub max_array_bytes: u32,
}

impl Default for GptLimits {
    /// Design limits (plan §3.7; not from a standard): 1024 entries of up to
    /// 1024 bytes, at most 1 MiB per array. Windows itself writes 128 × 128
    /// (`gpt.md` §10), well inside this.
    fn default() -> Self {
        Self {
            max_entries: 1024,
            max_entry_size: 1024,
            max_array_bytes: 1024 * 1024,
        }
    }
}

/// A validated table read back from a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptView {
    /// Logical block size.
    pub block: u32,
    /// Device size in logical blocks.
    pub total_lbas: u64,
    /// DiskGUID.
    pub disk_guid: Guid,
    /// FirstUsableLBA.
    pub first_usable: u64,
    /// LastUsableLBA.
    pub last_usable: u64,
    /// NumberOfPartitionEntries.
    pub entry_count: u32,
    /// SizeOfPartitionEntry.
    pub entry_size: u32,
    /// PartitionEntryLBA of the primary array.
    pub primary_array_lba: u64,
    /// PartitionEntryLBA of the backup array.
    pub backup_array_lba: u64,
    /// Used entries with their 0-based slot, in slot order.
    pub entries: Vec<(u32, PartitionEntry)>,
}

/// A complete table to write: 128 × 128-byte entries, primary array at
/// LBA 2, backup array immediately before the backup header at the last
/// LBA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptPlan {
    block: u32,
    total_lbas: u64,
    disk_guid: Guid,
    entries: Vec<PartitionEntry>,
}

/// Blocks the entry array occupies: `ceil(count × size / block)`.
fn array_lbas(count: u32, size: u32, block: u32) -> Option<u64> {
    let bytes = u64::from(count).checked_mul(u64::from(size))?;
    Some(bytes.div_ceil(u64::from(block)))
}

/// FirstUsableLBA and LastUsableLBA for our fixed geometry.
fn usable_range(block: u32, total_lbas: u64) -> Option<(u64, u64)> {
    let arr = array_lbas(ENTRY_COUNT, ENTRY_SIZE, block)?;
    let first = PRIMARY_ARRAY_LBA.checked_add(arr)?;
    let last_lba = total_lbas.checked_sub(1)?;
    // Backup array occupies [last_lba - arr, last_lba - 1]; usable ends
    // just before it.
    let last = last_lba.checked_sub(arr)?.checked_sub(1)?;
    (first <= last).then_some((first, last))
}

impl GptPlan {
    /// Builds and validates a table. `entries` fill slots 0.. in order and
    /// must each be inside the usable range, non-overlapping, with non-nil
    /// type and unique GUIDs, distinct unique GUIDs, and undefined
    /// attribute bits clear.
    ///
    /// # Errors
    /// [`GptError`] naming the first rule broken.
    pub fn new(
        block: u32,
        total_lbas: u64,
        disk_guid: Guid,
        entries: Vec<PartitionEntry>,
    ) -> Result<Self, GptError> {
        if !SUPPORTED_BLOCK_SIZES.contains(&block) {
            return Err(GptError::UnsupportedSectorSize(block));
        }
        let (first, last) = usable_range(block, total_lbas).ok_or(GptError::DeviceTooSmall {
            len: total_lbas.saturating_mul(u64::from(block)),
        })?;
        if disk_guid.is_nil() {
            return Err(GptError::Header {
                copy: GptCopy::Primary,
                reason: "nil disk GUID",
            });
        }
        if entries.len() > ENTRY_COUNT as usize {
            return Err(GptError::Limit("more entries than the array holds"));
        }
        let slotted: Vec<(u32, PartitionEntry)> = (0u32..).zip(entries.iter().copied()).collect();
        check_entries(&slotted, first, last, disk_guid)?;
        Ok(Self {
            block,
            total_lbas,
            disk_guid,
            entries,
        })
    }

    /// Logical block size.
    #[must_use]
    pub fn block(&self) -> u32 {
        self.block
    }

    /// Device size in logical blocks.
    #[must_use]
    pub fn total_lbas(&self) -> u64 {
        self.total_lbas
    }

    /// DiskGUID.
    #[must_use]
    pub fn disk_guid(&self) -> Guid {
        self.disk_guid
    }

    /// The entries, in slot order.
    #[must_use]
    pub fn entries(&self) -> &[PartitionEntry] {
        &self.entries
    }

    /// FirstUsableLBA and LastUsableLBA.
    #[must_use]
    pub fn usable(&self) -> (u64, u64) {
        // Validated in `new`.
        usable_range(self.block, self.total_lbas).unwrap_or((0, 0))
    }

    fn last_lba(&self) -> u64 {
        self.total_lbas.saturating_sub(1)
    }

    fn backup_array_lba(&self) -> u64 {
        let arr = array_lbas(ENTRY_COUNT, ENTRY_SIZE, self.block).unwrap_or(0);
        self.last_lba().saturating_sub(arr)
    }

    /// The encoded entry array, padded with zeros to whole blocks.
    fn encode_array(&self) -> Option<Vec<u8>> {
        let lbas = array_lbas(ENTRY_COUNT, ENTRY_SIZE, self.block)?;
        let len = usize::try_from(lbas.checked_mul(u64::from(self.block))?).ok()?;
        let mut buf = vec![0u8; len];
        let esz = ENTRY_SIZE as usize;
        for (e, slot) in self.entries.iter().zip(buf.chunks_exact_mut(esz)) {
            if !e.encode(slot) {
                return None;
            }
        }
        Some(buf)
    }

    fn encode_header(&self, my: u64, alt: u64, array_lba: u64, array_crc: u32) -> Option<Vec<u8>> {
        let (first, last) = self.usable();
        let mut h = vec![0u8; self.block as usize];
        let ok = bytes::put(&mut h, H_SIGNATURE, &SIGNATURE)
            && bytes::put(&mut h, H_REVISION, &REVISION.to_le_bytes())
            && bytes::put(&mut h, H_HEADER_SIZE, &HEADER_SIZE.to_le_bytes())
            && bytes::put(&mut h, H_MY_LBA, &my.to_le_bytes())
            && bytes::put(&mut h, H_ALT_LBA, &alt.to_le_bytes())
            && bytes::put(&mut h, H_FIRST_USABLE, &first.to_le_bytes())
            && bytes::put(&mut h, H_LAST_USABLE, &last.to_le_bytes())
            && bytes::put(&mut h, H_DISK_GUID, &self.disk_guid.0)
            && bytes::put(&mut h, H_ARRAY_LBA, &array_lba.to_le_bytes())
            && bytes::put(&mut h, H_ENTRY_COUNT, &ENTRY_COUNT.to_le_bytes())
            && bytes::put(&mut h, H_ENTRY_SIZE, &ENTRY_SIZE.to_le_bytes())
            && bytes::put(&mut h, H_ARRAY_CRC, &array_crc.to_le_bytes());
        if !ok {
            return None;
        }
        // HeaderCRC32: field zero, CRC over HeaderSize bytes (gpt.md §6).
        let crc = crc32(bytes::field(&h, 0, HEADER_SIZE as usize)?);
        bytes::put(&mut h, H_HEADER_CRC, &crc.to_le_bytes()).then_some(h)
    }

    /// Byte offset and contents of every block to write, in write order:
    /// backup array, backup header, primary array, primary header,
    /// protective MBR (`gpt.md` §7: backup first).
    ///
    /// # Errors
    /// [`GptError::Limit`] if a buffer cannot be sized (not reachable for a
    /// plan built by [`GptPlan::new`]).
    pub fn writes(&self) -> Result<Vec<(u64, Vec<u8>)>, GptError> {
        let fail = || GptError::Limit("cannot encode table");
        let block = u64::from(self.block);
        let array = self.encode_array().ok_or_else(fail)?;
        let array_crc =
            crc32(bytes::field(&array, 0, (ENTRY_COUNT * ENTRY_SIZE) as usize).ok_or_else(fail)?);
        let last = self.last_lba();
        let backup_arr = self.backup_array_lba();
        let backup_hdr = self
            .encode_header(last, PRIMARY_HEADER_LBA, backup_arr, array_crc)
            .ok_or_else(fail)?;
        let primary_hdr = self
            .encode_header(PRIMARY_HEADER_LBA, last, PRIMARY_ARRAY_LBA, array_crc)
            .ok_or_else(fail)?;
        let mbr = mbr::protective(self.total_lbas, self.block as usize).ok_or_else(fail)?;
        let at = |lba: u64| lba.checked_mul(block).ok_or_else(fail);
        Ok(vec![
            (at(backup_arr)?, array.clone()),
            (at(last)?, backup_hdr),
            (at(PRIMARY_ARRAY_LBA)?, array),
            (at(PRIMARY_HEADER_LBA)?, primary_hdr),
            (0, mbr),
        ])
    }

    /// `true` if `view` describes exactly this plan (read-back check).
    #[must_use]
    pub fn matches(&self, view: &GptView) -> bool {
        let (first, last) = self.usable();
        let want: Vec<(u32, PartitionEntry)> = (0u32..).zip(self.entries.iter().copied()).collect();
        view.block == self.block
            && view.total_lbas == self.total_lbas
            && view.disk_guid == self.disk_guid
            && view.first_usable == first
            && view.last_usable == last
            && view.entry_count == ENTRY_COUNT
            && view.entry_size == ENTRY_SIZE
            && view.primary_array_lba == PRIMARY_ARRAY_LBA
            && view.backup_array_lba == self.backup_array_lba()
            && view.entries == want
    }
}

/// Entry rules shared by the writer and the parser (`gpt.md` §5, §7;
/// REQ-DISK-009): inside the usable range, start ≤ end, no overlap,
/// non-nil unique GUIDs that are distinct from each other and from the
/// disk GUID, and undefined attribute bits clear.
fn check_entries(
    entries: &[(u32, PartitionEntry)],
    first_usable: u64,
    last_usable: u64,
    disk_guid: Guid,
) -> Result<(), GptError> {
    let err = |index: u32, reason| GptError::Entry { index, reason };
    let mut spans: Vec<(u64, u64, u32)> = Vec::with_capacity(entries.len());
    let mut guids: Vec<Guid> = Vec::with_capacity(entries.len());
    for &(index, e) in entries {
        if e.type_guid.is_nil() {
            return Err(err(index, "nil type GUID in a used entry"));
        }
        if e.unique_guid.is_nil() {
            return Err(err(index, "nil unique GUID"));
        }
        if e.unique_guid == disk_guid || guids.contains(&e.unique_guid) {
            return Err(err(index, "unique GUID repeated"));
        }
        guids.push(e.unique_guid);
        if e.first_lba > e.last_lba {
            return Err(err(index, "StartingLBA after EndingLBA"));
        }
        if e.first_lba < first_usable || e.last_lba > last_usable {
            return Err(err(index, "outside the usable range"));
        }
        if e.attributes & ATTR_UNDEFINED_MASK != 0 {
            return Err(err(index, "undefined attribute bits set"));
        }
        spans.push((e.first_lba, e.last_lba, index));
    }
    spans.sort_unstable();
    for pair in spans.windows(2) {
        if let [(_, a_last, _), (b_first, _, b_index)] = pair
            && b_first <= a_last
        {
            return Err(err(*b_index, "overlaps another partition"));
        }
    }
    Ok(())
}

/// Parsed header fields (after the CRC and self checks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    my_lba: u64,
    alt_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: Guid,
    array_lba: u64,
    entry_count: u32,
    entry_size: u32,
    array_crc: u32,
}

fn parse_header(
    block: &[u8],
    copy: GptCopy,
    expect_my: u64,
    expect_alt: u64,
    total_lbas: u64,
    limits: &GptLimits,
) -> Result<Header, GptError> {
    let bad = |reason| GptError::Header { copy, reason };
    let missing = || bad("truncated");
    if bytes::array::<8>(block, H_SIGNATURE) != Some(SIGNATURE) {
        return Err(bad("signature"));
    }
    if bytes::le_u32(block, H_REVISION) != Some(REVISION) {
        return Err(bad("revision"));
    }
    let header_size = bytes::le_u32(block, H_HEADER_SIZE).ok_or_else(missing)?;
    let hs = usize::try_from(header_size).map_err(|_| bad("HeaderSize"))?;
    if header_size < HEADER_SIZE || hs > block.len() {
        return Err(bad("HeaderSize"));
    }
    let stored_crc = bytes::le_u32(block, H_HEADER_CRC).ok_or_else(missing)?;
    let mut c = Crc32::new();
    c.update(bytes::field(block, 0, H_HEADER_CRC).ok_or_else(missing)?);
    c.update(&[0u8; 4]);
    c.update(bytes::field(block, H_RESERVED, hs - H_RESERVED).ok_or_else(missing)?);
    if c.finish() != stored_crc {
        return Err(bad("HeaderCRC32"));
    }
    if bytes::le_u32(block, H_RESERVED) != Some(0) {
        return Err(bad("reserved field not zero"));
    }
    if !bytes::zero_from(block, hs) {
        return Err(bad("reserved tail not zero"));
    }
    let h = Header {
        my_lba: bytes::le_u64(block, H_MY_LBA).ok_or_else(missing)?,
        alt_lba: bytes::le_u64(block, H_ALT_LBA).ok_or_else(missing)?,
        first_usable: bytes::le_u64(block, H_FIRST_USABLE).ok_or_else(missing)?,
        last_usable: bytes::le_u64(block, H_LAST_USABLE).ok_or_else(missing)?,
        disk_guid: Guid(bytes::array(block, H_DISK_GUID).ok_or_else(missing)?),
        array_lba: bytes::le_u64(block, H_ARRAY_LBA).ok_or_else(missing)?,
        entry_count: bytes::le_u32(block, H_ENTRY_COUNT).ok_or_else(missing)?,
        entry_size: bytes::le_u32(block, H_ENTRY_SIZE).ok_or_else(missing)?,
        array_crc: bytes::le_u32(block, H_ARRAY_CRC).ok_or_else(missing)?,
    };
    if h.my_lba != expect_my {
        return Err(bad("MyLBA is not the LBA it was read from"));
    }
    if h.alt_lba != expect_alt {
        return Err(bad("AlternateLBA"));
    }
    if h.disk_guid.is_nil() {
        return Err(bad("nil DiskGUID"));
    }
    // SizeOfPartitionEntry = 128 × 2^n (gpt.md §4).
    if h.entry_size < ENTRY_SIZE_UNIT
        || !h.entry_size.is_multiple_of(ENTRY_SIZE_UNIT)
        || !(h.entry_size / ENTRY_SIZE_UNIT).is_power_of_two()
    {
        return Err(bad("SizeOfPartitionEntry"));
    }
    if h.entry_size > limits.max_entry_size {
        return Err(GptError::Limit("SizeOfPartitionEntry"));
    }
    if h.entry_count > limits.max_entries {
        return Err(GptError::Limit("NumberOfPartitionEntries"));
    }
    let array_bytes = u64::from(h.entry_count) * u64::from(h.entry_size);
    if array_bytes > u64::from(limits.max_array_bytes) {
        return Err(GptError::Limit("entry array size"));
    }
    // Layout checks (gpt.md §2, §7): usable range inside the disk and
    // between the two header/array regions; array outside it and before the
    // other structures; 16,384 bytes reserved for the array.
    let last_lba = total_lbas.checked_sub(1).ok_or_else(missing)?;
    let blk = u64::try_from(block.len()).map_err(|_| bad("block size"))?;
    let arr_lbas = array_bytes.div_ceil(blk);
    let arr_end = h
        .array_lba
        .checked_add(arr_lbas)
        .ok_or_else(|| bad("PartitionEntryLBA"))?;
    let reserved_lbas = MIN_ARRAY_BYTES.div_ceil(blk);
    if h.first_usable > h.last_usable
        || h.first_usable <= PRIMARY_HEADER_LBA
        || h.last_usable >= last_lba
    {
        return Err(bad("usable range"));
    }
    let ok = match copy {
        GptCopy::Primary => {
            h.array_lba > PRIMARY_HEADER_LBA
                && arr_end <= h.first_usable
                && h.first_usable - h.array_lba >= reserved_lbas
        }
        GptCopy::Backup => {
            h.array_lba > h.last_usable
                && arr_end <= h.my_lba
                && h.my_lba - h.array_lba >= reserved_lbas
        }
    };
    if !ok {
        return Err(GptError::Array {
            copy,
            reason: "entry array location",
        });
    }
    Ok(h)
}

/// Reads and CRC-checks one header's entry array (exactly count × size
/// bytes; `gpt.md` §6).
fn read_array(dev: &mut dyn BlockDevice, h: &Header, copy: GptCopy) -> Result<Vec<u8>, GptError> {
    let block = u64::from(dev.logical_sector());
    let bytes_len = u64::from(h.entry_count) * u64::from(h.entry_size);
    let lbas = bytes_len.div_ceil(block);
    let bad = |reason| GptError::Array { copy, reason };
    let read_len = lbas
        .checked_mul(block)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| bad("size"))?;
    let off = h
        .array_lba
        .checked_mul(block)
        .ok_or_else(|| bad("offset"))?;
    let mut buf = vec![0u8; read_len];
    dev.read_at(off, &mut buf)?;
    let used = usize::try_from(bytes_len).map_err(|_| bad("size"))?;
    buf.truncate(used);
    if crc32(&buf) != h.array_crc {
        return Err(bad("PartitionEntryArrayCRC32"));
    }
    Ok(buf)
}

fn read_block(dev: &mut dyn BlockDevice, lba: u64) -> Result<Vec<u8>, GptError> {
    let block = dev.logical_sector();
    let off = lba
        .checked_mul(u64::from(block))
        .ok_or(GptError::Limit("LBA out of range"))?;
    let len = usize::try_from(block).map_err(|_| GptError::UnsupportedSectorSize(block))?;
    let mut buf = vec![0u8; len];
    dev.read_at(off, &mut buf)?;
    Ok(buf)
}

/// Reads LBA 0, both GPT headers and both entry arrays from `dev` and
/// validates them (`gpt.md` §3 to §7). Both copies must be valid and agree;
/// this is the read-back check, so no recovery from one copy is attempted.
///
/// # Errors
/// [`GptError`] naming the copy and the first check that failed.
pub fn parse_gpt(dev: &mut dyn BlockDevice, limits: &GptLimits) -> Result<GptView, GptError> {
    let block = dev.logical_sector();
    if !SUPPORTED_BLOCK_SIZES.contains(&block) {
        return Err(GptError::UnsupportedSectorSize(block));
    }
    let len = dev.len();
    let total_lbas = len / u64::from(block);
    if !len.is_multiple_of(u64::from(block)) || usable_range(block, total_lbas).is_none() {
        return Err(GptError::DeviceTooSmall { len });
    }
    let last_lba = total_lbas - 1;

    match mbr::read_lba0(&read_block(dev, 0)?) {
        mbr::Lba0::Protective => {}
        mbr::Lba0::Empty => return Err(GptError::NoProtectiveMbr("no MBR signature")),
        mbr::Lba0::Legacy(_) => return Err(GptError::NoProtectiveMbr("legacy MBR")),
    }

    let p_raw = read_block(dev, PRIMARY_HEADER_LBA)?;
    let p = parse_header(
        &p_raw,
        GptCopy::Primary,
        PRIMARY_HEADER_LBA,
        last_lba,
        total_lbas,
        limits,
    )?;
    let p_array = read_array(dev, &p, GptCopy::Primary)?;

    let b_raw = read_block(dev, p.alt_lba)?;
    let b = parse_header(
        &b_raw,
        GptCopy::Backup,
        last_lba,
        PRIMARY_HEADER_LBA,
        total_lbas,
        limits,
    )?;
    let b_array = read_array(dev, &b, GptCopy::Backup)?;

    // The backup mirrors the primary (gpt.md §4).
    if b.disk_guid != p.disk_guid {
        return Err(GptError::BackupMismatch("DiskGUID"));
    }
    if (b.first_usable, b.last_usable) != (p.first_usable, p.last_usable) {
        return Err(GptError::BackupMismatch("usable range"));
    }
    if (b.entry_count, b.entry_size, b.array_crc) != (p.entry_count, p.entry_size, p.array_crc)
        || b_array != p_array
    {
        return Err(GptError::BackupMismatch("entry array"));
    }

    let esz = usize::try_from(p.entry_size).map_err(|_| GptError::Limit("entry size"))?;
    let mut entries = Vec::new();
    for (slot, raw) in (0u32..).zip(p_array.chunks_exact(esz)) {
        let e = PartitionEntry::decode(raw).ok_or(GptError::Entry {
            index: slot,
            reason: "truncated",
        })?;
        if e.type_guid.is_nil() {
            continue;
        }
        if !bytes::zero_from(raw, E_RESERVED) {
            return Err(GptError::Entry {
                index: slot,
                reason: "reserved bytes not zero",
            });
        }
        entries.push((slot, e));
    }
    check_entries(&entries, p.first_usable, p.last_usable, p.disk_guid)?;

    Ok(GptView {
        block,
        total_lbas,
        disk_guid: p.disk_guid,
        first_usable: p.first_usable,
        last_usable: p.last_usable,
        entry_count: p.entry_count,
        entry_size: p.entry_size,
        primary_array_lba: p.array_lba,
        backup_array_lba: b.array_lba,
        entries,
    })
}
