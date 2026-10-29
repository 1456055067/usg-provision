//! Bounds-checked parsers for the variable-length buffers Windows returns.
//!
//! `DeviceIoControl` fills caller buffers with structures whose tail is
//! variable (descriptor strings, partition entries, disk extents). The FFI
//! layer copies each result into an owned `Vec<u8>`; the functions here
//! read fields from it at offsets taken from a layout description. On
//! Windows the layouts are computed from the `windows-sys` declarations
//! with `offset_of!`/`size_of` (`crate::layout`), so no structure layout or
//! numeric constant is written by hand (OPEN-WAPI-1). This module is pure
//! and OS-neutral so that its bounds checks are tested on every host with
//! synthetic layouts.
//!
//! Every read is checked: a field that would end past the reported size or
//! the buffer is a [`ParseError`], never a panic.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), SI-16 (Memory
//   Protection) - OS-returned structures parsed by safe, bounds-checked code
// - SPEC: specs/standards/windows-storage-firmware-api.md §1, §3, §4, §5,
//   §7, §8
// - DECISION: docs/decisions/0019-windows-api-binding.md

/// Most partition entries accepted from one drive-layout query.
pub const MAX_PARTITION_ENTRIES: u32 = 4096;
/// Most extents accepted for one volume.
pub const MAX_VOLUME_EXTENTS: u32 = 1024;
/// Longest descriptor identity string read (bytes, before the NUL).
pub const MAX_ID_STRING: usize = 256;

/// Why a buffer returned by Windows was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// A field ends past the end of the buffer or the reported size.
    OutOfBounds {
        /// Field offset.
        offset: usize,
        /// Field length.
        len: usize,
        /// Bytes available.
        available: usize,
    },
    /// The structure reports a size smaller than its fixed part.
    SizeTooSmall {
        /// Reported size.
        reported: u64,
        /// Size of the fixed part.
        fixed: usize,
    },
    /// The structure reports a size larger than the buffer it came in.
    SizeExceedsBuffer {
        /// Reported size.
        reported: u64,
        /// Bytes available.
        available: usize,
    },
    /// An element count is above the accepted maximum.
    CountTooLarge {
        /// Reported count.
        count: u32,
        /// Accepted maximum.
        limit: u32,
    },
    /// A byte offset or length that must be non-negative is negative.
    Negative,
    /// A string has no terminating NUL inside its bounds.
    Unterminated,
    /// A string is not valid UTF-16.
    InvalidUtf16,
    /// A structure breaks a documented rule (which one is named).
    Malformed(&'static str),
}

// Display by hand: this crate adds no dependency beyond windows-sys, so the
// shared Cargo.lock is unchanged (plan §2: lock edits belong to WU-0).
impl core::fmt::Display for ParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::OutOfBounds {
                offset,
                len,
                available,
            } => write!(
                f,
                "field at offset {offset} (+{len}) is outside the {available}-byte buffer"
            ),
            Self::SizeTooSmall { reported, fixed } => {
                write!(
                    f,
                    "reported size {reported} is below the fixed size {fixed}"
                )
            }
            Self::SizeExceedsBuffer {
                reported,
                available,
            } => write!(
                f,
                "reported size {reported} exceeds the {available}-byte buffer"
            ),
            Self::CountTooLarge { count, limit } => {
                write!(f, "count {count} exceeds the limit {limit}")
            }
            Self::Negative => f.write_str("negative offset or length"),
            Self::Unterminated => f.write_str("string is not NUL-terminated within bounds"),
            Self::InvalidUtf16 => f.write_str("string is not valid UTF-16"),
            Self::Malformed(what) => write!(f, "malformed: {what}"),
        }
    }
}

impl std::error::Error for ParseError {}

type Result<T> = core::result::Result<T, ParseError>;

// ---------------------------------------------------------------------------
// Primitive reads
// ---------------------------------------------------------------------------

fn bytes_at<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N]> {
    let oob = ParseError::OutOfBounds {
        offset,
        len: N,
        available: buf.len(),
    };
    let end = offset.checked_add(N).ok_or(oob)?;
    let slice = buf.get(offset..end).ok_or(oob)?;
    <[u8; N]>::try_from(slice).map_err(|_| oob)
}

/// Reads a `u8` at `offset`.
pub fn u8_at(buf: &[u8], offset: usize) -> Result<u8> {
    bytes_at::<1>(buf, offset).map(|b| b[0])
}

/// Reads a native-endian (little-endian on every Windows target) `u32`.
pub fn u32_at(buf: &[u8], offset: usize) -> Result<u32> {
    bytes_at::<4>(buf, offset).map(u32::from_le_bytes)
}

/// Reads a little-endian `i32`.
pub fn i32_at(buf: &[u8], offset: usize) -> Result<i32> {
    bytes_at::<4>(buf, offset).map(i32::from_le_bytes)
}

/// Reads a little-endian `u64`.
pub fn u64_at(buf: &[u8], offset: usize) -> Result<u64> {
    bytes_at::<8>(buf, offset).map(u64::from_le_bytes)
}

/// Reads a little-endian `i64` that must be non-negative, as `u64`.
pub fn nonneg_i64_at(buf: &[u8], offset: usize) -> Result<u64> {
    let v = bytes_at::<8>(buf, offset).map(i64::from_le_bytes)?;
    u64::try_from(v).map_err(|_| ParseError::Negative)
}

/// Reads a GUID stored in Windows memory order (little-endian first three
/// fields). That is also the GPT on-disk byte order (`gpt.md`).
pub fn guid_at(buf: &[u8], offset: usize) -> Result<Guid> {
    bytes_at::<16>(buf, offset).map(Guid::from_le_bytes)
}

/// Restricts `buf` to the size a structure reports about itself.
///
/// The size must cover the fixed part and must not exceed the buffer.
pub fn reported_extent(buf: &[u8], reported: u64, fixed: usize) -> Result<&[u8]> {
    let fixed_u64 =
        u64::try_from(fixed).map_err(|_| ParseError::SizeTooSmall { reported, fixed })?;
    if reported < fixed_u64 {
        return Err(ParseError::SizeTooSmall { reported, fixed });
    }
    let end = usize::try_from(reported).map_err(|_| ParseError::SizeExceedsBuffer {
        reported,
        available: buf.len(),
    })?;
    buf.get(..end).ok_or(ParseError::SizeExceedsBuffer {
        reported,
        available: buf.len(),
    })
}

/// Byte offset of element `index` in an array at `base` with `stride`.
fn element_offset(base: usize, stride: usize, index: u32) -> Result<usize> {
    let i = usize::try_from(index).map_err(|_| ParseError::CountTooLarge {
        count: index,
        limit: u32::MAX,
    })?;
    stride
        .checked_mul(i)
        .and_then(|o| o.checked_add(base))
        .ok_or(ParseError::OutOfBounds {
            offset: base,
            len: stride,
            available: 0,
        })
}

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------

/// A GUID in its four-field form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Guid {
    /// First field (32 bits).
    pub data1: u32,
    /// Second field (16 bits).
    pub data2: u16,
    /// Third field (16 bits).
    pub data3: u16,
    /// Last eight bytes, in order.
    pub data4: [u8; 8],
}

impl Guid {
    /// Decodes 16 bytes in Windows memory order (the GPT on-disk order).
    #[must_use]
    pub fn from_le_bytes(b: [u8; 16]) -> Self {
        let [
            a0,
            a1,
            a2,
            a3,
            b0,
            b1,
            c0,
            c1,
            d0,
            d1,
            d2,
            d3,
            d4,
            d5,
            d6,
            d7,
        ] = b;
        Self {
            data1: u32::from_le_bytes([a0, a1, a2, a3]),
            data2: u16::from_le_bytes([b0, b1]),
            data3: u16::from_le_bytes([c0, c1]),
            data4: [d0, d1, d2, d3, d4, d5, d6, d7],
        }
    }

    /// Encodes in Windows memory order (the GPT on-disk order).
    #[must_use]
    pub fn to_le_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        let parts = self
            .data1
            .to_le_bytes()
            .into_iter()
            .chain(self.data2.to_le_bytes())
            .chain(self.data3.to_le_bytes())
            .chain(self.data4);
        for (slot, byte) in out.iter_mut().zip(parts) {
            *slot = byte;
        }
        out
    }

    /// Upper-case braced text form `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`,
    /// as the firmware-variable functions take it
    /// (`windows-storage-firmware-api.md` §9).
    #[must_use]
    pub fn to_braced_upper(&self) -> String {
        let [d0, d1, d2, d3, d4, d5, d6, d7] = self.data4;
        format!(
            "{{{:08X}-{:04X}-{:04X}-{d0:02X}{d1:02X}-{d2:02X}{d3:02X}{d4:02X}{d5:02X}{d6:02X}{d7:02X}}}",
            self.data1, self.data2, self.data3
        )
    }
}

impl core::fmt::Display for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_braced_upper())
    }
}

// ---------------------------------------------------------------------------
// Storage descriptors (IOCTL_STORAGE_QUERY_PROPERTY), spec §3
// ---------------------------------------------------------------------------

/// Field offsets of the common descriptor header (`STORAGE_DESCRIPTOR_HEADER`).
#[derive(Debug, Clone, Copy)]
pub struct HeaderLayout {
    /// Offset of `Size`.
    pub size: usize,
    /// Size of the header.
    pub len: usize,
}

/// The full size a descriptor reports in its header (spec §3 sizing step).
pub fn descriptor_size(buf: &[u8], l: &HeaderLayout) -> Result<u32> {
    u32_at(buf, l.size)
}

/// Field offsets of the device descriptor (`STORAGE_DEVICE_DESCRIPTOR`).
#[derive(Debug, Clone, Copy)]
pub struct DeviceDescriptorLayout {
    /// Offset of `Size`.
    pub size: usize,
    /// Offset of `DeviceType`.
    pub device_type: usize,
    /// Offset of `RemovableMedia`.
    pub removable_media: usize,
    /// Offset of `VendorIdOffset`.
    pub vendor_id_offset: usize,
    /// Offset of `ProductIdOffset`.
    pub product_id_offset: usize,
    /// Offset of `ProductRevisionOffset`.
    pub product_revision_offset: usize,
    /// Offset of `SerialNumberOffset`.
    pub serial_number_offset: usize,
    /// Offset of `BusType`.
    pub bus_type: usize,
    /// Size of the fixed part (up to the raw bus-specific bytes).
    pub fixed_len: usize,
}

/// The device descriptor's fields, still in raw form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDeviceDescriptor {
    /// SCSI peripheral device type.
    pub device_type: u8,
    /// `RemovableMedia`. Any non-zero byte counts as removable (fail closed).
    pub removable_media: bool,
    /// Raw `STORAGE_BUS_TYPE` value.
    pub bus_type: i32,
    /// Vendor id string, if present.
    pub vendor_id: Option<String>,
    /// Product id string, if present.
    pub product_id: Option<String>,
    /// Product revision string, if present.
    pub product_revision: Option<String>,
    /// Serial number string, if present.
    pub serial_number: Option<String>,
}

/// Parses a device descriptor (spec §3.1).
pub fn device_descriptor(buf: &[u8], l: &DeviceDescriptorLayout) -> Result<RawDeviceDescriptor> {
    let size = u32_at(buf, l.size)?;
    let d = reported_extent(buf, u64::from(size), l.fixed_len)?;
    Ok(RawDeviceDescriptor {
        device_type: u8_at(d, l.device_type)?,
        removable_media: u8_at(d, l.removable_media)? != 0,
        bus_type: i32_at(d, l.bus_type)?,
        vendor_id: id_string(d, u32_at(d, l.vendor_id_offset)?)?,
        product_id: id_string(d, u32_at(d, l.product_id_offset)?)?,
        product_revision: id_string(d, u32_at(d, l.product_revision_offset)?)?,
        serial_number: id_string(d, u32_at(d, l.serial_number_offset)?)?,
    })
}

/// Reads a NUL-terminated ASCII identity string at `offset` inside the
/// descriptor. Zero means absent (spec §3.1). Bytes outside printable
/// ASCII are replaced by `?` so that the text is safe to display and log;
/// surrounding spaces are trimmed; an empty result is `None`.
fn id_string(d: &[u8], offset: u32) -> Result<Option<String>> {
    if offset == 0 {
        return Ok(None);
    }
    let start = usize::try_from(offset).map_err(|_| ParseError::Unterminated)?;
    let rest = d.get(start..).ok_or(ParseError::OutOfBounds {
        offset: start,
        len: 1,
        available: d.len(),
    })?;
    let window = rest
        .get(..rest.len().min(MAX_ID_STRING + 1))
        .unwrap_or(rest);
    let nul = window
        .iter()
        .position(|&b| b == 0)
        .ok_or(ParseError::Unterminated)?;
    let raw = window.get(..nul).ok_or(ParseError::Unterminated)?;
    let text: String = raw
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '?'
            }
        })
        .collect();
    let trimmed = text.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

/// Field offsets of the access-alignment descriptor
/// (`STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR`).
#[derive(Debug, Clone, Copy)]
pub struct AlignmentLayout {
    /// Offset of `Size`.
    pub size: usize,
    /// Offset of `BytesPerLogicalSector`.
    pub logical: usize,
    /// Offset of `BytesPerPhysicalSector`.
    pub physical: usize,
    /// Size of the structure.
    pub fixed_len: usize,
}

/// Logical and physical sector sizes (spec §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectorSizes {
    /// Bytes per logical sector.
    pub logical: u32,
    /// Bytes per physical sector.
    pub physical: u32,
}

/// Parses an access-alignment descriptor (spec §3.3).
pub fn access_alignment(buf: &[u8], l: &AlignmentLayout) -> Result<SectorSizes> {
    let size = u32_at(buf, l.size)?;
    let d = reported_extent(buf, u64::from(size), l.fixed_len)?;
    Ok(SectorSizes {
        logical: u32_at(d, l.logical)?,
        physical: u32_at(d, l.physical)?,
    })
}

// ---------------------------------------------------------------------------
// Geometry (IOCTL_DISK_GET_DRIVE_GEOMETRY_EX), spec §4
// ---------------------------------------------------------------------------

/// Field offsets of `DISK_GEOMETRY_EX`.
#[derive(Debug, Clone, Copy)]
pub struct GeometryLayout {
    /// Offset of `Geometry.MediaType`.
    pub media_type: usize,
    /// Offset of `Geometry.BytesPerSector`.
    pub bytes_per_sector: usize,
    /// Offset of `DiskSize`.
    pub disk_size: usize,
}

/// Geometry fields, raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawGeometry {
    /// Raw `MEDIA_TYPE` value.
    pub media_type: i32,
    /// `BytesPerSector`.
    pub bytes_per_sector: u32,
    /// `DiskSize` in bytes.
    pub disk_size: u64,
}

/// Parses `DISK_GEOMETRY_EX` (spec §4). Only the fixed fields are read; the
/// partition and detection information after `DiskSize` is not.
pub fn geometry(buf: &[u8], l: &GeometryLayout) -> Result<RawGeometry> {
    Ok(RawGeometry {
        media_type: i32_at(buf, l.media_type)?,
        bytes_per_sector: u32_at(buf, l.bytes_per_sector)?,
        disk_size: nonneg_i64_at(buf, l.disk_size)?,
    })
}

// ---------------------------------------------------------------------------
// Device number (IOCTL_STORAGE_GET_DEVICE_NUMBER), spec §7
// ---------------------------------------------------------------------------

/// Field offsets of `STORAGE_DEVICE_NUMBER`.
#[derive(Debug, Clone, Copy)]
pub struct DeviceNumberLayout {
    /// Offset of `DeviceType`.
    pub device_type: usize,
    /// Offset of `DeviceNumber`.
    pub device_number: usize,
    /// Offset of `PartitionNumber`.
    pub partition_number: usize,
}

/// A device's number. Valid only until removal or restart (spec §7); never
/// a lasting identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNumber {
    /// Device type (`FILE_DEVICE_*`).
    pub device_type: u32,
    /// Device number; for disks, the `N` of `PhysicalDriveN`.
    pub device_number: u32,
    /// Partition number; `u32::MAX` (−1) when the device cannot be
    /// partitioned.
    pub partition_number: u32,
}

/// Parses `STORAGE_DEVICE_NUMBER` (spec §7).
pub fn device_number(buf: &[u8], l: &DeviceNumberLayout) -> Result<DeviceNumber> {
    Ok(DeviceNumber {
        device_type: u32_at(buf, l.device_type)?,
        device_number: u32_at(buf, l.device_number)?,
        partition_number: u32_at(buf, l.partition_number)?,
    })
}

// ---------------------------------------------------------------------------
// Drive layout (IOCTL_DISK_GET_DRIVE_LAYOUT_EX), spec §5
// ---------------------------------------------------------------------------

/// Field offsets of `DRIVE_LAYOUT_INFORMATION_EX` and its entries, plus the
/// two partition-style values that select the union member.
#[derive(Debug, Clone, Copy)]
pub struct DriveLayoutLayout {
    /// Offset of `PartitionStyle`.
    pub style: usize,
    /// Offset of `PartitionCount`.
    pub count: usize,
    /// Offset of the GPT header's `DiskId`.
    pub gpt_disk_id: usize,
    /// Offset of the GPT header's `StartingUsableOffset`.
    pub gpt_starting_usable: usize,
    /// Offset of the GPT header's `UsableLength`.
    pub gpt_usable_length: usize,
    /// Offset of the GPT header's `MaxPartitionCount`.
    pub gpt_max_partition_count: usize,
    /// Offset of the MBR header's `Signature`.
    pub mbr_signature: usize,
    /// Offset of the first entry.
    pub entries: usize,
    /// Size of one entry.
    pub entry_stride: usize,
    /// Entry field offsets.
    pub entry: PartitionEntryLayout,
    /// `PARTITION_STYLE_GPT`.
    pub style_gpt: i32,
    /// `PARTITION_STYLE_MBR`.
    pub style_mbr: i32,
}

/// Field offsets inside one `PARTITION_INFORMATION_EX`.
#[derive(Debug, Clone, Copy)]
pub struct PartitionEntryLayout {
    /// Offset of `PartitionStyle`.
    pub style: usize,
    /// Offset of `StartingOffset`.
    pub starting_offset: usize,
    /// Offset of `PartitionLength`.
    pub length: usize,
    /// Offset of `PartitionNumber`.
    pub number: usize,
    /// Offset of the GPT part's `PartitionType`.
    pub gpt_type: usize,
    /// Offset of the GPT part's `PartitionId`.
    pub gpt_id: usize,
    /// Offset of the GPT part's `Attributes`.
    pub gpt_attributes: usize,
    /// Offset of the GPT part's `Name`.
    pub gpt_name: usize,
    /// Length of `Name` in UTF-16 units.
    pub gpt_name_units: usize,
    /// Offset of the MBR part's `PartitionType`.
    pub mbr_type: usize,
    /// Offset of the MBR part's `BootIndicator`.
    pub mbr_boot_indicator: usize,
}

/// A parsed drive layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDriveLayout {
    /// Raw partition style.
    pub style: i32,
    /// The GPT header, when the style is GPT.
    pub gpt: Option<GptLayoutHeader>,
    /// The MBR disk signature, when the style is MBR.
    pub mbr_signature: Option<u32>,
    /// Every entry Windows returned, in order (unused MBR slots included).
    pub partitions: Vec<RawPartition>,
}

/// GPT header fields of a drive layout (spec §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptLayoutHeader {
    /// Disk GUID.
    pub disk_id: Guid,
    /// Byte offset of the first usable block.
    pub starting_usable_offset: u64,
    /// Usable length in bytes.
    pub usable_length: u64,
    /// Entries allowed in the partition array.
    pub max_partition_count: u32,
}

/// One partition entry (spec §5). Offsets and lengths are in bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPartition {
    /// Raw entry style.
    pub style: i32,
    /// Starting offset in bytes.
    pub starting_offset: u64,
    /// Length in bytes.
    pub length: u64,
    /// 1-based partition number.
    pub number: u32,
    /// Style-specific details.
    pub kind: RawPartitionKind,
}

/// Style-specific part of a partition entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawPartitionKind {
    /// A GPT entry.
    Gpt {
        /// Partition type GUID.
        type_guid: Guid,
        /// Unique partition GUID.
        id: Guid,
        /// Attribute bits.
        attributes: u64,
        /// Name, up to the first NUL (unpaired surrogates replaced).
        name: String,
    },
    /// An MBR entry.
    Mbr {
        /// MBR partition type byte.
        partition_type: u8,
        /// Boot indicator.
        boot_indicator: bool,
    },
    /// Any other style; only the common fields are read.
    Other,
}

/// Parses a drive layout (spec §5).
///
/// `returned` is the number of bytes the call reported; the entry array
/// must lie entirely inside it.
pub fn drive_layout(buf: &[u8], l: &DriveLayoutLayout) -> Result<RawDriveLayout> {
    let style = i32_at(buf, l.style)?;
    let count = u32_at(buf, l.count)?;
    if count > MAX_PARTITION_ENTRIES {
        return Err(ParseError::CountTooLarge {
            count,
            limit: MAX_PARTITION_ENTRIES,
        });
    }
    let gpt = if style == l.style_gpt {
        Some(GptLayoutHeader {
            disk_id: guid_at(buf, l.gpt_disk_id)?,
            starting_usable_offset: nonneg_i64_at(buf, l.gpt_starting_usable)?,
            usable_length: nonneg_i64_at(buf, l.gpt_usable_length)?,
            max_partition_count: u32_at(buf, l.gpt_max_partition_count)?,
        })
    } else {
        None
    };
    let mbr_signature = if style == l.style_mbr {
        Some(u32_at(buf, l.mbr_signature)?)
    } else {
        None
    };
    let mut partitions = Vec::with_capacity(usize::try_from(count).unwrap_or(0).min(256));
    for i in 0..count {
        let base = element_offset(l.entries, l.entry_stride, i)?;
        let end = base
            .checked_add(l.entry_stride)
            .ok_or(ParseError::OutOfBounds {
                offset: base,
                len: l.entry_stride,
                available: buf.len(),
            })?;
        let e = buf.get(base..end).ok_or(ParseError::OutOfBounds {
            offset: base,
            len: l.entry_stride,
            available: buf.len(),
        })?;
        partitions.push(partition_entry(e, l)?);
    }
    Ok(RawDriveLayout {
        style,
        gpt,
        mbr_signature,
        partitions,
    })
}

fn partition_entry(e: &[u8], l: &DriveLayoutLayout) -> Result<RawPartition> {
    let el = &l.entry;
    let style = i32_at(e, el.style)?;
    let kind = if style == l.style_gpt {
        RawPartitionKind::Gpt {
            type_guid: guid_at(e, el.gpt_type)?,
            id: guid_at(e, el.gpt_id)?,
            attributes: u64_at(e, el.gpt_attributes)?,
            name: utf16_field(e, el.gpt_name, el.gpt_name_units)?,
        }
    } else if style == l.style_mbr {
        RawPartitionKind::Mbr {
            partition_type: u8_at(e, el.mbr_type)?,
            boot_indicator: u8_at(e, el.mbr_boot_indicator)? != 0,
        }
    } else {
        RawPartitionKind::Other
    };
    Ok(RawPartition {
        style,
        starting_offset: nonneg_i64_at(e, el.starting_offset)?,
        length: nonneg_i64_at(e, el.length)?,
        number: u32_at(e, el.number)?,
        kind,
    })
}

/// Reads a fixed UTF-16 field of `units` code units, up to the first NUL.
/// Used for display only, so unpaired surrogates become U+FFFD.
fn utf16_field(e: &[u8], offset: usize, units: usize) -> Result<String> {
    let len = units.checked_mul(2).ok_or(ParseError::OutOfBounds {
        offset,
        len: usize::MAX,
        available: e.len(),
    })?;
    let oob = ParseError::OutOfBounds {
        offset,
        len,
        available: e.len(),
    };
    let end = offset.checked_add(len).ok_or(oob)?;
    let raw = e.get(offset..end).ok_or(oob)?;
    let code_units = raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .take_while(|&u| u != 0);
    Ok(char::decode_utf16(code_units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect())
}

// ---------------------------------------------------------------------------
// Volume disk extents (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS), spec §8
// ---------------------------------------------------------------------------

/// Field offsets of `VOLUME_DISK_EXTENTS` and `DISK_EXTENT`.
#[derive(Debug, Clone, Copy)]
pub struct ExtentsLayout {
    /// Offset of `NumberOfDiskExtents`.
    pub count: usize,
    /// Offset of the first extent.
    pub entries: usize,
    /// Size of one extent.
    pub stride: usize,
    /// Offset of `DiskNumber` in an extent.
    pub disk_number: usize,
    /// Offset of `StartingOffset` in an extent.
    pub starting_offset: usize,
    /// Offset of `ExtentLength` in an extent.
    pub length: usize,
}

/// One extent of a volume (spec §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskExtent {
    /// Disk number (the `N` of `PhysicalDriveN`).
    pub disk_number: u32,
    /// Byte offset from the start of the disk.
    pub starting_offset: u64,
    /// Length in bytes.
    pub length: u64,
}

/// The extent count alone, read from a partial (`ERROR_MORE_DATA`) result.
pub fn extent_count(buf: &[u8], l: &ExtentsLayout) -> Result<u32> {
    let count = u32_at(buf, l.count)?;
    if count > MAX_VOLUME_EXTENTS {
        return Err(ParseError::CountTooLarge {
            count,
            limit: MAX_VOLUME_EXTENTS,
        });
    }
    Ok(count)
}

/// Bytes needed for `count` extents.
pub fn extents_len(l: &ExtentsLayout, count: u32) -> Result<usize> {
    element_offset(l.entries, l.stride, count)
}

/// Parses `VOLUME_DISK_EXTENTS` (spec §8).
pub fn disk_extents(buf: &[u8], l: &ExtentsLayout) -> Result<Vec<DiskExtent>> {
    let count = extent_count(buf, l)?;
    let mut out = Vec::with_capacity(usize::try_from(count).unwrap_or(0));
    for i in 0..count {
        let base = element_offset(l.entries, l.stride, i)?;
        let disk_number = u32_at(
            buf,
            base.checked_add(l.disk_number)
                .ok_or(ParseError::Negative)?,
        )?;
        let starting_offset = nonneg_i64_at(
            buf,
            base.checked_add(l.starting_offset)
                .ok_or(ParseError::Negative)?,
        )?;
        let length = nonneg_i64_at(buf, base.checked_add(l.length).ok_or(ParseError::Negative)?)?;
        out.push(DiskExtent {
            disk_number,
            starting_offset,
            length,
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Wide strings
// ---------------------------------------------------------------------------

/// Encodes `s` as NUL-terminated UTF-16. Refuses an interior NUL, which
/// would silently cut the string short at the API boundary.
pub fn to_wide_nul(s: &str) -> Option<Vec<u16>> {
    if s.contains('\0') {
        return None;
    }
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    Some(v)
}

/// Decodes UTF-16 up to the first NUL (or the end). Invalid UTF-16 is an
/// error: these strings are used as paths and must round-trip exactly.
pub fn from_wide(units: &[u16]) -> Result<String> {
    let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
    let s = units.get(..end).ok_or(ParseError::Unterminated)?;
    String::from_utf16(s).map_err(|_| ParseError::InvalidUtf16)
}

/// Splits a double-NUL-terminated list of strings (`REG_MULTI_SZ` form,
/// returned by `GetVolumePathNamesForVolumeNameW`). The list must end with
/// an empty string inside `units`.
pub fn split_multi_sz(units: &[u16]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut rest = units;
    loop {
        let nul = rest
            .iter()
            .position(|&u| u == 0)
            .ok_or(ParseError::Unterminated)?;
        if nul == 0 {
            return Ok(out);
        }
        let s = rest.get(..nul).ok_or(ParseError::Unterminated)?;
        out.push(String::from_utf16(s).map_err(|_| ParseError::InvalidUtf16)?);
        rest = rest.get(nul + 1..).ok_or(ParseError::Unterminated)?;
    }
}

// ---------------------------------------------------------------------------
// Self-relative security descriptors (bounds only)
// ---------------------------------------------------------------------------

/// Field offsets and constants for checking a self-relative security
/// descriptor, all from windows-sys (`SECURITY_DESCRIPTOR_RELATIVE`, `SID`,
/// `ACL`, `ACE_HEADER` and the control and revision constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityDescriptorLayout {
    /// Offset of `Revision`.
    pub revision: usize,
    /// Offset of `Control`.
    pub control: usize,
    /// Offset of `Owner`.
    pub owner: usize,
    /// Offset of `Group`.
    pub group: usize,
    /// Offset of `Sacl`.
    pub sacl: usize,
    /// Offset of `Dacl`.
    pub dacl: usize,
    /// Size of the fixed header.
    pub fixed_len: usize,
    /// `SECURITY_DESCRIPTOR_REVISION`.
    pub sd_revision: u8,
    /// `SE_SELF_RELATIVE`.
    pub self_relative: u16,
    /// `SE_SACL_PRESENT`.
    pub sacl_present: u16,
    /// `SE_DACL_PRESENT`.
    pub dacl_present: u16,
    /// Offset of `SID.Revision`.
    pub sid_revision_field: usize,
    /// `SID_REVISION`.
    pub sid_revision: u8,
    /// Offset of `SID.SubAuthorityCount`.
    pub sid_count: usize,
    /// `SID_MAX_SUB_AUTHORITIES`.
    pub sid_max_sub_authorities: u8,
    /// Offset of `SID.SubAuthority` (the first of `count` u32 values).
    pub sid_sub_authority: usize,
    /// Offset of `ACL.AclSize`.
    pub acl_size: usize,
    /// Offset of `ACL.AceCount`.
    pub acl_ace_count: usize,
    /// Size of the `ACL` header.
    pub acl_fixed_len: usize,
    /// Offset of `ACE_HEADER.AceSize`.
    pub ace_size: usize,
    /// Size of `ACE_HEADER`.
    pub ace_header_len: usize,
}

/// Largest descriptor accepted (bytes).
pub const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;

/// What a checked descriptor holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescriptorParts {
    /// An owner SID is present.
    pub owner: bool,
    /// A group SID is present.
    pub group: bool,
    /// The DACL-present flag is set.
    pub dacl: bool,
    /// The SACL-present flag is set.
    pub sacl: bool,
    /// The DACL-present flag is set with offset 0: a null DACL, which
    /// allows all access (topic 24 §10, topic 23 §20).
    pub null_dacl: bool,
    /// The `Control` word, as stored.
    pub control: u16,
}

/// Checks that `sd` is a well-formed self-relative descriptor by topic 24
/// §7 to §9 (`specs/standards/reparse-and-security-descriptors.md`):
/// at least the fixed part, revision 1, the self-relative flag set, each
/// non-zero offset at least the fixed size, SACL and DACL offsets in
/// agreement with their present flags (a present flag with offset zero is
/// a null list), every SID well formed (revision 1, at most 15
/// sub-authorities) and every ACL well formed (`AclSize` at least the
/// header, a multiple of 4, its `AceCount` ACEs each at least a header,
/// a multiple of 4, inside `AclSize`), and no part past the end. This
/// bounds every read Windows makes of the buffer; Windows' own validity
/// check runs afterwards.
pub fn check_security_descriptor(
    sd: &[u8],
    l: &SecurityDescriptorLayout,
) -> Result<DescriptorParts> {
    if sd.len() > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(ParseError::SizeExceedsBuffer {
            reported: u64::try_from(sd.len()).unwrap_or(u64::MAX),
            available: MAX_SECURITY_DESCRIPTOR_BYTES,
        });
    }
    if sd.len() < l.fixed_len {
        return Err(ParseError::SizeTooSmall {
            reported: u64::try_from(sd.len()).unwrap_or(u64::MAX),
            fixed: l.fixed_len,
        });
    }
    if u8_at(sd, l.revision)? != l.sd_revision {
        return Err(ParseError::Malformed("descriptor revision"));
    }
    let control = bytes_at::<2>(sd, l.control).map(u16::from_le_bytes)?;
    if control & l.self_relative == 0 {
        return Err(ParseError::Malformed("descriptor not self-relative"));
    }
    let offset = |field: usize| -> Result<usize> {
        let off = usize::try_from(u32_at(sd, field)?).map_err(|_| ParseError::Negative)?;
        if off != 0 && off < l.fixed_len {
            return Err(ParseError::Malformed("descriptor offset inside the header"));
        }
        Ok(off)
    };
    let owner = offset(l.owner)?;
    let group = offset(l.group)?;
    let sacl = offset(l.sacl)?;
    let dacl = offset(l.dacl)?;
    for off in [owner, group] {
        if off != 0 {
            check_sid(sd, off, l)?;
        }
    }
    let sacl_flag = control & l.sacl_present != 0;
    let dacl_flag = control & l.dacl_present != 0;
    for (off, flag) in [(sacl, sacl_flag), (dacl, dacl_flag)] {
        if off != 0 && !flag {
            return Err(ParseError::Malformed(
                "list offset without its present flag",
            ));
        }
        if off != 0 {
            check_acl(sd, off, l)?;
        }
    }
    Ok(DescriptorParts {
        owner: owner != 0,
        group: group != 0,
        dacl: dacl_flag,
        sacl: sacl_flag,
        null_dacl: dacl_flag && dacl == 0,
        control,
    })
}

fn check_sid(sd: &[u8], off: usize, l: &SecurityDescriptorLayout) -> Result<()> {
    let at = |rel: usize| off.checked_add(rel).ok_or(ParseError::Negative);
    if u8_at(sd, at(l.sid_revision_field)?)? != l.sid_revision {
        return Err(ParseError::Malformed("SID revision"));
    }
    let count = u8_at(sd, at(l.sid_count)?)?;
    if count > l.sid_max_sub_authorities {
        return Err(ParseError::Malformed("SID sub-authority count"));
    }
    let len = usize::from(count)
        .checked_mul(4)
        .and_then(|n| n.checked_add(l.sid_sub_authority))
        .ok_or(ParseError::Negative)?;
    within(sd, off, len)
}

fn check_acl(sd: &[u8], off: usize, l: &SecurityDescriptorLayout) -> Result<()> {
    within(sd, off, l.acl_fixed_len)?;
    let at = |rel: usize| off.checked_add(rel).ok_or(ParseError::Negative);
    let size = usize::from(bytes_at::<2>(sd, at(l.acl_size)?).map(u16::from_le_bytes)?);
    if size < l.acl_fixed_len || !size.is_multiple_of(4) {
        return Err(ParseError::Malformed("ACL size"));
    }
    within(sd, off, size)?;
    let count = bytes_at::<2>(sd, at(l.acl_ace_count)?).map(u16::from_le_bytes)?;
    let mut pos = l.acl_fixed_len;
    for _ in 0..count {
        if pos.checked_add(l.ace_header_len).is_none_or(|e| e > size) {
            return Err(ParseError::Malformed("ACE past the ACL"));
        }
        let ace = usize::from(
            bytes_at::<2>(
                sd,
                at(pos.checked_add(l.ace_size).ok_or(ParseError::Negative)?)?,
            )
            .map(u16::from_le_bytes)?,
        );
        if ace < l.ace_header_len || !ace.is_multiple_of(4) {
            return Err(ParseError::Malformed("ACE size"));
        }
        pos = pos.checked_add(ace).ok_or(ParseError::Negative)?;
        if pos > size {
            return Err(ParseError::Malformed("ACE past the ACL"));
        }
    }
    Ok(())
}

fn within(buf: &[u8], off: usize, len: usize) -> Result<()> {
    let oob = ParseError::OutOfBounds {
        offset: off,
        len,
        available: buf.len(),
    };
    match off.checked_add(len) {
        Some(end) if end <= buf.len() => Ok(()),
        _ => Err(oob),
    }
}

// ---------------------------------------------------------------------------
// Reparse buffers: structural check (topic 24 §2 to §5)
// ---------------------------------------------------------------------------

/// Offsets of `REPARSE_DATA_BUFFER` and its symbolic-link and mount-point
/// members, and the two tag values, from windows-sys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReparseLayout {
    /// Offset of `ReparseTag`.
    pub tag: usize,
    /// Offset of `ReparseDataLength`.
    pub data_length: usize,
    /// Offset of `Reserved`.
    pub reserved: usize,
    /// Offset of the data (the union).
    pub data: usize,
    /// Name fields of the symbolic-link member, within the data.
    pub symlink: NameFields,
    /// Offset of the symbolic-link `Flags` within the data.
    pub symlink_flags: usize,
    /// Name fields of the mount-point member, within the data.
    pub mount_point: NameFields,
    /// `IO_REPARSE_TAG_SYMLINK`.
    pub symlink_tag: u32,
    /// `IO_REPARSE_TAG_MOUNT_POINT`.
    pub mount_point_tag: u32,
    /// `SYMLINK_FLAG_RELATIVE`.
    pub relative_flag: u32,
}

/// Offsets of the four name fields and the path buffer of one member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameFields {
    /// `SubstituteNameOffset`.
    pub sub_offset: usize,
    /// `SubstituteNameLength`.
    pub sub_length: usize,
    /// `PrintNameOffset`.
    pub print_offset: usize,
    /// `PrintNameLength`.
    pub print_length: usize,
    /// `PathBuffer`.
    pub path_buffer: usize,
}

/// Longest pathname, in characters (topic 24 §5).
pub const MAX_PATHNAME_CHARS: usize = 32_760;

/// The kind of a structurally checked reparse buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReparseKind {
    /// Symbolic link (topic 24 §4).
    Symlink,
    /// Mount point / junction (topic 24 §3).
    MountPoint,
}

/// Why a reparse buffer was refused by the structural check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReparseRefusal {
    /// The tag is neither the symbolic-link nor the mount-point tag.
    UnsupportedTag,
    /// The buffer breaks topic 24 §2 to §5's bounds.
    Malformed(ParseError),
}

impl core::fmt::Display for ReparseRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedTag => {
                f.write_str("reparse tag is not a symbolic link or mount point")
            }
            Self::Malformed(e) => write!(f, "malformed reparse buffer: {e}"),
        }
    }
}

impl std::error::Error for ReparseRefusal {}

impl From<ParseError> for ReparseRefusal {
    fn from(e: ParseError) -> Self {
        Self::Malformed(e)
    }
}

fn u16_at(buf: &[u8], offset: usize) -> Result<u16> {
    bytes_at::<2>(buf, offset).map(u16::from_le_bytes)
}

/// Checks one name of a path buffer (§5): even offset and length, inside
/// the buffer, at most [`MAX_PATHNAME_CHARS`].
fn check_path_name(path: &[u8], off: u16, len: u16) -> Result<()> {
    let (off, len) = (usize::from(off), usize::from(len));
    if !off.is_multiple_of(2) || !len.is_multiple_of(2) || len / 2 > MAX_PATHNAME_CHARS {
        return Err(ParseError::Malformed("path name offset or length"));
    }
    within(path, off, len)
}

/// Structural check of a complete `REPARSE_DATA_BUFFER` before it is
/// passed to Windows (topic 24 §2 to §5). `usgp-image` has already
/// validated the content and decided which targets are applied
/// (decision 0022); this check only bounds what Windows will read:
///
/// - at least the 8-byte header, at most header + 65 535 bytes;
/// - `ReparseDataLength` equal to the data actually present, `Reserved`
///   zero;
/// - the tag is the symbolic-link or the mount-point tag;
/// - the fixed fields of that member fit, both names lie inside the path
///   buffer at even offsets and lengths, each at most 32 760 characters;
/// - a symbolic link's `Flags` is 0 or `SYMLINK_FLAG_RELATIVE`.
pub fn check_reparse_buffer(
    buf: &[u8],
    l: &ReparseLayout,
) -> core::result::Result<ReparseKind, ReparseRefusal> {
    let data = buf.get(l.data..).ok_or(ParseError::SizeTooSmall {
        reported: u64::try_from(buf.len()).unwrap_or(0),
        fixed: l.data,
    })?;
    let declared = usize::from(u16_at(buf, l.data_length)?);
    if declared != data.len() {
        return Err(ParseError::Malformed("reparse data length").into());
    }
    if u16_at(buf, l.reserved)? != 0 {
        return Err(ParseError::Malformed("reparse reserved field").into());
    }
    let tag = u32_at(buf, l.tag)?;
    let (kind, fields) = if tag == l.symlink_tag {
        (ReparseKind::Symlink, &l.symlink)
    } else if tag == l.mount_point_tag {
        (ReparseKind::MountPoint, &l.mount_point)
    } else {
        return Err(ReparseRefusal::UnsupportedTag);
    };
    if data.len() < fields.path_buffer {
        return Err(ParseError::SizeTooSmall {
            reported: u64::try_from(data.len()).unwrap_or(0),
            fixed: fields.path_buffer,
        }
        .into());
    }
    if kind == ReparseKind::Symlink {
        let flags = u32_at(data, l.symlink_flags)?;
        if flags != 0 && flags != l.relative_flag {
            return Err(ParseError::Malformed("symbolic link flags").into());
        }
    }
    let path = data.get(fields.path_buffer..).unwrap_or(&[]);
    check_path_name(
        path,
        u16_at(data, fields.sub_offset)?,
        u16_at(data, fields.sub_length)?,
    )?;
    check_path_name(
        path,
        u16_at(data, fields.print_offset)?,
        u16_at(data, fields.print_length)?,
    )?;
    Ok(kind)
}

/// Synthetic layouts for exercising [`check_security_descriptor`] and
/// [`check_reparse_buffer`] off Windows: the unit tests here and the
/// `winapi_sd` and `winapi_reparse` fuzz targets (SEC-004). Test and fuzz
/// use only (feature `parse-testkit`); production code always passes the
/// windows-sys layouts of `crate::layout` (OPEN-WAPI-1).
///
/// On Windows, `layout.rs`'s tests assert that these equal the
/// windows-sys values, so what is fuzzed is the shape the agent checks.
#[cfg(any(test, feature = "parse-testkit"))]
pub mod testkit {
    use super::{NameFields, ReparseLayout, SecurityDescriptorLayout};

    /// `SECURITY_DESCRIPTOR_RELATIVE`, `SID`, `ACL` and `ACE_HEADER`
    /// offsets and constants, as in `crate::layout::SECURITY_DESCRIPTOR`.
    pub const SECURITY_DESCRIPTOR: SecurityDescriptorLayout = SecurityDescriptorLayout {
        revision: 0,
        control: 2,
        owner: 4,
        group: 8,
        sacl: 12,
        dacl: 16,
        fixed_len: 20,
        sd_revision: 1,
        self_relative: 0x8000,
        sacl_present: 0x0010,
        dacl_present: 0x0004,
        sid_revision_field: 0,
        sid_revision: 1,
        sid_count: 1,
        sid_max_sub_authorities: 15,
        sid_sub_authority: 8,
        acl_size: 2,
        acl_ace_count: 4,
        acl_fixed_len: 8,
        ace_size: 2,
        ace_header_len: 4,
    };

    /// `REPARSE_DATA_BUFFER` offsets and tags, as in
    /// `crate::layout::REPARSE`.
    pub const REPARSE: ReparseLayout = ReparseLayout {
        tag: 0,
        data_length: 4,
        reserved: 6,
        data: 8,
        symlink: NameFields {
            sub_offset: 0,
            sub_length: 2,
            print_offset: 4,
            print_length: 6,
            path_buffer: 12,
        },
        symlink_flags: 8,
        mount_point: NameFields {
            sub_offset: 0,
            sub_length: 2,
            print_offset: 4,
            print_length: 6,
            path_buffer: 8,
        },
        symlink_tag: 0xA000_000C,
        mount_point_tag: 0xA000_0003,
        relative_flag: 1,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic layouts: the parsers take offsets as data, so their bounds
    // checks are exercised here without the Windows declarations. The real
    // layouts are checked against windows-sys in `crate::layout` tests on
    // the Windows runner.

    const DD: DeviceDescriptorLayout = DeviceDescriptorLayout {
        size: 4,
        device_type: 8,
        removable_media: 10,
        vendor_id_offset: 12,
        product_id_offset: 16,
        product_revision_offset: 20,
        serial_number_offset: 24,
        bus_type: 28,
        fixed_len: 36,
    };

    fn put_u32(b: &mut [u8], off: usize, v: u32) {
        for (slot, byte) in b.iter_mut().skip(off).zip(v.to_le_bytes()) {
            *slot = byte;
        }
    }

    fn put_u64(b: &mut [u8], off: usize, v: u64) {
        for (slot, byte) in b.iter_mut().skip(off).zip(v.to_le_bytes()) {
            *slot = byte;
        }
    }

    fn put_bytes(b: &mut [u8], off: usize, v: &[u8]) {
        for (slot, byte) in b.iter_mut().skip(off).zip(v) {
            *slot = *byte;
        }
    }

    fn descriptor() -> Vec<u8> {
        let mut b = vec![0u8; 64];
        put_u32(&mut b, 4, 64);
        put_bytes(&mut b, 8, &[0]);
        put_bytes(&mut b, 10, &[1]);
        put_u32(&mut b, 12, 40);
        put_u32(&mut b, 16, 48);
        put_u32(&mut b, 28, 7);
        put_bytes(&mut b, 40, b"  ACME \0");
        put_bytes(&mut b, 48, b"DISK\xff1\0");
        b
    }

    #[test]
    fn device_descriptor_reads_fields_and_strings() {
        let d = device_descriptor(&descriptor(), &DD);
        assert_eq!(
            d,
            Ok(RawDeviceDescriptor {
                device_type: 0,
                removable_media: true,
                bus_type: 7,
                vendor_id: Some("ACME".into()),
                product_id: Some("DISK?1".into()),
                product_revision: None,
                serial_number: None,
            })
        );
    }

    #[test]
    fn device_descriptor_any_nonzero_removable_byte_is_removable() {
        let mut b = descriptor();
        put_bytes(&mut b, 10, &[0x80]);
        assert!(device_descriptor(&b, &DD).is_ok_and(|d| d.removable_media));
    }

    #[test]
    fn device_descriptor_rejects_size_beyond_buffer() {
        let mut b = descriptor();
        put_u32(&mut b, 4, 65);
        assert!(matches!(
            device_descriptor(&b, &DD),
            Err(ParseError::SizeExceedsBuffer { .. })
        ));
    }

    #[test]
    fn device_descriptor_rejects_size_below_fixed_part() {
        let mut b = descriptor();
        put_u32(&mut b, 4, 20);
        assert!(matches!(
            device_descriptor(&b, &DD),
            Err(ParseError::SizeTooSmall { .. })
        ));
    }

    #[test]
    fn device_descriptor_rejects_string_outside_size_or_unterminated() {
        let mut b = descriptor();
        put_u32(&mut b, 20, 64);
        assert!(device_descriptor(&b, &DD).is_err());
        let mut b = descriptor();
        // The descriptor claims 44 bytes; the vendor string at 40 has no
        // NUL before byte 44.
        put_u32(&mut b, 4, 44);
        put_u32(&mut b, 16, 0);
        assert_eq!(device_descriptor(&b, &DD), Err(ParseError::Unterminated));
    }

    #[test]
    fn id_string_is_length_limited() {
        let mut b = vec![b'A'; 600];
        put_bytes(&mut b, 0, &[0; 8]);
        put_bytes(&mut b, 599, &[0]);
        assert_eq!(id_string(&b, 8), Err(ParseError::Unterminated));
        put_bytes(&mut b, 8 + MAX_ID_STRING, &[0]);
        assert!(id_string(&b, 8).is_ok_and(|s| s.is_some_and(|s| s.len() == MAX_ID_STRING)));
    }

    #[test]
    fn short_buffers_never_panic() {
        // Every prefix of a valid descriptor, and every parser on short or
        // empty input, returns an error or a value; none panics.
        let full = descriptor();
        for n in 0..full.len() {
            let _ = device_descriptor(full.get(..n).unwrap_or(&[]), &DD);
        }
        let empty: &[u8] = &[];
        assert!(geometry(empty, &GEO).is_err());
        assert!(drive_layout(empty, &DL).is_err());
        assert!(disk_extents(empty, &EXT).is_err());
        assert!(
            device_number(
                empty,
                &DeviceNumberLayout {
                    device_type: 0,
                    device_number: 4,
                    partition_number: 8
                }
            )
            .is_err()
        );
    }

    #[test]
    fn arbitrary_bytes_never_panic() {
        // Deterministic xorshift stream; no extra dependency.
        let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for round in 0..2000u32 {
            let len = usize::try_from(next() % 300).unwrap_or(0);
            let mut b: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            // Keep counts small in half the rounds so the loops run.
            if round % 2 == 0 && b.len() > 8 {
                put_u32(&mut b, 4, u32::try_from(next() % 5).unwrap_or(0));
                put_u32(&mut b, 0, u32::try_from(next() % 3).unwrap_or(0));
            }
            let _ = device_descriptor(&b, &DD);
            let _ = geometry(&b, &GEO);
            let _ = drive_layout(&b, &DL);
            let _ = disk_extents(&b, &EXT);
            let _ = access_alignment(&b, &AL);
            let units: Vec<u16> = b
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&pair| u16::from_le_bytes(pair))
                .collect();
            let _ = split_multi_sz(&units);
            let _ = from_wide(&units);
        }
    }

    const AL: AlignmentLayout = AlignmentLayout {
        size: 4,
        logical: 16,
        physical: 20,
        fixed_len: 28,
    };

    #[test]
    fn access_alignment_reads_sector_sizes() {
        let mut b = vec![0u8; 28];
        put_u32(&mut b, 4, 28);
        put_u32(&mut b, 16, 512);
        put_u32(&mut b, 20, 4096);
        assert_eq!(
            access_alignment(&b, &AL),
            Ok(SectorSizes {
                logical: 512,
                physical: 4096
            })
        );
        put_u32(&mut b, 4, 12);
        assert!(access_alignment(&b, &AL).is_err());
    }

    const GEO: GeometryLayout = GeometryLayout {
        media_type: 8,
        bytes_per_sector: 20,
        disk_size: 24,
    };

    #[test]
    fn geometry_rejects_negative_size() {
        let mut b = vec![0u8; 40];
        put_u32(&mut b, 8, 12);
        put_u32(&mut b, 20, 512);
        put_u64(&mut b, 24, 1 << 30);
        assert_eq!(
            geometry(&b, &GEO),
            Ok(RawGeometry {
                media_type: 12,
                bytes_per_sector: 512,
                disk_size: 1 << 30
            })
        );
        put_u64(&mut b, 24, u64::MAX);
        assert_eq!(geometry(&b, &GEO), Err(ParseError::Negative));
    }

    const DL: DriveLayoutLayout = DriveLayoutLayout {
        style: 0,
        count: 4,
        gpt_disk_id: 8,
        gpt_starting_usable: 24,
        gpt_usable_length: 32,
        gpt_max_partition_count: 40,
        mbr_signature: 8,
        entries: 48,
        entry_stride: 144,
        entry: PartitionEntryLayout {
            style: 0,
            starting_offset: 8,
            length: 16,
            number: 24,
            gpt_type: 32,
            gpt_id: 48,
            gpt_attributes: 64,
            gpt_name: 72,
            gpt_name_units: 36,
            mbr_type: 32,
            mbr_boot_indicator: 33,
        },
        style_gpt: 1,
        style_mbr: 0,
    };

    fn gpt_layout(count: u32) -> Vec<u8> {
        let mut b = vec![0u8; 48 + 144 * 2];
        put_u32(&mut b, 0, 1);
        put_u32(&mut b, 4, count);
        put_bytes(
            &mut b,
            8,
            &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        );
        put_u64(&mut b, 24, 17_408);
        put_u64(&mut b, 32, 1 << 30);
        put_u32(&mut b, 40, 128);
        // Entry 0: GPT, 1 MiB at 1 MiB, number 1, name "EFI".
        put_u32(&mut b, 48, 1);
        put_u64(&mut b, 56, 1 << 20);
        put_u64(&mut b, 64, 1 << 20);
        put_u32(&mut b, 72, 1);
        put_u64(&mut b, 48 + 64, 0x8000_0000_0000_0001);
        put_bytes(&mut b, 48 + 72, &[b'E', 0, b'F', 0, b'I', 0]);
        // Entry 1: unknown style 9.
        put_u32(&mut b, 192, 9);
        put_u32(&mut b, 192 + 24, 2);
        b
    }

    #[test]
    fn drive_layout_parses_gpt_header_and_entries() {
        let l = drive_layout(&gpt_layout(2), &DL);
        let Ok(l) = l else {
            panic!("parse failed: {l:?}");
        };
        assert_eq!(l.style, 1);
        assert_eq!(
            l.gpt.map(|g| g.disk_id.to_braced_upper()),
            Some("{04030201-0605-0807-090A-0B0C0D0E0F10}".to_owned())
        );
        assert_eq!(l.gpt.map(|g| g.max_partition_count), Some(128));
        assert_eq!(l.mbr_signature, None);
        assert_eq!(l.partitions.len(), 2);
        let p0 = l.partitions.first();
        assert_eq!(
            p0.map(|p| (p.starting_offset, p.length, p.number)),
            Some((1 << 20, 1 << 20, 1))
        );
        assert!(matches!(
            p0.map(|p| &p.kind),
            Some(RawPartitionKind::Gpt { attributes: 0x8000_0000_0000_0001, name, .. }) if name == "EFI"
        ));
        assert!(matches!(
            l.partitions.get(1).map(|p| &p.kind),
            Some(RawPartitionKind::Other)
        ));
    }

    #[test]
    fn drive_layout_rejects_count_past_buffer_or_limit() {
        assert!(matches!(
            drive_layout(&gpt_layout(3), &DL),
            Err(ParseError::OutOfBounds { .. })
        ));
        assert!(matches!(
            drive_layout(&gpt_layout(MAX_PARTITION_ENTRIES + 1), &DL),
            Err(ParseError::CountTooLarge { .. })
        ));
        assert!(matches!(
            drive_layout(&gpt_layout(u32::MAX), &DL),
            Err(ParseError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn drive_layout_rejects_negative_offsets() {
        let mut b = gpt_layout(1);
        put_u64(&mut b, 56, u64::MAX);
        assert_eq!(drive_layout(&b, &DL), Err(ParseError::Negative));
    }

    const EXT: ExtentsLayout = ExtentsLayout {
        count: 0,
        entries: 8,
        stride: 24,
        disk_number: 0,
        starting_offset: 8,
        length: 16,
    };

    #[test]
    fn extents_parse_and_bounds() {
        let mut b = vec![0u8; 8 + 24 * 2];
        put_u32(&mut b, 0, 2);
        put_u32(&mut b, 8, 3);
        put_u64(&mut b, 16, 1 << 20);
        put_u64(&mut b, 24, 100 << 20);
        put_u32(&mut b, 32, 4);
        put_u64(&mut b, 40, 2 << 20);
        put_u64(&mut b, 48, 1 << 20);
        assert_eq!(
            disk_extents(&b, &EXT),
            Ok(vec![
                DiskExtent {
                    disk_number: 3,
                    starting_offset: 1 << 20,
                    length: 100 << 20
                },
                DiskExtent {
                    disk_number: 4,
                    starting_offset: 2 << 20,
                    length: 1 << 20
                },
            ])
        );
        assert_eq!(extents_len(&EXT, 2), Ok(56));
        put_u32(&mut b, 0, 3);
        assert!(matches!(
            disk_extents(&b, &EXT),
            Err(ParseError::OutOfBounds { .. })
        ));
        put_u32(&mut b, 0, MAX_VOLUME_EXTENTS + 1);
        assert!(matches!(
            extent_count(&b, &EXT),
            Err(ParseError::CountTooLarge { .. })
        ));
    }

    #[test]
    fn guid_round_trips_and_formats() {
        let bytes = [
            0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03,
            0x2B, 0x8C,
        ];
        let g = Guid::from_le_bytes(bytes);
        assert_eq!(g.to_le_bytes(), bytes);
        // The EFI global variable GUID (uefi-boot-manager.md §10.3).
        assert_eq!(
            g.to_braced_upper(),
            "{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}"
        );
    }

    #[test]
    fn wide_strings() {
        assert_eq!(to_wide_nul("C:\\"), Some(vec![67, 58, 92, 0]));
        assert_eq!(to_wide_nul("a\0b"), None);
        assert_eq!(from_wide(&[72, 105, 0, 33]), Ok("Hi".to_owned()));
        assert_eq!(from_wide(&[0xD800, 0]), Err(ParseError::InvalidUtf16));
        assert_eq!(
            split_multi_sz(&[67, 58, 92, 0, 68, 58, 92, 0, 0]),
            Ok(vec!["C:\\".to_owned(), "D:\\".to_owned()])
        );
        assert_eq!(split_multi_sz(&[0]), Ok(vec![]));
        assert_eq!(split_multi_sz(&[67, 0]), Err(ParseError::Unterminated));
        assert_eq!(split_multi_sz(&[]), Err(ParseError::Unterminated));
    }

    const SDL: SecurityDescriptorLayout = testkit::SECURITY_DESCRIPTOR;

    /// Header; owner SID (1 sub-authority, 12 bytes) at 20; DACL at 32
    /// with one 16-byte ACE (size 24).
    fn sd() -> Vec<u8> {
        let mut b = vec![0u8; 56];
        put_bytes(&mut b, 0, &[1, 0, 0x04, 0x80]);
        put_u32(&mut b, 4, 20);
        put_u32(&mut b, 16, 32);
        put_bytes(&mut b, 20, &[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        put_bytes(&mut b, 32, &[2, 0, 24, 0, 1, 0, 0, 0]);
        put_bytes(&mut b, 40, &[0, 0, 16, 0]);
        b
    }

    #[test]
    fn security_descriptor_rules() {
        assert_eq!(
            check_security_descriptor(&sd(), &SDL),
            Ok(DescriptorParts {
                owner: true,
                group: false,
                dacl: true,
                sacl: false,
                null_dacl: false,
                control: 0x8004,
            })
        );
        let bad = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = sd();
            f(&mut b);
            check_security_descriptor(&b, &SDL).is_err()
        };
        assert!(bad(&|b| put_bytes(b, 0, &[2])), "revision");
        assert!(bad(&|b| put_bytes(b, 3, &[0])), "not self-relative");
        assert!(bad(&|b| put_bytes(b, 2, &[0])), "DACL offset without DP");
        assert!(bad(&|b| put_u32(b, 4, 8)), "offset inside the header");
        assert!(bad(&|b| put_bytes(b, 20, &[2])), "SID revision");
        assert!(
            bad(&|b| put_bytes(b, 21, &[16])),
            "too many sub-authorities"
        );
        assert!(bad(&|b| put_bytes(b, 21, &[15])), "SID past the end");
        assert!(
            bad(&|b| put_bytes(b, 34, &[26, 0])),
            "ACL size not a multiple of 4"
        );
        assert!(bad(&|b| put_bytes(b, 34, &[28, 0])), "ACL past the end");
        assert!(bad(&|b| put_bytes(b, 34, &[4, 0])), "ACL below its header");
        assert!(
            bad(&|b| put_bytes(b, 42, &[18, 0])),
            "ACE size not a multiple of 4"
        );
        assert!(bad(&|b| put_bytes(b, 42, &[20, 0])), "ACE past the ACL");
        assert!(bad(&|b| put_bytes(b, 36, &[2, 0])), "second ACE missing");
        assert!(bad(&|b| put_u32(b, 8, 0xFFFF_FFF0)), "offset past the end");
        // A SACL-present flag with a zero offset is a null SACL: allowed.
        let mut b = sd();
        put_bytes(&mut b, 2, &[0x14, 0x80]);
        assert!(check_security_descriptor(&b, &SDL).is_ok_and(|p| p.sacl));
        assert!(check_security_descriptor(&[], &SDL).is_err());
        assert!(
            check_security_descriptor(&vec![0u8; MAX_SECURITY_DESCRIPTOR_BYTES + 1], &SDL).is_err()
        );
        let full = sd();
        for n in 0..full.len() {
            let _ = check_security_descriptor(full.get(..n).unwrap_or(&[]), &SDL);
        }
    }

    const RL: ReparseLayout = testkit::REPARSE;

    /// A complete buffer: header, name fields, optional flags, names.
    fn reparse(tag: u32, sub: &str, print: &str, flags: Option<u32>) -> Vec<u8> {
        let s: Vec<u8> = sub.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let p: Vec<u8> = print.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let sl = u16::try_from(s.len()).unwrap_or(0);
        let pl = u16::try_from(p.len()).unwrap_or(0);
        let mut d = Vec::new();
        d.extend(0u16.to_le_bytes());
        d.extend(sl.to_le_bytes());
        d.extend(sl.to_le_bytes());
        d.extend(pl.to_le_bytes());
        if let Some(f) = flags {
            d.extend(f.to_le_bytes());
        }
        d.extend(s);
        d.extend(p);
        let mut b = Vec::new();
        b.extend(tag.to_le_bytes());
        b.extend(u16::try_from(d.len()).unwrap_or(0).to_le_bytes());
        b.extend([0u8, 0]);
        b.extend(d);
        b
    }

    #[test]
    fn reparse_buffer_structure() {
        let rel = reparse(0xA000_000C, "t.txt", "t.txt", Some(1));
        assert_eq!(check_reparse_buffer(&rel, &RL), Ok(ReparseKind::Symlink));
        let abs = reparse(0xA000_000C, "\\??\\P:\\t.txt", "P:\\t.txt", Some(0));
        assert_eq!(check_reparse_buffer(&abs, &RL), Ok(ReparseKind::Symlink));
        let mp = reparse(0xA000_0003, "\\??\\P:\\d", "P:\\d", None);
        assert_eq!(check_reparse_buffer(&mp, &RL), Ok(ReparseKind::MountPoint));
        assert_eq!(
            check_reparse_buffer(&reparse(0x8000_0017, "a", "a", None), &RL),
            Err(ReparseRefusal::UnsupportedTag)
        );
        let bad = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut b = rel.clone();
            f(&mut b);
            check_reparse_buffer(&b, &RL).is_err()
        };
        assert!(bad(&|b| put_bytes(b, 4, &[1, 0])), "declared length");
        assert!(bad(&|b| put_bytes(b, 6, &[1, 0])), "reserved");
        assert!(bad(&|b| put_u32(b, 16, 2)), "flags");
        assert!(
            bad(&|b| put_bytes(b, 10, &[200, 0])),
            "name past the buffer"
        );
        assert!(bad(&|b| put_bytes(b, 12, &[1, 0])), "odd offset");
        assert!(bad(&|b| b.truncate(14)), "short");
        assert!(check_reparse_buffer(&[], &RL).is_err());
        for n in 0..mp.len() {
            let _ = check_reparse_buffer(mp.get(..n).unwrap_or(&[]), &RL);
        }
        for n in 0..rel.len() {
            let _ = check_reparse_buffer(rel.get(..n).unwrap_or(&[]), &RL);
        }
    }
}
