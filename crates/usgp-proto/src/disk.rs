//! Disk descriptors and layout reports (M3 plan sections 3.1, 3.2 and
//! 3.4).
//!
//! - [`DiskDescriptorV1`]: what the agent tells the server about the disk
//!   the technician chose: a per-enumeration [`DiskToken`], the bus,
//!   model, serial, size, sector sizes, whether it is removable, and its
//!   existing partitions. It carries **no file content** (REQ-DISK-016):
//!   there is no field for it, and unknown fields are refused.
//! - [`PlanDiskV1`]: the disk fields the signed job plan binds
//!   (plan section 3.2), built from a descriptor.
//! - [`LayoutReportV1`]: the partitions the agent wrote, reported with
//!   progress (REQ-DISK-014).
//!
//! Every value is checked when it is parsed: sizes, sector sizes,
//! partition bounds against the disk, list lengths and text.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - closed value sets,
//   bounded text and lists, partitions checked against the disk size.
// - NIST 800-53: AC-4 (Information Flow Enforcement) - no field can carry
//   existing disk contents to the server.
// - SPEC: specs/disk.md#REQ-DISK-001 (size, model, bus, partitions shown),
//   #REQ-DISK-005 (removable and bus reported), #REQ-DISK-006 (existing
//   partitions and labels for the wipe screen), #REQ-DISK-014 (disk choice
//   and layout reported), #REQ-DISK-016 (no file content read out)
// - SPEC: specs/targeting.md#REQ-TGT-005 (disk choice)
// - specs/standards/gpt.md §5 (partition entries and names)

use std::collections::HashSet;
use std::fmt;

use crate::limits::MAX_PARTITIONS;
use crate::names::{DiskText, PartitionLabel};

closed_enum!(
    /// How a disk is attached (plan section 3.1).
    Bus, "bus" {
        /// Serial ATA.
        Sata => "sata",
        /// Parallel ATA.
        Ata => "ata",
        /// Serial attached SCSI.
        Sas => "sas",
        /// SCSI.
        Scsi => "scsi",
        /// NVM Express.
        Nvme => "nvme",
        /// A RAID controller's logical disk.
        Raid => "raid",
        /// USB.
        Usb => "usb",
        /// SD card.
        Sd => "sd",
        /// MMC / eMMC.
        Mmc => "mmc",
        /// A virtual disk (hypervisor or VHD).
        Virtual => "virtual",
        /// A file-backed disk.
        FileBacked => "file_backed",
        /// Anything else.
        Other => "other",
    }
);

closed_enum!(
    /// What an existing or written partition is (plan section 3.1).
    PartitionKind, "partition kind" {
        /// EFI system partition.
        Esp => "esp",
        /// Microsoft reserved partition.
        Msr => "msr",
        /// Basic data partition.
        Basic => "basic",
        /// Windows recovery partition.
        Recovery => "recovery",
        /// Any other GPT partition type.
        Other => "other",
        /// An entry of an MBR partition table.
        MbrEntry => "mbr_entry",
    }
);

closed_enum!(
    /// File system the agent had Windows format on a partition.
    FileSystem, "file system" {
        /// FAT32 (the ESP).
        Fat32 => "fat32",
        /// NTFS (Windows and recovery).
        Ntfs => "ntfs",
    }
);

/// Why a disk descriptor or layout report was refused. Values are never
/// echoed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DiskDataError {
    /// The disk token is not 32 lowercase hex digits.
    #[error("disk_token must be 32 lowercase hex digits")]
    BadToken,
    /// `size_bytes` is 0 or not a multiple of the logical sector size.
    #[error("size_bytes must be a non-zero multiple of logical_sector")]
    BadSize,
    /// `logical_sector` is not 512 or 4096.
    #[error("logical_sector must be 512 or 4096")]
    BadLogicalSector,
    /// `physical_sector` is not a power of two from the logical sector size
    /// to 65536.
    #[error("physical_sector must be a power of two from logical_sector to 65536")]
    BadPhysicalSector,
    /// More than [`MAX_PARTITIONS`] partitions.
    #[error("at most 128 partitions may be listed, got {count}")]
    TooManyPartitions {
        /// Number listed.
        count: usize,
    },
    /// A partition index is 0, above 128, or repeated.
    #[error("partition index must be 1 to 128 and unique")]
    BadPartitionIndex,
    /// A partition is empty or ends past the disk.
    #[error("partition {index} is empty or extends past the end of the disk")]
    PartitionOutOfBounds {
        /// The partition index.
        index: u32,
    },
    /// The disk GUID is not a hyphenated, non-nil GUID.
    #[error("disk_guid must be a hyphenated GUID and not all zero")]
    BadGuid,
}

/// A random token that names one disk in one enumeration on the device
/// (16 bytes, 32 lowercase hex digits on the wire). It is not a secret: it
/// binds the confirm request and the plan to the disk the technician
/// chose.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiskToken([u8; 16]);

impl DiskToken {
    /// A token from 16 bytes the caller drew from the `usgp-crypto` DRBG.
    #[must_use]
    pub const fn from_random_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parses exactly 32 lowercase hex digits.
    ///
    /// # Errors
    ///
    /// [`DiskDataError::BadToken`].
    pub fn parse(text: &str) -> Result<Self, DiskDataError> {
        let b = text.as_bytes();
        if b.len() != 32 {
            return Err(DiskDataError::BadToken);
        }
        let mut out = [0u8; 16];
        let (pairs, _) = b.as_chunks::<2>();
        for (o, [hi, lo]) in out.iter_mut().zip(pairs) {
            let hi = lower_hex(Some(*hi)).ok_or(DiskDataError::BadToken)?;
            let lo = lower_hex(Some(*lo)).ok_or(DiskDataError::BadToken)?;
            *o = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn lower_hex(b: Option<u8>) -> Option<u8> {
    match b? {
        c @ b'0'..=b'9' => Some(c - b'0'),
        c @ b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl fmt::Display for DiskToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for DiskToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiskToken({self})")
    }
}

impl serde::Serialize for DiskToken {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for DiskToken {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = DiskToken;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32 lowercase hex digits")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<DiskToken, E> {
                DiskToken::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// A GPT disk GUID in its text form (hyphenated, RFC 9562 §4 text layout;
/// `specs/standards/gpt.md` §4). The on-disk byte order is `usgp-disk`'s
/// concern; this type carries only the text. The nil GUID is refused.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DiskGuid(uuid::Uuid);

impl DiskGuid {
    /// Parses the 36-character hyphenated form (either case).
    ///
    /// # Errors
    ///
    /// [`DiskDataError::BadGuid`].
    pub fn parse(text: &str) -> Result<Self, DiskDataError> {
        if text.len() != crate::ids::UUID_TEXT_LEN {
            return Err(DiskDataError::BadGuid);
        }
        let u = uuid::Uuid::try_parse(text).map_err(|_| DiskDataError::BadGuid)?;
        if u.is_nil() {
            return Err(DiskDataError::BadGuid);
        }
        Ok(Self(u))
    }

    /// A GUID from its 16 bytes in text order (most significant first).
    ///
    /// # Errors
    ///
    /// [`DiskDataError::BadGuid`] for 16 zero bytes.
    pub fn from_text_order_bytes(bytes: [u8; 16]) -> Result<Self, DiskDataError> {
        let u = uuid::Uuid::from_bytes(bytes);
        if u.is_nil() {
            return Err(DiskDataError::BadGuid);
        }
        Ok(Self(u))
    }

    /// The 16 bytes in text order (most significant first).
    #[must_use]
    pub const fn text_order_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl fmt::Display for DiskGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0.hyphenated(), f)
    }
}

impl fmt::Debug for DiskGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DiskGuid({})", self.0.hyphenated())
    }
}

impl serde::Serialize for DiskGuid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for DiskGuid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;

        impl serde::de::Visitor<'_> for V {
            type Value = DiskGuid;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a hyphenated GUID")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<DiskGuid, E> {
                DiskGuid::parse(v).map_err(E::custom)
            }
        }

        d.deserialize_str(V)
    }
}

/// One existing partition on a disk (plan section 3.1). Only its place,
/// kind and label are described; never its contents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExistingPartitionV1 {
    /// Entry index in the partition table (1 to 128).
    pub index: u32,
    /// Kind.
    pub kind: PartitionKind,
    /// Start offset in bytes.
    pub start_bytes: u64,
    /// Size in bytes (at least 1).
    pub size_bytes: u64,
    /// Label, if the table records one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<PartitionLabel>,
}

/// Checks a partition list against a disk of `disk_bytes` (`None` when the
/// size is not known, as in a layout report).
fn check_partitions<'a>(
    parts: impl ExactSizeIterator<Item = (u32, u64, u64)> + 'a,
    disk_bytes: Option<u64>,
) -> Result<(), DiskDataError> {
    let count = parts.len();
    if count > MAX_PARTITIONS {
        return Err(DiskDataError::TooManyPartitions { count });
    }
    let mut seen = HashSet::with_capacity(count);
    for (index, start, size) in parts {
        if index == 0 || index > 128 || !seen.insert(index) {
            return Err(DiskDataError::BadPartitionIndex);
        }
        let end = start.checked_add(size);
        let fits = match (end, disk_bytes) {
            (None, _) => false,
            (Some(_), _) if size == 0 => false,
            (Some(end), Some(disk)) => end <= disk,
            (Some(_), None) => true,
        };
        if !fits {
            return Err(DiskDataError::PartitionOutOfBounds { index });
        }
    }
    Ok(())
}

fn check_geometry(size: u64, logical: u32, physical: u32) -> Result<(), DiskDataError> {
    if logical != 512 && logical != 4096 {
        return Err(DiskDataError::BadLogicalSector);
    }
    if !physical.is_power_of_two() || physical < logical || physical > 65_536 {
        return Err(DiskDataError::BadPhysicalSector);
    }
    if size == 0 || !size.is_multiple_of(u64::from(logical)) {
        return Err(DiskDataError::BadSize);
    }
    Ok(())
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskDescriptorWire {
    disk_token: DiskToken,
    bus: Bus,
    model: DiskText,
    serial: DiskText,
    size_bytes: u64,
    logical_sector: u32,
    physical_sector: u32,
    removable: bool,
    partitions: Vec<ExistingPartitionV1>,
}

/// The disk the technician chose, as the device describes it (plan
/// section 3.1). Parsing checks every rule; [`DiskDescriptorV1::new`] does
/// the same for values built in code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "DiskDescriptorWire")]
pub struct DiskDescriptorV1 {
    disk_token: DiskToken,
    bus: Bus,
    model: DiskText,
    serial: DiskText,
    size_bytes: u64,
    logical_sector: u32,
    physical_sector: u32,
    removable: bool,
    partitions: Vec<ExistingPartitionV1>,
}

/// The fields of a [`DiskDescriptorV1`], for [`DiskDescriptorV1::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskDescriptorParts {
    /// Token for this enumeration.
    pub disk_token: DiskToken,
    /// Bus.
    pub bus: Bus,
    /// Model, sanitized ([`DiskText::sanitized`]).
    pub model: DiskText,
    /// Serial number, sanitized.
    pub serial: DiskText,
    /// Size in bytes; a non-zero multiple of `logical_sector`.
    pub size_bytes: u64,
    /// 512 or 4096.
    pub logical_sector: u32,
    /// A power of two from `logical_sector` to 65536.
    pub physical_sector: u32,
    /// Whether the device reports removable media.
    pub removable: bool,
    /// Existing partitions (at most 128).
    pub partitions: Vec<ExistingPartitionV1>,
}

impl TryFrom<DiskDescriptorWire> for DiskDescriptorV1 {
    type Error = DiskDataError;

    fn try_from(w: DiskDescriptorWire) -> Result<Self, Self::Error> {
        Self::new(DiskDescriptorParts {
            disk_token: w.disk_token,
            bus: w.bus,
            model: w.model,
            serial: w.serial,
            size_bytes: w.size_bytes,
            logical_sector: w.logical_sector,
            physical_sector: w.physical_sector,
            removable: w.removable,
            partitions: w.partitions,
        })
    }
}

impl DiskDescriptorV1 {
    /// Builds a descriptor after checking every rule.
    ///
    /// # Errors
    ///
    /// [`DiskDataError`] naming the first rule broken.
    pub fn new(p: DiskDescriptorParts) -> Result<Self, DiskDataError> {
        check_geometry(p.size_bytes, p.logical_sector, p.physical_sector)?;
        check_partitions(
            p.partitions
                .iter()
                .map(|x| (x.index, x.start_bytes, x.size_bytes)),
            Some(p.size_bytes),
        )?;
        Ok(Self {
            disk_token: p.disk_token,
            bus: p.bus,
            model: p.model,
            serial: p.serial,
            size_bytes: p.size_bytes,
            logical_sector: p.logical_sector,
            physical_sector: p.physical_sector,
            removable: p.removable,
            partitions: p.partitions,
        })
    }

    /// Token for this enumeration.
    #[must_use]
    pub const fn disk_token(&self) -> DiskToken {
        self.disk_token
    }

    /// Bus.
    #[must_use]
    pub const fn bus(&self) -> Bus {
        self.bus
    }

    /// Model.
    #[must_use]
    pub const fn model(&self) -> &DiskText {
        &self.model
    }

    /// Serial number.
    #[must_use]
    pub const fn serial(&self) -> &DiskText {
        &self.serial
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Logical sector size.
    #[must_use]
    pub const fn logical_sector(&self) -> u32 {
        self.logical_sector
    }

    /// Physical sector size.
    #[must_use]
    pub const fn physical_sector(&self) -> u32 {
        self.physical_sector
    }

    /// Whether the device reports removable media.
    #[must_use]
    pub const fn removable(&self) -> bool {
        self.removable
    }

    /// Existing partitions.
    #[must_use]
    pub fn partitions(&self) -> &[ExistingPartitionV1] {
        &self.partitions
    }
}

/// The disk fields a signed job plan binds (plan section 3.2). The agent
/// refuses a plan whose disk differs from its chosen descriptor in any of
/// them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanDiskV1 {
    /// Token for the enumeration the technician chose from.
    pub disk_token: DiskToken,
    /// Bus.
    pub bus: Bus,
    /// Model.
    pub model: DiskText,
    /// Serial number.
    pub serial: DiskText,
    /// Size in bytes.
    pub size_bytes: u64,
    /// Logical sector size.
    pub logical_sector: u32,
    /// Physical sector size.
    pub physical_sector: u32,
}

impl From<&DiskDescriptorV1> for PlanDiskV1 {
    fn from(d: &DiskDescriptorV1) -> Self {
        Self {
            disk_token: d.disk_token,
            bus: d.bus,
            model: d.model.clone(),
            serial: d.serial.clone(),
            size_bytes: d.size_bytes,
            logical_sector: d.logical_sector,
            physical_sector: d.physical_sector,
        }
    }
}

impl PlanDiskV1 {
    /// Checks the geometry rules a descriptor meets.
    ///
    /// # Errors
    ///
    /// [`DiskDataError`].
    pub fn validate(&self) -> Result<(), DiskDataError> {
        check_geometry(self.size_bytes, self.logical_sector, self.physical_sector)
    }

    /// `true` if every bound field equals the descriptor's.
    #[must_use]
    pub fn matches(&self, d: &DiskDescriptorV1) -> bool {
        *self == Self::from(d)
    }
}

/// One partition the agent wrote (plan section 3.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrittenPartitionV1 {
    /// Entry index (1 to 128).
    pub index: u32,
    /// Kind.
    pub kind: PartitionKind,
    /// Start offset in bytes.
    pub start_bytes: u64,
    /// Size in bytes (at least 1).
    pub size_bytes: u64,
    /// File system, if formatted (the MSR is not).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fs: Option<FileSystem>,
    /// Label, if set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<PartitionLabel>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutReportWire {
    partitions: Vec<WrittenPartitionV1>,
    disk_guid: DiskGuid,
}

/// The layout the agent wrote (plan section 3.4; REQ-DISK-014).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "LayoutReportWire")]
pub struct LayoutReportV1 {
    partitions: Vec<WrittenPartitionV1>,
    disk_guid: DiskGuid,
}

impl TryFrom<LayoutReportWire> for LayoutReportV1 {
    type Error = DiskDataError;

    fn try_from(w: LayoutReportWire) -> Result<Self, Self::Error> {
        Self::new(w.partitions, w.disk_guid)
    }
}

impl LayoutReportV1 {
    /// Builds a report after checking the partition list (count, unique
    /// indexes, non-empty, no overflow).
    ///
    /// # Errors
    ///
    /// [`DiskDataError`].
    pub fn new(
        partitions: Vec<WrittenPartitionV1>,
        disk_guid: DiskGuid,
    ) -> Result<Self, DiskDataError> {
        check_partitions(
            partitions
                .iter()
                .map(|x| (x.index, x.start_bytes, x.size_bytes)),
            None,
        )?;
        Ok(Self {
            partitions,
            disk_guid,
        })
    }

    /// Partitions written.
    #[must_use]
    pub fn partitions(&self) -> &[WrittenPartitionV1] {
        &self.partitions
    }

    /// The new disk GUID.
    #[must_use]
    pub const fn disk_guid(&self) -> DiskGuid {
        self.disk_guid
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn token() -> DiskToken {
        DiskToken::from_random_bytes([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ])
    }

    pub(crate) fn descriptor() -> DiskDescriptorV1 {
        DiskDescriptorV1::new(DiskDescriptorParts {
            disk_token: token(),
            bus: Bus::Nvme,
            model: DiskText::sanitized("Example NVMe 1TB"),
            serial: DiskText::sanitized("SN0001"),
            size_bytes: 1_000_204_886_016,
            logical_sector: 512,
            physical_sector: 4096,
            removable: false,
            partitions: vec![ExistingPartitionV1 {
                index: 1,
                kind: PartitionKind::Esp,
                start_bytes: 1_048_576,
                size_bytes: 209_715_200,
                label: PartitionLabel::sanitized("EFI system partition"),
            }],
        })
        .unwrap()
    }

    #[test]
    fn token_text() {
        let t = token();
        assert_eq!(t.to_string(), "00112233445566778899aabbccddeeff");
        assert_eq!(DiskToken::parse(&t.to_string()).unwrap(), t);
        for bad in [
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "0011223344556677 899aabbccddeeff",
            "g0112233445566778899aabbccddeeff",
            "",
        ] {
            assert_eq!(DiskToken::parse(bad), Err(DiskDataError::BadToken), "{bad}");
        }
    }

    #[test]
    fn geometry_rules() {
        let ok = descriptor();
        let parts = |f: &dyn Fn(&mut DiskDescriptorParts)| {
            let mut p = DiskDescriptorParts {
                disk_token: ok.disk_token,
                bus: ok.bus,
                model: ok.model.clone(),
                serial: ok.serial.clone(),
                size_bytes: ok.size_bytes,
                logical_sector: ok.logical_sector,
                physical_sector: ok.physical_sector,
                removable: ok.removable,
                partitions: ok.partitions.clone(),
            };
            f(&mut p);
            DiskDescriptorV1::new(p)
        };
        assert!(parts(&|_| {}).is_ok());
        assert_eq!(
            parts(&|p| p.logical_sector = 1024).unwrap_err(),
            DiskDataError::BadLogicalSector
        );
        assert_eq!(
            parts(&|p| p.physical_sector = 256).unwrap_err(),
            DiskDataError::BadPhysicalSector
        );
        assert_eq!(
            parts(&|p| p.physical_sector = 3000).unwrap_err(),
            DiskDataError::BadPhysicalSector
        );
        assert_eq!(
            parts(&|p| p.physical_sector = 131_072).unwrap_err(),
            DiskDataError::BadPhysicalSector
        );
        assert_eq!(
            parts(&|p| p.size_bytes = 0).unwrap_err(),
            DiskDataError::BadSize
        );
        assert_eq!(
            parts(&|p| p.size_bytes = 1_000_204_886_017).unwrap_err(),
            DiskDataError::BadSize
        );
        assert_eq!(
            parts(&|p| p.partitions.first_mut().unwrap().size_bytes = 0).unwrap_err(),
            DiskDataError::PartitionOutOfBounds { index: 1 }
        );
        assert_eq!(
            parts(&|p| p.partitions.first_mut().unwrap().start_bytes = u64::MAX).unwrap_err(),
            DiskDataError::PartitionOutOfBounds { index: 1 }
        );
        assert_eq!(
            parts(&|p| p.partitions.first_mut().unwrap().start_bytes = p.size_bytes).unwrap_err(),
            DiskDataError::PartitionOutOfBounds { index: 1 }
        );
        assert_eq!(
            parts(&|p| p.partitions.first_mut().unwrap().index = 0).unwrap_err(),
            DiskDataError::BadPartitionIndex
        );
        assert_eq!(
            parts(&|p| p.partitions.first_mut().unwrap().index = 129).unwrap_err(),
            DiskDataError::BadPartitionIndex
        );
        assert_eq!(
            parts(&|p| {
                let dup = p.partitions.first().unwrap().clone();
                p.partitions.push(dup);
            })
            .unwrap_err(),
            DiskDataError::BadPartitionIndex
        );
        assert_eq!(
            parts(&|p| {
                p.partitions = (1..=129)
                    .map(|i| ExistingPartitionV1 {
                        index: i,
                        kind: PartitionKind::Other,
                        start_bytes: 0,
                        size_bytes: 1,
                        label: None,
                    })
                    .collect();
            })
            .unwrap_err(),
            DiskDataError::TooManyPartitions { count: 129 }
        );
    }

    #[test]
    fn plan_disk_binding() {
        let d = descriptor();
        let p = PlanDiskV1::from(&d);
        assert!(p.matches(&d));
        assert!(p.validate().is_ok());
        let mut other = p.clone();
        other.serial = DiskText::sanitized("SN0002");
        assert!(!other.matches(&d));
        let mut other = p.clone();
        other.size_bytes -= 512;
        assert!(!other.matches(&d));
    }

    #[test]
    fn guid_text() {
        let g = DiskGuid::parse("0B7C2F4E-9A1D-4C3B-8E6F-1A2B3C4D5E6F").unwrap();
        assert_eq!(g.to_string(), "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f");
        assert_eq!(
            DiskGuid::from_text_order_bytes(*g.text_order_bytes()),
            Ok(g)
        );
        assert_eq!(
            DiskGuid::parse("00000000-0000-0000-0000-000000000000"),
            Err(DiskDataError::BadGuid)
        );
        assert_eq!(
            DiskGuid::parse("0b7c2f4e9a1d4c3b8e6f1a2b3c4d5e6f"),
            Err(DiskDataError::BadGuid)
        );
        assert_eq!(
            DiskGuid::from_text_order_bytes([0; 16]),
            Err(DiskDataError::BadGuid)
        );
    }
}
