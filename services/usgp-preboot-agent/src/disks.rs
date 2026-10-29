//! The disk inventory shown at the device (REQ-DISK-001 to REQ-DISK-005).
//!
//! The platform reports each disk as a [`FoundDisk`] (facts only: identity,
//! bus, flags, sector sizes, size and the existing partitions with their
//! kinds and labels; never content, REQ-DISK-016). [`Inventory::build`]
//! gives each disk a fresh random token for this enumeration (plan section
//! 3.1), assesses it with `usgp-disk`'s fixed rules against the chosen
//! package's minimum, and builds the wire descriptor for the eligible ones.
//! Refused disks keep every reason, for the screen and for the
//! `no_disk` report.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement), CM-7 - removable, USB,
//   boot-media, read-only and odd-sector disks are never offered.
// - NIST 800-53: SI-10 - descriptors built only through the validating
//   `usgp-proto` constructors; text sanitised.
// - SPEC: specs/disk.md#REQ-DISK-001..005, #REQ-DISK-016
// - DECISION: docs/decisions/0018 items 7 and 8

use std::fmt;

use usgp_disk::{Bus as DiskBus, DiskFacts, EligibilityPolicy, Ineligible, assess_all};
use usgp_proto::device::{DiskRefusal, RefusedDiskV1};
use usgp_proto::disk::{Bus, DiskDescriptorParts, ExistingPartitionV1, PartitionKind};
use usgp_proto::limits::MAX_REFUSED_DISKS;
use usgp_proto::{DiskDescriptorV1, DiskText, DiskToken, PartitionLabel};

/// One disk as the platform sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundDisk {
    /// Facts for eligibility and the engine's identity check.
    pub facts: DiskFacts,
    /// The kind of each entry of `facts.partitions`, in the same order
    /// (missing entries are `other`).
    pub kinds: Vec<PartitionKind>,
    /// `false` if the platform could not tell which volumes lie on this
    /// disk, so it cannot rule out that the boot environment does
    /// (fail closed; WU-5 lock rule).
    pub volumes_known: bool,
}

/// Why a disk is not offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A `usgp-disk` eligibility rule.
    Ineligible(Ineligible),
    /// The volumes on the disk could not all be identified.
    VolumesUndetermined,
    /// Its partition list could not be described within the protocol's
    /// limits.
    Undescribable,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ineligible(Ineligible::TooSmall { size, min }) => write!(
                f,
                "too small: {} ({size} bytes); this package needs at least {} ({min} bytes)",
                gb(*size),
                gb(*min)
            ),
            Self::Ineligible(i) => i.fmt(f),
            Self::VolumesUndetermined => f.write_str(
                "the volumes on this disk could not all be identified, so it may hold the \
                 running boot environment",
            ),
            Self::Undescribable => f.write_str("its partition table could not be described"),
        }
    }
}

impl Refusal {
    /// The reason sent in the `no_disk` report. A future eligibility
    /// reason without a wire value of its own is sent as `boot_media` (the
    /// disk could not be shown not to hold the boot environment).
    #[must_use]
    pub fn wire(&self) -> DiskRefusal {
        match self {
            Self::Ineligible(Ineligible::BootMedia) => DiskRefusal::BootMedia,
            Self::Ineligible(Ineligible::Removable) => DiskRefusal::Removable,
            Self::Ineligible(Ineligible::UsbDisk) => DiskRefusal::UsbDisk,
            Self::Ineligible(Ineligible::UnsupportedBus(_)) => DiskRefusal::UnsupportedBus,
            Self::Ineligible(Ineligible::ReadOnly) => DiskRefusal::ReadOnly,
            Self::Ineligible(Ineligible::UnsupportedSectorSize { .. }) => {
                DiskRefusal::UnsupportedSectorSize
            }
            Self::Ineligible(Ineligible::TooSmall { .. }) => DiskRefusal::TooSmall,
            Self::VolumesUndetermined => DiskRefusal::VolumesUndetermined,
            Self::Undescribable => DiskRefusal::PartitionTableUndescribable,
            Self::Ineligible(_) => DiskRefusal::BootMedia,
        }
    }
}

/// Bytes as decimal gigabytes with one decimal (disk makers' unit).
#[must_use]
pub fn gb(bytes: u64) -> String {
    let tenths = bytes / 100_000_000;
    format!("{}.{} GB", tenths / 10, tenths % 10)
}

/// The wire bus for a platform bus. The same mapping as the engine's
/// identity check (`usgp-deploy` `engine::bus_of`), so a descriptor built
/// here compares equal to the opened disk.
#[must_use]
pub fn wire_bus(b: DiskBus) -> Bus {
    match b {
        DiskBus::Sata => Bus::Sata,
        DiskBus::Ata => Bus::Ata,
        DiskBus::Sas => Bus::Sas,
        DiskBus::Scsi => Bus::Scsi,
        DiskBus::Nvme => Bus::Nvme,
        DiskBus::Raid => Bus::Raid,
        DiskBus::Usb => Bus::Usb,
        DiskBus::Sd => Bus::Sd,
        DiskBus::Mmc => Bus::Mmc,
        DiskBus::Virtual => Bus::Virtual,
        DiskBus::FileBackedVirtual => Bus::FileBacked,
        _ => Bus::Other,
    }
}

/// The wire descriptor for `d` under `token`. Model and serial are
/// sanitised the way the engine compares them (a missing serial is the
/// empty text; WU-8 U-3). Partitions are numbered 1.. in the platform's
/// order.
///
/// # Errors
///
/// [`Refusal::Undescribable`] if the protocol's descriptor rules refuse
/// it (for example more than 128 partitions, or one past the end).
pub fn descriptor(token: DiskToken, d: &FoundDisk) -> Result<DiskDescriptorV1, Refusal> {
    let f = &d.facts;
    let mut partitions = Vec::with_capacity(f.partitions.len());
    for (i, p) in f.partitions.iter().enumerate() {
        let index = u32::try_from(i)
            .ok()
            .and_then(|i| i.checked_add(1))
            .ok_or(Refusal::Undescribable)?;
        partitions.push(ExistingPartitionV1 {
            index,
            kind: d.kinds.get(i).copied().unwrap_or(PartitionKind::Other),
            start_bytes: p.start_bytes,
            size_bytes: p.size_bytes,
            label: p.label.as_deref().and_then(PartitionLabel::sanitized),
        });
    }
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: token,
        bus: wire_bus(f.bus),
        model: DiskText::sanitized(&f.identity.model),
        serial: DiskText::sanitized(f.identity.serial.as_deref().unwrap_or("")),
        size_bytes: f.size_bytes,
        logical_sector: f.logical_sector,
        physical_sector: f.physical_sector,
        removable: f.removable,
        partitions,
    })
    .map_err(|_| Refusal::Undescribable)
}

/// One disk of an enumeration.
#[derive(Debug, Clone)]
pub struct DiskEntry {
    /// The token for this enumeration.
    pub token: DiskToken,
    /// What the platform reported.
    pub found: FoundDisk,
    /// The descriptor, for eligible disks.
    pub descriptor: Option<DiskDescriptorV1>,
    /// Every reason it is refused (empty: eligible).
    pub refusals: Vec<Refusal>,
}

impl DiskEntry {
    /// `true` if the disk may be chosen.
    #[must_use]
    pub fn eligible(&self) -> bool {
        self.refusals.is_empty() && self.descriptor.is_some()
    }
}

/// One enumeration of the disks.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    entries: Vec<DiskEntry>,
}

impl Inventory {
    /// Tokens every disk (`token` gives 16 fresh random bytes per call),
    /// and assesses it against `min_bytes` (the chosen package's
    /// `required_disk_bytes`; never below 64 GB).
    #[must_use]
    pub fn build(
        found: Vec<FoundDisk>,
        policy: &EligibilityPolicy,
        min_bytes: u64,
        token: &mut dyn FnMut() -> DiskToken,
    ) -> Self {
        let entries = found
            .into_iter()
            .map(|d| {
                let t = token();
                let mut refusals: Vec<Refusal> = assess_all(&d.facts, policy, min_bytes)
                    .into_iter()
                    .map(Refusal::Ineligible)
                    .collect();
                if !d.volumes_known {
                    refusals.push(Refusal::VolumesUndetermined);
                }
                let descriptor = if refusals.is_empty() {
                    match descriptor(t, &d) {
                        Ok(desc) => Some(desc),
                        Err(r) => {
                            refusals.push(r);
                            None
                        }
                    }
                } else {
                    None
                };
                DiskEntry {
                    token: t,
                    found: d,
                    descriptor,
                    refusals,
                }
            })
            .collect();
        Self { entries }
    }

    /// Every disk, in the platform's order.
    #[must_use]
    pub fn entries(&self) -> &[DiskEntry] {
        &self.entries
    }

    /// The eligible disks, in order.
    pub fn eligible(&self) -> impl Iterator<Item = &DiskEntry> {
        self.entries.iter().filter(|e| e.eligible())
    }

    /// The refused disks, in order.
    pub fn refused(&self) -> impl Iterator<Item = &DiskEntry> {
        self.entries.iter().filter(|e| !e.eligible())
    }

    /// The entry with `token`.
    #[must_use]
    pub fn by_token(&self, token: DiskToken) -> Option<&DiskEntry> {
        self.entries.iter().find(|e| e.token == token)
    }

    /// The `no_disk` report: bus, size and first reason of each refused
    /// disk, at most [`MAX_REFUSED_DISKS`] (REQ-DISK-003; no identity).
    #[must_use]
    pub fn refused_report(&self) -> Vec<RefusedDiskV1> {
        self.refused()
            .filter_map(|e| {
                e.refusals.first().map(|r| RefusedDiskV1 {
                    bus: wire_bus(e.found.facts.bus),
                    size_bytes: e.found.facts.size_bytes,
                    reason: r.wire(),
                })
            })
            .take(MAX_REFUSED_DISKS)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use usgp_disk::{DiskIdentity, ExistingPartition};

    use super::*;

    fn found(size: u64) -> FoundDisk {
        FoundDisk {
            facts: DiskFacts {
                identity: DiskIdentity {
                    device_number: 1,
                    model: "Disk\u{7}One".to_owned(),
                    serial: None,
                },
                bus: DiskBus::Nvme,
                removable: false,
                read_only: false,
                logical_sector: 512,
                physical_sector: 4096,
                size_bytes: size,
                hosts_boot_environment: false,
                partitions: vec![ExistingPartition {
                    start_bytes: 1 << 20,
                    size_bytes: 1 << 20,
                    label: Some("Data".to_owned()),
                }],
            },
            kinds: vec![PartitionKind::Basic],
            volumes_known: true,
        }
    }

    fn tokens() -> impl FnMut() -> DiskToken {
        let mut n = 0u8;
        move || {
            n = n.wrapping_add(1);
            DiskToken::from_random_bytes([n; 16])
        }
    }

    #[test]
    fn eligible_disk_gets_a_sanitised_descriptor() {
        let inv = Inventory::build(
            vec![found(100_000_000_000)],
            &EligibilityPolicy::default(),
            0,
            &mut tokens(),
        );
        let e = inv.eligible().next().unwrap();
        let d = e.descriptor.as_ref().unwrap();
        assert_eq!(d.model().as_str(), "Disk?One");
        assert_eq!(d.serial().as_str(), "");
        assert_eq!(d.bus(), Bus::Nvme);
        assert_eq!(d.partitions().len(), 1);
        assert_eq!(
            d.partitions()
                .first()
                .unwrap()
                .label
                .as_ref()
                .unwrap()
                .as_str(),
            "Data"
        );
    }

    #[test]
    fn refusals_are_all_listed_and_reported() {
        let mut usb = found(32_000_000_000);
        usb.facts.bus = DiskBus::Usb;
        usb.facts.removable = true;
        let mut boot = found(100_000_000_000);
        boot.facts.hosts_boot_environment = true;
        let mut unknown = found(100_000_000_000);
        unknown.volumes_known = false;
        let inv = Inventory::build(
            vec![usb, boot, unknown, found(70_000_000_000)],
            &EligibilityPolicy::default(),
            80_000_000_000,
            &mut tokens(),
        );
        assert_eq!(inv.eligible().count(), 0);
        let r: Vec<_> = inv.refused().map(|e| e.refusals.clone()).collect();
        assert_eq!(
            r.first().unwrap(),
            &vec![
                Refusal::Ineligible(Ineligible::Removable),
                Refusal::Ineligible(Ineligible::UsbDisk),
                Refusal::Ineligible(Ineligible::TooSmall {
                    size: 32_000_000_000,
                    min: 80_000_000_000
                }),
            ]
        );
        assert_eq!(r.get(2).unwrap(), &vec![Refusal::VolumesUndetermined]);
        let report = inv.refused_report();
        assert_eq!(report.len(), 4);
        assert_eq!(report.first().unwrap().reason, DiskRefusal::Removable);
        assert_eq!(report.get(1).unwrap().reason, DiskRefusal::BootMedia);
        assert_eq!(
            report.get(2).unwrap().reason,
            DiskRefusal::VolumesUndetermined
        );
        assert_eq!(report.get(3).unwrap().reason, DiskRefusal::TooSmall);
        let text = r.get(3).unwrap().first().unwrap().to_string();
        assert!(
            text.contains("70.0 GB") && text.contains("80.0 GB"),
            "{text}"
        );
    }

    #[test]
    fn tokens_differ_per_enumeration() {
        let mut t = tokens();
        let a = Inventory::build(
            vec![found(1 << 40)],
            &EligibilityPolicy::default(),
            0,
            &mut t,
        );
        let b = Inventory::build(
            vec![found(1 << 40)],
            &EligibilityPolicy::default(),
            0,
            &mut t,
        );
        let ta = a.entries().first().unwrap().token;
        assert_ne!(ta, b.entries().first().unwrap().token);
        assert!(a.by_token(ta).is_some() && b.by_token(ta).is_none());
    }

    #[test]
    fn partition_past_the_end_is_undescribable() {
        let mut d = found(100_000_000_000);
        d.facts.partitions.push(ExistingPartition {
            start_bytes: 99_000_000_000,
            size_bytes: 2_000_000_000,
            label: None,
        });
        let inv = Inventory::build(vec![d], &EligibilityPolicy::default(), 0, &mut tokens());
        assert_eq!(
            inv.entries().first().unwrap().refusals,
            vec![Refusal::Undescribable]
        );
        assert_eq!(
            inv.refused_report().first().unwrap().reason,
            DiskRefusal::PartitionTableUndescribable
        );
    }
}
