//! The simulated host for CI end-to-end tests (plan WU-12 feature `sim`;
//! section 10.1 `agent-sim-e2e`). Never in a Windows release build.
//!
//! - Disks are **regular files** (`usgp_deploy::sim::SimPlatform` opens them
//!   through `FileBlockDevice`, which refuses anything else), so the
//!   simulation can never reach a real disk. Their size is the file's
//!   length; the rest of their facts come from the simulation file.
//! - Only the chosen disk is handed to the engine's platform; the others
//!   cannot be opened by it at all (REQ-DISK-015).
//! - Volumes are directories under a work directory, boot files a marker,
//!   firmware variables a JSON file (the engine's simulation).
//! - Restart and shutdown are recorded, not done.
//!
//! The binary takes the simulation from `--sim <file>`:
//!
//! ```toml
//! work_dir = "/tmp/agent-sim/work"
//! firmware_file = "/tmp/agent-sim/firmware.json"
//! dhcp_addresses = ["192.0.2.10"]
//! firmware = "uefi"          # uefi | bios | unknown
//! arch = "x64"               # x64 | x86 | arm64 | unknown
//! secure_boot = "on"         # on | off | unknown
//! memory_bytes = 8589934592
//! macs = ["02:00:00:00:00:01"]
//! allow_file_backed = false
//!
//! [[disk]]
//! path = "/tmp/agent-sim/disk0.img"
//! bus = "nvme"
//! model = "Sim NVMe"
//! serial = "SIM-0001"
//! logical_sector = 512
//! physical_sector = 4096
//! # removable, read_only, boot_media: false; volumes_known: true
//!
//! [[disk.partition]]
//! start_bytes = 1048576
//! size_bytes = 104857600
//! kind = "basic"
//! label = "Data"
//! ```

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - NIST 800-53: CM-7 (Least Functionality) - test-only; regular files
//   only; only the chosen file reaches the engine.
// - SPEC: specs/disk.md#REQ-DISK-015

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use usgp_deploy::Platform;
use usgp_deploy::sim::{SimDisk, SimPlatform};
use usgp_disk::{Bus, DiskFacts, DiskIdentity, EligibilityPolicy, ExistingPartition};
use usgp_proto::device::{DeviceArch, FirmwareKind, MacAddress, SecureBootState};
use usgp_proto::disk::PartitionKind;

use crate::disks::{Discriminator, DiskEntry, FoundDisk};
use crate::host::{Host, HostError, HostFacts, PowerAction, WaitBudget};

/// Largest simulation file read.
const MAX_SIM_FILE_BYTES: u64 = 64 * 1024;

/// One simulated disk.
#[derive(Debug, Clone)]
pub struct SimDiskSpec {
    /// The regular file holding the disk image.
    pub path: PathBuf,
    /// Its facts; `size_bytes` is replaced by the file's length.
    pub facts: DiskFacts,
    /// Kinds of `facts.partitions`.
    pub kinds: Vec<PartitionKind>,
    /// Whether its volumes are known (see [`FoundDisk::volumes_known`]).
    pub volumes_known: bool,
}

/// The simulated host.
#[derive(Debug, Clone)]
pub struct SimHost {
    /// Hello facts.
    pub facts: HostFacts,
    /// Addresses the network wait sees.
    pub dhcp: Vec<Ipv4Addr>,
    /// The disks.
    pub disks: Vec<SimDiskSpec>,
    /// Where volume directories are made.
    pub work_dir: PathBuf,
    /// The firmware-variable file.
    pub firmware_file: PathBuf,
    /// Accept file-backed virtual disks (as the Windows CI job does).
    pub allow_file_backed: bool,
    /// Power actions requested.
    pub power_log: Vec<PowerAction>,
}

impl SimHost {
    /// A UEFI x64 host with Secure Boot on and the given MAC.
    #[must_use]
    pub fn new(work_dir: &Path, firmware_file: &Path, mac: MacAddress) -> Self {
        Self {
            facts: HostFacts {
                firmware: FirmwareKind::Uefi,
                arch: DeviceArch::X64,
                secure_boot: SecureBootState::On,
                memory_bytes: 8 << 30,
                macs: vec![mac],
            },
            dhcp: vec![Ipv4Addr::new(192, 0, 2, 10)],
            disks: Vec::new(),
            work_dir: work_dir.to_path_buf(),
            firmware_file: firmware_file.to_path_buf(),
            allow_file_backed: false,
            power_log: Vec::new(),
        }
    }

    /// Reads a simulation file (format in the module documentation).
    ///
    /// # Errors
    ///
    /// [`HostError`] naming the problem.
    pub fn from_file(path: &Path) -> Result<Self, HostError> {
        let text = usgp_common::config::read_bounded(path, MAX_SIM_FILE_BYTES)
            .map_err(|e| HostError(e.to_string()))?;
        let raw: SimToml =
            usgp_common::config::parse_toml(&text).map_err(|e| HostError(e.to_string()))?;
        let bad = |what: &str| HostError(format!("simulation file: bad {what}"));
        let macs = raw
            .macs
            .iter()
            .map(|m| MacAddress::parse(m).map_err(|_| bad("mac")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut disks = Vec::with_capacity(raw.disk.len());
        for (n, d) in raw.disk.into_iter().enumerate() {
            let mut partitions = Vec::with_capacity(d.partition.len());
            let mut kinds = Vec::with_capacity(d.partition.len());
            for p in d.partition {
                kinds.push(PartitionKind::parse(&p.kind).ok_or_else(|| bad("partition kind"))?);
                partitions.push(ExistingPartition {
                    start_bytes: p.start_bytes,
                    size_bytes: p.size_bytes,
                    label: p.label,
                });
            }
            disks.push(SimDiskSpec {
                path: d.path,
                facts: DiskFacts {
                    identity: DiskIdentity {
                        device_number: u32::try_from(n).map_err(|_| bad("disk count"))?,
                        model: d.model,
                        serial: d.serial,
                    },
                    bus: bus_from_name(&d.bus).ok_or_else(|| bad("bus"))?,
                    removable: d.removable,
                    read_only: d.read_only,
                    logical_sector: d.logical_sector,
                    physical_sector: d.physical_sector,
                    size_bytes: 0,
                    hosts_boot_environment: d.boot_media,
                    partitions,
                },
                kinds,
                volumes_known: d.volumes_known.unwrap_or(true),
            });
        }
        Ok(Self {
            facts: HostFacts {
                firmware: FirmwareKind::parse(&raw.firmware).ok_or_else(|| bad("firmware"))?,
                arch: DeviceArch::parse(&raw.arch).ok_or_else(|| bad("arch"))?,
                secure_boot: SecureBootState::parse(&raw.secure_boot)
                    .ok_or_else(|| bad("secure_boot"))?,
                memory_bytes: raw.memory_bytes,
                macs,
            },
            dhcp: raw.dhcp_addresses,
            disks,
            work_dir: raw.work_dir,
            firmware_file: raw.firmware_file,
            allow_file_backed: raw.allow_file_backed,
            power_log: Vec::new(),
        })
    }
}

/// The platform bus for a simulation bus name.
#[must_use]
pub fn bus_from_name(s: &str) -> Option<Bus> {
    Some(match s {
        "sata" => Bus::Sata,
        "ata" => Bus::Ata,
        "sas" => Bus::Sas,
        "scsi" => Bus::Scsi,
        "nvme" => Bus::Nvme,
        "raid" => Bus::Raid,
        "usb" => Bus::Usb,
        "sd" => Bus::Sd,
        "mmc" => Bus::Mmc,
        "virtual" => Bus::Virtual,
        "file_backed" => Bus::FileBackedVirtual,
        _ => return None,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SimToml {
    work_dir: PathBuf,
    firmware_file: PathBuf,
    #[serde(default)]
    dhcp_addresses: Vec<Ipv4Addr>,
    firmware: String,
    arch: String,
    secure_boot: String,
    memory_bytes: u64,
    macs: Vec<String>,
    #[serde(default)]
    allow_file_backed: bool,
    #[serde(default)]
    disk: Vec<SimDiskToml>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SimDiskToml {
    path: PathBuf,
    bus: String,
    model: String,
    serial: Option<String>,
    logical_sector: u32,
    physical_sector: u32,
    #[serde(default)]
    removable: bool,
    #[serde(default)]
    read_only: bool,
    #[serde(default)]
    boot_media: bool,
    volumes_known: Option<bool>,
    #[serde(default)]
    partition: Vec<SimPartToml>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SimPartToml {
    start_bytes: u64,
    size_bytes: u64,
    kind: String,
    label: Option<String>,
}

impl Host for SimHost {
    fn facts(&mut self) -> Result<HostFacts, HostError> {
        Ok(self.facts.clone())
    }

    fn dhcp_addresses(&mut self) -> Result<Vec<Ipv4Addr>, HostError> {
        Ok(self.dhcp.clone())
    }

    fn disks(&mut self) -> Result<Vec<FoundDisk>, HostError> {
        self.disks
            .iter()
            .map(|d| {
                let meta = std::fs::metadata(&d.path)
                    .map_err(|e| HostError(format!("simulated disk: {}", e.kind())))?;
                if !meta.is_file() {
                    return Err(HostError("simulated disk is not a regular file".to_owned()));
                }
                let mut facts = d.facts.clone();
                facts.size_bytes = meta.len();
                Ok(FoundDisk {
                    facts,
                    kinds: d.kinds.clone(),
                    volumes_known: d.volumes_known,
                    // The simulation has no device path or table identity.
                    discriminator: Discriminator::default(),
                })
            })
            .collect()
    }

    fn eligibility(&self) -> EligibilityPolicy {
        EligibilityPolicy {
            allow_file_backed_virtual: self.allow_file_backed,
        }
    }

    fn platform(
        &mut self,
        chosen: &DiskEntry,
        _budget: WaitBudget,
    ) -> Result<Box<dyn Platform + '_>, HostError> {
        let n = chosen.found.facts.identity.device_number;
        let spec = usize::try_from(n)
            .ok()
            .and_then(|i| self.disks.get(i))
            .ok_or_else(|| HostError("the chosen disk is gone".to_owned()))?;
        let mut p = SimPlatform::new(&self.work_dir, &self.firmware_file);
        // Only the chosen disk: no other file can be opened by the engine.
        p.add_disk(SimDisk {
            token: chosen.token,
            path: spec.path.clone(),
            facts: chosen.found.facts.clone(),
        });
        Ok(Box::new(p))
    }

    fn power(&mut self, action: PowerAction) -> Result<(), HostError> {
        self.power_log.push(action);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_file_parses_and_refuses_unknown_keys() {
        let dir = std::env::temp_dir().join(format!("usgp-agent-sim-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sim.toml");
        std::fs::write(
            &f,
            "work_dir = \"/w\"\nfirmware_file = \"/f.json\"\nfirmware = \"uefi\"\narch = \"x64\"\n\
             secure_boot = \"off\"\nmemory_bytes = 1\nmacs = [\"02:00:00:00:00:01\"]\n\
             [[disk]]\npath = \"/d\"\nbus = \"nvme\"\nmodel = \"M\"\nlogical_sector = 512\n\
             physical_sector = 512\n[[disk.partition]]\nstart_bytes = 1\nsize_bytes = 2\n\
             kind = \"esp\"\n",
        )
        .unwrap();
        let h = SimHost::from_file(&f).unwrap();
        assert_eq!(h.facts.secure_boot, SecureBootState::Off);
        assert_eq!(h.disks.first().unwrap().kinds, vec![PartitionKind::Esp]);
        std::fs::write(&f, "work_dir = \"/w\"\nskip_checks = true\n").unwrap();
        assert!(SimHost::from_file(&f).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
