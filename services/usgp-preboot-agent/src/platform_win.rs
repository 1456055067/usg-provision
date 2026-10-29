//! The Windows PE host and the engine platform on `usgp-winapi` (plan
//! sections 1.2(a) and 1.2(c); WU-12 `src/platform_win.rs`).
//!
//! - **Facts**: firmware mode (the documented empty-variable test), native
//!   architecture, Secure Boot (read only), memory, MACs and DHCP
//!   addresses, all through `usgp-winapi`.
//! - **Disks**: the documented enumeration, then descriptor, sector sizes,
//!   geometry, writability and layout on query-only handles (no content
//!   is read, REQ-DISK-016). A disk is the boot media if a volume of the
//!   running environment (the system directory, this program) lies on it;
//!   if that cannot be established, every disk is treated as boot media
//!   (fail closed). A disk whose volumes cannot all be placed is refused
//!   (WU-5 lock rule).
//! - **Open**: only the chosen disk, re-inspected through its interface
//!   path (topic 23 §2) and compared with what the person confirmed;
//!   every volume on it locked and dismounted; then opened for write by
//!   that same path with the job's recorded size (`RawDisk`), and the
//!   descriptor (model, serial, bus) and partition-table identity read on
//!   the write handle itself must match the listing (BOOT-002, SEC-003).
//! - **Format**: `IOCTL_DISK_UPDATE_PROPERTIES`, locks released, each new
//!   volume resolved by its exact extent on the chosen disk, a free letter
//!   assigned (never `X:`), the script written create-new under a random
//!   name (SEC-008), the letter re-resolved to the same volume and extent
//!   immediately before DiskPart starts (BOOT-001), DiskPart run with a
//!   script that selects only that letter, and the result read back (file
//!   system, label and extent).
//! - **Boot files**: BCDBoot from the applied image with `/s` naming the
//!   ESP (`uefi-boot-manager.md` §9.4); `\EFI\Microsoft\Boot\bootmgfw.efi`
//!   must then exist.
//! - **Firmware variables**: `BootOrder` and `Boot####` only, mapped from
//!   `usgp_disk::uefi::BootVarName` onto `usgp_winapi::vars::WritableBootVar`
//!   (the restriction holds at both layers).
//! - **Power**: `wpeutil Reboot` or `wpeutil Shutdown` (`winpe.md` §5.2).
//! - **Privileges** (AC-6, NIST-001): none is enabled at start-up; the
//!   agent only checks that its token holds them. The sink enables restore
//!   and backup for the apply step (and security or create-symbolic-link
//!   per call); the firmware privilege is enabled per firmware call.
//!
//! Every external tool and every wait is bounded by [`WaitBudget`], which
//! the session sizes below the job plan's limits (WU-8 POAM).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - only the chosen disk is
//   opened for write, after re-identification; volumes selected by our
//   own letters on exactly matched extents.
// - NIST 800-53: CM-7 (Least Functionality) - firmware writes limited to
//   BootOrder and Boot#### by type at two layers; no Secure Boot variable
//   can be named.
// - NIST 800-53: SI-7 - boot files come from the verified applied image
//   (BCDBoot from it).
// - NIST 800-53: SC-5 - every tool and wait bounded.
// - NIST 800-53: AC-6 (Least Privilege) - privileges checked at start-up,
//   enabled only by the operation that needs them (usgp-winapi).
// - SPEC: specs/standards/windows-storage-firmware-api.md §2, §7, §10, §23
// - SPEC: specs/standards/winpe.md §5.2, §11;
//   specs/standards/uefi-boot-manager.md §9.4
// - SPEC: specs/disk.md#REQ-DISK-005, #REQ-DISK-008, #REQ-DISK-015,
//   #REQ-DISK-016
// - SPEC: specs/boot-network.md#REQ-BOOT-065, #REQ-BOOT-066
// - SPEC: specs/preinstall-env.md#REQ-PE-014, #REQ-PE-019, #REQ-PE-020
// - DECISION: docs/decisions/0018 items 5, 8, 9; 0019

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use usgp_crypto::CryptoProvider;
use usgp_deploy::platform::{
    BootFiles, FirmwareVars as FirmwareVarsTrait, FormattedVolume, FwError, OpenedTarget, Platform,
    PlatformError, PlatformErrorKind, VolumeOps, VolumeSpec,
};
use usgp_disk::layout::{PartRole, WindowsUefiLayout};
use usgp_disk::uefi::BootVarName;
use usgp_disk::{BlockDevice, Bus, DiskFacts, DiskIdentity, ExistingPartition, Guid};
use usgp_image::apply::{ApplyRoot, ApplySink};
use usgp_proto::device::{DeviceArch, FirmwareKind, MacAddress, SecureBootState};
use usgp_proto::disk::{FileSystem, PartitionKind};
use usgp_winapi::WinApiError;
use usgp_winapi::disk::{
    self, DeviceDescriptor, DiskInfo, DiskInterface, MediaType, RawDisk, TableId, Writability,
};
use usgp_winapi::firmware::{self, FirmwareMode, FirmwareVars};
use usgp_winapi::paths::{DriveLetter, VolumeGuidPath};
use usgp_winapi::privilege::{self, Privilege};
use usgp_winapi::vars::{
    BOOT_VAR_ATTRIBUTES, EFI_GLOBAL_VARIABLE, FlagState, ReadableVar, WritableBootVar,
};
use usgp_winapi::volume::{self, LockedVolume, VolumeBacking};
use usgp_winapi::{net, system};

use crate::disks::{Discriminator, DiskEntry, FoundDisk, TableIdentity};
use crate::host::{Host, HostError, HostFacts, PowerAction, WaitBudget};
use crate::wintools::{self, ToolError, VolumeMatch};

/// How often a new volume is looked for.
const VOLUME_POLL: Duration = Duration::from_millis(500);
/// Most time `wpeutil` may take to accept a restart or shutdown.
const POWER_LIMIT: Duration = Duration::from_secs(60);

fn host_err(what: &str, e: &WinApiError) -> HostError {
    HostError(format!("{what}: {e}"))
}

fn perr(kind: PlatformErrorKind, what: &'static str) -> PlatformError {
    PlatformError::new(kind, what)
}

fn win_kind(e: &WinApiError) -> PlatformErrorKind {
    match e {
        WinApiError::Os { source, .. } => PlatformErrorKind::Io(source.kind()),
        WinApiError::DeviceMismatch { .. } => PlatformErrorKind::IdentityMismatch,
        WinApiError::NotUefi => PlatformErrorKind::Unsupported,
        _ => PlatformErrorKind::Refused,
    }
}

fn tool_err(e: ToolError, what: &'static str) -> PlatformError {
    match e {
        ToolError::Timeout => perr(PlatformErrorKind::Timeout, what),
        ToolError::Start(k) => perr(PlatformErrorKind::Io(k), what),
        ToolError::Failed(_) => perr(PlatformErrorKind::Refused, what),
    }
}

/// The disk numbers holding the running environment: `Some(set)` (empty
/// when it runs from a RAM disk), or `None` if that cannot be
/// established (every disk is then treated as boot media).
fn boot_disks(system_dir: &Path) -> Option<BTreeSet<u32>> {
    let mut paths = vec![system_dir.to_path_buf()];
    paths.push(std::env::current_exe().ok()?);
    let mut out = BTreeSet::new();
    for p in paths {
        let letter = match p.components().next() {
            Some(Component::Prefix(pre)) => match pre.kind() {
                Prefix::Disk(b) | Prefix::VerbatimDisk(b) => DriveLetter::new(char::from(b))?,
                _ => return None,
            },
            _ => return None,
        };
        let vol = volume::volume_at(letter).ok()?;
        match volume::backing(&vol) {
            VolumeBacking::NotDiskBacked(_) => {}
            VolumeBacking::OnDisks(extents) => out.extend(extents.iter().map(|e| e.disk_number)),
            VolumeBacking::Undetermined { .. } => return None,
        }
    }
    Some(out)
}

fn bus_of(b: disk::Bus) -> Bus {
    use disk::Bus as W;
    match b {
        W::Unknown => Bus::Unknown,
        W::Scsi => Bus::Scsi,
        W::Atapi => Bus::Atapi,
        W::Ata => Bus::Ata,
        W::Ieee1394 => Bus::Ieee1394,
        W::Ssa => Bus::Ssa,
        W::Fibre => Bus::Fibre,
        W::Usb => Bus::Usb,
        W::Raid => Bus::Raid,
        W::Iscsi => Bus::Iscsi,
        W::Sas => Bus::Sas,
        W::Sata => Bus::Sata,
        W::Sd => Bus::Sd,
        W::Mmc => Bus::Mmc,
        W::Virtual => Bus::Virtual,
        W::FileBackedVirtual => Bus::FileBackedVirtual,
        W::Spaces => Bus::Spaces,
        W::Nvme => Bus::Nvme,
        W::Scm => Bus::Scm,
        W::Ufs => Bus::Ufs,
        W::Other(v) => Bus::Other(u32::try_from(v).unwrap_or(u32::MAX)),
        // A value this backend does not know: refused as an unknown bus.
        _ => Bus::Unknown,
    }
}

fn guid_of(g: &usgp_winapi::parse::Guid) -> Guid {
    Guid::from_fields(g.data1, g.data2, g.data3, g.data4)
}

/// The facts and partition kinds of one inspected disk.
fn found_of(info: &DiskInfo, boot: Option<&BTreeSet<u32>>) -> FoundDisk {
    let d = &info.descriptor;
    let (model, serial, bus) = shown_identity(d);
    let (logical, physical) = match info.sector_sizes {
        Some(s) => (s.logical, s.physical),
        None => (
            info.geometry.bytes_per_sector,
            info.geometry.bytes_per_sector,
        ),
    };
    let mut partitions = Vec::with_capacity(info.layout.partitions.len());
    let mut kinds = Vec::with_capacity(info.layout.partitions.len());
    for p in &info.layout.partitions {
        let (kind, label) = match &p.kind {
            usgp_winapi::parse::RawPartitionKind::Gpt {
                type_guid, name, ..
            } => (
                wintools::gpt_kind(&guid_of(type_guid)),
                (!name.trim().is_empty()).then(|| name.clone()),
            ),
            usgp_winapi::parse::RawPartitionKind::Mbr { .. } => (PartitionKind::MbrEntry, None),
            _ => (PartitionKind::Other, None),
        };
        kinds.push(kind);
        partitions.push(ExistingPartition {
            start_bytes: p.starting_offset,
            size_bytes: p.length,
            label,
        });
    }
    let hosts_boot = boot.is_none_or(|b| b.contains(&info.number));
    FoundDisk {
        facts: DiskFacts {
            identity: DiskIdentity {
                device_number: info.number,
                model,
                serial,
            },
            bus,
            removable: d.removable_media || info.geometry.media == MediaType::Removable,
            read_only: info.writability != Writability::Writable,
            logical_sector: logical,
            physical_sector: physical,
            size_bytes: info.geometry.size_bytes,
            hosts_boot_environment: hosts_boot,
            partitions,
        },
        kinds,
        volumes_known: volume::volumes_on_disk(info.number).is_ok(),
        discriminator: Discriminator {
            interface_path: info.interface_path.clone(),
            table: table_identity(info.layout.table_id()),
        },
    }
}

fn table_identity(t: TableId) -> TableIdentity {
    match t {
        TableId::Gpt(g) => TableIdentity::Gpt(guid_of(&g)),
        TableId::Mbr(sig) => TableIdentity::Mbr(sig),
        _ => TableIdentity::None,
    }
}

/// The identity shown to the person, from a descriptor (as in `found_of`).
fn shown_identity(d: &DeviceDescriptor) -> (String, Option<String>, Bus) {
    let model = [d.vendor_id.as_deref(), d.product_id.as_deref()]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let serial = d
        .serial_number
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    (model, serial, bus_of(d.bus))
}

/// The Windows PE host.
#[derive(Debug)]
pub struct WinHost {
    system_dir: PathBuf,
    firmware: Option<FirmwareVars>,
}

impl WinHost {
    /// Reads the system directory and, on UEFI, opens firmware variable
    /// access. Checks that the token holds every privilege the job needs,
    /// leaving each disabled (NIST-001).
    ///
    /// # Errors
    ///
    /// [`HostError`].
    pub fn open() -> Result<Self, HostError> {
        // The Windows sink needs these for every apply (security
        // descriptors, owners, SACLs, symbolic links and junctions):
        // without any of them the agent does not start, rather than fail
        // after the wipe. Each is enabled and at once disabled; the sink
        // enables them again only for the apply step (usgp-winapi
        // `privilege`). The firmware privilege is checked by
        // `firmware_mode` below, the same way.
        for p in [
            Privilege::Restore,
            Privilege::Backup,
            Privilege::Security,
            Privilege::CreateSymbolicLink,
        ] {
            privilege::check_held(p).map_err(|e| host_err("check a privilege", &e))?;
        }
        let system_dir =
            system::system_directory().map_err(|e| host_err("system directory", &e))?;
        let firmware = match firmware::firmware_mode() {
            Ok(FirmwareMode::Uefi) => {
                Some(FirmwareVars::open().map_err(|e| host_err("firmware variables", &e))?)
            }
            Ok(FirmwareMode::LegacyBios) => None,
            Err(e) => return Err(host_err("firmware mode", &e)),
        };
        Ok(Self {
            system_dir,
            firmware,
        })
    }
}

impl Host for WinHost {
    fn facts(&mut self) -> Result<HostFacts, HostError> {
        let firmware = if self.firmware.is_some() {
            FirmwareKind::Uefi
        } else {
            FirmwareKind::Bios
        };
        let arch = match system::native_arch() {
            system::Arch::X64 => DeviceArch::X64,
            system::Arch::X86 => DeviceArch::X86,
            system::Arch::Arm64 => DeviceArch::Arm64,
            system::Arch::Other(_) => DeviceArch::Unknown,
        };
        let secure_boot = match self.firmware.as_ref().map(FirmwareVars::secure_boot_status) {
            Some(Ok(s)) if s.enforcing() => SecureBootState::On,
            Some(Ok(s)) if s.secure_boot == FlagState::Off => SecureBootState::Off,
            _ => SecureBootState::Unknown,
        };
        let memory_bytes = system::total_memory_bytes().unwrap_or(0);
        let adapters = net::adapters().map_err(|e| host_err("network adapters", &e))?;
        let macs = net::hello_macs(&adapters)
            .into_iter()
            .filter_map(|m| MacAddress::new(m.0).ok())
            .collect();
        Ok(HostFacts {
            firmware,
            arch,
            secure_boot,
            memory_bytes,
            macs,
        })
    }

    fn dhcp_addresses(&mut self) -> Result<Vec<Ipv4Addr>, HostError> {
        let adapters = net::adapters().map_err(|e| host_err("network adapters", &e))?;
        Ok(net::dhcp_ipv4_addresses(&adapters))
    }

    fn disks(&mut self) -> Result<Vec<FoundDisk>, HostError> {
        let boot = boot_disks(&self.system_dir);
        let infos = disk::inspect_all().map_err(|e| host_err("disk enumeration", &e))?;
        Ok(infos.iter().map(|i| found_of(i, boot.as_ref())).collect())
    }

    fn platform(
        &mut self,
        chosen: &DiskEntry,
        budget: WaitBudget,
    ) -> Result<Box<dyn Platform + '_>, HostError> {
        let shared = Rc::new(RefCell::new(Shared {
            chosen: chosen.clone(),
            disk: None,
            locks: Vec::new(),
            letters: Vec::new(),
            windows_letter: None,
        }));
        Ok(Box::new(WinPlatform {
            shared: Rc::clone(&shared),
            volumes: WinVolumes {
                shared: Rc::clone(&shared),
                system_dir: self.system_dir.clone(),
                budget,
            },
            boot: WinBootFiles { shared, budget },
            firmware: WinFirmware {
                vars: self.firmware.as_mut(),
            },
            system_dir: self.system_dir.clone(),
        }))
    }

    fn power(&mut self, action: PowerAction) -> Result<(), HostError> {
        // `winpe.md` §5.2 (SR-7): `wpeutil <command>`, one command per
        // invocation; `Reboot` restarts and `Shutdown` shuts down the
        // WinPE session; neither takes an argument. Spelt as documented
        // (CR-SR7-001).
        let mut cmd = Command::new(self.system_dir.join("wpeutil.exe"));
        cmd.arg(wintools::wpeutil_command(action));
        wintools::run_bounded(cmd, POWER_LIMIT).map_err(|e| HostError(format!("wpeutil: {e:?}")))
    }
}

/// State shared by the platform's parts for one job.
struct Shared {
    chosen: DiskEntry,
    disk: Option<Rc<RefCell<RawDisk>>>,
    locks: Vec<LockedVolume>,
    /// Letters we assigned, by volume locator.
    letters: Vec<(String, DriveLetter)>,
    /// The Windows volume's letter, reserved in step 1 (`windows_root`).
    /// Never given to another volume; checked free again, under the new
    /// volume's lock, when it is assigned.
    windows_letter: Option<DriveLetter>,
}

impl Shared {
    fn letter_of(&self, locator: &str) -> Option<DriveLetter> {
        self.letters
            .iter()
            .find(|(l, _)| l == locator)
            .map(|(_, d)| *d)
    }
}

/// The engine platform for one chosen disk.
struct WinPlatform<'h> {
    shared: Rc<RefCell<Shared>>,
    volumes: WinVolumes,
    boot: WinBootFiles,
    firmware: WinFirmware<'h>,
    system_dir: PathBuf,
}

/// The chosen disk as the engine's block device.
struct WinDisk(Rc<RefCell<RawDisk>>);

fn io_of(e: &WinApiError) -> io::Error {
    match e {
        WinApiError::Os { source, .. } => io::Error::new(source.kind(), "disk I/O failed"),
        WinApiError::Refused { reason } => io::Error::new(io::ErrorKind::InvalidInput, *reason),
        _ => io::Error::other("disk I/O failed"),
    }
}

impl BlockDevice for WinDisk {
    fn len(&self) -> u64 {
        self.0.borrow().len()
    }

    fn logical_sector(&self) -> u32 {
        self.0.borrow().logical_sector()
    }

    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.borrow_mut().read_at(off, buf).map_err(|e| io_of(&e))
    }

    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.0
            .borrow_mut()
            .write_at(off, buf)
            .map_err(|e| io_of(&e))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush().map_err(|e| io_of(&e))
    }
}

/// `true` if `now` is the disk the person confirmed (disk numbers are not
/// stable; spec §7).
fn same_disk(was: &DiskFacts, now: &DiskFacts) -> bool {
    was.identity.model == now.identity.model
        && was.identity.serial == now.identity.serial
        && was.size_bytes == now.size_bytes
        && was.logical_sector == now.logical_sector
        && was.physical_sector == now.physical_sector
        && was.bus == now.bus
}

impl Platform for WinPlatform<'_> {
    fn open_target(
        &mut self,
        want: &usgp_proto::disk::PlanDiskV1,
    ) -> Result<OpenedTarget, PlatformError> {
        const WHAT: &str = "open target disk";
        let mut sh = self.shared.borrow_mut();
        if sh.chosen.token != want.disk_token {
            return Err(perr(PlatformErrorKind::IdentityMismatch, WHAT));
        }
        if sh.disk.is_some() {
            return Err(perr(PlatformErrorKind::Refused, WHAT));
        }
        let n = sh.chosen.found.facts.identity.device_number;
        // BOOT-002: the disk is re-opened by the interface path it was
        // listed with, so the handles below are that device even if disk
        // numbers moved; no path, no write (fail closed).
        let iface = DiskInterface {
            number: n,
            path: sh
                .chosen
                .found
                .discriminator
                .interface_path
                .clone()
                .ok_or(perr(PlatformErrorKind::IdentityMismatch, WHAT))?,
        };
        let boot = boot_disks(&self.system_dir);
        let info = disk::DiskQuery::open_interface(&iface)
            .and_then(|q| q.inspect())
            .map_err(|e| perr(win_kind(&e), WHAT))?;
        let now = found_of(&info, boot.as_ref());
        if !same_disk(&sh.chosen.found.facts, &now.facts)
            || now.discriminator != sh.chosen.found.discriminator
        {
            return Err(perr(PlatformErrorKind::IdentityMismatch, WHAT));
        }
        if !now.volumes_known {
            return Err(perr(
                PlatformErrorKind::Refused,
                "identify volumes on the disk",
            ));
        }
        // Locks are held until the new table is written and the disk's
        // properties updated (WU-5); released in `format`.
        let locks = volume::lock_volumes_on_disk(n)
            .map_err(|_| perr(PlatformErrorKind::Refused, "lock and dismount volumes"))?;
        let raw = RawDisk::open_interface_for_write(&iface, want.size_bytes)
            .map_err(|e| perr(win_kind(&e), WHAT))?;
        // BOOT-002: identity read on the write handle itself (model,
        // serial, bus, and the table's GPT disk GUID or MBR signature).
        let on_handle = raw.descriptor().map_err(|e| perr(win_kind(&e), WHAT))?;
        let table = raw
            .layout()
            .map(|l| table_identity(l.table_id()))
            .map_err(|e| perr(win_kind(&e), WHAT))?;
        let (model, serial, bus) = shown_identity(&on_handle);
        let was = &sh.chosen.found;
        if model != was.facts.identity.model
            || serial != was.facts.identity.serial
            || bus != was.facts.bus
            || table != was.discriminator.table
        {
            return Err(perr(PlatformErrorKind::IdentityMismatch, WHAT));
        }
        let rc = Rc::new(RefCell::new(raw));
        sh.locks = locks;
        sh.disk = Some(Rc::clone(&rc));
        Ok(OpenedTarget {
            facts: now.facts,
            device: Box::new(WinDisk(rc)),
        })
    }

    fn volumes(&mut self) -> &mut dyn VolumeOps {
        &mut self.volumes
    }

    fn boot_files(&mut self) -> &mut dyn BootFiles {
        &mut self.boot
    }

    fn firmware(&mut self) -> &mut dyn FirmwareVarsTrait {
        &mut self.firmware
    }
}

struct WinVolumes {
    shared: Rc<RefCell<Shared>>,
    system_dir: PathBuf,
    budget: WaitBudget,
}

/// Every volume's extents (volumes whose extents cannot be read are left
/// out: they cannot match).
fn all_extents() -> Result<(Vec<VolumeGuidPath>, Vec<Vec<wintools::Extent>>), WinApiError> {
    let vols = volume::volumes()?;
    let ext = vols
        .iter()
        .map(|v| {
            volume::disk_extents(v)
                .map(|e| {
                    e.iter()
                        .map(|x| (x.disk_number, x.starting_offset, x.length))
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect();
    Ok((vols, ext))
}

/// The one volume at exactly `start`/`len` on disk `n`, waited for up to
/// `limit`.
fn wait_for_volume(
    n: u32,
    start: u64,
    len: u64,
    limit: Duration,
) -> Result<VolumeGuidPath, PlatformError> {
    const WHAT: &str = "resolve volume from extents";
    let t0 = Instant::now();
    loop {
        if let Ok((vols, ext)) = all_extents() {
            match wintools::match_volume(&ext, n, start, len) {
                VolumeMatch::One(i) => {
                    return vols
                        .get(i)
                        .cloned()
                        .ok_or(perr(PlatformErrorKind::NotFound, WHAT));
                }
                VolumeMatch::None => {}
                VolumeMatch::Ambiguous => {
                    return Err(perr(PlatformErrorKind::IdentityMismatch, WHAT));
                }
            }
        }
        if t0.elapsed() >= limit {
            return Err(perr(PlatformErrorKind::NotFound, WHAT));
        }
        std::thread::sleep(VOLUME_POLL);
    }
}

/// Letters in use by any volume.
fn used_letters() -> Result<Vec<char>, PlatformError> {
    let vols = volume::volumes().map_err(|e| perr(win_kind(&e), "list volumes"))?;
    let mut used = vec!['X'];
    for v in vols {
        if let Ok(ls) = volume::drive_letters(&v) {
            used.extend(ls.iter().map(|l| l.letter()));
        }
    }
    Ok(used)
}

impl WinVolumes {
    fn format_one(&self, n: u32, spec: &VolumeSpec) -> Result<FormattedVolume, PlatformError> {
        let vol = wait_for_volume(
            n,
            spec.start_bytes,
            spec.size_bytes,
            self.budget.volume_arrival,
        )?;
        let letter = if spec.role == PartRole::Windows {
            self.assign_windows_letter(&vol)?
        } else {
            // Any free letter, never X: and never the reserved Windows one.
            let mut used = used_letters()?;
            used.extend(self.shared.borrow().windows_letter.map(DriveLetter::letter));
            let letter = wintools::pick_letter(&used)
                .and_then(DriveLetter::new)
                .ok_or(perr(PlatformErrorKind::Refused, "find a free drive letter"))?;
            volume::assign_letter(letter, &vol)
                .map_err(|e| perr(win_kind(&e), "assign a drive letter"))?;
            letter
        };
        // SEC-008: a new file with a random name (create-new: an existing
        // or planted file of that name is never reused or followed).
        let mut random = [0u8; 16];
        usgp_crypto::provider()
            .fill_random(&mut random)
            .map_err(|_| perr(PlatformErrorKind::Refused, "random script name"))?;
        let script = wintools::write_script_new(
            &std::env::temp_dir(),
            random,
            &wintools::diskpart_script(letter.letter(), spec.fs, spec.label),
        )
        .map_err(|e| perr(PlatformErrorKind::Io(e.kind()), "write the format script"))?;
        // BOOT-001: immediately before DiskPart starts, the letter must
        // still name the volume resolved above, at exactly the planned
        // extent on the chosen disk (REQ-DISK-015).
        // POAM: BOOT-001 residual - DiskPart opens the volume itself, so
        // our lock cannot be held across its start; a change in the few
        // milliseconds between this check and DiskPart's `select volume`
        // is caught only by the read-back below (file system, label,
        // extent), after the format.
        let at_letter = volume::volume_at(letter).ok();
        let extents: Vec<wintools::Extent> = volume::disk_extents(&vol)
            .map(|e| {
                e.iter()
                    .map(|x| (x.disk_number, x.starting_offset, x.length))
                    .collect()
            })
            .unwrap_or_default();
        if !wintools::letter_still_names(
            at_letter.as_ref().map(VolumeGuidPath::as_str),
            vol.as_str(),
            &extents,
            (n, spec.start_bytes, spec.size_bytes),
        ) {
            let _ = std::fs::remove_file(&script);
            return Err(perr(
                PlatformErrorKind::IdentityMismatch,
                "volume at the drive letter before formatting",
            ));
        }
        // `winpe.md` §11 (SR-7): DiskPart runs a command file with
        // `diskpart /s <file>` in Microsoft's deployment samples, though
        // the "diskpart" page does not describe `/s` (OPEN-WINPE-2), and
        // the exit-code values are not documented (OPEN-WINPE-3). The exit
        // status is therefore only a first filter: the real check is the
        // read-back below (file system, label, extent).
        let mut cmd = Command::new(self.system_dir.join("diskpart.exe"));
        cmd.arg("/s").arg(&script);
        let ran = wintools::run_bounded(cmd, self.budget.tool);
        // Best effort: the script holds only our letter, fs and label.
        let _ = std::fs::remove_file(&script);
        ran.map_err(|e| tool_err(e, "format volume"))?;
        // Read back: the file system, and that the volume is still the one
        // at our extent.
        let fs = volume::file_system_name(&vol)
            .map_err(|e| perr(win_kind(&e), "read the file system"))?;
        if !fs.eq_ignore_ascii_case(wintools::fs_name(spec.fs)) {
            return Err(perr(
                PlatformErrorKind::IdentityMismatch,
                "formatted file system",
            ));
        }
        // The label is read back too (topic 23 §15). Compared ignoring
        // ASCII case: whether a FAT32 label keeps its letter case is not in
        // the standards summaries, and the labels are fixed ASCII words.
        let label = volume::label(&vol).map_err(|e| perr(win_kind(&e), "read the volume label"))?;
        if !label.eq_ignore_ascii_case(spec.label) {
            return Err(perr(
                PlatformErrorKind::IdentityMismatch,
                "formatted volume label",
            ));
        }
        let again =
            volume::disk_extents(&vol).map_err(|e| perr(win_kind(&e), "read volume extents"))?;
        if !matches!(again.as_slice(), [x] if x.disk_number == n
            && x.starting_offset == spec.start_bytes
            && x.length == spec.size_bytes)
        {
            return Err(perr(
                PlatformErrorKind::IdentityMismatch,
                "formatted volume extents",
            ));
        }
        let locator = vol.as_str().to_owned();
        let root = if spec.role == PartRole::Recovery {
            None
        } else {
            let now = volume::drive_letters(&vol)
                .map_err(|e| perr(win_kind(&e), "read the volume's drive letters"))?;
            if !now.contains(&letter) {
                return Err(perr(
                    PlatformErrorKind::IdentityMismatch,
                    "volume drive letter",
                ));
            }
            Some(letter.root())
        };
        if spec.role == PartRole::Recovery {
            // The recovery volume keeps no letter (plan section 1.2(c)).
            volume::remove_letter(letter)
                .map_err(|e| perr(win_kind(&e), "remove the recovery letter"))?;
        } else {
            self.shared
                .borrow_mut()
                .letters
                .push((locator.clone(), letter));
        }
        Ok(FormattedVolume {
            spec: *spec,
            fs: match spec.fs {
                FileSystem::Fat32 => FileSystem::Fat32,
                _ => FileSystem::Ntfs,
            },
            // Read back and checked above; reported in the plan's spelling.
            label: spec.label.to_owned(),
            locator,
            root,
        })
    }
}

impl WinVolumes {
    /// Gives the new Windows volume the letter reserved in step 1. The
    /// volume is locked while the letter is checked and assigned, and the
    /// letter must be free or already this volume's (automatic mounting);
    /// anything else fails closed (WU-8 U-9).
    fn assign_windows_letter(&self, vol: &VolumeGuidPath) -> Result<DriveLetter, PlatformError> {
        let letter = self.shared.borrow().windows_letter.ok_or(perr(
            PlatformErrorKind::Refused,
            "Windows letter not reserved",
        ))?;
        let lock = volume::lock_and_dismount(vol)
            .map_err(|_| perr(PlatformErrorKind::Refused, "lock the new Windows volume"))?;
        let mine = volume::drive_letters(vol)
            .map_err(|e| perr(win_kind(&e), "read the volume's drive letters"))?;
        if !mine.contains(&letter) {
            if used_letters()?.contains(&letter.letter()) {
                return Err(perr(
                    PlatformErrorKind::IdentityMismatch,
                    "the reserved Windows drive letter was taken",
                ));
            }
            volume::assign_letter(letter, vol)
                .map_err(|e| perr(win_kind(&e), "assign the Windows drive letter"))?;
        }
        // Unlocked before DiskPart opens the volume to format it.
        drop(lock);
        Ok(letter)
    }
}

impl VolumeOps for WinVolumes {
    fn windows_root(&mut self) -> Result<String, PlatformError> {
        let mut sh = self.shared.borrow_mut();
        if let Some(l) = sh.windows_letter {
            return Ok(l.root());
        }
        // POAM: Windows has no call in usgp-winapi to hold a drive letter
        // with no volume behind it; the letter is held by this agent (never
        // given to another volume) and checked free again under the
        // volume's lock in `format` (fail closed if taken).
        let letter = wintools::pick_letter(&used_letters()?)
            .and_then(DriveLetter::new)
            .ok_or(perr(PlatformErrorKind::Refused, "find a free drive letter"))?;
        sh.windows_letter = Some(letter);
        Ok(letter.root())
    }

    fn format(
        &mut self,
        device: &mut dyn BlockDevice,
        _layout: &WindowsUefiLayout,
        specs: &[VolumeSpec],
        windows_root: &ApplyRoot,
    ) -> Result<Vec<FormattedVolume>, PlatformError> {
        // The root must be exactly the reserved letter (`L:`).
        let reserved = self.shared.borrow().windows_letter;
        if reserved.map(|l| l.to_string()) != Some(windows_root.to_text()) {
            return Err(perr(
                PlatformErrorKind::IdentityMismatch,
                "Windows apply root",
            ));
        }
        device
            .flush()
            .map_err(|e| perr(PlatformErrorKind::Io(e.kind()), "flush the disk"))?;
        let (disk, n) = {
            let sh = self.shared.borrow();
            (
                sh.disk.clone(),
                sh.chosen.found.facts.identity.device_number,
            )
        };
        let disk = disk.ok_or(perr(PlatformErrorKind::Refused, "format before open"))?;
        disk.borrow_mut()
            .update_properties()
            .map_err(|e| perr(win_kind(&e), "update disk properties"))?;
        // The old volumes are gone with the old table: release their locks.
        self.shared.borrow_mut().locks.clear();
        specs.iter().map(|s| self.format_one(n, s)).collect()
    }

    fn windows_sink(
        &mut self,
        windows: &FormattedVolume,
    ) -> Result<Box<dyn ApplySink + '_>, PlatformError> {
        let letter = self
            .shared
            .borrow()
            .letter_of(&windows.locator)
            .ok_or(perr(PlatformErrorKind::NotFound, "Windows volume letter"))?;
        let sink = usgp_winapi::winsink::WinSink::new(Path::new(&letter.root()))
            .map_err(|e| perr(win_kind(&e), "open the apply target"))?;
        Ok(Box::new(sink))
    }
}

struct WinBootFiles {
    shared: Rc<RefCell<Shared>>,
    budget: WaitBudget,
}

impl BootFiles for WinBootFiles {
    fn create(
        &mut self,
        esp: &FormattedVolume,
        windows: &FormattedVolume,
    ) -> Result<(), PlatformError> {
        let (e, w) = {
            let sh = self.shared.borrow();
            (sh.letter_of(&esp.locator), sh.letter_of(&windows.locator))
        };
        let (e, w) = e
            .zip(w)
            .ok_or(perr(PlatformErrorKind::NotFound, "boot volume letters"))?;
        let (program, args) = wintools::bcdboot_command(w.letter(), e.letter());
        if !program.is_file() {
            return Err(perr(
                PlatformErrorKind::NotFound,
                "BCDBoot in the applied image",
            ));
        }
        let mut cmd = Command::new(program);
        cmd.args(args);
        wintools::run_bounded(cmd, self.budget.tool).map_err(|e| tool_err(e, "BCDBoot"))?;
        let manager = Path::new(&e.root())
            .join("EFI")
            .join("Microsoft")
            .join("Boot")
            .join("bootmgfw.efi");
        if !manager.is_file() {
            return Err(perr(PlatformErrorKind::NotFound, "boot manager on the ESP"));
        }
        Ok(())
    }
}

struct WinFirmware<'h> {
    vars: Option<&'h mut FirmwareVars>,
}

/// The `usgp-winapi` variable for an engine name, after checking that both
/// layers agree on the namespace and attributes.
fn writable(name: &BootVarName) -> Result<WritableBootVar, FwError> {
    let v = name.vendor();
    let g = EFI_GLOBAL_VARIABLE;
    if v != Guid::from_fields(g.data1, g.data2, g.data3, g.data4)
        || name.attributes() != BOOT_VAR_ATTRIBUTES
    {
        return Err(FwError::Denied);
    }
    Ok(match name.option_number() {
        Some(n) => WritableBootVar::Boot(n),
        None => WritableBootVar::BootOrder,
    })
}

fn fw_err(e: &WinApiError) -> FwError {
    match e {
        WinApiError::NotUefi => FwError::Unsupported,
        WinApiError::PrivilegeNotHeld { .. } | WinApiError::Refused { .. } => FwError::Denied,
        WinApiError::LimitExceeded { .. } => FwError::TooLarge,
        WinApiError::Os { source, .. } if source.kind() == io::ErrorKind::PermissionDenied => {
            FwError::Denied
        }
        _ => FwError::Io,
    }
}

impl FirmwareVarsTrait for WinFirmware<'_> {
    fn get(&mut self, name: &BootVarName) -> Result<Option<Vec<u8>>, FwError> {
        let vars = self.vars.as_deref().ok_or(FwError::Unsupported)?;
        let var = ReadableVar::from(writable(name)?);
        vars.get(var)
            .map(|o| o.map(|v| v.data))
            .map_err(|e| fw_err(&e))
    }

    fn set(&mut self, name: &BootVarName, data: &[u8]) -> Result<(), FwError> {
        let var = writable(name)?;
        let vars = self.vars.as_deref_mut().ok_or(FwError::Unsupported)?;
        vars.set_boot_var(var, data).map_err(|e| fw_err(&e))
    }
}
