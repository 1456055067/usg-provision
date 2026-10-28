//! A simulated platform for the agent's simulation tests (feature `sim`;
//! plan WU-8 and section 10.1 `agent-sim-e2e`). Never in a release build.
//!
//! - Disks are **regular files** opened through
//!   [`usgp_disk::FileBlockDevice`], which refuses anything that is not a
//!   regular file, so the simulation can never reach a real disk.
//! - "Formatting" creates one empty directory per volume under a work
//!   directory, after checking that the GPT just written has a partition
//!   at the volume's offset; the Windows volume's directory is the apply
//!   target ([`usgp_image::apply::DirSink`]).
//! - Boot-file creation writes a marker file under the ESP directory.
//! - Firmware variables live in a JSON file: an object from variable name
//!   (`BootOrder`, `Boot####`) to the value in lower-case hex.

// COMPLIANCE MAPPING:
// - NIST 800-53: CM-7 (Least Functionality) - test-only feature; regular
//   files only.
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/disk.md#REQ-DISK-015 (only the chosen disk file is opened
//   for writing)

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use usgp_disk::gpt::{GptLimits, parse_gpt};
use usgp_disk::layout::{PartRole, WindowsUefiLayout};
use usgp_disk::uefi::BootVarName;
use usgp_disk::{BlockDevice, DiskFacts, FileBlockDevice};
use usgp_image::apply::{ApplyRoot, ApplySink, DirSink, ReparseBuffer, SinkResult};
use usgp_image::wim::metadata::{Attributes, FileTimes};
use usgp_image::wim::names::{ImagePath, ShortName, StreamName};
use usgp_proto::DiskToken;
use usgp_proto::disk::PlanDiskV1;

use crate::platform::{
    BootFiles, FirmwareVars, FormattedVolume, FwError, OpenedTarget, Platform, PlatformError,
    PlatformErrorKind, VolumeOps, VolumeSpec,
};

/// Largest firmware JSON file read (design bound).
const MAX_FIRMWARE_FILE_BYTES: u64 = 1 << 20;

fn io_err(what: &'static str) -> impl Fn(io::Error) -> PlatformError {
    move |e| PlatformError::new(PlatformErrorKind::Io(e.kind()), what)
}

/// A disk file the simulation offers.
#[derive(Debug, Clone)]
pub struct SimDisk {
    /// The token the agent gave this disk in its enumeration.
    pub token: DiskToken,
    /// The regular file holding the disk image.
    pub path: PathBuf,
    /// The facts reported for it.
    pub facts: DiskFacts,
}

/// A reparse buffer the simulated apply target received (a directory
/// cannot hold one, so it is recorded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimReparse {
    /// The path, `\`-separated, relative to the Windows volume.
    pub path: String,
    /// The whole reparse buffer as the platform would set it.
    pub bytes: Vec<u8>,
    /// `true` if the target was re-based onto the apply root.
    pub rebased: bool,
}

/// Volumes as directories under a work directory.
#[derive(Debug)]
pub struct SimVolumes {
    root: PathBuf,
    windows_root: String,
    reparse: Vec<SimReparse>,
}

/// [`DirSink`] plus a record of the reparse buffers it was given.
struct RecordingSink<'a> {
    dir: DirSink,
    log: &'a mut Vec<SimReparse>,
}

impl ApplySink for RecordingSink<'_> {
    fn create_dir(&mut self, p: &ImagePath) -> SinkResult {
        self.dir.create_dir(p)
    }
    fn create_file(&mut self, p: &ImagePath) -> SinkResult {
        self.dir.create_file(p)
    }
    fn create_stream(&mut self, p: &ImagePath, s: &StreamName) -> SinkResult {
        self.dir.create_stream(p, s)
    }
    fn write(
        &mut self,
        p: &ImagePath,
        s: Option<&StreamName>,
        off: u64,
        data: &[u8],
    ) -> SinkResult {
        self.dir.write(p, s, off, data)
    }
    fn hard_link(&mut self, a: &ImagePath, b: &ImagePath) -> SinkResult {
        self.dir.hard_link(a, b)
    }
    fn set_reparse(&mut self, p: &ImagePath, buf: &ReparseBuffer) -> SinkResult {
        self.log.push(SimReparse {
            path: p
                .components()
                .iter()
                .map(|c| c.as_str())
                .collect::<Vec<_>>()
                .join("\\"),
            bytes: buf.bytes().to_vec(),
            rebased: buf.rebased(),
        });
        self.dir.set_reparse(p, buf)
    }
    fn set_security(&mut self, p: &ImagePath, sd: &[u8]) -> SinkResult {
        self.dir.set_security(p, sd)
    }
    fn set_short_name(&mut self, p: &ImagePath, n: &ShortName) -> SinkResult {
        self.dir.set_short_name(p, n)
    }
    fn set_times(&mut self, p: &ImagePath, t: &FileTimes) -> SinkResult {
        self.dir.set_times(p, t)
    }
    fn set_attributes(&mut self, p: &ImagePath, a: Attributes) -> SinkResult {
        self.dir.set_attributes(p, a)
    }
}

/// Boot files as a marker file.
#[derive(Debug)]
pub struct SimBootFiles {
    root: PathBuf,
}

/// Firmware variables in a JSON file.
#[derive(Debug)]
pub struct JsonFirmware {
    path: PathBuf,
}

/// The simulated platform.
#[derive(Debug)]
pub struct SimPlatform {
    disks: Vec<SimDisk>,
    volumes: SimVolumes,
    boot: SimBootFiles,
    firmware: JsonFirmware,
}

impl SimPlatform {
    /// A platform whose volumes live under `work` (an existing directory)
    /// and whose firmware variables are in `firmware_file`.
    #[must_use]
    pub fn new(work: &Path, firmware_file: &Path) -> Self {
        Self {
            disks: Vec::new(),
            volumes: SimVolumes {
                root: work.to_path_buf(),
                windows_root: "W:\\".to_owned(),
                reparse: Vec::new(),
            },
            boot: SimBootFiles {
                root: work.to_path_buf(),
            },
            firmware: JsonFirmware {
                path: firmware_file.to_path_buf(),
            },
        }
    }

    /// The drive-letter root the Windows volume is promised (default
    /// `W:\`). Any text is passed through, so tests can offer a bad one.
    pub fn set_windows_root(&mut self, text: &str) {
        self.volumes.windows_root = text.to_owned();
    }

    /// Reparse buffers the apply target received, in order.
    #[must_use]
    pub fn reparse_log(&self) -> &[SimReparse] {
        &self.volumes.reparse
    }

    /// Offers `disk`.
    pub fn add_disk(&mut self, disk: SimDisk) {
        self.disks.push(disk);
    }

    /// The directory a formatted volume is simulated in.
    #[must_use]
    pub fn volume_dir(&self, v: &FormattedVolume) -> PathBuf {
        self.volumes.root.join(&v.locator)
    }
}

impl Platform for SimPlatform {
    fn open_target(&mut self, want: &PlanDiskV1) -> Result<OpenedTarget, PlatformError> {
        let d = self
            .disks
            .iter()
            .find(|d| d.token == want.disk_token)
            .ok_or(PlatformError::new(
                PlatformErrorKind::IdentityMismatch,
                "open target disk",
            ))?;
        let dev = FileBlockDevice::open(&d.path, d.facts.logical_sector, true)
            .map_err(io_err("open target disk"))?;
        Ok(OpenedTarget {
            facts: d.facts.clone(),
            device: Box::new(dev),
        })
    }

    fn volumes(&mut self) -> &mut dyn VolumeOps {
        &mut self.volumes
    }

    fn boot_files(&mut self) -> &mut dyn BootFiles {
        &mut self.boot
    }

    fn firmware(&mut self) -> &mut dyn FirmwareVars {
        &mut self.firmware
    }
}

impl VolumeOps for SimVolumes {
    fn windows_root(&mut self) -> Result<String, PlatformError> {
        Ok(self.windows_root.clone())
    }

    fn format(
        &mut self,
        device: &mut dyn BlockDevice,
        layout: &WindowsUefiLayout,
        specs: &[VolumeSpec],
        windows_root: &ApplyRoot,
    ) -> Result<Vec<FormattedVolume>, PlatformError> {
        // Resolve each volume from the table on the disk, as the real
        // platform resolves it from the partition's extents.
        let view = parse_gpt(device, &GptLimits::default())
            .map_err(|_| PlatformError::new(PlatformErrorKind::NotFound, "read partition table"))?;
        let block = u64::from(layout.block);
        let mut out = Vec::with_capacity(specs.len());
        for spec in specs {
            let present = view.entries.iter().any(|(_, e)| {
                e.first_lba.saturating_mul(block) == spec.start_bytes
                    && e.len_lbas().map(|n| n.saturating_mul(block)) == Some(spec.size_bytes)
            });
            if !present {
                return Err(PlatformError::new(
                    PlatformErrorKind::NotFound,
                    "resolve volume from extents",
                ));
            }
            let locator = format!("vol-{}", spec.number);
            fs::create_dir(self.root.join(&locator)).map_err(io_err("format volume"))?;
            // The simulated letter: as promised for Windows, none otherwise.
            let root =
                (spec.role == PartRole::Windows).then(|| format!("{}\\", windows_root.to_text()));
            out.push(FormattedVolume {
                spec: *spec,
                fs: spec.fs,
                label: spec.label.to_owned(),
                locator,
                root,
            });
        }
        Ok(out)
    }

    fn windows_sink(
        &mut self,
        windows: &FormattedVolume,
    ) -> Result<Box<dyn ApplySink + '_>, PlatformError> {
        let dir =
            DirSink::new(&self.root.join(&windows.locator)).map_err(io_err("open apply target"))?;
        Ok(Box::new(RecordingSink {
            dir,
            log: &mut self.reparse,
        }))
    }
}

/// The marker file's path under the ESP directory.
pub const SIM_BOOT_MARKER: &str = "EFI/Microsoft/Boot/usgp-sim-boot-files";

impl BootFiles for SimBootFiles {
    fn create(
        &mut self,
        esp: &FormattedVolume,
        windows: &FormattedVolume,
    ) -> Result<(), PlatformError> {
        let win = self.root.join(&windows.locator);
        if !win.is_dir() {
            return Err(PlatformError::new(
                PlatformErrorKind::NotFound,
                "applied Windows volume",
            ));
        }
        let marker = self.root.join(&esp.locator).join(SIM_BOOT_MARKER);
        if let Some(dir) = marker.parent() {
            fs::create_dir_all(dir).map_err(io_err("create boot files"))?;
        }
        fs::write(&marker, windows.locator.as_bytes()).map_err(io_err("create boot files"))
    }
}

impl JsonFirmware {
    fn load(&self) -> Result<BTreeMap<String, String>, FwError> {
        let meta = match fs::metadata(&self.path) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
            Err(_) => return Err(FwError::Io),
        };
        if meta.len() > MAX_FIRMWARE_FILE_BYTES {
            return Err(FwError::TooLarge);
        }
        let bytes = fs::read(&self.path).map_err(|_| FwError::Io)?;
        serde_json::from_slice(&bytes).map_err(|_| FwError::Io)
    }

    fn store(&self, map: &BTreeMap<String, String>) -> Result<(), FwError> {
        let bytes = serde_json::to_vec_pretty(map).map_err(|_| FwError::Io)?;
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, bytes).map_err(|_| FwError::Io)?;
        fs::rename(&tmp, &self.path).map_err(|_| FwError::Io)
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One hex digit; signs and anything else are refused.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[hi, lo]| Some(hex_digit(hi)? << 4 | hex_digit(lo)?))
        .collect()
}

impl FirmwareVars for JsonFirmware {
    fn get(&mut self, name: &BootVarName) -> Result<Option<Vec<u8>>, FwError> {
        match self.load()?.get(&name.to_string()) {
            Some(h) => from_hex(h).map(Some).ok_or(FwError::Io),
            None => Ok(None),
        }
    }

    fn set(&mut self, name: &BootVarName, data: &[u8]) -> Result<(), FwError> {
        if data.is_empty() {
            return Err(FwError::Io);
        }
        let mut map = self.load()?;
        map.insert(name.to_string(), to_hex(data));
        self.store(&map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_and_refusals() {
        let b = [0u8, 1, 0xab, 0xff];
        assert_eq!(from_hex(&to_hex(&b)), Some(b.to_vec()));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("+1"), None);
    }
}
