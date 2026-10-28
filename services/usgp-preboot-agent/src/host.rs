//! What the agent needs from the machine it runs on, beyond the engine's
//! [`Platform`]: facts for the session hello, the network wait, the disk
//! inventory, the engine platform for the chosen disk, and restart or
//! shutdown.
//!
//! Implemented on `usgp-winapi` for Windows PE (`platform_win`) and by the
//! simulation for CI (`sim`).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - the platform is built for the one chosen disk.
// - SPEC: specs/preinstall-env.md#REQ-PE-014, #REQ-PE-019, #REQ-PE-020
// - SPEC: specs/disk.md#REQ-DISK-015

use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

use usgp_deploy::{EngineConfig, Platform};
use usgp_disk::EligibilityPolicy;
use usgp_proto::device::{DeviceArch, FirmwareKind, MacAddress, SecureBootState};

use crate::disks::{DiskEntry, FoundDisk};

/// What the device says about itself in the hello (every value is a
/// claim; plan section 3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    /// Firmware the environment booted from.
    pub firmware: FirmwareKind,
    /// Processor architecture.
    pub arch: DeviceArch,
    /// Secure Boot state.
    pub secure_boot: SecureBootState,
    /// Installed memory in bytes (0 if unknown).
    pub memory_bytes: u64,
    /// Reportable MAC addresses (1 to 16).
    pub macs: Vec<MacAddress>,
}

/// Restart or shut down (`wpeutil` on Windows PE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerAction {
    /// Restart the device.
    Restart,
    /// Shut the device down.
    Shutdown,
}

/// Limits on the platform's own waits (DiskPart, BCDBoot, volume
/// arrival), set below the job plan's step and stall limits (WU-8 POAM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitBudget {
    /// Most time one external tool may run.
    pub tool: Duration,
    /// Most time to wait for a new volume to appear.
    pub volume_arrival: Duration,
}

impl Default for WaitBudget {
    fn default() -> Self {
        Self {
            tool: Duration::from_secs(900),
            volume_arrival: Duration::from_secs(60),
        }
    }
}

/// A host failure: fixed text only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostError(pub String);

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HostError {}

/// The machine.
pub trait Host {
    /// Facts for the hello.
    ///
    /// # Errors
    ///
    /// [`HostError`] if they cannot be read (no MAC, for example).
    fn facts(&mut self) -> Result<HostFacts, HostError>;

    /// The usable DHCP-assigned IPv4 addresses now (REQ-PE-014). Polled
    /// by the bounded network wait.
    ///
    /// # Errors
    ///
    /// [`HostError`].
    fn dhcp_addresses(&mut self) -> Result<Vec<Ipv4Addr>, HostError>;

    /// The disks now (facts only; no content, REQ-DISK-016).
    ///
    /// # Errors
    ///
    /// [`HostError`]; the enumeration fails closed.
    fn disks(&mut self) -> Result<Vec<FoundDisk>, HostError>;

    /// The release eligibility rules (tests may allow file-backed disks).
    fn eligibility(&self) -> EligibilityPolicy {
        EligibilityPolicy::default()
    }

    /// The engine settings.
    fn engine_config(&self) -> EngineConfig {
        EngineConfig {
            eligibility: self.eligibility(),
            ..EngineConfig::default()
        }
    }

    /// The engine platform for `chosen` (the only disk it may open for
    /// writing), with its waits bounded by `budget`.
    ///
    /// # Errors
    ///
    /// [`HostError`].
    fn platform(
        &mut self,
        chosen: &DiskEntry,
        budget: WaitBudget,
    ) -> Result<Box<dyn Platform + '_>, HostError>;

    /// Restarts or shuts down the device. Returns only if that failed, or
    /// in the simulation.
    ///
    /// # Errors
    ///
    /// [`HostError`].
    fn power(&mut self, action: PowerAction) -> Result<(), HostError>;
}
