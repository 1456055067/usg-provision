//! Signed boot-policy list, version 1 (M3 plan section 3.6; decision 0021
//! item 2): the devices a boot service must stop offering a boot program
//! to, because their jobs succeeded (REQ-BOOT-067). Signed with the
//! server's **boot-policy key** (one key, one purpose), payload type
//! `application/vnd.usgp.boot-policy.v1+json`.
//!
//! The relay:
//!
//! 1. verifies the signature with its pinned key and parses
//!    ([`BootPolicyV1::open`]);
//! 2. checks the boot service and refuses a generation below its current
//!    one ([`BootPolicyV1::check_for`]);
//! 3. replaces its stop set atomically ([`BootPolicyV1::stop_set`]).
//!
//! On any error it keeps the last good list.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7(6) (Cryptographic Protection) - signed list; verify
//   before parse; separate key.
// - NIST 800-53: SC-23 (Session Authenticity) - rollback refused by
//   generation; list bound to one boot service.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded list,
//   unique MACs, strict parse.
// - NIST 800-53: CM-7 (Least Functionality) - no boot program offered to
//   provisioned devices.
// - SPEC: specs/boot-network.md#REQ-BOOT-067 (stop booting a device whose
//   install is done), #REQ-BOOT-060 (no network-boot loop)
// - Decision 0021 items 2 and 3

use std::collections::HashSet;

use usgp_common::Sha256Digest;

use crate::SignedManifestError;
use crate::device::MacAddress;
use crate::envelope::{PayloadType, SignatureVerifier, SignedEnvelopeV1};
use crate::ids::{BootServiceId, JobId, UnixMicros};
use crate::limits::{MAX_BOOT_STOPS, MAX_MANIFEST_PAYLOAD_BYTES};

/// The only boot-policy schema version.
pub const SCHEMA_V1: u32 = 1;

/// One stopped device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootStopEntryV1 {
    /// The device's MAC address.
    pub mac: MacAddress,
    /// The job that succeeded.
    pub job_id: JobId,
}

/// Boot-policy list, version 1.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPolicyV1 {
    /// Always [`SCHEMA_V1`].
    pub schema: u32,
    /// The boot service the list is for.
    pub boot_service_id: BootServiceId,
    /// Generation; increases with every change (at least 1).
    pub generation: u64,
    /// When it was signed.
    pub issued_at_us: UnixMicros,
    /// Key id (SHA-256 of the SPKI DER) of the boot-policy key.
    pub key_id: Sha256Digest,
    /// Stopped devices (at most [`MAX_BOOT_STOPS`], each MAC once).
    pub stops: Vec<BootStopEntryV1>,
}

/// Why a verified list is not applied. The relay keeps its last good list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum BootPolicyError {
    /// The list is for another boot service.
    #[error("boot-policy list is for another boot service")]
    WrongBootService,
    /// The generation is below the one already applied.
    #[error("boot-policy generation {got} is below the applied generation {have}")]
    Rollback {
        /// Applied generation.
        have: u64,
        /// Offered generation.
        got: u64,
    },
}

impl BootPolicyV1 {
    /// Checks every rule a v1 list must meet beyond its types.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::UnsupportedSchema`] or
    /// [`SignedManifestError::Invalid`].
    pub fn validate(&self) -> Result<(), SignedManifestError> {
        use SignedManifestError::Invalid;
        if self.schema != SCHEMA_V1 {
            return Err(SignedManifestError::UnsupportedSchema(self.schema));
        }
        if self.generation == 0 {
            return Err(Invalid("generation must be at least 1"));
        }
        if self.stops.len() > MAX_BOOT_STOPS {
            return Err(Invalid("stops must list at most 100000 devices"));
        }
        let mut seen = HashSet::with_capacity(self.stops.len());
        if !self.stops.iter().all(|s| seen.insert(s.mac)) {
            return Err(Invalid("stops must list each MAC address once"));
        }
        Ok(())
    }

    /// The exact bytes to sign: compact JSON in field order.
    ///
    /// # Errors
    ///
    /// As [`BootPolicyV1::validate`]; [`SignedManifestError::TooLarge`].
    pub fn to_payload(&self) -> Result<Vec<u8>, SignedManifestError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(SignedManifestError::Json)?;
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        Ok(bytes)
    }

    /// Parses and validates payload bytes (verified, or the relay's own
    /// cache file after it re-verifies the envelope; prefer
    /// [`BootPolicyV1::open`]).
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::TooLarge`] before parsing;
    /// [`SignedManifestError::Json`]; or as [`BootPolicyV1::validate`].
    pub fn from_payload(bytes: &[u8]) -> Result<Self, SignedManifestError> {
        if bytes.len() > MAX_MANIFEST_PAYLOAD_BYTES {
            return Err(SignedManifestError::TooLarge { len: bytes.len() });
        }
        let p: Self = serde_json::from_slice(bytes).map_err(SignedManifestError::Json)?;
        p.validate()?;
        Ok(p)
    }

    /// Verifies the envelope with the pinned boot-policy key, then parses
    /// and validates, then checks that `key_id` is the verifying key.
    ///
    /// # Errors
    ///
    /// [`SignedManifestError::Envelope`] if verification fails (nothing is
    /// parsed); otherwise as [`BootPolicyV1::from_payload`], or
    /// [`SignedManifestError::KeyIdMismatch`].
    pub fn open(
        envelope: &SignedEnvelopeV1,
        verifier: &dyn SignatureVerifier,
    ) -> Result<Self, SignedManifestError> {
        let verified = envelope.verified_payload(PayloadType::BootPolicyV1, verifier)?;
        let p = Self::from_payload(verified.bytes)?;
        if p.key_id != verified.key_id {
            return Err(SignedManifestError::KeyIdMismatch);
        }
        Ok(p)
    }

    /// Checks that the list is for `boot_service_id` and not older than
    /// `applied_generation` (the relay's current one, if any). An equal
    /// generation is accepted (it is the same list).
    ///
    /// # Errors
    ///
    /// [`BootPolicyError`].
    pub fn check_for(
        &self,
        boot_service_id: BootServiceId,
        applied_generation: Option<u64>,
    ) -> Result<(), BootPolicyError> {
        if self.boot_service_id != boot_service_id {
            return Err(BootPolicyError::WrongBootService);
        }
        if let Some(have) = applied_generation
            && self.generation < have
        {
            return Err(BootPolicyError::Rollback {
                have,
                got: self.generation,
            });
        }
        Ok(())
    }

    /// The stopped MAC addresses, for an atomic swap of the relay's set.
    #[must_use]
    pub fn stop_set(&self) -> HashSet<MacAddress> {
        self.stops.iter().map(|s| s.mac).collect()
    }
}
