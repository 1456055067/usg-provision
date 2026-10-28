//! Which packages a device session is offered (REQ-TGT-001 to 003).
//!
//! A package is offered only if all of these hold, checked on every
//! listing, choice and confirmation (not cached):
//!
//! 1. it is assigned to the session's boot service, which is active
//!    (REQ-TGT-001);
//! 2. it is Ready, and its signed package manifest verifies; its image and
//!    PE are Ready and their signed content manifests verify and match
//!    their records (REQ-TGT-002, REQ-IMG-050);
//! 3. the device reports UEFI and x64, the PE is x64 and the edition is
//!    declared x64 (REQ-TGT-003, M3 scope);
//! 4. the content manifest states the edition's expanded size, which the
//!    disk minimum needs (REQ-DISK-004); without it the package is not
//!    offered (fail closed).
//!
//! The smallest disk offered for a package is the larger of the fixed
//! minimum (64 × 10⁹ bytes) and the fixed layout plus the edition's
//! expanded size (REQ-DISK-004, plan section 3.9).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, AC-4 - only the boot service's packages, only to an
//   authorised session.
// - NIST 800-53: SI-7, SI-7(6) - signed package and content manifests
//   verified before a package is offered.
// - SPEC: specs/targeting.md#REQ-TGT-001, #REQ-TGT-002, #REQ-TGT-003,
//   #REQ-TGT-008; specs/disk.md#REQ-DISK-004

use usgp_common::Sha256Digest;
use usgp_db::{Content, DeviceSession, RepoTx, StoredManifest};
use usgp_proto::device::{DeviceArch, DeviceOsV1, DevicePackageV1, FirmwareKind};
use usgp_proto::job_plan::LayoutPolicyV1;
use usgp_proto::ops::BootServiceStatus;
use usgp_proto::{Architecture, ContentState, EditionIndex, PackageId, PackageStatus, WimText};

use crate::context::Api;
use crate::error::ApiError;
use crate::handlers::content::verified_manifest;
use crate::manifest::open_package;

const MIB: u64 = 1024 * 1024;

/// The fixed layout's size besides the Windows partition, with alignment
/// and the backup GPT: 1 MiB head, ESP (300 MiB, the 4K-native size), MSR
/// 16 MiB, recovery 990 MiB, 1 MiB tail (REQ-DISK-008, REQ-DISK-010).
pub(crate) fn layout_overhead_bytes() -> u64 {
    let p = LayoutPolicyV1::STANDARD;
    let mib =
        1 + u64::from(p.esp_mib_4k) + u64::from(p.msr_mib) + u64::from(p.recovery_min_mib) + 1;
    mib.saturating_mul(MIB)
}

/// The smallest disk for an edition of `total_bytes` (REQ-DISK-004).
pub(crate) fn required_disk_bytes(total_bytes: u64) -> u64 {
    LayoutPolicyV1::STANDARD
        .min_disk_bytes
        .max(total_bytes.saturating_add(layout_overhead_bytes()))
}

/// One offered package with everything a plan needs.
#[derive(Debug, Clone)]
pub(crate) struct Offer {
    /// The device's view.
    pub view: DevicePackageV1,
    /// The image content.
    pub image: Content,
    /// The image's stored (signed) content manifest.
    pub stored_content_manifest: StoredManifest,
    /// SHA-256 of the package manifest payload.
    pub package_manifest_sha256: Sha256Digest,
    /// The edition.
    pub edition_index: EditionIndex,
    /// Its name (from the verified content manifest).
    pub edition_name: WimText,
    /// Its expanded size (from the verified content manifest).
    pub total_bytes: u64,
}

/// Why a session is offered nothing (REQ-TGT-008), for the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NoOffer {
    /// The source address matched no single active boot service.
    NoBootService,
    /// The device is not UEFI on x64 (REQ-TGT-003).
    DeviceUnsupported,
}

impl NoOffer {
    pub(crate) const fn reason(self) -> &'static str {
        match self {
            Self::NoBootService => "no_boot_service",
            Self::DeviceUnsupported => "firmware_unsupported",
        }
    }
}

/// The packages offered to `s` now, in assignment order.
pub(crate) async fn offered<S: usgp_db::Store + 'static, T: RepoTx>(
    api: &Api<S>,
    tx: &mut T,
    s: &DeviceSession,
) -> Result<Result<Vec<Offer>, NoOffer>, ApiError> {
    let Some(bs_id) = s.boot_service_id else {
        return Ok(Err(NoOffer::NoBootService));
    };
    match tx.boot_service(bs_id).await? {
        Some(b) if b.status == BootServiceStatus::Active => {}
        _ => return Ok(Err(NoOffer::NoBootService)),
    }
    if s.firmware != FirmwareKind::Uefi || s.arch != DeviceArch::X64 {
        return Ok(Err(NoOffer::DeviceUnsupported));
    }
    let mut out = Vec::new();
    for a in tx.boot_service_packages(bs_id).await? {
        if let Some(o) = offer(api, tx, a.package_id).await? {
            out.push(o);
        }
    }
    Ok(Ok(out))
}

/// The offer for one package, or `None` if it is not usable.
async fn offer<S: usgp_db::Store + 'static, T: RepoTx>(
    api: &Api<S>,
    tx: &mut T,
    id: PackageId,
) -> Result<Option<Offer>, ApiError> {
    let Some(p) = tx.package(id).await? else {
        return Ok(None);
    };
    if p.status != PackageStatus::Ready {
        return Ok(None);
    }
    let Some(pm) = &p.manifest else {
        return Ok(None);
    };
    if open_package(api.keys(), pm).is_err() {
        return Ok(None);
    }
    let (Some(image), Some(pe)) = (tx.content(p.image_id).await?, tx.content(p.pe_id).await?)
    else {
        return Ok(None);
    };
    if image.state != ContentState::Ready || pe.state != ContentState::Ready {
        return Ok(None);
    }
    let (Ok(cm), Ok(_)) = (verified_manifest(api, &image), verified_manifest(api, &pe)) else {
        return Ok(None);
    };
    if pe
        .pe
        .as_ref()
        .is_none_or(|d| d.architecture.value != Architecture::X64)
    {
        return Ok(None);
    }
    let Some(edition) = tx.edition(p.image_id, p.edition_index).await? else {
        return Ok(None);
    };
    let Some(decl) = &edition.declaration else {
        return Ok(None);
    };
    if decl.facts.architecture.value != Architecture::X64 {
        return Ok(None);
    }
    let Ok(edition_index) = EditionIndex::new(u64::from(p.edition_index)) else {
        return Ok(None);
    };
    let Some(me) = cm.wim.editions.iter().find(|e| e.index == edition_index) else {
        return Ok(None);
    };
    let Some(total_bytes) = me.total_bytes else {
        return Ok(None);
    };
    let Some(stored) = image.manifest.clone() else {
        return Ok(None);
    };
    let view = DevicePackageV1 {
        package_id: p.id,
        revision: p.revision,
        name: p.name.clone(),
        description: p.description.clone(),
        os: DeviceOsV1::from_facts(&decl.facts),
        image_bytes: image.size,
        required_disk_bytes: required_disk_bytes(total_bytes),
    };
    Ok(Some(Offer {
        view,
        package_manifest_sha256: usgp_crypto::sha256(&pm.payload),
        edition_name: me.name.clone(),
        stored_content_manifest: stored,
        image,
        edition_index,
        total_bytes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_minimum() {
        assert_eq!(required_disk_bytes(1000), 64_000_000_000);
        let big = 100_000_000_000;
        assert_eq!(
            required_disk_bytes(big),
            big + (1 + 300 + 16 + 990 + 1) * MIB
        );
        assert_eq!(required_disk_bytes(u64::MAX), u64::MAX);
    }
}
