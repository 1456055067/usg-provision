//! Permissions and the one built-in role (REQ-RBAC-001, REQ-RBAC-004).
//!
//! M3 adds the code, device-session, job, boot-service and boot-stop
//! permissions (plan M3 section 3.5). A boot service (relay) is not an
//! operator and holds none of these; its one route is marked
//! [`crate::routes::Access::BootService`].
//!
//! The permission set is fixed and closed. M2 has one role,
//! `administrator`, which holds every permission. An operator holds that
//! role or none; an operator with no role is refused (403) on every route,
//! which is how REQ-RBAC-003 is exercised without further roles. Roles for
//! viewing without change (REQ-RBAC-002) are OPEN and not built.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - every route names one of
//   these permissions; the router enforces it before the handler runs.
// - NIST 800-53: AC-6 (Least Privilege) - no role means no permission.
// - SPEC: specs/operator-access.md#REQ-RBAC-001, #REQ-RBAC-003,
//   #REQ-RBAC-004
// - SPEC: specs/targeting.md#REQ-TGT-001, #REQ-TGT-013, #REQ-TGT-014;
//   specs/progress.md#REQ-JOB-001; specs/boot-network.md#REQ-BOOT-067

use usgp_db::OperatorRole;

/// One content action (REQ-RBAC-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Permission {
    /// Read the server's stated limits.
    LimitsView,
    /// Upload an image file; declare its editions.
    ImageUpload,
    /// View image files; download and read their manifests.
    ImageView,
    /// Delete an image file.
    ImageDelete,
    /// Import a preinstall environment.
    PeImport,
    /// View preinstall environments; download and read their manifests.
    PeView,
    /// Delete a preinstall environment.
    PeDelete,
    /// View packages and their manifests.
    PackageView,
    /// Create a package.
    PackageCreate,
    /// Edit a package.
    PackageEdit,
    /// Clone a package.
    PackageClone,
    /// Delete a package.
    PackageDelete,
    /// Issue a single-use device code (M3, REQ-TGT-013).
    AuthCodeIssue,
    /// List codes (never their values).
    AuthCodeView,
    /// Revoke an unused code.
    AuthCodeRevoke,
    /// View device sessions (REQ-TGT-014, REQ-TGT-016).
    DeviceSessionView,
    /// Approve or refuse a waiting device session (REQ-TGT-014).
    DeviceSessionApprove,
    /// View jobs (REQ-JOB-001).
    JobView,
    /// Acknowledge a failed job.
    JobAcknowledge,
    /// Fail a running or lost job (finding SEC-012: releases the MACs it
    /// claims).
    JobFail,
    /// View boot services and their packages (REQ-TGT-001, REQ-TGT-008).
    BootServiceView,
    /// Set the packages a boot service offers (REQ-TGT-001).
    BootServiceAssign,
    /// View boot stops (REQ-BOOT-067).
    BootStopView,
    /// Clear a boot stop, the minimal reversal of REQ-BOOT-067.
    DeviceBootReenable,
}

impl Permission {
    /// Every permission.
    pub const ALL: &'static [Self] = &[
        Self::LimitsView,
        Self::ImageUpload,
        Self::ImageView,
        Self::ImageDelete,
        Self::PeImport,
        Self::PeView,
        Self::PeDelete,
        Self::PackageView,
        Self::PackageCreate,
        Self::PackageEdit,
        Self::PackageClone,
        Self::PackageDelete,
        Self::AuthCodeIssue,
        Self::AuthCodeView,
        Self::AuthCodeRevoke,
        Self::DeviceSessionView,
        Self::DeviceSessionApprove,
        Self::JobView,
        Self::JobAcknowledge,
        Self::JobFail,
        Self::BootServiceView,
        Self::BootServiceAssign,
        Self::BootStopView,
        Self::DeviceBootReenable,
    ];

    /// Stable name (audit detail).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LimitsView => "limits.view",
            Self::ImageUpload => "image.upload",
            Self::ImageView => "image.view",
            Self::ImageDelete => "image.delete",
            Self::PeImport => "pe.import",
            Self::PeView => "pe.view",
            Self::PeDelete => "pe.delete",
            Self::PackageView => "package.view",
            Self::PackageCreate => "package.create",
            Self::PackageEdit => "package.edit",
            Self::PackageClone => "package.clone",
            Self::PackageDelete => "package.delete",
            Self::AuthCodeIssue => "auth_code.issue",
            Self::AuthCodeView => "auth_code.view",
            Self::AuthCodeRevoke => "auth_code.revoke",
            Self::DeviceSessionView => "device_session.view",
            Self::DeviceSessionApprove => "device_session.approve",
            Self::JobView => "job.view",
            Self::JobAcknowledge => "job.acknowledge",
            Self::JobFail => "job.fail",
            Self::BootServiceView => "boot_service.view",
            Self::BootServiceAssign => "boot_service.assign",
            Self::BootStopView => "boot_stop.view",
            Self::DeviceBootReenable => "device.boot_reenable",
        }
    }
}

/// The permissions a role grants. `None` (no role) grants nothing.
#[must_use]
pub const fn role_permissions(role: Option<OperatorRole>) -> &'static [Permission] {
    match role {
        Some(OperatorRole::Administrator) => Permission::ALL,
        None => &[],
    }
}

/// True if `role` grants `p`.
#[must_use]
pub fn allows(role: Option<OperatorRole>, p: Permission) -> bool {
    role_permissions(role).contains(&p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrator_holds_every_permission_none_holds_nothing() {
        for &p in Permission::ALL {
            assert!(allows(Some(OperatorRole::Administrator), p), "{p:?}");
            assert!(!allows(None, p), "{p:?}");
        }
        let names: std::collections::HashSet<_> =
            Permission::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(names.len(), Permission::ALL.len());
    }
}
