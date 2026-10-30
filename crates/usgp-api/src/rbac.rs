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
//!
//! M4 (plan section 1.3, follow-up U-2) adds a second role,
//! `escrow_officer`, and the permissions of the M4 routes. Separation of
//! duties: `escrow.reveal` is held by `escrow_officer` alone, never by
//! `administrator`, and an operator holds one role. No API route grants
//! or changes a role; roles are written only by the server's local
//! enrolment command. The self-grant guard is enforced at the point of
//! use ([`self_granted`]): an escrow officer whose certificate subject is
//! also an active administrator's is refused the reveal.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - every route names one of
//   these permissions; the router enforces it before the handler runs.
// - NIST 800-53: AC-6 (Least Privilege) - no role means no permission.
// - SPEC: specs/operator-access.md#REQ-RBAC-001, #REQ-RBAC-003,
//   #REQ-RBAC-004
// - SPEC: specs/targeting.md#REQ-TGT-001, #REQ-TGT-013, #REQ-TGT-014;
//   specs/progress.md#REQ-JOB-001; specs/boot-network.md#REQ-BOOT-067
// - NIST 800-53: AC-5 (Separation of Duties) - the escrow reveal is held
//   by `escrow_officer` only, and an administrator cannot hold it through
//   a second certificate in their own name (M4 plan section 1.3).
// - SPEC: specs/configuration.md#REQ-CFG-010; Decision 0024 item 1

use usgp_db::{Operator, OperatorRole, OperatorStatus};

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
    /// Register, list and revoke agent-package signer keys (M4, admin).
    AgentSignerManage,
    /// Set and delete per-device values (M4).
    DeviceValueManage,
    /// View per-device values (M4).
    DeviceValueView,
    /// Reveal an escrowed administrator password (M4; `escrow_officer`
    /// only).
    EscrowReveal,
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
        Self::AgentSignerManage,
        Self::DeviceValueManage,
        Self::DeviceValueView,
        Self::EscrowReveal,
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
            Self::AgentSignerManage => "agent_signer.manage",
            Self::DeviceValueManage => "device_value.manage",
            Self::DeviceValueView => "device_value.view",
            Self::EscrowReveal => "escrow.reveal",
        }
    }
}

/// The administrator's permissions: every one but [`Permission::EscrowReveal`].
const ADMINISTRATOR: &[Permission] = &[
    Permission::LimitsView,
    Permission::ImageUpload,
    Permission::ImageView,
    Permission::ImageDelete,
    Permission::PeImport,
    Permission::PeView,
    Permission::PeDelete,
    Permission::PackageView,
    Permission::PackageCreate,
    Permission::PackageEdit,
    Permission::PackageClone,
    Permission::PackageDelete,
    Permission::AuthCodeIssue,
    Permission::AuthCodeView,
    Permission::AuthCodeRevoke,
    Permission::DeviceSessionView,
    Permission::DeviceSessionApprove,
    Permission::JobView,
    Permission::JobAcknowledge,
    Permission::JobFail,
    Permission::BootServiceView,
    Permission::BootServiceAssign,
    Permission::BootStopView,
    Permission::DeviceBootReenable,
    Permission::AgentSignerManage,
    Permission::DeviceValueManage,
    Permission::DeviceValueView,
];

/// The escrow officer's permissions: the reveal, and the job view needed
/// to find the job and read the escrow metadata.
const ESCROW_OFFICER: &[Permission] = &[Permission::EscrowReveal, Permission::JobView];

/// The permissions a role grants. `None` (no role) grants nothing.
#[must_use]
pub const fn role_permissions(role: Option<OperatorRole>) -> &'static [Permission] {
    match role {
        Some(OperatorRole::Administrator) => ADMINISTRATOR,
        Some(OperatorRole::EscrowOfficer) => ESCROW_OFFICER,
        None => &[],
    }
}

/// True if `officer` holds the reveal through a self-grant: another
/// active operator with the administrator role carries the same
/// certificate subject (the same person enrolled twice). Operator rows do
/// not record who granted a role (WU-6 follow-up U-2), so the guard is
/// applied where the reveal is used, and fails closed: an empty subject
/// counts as a match.
#[must_use]
pub fn self_granted(officer: &Operator, operators: &[Operator]) -> bool {
    let subject = officer.cert_subject.trim();
    operators.iter().any(|o| {
        o.id != officer.id
            && o.status == OperatorStatus::Active
            && o.role == Some(OperatorRole::Administrator)
            && (subject.is_empty() || o.cert_subject.trim().eq_ignore_ascii_case(subject))
    })
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
    fn administrator_holds_every_permission_but_reveal_none_holds_nothing() {
        for &p in Permission::ALL {
            assert_eq!(
                allows(Some(OperatorRole::Administrator), p),
                p != Permission::EscrowReveal,
                "{p:?}"
            );
            assert!(!allows(None, p), "{p:?}");
        }
        // Separation of duties (AC-5): the officer reveals and views jobs,
        // nothing else; no role holds both the reveal and administration.
        for &p in Permission::ALL {
            assert_eq!(
                allows(Some(OperatorRole::EscrowOfficer), p),
                matches!(p, Permission::EscrowReveal | Permission::JobView),
                "{p:?}"
            );
        }
        assert_eq!(ADMINISTRATOR.len() + 1, Permission::ALL.len());
    }

    fn op(n: u8, subject: &str, role: Option<OperatorRole>, status: OperatorStatus) -> Operator {
        Operator {
            id: usgp_proto::OperatorId::from_random_bytes([n; 16]),
            display_name: usgp_proto::DisplayName::new("x").unwrap(),
            cert_sha256: usgp_common::Sha256Digest([n; 32]),
            cert_subject: subject.to_owned(),
            cert_issuer: "CN=CA".to_owned(),
            cert_serial: "01".to_owned(),
            cert_not_after: usgp_proto::UnixMicros::new(1).unwrap(),
            role,
            status,
            created_at: usgp_proto::UnixMicros::new(1).unwrap(),
            created_by: "uid:0".to_owned(),
        }
    }

    #[test]
    fn self_grant_guard() {
        let admin = op(
            1,
            "CN=Pat",
            Some(OperatorRole::Administrator),
            OperatorStatus::Active,
        );
        let officer = op(
            2,
            "CN=Lee",
            Some(OperatorRole::EscrowOfficer),
            OperatorStatus::Active,
        );
        let twin = op(
            3,
            "cn=pat",
            Some(OperatorRole::EscrowOfficer),
            OperatorStatus::Active,
        );
        let blank = op(
            4,
            " ",
            Some(OperatorRole::EscrowOfficer),
            OperatorStatus::Active,
        );
        let gone = op(
            5,
            "CN=Lee",
            Some(OperatorRole::Administrator),
            OperatorStatus::Disabled,
        );
        let all = vec![admin, officer.clone(), twin.clone(), gone];
        assert!(!self_granted(&officer, &all));
        assert!(self_granted(&twin, &all));
        // Fail closed: an empty subject matches any administrator.
        assert!(self_granted(&blank, &all));
        let names: std::collections::HashSet<_> =
            Permission::ALL.iter().map(|p| p.as_str()).collect();
        assert_eq!(names.len(), Permission::ALL.len());
    }
}
