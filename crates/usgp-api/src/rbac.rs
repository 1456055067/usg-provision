//! Permissions and the one built-in role (REQ-RBAC-001, REQ-RBAC-004).
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
