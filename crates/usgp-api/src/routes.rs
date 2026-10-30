//! The route table (plan M2 section 3.2, plus the M3 operator and relay
//! routes of plan M3 section 3.5): every route with its method, path
//! pattern, permission and audit events.
//!
//! The router refuses a request unless its route is in this table, and
//! checks the route's permission before the handler runs. A test proves
//! that every route names a permission, a success event and a refusal
//! event (REQ-RBAC-001, REQ-AUD-001).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - one permission per route.
// - NIST 800-53: AU-2 (Event Logging) - one success and one refusal event
//   per route.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded paths;
//   parameters parsed as UUIDs or decimal indexes by the handlers.
// - SPEC: specs/operator-access.md#REQ-RBAC-001, #REQ-AUD-001

use crate::rbac::Permission;

/// Every route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteId {
    /// `GET /v1/limits`
    Limits,
    /// `POST /v1/uploads`
    UploadCreate,
    /// `PUT /v1/uploads/{id}`
    UploadPut,
    /// `DELETE /v1/uploads/{id}`
    UploadCancel,
    /// `GET /v1/images`
    ImageList,
    /// `GET /v1/images/{id}`
    ImageGet,
    /// `PUT /v1/images/{id}/editions/{index}/declaration`
    ImageDeclare,
    /// `DELETE /v1/images/{id}`
    ImageDelete,
    /// `GET /v1/images/{id}/manifest`
    ImageManifest,
    /// `GET /v1/pe`
    PeList,
    /// `GET /v1/pe/{id}`
    PeGet,
    /// `DELETE /v1/pe/{id}`
    PeDelete,
    /// `GET /v1/pe/{id}/manifest`
    PeManifest,
    /// `GET /v1/content/{id}`
    ContentGet,
    /// `GET /v1/packages`
    PackageList,
    /// `GET /v1/packages/{id}`
    PackageGet,
    /// `POST /v1/packages`
    PackageCreate,
    /// `PUT /v1/packages/{id}`
    PackageEdit,
    /// `POST /v1/packages/{id}/clone`
    PackageClone,
    /// `DELETE /v1/packages/{id}`
    PackageDelete,
    /// `GET /v1/packages/{id}/manifest`
    PackageManifest,
    /// `POST /v1/auth-codes`
    AuthCodeIssue,
    /// `GET /v1/auth-codes`
    AuthCodeList,
    /// `DELETE /v1/auth-codes/{id}`
    AuthCodeRevoke,
    /// `GET /v1/device-sessions`
    DeviceSessionList,
    /// `POST /v1/device-sessions/{id}/approve`
    DeviceSessionApprove,
    /// `POST /v1/device-sessions/{id}/refuse`
    DeviceSessionRefuse,
    /// `GET /v1/jobs`
    JobList,
    /// `GET /v1/jobs/{id}`
    JobGet,
    /// `POST /v1/jobs/{id}/acknowledge`
    JobAcknowledge,
    /// `POST /v1/jobs/{id}/fail` (finding SEC-012)
    JobFail,
    /// `GET /v1/boot-services`
    BootServiceList,
    /// `GET /v1/boot-services/{id}`
    BootServiceGet,
    /// `PUT /v1/boot-services/{id}/packages`
    BootServicePackages,
    /// `GET /v1/boot-stops`
    BootStopList,
    /// `POST /v1/boot-stops/{id}/clear`
    BootStopClear,
    /// `GET /v1/relay/boot-policy?have=<generation>`
    RelayBootPolicy,
    /// `POST /v1/agent-signers` (M4)
    AgentSignerAdd,
    /// `GET /v1/agent-signers` (M4)
    AgentSignerList,
    /// `DELETE /v1/agent-signers/{id}` (M4)
    AgentSignerRevoke,
    /// `PUT /v1/packages/{id}/config` (M4)
    PackageConfigSet,
    /// `PUT /v1/packages/{id}/drivers` (M4)
    PackageDriversSet,
    /// `PUT /v1/device-values/{mac}` (M4)
    DeviceValueSet,
    /// `GET /v1/device-values/{mac}` (M4)
    DeviceValueGet,
    /// `DELETE /v1/device-values/{mac}` (M4)
    DeviceValueDelete,
    /// `GET /v1/jobs/{id}/admin-password` (M4)
    EscrowMetadata,
    /// `POST /v1/jobs/{id}/admin-password/reveal` (M4)
    EscrowReveal,
}

/// The permission a route needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// This permission.
    One(Permission),
    /// One of these, chosen by the content kind once it is known; the
    /// router requires at least one, the handler the right one.
    ByKind {
        /// For images.
        image: Permission,
        /// For preinstall environments.
        pe: Permission,
    },
    /// Only an authenticated boot service (relay) whose certificate is
    /// bound to its record; no operator permission grants it, and a boot
    /// service may call nothing else (plan M3 section 3.5).
    BootService,
}

impl Access {
    /// The operator permissions named (none for [`Access::BootService`]).
    #[must_use]
    pub fn permissions(self) -> Vec<Permission> {
        match self {
            Self::One(p) => vec![p],
            Self::ByKind { image, pe } => vec![image, pe],
            Self::BootService => Vec::new(),
        }
    }

    /// Text for the audit detail.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::One(p) => p.as_str(),
            Self::ByKind { image, .. } => match image {
                Permission::ImageUpload => "image.upload|pe.import",
                Permission::ImageView => "image.view|pe.view",
                _ => "by-kind",
            },
            Self::BootService => "boot_service",
        }
    }
}

/// One route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSpec {
    /// Identifier.
    pub id: RouteId,
    /// HTTP method.
    pub method: &'static str,
    /// Path pattern; `{name}` matches one segment.
    pub pattern: &'static str,
    /// Permission.
    pub access: Access,
    /// Audit events written on success (the first is the main one).
    pub events: &'static [&'static str],
    /// Audit event for a refusal, unless the handler names another.
    pub refused_event: &'static str,
    /// Audit target kind of the first path parameter (or the collection).
    pub target_kind: &'static str,
    /// True if the request carries a JSON body.
    pub json_body: bool,
}

const UPLOAD: Access = Access::ByKind {
    image: Permission::ImageUpload,
    pe: Permission::PeImport,
};

/// The table (plan section 3.2).
pub const ROUTES: &[RouteSpec] = &[
    RouteSpec {
        id: RouteId::Limits,
        method: "GET",
        pattern: "/v1/limits",
        access: Access::One(Permission::LimitsView),
        events: &["api.limits.read"],
        refused_event: "api.limits.read",
        target_kind: "limits",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::UploadCreate,
        method: "POST",
        pattern: "/v1/uploads",
        access: UPLOAD,
        events: &["content.upload.created"],
        refused_event: "content.upload.refused",
        target_kind: "upload",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::UploadPut,
        method: "PUT",
        pattern: "/v1/uploads/{id}",
        access: UPLOAD,
        events: &[
            "content.upload.started",
            "content.upload.received",
            "content.upload.failed",
            "content.check.started",
            "content.failed",
        ],
        refused_event: "content.upload.refused",
        target_kind: "upload",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::UploadCancel,
        method: "DELETE",
        pattern: "/v1/uploads/{id}",
        access: UPLOAD,
        events: &["content.upload.cancelled", "content.failed"],
        refused_event: "content.upload.refused",
        target_kind: "upload",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::ImageList,
        method: "GET",
        pattern: "/v1/images",
        access: Access::One(Permission::ImageView),
        events: &["image.list.read"],
        refused_event: "image.list.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::ImageGet,
        method: "GET",
        pattern: "/v1/images/{id}",
        access: Access::One(Permission::ImageView),
        events: &["image.read"],
        refused_event: "image.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::ImageDeclare,
        method: "PUT",
        pattern: "/v1/images/{id}/editions/{index}/declaration",
        access: Access::One(Permission::ImageUpload),
        events: &["edition.declared"],
        refused_event: "edition.declaration.refused",
        target_kind: "content",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::ImageDelete,
        method: "DELETE",
        pattern: "/v1/images/{id}",
        access: Access::One(Permission::ImageDelete),
        events: &["image.deleted"],
        refused_event: "image.delete.refused",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::ImageManifest,
        method: "GET",
        pattern: "/v1/images/{id}/manifest",
        access: Access::One(Permission::ImageView),
        events: &["content.manifest.read"],
        refused_event: "content.manifest.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PeList,
        method: "GET",
        pattern: "/v1/pe",
        access: Access::One(Permission::PeView),
        events: &["pe.list.read"],
        refused_event: "pe.list.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PeGet,
        method: "GET",
        pattern: "/v1/pe/{id}",
        access: Access::One(Permission::PeView),
        events: &["pe.read"],
        refused_event: "pe.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PeDelete,
        method: "DELETE",
        pattern: "/v1/pe/{id}",
        access: Access::One(Permission::PeDelete),
        events: &["pe.deleted"],
        refused_event: "pe.delete.refused",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PeManifest,
        method: "GET",
        pattern: "/v1/pe/{id}/manifest",
        access: Access::One(Permission::PeView),
        events: &["content.manifest.read"],
        refused_event: "content.manifest.read",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::ContentGet,
        method: "GET",
        pattern: "/v1/content/{id}",
        access: Access::ByKind {
            image: Permission::ImageView,
            pe: Permission::PeView,
        },
        events: &[
            "content.download",
            "content.download.completed",
            "content.download.aborted",
            "content.integrity.failed",
        ],
        refused_event: "content.download",
        target_kind: "content",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PackageList,
        method: "GET",
        pattern: "/v1/packages",
        access: Access::One(Permission::PackageView),
        events: &["package.list.read"],
        refused_event: "package.list.read",
        target_kind: "package",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PackageGet,
        method: "GET",
        pattern: "/v1/packages/{id}",
        access: Access::One(Permission::PackageView),
        events: &["package.read"],
        refused_event: "package.read",
        target_kind: "package",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PackageCreate,
        method: "POST",
        pattern: "/v1/packages",
        access: Access::One(Permission::PackageCreate),
        events: &["package.created", "package.manifest.signed"],
        refused_event: "package.refused",
        target_kind: "package",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::PackageEdit,
        method: "PUT",
        pattern: "/v1/packages/{id}",
        access: Access::One(Permission::PackageEdit),
        events: &[
            "package.edited",
            "package.status.changed",
            "package.manifest.signed",
        ],
        refused_event: "package.refused",
        target_kind: "package",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::PackageClone,
        method: "POST",
        pattern: "/v1/packages/{id}/clone",
        access: Access::One(Permission::PackageClone),
        events: &["package.cloned", "package.manifest.signed"],
        refused_event: "package.refused",
        target_kind: "package",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::PackageDelete,
        method: "DELETE",
        pattern: "/v1/packages/{id}",
        access: Access::One(Permission::PackageDelete),
        events: &["package.deleted"],
        refused_event: "package.refused",
        target_kind: "package",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PackageManifest,
        method: "GET",
        pattern: "/v1/packages/{id}/manifest",
        access: Access::One(Permission::PackageView),
        events: &["package.manifest.read"],
        refused_event: "package.manifest.read",
        target_kind: "package",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::AuthCodeIssue,
        method: "POST",
        pattern: "/v1/auth-codes",
        access: Access::One(Permission::AuthCodeIssue),
        events: &["auth_code.issued"],
        refused_event: "auth_code.refused",
        target_kind: "auth_code",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::AuthCodeList,
        method: "GET",
        pattern: "/v1/auth-codes",
        access: Access::One(Permission::AuthCodeView),
        events: &["auth_code.list.read"],
        refused_event: "auth_code.list.read",
        target_kind: "auth_code",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::AuthCodeRevoke,
        method: "DELETE",
        pattern: "/v1/auth-codes/{id}",
        access: Access::One(Permission::AuthCodeRevoke),
        events: &["auth_code.revoked"],
        refused_event: "auth_code.revoke_refused",
        target_kind: "auth_code",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::DeviceSessionList,
        method: "GET",
        pattern: "/v1/device-sessions",
        access: Access::One(Permission::DeviceSessionView),
        events: &["device_session.list.read"],
        refused_event: "device_session.list.read",
        target_kind: "device_session",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::DeviceSessionApprove,
        method: "POST",
        pattern: "/v1/device-sessions/{id}/approve",
        access: Access::One(Permission::DeviceSessionApprove),
        events: &["device.session.approved"],
        refused_event: "device.session.approve_refused",
        target_kind: "device_session",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::DeviceSessionRefuse,
        method: "POST",
        pattern: "/v1/device-sessions/{id}/refuse",
        access: Access::One(Permission::DeviceSessionApprove),
        events: &["device.session.refused"],
        refused_event: "device.session.refuse_refused",
        target_kind: "device_session",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::JobList,
        method: "GET",
        pattern: "/v1/jobs",
        access: Access::One(Permission::JobView),
        events: &["job.list.read"],
        refused_event: "job.list.read",
        target_kind: "job",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::JobGet,
        method: "GET",
        pattern: "/v1/jobs/{id}",
        access: Access::One(Permission::JobView),
        events: &["job.read"],
        refused_event: "job.read",
        target_kind: "job",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::JobAcknowledge,
        method: "POST",
        pattern: "/v1/jobs/{id}/acknowledge",
        access: Access::One(Permission::JobAcknowledge),
        events: &["job.failure.acknowledged"],
        refused_event: "job.acknowledge_refused",
        target_kind: "job",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::JobFail,
        method: "POST",
        pattern: "/v1/jobs/{id}/fail",
        access: Access::One(Permission::JobFail),
        events: &["job.failed"],
        refused_event: "job.fail_refused",
        target_kind: "job",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::BootServiceList,
        method: "GET",
        pattern: "/v1/boot-services",
        access: Access::One(Permission::BootServiceView),
        events: &["boot_service.read"],
        refused_event: "boot_service.read",
        target_kind: "boot_service",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::BootServiceGet,
        method: "GET",
        pattern: "/v1/boot-services/{id}",
        access: Access::One(Permission::BootServiceView),
        events: &["boot_service.read"],
        refused_event: "boot_service.read",
        target_kind: "boot_service",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::BootServicePackages,
        method: "PUT",
        pattern: "/v1/boot-services/{id}/packages",
        access: Access::One(Permission::BootServiceAssign),
        events: &["boot_service.packages.set"],
        refused_event: "boot_service.packages.refused",
        target_kind: "boot_service",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::BootStopList,
        method: "GET",
        pattern: "/v1/boot-stops",
        access: Access::One(Permission::BootStopView),
        events: &["boot_stop.list.read"],
        refused_event: "boot_stop.list.read",
        target_kind: "boot_stop",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::BootStopClear,
        method: "POST",
        pattern: "/v1/boot-stops/{id}/clear",
        access: Access::One(Permission::DeviceBootReenable),
        events: &["boot_stop.cleared"],
        refused_event: "boot_stop.clear_refused",
        target_kind: "boot_stop",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::RelayBootPolicy,
        method: "GET",
        pattern: "/v1/relay/boot-policy",
        access: Access::BootService,
        events: &["boot_policy.read"],
        refused_event: "boot_policy.refused",
        target_kind: "boot_service",
        json_body: false,
    },
    // M4 plan section 3.2.
    RouteSpec {
        id: RouteId::AgentSignerAdd,
        method: "POST",
        pattern: "/v1/agent-signers",
        access: Access::One(Permission::AgentSignerManage),
        events: &["agent_signer.added"],
        refused_event: "agent_signer.refused",
        target_kind: "agent_signer",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::AgentSignerList,
        method: "GET",
        pattern: "/v1/agent-signers",
        access: Access::One(Permission::AgentSignerManage),
        events: &["agent_signer.list.read"],
        refused_event: "agent_signer.list.read",
        target_kind: "agent_signer",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::AgentSignerRevoke,
        method: "DELETE",
        pattern: "/v1/agent-signers/{id}",
        access: Access::One(Permission::AgentSignerManage),
        events: &[
            "agent_signer.revoked",
            "agent_package.refused",
            "package.status.changed",
        ],
        refused_event: "agent_signer.revoke_refused",
        target_kind: "agent_signer",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::PackageConfigSet,
        method: "PUT",
        pattern: "/v1/packages/{id}/config",
        access: Access::One(Permission::PackageEdit),
        events: &["package.config.set", "agent_package.attached"],
        refused_event: "package.config.refused",
        target_kind: "package",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::PackageDriversSet,
        method: "PUT",
        pattern: "/v1/packages/{id}/drivers",
        access: Access::One(Permission::PackageEdit),
        events: &["package.drivers.set"],
        refused_event: "package.drivers.refused",
        target_kind: "package",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::DeviceValueSet,
        method: "PUT",
        pattern: "/v1/device-values/{mac}",
        access: Access::One(Permission::DeviceValueManage),
        events: &["device_value.set"],
        refused_event: "device_value.refused",
        target_kind: "device_value",
        json_body: true,
    },
    RouteSpec {
        id: RouteId::DeviceValueGet,
        method: "GET",
        pattern: "/v1/device-values/{mac}",
        access: Access::One(Permission::DeviceValueView),
        events: &["device_value.read"],
        refused_event: "device_value.read",
        target_kind: "device_value",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::DeviceValueDelete,
        method: "DELETE",
        pattern: "/v1/device-values/{mac}",
        access: Access::One(Permission::DeviceValueManage),
        events: &["device_value.deleted"],
        refused_event: "device_value.refused",
        target_kind: "device_value",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::EscrowMetadata,
        method: "GET",
        pattern: "/v1/jobs/{id}/admin-password",
        access: Access::One(Permission::JobView),
        events: &["escrow.metadata.read"],
        refused_event: "escrow.metadata.read",
        target_kind: "job",
        json_body: false,
    },
    RouteSpec {
        id: RouteId::EscrowReveal,
        method: "POST",
        pattern: "/v1/jobs/{id}/admin-password/reveal",
        access: Access::One(Permission::EscrowReveal),
        events: &["escrow.revealed"],
        refused_event: "escrow.reveal_refused",
        target_kind: "job",
        json_body: true,
    },
];

/// Longest request path accepted, in bytes.
pub const MAX_PATH_BYTES: usize = 256;

/// Longest path parameter, in bytes (a UUID is 36).
pub const MAX_PARAM_BYTES: usize = 64;

/// Path parameters of a matched route, in pattern order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Params(Vec<String>);

impl Params {
    /// Parameter `n` (0-based), or `""`.
    #[must_use]
    pub fn get(&self, n: usize) -> &str {
        self.0.get(n).map_or("", String::as_str)
    }
}

/// The result of matching a request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// A route and its parameters.
    Found(&'static RouteSpec, Params),
    /// The path exists for other methods only (405).
    MethodNotAllowed,
    /// No route (404).
    NotFound,
}

pub(crate) fn match_pattern(pattern: &str, path: &str) -> Option<Params> {
    let mut params = Vec::new();
    let mut p = pattern.split('/');
    let mut s = path.split('/');
    loop {
        match (p.next(), s.next()) {
            (None, None) => return Some(Params(params)),
            (Some(pp), Some(ss)) => {
                if pp.starts_with('{') {
                    if ss.is_empty() || ss.len() > MAX_PARAM_BYTES {
                        return None;
                    }
                    params.push(ss.to_owned());
                } else if pp != ss {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// The methods routed for `path` (for the `Allow` header of a 405).
#[must_use]
pub fn allowed_methods(path: &str) -> Vec<&'static str> {
    if path.len() > MAX_PATH_BYTES {
        return Vec::new();
    }
    ROUTES
        .iter()
        .filter(|r| match_pattern(r.pattern, path).is_some())
        .map(|r| r.method)
        .collect()
}

/// Matches a method and path (no query) against [`ROUTES`].
#[must_use]
pub fn match_route(method: &str, path: &str) -> Match {
    if path.len() > MAX_PATH_BYTES {
        return Match::NotFound;
    }
    let mut other_method = false;
    for r in ROUTES {
        if let Some(params) = match_pattern(r.pattern, path) {
            if r.method == method {
                return Match::Found(r, params);
            }
            other_method = true;
        }
    }
    if other_method {
        Match::MethodNotAllowed
    } else {
        Match::NotFound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let Match::Found(r, p) = match_route(
            "PUT",
            "/v1/images/0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f/editions/3/declaration",
        ) else {
            panic!("no match");
        };
        assert_eq!(r.id, RouteId::ImageDeclare);
        assert_eq!(p.get(0), "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f");
        assert_eq!(p.get(1), "3");
        assert_eq!(p.get(2), "");
        assert_eq!(match_route("PATCH", "/v1/limits"), Match::MethodNotAllowed);
        assert_eq!(match_route("GET", "/v1/limits/"), Match::NotFound);
        assert_eq!(match_route("GET", "/v1/images//manifest"), Match::NotFound);
        assert_eq!(match_route("GET", "/v2/limits"), Match::NotFound);
        let long = format!("/v1/images/{}", "a".repeat(300));
        assert_eq!(match_route("GET", &long), Match::NotFound);
        let param = format!("/v1/images/{}", "a".repeat(65));
        assert_eq!(match_route("GET", &param), Match::NotFound);
    }

    #[test]
    fn method_and_pattern_unique() {
        let mut seen = std::collections::HashSet::new();
        for r in ROUTES {
            assert!(seen.insert((r.method, r.pattern)), "{r:?}");
        }
    }
}
