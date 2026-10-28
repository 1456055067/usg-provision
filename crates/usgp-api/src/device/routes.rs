//! The device route table (plan M3 sections 3.1, 3.3 and 3.4): every
//! route with its method, path pattern, whether it needs the session's
//! bearer token, and its audit events.
//!
//! The device router refuses a request unless its route is here. Every
//! route except open needs a bearer token bound to a session; a test
//! proves it, and that every route names its events.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 (Access Enforcement) - bearer session on every
//   route but open; the table is closed.
// - NIST 800-53: AU-2 (Event Logging) - success and refusal events named
//   per route.
// - NIST 800-53: SI-10 - bounded paths (the operator table's limits).
// - SPEC: specs/targeting.md#REQ-TGT-012, #REQ-TGT-015

use crate::routes::{MAX_PATH_BYTES, Params, match_pattern};

/// Every device route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceRouteId {
    /// `POST /v1/device/sessions`
    Open,
    /// `GET /v1/device/session`
    Status,
    /// `POST /v1/device/session/code`
    Code,
    /// `GET /v1/device/session/packages`
    Packages,
    /// `POST /v1/device/session/package`
    ChoosePackage,
    /// `POST /v1/device/session/disk`
    ChooseDisk,
    /// `POST /v1/device/session/confirm`
    Confirm,
    /// `POST /v1/device/session/cancel`
    Cancel,
    /// `POST /v1/device/session/end`
    End,
    /// `GET /v1/device/jobs/{job}/content/{sha256}/chunks/{n}`
    Chunk,
    /// `POST /v1/device/jobs/{job}/progress`
    Progress,
}

/// One device route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRoute {
    /// Identifier.
    pub id: DeviceRouteId,
    /// HTTP method.
    pub method: &'static str,
    /// Path pattern; `{name}` matches one segment.
    pub pattern: &'static str,
    /// True if the request must carry the session's bearer token.
    pub bearer: bool,
    /// True if the request carries a JSON body.
    pub json_body: bool,
    /// Audit events written on success (empty for reads that change
    /// nothing, such as the poll).
    pub events: &'static [&'static str],
    /// Audit event for a refusal, unless the handler names another.
    pub refused_event: &'static str,
    /// True if refusals are audited under the per-source cap (high-volume
    /// routes; plan section 7, "rate-capped").
    pub capped_refusals: bool,
}

/// The table.
pub const DEVICE_ROUTES: &[DeviceRoute] = &[
    DeviceRoute {
        id: DeviceRouteId::Open,
        method: "POST",
        pattern: "/v1/device/sessions",
        bearer: false,
        json_body: true,
        events: &["device.session.opened"],
        refused_event: "device.session.open_refused",
        capped_refusals: true,
    },
    DeviceRoute {
        id: DeviceRouteId::Status,
        method: "GET",
        pattern: "/v1/device/session",
        bearer: true,
        json_body: false,
        events: &[],
        refused_event: "device.session.status_refused",
        capped_refusals: true,
    },
    DeviceRoute {
        id: DeviceRouteId::Code,
        method: "POST",
        pattern: "/v1/device/session/code",
        bearer: true,
        json_body: true,
        events: &["auth_code.used", "device.session.authorised"],
        refused_event: "device.session.code_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::Packages,
        method: "GET",
        pattern: "/v1/device/session/packages",
        bearer: true,
        json_body: false,
        events: &[
            "device.session.packages.read",
            "boot_service.no_usable_package",
            "device.session.no_boot_service",
        ],
        refused_event: "device.session.packages_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::ChoosePackage,
        method: "POST",
        pattern: "/v1/device/session/package",
        bearer: true,
        json_body: true,
        events: &["device.session.package_chosen"],
        refused_event: "device.session.package_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::ChooseDisk,
        method: "POST",
        pattern: "/v1/device/session/disk",
        bearer: true,
        json_body: true,
        events: &["device.session.disk_chosen"],
        refused_event: "device.session.disk_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::Confirm,
        method: "POST",
        pattern: "/v1/device/session/confirm",
        bearer: true,
        json_body: true,
        events: &["job.created", "disk.wipe.authorised", "job.plan.issued"],
        refused_event: "device.session.confirm_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::Cancel,
        method: "POST",
        pattern: "/v1/device/session/cancel",
        bearer: true,
        json_body: true,
        events: &["device.session.cancelled"],
        refused_event: "device.session.cancel_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::End,
        method: "POST",
        pattern: "/v1/device/session/end",
        bearer: true,
        json_body: true,
        events: &["device.session.ended"],
        refused_event: "device.session.end_refused",
        capped_refusals: false,
    },
    DeviceRoute {
        id: DeviceRouteId::Chunk,
        method: "GET",
        pattern: "/v1/device/jobs/{job}/content/{sha256}/chunks/{n}",
        bearer: true,
        json_body: false,
        events: &[
            "job.content.read",
            "content.integrity.failed",
            "job.resumed",
        ],
        refused_event: "job.content.refused",
        capped_refusals: true,
    },
    DeviceRoute {
        id: DeviceRouteId::Progress,
        method: "POST",
        pattern: "/v1/device/jobs/{job}/progress",
        bearer: true,
        json_body: true,
        events: &[
            "job.step.started",
            "job.step.completed",
            "job.failed",
            "job.succeeded",
            "job.resumed",
            "boot_stop.added",
        ],
        refused_event: "job.progress.refused",
        capped_refusals: true,
    },
];

/// The result of matching a device request line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceMatch {
    /// A route and its parameters.
    Found(&'static DeviceRoute, Params),
    /// The path exists for other methods only (405).
    MethodNotAllowed,
    /// No route (404).
    NotFound,
}

/// Matches a method and path (no query) against [`DEVICE_ROUTES`].
#[must_use]
pub fn match_device_route(method: &str, path: &str) -> DeviceMatch {
    if path.len() > MAX_PATH_BYTES {
        return DeviceMatch::NotFound;
    }
    let mut other_method = false;
    for r in DEVICE_ROUTES {
        if let Some(params) = match_pattern(r.pattern, path) {
            if r.method == method {
                return DeviceMatch::Found(r, params);
            }
            other_method = true;
        }
    }
    if other_method {
        DeviceMatch::MethodNotAllowed
    } else {
        DeviceMatch::NotFound
    }
}

/// The methods routed for `path` (the `Allow` header of a 405).
#[must_use]
pub fn device_allowed_methods(path: &str) -> Vec<&'static str> {
    if path.len() > MAX_PATH_BYTES {
        return Vec::new();
    }
    DEVICE_ROUTES
        .iter()
        .filter(|r| match_pattern(r.pattern, path).is_some())
        .map(|r| r.method)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_open_is_without_bearer_and_patterns_unique() {
        let mut seen = std::collections::HashSet::new();
        for r in DEVICE_ROUTES {
            assert!(seen.insert((r.method, r.pattern)), "{r:?}");
            assert_eq!(r.bearer, r.id != DeviceRouteId::Open, "{r:?}");
            assert!(!r.refused_event.is_empty());
        }
        let sha = "a".repeat(64);
        let path =
            format!("/v1/device/jobs/0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f/content/{sha}/chunks/3");
        let DeviceMatch::Found(r, p) = match_device_route("GET", &path) else {
            panic!("no match");
        };
        assert_eq!(r.id, DeviceRouteId::Chunk);
        assert_eq!(p.get(1), sha);
        assert_eq!(p.get(2), "3");
        assert_eq!(
            match_device_route("GET", "/v1/device/sessions"),
            DeviceMatch::MethodNotAllowed
        );
        assert_eq!(
            match_device_route("GET", "/v1/limits"),
            DeviceMatch::NotFound
        );
    }
}
