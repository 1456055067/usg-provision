//! Package configuration and driver list (M4 plan sections 1.6, 1.7 and
//! 3.2; follow-up U-1).
//!
//! `PUT /v1/packages/{id}/config` stores, in one row, the answer-file
//! template (inline, 1 byte to 1 MiB, sent as base64 in a body of at most
//! [`MAX_CONFIG_BODY_BYTES`]), the package values, the tags, the agent
//! package and the administrator-password mode. The template is parsed
//! and linted before it is stored: a template the parser refuses, or one
//! the lint finds a problem in (secret-bearing setting, reference in a
//! command, unknown reference, value not referenced, invalid literal
//! value), is refused with 422 and nothing is stored. The record carries
//! the template's SHA-256 and the names of the fields set, never the
//! text.
//!
//! `PUT /v1/packages/{id}/drivers` replaces the ordered driver-archive
//! list (at most 64, distinct, every one Ready), guarded by `If-Match`
//! on the package revision.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - `package.edit`.
// - NIST 800-53: AU-2, AU-3, AU-12 - `package.config.set` (field names and
//   the template digest), `agent_package.attached`, `package.drivers.set`
//   in the same transaction as the change.
// - NIST 800-53: SI-10 - body bounded before parsing; the template parsed
//   with no DTD, no external entities and bounded depth and size
//   (usgp-wincfg); values checked by their rules.
// - NIST 800-53: CM-6 - only validated configuration is stored.
// - NIST 800-53: IA-5, SC-28 - the lint refuses settings that carry a
//   secret, so no password can reach an answer file (REQ-CFG-010).
// - SPEC: specs/configuration.md#REQ-CFG-002, #REQ-CFG-003, #REQ-CFG-005,
//   #REQ-CFG-007, #REQ-CFG-008, #REQ-CFG-009, #REQ-CFG-010;
//   specs/drivers.md#REQ-DRV-004; specs/agent-handoff.md#REQ-AGT-001
// - Decision 0024 items 1 and 2

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::{Detail, Outcome};
use usgp_common::Sha256Digest;
use usgp_db::{
    AdminPasswordMode, AgentPackageStatus, DbError, DriverArchiveStatus, PackageConfig,
    PackageValues, RepoTx, Store,
};
use usgp_proto::api::if_match_revision;
use usgp_proto::limits::{MAX_ANSWER_FILE_BYTES, MAX_PLAN_DRIVERS};
use usgp_proto::{
    AgentPackageId, B64Bytes, DriverArchiveId, ErrorCode, OperatorId, PackageId, Tag, UnixMicros,
    codes,
};
use usgp_wincfg::unattend::{self, ComputerNameSource, LintFinding, Template};

use super::{if_match, json_response, package_id, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// Largest body of `PUT /v1/packages/{id}/config` (2 MiB: a 1 MiB
/// template as base64 plus the other fields; follow-up U-1).
pub const MAX_CONFIG_BODY_BYTES: usize = 2 * 1024 * 1024;

/// `PUT /v1/packages/{id}/config` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetConfig {
    answer_template_b64: B64Bytes<1, MAX_ANSWER_FILE_BYTES>,
    #[serde(default)]
    values: PackageValues,
    #[serde(default)]
    tags: Vec<Tag>,
    agent_package_id: AgentPackageId,
    admin_password: String,
}

/// The view of a package's configuration (no template text).
#[derive(Debug, serde::Serialize)]
struct ConfigView {
    package_id: PackageId,
    answer_sha256: Sha256Digest,
    answer_bytes: usize,
    values: PackageValues,
    tags: Vec<Tag>,
    agent_package_id: AgentPackageId,
    admin_password: &'static str,
    updated_by: OperatorId,
    updated_at: UnixMicros,
}

fn config_view(c: &PackageConfig) -> ConfigView {
    ConfigView {
        package_id: c.package_id,
        answer_sha256: c.answer_sha256,
        answer_bytes: c.answer_template.len(),
        values: c.values.clone(),
        tags: c.tags.clone(),
        agent_package_id: c.agent_package_id,
        admin_password: c.admin_password.as_str(),
        updated_by: c.updated_by,
        updated_at: c.updated_at,
    }
}

fn invalid(field: &str, message: impl Into<String>) -> ApiError {
    ApiError::unprocessable(
        codes::INVALID_VALUE
            .with_param(field)
            .unwrap_or(codes::INVALID_VALUE),
        message,
    )
}

/// The reason code and operator text of a lint finding (names and element
/// paths only, never values).
fn finding_error(f: &LintFinding) -> ApiError {
    let (base, param, text) = match f {
        LintFinding::SecretBearingSetting { path } => (
            "secret_bearing_setting",
            path.clone(),
            format!("the answer file sets {path}, which carries a secret; secrets are not allowed"),
        ),
        LintFinding::ReferenceInCommand { path } => (
            "reference_in_command",
            path.clone(),
            format!("the command setting {path} holds a value reference; commands take no values"),
        ),
        LintFinding::UnknownReference { name } => (
            "unknown_reference",
            name.clone(),
            format!("the answer file refers to {name}, which is not a known value"),
        ),
        LintFinding::ValueNotReferenced { name } => (
            "value_not_referenced",
            (*name).to_owned(),
            format!("the package sets {name}, but the answer file does not use it where required"),
        ),
        LintFinding::InvalidValue { name, reason } => (
            "invalid_value",
            (*name).to_owned(),
            format!("the package value {name} is not valid: {reason}"),
        ),
    };
    let code = ErrorCode::new(base)
        .ok()
        .and_then(|c| c.with_param(&param).ok().or(Some(c)))
        .unwrap_or(codes::INVALID_VALUE);
    ApiError::unprocessable(code, text)
}

/// The lint's view of the package values: a literal computer name, or a
/// per-device one when the template uses `{{device.computer_name}}`.
pub(crate) fn lint_values(v: &PackageValues, t: &Template) -> unattend::PackageValues {
    let computer_name = match &v.computer_name {
        Some(n) => Some(ComputerNameSource::Value(n.clone())),
        None => t
            .references()
            .iter()
            .any(|r| r == "device.computer_name")
            .then_some(ComputerNameSource::PerDevice),
    };
    unattend::PackageValues {
        computer_name,
        time_zone: v.time_zone.clone(),
        domain: v.domain.clone(),
        machine_ou: v.machine_ou.clone(),
    }
}

/// Parses and lints a template against the package values.
pub(crate) fn check_template(bytes: &[u8], values: &PackageValues) -> Result<Template, ApiError> {
    let t = Template::parse(bytes, &unattend::Limits::default()).map_err(|e| {
        invalid(
            "answer_template_b64",
            format!("the answer file was refused: {e}"),
        )
    })?;
    if let Some(f) = t.lint(&lint_values(values, &t)).first() {
        return Err(finding_error(f));
    }
    Ok(t)
}

fn changed_fields(before: Option<&PackageConfig>, after: &PackageConfig) -> String {
    let mut v = Vec::new();
    let b = before;
    if b.is_none_or(|b| b.answer_sha256 != after.answer_sha256) {
        v.push("answer_template");
    }
    let (bv, av) = (b.map(|b| &b.values), &after.values);
    if bv.is_none_or(|x| x.computer_name != av.computer_name) {
        v.push("values.computer_name");
    }
    if bv.is_none_or(|x| x.time_zone != av.time_zone) {
        v.push("values.time_zone");
    }
    if bv.is_none_or(|x| x.domain != av.domain) {
        v.push("values.domain");
    }
    if bv.is_none_or(|x| x.machine_ou != av.machine_ou) {
        v.push("values.machine_ou");
    }
    if b.is_none_or(|b| b.tags != after.tags) {
        v.push("tags");
    }
    if b.is_none_or(|b| b.agent_package_id != after.agent_package_id) {
        v.push("agent_package_id");
    }
    if b.is_none_or(|b| b.admin_password != after.admin_password) {
        v.push("admin_password");
    }
    v.join(",")
}

/// `PUT /v1/packages/{id}/config`.
pub(crate) async fn set_config<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let body = read_body(req, MAX_CONFIG_BODY_BYTES).await?;
    let s = parse_json!(SetConfig, &body, MAX_CONFIG_BODY_BYTES)?;
    drop(body);
    let mode = AdminPasswordMode::parse(&s.admin_password).ok_or_else(|| {
        invalid(
            "admin_password",
            "admin_password must be \"generate_and_escrow\" or \"none\"",
        )
    })?;
    if !s.values.valid() {
        return Err(invalid(
            "values",
            "each value must be 1 to 2048 characters with no control characters",
        ));
    }
    if let Some(tz) = &s.values.time_zone {
        unattend::values::check_time_zone(tz)
            .map_err(|e| invalid("values.time_zone", format!("time_zone is not valid: {e}")))?;
    }
    for (name, v) in [
        ("values.domain", &s.values.domain),
        ("values.machine_ou", &s.values.machine_ou),
    ] {
        if let Some(v) = v {
            unattend::values::check_carried(v)
                .map_err(|e| invalid(name, format!("the value is not valid: {e}")))?;
        }
    }
    unattend::values::check_tags(&s.tags.iter().map(Tag::as_str).collect::<Vec<_>>())
        .map_err(|e| invalid("tags", format!("the tags are not valid: {e}")))?;
    let template = s.answer_template_b64.into_bytes();
    check_template(&template, &s.values)?;
    let answer_sha256 = usgp_crypto::sha256(&template);
    let at = api.now()?;

    let mut tx = api.store().begin().await?;
    tx.lock_package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    let ap = tx
        .agent_package(s.agent_package_id)
        .await?
        .ok_or_else(|| invalid("agent_package_id", "the agent package does not exist"))?;
    if ap.status != AgentPackageStatus::Ready {
        return Err(ApiError::conflict(
            codes::NOT_READY
                .with_param("agent_package")
                .unwrap_or(codes::NOT_READY),
            format!(
                "the agent package is {}; only a ready one can be attached",
                ap.status.as_str()
            ),
        ));
    }
    let before = tx.package_config(id).await?;
    let c = PackageConfig {
        package_id: id,
        answer_template: template,
        answer_sha256,
        values: s.values,
        tags: s.tags,
        agent_package_id: s.agent_package_id,
        admin_password: mode,
        updated_by: ctx.principal.operator.id,
        updated_at: at,
    };
    match tx.set_package_config(&c).await {
        Ok(()) => {}
        Err(DbError::InvalidArgument { .. } | DbError::Constraint { .. }) => {
            return Err(invalid("config", "the configuration breaks a storage rule"));
        }
        Err(e) => return Err(e.into()),
    }
    let target = id.to_string();
    let d = ctx
        .ok("package.config.set")
        .target("package", &target)
        .detail(
            Detail::new()
                .with("fields", &changed_fields(before.as_ref(), &c))
                .with("answer_sha256", &answer_sha256)
                .with("answer_bytes", &c.answer_template.len())
                .with("tags", &c.tags.len())
                .with("agent_package_id", &c.agent_package_id.to_string())
                .with("admin_password", mode.as_str()),
        );
    let first = api.append(&mut tx, &d).await?;
    let seq = first.seq;
    let mut recs = vec![first];
    if before
        .as_ref()
        .is_none_or(|b| b.agent_package_id != c.agent_package_id)
    {
        let d = ctx
            .draft("agent_package.attached", Outcome::Success)
            .target("agent_package", &c.agent_package_id.to_string())
            .initiated_by(seq)
            .detail(Detail::new().with("package_id", &target));
        recs.push(api.append(&mut tx, &d).await?);
    }
    api.commit(tx, &recs).await?;
    json_response!(StatusCode::OK, &config_view(&c))
}

/// `PUT /v1/packages/{id}/drivers` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetDrivers {
    archive_ids: Vec<DriverArchiveId>,
}

#[derive(Debug, serde::Serialize)]
struct DriversView {
    package_id: PackageId,
    archive_ids: Vec<DriverArchiveId>,
}

/// `PUT /v1/packages/{id}/drivers` (`If-Match: "r<revision>"`).
pub(crate) async fn set_drivers<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = package_id(ctx)?;
    let expected = if_match_revision(if_match(&req)?).ok_or_else(ApiError::precondition_failed)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let s = parse_json!(SetDrivers, &body, max)?;
    if s.archive_ids.len() > MAX_PLAN_DRIVERS {
        return Err(invalid("archive_ids", "at most 64 driver archives"));
    }
    for (i, a) in s.archive_ids.iter().enumerate() {
        if s.archive_ids.iter().take(i).any(|o| o == a) {
            return Err(invalid("archive_ids", "a driver archive is listed twice"));
        }
    }
    let mut tx = api.store().begin().await?;
    let p = tx
        .lock_package(id)
        .await?
        .ok_or_else(|| ApiError::not_found("package"))?;
    if p.revision != expected {
        return Err(ApiError::precondition_failed().detail(
            Detail::new()
                .with("expected", &expected)
                .with("current", &p.revision),
        ));
    }
    for a in &s.archive_ids {
        let d = tx.driver_archive(*a).await?;
        match d {
            Some(d) if d.status == DriverArchiveStatus::Ready => {}
            Some(d) => {
                return Err(ApiError::conflict(
                    codes::NOT_READY
                        .with_param("driver_archive")
                        .unwrap_or(codes::NOT_READY),
                    format!(
                        "driver archive {a} is {}; only ready archives can be listed",
                        d.status.as_str()
                    ),
                ));
            }
            None => {
                return Err(invalid(
                    "archive_ids",
                    format!("driver archive {a} does not exist"),
                ));
            }
        }
    }
    let before = tx.package_drivers(id).await?;
    match tx.set_package_drivers(id, &s.archive_ids).await {
        Ok(()) => {}
        Err(DbError::Constraint { .. } | DbError::InvalidArgument { .. }) => {
            return Err(invalid("archive_ids", "a driver archive cannot be listed"));
        }
        Err(e) => return Err(e.into()),
    }
    let list = |v: &[DriverArchiveId]| {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    let d = ctx
        .ok("package.drivers.set")
        .target("package", &id.to_string())
        .detail(
            Detail::new()
                .with("archive_ids", &list(&s.archive_ids))
                .with("previous_archive_ids", &list(&before))
                .with("revision", &p.revision),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(
        StatusCode::OK,
        &DriversView {
            package_id: id,
            archive_ids: s.archive_ids,
        }
    )
}
