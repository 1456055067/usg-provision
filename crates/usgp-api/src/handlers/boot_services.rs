//! Boot services for the operator: list, view, and set the packages each
//! one offers (plan M3 section 3.5; REQ-TGT-001, REQ-TGT-008).
//!
//! Enrolment and disabling are local administrative commands of
//! `usgp-server` under the `usgp_admin` database role (decisions 0016 and
//! 0021 item 1); the API role can only read boot-service records.
//!
//! The assignment list has no revision column, so its `ETag` is derived
//! from the sorted assigned package ids (WU-7 note):
//! `"bsp-<sha256 hex>"`. `PUT .../packages` needs `If-Match` with the
//! current value (428 without, 412 on a change in between).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - assignment needs `boot_service.assign`.
// - NIST 800-53: AU-2, AU-3, AU-12 - reads and assignment changes audited.
// - NIST 800-53: SI-10 - package ids parsed and bounded (256).
// - SPEC: specs/targeting.md#REQ-TGT-001 (per boot service),
//   #REQ-TGT-008 (operator told when none is usable)
// - RFC 9110 §8.8.3 (ETag), §13.1.1 (If-Match)

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{BootService, DbError, RepoTx, Store};
use usgp_proto::api::{Message, PackageRef, Reason};
use usgp_proto::ops::{BootServiceList, BootServiceView, SetBootServicePackagesRequest};
use usgp_proto::{BootServiceId, PackageId, PackageStatus, codes};

use super::{code_of, field_error, if_match, json_response, parse_json, read_body, with_etag};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

fn bs_id(ctx: &RequestCtx) -> Result<BootServiceId, ApiError> {
    BootServiceId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("boot service"))
}

/// The `ETag` of an assignment list: SHA-256 over the sorted package ids.
#[must_use]
pub fn assignment_etag(ids: &[PackageId]) -> String {
    let mut sorted: Vec<String> = ids.iter().map(ToString::to_string).collect();
    sorted.sort();
    let text = format!("bsp-v1\n{}", sorted.join("\n"));
    format!("\"bsp-{}\"", usgp_crypto::sha256(text.as_bytes()).to_hex())
}

/// The view of a boot service and the `ETag` of its assignments.
pub(crate) async fn view<T: RepoTx>(
    tx: &mut T,
    b: &BootService,
) -> Result<(BootServiceView, String), ApiError> {
    let assigned = tx.boot_service_packages(b.id).await?;
    let ids: Vec<PackageId> = assigned.iter().map(|a| a.package_id).collect();
    let mut packages = Vec::with_capacity(ids.len());
    let mut usable: u32 = 0;
    for id in &ids {
        let Some(p) = tx.package(*id).await? else {
            continue;
        };
        if p.status == PackageStatus::Ready {
            usable = usable.saturating_add(1);
        }
        packages.push(PackageRef {
            id: p.id,
            name: p.name,
        });
    }
    let warning = (usable == 0).then(|| Reason {
        code: code_of("no_usable_package"),
        message: Message::truncated(
            "this boot service has no usable package; devices it boots are offered nothing",
        ),
    });
    Ok((
        BootServiceView {
            id: b.id,
            name: b.name.clone(),
            served_subnets: b.served_subnets.clone(),
            status: b.status,
            packages,
            usable_count: usable,
            warning,
        },
        assignment_etag(&ids),
    ))
}

/// `GET /v1/boot-services`.
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mut tx = api.store().begin().await?;
    let mut out = Vec::new();
    for b in tx.list_boot_services().await? {
        out.push(view(&mut tx, &b).await?.0);
    }
    let list = BootServiceList { boot_services: out };
    let d = ctx
        .ok("boot_service.read")
        .detail(Detail::new().with("count", &list.boot_services.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &list)
}

/// `GET /v1/boot-services/{id}`.
pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = bs_id(ctx)?;
    let mut tx = api.store().begin().await?;
    let b = tx
        .boot_service(id)
        .await?
        .ok_or_else(|| ApiError::not_found("boot service"))?;
    let (v, etag) = view(&mut tx, &b).await?;
    let d = ctx
        .ok("boot_service.read")
        .target("boot_service", &id.to_string());
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    Ok(with_etag(json_response!(StatusCode::OK, &v)?, &etag))
}

/// `PUT /v1/boot-services/{id}/packages`.
pub(crate) async fn set_packages<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let id = bs_id(ctx)?;
    let expected = if_match(&req)?.to_vec();
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let wire = parse_json!(SetBootServicePackagesRequest, &body, max)?;
    let ids = wire.validate().map_err(|e| field_error(&e))?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let b = tx
        .boot_service(id)
        .await?
        .ok_or_else(|| ApiError::not_found("boot service"))?;
    let before: Vec<PackageId> = tx
        .boot_service_packages(id)
        .await?
        .iter()
        .map(|a| a.package_id)
        .collect();
    if expected != assignment_etag(&before).as_bytes() {
        return Err(ApiError::precondition_failed());
    }
    match tx
        .set_boot_service_packages(id, &ids, ctx.principal.operator.id, at)
        .await
    {
        Ok(()) => {}
        Err(DbError::NotFound { .. }) => return Err(ApiError::not_found("boot service")),
        Err(DbError::Constraint { .. }) => {
            return Err(ApiError::unprocessable(
                codes::INVALID_VALUE
                    .with_param("package_ids")
                    .unwrap_or(codes::INVALID_VALUE),
                "a package id names no package",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let added = ids.iter().filter(|p| !before.contains(p)).count();
    let removed = before.iter().filter(|p| !ids.contains(p)).count();
    let (v, etag) = view(&mut tx, &b).await?;
    let d = ctx
        .ok("boot_service.packages.set")
        .target("boot_service", &id.to_string())
        .detail(
            Detail::new()
                .with("count", &ids.len())
                .with("added", &added)
                .with("removed", &removed)
                .with(
                    "package_ids",
                    &ids.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                )
                .with("usable_count", &v.usable_count),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    Ok(with_etag(json_response!(StatusCode::OK, &v)?, &etag))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etag_ignores_order_and_changes_with_content() {
        let a = PackageId::from_random_bytes([1; 16]);
        let b = PackageId::from_random_bytes([2; 16]);
        assert_eq!(assignment_etag(&[a, b]), assignment_etag(&[b, a]));
        assert_ne!(assignment_etag(&[a]), assignment_etag(&[a, b]));
        assert_ne!(assignment_etag(&[]), assignment_etag(&[a]));
        assert!(assignment_etag(&[]).starts_with("\"bsp-"));
    }
}
