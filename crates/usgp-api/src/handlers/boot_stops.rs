//! Boot stops (REQ-BOOT-067): list, and the minimal operator reversal
//! `POST /v1/boot-stops/{id}/clear` (decision 0021 item 3; REQ-BOOT-062
//! stays OPEN). Clearing bumps the boot service's policy generation in the
//! same transaction, so the relay learns of it at its next pull.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - clearing needs `device.boot_reenable`.
// - NIST 800-53: AU-2, AU-3, AU-12 - list and clear audited
//   (`boot_stop.cleared` names the device, job and new generation).
// - NIST 800-53: CM-3 - the stop-list change and its generation commit
//   with the audit record.
// - SPEC: specs/boot-network.md#REQ-BOOT-067
// - Decision 0021 items 2 and 3

use hyper::{Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::{DbError, RepoTx, Store};
use usgp_proto::ops::BootStopList;
use usgp_proto::{BootStopId, codes};

use super::json_response;
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// `GET /v1/boot-stops` (active and cleared).
pub(crate) async fn list<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mut tx = api.store().begin().await?;
    let list = BootStopList {
        stops: tx
            .list_boot_stops(None, false)
            .await?
            .iter()
            .map(usgp_db::BootStop::view)
            .collect(),
    };
    let d = ctx
        .ok("boot_stop.list.read")
        .detail(Detail::new().with("count", &list.stops.len()));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &list)
}

/// `POST /v1/boot-stops/{id}/clear`.
pub(crate) async fn clear<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let id = BootStopId::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("boot stop"))?;
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let stop = tx
        .boot_stop(id)
        .await?
        .ok_or_else(|| ApiError::not_found("boot stop"))?;
    match tx.clear_boot_stop(id, ctx.principal.operator.id, at).await {
        Ok(()) => {}
        Err(DbError::Conflict { .. }) => {
            return Err(ApiError::conflict(
                codes::WRONG_STATE,
                "the boot stop is already cleared",
            ));
        }
        Err(e) => return Err(e.into()),
    }
    let generation = tx.bump_boot_policy_generation(stop.boot_service_id).await?;
    let d = ctx
        .ok("boot_stop.cleared")
        .target("boot_stop", &id.to_string())
        .detail(
            Detail::new()
                .with("mac", &stop.mac.to_string())
                .with("job_id", &stop.job_id.to_string())
                .with("boot_service_id", &stop.boot_service_id.to_string())
                .with("generation", &generation),
        );
    let r = api.append(&mut tx, &d).await?;
    let view = tx
        .boot_stop(id)
        .await?
        .ok_or_else(|| ApiError::internal_error("boot stop vanished"))?
        .view();
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view)
}
