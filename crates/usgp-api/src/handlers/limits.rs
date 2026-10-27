//! `GET /v1/limits`: the limits the server applies, so the operator learns
//! them before an upload (REQ-IMG-031).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12 - the read is audited (`api.limits.read`).
// - SPEC: specs/os-images.md#REQ-IMG-031 (the limit is stated)

use hyper::{Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::Store;
use usgp_proto::api::LimitsView;

use super::json_response;
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let c = api.config();
    let view = LimitsView::new(
        c.content.max_upload_bytes,
        u64::try_from(c.limits.max_json_bytes).unwrap_or(u64::MAX),
    );
    let d = ctx.ok("api.limits.read").detail(
        Detail::new()
            .with("max_upload_bytes", &view.max_upload_bytes)
            .with("max_json_bytes", &view.max_json_bytes),
    );
    api.record(&d).await?;
    json_response!(StatusCode::OK, &view)
}
