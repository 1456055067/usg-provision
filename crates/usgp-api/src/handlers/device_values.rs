//! Per-device values (M4 plan sections 1.6 and 3.2): values an operator
//! sets for one MAC address, referenced from an answer-file template as
//! `{{device.<key>}}`. None is a secret.
//!
//! A value is checked when it is saved and again when it is rendered
//! (OPEN-CFG-2: both, the earliest point): `computer_name` by the
//! computer-name rules, `time_zone` by the time-zone rules, any other key
//! as a carried value.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3 - `device_value.manage` / `device_value.view`.
// - NIST 800-53: AU-2, AU-3, AU-12 - set and delete audited with the key
//   names, never the values; reads audited.
// - NIST 800-53: SI-10 - at most 32 values; keys `[a-z][a-z0-9_]*` of at
//   most 57 bytes; values checked by their rules.
// - NIST 800-53: CM-6 - values validated before they can reach an answer
//   file.
// - SPEC: specs/configuration.md#REQ-CFG-004, #REQ-CFG-005, #REQ-CFG-007

use std::collections::BTreeMap;

use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use usgp_audit::Detail;
use usgp_db::model::{MAX_DEVICE_VALUES, config_value_ok, device_value_key_ok};
use usgp_db::{DbError, DeviceValues, RepoTx, Store};
use usgp_proto::{MacAddress, OperatorId, UnixMicros, codes};
use usgp_wincfg::unattend::values::{check_carried, check_computer_name, check_time_zone};

use super::{json_response, parse_json, read_body};
use crate::body::ApiBody;
use crate::context::{Api, RequestCtx};
use crate::error::ApiError;

/// `PUT /v1/device-values/{mac}` body.
#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SetValues {
    values: BTreeMap<String, String>,
}

#[derive(Debug, serde::Serialize)]
struct ValuesView {
    mac: String,
    values: BTreeMap<String, String>,
    updated_by: OperatorId,
    updated_at: UnixMicros,
}

fn mac_param(ctx: &RequestCtx) -> Result<MacAddress, ApiError> {
    MacAddress::parse(ctx.params.get(0)).map_err(|_| ApiError::not_found("device values"))
}

fn invalid(key: &str, why: &str) -> ApiError {
    let field = if device_value_key_ok(key) {
        format!("values.{key}")
    } else {
        "values".to_owned()
    };
    ApiError::unprocessable(
        codes::INVALID_VALUE
            .with_param(&field)
            .unwrap_or(codes::INVALID_VALUE),
        why.to_owned(),
    )
}

/// Checks one device value by its key's rules (also used at render).
pub(crate) fn check_device_value(key: &str, value: &str) -> Result<(), &'static str> {
    let r = match key {
        "computer_name" => check_computer_name(value),
        "time_zone" => check_time_zone(value),
        _ => check_carried(value),
    };
    r.map_err(|_| "the value breaks the rules for its key")
}

fn validate(values: &BTreeMap<String, String>) -> Result<(), ApiError> {
    if values.is_empty() || values.len() > MAX_DEVICE_VALUES {
        return Err(invalid(
            "",
            "values must hold 1 to 32 entries (delete the entry to clear it)",
        ));
    }
    for (k, v) in values {
        if !device_value_key_ok(k) {
            return Err(invalid(
                k,
                "each key must match [a-z][a-z0-9_]* and be at most 57 bytes",
            ));
        }
        if !config_value_ok(v) {
            return Err(invalid(
                k,
                "each value must be 1 to 2048 characters with no control characters",
            ));
        }
        check_device_value(k, v).map_err(|why| invalid(k, why))?;
    }
    Ok(())
}

fn view(v: &DeviceValues) -> ValuesView {
    ValuesView {
        mac: v.mac.to_string(),
        values: v.values.clone(),
        updated_by: v.updated_by,
        updated_at: v.updated_at,
    }
}

fn keys(v: &BTreeMap<String, String>) -> String {
    v.keys().map(String::as_str).collect::<Vec<_>>().join(",")
}

/// `PUT /v1/device-values/{mac}`.
pub(crate) async fn set<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
    req: Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let mac = mac_param(ctx)?;
    let max = api.config().limits.max_json_bytes;
    let body = read_body(req, max).await?;
    let s = parse_json!(SetValues, &body, max)?;
    validate(&s.values)?;
    let at = api.now()?;
    let v = DeviceValues {
        mac,
        values: s.values,
        updated_by: ctx.principal.operator.id,
        updated_at: at,
    };
    let mut tx = api.store().begin().await?;
    let before = tx.device_values(mac).await?;
    match tx.set_device_values(&v).await {
        Ok(()) => {}
        Err(DbError::InvalidArgument { .. }) => {
            return Err(invalid("", "the values break a storage bound"));
        }
        Err(e) => return Err(e.into()),
    }
    // Names of the keys only; values are not recorded (they are not
    // secret, but the record does not need them).
    let d = ctx
        .ok("device_value.set")
        .target("device_value", &mac.to_string())
        .detail(
            Detail::new().with("keys", &keys(&v.values)).with(
                "previous_keys",
                &before
                    .as_ref()
                    .map_or_else(String::new, |b| keys(&b.values)),
            ),
        );
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view(&v))
}

/// `GET /v1/device-values/{mac}`.
pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mac = mac_param(ctx)?;
    let mut tx = api.store().begin().await?;
    let v = tx
        .device_values(mac)
        .await?
        .ok_or_else(|| ApiError::not_found("device values"))?;
    let d = ctx
        .ok("device_value.read")
        .target("device_value", &mac.to_string());
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    json_response!(StatusCode::OK, &view(&v))
}

/// `DELETE /v1/device-values/{mac}`.
pub(crate) async fn delete<S: Store + 'static>(
    api: &Api<S>,
    ctx: &RequestCtx,
) -> Result<Response<ApiBody>, ApiError> {
    let mac = mac_param(ctx)?;
    let mut tx = api.store().begin().await?;
    let before = tx
        .device_values(mac)
        .await?
        .ok_or_else(|| ApiError::not_found("device values"))?;
    match tx.delete_device_values(mac).await {
        Ok(()) => {}
        Err(DbError::NotFound { .. }) => return Err(ApiError::not_found("device values")),
        Err(e) => return Err(e.into()),
    }
    let d = ctx
        .ok("device_value.deleted")
        .target("device_value", &mac.to_string())
        .detail(Detail::new().with("keys", &keys(&before.values)));
    let r = api.append(&mut tx, &d).await?;
    api.commit(tx, &[r]).await?;
    let mut resp = Response::new(ApiBody::empty());
    *resp.status_mut() = StatusCode::NO_CONTENT;
    Ok(resp)
}
