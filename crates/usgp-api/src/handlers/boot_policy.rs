//! `GET /v1/relay/boot-policy?have=<generation>`: the signed boot-policy
//! list a relay pulls over mTLS (plan M3 section 3.6; decision 0021 item
//! 2). Only an authenticated boot service may call it, and it gets the
//! list of its own record: the boot service is the one its client
//! certificate is bound to, never one named in the request.
//!
//! - `have` equal to the current generation: 304, no body.
//! - otherwise: 200 with the JSON of a `SignedEnvelopeV1` whose payload is
//!   a `BootPolicyV1` (schema 1, this boot service, the current
//!   generation, `key_id` = the boot-policy key, the uncleared stops),
//!   signed with the boot-policy key. A relay that is ahead (after a
//!   database restore) gets the current list and refuses it as a rollback
//!   on its side.
//! - Generations start at 1: a boot service whose stop set never changed
//!   gets generation 1 on its first pull (audited), so a relay that starts
//!   with no list (`have=0`) can leave its fail-closed state.
//!
//! The generation is read before the stops, in one transaction; a stop
//! change commits together with its generation bump, so a list never
//! carries a newer generation than its stops.
//!
//! Every 200 is audited (`boot_policy.read`); 304 answers are audited at
//! most once per [`NOT_MODIFIED_RECORD_EVERY`] per boot service, with the
//! number left out since the last record.

// COMPLIANCE MAPPING:
// - NIST 800-53: IA-3, IA-5(2) - relay identified by its client
//   certificate bound to one active boot-service record.
// - NIST 800-53: SI-7, SI-7(6) - list signed with the boot-policy key
//   (ECDSA P-384, FIPS module).
// - NIST 800-53: SC-23 - monotonic generation (rollback refused by the
//   relay).
// - NIST 800-53: AU-2, AU-12, AU-4 - reads audited, 304 records rate-capped.
// - SPEC: specs/boot-network.md#REQ-BOOT-067
// - Decision 0021 items 1 and 2
// - RFC 9110 §15.4.5 (304 Not Modified)

use std::time::{Duration, Instant};

use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::{Request, Response, StatusCode};
use usgp_audit::{AuditDraft, Detail, Interface, Outcome};
use usgp_db::{RepoTx, Store};
use usgp_proto::boot_policy::SCHEMA_V1;
use usgp_proto::{BootPolicyV1, BootStopEntryV1, PayloadType};

use super::auth_codes::keys_unavailable;
use crate::authn::BootServicePrincipal;
use crate::body::ApiBody;
use crate::context::{AlarmGate, Api};
use crate::error::ApiError;
use crate::manifest::envelope;

/// At most one `boot_policy.read` record per boot service in this
/// interval for 304 answers (a relay polls every 30 s by default).
pub const NOT_MODIFIED_RECORD_EVERY: Duration = Duration::from_secs(900);

/// Longest `have` value text (u64 has at most 20 digits).
const MAX_HAVE_DIGITS: usize = 20;

/// The `have` generation: the query must be exactly `have=<decimal>`.
fn have<B>(req: &Request<B>) -> Result<u64, ApiError> {
    let bad = || ApiError::bad_request("the query must be have=<generation>");
    let q = req.uri().query().ok_or_else(bad)?;
    let v = q.strip_prefix("have=").ok_or_else(bad)?;
    if v.is_empty() || v.len() > MAX_HAVE_DIGITS || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    v.parse::<u64>().map_err(|_| bad())
}

/// Serves the boot policy of the calling boot service.
pub(crate) async fn get<S: Store + 'static>(
    api: &Api<S>,
    b: &BootServicePrincipal,
    source: &str,
    req: &Request<Incoming>,
) -> Result<Response<ApiBody>, ApiError> {
    let have = have(req)?;
    let keys = api.provisioning_keys().ok_or_else(keys_unavailable)?;
    let id = b.boot_service.id;
    let draft = |event: &str| {
        AuditDraft::new(event, Outcome::Success, b.actor(), Interface::RelayFeed)
            .source(source)
            .target("boot_service", &id.to_string())
    };
    let at = api.now()?;
    let mut tx = api.store().begin().await?;
    let mut recs = Vec::new();
    let mut generation = tx.boot_policy_generation(id).await?;
    if generation == 0 {
        generation = tx.bump_boot_policy_generation(id).await?;
        let d = draft("boot_policy.generation.initialised")
            .detail(Detail::new().with("generation", &generation));
        recs.push(api.append(&mut tx, &d).await?);
    }
    if have == generation {
        let fire = api
            .inner
            .device
            .policy_reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(id)
            .or_insert_with(|| AlarmGate::new(NOT_MODIFIED_RECORD_EVERY))
            .fire(Instant::now());
        if let Some(suppressed) = fire {
            let d = draft("boot_policy.read").detail(
                Detail::new()
                    .with("have", &have)
                    .with("generation", &generation)
                    .with("not_modified", &true)
                    .with("not_modified_unrecorded", &suppressed),
            );
            recs.push(api.append(&mut tx, &d).await?);
        }
        if recs.is_empty() {
            tx.rollback().await;
        } else {
            api.commit(tx, &recs).await?;
        }
        let mut r = Response::new(ApiBody::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        return Ok(r);
    }
    let stops: Vec<BootStopEntryV1> = tx
        .list_boot_stops(Some(id), true)
        .await?
        .iter()
        .map(|s| BootStopEntryV1 {
            mac: s.mac,
            job_id: s.job_id,
        })
        .collect();
    let policy = BootPolicyV1 {
        schema: SCHEMA_V1,
        boot_service_id: id,
        generation,
        issued_at_us: at,
        key_id: keys.boot_policy_key_id().0,
        stops,
    };
    let payload = policy.to_payload().map_err(ApiError::internal_error)?;
    let payload_sha256 = usgp_crypto::sha256(&payload);
    let signed = keys
        .sign_boot_policy(payload)
        .map_err(ApiError::internal_error)?;
    let json = envelope(PayloadType::BootPolicyV1, &signed)
        .map_err(ApiError::internal_error)?
        .to_json()
        .map_err(ApiError::internal_error)?;
    let d = draft("boot_policy.read").detail(
        Detail::new()
            .with("have", &have)
            .with("generation", &generation)
            .with("stops", &policy.stops.len())
            .with("payload_sha256", &payload_sha256)
            .with("key_id", &signed.key_id),
    );
    recs.push(api.append(&mut tx, &d).await?);
    api.commit(tx, &recs).await?;
    let mut r = Response::new(ApiBody::full(json));
    r.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(usgp_proto::api::JSON_MEDIA_TYPE),
    );
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(q: &str) -> Request<()> {
        Request::get(format!("/v1/relay/boot-policy{q}"))
            .body(())
            .unwrap()
    }

    #[test]
    fn have_is_strict() {
        assert_eq!(have(&req("?have=0")).unwrap(), 0);
        assert_eq!(have(&req("?have=42")).unwrap(), 42);
        for bad in [
            "",
            "?",
            "?have=",
            "?have=-1",
            "?have=1&x=2",
            "?x=1",
            "?have=+1",
            "?have=99999999999999999999",
            "?have=1%20",
        ] {
            assert!(have(&req(bad)).is_err(), "{bad}");
        }
    }
}
