//! The device route table (M3 plan section 3.1): every route but open
//! needs a bearer token; no route answers without one; unknown routes and
//! methods are refused; the operator routes are not on the device
//! listener and the device routes are not on the operator listener.

use usgp_api::device::routes::{DEVICE_ROUTES, DeviceRouteId};

use crate::common::{Harness, Who};

fn concrete(pattern: &str) -> String {
    pattern
        .replace("{job}", crate::authz_matrix::NOWHERE)
        .replace("{sha256}", &"ab".repeat(32))
        .replace("{n}", "0")
}

#[tokio::test]
async fn every_bearer_route_refuses_without_token() {
    let h = Harness::m3().await;
    h.loopback_service("routes").await;
    let mut n = 0;
    for r in DEVICE_ROUTES.iter().filter(|r| r.id != DeviceRouteId::Open) {
        let body = r.json_body.then(|| b"{}".to_vec());
        let resp = h
            .dev_raw(
                r.method,
                &concrete(r.pattern),
                &[("content-type", "application/json")],
                body,
            )
            .await;
        assert_eq!(resp.status, 401, "{} {}", r.method, r.pattern);
        assert_eq!(resp.code(), "invalid_token");
        n += 1;
    }
    assert_eq!(n, DEVICE_ROUTES.len() - 1);
    assert_eq!(h.events("auth.unauthenticated").len(), n);
}

#[tokio::test]
async fn listeners_are_separate() {
    let h = Harness::m3().await;
    h.loopback_service("separate").await;
    // Operator routes do not exist on the device listener.
    let r = h.dev_raw("GET", "/v1/packages", &[], None).await;
    assert_eq!(r.status, 404);
    let r = h
        .dev_raw("GET", "/v1/relay/boot-policy?have=0", &[], None)
        .await;
    assert_eq!(r.status, 404);
    let r = h.dev_raw("DELETE", "/v1/device/sessions", &[], None).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow").as_deref(), Some("POST"));
    // Device routes do not exist on the operator listener.
    let r = h
        .post_json(
            Who::Admin,
            "/v1/device/sessions",
            crate::common::hello(&["02:00:00:00:03:01"]),
        )
        .await;
    assert_eq!(r.status, 404);
    // The device listener needs JSON on JSON routes.
    let r = h
        .dev_raw(
            "POST",
            "/v1/device/sessions",
            &[("content-type", "text/plain")],
            Some(b"{}".to_vec()),
        )
        .await;
    assert_eq!(r.status, 415);
}
