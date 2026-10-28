//! Operator codes (M3 plan section 3.5): issue (shown once, never
//! stored, logged or audited), list without values, revoke once; lifetime
//! bounded by the server's maximum.

use crate::common::{Harness, Who};

#[tokio::test]
async fn issue_list_revoke() {
    let h = Harness::m3().await;
    let r = h
        .post_json(
            Who::Admin,
            "/v1/auth-codes",
            serde_json::json!({"ttl_s": 600, "note": "rack 4"}),
        )
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let j = r.json();
    let code = j["code"].as_str().unwrap().to_owned();
    let id = j["id"].as_str().unwrap().to_owned();
    assert_eq!(code.len(), 11, "XXXXX-XXXXX");
    // The value is in no record and no later response.
    let plain: String = code.chars().filter(|c| *c != '-').collect();
    let text = h.all_record_text();
    assert!(!text.contains(&code) && !text.contains(&plain));
    let r = h.get(Who::Admin, "/v1/auth-codes").await;
    assert_eq!(r.status, 200);
    let body = String::from_utf8(r.body.clone()).unwrap();
    assert!(!body.contains(&plain) && !body.contains(&code));
    assert_eq!(r.json()["codes"][0]["state"], "active");
    assert_eq!(r.json()["codes"][0]["note"], "rack 4");
    let path = format!("/v1/auth-codes/{id}");
    let r = h.req(Who::Admin, "DELETE", &path, &[], None).await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "revoked");
    let r = h.req(Who::Admin, "DELETE", &path, &[], None).await;
    assert_eq!(r.status, 409);
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/auth-codes/{}", crate::authz_matrix::NOWHERE),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 404);
    for e in [
        "auth_code.issued",
        "auth_code.list.read",
        "auth_code.revoked",
    ] {
        assert_eq!(h.events(e).len(), 1, "{e}");
    }
    assert_eq!(h.events("auth_code.revoke_refused").len(), 2);
}

#[tokio::test]
async fn lifetime_bounded() {
    let h = Harness::m3().await;
    let r = h
        .post_json(
            Who::Admin,
            "/v1/auth-codes",
            serde_json::json!({"ttl_s": 3601}),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "out_of_range:ttl_s");
    let r = h
        .post_json(
            Who::Admin,
            "/v1/auth-codes",
            serde_json::json!({"ttl_s": 0}),
        )
        .await;
    assert_eq!(r.status, 422);
    let r = h
        .post_json(
            Who::Admin,
            "/v1/auth-codes",
            serde_json::json!({"code": "X"}),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(h.events("auth_code.refused").len(), 3);
    // Default lifetime: 900 s.
    let r = h
        .post_json(Who::Admin, "/v1/auth-codes", serde_json::json!({}))
        .await;
    assert_eq!(r.status, 201);
    let exp = r.json()["expires_at"].as_i64().unwrap();
    let now = h.records().last().unwrap().ts_us;
    assert_eq!(exp - now, 900_000_000);
}

/// Without the M3 keys the server refuses to issue codes (fail closed).
#[tokio::test]
async fn no_keys_no_codes() {
    let h = Harness::m3().await;
    let keys = usgp_api::ContentKeys::new(usgp_crypto::SigningKey::generate().unwrap(), Vec::new());
    assert!(keys.is_err(), "content key must be trusted");
    // A server built without provisioning keys.
    let k = usgp_crypto::SigningKey::generate().unwrap();
    let pubk = k.verifying_key().clone();
    let addr = h
        .second_server(usgp_api::ContentKeys::new(k, vec![pubk]).unwrap())
        .await;
    let r = h
        .req_at(
            addr,
            h.cert(Who::Admin),
            "POST",
            "/v1/auth-codes",
            &[],
            Some(b"{}".to_vec()),
        )
        .await;
    assert_eq!(r.status, 503);
    assert_eq!(r.code(), "unavailable");
}
