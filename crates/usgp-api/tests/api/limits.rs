//! Request limits (plan section 3.2; REQ-IMG-031; SC-5).

use crate::common::{Harness, Opts, Who};

#[tokio::test]
async fn limits_route_states_max() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.content.max_upload_bytes = 12_345_678_901),
        ..Opts::default()
    })
    .await;
    let r = h.get(Who::Admin, "/v1/limits").await;
    assert_eq!(r.status, 200);
    let j = r.json();
    assert_eq!(j["max_upload_bytes"], 12_345_678_901u64);
    assert_eq!(j["max_json_bytes"], 65_536);
    assert_eq!(j["chunk_size"], 8_388_608);
    assert_eq!(h.events("api.limits.read").len(), 1);
}

/// REQ-IMG-031: over the stated limit is refused at session creation,
/// with the limit, before any body is sent.
#[tokio::test]
async fn too_large_413_before_body() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.content.max_upload_bytes = 1000),
        ..Opts::default()
    })
    .await;
    let r = h
        .post_json(
            Who::Admin,
            "/v1/uploads",
            serde_json::json!({
                "kind": "image", "display_name": "Huge", "file_name": "huge.wim",
                "size": 11u64 * 1024 * 1024 * 1024, "sha256": "00".repeat(32)
            }),
        )
        .await;
    assert_eq!(r.status, 413);
    assert_eq!(r.code(), "too_large");
    assert_eq!(r.json()["error"]["limit_bytes"], 1000);
    assert!(h.api.files().list_staging().unwrap().is_empty());
    assert_eq!(
        h.events("content.upload.refused")[0].reason.as_deref(),
        Some("too_large")
    );
}

#[tokio::test]
async fn json_body_limits_and_media_type() {
    let h = Harness::start().await;
    let big = format!("{{\"name\":\"{}\"}}", "x".repeat(70_000));
    let r = h
        .req(
            Who::Admin,
            "POST",
            "/v1/packages",
            &[],
            Some(big.into_bytes()),
        )
        .await;
    assert_eq!(r.status, 413);
    assert_eq!(r.code(), "body_too_large");
    let r = h
        .req(
            Who::Admin,
            "POST",
            "/v1/packages",
            &[("content-type", "text/plain")],
            Some(b"{}".to_vec()),
        )
        .await;
    assert_eq!(r.status, 415);
    let r = h
        .req(
            Who::Admin,
            "POST",
            "/v1/packages",
            &[],
            Some(b"{\"name\":1".to_vec()),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.code(), "invalid_json");
    let r = h
        .req(
            Who::Admin,
            "POST",
            "/v1/packages",
            &[],
            Some(
                br#"{"name":"a","image_id":"x","edition_index":1,"pe_id":"y","extra":1}"#.to_vec(),
            ),
        )
        .await;
    assert_eq!(r.code(), "invalid_json");
}

#[tokio::test]
async fn unknown_route_404_method_405_bad_id_404() {
    let h = Harness::start().await;
    assert_eq!(h.get(Who::Admin, "/v1/nothing").await.status, 404);
    let r = h.req(Who::Admin, "PATCH", "/v1/limits", &[], None).await;
    assert_eq!(r.status, 405);
    assert_eq!(r.header("allow").as_deref(), Some("GET"));
    assert_eq!(h.get(Who::Admin, "/v1/images/not-a-uuid").await.status, 404);
    assert_eq!(h.events("api.request.refused").len(), 2);
}

#[tokio::test]
async fn too_many_headers_refused() {
    let h = Harness::start().await;
    let mut raw = b"GET /v1/limits HTTP/1.1\r\nhost: localhost\r\n".to_vec();
    for i in 0..80 {
        raw.extend_from_slice(format!("x-h{i}: v\r\n").as_bytes());
    }
    raw.extend_from_slice(b"\r\n");
    let out = h.raw(Who::Admin, &raw, false).await;
    let text = String::from_utf8_lossy(&out);
    assert!(text.starts_with("HTTP/1.1 431"), "{text}");
}
