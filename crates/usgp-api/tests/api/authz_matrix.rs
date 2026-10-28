//! Authorisation on every route (REQ-RBAC-001, REQ-RBAC-003,
//! REQ-RBAC-004).

use usgp_api::routes::ROUTES;

use crate::common::{Harness, Who};

/// A concrete request for every route, with real ids where `real`, or
/// fresh ids that name nothing.
pub(crate) fn requests(
    image: &str,
    pe: &str,
    pkg: &str,
    upload: &str,
) -> Vec<(&'static str, String, Option<serde_json::Value>)> {
    let pkg_body = serde_json::json!({
        "name": "X", "image_id": image, "edition_index": 1, "pe_id": pe
    });
    let decl = serde_json::json!({"release": "windows-11", "edition": "enterprise", "architecture": "x64"});
    vec![
        ("GET", "/v1/limits".into(), None),
        (
            "POST",
            "/v1/uploads".into(),
            Some(serde_json::json!({
                "kind": "image", "display_name": "Z", "file_name": "z.wim", "size": 5,
                "sha256": "00".repeat(32)
            })),
        ),
        ("PUT", format!("/v1/uploads/{upload}"), None),
        ("DELETE", format!("/v1/uploads/{upload}"), None),
        ("GET", "/v1/images".into(), None),
        ("GET", format!("/v1/images/{image}"), None),
        (
            "PUT",
            format!("/v1/images/{image}/editions/2/declaration"),
            Some(decl),
        ),
        ("DELETE", format!("/v1/images/{image}"), None),
        ("GET", format!("/v1/images/{image}/manifest"), None),
        ("GET", "/v1/pe".into(), None),
        ("GET", format!("/v1/pe/{pe}"), None),
        ("DELETE", format!("/v1/pe/{pe}"), None),
        ("GET", format!("/v1/pe/{pe}/manifest"), None),
        ("GET", format!("/v1/content/{image}"), None),
        ("GET", "/v1/packages".into(), None),
        ("GET", format!("/v1/packages/{pkg}"), None),
        ("POST", "/v1/packages".into(), Some(pkg_body.clone())),
        ("PUT", format!("/v1/packages/{pkg}"), Some(pkg_body)),
        (
            "POST",
            format!("/v1/packages/{pkg}/clone"),
            Some(serde_json::json!({"name": "C"})),
        ),
        ("DELETE", format!("/v1/packages/{pkg}"), None),
        ("GET", format!("/v1/packages/{pkg}/manifest"), None),
        // M3 (plan section 3.5); ids name nothing.
        (
            "POST",
            "/v1/auth-codes".into(),
            Some(serde_json::json!({"ttl_s": 600})),
        ),
        ("GET", "/v1/auth-codes".into(), None),
        ("DELETE", format!("/v1/auth-codes/{NOWHERE}"), None),
        ("GET", "/v1/device-sessions".into(), None),
        (
            "POST",
            format!("/v1/device-sessions/{NOWHERE}/approve"),
            Some(serde_json::json!({"display_code": "ABC-DEF"})),
        ),
        (
            "POST",
            format!("/v1/device-sessions/{NOWHERE}/refuse"),
            Some(serde_json::json!({})),
        ),
        ("GET", "/v1/jobs".into(), None),
        ("GET", format!("/v1/jobs/{NOWHERE}"), None),
        ("POST", format!("/v1/jobs/{NOWHERE}/acknowledge"), None),
        ("GET", "/v1/boot-services".into(), None),
        ("GET", format!("/v1/boot-services/{NOWHERE}"), None),
        (
            "PUT",
            format!("/v1/boot-services/{NOWHERE}/packages"),
            Some(serde_json::json!({"package_ids": []})),
        ),
        ("GET", "/v1/boot-stops".into(), None),
        ("POST", format!("/v1/boot-stops/{NOWHERE}/clear"), None),
        ("GET", "/v1/relay/boot-policy?have=0".into(), None),
    ]
}

/// The one route no operator may call (a boot service's own).
pub(crate) const RELAY_ROUTE: &str = "/v1/relay/boot-policy";

pub(crate) const NOWHERE: &str = "0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f";

/// An operator with no role gets the same 403 on every route, for real
/// and for non-existent items alike; nothing changes; each refusal is
/// audited as `authz.denied`.
#[tokio::test]
async fn no_role_403_nothing_changes_audited_no_existence_leak() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("authz").await;
    let r = h
        .create_upload("image", "Open", b"FAKEWIM:1:open", None)
        .await;
    let upload = r.json()["upload_id"].as_str().unwrap().to_owned();
    let before = h.snapshot().await;
    let denied_before = h.events("authz.denied").len();

    let real = requests(&image.to_string(), &pe.to_string(), &pkg, &upload);
    let fake = requests(NOWHERE, NOWHERE, NOWHERE, NOWHERE);
    assert_eq!(real.len(), ROUTES.len());
    let mut n = 0;
    for list in [real, fake] {
        let mut bodies = Vec::new();
        for (m, path, body) in list {
            let r = h
                .req(
                    Who::NoRole,
                    m,
                    &path,
                    &[("if-match", "\"r1\"")],
                    body.map(|b| serde_json::to_vec(&b).unwrap()),
                )
                .await;
            assert_eq!(
                r.status,
                403,
                "{m} {path}: {}",
                String::from_utf8_lossy(&r.body)
            );
            assert_eq!(r.code(), "forbidden");
            bodies.push(r.body);
            n += 1;
        }
        // Identical bodies whether or not the item exists.
        assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    }
    assert_eq!(
        h.snapshot().await,
        before,
        "a refused request changed state"
    );
    let denied = h.events("authz.denied");
    assert_eq!(denied.len() - denied_before, n);
    for d in &denied[denied_before..] {
        assert_eq!(d.outcome, "refused");
        assert_eq!(d.reason.as_deref(), Some("forbidden"));
        assert!(d.detail.contains("\"permission\""), "{}", d.detail);
    }
}

/// The administrator role reaches every operator route (no 401/403); the
/// relay's route refuses every operator (403, M3 plan section 3.5).
#[tokio::test]
async fn administrator_can_do_every_route() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("admin").await;
    let r = h
        .create_upload("image", "Open", b"FAKEWIM:1:open2", None)
        .await;
    let upload = r.json()["upload_id"].as_str().unwrap().to_owned();
    for (m, path, body) in requests(&image.to_string(), &pe.to_string(), &pkg, &upload) {
        let r = h
            .req(
                Who::Admin,
                m,
                &path,
                &[],
                body.map(|b| serde_json::to_vec(&b).unwrap()),
            )
            .await;
        if path.starts_with(RELAY_ROUTE) {
            assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
            assert_eq!(r.code(), "forbidden");
            continue;
        }
        assert!(
            r.status != 401 && r.status != 403,
            "{m} {path}: {} {}",
            r.status,
            String::from_utf8_lossy(&r.body)
        );
    }
}
