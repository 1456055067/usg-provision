//! The route table is complete and every route names a permission and
//! audit events (REQ-RBAC-001, REQ-AUD-001); every mutation in a full flow
//! leaves its audit record; no response or record can carry key material
//! (REQ-IMG-054, REQ-RBAC-006, REQ-AUD-003).

use std::collections::HashSet;

use usgp_api::routes::{Access, ROUTES};
use usgp_audit::verify_chain;

use crate::common::{Harness, Who};

/// Plan section 3.2 (M2) and M3 plan section 3.5, method and path for
/// every route.
const PLAN: &[(&str, &str)] = &[
    ("GET", "/v1/limits"),
    ("POST", "/v1/uploads"),
    ("PUT", "/v1/uploads/{id}"),
    ("DELETE", "/v1/uploads/{id}"),
    ("GET", "/v1/images"),
    ("GET", "/v1/images/{id}"),
    ("PUT", "/v1/images/{id}/editions/{index}/declaration"),
    ("DELETE", "/v1/images/{id}"),
    ("GET", "/v1/images/{id}/manifest"),
    ("GET", "/v1/pe"),
    ("GET", "/v1/pe/{id}"),
    ("DELETE", "/v1/pe/{id}"),
    ("GET", "/v1/pe/{id}/manifest"),
    ("GET", "/v1/content/{id}"),
    ("GET", "/v1/packages"),
    ("GET", "/v1/packages/{id}"),
    ("POST", "/v1/packages"),
    ("PUT", "/v1/packages/{id}"),
    ("POST", "/v1/packages/{id}/clone"),
    ("DELETE", "/v1/packages/{id}"),
    ("GET", "/v1/packages/{id}/manifest"),
    // M3 plan section 3.5.
    ("POST", "/v1/auth-codes"),
    ("GET", "/v1/auth-codes"),
    ("DELETE", "/v1/auth-codes/{id}"),
    ("GET", "/v1/device-sessions"),
    ("POST", "/v1/device-sessions/{id}/approve"),
    ("POST", "/v1/device-sessions/{id}/refuse"),
    ("GET", "/v1/jobs"),
    ("GET", "/v1/jobs/{id}"),
    ("POST", "/v1/jobs/{id}/acknowledge"),
    ("GET", "/v1/boot-services"),
    ("GET", "/v1/boot-services/{id}"),
    ("PUT", "/v1/boot-services/{id}/packages"),
    ("GET", "/v1/boot-stops"),
    ("POST", "/v1/boot-stops/{id}/clear"),
    ("GET", "/v1/relay/boot-policy"),
];

#[test]
fn every_route_has_permission_and_audit() {
    let table: HashSet<_> = ROUTES.iter().map(|r| (r.method, r.pattern)).collect();
    let plan: HashSet<_> = PLAN.iter().copied().collect();
    assert_eq!(table, plan, "route table differs from plan section 3.2");
    for r in ROUTES {
        assert!(!r.events.is_empty(), "{r:?} has no success event");
        assert!(!r.refused_event.is_empty(), "{r:?} has no refusal event");
        for e in r.events.iter().chain([&r.refused_event]) {
            assert!(
                e.split('.').all(
                    |p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                ),
                "{e}"
            );
        }
        match r.access {
            Access::One(_) => {}
            Access::ByKind { image, pe } => assert_ne!(image, pe),
            // Only the relay route; no operator permission names it.
            Access::BootService => {
                assert_eq!(r.pattern, "/v1/relay/boot-policy");
                assert!(r.access.permissions().is_empty());
            }
        }
    }
}

/// A full flow; then every mutating route has left its main event, and
/// the chain verifies (REQ-AUD-001, REQ-AUD-005 through usgp-audit).
#[tokio::test]
async fn every_mutation_emits_audit() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("flow").await;
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/packages/{pkg}"),
            &[("if-match", "\"r1\"")],
            Some(
                serde_json::to_vec(&serde_json::json!({
                    "name": "Renamed", "image_id": image.to_string(),
                    "edition_index": 1, "pe_id": pe.to_string()
                }))
                .unwrap(),
            ),
        )
        .await;
    assert_eq!(r.status, 200);
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/packages/{pkg}/clone"),
            serde_json::json!({"name": "Copy"}),
        )
        .await;
    assert_eq!(r.status, 201);
    let copy = r.json()["id"].as_str().unwrap().to_owned();
    for p in [&pkg, &copy] {
        let r = h.get(Who::Admin, &format!("/v1/packages/{p}")).await;
        let etag = r.header("etag").unwrap();
        let r = h
            .req(
                Who::Admin,
                "DELETE",
                &format!("/v1/packages/{p}"),
                &[("if-match", &etag)],
                None,
            )
            .await;
        assert_eq!(r.status, 204);
    }
    for (path, id) in [("images", image), ("pe", pe)] {
        let r = h.get(Who::Admin, &format!("/v1/{path}/{id}")).await;
        let etag = r.header("etag").unwrap();
        let r = h
            .req(
                Who::Admin,
                "DELETE",
                &format!("/v1/{path}/{id}"),
                &[("if-match", &etag)],
                None,
            )
            .await;
        assert_eq!(r.status, 204, "{}", String::from_utf8_lossy(&r.body));
    }
    // Cancel of an open upload.
    let r = h
        .create_upload("image", "Cancelled", b"FAKEWIM:1:c", None)
        .await;
    let up = r.json()["upload_id"].as_str().unwrap().to_owned();
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/uploads/{up}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 204);

    for event in [
        "content.upload.created",
        "content.upload.started",
        "content.upload.received",
        "content.check.started",
        "content.ready",
        "content.manifest.signed",
        "pe.declared",
        "edition.declared",
        "package.created",
        "package.manifest.signed",
        "package.edited",
        "package.cloned",
        "package.deleted",
        "image.deleted",
        "pe.deleted",
        "content.upload.cancelled",
        "content.failed",
    ] {
        assert!(!h.events(event).is_empty(), "no {event} record");
    }
    // Who, where, source on every API record (AU-3).
    for r in h.records().iter().filter(|r| r.interface == "api") {
        assert_eq!(r.actor_kind, "operator", "{r:?}");
        assert!(r.actor_id.is_some() && r.source.is_some(), "{r:?}");
        assert_eq!(r.node, "test-node");
    }
    // The chain is intact (no checkpoints in this harness: one trusted key
    // is still required by the verifier).
    let k = usgp_crypto::SigningKey::generate().unwrap();
    let rep = verify_chain(&h.records(), &[], &[k.verifying_key().clone()]).unwrap();
    assert!(rep.is_intact(), "{rep:?}");
}

/// No response body or audit record contains key material: no PEM
/// armour, and not the base64 or hex of the content key's SPKI (a public
/// key, used as a canary for "key bytes leaked").
#[tokio::test]
async fn no_secret_fields_in_types() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("secrets").await;
    let mut bodies = Vec::new();
    for p in [
        "/v1/limits".to_owned(),
        "/v1/images".to_owned(),
        format!("/v1/images/{image}"),
        format!("/v1/images/{image}/manifest"),
        "/v1/pe".to_owned(),
        format!("/v1/pe/{pe}"),
        format!("/v1/pe/{pe}/manifest"),
        "/v1/packages".to_owned(),
        format!("/v1/packages/{pkg}"),
        format!("/v1/packages/{pkg}/manifest"),
    ] {
        let r = h.get(Who::Admin, &p).await;
        assert_eq!(r.status, 200, "{p}");
        bodies.push(String::from_utf8(r.body).unwrap());
    }
    for r in h.records() {
        bodies.push(format!("{r:?}"));
    }
    let spki_hex: String = h
        .content_pub
        .spki_der()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for b in &bodies {
        for bad in ["BEGIN", "PRIVATE KEY", "password", spki_hex.as_str()] {
            assert!(!b.contains(bad), "{bad} found in {b}");
        }
    }
}
