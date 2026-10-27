//! Packages (REQ-IMG-001, -010 to -015, -041; REQ-OS-005, -009;
//! REQ-PE-007).

use usgp_proto::{PackageManifestV1, SignedEnvelopeV1};

use crate::common::{Harness, Pinned, Who};

fn body(name: &str, image: impl ToString, index: u32, pe: impl ToString) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "name": name, "image_id": image.to_string(), "edition_index": index,
        "pe_id": pe.to_string()
    }))
    .unwrap()
}

/// Ready when declared in scope; the signed manifest verifies with the
/// pinned key and carries the facts with their sources.
#[tokio::test]
async fn ready_when_declared_in_scope_manifest_signed() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("ready").await;
    let v = h.get(Who::Admin, &format!("/v1/packages/{pkg}")).await;
    assert_eq!(v.header("etag").as_deref(), Some("\"r1\""));
    let j = v.json();
    assert_eq!(j["status"], "ready");
    assert_eq!(j["image"]["edition_index"], 1);
    assert_eq!(j["image"]["edition_name"], "Edition 1");
    assert_eq!(j["pe"]["architecture"]["value"], "x64");
    let m = h
        .get(Who::Admin, &format!("/v1/packages/{pkg}/manifest"))
        .await;
    assert_eq!(m.status, 200);
    let env = SignedEnvelopeV1::from_json(&m.body).unwrap();
    let man = PackageManifestV1::open(&env, &Pinned(h.content_pub.clone())).unwrap();
    assert_eq!(man.package_id.to_string(), pkg);
    assert_eq!(man.revision, 1);
    assert_eq!(man.image.facts.release.source.as_str(), "declared");
    assert_eq!(man.image.declared_by, h.admin_id);
    assert!(man.image.declared_audit_seq > 0);
    let _ = (image, pe);
    // Another key does not verify it.
    let other = usgp_crypto::SigningKey::generate().unwrap();
    assert!(PackageManifestV1::open(&env, &Pinned(other.verifying_key().clone())).is_err());
}

/// REQ-OS-009: an undeclared edition makes a not-usable package (no
/// manifest).
#[tokio::test]
async fn undeclared_edition_not_usable() {
    let h = Harness::start().await;
    let image = h.ready_image(2, "undecl").await;
    let pe = h.ready_pe("undecl").await;
    let r = h.create_package("P", image, 2, pe).await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json()["status"], "not_usable");
    assert_eq!(r.json()["status_reason"]["code"], "os_support_unknown");
    let id = r.json()["id"].as_str().unwrap().to_owned();
    let m = h
        .get(Who::Admin, &format!("/v1/packages/{id}/manifest"))
        .await;
    assert_eq!(m.status, 409);
    assert_eq!(m.code(), "package_not_ready");
}

/// REQ-OS-005: an out-of-scope edition is refused at selection, naming
/// the fact; nothing is created; audited `os_support.refused`.
#[tokio::test]
async fn os_scope_refused_at_selection_nothing_created_audited() {
    let h = Harness::start().await;
    let image = h.ready_image(4, "scope").await;
    let pe = h.ready_pe("scope").await;
    h.declare(image, 2, "windows-10", "enterprise", "x64").await;
    h.declare(image, 3, "windows-11", "enterprise-ltsc", "x64")
        .await;
    h.declare(image, 4, "windows-11", "enterprise", "arm64")
        .await;
    let before = h.snapshot().await;
    for (idx, reason) in [
        (2, "release_not_supported:windows-10"),
        (3, "edition_not_supported:enterprise-ltsc"),
        (4, "architecture_not_supported:arm64"),
    ] {
        let r = h.create_package("Bad", image, idx, pe).await;
        assert_eq!(r.status, 422);
        assert_eq!(r.code(), "os_scope");
        assert!(
            r.json()["error"]["message"]
                .as_str()
                .unwrap()
                .contains(reason)
        );
    }
    assert_eq!(h.snapshot().await, before);
    let rec = h.events("os_support.refused");
    assert_eq!(rec.len(), 3);
    assert!(rec[2].detail.contains("\"architecture\":\"arm64\""));
}

#[tokio::test]
async fn bad_index_422_and_not_ready_409() {
    let h = Harness::start().await;
    let image = h.ready_image(2, "idx").await;
    let pe = h.ready_pe("idx").await;
    let r = h.create_package("P", image, 3, pe).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "out_of_range:edition_index");
    let r = h.create_package("P", image, 0, pe).await;
    assert_eq!(r.status, 422);
    let r = h.create_package("P", pe, 1, pe).await;
    assert_eq!(r.code(), "invalid_value:image_id");
    let r = h
        .create_upload("pe", "Open", b"FAKEWIM:1:open pe", Some(("x64", "10.1.1")))
        .await;
    let open_pe = r.json()["content_id"].as_str().unwrap().to_owned();
    let r = h
        .post_json(
            Who::Admin,
            "/v1/packages",
            serde_json::json!({"name": "P", "image_id": image.to_string(), "edition_index": 1, "pe_id": open_pe}),
        )
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "not_ready_content");
}

/// REQ-IMG-012: If-Match required (428), mismatch 412, edit is all or
/// nothing; REQ-PE-007: the PE can be switched.
#[tokio::test]
async fn edit_if_match_all_or_nothing_switch_pe() {
    let h = Harness::start().await;
    let (pkg, image, _pe) = h.ready_package("edit").await;
    let pe2 = h.ready_pe("edit two").await;
    let path = format!("/v1/packages/{pkg}");
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[],
            Some(body("N", image, 1, pe2)),
        )
        .await;
    assert_eq!(r.status, 428);
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", "\"r7\"")],
            Some(body("N", image, 1, pe2)),
        )
        .await;
    assert_eq!(r.status, 412);
    // Out of scope edition: refused, unchanged.
    h.declare(image, 2, "windows-11", "home", "x64").await;
    let before = h.get(Who::Admin, &path).await.body;
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", "\"r1\"")],
            Some(body("N", image, 2, pe2)),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "os_scope");
    assert_eq!(h.get(Who::Admin, &path).await.body, before);
    // Switch PE: revision 2, re-signed.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", "\"r1\"")],
            Some(body("New name", image, 1, pe2)),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.header("etag").as_deref(), Some("\"r2\""));
    assert_eq!(r.json()["pe"]["pe_id"], pe2.to_string());
    let env =
        SignedEnvelopeV1::from_json(&h.get(Who::Admin, &format!("{path}/manifest")).await.body)
            .unwrap();
    let man = PackageManifestV1::open(&env, &Pinned(h.content_pub.clone())).unwrap();
    assert_eq!(man.revision, 2);
    // Edit to an undeclared edition: status change audited.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &path,
            &[("if-match", "\"r2\"")],
            Some(body("New name", image, 3, pe2)),
        )
        .await;
    assert_eq!(r.json()["status"], "not_usable");
    assert_eq!(h.events("package.status.changed").len(), 1);
}

/// REQ-IMG-013: a clone copies everything; the original is unchanged.
#[tokio::test]
async fn clone_copies_all_original_unchanged() {
    let h = Harness::start().await;
    let (pkg, _image, _pe) = h.ready_package("clone").await;
    let orig = h
        .get(Who::Admin, &format!("/v1/packages/{pkg}"))
        .await
        .json();
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/packages/{pkg}/clone"),
            serde_json::json!({"name": "Copy"}),
        )
        .await;
    assert_eq!(r.status, 201);
    let c = r.json();
    assert_ne!(c["id"], orig["id"]);
    assert_eq!(c["name"], "Copy");
    assert_eq!(c["revision"], 1);
    assert_eq!(c["image"], orig["image"]);
    assert_eq!(c["pe"], orig["pe"]);
    assert_eq!(c["status"], "ready");
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/packages/{pkg}"))
            .await
            .json(),
        orig
    );
    let m = h
        .get(
            Who::Admin,
            &format!("/v1/packages/{}/manifest", c["id"].as_str().unwrap()),
        )
        .await;
    assert_eq!(m.status, 200);
}

/// REQ-IMG-014/015: delete needs If-Match; in-use image and PE deletes are
/// refused naming the dependants (decision 0015 item 2).
#[tokio::test]
async fn delete_requires_if_match_in_use_409_names_dependants() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("del").await;
    for (path, id) in [("images", image), ("pe", pe)] {
        let v = h.get(Who::Admin, &format!("/v1/{path}/{id}")).await;
        let etag = v.header("etag").unwrap();
        let r = h
            .req(Who::Admin, "DELETE", &format!("/v1/{path}/{id}"), &[], None)
            .await;
        assert_eq!(r.status, 428);
        let r = h
            .req(
                Who::Admin,
                "DELETE",
                &format!("/v1/{path}/{id}"),
                &[("if-match", "\"sha256:00\"")],
                None,
            )
            .await;
        assert_eq!(r.status, 412);
        let r = h
            .req(
                Who::Admin,
                "DELETE",
                &format!("/v1/{path}/{id}"),
                &[("if-match", &etag)],
                None,
            )
            .await;
        assert_eq!(r.status, 409);
        assert_eq!(r.code(), "in_use");
        assert_eq!(r.json()["error"]["dependants"][0]["id"], pkg);
        assert_eq!(r.json()["error"]["dependants"][0]["name"], "Package del");
    }
    let refused = h.events("image.delete.refused");
    assert!(
        refused
            .iter()
            .any(|r| r.reason.as_deref() == Some("in_use"))
    );
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/packages/{pkg}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 428);
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/packages/{pkg}"),
            &[("if-match", "\"r2\"")],
            None,
        )
        .await;
    assert_eq!(r.status, 412);
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/packages/{pkg}"),
            &[("if-match", "\"r1\"")],
            None,
        )
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/packages/{pkg}"))
            .await
            .status,
        404
    );
    // Now the image can go; its object is unlinked.
    let v = h.get(Who::Admin, &format!("/v1/images/{image}")).await;
    let sha = v.json()["sha256"].as_str().unwrap().to_owned();
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/images/{image}"),
            &[("if-match", &v.header("etag").unwrap())],
            None,
        )
        .await;
    assert_eq!(r.status, 204);
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/images/{image}"))
            .await
            .status,
        404
    );
    let obj = h
        .api
        .files()
        .object_path(&usgp_common::Sha256Digest::from_hex(&sha).unwrap());
    assert!(!obj.exists());
}

/// REQ-AUD-006 for a package action.
#[tokio::test]
async fn audit_failure_refuses_package_create() {
    let h = Harness::start().await;
    let image = h.ready_image(1, "af").await;
    let pe = h.ready_pe("af").await;
    h.declare(image, 1, "windows-11", "enterprise", "x64").await;
    let before = h.snapshot().await;
    h.store.fail_next_audit_writes(1);
    let r = h.create_package("P", image, 1, pe).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "audit_unavailable");
    assert_eq!(h.snapshot().await, before);
}
