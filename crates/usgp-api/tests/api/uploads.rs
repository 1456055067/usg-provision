//! Uploads, checks and PE import (REQ-IMG-004, -020, -021, -022, -030,
//! -033, -035, -052; REQ-PE-002, -004, -005, -009; REQ-AUD-002, -006).

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use usgp_api::WimChecker;
use usgp_proto::{ContentId, ContentState, KitVersion};

use crate::common::{Harness, Opts, Who};

fn upload_id(r: &crate::common::Resp) -> String {
    r.json()["upload_id"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn zero_size_refused_422() {
    let h = Harness::start().await;
    let before = h.snapshot().await;
    let r = h.create_upload("image", "Empty", b"", None).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "empty_file");
    assert_eq!(h.snapshot().await, before);
    let rec = h.events("content.upload.refused");
    assert_eq!(rec.len(), 1);
    assert_eq!(rec[0].reason.as_deref(), Some("empty_file"));
}

/// Upload, check, Ready; file names with spaces round-trip; states and
/// the reason are visible; the object is read-only; the records name the
/// upload that started them (REQ-AUD-002).
#[tokio::test]
async fn file_name_with_spaces_roundtrip_ready_object_readonly() {
    let h = Harness::start().await;
    let data = b"FAKEWIM:2:spaces";
    let r = h
        .post_json(
            Who::Admin,
            "/v1/uploads",
            serde_json::json!({
                "kind": "image", "display_name": "Win 11 Ent", "file_name": "install image (1).wim",
                "size": data.len(), "sha256": usgp_crypto::sha256(data).to_hex()
            }),
        )
        .await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json()["state"], "open");
    let up = upload_id(&r);
    let id = ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap();
    // Receiving is visible before the body.
    let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await;
    assert_eq!(v.json()["state"], "receiving");
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(data.to_vec()),
        )
        .await;
    assert_eq!(r.status, 202);
    assert_eq!(r.json()["state"], "checking");
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Ready);
    let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await;
    let j = v.json();
    assert_eq!(j["file_name"], "install image (1).wim");
    assert_eq!(j["state"], "ready");
    assert_eq!(j["editions"].as_array().unwrap().len(), 2);
    assert_eq!(j["editions"][1]["name"], "Edition 2");
    assert_eq!(j["editions"][0]["support"]["status"], "unknown");
    assert_eq!(j["sha256"], usgp_crypto::sha256(data).to_hex());
    assert_eq!(
        v.header("etag").unwrap(),
        format!("\"sha256:{}\"", usgp_crypto::sha256(data).to_hex())
    );
    // Read-only object under the content root (REQ-IMG-052).
    let obj = h.api.files().object_path(&c.sha256);
    let mode = std::fs::metadata(&obj).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o440);
    assert!(h.api.files().list_staging().unwrap().is_empty());
    // Download returns the same bytes under the same name's content.
    let d = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_eq!(d.status, 200);
    assert_eq!(d.body, data);
    // REQ-AUD-002: later state changes name the upload record.
    let created = h.events("content.upload.created");
    let seq = created.last().unwrap().seq;
    for e in [
        "content.ready",
        "content.manifest.signed",
        "content.upload.received",
    ] {
        let r = h.events(e);
        assert_eq!(r.last().unwrap().initiating_seq, Some(seq), "{e}");
    }
}

#[tokio::test]
async fn reason_in_body_and_failed_audited() {
    // The production WIM checker on bytes that are not a WIM.
    let h = Harness::with(Opts {
        checker: Some(Arc::new(WimChecker::new(usgp_image::WimLimits::DEFAULT))),
        ..Opts::default()
    })
    .await;
    let id = h
        .upload("image", "Not a WIM", b"this is not a wim file", None)
        .await;
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await;
    assert_eq!(v.json()["reason"]["code"], "wim_not_wim");
    assert!(!v.json()["reason"]["message"].as_str().unwrap().is_empty());
    let f = h.events("content.failed");
    assert_eq!(f.last().unwrap().reason.as_deref(), Some("wim_not_wim"));
    assert!(f.last().unwrap().initiating_seq.is_some());
    assert!(h.api.files().list_staging().unwrap().is_empty());
}

#[tokio::test]
async fn digest_mismatch_failed_staging_removed() {
    let h = Harness::start().await;
    let r = h
        .post_json(
            Who::Admin,
            "/v1/uploads",
            serde_json::json!({
                "kind": "image", "display_name": "D", "file_name": "d.wim",
                "size": 5, "sha256": "ab".repeat(32)
            }),
        )
        .await;
    let up = upload_id(&r);
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"12345".to_vec()),
        )
        .await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "digest_mismatch");
    assert!(h.api.files().list_staging().unwrap().is_empty());
    assert_eq!(
        h.events("content.upload.failed")
            .last()
            .unwrap()
            .reason
            .as_deref(),
        Some("digest_mismatch")
    );
}

/// REQ-IMG-035: a body that stops early leaves the content Failed and the
/// partial data removed.
#[tokio::test]
async fn interrupted_body_failed_staging_removed() {
    let h = Harness::start().await;
    let data = vec![7u8; 100_000];
    let r = h.create_upload("image", "Cut", &data, None).await;
    let up = upload_id(&r);
    let id = ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap();
    let mut req = format!(
        "PUT /v1/uploads/{up} HTTP/1.1\r\nhost: localhost\r\ncontent-length: {}\r\n\r\n",
        data.len()
    )
    .into_bytes();
    req.extend_from_slice(&data[..40_000]);
    h.raw(Who::Admin, &req, true).await;
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    assert_eq!(c.reason.unwrap().code, "interrupted");
    assert!(h.api.files().list_staging().unwrap().is_empty());
    let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await;
    assert_eq!(v.json()["state"], "failed");
}

#[tokio::test]
async fn chunked_411_size_mismatch_400_and_wrong_owner_403() {
    let h = Harness::start().await;
    let r = h.create_upload("image", "L", b"FAKEWIM:1:len", None).await;
    let up = upload_id(&r);
    let raw = format!(
        "PUT /v1/uploads/{up} HTTP/1.1\r\nhost: localhost\r\ntransfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
    let out = h.raw(Who::Admin, raw.as_bytes(), false).await;
    assert!(
        String::from_utf8_lossy(&out).starts_with("HTTP/1.1 411"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"short".to_vec()),
        )
        .await;
    assert_eq!(r.status, 400);
    assert_eq!(r.code(), "size_mismatch");
    // Only the operator who opened the session may send its body or
    // cancel it.
    for m in ["PUT", "DELETE"] {
        let r = h
            .req(
                Who::Admin2,
                m,
                &format!("/v1/uploads/{up}"),
                &[],
                Some(b"FAKEWIM:1:len".to_vec()),
            )
            .await;
        assert_eq!(r.status, 403, "{m}");
    }
    assert_eq!(
        h.events("authz.denied")
            .iter()
            .filter(|r| r.detail.contains("not_session_owner"))
            .count(),
        2
    );
    // Still open: the right body is accepted afterwards.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"FAKEWIM:1:len".to_vec()),
        )
        .await;
    assert_eq!(r.status, 202);
    // A second body for the same session is refused.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"FAKEWIM:1:len".to_vec()),
        )
        .await;
    assert_eq!(r.status, 409);
}

#[tokio::test]
async fn duplicate_409_and_quota_429() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.content.max_open_uploads = 3;
            c.content.max_open_uploads_per_operator = 2;
        }),
        ..Opts::default()
    })
    .await;
    let id = h.ready_image(1, "dup").await;
    let r = h
        .create_upload("image", "Again", b"FAKEWIM:1:image dup", None)
        .await;
    assert_eq!(r.status, 409);
    assert_eq!(r.code(), "duplicate");
    assert_eq!(r.json()["error"]["existing_id"], id.to_string());
    assert_eq!(h.create_upload("image", "A", b"a", None).await.status, 201);
    assert_eq!(h.create_upload("image", "B", b"b", None).await.status, 201);
    let r = h.create_upload("image", "C", b"c", None).await;
    assert_eq!(r.status, 429);
    assert_eq!(r.code(), "quota");
}

#[tokio::test]
async fn cancel() {
    let h = Harness::start().await;
    let r = h.create_upload("image", "X", b"FAKEWIM:1:x", None).await;
    let up = upload_id(&r);
    let id = ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap();
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
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    assert_eq!(c.reason.unwrap().code, "cancelled");
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"FAKEWIM:1:x".to_vec()),
        )
        .await;
    assert_eq!(r.status, 409);
}

/// REQ-IMG-021: a check with no progress fails; it does not hang.
#[tokio::test]
async fn stall_watchdog_fails() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.content.check_stall_timeout = Duration::from_secs(1)),
        ..Opts::default()
    })
    .await;
    let id = h.upload("image", "Stall", b"STALL forever", None).await;
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    assert_eq!(c.reason.unwrap().code, "wim_check_stalled");
}

/// REQ-PE-002/004/005: an x64 PE imports with its declaration recorded
/// as `declared`; non-x64 is refused before any body, naming the
/// architecture; the declaration is required.
#[tokio::test]
async fn pe_import_declaration_rules() {
    let h = Harness::start().await;
    let id = h.ready_pe("ok").await;
    let v = h.get(Who::Admin, &format!("/v1/pe/{id}")).await;
    let j = v.json();
    assert_eq!(
        j["architecture"],
        serde_json::json!({"value": "x64", "source": "declared"})
    );
    assert_eq!(j["kit_version"]["value"], "10.1.26100.1");
    assert_eq!(j["kit_version"]["source"], "declared");
    assert_eq!(j["usable_index"], 1);
    assert!(j["kit_warning"].is_null());
    assert_eq!(h.events("pe.declared").len(), 1);

    let before = h.snapshot().await;
    for arch in ["x86", "arm64", "arm"] {
        let r = h
            .create_upload("pe", "Bad", b"FAKEWIM:1:pe bad", Some((arch, "10.1.1.1")))
            .await;
        assert_eq!(r.status, 422);
        assert_eq!(r.code(), format!("pe_architecture_not_supported:{arch}"));
    }
    let r = h.create_upload("pe", "NoDecl", b"FAKEWIM:1:x", None).await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "required:pe_declaration");
    let r = h
        .create_upload("pe", "BadKit", b"FAKEWIM:1:x", Some(("x64", "10.01.1")))
        .await;
    assert_eq!(r.code(), "invalid_value:kit_version");
    let r = h
        .create_upload("image", "ImgDecl", b"FAKEWIM:1:x", Some(("x64", "10.1.1")))
        .await;
    assert_eq!(r.code(), "not_allowed:pe_declaration");
    assert_eq!(h.snapshot().await, before);
    let refused = h.events("content.upload.refused");
    assert!(refused.iter().any(|r| r.reason.as_deref()
        == Some("pe_architecture_not_supported:arm64")
        && r.detail.contains("\"architecture\":\"arm64\"")));
}

/// REQ-PE-009: a kit version on the configured list is shown with a
/// warning and audited.
#[tokio::test]
async fn known_bad_kit_warns_and_audits() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.known_bad_kit_versions = vec![KitVersion::parse("10.1.26100.1").unwrap()];
        }),
        ..Opts::default()
    })
    .await;
    let id = h.ready_pe("bad kit").await;
    let v = h.get(Who::Admin, &format!("/v1/pe/{id}")).await;
    assert_eq!(v.json()["kit_warning"]["code"], "kit_version_known_bad");
    assert!(
        h.events("pe.declared")[0]
            .detail
            .contains("kit_version_known_bad")
    );
}

/// REQ-AUD-006: if the record cannot be written, the action is refused,
/// the operator is told why, and nothing changes.
#[tokio::test]
async fn audit_failure_refuses_upload_nothing_changes() {
    let h = Harness::start().await;
    let before = h.snapshot().await;
    let n = h.records().len();
    h.store.fail_next_audit_writes(1);
    let r = h
        .create_upload("image", "NoAudit", b"FAKEWIM:1:na", None)
        .await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "audit_unavailable");
    assert_eq!(h.snapshot().await, before);
    assert_eq!(h.records().len(), n);
}

/// Start-up recovery: Receiving/Checking items become Failed
/// (`interrupted_by_restart`), audited; staging files are removed.
#[tokio::test]
async fn restart_recovery_marks_failed() {
    let h = Harness::start().await;
    let r = h
        .create_upload("image", "Left", b"FAKEWIM:1:left", None)
        .await;
    let id = ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap();
    let stray = h
        .api
        .files()
        .create_staging("0b7c2f4e-9a1d-4c3b-8e6f-1a2b3c4d5e6f.part")
        .unwrap();
    drop(stray);
    let rep = h.api.recover().await.unwrap();
    assert_eq!(rep.failed, vec![id]);
    assert_eq!(rep.staging_removed, 1);
    let c = h.wait_settled(id).await;
    assert_eq!(c.reason.unwrap().code, "interrupted_by_restart");
    assert_eq!(
        h.events("content.failed").last().unwrap().reason.as_deref(),
        Some("interrupted_by_restart")
    );
}

/// Sessions whose body never arrives expire (Failed, audited); an object
/// no Ready item refers to is reported at start-up, never deleted.
#[tokio::test]
async fn expired_session_failed_and_orphan_reported() {
    let h = Harness::start().await;
    let r = h
        .create_upload("image", "Late", b"FAKEWIM:1:late", None)
        .await;
    let up = upload_id(&r);
    let id = ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap();
    assert_eq!(h.api.expire_uploads().await.unwrap(), 0);
    h.clock.advance(Duration::from_secs(86_400 + 1));
    assert_eq!(h.api.expire_uploads().await.unwrap(), 1);
    let c = h.wait_settled(id).await;
    assert_eq!(c.reason.unwrap().code, "upload_expired");
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(b"FAKEWIM:1:late".to_vec()),
        )
        .await;
    assert_eq!(r.status, 409);

    let orphan = h
        .api
        .files()
        .object_path(&usgp_common::Sha256Digest([9; 32]));
    std::fs::create_dir_all(orphan.parent().unwrap()).unwrap();
    std::fs::write(&orphan, b"x").unwrap();
    let rep = h.api.recover().await.unwrap();
    assert_eq!(rep.orphans, 1);
    assert!(orphan.exists(), "orphans are never deleted");
    assert_eq!(h.events("content.orphan.found").len(), 1);
}
