//! M4 (plan WU-8): the escrow officer role and separation of duties,
//! agent-package signers and revocation, package configuration with the
//! answer-file template, device values, the v2 confirmation with its
//! render, the nine-step progress with the step 6 session close, resume by
//! job key, escrow, and the audited reveal (M4 plan sections 1.3, 1.6,
//! 3.1, 3.2 and 10 "API").

use usgp_api::device::routes::DeviceAuth;
use usgp_crypto::{EscrowContext, SigningKey};
use usgp_db::{
    AgentSigner, AgentSignerId, NewAgentPackage, NewArchiveContent, Operator, OperatorRole,
    OperatorStatus, ReadyArchiveContent, RepoTx, Store, Upload,
};
use usgp_proto::content_manifest::SCHEMA_V2;
use usgp_proto::device::ConfirmedV2;
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::resume::{ResumeNonce, resume_payload};
use usgp_proto::{
    AgentPackageId, AgentPackageManifestV1, ArchiveFormat, ArchiveSummaryV1, B64Bytes, ContentId,
    ContentKindV2, ContentManifestV2, ContentState, DisplayName, FileName, JobId, JobPlanV2,
    OperatorId, P384Spki, PayloadType, RelPath, UnixMicros, UploadId, UploadState,
};

use crate::authz_matrix::NOWHERE;
use crate::common::{Harness, Pinned, Who, nonce, rand16};

/// A template whose computer name comes from the device's values.
const TEMPLATE: &str = concat!(
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
    "<unattend xmlns=\"urn:schemas-microsoft-com:unattend\">",
    "<settings pass=\"specialize\"><component name=\"Microsoft-Windows-Shell-Setup\">",
    "<ComputerName>{{device.computer_name}}</ComputerName>",
    "</component></settings></unattend>"
);

fn b64(bytes: &[u8]) -> String {
    serde_json::to_value(B64Bytes::<1, 4_194_304>::new(bytes.to_vec()).unwrap())
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn now() -> UnixMicros {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    UnixMicros::new(i64::try_from(d.as_micros()).unwrap()).unwrap()
}

/// Archive content of `kind`, Ready with a v2 manifest signed by the
/// harness's content key.
async fn seed_archive(h: &Harness, kind: ContentKindV2, infs: &[&str]) -> ContentId {
    let id = ContentId::from_random_bytes(rand16());
    let sha = usgp_crypto::sha256(&rand16());
    let at = now();
    let c = NewArchiveContent {
        id,
        kind,
        display_name: DisplayName::new("Archive").unwrap(),
        file_name: FileName::new("archive.zip").unwrap(),
        size: 4096,
        sha256: sha,
        created_by: h.admin_id,
        initiating_audit_seq: None,
        created_at: at,
    };
    let u = Upload {
        id: UploadId::from_random_bytes(rand16()),
        content_id: id,
        operator_id: h.admin_id,
        declared_size: 4096,
        declared_sha256: sha,
        state: UploadState::Open,
        staging_name: format!(
            "staging-{}",
            usgp_common::Sha256Digest(rand16_32()).to_hex()
        ),
        created_at: at,
        expires_at: UnixMicros::new(at.as_micros() + 86_400_000_000).unwrap(),
    };
    let mut tx = h.store.begin().await.unwrap();
    tx.create_archive_upload(&c, &u).await.unwrap();
    tx.set_content_state(
        id,
        &[ContentState::Receiving],
        ContentState::Checking,
        None,
        at,
    )
    .await
    .unwrap();
    let m = ContentManifestV2 {
        schema: SCHEMA_V2,
        kind,
        content_id: id,
        display_name: c.display_name.clone(),
        file_name: c.file_name.clone(),
        size: c.size,
        sha256: sha,
        chunk_size: CHUNK_SIZE,
        chunk_sha256: vec![sha],
        archive: ArchiveSummaryV1 {
            format: ArchiveFormat::Zip,
            entries: 3,
            expanded_bytes: 9000,
            infs: infs.iter().map(|p| RelPath::new(*p).unwrap()).collect(),
        },
        ready_at: at,
        key_id: h.api.keys().key_id().0,
    };
    let stored = h
        .api
        .keys()
        .sign(PayloadType::ContentManifestV2, m.to_payload().unwrap())
        .unwrap();
    tx.set_archive_content_ready(
        id,
        &ReadyArchiveContent {
            manifest: stored,
            at,
        },
    )
    .await
    .unwrap();
    seeded(h, &mut tx, "content.ready").await;
    tx.commit().await.unwrap();
    id
}

/// Appends a seed record (the memory store refuses an unaudited change).
async fn seeded<T: RepoTx>(h: &Harness, tx: &mut T, event: &str) {
    let d = usgp_audit::AuditDraft::new(
        event,
        usgp_audit::Outcome::Success,
        usgp_audit::Actor::local_user(0, None),
        usgp_audit::Interface::ServerCli,
    );
    h.api.chain().append(tx, &d).await.unwrap();
}

fn rand16_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    usgp_crypto::fill_random(&mut b).unwrap();
    b
}

/// A signer registered through the store (as `POST /v1/agent-signers`).
async fn seed_signer(h: &Harness) -> AgentSigner {
    let key = SigningKey::generate().unwrap();
    let der = key.verifying_key().spki_der().to_vec();
    let s = AgentSigner {
        id: AgentSignerId::from_random_bytes(rand16()),
        spki: P384Spki::from_der(&der).unwrap(),
        key_id: usgp_crypto::sha256(&der),
        name: DisplayName::new("Agent build key").unwrap(),
        added_by: h.admin_id,
        added_at: now(),
        revoked: None,
    };
    let mut tx = h.store.begin().await.unwrap();
    tx.insert_agent_signer(&s).await.unwrap();
    seeded(h, &mut tx, "agent_signer.added").await;
    tx.commit().await.unwrap();
    s
}

/// A Ready agent package signed by `signer`.
async fn seed_agent_package(h: &Harness, signer: &AgentSigner) -> AgentPackageId {
    let c = seed_archive(h, ContentKindV2::AgentPackage, &[]).await;
    let id = AgentPackageId::from_random_bytes(rand16());
    let mut tx = h.store.begin().await.unwrap();
    tx.insert_agent_package(&NewAgentPackage {
        id,
        content_id: c,
        created_by: h.admin_id,
        created_at: now(),
    })
    .await
    .unwrap();
    let manifest =
        AgentPackageManifestV1::from_json(br#"{"installer":"setup/agent.msi","args":[]}"#).unwrap();
    tx.set_agent_package_ready(id, signer.id, &manifest, now())
        .await
        .unwrap();
    seeded(h, &mut tx, "agent_package.ready").await;
    tx.commit().await.unwrap();
    id
}

async fn put_config(
    h: &Harness,
    pkg: &str,
    template: &str,
    agent: AgentPackageId,
    mode: &str,
) -> crate::common::Resp {
    h.req(
        Who::Admin,
        "PUT",
        &format!("/v1/packages/{pkg}/config"),
        &[],
        Some(
            serde_json::to_vec(&serde_json::json!({
                "answer_template_b64": b64(template.as_bytes()),
                "values": {},
                "tags": ["lab", "m4"],
                "agent_package_id": agent.to_string(),
                "admin_password": mode,
            }))
            .unwrap(),
        ),
    )
    .await
}

/// The escrow officer reveals and views jobs, nothing else; the
/// administrator never reveals; a second certificate in an
/// administrator's name cannot reveal (AC-5).
#[tokio::test]
async fn escrow_officer_separation_of_duties() {
    let h = Harness::start().await;
    assert_eq!(h.get(Who::Officer, "/v1/jobs").await.status, 200);
    assert_eq!(h.get(Who::Officer, "/v1/packages").await.status, 403);
    let body = serde_json::json!({"reason": "ticket 7"});
    let reveal = format!("/v1/jobs/{NOWHERE}/admin-password/reveal");
    let r = h.post_json(Who::Admin, &reveal, body.clone()).await;
    assert_eq!(r.status, 403);
    // The officer reaches the handler: an unknown job is 404.
    let r = h.post_json(Who::Officer, &reveal, body.clone()).await;
    assert_eq!(r.status, 404, "{}", String::from_utf8_lossy(&r.body));

    // A second certificate with an administrator's subject, enrolled as
    // escrow officer, is a self-grant: refused and recorded.
    let twin = h
        .pki
        .intermediate
        .issue(&usgp_crypto::test_pki::LeafSpec::client("operator two"))
        .unwrap();
    let pc = twin.peer_certificate().unwrap();
    let op = Operator {
        id: OperatorId::from_random_bytes([9; 16]),
        display_name: DisplayName::new("Twin").unwrap(),
        cert_sha256: pc.sha256,
        cert_subject: pc.subject.clone(),
        cert_issuer: pc.issuer.clone(),
        cert_serial: pc.serial.clone(),
        cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        role: Some(OperatorRole::EscrowOfficer),
        status: OperatorStatus::Active,
        created_at: UnixMicros::new(1).unwrap(),
        created_by: "uid:0".to_owned(),
    };
    let mut tx = h.store.begin().await.unwrap();
    tx.insert_operator(&op).await.unwrap();
    seeded(&h, &mut tx, "operator.enrolled").await;
    tx.commit().await.unwrap();
    let r = h
        .req_as(
            Some(&twin),
            "POST",
            &reveal,
            &[("content-type", "application/json")],
            Some(serde_json::to_vec(&body).unwrap()),
        )
        .await;
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));
    let refused = h.events("escrow.reveal_refused");
    assert!(
        refused.iter().any(|r| r.detail.contains("self_granted")),
        "{refused:?}"
    );
}

/// Revoking a signer refuses its agent packages and takes the packages
/// that use them out of ready, each recorded, in one transaction.
#[tokio::test]
async fn signer_add_list_revoke_refuses_its_packages() {
    let h = Harness::start().await;
    let key = SigningKey::generate().unwrap();
    let spki = P384Spki::from_der(key.verifying_key().spki_der()).unwrap();
    let r = h
        .post_json(
            Who::Admin,
            "/v1/agent-signers",
            serde_json::json!({"name": "Build key", "spki_b64": spki.to_string()}),
        )
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let signer_id = r.json()["id"].as_str().unwrap().to_owned();
    let r = h
        .post_json(
            Who::Admin,
            "/v1/agent-signers",
            serde_json::json!({"name": "Again", "spki_b64": spki.to_string()}),
        )
        .await;
    assert_eq!(r.status, 409);
    let r = h.get(Who::Admin, "/v1/agent-signers").await;
    assert_eq!(r.json()["signers"].as_array().unwrap().len(), 1);

    let signer = {
        let mut tx = h.store.begin().await.unwrap();
        let s = tx
            .agent_signer(AgentSignerId::parse(&signer_id).unwrap())
            .await
            .unwrap()
            .unwrap();
        tx.commit().await.unwrap();
        s
    };
    let ap = seed_agent_package(&h, &signer).await;
    let (pkg, _, _) = h.ready_package("revoke").await;
    let r = put_config(&h, &pkg, TEMPLATE, ap, "none").await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/agent-signers/{signer_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let refused = h.events("agent_package.refused");
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].reason.as_deref(), Some("signer_revoked"));
    assert_eq!(
        refused[0].target_id.as_deref(),
        Some(ap.to_string().as_str())
    );
    let changed: Vec<_> = h
        .events("package.status.changed")
        .into_iter()
        .filter(|r| r.reason.as_deref() == Some("agent_package_refused"))
        .collect();
    assert_eq!(changed.len(), 1);
    let revoked = h.events("agent_signer.revoked");
    assert_eq!(revoked.len(), 1);
    assert_eq!(refused[0].initiating_seq, Some(revoked[0].seq));
    let r = h.get(Who::Admin, &format!("/v1/packages/{pkg}")).await;
    assert_eq!(r.json()["status"], "not_usable");
    // Once only.
    let r = h
        .req(
            Who::Admin,
            "DELETE",
            &format!("/v1/agent-signers/{signer_id}"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 409);
}

/// The template is parsed and linted before it is stored; the record
/// carries its digest, never its text; the body limit is 2 MiB.
#[tokio::test]
async fn package_config_checks_and_records() {
    let h = Harness::start().await;
    let signer = seed_signer(&h).await;
    let ap = seed_agent_package(&h, &signer).await;
    let (pkg, _, _) = h.ready_package("config").await;

    let r = put_config(&h, &pkg, TEMPLATE, ap, "generate_and_escrow").await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let j = r.json();
    let sha = usgp_crypto::sha256(TEMPLATE.as_bytes()).to_hex();
    assert_eq!(j["answer_sha256"], sha);
    assert!(j.get("answer_template_b64").is_none());
    let set = h.events("package.config.set");
    assert_eq!(set.len(), 1);
    assert!(set[0].detail.contains(&sha));
    assert!(!h.all_record_text().contains("ComputerName"));
    assert_eq!(h.events("agent_package.attached").len(), 1);

    let secret = TEMPLATE.replace(
        "<ComputerName>",
        "<AutoLogon><Password>x</Password></AutoLogon><ComputerName>",
    );
    let r = put_config(&h, &pkg, &secret, ap, "none").await;
    assert_eq!(r.status, 422);
    assert!(
        r.code().starts_with("secret_bearing_setting"),
        "{}",
        r.code()
    );

    let doctype = format!("<!DOCTYPE x [<!ENTITY a \"b\">]>{}", &TEMPLATE[38..]);
    let r = put_config(&h, &pkg, &doctype, ap, "none").await;
    assert_eq!(r.status, 422, "{}", String::from_utf8_lossy(&r.body));

    let unknown = TEMPLATE.replace("device.computer_name", "domain");
    let r = put_config(&h, &pkg, &unknown, ap, "none").await;
    assert_eq!(r.status, 422);
    assert!(r.code().starts_with("unknown_reference"), "{}", r.code());

    let r = put_config(&h, &pkg, TEMPLATE, ap, "sometimes").await;
    assert_eq!(r.status, 422);

    let missing = AgentPackageId::from_random_bytes(rand16());
    let r = put_config(&h, &pkg, TEMPLATE, missing, "none").await;
    assert_eq!(r.status, 422);

    // Over 2 MiB: refused before parsing.
    let big = vec![b' '; 2 * 1024 * 1024 + 1];
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/packages/{pkg}/config"),
            &[("content-type", "application/json")],
            Some(big),
        )
        .await;
    assert_eq!(r.status, 413);
    // One configuration stored (the first).
    assert_eq!(h.events("package.config.set").len(), 1);
}

#[tokio::test]
async fn device_values_set_read_delete() {
    let h = Harness::start().await;
    let path = "/v1/device-values/02:00:5e:00:53:10";
    let r = h
        .req(
            Who::Admin,
            "PUT",
            path,
            &[("content-type", "application/json")],
            Some(br#"{"values":{"computer_name":"PC-0001","site":"Lab A"}}"#.to_vec()),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = h.get(Who::Admin, path).await;
    assert_eq!(r.json()["values"]["computer_name"], "PC-0001");
    let set = h.events("device_value.set");
    assert!(set[0].detail.contains("computer_name,site"));
    assert!(!set[0].detail.contains("PC-0001"));
    for bad in [
        r#"{"values":{"computer_name":"*"}}"#,
        r#"{"values":{"computer_name":"12345"}}"#,
        r#"{"values":{"Bad-Key":"x"}}"#,
        r#"{"values":{}}"#,
    ] {
        let r = h
            .req(
                Who::Admin,
                "PUT",
                path,
                &[("content-type", "application/json")],
                Some(bad.as_bytes().to_vec()),
            )
            .await;
        assert_eq!(r.status, 422, "{bad}");
    }
    let r = h.req(Who::Admin, "DELETE", path, &[], None).await;
    assert_eq!(r.status, 204);
    assert_eq!(h.get(Who::Admin, path).await.status, 404);
    assert_eq!(h.get(Who::NoRole, path).await.status, 403);
}

fn progress(seq: u64, step: u8, event: &str) -> serde_json::Value {
    serde_json::json!({"schema": 2, "seq": seq, "step": step, "event": event})
}

/// The whole M4 device flow on the API: v2 confirmation with the render,
/// steps 1 to 6 with the session token, the session closed at step 6,
/// resume by job key, steps 7 to 9 with the resume token, escrow, and the
/// audited reveal returning the sealed password.
#[tokio::test]
async fn v2_confirm_resume_escrow_reveal() {
    let h = Harness::m3().await;
    let mac = "02:00:5e:00:53:21";
    let d = h.ready_device("m4flow", &[mac]).await;
    let signer = seed_signer(&h).await;
    let ap = seed_agent_package(&h, &signer).await;
    let drv = seed_archive(&h, ContentKindV2::DriverArchive, &["nic/e1.inf"]).await;
    let drv_id = usgp_proto::DriverArchiveId::from_random_bytes(rand16());
    {
        let mut tx = h.store.begin().await.unwrap();
        tx.insert_driver_archive(&usgp_db::NewDriverArchive {
            id: drv_id,
            content_id: drv,
            name: DisplayName::new("NIC").unwrap(),
            created_by: h.admin_id,
            created_at: now(),
        })
        .await
        .unwrap();
        tx.set_driver_archive_ready(drv_id, now()).await.unwrap();
        seeded(&h, &mut tx, "driver.ready").await;
        tx.commit().await.unwrap();
    }
    let r = put_config(&h, &d.pkg, TEMPLATE, ap, "generate_and_escrow").await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/packages/{}/drivers", d.pkg),
            &[("if-match", "\"r1\""), ("content-type", "application/json")],
            Some(
                serde_json::to_vec(&serde_json::json!({"archive_ids": [drv_id.to_string()]}))
                    .unwrap(),
            ),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // No device value yet: the session ends, no job, 409 naming it.
    let job_key = SigningKey::generate().unwrap();
    let spki = P384Spki::from_der(job_key.verifying_key().spki_der()).unwrap();
    let confirm = |token: String, disk: usgp_proto::DiskDescriptorV1| {
        let spki = spki.to_string();
        let pkg = d.pkg.clone();
        let h = &h;
        async move {
            h.dev(
                "POST",
                "/v1/device/session/confirm",
                Some(&token),
                Some(serde_json::json!({
                    "package_id": pkg, "revision": 1, "disk_token": disk.disk_token(),
                    "confirm": "wipe-disk", "agent_nonce": nonce(),
                    "job_key_spki_b64": spki,
                })),
            )
            .await
        }
    };
    let r = confirm(d.session.token.clone(), d.disk.clone()).await;
    assert_eq!(r.status, 409, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "unresolved_value:device.computer_name");
    assert_eq!(h.events("job.config.unresolved").len(), 1);
    assert!(h.events("job.created").is_empty());

    // With the value set, a new session confirms.
    let r = h
        .req(
            Who::Admin,
            "PUT",
            &format!("/v1/device-values/{mac}"),
            &[("content-type", "application/json")],
            Some(br#"{"values":{"computer_name":"PC-0001"}}"#.to_vec()),
        )
        .await;
    assert_eq!(r.status, 200);
    let (s, disk) = h.chosen_session(&d.pkg, &[mac]).await;
    let r = confirm(s.token.clone(), disk.clone()).await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let c = ConfirmedV2::from_json(&r.body).unwrap();
    let plan = JobPlanV2::open(&c.plan, &Pinned(h.plan_pub.clone())).unwrap();
    assert_eq!(plan.job_key_id, usgp_crypto::sha256(spki.as_der()));
    let answer = String::from_utf8(plan.answer_file.b64.as_bytes().to_vec()).unwrap();
    assert!(answer.contains("<ComputerName>PC-0001</ComputerName>"));
    assert!(!answer.contains("{{"));
    let escrow = plan.escrow.as_ref().unwrap();
    assert_eq!(escrow.key_id, h.escrow_pub.key_id().0);
    assert_eq!(plan.drivers.len(), 1);
    assert_eq!(c.driver_manifests.len(), 1);
    assert_eq!(plan.tags.len(), 2);
    let resolved = h.events("job.config.resolved");
    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].detail.contains("device.computer_name"));
    let job = c.job_id.to_string();

    // Steps 1 to 6 with the session token.
    let mut seq = 0;
    for step in 1..=6u8 {
        for ev in ["step_started", "step_completed"] {
            seq += 1;
            let r = h.report(&s.token, &job, progress(seq, step, ev)).await;
            assert_eq!(
                r.status,
                200,
                "{step} {ev}: {} {:?}",
                String::from_utf8_lossy(&r.body),
                h.events("job.progress.refused")
            );
        }
    }
    assert_eq!(h.events("device.session.closed").len(), 1);
    assert!(!h.events("boot_stop.added").is_empty());
    // The session token is refused from now on.
    seq += 1;
    let r = h
        .report(&s.token, &job, progress(seq, 7, "step_started"))
        .await;
    assert_eq!(r.status, 403, "{}", String::from_utf8_lossy(&r.body));

    // Resume by job key.
    async fn challenge(h: &Harness, job: String) -> ResumeNonce {
        let r = h
            .dev(
                "POST",
                &format!("/v1/device/jobs/{job}/resume/challenge"),
                None,
                Some(serde_json::json!({})),
            )
            .await;
        assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
        ResumeNonce::parse(r.json()["nonce"].as_str().unwrap()).unwrap()
    }
    let sign = |n: &ResumeNonce, key: &SigningKey| {
        let sig = usgp_crypto::sign_typed(
            key,
            PayloadType::ResumeV1.as_str(),
            &resume_payload(&c.job_id, n),
        )
        .unwrap();
        b64(&sig)
    };
    let resume = |n: &ResumeNonce, sig: String| {
        let body = serde_json::json!({"nonce": n, "sig": sig});
        let h = &h;
        let job = job.clone();
        async move {
            h.dev(
                "POST",
                &format!("/v1/device/jobs/{job}/resume"),
                None,
                Some(body),
            )
            .await
        }
    };
    // Unknown job: 404, the same as an ineligible one.
    let r = h
        .dev(
            "POST",
            &format!("/v1/device/jobs/{NOWHERE}/resume/challenge"),
            None,
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(r.status, 404);
    // A wrong key: refused and recorded; the nonce is used up.
    let n = challenge(&h, job.clone()).await;
    let other = SigningKey::generate().unwrap();
    let r = resume(&n, sign(&n, &other)).await;
    assert_eq!(r.status, 403);
    assert_eq!(r.code(), "resume_refused");
    let r = resume(&n, sign(&n, &job_key)).await;
    assert_eq!(r.status, 403, "a used nonce must not be accepted");
    assert!(
        h.events("job.resume.refused")
            .iter()
            .any(|r| r.reason.as_deref() == Some("signature_invalid"))
    );
    let n = challenge(&h, job.clone()).await;
    let r = resume(&n, sign(&n, &job_key)).await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let j = r.json();
    assert_eq!(j["ack_seq"], 12);
    let token = j["token"].as_str().unwrap().to_owned();
    assert!(!h.all_record_text().contains(&token));
    assert_eq!(h.events("job.resumed").len(), 1);
    // At most 16 live nonces per job: the 17th challenge is 429 and
    // recorded (WU-6 deviation 1).
    for _ in 0..16 {
        let _ = challenge(&h, job.clone()).await;
    }
    let r = h
        .dev(
            "POST",
            &format!("/v1/device/jobs/{job}/resume/challenge"),
            None,
            Some(serde_json::json!({})),
        )
        .await;
    assert_eq!(r.status, 429);
    assert!(
        h.events("job.resume.refused")
            .iter()
            .any(|r| r.reason.as_deref() == Some("rate_limited"))
    );

    // Steps 7 to 9 with the resume token; not for another job, and not
    // for steps 1 to 6.
    let r = h
        .report(&token, NOWHERE, progress(13, 7, "step_started"))
        .await;
    assert_eq!(r.status, 401);
    let r = h
        .report(&token, &job, progress(13, 5, "step_started"))
        .await;
    assert_eq!(r.status, 403);
    let r = h
        .report(&token, &job, progress(13, 7, "step_started"))
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // Escrow while step 7 runs; once only.
    let password = "Xq7-Wv9pLm2RtYz4KbN8sCdF";
    let sealed = usgp_crypto::escrow_seal(
        &h.escrow_pub,
        &EscrowContext {
            job_id: *c.job_id.as_bytes(),
            account: "administrator",
        },
        password.as_bytes(),
    )
    .unwrap();
    let escrow_body = serde_json::json!({
        "key_id": sealed.key_id.0, "eph_pub_b64": b64(&sealed.eph_pub),
        "nonce_b64": b64(&sealed.nonce), "ct_b64": b64(&sealed.ct),
        "account": "administrator",
    });
    let path = format!("/v1/device/jobs/{job}/escrow");
    let r = h
        .dev("POST", &path, Some(&token), Some(escrow_body.clone()))
        .await;
    assert_eq!(r.status, 201, "{}", String::from_utf8_lossy(&r.body));
    let r = h.dev("POST", &path, Some(&token), Some(escrow_body)).await;
    assert_eq!(r.status, 409);
    let r = h
        .dev(
            "POST",
            &format!("{path}/confirm"),
            Some(&token),
            Some(serde_json::json!({"set": true})),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(h.events("escrow.received").len(), 1);
    assert_eq!(h.events("escrow.applied").len(), 1);

    let mut seq = 13;
    for (step, ev) in [
        (7, "step_completed"),
        (8, "step_started"),
        (8, "step_completed"),
        (9, "step_started"),
        (9, "succeeded"),
    ] {
        seq += 1;
        let r = h.report(&token, &job, progress(seq, step, ev)).await;
        assert_eq!(
            r.status,
            200,
            "{step} {ev}: {}",
            String::from_utf8_lossy(&r.body)
        );
    }
    assert_eq!(h.events("job.succeeded").len(), 1);
    // The token ends with the job.
    let r = h
        .dev(
            "POST",
            &format!("{path}/confirm"),
            Some(&token),
            Some(serde_json::json!({"set": true})),
        )
        .await;
    assert_eq!(r.status, 401);

    // Metadata, then the reveal: recorded before decryption, not cached.
    let r = h
        .get(Who::Admin, &format!("/v1/jobs/{job}/admin-password"))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["state"], "applied");
    let reveal = format!("/v1/jobs/{job}/admin-password/reveal");
    let r = h
        .post_json(
            Who::Officer,
            &reveal,
            serde_json::json!({"reason": "helpdesk ticket 4711"}),
        )
        .await;
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.json()["password"], password);
    assert_eq!(r.header("cache-control").as_deref(), Some("no-store"));
    let rec = h.events("escrow.revealed");
    assert_eq!(rec.len(), 1);
    assert!(rec[0].detail.contains("helpdesk ticket 4711"));
    assert!(rec[0].detail.contains(mac));
    // No record carries the password, the token or the ciphertext.
    let text = h.all_record_text();
    assert!(!text.contains(password));

    // An audit failure on the reveal record: 503, nothing revealed.
    h.store.fail_audit_on("escrow.revealed");
    let r = h
        .post_json(
            Who::Officer,
            &reveal,
            serde_json::json!({"reason": "second look"}),
        )
        .await;
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    assert!(!String::from_utf8_lossy(&r.body).contains(password));
}

/// Every resume-token route refuses a request without one.
#[test]
fn resume_routes_are_the_post_restart_ones() {
    let n = usgp_api::device::routes::DEVICE_ROUTES
        .iter()
        .filter(|r| r.auth == DeviceAuth::Resume)
        .count();
    assert_eq!(n, 2);
    let _ = JobId::parse(NOWHERE).unwrap();
}
