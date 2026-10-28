//! The M3 device flow against a running server (plan M3 sections 1.1,
//! 3.1 to 3.6), shared by `device_e2e.rs` (in-memory store) and
//! `e2e_pg.rs` (PostgreSQL): the operator assigns a Ready package to the
//! boot service and issues a code; a device opens a session, is
//! authorised by the code, sees and chooses the package and a disk,
//! confirms the wipe, verifies the signed plan and content manifest with
//! the pinned keys, fetches every chunk of the edition's image (each
//! checked against the signed manifest, and the whole file against the
//! digest the test computed itself), reports steps 1 to 5 to success;
//! the operator sees the job succeeded; the relay's signed boot policy
//! lists the device's MAC.
//!
//! Every check is made as the agent would make it: signatures with the
//! pinned public keys from the fixture, digests computed here.

use std::collections::HashSet;
use std::net::SocketAddr;

use usgp_common::Sha256Digest;
use usgp_crypto::test_pki::TestCert;
use usgp_proto::device::{ConfirmedV1, DevicePackageListV1, SessionOpenedV1, SessionStatusV1};
use usgp_proto::disk::{Bus, DiskDescriptorParts, ExistingPartitionV1, PartitionKind};
use usgp_proto::{
    AgentNonce, BootPolicyV1, DiskDescriptorV1, DiskText, DiskToken, JobId, MacAddress, PackageId,
    PartitionLabel, PlanExpectation, SessionId, SignedEnvelopeV1, VerifiedJobPlan,
};

use super::stream::Pinned;
use super::{Fixture, RawResponse, request};

/// The MAC the test device reports.
pub const DEVICE_MAC: &str = "02:00:5e:10:00:01";

/// What the flow produced.
#[derive(Debug, Clone)]
pub struct DeviceOutcome {
    /// The session.
    pub session_id: String,
    /// The job.
    pub job_id: String,
    /// The device's MAC.
    pub mac: MacAddress,
    /// The boot-policy generation the relay saw with the stop.
    pub generation: u64,
}

fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    usgp_crypto::fill_random(&mut b).unwrap();
    b
}

fn nonce() -> AgentNonce {
    let mut b = [0u8; 32];
    usgp_crypto::fill_random(&mut b).unwrap();
    AgentNonce::from_random_bytes(b)
}

/// A 1 TB NVMe disk with one existing data partition.
pub fn disk() -> DiskDescriptorV1 {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: DiskToken::from_random_bytes(rand16()),
        bus: Bus::Nvme,
        model: DiskText::sanitized("Example NVMe 1TB"),
        serial: DiskText::sanitized("SN-E2E-0001"),
        size_bytes: 1_000_204_886_016,
        logical_sector: 512,
        physical_sector: 4096,
        removable: false,
        partitions: vec![ExistingPartitionV1 {
            index: 1,
            kind: PartitionKind::Basic,
            start_bytes: 1_048_576,
            size_bytes: 1_048_576,
            label: PartitionLabel::sanitized("Data"),
        }],
    })
    .unwrap()
}

/// An operator request (the fixture's administrator certificate).
pub async fn op(
    addr: SocketAddr,
    f: &Fixture,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> RawResponse {
    let body = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    request(
        addr,
        &f.pki,
        Some(&f.pki.client),
        method,
        path,
        headers,
        &body,
    )
    .await
    .unwrap()
}

/// A device request (no client certificate), with the bearer token.
pub async fn dev(
    addr: SocketAddr,
    f: &Fixture,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> RawResponse {
    let auth = token.map(|t| format!("Bearer {t}"));
    let headers: Vec<(&str, &str)> = auth
        .as_deref()
        .map(|a| vec![("authorization", a)])
        .unwrap_or_default();
    let body = body
        .map(|b| serde_json::to_vec(&b).unwrap())
        .unwrap_or_default();
    request(addr, &f.pki, None, method, path, &headers, &body)
        .await
        .unwrap()
}

/// The relay's boot-policy pull with its client certificate.
pub async fn pull(api: SocketAddr, f: &Fixture, relay: &TestCert, have: u64) -> RawResponse {
    request(
        api,
        &f.pki,
        Some(relay),
        "GET",
        &format!("/v1/relay/boot-policy?have={have}"),
        &[],
        &[],
    )
    .await
    .unwrap()
}

/// Opens a 200 boot-policy response with the pinned boot-policy key; it
/// must not open with the plan key (one key, one purpose).
pub fn open_policy(f: &Fixture, r: &RawResponse) -> BootPolicyV1 {
    assert_eq!(r.status, 200, "{}", r.text());
    let env = SignedEnvelopeV1::from_json(&r.body).unwrap();
    assert!(BootPolicyV1::open(&env, &Pinned(f.plan_pub.clone())).is_err());
    BootPolicyV1::open(&env, &Pinned(f.policy_pub.clone())).unwrap()
}

/// Assigns `package` to boot service `bs` (ETag first, `If-Match`).
pub async fn assign(api: SocketAddr, f: &Fixture, bs: &str, package: &str) {
    let r = op(api, f, "GET", &format!("/v1/boot-services/{bs}"), &[], None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let etag = r.header("etag").expect("ETag");
    let r = op(
        api,
        f,
        "PUT",
        &format!("/v1/boot-services/{bs}/packages"),
        &[("if-match", &etag)],
        Some(serde_json::json!({ "package_ids": [package] })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
}

/// The whole device flow. `image_sha256` is the digest the test computed
/// for the uploaded WIM; `relay` is the certificate enrolled for `bs`.
pub async fn run(
    api: SocketAddr,
    device: SocketAddr,
    f: &Fixture,
    bs: &str,
    package: &str,
    image_sha256: Sha256Digest,
    relay: &TestCert,
) -> DeviceOutcome {
    assign(api, f, bs, package).await;
    // The relay's first pull: generation 1, no stop.
    let g1 = open_policy(f, &pull(api, f, relay, 0).await);
    assert_eq!(g1.boot_service_id.to_string(), bs);
    let mac = MacAddress::parse(DEVICE_MAC).unwrap();
    assert!(!g1.stop_set().contains(&mac));

    // 1. The device opens a session; nothing is offered before
    //    authorisation.
    let hello = serde_json::json!({
        "schema": 1, "agent_version": "0.3.0", "firmware": "uefi", "arch": "x64",
        "secure_boot": "on", "memory_bytes": 8_589_934_592u64, "macs": [DEVICE_MAC],
    });
    let r = dev(device, f, "POST", "/v1/device/sessions", None, Some(hello)).await;
    assert_eq!(r.status, 201, "{}", r.text());
    let opened: SessionOpenedV1 = serde_json::from_slice(&r.body).unwrap();
    let token = opened.token.expose().to_owned();
    let tok = Some(token.as_str());
    let r = dev(device, f, "GET", "/v1/device/session/packages", tok, None).await;
    assert_eq!(
        r.status,
        403,
        "no packages before authorisation: {}",
        r.text()
    );

    // 2. The operator issues a code (shown once, not cached); the device
    //    enters it.
    let r = op(
        api,
        f,
        "POST",
        "/v1/auth-codes",
        &[],
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.text());
    assert!(r.head.contains("cache-control: no-store"), "{}", r.head);
    let code = r.json()["code"].as_str().unwrap().to_owned();
    let r = dev(
        device,
        f,
        "POST",
        "/v1/device/session/code",
        tok,
        Some(serde_json::json!({ "code": code })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let st: SessionStatusV1 = serde_json::from_slice(&r.body).unwrap();
    assert_eq!(st.state.as_str(), "authorised");
    let r = dev(device, f, "GET", "/v1/device/session", tok, None).await;
    assert_eq!(r.status, 200, "{}", r.text());

    // 3. Packages, then package and disk choices.
    let r = dev(device, f, "GET", "/v1/device/session/packages", tok, None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    let list: DevicePackageListV1 = serde_json::from_slice(&r.body).unwrap();
    let offered = list
        .packages()
        .iter()
        .find(|p| p.package_id.to_string() == package)
        .unwrap_or_else(|| panic!("package not offered: {}", r.text()));
    assert!(offered.required_disk_bytes >= 64_000_000_000);
    let revision = offered.revision;
    let r = dev(
        device,
        f,
        "POST",
        "/v1/device/session/package",
        tok,
        Some(serde_json::json!({ "package_id": package, "revision": revision })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());
    let d = disk();
    let r = dev(
        device,
        f,
        "POST",
        "/v1/device/session/disk",
        tok,
        Some(serde_json::json!({ "disk": d })),
    )
    .await;
    assert_eq!(r.status, 200, "{}", r.text());

    // 4. The wipe confirmation: a job and a signed plan.
    let n = nonce();
    let r = dev(
        device,
        f,
        "POST",
        "/v1/device/session/confirm",
        tok,
        Some(serde_json::json!({
            "package_id": package, "revision": revision, "disk_token": d.disk_token(),
            "confirm": "wipe-disk", "agent_nonce": n,
        })),
    )
    .await;
    assert_eq!(r.status, 201, "{}", r.text());
    let confirmed = ConfirmedV1::from_json(&r.body).unwrap();
    let job_id: JobId = confirmed.job_id;
    let expect = PlanExpectation {
        agent_nonce: &n,
        session_id: opened.session_id,
        job_id,
        package_id: PackageId::parse(package).unwrap(),
        package_revision: revision,
        disk: &d,
    };
    let verified = VerifiedJobPlan::verify(
        &confirmed.plan,
        &Pinned(f.plan_pub.clone()),
        &confirmed.content_manifest,
        &Pinned(f.content_pub.clone()),
        &usgp_crypto::sha256,
        &expect,
    )
    .expect("the plan verifies with the pinned plan and content keys");
    // Not with the content key as the plan key.
    assert!(
        VerifiedJobPlan::verify(
            &confirmed.plan,
            &Pinned(f.content_pub.clone()),
            &confirmed.content_manifest,
            &Pinned(f.content_pub.clone()),
            &usgp_crypto::sha256,
            &expect,
        )
        .is_err()
    );
    let cm = verified.content_manifest();
    assert_eq!(cm.sha256, image_sha256, "the plan names the uploaded image");
    // Cancelling after the wipe confirmation is refused (REQ-TGT-011).
    let r = dev(
        device,
        f,
        "POST",
        "/v1/device/session/cancel",
        tok,
        Some(serde_json::json!({})),
    )
    .await;
    assert_eq!(r.status, 409, "{}", r.text());

    // 5. Every chunk, verified against the signed manifest, then the
    //    whole file against the test's own digest (step 1's pass).
    let job = job_id.to_string();
    let sha = cm.sha256.to_hex();
    let mut whole = usgp_crypto::Sha256Hasher::new();
    let mut total = 0u64;
    for (i, want) in cm.chunk_sha256.iter().enumerate() {
        let r = dev(
            device,
            f,
            "GET",
            &format!("/v1/device/jobs/{job}/content/{sha}/chunks/{i}"),
            tok,
            None,
        )
        .await;
        assert_eq!(r.status, 200, "chunk {i}: {}", r.text());
        assert_eq!(usgp_crypto::sha256(&r.body), *want, "chunk {i}");
        whole.update(&r.body);
        total += u64::try_from(r.body.len()).unwrap();
    }
    assert_eq!(total, cm.size);
    assert_eq!(whole.finish(), image_sha256);
    // Beyond the last chunk: 404.
    let r = dev(
        device,
        f,
        "GET",
        &format!(
            "/v1/device/jobs/{job}/content/{sha}/chunks/{}",
            cm.chunk_sha256.len()
        ),
        tok,
        None,
    )
    .await;
    assert_eq!(r.status, 404);

    // 6. Progress: steps 1 to 4, then success.
    let mut seq = 1u64;
    let mut report = |step: u8, event: &'static str| {
        let body = serde_json::json!({ "seq": seq, "step": step, "event": event });
        seq += 1;
        body
    };
    let mut reports = Vec::new();
    for step in 1..=4u8 {
        if step > 1 {
            reports.push(report(step, "step_started"));
        }
        reports.push(report(step, "step_completed"));
    }
    reports.push(report(5, "step_started"));
    reports.push(report(5, "succeeded"));
    let path = format!("/v1/device/jobs/{job}/progress");
    let mut last = serde_json::Value::Null;
    for body in reports {
        let r = dev(device, f, "POST", &path, tok, Some(body)).await;
        assert_eq!(r.status, 200, "{}", r.text());
        last = r.json();
    }
    assert_eq!(last["job_state"], "succeeded", "{last}");

    // 7. The operator sees the job succeeded.
    let r = op(api, f, "GET", &format!("/v1/jobs/{job}"), &[], None).await;
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["state"], "succeeded", "{}", r.text());

    // 8. The relay's signed policy now stops the device (REQ-BOOT-067).
    let g2 = open_policy(f, &pull(api, f, relay, g1.generation).await);
    assert!(g2.generation > g1.generation);
    let stops: HashSet<MacAddress> = g2.stop_set();
    assert!(stops.contains(&mac), "{g2:?}");
    assert!(
        g2.stops
            .iter()
            .any(|s| s.mac == mac && s.job_id.to_string() == job)
    );
    assert_eq!(pull(api, f, relay, g2.generation).await.status, 304);

    DeviceOutcome {
        session_id: opened.session_id.to_string(),
        job_id: job,
        mac,
        generation: g2.generation,
    }
}

/// The session id type is used by callers comparing records.
pub fn session_id(text: &str) -> SessionId {
    SessionId::parse(text).unwrap()
}
