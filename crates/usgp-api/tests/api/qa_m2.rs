//! QA gap tests for M2 (qa-engineer, run 20261026-225553-m2-content-store).
//!
//! | Area | Test |
//! |------|------|
//! | 401 + audit on every route for no cert, unknown cert, disabled operator (REQ-RBAC-005, REQ-AUD-001; exit 4) | `every_route_401_audited_for_each_authn_failure` |
//! | every TLS failure class reaching the API is audited (REQ-RBAC-005, REQ-AUD-001) | `tls_failure_classes_audited`, `tls_stale_crl_and_policy_audited` |
//! | audit write failure refuses every mutation and every protected read (REQ-AUD-006, 0015 item 1) | `audit_failure_refuses_every_mutation`, `audit_failure_refuses_every_protected_read` |
//! | a state change does not make content Ready unless its record is written (REQ-AUD-006 sentence 3) | `audit_failure_blocks_ready_transition` |
//! | in-use PE delete names dependants in the audit record (REQ-IMG-015 item 1) | `in_use_delete_refusal_audit_names_dependants` |
//! | verified facts carried into the signed package manifest; declared stays declared (REQ-IMG-043 item 3, 0013) | `verified_and_declared_sources_signed_into_package_manifest` |
//! | PE declaration contradicting a file fact fails the import, audited (REQ-PE-005 item 2) | `pe_declaration_contradicting_file_fails_import_audited` |
//! | self-contradicting file refuses a declaration (REQ-IMG-043 item 2) | `inconsistent_file_fact_refuses_declaration` |
//! | every out-of-scope edition/arch/release refused at selection and audited (REQ-OS-001/002/004/005/007) | `every_out_of_scope_value_refused_at_selection_audited` |
//! | integrity is checked on every download, not cached (REQ-IMG-050, REQ-PE-008, 0011) | `chunks_verified_on_every_download_not_cached`, `pe_tamper_detected_package_not_usable` |
//! | package manifest under an untrusted key is not served (REQ-IMG-050, SI-7(6)) | `package_manifest_bad_signature_refused` |
//! | content keys never appear in Debug or audit records (REQ-AUD-003, REQ-RBAC-006) | `content_private_key_never_in_debug_or_records` |

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use usgp_api::{
    Api, ApiConfig, CheckReport, ContentChecker, ContentKeys, TlsAcceptorHandle, WimChecker,
};
use usgp_audit::AuditChain;
use usgp_crypto::SigningKey;
use usgp_crypto::tls::{ServerTls, TlsMinVersion};
use usgp_db::RepoTx;
use usgp_image::facts::{FileFact, FileFacts};
use usgp_image::testkit::builder::WimBuilder;
use usgp_image::{Compression, Progress, WimError};
use usgp_proto::facts::FactSource;
use usgp_proto::{Architecture, ContentId, ContentState, PackageManifestV1, SignedEnvelopeV1};

use crate::authz_matrix::requests;
use crate::common::{FakeChecker, Harness, Opts, Pinned, Who};

const MIB: usize = 1024 * 1024;

/// Method, path, headers, body.
type Case = (
    &'static str,
    String,
    Vec<(&'static str, String)>,
    Option<Vec<u8>>,
);

fn body(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn content_id(r: &crate::common::Resp) -> ContentId {
    ContentId::parse(r.json()["content_id"].as_str().unwrap()).unwrap()
}

/// A harness whose unauthenticated audit cap does not interfere.
async fn uncapped() -> Harness {
    Harness::with(Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 10_000;
            // M3 added routes: two credential failure kinds x every route
            // exceed the default credential cap of 60 per minute.
            c.credential_failure_records_per_source_per_min = 10_000;
        }),
        ..Opts::default()
    })
    .await
}

// ------------------------------------------------------------- authn

/// Exit criterion 4 on every route, for each kind of authentication
/// failure: 401 with `WWW-Authenticate`, the same body everywhere, one
/// audit record per request with the source and the path, and nothing
/// changed.
#[tokio::test]
async fn every_route_401_audited_for_each_authn_failure() {
    let h = uncapped().await;
    let (pkg, image, pe) = h.ready_package("authn").await;
    let r = h
        .create_upload("image", "Open", b"FAKEWIM:1:open authn", None)
        .await;
    let upload = r.json()["upload_id"].as_str().unwrap().to_owned();
    let list = requests(&image.to_string(), &pe.to_string(), &pkg, &upload);
    assert_eq!(list.len(), usgp_api::routes::ROUTES.len());
    let before = h.snapshot().await;

    for (who, event, reason) in [
        (
            Who::Anonymous,
            "auth.unauthenticated",
            "no_client_certificate",
        ),
        (
            Who::Unknown,
            "auth.unknown_certificate",
            "unknown_certificate",
        ),
        (Who::Disabled, "auth.operator_disabled", "operator_disabled"),
    ] {
        let n0 = h.events(event).len();
        let mut bodies = Vec::new();
        for (m, path, b) in list.clone() {
            let r = h
                .req(
                    who,
                    m,
                    &path,
                    &[("if-match", "\"r1\"")],
                    b.map(|v| body(&v)),
                )
                .await;
            assert_eq!(r.status, 401, "{who:?} {m} {path}");
            assert_eq!(
                r.header("www-authenticate").as_deref(),
                Some("usgp-client-cert realm=\"usg-provision\""),
                "{who:?} {m} {path}"
            );
            assert_eq!(r.code(), "unauthenticated");
            bodies.push(r.body);
        }
        assert!(
            bodies.windows(2).all(|w| w[0] == w[1]),
            "401 bodies differ by route for {who:?}"
        );
        let recs = h.events(event);
        assert_eq!(
            recs.len() - n0,
            list.len(),
            "{event}: one record per request"
        );
        for (rec, (m, path, _)) in recs[n0..].iter().zip(list.iter()) {
            assert_eq!(rec.outcome, "refused");
            assert_eq!(rec.actor_kind, "unauthenticated");
            assert_eq!(rec.interface, "api");
            assert_eq!(rec.reason.as_deref(), Some(reason));
            assert!(rec.source.as_deref().unwrap().starts_with("127.0.0.1:"));
            assert!(
                rec.detail.contains(&format!("\"method\":\"{m}\"")),
                "{}",
                rec.detail
            );
            // The record names the path without its query (M3 relay route).
            let path_only = path.split('?').next().unwrap_or_default();
            assert!(rec.detail.contains(path_only), "{}", rec.detail);
            if who != Who::Anonymous {
                // What the product could learn of the requester (REQ-AUD-001).
                let fp = h
                    .cert(who)
                    .unwrap()
                    .peer_certificate()
                    .unwrap()
                    .sha256
                    .to_hex();
                assert!(rec.actor_label.as_deref().unwrap().contains(&fp));
            }
        }
    }
    assert_eq!(
        h.snapshot().await,
        before,
        "an unauthenticated request changed state"
    );
}

/// Every TLS failure class the default server can see reaches the audit
/// chain with its class, the source and an unauthenticated actor.
#[tokio::test]
async fn tls_failure_classes_audited() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 10_000;
            c.limits.handshake_timeout = Duration::from_secs(1);
        }),
        ..Opts::default()
    })
    .await;
    let before = h.snapshot().await;
    let mut want = Vec::new();
    for (cert, class) in [
        (&h.pki.client_not_yet_valid, "not_yet_valid"),
        (&h.pki.client_server_eku, "bad_eku"),
        (&h.pki.client_under_revoked, "revoked"),
        (&h.pki.client_revoked, "revoked"),
        (&h.pki.client_expired, "expired"),
        (&h.pki.client_untrusted, "untrusted"),
    ] {
        let _ = h.connect(Some(cert)).await;
        want.push(class);
        h.wait_events("auth.tls.failed", want.len()).await;
    }
    // A critical extension the client library itself refuses to send:
    // use a client with no local checks.
    let tls =
        usgp_crypto::test_pki::client_tls_without_local_checks(&h.pki, &h.pki.client_critical_ext)
            .unwrap();
    let _ = tls
        .connect(TcpStream::connect(h.addr).await.unwrap(), "localhost")
        .await;
    want.push("unknown_critical_ext");
    h.wait_events("auth.tls.failed", want.len()).await;
    // Not TLS at all.
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(b"GET /v1/limits HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    want.push("protocol");
    h.wait_events("auth.tls.failed", want.len()).await;
    drop(s);
    // Connected, silent: handshake timeout.
    let silent = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    want.push("handshake_timeout");
    let recs = h.wait_events("auth.tls.failed", want.len()).await;
    drop(silent);

    let mut got: Vec<&str> = recs.iter().map(|r| r.reason.as_deref().unwrap()).collect();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "{recs:?}");
    for r in &recs {
        assert_eq!(r.outcome, "refused");
        assert_eq!(r.actor_kind, "unauthenticated");
        assert_eq!(r.interface, "api");
        assert!(r.source.as_deref().unwrap().starts_with("127.0.0.1:"));
        assert!(r.detail.contains("\"class\""), "{}", r.detail);
    }
    assert_eq!(h.snapshot().await, before);
}

/// A second API on the harness store with its own TLS settings.
async fn server_with_tls(
    h: &Harness,
    crls: Vec<Vec<u8>>,
    policies: Vec<String>,
) -> std::net::SocketAddr {
    let mut config = ApiConfig::new(h.dir.join("content"));
    config.limits = h.api.config().limits.clone();
    let key = SigningKey::generate().unwrap();
    let pubk = key.verifying_key().clone();
    let api = Api::builder(
        h.store.clone(),
        config,
        AuditChain::new("test-node").unwrap(),
        ContentKeys::new(key, vec![pubk]).unwrap(),
    )
    .checker(Arc::clone(&h.fake) as Arc<dyn ContentChecker>)
    .build()
    .unwrap();
    let settings = h
        .pki
        .server_settings(crls, policies, TlsMinVersion::Tls12)
        .unwrap();
    let tls = Arc::new(TlsAcceptorHandle::new(ServerTls::new(&settings).unwrap()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = usgp_api::serve(api, listener, tls, std::future::pending()).await;
    });
    addr
}

/// Stale CRL (fail closed) and a certificate-policy mismatch, both with
/// a certificate that is otherwise valid: refused and audited.
#[tokio::test]
async fn tls_stale_crl_and_policy_audited() {
    let h = Harness::start().await;
    let stale = server_with_tls(&h, h.pki.crls_with_stale_intermediate().unwrap(), vec![]).await;
    let _ = h.connect_to(stale, Some(&h.pki.client)).await;
    let recs = h.wait_events("auth.tls.failed", 1).await;
    assert_eq!(recs[0].reason.as_deref(), Some("crl_stale"));
    // An OID no test certificate carries.
    let policy = server_with_tls(
        &h,
        h.pki.current_crls().unwrap(),
        vec!["1.3.6.1.4.1.55555.9.9.9".to_owned()],
    )
    .await;
    let _ = h.connect_to(policy, Some(&h.pki.client)).await;
    let recs = h.wait_events("auth.tls.failed", 2).await;
    assert_eq!(recs[1].reason.as_deref(), Some("policy"));
}

// ------------------------------------------------- audit fail-closed

/// REQ-AUD-006 / decision 0015 item 1 on every mutating route: with the
/// next audit write failing, the action is refused with
/// `audit_unavailable` and nothing changes.
#[tokio::test]
async fn audit_failure_refuses_every_mutation() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("afm").await;
    let spare = h.ready_image(2, "afm spare").await;
    let r = h
        .create_upload("image", "Open", b"FAKEWIM:1:afm open", None)
        .await;
    let upload = r.json()["upload_id"].as_str().unwrap().to_owned();
    let pkg_body = body(&serde_json::json!({
        "name": "Renamed", "image_id": image.to_string(), "edition_index": 1, "pe_id": pe.to_string()
    }));
    let img_etag = h
        .get(Who::Admin, &format!("/v1/images/{spare}"))
        .await
        .header("etag")
        .unwrap();
    let decl = body(
        &serde_json::json!({"release": "windows-11", "edition": "enterprise", "architecture": "x64"}),
    );
    let cases: Vec<Case> = vec![
        (
            "POST",
            "/v1/uploads".into(),
            vec![],
            Some(body(&serde_json::json!({
                "kind": "image", "display_name": "N", "file_name": "n.wim", "size": 9,
                "sha256": usgp_crypto::sha256(b"FAKEWIM:1").to_hex()
            }))),
        ),
        (
            "PUT",
            format!("/v1/uploads/{upload}"),
            vec![("content-type", "application/octet-stream".into())],
            Some(b"FAKEWIM:1:afm open".to_vec()),
        ),
        ("DELETE", format!("/v1/uploads/{upload}"), vec![], None),
        (
            "PUT",
            format!("/v1/images/{spare}/editions/1/declaration"),
            vec![],
            Some(decl),
        ),
        (
            "DELETE",
            format!("/v1/images/{spare}"),
            vec![("if-match", img_etag)],
            None,
        ),
        (
            "PUT",
            format!("/v1/packages/{pkg}"),
            vec![("if-match", "\"r1\"".into())],
            Some(pkg_body),
        ),
        (
            "POST",
            format!("/v1/packages/{pkg}/clone"),
            vec![],
            Some(body(&serde_json::json!({"name": "Copy"}))),
        ),
        (
            "DELETE",
            format!("/v1/packages/{pkg}"),
            vec![("if-match", "\"r1\"".into())],
            None,
        ),
    ];
    for (m, path, headers, b) in cases {
        let before = h.snapshot().await;
        let staging_before = h.api.files().list_staging().unwrap().len();
        h.store.fail_next_audit_writes(1);
        let hdrs: Vec<(&str, &str)> = headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let r = h.req(Who::Admin, m, &path, &hdrs, b).await;
        assert_eq!(
            r.status,
            500,
            "{m} {path}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(r.code(), "audit_unavailable", "{m} {path}");
        assert!(
            !r.json()["error"]["message"].as_str().unwrap().is_empty(),
            "the operator is told why"
        );
        // Give any background work a moment, then nothing has changed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(h.snapshot().await, before, "{m} {path} changed state");
        assert_eq!(
            h.api.files().list_staging().unwrap().len(),
            staging_before,
            "{m} {path} left a staging file"
        );
    }
    // The spare image's object is still there (the delete did not unlink).
    let c = h.wait_settled(spare).await;
    assert!(h.api.files().object_path(&c.sha256).exists());
}

/// REQ-AUD-001 (protected reads are audited) with REQ-AUD-006: a read of
/// protected content whose record cannot be written is refused and
/// returns none of the content.
#[tokio::test]
async fn audit_failure_refuses_every_protected_read() {
    let h = Harness::start().await;
    let (pkg, image, pe) = h.ready_package("afr").await;
    for path in [
        "/v1/limits".to_owned(),
        "/v1/images".to_owned(),
        format!("/v1/images/{image}"),
        format!("/v1/images/{image}/manifest"),
        "/v1/pe".to_owned(),
        format!("/v1/pe/{pe}"),
        format!("/v1/pe/{pe}/manifest"),
        format!("/v1/content/{image}"),
        format!("/v1/content/{pe}"),
        "/v1/packages".to_owned(),
        format!("/v1/packages/{pkg}"),
        format!("/v1/packages/{pkg}/manifest"),
    ] {
        h.store.fail_next_audit_writes(1);
        let r = h.get(Who::Admin, &path).await;
        assert_eq!(
            r.status,
            500,
            "{path}: {}",
            String::from_utf8_lossy(&r.body)
        );
        assert_eq!(r.code(), "audit_unavailable", "{path}");
        assert!(
            !String::from_utf8_lossy(&r.body).contains("FAKEWIM"),
            "{path} returned content"
        );
    }
    // Content is untouched by the refused reads.
    assert_eq!(h.wait_settled(image).await.state, ContentState::Ready);
    assert_eq!(h.wait_settled(pe).await.state, ContentState::Ready);
}

/// A checker that blocks until opened.
#[derive(Debug, Default)]
struct GateChecker {
    inner: FakeChecker,
    open: Mutex<bool>,
    cv: Condvar,
}

impl GateChecker {
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.cv.notify_all();
    }
}

impl ContentChecker for GateChecker {
    fn check(
        &self,
        path: &Path,
        kind: usgp_proto::ContentKind,
        progress: &mut dyn Progress,
    ) -> Result<CheckReport, WimError> {
        let mut g = self.open.lock().unwrap();
        while !*g {
            let (n, _) = self.cv.wait_timeout(g, Duration::from_millis(20)).unwrap();
            g = n;
            // Keep the stall watchdog quiet while gated.
            let _ = progress.advance(1);
        }
        drop(g);
        self.inner.check(path, kind, progress)
    }

    fn file_facts(&self, path: &Path, index: u32) -> Result<FileFacts, WimError> {
        self.inner.file_facts(path, index)
    }
}

/// REQ-AUD-006 last sentence: content does not become Ready unless its
/// record is written; no object is left in the store as if it were.
#[tokio::test]
async fn audit_failure_blocks_ready_transition() {
    let gate = Arc::new(GateChecker::default());
    let h = Harness::with(Opts {
        checker: Some(Arc::clone(&gate) as Arc<dyn ContentChecker>),
        ..Opts::default()
    })
    .await;
    let data = b"FAKEWIM:2:gated".to_vec();
    let id = h.upload("image", "Gated", &data, None).await;
    h.store.set_fail_audit_writes(true);
    gate.release();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut tx = usgp_db::Store::begin(&h.store).await.unwrap();
    let c = usgp_db::RepoTx::content(&mut tx, id)
        .await
        .unwrap()
        .unwrap();
    tx.rollback().await;
    assert_ne!(
        c.state,
        ContentState::Ready,
        "Ready without its audit record"
    );
    assert!(h.events("content.ready").is_empty());
    assert!(
        !h.api
            .files()
            .object_path(&usgp_crypto::sha256(&data))
            .exists(),
        "an object exists for content that is not Ready"
    );
    h.store.set_fail_audit_writes(false);
    // Recovery settles it as Failed (never Ready), audited.
    let _ = h.api.recover().await.unwrap();
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed, "{:?}", c.reason);
}

// ----------------------------------------------------- in-use delete

/// REQ-IMG-015 item 1: the in-use refusal names every dependant, in the
/// response and in the audit record, for image and PE.
#[tokio::test]
async fn in_use_delete_refusal_audit_names_dependants() {
    let h = Harness::start().await;
    let (pkg1, image, pe) = h.ready_package("dep").await;
    let r = h
        .post_json(
            Who::Admin,
            &format!("/v1/packages/{pkg1}/clone"),
            serde_json::json!({"name": "Dep Clone"}),
        )
        .await;
    assert_eq!(r.status, 201);
    let pkg2 = r.json()["id"].as_str().unwrap().to_owned();
    for (path, id, event) in [
        ("images", image, "image.delete.refused"),
        ("pe", pe, "pe.delete.refused"),
    ] {
        let etag = h
            .get(Who::Admin, &format!("/v1/{path}/{id}"))
            .await
            .header("etag")
            .unwrap();
        let before = h.snapshot().await;
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
        let deps: Vec<String> = r.json()["error"]["dependants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(deps.contains(&pkg1) && deps.contains(&pkg2), "{deps:?}");
        let msg = r.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(
            msg.contains("Package dep") && msg.contains("Dep Clone"),
            "{msg}"
        );
        assert_eq!(h.snapshot().await, before);
        let rec = h.events(event);
        let last = rec.last().unwrap_or_else(|| panic!("no {event}"));
        assert_eq!(last.reason.as_deref(), Some("in_use"));
        assert_eq!(last.target_id.as_deref(), Some(id.to_string().as_str()));
        assert!(
            last.detail.contains(&pkg1) && last.detail.contains(&pkg2),
            "{}",
            last.detail
        );
    }
}

// ------------------------------------------------ facts (0013)

/// Decision 0013 item 2 / REQ-IMG-043 item 3: a fact the file states and
/// the declaration matches is `verified`, the rest `declared`, in the
/// view and in the signed package manifest (image and PE).
#[tokio::test]
async fn verified_and_declared_sources_signed_into_package_manifest() {
    let h = Harness::start().await;
    *h.fake.facts.lock().unwrap() = FileFacts {
        release: FileFact::NotStated,
        edition: FileFact::NotStated,
        architecture: FileFact::Stated(Architecture::X64),
    };
    let (pkg, _image, pe) = h.ready_package("verified").await;
    let pv = h.get(Who::Admin, &format!("/v1/pe/{pe}")).await.json();
    assert_eq!(pv["architecture"]["source"], "verified");
    assert_eq!(pv["kit_version"]["source"], "declared");
    let env = SignedEnvelopeV1::from_json(
        &h.get(Who::Admin, &format!("/v1/packages/{pkg}/manifest"))
            .await
            .body,
    )
    .unwrap();
    let m = PackageManifestV1::open(&env, &Pinned(h.content_pub.clone())).unwrap();
    assert_eq!(m.image.facts.architecture.source, FactSource::Verified);
    assert_eq!(m.image.facts.release.source, FactSource::Declared);
    assert_eq!(m.image.facts.edition.source, FactSource::Declared);
    assert_eq!(m.pe.architecture.source, FactSource::Verified);
    assert_eq!(m.pe.kit_version.source, FactSource::Declared);
    // The declaration record carries the per-fact sources.
    let d = h.events("edition.declared");
    assert!(
        d.last().unwrap().detail.contains("verified"),
        "{}",
        d.last().unwrap().detail
    );
}

/// REQ-PE-005 item 2: a PE declared x64 whose file states another
/// architecture is refused at import (Failed, reason naming the fact),
/// audited, and never Ready.
#[tokio::test]
async fn pe_declaration_contradicting_file_fails_import_audited() {
    let h = Harness::start().await;
    h.fake.facts.lock().unwrap().architecture = FileFact::Stated(Architecture::Arm64);
    let id = h
        .upload(
            "pe",
            "Contra PE",
            b"FAKEWIM:1:contra pe",
            Some(("x64", "10.1.26100.1")),
        )
        .await;
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    let reason = c.reason.unwrap();
    assert_eq!(reason.code, "declaration_contradicts_file:architecture");
    let f = h.events("content.failed");
    let rec = f.last().unwrap();
    assert_eq!(
        rec.reason.as_deref(),
        Some("declaration_contradicts_file:architecture")
    );
    assert_eq!(rec.target_id.as_deref(), Some(id.to_string().as_str()));
    assert!(h.events("pe.declared").is_empty());
    assert!(h.api.files().list_staging().unwrap().is_empty());
}

/// REQ-IMG-043 item 2: when the file contradicts itself, no declaration
/// of that fact can be verified; the declaration is refused and audited.
#[tokio::test]
async fn inconsistent_file_fact_refuses_declaration() {
    let h = Harness::start().await;
    let image = h.ready_image(1, "incons").await;
    h.fake.facts.lock().unwrap().architecture = FileFact::Inconsistent;
    let before = h.snapshot().await;
    let r = h.declare(image, 1, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.status, 422);
    assert_eq!(r.code(), "declaration_contradicts_file:architecture");
    assert_eq!(h.snapshot().await, before);
    let rec = h.events("edition.declaration.refused");
    assert_eq!(
        rec.last().unwrap().reason.as_deref(),
        Some("declaration_contradicts_file:architecture")
    );
}

/// REQ-OS-001/002/004/005/007 and decision 0013 item 3: every value
/// outside Windows 11 / Enterprise / x64 is refused at selection with a
/// reason naming it, audited `os_support.refused`, nothing created; the
/// one in-scope triple makes a Ready package.
#[tokio::test]
async fn every_out_of_scope_value_refused_at_selection_audited() {
    let h = Harness::start().await;
    let bad: &[(&str, &str, &str, &str)] = &[
        (
            "windows-10",
            "enterprise",
            "x64",
            "release_not_supported:windows-10",
        ),
        ("other", "enterprise", "x64", "release_not_supported:other"),
        (
            "windows-11",
            "enterprise-ltsc",
            "x64",
            "edition_not_supported:enterprise-ltsc",
        ),
        (
            "windows-11",
            "iot-enterprise",
            "x64",
            "edition_not_supported:iot-enterprise",
        ),
        (
            "windows-11",
            "education",
            "x64",
            "edition_not_supported:education",
        ),
        ("windows-11", "pro", "x64", "edition_not_supported:pro"),
        ("windows-11", "home", "x64", "edition_not_supported:home"),
        ("windows-11", "other", "x64", "edition_not_supported:other"),
        (
            "windows-11",
            "enterprise",
            "x86",
            "architecture_not_supported:x86",
        ),
        (
            "windows-11",
            "enterprise",
            "arm64",
            "architecture_not_supported:arm64",
        ),
        (
            "windows-11",
            "enterprise",
            "arm",
            "architecture_not_supported:arm",
        ),
    ];
    let n = u32::try_from(bad.len()).unwrap() + 1;
    let image = h.ready_image(n, "scope all").await;
    let pe = h.ready_pe("scope all").await;
    for (i, (rel, ed, arch, _)) in bad.iter().enumerate() {
        let idx = u32::try_from(i).unwrap() + 1;
        let r = h.declare(image, idx, rel, ed, arch).await;
        assert_eq!(r.status, 200, "{rel}/{ed}/{arch}");
        assert_eq!(r.json()["support"]["status"], "not_supported");
    }
    let before = h.snapshot().await;
    let n0 = h.events("os_support.refused").len();
    for (i, (_, _, _, reason)) in bad.iter().enumerate() {
        let idx = u32::try_from(i).unwrap() + 1;
        let r = h.create_package("Out of scope", image, idx, pe).await;
        assert_eq!(r.status, 422, "{reason}");
        assert_eq!(r.code(), "os_scope");
        let msg = r.json()["error"]["message"].as_str().unwrap().to_owned();
        assert!(msg.contains(reason), "{reason}: {msg}");
        let rec = h.events("os_support.refused");
        let last = rec.last().unwrap();
        assert_eq!(last.outcome, "refused");
        assert_eq!(last.actor_kind, "operator");
    }
    assert_eq!(h.events("os_support.refused").len() - n0, bad.len());
    assert_eq!(
        h.snapshot().await,
        before,
        "a refused selection created something"
    );
    // The one in-scope triple.
    let r = h.declare(image, n, "windows-11", "enterprise", "x64").await;
    assert_eq!(r.json()["support"]["status"], "supported");
    let r = h.create_package("In scope", image, n, pe).await;
    assert_eq!(r.status, 201);
    assert_eq!(r.json()["status"], "ready");
}

// ---------------------------------------------- integrity on use

fn big(tag: u8) -> Vec<u8> {
    let mut v = format!("FAKEWIM:1:{tag}:").into_bytes();
    v.resize(9 * MIB, tag);
    v
}

fn tamper(h: &Harness, sha: &usgp_common::Sha256Digest, at: usize) {
    let p = h.api.files().object_path(sha);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let mut b = std::fs::read(&p).unwrap();
    b[at] ^= 0x01;
    std::fs::write(&p, b).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o440)).unwrap();
}

/// Decision 0011 / REQ-IMG-050: verification is repeated on every use. Two
/// good downloads, then one changed byte in the last chunk: the third
/// download does not deliver the changed chunk, and the item is Failed.
#[tokio::test]
async fn chunks_verified_on_every_download_not_cached() {
    let h = Harness::start().await;
    let data = big(7);
    let id = h.ready("image", "Every use", &data, None).await;
    for i in 1..=2 {
        let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
        assert_eq!(r.status, 200);
        assert_eq!(r.body, data, "download {i}");
        h.wait_events("content.download.completed", i).await;
    }
    tamper(&h, &usgp_crypto::sha256(&data), data.len() - 1);
    let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_ne!(r.body, data, "a changed chunk was delivered");
    assert!(r.body.len() <= 8 * MIB || r.body == b"<aborted>");
    h.wait_events("content.download.aborted", 1).await;
    let c = h.wait_settled(id).await;
    assert_eq!(c.state, ContentState::Failed);
    assert_eq!(c.reason.unwrap().code, "integrity_failed_on_use");
    assert_eq!(h.events("content.integrity.failed").len(), 1);
    // And it is never served again.
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/content/{id}")).await.status,
        409
    );
}

/// REQ-PE-008: the PE gets the same protection; its Ready packages become
/// not usable, naming the PE.
#[tokio::test]
async fn pe_tamper_detected_package_not_usable() {
    let h = Harness::start().await;
    let (pkg, _image, pe) = h.ready_package("pe tamper").await;
    let c = h.wait_settled(pe).await;
    tamper(&h, &c.sha256, 0);
    let r = h.get(Who::Admin, &format!("/v1/content/{pe}")).await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    let c = h.wait_settled(pe).await;
    assert_eq!(c.state, ContentState::Failed);
    let p = h
        .get(Who::Admin, &format!("/v1/packages/{pkg}"))
        .await
        .json();
    assert_eq!(p["status"], "not_usable");
    assert_eq!(p["status_reason"]["code"], "not_ready_content:pe");
    let m = h
        .get(Who::Admin, &format!("/v1/packages/{pkg}/manifest"))
        .await;
    assert_eq!(m.status, 409);
    assert_eq!(m.code(), "package_not_ready");
}

/// SI-7(6): a package manifest that no trusted key signed is not served.
#[tokio::test]
async fn package_manifest_bad_signature_refused() {
    let h = Harness::start().await;
    let (pkg, _image, _pe) = h.ready_package("pkg sig").await;
    let other = SigningKey::generate().unwrap();
    let pubk = other.verifying_key().clone();
    let addr = h
        .second_server(ContentKeys::new(other, vec![pubk]).unwrap())
        .await;
    let r = h
        .req_at(
            addr,
            h.cert(Who::Admin),
            "GET",
            &format!("/v1/packages/{pkg}/manifest"),
            &[],
            None,
        )
        .await;
    assert_eq!(r.status, 500);
    assert_eq!(r.code(), "integrity_failed");
    assert!(!String::from_utf8_lossy(&r.body).contains("payload_b64"));
    assert!(
        h.records()
            .iter()
            .any(|x| x.reason.as_deref() == Some("integrity_failed")),
        "the refusal is audited"
    );
}

// ------------------------------------------------------- secrets

/// RFC 4648 §4 base64 (no new dev-dependency for one canary).
fn b64_std(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(char::from(A[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// REQ-AUD-003 / REQ-RBAC-006 / decision 0011: the content signing key's
/// private bytes never appear in `Debug` output, responses or audit
/// records, after a full flow signed with that key.
#[tokio::test]
async fn content_private_key_never_in_debug_or_records() {
    let h = Harness::start().await;
    let key = SigningKey::generate().unwrap();
    let der = key.to_pkcs8_der().unwrap();
    let hex: String = der.iter().map(|b| format!("{b:02x}")).collect();
    let b64 = b64_std(der.as_slice());
    // The private scalar is the tail of the PKCS#8 structure; a 16-byte
    // window of it is a sufficient canary.
    let tail_hex = hex[hex.len() - 32..].to_owned();
    let pubk = key.verifying_key().clone();
    let keys = ContentKeys::new(key, vec![pubk]).unwrap();
    let dbg = format!("{keys:?}");
    for bad in [hex.as_str(), b64.as_str(), tail_hex.as_str()] {
        assert!(!dbg.contains(bad), "ContentKeys Debug leaks key bytes");
    }
    let addr = h.second_server(keys).await;
    // A flow on the second server, so its manifests are signed with `key`.
    let admin = h.cert(Who::Admin);
    let data = b"FAKEWIM:2:secret flow".to_vec();
    let r = h
        .req_at(
            addr,
            admin,
            "POST",
            "/v1/uploads",
            &[],
            Some(body(&serde_json::json!({
                "kind": "image", "display_name": "S", "file_name": "s.wim",
                "size": data.len(), "sha256": usgp_crypto::sha256(&data).to_hex()
            }))),
        )
        .await;
    assert_eq!(r.status, 201);
    let up = r.json()["upload_id"].as_str().unwrap().to_owned();
    let id = content_id(&r);
    let r = h
        .req_at(
            addr,
            admin,
            "PUT",
            &format!("/v1/uploads/{up}"),
            &[],
            Some(data),
        )
        .await;
    assert_eq!(r.status, 202);
    assert_eq!(h.wait_settled(id).await.state, ContentState::Ready);
    let mut texts = Vec::new();
    for p in [
        format!("/v1/images/{id}"),
        format!("/v1/images/{id}/manifest"),
        "/v1/limits".to_owned(),
    ] {
        let r = h.req_at(addr, admin, "GET", &p, &[], None).await;
        assert_eq!(r.status, 200, "{p}");
        texts.push(String::from_utf8_lossy(&r.body).into_owned());
    }
    for r in h.records() {
        texts.push(format!("{r:?}"));
    }
    for t in &texts {
        for bad in [hex.as_str(), b64.as_str(), tail_hex.as_str(), "PRIVATE KEY"] {
            assert!(!t.contains(bad), "key material found");
        }
    }
}

// ------------------------------------------------- refused codecs

/// Decision 0014 / REQ-IMG-038 through the API with the production
/// checker: LZMS/.esd-style, resource-only and metadata-only files are
/// Failed with their named reason codes and audited; nothing is served.
#[tokio::test]
async fn lzms_esd_resource_only_metadata_only_refused_via_api() {
    let h = Harness::with(Opts {
        checker: Some(Arc::new(WimChecker::new(usgp_image::WimLimits::DEFAULT))),
        ..Opts::default()
    })
    .await;
    let mk = |c: Compression, flags: u32| {
        WimBuilder::new(c)
            .image("a", "b")
            .header_flags(flags)
            .build()
            .unwrap()
            .0
    };
    let cases = [
        (
            "LZMS esd",
            mk(Compression::Xpress, 0x0008_0082),
            "wim_compression_not_supported",
        ),
        (
            "Unknown codec",
            mk(Compression::Xpress, 0x0001_0082),
            "wim_compression_not_supported",
        ),
        (
            "Resource only",
            mk(Compression::None, 0x90),
            "wim_resource_only_not_supported",
        ),
        (
            "Metadata only",
            mk(Compression::None, 0xa0),
            "wim_metadata_only_not_supported",
        ),
        (
            "Not a WIM (.esd text)",
            b"MSWIM\0\0\0 but truncated".to_vec(),
            "wim_truncated",
        ),
    ];
    for (name, data, code) in cases {
        let id = h.upload("image", name, &data, None).await;
        let c = h.wait_settled(id).await;
        assert_eq!(c.state, ContentState::Failed, "{name}");
        let v = h.get(Who::Admin, &format!("/v1/images/{id}")).await.json();
        assert_eq!(v["reason"]["code"], code, "{name}");
        assert!(!v["reason"]["message"].as_str().unwrap().is_empty());
        assert!(
            h.events("content.failed")
                .iter()
                .any(|r| r.reason.as_deref() == Some(code)
                    && r.target_id.as_deref() == Some(id.to_string().as_str())),
            "{name} not audited"
        );
        assert_eq!(
            h.get(Who::Admin, &format!("/v1/content/{id}")).await.status,
            409
        );
    }
    assert!(h.api.files().list_staging().unwrap().is_empty());
}

/// REQ-PE-006: the PE view shows the operator's name, architecture and
/// kit version with their sources, when it was imported, its status, its
/// digest and which packages use it.
#[tokio::test]
async fn pe_view_shows_required_fields_and_packages_using_it() {
    let h = Harness::start().await;
    let (pkg, _image, pe) = h.ready_package("pe view").await;
    let c = h.wait_settled(pe).await;
    let v = h.get(Who::Admin, &format!("/v1/pe/{pe}")).await;
    assert_eq!(v.status, 200);
    let j = v.json();
    assert_eq!(j["display_name"], "PE pe view");
    assert_eq!(j["architecture"]["value"], "x64");
    assert_eq!(j["architecture"]["source"], "declared");
    assert_eq!(j["kit_version"]["value"], "10.1.26100.1");
    assert!(j["imported_at"].is_number() || j["imported_at"].is_string());
    assert_eq!(j["state"], "ready");
    assert_eq!(j["sha256"], c.sha256.to_hex());
    let used: Vec<&str> = j["used_by"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(used, vec![pkg.as_str()]);
}
