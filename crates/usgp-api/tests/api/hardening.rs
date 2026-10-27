//! Review round 1 (M2): connection caps and lifetime (SEC-001, SEC-007,
//! NIST-010), audit budgets (SEC-004, NIST-001, NIST-005, SEC-012), checkpoint
//! failure reporting (NIST-003), download I/O errors (SEC-008) and upload
//! quota serialisation (SEC-009).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use usgp_api::context::CheckpointStatus;
use usgp_api::{Api, ApiConfig, ContentKeys};
use usgp_audit::{AuditChain, CheckpointPolicy, Checkpointer};
use usgp_crypto::SigningKey;
use usgp_crypto::tls::{ServerTls, TlsMinVersion};
use usgp_db::{MemoryStore, RepoTx, Store};
use usgp_proto::ContentState;

use crate::common::{Harness, Opts, Who};

const REQ: &[u8] = b"GET /v1/limits HTTP/1.1\r\nhost: localhost\r\n\r\n";

/// Reads until the peer closes, for at most `limit`; `None` on timeout.
async fn read_to_close<S: AsyncReadExt + Unpin>(s: &mut S, limit: Duration) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match tokio::time::timeout(limit, s.read_to_end(&mut out)).await {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}

/// SEC-001: a 401 carries `Connection: close` and the server closes the
/// connection (no keep-alive slot for an unauthenticated peer).
#[tokio::test]
async fn unauthenticated_401_closes_the_connection() {
    let h = Harness::start().await;
    let mut s = h.connect(None).await.unwrap();
    s.write_all(REQ).await.unwrap();
    s.flush().await.unwrap();
    let out = read_to_close(&mut s, Duration::from_secs(5))
        .await
        .expect("the server closed the connection after the 401");
    let text = String::from_utf8_lossy(&out).to_ascii_lowercase();
    assert!(text.starts_with("http/1.1 401"), "{text}");
    assert!(text.contains("connection: close"), "{text}");
}

/// SEC-001: connections and handshakes per source are capped; a source
/// at its cap is closed at accept, and its slots come back when its
/// connections end.
#[tokio::test]
async fn per_source_connection_cap() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.limits.max_connections_per_source = 2;
            c.limits.max_handshakes_per_source = 2;
            c.limits.handshake_timeout = Duration::from_secs(5);
            c.unauth_records_per_source_per_min = 10_000;
        }),
        ..Opts::default()
    })
    .await;
    // Two silent connections (handshakes in progress) fill the source.
    let a = TcpStream::connect(h.addr).await.unwrap();
    let b = TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut c = TcpStream::connect(h.addr).await.unwrap();
    let out = read_to_close(&mut c, Duration::from_secs(2))
        .await
        .expect("the over-cap connection is closed at once");
    assert!(out.is_empty());
    drop((a, b));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.get(Who::Admin, "/v1/limits").await.status, 200);
}

/// SEC-001: connections without a client certificate may hold only the
/// unreserved slots; the reserved ones stay usable by operators.
#[tokio::test]
async fn reserved_slots_for_certificate_holders() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.limits.max_connections = 4;
            c.limits.max_connections_per_source = 4;
            c.limits.max_handshakes_per_source = 4;
            c.limits.reserved_cert_connections = 2;
        }),
        ..Opts::default()
    })
    .await;
    // Two anonymous TLS connections, kept open and idle.
    let anon1 = h.connect(None).await.unwrap();
    let anon2 = h.connect(None).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    // A third anonymous connection is closed without an HTTP answer.
    let out = h.raw(Who::Anonymous, REQ, false).await;
    assert!(
        !String::from_utf8_lossy(&out).contains("HTTP/1.1"),
        "{}",
        String::from_utf8_lossy(&out)
    );
    // An operator still gets in.
    assert_eq!(h.get(Who::Admin, "/v1/limits").await.status, 200);
    drop((anon1, anon2));
}

/// SEC-007 / NIST-010: a connection older than `max_connection_age` is
/// closed after its request completes.
#[tokio::test]
async fn connection_age_cap_closes_after_the_request() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.limits.max_connection_age = Duration::from_secs(1)),
        ..Opts::default()
    })
    .await;
    let mut s = h.connect(h.cert(Who::Admin)).await.unwrap();
    s.write_all(REQ).await.unwrap();
    s.flush().await.unwrap();
    let t = Instant::now();
    let out = read_to_close(&mut s, Duration::from_secs(10))
        .await
        .expect("closed by the age cap");
    assert!(String::from_utf8_lossy(&out).starts_with("HTTP/1.1 200"));
    assert!(
        t.elapsed() >= Duration::from_millis(500),
        "{:?}",
        t.elapsed()
    );
}

/// SEC-007 / NIST-010: after the acceptor is replaced (CRL reload),
/// connections accepted before it are closed.
#[tokio::test]
async fn crl_reload_closes_older_connections() {
    let h = Harness::start().await;
    let mut s = h.connect(h.cert(Who::Admin)).await.unwrap();
    s.write_all(REQ).await.unwrap();
    s.flush().await.unwrap();
    // Keep-alive: still open after the response.
    let mut first = [0u8; 12];
    s.read_exact(&mut first).await.unwrap();
    assert_eq!(&first, b"HTTP/1.1 200");
    assert!(
        read_to_close(&mut s, Duration::from_millis(500))
            .await
            .is_none(),
        "kept alive before the reload"
    );
    let g = h.tls.generation();
    let settings = h
        .pki
        .server_settings(
            h.pki.current_crls().unwrap(),
            Vec::new(),
            TlsMinVersion::Tls12,
        )
        .unwrap();
    h.tls.replace(ServerTls::new(&settings).unwrap());
    assert_eq!(h.tls.generation(), g + 1);
    assert!(
        read_to_close(&mut s, Duration::from_secs(5))
            .await
            .is_some(),
        "closed after the reload"
    );
    // New connections use the new acceptor.
    assert_eq!(h.get(Who::Admin, "/v1/limits").await.status, 200);
}

/// NIST-001 (and SEC-004): anonymous noise up to and past its cap does
/// not suppress a credential failure from the same source; the summary
/// counts per reason. NIST-005: the refused record names the presented
/// certificate.
#[tokio::test]
async fn anonymous_noise_then_revoked_certificate_still_recorded() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.unauth_records_per_source_per_min = 2),
        ..Opts::default()
    })
    .await;
    for _ in 0..5 {
        assert_eq!(h.get(Who::Anonymous, "/v1/limits").await.status, 401);
    }
    assert_eq!(h.events("auth.unauthenticated").len(), 2);
    let _ = h.connect(Some(&h.pki.client_revoked)).await;
    let recs = h.wait_events("auth.tls.failed", 1).await;
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].reason.as_deref(), Some("revoked"));
    let fp = h
        .pki
        .client_revoked
        .peer_certificate()
        .unwrap()
        .sha256
        .to_hex();
    assert!(
        recs[0].actor_label.as_deref().unwrap_or("").contains(&fp),
        "{:?}",
        recs[0]
    );
    h.api.flush_unauthenticated_summary().await;
    let s = h.events("auth.unauthenticated.summary");
    assert_eq!(s.len(), 1);
    assert!(
        s[0].detail.contains("\"suppressed\":\"3\""),
        "{}",
        s[0].detail
    );
    assert!(
        s[0].detail.contains("\"no_client_certificate\":\"3\""),
        "{}",
        s[0].detail
    );
}

/// SEC-012 / NIST-014: certificates that do not chain to our trust
/// anchors (self-made, foreign issuer) draw on the anonymous budget, so a
/// flood of them cannot suppress the individual record of a revoked
/// certificate from our PKI. (Many sources: `authn` unit test
/// `self_made_certificates_cannot_use_up_the_credential_budget`.)
#[tokio::test]
async fn self_made_certificates_then_revoked_certificate_still_recorded() {
    let h = Harness::with(Opts {
        config: Box::new(|c| {
            c.unauth_records_per_source_per_min = 2;
            c.credential_failure_records_per_source_per_min = 1;
            c.credential_failure_records_global_per_min = 1;
        }),
        ..Opts::default()
    })
    .await;
    for _ in 0..6 {
        let _ = h.connect(Some(&h.pki.client_untrusted)).await;
    }
    let untrusted = h.wait_events("auth.tls.failed", 2).await;
    assert_eq!(untrusted.len(), 2, "anonymous cap");
    for r in &untrusted {
        assert_eq!(r.reason.as_deref(), Some("untrusted"));
        assert!(
            r.detail.contains("\"trust_anchor\":\"not_chained\""),
            "{}",
            r.detail
        );
    }
    let _ = h.connect(Some(&h.pki.client_revoked)).await;
    let recs = h.wait_events("auth.tls.failed", 3).await;
    let revoked: Vec<_> = recs
        .iter()
        .filter(|r| r.reason.as_deref() == Some("revoked"))
        .collect();
    assert_eq!(revoked.len(), 1, "{recs:?}");
    assert!(
        revoked[0].detail.contains("\"trust_anchor\":\"chained\""),
        "{}",
        revoked[0].detail
    );
    let fp = h
        .pki
        .client_revoked
        .peer_certificate()
        .unwrap()
        .sha256
        .to_hex();
    assert!(
        revoked[0]
            .actor_label
            .as_deref()
            .unwrap_or("")
            .contains(&fp)
    );
    h.api.flush_unauthenticated_summary().await;
    let s = h.events("auth.unauthenticated.summary");
    assert_eq!(s.len(), 1);
    assert!(
        s[0].detail.contains("\"untrusted\":\"4\""),
        "{}",
        s[0].detail
    );
}

/// NIST-003: a checkpoint that cannot be written is reported (and
/// retried); the next attempt signs it.
#[tokio::test]
async fn checkpoint_failure_reported_and_retried() {
    let dir = std::env::temp_dir().join(format!("usgp-api-cp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let store = MemoryStore::new();
    let chain = AuditChain::new("test-node").unwrap();
    let audit_key = SigningKey::generate().unwrap();
    let mut tx = store.begin().await.unwrap();
    chain
        .ensure_genesis(&mut tx, &audit_key.key_id())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let content_key = SigningKey::generate().unwrap();
    let content_pub = content_key.verifying_key().clone();
    let api = Api::builder(
        store.clone(),
        ApiConfig::new(PathBuf::from(&dir).join("content")),
        chain,
        ContentKeys::new(content_key, vec![content_pub]).unwrap(),
    )
    .checkpointer(Checkpointer::new(audit_key, CheckpointPolicy::default()).unwrap())
    .build()
    .unwrap();
    store.fail_next_audit_writes(1);
    assert!(matches!(
        api.checkpoint(true).await,
        CheckpointStatus::Failed(_)
    ));
    assert!(store.audit_checkpoints().is_empty());
    assert!(matches!(
        api.checkpoint(true).await,
        CheckpointStatus::Signed(_)
    ));
    assert_eq!(store.audit_checkpoints().len(), 1);
    assert_eq!(api.checkpoint(true).await, CheckpointStatus::NotDue);
    drop(api);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The alarm gate: first failure reported, then at most once per
/// interval with the number suppressed.
#[test]
fn checkpoint_alarm_rate_limited() {
    let mut g = usgp_api::context::AlarmGate::new(Duration::from_secs(60));
    let t = Instant::now();
    assert_eq!(g.fire(t), Some(0));
    assert_eq!(g.fire(t + Duration::from_secs(1)), None);
    assert_eq!(g.fire(t + Duration::from_secs(2)), None);
    assert_eq!(g.fire(t + Duration::from_secs(61)), Some(2));
}

/// SEC-008: an object that cannot be read is a 503, audited as an
/// aborted download with the I/O kind; the content stays Ready.
#[tokio::test]
async fn unreadable_object_is_503_and_content_stays_ready() {
    let h = Harness::start().await;
    let id = h.ready_image(1, "io").await;
    let c = h.wait_settled(id).await;
    let p = h.api.files().object_path(&c.sha256);
    let moved = p.with_extension("away");
    std::fs::rename(&p, &moved).unwrap();
    let r = h.get(Who::Admin, &format!("/v1/content/{id}")).await;
    assert_eq!(r.status, 503, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(r.code(), "storage_error");
    assert_eq!(h.wait_settled(id).await.state, ContentState::Ready);
    let a = h.wait_events("content.download.aborted", 1).await;
    assert!(a[0].detail.contains("\"io_kind\""), "{}", a[0].detail);
    assert!(h.events("content.integrity.failed").is_empty());
    // Back in place: served again.
    std::fs::rename(&moved, &p).unwrap();
    assert_eq!(
        h.get(Who::Admin, &format!("/v1/content/{id}")).await.status,
        200
    );
}

/// SEC-009: concurrent session creates cannot exceed the open-upload cap.
#[tokio::test]
async fn upload_quota_holds_under_concurrency() {
    let h = Arc::new(
        Harness::with(Opts {
            config: Box::new(|c| {
                c.content.max_open_uploads = 1;
                c.content.max_open_uploads_per_operator = 1;
            }),
            ..Opts::default()
        })
        .await,
    );
    let mut tasks = Vec::new();
    for i in 0..6u8 {
        let h = Arc::clone(&h);
        tasks.push(tokio::spawn(async move {
            let data = format!("FAKEWIM:1:quota {i}").into_bytes();
            h.create_upload("image", &format!("Q{i}"), &data, None)
                .await
                .status
        }));
    }
    let mut created = 0;
    for t in tasks {
        let s = t.await.unwrap();
        assert!(s == 201 || s == 429, "{s}");
        created += usize::from(s == 201);
    }
    assert_eq!(created, 1);
    let mut tx = h.store.begin().await.unwrap();
    assert_eq!(tx.count_active_uploads(None).await.unwrap(), 1);
    tx.rollback().await;
}
