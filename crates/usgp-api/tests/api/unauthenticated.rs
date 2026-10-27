//! Authentication (REQ-RBAC-005, REQ-AUD-001; exit criterion 4).

use crate::common::{Harness, Opts, Who};

/// No client certificate: 401 with `WWW-Authenticate`, an audit record
/// naming the source, and nothing else learned (not even whether the
/// route exists).
#[tokio::test]
async fn no_cert_401_www_authenticate_audited() {
    let h = Harness::start().await;
    let before = h.snapshot().await;
    for path in ["/v1/limits", "/v1/images", "/v1/no-such-route"] {
        let r = h.get(Who::Anonymous, path).await;
        assert_eq!(r.status, 401, "{path}");
        assert_eq!(
            r.header("www-authenticate").as_deref(),
            Some("usgp-client-cert realm=\"usg-provision\"")
        );
        assert_eq!(r.code(), "unauthenticated");
    }
    let r = h
        .post_json(Who::Anonymous, "/v1/packages", serde_json::json!({}))
        .await;
    assert_eq!(r.status, 401);
    assert_eq!(h.snapshot().await, before);
    let recs = h.events("auth.unauthenticated");
    assert_eq!(recs.len(), 4);
    for r in &recs {
        assert_eq!(r.actor_kind, "unauthenticated");
        assert_eq!(r.outcome, "refused");
        assert_eq!(r.interface, "api");
        assert!(r.source.as_deref().unwrap().starts_with("127.0.0.1:"));
        assert_eq!(r.reason.as_deref(), Some("no_client_certificate"));
    }
}

/// A valid certificate with no operator bound to it: 401, audited with
/// the presented fingerprint.
#[tokio::test]
async fn unknown_cert_401() {
    let h = Harness::start().await;
    let r = h.get(Who::Unknown, "/v1/limits").await;
    assert_eq!(r.status, 401);
    let recs = h.events("auth.unknown_certificate");
    assert_eq!(recs.len(), 1);
    let fp = h.unknown.peer_certificate().unwrap().sha256.to_hex();
    assert!(recs[0].actor_label.as_deref().unwrap().contains(&fp));
}

/// A disabled operator: 401, audited.
#[tokio::test]
async fn disabled_401() {
    let h = Harness::start().await;
    let r = h.get(Who::Disabled, "/v1/limits").await;
    assert_eq!(r.status, 401);
    assert_eq!(h.events("auth.operator_disabled").len(), 1);
}

/// A presented certificate that fails validation fails the handshake;
/// the refusal is audited with its class.
#[tokio::test]
async fn tls_failures_audited_with_class() {
    let h = Harness::start().await;
    for (i, (cert, class)) in [
        (&h.pki.client_revoked, "revoked"),
        (&h.pki.client_expired, "expired"),
        (&h.pki.client_untrusted, "untrusted"),
    ]
    .into_iter()
    .enumerate()
    {
        // With TLS 1.3 the client may finish before the server's alert
        // arrives, so only the server-side record is asserted.
        let _ = h.connect(Some(cert)).await;
        let recs = h.wait_events("auth.tls.failed", i + 1).await;
        let rec = recs
            .iter()
            .find(|r| r.reason.as_deref() == Some(class))
            .unwrap_or_else(|| panic!("{class}: {recs:?}"));
        // NIST-005: the record names what was presented (a claim, the
        // actor stays unauthenticated).
        let pc = cert.peer_certificate().unwrap();
        let label = rec.actor_label.as_deref().unwrap_or("");
        assert_eq!(rec.actor_kind, "unauthenticated");
        assert!(label.contains(&pc.sha256.to_hex()), "{class}: {label}");
        assert!(label.contains(&pc.serial), "{class}: {label}");
    }
}

/// Unauthenticated audit volume is capped per source; the excess is
/// summarised (plan section 3.2).
#[tokio::test]
async fn unauthenticated_records_capped_and_summarised() {
    let h = Harness::with(Opts {
        config: Box::new(|c| c.unauth_records_per_source_per_min = 3),
        ..Opts::default()
    })
    .await;
    for _ in 0..7 {
        assert_eq!(h.get(Who::Anonymous, "/v1/limits").await.status, 401);
    }
    assert_eq!(h.events("auth.unauthenticated").len(), 3);
    h.api.flush_unauthenticated_summary().await;
    let s = h.events("auth.unauthenticated.summary");
    assert_eq!(s.len(), 1);
    assert!(
        s[0].detail.contains("\"suppressed\":\"4\""),
        "{}",
        s[0].detail
    );
}
