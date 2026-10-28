//! `serve` in-process on the in-memory store, over real mutual TLS on
//! 127.0.0.1 with the test PKI (plan M2 sections 1.1, 5.4, 5.6, 7;
//! WU-7). The PostgreSQL path is `e2e_pg.rs` (CI).
//!
//! | Behaviour | Test |
//! |-----------|------|
//! | genesis, `server.start`, mTLS, 401 + audit, `server.stop`, final checkpoint, chain verifies | `serves_and_stops_with_final_checkpoint` |
//! | restart recovery marks an interrupted upload Failed (REQ-IMG-021) | `restart_marks_interrupted_upload_failed` |
//! | CRL reload: a bad CRL keeps the old acceptor; a revoking CRL refuses the operator | `crl_reload_fail_closed_then_revokes` |
//! | CRL reload: a lower cRLNumber is refused and audited (SEC-007) | `crl_rollback_refused_and_audited` |
//! | operator enrol/disable, refusals audited; disabled → 401 | `operator_commands_and_disabled_operator` |
//! | `audit verify` detects a modified record and an untrusted key | `audit_verify_detects_tampering` |
//! | audit unavailable → start refused (exit 1); content root not 0700 → refused (78) | `start_refusals` |
//! | local administrative commands only as root or the admin uid | `local_admin_rule` |

#[cfg(test)]
pub mod common;

#[cfg(test)]
mod serve {
    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use usgp_audit::{AuditChain, AuditRecord, verify_chain};
    use usgp_common::config::TrustPolicy;
    use usgp_crypto::test_pki::TestCert;
    use usgp_db::{MemoryStore, OperatorRole, SCHEMA_VERSION};
    use usgp_proto::DisplayName;
    use usgp_server::config::{LoadedConfig, load};
    use usgp_server::events::{self, LocalUser, local_admin};
    use usgp_server::operator::{self, Disabled, Enrolment, OperatorCmdError};
    use usgp_server::serve::{RunOptions, ServeError, prepare, run, shared_admin_uid_refusal};
    use usgp_server::{EXIT_CONFIG, EXIT_FAILURE, audit_cmd};

    use crate::common::{Fixture, admin_uid, https, json_str, set_mode};

    fn trust() -> TrustPolicy {
        TrustPolicy::with_admin(admin_uid())
    }

    fn opts() -> RunOptions {
        RunOptions {
            trust: trust(),
            allow_shared_admin_uid: true,
            service_uid: Some(admin_uid()),
        }
    }

    fn loaded(f: &Fixture) -> LoadedConfig {
        let path = f.write_config(&f.config_text(&f.unreachable_db()));
        load(&path, &trust()).unwrap()
    }

    struct Running {
        addr: SocketAddr,
        stop: oneshot::Sender<()>,
        task: JoinHandle<Result<(), ServeError>>,
    }

    impl Running {
        async fn stop(self) -> Result<(), ServeError> {
            let _ = self.stop.send(());
            self.task.await.unwrap()
        }
    }

    async fn start(f: &Fixture, store: &MemoryStore) -> Running {
        let l = loaded(f);
        let prepared = prepare(&l.config, &trust()).unwrap();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let store = store.clone();
        let task = tokio::spawn(async move {
            let shutdown = async move {
                let _ = stop_rx.await;
                "test"
            };
            run(
                store,
                &l,
                prepared,
                opts(),
                SCHEMA_VERSION,
                shutdown,
                Some(ready_tx),
            )
            .await
        });
        let addr = tokio::time::timeout(Duration::from_secs(20), ready_rx)
            .await
            .expect("server did not start")
            .expect("server stopped before serving")
            .api;
        Running {
            addr,
            stop: stop_tx,
            task,
        }
    }

    async fn enrol(
        f: &Fixture,
        store: &MemoryStore,
        cert: &TestCert,
        admin: bool,
    ) -> usgp_db::Operator {
        let chain = AuditChain::new("test-node").unwrap();
        events::ensure_genesis(store, &chain, &f.audit_pub.key_id())
            .await
            .unwrap();
        operator::enrol(
            store,
            &chain,
            &LocalUser { uid: admin_uid() },
            &Enrolment {
                cert: cert.peer_certificate().unwrap(),
                name: DisplayName::new("Operator One").unwrap(),
                role: admin.then_some(OperatorRole::Administrator),
            },
        )
        .await
        .unwrap()
    }

    fn events_of(records: &[AuditRecord]) -> Vec<&str> {
        records.iter().map(|r| r.event.as_str()).collect()
    }

    fn find<'a>(records: &'a [AuditRecord], event: &str) -> &'a AuditRecord {
        records
            .iter()
            .find(|r| r.event == event)
            .unwrap_or_else(|| panic!("no {event} in {:?}", events_of(records)))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn serves_and_stops_with_final_checkpoint() {
        let f = Fixture::new("serve-basic");
        let store = MemoryStore::new();
        enrol(&f, &store, &f.pki.client, true).await;
        let s = start(&f, &store).await;
        let addr = s.addr;
        assert!(addr.ip().is_loopback());

        // No certificate: 401 with the auth-scheme header, audited.
        let r = https(s.addr, &f.pki, None, "GET", "/v1/limits", None)
            .await
            .unwrap();
        assert_eq!(r.status, 401);
        assert!(
            r.head.contains("www-authenticate: usgp-client-cert"),
            "{}",
            r.head
        );
        // Enrolled administrator: the stated limit is the configured one.
        let r = https(
            s.addr,
            &f.pki,
            Some(&f.pki.client),
            "GET",
            "/v1/limits",
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(
            r.body.contains("\"max_upload_bytes\":1048576"),
            "{}",
            r.body
        );
        // An untrusted certificate fails the handshake (no HTTP).
        assert!(
            https(
                s.addr,
                &f.pki,
                Some(&f.pki.client_untrusted),
                "GET",
                "/v1/limits",
                None
            )
            .await
            .is_err()
        );

        s.stop().await.unwrap();
        let records = store.audit_records();
        let ev = events_of(&records);
        for e in [
            "audit.chain.genesis",
            "operator.enrolled",
            "server.start",
            "auth.unauthenticated",
            "api.limits.read",
            "auth.tls.failed",
            "server.stop",
        ] {
            assert!(ev.contains(&e), "{e} missing from {ev:?}");
        }
        let start = find(&records, "server.start");
        assert_eq!(start.interface, "system");
        assert!(start.detail.contains("config_sha256"), "{}", start.detail);
        assert!(start.detail.contains(&addr.to_string()), "{}", start.detail);
        assert!(start.detail.contains(&f.audit_pub.key_id().to_hex()));
        // The last record is the shutdown checkpoint, covering server.stop.
        let last = records.last().unwrap();
        assert_eq!(last.event, "audit.checkpoint");
        let stop = find(&records, "server.stop");
        assert!(
            stop.detail.contains("\"reason\":\"test\""),
            "{}",
            stop.detail
        );
        let cps = store.audit_checkpoints();
        assert!(cps.iter().any(|c| c.seq >= stop.seq), "{cps:?}");
        let report = verify_chain(&records, &cps, std::slice::from_ref(&f.audit_pub)).unwrap();
        assert!(report.is_intact(), "{report:?}");
        // Only the checkpoint's own record follows the checkpointed seq.
        assert_eq!(report.unsigned_tail, 1);
        assert_eq!(report.last_checkpoint_seq, Some(last.seq - 1));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn restart_marks_interrupted_upload_failed() {
        let f = Fixture::new("serve-restart");
        let store = MemoryStore::new();
        enrol(&f, &store, &f.pki.client, true).await;
        let s = start(&f, &store).await;
        let body = format!(
            r#"{{"kind":"image","display_name":"Interrupted","file_name":"x.wim","size":4096,"sha256":"{}"}}"#,
            "ab".repeat(32)
        );
        let r = https(
            s.addr,
            &f.pki,
            Some(&f.pki.client),
            "POST",
            "/v1/uploads",
            Some(&body),
        )
        .await
        .unwrap();
        assert_eq!(r.status, 201, "{}", r.body);
        let content_id = json_str(&r.body, "content_id").unwrap();
        s.stop().await.unwrap();

        // Restart on the same store: the session never got its body.
        let s = start(&f, &store).await;
        let r = https(
            s.addr,
            &f.pki,
            Some(&f.pki.client),
            "GET",
            &format!("/v1/images/{content_id}"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(r.body.contains("\"failed\""), "{}", r.body);
        assert!(r.body.contains("interrupted_by_restart"), "{}", r.body);
        s.stop().await.unwrap();
        let records = store.audit_records();
        let failed = records
            .iter()
            .find(|r| r.event == "content.failed")
            .expect("content.failed recorded");
        assert_eq!(failed.reason.as_deref(), Some("interrupted_by_restart"));
        assert_eq!(failed.target_id.as_deref(), Some(content_id.as_str()));
        assert!(failed.initiating_seq.is_some());
        let starts = records.iter().filter(|r| r.event == "server.start").count();
        assert_eq!(starts, 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn crl_reload_fail_closed_then_revokes() {
        // crl_reload_s = 1 in the fixture.
        let f = Fixture::new("serve-crl");
        let store = MemoryStore::new();
        enrol(&f, &store, &f.pki.client, true).await;
        let s = start(&f, &store).await;
        let get = || {
            https(
                s.addr,
                &f.pki,
                Some(&f.pki.client),
                "GET",
                "/v1/limits",
                None,
            )
        };
        assert_eq!(get().await.unwrap().status, 200);

        // An unreadable CRL: the reload fails, is recorded, and the
        // previous acceptor keeps serving.
        let crl1 = f.scratch.path("crl-1.der");
        let good = std::fs::read(&crl1).unwrap();
        std::fs::write(&crl1, b"not a crl").unwrap();
        wait_for(&store, "auth.tls.crl_reloaded", "failure").await;
        assert_eq!(get().await.unwrap().status, 200);

        // The intermediate now revokes the operator's certificate.
        let revoking = f
            .pki
            .intermediate
            .crl(
                &[f.pki.client_revoked.serial(), f.pki.client.serial()],
                false,
            )
            .unwrap();
        assert_ne!(revoking, good);
        std::fs::write(&crl1, &revoking).unwrap();
        wait_for(&store, "auth.tls.crl_reloaded", "success").await;
        assert!(get().await.is_err(), "revoked certificate still accepted");
        s.stop().await.unwrap();
        let records = store.audit_records();
        assert!(
            records
                .iter()
                .any(|r| r.event == "auth.tls.failed" && r.reason.as_deref() == Some("revoked")),
            "{:?}",
            events_of(&records)
        );
    }

    /// SEC-007: a reload that would take an issuer back to a lower
    /// cRLNumber (here: un-revoking the operator) is refused, audited with
    /// both numbers, and the newer CRL stays in force.
    #[tokio::test(flavor = "multi_thread")]
    async fn crl_rollback_refused_and_audited() {
        let f = Fixture::new("serve-crl-rollback");
        let store = MemoryStore::new();
        enrol(&f, &store, &f.pki.client, true).await;
        let s = start(&f, &store).await;
        let get = || {
            https(
                s.addr,
                &f.pki,
                Some(&f.pki.client),
                "GET",
                "/v1/limits",
                None,
            )
        };
        assert_eq!(get().await.unwrap().status, 200);
        let crl1 = f.scratch.path("crl-1.der");
        let revoking = f
            .pki
            .intermediate
            .crl_numbered(
                &[f.pki.client_revoked.serial(), f.pki.client.serial()],
                false,
                5,
            )
            .unwrap();
        std::fs::write(&crl1, &revoking).unwrap();
        wait_for(&store, "auth.tls.crl_reloaded", "success").await;
        assert!(get().await.is_err(), "revoked certificate still accepted");

        // An older CRL (number 2) that does not revoke the operator.
        let older = f
            .pki
            .intermediate
            .crl_numbered(&[f.pki.client_revoked.serial()], false, 2)
            .unwrap();
        std::fs::write(&crl1, &older).unwrap();
        wait_for(&store, "auth.tls.crl_reloaded", "failure").await;
        assert!(get().await.is_err(), "rollback must not un-revoke");
        s.stop().await.unwrap();
        let records = store.audit_records();
        let r = records
            .iter()
            .find(|r| {
                r.event == "auth.tls.crl_reloaded"
                    && r.reason.as_deref() == Some("crl_number_rollback")
            })
            .unwrap_or_else(|| panic!("{:?}", events_of(&records)));
        assert!(
            r.detail.contains("\"loaded_crl_number\":\"05\""),
            "{}",
            r.detail
        );
        assert!(
            r.detail.contains("\"offered_crl_number\":\"02\""),
            "{}",
            r.detail
        );
        assert!(r.detail.contains("usgp test operator ca"), "{}", r.detail);
    }

    async fn wait_for(store: &MemoryStore, event: &str, outcome: &str) {
        for _ in 0..100 {
            if store
                .audit_records()
                .iter()
                .any(|r| r.event == event && r.outcome == outcome)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("{event} ({outcome}) not recorded");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn operator_commands_and_disabled_operator() {
        let f = Fixture::new("serve-operators");
        let store = MemoryStore::new();
        let chain = AuditChain::new("test-node").unwrap();
        let who = LocalUser { uid: admin_uid() };
        let op = enrol(&f, &store, &f.pki.client, true).await;
        assert_eq!(
            op.cert_sha256,
            f.pki.client.peer_certificate().unwrap().sha256
        );
        // One certificate, one operator.
        let again = operator::enrol(
            &store,
            &chain,
            &who,
            &Enrolment {
                cert: f.pki.client.peer_certificate().unwrap(),
                name: DisplayName::new("Duplicate").unwrap(),
                role: None,
            },
        )
        .await;
        assert!(matches!(
            again,
            Err(OperatorCmdError::Refused("certificate_already_enrolled"))
        ));
        // SEC-006: a certificate without the TLS client purpose can never
        // log in, so it is refused (and recorded) at enrolment.
        let no_eku = operator::enrol(
            &store,
            &chain,
            &who,
            &Enrolment {
                cert: f.pki.client_no_eku.peer_certificate().unwrap(),
                name: DisplayName::new("No EKU").unwrap(),
                role: Some(usgp_db::OperatorRole::Administrator),
            },
        )
        .await;
        assert!(matches!(
            no_eku,
            Err(OperatorCmdError::Refused("certificate_eku"))
        ));
        assert!(store.audit_records().iter().any(|r| {
            r.event == "operator.enrol.refused" && r.reason.as_deref() == Some("certificate_eku")
        }));
        assert_eq!(
            operator::disable(&store, &chain, &who, op.id)
                .await
                .unwrap(),
            Disabled::Changed
        );
        assert_eq!(
            operator::disable(&store, &chain, &who, op.id)
                .await
                .unwrap(),
            Disabled::AlreadyDisabled
        );
        let unknown = usgp_proto::OperatorId::from_random_bytes([7; 16]);
        assert!(matches!(
            operator::disable(&store, &chain, &who, unknown).await,
            Err(OperatorCmdError::Refused("operator_not_found"))
        ));

        let s = start(&f, &store).await;
        let r = https(
            s.addr,
            &f.pki,
            Some(&f.pki.client),
            "GET",
            "/v1/limits",
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.status, 401);
        s.stop().await.unwrap();

        let records = store.audit_records();
        let enrolled = find(&records, "operator.enrolled");
        assert_eq!(enrolled.interface, "server-cli");
        assert_eq!(enrolled.actor_kind, "local_user");
        assert_eq!(enrolled.source.as_deref(), Some(who.source().as_str()));
        assert!(
            enrolled.detail.contains("administrator"),
            "{}",
            enrolled.detail
        );
        let refused = find(&records, "operator.enrol.refused");
        assert_eq!(
            refused.reason.as_deref(),
            Some("certificate_already_enrolled")
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| r.event == "operator.disabled")
                .count(),
            2
        );
        assert_eq!(
            find(&records, "operator.disable.refused").reason.as_deref(),
            Some("operator_not_found")
        );
        find(&records, "auth.operator_disabled");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn audit_verify_detects_tampering() {
        let f = Fixture::new("serve-verify");
        let store = MemoryStore::new();
        enrol(&f, &store, &f.pki.client, true).await;
        let s = start(&f, &store).await;
        https(
            s.addr,
            &f.pki,
            Some(&f.pki.client),
            "GET",
            "/v1/limits",
            None,
        )
        .await
        .unwrap();
        s.stop().await.unwrap();

        let trusted = [f.audit_pub.clone()];
        let report = audit_cmd::verify(&store, &trusted).await.unwrap();
        assert!(report.is_intact(), "{report:?}");
        assert_eq!(audit_cmd::exit_code(&report), 0);
        assert!(audit_cmd::render(&report).starts_with("audit chain: intact"));

        // The run is recorded.
        let chain = AuditChain::new("test-node").unwrap();
        let who = LocalUser { uid: admin_uid() };
        audit_cmd::record_result(&store, &chain, &who, &report, &trusted).await;
        let rec = store.audit_records();
        let v = rec.last().unwrap();
        assert_eq!(v.event, "audit.verify");
        assert_eq!(v.outcome, "success");
        assert_eq!(v.interface, "server-cli");

        // The content key is not trusted for checkpoints.
        let wrong = audit_cmd::verify(&store, std::slice::from_ref(&f.content_pub))
            .await
            .unwrap();
        assert_eq!(audit_cmd::exit_code(&wrong), EXIT_FAILURE);
        assert!(
            audit_cmd::render(&wrong).contains("checkpoint_untrusted_key"),
            "{}",
            audit_cmd::render(&wrong)
        );

        // An edited row (an attacker with database access).
        let target = find(&rec, "api.limits.read").seq;
        store.tamper_audit_for_test(|records, _, _| {
            let r = records.iter_mut().find(|r| r.seq == target).unwrap();
            r.outcome = "refused".to_owned();
        });
        let bad = audit_cmd::verify(&store, &trusted).await.unwrap();
        assert!(!bad.is_intact());
        assert_eq!(audit_cmd::exit_code(&bad), EXIT_FAILURE);
        let first = bad.first_finding().unwrap();
        assert_eq!(first.seq, target);
        assert_eq!(first.violation.as_str(), "record_hash_mismatch");
        let text = audit_cmd::render(&bad);
        assert!(text.starts_with("audit chain: TAMPERED"), "{text}");
        assert!(text.contains(&format!("finding: seq {target} rule record_hash_mismatch")));
        audit_cmd::record_result(&store, &chain, &who, &bad, &trusted).await;
        let v = store.audit_records().last().cloned().unwrap();
        assert_eq!(v.event, "audit.verify");
        assert_eq!(v.outcome, "failure");
        assert_eq!(v.reason.as_deref(), Some("chain_tampered"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn start_refusals() {
        // The audit chain cannot be written: no start (decision 0015).
        let f = Fixture::new("serve-refuse");
        let l = loaded(&f);
        let store = MemoryStore::new();
        store.set_fail_audit_writes(true);
        let r = run(
            store.clone(),
            &l,
            prepare(&l.config, &trust()).unwrap(),
            opts(),
            SCHEMA_VERSION,
            async { "test" },
            None,
        )
        .await;
        let e = r.unwrap_err();
        assert_eq!(e.exit_code(), EXIT_FAILURE);
        assert_eq!(e.reason(), "audit_unavailable");
        assert!(store.audit_records().is_empty());

        // The content root is group-readable: refused, and recorded.
        store.set_fail_audit_writes(false);
        set_mode(&f.scratch.path("content"), 0o750);
        let e = run(
            store.clone(),
            &l,
            prepare(&l.config, &trust()).unwrap(),
            opts(),
            SCHEMA_VERSION,
            async { "test" },
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(e.exit_code(), EXIT_CONFIG);
        assert_eq!(e.reason(), "content_root_mode_not_0700");
        let records = store.audit_records();
        let refused = find(&records, "server.start.refused");
        assert_eq!(
            refused.reason.as_deref(),
            Some("content_root_mode_not_0700")
        );
        assert!(!events_of(&records).contains(&"server.start"));
        set_mode(&f.scratch.path("content"), 0o700);

        // A service uid other than the content root's owner: refused.
        let other = RunOptions {
            service_uid: Some(admin_uid().wrapping_add(1)),
            ..opts()
        };
        let e = run(
            store.clone(),
            &l,
            prepare(&l.config, &trust()).unwrap(),
            other,
            SCHEMA_VERSION,
            async { "test" },
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(e.reason(), "content_root_not_owned_by_service");
    }

    #[test]
    fn local_admin_rule() {
        let p = TrustPolicy::with_admin(1000);
        // Root always; the config owner only if it is also trusted.
        assert_eq!(local_admin(&p, Some(0), Ok(0)).unwrap().uid, 0);
        assert_eq!(local_admin(&p, None, Ok(0)).unwrap().uid, 0);
        assert_eq!(local_admin(&p, Some(1000), Ok(1000)).unwrap().uid, 1000);
        // Decision 0016 item 3: `--admin-uid $(id -u)` alone is not
        // enough; the uid must own the configuration file.
        assert_eq!(
            local_admin(&p, Some(0), Ok(1000)).unwrap_err(),
            "not_local_admin"
        );
        assert_eq!(
            local_admin(&TrustPolicy::with_admin(1001), Some(0), Ok(1001)).unwrap_err(),
            "not_local_admin"
        );
        assert_eq!(
            local_admin(&p, None, Ok(1000)).unwrap_err(),
            "not_local_admin"
        );
        assert_eq!(
            local_admin(&p, Some(1001), Ok(1001)).unwrap_err(),
            "not_local_admin"
        );
        assert_eq!(
            local_admin(&TrustPolicy::root_only(), Some(1000), Ok(1000)).unwrap_err(),
            "not_local_admin"
        );
        assert_eq!(
            local_admin(&p, Some(1000), Err(std::io::Error::other("x"))).unwrap_err(),
            "uid_unknown"
        );
        // serve: the admin uid may not run the service unless allowed.
        assert_eq!(
            shared_admin_uid_refusal(Some(1000), &p, false),
            Some("service_uid_is_admin_uid")
        );
        assert_eq!(shared_admin_uid_refusal(Some(1000), &p, true), None);
        assert_eq!(shared_admin_uid_refusal(Some(999), &p, false), None);
        assert_eq!(
            shared_admin_uid_refusal(None, &p, false),
            Some("service_uid_unknown")
        );
        assert_eq!(
            shared_admin_uid_refusal(Some(0), &TrustPolicy::root_only(), false),
            None
        );
    }
}
