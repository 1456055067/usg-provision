//! The repository rules on the in-memory store (runs everywhere). The same
//! scenarios run against PostgreSQL in `repo_pg.rs` (CI).

#[cfg(test)]
pub mod common;

// Helpers and tests in one `cfg(test)` module so the workspace's
// test-only clippy allowances apply (same convention as usgp-audit).
#[cfg(test)]
mod t {
    use super::common;

    use common::m3;
    use common::{
        Audit, append, enrol, flow_atomic_with_audit, flow_chain_verifies, flow_content_lifecycle,
        flow_operator_rules, flow_package_lifecycle, flow_unaudited_change_refused, init_audit,
        operator,
    };
    use usgp_audit::{AuditRead, verify_store};
    use usgp_db::{DbError, MemoryStore, RepoTx, Store};
    use usgp_proto::JobId;
    use usgp_proto::device::SessionState;

    async fn setup() -> (MemoryStore, Audit) {
        let store = MemoryStore::new();
        let a = init_audit(&store).await;
        (store, a)
    }

    #[tokio::test]
    async fn unaudited_change_refused() {
        let (s, a) = setup().await;
        flow_unaudited_change_refused(&s, &a).await;
    }

    #[tokio::test]
    async fn change_and_record_are_atomic() {
        let (s, a) = setup().await;
        flow_atomic_with_audit(&s, &a).await;
    }

    #[tokio::test]
    async fn operator_rules() {
        let (s, a) = setup().await;
        flow_operator_rules(&s, &a).await;
    }

    #[tokio::test]
    async fn content_lifecycle() {
        let (s, a) = setup().await;
        flow_content_lifecycle(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn package_lifecycle() {
        let (s, a) = setup().await;
        flow_package_lifecycle(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn whole_flow_chain_verifies() {
        let (s, a) = setup().await;
        flow_atomic_with_audit(&s, &a).await;
        flow_content_lifecycle(&s, &s, &a).await;
        flow_package_lifecycle(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    /// REQ-AUD-006 / decision 0015 item 1: an audit write failure refuses the
    /// action and changes nothing.
    #[tokio::test]
    async fn audit_failure_refuses_and_changes_nothing() {
        let (s, a) = setup().await;
        let head = s.head().await.unwrap();
        let op = operator("not recorded");
        s.fail_next_audit_writes(1);
        let mut tx = s.begin().await.unwrap();
        tx.insert_operator(&op).await.unwrap();
        let err = a
            .chain
            .append(
                &mut tx,
                &common::draft("operator.enrolled", "operator", "x"),
            )
            .await;
        assert!(err.is_err());
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
        assert_eq!(s.head().await.unwrap(), head);
        let mut tx = s.begin().await.unwrap();
        assert!(tx.operator(op.id).await.unwrap().is_none());
        tx.rollback().await;

        // Persistent failure: every attempt refused.
        s.set_fail_audit_writes(true);
        for _ in 0..3 {
            let mut tx = s.begin().await.unwrap();
            tx.insert_operator(&op).await.unwrap();
            assert!(
                a.chain
                    .append(
                        &mut tx,
                        &common::draft("operator.enrolled", "operator", "x")
                    )
                    .await
                    .is_err()
            );
            drop(tx);
        }
        s.set_fail_audit_writes(false);
        let op = enrol(&s, &a, "recorded").await;
        let mut tx = s.begin().await.unwrap();
        assert!(tx.operator(op.id).await.unwrap().is_some());
        tx.rollback().await;
    }

    /// A tampered record is detected by the verifier over the store.
    #[tokio::test]
    async fn tampering_detected() {
        let (s, a) = setup().await;
        let op = enrol(&s, &a, "someone").await;
        let mut tx = s.begin().await.unwrap();
        append(
            &a,
            &mut tx,
            "operator.disabled",
            "operator",
            &op.id.to_string(),
        )
        .await;
        tx.commit().await.unwrap();
        flow_chain_verifies(&s, &a).await;
        s.tamper_audit_for_test(|records, _, _| {
            if let Some(r) = records.get_mut(1) {
                r.detail = "{\"test\":\"2\"}".into();
            }
        });
        let report = verify_store(&s, std::slice::from_ref(&a.public), 100)
            .await
            .unwrap();
        assert!(!report.is_intact());
        assert_eq!(report.first_finding().unwrap().seq, 2);
    }

    /// Records must extend the head, as the 0001 trigger enforces.
    #[tokio::test]
    async fn record_not_extending_head_refused() {
        let (s, a) = setup().await;
        let mut tx = s.begin().await.unwrap();
        let rec = a
            .chain
            .append(
                &mut tx,
                &common::draft("operator.enrolled", "operator", "y"),
            )
            .await
            .unwrap();
        // Re-inserting the same seq does not extend the new head.
        assert!(
            usgp_audit::AuditTx::insert_record(&mut tx, &rec)
                .await
                .is_err()
        );
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
    }

    // ------------------------------------------------- M3 (migration 0004)

    #[tokio::test]
    async fn m3_boot_services() {
        let (s, a) = setup().await;
        m3::flow_boot_services(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_codes() {
        let (s, a) = setup().await;
        m3::flow_codes(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_sessions() {
        let (s, a) = setup().await;
        m3::flow_sessions(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_session_scopes_and_idle() {
        let (s, a) = setup().await;
        m3::flow_session_scopes_and_idle(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_job_timeouts_checked() {
        let (s, a) = setup().await;
        m3::flow_job_timeouts_checked(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_raise_generation() {
        let (s, a) = setup().await;
        m3::flow_raise_generation(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_expiry_is_audited() {
        let (s, a) = setup().await;
        m3::flow_expiry_is_audited(&s, &a).await;
    }

    #[tokio::test]
    async fn m3_job_success() {
        let (s, a) = setup().await;
        m3::flow_job_success(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_job_failure() {
        let (s, a) = setup().await;
        m3::flow_job_failure(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_wipe_guard() {
        let (s, a) = setup().await;
        m3::flow_wipe_guard(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m3_whole_flow_chain_verifies() {
        let (s, a) = setup().await;
        m3::flow_boot_services(&s, &s, &a).await;
        m3::flow_codes(&s, &s, &a).await;
        m3::flow_job_success(&s, &s, &a).await;
        m3::flow_wipe_guard(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    /// Acceptance criterion 3 (brief): when `disk.wipe.authorised` cannot
    /// be written, the confirm transaction fails, no job exists, the
    /// session is still authorised, and the chain head has not moved; once
    /// the audit store recovers, the same confirmation succeeds.
    #[tokio::test]
    async fn wipe_record_failure_creates_no_job() {
        let (s, a) = setup().await;
        let op = enrol(&s, &a, "wipe fault").await;
        let bs = m3::enrol_boot_service(&s, &a, "relay fault").await;
        let p = m3::ready_package(&s, &a, &op).await;
        let session = m3::ready_session(&s, &a, &op, bs.id, &p, m3::macs(1)).await;
        let head = s.head().await.unwrap();

        s.fail_audit_on(m3::WIPE_EVENT);
        let id = JobId::from_random_bytes(common::rand_bytes());
        let mut tx = s.begin().await.unwrap();
        // job.created is still written ...
        append(&a, &mut tx, "job.created", "job", &id.to_string()).await;
        // ... the wipe record is not.
        assert!(a.chain.append(&mut tx, &m3::wipe_draft(id)).await.is_err());
        // The transaction is dead: no job, no plan.
        assert!(matches!(tx.lock_job(id).await, Err(DbError::TxFailed)));
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
        assert_eq!(s.head().await.unwrap(), head);
        let mut tx = s.begin().await.unwrap();
        assert!(tx.job_by_session(session.id).await.unwrap().is_none());
        assert_eq!(
            tx.device_session(session.id).await.unwrap().unwrap().state,
            SessionState::Authorised
        );
        tx.rollback().await;
        // The helper sees the same refusal.
        assert!(m3::confirm(&s, &a, &session, bs.id, &p).await.is_err());

        // Other events are unaffected; the fault is per event.
        let other = m3::open_session(&s, &a, None, m3::macs(1)).await;
        let mut tx = s.begin().await.unwrap();
        assert!(tx.device_session(other.id).await.unwrap().is_some());
        tx.rollback().await;

        s.clear_audit_faults();
        let job = m3::confirm(&s, &a, &session, bs.id, &p).await.unwrap();
        let mut tx = s.begin().await.unwrap();
        let j = tx.job(job).await.unwrap().unwrap();
        let rec = s
            .audit_records()
            .into_iter()
            .find(|r| r.seq == j.wipe_audit_seq)
            .unwrap();
        assert_eq!(rec.event, m3::WIPE_EVENT);
        assert_eq!(rec.record_hash, j.wipe_record_hash);
        assert_eq!(rec.target_id.as_deref(), Some(job.to_string().as_str()));
        tx.rollback().await;
    }

    /// Transactions are serialised: a second `begin` waits for the first.
    #[tokio::test]
    async fn transactions_are_serialised() {
        let (s, a) = setup().await;
        let tx1 = s.begin().await.unwrap();
        let s2 = s.clone();
        let waiter = tokio::spawn(async move { s2.begin().await.map(|_| ()) });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        drop(tx1);
        waiter.await.unwrap().unwrap();
        // Still usable afterwards.
        enrol(&s, &a, "after").await;
    }
    // ------------------------------------------------ M4 (migration 0005)

    #[tokio::test]
    async fn m4_archive_content() {
        let (s, a) = setup().await;
        common::m4::flow_archive_content(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    #[tokio::test]
    async fn m4_driver_archives() {
        let (s, a) = setup().await;
        common::m4::flow_driver_archives(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    #[tokio::test]
    async fn m4_agent_packages_and_config() {
        let (s, a) = setup().await;
        common::m4::flow_agent_packages_and_config(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    #[tokio::test]
    async fn m4_device_values() {
        let (s, a) = setup().await;
        common::m4::flow_device_values(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m4_job_v2() {
        let (s, a) = setup().await;
        common::m4::flow_job_v2(&s, &s, &a).await;
        flow_chain_verifies(&s, &a).await;
    }

    #[tokio::test]
    async fn m4_job_v2_failure() {
        let (s, a) = setup().await;
        common::m4::flow_job_v2_failure(&s, &s, &a).await;
    }

    #[tokio::test]
    async fn m4_job_v2_guards() {
        let (s, a) = setup().await;
        common::m4::flow_job_v2_guards(&s, &s, &a).await;
    }

    /// AU-5 / REQ-AUD-006 on the memory store: an escrow whose
    /// `escrow.received` record cannot be written is not stored.
    #[tokio::test]
    async fn m4_escrow_needs_its_record() {
        let (s, a) = setup().await;
        let op = enrol(&s, &a, "m4-au5").await;
        let bs = m3::enrol_boot_service(&s, &a, "m4-au5-relay").await.id;
        let p = m3::ready_package(&s, &a, &op).await;
        let sess = m3::ready_session(&s, &a, &op, bs, &p, m3::macs(1)).await;
        let job = common::m4::confirm_v2(&s, &a, &sess, bs, &p).await;
        s.fail_audit_on("escrow.received");
        let mut tx = s.begin().await.unwrap();
        tx.insert_escrow(&usgp_db::NewEscrow {
            job_id: job,
            account: usgp_proto::EscrowAccount::Administrator,
            key_id: common::digest(),
            sealed: common::m4::sealed(40),
            received_at: common::now(),
        })
        .await
        .unwrap();
        assert!(
            a.chain
                .append(
                    &mut tx,
                    &common::draft("escrow.received", "job", &job.to_string())
                )
                .await
                .is_err()
        );
        assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));
        s.clear_audit_faults();
        let mut tx = s.begin().await.unwrap();
        assert!(tx.escrow(job).await.unwrap().is_none());
        tx.rollback().await;
    }
}
