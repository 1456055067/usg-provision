//! QA gap test (M2, exit criterion 3; REQ-AUD-005): the `audit verify`
//! command logic (`usgp_server::audit_cmd`) reports a deleted, a
//! reordered (contents swapped, seq kept, as rows come back ordered by
//! seq) and an inserted record as tampered with exit status 1, naming
//! the first bad seq. Modification is covered by
//! `serve.rs::audit_verify_detects_tampering`; the library-level rules by
//! `crates/usgp-audit/tests/audit/chain_tamper.rs`.

#[cfg(test)]
mod qa_audit_verify {
    use usgp_audit::{
        Actor, AuditChain, AuditDraft, AuditRecord, ChainHead, Interface, Outcome, seal,
    };
    use usgp_crypto::SigningKey;
    use usgp_db::{MemoryStore, RepoTx, Store};
    use usgp_server::{EXIT_FAILURE, audit_cmd};

    fn draft(n: u32) -> AuditDraft {
        AuditDraft::new(
            "package.created",
            Outcome::Success,
            Actor::operator("op-1", "Admin One"),
            Interface::Api,
        )
        .source("127.0.0.1:1")
        .target("package", &format!("p-{n}"))
    }

    /// Genesis plus 9 records (seq 1..=10).
    async fn chain() -> (MemoryStore, SigningKey) {
        let store = MemoryStore::new();
        let key = SigningKey::generate().unwrap();
        let chain = AuditChain::new("ctl-01").unwrap();
        let mut tx = store.begin().await.unwrap();
        chain.ensure_genesis(&mut tx, &key.key_id()).await.unwrap();
        tx.commit().await.unwrap();
        for n in 0..9 {
            let mut tx = store.begin().await.unwrap();
            chain.append(&mut tx, &draft(n)).await.unwrap();
            tx.commit().await.unwrap();
        }
        assert_eq!(store.audit_records().len(), 10);
        (store, key)
    }

    async fn verdict(store: &MemoryStore, key: &SigningKey) -> (u8, u64, String) {
        let rep = audit_cmd::verify(store, std::slice::from_ref(key.verifying_key()))
            .await
            .unwrap();
        let text = audit_cmd::render(&rep);
        let seq = rep.first_finding().map_or(0, |f| f.seq);
        (audit_cmd::exit_code(&rep), seq, text)
    }

    #[tokio::test]
    async fn intact_chain_exit_0() {
        let (store, key) = chain().await;
        let (code, _, text) = verdict(&store, &key).await;
        assert_eq!(code, 0, "{text}");
        assert!(text.starts_with("audit chain: intact"));
    }

    #[tokio::test]
    async fn deleted_record_exit_1() {
        let (store, key) = chain().await;
        store.tamper_audit_for_test(|r, _, _| r.retain(|x| x.seq != 5));
        let (code, seq, text) = verdict(&store, &key).await;
        assert_eq!(code, EXIT_FAILURE, "{text}");
        assert_eq!(code, 1);
        assert_eq!(seq, 6, "{text}");
        assert!(text.starts_with("audit chain: TAMPERED"));
    }

    #[tokio::test]
    async fn reordered_record_contents_exit_1() {
        let (store, key) = chain().await;
        store.tamper_audit_for_test(|r, _, _| {
            let a = r.iter().position(|x| x.seq == 5).unwrap();
            let b = r.iter().position(|x| x.seq == 6).unwrap();
            let (ra, rb) = (r[a].clone(), r[b].clone());
            r[a] = AuditRecord { seq: 5, ..rb };
            r[b] = AuditRecord { seq: 6, ..ra };
        });
        let (code, seq, text) = verdict(&store, &key).await;
        assert_eq!(code, 1, "{text}");
        assert_eq!(seq, 5, "{text}");
    }

    #[tokio::test]
    async fn inserted_record_exit_1() {
        let (store, key) = chain().await;
        store.tamper_audit_for_test(|r, _, head| {
            let i4 = r.iter().position(|x| x.seq == 4).unwrap();
            // Well-formed and chained onto seq 4 by someone without the
            // audit key; every later record renumbered, head moved on.
            let forged = seal(Some(&ChainHead::from(&r[i4])), &draft(99), 1, "ctl-01").unwrap();
            r.insert(i4 + 1, forged);
            for x in r.iter_mut().skip(i4 + 2) {
                x.seq += 1;
            }
            *head = Some(ChainHead::from(r.last().unwrap()));
        });
        let (code, seq, text) = verdict(&store, &key).await;
        assert_eq!(code, 1, "{text}");
        assert_eq!(seq, 6, "{text}");
    }

    #[tokio::test]
    async fn modified_detail_exit_1() {
        let (store, key) = chain().await;
        store.tamper_audit_for_test(|r, _, _| {
            let x = r.iter_mut().find(|x| x.seq == 7).unwrap();
            x.target_id = Some("p-other".to_owned());
        });
        let (code, seq, text) = verdict(&store, &key).await;
        assert_eq!(code, 1, "{text}");
        assert_eq!(seq, 7, "{text}");
        assert!(text.contains("record_hash_mismatch"), "{text}");
    }
}
