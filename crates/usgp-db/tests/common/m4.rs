//! M4 fixtures and store-generic scenarios (migration 0005): archive
//! content with v2 manifests, driver archives and package driver lists,
//! agent signers and packages, package configuration, device values, the
//! nine-step job, resume nonces and tokens, and the escrow. The same
//! scenarios run on the in-memory store (`memory_repo.rs`) and on
//! PostgreSQL (`repo_pg.rs`, CI).

use std::collections::BTreeMap;

use usgp_common::Sha256Digest;
use usgp_crypto::{KeyId, SigningKey};
use usgp_db::{AGENT_PACKAGE_REFUSED, MAX_LIVE_RESUME_NONCES, NonceIssue, SIGNER_REVOKED};
use usgp_db::{
    AdminPasswordMode, AgentPackageStatus, AgentSigner, AgentSignerId, ArchiveContent,
    ChosenPackage, DbError, DeviceValues, DriverArchiveStatus, EscrowState, JobTimeoutsV2,
    NewAgentPackage, NewArchiveContent, NewDeviceSession, NewDriverArchive, NewEscrow, NewJobV2,
    NewResumeNonce, NewResumeToken, Operator, Package, PackageConfig, PackageValues,
    ReadyArchiveContent, RepoTx, SealedPassword, Store, StoredManifest, Upload,
};
use usgp_proto::content_manifest::SCHEMA_V2;
use usgp_proto::device::SessionState;
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::progress::FailureCategory;
use usgp_proto::{
    AgentPackageId, AgentPackageManifestV1, ArchiveFormat, ArchiveSummaryV1, BootServiceId,
    ContentId, ContentKind, ContentKindV2, ContentManifestV2, ContentState, DisplayName,
    DriverArchiveId, EditionIndex, ErrorCode, EscrowAccount, FailureV2, FileName, JobId, JobState,
    OperatorId, P384Spki, PackageId, RelPath, StepState, StepV2, Tag, UnixMicros, UploadId,
    UploadState,
};

use super::m3::{disk, enrol_boot_service, later, macs, ready_package, ready_session, wipe_draft};
use super::{Audit, append, digest, enrol, new_upload, now, rand_bytes};

/// A fresh P-384 SPKI DER and its key id (SHA-256 of the DER).
pub fn spki() -> (P384Spki, Sha256Digest) {
    let key = SigningKey::generate().unwrap();
    let der = key.verifying_key().spki_der().to_vec();
    let spki = P384Spki::from_der(&der).unwrap();
    (spki, usgp_crypto::sha256(&der))
}

/// A new archive upload of `kind`.
pub fn new_archive_upload(by: OperatorId, kind: ContentKindV2) -> (NewArchiveContent, Upload) {
    let id = ContentId::from_random_bytes(rand_bytes());
    let at = now();
    let sha = digest();
    let c = NewArchiveContent {
        id,
        kind,
        display_name: DisplayName::new("NIC drivers").unwrap(),
        file_name: FileName::new("drivers.zip").unwrap(),
        size: 4096,
        sha256: sha,
        created_by: by,
        initiating_audit_seq: None,
        created_at: at,
    };
    let u = Upload {
        id: UploadId::from_random_bytes(rand_bytes()),
        content_id: id,
        operator_id: by,
        declared_size: 4096,
        declared_sha256: sha,
        state: UploadState::Open,
        staging_name: format!("staging-{}", Sha256Digest(rand_bytes()).to_hex()),
        created_at: at,
        expires_at: later(at, 86_400),
    };
    (c, u)
}

/// The signed v2 manifest of an archive item (the signature is a stand-in;
/// the repository stores bytes and checks the payload against the row).
pub fn archive_manifest(
    c: &NewArchiveContent,
    infs: &[&str],
    at: UnixMicros,
) -> ReadyArchiveContent {
    let m = ContentManifestV2 {
        schema: SCHEMA_V2,
        kind: c.kind,
        content_id: c.id,
        display_name: c.display_name.clone(),
        file_name: c.file_name.clone(),
        size: c.size,
        sha256: c.sha256,
        chunk_size: CHUNK_SIZE,
        chunk_sha256: vec![c.sha256],
        archive: ArchiveSummaryV1 {
            format: ArchiveFormat::Zip,
            entries: 7,
            expanded_bytes: 9000,
            infs: infs.iter().map(|p| RelPath::new(*p).unwrap()).collect(),
        },
        ready_at: at,
        key_id: Sha256Digest([4; 32]),
    };
    ReadyArchiveContent {
        manifest: StoredManifest {
            payload: m.to_payload().unwrap(),
            signature: vec![0x30, 0x02, 0x01, 0x01],
            key_id: KeyId(Sha256Digest([4; 32])),
        },
        at,
    }
}

/// Uploads an archive item and takes it to Ready with a v2 manifest
/// listing `infs`.
pub async fn ready_archive<S: Store>(
    store: &S,
    a: &Audit,
    by: OperatorId,
    kind: ContentKindV2,
    infs: &[&str],
) -> ArchiveContent {
    let (c, u) = new_archive_upload(by, kind);
    let mut tx = store.begin().await.unwrap();
    let seq = append(
        a,
        &mut tx,
        "content.upload.created",
        "content",
        &c.id.to_string(),
    )
    .await;
    let c = NewArchiveContent {
        initiating_audit_seq: Some(seq),
        ..c
    };
    tx.create_archive_upload(&c, &u).await.unwrap();
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    tx.set_content_state(
        c.id,
        &[ContentState::Receiving],
        ContentState::Checking,
        None,
        now(),
    )
    .await
    .unwrap();
    append(
        a,
        &mut tx,
        "content.upload.received",
        "content",
        &c.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    tx.set_archive_content_ready(c.id, &archive_manifest(&c, infs, now()))
        .await
        .unwrap();
    append(a, &mut tx, "content.ready", "content", &c.id.to_string()).await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let got = tx.archive_content(c.id).await.unwrap().unwrap();
    tx.commit().await.unwrap();
    got
}

/// A minimal valid `agent.json`.
pub fn agent_json() -> AgentPackageManifestV1 {
    AgentPackageManifestV1::from_json(br#"{"installer":"setup/agent.msi","args":["/l*v","x.log"]}"#)
        .unwrap()
}

/// Commits `tx` with one audit record.
async fn audited<T: RepoTx>(a: &Audit, mut tx: T, event: &str, kind: &str, id: &str) {
    append(a, &mut tx, event, kind, id).await;
    tx.commit().await.unwrap();
}

/// An agent signer registered by `op`.
pub async fn register_signer<S: Store>(store: &S, a: &Audit, op: &Operator) -> AgentSigner {
    let (spki, key_id) = spki();
    let s = AgentSigner {
        id: AgentSignerId::from_random_bytes(rand_bytes()),
        spki,
        key_id,
        name: DisplayName::new("Agent build key").unwrap(),
        added_by: op.id,
        added_at: now(),
        revoked: None,
    };
    let mut tx = store.begin().await.unwrap();
    tx.insert_agent_signer(&s).await.unwrap();
    audited(
        a,
        tx,
        "agent_signer.added",
        "agent_signer",
        &s.id.to_string(),
    )
    .await;
    s
}

/// A Ready agent package signed by `signer`.
pub async fn ready_agent_package<S: Store>(
    store: &S,
    a: &Audit,
    op: &Operator,
    signer: &AgentSigner,
) -> AgentPackageId {
    let c = ready_archive(store, a, op.id, ContentKindV2::AgentPackage, &[]).await;
    let id = AgentPackageId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    tx.insert_agent_package(&NewAgentPackage {
        id,
        content_id: c.id,
        created_by: op.id,
        created_at: now(),
    })
    .await
    .unwrap();
    tx.set_agent_package_ready(id, signer.id, &agent_json(), now())
        .await
        .unwrap();
    audited(
        a,
        tx,
        "agent_package.ready",
        "agent_package",
        &id.to_string(),
    )
    .await;
    id
}

/// A stand-in answer-file template.
pub const ANSWER: &[u8] = b"<unattend xmlns=\"urn:schemas-microsoft-com:unattend\"/>";

/// A package configuration for `p`.
pub fn config(p: &Package, agent: AgentPackageId, by: OperatorId) -> PackageConfig {
    PackageConfig {
        package_id: p.id,
        answer_template: ANSWER.to_vec(),
        answer_sha256: usgp_crypto::sha256(ANSWER),
        values: PackageValues {
            computer_name: Some("WS-01".to_owned()),
            time_zone: Some("Pacific Standard Time".to_owned()),
            domain: None,
            machine_ou: Some("OU=Lab,DC=example,DC=org".to_owned()),
        },
        tags: vec![Tag::new("site:hq").unwrap(), Tag::new("ring-1").unwrap()],
        agent_package_id: agent,
        admin_password: AdminPasswordMode::GenerateAndEscrow,
        updated_by: by,
        updated_at: now(),
    }
}

/// The v2 plan timeouts the test jobs carry.
pub const TIMEOUTS_V2: JobTimeoutsV2 = JobTimeoutsV2 {
    steps_s: [21_600, 1800, 21_600, 7200, 1800, 3600, 14_400, 10_800, 1800],
    stall_s: 1800,
};

/// A v2 job for a ready session.
pub fn new_job_v2(
    s: &NewDeviceSession,
    bs: BootServiceId,
    p: &Package,
    id: JobId,
    wipe: &usgp_audit::AuditRecord,
) -> NewJobV2 {
    let (job_key_spki, job_key_id) = spki();
    NewJobV2 {
        id,
        session_id: s.id,
        boot_service_id: bs,
        package: ChosenPackage {
            id: p.id,
            revision: p.revision,
        },
        image_content_id: p.image_id,
        edition_index: EditionIndex::new(u64::from(p.edition_index)).unwrap(),
        disk: disk(),
        macs: s.macs.clone(),
        previous_job_id: None,
        wipe_audit_seq: wipe.seq,
        wipe_record_hash: wipe.record_hash,
        plan_sha256: digest(),
        plan_key_id: KeyId(Sha256Digest([5; 32])),
        timeouts: TIMEOUTS_V2,
        bytes_total: Some(4096),
        started_at: now(),
        job_key_spki,
        job_key_id,
        rendered_answer_sha256: digest(),
        tags: vec![Tag::new("site:hq").unwrap()],
    }
}

/// Confirms a v2 job (job, `job.created`, `disk.wipe.authorised`, session
/// confirmed, together).
pub async fn confirm_v2<S: Store>(
    store: &S,
    a: &Audit,
    s: &NewDeviceSession,
    bs: BootServiceId,
    p: &Package,
) -> JobId {
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    append(a, &mut tx, "job.created", "job", &id.to_string()).await;
    let wipe = a.chain.append(&mut tx, &wipe_draft(id)).await.unwrap();
    tx.insert_job_v2(&new_job_v2(s, bs, p, id, &wipe))
        .await
        .unwrap();
    tx.set_device_session_state(
        s.id,
        &[SessionState::Authorised],
        SessionState::Confirmed,
        None,
        now(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    id
}

/// A sealed password of `ct_len` ciphertext bytes (stand-in bytes).
pub fn sealed(ct_len: usize) -> SealedPassword {
    let mut eph_pub = [0x11u8; 97];
    eph_pub[0] = 0x04;
    SealedPassword {
        eph_pub,
        nonce: [7; 12],
        ciphertext: vec![0xAB; ct_len],
    }
}

/// Runs step `n` from pending to done.
async fn run_step<S: Store>(store: &S, a: &Audit, job: JobId, step: StepV2) {
    let mut tx = store.begin().await.unwrap();
    if step != StepV2::VERIFY_CONTENT {
        tx.set_job_step_v2(job, step, StepState::Running, now())
            .await
            .unwrap();
    }
    tx.set_job_step_v2(job, step, StepState::Done, now())
        .await
        .unwrap();
    audited(a, tx, "job.step.completed", "job", &job.to_string()).await;
}

// --------------------------------------------------------------- flows --

/// Archive content: v2 manifests stored and checked against the row; the
/// M2 readers never see archive kinds; one live item per digest across
/// kinds.
pub async fn flow_archive_content<S: Store>(store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-content").await;
    let c = ready_archive(
        store,
        a,
        op.id,
        ContentKindV2::DriverArchive,
        &["net/e1d.inf"],
    )
    .await;
    assert_eq!(c.state, ContentState::Ready);
    let facts = c.archive.unwrap();
    assert_eq!(facts.format, ArchiveFormat::Zip);
    assert_eq!((facts.entries, facts.expanded_bytes), (7, 9000));

    let mut tx = store.begin().await.unwrap();
    assert!(tx.content(c.id).await.unwrap().is_none());
    assert!(tx.content_by_sha256(&c.sha256).await.unwrap().is_none());
    assert_eq!(
        tx.archive_content_by_sha256(&c.sha256)
            .await
            .unwrap()
            .unwrap()
            .id,
        c.id
    );
    assert!(
        tx.list_content(None, &[])
            .await
            .unwrap()
            .iter()
            .all(|x| x.id != c.id)
    );
    let listed = tx
        .list_archive_content(Some(ContentKindV2::DriverArchive), &[ContentState::Ready])
        .await
        .unwrap();
    assert!(listed.iter().any(|x| x.id == c.id));
    assert!(
        tx.list_archive_content(Some(ContentKindV2::AgentPackage), &[])
            .await
            .unwrap()
            .iter()
            .all(|x| x.id != c.id)
    );
    tx.commit().await.unwrap();

    // One live item per digest, across kinds.
    let (img, u) = new_upload(op.id, ContentKind::Image, c.sha256);
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.create_upload(&img, &u).await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    // A manifest that does not describe the row is refused.
    let (n, u) = new_archive_upload(op.id, ContentKindV2::DriverArchive);
    let mut tx = store.begin().await.unwrap();
    tx.create_archive_upload(&n, &u).await.unwrap();
    tx.set_content_state(
        n.id,
        &[ContentState::Receiving],
        ContentState::Checking,
        None,
        now(),
    )
    .await
    .unwrap();
    let mut other = n.clone();
    other.kind = ContentKindV2::AgentPackage;
    assert!(matches!(
        tx.set_archive_content_ready(n.id, &archive_manifest(&other, &[], now()))
            .await,
        Err(DbError::InvalidArgument { .. })
    ));
    let mut other = n.clone();
    other.size = 4097;
    assert!(matches!(
        tx.set_archive_content_ready(n.id, &archive_manifest(&other, &["a.inf"], now()))
            .await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.set_archive_content_ready(n.id, &archive_manifest(&n, &["a.inf"], now()))
        .await
        .unwrap();
    // Ready only once.
    assert!(matches!(
        tx.set_archive_content_ready(n.id, &archive_manifest(&n, &["a.inf"], now()))
            .await,
        Err(DbError::Conflict { .. })
    ));
    audited(a, tx, "content.ready", "content", &n.id.to_string()).await;
}

/// Driver archives: ready from the manifest, refusal, replacement keeps
/// the id, ordered package lists, deletion rules.
pub async fn flow_driver_archives<S: Store>(store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-drivers").await;
    let p = ready_package(store, a, &op).await;
    let c1 = ready_archive(
        store,
        a,
        op.id,
        ContentKindV2::DriverArchive,
        &["net/e1d.inf", "storage/iastor.inf"],
    )
    .await;
    let id = DriverArchiveId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    tx.insert_driver_archive(&NewDriverArchive {
        id,
        content_id: c1.id,
        name: DisplayName::new("Lab NIC").unwrap(),
        created_by: op.id,
        created_at: now(),
    })
    .await
    .unwrap();
    let d = tx.driver_archive(id).await.unwrap().unwrap();
    assert_eq!(d.status, DriverArchiveStatus::Checking);
    assert!(d.infs.is_empty() && d.format.is_none());
    tx.set_driver_archive_ready(id, now()).await.unwrap();
    audited(a, tx, "driver.ready", "driver_archive", &id.to_string()).await;

    let mut tx = store.begin().await.unwrap();
    let d = tx.driver_archive(id).await.unwrap().unwrap();
    assert_eq!(d.status, DriverArchiveStatus::Ready);
    assert_eq!(d.format, Some(ArchiveFormat::Zip));
    assert_eq!(d.expanded_bytes, Some(9000));
    let infs: Vec<&str> = d.infs.iter().map(RelPath::as_str).collect();
    assert_eq!(infs, ["net/e1d.inf", "storage/iastor.inf"]);
    tx.commit().await.unwrap();

    // Agent-package content cannot back a driver archive.
    let ac = ready_archive(store, a, op.id, ContentKindV2::AgentPackage, &[]).await;
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.insert_driver_archive(&NewDriverArchive {
            id: DriverArchiveId::from_random_bytes(rand_bytes()),
            content_id: ac.id,
            name: DisplayName::new("wrong kind").unwrap(),
            created_by: op.id,
            created_at: now(),
        })
        .await,
        Err(DbError::Constraint { .. })
    ));
    tx.rollback().await;

    // Replacement keeps the id and restarts the check (REQ-DRV-003).
    let c2 = ready_archive(
        store,
        a,
        op.id,
        ContentKindV2::DriverArchive,
        &["v2/e1d.inf"],
    )
    .await;
    let mut tx = store.begin().await.unwrap();
    tx.replace_driver_archive(id, c2.id, now()).await.unwrap();
    let d = tx.driver_archive(id).await.unwrap().unwrap();
    assert_eq!(d.status, DriverArchiveStatus::Checking);
    assert_eq!(d.content_id, c2.id);
    assert!(d.infs.is_empty() && d.replaced_at.is_some());
    // Only once per check.
    assert!(matches!(
        tx.replace_driver_archive(id, c1.id, now()).await,
        Err(DbError::Conflict { .. })
    ));
    tx.set_driver_archive_ready(id, now()).await.unwrap();
    audited(a, tx, "driver.replaced", "driver_archive", &id.to_string()).await;

    // U-4: the old file is superseded: still readable (served to packages
    // that pin it), never attached again.
    let mut tx = store.begin().await.unwrap();
    let old = tx.archive_content(c1.id).await.unwrap().unwrap();
    assert!(old.superseded_at.is_some() && old.state == ContentState::Ready);
    assert!(
        tx.archive_content(c2.id)
            .await
            .unwrap()
            .unwrap()
            .superseded_at
            .is_none()
    );
    assert!(matches!(
        tx.insert_driver_archive(&NewDriverArchive {
            id: DriverArchiveId::from_random_bytes(rand_bytes()),
            content_id: c1.id,
            name: DisplayName::new("reattach").unwrap(),
            created_by: op.id,
            created_at: now(),
        })
        .await,
        Err(DbError::Constraint { .. })
    ));
    tx.rollback().await;

    // A refused archive.
    let c3 = ready_archive(store, a, op.id, ContentKindV2::DriverArchive, &["x.inf"]).await;
    let refused = DriverArchiveId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    tx.insert_driver_archive(&NewDriverArchive {
        id: refused,
        content_id: c3.id,
        name: DisplayName::new("LZX cab").unwrap(),
        created_by: op.id,
        created_at: now(),
    })
    .await
    .unwrap();
    let why = ErrorCode::new("archive_refused:cab_lzx").unwrap();
    tx.refuse_driver_archive(refused, &why, now())
        .await
        .unwrap();
    assert!(matches!(
        tx.set_driver_archive_ready(refused, now()).await,
        Err(DbError::Conflict { .. })
    ));
    audited(
        a,
        tx,
        "driver.refused",
        "driver_archive",
        &refused.to_string(),
    )
    .await;
    let mut tx = store.begin().await.unwrap();
    let r = tx.driver_archive(refused).await.unwrap().unwrap();
    assert_eq!(r.status, DriverArchiveStatus::Refused);
    assert_eq!(r.refusal, Some(why));
    let listed = tx
        .list_driver_archives(&[DriverArchiveStatus::Ready])
        .await
        .unwrap();
    assert!(listed.iter().any(|x| x.id == id) && listed.iter().all(|x| x.id != refused));
    tx.commit().await.unwrap();

    // Package driver lists: ordered, distinct, at most 64.
    let mut tx = store.begin().await.unwrap();
    tx.set_package_drivers(p.id, &[refused, id]).await.unwrap();
    assert_eq!(tx.package_drivers(p.id).await.unwrap(), vec![refused, id]);
    tx.set_package_drivers(p.id, &[id]).await.unwrap();
    assert_eq!(tx.package_drivers(p.id).await.unwrap(), vec![id]);
    assert!(matches!(
        tx.set_package_drivers(p.id, &[id, id]).await,
        Err(DbError::InvalidArgument { .. })
    ));
    audited(a, tx, "package.drivers.set", "package", &p.id.to_string()).await;

    // A listed archive cannot be deleted; its packages are named.
    let mut tx = store.begin().await.unwrap();
    let users = tx.packages_using_driver_archive(id).await.unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users.first().unwrap().id, p.id);
    assert!(matches!(
        tx.delete_driver_archive(id, now()).await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    tx.delete_driver_archive(refused, now()).await.unwrap();
    assert!(matches!(
        tx.delete_driver_archive(refused, now()).await,
        Err(DbError::Conflict { .. })
    ));
    audited(
        a,
        tx,
        "driver.deleted",
        "driver_archive",
        &refused.to_string(),
    )
    .await;

    // A deleted archive cannot be listed again.
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.set_package_drivers(p.id, &[id, refused]).await,
        Err(DbError::Constraint { .. })
    ));
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    let unknown = PackageId::from_random_bytes(rand_bytes());
    assert!(matches!(
        tx.set_package_drivers(unknown, &[id]).await,
        Err(DbError::NotFound { .. })
    ));
    tx.rollback().await;
}

/// Agent signers and packages; package configuration.
pub async fn flow_agent_packages_and_config<S: Store>(store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-agent").await;
    let signer = register_signer(store, a, &op).await;

    // Key id must be the digest of the SPKI; a key registers once.
    let mut tx = store.begin().await.unwrap();
    let mut bad = signer.clone();
    bad.id = AgentSignerId::from_random_bytes(rand_bytes());
    bad.key_id = digest();
    assert!(matches!(
        tx.insert_agent_signer(&bad).await,
        Err(DbError::InvalidArgument { .. })
    ));
    let mut dup = signer.clone();
    dup.id = AgentSignerId::from_random_bytes(rand_bytes());
    assert!(matches!(
        tx.insert_agent_signer(&dup).await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.agent_signer_by_key_id(&signer.key_id)
            .await
            .unwrap()
            .unwrap(),
        signer
    );
    assert!(tx.list_agent_signers().await.unwrap().contains(&signer));
    tx.commit().await.unwrap();

    let agent = ready_agent_package(store, a, &op, &signer).await;
    let mut tx = store.begin().await.unwrap();
    let ap = tx.agent_package(agent).await.unwrap().unwrap();
    assert_eq!(ap.status, AgentPackageStatus::Ready);
    assert_eq!(ap.signer_id, Some(signer.id));
    assert_eq!(ap.manifest, Some(agent_json()));
    // Ready is final.
    assert!(matches!(
        tx.refuse_agent_package(agent, &ErrorCode::new("x").unwrap(), now())
            .await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    // U-3: revoking the signer refuses its ready agent packages and takes
    // the packages that use them out of ready, in one transaction.
    let p0 = ready_package(store, a, &op).await;
    let mut tx = store.begin().await.unwrap();
    tx.set_package_config(&config(&p0, agent, op.id))
        .await
        .unwrap();
    audited(a, tx, "package.config.set", "package", &p0.id.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    let rev = tx
        .revoke_agent_signer(signer.id, op.id, now())
        .await
        .unwrap();
    assert_eq!(rev.refused_agent_packages, vec![agent]);
    assert_eq!(rev.packages_not_ready, vec![p0.id]);
    let ap = tx.agent_package(agent).await.unwrap().unwrap();
    assert_eq!(ap.status, AgentPackageStatus::Refused);
    assert_eq!(
        ap.refusal.as_ref().map(ErrorCode::as_str),
        Some(SIGNER_REVOKED)
    );
    let pk = tx.package(p0.id).await.unwrap().unwrap();
    assert_eq!(pk.status, usgp_proto::PackageStatus::NotUsable);
    assert_eq!(pk.status_reason.as_deref(), Some(AGENT_PACKAGE_REFUSED));
    append(
        a,
        &mut tx,
        "agent_package.refused",
        "agent_package",
        &agent.to_string(),
    )
    .await;
    assert!(matches!(
        tx.revoke_agent_signer(signer.id, op.id, now()).await,
        Err(DbError::Conflict { .. })
    ));
    audited(
        a,
        tx,
        "agent_signer.revoked",
        "agent_signer",
        &signer.id.to_string(),
    )
    .await;
    let c = ready_archive(store, a, op.id, ContentKindV2::AgentPackage, &[]).await;
    let pending = AgentPackageId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    tx.insert_agent_package(&NewAgentPackage {
        id: pending,
        content_id: c.id,
        created_by: op.id,
        created_at: now(),
    })
    .await
    .unwrap();
    assert!(matches!(
        tx.set_agent_package_ready(pending, signer.id, &agent_json(), now())
            .await,
        Err(DbError::Conflict { .. })
    ));
    tx.refuse_agent_package(pending, &ErrorCode::new("signer_unknown").unwrap(), now())
        .await
        .unwrap();
    audited(
        a,
        tx,
        "agent_package.refused",
        "agent_package",
        &pending.to_string(),
    )
    .await;
    let mut tx = store.begin().await.unwrap();
    let refused = tx
        .list_agent_packages(&[AgentPackageStatus::Refused])
        .await
        .unwrap();
    assert!(
        refused
            .iter()
            .any(|p| p.id == pending && p.signer_id.is_none())
    );
    tx.commit().await.unwrap();

    // Package configuration: set, replace, read back, named by the agent
    // package, removed with the package.
    let p = ready_package(store, a, &op).await;
    let cfg = config(&p, agent, op.id);
    let mut tx = store.begin().await.unwrap();
    tx.set_package_config(&cfg).await.unwrap();
    audited(a, tx, "package.config.set", "package", &p.id.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.package_config(p.id).await.unwrap().unwrap(), cfg);
    let mut cfg2 = cfg.clone();
    cfg2.admin_password = AdminPasswordMode::None;
    cfg2.tags = Vec::new();
    cfg2.values = PackageValues::default();
    tx.set_package_config(&cfg2).await.unwrap();
    assert_eq!(tx.package_config(p.id).await.unwrap().unwrap(), cfg2);
    // `p0` (taken out of ready above) and `p` name it.
    let users = tx.packages_using_agent_package(agent).await.unwrap();
    assert_eq!(users.len(), 2);
    // Bounds: the template is 1 B to 1 MiB and its digest must match.
    for (tpl, sha) in [
        (Vec::new(), usgp_crypto::sha256(b"")),
        (vec![b'x'; 1024 * 1024 + 1], usgp_crypto::sha256(b"x")),
        (ANSWER.to_vec(), digest()),
    ] {
        let mut bad = cfg.clone();
        bad.answer_template = tpl;
        bad.answer_sha256 = sha;
        assert!(matches!(
            tx.set_package_config(&bad).await,
            Err(DbError::InvalidArgument { .. })
        ));
    }
    let mut bad = cfg.clone();
    bad.values.time_zone = Some(String::new());
    assert!(matches!(
        tx.set_package_config(&bad).await,
        Err(DbError::InvalidArgument { .. })
    ));
    let mut bad = cfg.clone();
    bad.tags = (0..65)
        .map(|i| Tag::new(format!("t{i}")).unwrap())
        .collect();
    assert!(matches!(
        tx.set_package_config(&bad).await,
        Err(DbError::InvalidArgument { .. })
    ));
    audited(a, tx, "package.config.set", "package", &p.id.to_string()).await;

    let mut tx = store.begin().await.unwrap();
    let mut unknown = cfg.clone();
    unknown.agent_package_id = AgentPackageId::from_random_bytes(rand_bytes());
    assert!(matches!(
        tx.set_package_config(&unknown).await,
        Err(DbError::Constraint { .. })
    ));
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    tx.delete_package(p.id, p.revision).await.unwrap();
    audited(a, tx, "package.deleted", "package", &p.id.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert!(tx.package_config(p.id).await.unwrap().is_none());
    let left = tx.packages_using_agent_package(agent).await.unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left.first().unwrap().id, p0.id);
    tx.commit().await.unwrap();
}

/// Device values: set, replace, read, delete, bounds.
pub async fn flow_device_values<S: Store>(store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-values").await;
    let mac = super::m3::mac();
    let v = DeviceValues {
        mac,
        values: BTreeMap::from([
            ("computer_name".to_owned(), "WS-0042".to_owned()),
            ("asset_tag".to_owned(), "A-1 \"quoted\" & <x>".to_owned()),
        ]),
        updated_by: op.id,
        updated_at: now(),
    };
    let mut tx = store.begin().await.unwrap();
    tx.set_device_values(&v).await.unwrap();
    audited(a, tx, "device_value.set", "device_value", &mac.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.device_values(mac).await.unwrap().unwrap(), v);
    let mut v2 = v.clone();
    v2.values.remove("asset_tag");
    tx.set_device_values(&v2).await.unwrap();
    assert_eq!(tx.device_values(mac).await.unwrap().unwrap(), v2);
    for (k, val) in [
        ("Bad", "x"),
        ("device.x", "x"),
        ("ok", ""),
        ("ok", "a\nb"),
        (&"k".repeat(58), "x"),
    ] {
        let bad = DeviceValues {
            values: BTreeMap::from([(k.to_owned(), val.to_owned())]),
            ..v.clone()
        };
        assert!(
            matches!(
                tx.set_device_values(&bad).await,
                Err(DbError::InvalidArgument { .. })
            ),
            "{k:?}={val:?}"
        );
    }
    let too_many = DeviceValues {
        values: (0..33).map(|i| (format!("k{i}"), "v".to_owned())).collect(),
        ..v.clone()
    };
    assert!(matches!(
        tx.set_device_values(&too_many).await,
        Err(DbError::InvalidArgument { .. })
    ));
    audited(a, tx, "device_value.set", "device_value", &mac.to_string()).await;

    let mut tx = store.begin().await.unwrap();
    tx.delete_device_values(mac).await.unwrap();
    audited(
        a,
        tx,
        "device_value.deleted",
        "device_value",
        &mac.to_string(),
    )
    .await;
    let mut tx = store.begin().await.unwrap();
    assert!(tx.device_values(mac).await.unwrap().is_none());
    assert!(matches!(
        tx.delete_device_values(mac).await,
        Err(DbError::NotFound { .. })
    ));
    tx.rollback().await;
}

/// The nine-step job: v1 and v2 readers kept apart, steps in order,
/// success only after step 9, session closed at step 6, resume nonces and
/// tokens, escrow rules, restart pending, failure.
pub async fn flow_job_v2<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-job").await;
    let bs = enrol_boot_service(admin, a, "m4-relay").await.id;
    let p = ready_package(store, a, &op).await;
    let s = ready_session(store, a, &op, bs, &p, macs(2)).await;
    let job = confirm_v2(store, a, &s, bs, &p).await;

    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.job_plan_schema(job).await.unwrap(), Some(2));
    assert!(tx.job(job).await.unwrap().is_none());
    assert!(tx.job_by_session(s.id).await.unwrap().is_none());
    assert!(tx.job_steps(job).await.unwrap().is_empty());
    assert!(tx.list_jobs(&[]).await.unwrap().iter().all(|j| j.id != job));
    let j = tx.job_v2(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Running);
    assert_eq!(j.current_step, StepV2::VERIFY_CONTENT);
    assert_eq!(j.timeouts, TIMEOUTS_V2);
    assert_eq!(j.tags, vec![Tag::new("site:hq").unwrap()]);
    assert!(!j.restart_pending);
    assert_eq!(usgp_crypto::sha256(j.job_key_spki.as_der()), j.job_key_id);
    assert_eq!(tx.job_v2_by_session(s.id).await.unwrap().unwrap().id, job);
    assert!(
        tx.list_jobs_v2(&[JobState::Running])
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == job)
    );
    let steps = tx.job_steps_v2(job).await.unwrap();
    assert_eq!(steps.len(), 9);
    assert_eq!(steps.first().unwrap().state, StepState::Running);
    assert!(steps.iter().skip(1).all(|x| x.state == StepState::Pending));
    // The job is found by MAC like a v1 job.
    assert_eq!(tx.running_jobs_for_macs(&s.macs).await.unwrap(), vec![job]);
    // Steps advance in order; a v1 step move does not touch a v2 job.
    assert!(matches!(
        tx.set_job_step_v2(job, StepV2::APPLY_IMAGE, StepState::Running, now())
            .await,
        Err(DbError::Conflict { .. })
    ));
    assert!(matches!(
        tx.set_job_step(
            job,
            usgp_proto::Step::PARTITION_FORMAT,
            StepState::Running,
            now()
        )
        .await,
        Err(DbError::NotFound { .. })
    ));
    tx.rollback().await;

    // No challenge before step 6.
    let nonce = |hash: Sha256Digest, at: UnixMicros| NewResumeNonce {
        nonce_hash: hash,
        job_id: job,
        issued_at: at,
        expires_at: later(at, 60),
    };
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.insert_resume_nonce(&nonce(digest(), now()))
            .await
            .unwrap()
            == NonceIssue::NotEligible
    );
    tx.commit().await.unwrap();

    for step in StepV2::ALL.into_iter().take(5) {
        run_step(store, a, job, step).await;
    }
    // Success is refused before step 9.
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.set_job_state(job, &[JobState::Running], JobState::Succeeded, now())
            .await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    // Step 6 done: the WinPE session token is revoked (session ended).
    run_step(store, a, job, StepV2::MAKE_BOOTABLE_RESTART).await;
    let mut tx = store.begin().await.unwrap();
    let restarting = ErrorCode::new("restarting").unwrap();
    tx.close_confirmed_session(s.id, &restarting, now())
        .await
        .unwrap();
    assert!(matches!(
        tx.close_confirmed_session(s.id, &restarting, now()).await,
        Err(DbError::Conflict { .. })
    ));
    audited(
        a,
        tx,
        "device.session.closed",
        "device_session",
        &s.id.to_string(),
    )
    .await;
    let mut tx = store.begin().await.unwrap();
    let sess = tx.device_session(s.id).await.unwrap().unwrap();
    assert_eq!(sess.state, SessionState::Ended);
    assert_eq!(sess.end_reason, Some(restarting));
    tx.commit().await.unwrap();

    // Challenge nonces: no audit needed; capped per job; single use.
    let t0 = now();
    let (h1, h2, h3) = (digest(), digest(), digest());
    let mut tx = store.begin().await.unwrap();
    for h in [h1, h2] {
        assert_eq!(
            tx.insert_resume_nonce(&nonce(h, t0)).await.unwrap(),
            NonceIssue::Issued
        );
    }
    for _ in 2..MAX_LIVE_RESUME_NONCES {
        assert_eq!(
            tx.insert_resume_nonce(&nonce(digest(), t0)).await.unwrap(),
            NonceIssue::Issued
        );
    }
    // Above the cap: refused with its own answer (429), nothing written.
    assert_eq!(
        tx.insert_resume_nonce(&nonce(h3, t0)).await.unwrap(),
        NonceIssue::OverCap
    );
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    // Expired at use.
    assert!(
        !tx.consume_resume_nonce(job, &h2, later(t0, 61))
            .await
            .unwrap()
    );
    // Wrong job.
    let other = JobId::from_random_bytes(rand_bytes());
    assert!(!tx.consume_resume_nonce(other, &h1, t0).await.unwrap());
    assert!(
        tx.consume_resume_nonce(job, &h1, later(t0, 1))
            .await
            .unwrap()
    );
    assert!(
        !tx.consume_resume_nonce(job, &h1, later(t0, 2))
            .await
            .unwrap()
    );
    // A used nonce is a state change: it needs its audit record.
    let token_hash = digest();
    tx.insert_resume_token(&NewResumeToken {
        token_hash,
        job_id: job,
        issued_at: t0,
        expires_at: later(t0, 86_400),
    })
    .await
    .unwrap();
    audited(a, tx, "job.resumed", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.count_resume_tokens(job).await.unwrap(), 1);
    let t = tx.resume_token(&token_hash).await.unwrap().unwrap();
    assert_eq!(t.job_id, job);
    assert!(t.live(later(t0, 10)) && !t.live(later(t0, 86_400)));
    assert!(tx.resume_token(&digest()).await.unwrap().is_none());
    assert!(matches!(
        tx.insert_resume_token(&NewResumeToken {
            token_hash,
            job_id: job,
            issued_at: t0,
            expires_at: later(t0, 1),
        })
        .await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;

    // Escrow: once per job; sealed bytes only; outcome once; reveals
    // counted; nothing commits without its record.
    let key_id = digest();
    let e = NewEscrow {
        job_id: job,
        account: EscrowAccount::Administrator,
        key_id,
        sealed: sealed(40),
        received_at: now(),
    };
    let mut tx = store.begin().await.unwrap();
    tx.insert_escrow(&e).await.unwrap();
    assert!(matches!(tx.commit().await, Err(DbError::Unaudited)));
    let mut tx = store.begin().await.unwrap();
    assert!(tx.escrow(job).await.unwrap().is_none());
    assert!(matches!(
        tx.insert_escrow(&NewEscrow {
            sealed: sealed(16),
            ..e.clone()
        })
        .await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.insert_escrow(&e).await.unwrap();
    audited(a, tx, "escrow.received", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.insert_escrow(&NewEscrow {
            sealed: sealed(60),
            ..e.clone()
        })
        .await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;
    let mut tx = store.begin().await.unwrap();
    let rec = tx.lock_escrow(job).await.unwrap().unwrap();
    assert_eq!(rec.state, EscrowState::Received);
    assert_eq!((rec.key_id, rec.reveal_count), (key_id, 0));
    let got = tx.escrow_sealed(job).await.unwrap().unwrap();
    assert_eq!(got, e.sealed);
    let dbg = format!("{got:?}");
    assert!(dbg.contains("<40 bytes>") && !dbg.contains("171"), "{dbg}");
    tx.set_escrow_outcome(job, true, now()).await.unwrap();
    assert!(matches!(
        tx.set_escrow_outcome(job, false, now()).await,
        Err(DbError::Conflict { .. })
    ));
    audited(a, tx, "escrow.applied", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.record_escrow_reveal(job).await.unwrap(), 1);
    assert_eq!(tx.record_escrow_reveal(job).await.unwrap(), 2);
    audited(a, tx, "escrow.revealed", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    let rec = tx.escrow(job).await.unwrap().unwrap();
    assert_eq!((rec.state, rec.reveal_count), (EscrowState::Applied, 2));
    assert!(rec.applied_at.is_some());
    assert!(matches!(
        tx.record_escrow_reveal(other).await,
        Err(DbError::NotFound { .. })
    ));
    tx.rollback().await;

    run_step(store, a, job, StepV2::WINDOWS_SETUP).await;
    run_step(store, a, job, StepV2::INSTALL_AGENT).await;
    let mut tx = store.begin().await.unwrap();
    tx.set_job_restart_pending(job).await.unwrap();
    audited(a, tx, "job.step.completed", "job", &job.to_string()).await;
    run_step(store, a, job, StepV2::REPORT_READY).await;

    let mut tx = store.begin().await.unwrap();
    tx.set_job_state(job, &[JobState::Running], JobState::Succeeded, now())
        .await
        .unwrap();
    assert_eq!(tx.revoke_resume_tokens(job, now()).await.unwrap(), 1);
    assert_eq!(tx.revoke_resume_tokens(job, now()).await.unwrap(), 0);
    audited(a, tx, "job.succeeded", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    let j = tx.job_v2(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Succeeded);
    assert_eq!(j.current_step, StepV2::REPORT_READY);
    assert!(j.restart_pending && j.finished_at.is_some());
    assert!(
        tx.resume_token(&token_hash)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    // A finished job takes no further nonce or change.
    assert!(
        tx.insert_resume_nonce(&nonce(digest(), now()))
            .await
            .unwrap()
            == NonceIssue::NotEligible
    );
    assert!(matches!(
        tx.set_job_restart_pending(job).await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;
}

/// A v2 job fails with a v2 failure; v1 and v2 failure calls do not cross.
pub async fn flow_job_v2_failure<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-fail").await;
    let bs = enrol_boot_service(admin, a, "m4-fail-relay").await.id;
    let p = ready_package(store, a, &op).await;
    let s = ready_session(store, a, &op, bs, &p, macs(1)).await;
    let job = confirm_v2(store, a, &s, bs, &p).await;
    let f = FailureV2 {
        step: StepV2::ADD_DRIVERS,
        category: FailureCategory::Local,
        code: ErrorCode::new("driver_not_staged:abc").unwrap(),
        files: Vec::new(),
        count: 0,
        attempts: 1,
    };
    let mut tx = store.begin().await.unwrap();
    assert!(matches!(
        tx.fail_job(
            job,
            &[JobState::Running],
            &super::m3::failure(usgp_proto::Step::APPLY_IMAGE),
            now()
        )
        .await,
        Err(DbError::Conflict { .. })
    ));
    tx.rollback().await;
    let mut tx = store.begin().await.unwrap();
    tx.fail_job_v2(job, &[JobState::Running], &f, now())
        .await
        .unwrap();
    audited(a, tx, "job.failed", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    let j = tx.job_v2(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Failed);
    assert_eq!(j.failure, Some(f));
    assert_eq!(tx.previous_failed_job(&s.macs).await.unwrap(), Some(job));
    tx.acknowledge_job_failure(job, op.id, now()).await.unwrap();
    audited(a, tx, "job.failure.acknowledged", "job", &job.to_string()).await;
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.job_v2(job)
            .await
            .unwrap()
            .unwrap()
            .acknowledged
            .is_some()
    );
    // Escrow and tokens need a v2 job; none for an unknown job.
    let unknown = JobId::from_random_bytes(rand_bytes());
    assert!(matches!(
        tx.insert_escrow(&NewEscrow {
            job_id: unknown,
            account: EscrowAccount::Administrator,
            key_id: digest(),
            sealed: sealed(40),
            received_at: now(),
        })
        .await,
        Err(DbError::Constraint { .. })
    ));
    tx.rollback().await;
}

/// The wipe guard holds for v2 jobs: no `disk.wipe.authorised` record, no
/// job; a job key id that is not the key's digest is refused.
pub async fn flow_job_v2_guards<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(store, a, "m4-guard").await;
    let bs = enrol_boot_service(admin, a, "m4-guard-relay").await.id;
    let p = ready_package(store, a, &op).await;
    let s = ready_session(store, a, &op, bs, &p, macs(1)).await;
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    // Name a record that is not a wipe authorisation.
    let created = a
        .chain
        .append(
            &mut tx,
            &super::draft("job.created", "job", &id.to_string()),
        )
        .await
        .unwrap();
    let j = new_job_v2(&s, bs, &p, id, &created);
    let mut wrong = j.clone();
    wrong.job_key_id = digest();
    assert!(matches!(
        tx.insert_job_v2(&wrong).await,
        Err(DbError::InvalidArgument { .. })
    ));
    let mut bad_t = j.clone();
    bad_t.timeouts.steps_s[3] = 0;
    assert!(matches!(
        tx.insert_job_v2(&bad_t).await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.insert_job_v2(&j).await.unwrap();
    assert!(matches!(tx.commit().await, Err(DbError::Constraint { .. })));
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.job_plan_schema(id).await.unwrap(), None);
    tx.rollback().await;
}
