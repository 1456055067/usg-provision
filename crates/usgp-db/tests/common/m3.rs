//! M3 fixtures and store-generic scenarios (migration 0004): boot
//! services, operator codes, device sessions, jobs, boot stops and the
//! wipe guard. The same scenarios run on the in-memory store
//! (`memory_repo.rs`) and on PostgreSQL (`repo_pg.rs`, CI).
//!
//! Every scenario takes an administrative store (`admin`: operators and
//! boot services, decisions 0016 and 0021) and the application store
//! (`store`: everything else); on the memory store both are one store.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use usgp_audit::{Actor, AuditDraft, AuditRecord, Detail, Interface, Outcome};
use usgp_common::Sha256Digest;
use usgp_crypto::{HmacKey, HmacTag, KeyId};
use usgp_db::{
    BootService, ChosenPackage, DbError, JobTimeouts, NewAuthCode, NewBootStop, NewDeviceSession,
    NewJob, Operator, Package, RepoTx, SessionAuth, SessionScope, Store,
};
use usgp_proto::device::{DeviceArch, FirmwareKind, SecureBootState, SessionState};
use usgp_proto::disk::{
    Bus, DiskDescriptorParts, ExistingPartitionV1, FileSystem, PartitionKind, WrittenPartitionV1,
};
use usgp_proto::ops::{AuthCodeState, BootServiceStatus, IpCidr, SubnetList};
use usgp_proto::progress::{FailureCategory, FileRole, ProgressItemV1};
use usgp_proto::{
    AgentVersion, AuthCodeId, BootServiceId, BootStopId, ContentKind, DiskDescriptorV1, DiskGuid,
    DiskText, DiskToken, DisplayCode, DisplayName, EditionIndex, ErrorCode, FailureV1, ItemName,
    JobId, JobState, LayoutReportV1, MacAddress, MacList, PackageStatus, PartitionLabel, SessionId,
    Step, StepState, UnixMicros,
};

use super::{Audit, append, digest, enrol, make_ready, manifest, now, package, rand_bytes};

/// The event the wipe guard requires.
pub const WIPE_EVENT: &str = "disk.wipe.authorised";

/// `t` plus `secs` seconds.
pub fn later(t: UnixMicros, secs: i64) -> UnixMicros {
    UnixMicros::new(t.as_micros() + secs * 1_000_000).unwrap()
}

/// The earliest time (an idle cut-off that expires nothing).
pub fn epoch() -> UnixMicros {
    UnixMicros::new(0).unwrap()
}

/// A random unicast, locally administered MAC.
pub fn mac() -> MacAddress {
    let mut b: [u8; 6] = rand_bytes();
    if let Some(first) = b.first_mut() {
        *first = 0x02;
    }
    MacAddress::new(b).unwrap()
}

/// A list of `n` random MACs.
pub fn macs(n: usize) -> MacList {
    MacList::new((0..n).map(|_| mac()).collect()).unwrap()
}

/// An active boot service serving 10.20.0.0/16.
pub fn boot_service(name: &str) -> BootService {
    BootService {
        id: BootServiceId::from_random_bytes(rand_bytes()),
        name: DisplayName::new(name).unwrap(),
        cert_sha256: digest(),
        cert_not_after: UnixMicros::new(4_000_000_000_000_000).unwrap(),
        served_subnets: SubnetList::new(vec![
            IpCidr::parse("10.20.0.0/16").unwrap(),
            IpCidr::parse("2001:db8::/32").unwrap(),
        ])
        .unwrap(),
        status: BootServiceStatus::Active,
        created_at: now(),
        created_by: "uid:0".into(),
    }
}

/// Enrols a boot service through `admin` (audited) and returns it.
pub async fn enrol_boot_service<A: Store>(admin: &A, a: &Audit, name: &str) -> BootService {
    let b = boot_service(name);
    let mut tx = admin.begin().await.unwrap();
    tx.insert_boot_service(&b).await.unwrap();
    append(
        a,
        &mut tx,
        "boot_service.enrolled",
        "boot_service",
        &b.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    b
}

/// A disk descriptor with one existing partition.
pub fn disk() -> DiskDescriptorV1 {
    DiskDescriptorV1::new(DiskDescriptorParts {
        disk_token: DiskToken::from_random_bytes(rand_bytes()),
        bus: Bus::Nvme,
        model: DiskText::sanitized("Example NVMe 1TB"),
        serial: DiskText::sanitized("SN-0001"),
        size_bytes: 1_000_204_886_016,
        logical_sector: 512,
        physical_sector: 4096,
        removable: false,
        partitions: vec![ExistingPartitionV1 {
            index: 1,
            kind: PartitionKind::Basic,
            start_bytes: 1_048_576,
            size_bytes: 500_000_000_000,
            label: PartitionLabel::sanitized("Data"),
        }],
    })
    .unwrap()
}

/// A layout report of two partitions.
pub fn layout() -> LayoutReportV1 {
    LayoutReportV1::new(
        vec![
            WrittenPartitionV1 {
                index: 1,
                kind: PartitionKind::Esp,
                start_bytes: 1_048_576,
                size_bytes: 209_715_200,
                fs: Some(FileSystem::Fat32),
                label: PartitionLabel::sanitized("System"),
            },
            WrittenPartitionV1 {
                index: 3,
                kind: PartitionKind::Basic,
                start_bytes: 228_589_568,
                size_bytes: 900_000_000_000,
                fs: Some(FileSystem::Ntfs),
                label: PartitionLabel::sanitized("Windows"),
            },
        ],
        DiskGuid::from_text_order_bytes(rand_bytes()).unwrap(),
    )
    .unwrap()
}

/// A failure at `step`.
pub fn failure(step: Step) -> FailureV1 {
    FailureV1 {
        step,
        category: FailureCategory::Integrity,
        code: ErrorCode::new("chunk_digest_mismatch").unwrap(),
        files: vec![ProgressItemV1 {
            role: FileRole::Image,
            name: ItemName::new("install.wim").unwrap(),
        }],
        count: 1,
        attempts: 1,
    }
}

/// A new session from 10.20.1.2 with a random token and display code.
pub fn new_session(bs: Option<BootServiceId>, macs: MacList) -> NewDeviceSession {
    let at = now();
    NewDeviceSession {
        id: SessionId::from_random_bytes(rand_bytes()),
        token_sha256: digest(),
        boot_service_id: bs,
        source_ip: IpAddr::V4(Ipv4Addr::new(10, 20, 1, 2)),
        macs,
        firmware: FirmwareKind::Uefi,
        arch: DeviceArch::X64,
        secure_boot: SecureBootState::On,
        memory_bytes: 8 * 1024 * 1024 * 1024,
        agent_version: AgentVersion::new("0.3.0").unwrap(),
        display_code: DisplayCode::from_random_bytes(rand_bytes()),
        created_at: at,
        expires_at: later(at, 3600),
    }
}

/// Opens a session (audited) and returns it.
pub async fn open_session<S: Store>(
    store: &S,
    a: &Audit,
    bs: Option<BootServiceId>,
    macs: MacList,
) -> NewDeviceSession {
    let s = new_session(bs, macs);
    let mut tx = store.begin().await.unwrap();
    tx.insert_device_session(&s).await.unwrap();
    append(
        a,
        &mut tx,
        "device.session.opened",
        "device_session",
        &s.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    s
}

/// The HMAC of a code text under a fixed test key.
pub fn code_hmac(code: &str) -> HmacTag {
    HmacKey::from_bytes(&[0x42; 32])
        .unwrap()
        .sign(code.as_bytes())
}

/// Issues a code (audited) by `op` and returns its id.
pub async fn issue_code<S: Store>(
    store: &S,
    a: &Audit,
    op: &Operator,
    code: &str,
    ttl_s: i64,
) -> AuthCodeId {
    let at = now();
    let c = NewAuthCode {
        id: AuthCodeId::from_random_bytes(rand_bytes()),
        code_hmac: code_hmac(code),
        issued_by: op.id,
        issued_at: at,
        expires_at: later(at, ttl_s),
        note: None,
    };
    let mut tx = store.begin().await.unwrap();
    tx.insert_auth_code(&c).await.unwrap();
    append(
        a,
        &mut tx,
        "auth_code.issued",
        "auth_code",
        &c.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    c.id
}

/// A Ready package (image with one edition, PE) created by `op`.
pub async fn ready_package<S: Store>(store: &S, a: &Audit, op: &Operator) -> Package {
    let image = make_ready(store, a, op.id, ContentKind::Image, 1).await;
    let pe = make_ready(store, a, op.id, ContentKind::Pe, 1).await;
    let p = package(image.id, 1, pe.id, op.id);
    let mut tx = store.begin().await.unwrap();
    tx.insert_package(&p).await.unwrap();
    tx.set_package_status(p.id, PackageStatus::Ready, None, Some(&manifest(3)), now())
        .await
        .unwrap();
    append(a, &mut tx, "package.created", "package", &p.id.to_string()).await;
    tx.commit().await.unwrap();
    p
}

/// The `disk.wipe.authorised` draft for `job` (target `job`, the job id).
pub fn wipe_draft(job: JobId) -> AuditDraft {
    AuditDraft::new(
        WIPE_EVENT,
        Outcome::Success,
        Actor::system(),
        Interface::System,
    )
    .target("job", &job.to_string())
    .detail(Detail::new().with("scope", "tables+volume-heads-1mib"))
}

/// The plan timeouts the test jobs carry.
pub const TIMEOUTS: JobTimeouts = JobTimeouts {
    steps_s: [21_600, 1800, 21_600, 1800, 600],
    stall_s: 1800,
};

/// A job for an authorised, disk-chosen session, naming `wipe`.
pub fn new_job(
    s: &NewDeviceSession,
    bs: BootServiceId,
    p: &Package,
    id: JobId,
    wipe: &AuditRecord,
) -> NewJob {
    NewJob {
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
        timeouts: TIMEOUTS,
        bytes_total: Some(4096),
        started_at: now(),
    }
}

/// A session authorised by approval, with package and disk chosen.
pub async fn ready_session<S: Store>(
    store: &S,
    a: &Audit,
    op: &Operator,
    bs: BootServiceId,
    p: &Package,
    macs: MacList,
) -> NewDeviceSession {
    let s = open_session(store, a, Some(bs), macs).await;
    let mut tx = store.begin().await.unwrap();
    tx.authorise_device_session(s.id, SessionAuth::Approval(op.id), now())
        .await
        .unwrap();
    tx.choose_session_package(
        s.id,
        ChosenPackage {
            id: p.id,
            revision: p.revision,
        },
    )
    .await
    .unwrap();
    tx.choose_session_disk(s.id, &disk()).await.unwrap();
    append(
        a,
        &mut tx,
        "device.session.approved",
        "device_session",
        &s.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    s
}

/// The confirm transaction of plan section 3.1: job, `job.created`,
/// `disk.wipe.authorised`, session confirmed, together.
pub async fn confirm<S: Store>(
    store: &S,
    a: &Audit,
    s: &NewDeviceSession,
    bs: BootServiceId,
    p: &Package,
) -> Result<JobId, DbError> {
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await?;
    append(a, &mut tx, "job.created", "job", &id.to_string()).await;
    let wipe = a
        .chain
        .append(&mut tx, &wipe_draft(id))
        .await
        .map_err(|_| DbError::TxFailed)?;
    tx.insert_job(&new_job(s, bs, p, id, &wipe)).await?;
    tx.set_device_session_state(
        s.id,
        &[SessionState::Authorised],
        SessionState::Confirmed,
        None,
        now(),
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

// --------------------------------------------------------------- flows --

/// Boot services: enrolment, lookups, assignments, an assigned package
/// cannot be deleted.
pub async fn flow_boot_services<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "assigner").await;
    let bs = enrol_boot_service(admin, a, "relay one").await;

    // Same certificate or name → conflict.
    let mut dup = boot_service("relay two");
    dup.cert_sha256 = bs.cert_sha256;
    let mut tx = admin.begin().await.unwrap();
    assert!(
        tx.insert_boot_service(&dup)
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.boot_service(bs.id).await.unwrap().unwrap(), bs);
    assert_eq!(
        tx.boot_service_by_cert(&bs.cert_sha256)
            .await
            .unwrap()
            .unwrap()
            .id,
        bs.id
    );
    assert!(
        tx.list_boot_services()
            .await
            .unwrap()
            .iter()
            .any(|x| x.id == bs.id)
    );
    tx.rollback().await;

    let p1 = ready_package(store, a, &op).await;
    let p2 = ready_package(store, a, &op).await;

    // Assign two, then replace with one; replacing is audited.
    let mut tx = store.begin().await.unwrap();
    tx.set_boot_service_packages(bs.id, &[p1.id, p2.id], op.id, now())
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "boot_service.packages.set",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let first = tx.boot_service_packages(bs.id).await.unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(
        tx.boot_services_using_package(p1.id).await.unwrap(),
        vec![bs.id]
    );
    // Duplicates refused before any write.
    assert!(matches!(
        tx.set_boot_service_packages(bs.id, &[p1.id, p1.id], op.id, now())
            .await,
        Err(DbError::InvalidArgument { .. })
    ));
    let missing = BootServiceId::from_random_bytes(rand_bytes());
    assert!(
        tx.set_boot_service_packages(missing, &[p1.id], op.id, now())
            .await
            .unwrap_err()
            .is_not_found()
    );
    tx.set_boot_service_packages(bs.id, &[p2.id], op.id, now())
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "boot_service.packages.set",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let after = tx.boot_service_packages(bs.id).await.unwrap();
    assert_eq!(after.len(), 1);
    let kept = after.first().unwrap();
    assert_eq!(kept.package_id, p2.id);
    // A kept assignment keeps its original time.
    assert_eq!(
        Some(kept.added_at),
        first
            .iter()
            .find(|x| x.package_id == p2.id)
            .map(|x| x.added_at)
    );
    assert!(
        tx.boot_services_using_package(p1.id)
            .await
            .unwrap()
            .is_empty()
    );
    tx.rollback().await;

    // An assigned package cannot be deleted; an unassigned one can.
    let mut tx = store.begin().await.unwrap();
    let e = tx.delete_package(p2.id, p2.revision).await.unwrap_err();
    assert!(matches!(e, DbError::Constraint { .. }), "{e:?}");
    tx.rollback().await;
    let mut tx = store.begin().await.unwrap();
    tx.delete_package(p1.id, p1.revision).await.unwrap();
    append(a, &mut tx, "package.deleted", "package", &p1.id.to_string()).await;
    tx.commit().await.unwrap();

    // Disable (administrative role).
    let mut tx = admin.begin().await.unwrap();
    tx.set_boot_service_status(bs.id, BootServiceStatus::Disabled)
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "boot_service.disabled",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.boot_service(bs.id).await.unwrap().unwrap().status,
        BootServiceStatus::Disabled
    );
    tx.rollback().await;
}

/// Codes: stored by HMAC, single use, the same "no match" for wrong,
/// expired, used and revoked codes, revocation rules (REQ-TGT-013).
pub async fn flow_codes<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "code issuer").await;
    let s1 = open_session(store, a, None, macs(1)).await;
    let s2 = open_session(store, a, None, macs(1)).await;
    let id = issue_code(store, a, &op, "ABCDE12345", 900).await;

    // Same HMAC again → conflict (draw a new code), poisons as PostgreSQL.
    let at = now();
    let mut tx = store.begin().await.unwrap();
    let dup = NewAuthCode {
        id: AuthCodeId::from_random_bytes(rand_bytes()),
        code_hmac: code_hmac("ABCDE12345"),
        issued_by: op.id,
        issued_at: at,
        expires_at: later(at, 60),
        note: None,
    };
    assert!(tx.insert_auth_code(&dup).await.unwrap_err().is_conflict());
    assert!(matches!(tx.commit().await, Err(DbError::TxFailed)));

    // A wrong code matches nothing and changes nothing.
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.consume_auth_code(&code_hmac("WRONG00000"), s1.id, now())
            .await
            .unwrap(),
        None
    );
    tx.commit().await.unwrap();

    // The right code once.
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.consume_auth_code(&code_hmac("ABCDE12345"), s1.id, now())
            .await
            .unwrap(),
        Some(id)
    );
    tx.authorise_device_session(s1.id, SessionAuth::Code(id), now())
        .await
        .unwrap();
    append(a, &mut tx, "auth_code.used", "auth_code", &id.to_string()).await;
    tx.commit().await.unwrap();
    // Not twice, not for another session.
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.consume_auth_code(&code_hmac("ABCDE12345"), s2.id, now())
            .await
            .unwrap(),
        None
    );
    let rec = tx.auth_code(id).await.unwrap().unwrap();
    assert_eq!(rec.used_by_session, Some(s1.id));
    assert_eq!(rec.state(now()), AuthCodeState::Used);
    assert_eq!(rec.view(now()).state, AuthCodeState::Used);
    // A used code cannot be revoked.
    assert!(
        tx.revoke_auth_code(id, op.id, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.device_session(s1.id).await.unwrap().unwrap().auth,
        Some(SessionAuth::Code(id))
    );
    tx.rollback().await;

    // Revoked → no match.
    let rid = issue_code(store, a, &op, "REV0K00001", 900).await;
    let mut tx = store.begin().await.unwrap();
    tx.revoke_auth_code(rid, op.id, now()).await.unwrap();
    append(
        a,
        &mut tx,
        "auth_code.revoked",
        "auth_code",
        &rid.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.revoke_auth_code(rid, op.id, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert_eq!(
        tx.consume_auth_code(&code_hmac("REV0K00001"), s2.id, now())
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        tx.auth_code(rid).await.unwrap().unwrap().state(now()),
        AuthCodeState::Revoked
    );
    assert!(
        tx.revoke_auth_code(AuthCodeId::from_random_bytes(rand_bytes()), op.id, now())
            .await
            .unwrap_err()
            .is_not_found()
    );
    tx.rollback().await;

    // Expired → no match (checked at the time given).
    let eid = issue_code(store, a, &op, "EXP1RED001", 60).await;
    let mut tx = store.begin().await.unwrap();
    let past_expiry = later(now(), 120);
    assert_eq!(
        tx.consume_auth_code(&code_hmac("EXP1RED001"), s2.id, past_expiry)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        tx.auth_code(eid).await.unwrap().unwrap().state(past_expiry),
        AuthCodeState::Expired
    );
    let listed = tx.list_auth_codes().await.unwrap();
    for x in [id, rid, eid] {
        assert!(listed.iter().any(|r| r.id == x));
    }
    tx.rollback().await;
}

/// Sessions: unique live display codes, caps, authorisation before any
/// choice, confirmation needs a disk, final states stay, expiry
/// (REQ-TGT-010, REQ-TGT-014).
pub async fn flow_sessions<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "approver").await;
    let bs = enrol_boot_service(admin, a, "relay sessions").await;
    let p = ready_package(store, a, &op).await;
    let s = open_session(store, a, Some(bs.id), macs(2)).await;

    // Live display code reused → conflict; token reused → conflict.
    let mut same_code = new_session(Some(bs.id), macs(1));
    same_code.display_code = s.display_code;
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.insert_device_session(&same_code)
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;
    let mut same_token = new_session(Some(bs.id), macs(1));
    same_token.token_sha256 = s.token_sha256;
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.insert_device_session(&same_token)
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;

    let mut tx = store.begin().await.unwrap();
    tx.lock_device_session_quota().await.unwrap();
    let ip = s.source_ip;
    assert!(
        tx.count_device_sessions(
            &[SessionState::AwaitingAuthorisation],
            SessionScope::SourceNetwork(ip)
        )
        .await
        .unwrap()
            >= 1
    );
    assert_eq!(
        tx.count_device_sessions(
            &[SessionState::AwaitingAuthorisation],
            SessionScope::SourceNetwork(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        )
        .await
        .unwrap(),
        0
    );
    let got = tx
        .device_session_by_token(&s.token_sha256)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.id, s.id);
    assert_eq!(got.state, SessionState::AwaitingAuthorisation);
    assert_eq!(got.macs, s.macs);
    assert_eq!(got.source_ip, s.source_ip);
    assert_eq!(
        got.view(Some(bs.name.clone())).boot_service_name,
        Some(bs.name.clone())
    );
    // Nothing chosen before authorisation.
    let chosen = ChosenPackage {
        id: p.id,
        revision: p.revision,
    };
    assert!(
        tx.choose_session_package(s.id, chosen)
            .await
            .unwrap_err()
            .is_conflict()
    );
    // Authorised is reached only through authorise_device_session.
    assert!(matches!(
        tx.set_device_session_state(
            s.id,
            &[SessionState::AwaitingAuthorisation],
            SessionState::Authorised,
            None,
            now()
        )
        .await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.rollback().await;

    // A poll is bookkeeping: commits without an audit record.
    let mut tx = store.begin().await.unwrap();
    let seen = later(now(), 5);
    tx.touch_device_session(s.id, seen).await.unwrap();
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.device_session(s.id).await.unwrap().unwrap().last_seen_at,
        seen
    );
    tx.rollback().await;

    // Failed attempts are counted (audited).
    for expect in 1..=2u32 {
        let mut tx = store.begin().await.unwrap();
        assert_eq!(tx.record_failed_code_attempt(s.id).await.unwrap(), expect);
        append(
            a,
            &mut tx,
            "device.session.code_refused",
            "device_session",
            &s.id.to_string(),
        )
        .await;
        tx.commit().await.unwrap();
    }

    // Approval; then package; then disk; confirming needs the disk.
    let mut tx = store.begin().await.unwrap();
    tx.authorise_device_session(s.id, SessionAuth::Approval(op.id), now())
        .await
        .unwrap();
    assert!(
        tx.authorise_device_session(s.id, SessionAuth::Approval(op.id), now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.record_failed_code_attempt(s.id)
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.choose_session_disk(s.id, &disk())
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.choose_session_package(s.id, chosen).await.unwrap();
    assert!(
        tx.set_device_session_state(
            s.id,
            &[SessionState::Authorised],
            SessionState::Confirmed,
            None,
            now()
        )
        .await
        .unwrap_err()
        .is_conflict()
    );
    let d = disk();
    tx.choose_session_disk(s.id, &d).await.unwrap();
    append(
        a,
        &mut tx,
        "device.session.approved",
        "device_session",
        &s.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let got = tx.lock_device_session(s.id).await.unwrap().unwrap();
    assert_eq!(got.state, SessionState::Authorised);
    assert_eq!(got.auth, Some(SessionAuth::Approval(op.id)));
    assert_eq!(got.failed_code_attempts, 2);
    assert_eq!(got.chosen_package, Some(chosen));
    assert_eq!(got.chosen_disk, Some(d));
    tx.rollback().await;
    // Choosing the package again clears the disk.
    let mut tx = store.begin().await.unwrap();
    tx.choose_session_package(s.id, chosen).await.unwrap();
    assert_eq!(
        tx.device_session(s.id).await.unwrap().unwrap().chosen_disk,
        None
    );
    tx.rollback().await;

    // Cancel (final) with a reason; nothing moves it afterwards.
    let mut tx = store.begin().await.unwrap();
    let reason = ErrorCode::new("cancelled_at_device").unwrap();
    tx.set_device_session_state(
        s.id,
        &[
            SessionState::AwaitingAuthorisation,
            SessionState::Authorised,
        ],
        SessionState::Cancelled,
        Some(&reason),
        now(),
    )
    .await
    .unwrap();
    append(
        a,
        &mut tx,
        "device.session.cancelled",
        "device_session",
        &s.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let got = tx.device_session(s.id).await.unwrap().unwrap();
    assert_eq!(got.state, SessionState::Cancelled);
    assert_eq!(got.end_reason, Some(reason));
    assert!(got.ended_at.is_some());
    assert!(
        tx.set_device_session_state(
            s.id,
            &[SessionState::Cancelled],
            SessionState::Ended,
            None,
            now()
        )
        .await
        .unwrap_err()
        .is_conflict()
    );
    tx.rollback().await;

    // The display code is free again once the session is final.
    let mut again = new_session(Some(bs.id), macs(1));
    again.display_code = s.display_code;
    let mut tx = store.begin().await.unwrap();
    tx.insert_device_session(&again).await.unwrap();
    append(
        a,
        &mut tx,
        "device.session.opened",
        "device_session",
        &again.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    // Expiry: none due now; all live ones due after their expiry.
    let mut tx = store.begin().await.unwrap();
    assert!(
        !tx.expire_device_sessions(now(), epoch())
            .await
            .unwrap()
            .contains(&again.id)
    );
    // Nothing expired → nothing to audit → commits.
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let expired = tx
        .expire_device_sessions(later(now(), 7200), epoch())
        .await
        .unwrap();
    assert!(expired.contains(&again.id));
    // Expiring changed state: no commit without its records.
    for id in &expired {
        append(
            a,
            &mut tx,
            "device.session.expired",
            "device_session",
            &id.to_string(),
        )
        .await;
    }
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.device_session(again.id).await.unwrap().unwrap().state,
        SessionState::Expired
    );
    // An expired session cannot be authorised.
    assert!(
        tx.authorise_device_session(again.id, SessionAuth::Approval(op.id), now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        !tx.list_device_sessions(&[SessionState::Expired])
            .await
            .unwrap()
            .is_empty()
    );
    tx.rollback().await;
}

/// Expiring sessions without recording it cannot commit.
pub async fn flow_expiry_is_audited<S: Store>(store: &S, a: &Audit) {
    let s = open_session(store, a, None, macs(1)).await;
    let mut tx = store.begin().await.unwrap();
    let ids = tx
        .expire_device_sessions(later(now(), 7200), epoch())
        .await
        .unwrap();
    assert!(ids.contains(&s.id));
    assert!(matches!(tx.commit().await, Err(DbError::Unaudited)));
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.device_session(s.id).await.unwrap().unwrap().state,
        SessionState::AwaitingAuthorisation
    );
    tx.rollback().await;
}

/// A whole successful job: confirm (wipe guard satisfied), steps in
/// order, progress bookkeeping, success after step 4, boot stops and
/// generations, and a finished job never changes (REQ-JOB-012,
/// REQ-JOB-013, REQ-BOOT-067).
pub async fn flow_job_success<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "job operator").await;
    let bs = enrol_boot_service(admin, a, "relay jobs").await;
    let p = ready_package(store, a, &op).await;
    let device_macs = macs(2);
    let s = ready_session(store, a, &op, bs.id, &p, device_macs.clone()).await;
    let job = confirm(store, a, &s, bs.id, &p).await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let j = tx.job(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Running);
    assert_eq!(j.current_step, Step::VERIFY_CONTENT);
    assert_eq!(j.session_id, s.id);
    assert_eq!(j.macs, device_macs);
    // Finding SEC-012: the plan's timeouts are stored with the job.
    assert_eq!(j.timeouts, TIMEOUTS);
    assert_eq!(tx.job_by_session(s.id).await.unwrap().unwrap().id, job);
    // Decision 0023 item 2: the running job holds its MACs.
    assert_eq!(tx.running_jobs_for_macs(&device_macs).await.unwrap(), [job]);
    assert!(tx.running_jobs_for_macs(&macs(2)).await.unwrap().is_empty());
    assert!(
        tx.active_boot_stops_for_macs(&device_macs)
            .await
            .unwrap()
            .is_empty()
    );
    let steps = tx.job_steps(job).await.unwrap();
    assert_eq!(steps.len(), 5);
    assert_eq!(steps.first().unwrap().state, StepState::Running);
    assert!(steps.iter().skip(1).all(|x| x.state == StepState::Pending));
    assert_eq!(
        tx.device_session(s.id).await.unwrap().unwrap().state,
        SessionState::Confirmed
    );
    // A second job for the session → conflict.
    let wipe = a.chain.append(&mut tx, &wipe_draft(job)).await.unwrap();
    let again = new_job(&s, bs.id, &p, JobId::from_random_bytes(rand_bytes()), &wipe);
    assert!(tx.insert_job(&again).await.unwrap_err().is_conflict());
    tx.rollback().await;

    // Steps only in order.
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.set_job_step(job, Step::APPLY_IMAGE, StepState::Running, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(matches!(
        tx.set_job_step(job, Step::APPLY_IMAGE, StepState::Pending, now())
            .await,
        Err(DbError::InvalidArgument { .. })
    ));
    // Success before step 4 → conflict.
    assert!(
        tx.set_job_state(job, &[JobState::Running], JobState::Succeeded, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;

    // Progress is bookkeeping: commits without a record; seq must rise.
    let mut tx = store.begin().await.unwrap();
    tx.record_job_progress(job, 1, Some(1024), Some(4096), now())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.record_job_progress(job, 1, Some(2048), None, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.record_job_progress(job, 2, Some(9999), None, now())
            .await
            .unwrap_err()
            .is_conflict(),
        "done above the stored total"
    );
    tx.rollback().await;

    let written = layout();
    let mut seq = 1;
    for step in Step::ALL.into_iter().take(4) {
        let mut tx = store.begin().await.unwrap();
        if step != Step::VERIFY_CONTENT {
            tx.set_job_step(job, step, StepState::Running, now())
                .await
                .unwrap();
            append(a, &mut tx, "job.step.started", "job", &job.to_string()).await;
        }
        if step == Step::PARTITION_FORMAT {
            tx.set_job_layout(job, &written).await.unwrap();
        }
        tx.set_job_step(job, step, StepState::Done, now())
            .await
            .unwrap();
        seq += 1;
        tx.record_job_progress(job, seq, None, None, now())
            .await
            .unwrap();
        append(a, &mut tx, "job.step.completed", "job", &job.to_string()).await;
        tx.commit().await.unwrap();
    }
    let mut tx = store.begin().await.unwrap();
    let j = tx.job(job).await.unwrap().unwrap();
    assert_eq!(j.current_step, Step::MAKE_BOOTABLE);
    assert_eq!(j.last_seq, seq);
    assert_eq!(j.layout, Some(written));
    assert_eq!(j.bytes_done, Some(1024));
    assert_eq!(j.view(&tx.job_steps(job).await.unwrap()).percent, Some(25));
    tx.rollback().await;

    // Success, boot stops for every MAC, generation bumped, together.
    let mut tx = store.begin().await.unwrap();
    tx.set_job_state(job, &[JobState::Running], JobState::Succeeded, now())
        .await
        .unwrap();
    for m in device_macs.as_slice() {
        let added = tx
            .add_boot_stop(&NewBootStop {
                id: BootStopId::from_random_bytes(rand_bytes()),
                boot_service_id: bs.id,
                mac: *m,
                job_id: job,
                created_at: now(),
            })
            .await
            .unwrap();
        assert!(added);
    }
    assert_eq!(tx.bump_boot_policy_generation(bs.id).await.unwrap(), 1);
    append(a, &mut tx, "job.succeeded", "job", &job.to_string()).await;
    append(
        a,
        &mut tx,
        "boot_stop.added",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    let mut tx = store.begin().await.unwrap();
    let j = tx.job(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Succeeded);
    assert!(j.finished_at.is_some());
    assert_eq!(tx.boot_policy_generation(bs.id).await.unwrap(), 1);
    let stops = tx.list_boot_stops(Some(bs.id), true).await.unwrap();
    assert_eq!(stops.len(), 2);
    // Decision 0023 item 2: the stops are found by MAC; the finished job
    // no longer holds them.
    assert_eq!(
        tx.active_boot_stops_for_macs(&device_macs)
            .await
            .unwrap()
            .len(),
        2
    );
    let one = MacList::new(vec![*device_macs.as_slice().first().unwrap()]).unwrap();
    assert_eq!(tx.active_boot_stops_for_macs(&one).await.unwrap().len(), 1);
    assert!(
        tx.active_boot_stops_for_macs(&macs(1))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        tx.running_jobs_for_macs(&device_macs)
            .await
            .unwrap()
            .is_empty()
    );
    // A second active stop for the same MAC adds nothing.
    let dup = NewBootStop {
        id: BootStopId::from_random_bytes(rand_bytes()),
        boot_service_id: bs.id,
        mac: *device_macs.as_slice().first().unwrap(),
        job_id: job,
        created_at: now(),
    };
    assert!(!tx.add_boot_stop(&dup).await.unwrap());
    // A finished job never changes.
    assert!(
        tx.set_job_state(
            job,
            &[JobState::Running, JobState::Lost],
            JobState::Running,
            now()
        )
        .await
        .unwrap_err()
        .is_conflict()
    );
    assert!(
        tx.fail_job(
            job,
            &[JobState::Running, JobState::Lost],
            &failure(Step::REPORT_RESTART),
            now()
        )
        .await
        .unwrap_err()
        .is_conflict()
    );
    assert!(
        tx.set_job_step(job, Step::REPORT_RESTART, StepState::Running, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.record_job_progress(job, seq + 1, None, None, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.acknowledge_job_failure(job, op.id, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    tx.rollback().await;

    // Clear one stop (the minimal reversal), audited; generation bumps.
    let first = *stops.first().unwrap();
    let mut tx = store.begin().await.unwrap();
    tx.clear_boot_stop(first.id, op.id, now()).await.unwrap();
    assert_eq!(tx.bump_boot_policy_generation(bs.id).await.unwrap(), 2);
    append(
        a,
        &mut tx,
        "boot_stop.cleared",
        "boot_stop",
        &first.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.clear_boot_stop(first.id, op.id, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    assert!(
        tx.clear_boot_stop(BootStopId::from_random_bytes(rand_bytes()), op.id, now())
            .await
            .unwrap_err()
            .is_not_found()
    );
    let cleared = tx.boot_stop(first.id).await.unwrap().unwrap();
    assert_eq!(cleared.cleared_by, Some(op.id));
    assert_eq!(
        tx.list_boot_stops(Some(bs.id), true).await.unwrap().len(),
        1
    );
    assert_eq!(tx.list_boot_stops(None, false).await.unwrap().len(), 2);
    // A cleared stop is no longer found by its MAC.
    assert_eq!(
        tx.active_boot_stops_for_macs(&device_macs)
            .await
            .unwrap()
            .len(),
        1
    );
    // After clearing, the MAC can be stopped again.
    let re = NewBootStop {
        id: BootStopId::from_random_bytes(rand_bytes()),
        mac: first.mac,
        ..dup
    };
    assert!(tx.add_boot_stop(&re).await.unwrap());
    tx.rollback().await;
}

/// Failure, acknowledgement once, `previous_job_id` by MAC overlap, lost
/// and resumed (REQ-JOB-005, REQ-JOB-006, REQ-JOB-009).
pub async fn flow_job_failure<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "failure operator").await;
    let bs = enrol_boot_service(admin, a, "relay failures").await;
    let p = ready_package(store, a, &op).await;
    let device_macs = macs(2);
    let s = ready_session(store, a, &op, bs.id, &p, device_macs.clone()).await;
    let job = confirm(store, a, &s, bs.id, &p).await.unwrap();

    // Lost (no report since long before), then resumed.
    let mut tx = store.begin().await.unwrap();
    let lost = tx.mark_lost_jobs(later(now(), 3600)).await.unwrap();
    assert!(lost.contains(&job));
    for id in &lost {
        append(a, &mut tx, "job.lost", "job", &id.to_string()).await;
    }
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.job(job).await.unwrap().unwrap().state, JobState::Lost);
    tx.set_job_state(job, &[JobState::Lost], JobState::Running, now())
        .await
        .unwrap();
    append(a, &mut tx, "job.resumed", "job", &job.to_string()).await;
    tx.commit().await.unwrap();

    // Fail at step 1.
    let f = failure(Step::VERIFY_CONTENT);
    let mut tx = store.begin().await.unwrap();
    tx.set_job_step(job, Step::VERIFY_CONTENT, StepState::Failed, now())
        .await
        .unwrap();
    tx.fail_job(job, &[JobState::Running, JobState::Lost], &f, now())
        .await
        .unwrap();
    append(a, &mut tx, "job.failed", "job", &job.to_string()).await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let j = tx.job(job).await.unwrap().unwrap();
    assert_eq!(j.state, JobState::Failed);
    assert_eq!(j.failure, Some(f.clone()));
    assert_eq!(j.attempts, 1);
    let v = j.view(&tx.job_steps(job).await.unwrap());
    assert_eq!(v.failed_at, j.finished_at);
    assert!(!v.acknowledged);
    assert_eq!(
        tx.list_jobs(&[JobState::Failed])
            .await
            .unwrap()
            .iter()
            .filter(|x| x.id == job)
            .count(),
        1
    );
    // A later session of the same device links to it (any shared MAC).
    let other = MacList::new(vec![*device_macs.as_slice().get(1).unwrap(), mac()]).unwrap();
    assert_eq!(tx.previous_failed_job(&other).await.unwrap(), Some(job));
    assert_eq!(tx.previous_failed_job(&macs(1)).await.unwrap(), None);
    tx.rollback().await;

    // Acknowledge once.
    let mut tx = store.begin().await.unwrap();
    tx.acknowledge_job_failure(job, op.id, now()).await.unwrap();
    append(
        a,
        &mut tx,
        "job.failure.acknowledged",
        "job",
        &job.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert!(
        tx.acknowledge_job_failure(job, op.id, now())
            .await
            .unwrap_err()
            .is_conflict()
    );
    let j = tx.job(job).await.unwrap().unwrap();
    assert_eq!(j.acknowledged.map(|(by, _)| by), Some(op.id));
    assert_eq!(j.state, JobState::Failed);
    tx.rollback().await;

    // The retry job links back.
    let s2 = ready_session(store, a, &op, bs.id, &p, other.clone()).await;
    let id2 = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    let prev = tx.previous_failed_job(&other).await.unwrap();
    let wipe = a.chain.append(&mut tx, &wipe_draft(id2)).await.unwrap();
    let mut nj = new_job(&s2, bs.id, &p, id2, &wipe);
    nj.previous_job_id = prev;
    tx.insert_job(&nj).await.unwrap();
    tx.set_device_session_state(
        s2.id,
        &[SessionState::Authorised],
        SessionState::Confirmed,
        None,
        now(),
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.job(id2).await.unwrap().unwrap().previous_job_id,
        Some(job)
    );
    tx.rollback().await;
}

/// The wipe guard (REQ-DISK-006, decision 0018 item 7): a job commits
/// only with a successful `disk.wipe.authorised` record that targets it.
/// Every refusal leaves no job and the session still authorised.
pub async fn flow_wipe_guard<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "wipe operator").await;
    let bs = enrol_boot_service(admin, a, "relay wipe").await;
    let p = ready_package(store, a, &op).await;
    let s = ready_session(store, a, &op, bs.id, &p, macs(1)).await;

    type Wrong = fn(JobId) -> AuditDraft;
    let wrong: [(&str, Wrong); 4] = [
        ("other event", |id| {
            AuditDraft::new(
                "job.created",
                Outcome::Success,
                Actor::system(),
                Interface::System,
            )
            .target("job", &id.to_string())
        }),
        ("other target", |_| {
            AuditDraft::new(
                WIPE_EVENT,
                Outcome::Success,
                Actor::system(),
                Interface::System,
            )
            .target("job", &JobId::from_random_bytes(rand_bytes()).to_string())
        }),
        ("no target", |_| {
            AuditDraft::new(
                WIPE_EVENT,
                Outcome::Success,
                Actor::system(),
                Interface::System,
            )
        }),
        ("failure outcome", |id| {
            AuditDraft::new(
                WIPE_EVENT,
                Outcome::Failure,
                Actor::system(),
                Interface::System,
            )
            .target("job", &id.to_string())
            .reason("audit_unavailable")
        }),
    ];
    for (what, draft) in wrong {
        let id = JobId::from_random_bytes(rand_bytes());
        let mut tx = store.begin().await.unwrap();
        let rec = a.chain.append(&mut tx, &draft(id)).await.unwrap();
        tx.insert_job(&new_job(&s, bs.id, &p, id, &rec))
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
        let e = tx.commit().await.unwrap_err();
        assert!(matches!(e, DbError::Constraint { .. }), "{what}: {e:?}");
        assert!(!e.outcome_unknown(), "{what}");
    }

    // A record hash that does not match the named seq.
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    let rec = a.chain.append(&mut tx, &wipe_draft(id)).await.unwrap();
    let mut j = new_job(&s, bs.id, &p, id, &rec);
    j.wipe_record_hash = digest();
    tx.insert_job(&j).await.unwrap();
    let e = tx.commit().await.unwrap_err();
    assert!(matches!(e, DbError::Constraint { .. }), "{e:?}");

    // A seq with no record at all.
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    let rec = a.chain.append(&mut tx, &wipe_draft(id)).await.unwrap();
    let mut j = new_job(&s, bs.id, &p, id, &rec);
    j.wipe_audit_seq = rec.seq + 1000;
    tx.insert_job(&j).await.unwrap();
    let e = tx.commit().await.unwrap_err();
    assert!(matches!(e, DbError::Constraint { .. }), "{e:?}");

    // Nothing was written; the session can still confirm properly.
    let mut tx = store.begin().await.unwrap();
    assert!(tx.job_by_session(s.id).await.unwrap().is_none());
    assert_eq!(
        tx.device_session(s.id).await.unwrap().unwrap().state,
        SessionState::Authorised
    );
    tx.rollback().await;
    let job = confirm(store, a, &s, bs.id, &p).await.unwrap();

    // One wipe record authorises one job only.
    let s2 = ready_session(store, a, &op, bs.id, &p, macs(1)).await;
    let mut tx = store.begin().await.unwrap();
    let first = tx.job(job).await.unwrap().unwrap();
    let id2 = JobId::from_random_bytes(rand_bytes());
    let fresh = a.chain.append(&mut tx, &wipe_draft(id2)).await.unwrap();
    let mut j = new_job(&s2, bs.id, &p, id2, &fresh);
    j.wipe_audit_seq = first.wipe_audit_seq;
    j.wipe_record_hash = first.wipe_record_hash;
    assert!(tx.insert_job(&j).await.unwrap_err().is_conflict());
    tx.rollback().await;
}

/// Finding SEC-001: pending sessions counted per source network (an
/// IPv4 address, or the IPv6 /64) and per boot service; idle sessions
/// that were never authorised expire.
pub async fn flow_session_scopes_and_idle<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "scope operator").await;
    let bs = enrol_boot_service(admin, a, "relay scopes").await;
    let other_bs = enrol_boot_service(admin, a, "relay scopes two").await;
    let v6 = |s: &str| IpAddr::V6(s.parse::<Ipv6Addr>().unwrap());
    let mut opened = Vec::new();
    for (ip, b) in [
        (v6("2001:db8:1:2::5"), bs.id),
        (v6("2001:db8:1:2:ffff::9"), bs.id),
        (v6("2001:db8:1:3::5"), other_bs.id),
        (IpAddr::V4(Ipv4Addr::new(10, 20, 1, 3)), other_bs.id),
    ] {
        let mut n = new_session(Some(b), macs(1));
        n.source_ip = ip;
        let mut tx = store.begin().await.unwrap();
        tx.insert_device_session(&n).await.unwrap();
        append(
            a,
            &mut tx,
            "device.session.opened",
            "device_session",
            &n.id.to_string(),
        )
        .await;
        tx.commit().await.unwrap();
        opened.push(n);
    }
    let pending = [
        SessionState::AwaitingAuthorisation,
        SessionState::Authorised,
    ];
    let mut tx = store.begin().await.unwrap();
    tx.lock_device_session_quota().await.unwrap();
    for (scope, want) in [
        (SessionScope::SourceNetwork(v6("2001:db8:1:2:abcd::1")), 2),
        (SessionScope::SourceNetwork(v6("2001:db8:1:3::")), 1),
        (SessionScope::SourceNetwork(v6("2001:db8:1:4::5")), 0),
        (
            SessionScope::SourceNetwork(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 3))),
            1,
        ),
        // Another IPv4 address in the same /24 is another source.
        (
            SessionScope::SourceNetwork(IpAddr::V4(Ipv4Addr::new(10, 20, 1, 4))),
            0,
        ),
        (SessionScope::BootService(bs.id), 2),
        (SessionScope::BootService(other_bs.id), 2),
    ] {
        assert_eq!(
            tx.count_device_sessions(&pending, scope).await.unwrap(),
            want,
            "{scope:?}"
        );
    }
    assert!(
        tx.count_device_sessions(&pending, SessionScope::All)
            .await
            .unwrap()
            >= 4
    );
    tx.rollback().await;

    // One of the four is authorised: idle expiry spares it.
    let kept = opened.first().unwrap();
    let mut tx = store.begin().await.unwrap();
    tx.authorise_device_session(kept.id, SessionAuth::Approval(op.id), now())
        .await
        .unwrap();
    append(
        a,
        &mut tx,
        "device.session.approved",
        "device_session",
        &kept.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    // A cut-off before the sessions were seen expires nothing.
    let mut tx = store.begin().await.unwrap();
    let ids = tx
        .expire_device_sessions(now(), later(kept.created_at, -60))
        .await
        .unwrap();
    assert!(opened.iter().all(|o| !ids.contains(&o.id)));
    tx.rollback().await;
    // A cut-off after: the three waiting ones expire before their TTL.
    let mut tx = store.begin().await.unwrap();
    let ids = tx
        .expire_device_sessions(now(), later(now(), 1))
        .await
        .unwrap();
    for o in opened.iter().skip(1) {
        assert!(ids.contains(&o.id));
        append(
            a,
            &mut tx,
            "device.session.expired",
            "device_session",
            &o.id.to_string(),
        )
        .await;
    }
    assert!(!ids.contains(&kept.id));
    for id in ids.iter().filter(|i| opened.iter().all(|o| o.id != **i)) {
        append(
            a,
            &mut tx,
            "device.session.expired",
            "device_session",
            &id.to_string(),
        )
        .await;
    }
    tx.commit().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    assert_eq!(
        tx.device_session(kept.id).await.unwrap().unwrap().state,
        SessionState::Authorised
    );
    assert_eq!(
        tx.count_device_sessions(&pending, SessionScope::BootService(other_bs.id))
            .await
            .unwrap(),
        0
    );
    tx.rollback().await;
}

/// Finding NIST-013: the administrative role raises a boot service's
/// generation after a restore; it never lowers it or sets it equal.
pub async fn flow_raise_generation<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let bs = enrol_boot_service(admin, a, "relay restored").await;
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.bump_boot_policy_generation(bs.id).await.unwrap(), 1);
    append(
        a,
        &mut tx,
        "boot_policy.generation.initialised",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();

    let mut tx = admin.begin().await.unwrap();
    tx.raise_boot_policy_generation(bs.id, 1000).await.unwrap();
    append(
        a,
        &mut tx,
        "boot_policy.generation.raised",
        "boot_service",
        &bs.id.to_string(),
    )
    .await;
    tx.commit().await.unwrap();
    let mut tx = admin.begin().await.unwrap();
    for to in [1000, 999, 1] {
        assert!(
            tx.raise_boot_policy_generation(bs.id, to)
                .await
                .unwrap_err()
                .is_conflict(),
            "{to}"
        );
    }
    tx.rollback().await;
    let mut tx = admin.begin().await.unwrap();
    assert!(matches!(
        tx.raise_boot_policy_generation(bs.id, 0).await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.rollback().await;
    // Raising is a state change: no commit without its record.
    let mut tx = admin.begin().await.unwrap();
    tx.raise_boot_policy_generation(bs.id, 2000).await.unwrap();
    assert!(matches!(tx.commit().await, Err(DbError::Unaudited)));
    let mut tx = store.begin().await.unwrap();
    assert_eq!(tx.boot_policy_generation(bs.id).await.unwrap(), 1000);
    // The next stop change continues from the raised value.
    assert_eq!(tx.bump_boot_policy_generation(bs.id).await.unwrap(), 1001);
    tx.rollback().await;
}

/// Finding SEC-012: a job whose timeouts are 0 is refused before anything
/// is written.
pub async fn flow_job_timeouts_checked<A: Store, S: Store>(admin: &A, store: &S, a: &Audit) {
    let op = enrol(admin, a, "timeouts operator").await;
    let bs = enrol_boot_service(admin, a, "relay timeouts").await;
    let p = ready_package(store, a, &op).await;
    let s = ready_session(store, a, &op, bs.id, &p, macs(1)).await;
    let id = JobId::from_random_bytes(rand_bytes());
    let mut tx = store.begin().await.unwrap();
    let wipe = a.chain.append(&mut tx, &wipe_draft(id)).await.unwrap();
    let mut j = new_job(&s, bs.id, &p, id, &wipe);
    j.timeouts.steps_s[2] = 0;
    assert!(matches!(
        tx.insert_job(&j).await,
        Err(DbError::InvalidArgument { .. })
    ));
    tx.rollback().await;
}

/// Finding SEC-013.1: the claim lock serialises two transactions; the
/// second sees what the first committed (its running job) once it holds
/// the lock.
pub async fn flow_claim_lock_serialises<A: Store, S: Store + Clone + 'static>(
    admin: &A,
    store: &S,
    a: &Audit,
) {
    let op = enrol(admin, a, "claims operator").await;
    let bs = enrol_boot_service(admin, a, "relay claims").await;
    let p = ready_package(store, a, &op).await;
    let shared = macs(1);
    let s = ready_session(store, a, &op, bs.id, &p, shared.clone()).await;

    let mut first = store.begin().await.unwrap();
    first.lock_mac_claims().await.unwrap();
    assert!(
        first
            .running_jobs_for_macs(&shared)
            .await
            .unwrap()
            .is_empty()
    );

    let other = store.clone();
    let claim = shared.clone();
    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let second = tokio::spawn(async move {
        let mut tx = other.begin().await.unwrap();
        tx.lock_mac_claims().await.unwrap();
        let _ = held_tx.send(());
        let seen = tx.running_jobs_for_macs(&claim).await.unwrap();
        tx.rollback().await;
        seen
    });
    let mut held_rx = held_rx;
    // The second cannot take the lock while the first holds it.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(300), &mut held_rx)
            .await
            .is_err(),
        "the claim lock did not block"
    );
    // The first confirms (job running) and commits.
    let id = JobId::from_random_bytes(rand_bytes());
    append(a, &mut first, "job.created", "job", &id.to_string()).await;
    let wipe = a.chain.append(&mut first, &wipe_draft(id)).await.unwrap();
    first
        .insert_job(&new_job(&s, bs.id, &p, id, &wipe))
        .await
        .unwrap();
    first
        .set_device_session_state(
            s.id,
            &[SessionState::Authorised],
            SessionState::Confirmed,
            None,
            now(),
        )
        .await
        .unwrap();
    first.commit().await.unwrap();
    assert_eq!(second.await.unwrap(), [id]);
}
