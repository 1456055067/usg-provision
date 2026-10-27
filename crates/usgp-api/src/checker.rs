//! The background check of uploaded content, its stall watchdog, and
//! start-up recovery (plan M2 sections 1.1 and 5.7; WU-6 `checker.rs`).
//!
//! After an upload's body has arrived and its SHA-256 matched, the file
//! is checked on the blocking pool (at most `check_concurrency` at once).
//! A check that makes no read progress for `check_stall_timeout` fails
//! with `wim_check_stalled` (REQ-IMG-021); a check that keeps reading is
//! never cut off (REQ-IMG-032). On success the file is moved into the
//! object store read-only, the content manifest is signed, and the item
//! becomes Ready in one transaction with its audit records; on failure it
//! becomes Failed with the check's reason code (REQ-IMG-022). Either way
//! the record names the upload record that started it (REQ-AUD-002).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   only checked content with a signed manifest becomes Ready.
// - NIST 800-53: SI-10 (Information Input Validation) - the WIM check.
// - NIST 800-53: SC-5 - bounded concurrency; stall watchdog.
// - NIST 800-53: AU-2, AU-12 - every state change audited with its
//   initiating record.
// - SPEC: specs/os-images.md#REQ-IMG-021, #REQ-IMG-022, #REQ-IMG-030,
//   #REQ-IMG-032, #REQ-IMG-035, #REQ-IMG-037, #REQ-IMG-040, #REQ-IMG-050,
//   #REQ-IMG-052
// - SPEC: specs/preinstall-env.md#REQ-PE-002, #REQ-PE-004, #REQ-PE-005,
//   #REQ-PE-009
// - SPEC: specs/operator-access.md#REQ-AUD-002, #REQ-AUD-006
// - Decisions 0011, 0013, 0014

use std::collections::HashSet;
use std::io::{BufReader, Seek};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use usgp_audit::{AuditRecord, Detail, Outcome};
use usgp_db::{Content, NewEdition, PeDeclaration, ReadyContent, Reason, RepoTx, Store, WimFacts};
use usgp_image::chunks::ContentDigests;
use usgp_image::facts::{FactTable, FileFact, FileFacts, read_file_facts, reconcile_pe};
use usgp_image::os_support::{SupportStatus, evaluate_pe};
use usgp_image::{Progress, WimError, WimLimits, WimSummary, check_pe, check_wim};
use usgp_proto::content_manifest::SCHEMA_V1;
use usgp_proto::limits::CHUNK_SIZE;
use usgp_proto::{
    ContentId, ContentKind, ContentManifestV1, ContentState, EditionIndex, ErrorCode, KitVersion,
    ManifestEdition, PayloadType, UploadState, WimCompression, WimSummaryV1, WimText, codes,
};

use crate::context::{Api, system_draft};
use crate::error::ApiError;

/// What a successful check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The WIM summary.
    pub summary: WimSummary,
    /// The PE's usable image (PEs only, REQ-PE-004).
    pub usable_index: Option<u32>,
    /// Facts the file states for each image, by index 1..=n (decision
    /// 0013; all `NotStated` while the documented table is empty).
    pub file_facts: Vec<FileFacts>,
}

/// Checks content files. Runs on the blocking pool.
pub trait ContentChecker: Send + Sync + 'static {
    /// Checks the file at `path` as `kind`, reporting read progress.
    ///
    /// # Errors
    ///
    /// [`WimError`] with the refusal's reason code.
    fn check(
        &self,
        path: &Path,
        kind: ContentKind,
        progress: &mut dyn Progress,
    ) -> Result<CheckReport, WimError>;

    /// Facts the Ready object at `path` states for image `index` (for
    /// the declaration cross-check, decision 0013 item 2).
    ///
    /// # Errors
    ///
    /// [`WimError`] if the file cannot be read.
    fn file_facts(&self, path: &Path, index: u32) -> Result<FileFacts, WimError>;
}

/// Nothing stated.
#[must_use]
pub const fn no_facts() -> FileFacts {
    FileFacts {
        release: FileFact::NotStated,
        edition: FileFact::NotStated,
        architecture: FileFact::NotStated,
    }
}

/// The production checker: `usgp_image::check_wim` (and `check_pe`) with
/// the documented fact table.
#[derive(Debug, Clone)]
pub struct WimChecker {
    limits: WimLimits,
    table: FactTable,
}

impl WimChecker {
    /// A checker with `limits` and [`FactTable::DOCUMENTED`].
    #[must_use]
    pub const fn new(limits: WimLimits) -> Self {
        Self {
            limits,
            table: FactTable::DOCUMENTED,
        }
    }

    fn run(&self, path: &Path, progress: &mut dyn Progress) -> Result<WimSummary, WimError> {
        let file = std::fs::File::open(path).map_err(|e| WimError::Io(e.kind()))?;
        let len = file.metadata().map_err(|e| WimError::Io(e.kind()))?.len();
        let mut r = BufReader::with_capacity(64 * 1024, file);
        r.rewind().map_err(|e| WimError::Io(e.kind()))?;
        check_wim(&mut r, len, &self.limits, usgp_crypto::provider(), progress)
    }
}

impl ContentChecker for WimChecker {
    fn check(
        &self,
        path: &Path,
        kind: ContentKind,
        progress: &mut dyn Progress,
    ) -> Result<CheckReport, WimError> {
        let summary = self.run(path, progress)?;
        let usable_index = match kind {
            ContentKind::Pe => Some(check_pe(&summary)?),
            ContentKind::Image => None,
        };
        let file_facts = (1..=summary.image_count)
            .map(|i| {
                summary
                    .xml_image(i)
                    .map_or_else(no_facts, |x| read_file_facts(x, &self.table))
            })
            .collect();
        Ok(CheckReport {
            summary,
            usable_index,
            file_facts,
        })
    }

    fn file_facts(&self, path: &Path, index: u32) -> Result<FileFacts, WimError> {
        if self.table.rules().is_empty() {
            // M2: no documented XML element states a fact (OPEN-WIM-8), so
            // the file is not read again.
            return Ok(no_facts());
        }
        let summary = self.run(path, &mut usgp_image::NoProgress)?;
        Ok(summary
            .xml_image(index)
            .map_or_else(no_facts, |x| read_file_facts(x, &self.table)))
    }
}

/// A check to run after an upload.
#[derive(Debug, Clone)]
pub(crate) struct CheckJob {
    pub(crate) content_id: ContentId,
    pub(crate) staging_name: String,
    pub(crate) digests: ContentDigests,
    pub(crate) initiating_seq: Option<u64>,
}

/// Why a check failed: a reason code and operator text.
struct Failure {
    code: ErrorCode,
    text: String,
}

impl Failure {
    fn new(code: ErrorCode, text: impl Into<String>) -> Self {
        Self {
            code,
            text: text.into(),
        }
    }

    fn wim(e: &WimError) -> Self {
        Self::new(
            ErrorCode::new(e.reason_code()).unwrap_or(codes::INTERNAL),
            e.operator_message(),
        )
    }
}

fn reason(code: &ErrorCode, text: &str) -> Reason {
    Reason {
        code: code.as_str().to_owned(),
        text: text.to_owned(),
    }
}

/// A kit-version warning (REQ-PE-009), if `v` is on the known-bad list.
#[must_use]
pub fn kit_warning(v: &KitVersion, known_bad: &[KitVersion]) -> Option<(ErrorCode, String)> {
    known_bad.contains(v).then(|| {
        (
            codes::KIT_VERSION_KNOWN_BAD,
            format!("kit version {v} is on the server's known-bad list"),
        )
    })
}

impl<S: Store + 'static> Api<S> {
    /// Runs a check job to its end (Ready or Failed). Spawned by the
    /// upload handler.
    pub(crate) async fn run_check(&self, job: CheckJob) {
        let Ok(_slot) = Arc::clone(&self.inner.check_slots).acquire_owned().await else {
            return;
        };
        let outcome = self.check_with_watchdog(&job).await;
        let result = match outcome {
            Ok(report) => self.finalise(&job, report).await,
            Err(f) => Err(f),
        };
        if let Err(f) = result {
            self.fail_check(&job, &f).await;
        }
    }

    async fn check_with_watchdog(&self, job: &CheckJob) -> Result<CheckReport, Failure> {
        let path = self
            .inner
            .files
            .staging_path(&job.staging_name)
            .map_err(|_| Failure::new(codes::STORAGE_ERROR, "staging file name is invalid"))?;
        let kind = {
            let mut tx = self.inner.store.begin().await.map_err(|_| {
                Failure::new(codes::INTERNAL, "the content record could not be read")
            })?;
            let c = tx.content(job.content_id).await;
            tx.rollback().await;
            c.ok()
                .flatten()
                .ok_or_else(|| Failure::new(codes::INTERNAL, "the content record is missing"))?
                .kind
        };
        let read = Arc::new(AtomicU64::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let checker = Arc::clone(&self.inner.checker);
        let (r2, c2) = (Arc::clone(&read), Arc::clone(&cancel));
        let mut handle = tokio::task::spawn_blocking(move || {
            let mut progress = |n: u64| {
                r2.fetch_add(n, Ordering::Relaxed);
                if c2.load(Ordering::Relaxed) {
                    ControlFlow::Break(())
                } else {
                    ControlFlow::Continue(())
                }
            };
            checker.check(&path, kind, &mut progress)
        });
        let stall = self.inner.config.content.check_stall_timeout;
        let tick = (stall / 8).clamp(Duration::from_millis(10), Duration::from_secs(5));
        let mut last = read.load(Ordering::Relaxed);
        let mut idle = Duration::ZERO;
        let mut cancelled_for = Duration::ZERO;
        loop {
            match tokio::time::timeout(tick, &mut handle).await {
                Ok(joined) => {
                    return match joined {
                        Ok(Ok(_)) if cancel.load(Ordering::Relaxed) => {
                            Err(Failure::wim(&WimError::Stalled))
                        }
                        Ok(Ok(report)) => Ok(report),
                        Ok(Err(e)) => Err(Failure::wim(&e)),
                        Err(_) => Err(Failure::new(
                            codes::INTERNAL,
                            "the check stopped unexpectedly",
                        )),
                    };
                }
                Err(_) if cancel.load(Ordering::Relaxed) => {
                    // The check was told to stop; if it is blocked in a
                    // read it cannot see that, so give up waiting.
                    cancelled_for += tick;
                    if cancelled_for >= stall.min(Duration::from_secs(30)) {
                        return Err(Failure::wim(&WimError::Stalled));
                    }
                }
                Err(_) => {
                    let now = read.load(Ordering::Relaxed);
                    if now == last {
                        idle += tick;
                        if idle >= stall {
                            cancel.store(true, Ordering::Relaxed);
                        }
                    } else {
                        last = now;
                        idle = Duration::ZERO;
                    }
                }
            }
        }
    }

    async fn finalise(&self, job: &CheckJob, report: CheckReport) -> Result<(), Failure> {
        let internal = |_| Failure::new(codes::INTERNAL, "internal error during the check");
        let mut tx = self.inner.store.begin().await.map_err(internal)?;
        let c = tx
            .lock_content(job.content_id)
            .await
            .map_err(internal)?
            .ok_or_else(|| Failure::new(codes::INTERNAL, "the content record is missing"))?;
        if c.state != ContentState::Checking {
            // Changed meanwhile (for example by recovery); nothing to do.
            return Ok(());
        }
        if job.digests.total != c.sha256 || job.digests.size != c.size {
            return Err(Failure::new(
                codes::DIGEST_MISMATCH,
                "the received file does not match the declared SHA-256",
            ));
        }
        let s = &report.summary;
        let compression = WimCompression::parse(s.compression.as_str())
            .ok_or_else(|| Failure::wim(&WimError::CompressionNotSupported))?;
        let (pe, pe_detail) = self.pe_facts(&c, &report)?;
        let mut editions = Vec::with_capacity(s.editions.len());
        let mut man_editions = Vec::with_capacity(s.editions.len());
        for e in &s.editions {
            let name = WimText::new(e.name.clone())
                .map_err(|_| Failure::wim(&WimError::LimitExceeded { what: "image name" }))?;
            let description = WimText::new(e.description.clone()).map_err(|_| {
                Failure::wim(&WimError::LimitExceeded {
                    what: "image description",
                })
            })?;
            let index = EditionIndex::new(u64::from(e.index)).map_err(|_| {
                Failure::wim(&WimError::Malformed {
                    what: "image index",
                })
            })?;
            man_editions.push(ManifestEdition {
                index,
                name: name.clone(),
                description: description.clone(),
                total_bytes: e.total_bytes,
            });
            editions.push(NewEdition {
                index: e.index,
                name,
                description,
                total_bytes: e.total_bytes,
            });
        }
        let at = self
            .now()
            .map_err(|_| Failure::new(codes::INTERNAL, "clock unavailable"))?;
        let manifest = ContentManifestV1 {
            schema: SCHEMA_V1,
            kind: c.kind,
            content_id: c.id,
            display_name: c.display_name.clone(),
            file_name: c.file_name.clone(),
            size: c.size,
            sha256: c.sha256,
            chunk_size: CHUNK_SIZE,
            chunk_sha256: job.digests.chunks.clone(),
            wim: WimSummaryV1 {
                compression,
                image_count: s.image_count,
                boot_index: s.boot_index,
                editions: man_editions,
            },
            ready_at: at,
            key_id: self.inner.keys.key_id().0,
        };
        let payload = manifest
            .to_payload()
            .map_err(|_| Failure::new(codes::INTERNAL, "the content manifest is invalid"))?;
        let stored = self
            .inner
            .keys
            .sign(PayloadType::ContentManifestV1, payload)
            .map_err(|_| {
                Failure::new(codes::INTERNAL, "the content manifest could not be signed")
            })?;
        // Move into the object store first (read-only); the database
        // decides readiness, and the object is removed again if the
        // transaction does not commit.
        let files = self.inner.files.clone();
        let (name, sha) = (job.staging_name.clone(), c.sha256);
        tokio::task::spawn_blocking(move || files.finalise(&name, &sha))
            .await
            .map_err(|_| Failure::new(codes::STORAGE_ERROR, "the content could not be stored"))?
            .map_err(|_| Failure::new(codes::STORAGE_ERROR, "the content could not be stored"))?;
        let ready = ReadyContent {
            wim: WimFacts {
                compression,
                image_count: s.image_count,
                boot_index: s.boot_index,
            },
            usable_index: report.usable_index,
            editions,
            manifest: stored.clone(),
            pe: pe.clone(),
            at,
        };
        let committed = self.commit_ready(tx, job, &c, &ready, pe_detail).await;
        if committed.is_err() {
            let files = self.inner.files.clone();
            let sha = c.sha256;
            let _ = tokio::task::spawn_blocking(move || files.remove_object(&sha)).await;
            return Err(Failure::new(
                codes::AUDIT_UNAVAILABLE,
                "the content could not be made ready because its record could not be written",
            ));
        }
        Ok(())
    }

    /// The PE declaration after reconciling with the file, plus audit
    /// detail; `None` for images.
    fn pe_facts(
        &self,
        c: &Content,
        report: &CheckReport,
    ) -> Result<(Option<PeDeclaration>, Option<Detail>), Failure> {
        if c.kind != ContentKind::Pe {
            return Ok((None, None));
        }
        let decl =
            c.pe.clone()
                .ok_or_else(|| Failure::new(codes::INTERNAL, "the PE declaration is missing"))?;
        let usable = report
            .usable_index
            .ok_or_else(|| Failure::wim(&WimError::PeNoUsableImage { image_count: 0 }))?;
        let ff = usize::try_from(usable)
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| report.file_facts.get(i))
            .copied()
            .unwrap_or_else(no_facts);
        let arch = reconcile_pe(decl.architecture.value, &ff)
            .map_err(|k| Failure::new(k.reason_code(), k.operator_message()))?;
        if let SupportStatus::NotSupported { reasons } = evaluate_pe(arch.value) {
            let code = reasons
                .first()
                .cloned()
                .unwrap_or(codes::PE_ARCHITECTURE_NOT_SUPPORTED);
            return Err(Failure::new(
                code,
                format!(
                    "preinstall environment architecture {} is not supported; only x64 is",
                    arch.value.as_str()
                ),
            ));
        }
        let kit = decl.kit_version.clone();
        let mut detail = Detail::new()
            .with("architecture", arch.value.as_str())
            .with("architecture_source", arch.source.as_str())
            .with("kit_version", &kit.value.to_string())
            .with("kit_version_source", kit.source.as_str())
            .with("usable_index", &usable);
        if let Some((code, _)) = kit_warning(&kit.value, &self.inner.config.known_bad_kit_versions)
        {
            detail = detail.with("kit_warning", code.as_str());
        }
        Ok((
            Some(PeDeclaration {
                architecture: arch,
                kit_version: kit,
            }),
            Some(detail),
        ))
    }

    async fn commit_ready(
        &self,
        mut tx: S::Tx,
        job: &CheckJob,
        c: &Content,
        ready: &ReadyContent,
        pe_detail: Option<Detail>,
    ) -> Result<(), ApiError> {
        tx.set_content_ready(c.id, ready).await?;
        let id = c.id.to_string();
        let with_init = |d: usgp_audit::AuditDraft| match job.initiating_seq {
            Some(s) => d.initiated_by(s),
            None => d,
        };
        let mut recs: Vec<AuditRecord> = Vec::new();
        let d = with_init(
            system_draft("content.ready", Outcome::Success)
                .target("content", &id)
                .detail(
                    Detail::new()
                        .with("kind", c.kind.as_str())
                        .with("sha256", &c.sha256)
                        .with("size", &c.size)
                        .with("image_count", &ready.wim.image_count)
                        .with("compression", ready.wim.compression.as_str()),
                ),
        );
        recs.push(self.append(&mut tx, &d).await?);
        let d = with_init(
            system_draft("content.manifest.signed", Outcome::Success)
                .target("content", &id)
                .detail(
                    Detail::new()
                        .with("key_id", &ready.manifest.key_id)
                        .with("chunks", &job.digests.chunks.len()),
                ),
        );
        recs.push(self.append(&mut tx, &d).await?);
        if let Some(detail) = pe_detail {
            let d = with_init(
                system_draft("pe.declared", Outcome::Success)
                    .target("content", &id)
                    .detail(detail),
            );
            recs.push(self.append(&mut tx, &d).await?);
        }
        self.commit(tx, &recs).await
    }

    async fn fail_check(&self, job: &CheckJob, f: &Failure) {
        let files = self.inner.files.clone();
        let name = job.staging_name.clone();
        let _ = tokio::task::spawn_blocking(move || files.remove_staging(&name)).await;
        let Ok(mut tx) = self.inner.store.begin().await else {
            return;
        };
        let Ok(at) = self.now() else { return };
        let r = reason(&f.code, &f.text);
        if tx
            .set_content_state(
                job.content_id,
                &[ContentState::Checking],
                ContentState::Failed,
                Some(&r),
                at,
            )
            .await
            .is_err()
        {
            tx.rollback().await;
            return;
        }
        let mut d = system_draft("content.failed", Outcome::Failure)
            .target("content", &job.content_id.to_string())
            .reason(f.code.as_str());
        if let Some(s) = job.initiating_seq {
            d = d.initiated_by(s);
        }
        let Ok(rec) = self.append(&mut tx, &d).await else {
            return;
        };
        let _ = self.commit(tx, &[rec]).await;
    }

    /// Start-up recovery (plan section 1.1; REQ-IMG-021, REQ-IMG-035):
    ///
    /// - every Receiving or Checking item left by a previous run becomes
    ///   Failed (`interrupted_by_restart`), with its open upload, audited;
    /// - staging files are removed (partial data, REQ-IMG-035);
    /// - object files no Ready item refers to are reported
    ///   (`content.orphan.found`) and never deleted.
    ///
    /// The server calls this once before serving.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the database or an audit write fails; the server
    /// then refuses to start.
    pub async fn recover(&self) -> Result<RecoveryReport, ApiError> {
        let mut report = RecoveryReport::default();
        let mut tx = self.inner.store.begin().await?;
        let stuck = tx
            .list_content(None, &[ContentState::Receiving, ContentState::Checking])
            .await?;
        let uploads = tx
            .list_uploads(&[UploadState::Open, UploadState::Streaming])
            .await?;
        let at = self.now()?;
        let r = reason(
            &codes::INTERRUPTED_BY_RESTART,
            "the server restarted before the upload or check completed",
        );
        let mut recs = Vec::new();
        for u in &uploads {
            tx.set_upload_state(
                u.id,
                &[UploadState::Open, UploadState::Streaming],
                UploadState::Failed,
            )
            .await?;
        }
        for c in &stuck {
            tx.set_content_state(
                c.id,
                &[ContentState::Receiving, ContentState::Checking],
                ContentState::Failed,
                Some(&r),
                at,
            )
            .await?;
            let mut d = system_draft("content.failed", Outcome::Failure)
                .target("content", &c.id.to_string())
                .reason(codes::INTERRUPTED_BY_RESTART.as_str())
                .detail(Detail::new().with("previous_state", c.state.as_str()));
            if let Some(s) = c.initiating_audit_seq {
                d = d.initiated_by(s);
            }
            recs.push(self.append(&mut tx, &d).await?);
            report.failed.push(c.id);
        }
        let ready: HashSet<_> = tx
            .list_content(None, &[ContentState::Ready])
            .await?
            .into_iter()
            .map(|c| c.sha256)
            .collect();
        if recs.is_empty() {
            tx.rollback().await;
        } else {
            self.commit(tx, &recs).await?;
        }
        let files = self.inner.files.clone();
        let (removed, objects) = tokio::task::spawn_blocking(move || {
            let mut removed = 0u64;
            for name in files.list_staging().unwrap_or_default() {
                if files.remove_staging(&name).is_ok() {
                    removed += 1;
                }
            }
            (removed, files.list_objects())
        })
        .await
        .map_err(|_| ApiError::internal_error("recovery task failed"))?;
        report.staging_removed = removed;
        let objects = objects.map_err(ApiError::internal_error)?;
        for o in objects {
            let (what, path): (String, PathBuf) = match o {
                Ok(d) if ready.contains(&d) => continue,
                Ok(d) => (d.to_hex(), self.inner.files.object_path(&d)),
                Err(p) => ("unrecognised".to_owned(), p),
            };
            let d = system_draft("content.orphan.found", Outcome::Success)
                .target("object", &what)
                .detail(Detail::new().with("path", &path.display().to_string()));
            self.record(&d).await?;
            report.orphans += 1;
        }
        Ok(report)
    }

    /// Expires upload sessions whose body never arrived (their content
    /// becomes Failed `upload_expired`, audited). The server calls this
    /// periodically.
    ///
    /// # Errors
    ///
    /// [`ApiError`] for a database or audit failure.
    pub async fn expire_uploads(&self) -> Result<u64, ApiError> {
        let mut tx = self.inner.store.begin().await?;
        let now = self.now()?;
        let open = tx.list_uploads(&[UploadState::Open]).await?;
        let code = ErrorCode::new("upload_expired").unwrap_or(codes::CANCELLED);
        let r = reason(&code, "the upload session expired before its body arrived");
        let mut recs = Vec::new();
        for u in open.iter().filter(|u| u.expires_at <= now) {
            tx.set_upload_state(u.id, &[UploadState::Open], UploadState::Failed)
                .await?;
            tx.set_content_state(
                u.content_id,
                &[ContentState::Receiving],
                ContentState::Failed,
                Some(&r),
                now,
            )
            .await?;
            let init = tx
                .content(u.content_id)
                .await?
                .and_then(|c| c.initiating_audit_seq);
            let mut d = system_draft("content.upload.failed", Outcome::Failure)
                .target("upload", &u.id.to_string())
                .reason(code.as_str())
                .detail(Detail::new().with("content_id", &u.content_id.to_string()));
            let mut c = system_draft("content.failed", Outcome::Failure)
                .target("content", &u.content_id.to_string())
                .reason(code.as_str());
            if let Some(s) = init {
                d = d.initiated_by(s);
                c = c.initiated_by(s);
            }
            recs.push(self.append(&mut tx, &d).await?);
            recs.push(self.append(&mut tx, &c).await?);
        }
        let n = u64::try_from(recs.len() / 2).unwrap_or(u64::MAX);
        if recs.is_empty() {
            tx.rollback().await;
        } else {
            self.commit(tx, &recs).await?;
        }
        Ok(n)
    }
}

/// What [`Api::recover`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Items marked Failed.
    pub failed: Vec<ContentId>,
    /// Staging files removed.
    pub staging_removed: u64,
    /// Orphaned objects reported.
    pub orphans: u64,
}
