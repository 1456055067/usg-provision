//! Step 4, `add_drivers` (M4 plan §1.4, WU-7a items 4 and 7; decision
//! 0024 item 4).
//!
//! 1. The offline volume's driver list is read before anything is added.
//! 2. For each archive, in plan order:
//!    - every chunk is fetched again, verified against the signed content
//!      manifest, and only then appended to the staged file
//!      `$usgp-stage\arc\<i>.bin`; the whole file's SHA-256 is checked
//!      against the manifest at the end (REQ-DRV-008: a tampered chunk
//!      fails before extraction, and nothing unverified is written);
//!    - the archive is extracted from that file with `usgp-wincfg`'s
//!      bounded reader into its own folder `$usgp-stage\drv\<i>` (paths
//!      built from the index only), hashing every INF on the way;
//!    - the INF list re-derived from the extracted archive must equal the
//!      plan's;
//!    - DISM adds the folder (`/Add-Driver /Recurse`, never
//!      `/ForceUnsigned`); a non-zero exit fails the step;
//!    - the driver list is read again. Each expected INF must be matched
//!      by a row new in **this archive's** listing difference with the
//!      same original file name (case-insensitive), or by a row an earlier
//!      archive of this job added for an INF with the same SHA-256 (DISM
//!      skips an identical package). Anything else fails the step
//!      (`driver_not_staged`, decision 0025: fail closed for OPEN-DRVS-2),
//!      with this archive's new listing rows in the failure text.
//! 3. The staging root is removed and its absence checked, on success and
//!    on failure. If it cannot be removed, the step fails
//!    (`staging_not_removed`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) (Integrity Checks) - archive re-verified
//   chunk by chunk before each write and as a whole before extraction.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded archive
//   reader and bounded DISM listing parser.
// - NIST 800-53: CM-7, CM-7(5) - signed drivers only (no
//   `/ForceUnsigned`); every expected INF proven staged, per archive.
// - NIST 800-53: SC-4 (Information in Shared System Resources) - nothing
//   left on the target: staging removed and the removal verified.
// - SPEC: specs/drivers.md#REQ-DRV-004, #REQ-DRV-007, #REQ-DRV-008,
//   #REQ-DRV-010
// - DECISION: docs/decisions/0024 item 4, 0025

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use usgp_common::Sha256Digest;
use usgp_crypto::Sha256Hasher;
use usgp_proto::codes;
use usgp_proto::content_manifest::ContentManifestV2;
use usgp_proto::job_plan::PlanDriverV2;
use usgp_proto::progress::{FailureCategory, StepV2};
use usgp_wincfg::archive::{
    ArchiveLimits, ArchiveMode, ExtractSink, RelPath as ArcPath, extract_archive_mode,
};
use usgp_wincfg::dism::parse_driver_table;

use super::{StepCtx, chunk_failure, local, platform_failure, time_check};
use crate::content::{StreamError, VerifiedChunks};
use crate::error::{JobFailureV2, code, code_of, code_with};
use crate::link::ServerLink;
use crate::platform::{Platform, StagePath, StagedArchive};

const STEP: StepV2 = StepV2::ADD_DRIVERS;

/// Bounds for step 4.
#[derive(Debug, Clone, Default)]
pub struct DriverStepConfig {
    /// Bounds for extracting one archive (the same rules as the server's
    /// upload check, M4 plan §1.5). Archives are staged to a file, so no
    /// in-memory bound applies (WU-7a item 4).
    pub archive_limits: ArchiveLimits,
}

/// One driver archive of the verified plan, with its verified manifest.
#[derive(Debug, Clone, Copy)]
pub struct DriverArchive<'p> {
    /// The plan entry.
    pub plan: &'p PlanDriverV2,
    /// Its signed content manifest, verified with the plan.
    pub manifest: &'p ContentManifestV2,
}

/// What step 4 checked (counts only; reported as `job.drivers.checked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverCheck {
    /// Archives added.
    pub archives: usize,
    /// INF packages proven staged.
    pub infs: usize,
    /// Drivers in the listing after the step that were not there before.
    pub new_drivers: usize,
    /// INFs satisfied by a row an earlier archive added for an identical
    /// INF (same SHA-256), because DISM skipped the duplicate.
    pub reused: usize,
}

/// The last segment of a `/`-separated relative path, lower case.
fn inf_file_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_lowercase()
}

/// Original file names (lower case) of the drivers in a listing, keyed by
/// published name.
fn listing(platform: &mut dyn Platform) -> Result<BTreeSet<(String, String)>, JobFailureV2> {
    let text = platform
        .dism_list_drivers()
        .map_err(|e| platform_failure(STEP, code_of(code::DRIVER_LIST_FAILED), e))?;
    let rows = parse_driver_table(&text).map_err(|e| {
        local(
            STEP,
            code_of(code::DRIVER_LIST_FAILED),
            format!("driver listing refused: {e}"),
        )
    })?;
    Ok(rows
        .into_iter()
        .map(|r| {
            (
                r.published_name.to_lowercase(),
                r.original_file_name.to_lowercase(),
            )
        })
        .collect())
}

/// Runs step 4 after its start report. The staging root is removed and
/// its absence checked whatever the outcome.
///
/// # Errors
///
/// [`JobFailureV2`] for step 4.
pub fn add_drivers(
    ctx: &StepCtx<'_>,
    archives: &[DriverArchive<'_>],
    config: &DriverStepConfig,
    platform: &mut dyn Platform,
    link: &mut dyn ServerLink,
) -> Result<DriverCheck, JobFailureV2> {
    let result = add_all(ctx, archives, config, platform, link);
    let cleanup = remove_staging(platform);
    match (result, cleanup) {
        (Ok(check), Ok(())) => Ok(check),
        // The first failure is the one named; the staging failure is in
        // the message so the person sees both.
        (Err(mut f), Err(c)) => {
            f.message = format!("{}; also: {}", f.message, c.message);
            Err(f)
        }
        (Err(f), Ok(())) | (Ok(_), Err(f)) => Err(f),
    }
}

/// Removes the staging root, then checks it is gone.
fn remove_staging(platform: &mut dyn Platform) -> Result<(), JobFailureV2> {
    let not_removed = |why: String| {
        local(
            STEP,
            codes::STAGING_NOT_REMOVED,
            format!("the driver staging folder could not be removed ({why})"),
        )
    };
    platform
        .remove_staging()
        .map_err(|e| not_removed(e.to_string()))?;
    match platform.staging_exists() {
        Ok(false) => Ok(()),
        Ok(true) => Err(not_removed("it is still present".to_owned())),
        Err(e) => Err(not_removed(e.to_string())),
    }
}

/// An extraction sink that passes everything on and keeps the SHA-256 of
/// every `.inf` file, keyed by its path in the archive.
struct InfHashes<'s> {
    inner: &'s mut dyn ExtractSink,
    current: Option<(String, Sha256Hasher)>,
    hashes: BTreeMap<String, Sha256Digest>,
    make: &'s dyn Fn() -> Sha256Hasher,
}

impl ExtractSink for InfHashes<'_> {
    fn create_dir(&mut self, path: &ArcPath) -> io::Result<()> {
        self.inner.create_dir(path)
    }

    fn begin_file(&mut self, path: &ArcPath, size: u64) -> io::Result<()> {
        let is_inf = path
            .file_name()
            .rsplit_once('.')
            .is_some_and(|(_, e)| e.eq_ignore_ascii_case("inf"));
        self.current = is_inf.then(|| (path.as_str().to_owned(), (self.make)()));
        self.inner.begin_file(path, size)
    }

    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some((_, h)) = self.current.as_mut() {
            h.update(data);
        }
        self.inner.write(data)
    }

    fn end_file(&mut self) -> io::Result<()> {
        if let Some((p, h)) = self.current.take() {
            self.hashes.insert(p, h.finish());
        }
        self.inner.end_file()
    }
}

/// A row one of this job's archives added: its original file name (lower
/// case) and the SHA-256 of the INF it was matched to.
struct Added {
    name: String,
    sha256: Sha256Digest,
}

/// The new rows of one archive, for the failure text (bounded by the
/// failure message limit).
fn delta_text(delta: &[&(String, String)]) -> String {
    if delta.is_empty() {
        return "no new drivers".to_owned();
    }
    let rows: Vec<String> = delta.iter().map(|(p, o)| format!("{p}={o}")).collect();
    format!("new drivers: {}", rows.join(", "))
}

fn add_all(
    ctx: &StepCtx<'_>,
    archives: &[DriverArchive<'_>],
    config: &DriverStepConfig,
    platform: &mut dyn Platform,
    link: &mut dyn ServerLink,
) -> Result<DriverCheck, JobFailureV2> {
    let mut check = DriverCheck {
        archives: 0,
        infs: 0,
        new_drivers: 0,
        reused: 0,
    };
    if archives.is_empty() {
        return Ok(check);
    }
    let mut before = listing(platform)?;
    let mut added: Vec<Added> = Vec::new();
    for (i, a) in archives.iter().enumerate() {
        let id = a.plan.archive_id.to_string();
        let index = u16::try_from(i).map_err(|_| {
            local(
                STEP,
                codes::DRIVER_EXTRACT_REFUSED,
                "too many driver archives",
            )
        })?;
        let refused = |reason: &str, msg: String| {
            JobFailureV2::new(
                STEP,
                FailureCategory::Refused,
                code_with(&codes::DRIVER_EXTRACT_REFUSED, &[&id, reason]),
                msg,
            )
        };

        // Re-verify every chunk before it is written, and the whole file
        // (REQ-DRV-008; WU-7a item 4).
        if a.manifest.sha256 != a.plan.content_sha256 {
            return Err(JobFailureV2::new(
                STEP,
                FailureCategory::Integrity,
                codes::CONTENT_MANIFEST_MISMATCH,
                format!("driver archive {}: manifest does not match the plan", i + 1),
            ));
        }
        let mut file = platform
            .stage_archive_file(&StagedArchive::driver(index))
            .map_err(|e| platform_failure(STEP, code_of(code::CONFIG_WRITE_FAILED), e))?;
        let len = {
            let mut src = VerifiedChunks::for_archive(
                &mut *link, ctx.crypto, ctx.clock, ctx.job, ctx.retry, a.manifest,
            )
            .with_watch(ctx.watch);
            src.stream_to(&mut |c| file.append(c))
                .map_err(|e| match e {
                    StreamError::Chunk(c) => {
                        chunk_failure(STEP, &format!("driver archive {}", i + 1), c)
                    }
                    StreamError::Write(e) => local(
                        STEP,
                        code_of(code::CONFIG_WRITE_FAILED),
                        format!(
                            "driver archive {} could not be staged ({})",
                            i + 1,
                            e.kind()
                        ),
                    ),
                })?
        };
        file.finish().map_err(|e| {
            local(
                STEP,
                code_of(code::CONFIG_WRITE_FAILED),
                format!(
                    "driver archive {} could not be staged ({})",
                    i + 1,
                    e.kind()
                ),
            )
        })?;
        time_check(STEP, ctx.watch)?;

        // Extract from the staged file into this archive's own folder.
        let stage = StagePath::driver(index);
        let make = || ctx.crypto.sha256_hasher();
        let (report, inf_sha) = {
            let mut sink = platform
                .stage_sink(&stage)
                .map_err(|e| platform_failure(STEP, code_of(code::CONFIG_WRITE_FAILED), e))?;
            let mut tee = InfHashes {
                inner: &mut *sink,
                current: None,
                hashes: BTreeMap::new(),
                make: &make,
            };
            let r = extract_archive_mode(
                &*file,
                len,
                &config.archive_limits,
                ArchiveMode::DriverPackages,
                &mut tee,
            )
            .map_err(|e| {
                refused(
                    e.reason(),
                    format!("driver archive {} refused at extraction: {e}", i + 1),
                )
            })?;
            (r, tee.hashes)
        };
        drop(file);
        let mut found: Vec<&str> = report.infs.iter().map(|p| p.as_str()).collect();
        let mut want: Vec<&str> = a.plan.infs.iter().map(|p| p.as_str()).collect();
        found.sort_unstable();
        want.sort_unstable();
        if found != want {
            return Err(refused(
                "inf_list_mismatch",
                format!(
                    "driver archive {}: the INF packages found ({}) differ from the plan ({})",
                    i + 1,
                    found.len(),
                    want.len()
                ),
            ));
        }
        time_check(STEP, ctx.watch)?;

        // DISM, one call per archive (no `/ForceUnsigned`, REQ-DRV-007).
        let out = platform
            .dism_add_driver(&stage)
            .map_err(|e| platform_failure(STEP, codes::DRIVER_ADD_FAILED, e))?;
        if out.exit_code != 0 {
            return Err(JobFailureV2::new(
                STEP,
                FailureCategory::Local,
                code_with(
                    &codes::DRIVER_ADD_FAILED,
                    &[&id, &out.exit_code.to_string()],
                ),
                format!(
                    "adding driver archive {} failed (exit {}); log: {}",
                    i + 1,
                    out.exit_code,
                    out.log_tail
                ),
            ));
        }

        // This archive's INFs must be in its own listing difference, or
        // be identical to one an earlier archive of ours added
        // (REQ-DRV-010; WU-7a item 7).
        let after = listing(platform)?;
        let delta: Vec<&(String, String)> = after.difference(&before).collect();
        let mut matched = Vec::new();
        for inf in &a.plan.infs {
            let name = inf_file_name(inf.as_str());
            let sha = inf_sha.get(inf.as_str()).copied();
            if delta.iter().any(|(_, o)| *o == name) {
                if let Some(sha256) = sha {
                    matched.push(Added {
                        name: name.clone(),
                        sha256,
                    });
                }
            } else if sha.is_some_and(|d| added.iter().any(|x| x.name == name && x.sha256 == d)) {
                check.reused = check.reused.saturating_add(1);
            } else {
                return Err(JobFailureV2::new(
                    STEP,
                    FailureCategory::Refused,
                    code_with(&codes::DRIVER_NOT_STAGED, &[&id, &name]),
                    format!(
                        "driver archive {}: a driver package was not added to the image ({name}); {}",
                        i + 1,
                        delta_text(&delta)
                    ),
                ));
            }
            check.infs = check.infs.saturating_add(1);
        }
        added.extend(matched);
        check.new_drivers = check.new_drivers.saturating_add(delta.len());
        check.archives = check.archives.saturating_add(1);
        before = after;
        time_check(STEP, ctx.watch)?;
    }
    Ok(check)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inf_names_are_last_segment_lower_case() {
        assert_eq!(inf_file_name("Net/Intel/E1000.INF"), "e1000.inf");
        assert_eq!(inf_file_name("a.inf"), "a.inf");
    }
}
