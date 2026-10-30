//! Step 4, `add_drivers` (M4 plan §1.4; decision 0024 item 4).
//!
//! 1. The offline volume's driver list is read before anything is added.
//! 2. For each archive, in plan order:
//!    - every chunk is fetched again and verified against the signed
//!      content manifest, and the whole file's SHA-256 against the plan
//!      (REQ-DRV-008: a tampered chunk fails before extraction);
//!    - the archive is extracted with `usgp-wincfg`'s bounded reader into
//!      its own folder `$usgp-stage\drv\<i>` (a path built from the index
//!      only);
//!    - the INF list re-derived from the extracted archive must equal the
//!      plan's;
//!    - DISM adds the folder (`/Add-Driver /Recurse`, never
//!      `/ForceUnsigned`); a non-zero exit fails the step.
//! 3. The driver list is read again. For every INF of every archive, a
//!    driver new since step 1 must have that original file name
//!    (case-insensitive). A missing one fails the step
//!    (`driver_not_staged`, decision 0025: fail closed for OPEN-DRVS-2).
//! 4. The staging root is removed and its absence checked, on success and
//!    on failure. If it cannot be removed, the step fails
//!    (`staging_not_removed`).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7, SI-7(1) (Integrity Checks) - archive re-verified
//   chunk by chunk before extraction.
// - NIST 800-53: SI-10 (Information Input Validation) - bounded archive
//   reader and bounded DISM listing parser.
// - NIST 800-53: CM-7, CM-7(5) - signed drivers only (no
//   `/ForceUnsigned`); every expected INF proven staged.
// - NIST 800-53: SC-4 (Information in Shared System Resources) - nothing
//   left on the target: staging removed and the removal verified.
// - SPEC: specs/drivers.md#REQ-DRV-004, #REQ-DRV-007, #REQ-DRV-008,
//   #REQ-DRV-010
// - DECISION: docs/decisions/0024 item 4, 0025

use std::collections::BTreeSet;

use usgp_proto::codes;
use usgp_proto::content_manifest::ContentManifestV2;
use usgp_proto::job_plan::PlanDriverV2;
use usgp_proto::progress::{FailureCategory, StepV2};
use usgp_wincfg::archive::{ArchiveLimits, extract_archive};
use usgp_wincfg::dism::parse_driver_table;

use super::{StepCtx, chunk_failure, local, platform_failure, time_check};
use crate::content::VerifiedChunks;
use crate::error::{JobFailureV2, code, code_of, code_with};
use crate::link::ServerLink;
use crate::platform::{Platform, StagePath};

const STEP: StepV2 = StepV2::ADD_DRIVERS;

/// Bounds for step 4.
#[derive(Debug, Clone)]
pub struct DriverStepConfig {
    /// Bounds for extracting one archive (the same rules as the server's
    /// upload check).
    pub archive_limits: ArchiveLimits,
    /// Largest archive held in memory between verification and
    /// extraction, in bytes.
    // POAM: archives are re-verified into memory (nothing is cached on the
    // target before extraction), so this bound is below the server's
    // `drivers.max_archive_bytes`; larger archives fail step 4 with
    // `driver_extract_refused:<archive>:limit_exceeded`.
    pub max_archive_bytes: u64,
}

impl Default for DriverStepConfig {
    fn default() -> Self {
        Self {
            archive_limits: ArchiveLimits::default(),
            max_archive_bytes: 1 << 30,
        }
    }
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

fn add_all(
    ctx: &StepCtx<'_>,
    archives: &[DriverArchive<'_>],
    config: &DriverStepConfig,
    platform: &mut dyn Platform,
    link: &mut dyn ServerLink,
) -> Result<DriverCheck, JobFailureV2> {
    if archives.is_empty() {
        return Ok(DriverCheck {
            archives: 0,
            infs: 0,
            new_drivers: 0,
        });
    }
    let before = listing(platform)?;
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

        // Re-verify every chunk and the whole file (REQ-DRV-008).
        if a.manifest.sha256 != a.plan.content_sha256 {
            return Err(JobFailureV2::new(
                STEP,
                FailureCategory::Integrity,
                codes::CONTENT_MANIFEST_MISMATCH,
                format!("driver archive {}: manifest does not match the plan", i + 1),
            ));
        }
        if a.manifest.size > config.max_archive_bytes {
            return Err(refused(
                "limit_exceeded",
                format!(
                    "driver archive {} is larger than {} bytes",
                    i + 1,
                    config.max_archive_bytes
                ),
            ));
        }
        let bytes = {
            let mut src = VerifiedChunks::for_archive(
                &mut *link, ctx.crypto, ctx.clock, ctx.job, ctx.retry, a.manifest,
            )
            .with_watch(ctx.watch);
            src.read_all(config.max_archive_bytes)
                .map_err(|c| chunk_failure(STEP, &format!("driver archive {}", i + 1), c))?
        };
        time_check(STEP, ctx.watch)?;

        // Extract into this archive's own folder.
        let stage = StagePath::driver(index);
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let report = {
            let mut sink = platform
                .stage_sink(&stage)
                .map_err(|e| platform_failure(STEP, code_of(code::CONFIG_WRITE_FAILED), e))?;
            extract_archive(&bytes.as_slice(), len, &config.archive_limits, &mut *sink).map_err(
                |e| {
                    refused(
                        e.reason(),
                        format!("driver archive {} refused at extraction: {e}", i + 1),
                    )
                },
            )?
        };
        drop(bytes);
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
        time_check(STEP, ctx.watch)?;
    }

    // Every expected INF must now be in the image (REQ-DRV-010).
    let after = listing(platform)?;
    let new: Vec<&String> = after.difference(&before).map(|(_, o)| o).collect();
    let mut infs = 0usize;
    for (i, a) in archives.iter().enumerate() {
        for inf in &a.plan.infs {
            let name = inf_file_name(inf.as_str());
            if !new.iter().any(|o| **o == name) {
                return Err(JobFailureV2::new(
                    STEP,
                    FailureCategory::Refused,
                    code_with(
                        &codes::DRIVER_NOT_STAGED,
                        &[&a.plan.archive_id.to_string(), &name],
                    ),
                    format!(
                        "driver archive {}: a driver package was not added to the image ({name})",
                        i + 1
                    ),
                ));
            }
            infs = infs.saturating_add(1);
        }
    }
    Ok(DriverCheck {
        archives: archives.len(),
        infs,
        new_drivers: new.len(),
    })
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
