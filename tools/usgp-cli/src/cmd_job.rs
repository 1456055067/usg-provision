//! `usgp-cli job list | show | ack`: provisioning job status (M3 plan
//! WU-13, section 3.5; REQ-JOB-001, REQ-JOB-005, REQ-JOB-006).
//!
//! A failed job shows its persistent error detail (step, category, reason
//! code, files, attempts, when) until an operator acknowledges it, and
//! after: acknowledging only clears the attention flag; the job stays
//! `failed`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-11 (Error Handling) - failure detail as the device
//   reported it, through validated types, escaped on output.
// - NIST 800-53: AU-6 (basis) - operators see job state and failures.
// - NIST 800-53: SI-10 - ids and states parsed locally.
// - SPEC: specs/progress.md#REQ-JOB-001 (status items), #REQ-JOB-002
//   (steps), #REQ-JOB-003 (percentage), #REQ-JOB-005 (persistent error),
//   #REQ-JOB-006 (failure detail, attempts, acknowledgement),
//   #REQ-JOB-009 (previous job), #REQ-JOB-012 (states)
// - SPEC: specs/disk.md#REQ-DISK-014 (disk and layout shown)

use std::io::Write;

use usgp_proto::ids::JobId;
use usgp_proto::ops::{JobList, JobView};
use usgp_proto::progress::FailureV1;
use usgp_proto::{JobState, LayoutReportV1};

use crate::client::{ApiClient, Body, ClientError, Method, Transport};
use crate::cmd_content::CmdError;
use crate::cmd_session::{macs, print_disk};
use crate::display::{esc, utc};

/// Parses a job id given on the command line.
///
/// # Errors
///
/// [`CmdError::Invalid`].
pub fn job_id(text: &str) -> Result<JobId, CmdError> {
    JobId::parse(text).map_err(|e| CmdError::Invalid(format!("ID {}: {e}", esc(text))))
}

/// Parses `--state` for `job list`.
///
/// # Errors
///
/// [`CmdError::Invalid`] naming the allowed values.
pub fn job_state(text: &str) -> Result<JobState, CmdError> {
    JobState::parse(text).ok_or_else(|| {
        CmdError::Invalid(format!(
            "--state {}: must be one of running, succeeded, failed, lost",
            esc(text)
        ))
    })
}

/// Writes a failure (REQ-JOB-006).
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_failure(
    out: &mut dyn Write,
    f: &FailureV1,
    at: Option<i64>,
    acknowledged: bool,
) -> Result<(), CmdError> {
    writeln!(
        out,
        "  FAILED at step {}: {} ({}){}",
        f.step,
        esc(f.code.as_str()),
        f.category,
        if acknowledged {
            ", acknowledged"
        } else {
            ", needs attention (acknowledge with: usgp-cli job ack ID)"
        }
    )?;
    if let Some(at) = at {
        writeln!(out, "    when:     {}", utc(at))?;
    }
    writeln!(out, "    attempts: {}", f.attempts)?;
    if f.count > 0 {
        writeln!(out, "    failed items: {}", f.count)?;
    }
    for i in &f.files {
        writeln!(out, "      {} {}", i.role, esc(i.name.as_str()))?;
    }
    let shown = u32::try_from(f.files.len()).unwrap_or(u32::MAX);
    if f.count > shown {
        writeln!(out, "      ... and {} more", f.count.saturating_sub(shown))?;
    }
    Ok(())
}

fn print_layout(out: &mut dyn Write, l: &LayoutReportV1) -> Result<(), CmdError> {
    writeln!(out, "  layout written: disk guid {}", l.disk_guid())?;
    for p in l.partitions() {
        writeln!(
            out,
            "    partition {}: {} at {} size {}{}{}",
            p.index,
            p.kind,
            p.start_bytes,
            p.size_bytes,
            p.fs.map(|f| format!(" {f}")).unwrap_or_default(),
            p.label
                .as_ref()
                .map(|x| format!(" label {}", esc(x.as_str())))
                .unwrap_or_default()
        )?;
    }
    Ok(())
}

/// Writes one job; `detail` adds the steps, disk and layout.
///
/// # Errors
///
/// [`CmdError::Output`].
pub fn print_job(out: &mut dyn Write, v: &JobView, detail: bool) -> Result<(), CmdError> {
    writeln!(out, "job {}", v.id)?;
    writeln!(out, "  state:    {}", v.state)?;
    writeln!(out, "  step:     {}", v.current_step)?;
    match (v.percent, v.bytes_done, v.bytes_total) {
        (Some(p), Some(d), Some(t)) => writeln!(out, "  progress: {p}% ({d} of {t} bytes)")?,
        (Some(p), _, _) => writeln!(out, "  progress: {p}%")?,
        _ => {}
    }
    writeln!(
        out,
        "  package:  {} revision {} edition {}",
        v.package_id,
        v.package_revision,
        v.edition_index.get()
    )?;
    writeln!(out, "  device:   {}", macs(&v.macs))?;
    writeln!(out, "  session:  {}", v.session_id)?;
    writeln!(out, "  boot service: {}", v.boot_service_id)?;
    writeln!(out, "  started:  {}", utc(v.started_at.as_micros()))?;
    if let Some(t) = v.last_report_at {
        writeln!(out, "  last report: {}", utc(t.as_micros()))?;
    }
    if let Some(t) = v.finished_at {
        writeln!(out, "  finished: {}", utc(t.as_micros()))?;
    }
    if let Some(p) = v.previous_job_id {
        writeln!(out, "  previous job: {p}")?;
    }
    if let Some(f) = &v.failure {
        print_failure(out, f, v.failed_at.map(|t| t.as_micros()), v.acknowledged)?;
    } else if v.state == JobState::Failed {
        // A failed job without detail is shown as such, never as healthy.
        writeln!(
            out,
            "  FAILED (no detail recorded){}",
            if v.acknowledged {
                ", acknowledged"
            } else {
                ", needs attention"
            }
        )?;
    }
    if detail {
        writeln!(out, "  attempts in this step: {}", v.attempts)?;
        writeln!(out, "  steps:")?;
        for s in &v.steps {
            write!(out, "    {} {}", s.step, s.state)?;
            if let Some(t) = s.started_at {
                write!(out, " started {}", utc(t.as_micros()))?;
            }
            if let Some(t) = s.finished_at {
                write!(out, " finished {}", utc(t.as_micros()))?;
            }
            writeln!(out)?;
        }
        print_disk(out, "  ", &v.disk)?;
        if let Some(l) = &v.layout {
            print_layout(out, l)?;
        }
    }
    Ok(())
}

/// `job list [--state S]`.
///
/// # Errors
///
/// [`CmdError`].
pub fn list<T: Transport>(
    api: &mut ApiClient<T>,
    state: Option<&str>,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let state = state.map(job_state).transpose()?;
    let path = match state {
        Some(s) => format!("/v1/jobs?state={s}"),
        None => "/v1/jobs".to_owned(),
    };
    let raw = api.get(path)?;
    let list: JobList = parse_json!(raw)?;
    if let Some(s) = state
        && list.jobs.iter().any(|j| j.state != s)
    {
        return Err(ClientError::BadResponse("the server returned jobs in another state").into());
    }
    if list.jobs.is_empty() {
        writeln!(out, "no jobs")?;
    }
    for v in &list.jobs {
        print_job(out, v, false)?;
    }
    Ok(())
}

fn one(raw: &crate::client::Raw, id: JobId) -> Result<JobView, CmdError> {
    let v: JobView = parse_json!(raw)?;
    if v.id != id {
        return Err(ClientError::BadResponse("the server returned a different job").into());
    }
    Ok(v)
}

/// `job show ID`.
///
/// # Errors
///
/// [`CmdError`].
pub fn show<T: Transport>(
    api: &mut ApiClient<T>,
    id: JobId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let raw = api.get(format!("/v1/jobs/{id}"))?;
    print_job(out, &one(&raw, id)?, true)
}

/// `job ack ID`: acknowledges a failed job's error (the state stays
/// `failed`).
///
/// # Errors
///
/// [`CmdError`].
pub fn ack<T: Transport>(
    api: &mut ApiClient<T>,
    id: JobId,
    out: &mut dyn Write,
) -> Result<(), CmdError> {
    let raw = api.call(
        Method::Post,
        format!("/v1/jobs/{id}/acknowledge"),
        None,
        Body::Empty,
    )?;
    let v = one(&raw, id)?;
    writeln!(out, "acknowledged job {id}")?;
    print_job(out, &v, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::fake::{FakeTransport, Scripted};

    const JOB: &str = "8a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6";

    /// A failed job from JSON (the view types have private parts that
    /// only deserialisation builds).
    fn failed_job(acknowledged: bool) -> Vec<u8> {
        let disk = serde_json::json!({
            "disk_token": "00112233445566778899aabbccddeeff",
            "bus": "nvme",
            "model": "Disk 1",
            "serial": "S1",
            "size_bytes": 128_000_000_000u64,
            "logical_sector": 512,
            "physical_sector": 4096,
            "removable": false,
            "partitions": []
        });
        let v = serde_json::json!({
            "id": JOB,
            "session_id": "6a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
            "boot_service_id": "9a1e2f3a-4b5c-4d6e-8f70-8192a3b4c5d6",
            "package_id": "1c9e8a70-2b3d-4e5f-9a0b-c1d2e3f40516",
            "package_revision": 3,
            "edition_index": 2,
            "macs": ["02:00:00:00:00:01"],
            "disk": disk,
            "state": "failed",
            "current_step": 1,
            "steps": [{"step": 1, "kind": "verify_content", "state": "failed"}],
            "failure": {
                "step": 1,
                "category": "integrity",
                "code": "chunk_digest_mismatch",
                "files": [{"role": "image", "name": "install.wim\u{202e}x"}],
                "count": 3,
                "attempts": 1
            },
            "failed_at": 1_793_097_001_000_000i64,
            "attempts": 1,
            "acknowledged": acknowledged,
            "started_at": 1_793_097_000_000_000i64
        });
        serde_json::to_vec(&v).unwrap()
    }

    #[test]
    fn show_has_persistent_failure_detail_escaped() {
        let body = failed_job(false);
        // The test JSON must match the current wire types.
        let parsed: Result<JobView, _> = serde_json::from_slice(&body);
        assert!(parsed.is_ok(), "{:?}", parsed.err());
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Get,
            &format!("/v1/jobs/{JOB}"),
            Scripted::bytes(200, body),
        ));
        let mut out = Vec::new();
        show(&mut api, job_id(JOB).unwrap(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("state:    failed"), "{text}");
        assert!(
            text.contains("FAILED at step 1 (verify_content): chunk_digest_mismatch (integrity), needs attention"),
            "{text}"
        );
        assert!(
            text.contains("when:     2026-10-27T10:30:01.000000Z"),
            "{text}"
        );
        assert!(text.contains("failed items: 3"), "{text}");
        assert!(text.contains("... and 2 more"), "{text}");
        // Bidirectional overrides (allowed in item names) are escaped.
        assert!(text.contains("install.wim\\u{202e}x"), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
    }

    #[test]
    fn ack_keeps_failure_visible() {
        let mut api = ApiClient::new(FakeTransport::default().expect(
            Method::Post,
            &format!("/v1/jobs/{JOB}/acknowledge"),
            Scripted::bytes(200, failed_job(true)),
        ));
        let mut out = Vec::new();
        ack(&mut api, job_id(JOB).unwrap(), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("acknowledged job {JOB}")), "{text}");
        assert!(
            text.contains("chunk_digest_mismatch (integrity), acknowledged"),
            "{text}"
        );
        assert!(api.transport().seen.first().unwrap().body.is_empty());
    }

    #[test]
    fn list_state_checked_locally_and_in_response() {
        let mut api = ApiClient::new(FakeTransport::default());
        assert!(matches!(
            list(&mut api, Some("done"), &mut Vec::new()),
            Err(CmdError::Invalid(_))
        ));
        assert!(api.transport().seen.is_empty());
        let body = format!(
            "{{\"jobs\":[{}]}}",
            String::from_utf8(failed_job(false)).unwrap()
        );
        let mut api = ApiClient::new(
            FakeTransport::default()
                .expect(
                    Method::Get,
                    "/v1/jobs?state=failed",
                    Scripted::bytes(200, body.clone().into_bytes()),
                )
                .expect(
                    Method::Get,
                    "/v1/jobs?state=running",
                    Scripted::bytes(200, body.into_bytes()),
                ),
        );
        let mut out = Vec::new();
        list(&mut api, Some("failed"), &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("needs attention"));
        assert!(matches!(
            list(&mut api, Some("running"), &mut Vec::new()),
            Err(CmdError::Client(ClientError::BadResponse(_)))
        ));
    }
}
