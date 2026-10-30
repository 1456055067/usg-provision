//! Progress schema 2 reports (M4 plan section 3.1), for steps 4 to 9.
//!
//! The same rules as the v1 [`crate::report`] queue:
//!
//! - every report gets the next sequence number, strictly increasing;
//! - state reports are queued in order and sent when the server answers;
//!   a report the server refuses outright is dropped so later ones can go;
//! - a report that must reach the server (step 6 `step_completed`, which
//!   makes the server add the boot stop and allows the resume; the final
//!   `succeeded` or `failed`) is delivered with retries, after everything
//!   queued before it.
//!
//! The post-setup runner starts its sequence at [`POSTSETUP_SEQ_BASE`]
//! (see there).

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12 (Audit Record Generation, basis) - every step
//   state change is reported so the server records it (REQ-SEQ-007).
// - NIST 800-53: SI-11 (Error Handling) - failures carry named fields
//   only.
// - SPEC: specs/workflow.md#REQ-SEQ-002, #REQ-SEQ-006, #REQ-SEQ-007

use std::collections::VecDeque;

use usgp_proto::JobId;
use usgp_proto::job_plan::RetryPolicyV1;
use usgp_proto::progress::{
    FailureV2, PROGRESS_SCHEMA_V2, ProgressAckV1, ProgressEvent, ProgressV2, StepV2,
};

use crate::clock::{Clock, Watch, backoff};
use crate::link::{LinkError, ProgressLinkV2};

/// First sequence number the post-setup runner uses, minus one.
///
/// [project rule] The plan says the sequence continues across the restart
/// (`ProgressV2::seq`), but nothing carries the last Windows PE number to
/// the runner, and `job.json` is written before step 6 reports. Windows PE
/// sends far fewer than 2^40 reports, so starting the runner above it keeps
/// the sequence strictly increasing for the server.
pub const POSTSETUP_SEQ_BASE: u64 = 1 << 40;

/// Design bound on queued state reports (a job has at most 20).
const MAX_QUEUED: usize = 32;

/// A report that must be delivered ([`ReporterV2::deliver`]).
pub(crate) struct Must {
    pub(crate) step: StepV2,
    pub(crate) event: ProgressEvent,
    pub(crate) restart_pending: Option<bool>,
    pub(crate) failure: Option<FailureV2>,
}

impl Must {
    /// `event` on `step`, with nothing else.
    pub(crate) fn event(step: StepV2, event: ProgressEvent) -> Self {
        Self {
            step,
            event,
            restart_pending: None,
            failure: None,
        }
    }

    /// `failed` on the failure's step.
    pub(crate) fn failed(f: FailureV2) -> Self {
        Self {
            step: f.step,
            event: ProgressEvent::Failed,
            restart_pending: None,
            failure: Some(f),
        }
    }
}

/// The v2 report state of one job.
pub(crate) struct ReporterV2 {
    job: JobId,
    seq: u64,
    queue: VecDeque<ProgressV2>,
    sent: Vec<ProgressV2>,
}

impl ReporterV2 {
    /// Reports for `job`, numbered from `after + 1`.
    pub(crate) fn new(job: JobId, after: u64) -> Self {
        Self {
            job,
            seq: after,
            queue: VecDeque::new(),
            sent: Vec::new(),
        }
    }

    /// Reports delivered so far, in order (no secrets).
    pub(crate) fn delivered(&self) -> &[ProgressV2] {
        &self.sent
    }

    fn make(
        &mut self,
        step: StepV2,
        event: ProgressEvent,
        restart_pending: Option<bool>,
        failure: Option<FailureV2>,
    ) -> ProgressV2 {
        self.seq = self.seq.saturating_add(1);
        ProgressV2 {
            schema: PROGRESS_SCHEMA_V2,
            seq: self.seq,
            step,
            event,
            bytes_done: None,
            bytes_total: None,
            item: None,
            layout: None,
            restart_pending,
            failure,
        }
    }

    fn push(&mut self, r: ProgressV2) {
        if self.queue.len() >= MAX_QUEUED {
            self.queue.pop_front();
        }
        self.queue.push_back(r);
    }

    /// Queues a state report and tries once to send what is queued.
    pub(crate) fn state(&mut self, link: &mut dyn ProgressLinkV2, step: StepV2, e: ProgressEvent) {
        self.state_with(link, step, e, None);
    }

    /// As [`ReporterV2::state`], with `restart_pending` (step 8
    /// `step_completed` only).
    pub(crate) fn state_with(
        &mut self,
        link: &mut dyn ProgressLinkV2,
        step: StepV2,
        e: ProgressEvent,
        restart_pending: Option<bool>,
    ) {
        let r = self.make(step, e, restart_pending, None);
        self.push(r);
        while let Some(r) = self.queue.front() {
            match link.report_v2(self.job, r) {
                Ok(_) => {
                    if let Some(r) = self.queue.pop_front() {
                        self.sent.push(r);
                    }
                }
                Err(e) if e.is_transient() => return,
                Err(_) => {
                    self.queue.pop_front();
                }
            }
        }
    }

    /// Sends everything queued, then this report, retrying transient
    /// failures by `retry` (and within `watch`, if given). Returns the
    /// server's answer to this report.
    pub(crate) fn deliver(
        &mut self,
        link: &mut dyn ProgressLinkV2,
        clock: &dyn Clock,
        retry: &RetryPolicyV1,
        watch: Option<&Watch<'_>>,
        r: Must,
    ) -> Result<ProgressAckV1, LinkError> {
        let last = self.make(r.step, r.event, r.restart_pending, r.failure);
        self.push(last);
        let mut failures: u32 = 0;
        loop {
            let Some(r) = self.queue.front() else {
                return Err(LinkError::Protocol);
            };
            let is_last = self.queue.len() == 1;
            match link.report_v2(self.job, r) {
                Ok(ack) => {
                    failures = 0;
                    if let Some(r) = self.queue.pop_front() {
                        self.sent.push(r);
                    }
                    if is_last {
                        return Ok(ack);
                    }
                }
                Err(e) if e.is_transient() => {
                    failures = failures.saturating_add(1);
                    if failures >= retry.attempts {
                        return Err(e);
                    }
                    let d = backoff(retry.base_ms, retry.max_ms, failures);
                    if let Some(w) = watch
                        && w.check_wait(d).is_err()
                    {
                        return Err(e);
                    }
                    clock.sleep(d);
                }
                Err(e) if is_last => {
                    self.queue.pop_front();
                    return Err(e);
                }
                Err(_) => {
                    self.queue.pop_front();
                }
            }
        }
    }
}
