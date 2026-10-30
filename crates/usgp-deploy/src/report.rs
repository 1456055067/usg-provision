//! Progress reports to the server (plan section 3.4).
//!
//! - Every report gets the next sequence number (from 1, strictly
//!   increasing).
//! - State reports (`step_started`, `step_completed`) are queued in order
//!   and never dropped while the queue has room; a report the server
//!   refuses outright is dropped so later ones can go.
//! - `progress` reports keep only the latest and are sent at most once per
//!   `report_interval_s`, and only when no state report is waiting.
//! - A report that cannot be sent stays queued: the step goes on
//!   (REQ-DISK-012: partitioning does not depend on the network) and the
//!   queue is sent when the server answers again.
//! - The final report (`succeeded` or `failed`) is delivered with retries,
//!   after everything queued before it.

// COMPLIANCE MAPPING:
// - NIST 800-53: AU-12 (Audit Record Generation, basis) - every state
//   change is reported so the server records it (plan section 7).
// - NIST 800-53: SI-11 (Error Handling) - failures reported with their
//   named fields only.
// - SPEC: specs/progress.md#REQ-JOB-002, #REQ-JOB-003, #REQ-JOB-006,
//   #REQ-JOB-007, #REQ-JOB-013; specs/disk.md#REQ-DISK-012, #REQ-DISK-014

use std::collections::VecDeque;
use std::time::Duration;

use usgp_proto::JobId;
use usgp_proto::disk::LayoutReportV1;
use usgp_proto::job_plan::RetryPolicyV1;
use usgp_proto::progress::{
    FailureV1, ProgressAckV1, ProgressEvent, ProgressItemV1, ProgressV1, Step,
};

use crate::clock::{Clock, Watch, backoff};
use crate::link::{LinkError, ServerLink};

/// Design bound on queued state reports. A job has at most 10 state
/// reports, so this is never reached in practice; past it the oldest is
/// dropped (the server keeps the latest state, plan section 3.4).
const MAX_QUEUED: usize = 32;

/// The report state of one job.
pub(crate) struct Reporter {
    job: JobId,
    seq: u64,
    queue: VecDeque<ProgressV1>,
    progress: Option<ProgressV1>,
    last_progress_sent: Option<Duration>,
    interval: Duration,
    sent: Vec<ProgressV1>,
}

impl Reporter {
    pub(crate) fn new(job: JobId, interval: Duration) -> Self {
        Self {
            job,
            seq: 0,
            queue: VecDeque::new(),
            progress: None,
            last_progress_sent: None,
            interval,
            sent: Vec::new(),
        }
    }

    /// Reports delivered so far, in order (kept for the caller's record;
    /// they carry no secrets).
    pub(crate) fn delivered(&self) -> &[ProgressV1] {
        &self.sent
    }

    fn report(
        &mut self,
        step: Step,
        event: ProgressEvent,
        layout: Option<LayoutReportV1>,
        failure: Option<FailureV1>,
    ) -> ProgressV1 {
        self.seq = self.seq.saturating_add(1);
        ProgressV1 {
            seq: self.seq,
            step,
            event,
            bytes_done: None,
            bytes_total: None,
            item: None,
            layout,
            failure,
        }
    }

    /// Ends this reporter for a v2 job's hand-over to the v2 reporter (M4
    /// plan WU-7a item 3): the last sequence number used, the state
    /// reports not yet sent, and the reports delivered. A pending byte
    /// progress report is dropped.
    pub(crate) fn hand_off(&mut self) -> (u64, Vec<ProgressV1>, Vec<ProgressV1>) {
        self.progress = None;
        (
            self.seq,
            self.queue.drain(..).collect(),
            std::mem::take(&mut self.sent),
        )
    }

    /// Queues a state report and tries once to send what is queued.
    pub(crate) fn state(
        &mut self,
        link: &mut dyn ServerLink,
        step: Step,
        event: ProgressEvent,
        layout: Option<LayoutReportV1>,
    ) {
        let r = self.report(step, event, layout, None);
        if self.queue.len() >= MAX_QUEUED {
            self.queue.pop_front();
        }
        self.queue.push_back(r);
        // A superseded progress report is no longer worth sending.
        self.progress = None;
        self.flush_once(link);
    }

    /// Records the latest byte counts; sends them if the interval has
    /// passed and nothing else is waiting.
    pub(crate) fn progress(
        &mut self,
        link: &mut dyn ServerLink,
        now: Duration,
        step: Step,
        done: u64,
        total: u64,
        item: Option<ProgressItemV1>,
    ) {
        let mut r = self.report(step, ProgressEvent::Progress, None, None);
        r.bytes_total = Some(total);
        r.bytes_done = Some(done.min(total));
        r.item = item;
        self.progress = Some(r);
        let due = self
            .last_progress_sent
            .is_none_or(|t| now.saturating_sub(t) >= self.interval);
        if due {
            self.last_progress_sent = Some(now);
            self.flush_once(link);
        }
    }

    /// One attempt at each waiting report, in order; stops at the first
    /// transient failure. Returns `true` if nothing is left.
    fn flush_once(&mut self, link: &mut dyn ServerLink) -> bool {
        while let Some(r) = self.queue.front() {
            match link.report(self.job, r) {
                Ok(_) => {
                    if let Some(r) = self.queue.pop_front() {
                        self.sent.push(r);
                    }
                }
                Err(e) if e.is_transient() => return false,
                // Refused or malformed: drop it so later reports can go.
                Err(_) => {
                    self.queue.pop_front();
                }
            }
        }
        if let Some(r) = self.progress.take() {
            match link.report(self.job, &r) {
                Ok(_) => self.sent.push(r),
                Err(e) if e.is_transient() => {
                    self.progress = Some(r);
                    return false;
                }
                Err(_) => {}
            }
        }
        true
    }

    /// Sends everything queued, then `succeeded` (`failure` is `None`) or
    /// `failed`, retrying transient failures by `retry`. Returns the
    /// server's answer to the final report.
    pub(crate) fn finish(
        &mut self,
        link: &mut dyn ServerLink,
        clock: &dyn Clock,
        retry: &RetryPolicyV1,
        watch: Option<&Watch<'_>>,
        step: Step,
        failure: Option<FailureV1>,
    ) -> Result<ProgressAckV1, LinkError> {
        let event = if failure.is_some() {
            ProgressEvent::Failed
        } else {
            ProgressEvent::Succeeded
        };
        // Progress counts no longer matter.
        self.progress = None;
        let last = self.report(step, event, None, failure);
        if self.queue.len() >= MAX_QUEUED {
            self.queue.pop_front();
        }
        self.queue.push_back(last);
        let mut failures: u32 = 0;
        loop {
            let Some(r) = self.queue.front() else {
                return Err(LinkError::Protocol);
            };
            let is_last = self.queue.len() == 1;
            match link.report(self.job, r) {
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
                Err(e) if is_last => return Err(e),
                Err(_) => {
                    self.queue.pop_front();
                }
            }
        }
    }
}
