//! The device listener (plan M3 section 3.1): the session protocol the
//! pre-boot agent speaks, on its own TLS listener with server
//! authentication only (`usgp_crypto::tls::DeviceServerTls`; devices hold
//! no certificate, decision 0020).
//!
//! - [`routes`]: the device route table.
//! - [`router`]: per-request pipeline (route, bearer session, handler,
//!   audit).
//! - [`auth`]: bearer-token sessions, bound to one session, with expiry.
//! - `handlers`, `confirm`, `job`, `offer`: the routes.
//! - [`limits`]: settings and per-source rate limits.
//! - [`server`]: the accept loop.
//!
//! The device's credential is the operator-issued code or the operator's
//! approval (decision 0020 item 3). Until a session is authorised it gets
//! no package list, plan or content (REQ-TGT-013 to 015). Every
//! state-changing route writes its audit record in the same transaction
//! as the change (decision 0015 item 1, 0018 item 10).

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-3, IA-2 - bearer session on every route but open;
//   nothing listed before authorisation.
// - NIST 800-53: AU-2, AU-3, AU-12 - device choices and job state changes
//   audited (decision 0018 item 10).
// - NIST 800-53: SC-5 - per-source rate limits; chunk concurrency per job.
// - SPEC: specs/targeting.md#REQ-TGT-012 to #REQ-TGT-016
// - Decisions 0018, 0020

pub mod auth;
mod confirm;
mod handlers;
mod job;
pub mod limits;
mod offer;
pub mod router;
pub mod routes;
pub mod server;

use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError};

use usgp_proto::{BootServiceId, JobId};

use crate::context::AlarmGate;
use limits::{DeviceConfig, PerSourceRate};

pub use limits::JobSettings;
pub use server::serve_device;

/// Most job/pass pairs remembered for "one `job.content.read` per pass".
/// Beyond it the set is cleared, which at worst writes one more record.
const MAX_CONTENT_READS_TRACKED: usize = 65_536;

/// In-memory state of the device routes (rate windows, chunk slots, read
/// records already written). Lost at restart, which only means an extra
/// read record or a fresh rate window.
#[derive(Debug)]
pub(crate) struct DeviceState {
    /// Session opens per source.
    pub(crate) opens: PerSourceRate,
    /// Code attempts per source.
    pub(crate) code_attempts: PerSourceRate,
    /// Chunk requests in progress per job.
    chunk_slots: Mutex<HashMap<JobId, usize>>,
    /// (job, step) pairs whose `job.content.read` record exists.
    content_reads: Mutex<HashSet<(JobId, u8)>>,
    /// Rate gates for `boot_policy.read` records of 304 answers.
    pub(crate) policy_reads: Mutex<HashMap<BootServiceId, AlarmGate>>,
}

impl DeviceState {
    pub(crate) fn new(c: &DeviceConfig) -> Self {
        Self {
            opens: PerSourceRate::new(c.session_opens_per_ip_per_min),
            code_attempts: PerSourceRate::new(c.code_attempts_per_ip_per_min),
            chunk_slots: Mutex::new(HashMap::new()),
            content_reads: Mutex::new(HashSet::new()),
            policy_reads: Mutex::new(HashMap::new()),
        }
    }

    /// A chunk slot for `job`, or `None` if `max` requests are in
    /// progress for it.
    pub(crate) fn chunk_slot(&self, job: JobId, max: usize) -> Option<ChunkSlot<'_>> {
        let mut m = self
            .chunk_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(job).or_insert(0);
        if *n >= max {
            return None;
        }
        *n = n.saturating_add(1);
        Some(ChunkSlot { state: self, job })
    }

    /// True if no `job.content.read` record was written yet for this job
    /// and step (and marks it written). [`Self::forget_content_read`]
    /// undoes it if the record could not be written.
    pub(crate) fn first_content_read(&self, job: JobId, step: u8) -> bool {
        let mut s = self
            .content_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if s.len() >= MAX_CONTENT_READS_TRACKED {
            s.clear();
        }
        s.insert((job, step))
    }

    pub(crate) fn forget_content_read(&self, job: JobId, step: u8) {
        self.content_reads
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(job, step));
    }
}

/// A chunk request in progress; released on drop.
#[derive(Debug)]
pub(crate) struct ChunkSlot<'a> {
    state: &'a DeviceState,
    job: JobId,
}

impl Drop for ChunkSlot<'_> {
    fn drop(&mut self) {
        let mut m = self
            .state
            .chunk_slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.job) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.job);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_slots_bounded_per_job() {
        let s = DeviceState::new(&DeviceConfig::default());
        let a = JobId::from_random_bytes([1; 16]);
        let b = JobId::from_random_bytes([2; 16]);
        let one = s.chunk_slot(a, 2).unwrap();
        let two = s.chunk_slot(a, 2).unwrap();
        assert!(s.chunk_slot(a, 2).is_none());
        assert!(s.chunk_slot(b, 2).is_some());
        drop(one);
        assert!(s.chunk_slot(a, 2).is_some());
        drop(two);
        assert!(s.chunk_slots.lock().unwrap().is_empty());
        assert!(s.first_content_read(a, 1));
        assert!(!s.first_content_read(a, 1));
        assert!(s.first_content_read(a, 3));
        s.forget_content_read(a, 1);
        assert!(s.first_content_read(a, 1));
    }
}
