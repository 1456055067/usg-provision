//! Connection admission on the device listener (finding SEC-001): a TCP
//! connection is admitted only from a source that an active boot service
//! serves, and only while that boot service has fewer than
//! `device_api.max_connections_per_boot_service` connections. A source
//! several services serve counts against the first enrolled of them: it
//! is inside a served subnet, and a device already running a job there
//! must still reach its job (session open refuses the ambiguity itself).
//!
//! The served-subnet table is a cache of the active boot services and
//! their subnets, loaded from the store when the listener starts, every
//! `device_api.boot_service_refresh_s`, and when a source matches nothing
//! (at most one attempt per [`MISS_RELOAD_EVERY`], and never waiting for a
//! load already in progress), so a newly enrolled boot service is served
//! within about a second.
//! Until the first load succeeds nothing is admitted (fail closed). The
//! store stays authoritative: the session routes resolve the boot
//! service again in their own transactions.

// COMPLIANCE MAPPING:
// - NIST 800-53: SC-5 (Denial-of-Service Protection) - sources outside
//   every served subnet cannot take connection slots; connections capped
//   per boot service, per source and in total (finding SEC-001).
// - NIST 800-53: AC-4 (Information Flow Enforcement) - the device listener
//   answers only networks a boot service is enrolled for.
// - NIST 800-53: AU-2, AU-12, AU-4 - refused connections audited under
//   the anonymous per-source cap, the excess counted in the
//   unauthenticated summary.
// - SPEC: specs/targeting.md#REQ-TGT-001, #REQ-TGT-012

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use usgp_db::{BootService, RepoTx, Store};
use usgp_proto::BootServiceId;
use usgp_proto::ops::BootServiceStatus;

use crate::context::Api;
use crate::error::ApiError;

/// A miss reloads the table at most this often.
pub const MISS_RELOAD_EVERY: Duration = Duration::from_secs(1);

/// What the table says about a source address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// An active boot service serves it (the first enrolled, if several).
    Served(BootServiceId),
    /// No active boot service serves it.
    NotServed,
    /// The table was never loaded (store unavailable since start).
    Unavailable,
}

impl Admission {
    /// The audit reason of a refusal.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Served(_) => "served",
            Self::NotServed => "no_boot_service",
            Self::Unavailable => "boot_service_table_unavailable",
        }
    }
}

/// The cached served-subnet table.
#[derive(Debug, Default)]
pub(crate) struct ServedSubnets {
    table: RwLock<Option<Arc<Vec<BootService>>>>,
    /// When the last load was started (successful or not).
    last_attempt: Mutex<Option<Instant>>,
    loading: tokio::sync::Mutex<()>,
}

impl ServedSubnets {
    fn lookup(&self, ip: IpAddr) -> Admission {
        let t = self
            .table
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(t) = t else {
            return Admission::Unavailable;
        };
        // The store lists boot services by creation time.
        t.iter()
            .find(|b| b.served_subnets.contains(ip))
            .map_or(Admission::NotServed, |b| Admission::Served(b.id))
    }

    fn replace(&self, active: Vec<BootService>) {
        *self.table.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::new(active));
    }

    /// True (and the attempt noted) if a miss may start a reload now.
    fn claim_miss_reload(&self, now: Instant) -> bool {
        let mut last = self
            .last_attempt
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if last.is_some_and(|t| now.saturating_duration_since(t) < MISS_RELOAD_EVERY) {
            return false;
        }
        *last = Some(now);
        true
    }
}

impl<S: Store + 'static> Api<S> {
    /// Reloads the device listener's served-subnet table from the store
    /// (active boot services only). Returns how many are active. On error
    /// the previous table stays in use.
    ///
    /// # Errors
    ///
    /// [`ApiError`] if the store could not be read.
    pub async fn refresh_device_boot_services(&self) -> Result<usize, ApiError> {
        let served = &self.inner.device.served;
        let _one = served.loading.lock().await;
        self.load_boot_services().await
    }

    async fn load_boot_services(&self) -> Result<usize, ApiError> {
        let served = &self.inner.device.served;
        *served
            .last_attempt
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Instant::now());
        let mut tx = self.store().begin().await?;
        let all = tx.list_boot_services().await;
        tx.rollback().await;
        let active: Vec<BootService> = all?
            .into_iter()
            .filter(|b| b.status == BootServiceStatus::Active)
            .collect();
        let n = active.len();
        served.replace(active);
        Ok(n)
    }

    /// The admission of a connection from `ip`: from the cached table,
    /// reloaded first if it does not say "served", no load is in
    /// progress, and none was started in the last [`MISS_RELOAD_EVERY`].
    pub async fn device_admission(&self, ip: IpAddr) -> Admission {
        let served = &self.inner.device.served;
        let first = served.lookup(ip);
        if matches!(first, Admission::Served(_)) {
            return first;
        }
        let Ok(_one) = served.loading.try_lock() else {
            return first;
        };
        if !served.claim_miss_reload(Instant::now()) {
            return first;
        }
        // A failed reload keeps the old table (and its answer).
        let _ = self.load_boot_services().await;
        served.lookup(ip)
    }
}

/// Connections per boot service (finding SEC-001).
#[derive(Debug, Clone, Default)]
pub(crate) struct ServiceConnections {
    counts: Arc<Mutex<HashMap<BootServiceId, usize>>>,
}

impl ServiceConnections {
    /// A slot for one more connection of `service`, or `None` at `max`.
    pub(crate) fn take(&self, service: BootServiceId, max: usize) -> Option<ServiceSlot> {
        let mut m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(service).or_insert(0);
        if *n >= max {
            return None;
        }
        *n = n.saturating_add(1);
        Some(ServiceSlot {
            counts: Arc::clone(&self.counts),
            service,
        })
    }

    #[cfg(test)]
    fn count(&self, service: BootServiceId) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&service)
            .copied()
            .unwrap_or(0)
    }
}

/// One admitted connection of a boot service; released on drop.
#[derive(Debug)]
pub(crate) struct ServiceSlot {
    counts: Arc<Mutex<HashMap<BootServiceId, usize>>>,
    service: BootServiceId,
}

impl Drop for ServiceSlot {
    fn drop(&mut self) {
        let mut m = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.service) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.service);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_capped_per_service() {
        let c = ServiceConnections::default();
        let a = BootServiceId::from_random_bytes([1; 16]);
        let b = BootServiceId::from_random_bytes([2; 16]);
        let one = c.take(a, 2).unwrap();
        let two = c.take(a, 2).unwrap();
        assert!(c.take(a, 2).is_none());
        assert!(c.take(b, 2).is_some());
        drop(one);
        assert_eq!(c.count(a), 1);
        assert!(c.take(a, 2).is_some());
        drop(two);
    }

    #[test]
    fn table_unloaded_is_unavailable() {
        let s = ServedSubnets::default();
        assert_eq!(
            s.lookup("10.0.0.1".parse().unwrap()),
            Admission::Unavailable
        );
        s.replace(Vec::new());
        assert!(s.claim_miss_reload(Instant::now()));
        assert!(!s.claim_miss_reload(Instant::now()));
        assert_eq!(s.lookup("10.0.0.1".parse().unwrap()), Admission::NotServed);
    }
}
