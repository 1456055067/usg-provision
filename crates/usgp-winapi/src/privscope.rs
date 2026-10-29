//! Nested use counts for token privileges: a privilege is enabled when
//! its first user starts and disabled when its last user ends.
//!
//! Pure and OS-neutral, so the counting rules are tested on every host;
//! `privilege.rs` holds one counter per privilege behind a lock and passes
//! the real adjust call in.

// COMPLIANCE MAPPING:
// - NIST 800-53: AC-6 (Least Privilege) - a privilege is enabled only
//   while some operation that needs it runs
// - SPEC: specs/standards/windows-storage-firmware-api.md §10, §23

/// One use count per privilege, indexed `0..N`.
#[derive(Debug)]
pub(crate) struct ScopeCounts<const N: usize> {
    counts: [u32; N],
}

impl<const N: usize> ScopeCounts<N> {
    /// All counts zero (every privilege disabled by this crate).
    pub(crate) const fn new() -> Self {
        Self { counts: [0; N] }
    }

    /// The current count of `i` (0 for an index out of range).
    pub(crate) fn count(&self, i: usize) -> u32 {
        self.counts.get(i).copied().unwrap_or(0)
    }

    /// Starts one use of `i`. `adjust(true)` (enable) runs only when the
    /// count goes from 0 to 1; if it fails, the count is unchanged and the
    /// error returned. An index out of range is not counted: `adjust(true)`
    /// runs every time.
    pub(crate) fn acquire<E>(
        &mut self,
        i: usize,
        adjust: impl FnOnce(bool) -> Result<(), E>,
    ) -> Result<(), E> {
        let Some(c) = self.counts.get_mut(i) else {
            return adjust(true);
        };
        if *c == 0 {
            adjust(true)?;
        }
        *c = c.saturating_add(1);
        Ok(())
    }

    /// Ends one use of `i`. `adjust(false)` (disable) runs only when the
    /// count goes from 1 to 0. The count goes down whatever the result,
    /// so a failed disable is not retried by a later user. Releasing an
    /// index whose count is already 0 does nothing.
    pub(crate) fn release<E>(
        &mut self,
        i: usize,
        adjust: impl FnOnce(bool) -> Result<(), E>,
    ) -> Result<(), E> {
        match self.counts.get_mut(i) {
            None => adjust(false),
            Some(c) if *c == 0 => Ok(()),
            Some(c) => {
                *c -= 1;
                if *c == 0 { adjust(false) } else { Ok(()) }
            }
        }
    }

    /// Checks that `i` can be enabled, leaving it as it was: when no use is
    /// running, `adjust(true)` then `adjust(false)`; when one is running it
    /// is enabled already and nothing is called. The disable runs even if
    /// the enable reported an error.
    pub(crate) fn probe<E>(
        &mut self,
        i: usize,
        mut adjust: impl FnMut(bool) -> Result<(), E>,
    ) -> Result<(), E> {
        if self.count(i) > 0 {
            return Ok(());
        }
        let enabled = adjust(true);
        let disabled = adjust(false);
        enabled.and(disabled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_on_first_use_disabled_after_last() {
        let mut log = Vec::new();
        let mut s = ScopeCounts::<2>::new();
        let mut adj = |on: bool| -> Result<(), ()> {
            log.push(on);
            Ok(())
        };
        s.acquire(0, &mut adj).unwrap();
        s.acquire(0, &mut adj).unwrap();
        assert_eq!(s.count(0), 2);
        s.release(0, &mut adj).unwrap();
        assert_eq!(s.count(0), 1);
        s.release(0, &mut adj).unwrap();
        assert_eq!(s.count(0), 0);
        // An extra release does nothing.
        s.release(0, &mut adj).unwrap();
        assert_eq!(log, vec![true, false]);
    }

    #[test]
    fn a_failed_enable_is_not_counted() {
        let mut s = ScopeCounts::<1>::new();
        assert_eq!(s.acquire(0, |_| Err("not held")), Err("not held"));
        assert_eq!(s.count(0), 0);
        let mut calls = 0;
        s.release(0, |_| -> Result<(), ()> {
            calls += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 0, "nothing to disable");
    }

    #[test]
    fn a_failed_disable_still_ends_the_use() {
        let mut s = ScopeCounts::<1>::new();
        s.acquire(0, |_| Ok::<(), ()>(())).unwrap();
        assert_eq!(s.release(0, |_| Err("x")), Err("x"));
        assert_eq!(s.count(0), 0);
    }

    #[test]
    fn probe_leaves_the_state_as_it_was() {
        let mut log = Vec::new();
        let mut s = ScopeCounts::<1>::new();
        s.probe(0, |on| -> Result<(), ()> {
            log.push(on);
            Ok(())
        })
        .unwrap();
        assert_eq!(log, vec![true, false]);
        assert_eq!(s.count(0), 0);
        // Not held: the error is returned and the disable still runs.
        let mut log = Vec::new();
        let r = s.probe(0, |on| {
            log.push(on);
            if on { Err("not held") } else { Ok(()) }
        });
        assert_eq!(r, Err("not held"));
        assert_eq!(log, vec![true, false]);
        // In use: nothing is called, so the running use keeps it enabled.
        s.acquire(0, |_| Ok::<(), ()>(())).unwrap();
        let mut called = false;
        s.probe(0, |_| -> Result<(), ()> {
            called = true;
            Ok(())
        })
        .unwrap();
        assert!(!called);
        assert_eq!(s.count(0), 1);
    }

    #[test]
    fn out_of_range_is_not_counted() {
        let mut s = ScopeCounts::<1>::new();
        let mut log = Vec::new();
        s.acquire(5, |on| -> Result<(), ()> {
            log.push(on);
            Ok(())
        })
        .unwrap();
        s.release(5, |on| -> Result<(), ()> {
            log.push(on);
            Ok(())
        })
        .unwrap();
        assert_eq!(log, vec![true, false]);
        assert_eq!(s.count(5), 0);
    }
}
