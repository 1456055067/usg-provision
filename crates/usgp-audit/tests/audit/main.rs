//! usgp-audit integration tests (plan M2 section 10, "Audit chain").
//!
//! One test binary so the shared fixture is compiled once. Modules are
//! `cfg(test)` so the workspace's test-only clippy allowances apply to
//! the shared helpers too (same convention as usgp-crypto's tests).

#[cfg(test)]
mod append;
#[cfg(test)]
mod chain_tamper;
#[cfg(test)]
mod checkpoint;
#[cfg(test)]
mod common;
#[cfg(test)]
mod policy;
