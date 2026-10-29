//! usgp-api integration tests (plan M2 section 10, "API" row): the API on
//! the in-memory store, over real mutual TLS on loopback with the test
//! PKI. One binary, one module per area named in the plan.
//!
//! Every module is `#[cfg(test)]`, so the workspace's test-only clippy
//! allowances (unwrap/expect/panic in tests) apply to the shared helpers
//! too, as in usgp-db and usgp-audit.

#[cfg(test)]
mod common;

#[cfg(test)]
mod authz_matrix;
#[cfg(test)]
mod boot_policy;
#[cfg(test)]
mod codes;
#[cfg(test)]
mod content_verify;
#[cfg(test)]
mod declarations;
#[cfg(test)]
mod device_routes_table;
#[cfg(test)]
mod device_session;
#[cfg(test)]
mod fix_round1;
#[cfg(test)]
mod fix_round2;
#[cfg(test)]
mod fix_round3;
#[cfg(test)]
mod hardening;
#[cfg(test)]
mod jobs;
#[cfg(test)]
mod limits;
#[cfg(test)]
mod packages;
#[cfg(test)]
mod qa_m2;
#[cfg(test)]
mod qa_m3;
#[cfg(test)]
mod real_wim;
#[cfg(test)]
mod routes_table;
#[cfg(test)]
mod unauthenticated;
#[cfg(test)]
mod uploads;
