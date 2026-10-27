# 0012: PostgreSQL Driver and Certificate-Only Database Login

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Refines: decision 0008

## Context

The pure-Rust driver `tokio-postgres` contains password authentication code
(SCRAM-SHA-256 and MD5) that does not use the FIPS module (decision 0001).

## Decision

Use `tokio-postgres`, with its TLS hook implemented over `usgp-crypto`.
The server logs in to PostgreSQL with a TLS client certificate only; no
database password is ever configured, so the non-FIPS password code is
present but unreachable. A test and a start-up check refuse any
configuration that would enable password authentication.

## Consequences

- The residual (non-FIPS code linked but unreachable) is recorded as a
  POA&M item and reviewed if the driver changes.
