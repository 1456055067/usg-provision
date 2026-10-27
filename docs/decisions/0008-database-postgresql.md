# 0008: PostgreSQL as the Control-Plane Database

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner
- Resolves: roadmap decision D-7

## Decision

The control plane stores its records in PostgreSQL, accessed through a
pure-Rust driver whose TLS goes through `usgp-crypto` (no C client
libraries such as libpq; pure-Rust rule and decision 0001). Schema changes
are versioned, ordered migrations.

## Consequences

- Integration tests need a PostgreSQL instance (container in CI); gates
  that need it are NOT RUN, not PASS, where it is absent.
- Backup and recovery (CP-9/CP-10) follow PostgreSQL practice and are
  documented in operations docs.
