# NIST SP 800-53 Rev 5 control mapping

Status as of the bootstrap run (M0, 2026-10-25). Statuses are backed by code
and passing gates only; nothing here is a claim of control satisfaction for
the ATO. Values: Not implemented, Planned, Partial, Implemented.

| Control | Family | Status | Implementation | Evidence | Gaps |
|---------|--------|--------|----------------|----------|------|
| SC-13 | System and Communications Protection | Partial | `usgp-crypto` uses the FIPS 140-3 validated AWS-LC module (`aws-lc-rs` `fips`) and the rustls FIPS provider; every binary calls `usgp_crypto::fips_status()` first and exits non-zero if FIPS mode is inactive (decision 0001). | `usgp-crypto` unit tests; `scripts/check-fips-linkage.sh` | Validated operational environment not confirmed (macOS dev hosts are functional only; Windows PE and Windows relay hosts open, D-5). No algorithms exposed yet (M1/M2). |
| CM-2 | Configuration Management | Partial | Pinned toolchain (`rust-toolchain.toml`, `fuzz/rust-toolchain.toml`), committed `Cargo.lock`, `--locked` in CI. | `.github/workflows/ci.yml` | No released baseline yet. |
| CM-6 | Configuration Management | Partial | FIPS is the only crypto build configuration; workspace lints. | `Cargo.toml`, `crates/usgp-crypto` | No runtime configuration keys yet; secure-default rule applies from M1. |
| SA-11 | System and Services Acquisition | Partial | CI gates: fmt, clippy `-D warnings`, tests, pure-Rust check, name check, fuzz harness build. | `scripts/gates.sh`, `.github/workflows/ci.yml` | No feature code or fuzz targets for parsers yet. |
| SR-3 | Supply Chain Risk Management | Partial | `cargo deny` (licenses, bans, sources, C-crate confinement), `cargo audit`, actions pinned by commit SHA. | `deny.toml`, CI `supply-chain` job | Not yet run in CI (workflow not yet executed). |
| SR-4 | Supply Chain Risk Management | Partial | Lockfile and pinned action SHAs record component provenance. | `Cargo.lock`, `.github/workflows/ci.yml` | No SBOM yet. |
| SI-10 | System and Information Integrity | Planned | Bounds-checked, non-panicking parsers with fuzz targets (M1: DHCP, TFTP). | None | Not implemented. |
| SI-7 | System and Information Integrity | Planned | SHA-256 verification of boot files (M1) and signed manifests (M2) before serve or write. | None | Not implemented. |
| AC-3 | Access Control | Planned | Authorization on every API route (M2 minimal, M6 full RBAC). | None | Not implemented. |
| AU-2 | Audit and Accountability | Planned | Audit events for operator actions and job state changes (M1 relay events, M2 API). | None | Not implemented. |
| AU-9 | Audit and Accountability | Planned | Hash-chained, signed audit log (M2). | None | Not implemented. |
| AU-12 | Audit and Accountability | Planned | Audit record generation in every service (M1 onward). | None | Not implemented. |
| IA-2 | Identification and Authentication | Planned | Operator authentication (M2, mechanism D-6). | None | Not implemented. |
| IA-3 | Identification and Authentication | Planned | Relay identity certificates (M5); device session authorization (M3, D-3). | None | Not implemented. |
| SC-8 | System and Communications Protection | Planned | TLS 1.3 only through the rustls FIPS provider (M2). | None | Not implemented. |
