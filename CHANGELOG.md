# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rules in [CONTRIBUTING.md](CONTRIBUTING.md#versioning).

## [Unreleased]

### Added

- **workspace**: Cargo workspace (edition 2024, Rust 1.99.1 pinned in
  `rust-toolchain.toml`) with stub crates under `crates/`, `services/`, and
  `tools/`. `unsafe` is forbidden workspace-wide. Release builds keep
  overflow checks.
- **usgp-crypto**: the `CryptoProvider` trait, `FipsProvider`, and
  `fips_status()` on the FIPS 140-3 AWS-LC module (`aws-lc-rs` `fips`) and
  the rustls FIPS provider. This crate is the only crypto boundary
  (decision 0001 with Amendment 1).
- **usgp-server, usgp-relay, usgp-preboot-agent, usgp-cli**: each binary
  checks FIPS mode at start-up and refuses to start if it is not active.
- **usgp-dhcp**: ProxyDHCP-only scope recorded in the crate docs
  (decision 0003).
- **usgp-common, usgp-audit, usgp-db, usgp-proto, usgp-tftp,
  usgp-httpboot, usgp-image, usgp-disk, usgp-wincfg, usgp-deploy,
  usgp-cache, usgp-api**: empty library stubs. Parser crates deny
  `clippy::indexing_slicing`.
- **ci**: GitHub Actions workflow (actions pinned by commit SHA) with
  format, clippy, test, doc-test, pure-Rust, name, FIPS-linkage,
  supply-chain (`cargo deny`, `cargo audit`, including `fuzz/Cargo.lock`),
  markdown, shellcheck, actionlint, and fuzz-build gates. The FIPS module
  toolchain (Go 1.22, CMake 3.28, clang 18, Perl 5.38) is pinned by series,
  asserted, and recorded in each job summary. markdownlint installs from a
  committed npm lockfile.
- **supply chain**: `deny.toml` licence, source, and ban policy that confines
  the AWS-LC chain and its build-only tools to `usgp-crypto`. Gate scripts
  live under `scripts/`.
- **fuzz**: separate fuzz workspace skeleton with its own pinned nightly
  (decision 0002).
- **docs**: architecture, roadmap, decision records 0001 to 0003, and seed
  compliance documents under `docs/compliance/`.
- **docs**: `docs/BUILDING.md`, the FIPS build procedure (build hosts,
  toolchain, environment, FIPS-mode and static-linkage checks).
