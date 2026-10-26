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

M1, network boot to a test payload (`docs/ROADMAP.md` §M1,
`specs/boot-network.md`):

- **usgp-relay**: ProxyDHCP and read-only TFTP service for UEFI x86-64 over
  IPv4 (decisions 0003, 0004). It answers PXE clients on UDP 67 and 4011
  and never offers an address (`yiaddr` 0, no lease options). It answers
  relayed requests to `giaddr:67`. It serves boot files on UDP 69 in octet
  mode only, with blksize and tsize negotiation. It binds only the
  configured interfaces (Linux `SO_BINDTODEVICE`). Every boot file is
  checked against the SHA-256 boot manifest before it is served. A
  mismatch refuses the file, moves the service to
  `running_missing_content` and stops offers (SI-7). Per-device
  suppression comes from a reloadable file (REQ-BOOT-050). Audit events
  are JSON lines on stdout.
- **usgp-relay**: command line `--config PATH` (run), `--check-config
  PATH` (validate config, trust rules, manifest and content; exit 0
  running, 3 missing content, 78 invalid) and `--self-check` (FIPS check
  only). `--admin-uid UID` names the one non-root uid that may own the
  trusted files. `--allow-shared-admin-uid` (with `--config` only) is the
  explicit, audited opt-in to run as that uid. The config is
  `/etc/usgp-relay/relay.toml` (`schema_version = 1`, unknown keys
  refused).
- **usgp-relay**: rate limits per client, per routed source, per
  interface and globally. DHCP requests are classified as same-segment or
  routed against each interface's prefix, and each class has its own
  global budget. TFTP requests pass a per-interface admission bucket, and
  every pending transfer ends at a handshake deadline that also bounds
  file verification. Every numeric default is project design
  (OPEN-BOOT-L1).
- **usgp-relay**: new configuration keys `interface[i].prefix_len`
  (optional, 8 to 31; otherwise taken from the interface's connected
  route, and start-up is refused if neither exists),
  `tftp.handshake_timeout_ms` (default 2000),
  `limits.dhcp_relayed_global_per_sec` (default 200),
  `limits.tftp_rrq_global_per_sec` (default 50, per interface) and
  `limits.tftp_rrq_global_burst` (default 100, per interface).
- **usgp-relay**: audit events and fields: `boot.file.verify_slow`
  (rate-limited to one per file per 60 s). `relay.start` reports
  `node_name` and `node_name_source`, `service_uid`, `admin_uid`,
  `allow_shared_admin_uid`, `interface_prefixes` and a `warning`
  (`running_as_root`, `service_uid_owns_trusted_files`,
  `service_uid_unknown`), and is also emitted with outcome `failure` for
  errors before serving. DHCP reply events carry `origin` and the `yiaddr`
  read from the reply bytes. TFTP transfer events carry the served
  file's manifest `sha256`. New drop labels `short_message`,
  `off_segment_source` and `bad_source`. New shed labels
  `dhcp_relayed_global`, `tftp_rrq_global` and `tftp_verify_timeout`.
  Without `log.node_name`, the host name is used.
- **usgp-cli**: `boot-manifest create` and `boot-manifest verify`. They
  write and check the SHA-256 boot manifest, refuse symlinks, non-regular
  files and overwrites, and emit one audit event per run with
  `effective_uid`, `real_uid` (Linux) and `env_user_claimed`.
- **usgp-dhcp**: sans-IO ProxyDHCP parser and responder. Every RFC length
  and option limit is enforced, requests shorter than 300 octets are
  refused (`ParseError::ShortMessage`, RFC 2131 / BOOTP minimum), RFC 3396
  long options are reassembled, option 82 is echoed byte for byte, and
  options 93, 94 and 97 are in every reply. Includes a client-side request
  builder (padded to 300 octets) for tests and fuzz seeds.
- **usgp-tftp**: sans-IO read-only TFTP server: packet codec, RFC 2347
  option negotiation of `blksize` (RFC 2348) and `tsize` (RFC 2349; the
  `timeout` option is never acknowledged), adaptive retransmission, and a
  `ReadTransfer` state machine. A duplicate ACK never resends (no
  Sorcerer's Apprentice). A file that needs more than 65535 blocks is
  refused, never wrapped (REQ-BOOT-035). A client ERROR ends the transfer
  even when it is not well-formed (RFC 1350 §7).
- **usgp-proto**: `BootFileName` and the TOML boot manifest format
  (`BootManifest`, `ManifestEntry`), with size and count limits.
- **usgp-common**: `Sha256Digest`, the trusted-file reader
  (`config::read_trusted`, `ensure_trusted_file`, `ensure_trusted_dir`,
  `TrustPolicy`), audit events (`AuditEvent`, `emit`), JSON or text
  telemetry set-up, and process facts (host name, effective and real uid).
- **usgp-crypto**: SHA-256 through the FIPS module
  (`CryptoProvider::sha256`, `usgp_crypto::sha256`).
- **fuzz**: `dhcp_packet` and `tftp_packet` targets with seed corpora that
  our own generators produce (origin recorded in `SOURCE.md`).
- **testing**: test-only workspaces that are never shipped:
  `testing/uefi-payload`, an unsigned pure-Rust UEFI application that
  prints a marker on serial and builds bit-reproducibly (`/Brepro`,
  `/DEBUG:NONE`), and `testing/netlab`, a lab DHCP server, a DHCP relay
  agent and a probe.
- **scripts**: `scripts/boot-smoke.sh`, a QEMU and OVMF boot smoke with
  scenarios S1 to S8 on Linux with root, plus a payload disk boot. Exit 77
  means NOT RUN. `scripts/check-artifact-names.sh`, the clean-room name
  scan of the release relay and cli, the staged payloads and the boot
  smoke evidence, with no exclusions.
- **ci**: `boot-smoke` job (Ubuntu, sudo, KVM when present, evidence
  artifact; exit 77 fails the job as NOT RUN). `fuzz-smoke` job (each
  target 600 s, scheduled and manual). `testing-workspaces` job (fmt,
  clippy, tests, UEFI build, payload reproducibility, pure-Rust check).
  Supply-chain checks for the `testing/` lockfiles. The fuzz workspace
  gets fmt, clippy and seed replay. Artifact name scan in `fips-linkage`
  and `boot-smoke`. Shared `.github/actions/fips-toolchain` composite
  action.
- **docs**: `docs/operations/relay.md` (operating guide: trust rules,
  command line, configuration reference, example service unit, network
  requirements, audit event catalogue). Decision 0005, the name gate's
  fixed exclusion list (Accepted). M1 updates to `docs/compliance/`.

### Changed

- **usgp-relay**: with no arguments the relay now prints usage on stderr
  and exits 2 after the FIPS check. Before, it exited 0. Use `--self-check`
  for a FIPS-only start-up check.
- **usgp-dhcp, usgp-tftp**: no longer depend on `usgp-common`, so the
  parsers stay dependency-light for fuzzing.
- **deps**: new workspace dependencies `tokio`, `socket2`, `libc`,
  `serde`, `toml` 1.x, `tracing` and `tracing-subscriber`. All are pure
  Rust under MIT or MIT OR Apache-2.0. `windows-sys` is on the pure-Rust
  allowlist (Windows targets only; compiles no C). `usgp-common` and
  `usgp-cli` use `libc` for `O_NOFOLLOW` and `O_NONBLOCK` opens.
- **fuzz**: `fuzz/rust-toolchain.toml` adds the `rustfmt` and `clippy`
  components for the pinned nightly.
- **scripts**: `scripts/gates.sh` also covers the `testing/` and `fuzz/`
  workspaces, the boot smoke and the artifact name scan. It reports NOT
  RUN separately and exits 77 when nothing failed but something did not
  run. `scripts/check-fips-linkage.sh` runs `usgp-relay --self-check`.
  `scripts/test-check-names.sh` asserts that the name gate's exclusions
  match decision 0005.

### Removed

- **fuzz**: the placeholder `noop` target.

### Security

Hardening from the M1 security, NIST and boot reviews, before first
release:

- **usgp-relay**: the configuration, manifest and suppression files are
  read through the trusted-file rules (CM-5, SI-7). Each is opened once
  without following a final symlink and checked on the open handle. It
  must be owned by root or `--admin-uid` and not group- or
  world-writable. Every directory up to `/` must be owned by root or
  `--admin-uid` and not group- or world-writable unless sticky, and the
  path must still name the opened file afterwards. The boot root is
  resolved once at start-up and must not be group- or world-writable.
  The suppression file is re-checked on every reload.
- **usgp-relay**: the relay refuses to run as a non-zero `--admin-uid`,
  or when its effective uid is unknown, unless `--allow-shared-admin-uid`
  is given (exit 78, audited).
- **usgp-relay**: boot files are read without following symlinks, in the
  file or in any directory below the boot root, and FIFOs and devices are
  refused without blocking. A file replaced during the open is refused.
- **usgp-relay**: TFTP pending-transfer exhaustion by spoofed requests is
  bounded (SC-5). New handshake deadline (default 2000 ms), one handshake
  resend by default (was 2), `limits.tftp_max_pending` default 256 (was
  16; range 1 to 4096), and a per-interface admission bucket. File
  verification counts against the deadline, and a cancelled verification
  keeps its read permit until the read ends, so at most
  `verify_concurrency` reads run at once.
- **usgp-relay**: `limits.dhcp_global_per_sec` now covers same-segment
  requests only. Relayed and other routed requests use the new
  `limits.dhcp_relayed_global_per_sec`, so a routed flood cannot use up
  the local segment's budget. On port 67, requests with no `giaddr` from
  outside the interface prefix are dropped unless `ciaddr` equals the
  source, which is then answered by unicast.
- **usgp-relay**: TFTP requests from non-unicast or port-0 sources are
  dropped before any rate bucket or slot is used.
- **usgp-relay**: a stale verification result can no longer overwrite a
  newer one in the content cache.
- **usgp-dhcp**: on port 67 with no `giaddr`, a reply is unicast to
  `ciaddr` only when `ciaddr` equals the UDP source; otherwise it is
  broadcast. This stops reflection to a spoofed `ciaddr`.
- **usgp-cli**: boot files are opened with `O_NOFOLLOW` and `O_NONBLOCK`
  and checked on the open handle.
