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

M2, content store (`docs/ROADMAP.md` §M2, `specs/os-images.md`,
`specs/preinstall-env.md`, `specs/operator-access.md`):

- **usgp-server**: new control-plane service. Commands `serve`,
  `--check-config`, `--self-check`, `migrate`, `keygen --purpose
  content|audit`, `operator enrol|disable` and `audit verify`
  (`--max-unsigned-records`, `--max-checkpoint-age`). Exit codes: 0, 1
  (FIPS, database or bind failure; for `audit verify`, a tampered chain),
  2 usage, 69 unreadable, 77, 78 configuration refused. With no arguments
  it prints usage and exits 2. Configuration `schema_version = 1`, unknown
  keys refused, read through the trusted-file rules. Sections and keys:
  `node_name`; `[api]` `listen` (default `127.0.0.1:8443`, loopback only),
  `max_connections`, `header_timeout_s`, `idle_timeout_s`,
  `handshake_timeout_s` (default 5), `max_json_bytes`, `max_headers`,
  `max_header_bytes`, `max_connections_per_source` (16),
  `max_handshakes_per_source` (8), `reserved_cert_connections`,
  `max_connection_age_s` (300); `[tls]` `cert_chain`, `private_key`,
  `min_version` (TLS 1.2 minimum), `client_trust_anchors`, `client_crls`
  (required), `crl_reload_s`, `acceptable_policy_oids`; `[database]`
  `host`, `port`, `dbname`, `user`, `server_ca`, `server_name`,
  `client_cert`, `client_key`, `pool_size`, `connect_timeout_s`;
  `[database.admin]` `user`, `client_cert`, `client_key`; `[content]`
  `root`, `max_upload_bytes`, `max_open_uploads`,
  `max_open_uploads_per_operator`, `upload_idle_timeout_s`,
  `upload_session_ttl_s`, `check_concurrency`, `check_stall_timeout_s`;
  `[signing]` `content_key`, `audit_key`, `previous_content_pubs`;
  `[audit]` `checkpoint_every_records`, `checkpoint_every_s`,
  `checkpoint_heartbeat_s` (900), `unauth_records_per_source_per_min`,
  `unauth_records_global_per_min` (300),
  `credential_failure_records_per_source_per_min` (60),
  `credential_failure_records_global_per_min` (600); `[pe]`
  `known_bad_kit_versions`; `[wim]` `max_xml_bytes`, `max_images`,
  `max_lookup_bytes`, `max_metadata_bytes`, `max_metadata_total_bytes`,
  `max_name_chars`, `max_xml_depth`, `max_xml_elements_per_image`,
  `max_integrity_bytes`; `[log]` `level`. No password key exists
  (decision 0012).
- **usgp-server**: audit events `server.start`, `server.start.refused`,
  `server.stop`, `server.migrate`, `operator.enrolled`,
  `operator.enrol.refused`, `operator.disabled`,
  `operator.disable.refused`, `audit.verify`, `audit.checkpoint.failed`
  (unpersisted alarm, at most one per 60 s), `key.generated` and
  `key.generation.failed`.
- **usgp-api**: operator API, HTTP/1.1 over mutual TLS, under `/v1`:
  `limits`, `uploads`, `images` (list, view, edition declaration, delete,
  signed manifest), `pe` (import, list, view, delete, manifest),
  `content/{id}` (verified download with `ETag` `"sha256:<hex>"`) and
  `packages` (create, list, view, edit, clone, delete, signed manifest).
  Each request is bound to one enrolled operator by its client
  certificate's SHA-256, checked against the route's permission (roles
  `administrator` and `none`), and audited in the same transaction as the
  change; if the record cannot be written, the action is refused
  (decision 0015). Uploads are streamed into a content-addressed store and
  checked in the background; Ready content is read-only and gets a signed
  content manifest; downloads are re-verified chunk by chunk.
- **usgp-api**: audit events `auth.tls.failed`, `auth.unknown_certificate`,
  `auth.operator_disabled`, `auth.unauthenticated`,
  `auth.unauthenticated.summary`, `auth.tls.crl_reloaded`, `authz.denied`,
  `api.request.failed`, `api.request.refused`, `api.limits.read`,
  `content.upload.{created,started,received,refused,failed,cancelled}`,
  `content.check.started`, `content.ready`, `content.failed`,
  `content.integrity.failed`, `content.orphan.found`,
  `content.manifest.{signed,read}`, `content.download`,
  `content.download.{completed,aborted}`, `image.list.read`,
  `image.read`, `image.delete.refused`, `image.deleted`,
  `edition.declared`, `edition.declaration.refused`, `pe.declared`,
  `pe.list.read`, `pe.read`, `pe.delete.refused`, `pe.deleted`,
  `package.{created,edited,cloned,deleted,refused,status.changed}`,
  `package.list.read`, `package.read` and `package.manifest.{signed,read}`.
- **usgp-image**: `check_wim` checks an uploaded WIM before it becomes
  Ready: header, flags, resource bounds, lookup table, XML image
  information, integrity table and metadata hashes, each refusal with a
  named reason code. Uncompressed and XPRESS only (decision 0014); LZX,
  LZMS, `.esd`, split and resource-only files are refused. Our own XPRESS
  decoder (MS-XCA). `check_pe` picks the usable image of a preinstall
  environment. `ContentHasher` computes whole-file and per-chunk SHA-256
  in one pass. The `testkit` feature (test-only) adds a WIM builder.
- **usgp-proto**: operator API request, response and error types,
  validated names and ids, the declared/verified fact model (decision
  0013), lifecycle states, reason codes, the signed envelope, and the
  content and package manifests.
- **usgp-db**: PostgreSQL store over `tokio-postgres` with its TLS hook
  on `usgp-crypto` and certificate-only login (decision 0012). A
  transaction cannot commit a state change without its audit record.
  Embedded, ordered, checksummed migrations: `0001_init` (audit tables
  with append-only triggers, operators, content, editions, uploads,
  packages), `0002_roles_and_guards` (`usgp_app` grants) and
  `0003_admin_role` (`usgp_admin` grants; decision 0016). Schema version 3.
  Three database roles, each with its own client certificate:
  `usgp_owner` (migrations), `usgp_app` (the service) and `usgp_admin`
  (local administrative commands). The roles are created by the database
  administrator; migration 0003 fails if `usgp_admin` is missing. An
  in-memory store with the same rules is used by tests.
- **usgp-audit**: tamper-evident audit chain: canonical records with the
  AU-3 fields, SHA-256 hash chain, signed checkpoints (ECDSA P-384 through
  `usgp-crypto`) every N records, every T seconds, on a heartbeat and at
  shutdown, and a verifier with a policy for the longest unsigned run and
  the oldest checkpoint.
- **usgp-crypto**: streaming SHA-256, SHA-1 for WIM format hashes only,
  DRBG output, ECDSA P-384/SHA-384 signing keys with domain-separated
  typed signatures, X.509 facts and CRL facts, and mutual-TLS server and
  client configurations on the FIPS provider. The `test-pki` feature
  (test-only) adds a test certificate hierarchy.
- **usgp-cli**: `limits`, `image upload|list|view|declare|download|delete`,
  `pe import|list|view|download|delete` and `package
  create|edit|list|view|clone|delete|manifest` against the operator API
  over mutual TLS.
- **fuzz**: targets `wim_header`, `wim_lookup`, `wim_xml`, `wim_check`,
  `xpress_chunk` and `api_json`.
- **docs**: decisions 0012 (PostgreSQL driver, certificate-only login),
  0013 (operator-declared image facts), 0014 (M2 WIM compression scope),
  0015 (content and audit operating rules), 0016 (separate administrative
  database role), all Accepted, and 0017 (WIM header strictness),
  Proposed. `docs/formats/wim-observed.md` and the DISM sample tooling in
  `scripts/wim-samples/`.

M2 CI and local gates (plan WU-3b, WU-9, WU-10, WU-W):

- **ci**: `pg-integration` job: PostgreSQL 16 (digest-pinned) over TLS
  with certificate-only login, set up and checked by
  `scripts/pg-test-setup.sh`. The `usgp-db` `*_pg` tests and the
  `usgp-server` `e2e_pg` test must fail without the database and must
  each pass at least one test, none ignored, with it.
- **ci**: `large-upload` job (weekly and manual): the 10.5 GiB
  `large_upload_pg` flow against PostgreSQL, with a free-disk preflight.
  Too little disk, a missing test or the test's own NOT RUN marker fails
  the job with a `large-upload NOT RUN` annotation, never a pass.
- **ci**: `wim-samples` workflow: DISM sample WIMs made on a Windows
  runner from our own content (14-day artifact, never committed), and a
  Linux `verify` job that runs `usgp-image` with `dism-samples` against
  them and requires the `dism_samples` tests to pass.
- **ci**: the `gates` job lints the code behind every test-only feature,
  runs `usgp-crypto` with `test-pki` and `usgp-image` with `testkit` per
  package (each named test binary must pass a test), and fails if a
  test-only feature reaches the shipped build graph.
- **ci**: `fuzz-build` replays the seeds of all eight fuzz targets.
  `fuzz-smoke` adds `wim_header`, `wim_xml` and `xpress_chunk` (600 s)
  and `wim_lookup`, `wim_check` and `api_json` (60 s), each with its own
  `-max_len`, and every run uses `-rss_limit_mb=2048 -timeout=10`.
- **ci**: the `gates` job runs `scripts/check-pe-files.sh repo` and its
  43-case test `scripts/test-check-pe-files.sh` (REQ-PE-001, QA-001).
  `fips-linkage` runs `check-pe-files.sh` and the name scan on all four
  release binaries.
- **ci**: `pg-integration` and `large-upload` fail if the runner user is
  root (the admin-key rule cannot be tested as root) and require the
  `usgp_admin` login variables in the test environment file.
- **ci**: `wim-samples` builds S10, S11A/B and S12A/B. `verify` checks
  every manifest row before the parser runs: known `expected` and
  `status` tokens, `dism-refused` only on `observe` rows, a row for every
  Standard sample; anything else fails. The `observe` and `dism-refused`
  results go to the job summary, to `::notice::` lines and to the
  `wim-samples-observations` artifact (BOOT-015).
- **docs**: `docs/BUILDING.md` section 8, PostgreSQL for tests, with the
  three database roles and the private-key mode rules.

M3 toolchain, Windows target and gates (M3 plan WU-0, decision 0019):

- **usgp-winapi**: new skeleton crate for the pre-boot agent's Windows API
  calls. It is the only crate that may use `windows-sys`, and its
  `src/ffi.rs` is the only file in the workspace that may allow `unsafe`
  (the crate sets `unsafe_code = "deny"`; every other crate keeps
  `forbid`). On other targets the crate is empty. A test in `ffi.rs`
  checks that `windows-sys` links (raw-dylib) in a static-CRT build.
- **deps**: workspace dependencies `windows-sys` `=0.61.2` (declarations
  only, through `windows-link`; compiles no C) with the plan's Win32
  feature list, and `httparse` 1.x. Both are MIT OR Apache-2.0.
- **build**: `.cargo/config.toml` builds `x86_64-pc-windows-msvc` with
  `+crt-static`, so the agent needs no VC runtime in Windows PE. On that
  target the FIPS module is pinned to its DLL build
  (`AWS_LC_FIPS_SYS_STATIC_x86_64_pc_windows_msvc=0`); AWS-LC builds a
  static FIPS module only on Linux.
- **ci**: `windows-agent` job on `windows-2025` (skeleton; WU-15 fills
  it). It records the FIPS build toolchain, builds the release agent and
  checks the FIPS module's CRT setting, the imported DLLs of the agent and
  the module (no dynamic C runtime), and the FIPS start-up check from a
  staging directory. It records the agent's dependency tree and whether
  `usgp-crypto`'s tokio pulls in `windows-sys`, then runs clippy, build
  and tests for the crates that compile on Windows.
- **scripts**: `scripts/gates.sh` lints the C-free crates for the Windows
  target when that target is installed, and reports the `windows-agent`
  job as NOT RUN.

### Changed

- **ci**: the `gates` job runs `usgp-server --self-check` and requires
  `usgp-server` with no arguments to exit 2 (usage), as for the relay.
  `docs/BUILDING.md` section 6's hand check passes `--self-check` to the
  server and the relay.
- **ci**: the fuzz jobs install the pinned FIPS toolchain (the fuzz
  workspace now builds the AWS-LC FIPS module through `usgp-image`), cache
  `target/fuzz` instead of `fuzz/target` (decision 0005), and allow
  60 minutes.
- **scripts**: `scripts/gates.sh` mirrors the CI changes above. It runs
  the PostgreSQL tests when `USGP_TEST_PG_*` is set, the DISM sample check
  when `USGP_WIM_SAMPLES` is set, and the large upload when
  `GATES_LARGE=1` (Linux, PostgreSQL, 14 GiB free). Otherwise each is
  NOT RUN. The PostgreSQL tests are also NOT RUN as root. It runs
  `check-pe-files.sh` on all four release binaries.

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

- **scripts**: `scripts/check-pure-rust.sh` adds the decision 0019 rules.
  `usgp-disk`, `usgp-deploy` and `usgp-image` may have no `-sys` crate or
  native build helper on any target, allowlisted or not (only the FIPS
  chain under `usgp-crypto` is pruned). The agent's tree for
  `x86_64-pc-windows-msvc` may hold only the AWS-LC chain under
  `usgp-crypto` and `windows-sys` under `usgp-winapi`. Every member except
  `usgp-winapi` must use the workspace lints, and only
  `crates/usgp-winapi/src/ffi.rs` may allow `unsafe_code`. The
  `windows-sys` allowlist entry is amended to match.
- **supply chain**: `deny.toml` confines `windows-sys` to `usgp-winapi`
  and its existing tokio, socket2, mio and errno paths, `windows-link` to
  `windows-sys`, `libloading` and `parking_lot_core`, and `httparse` to
  hyper and `usgp-preboot-agent`.

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

Hardening from the M2 security, NIST and boot reviews (fix rounds 1 and
2), before first release:

- **usgp-api**: per-source caps on open connections and handshakes in
  progress (IPv4 /32, IPv6 /64), checked before the TLS handshake; a
  maximum connection age, with graceful close of older connections when
  the CRLs are reloaded; handshake timeout default lowered to 5 s (SC-5,
  SEC-001, SEC-007). A residual pre-authentication slot limit is recorded
  as a POA&M item.
- **usgp-api**: unauthenticated and credential-failure audit records are
  rate-limited per source and globally, in two separate budgets, with
  summary counters beyond the caps (AU-5, SEC-004, NIST-001). Failed
  handshakes record the presented certificate's facts (NIST-005).
- **usgp-api**: an upload-quota race is closed with a transaction lock
  (SEC-009). An I/O error while serving a download is reported as a
  storage error and no longer marks content Failed; only an integrity
  failure does (SEC-008). A caller without both view permissions gets
  the same 403 for an absent id as for an item of the other kind
  (SEC-010).
- **usgp-crypto**: operator certificates must carry the clientAuth
  extended key usage (SEC-006). Client chains are pre-checked with a
  bounded name and signature probe before path building (SEC-012,
  NIST-014). CRL numbers are parsed so the server refuses a reload that
  rolls a CRL back (SEC-007).
- **usgp-audit**: `audit verify` fails on a run of unsigned records
  longer than the policy, a chain with no checkpoint, an old checkpoint,
  or records beyond the stored head; backwards timestamps are reported
  as notices. Checkpoints are also signed on a heartbeat with no new
  records, and the allowed slack follows the number of concurrent
  writers (SEC-002, SEC-013, SEC-015, NIST-006).
- **usgp-db**: migration 0003: the service role `usgp_app` can no longer
  create or change operators; only `usgp_admin`, used by the local
  administrative commands, can (AC-6(1), NIST-004, decision 0016).
- **usgp-server**: private keys must not be readable by others, nor by a
  group other than the service's (SEC-005). The owner and admin database
  keys must be 0600 or 0400 whoever runs the command, and `serve` refuses
  to start if it can read the admin key (SEC-011). Checkpoint failures
  raise an alarm (NIST-003). A commit with an unknown outcome is reported
  as such (NIST-013). Key generation and its failure are audited
  (NIST-011, NIST-016).
- **usgp-image**: duplicate file resources and overlapping resource
  ranges are refused; metadata must be in offset order (refusal names
  the remedy: export each image to a new file); the boot metadata header
  must match the boot image; compressed chunk tables are checked;
  impossible part fields, unknown resource flags and non-zero integrity
  flags are refused; truncated XPRESS input is always an error; memory
  for the lookup walk is reserved fallibly (SEC-003, SEC-014, BOOT-001 to
  BOOT-013). Header `cbSize` must be 208 and, for XPRESS, the offset-20
  field 32768 (decision 0017, Proposed).
