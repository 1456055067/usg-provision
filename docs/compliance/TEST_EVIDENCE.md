# Test evidence

Tests that back control or requirement claims. Entries are added after QA
records a passing run; the M0 `usgp-crypto` tests are pending QA.

M1 results (2026-10-26) are recorded as they were reported:

- **QA** means the M1 QA report: the initial pass (464 workspace tests
  passed) or re-verify round 1 (510 passed). Both ran on the macOS
  development host.
- **Final gate run** means the orchestrator's gate run after fix round 3:
  no failures, 576 tests passed and 0 failed. Two items were NOT RUN: the
  timed fuzz step inside `scripts/gates.sh`, because its time variable was
  unset, and boot smoke S1 to S8, because the host is Darwin.
- **QA final pass** means QA's last pass after fix rounds 2 and 3 and the
  docs phase: `GATES_FUZZ_SECONDS=60 scripts/gates.sh` exit 77, with 40
  PASS, 0 FAIL and 1 NOT RUN (boot smoke S1 to S8). 581 tests in total:
  531 workspace, 41 netlab, 8 uefi-payload and 1 doctest. QA confirmed
  each round-2 and round-3 test by name. The orchestrator's earlier
  figure of 576 is the same sum before QA added 5 tests.
- **CI 40438138720** means GitHub Actions run 40438138720 on the push of
  commit 70e3c1f (2026-10-27,
  <https://github.com/1456055067/usg-provision/actions/runs/40438138720>),
  conclusion success. Boot smoke results are copied from its
  `boot-smoke-evidence` artifact (`summary.txt`, `results.txt`,
  `environment.txt`, `relay.log`, `serial/`, `probe/`): `pass=9 fail=0
  not_run=0`, preflight OK. Commit 70e3c1f changed only `scripts/` and
  `testing/` relative to the M1 commit 2c0807c, so the product code under
  test is the M1 code. Environment: GitHub-hosted `ubuntu-24.04` runner,
  kernel 6.17.0-1022-azure x86_64, QEMU 8.2.2 (Debian
  1:8.2.2+ds-0ubuntu1.18), KVM acceleration, relay run as uid 65534.
  Firmware and binary SHA-256 values are in
  `docs/compliance/ATO_EVIDENCE.md`. The artifact has a 30-day retention.
- **CI 40439279903** means GitHub Actions run 40439279903, a manual
  (`workflow_dispatch`) run on the same commit 70e3c1f (2026-10-27,
  <https://github.com/1456055067/usg-provision/actions/runs/40439279903>),
  conclusion success, every job success. It is the first run of the
  `fuzz-smoke` job: one `ubuntu-24.04` job per target, 600 s each
  (`-max_total_time=600`), and the job fails if libFuzzer reports under
  600 s. Results are copied from the job logs (`Done … runs in …
  second(s)`). Each `fuzz-smoke-<target>` artifact (30-day retention)
  holds one file, the job's `fuzz.log`; no crash, OOM or timeout input
  was written. The same run re-ran boot smoke: `pass=9 fail=0
  not_run=0`, preflight OK.

The full gate list and the commands are in `docs/compliance/ATO_EVIDENCE.md`.
Each group row below names its tests; the per-REQ mapping is in
`docs/compliance/SPEC_TRACEABILITY.md`.

| Test | Crate | Proves | Control / REQ | Last result |
|------|-------|--------|---------------|-------------|
| `tests/negative.rs` (73 at QA) | `usgp-dhcp` | Every DHCP length and option limit is dropped without a panic | SI-10, REQ-BOOT-006 | PASS (QA) |
| `tests/negative.rs::size_240_to_299_short_message` | `usgp-dhcp` | Requests of 240 to 299 octets are dropped as `short_message` | SI-10, REQ-BOOT-006, RFC 1542 §2.1 | PASS (QA final pass) |
| `tests/qa_invariants.rs` (2) | `usgp-dhcp` | Under 24,000 mutated requests, every reply has `yiaddr` and `ciaddr` 0, the server's own address, only allowed options and option 82 only as an unchanged echo; suppression wins on every reply path | SC-7, CM-7, REQ-BOOT-010, 021, 022, 051 | PASS (QA) |
| `src/responder.rs`, `src/reply.rs`, `src/ident.rs` unit tests | `usgp-dhcp` | Same-segment, relayed and 4011 replies; arch 7 only; PXE class only; option 82 echo; no lease fields; MAC and GUID parsing; `ciaddr` only when it equals the source | REQ-BOOT-001 to 007, 010, 020 to 022, 051 | PASS (QA) |
| `tests/negative.rs` (51) | `usgp-tftp` | Every TFTP length and option limit is handled without a panic | SI-10, REQ-BOOT-031 | PASS (QA) |
| `tests/sorcerer.rs` (3) | `usgp-tftp` | A duplicate ACK never causes a resend; block numbers rise strictly | REQ-BOOT-032, RFC 1123 §4.2.3.1 | PASS (QA) |
| `tests/qa_rfc_limits.rs` (4) | `usgp-tftp` | A full 65535-block transfer never wraps; one octet over the limit is refused with ERROR 3 at three block sizes; option names are case-insensitive; 20,000 random option sets keep OACK rules | REQ-BOOT-031, 035 | PASS (QA) |
| `src/transfer.rs`, `src/rto.rs` unit tests | `usgp-tftp` | Octet-only reads, OACK rules, timeout option not acknowledged, adaptive RTO with Karn's rule, retry cap, refuse before OACK, client ERROR ends the transfer | REQ-BOOT-030 to 032, 035 | PASS (QA) |
| `tests/content_integrity.rs` | `usgp-relay` | One changed, truncated or appended byte gives ERROR 1, no offers and an audit event, then recovery; symbolic links, symbolic-link directories and FIFOs are refused | SI-7, REQ-BOOT-033, 041, 052; M1 exit 2 | PASS (QA) |
| `tests/dhcp_service.rs` | `usgp-relay` | In-process DHCP service: offers, relayed replies, suppression, missing content, per-client, per-relay and global budgets, flood recovery, reply latency under 50 ms | SC-5, REQ-BOOT-001, 002, 044, 050, 052, 070 | PASS (QA) |
| `tests/dhcp_service.rs::off_segment_sources_never_use_same_segment_budget`, `unknown_prefix_fails_closed`, `short_requests_dropped_and_counted`, `off_segment_ciaddr_source_on_67_routed_unicast` | `usgp-relay` | Off-subnet senders never use the same-segment budget; an unknown prefix fails closed; short requests are counted; an off-subnet request with `ciaddr` equal to its source gets a unicast on the routed budget | SC-5, REQ-BOOT-044 | PASS (QA final pass) |
| `tests/tftp_service.rs` | `usgp-relay` | In-process TFTP service: downloads, OACK, retry cap, handshake timeout, spoofed RRQ trickle, admission bucket, source filter, pending, per-client and established caps, ERROR rate cap, 50 parallel clients | SC-5, SI-10, REQ-BOOT-030 to 034, 040, 041, 044 | PASS (QA) |
| `tests/tftp_service.rs::rrq_flood_on_one_interface_does_not_shed_another`, `verification_wait_bounded_by_handshake_timeout` | `usgp-relay` | A flood on one interface does not shed another; verification waits are bounded by the handshake deadline and reported as `boot.file.verify_slow` | SC-5, REQ-BOOT-044 | PASS (QA final pass) |
| `src/content.rs::cancelled_verification_keeps_permit_until_read_ends`, `verify_slow_report_rate_limited_per_file` | `usgp-relay` | A cancelled verification keeps its permit until its read ends, so at most `verify_concurrency` reads exist; `boot.file.verify_slow` is limited to one event per file per 60 s | SC-5, AU-2, REQ-BOOT-044 | PASS (QA final pass) |
| `tests/config.rs`, `tests/startup.rs` | `usgp-relay` | Config schema, ranges and defaults; trusted-file rules; process contract and exit codes; `--check-config` audits | CM-5, CM-6, AU-2, REQ-BOOT-022, 053 | PASS (QA) |
| `tests/startup.rs::run_as_admin_uid_refused_unless_allowed`; `tests/config.rs::boot_root_resolved_once_at_load`, `interface_prefix_len_rules` | `usgp-relay` | Running as the `--admin-uid` is refused unless opted in; the boot root is resolved once at load; prefix length rules | CM-5, AC-6, CM-6 | PASS (QA final pass) |
| `tests/startup.rs::config_rejected_carries_host_node_name` | `usgp-relay` | Configuration rejections carry the host name | AU-3 | NOT RUN on the macOS host (Linux only). Inferred PASS on Linux: the CI 40438138720 `gates` job ran `cargo test --workspace --locked` on `ubuntu-24.04` and succeeded. The per-test log line has not been reviewed, so this row is not counted as Tested |
| `tests/qa_m1.rs` (19) | `usgp-relay` | Audit event fields and outcomes; no lease on any path; suppression on every path; tamper chain end to end; refusals disclose nothing; option 82 audit; `ciaddr` spoofing; yiaddr in events read from the wire | AU-2, AU-3, SI-7, SI-11, REQ-BOOT-010, 021, 035, 043, 051, 052 | PASS (QA, 3 runs, no flake) |
| `tests/qa_r1.rs` (8) | `usgp-relay` | Symbolic-link manifest refused; suppression trust at start and reload; `--admin-uid` contract; audited refusals; check results ordered under 2000 random schedules | CM-5, AU-2, REQ-BOOT-050, 052 | PASS (QA, 3 runs) |
| `tests/qa_r3.rs` (4): `origin_recorded_in_dhcp_events_on_every_path`, `same_segment_prefix_boundaries`, `verify_slow_event_fields_and_rate_limit_from_tftp_path`, `boot_root_symlink_target_is_what_gets_trust_checked` | `usgp-relay` | DHCP events record `origin` on every path; same-segment boundaries for /8, /20, /24 and /31; `boot.file.verify_slow` fields and rate limit from the real TFTP path; the boot-root link target is what gets trust-checked | AU-2, AU-3, SC-5, CM-5, SI-7; REQ-BOOT-002, 034, 041, 044 | PASS (QA final pass) |
| `testing/uefi-payload` (8) and `testing/netlab` (39 + 2) | test workspaces | Test payload library; lab DHCP server, relay agent and probe codec | REQ-BOOT-011 (lab tool only) | PASS (QA final pass) |
| `testing/netlab/src/probe.rs::qa_vectors_meet_bootp_minimum_in_every_mode_and_seed` | `testing/netlab` | Every non-`size-*` probe vector is at least 300 octets in direct and relayed modes over 6 seeds | SI-10; REQ-BOOT-006 | PASS (QA final pass) |
| Fuzz `dhcp_packet`, 600 s | `fuzz` | 152,795,348 executions in 601 s; no crash, OOM or timeout | SI-10; M1 exit 3 | PASS (WU-8, 2026-10-26) |
| Fuzz `tftp_packet`, 600 s | `fuzz` | 26,315,233 executions in 601 s; no crash, OOM or timeout | SI-10; M1 exit 3 | PASS (WU-8, 2026-10-26) |
| Fuzz `tftp_packet`, 600 s, after fix round 2 | `fuzz` | 10,934,114 executions; no crash. One slow-unit artifact was written; it is not a crash | SI-10; M1 exit 3 | PASS (orchestrator, 2026-10-26) |
| Fuzz `dhcp_packet` and `tftp_packet`, 60 s each through `scripts/gates.sh` | `fuzz` | 15,140,134 and 2,100,492 executions; no artifacts. The tftp run includes the client-ERROR invariant added in fix round 1 | SI-10 | PASS (QA re-verify round 1) |
| Fuzz `dhcp_packet` and `tftp_packet`, 60 s each through `scripts/gates.sh` (final pass) | `fuzz` | 11,061,574 and 1,005,497 executions; no crash, no new artifact | SI-10 | PASS (QA final pass) |
| Boot smoke `payload-disk` | `scripts/boot-smoke.sh` | The test payload, booted from a disk image by OVMF under QEMU, prints its marker on serial. Proves the payload only: no relay, no network, no Secure Boot | Test payload for M1 exit 1 | PASS (QA, macOS); PASS (CI 40438138720, KVM; payload sha256 `2a412529…ec241c9a`) |
| Boot smoke preflight | `scripts/boot-smoke.sh` | The lab is usable: firmware sends a PXE DISCOVER, the relay is up as uid 65534, acceleration is known | Harness precondition | OK (CI 40438138720) |
| Boot smoke S1 | `scripts/boot-smoke.sh` | Same-segment UEFI PXE boot: OVMF gets its address from the lab site DHCP server (10.20.1.101), the relay's OFFER has `yiaddr` 0.0.0.0, the relay serves `usgp-test-payload.efi` by TFTP with the manifest digest, and the payload prints `USGP-M1-PAYLOAD-OK` | M1 exit 1 (same segment); REQ-BOOT-001, 003, 010, 011, 030, 031 | PASS (CI 40438138720) |
| Boot smoke S2 | `scripts/boot-smoke.sh` | Cross-subnet boot through the lab DHCP relay agent: the relay's OFFER goes to `giaddr` 10.20.2.1:67, the relay agent gets it back with option 82 unchanged, the guest on 10.20.2.100 downloads the payload and prints the marker | M1 exit 1 (relayed); REQ-BOOT-002, 020, 021, 022 | PASS (CI 40438138720) |
| Boot smoke S3 | `scripts/boot-smoke.sh` | One changed byte (offset 1536) in the served file, relay not restarted: `boot.file.integrity_failed` (`digest_mismatch`), state `running_missing_content`, no DHCP offer to a probe, `--check-config` exits 3, `dhcp.drop.summary` counts `missing_content`, no payload marker on the guest; after the file is restored the relay returns to `running` with the same pid | M1 exit 2 (live); SI-7; REQ-BOOT-052 | PASS (CI 40438138720) |
| Boot smoke S4 | `scripts/boot-smoke.sh` | Live probes against the running relay: a reply on port 67 and on port 4011, each with `yiaddr` 0 and no lease options; 82 DHCP vectors (including non-PXE class and architecture 0) answered or dropped as expected; no offer or ack for the 4 `giaddr-*` vectors; 10,000 random packets give 0 replies and a valid request still gets an offer; rate limit 500 sent, 12 replies (bound 8 to 13); no reply to a DHCP request sent to the relay host on its unconfigured interface `relay9`; WRQ gets ERROR 2; 9 traversal names get ERROR 1; RRQs to 255.255.255.255 and 10.20.1.255 get no reply; a normal RRQ returns identical bytes; `ss` shows exactly `0.0.0.0%relay0:67`, `10.20.1.2%relay0:4011` and `10.20.1.2%relay0:69` and no socket outside `relay0`; relay pid unchanged | M1 exit 4 (bind, malformed, rate, no address); SC-7, CM-7, SI-10, SC-5; REQ-BOOT-004, 005, 006, 010, 040, 041, 042, 044 | PASS (CI 40438138720) |
| Boot smoke S5 | `scripts/boot-smoke.sh` | Secure Boot firmware (`OVMF_CODE_4M.secboot.fd` with `OVMF_VARS_4M.ms.fd`) downloads the verified, unsigned payload from the relay and refuses it (`Access Denied`), then moves to its next boot option; no payload marker | M1 exit 5; SI-7 in transit (device side); POAM-8, POAM-11 compensating control | PASS (CI 40438138720) |
| Boot smoke S6 | `scripts/boot-smoke.sh` | With the guest's MAC in the suppression file the relay logs `dhcp.suppressed` and sends no offer; OVMF reports `PXE-E16: No valid offer received`, its PXEv4 option fails before the disk marker `USGP-M1-DISK-FALLBACK-OK`; after the entry is removed (reload, no restart, same pid) the same guest network-boots the payload | REQ-BOOT-007 (MAC), 050, 051; REQ-BOOT-060 hook only (POAM-16) | PASS (CI 40438138720) |
| Boot smoke S7 | `scripts/boot-smoke.sh` | Lab site DHCP stopped: the relay answers the guest 4 times, each OFFER with `yiaddr` 0.0.0.0; OVMF gets no address, its PXEv4 option fails, and the guest boots from disk | REQ-BOOT-010, 012 | PASS (CI 40438138720) |
| Boot smoke S8 | `scripts/boot-smoke.sh` | Two guests, one on each segment (one relayed), both print the payload marker; their downloads complete within 2 ms of each other; relay pid unchanged. Limit: the stalling probe's transfer started at 02:33:24.6 and the relay ended it with `handshake_timeout` at 02:33:26.6, 4.4 s before the guests' transfers started (02:33:30.99). The scenario therefore shows a stalled client being cut off by the 2 s deadline and two concurrent boots, not boots overlapping a live stalled transfer | REQ-BOOT-034 (concurrency part) | PASS (CI 40438138720), with the limit stated |
| Boot smoke S1 to S8, first CI run | `scripts/boot-smoke.sh` | Run 40434148508 on commit 2c0807c: S4, S6 and S7 failed, as did the `fips-linkage` and `ci-lint` jobs. All causes were harness and script defects (probe expectations for repeated options contrary to RFC 3396; fall-through deadline shorter than OVMF's IPv6 and HTTP boot attempts; a `grep -q` under `pipefail` false negative; shellcheck findings), fixed in 70e3c1f without product code changes | None | Superseded by CI 40438138720; not counted as evidence either way |
| `scripts/check-fips-linkage.sh release` | CI `fips-linkage` job | On Linux, for `usgp-server`, `usgp-relay`, `usgp-preboot-agent` and `usgp-cli` release builds: FIPS module symbols (`aws_lc_fips_*`) are defined in the binary (static linkage), no non-FIPS AWS-LC symbols, no AWS-LC shared library among the dynamic dependencies, and each binary exits 0 from its FIPS start-up check | SC-13; decision 0001 Amendment 1 | PASS (CI 40438138720, job conclusion success; first Linux result). FAIL in run 40434148508 was a script false negative, fixed in 70e3c1f |
| CI `gates`, `testing-workspaces`, `supply-chain`, `markdown`, `ci-lint`, `fuzz-build` jobs | `.github/workflows/ci.yml` | fmt, clippy, workspace and doc tests, pure-Rust and name checks, FIPS start-up of every binary (Linux, debug); testing workspaces including payload reproducibility; `cargo deny` and `cargo audit`; markdownlint; shellcheck and actionlint; fuzz build and seed replay | SA-11, SR-3, CM-2, SC-13 | PASS (CI 40438138720, job conclusions only; per-step logs not reviewed here) |
| CI `fuzz-smoke (dhcp_packet, 1600)` | `.github/workflows/ci.yml`, `fuzz` | 62,568,898 executions in 601 s with `-max_len=1600` on Linux (`ubuntu-24.04`); no crash, OOM or timeout | SI-10, SA-11; M1 exit 3 | PASS (CI 40439279903). Not run in CI 40438138720 (push; the job runs on dispatch and schedule only) |
| CI `fuzz-smoke (tftp_packet, 4096)` | `.github/workflows/ci.yml`, `fuzz` | 9,715,509 executions in 601 s with `-max_len=4096` on Linux (`ubuntu-24.04`); no crash, OOM or timeout | SI-10, SA-11; M1 exit 3 | PASS (CI 40439279903). Not run in CI 40438138720 (push; the job runs on dispatch and schedule only) |
| Boot smoke preflight, `payload-disk` and S1 to S8, re-run | `scripts/boot-smoke.sh` | Same scenarios as the CI 40438138720 rows above, same commit | M1 exit 1 to 5 | PASS (CI 40439279903): `pass=9 fail=0 not_run=0`, preflight OK, relay uid 65534, KVM. Job log only; the per-scenario rows above remain sourced from CI 40438138720 |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-27 | M1 CI fuzz evidence: recorded CI run 40439279903 (`workflow_dispatch`, commit 70e3c1f). Replaced the `fuzz-smoke` NOT RUN row with one PASS row per target (`dhcp_packet` 62,568,898 and `tftp_packet` 9,715,509 executions in 601 s, no crash); added the boot smoke re-run in the same run (`pass=9 fail=0 not_run=0`). |
| 2026-10-27 | M1 CI evidence: recorded CI run 40438138720 (commit 70e3c1f). Boot smoke preflight, `payload-disk` and S1 to S8 PASS, one row per scenario with what it proves; S8 recorded with its stall-timing limit. Recorded the superseded first run 40434148508, the first Linux `fips-linkage` PASS, the other CI job conclusions, and `fuzz-smoke` as NOT RUN in that run. `config_rejected_carries_host_node_name` noted as an inferred Linux PASS, not counted as Tested. |
| 2026-10-26 | M1 final pass (QA report FP.8): round-2 and round-3 tests moved to PASS (QA final pass); added `qa_r3.rs` and the netlab probe test; recorded the final gate run and 60 s fuzz runs; `config_rejected_carries_host_node_name` stays NOT RUN. |
| 2026-10-26 | M1: recorded QA results (initial pass and re-verify round 1), the orchestrator's final gate run after fix round 3, the fuzz runs, boot smoke `payload-disk` as payload-only evidence, and S1 to S8 as NOT RUN. |
