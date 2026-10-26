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
| `tests/startup.rs::config_rejected_carries_host_node_name` | `usgp-relay` | Configuration rejections carry the host name | AU-3 | NOT RUN (Linux only; not compiled on the macOS host) |
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
| Boot smoke `payload-disk` | `scripts/boot-smoke.sh` | The test payload, booted from a disk image by OVMF under QEMU, prints its marker on serial. Proves the payload only: no relay, no network, no Secure Boot | Test payload for M1 exit 1 | PASS (QA) |
| Boot smoke S1 to S8 | `scripts/boot-smoke.sh` | Live network boot, same segment and relayed; tamper; bind and probes; Secure Boot refusal; suppression; no site DHCP; two guests | M1 exits 1, 4 (bind part) and 5; REQ-BOOT-011, 012, 042, 051, 060 | NOT RUN (Darwin host; pending the CI `boot-smoke` job) |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-26 | M1 final pass (QA report FP.8): round-2 and round-3 tests moved to PASS (QA final pass); added `qa_r3.rs` and the netlab probe test; recorded the final gate run and 60 s fuzz runs; `config_rejected_carries_host_node_name` stays NOT RUN. |
| 2026-10-26 | M1: recorded QA results (initial pass and re-verify round 1), the orchestrator's final gate run after fix round 3, the fuzz runs, boot smoke `payload-disk` as payload-only evidence, and S1 to S8 as NOT RUN. |
