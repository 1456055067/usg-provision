# ATO evidence log

Gate runs recorded as evidence. Entries are added from a run's
`qa-report.md` after QA records the gates; the M0 entry is pending QA.

M1 entries (run `20261026-003451-m1-network-boot`) are copied as reported.
All of them ran on the macOS arm64 development host against the
uncommitted M1 work tree on base commit 44b1083. Results on macOS count
as functional evidence only (POAM-2). No CI run of the M1 jobs exists yet.

| Date | Run | Command | Result |
|------|-----|---------|--------|
| 2026-10-26 | M1 WU-8 fuzz | `(cd fuzz) cargo fuzz run dhcp_packet <work> corpus/dhcp_packet -- -max_total_time=600 -max_len=1600` | PASS: 152,795,348 executions in 601 s, no crash, OOM or timeout |
| 2026-10-26 | M1 WU-8 fuzz | `(cd fuzz) cargo fuzz run tftp_packet <work> corpus/tftp_packet -- -max_total_time=600 -max_len=4096` | PASS: 26,315,233 executions in 601 s, no crash, OOM or timeout |
| 2026-10-26 | M1 QA, initial pass | `GATES_FUZZ_SECONDS=60 scripts/gates.sh` | FAIL (exit 1): 37 PASS, 2 FAIL (the timed fuzz step had a harness defect, not a crash; QA-002), 1 NOT RUN (boot smoke) |
| 2026-10-26 | M1 QA, initial pass | `cargo test --locked --workspace` | PASS: 464 passed, 0 failed, 0 ignored |
| 2026-10-26 | M1 QA, initial pass | spec traceability check over the 32 brief REQ IDs | FAIL: 0 of 32 present (QA-003; this documentation change) |
| 2026-10-26 | M1 QA, initial pass | `scripts/boot-smoke.sh all` | `payload-disk` PASS (payload marker on serial; payload-only evidence). S1 to S8 NOT RUN (exit 77, Darwin host) |
| 2026-10-26 | M1 QA, re-verify round 1 | `GATES_FUZZ_SECONDS=60 scripts/gates.sh` | Exit 77: 40 PASS, 0 FAIL, 1 NOT RUN (boot smoke S1 to S8) |
| 2026-10-26 | M1 QA, re-verify round 1 | `cargo test --locked --workspace` | PASS: 510 passed, 0 failed, 0 ignored |
| 2026-10-26 | M1 QA, re-verify round 1 | `cargo deny --locked check`; `cargo audit` (root, `testing/*`, `fuzz`) | PASS |
| 2026-10-26 | M1 QA, re-verify round 1 | `cargo build --release --locked -p usgp-relay -p usgp-cli`; `scripts/check-artifact-names.sh` | PASS: `artifact-names: OK (26 files scanned)` |
| 2026-10-26 | M1 QA, re-verify round 1 | `scripts/boot-smoke.sh build` | PASS: payload sha256 `2a412529…ec241c9a` (reproducible build) |
| 2026-10-26 | M1 QA, re-verify round 1 | spec traceability check | FAIL: 0 of 32 present (QA-003; this documentation change) |
| 2026-10-26 | M1 orchestrator, after fix round 2 | `(cd fuzz) cargo fuzz run tftp_packet …` for 600 s | PASS: 10,934,114 executions, no crash; one slow-unit artifact, not a crash |
| 2026-10-26 | M1 orchestrator, final gate run after fix round 3 | `scripts/gates.sh` | No failures. 576 tests passed, 0 failed. NOT RUN: timed fuzz inside `gates.sh` (time variable unset) and boot smoke S1 to S8 (Darwin host) |
| 2026-10-26 | M1 QA, final pass | `GATES_FUZZ_SECONDS=60 scripts/gates.sh` | Exit 77 (not a PASS): 40 PASS, 0 FAIL, 1 NOT RUN (boot smoke S1 to S8, Darwin host) |
| 2026-10-26 | M1 QA, final pass | `cargo test --locked --workspace`; netlab, uefi-payload and doc tests | PASS: 581 tests in total (531 workspace, 41 netlab, 8 uefi-payload, 1 doctest), 0 failed. `startup::config_rejected_carries_host_node_name` NOT RUN (Linux only) |
| 2026-10-26 | M1 QA, final pass | `(cd fuzz) cargo fuzz run <target> … -- -max_total_time=60` via `gates.sh` | PASS: `dhcp_packet` 11,061,574 runs, `tftp_packet` 1,005,497 runs, no crash, no new artifact |
| 2026-10-26 | M1 QA, final pass | spec traceability check over the 32 brief REQ IDs | PASS: 32 of 32 present (QA-003 closed) |
| Pending | M1 CI | `boot-smoke` job (Linux, sudo, OVMF with Secure Boot keys) | NOT RUN. M1 exits 1 and 5 and the bind part of exit 4 stay NOT RUN until a green run (POAM-17) |
| Pending | M1 CI | `fuzz-smoke` job (600 s per target) | NOT RUN |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-26 | M1 final pass: recorded QA's final gate run, test totals, 60 s fuzz runs and the passing traceability check. |
| 2026-10-26 | M1: recorded the QA gate runs (initial pass and re-verify round 1), the fuzz runs, the orchestrator's final gate run, and the pending CI jobs. |
