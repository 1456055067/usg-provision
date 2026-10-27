# ATO evidence log

Gate runs recorded as evidence. Entries are added from a run's
`qa-report.md` after QA records the gates; the M0 entry is pending QA.

M1 entries (run `20261026-003451-m1-network-boot`) are copied as reported.
All of them ran on the macOS arm64 development host against the
uncommitted M1 work tree on base commit 44b1083. Results on macOS count
as functional evidence only (POAM-2).

M1 CI entries (2026-10-27) come from GitHub Actions on the private
repository. The first run (40434148508, commit 2c0807c) failed on harness
and script defects and is superseded. Run 40438138720 (commit 70e3c1f,
which changed only `scripts/` and `testing/`) succeeded:
<https://github.com/1456055067/usg-provision/actions/runs/40438138720>.
Its boot smoke evidence is the `boot-smoke-evidence` artifact (30-day
retention); the values below are copied from its `summary.txt`,
`results.txt`, `environment.txt` and `relay.log`.

Run 40439279903 is a manual (`workflow_dispatch`) run on the same commit
70e3c1f, conclusion success, every job success:
<https://github.com/1456055067/usg-provision/actions/runs/40439279903>.
It is the first run of the `fuzz-smoke` job (Linux, `ubuntu-24.04`
runner image 20261012.334, fuzz toolchain from `fuzz/rust-toolchain.toml`,
`cargo-fuzz` 0.13.2). Its fuzz results are copied from the job logs; its
`fuzz-smoke-<target>` artifacts (30-day retention) each hold only the
job's `fuzz.log`.

M2 entries (run `20261026-225553-m2-content-store`, 2026-10-27) ran on the
macOS arm64 development host against the uncommitted M2 work tree on base
commit 55bd6a1, and are functional evidence only (POAM-2). No M2 CI run
exists yet: every PostgreSQL, large-upload, Linux DISM-sample and 600 s
fuzz entry is NOT RUN until CI runs on a commit (POAM-34). The DISM sample
method awaits counsel (OPEN-PE-LIC, POAM-35). The one CI run that touched
M2 is the sample generation run R1 below.

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
| 2026-10-27 | M1 CI 40434148508 (push of 2c0807c) | All CI jobs | Superseded, FAIL: boot smoke S4, S6 and S7, `fips-linkage` and `ci-lint` failed. Causes were in the harness and scripts, not the product (RFC 3396 probe expectations, fall-through deadline, `grep -q` under `pipefail`, shellcheck findings); fixed in 70e3c1f |
| 2026-10-27 | M1 CI 40438138720 (push of 70e3c1f) | Workflow `ci` | PASS (conclusion success). Jobs `gates`, `fips-linkage`, `ci-lint`, `testing-workspaces`, `supply-chain`, `markdown`, `fuzz-build`, `boot-smoke` success; `fuzz-smoke` skipped (dispatch and schedule only) |
| 2026-10-27 | M1 CI 40438138720 | `scripts/check-fips-linkage.sh release` (`fips-linkage` job, `ubuntu-24.04`) | PASS: first Linux evidence that the four release binaries link the FIPS module statically, link no non-FIPS AWS-LC and start in FIPS mode (decision 0001 Amendment 1). Job conclusion; module version and certificate still unconfirmed (POAM-3) |
| 2026-10-27 | M1 CI 40438138720 | `sudo -E scripts/boot-smoke.sh all` (`boot-smoke` job) | PASS: `pass=9 fail=0 not_run=0`, `preflight=OK`. `payload-disk` PASS; S1 PASS (exit 1a); S2 PASS (exit 1b); S3 PASS (exit 2); S4 PASS (exit 4); S5 PASS (exit 5); S6 PASS (REQ-BOOT-050, 051, 060); S7 PASS (REQ-BOOT-012); S8 PASS (REQ-BOOT-034). Per-scenario detail in `docs/compliance/TEST_EVIDENCE.md` |
| 2026-10-27 | M1 CI 40438138720, boot smoke environment | `environment.txt` | Host Linux 6.17.0-1022-azure x86_64 (`ubuntu-24.04` runner); QEMU 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.18); `accel=kvm`; relay uid 65534 (`relay.start` `service_uid` 65534, no warning) |
| 2026-10-27 | M1 CI 40438138720, firmware | SHA-256 from `environment.txt` | `OVMF_CODE_4M.fd` `ad23261d43116abc3747d59a7837fbf578c9586a8993f4eeba064cd07eccb083`; `OVMF_VARS_4M.fd` `5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e`; `OVMF_CODE_4M.secboot.fd` `1286f2a3217d09b374d05951355d7a561c8bacecd74845c8a1fbb71a48c0de8d`; `OVMF_VARS_4M.ms.fd` `a9b2b13aba3d4629593913471af7545bd8eef1d414f33cab4c86fff7d5bc09b9`. The `ovmf` package version is not in the artifact; the CI fix notes match these digests to Ubuntu `ovmf` 2024.02-2ubuntu0.10 |
| 2026-10-27 | M1 CI 40438138720, binaries under test | SHA-256 from `environment.txt` | `usgp-relay` `f0372a594c2181f11275c745e1407a31723c33ac020fb40c7179878d1f0cfd80`; `usgp-cli` `4100f13435dfe03c6f6c663008d780988cb26d2938275f11c69a7fc1d8036307`; `usgp-test-payload.efi` `2a4125291a586d94ba43be5565d7065b6cb57514983fcf67b45a1f9eec241c9a` (equals the reproducible-build digest recorded on 2026-10-26); `disk-fallback.efi` `4811c3db6ca4b95c9a8ed646ff2b29efa9b54e7d03b4decabe36fd61ceb8707e`; lab tools `lab-dhcpd` `02a722cf33597946ac3e7fc2d826ae0afe39e1067227332080aff3f57d214bb6`, `lab-relay-agent` `7273cc8486a744c18d93361196e5de5759b2c21ddb1d01eb78f94ead9195f6ec`, `lab-probe` `128a508444f5f726b80ae85812a6ea01cdd904533d741a4960f57011d8969bb3` |
| 2026-10-27 | M1 CI 40439279903 (dispatch on 70e3c1f) | Workflow `ci` | PASS (conclusion success). Jobs `gates`, `fips-linkage`, `ci-lint`, `testing-workspaces`, `supply-chain`, `markdown`, `fuzz-build`, `boot-smoke`, `fuzz-smoke (dhcp_packet, 1600)` and `fuzz-smoke (tftp_packet, 4096)` success |
| 2026-10-27 | M1 CI 40439279903, fuzz (CI, Linux) | `(cd fuzz) cargo fuzz run dhcp_packet <work> corpus/dhcp_packet -- -max_total_time=600 -max_len=1600 -print_final_stats=1` (`fuzz-smoke` job) | PASS: `Done 62568898 runs in 601 second(s)`, no crash, OOM or timeout. Artifact `fuzz-smoke-dhcp_packet` (log only) SHA-256 `4d70f0e1fa30737c9714564f6b8b6767dd2cb5b2e95842b9b4865fb76dd3da51` |
| 2026-10-27 | M1 CI 40439279903, fuzz (CI, Linux) | `(cd fuzz) cargo fuzz run tftp_packet <work> corpus/tftp_packet -- -max_total_time=600 -max_len=4096 -print_final_stats=1` (`fuzz-smoke` job) | PASS: `Done 9715509 runs in 601 second(s)`, no crash, OOM or timeout. Artifact `fuzz-smoke-tftp_packet` (log only) SHA-256 `fc6171f78b2c07d8a8ddbd8c920a814d6359d35f3289ffa4b67d27655f259cd3` |
| 2026-10-27 | M1 CI 40439279903 | `sudo -E scripts/boot-smoke.sh all` (`boot-smoke` job, re-run) | PASS: `pass=9 fail=0 not_run=0`, preflight OK (relay uid 65534, `accel=kvm`); payload sha256 `2a412529…ec241c9a` as before. From the job log; the environment and digest rows above are from run 40438138720 |
| 2026-10-27 | M2 `wim-samples` R1 (GitHub run 40535666995, attempt 1, commit ba23bed on branch `m2-wim-samples`) | `generate` job on `windows-2025` (`win25-vs2026` 20261021.278.1; Windows build 26100.33650; `Dism.exe` 10.0.26100.32860) | Samples S01 to S07 and S09 produced, every DISM command exit 0, 14 files with SHA-256 in `SHA256SUMS` (verified on macOS). Basis of OBS-001 to OBS-017 in `docs/formats/wim-observed.md`. No S08 (large job not run); S10 to S12 not yet in the scripts at R1. Artifact retention 14 days; keeping it is an owner action subject to OPEN-PE-LIC. The `verify` job result of that run was not reviewed and is not counted as evidence |
| 2026-10-27 | M2 QA gate run | `USGP_WIM_SAMPLES=<local copy of R1> GATES_FUZZ_SECONDS=60 scripts/gates.sh` | Exit 1 (not a PASS): 57 PASS, 1 FAIL, 3 NOT RUN. FAIL: `tftp_packet` libFuzzer timeout during host sleep (environmental; input replays in 0 ms; 60 s re-run PASS, QA-003). NOT RUN: PostgreSQL tests (no database), large upload (`GATES_LARGE` unset; needs Linux and PostgreSQL), boot smoke S1 to S8 (Darwin) |
| 2026-10-27 | M2 QA gate run | `cargo test --locked --workspace`; `--doc`; `cargo test --workspace --release` | PASS: 1054 passed, 0 failed, 0 ignored; 2 doc tests; release 1055 passed after QA's last test |
| 2026-10-27 | M2 QA gate run | `cargo test --locked -p usgp-crypto --features test-pki`; `-p usgp-image --features testkit`; `-p usgp-image --features dism-samples` (local R1) | PASS: 85; 109; 112 (including 3 `dism_samples`) |
| 2026-10-27 | M2 QA gate run | `cargo clippy` (default and all test features), `cargo fmt --check`, `scripts/check-pure-rust.sh`, `scripts/check-names.sh`, `cargo deny --locked check`, `cargo audit`, `scripts/check-fips-linkage.sh debug`, `no_test_features_shipped`, markdownlint, release build with `scripts/check-artifact-names.sh` | PASS. FIPS linkage on macOS is functional only |
| 2026-10-27 | M2 QA gate run | fuzz 60 s per target via `gates.sh` | `wim_header` 1,033,001, `wim_xml` 757,271, `xpress_chunk` 64,749, `wim_lookup` 861,119, `wim_check` 512,166, `api_json` 2,042,420, `dhcp_packet` 9,118,931 runs, no crash; `tftp_packet` environmental FAIL, re-run PASS (1,495,382 runs). Smoke only: the 10-minute runs of M2 exit 2 are NOT RUN |
| 2026-10-27 | M2 QA gate run | spec traceability check | NOT RUN at QA time (QA-002); the M2 section of `SPEC_TRACEABILITY.md` was added afterwards in this documentation change |
| 2026-10-27 | M2 fix round 1 (coders, local) | `scripts/check-pe-files.sh repo`; `scripts/test-check-pe-files.sh`; `USGP_WIM_SAMPLES=<R1> cargo test -p usgp-image --features dism-samples` | PASS: 508 files OK (22 WIM-signature files, all builder seeds); 43 cases OK; 4 `dism_samples` tests, every compressed R1 resource decodes (83 resources, 369 chunks). Not QA-confirmed |
| 2026-10-27 | M2 re-verify round 2 (reviewers, local) | `cargo test --offline -p usgp-audit -p usgp-api -p usgp-server -p usgp-crypto --features usgp-crypto/test-pki`; `cargo test -p usgp-image --features testkit` | PASS: 307 passed, 0 failed; 46 unit, 14 check, 35 negative, 28 xpress_vectors. Not QA-confirmed |
| 2026-10-27 | M2, PostgreSQL | `cargo test --workspace --features pg-integration` (CI `pg-integration`) | NOT RUN. Locally, without `USGP_TEST_PG_*`, the PostgreSQL targets fail by design (fail, not skip) |
| 2026-10-27 | M2, large upload | `cargo test -p usgp-server --release --features pg-integration,large-tests --test large_upload_pg` (CI `large-upload`) | NOT RUN (exit 1b) |
| 2026-10-27 | M2, DISM samples on Linux | `wim-samples` `verify` job | NOT RUN on the M2 code |
| 2026-10-27 | M2, fuzz 600 s | CI `fuzz-smoke` for `wim_header`, `wim_xml`, `xpress_chunk` | NOT RUN (exit 2b). Whether AWS-LC FIPS builds under the fuzz sanitizer on Linux is unproven (REL-M2-CI-002) |
| 2026-10-27 | M2, real media | MT-1 | NOT RUN (owner action with licensed media; exit 1c) |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-27 | M2 (content store, uncommitted on 55bd6a1): recorded the `wim-samples` generation run R1 (40535666995), the M2 QA gate run (exit 1: 57 PASS, 1 environmental FAIL, 3 NOT RUN; 1054 tests passed), the fix-round and re-verify local runs (not QA-confirmed), and NOT RUN entries for PostgreSQL, large upload, Linux DISM-sample verification, 600 s fuzzing and MT-1. Flagged OPEN-PE-LIC against the DISM sample method. |
| 2026-10-27 | M1 CI fuzz evidence: recorded dispatched run 40439279903 (all jobs success), its two 600 s `fuzz-smoke` results on Linux beside the local 600 s runs, the artifact digests, and the boot smoke re-run (9 PASS, 0 FAIL, 0 NOT RUN). Replaced the pending `fuzz-smoke` row; no CI rows remain pending. |
| 2026-10-27 | M1 CI evidence: recorded run 40438138720 (all jobs success, boot smoke 9 PASS, 0 FAIL, 0 NOT RUN), its environment, firmware and binary digests, the first Linux `fips-linkage` PASS, and the superseded run 40434148508. Replaced the pending `boot-smoke` row; `fuzz-smoke` stays pending. |
| 2026-10-26 | M1 final pass: recorded QA's final gate run, test totals, 60 s fuzz runs and the passing traceability check. |
| 2026-10-26 | M1: recorded the QA gate runs (initial pass and re-verify round 1), the fuzz runs, the orchestrator's final gate run, and the pending CI jobs. |
