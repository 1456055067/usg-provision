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

M2 CI entries (2026-10-27) come from GitHub Actions on commit d72b761
(the M2 commit 5d3c8c7 plus CI fixes), on the GitHub-hosted
`ubuntu-24.04` runner image 20261012.334.1. Values are copied from the
job logs (`gh run view <id> --log`) and artifact digests from the
GitHub API. The `ci` runs on 5d3c8c7 (40599553314) and the `verify` job
of `wim-samples` run 40599556702 failed on log parsing (coloured cargo
output) that d72b761 fixed. They are superseded and are not counted
either way. The `generate` and `generate-large` jobs of 40599556702
(R2) are counted as sample production only. On d72b761 **M2 was not
met:** `pg-integration` failed, `repo_pg` and `e2e_pg` did not run, and
MT-1 had not run (POAM-33, POAM-34).

The S11/S12 WIM change (run `20261027-181908-m2-s11-s12`, uncommitted on
d72b761 when first recorded) has no QA report. Its local entries are the
coder's and reviewers' runs on macOS, as written in the run's notes and
findings. It was committed as 5ea03a1.

CI entries on commit 5ea03a1 (runs started 2026-10-28 UTC; the S11/S12
change on top of 4cad7ec, which fixed `newer_schema_refused`) come from
`ci` runs 40633650457 (dispatch) and 40633638960 (push) and
`wim-samples` runs 40633638946 (push) and 40633653170 (dispatch). Every
one ended in success. Values are copied from the job logs
(`gh run view <id> --log`), and artifact digests come from the GitHub
API. These closed POAM-34.

M2 exit criteria, with the labels of the M2 gate:

| Exit | Evidence on 5ea03a1 |
|------|---------------------|
| 1a. Real Windows 11 Enterprise media (MT-1) | NOT RUN (owner action, licensed media; POAM-33) |
| 1b. Synthetic 10.5 GiB flow end to end on PostgreSQL | CI PASS (`large-upload`, 40633650457) |
| 2a. Malformed or tampered images refused | CI PASS (`gates` negative and check tests; `wim-samples` `verify`) |
| 2b. 10-minute fuzz runs | CI PASS (`fuzz-smoke`, 40633650457), without ASan (POAM-37) |
| 3. Route table and audit tamper detection | CI PASS (`gates`; `audit_pg` on PostgreSQL) |
| 4. Unauthenticated access refused, end to end | CI PASS (`gates`; `e2e_pg` on PostgreSQL) |

M2 is met except exit 1a (MT-1, owner action), so M2 is **not met**.

M3 entries (run `20261028-104815-m3-preboot-apply`, branch `m3/build`,
2026-10-28 and 2026-10-29) come from the M3 QA report's gate run on the
macOS arm64 development host at commit 647af22 (functional evidence
only, POAM-2), the review fix rounds' local runs (not QA-confirmed), and
four CI runs. The CI results are recorded as the orchestrator stated
them: run 40818350636 (647af22) before the reviews; 40876728637
(349de13); 40910029759 (fff029f); and 40928612312 (21c1efb, the current
head at the time), conclusion failure in `windows-agent` only (POAM-53,
since closed). CI run 40980499705 (commit 7cd5ecf, after fix rounds 4
to 7) then passed all 35 jobs.

M3 exit criteria (roadmap M3):

| Exit | Evidence |
|------|----------|
| 1. Lab install with an operator-built Windows PE and a Windows 11 Enterprise WIM | **NOT RUN** (owner lab MT-2, L1 to L12; POAM-59). CI parts: the agent and server on a simulated platform with a synthetic WIM (QA M3; CI 40818350636 `gates`); our GPT under OVMF (S10 PASS, CI 40876728637); the relay's BOOT-5 stop with OVMF (S9 PASS, CI 40910029759); TFTP wraparound in-process (QA M3) |
| 2. Disk-layout tests on files only; too small, existing partitions, removable and boot-media disks refused | PASS (QA M3): `usgp-disk` tests on loopback and image files only; `eligibility` refusals; agent `qa_m3::install_beside_removable_and_boot_disks_touches_only_the_target` |
| 3. No wipe without a durable `disk.wipe.authorised` record, tested by failing the audit write | PASS (QA M3, memory store): `api::device_session::wipe_record_failure_creates_no_job`, agent `sim_e2e::wipe_record_failure_starts_nothing`, `disk::wipe::refused_without_durable_record_nothing_written`, `deploy::engine::plan_without_a_durable_wipe_record_is_refused`. PostgreSQL: the deferred `job_wipe_authorised` trigger (`repo_pg::m3_wipe_guard`) PASS in CI 40818350636; the PostgreSQL audit-write fault (`repo_pg::m3_wipe_record_failure_creates_no_job`, QA-005) PASS in CI 40928612312 |
| 4. A tampered chunk or plan signature fails the job before any disk write, with a persistent error at the device and in the job status | PASS (QA M3): `deploy::engine` tamper tests; agent `sim_e2e::tampered_chunk_fails_before_any_write`, `approval_path_with_a_wrong_plan_key_writes_nothing`; agent `qa_m3` plan payload, plan signature and chunk tests (exit 4, nothing written, same failure fields at the device and in the job). Real Windows: MT-2 L11 NOT RUN |

M3 is **not met**: exit 1 is NOT RUN. CI on the current commit (run
40980499705) is green.

**Wipe guard and audit before the wipe (SI-17, AU-5; REQ-DISK-006;
decision 0018 item 7).** The chain of evidence:

1. The server creates the job, the `disk.wipe.authorised` record and the
   `job.created` record in one transaction; the plan is signed only after
   it commits
   ([`confirm.rs`](../../crates/usgp-api/src/device/confirm.rs)).
2. In PostgreSQL the deferred constraint trigger `job_wipe_authorised`
   refuses to commit a job whose `wipe_audit_seq` and `wipe_record_hash`
   do not name a successful `disk.wipe.authorised` record for that job
   ([`0004_device_sessions_jobs.sql`](../../crates/usgp-db/migrations/0004_device_sessions_jobs.sql)).
3. The plan carries the record's sequence number and hash; the agent can
   build the wipe authorisation only from a verified plan
   (`WipeAuthorisation::from_verified_plan`,
   [`executor.rs`](../../crates/usgp-disk/src/executor.rs)), and the
   wipe refuses a zero sequence number or hash.
4. Tests: the four exit-3 tests above (QA M3); `repo_pg::m3_wipe_guard`
   (CI 40818350636); fix-round M3: `disk::wipe::authorisation_comes_from_the_verified_plan`,
   `repo_pg::m3_wipe_record_failure_creates_no_job` (PASS in CI
   40928612312), and two
   `compile_fail` doctests showing that no other code can construct the
   authorisation.
5. Limits: the wipe is not a sanitisation (POAM-47); after the wipe the
   device continues while the server answers 503 (POAM-41).

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
| 2026-10-27 | M2, PostgreSQL | `cargo test --workspace --features pg-integration` (CI `pg-integration`) | NOT RUN at the time of the M2 QA run. Locally, without `USGP_TEST_PG_*`, the PostgreSQL targets fail by design (fail, not skip). First CI result: CI 40601242085 below |
| 2026-10-27 | M2, large upload | `cargo test -p usgp-server --release --features pg-integration,large-tests --test large_upload_pg` (CI `large-upload`) | NOT RUN at the time of the M2 QA run (exit 1b). First CI result: CI 40601242085 below |
| 2026-10-27 | M2, DISM samples on Linux | `wim-samples` `verify` job | NOT RUN on the M2 code at the time of the M2 QA run. First result: runs 40601244164 and 40601244679 below |
| 2026-10-27 | M2, fuzz 600 s | CI `fuzz-smoke` for `wim_header`, `wim_xml`, `xpress_chunk` | NOT RUN at the time of the M2 QA run (exit 2b). Whether AWS-LC FIPS builds under the fuzz sanitizer on Linux was unproven (REL-M2-CI-002); it does not, see POAM-37. First CI result: CI 40601242085 below |
| 2026-10-27 | M2, real media | MT-1 | NOT RUN (owner action with licensed media; exit 1a) |
| 2026-10-27 | M2 CI 40601242085 (dispatch on d72b761) | Workflow `ci` (<https://github.com/1456055067/usg-provision/actions/runs/40601242085>) | Conclusion failure. Success: `gates`, `fips-linkage`, `supply-chain`, `markdown`, `ci-lint`, `testing-workspaces`, `fuzz-build`, `boot-smoke`, `large-upload` and all eight `fuzz-smoke` jobs. Failure: `pg-integration` |
| 2026-10-27 | M2 CI 40601244276 (push of d72b761) | Workflow `ci` | Conclusion failure. The same job results as 40601242085; `large-upload` and `fuzz-smoke` skipped (dispatch and schedule only). `pg-integration` failed on the same test |
| 2026-10-27 | M2 CI 40601242085, `gates` | `cargo test --workspace --locked`; `--doc`; feature-gated `usgp-crypto test-pki` and `usgp-image testkit` | PASS on Linux: 1122 passed, 0 failed, 0 ignored (75 test binaries); doc 2 passed; feature-gated 217 passed (11 test binaries; corrected 2026-10-28 from 347, which also counted the step's 6 summary lines). Includes `startup::config_rejected_carries_host_node_name ... ok` (Linux only) |
| 2026-10-27 | M2 CI 40601242085, `fips-linkage` | `scripts/check-fips-linkage.sh release`; `scripts/check-pe-files.sh`; `scripts/check-artifact-names.sh` | PASS: `fips-linkage: OK (Linux; usgp-server usgp-relay usgp-preboot-agent usgp-cli)` on the M2 code; `pe-files: OK (repo: 515 files checked)`; shipped binaries name scan and REQ-PE-001 OK (4 files). Module version and certificate still unconfirmed (POAM-3) |
| 2026-10-27 | M2 CI 40601242085, `pg-integration` | `scripts/pg-test-setup.sh up`; `cargo test --features pg-integration` (`migrate_pg`, `repo_pg`, `audit_pg`, `e2e_pg` required) | **FAIL.** Setup checks OK: PostgreSQL 16.15, loopback only, TLS on with minimum TLSv1.2, certificate-only login for `usgp_app`, `usgp_owner` and `usgp_admin` (no role has a password); plaintext, TLS without a client certificate, CN mismatch and a SCRAM-requesting role refused. `audit_pg`: 9 passed, 0 failed. `migrate_pg`: 8 passed, 1 failed (`t::newer_schema_refused`, panicked at `crates/usgp-db/tests/migrate_pg.rs:96`; stale test using version 3 after migration 0003; fix staged, not committed, not run). `repo_pg` and `e2e_pg`: NOT RUN, because cargo stopped at the failing binary. Configuration re-check after the tests OK; container and test keys removed |
| 2026-10-27 | M2 CI 40601244276, `pg-integration` | As above | **FAIL**, same result: `audit_pg` 9 passed; `migrate_pg` 8 passed, 1 failed (`newer_schema_refused`); `repo_pg` and `e2e_pg` NOT RUN |
| 2026-10-27 | M2 CI 40601242085, `large-upload` | `cargo test -p usgp-server --release --locked --features pg-integration,large-tests --test large_upload_pg -- --nocapture`, PostgreSQL 16 with certificate-only login, 85 GiB free before the build (14 GiB required) | **PASS** (exit 1b, synthetic content): `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 77.14s`. `large: built 11274513842 bytes in 6.723434944s`; `large: source digests (1345 chunks) in 15.770641451s`; `large: flow (upload, check, package, download) in 53.585264595s`; `large: server peak RSS 51 MiB (VmHWM), max sampled VmRSS 51 MiB; test client peak RSS 10 MiB` (asserted bound 256 MiB); `large: total 76.579889349s`. The superseded run 40599553314 logged the same test passing (server peak 48 MiB) but its job failed on log parsing; it is not counted |
| 2026-10-27 | M2 CI 40601242085, fuzz (Linux, `--sanitizer none`) | `(cd fuzz) cargo fuzz run --sanitizer none <target> <work> corpus/<target> -- -max_total_time=<secs> -max_len=<len> -rss_limit_mb=2048 -timeout=10 -print_final_stats=1` (`fuzz-smoke` matrix; `cargo-fuzz` 0.13.2) | **PASS**, no crash, OOM or timeout, every job at its full length (exit 2b for the three 600 s WIM and XPRESS targets): `wim_header` 382,136,141 runs in 601 s; `wim_xml` 33,448,792 runs in 601 s; `xpress_chunk` 920,693 runs in 601 s; `dhcp_packet` 598,515,071 runs in 601 s; `tftp_packet` 54,257,019 runs in 601 s; `wim_lookup` 6,558,248 runs in 61 s; `wim_check` 3,330,146 runs in 61 s; `api_json` 10,167,032 runs in 61 s (from `Done N runs` and `stat::number_of_executed_units`). Without ASan (POAM-37). Artifacts (log only, 30-day retention) SHA-256: `fuzz-smoke-wim_header` `fff17ec0b664236b12fff930333b7ba71a9b03276791eabc6dd5bf03cab80c05`; `fuzz-smoke-wim_xml` `84c37bfabb062c812595a38ca7cc4667c9573e60037bacfcacd74d0e9d5c821a`; `fuzz-smoke-xpress_chunk` `2e46fd1d8b3d78e11f9f3ab08babc754abd8395f5c08003e5b1d73b9d4959472`; `fuzz-smoke-dhcp_packet` `03fc25687eff1c3984c75aac22e9ed468d5ab34969d886652c68b7cda5aeac24`; `fuzz-smoke-tftp_packet` `4a9dfa76da55c061a17c04f3bf98aef1dff88bcd948d60ad553adb1743fa2edb`; `fuzz-smoke-wim_lookup` `384aa9c323f39ed0a5b26a0d92b2dcfcce951311a849cf27615dd7ab5afb6e2c`; `fuzz-smoke-wim_check` `4ae49ecd60751adcd6f0ba1f7a00180568f9813cb9af7b1a749bb98c4044862f`; `fuzz-smoke-api_json` `df7010dfd8acc29de10eb74d29fceab4a07a61d61229814d2554a498c92c17f3` |
| 2026-10-27 | M2 CI 40601242085, `boot-smoke` | `sudo -E scripts/boot-smoke.sh all` | PASS: `totals: pass=9 fail=0 not_run=0`, on the M2 code. Artifact `boot-smoke-evidence` SHA-256 `1c535ac23560c3b58e474ebb1b038f73eea8e5fc4388f5166e659a743443e3c2` (job log reviewed, artifact contents not) |
| 2026-10-27 | M2 `wim-samples` R2 (GitHub run 40599556702, commit 5d3c8c7) | `generate` and `generate-large` jobs on `windows-2025` (`win25-vs2026` 20261021.278.1; DISM as R1) | Samples produced, including S10, S11A, S11B, S12A, S12B and the large S08 (in the separate large-observations artifact). 19 files in `SHA256SUMS` (verified on macOS for the S11/S12 change). Basis of OBS-018 to OBS-023. S08 and S10 have no OBS record yet. The run's `verify` job failed on log parsing and is superseded |
| 2026-10-27 | M2 `wim-samples` 40601244164 (push of d72b761) and 40601244679 (dispatch) | `generate` on Windows, then `verify` on Linux (`sha256sum --strict -c SHA256SUMS`, `cargo test -p usgp-image --features dism-samples`) | **PASS** (conclusion success; `generate-large` skipped). `SHA256SUMS`: 19 of 19 files OK in each run, including S10, S11A, S11B, S12A and S12B. `dism_samples`: `test result: ok. 4 passed`; `decoded 171 compressed resources, 747 chunks`; `wim-samples verify: PASS`. Committed checker verdicts kept as notices (BOOT-015): `observe S11A` and `S11B` refused `wim_resource_overlap`; `observe S12A` refused `wim_metadata_order_not_supported`; `observe S12B` accepted, 12 images, XPRESS. Artifact `wim-samples` SHA-256 `7d4bc4dacd71897d7835c9567bac6844cccc3248d8a76c9d7b342d79ce6a5666` (40601244164) and `81ea9195b2892301862bd2e211102886cc8ea55b985a988bbfe04fb39d6af135` (40601244679), 14-day retention, subject to OPEN-PE-LIC |
| 2026-10-27 | S11/S12 change (local, macOS, uncommitted on d72b761) | `cargo test -p usgp-image --features testkit`; `USGP_WIM_SAMPLES=<R2 copy> cargo test -p usgp-image --features dism-samples`; the same with R1 | PASS after fix round 1: 50 lib, 17 check, 39 negative, 28 xpress_vectors, 0 failed, 0 ignored. With R2: 5 `dism_samples` passed; S11A, S11B (OBS-018), S12A (OBS-021) and S12B (OBS-023) judged `accept`; 171 resources and 747 chunks decode. With R1: 5 passed. Boot-protocol and security reviewers repeated the runs and approved (re-verify round 1). Not QA-confirmed; no CI run |
| 2026-10-27 | S11/S12 change (local, macOS) | `cargo clippy --workspace --all-targets --features test-pki,testkit,dism-samples -- -D warnings`; `cargo fmt --all --check` (root and `fuzz`); `scripts/check-names.sh`; markdownlint 0.45.0 on the changed format, script and corpus docs | PASS (coder, fix round 1) |
| 2026-10-27 | S11/S12 change (local, macOS) | `(cd fuzz) cargo fuzz run --sanitizer none wim_check …` and `wim_lookup …` | PASS: coder 120 s each, 2,794,572 and 3,661,338 runs; security reviewer 60 s each, 1,505,876 and 1,848,299 runs; no crash. Generated inputs written to scratch directories only |
| 2026-10-28 | M2 CI 40633650457 (dispatch on 5ea03a1) | Workflow `ci` (<https://github.com/1456055067/usg-provision/actions/runs/40633650457>) | Conclusion success. All 18 jobs success: `gates`, `fips-linkage`, `supply-chain`, `markdown`, `ci-lint`, `testing-workspaces`, `fuzz-build`, `boot-smoke`, `pg-integration`, `large-upload` and all eight `fuzz-smoke` jobs. Runner image `ubuntu-24.04` 20261012.334.1 (`ci-lint` 20261025.353.1) |
| 2026-10-28 | M2 CI 40633638960 (push of 5ea03a1) | Workflow `ci` | Conclusion success. Nine jobs success, including `gates`, `pg-integration` and `boot-smoke`; `large-upload` and `fuzz-smoke` skipped (dispatch and schedule only). Runner images 20261012.334.1 and 20261025.353.1 |
| 2026-10-28 | M2 CI 40633650457 and 40633638960, `gates` | `cargo test --workspace --locked`; `--doc`; feature-gated `usgp-crypto test-pki` and `usgp-image testkit`; `scripts/check-pe-files.sh repo`; `scripts/test-check-pe-files.sh` | PASS on Linux, the same counts in both runs: 1133 passed, 0 failed, 0 ignored (75 test binaries); doc 2 passed; feature-gated 228 passed (11 test binaries). Every S11/S12 test named in `TEST_EVIDENCE.md` reports `... ok`. `pe-files: OK (repo: 525 files checked)`; `test-check-pe-files: OK (43 cases)` |
| 2026-10-28 | M2 CI 40633650457 and 40633638960, `fips-linkage` | `scripts/check-fips-linkage.sh release`; `scripts/check-pe-files.sh`; `scripts/check-artifact-names.sh` | PASS: `fips-linkage: OK (Linux; usgp-server usgp-relay usgp-preboot-agent usgp-cli)`; `artifact-names: OK`. Module version and certificate still unconfirmed (POAM-3) |
| 2026-10-28 | M2 CI 40633650457 and 40633638960, `pg-integration` | `scripts/pg-test-setup.sh up`; `cargo test --features pg-integration` (`migrate_pg`, `repo_pg`, `audit_pg`, `e2e_pg` required) | **PASS** in both runs. First, each of the four targets fails without a database (exit 101). Setup checks OK: PostgreSQL 16.15, loopback only, TLS on with minimum TLSv1.2, certificate-only login for `usgp_app`, `usgp_owner` and `usgp_admin` (no role has a password); plaintext, TLS without a client certificate, CN mismatch and a SCRAM-requesting role refused. `ok: usgp-db:migrate_pg: test result: ok. 9 passed; 0 failed` (including `t::newer_schema_refused ... ok`); `ok: usgp-db:repo_pg: ... 9 passed; 0 failed`; `ok: usgp-db:audit_pg: ... 9 passed; 0 failed`; `ok: usgp-server:e2e_pg: ... 1 passed; 0 failed` (`e2e::e2e_flow_on_postgres`). Configuration re-check after the tests OK; container and test keys removed |
| 2026-10-28 | M2 CI 40633650457, `large-upload` | `cargo test -p usgp-server --release --locked --features pg-integration,large-tests --test large_upload_pg -- --nocapture`, PostgreSQL 16 with certificate-only login, 85 GiB free before the build (14 GiB required) | **PASS** (exit 1b, synthetic content): `test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 96.59s`. `large: built 11274513842 bytes in 6.052903714s`; `large: source digests (1345 chunks) in 14.067691922s`; `large: flow (upload, check, package, download) in 75.333460581s`; `large: server peak RSS 54 MiB (VmHWM), max sampled VmRSS 54 MiB; test client peak RSS 11 MiB` (asserted bound 256 MiB); `large: total 96.039468489s` |
| 2026-10-28 | M2 CI 40633650457, fuzz (Linux, `--sanitizer none`) | As for CI 40601242085 (`fuzz-smoke` matrix) | **PASS**, no crash, OOM or timeout, every job at its full length (exit 2b for the three 600 s WIM and XPRESS targets): `wim_header` 275,851,924 runs in 601 s; `wim_xml` 21,156,384 runs in 601 s; `xpress_chunk` 1,074,856 runs in 601 s; `dhcp_packet` 331,607,505 runs in 601 s; `tftp_packet` 23,123,929 runs in 601 s; `wim_lookup` 5,571,523 runs in 61 s; `wim_check` 1,973,773 runs in 61 s; `api_json` 7,424,454 runs in 61 s (from `Done N runs` and `stat::number_of_executed_units`). The `wim_lookup` and `wim_check` targets include the S11/S12 reference model. Without ASan (POAM-37). Artifacts (log only, 30-day retention) SHA-256: `fuzz-smoke-wim_header` `b6c628f9ce4f7bbc71e1c4793072b58574e47a0d08734d2e0e3690ef8b958bf1`; `fuzz-smoke-wim_xml` `35f2818a98672349ea6f498c6b62af4a76945d46caf6f3e305a847dfb4e686b3`; `fuzz-smoke-xpress_chunk` `689d2b3de978a63bad13e359d050f636fcc0bd5ac39f293831b32b307f6af26c`; `fuzz-smoke-dhcp_packet` `70970f8f2f49ae1a9f46f55baad04ba2cb25a628e7827455d2b60164197f3a80`; `fuzz-smoke-tftp_packet` `fe3a8599d0c1a5f84b7aa49d2a7b26b7ae80ee146dae259004fbb0790b04d11a`; `fuzz-smoke-wim_lookup` `d1e2aa81e2472e1ab6b85226210a7ae80f22f4deeada716f004b7e33753bc7a0`; `fuzz-smoke-wim_check` `bed6e79603e9ef12f276168af50f1ea99d7de840c1fa6d3257165347424c86a5`; `fuzz-smoke-api_json` `de445706265555229b1758d6ad404bd52854ee81d4609c7601983e3d5833cff2` |
| 2026-10-28 | M2 CI 40633650457 and 40633638960, `boot-smoke` | `sudo -E scripts/boot-smoke.sh all` | PASS in both runs: `totals: pass=9 fail=0 not_run=0`. Artifact `boot-smoke-evidence` SHA-256 `7120433e7ed82efad810d72f42f8190a485df197d83a573d7b0ce4151efc23db` (40633650457) and `6dab085a2f0c14b507f7cca12b39ac839cf9180385ff800fb0bfa714611f206a` (40633638960) (job logs reviewed, artifact contents not) |
| 2026-10-28 | M2 `wim-samples` 40633638946 (push of 5ea03a1) and 40633653170 (dispatch) | `generate` on Windows (`windows-2025-vs2026` 20261021.278.1), then `verify` on Linux (`sha256sum --strict -c SHA256SUMS`, manifest check with required ids S01 to S07, S09, S10, S11A, S11B, S12A and S12B, `cargo test -p usgp-image --features dism-samples`) | **PASS** (conclusion success; `generate-large` skipped). `SHA256SUMS`: 19 of 19 files OK in each run. `dism_samples`: `test result: ok. 5 passed; 0 failed; 0 ignored`, including `dism::serviced_layouts_match_observations ... ok` and `dism::every_sample_meets_its_expectation ... ok`; `decoded 171 compressed resources, 747 chunks`; `wim-samples verify: PASS`. With the S11/S12 rules, S11A, S11B, S12A and S12B are judged `accept` by the test's `RECORDED` table. Artifact `wim-samples` SHA-256 `07cb575a5b424cb77934ee47b98e65218e88c694c04c79be0e6b1271c721ec84` (40633638946) and `9d4c5ffd8b564f4243813e98a244ff701c9ac228cb444f93b8ea183b8e57063d` (40633653170), 14-day retention, subject to OPEN-PE-LIC. Artifact `wim-samples-observations` (148 bytes each; contents not reviewed) SHA-256 `66abee6b17f45fc948bf2ecf0628848777a711cb21d873b3bd4c9257d33710ff` and `edf6f7c861a0fdaaf3666b651baa936b086544f319872bb392b60cd563b4e451` |
| 2026-10-29 | M3 QA gate run (647af22, macOS) | `USGP_WIM_SAMPLES=<R5> USGP_WIM_REFERENCE=<R5> GATES_FUZZ_SECONDS=30 caffeinate -i scripts/gates.sh` | Exit 77 (not a PASS): 63 PASS, 4 NOT RUN (`pg-integration`, `large_upload_pg`, `windows-agent`, boot smoke S1 to S8), 0 FAIL. `cargo test --locked --workspace` 1701 passed, 0 failed, 0 ignored (106 binaries); with QA's 13 tests 1714 (107 binaries). `dism_samples` 12 passed against local R5 samples. Fuzz: the 8 M2 targets, 30 s each, no crash. QA verdict FAIL on QA-001 to QA-003 |
| 2026-10-29 | M3 CI 40818350636 (647af22) | Workflow `ci` | All 19 jobs passed: `gates`, `ci-lint`, `markdown`, `supply-chain`, `fips-linkage`, `pg-integration`, `large-upload`, `boot-smoke`, `windows-agent`, `testing-workspaces`, `fuzz-build` and `fuzz-smoke` for the 8 M2 targets. Before the reviews. Boot smoke ran S1 to S8 and `payload-disk` only; `windows-agent` ran no `--ignored` test; no M3 fuzz target existed |
| 2026-10-29 | M3 CI 40876728637 (349de13) | Workflow `ci` (boot smoke and `windows-agent`) | S10 (GPT-OBS-002) PASS; S1 to S8 PASS; the Windows VHD step and S9 failed. Other jobs are not recorded here |
| 2026-10-29 | M3 CI 40910029759 (fff029f) | Workflow `ci` | S9 PASS; GPT-OBS-001 accepted (128 entries, first and last usable LBA 34 and 2097118, 512-byte blocks); boot smoke 11 of 11. `gates` and `pg-integration` timed out: four `run_scoped` tests in the agent's `qa_m3.rs` hung after an assertion failed (harness fixed in 21c1efb; the failure itself was the device listener refusing a boot service enrolled in the same second, fixed in the test harness). The fix-round notes record that `boot004_recovery_typed_partition_formats` failed on a drive-letter clash (fixed in 21c1efb) |
| 2026-10-29 | M3 CI 40928612312 (21c1efb) | Workflow `ci` | Conclusion **failure**. PASS: `gates`, `pg-integration` (so the fix-round M3 tests, including the PostgreSQL QA-005 wipe-record fault test, now have CI evidence), boot smoke S1 to S10, `fuzz-smoke` for 24 targets, `large-upload`. `windows-agent`: FIPS probe PASS; `vhd_raw_io_update_and_volume_letters` PASS (GPT-OBS-001 accepted again; sentinel disk untouched); `boot004_recovery_typed_partition_formats` **FAIL**: the ESP got P:, then `SetVolumeMountPoint` returned error 87 for the Windows partition, before any format. The BOOT-004 recovery-format question has no result (NOT RUN). Likely cause, not confirmed: Windows automount had already given the new volume a letter; the agent's Windows letter path could fail the same way after the wipe. Open defect pending the owner's decision (fourth fix round or POAM; POAM-53) |
| 2026-10-29 | M3 CI 40980499705 (7cd5ecf, after fix rounds 4 to 7) | Workflow `ci` | Conclusion **success**: all 35 jobs, including `windows-agent`, `gates`, `pg-integration`, boot smoke S1 to S10, `fuzz-smoke` (24 targets) and `large-upload`. `windows-agent`: `vhd_disk` (2) and `winsink` (5) PASS; sentinel disk untouched; `GPT-OBS-001 accepted`; `BOOT-004 recovery-format accepted: NTFS ... (type DE94BBA4-..., attributes 0x8000000000000001)`; `LETTER-OBS Windows letters before assign: [E]`; synthetic WIM apply with every descriptor equal to the stored SDDL; probes OPEN-WAPI-7 (`SetKernelObjectSecurity` verbatim, `SetSecurityInfo` merges), OPEN-WAPI-12 (NORMAL clears directory ARCHIVE, 0x30 to 0x10), OPEN-WAPI-9 (short name settable with 8.3 generation off). POAM-53 closed. M3 still not met (MT-2, MT-1 NOT RUN) |
| 2026-10-29 | M3 fix rounds 1 to 3 (coders, local, macOS) | `cargo fmt`, `cargo clippy --workspace --all-targets -- -D warnings` (with and without `pg-integration`), `cargo test --workspace --no-fail-fast`, `scripts/check-names.sh`, `scripts/check-pure-rust.sh`, Windows-target clippy of `usgp-winapi` | PASS at round 3: 107 test binaries, no failure; names OK; pure-Rust OK. Not QA-confirmed; PostgreSQL tests compiled but not run locally |
| 2026-10-29 | M3 fuzz (local, `--sanitizer none`) | `cargo fuzz run <target> … -max_total_time=60` for the 13 WU-14 targets, `agent_http_head`, `winapi_sd`, `winapi_reparse` | PASS, no crash (WU-14 and the release engineer; counts in `TEST_EVIDENCE.md`). No CI `fuzz-smoke` result for an M3 target is recorded |
| 2026-10-29 | M3 owner lab | MT-2, L1 to L12 | NOT RUN (owner action with licensed media; POAM-59) |
| 2026-10-29 | M2 real media | MT-1 | NOT RUN (POAM-33); the procedure document now exists |

## Owner decision log

| Date | Decision | Effect |
|------|----------|--------|
| 2026-10-29 | M3 gate accepted (run `20261028-104815-m3-preboot-apply`, `gate.md`) | POAM-38 to POAM-63, the M3 extensions to POAM-1, 6, 11, 16, 18, 21, 26, 31 and 36 and the narrowed POAM-58 accepted; POAM-53 closure confirmed; SEC-R47-001 accepted as POAM-64; POAM-61 keeps tolerating directory ARCHIVE; POAM-62 keeps `SetSecurityInfo` until MT-2 L8; decision 0023 item 1 clarification confirmed. M3 is not met until MT-2 (POAM-59). |

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-29 | Added the owner decision log with the M3 gate acceptance. No new test evidence. |
| 2026-10-29 | Added CI run 40980499705 (7cd5ecf, all 35 jobs green, Windows VHD and WinSink results, probes); preamble and M3 status updated; POAM-53 closed. M3 not met. |
| 2026-10-29 | CI run 40928612312 recorded as stated (conclusion failure: `windows-agent` BOOT-004 VHD test failed with error 87 before any format; everything else named passed). Exit 3: PostgreSQL QA-005 test now PASS in CI. Preamble and M3 status updated; M3 not met. |
| 2026-10-29 | M3 (WU-17; `m3/build` at 21c1efb). Added the M3 preamble, the M3 exit-criteria table (exit 1 NOT RUN; exits 2, 3 and 4 PASS in QA M3 with their limits; M3 not met), the wipe-guard and audit-before-wipe evidence chain, and rows for the M3 QA gate run, CI runs 40818350636, 40876728637, 40910029759 (as recorded) and 40928612312 (pending), the fix rounds' local runs, local M3 fuzzing, MT-2 and MT-1 NOT RUN. |
| 2026-10-28 | CI on commit 5ea03a1 (the committed S11/S12 change on top of the `newer_schema_refused` fix). Added rows for `ci` runs 40633650457 and 40633638960 (all jobs success; `gates` 1133, 2 and 228; `fips-linkage`; `pg-integration` PASS with `migrate_pg`, `repo_pg` and `audit_pg` 9 each and `e2e_pg` 1; `large-upload` PASS, peak RSS 54 MiB; eight `fuzz-smoke` results without ASan, with artifact digests; boot smoke) and `wim-samples` 40633638946 and 40633653170 (`verify` PASS with the S11/S12 rules, 5 `dism_samples`). Added the M2 exit criteria table: met except exit 1a (MT-1, owner action), so M2 is not met. MT-1 label corrected to exit 1a. Corrected the CI 40601242085 feature-gated total from 347 to 217. |
| 2026-10-27 | First M2 CI evidence on commit d72b761 and the uncommitted S11/S12 WIM change. Added rows for `ci` runs 40601242085 and 40601244276 (job results, `gates` totals, `fips-linkage`, `pg-integration` FAIL with `audit_pg` 9 passed, `migrate_pg` 8 of 9, `repo_pg` and `e2e_pg` NOT RUN; `large-upload` PASS with the logged figures; eight `fuzz-smoke` results without ASan, with artifact digests; boot smoke), `wim-samples` R2 (40599556702) as sample production, and `wim-samples` 40601244164 and 40601244679 (`verify` PASS on Linux with the committed checker's S11 and S12 verdicts). Marked the superseded runs on 5d3c8c7. Added the S11/S12 local runs, labelled not QA-confirmed. Pointed the four earlier NOT RUN rows at the CI rows. MT-1 still NOT RUN; M2 not met. |
| 2026-10-27 | M2 (content store, uncommitted on 55bd6a1): recorded the `wim-samples` generation run R1 (40535666995), the M2 QA gate run (exit 1: 57 PASS, 1 environmental FAIL, 3 NOT RUN; 1054 tests passed), the fix-round and re-verify local runs (not QA-confirmed), and NOT RUN entries for PostgreSQL, large upload, Linux DISM-sample verification, 600 s fuzzing and MT-1. Flagged OPEN-PE-LIC against the DISM sample method. |
| 2026-10-27 | M1 CI fuzz evidence: recorded dispatched run 40439279903 (all jobs success), its two 600 s `fuzz-smoke` results on Linux beside the local 600 s runs, the artifact digests, and the boot smoke re-run (9 PASS, 0 FAIL, 0 NOT RUN). Replaced the pending `fuzz-smoke` row; no CI rows remain pending. |
| 2026-10-27 | M1 CI evidence: recorded run 40438138720 (all jobs success, boot smoke 9 PASS, 0 FAIL, 0 NOT RUN), its environment, firmware and binary digests, the first Linux `fips-linkage` PASS, and the superseded run 40434148508. Replaced the pending `boot-smoke` row; `fuzz-smoke` stays pending. |
| 2026-10-26 | M1 final pass: recorded QA's final gate run, test totals, 60 s fuzz runs and the passing traceability check. |
| 2026-10-26 | M1: recorded the QA gate runs (initial pass and re-verify round 1), the fuzz runs, the orchestrator's final gate run, and the pending CI jobs. |
