# Building usg-provision (FIPS build procedure)

This document is the build procedure for the FIPS 140-3 cryptographic module
that usg-provision links. It covers the build hosts, toolchain, environment,
and the checks that show a build is in FIPS mode and statically linked.
Decision [0001](decisions/0001-fips-validated-crypto.md) (with Amendment 1)
says the build "must match the validated module's operational environment
and build procedure". This file records that procedure (release-notes
REL-002).

COMPLIANCE MAPPING:

- NIST 800-53: CM-2 (Baseline Configuration), CM-6 (Configuration
  Settings), SA-10 (Developer Configuration Management), SC-13
  (Cryptographic Protection), SI-7 (Software, Firmware, and Information
  Integrity)

## 1. Cryptographic module

| Item | Value |
|------|-------|
| Rust binding | `aws-lc-rs` with the `fips` feature, through `usgp-crypto` only |
| Native crate | `aws-lc-fips-sys` 0.14.3 (from `Cargo.lock`) |
| Module source | AWS-LC FIPS source bundled in the `aws-lc-fips-sys` crate; never a system install |
| Library version in the bundled source | `AWSLC_VERSION_NUMBER_STRING "4.2.0"` (`include/openssl/base.h`) |
| Module named by the crate README | "AWS-LC-FIPS 3.0.x" |
| FIPS module version | **TODO (REL-001)**: owner to confirm |
| CMVP certificate number | **TODO (REL-001)**: owner to confirm |
| Validation status | **TODO (REL-001)**: certificate, or Modules-In-Process (MIP) entry |
| Security policy | **TODO (REL-001)**: the security-policy document and revision that match the certificate |

> **TODO (REL-001), owner action required.** The values above marked TODO
> have **not** been verified. The crate README says it binds "the latest
> version of the AWS-LC-FIPS module that has completed FIPS validation
> testing ... and has been submitted to NIST", so it may be in process
> rather than certified. The README names module 3.0.x, but the bundled
> header reports library version 4.2.0. The project owner, with the
> security/NIST reviewer, must confirm the module version, the CMVP
> certificate number (or MIP status), and the security-policy revision
> against the [CMVP database](https://csrc.nist.gov/projects/cryptographic-module-validation-program),
> and record them here, in decision 0001, and in
> `docs/compliance/ATO_EVIDENCE.md`. Until then, do not claim "FIPS 140-3
> validated" for any artifact. Claim only "built from the AWS-LC FIPS
> module source in FIPS mode".

A change to `aws-lc-rs` or `aws-lc-fips-sys` in `Cargo.lock` can change the
module. Treat any such change as a change to this baseline (CM-3). Re-check
the TODO rows and re-run section 6 before you accept it.

## 2. Build hosts

| Host | Status | Linkage | Use |
|------|--------|---------|-----|
| Linux x86_64 (`x86_64-unknown-linux-gnu`), Ubuntu 24.04 | **Authoritative** | Static | CI evidence builds and release builds |
| Linux aarch64 (`aarch64-unknown-linux-gnu`), Ubuntu 24.04 | **Authoritative** | Static | Release builds (no CI job yet) |
| macOS (arm64, x86_64) | **Development only** | Dynamic (`libaws_lc_fips_*.dylib`) | Local development and functional tests |
| Windows | Not supported yet | - | Open: POAM-1, ROADMAP D-5 |

Only the Linux hosts produce evidence or shipped artifacts. On Linux x86_64
and aarch64, `aws-lc-fips-sys` builds the module statically, and
`.cargo/config.toml` forces `AWS_LC_FIPS_SYS_STATIC=1` for the Linux
targets.

macOS is a **development-only** host (POAM-2). On macOS, `aws-lc-fips-sys`
always builds the FIPS module as a shared library. The binaries load it
through `@rpath` with no rpath set, so they start only through `cargo run`.
macOS builds are functional only (POAM-1). They are not evidence of a
validated operational environment and must not be packaged or shipped.

The operational environments (OEs) in the security policy are the
authority for where the module may run. **TODO (REL-001)**: list the tested
OEs from the confirmed security policy here, and confirm that the shipped
targets (Linux x86_64 and aarch64) are covered.

## 3. Toolchain

CI installs the toolchain on the GitHub-hosted `ubuntu-24.04` runner from
the Ubuntu 24.04 (noble) archive. The `gates` and `fips-linkage` jobs fail
if a tool is outside the pinned series below. They also write the exact
package versions (`dpkg-query`) to the job summary as evidence.

| Tool | CI package (noble) | Pinned series (CI asserts) | Used for |
|------|--------------------|----------------------------|----------|
| Rust | rustup, `rust-toolchain.toml` | `1.99.1` exactly | Workspace build |
| Go | `golang-1.22-go` | `1.22.x` | AWS-LC FIPS code generation and `delocate` (hard requirement; minimum 1.17.13) |
| CMake | `cmake` | `3.28.x` | AWS-LC build (minimum 3.5) |
| C compiler | `clang-18` | `18.1.x` | AWS-LC C and assembly sources |
| libclang | `libclang-18-dev` | `18.1.x` | `bindgen` (build-only, Amendment 1) |
| Perl | `perl` | `5.38.x` | AWS-LC FIPS build (hard requirement) |

Notes:

- **Patch levels are recorded, not pinned.** Ubuntu security updates can
  move a tool's patch level within its series. Each CI run records the
  exact Debian package versions in its job summary. If an assessor needs a
  byte-for-byte rebuild, build in a digest-pinned container image (tracked
  in REL-007).
- **Which tools are used is fixed.** CI sets `CMAKE=/usr/bin/cmake`,
  `CC=/usr/bin/clang-18`, and `CXX=/usr/bin/clang++-18`, and puts
  `/usr/lib/go-1.22/bin` first on `PATH`. The tools that come with the
  runner image (its own CMake and Go) are therefore not used.
- **Go never uses the network.** `GOTOOLCHAIN=local` stops Go from
  downloading another toolchain, and `GOPROXY=off` stops it from fetching
  modules. The AWS-LC Go code uses only the standard library.
- macOS development hosts can use any recent Go, CMake, Xcode clang, and
  Perl. They are not evidence builds, so their versions are not pinned.

To set up a Linux build host to match CI:

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential cmake golang-1.22-go clang-18 libclang-18-dev perl
export PATH="/usr/lib/go-1.22/bin:$PATH"
```

## 4. Build environment

| Variable | Value | Set by | Purpose |
|----------|-------|--------|---------|
| `AWS_LC_FIPS_SYS_USE_SYSTEM` | `0` | `.cargo/config.toml` (forced), CI | Build the module from the bundled source; never adopt a system AWS-LC or OpenSSL |
| `AWS_LC_SYS_USE_SYSTEM` | `0` | `.cargo/config.toml` (forced), CI | The same for the build-only non-FIPS crate |
| `AWS_LC_FIPS_SYS_STATIC_<linux triple>` | `1` | `.cargo/config.toml` (forced) | Static FIPS linkage on Linux |
| `AWS_LC_FIPS_SYS_STATIC` | `1` | CI | The same, for CI (Linux only) |
| `CMAKE` | `/usr/bin/cmake` | CI | Selects the pinned CMake |
| `CC`, `CXX` | `/usr/bin/clang-18`, `/usr/bin/clang++-18` | CI | Selects the pinned compiler |
| `LIBCLANG_PATH` | `/usr/lib/llvm-18/lib` | CI | Selects the pinned libclang for `bindgen` |
| `GOTOOLCHAIN` | `local` | CI | No Go toolchain download |
| `GOPROXY` | `off` | CI | No Go module download |

Do not set any of these:

- `AWS_LC_FIPS_SYS_SYSTEM_DIR`, `OPENSSL_DIR`, `OPENSSL_LIB_DIR`, or
  `OPENSSL_INCLUDE_DIR`. They would link a module other than the reviewed
  bundled source.
- `AWS_LC_FIPS_SYS_SMALL=1`. It changes the compiled FIPS module and may
  affect its validation status.
- `AWS_LC_FIPS_SYS_SYSTEM_SKIP_VERSION_CHECK`.
- Sanitizer variables such as `AWS_LC_SYS_SANITIZER`.

## 5. Build

```bash
cargo build --workspace --bins --release --locked
```

`--locked` is required. It makes the build use exactly the module version in
`Cargo.lock`.

## 6. Verify FIPS mode and static linkage

Run these checks on every evidence or release build (Linux):

```bash
scripts/check-fips-linkage.sh release
```

The script checks each shipped binary (`usgp-server`, `usgp-relay`,
`usgp-preboot-agent`, `usgp-cli`):

- it contains FIPS module symbols (`aws_lc_fips_<version>_*`),
- it contains no non-FIPS AWS-LC symbols (`aws_lc_<version>_*`),
- it has no non-FIPS AWS-LC shared library among its dynamic dependencies,
- it exits 0 at start-up, meaning `usgp-crypto` found FIPS mode active.
  The binaries fail closed if it is not. `usgp-server` and `usgp-relay`
  run with `--self-check` (FIPS check only). With no arguments they print
  usage and exit 2, so a bare run is not a FIPS check.

To check static linkage on Linux by hand (the script does not yet assert
it, REL-003):

```bash
for b in usgp-server usgp-relay usgp-preboot-agent usgp-cli; do
  p="target/release/$b"
  # No AWS-LC shared library may be needed at run time.
  if readelf -d "$p" | grep NEEDED | grep -q 'libaws_lc'; then
    echo "FAIL $b: AWS-LC linked dynamically"
  fi
  # The FIPS module must be defined in the binary itself (T = text symbol).
  nm "$p" | grep -qE ' T aws_lc_fips_[0-9]' || echo "FAIL $b: FIPS module not linked statically"
  # Run the binary directly, not through cargo run, so a missing library fails.
  # The server and relay need --self-check; with no arguments they exit 2.
  case "$b" in
    usgp-server | usgp-relay) args=(--self-check) ;;
    *) args=() ;;
  esac
  "$p" "${args[@]}" > /dev/null || echo "FAIL $b: FIPS mode not active"
done
```

Do not strip the binaries before you run these checks: the checks need the
symbols. If release artifacts are stripped, run the checks on the unstripped
build first, and record both digests.

## 7. Evidence to keep

For each evidence or release build, keep:

- the CI job summary (toolchain versions and package versions),
- the `fips-linkage: OK` output,
- `Cargo.lock` at the build commit, which identifies `aws-lc-fips-sys`,
- the module version, CMVP certificate, and security-policy revision from
  section 1 (TODO REL-001).

SBOM, signing, and provenance for release artifacts are tracked in REL-007.

## 8. PostgreSQL for tests

The `pg-integration` tests (plan WU-3b; decisions 0008 and 0012) run
against PostgreSQL 16 over TLS with certificate-only login:

- `usgp-db`: `tests/migrate_pg.rs`, `tests/repo_pg.rs`,
  `tests/audit_pg.rs`;
- `usgp-server`: `tests/e2e_pg.rs` (the M2 end-to-end flow);
- `usgp-server`: `tests/large_upload_pg.rs`, which also needs the
  `large-tests` feature, about 14 GiB of free disk and Linux.

Built with `--features pg-integration`, these tests **fail** (they do not
skip) when the `USGP_TEST_PG_*` variables are missing. CI runs them in the
`pg-integration` job on every change, and the large upload in the
`large-upload` job (weekly and on manual dispatch). Locally they are
**NOT RUN** unless you set up a database as below. `scripts/gates.sh`
records NOT RUN for them, never PASS.

`scripts/pg-test-setup.sh` needs `docker` and `openssl`. It makes a
throwaway test PKI in a temporary directory outside the work tree (the CA
key is deleted once the certificates are issued; certificates are valid
for 2 days), and starts a digest-pinned `postgres:16` container published
on `127.0.0.1` only. `pg_hba.conf` allows TLS client-certificate login
only, and no role has a password. The script checks this configuration
and smoke-tests the logins before it writes the environment file.

### Database roles and key files

The script creates three login roles, each with its own client
certificate and no password (decisions 0012 and 0016). Migrations
0002 and 0003 set their grants; migration 0003 fails if `usgp_admin`
does not exist, so a real deployment's database administrator creates
all three roles before the first `usgp-server migrate`.

| Role | Used by | Environment variables | Rights |
|---|---|---|---|
| `usgp_owner` | `usgp-server migrate` (`--owner-user`, `--owner-cert`, `--owner-key`) | `USGP_TEST_PG_OWNER_{USER,CERT,KEY}` | owns the schema; runs migrations 0001 to 0003 (schema version 3) |
| `usgp_app` | `usgp-server serve` (`[database]`) | `USGP_TEST_PG_APP_{USER,CERT,KEY}` | what the API needs; SELECT only on operator records |
| `usgp_admin` | `operator enrol`, `operator disable`, `audit verify` (`[database.admin]`) | `USGP_TEST_PG_ADMIN_{USER,CERT,KEY}` | operator records; appends to and reads the audit chain, never updates or deletes it |

Private key files follow these rules:

- The owner key (`--owner-key`) and the admin key
  (`[database.admin].client_key`) must be mode 0600 or 0400: no group or
  other read bit, whoever runs the command, root included. Otherwise the
  command refuses to start.
- `serve` refuses to start (exit 78, `server.start.refused` with reason
  `admin_key_readable_by_service`) if it can open the configured admin
  key. In a deployment the admin key belongs to root (or a designated
  administrator account) and the service account cannot read it.
- The application key, the TLS key and the signing keys must not be
  readable by others, and are readable by the group only if it is the
  service's group.

The tests run every role as one uid. They set the copied admin key to
mode 0000 while `serve` runs and back to 0600 for the admin commands.
**Run the pg tests as a non-root user:** root can open a 0000 file, so
under root every `serve` in `e2e_pg` and `large_upload_pg` is refused.
CI checks that its runner user is not root, and `scripts/gates.sh`
records these tests as NOT RUN when it runs as root.

```bash
scripts/pg-test-setup.sh up
# The script prints the env file path; by default it is
# ${RUNNER_TEMP:-${TMPDIR:-/tmp}}/usgp-pg-test/pg-test.env
set -a
. "${TMPDIR:-/tmp}/usgp-pg-test/pg-test.env"
set +a

cargo test --locked --workspace --features pg-integration
# or the whole local gate run, which then includes these tests:
scripts/gates.sh

scripts/pg-test-setup.sh check   # re-check the configuration (optional)
scripts/pg-test-setup.sh down    # remove the container and the test keys
```

Options (environment): `USGP_PG_TEST_DIR` (key and env-file directory;
refused inside the work tree except under `target/`), `USGP_PG_TEST_PORT`
(default 55432), and `USGP_PG_TEST_IMAGE` (must be pinned by
`@sha256:` digest). The image digest is part of the test baseline: change
it deliberately (CM-3) and re-run CI.

The large upload test is opt-in locally because it writes about 10.5 GiB:

```bash
GATES_LARGE=1 TMPDIR=/path/with/14GiB/free scripts/gates.sh
```

Test-only features are never enabled in shipped builds. CI and
`scripts/gates.sh` fail if the release build graph turns on `test-pki`,
`testkit`, `dism-samples`, `pg-integration` or `large-tests`. The
`dism-samples` tests run only with a `wim-samples` workflow artifact
(`USGP_WIM_SAMPLES`); they fail without it by design.
