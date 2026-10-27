#!/usr/bin/env bash
# Runs every local quality gate in order, printing each command and its exit
# status. Continues past failures so a whole run is recorded. See
# .claude/skills/provision-workflow/references/quality-gates.md.
#
# Each gate ends as PASS (exit 0), FAIL (any other status) or NOT RUN (exit
# 77, or a missing prerequisite such as cargo-fuzz). NOT RUN is never counted
# as PASS (CONTRIBUTING.md "Gates").
#
# Exit status: 1 if any gate failed; otherwise 77 if any gate was NOT RUN;
# otherwise 0. On a macOS host the network boot smoke is always NOT RUN (plan
# section 0), so a clean macOS run exits 77, not 0.
#
# Optional environment:
#   GATES_FUZZ_SECONDS  run each fuzz target for this many seconds (CI
#                       fuzz-smoke uses 600, or 60 for the M2 smoke targets).
#                       Unset: seeds are replayed only.
#   USGP_TEST_PG_*      PostgreSQL for the pg-integration tests, from
#                       `scripts/pg-test-setup.sh up` (docs/BUILDING.md
#                       section 8). Unset: those gates are NOT RUN.
#   USGP_WIM_SAMPLES    a downloaded `wim-samples` artifact directory (the
#                       wim-samples workflow). Unset: the DISM sample check is
#                       NOT RUN.
#   GATES_LARGE=1       also run the 10.5 GiB large upload test (Linux, with
#                       PostgreSQL and 14 GiB free under TMPDIR). Otherwise
#                       NOT RUN.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root" || exit 1

results=()
failed=0
not_run=0

# record <status> <label>: 77 is NOT RUN, 0 is PASS, anything else FAIL.
record() {
  local status=$1 label=$2 verdict
  case "$status" in
    0) verdict=PASS ;;
    77)
      verdict="NOT RUN"
      not_run=1
      ;;
    *)
      verdict=FAIL
      failed=1
      ;;
  esac
  echo "<== exit $status ($verdict): $label"
  results+=("$(printf '%-7s %3s  %s' "$verdict" "$status" "$label")")
}

# run <cmd...>: run from the repository root.
run() {
  echo "==> $*"
  "$@"
  record "$?" "$*"
}

# run_in <dir> <cmd...>: run in a separate workspace (testing/*, fuzz/). Its
# rust-toolchain.toml and .cargo/config.toml apply; CARGO_TARGET_DIR is unset
# so the testing workspaces build into target/testing/<name>/ as configured
# (keeps their output out of the name gate's scan, impl-notes-wu9-10 D-2;
# decision 0005).
run_in() {
  local dir=$1
  shift
  echo "==> (cd $dir) $*"
  (cd "$dir" && env -u CARGO_TARGET_DIR "$@")
  record "$?" "(cd $dir) $*"
}

# skip <reason> <label>: a gate whose prerequisite is missing.
skip() {
  echo "==> NOT RUN: $2 ($1)"
  record 77 "$2 [$1]"
}

# expect_exit <want> <cmd...>: PASS only if the command exits with <want>.
expect_exit() {
  local want=$1 status
  shift
  echo "==> (expect exit $want) $*"
  "$@" > /dev/null 2>&1
  status=$?
  if [ "$status" -eq "$want" ]; then
    record 0 "(expect exit $want) $*"
  else
    echo "    got exit $status"
    record 1 "(expect exit $want, got $status) $*"
  fi
}

# Pure-Rust check for the separate testing/ workspaces: the same crate
# pattern and allowlist as scripts/check-pure-rust.sh (REL-M1-003 tracks
# moving this into that script).
# shellcheck disable=SC2317,SC2329 # invoked indirectly, through `run pure_rust_ws`
pure_rust_ws() {
  local dir=$1 hits h bad=0
  local pattern='^([A-Za-z0-9_-]+-sys|cc|bindgen|cmake|pkg-config|vcpkg|cxx|cxx-build|link-cplusplus|nasm-rs|openssl-src|autotools) v'
  hits="$(cd "$dir" && cargo tree --locked -e normal,build,dev --target all --prefix none \
    | grep -E "$pattern" | awk '{print $1}' | sort -u)" || true
  for h in $hits; do
    if ! grep -qE "^${h}[[:space:]]*(#|$)" scripts/pure-rust-allowlist.txt; then
      echo "pure-rust ($dir): depends on $h"
      bad=1
    fi
  done
  [ "$bad" -eq 0 ] && echo "pure-rust ($dir): OK"
  return "$bad"
}

# The graph that `cargo build --workspace --bins --release` resolves (normal
# and build edges, no dev) must not enable a test-only feature (as the CI
# gates job).
# shellcheck disable=SC2317,SC2329 # invoked indirectly, through `run`
no_test_features_shipped() {
  local hits
  hits="$(cargo tree --locked --workspace -e features,normal,build --target all --prefix none \
    | grep -E '(feature "(test-pki|testkit|dism-samples|pg-integration|large-tests)"|^x509-cert feature "builder")' \
    | sort -u)" || true
  if [ -n "$hits" ]; then
    echo "test-only features reach the shipped build graph:"
    echo "$hits"
    return 1
  fi
  echo "test-only features: none in the shipped build graph"
}

# free_gib <dir>: whole GiB available on the file system holding <dir>.
free_gib() {
  df -P -k "$1" | awk 'NR == 2 { printf "%d", $4 / 1048576 }'
}

# The large upload test. Exit 77 (NOT RUN) when the test reports its disk
# marker (`NOT RUN: insufficient disk`, large_upload_pg.rs), as CI does.
# shellcheck disable=SC2317,SC2329 # invoked indirectly, through `run`
large_upload() {
  local log status=0
  log="$(mktemp "${TMPDIR:-/tmp}/usgp-large.XXXXXX")"
  cargo test --locked -p usgp-server --release --features pg-integration,large-tests \
    --test large_upload_pg -- --nocapture 2>&1 | tee "$log" || status=$?
  if grep -qF 'NOT RUN: insufficient disk' "$log"; then
    status=77
  fi
  rm -f "$log"
  return "$status"
}

# ------------------------------------------------------- main workspace --

# --locked everywhere (CM-2): a gate run must never rewrite Cargo.lock, and a
# manifest edit without a lockfile update fails here as it does in CI.
run cargo fmt --all --check
run cargo clippy --locked --workspace --all-targets -- -D warnings
# Lint the code behind the test-only features (never run here with them all:
# the dism-samples and pg tests fail by design without their data).
run cargo clippy --locked --workspace --all-targets \
  --features test-pki,testkit,dism-samples,pg-integration,large-tests -- -D warnings
run cargo test --locked --workspace
run cargo test --locked --workspace --doc
# Feature-gated tests per package, as CI: the mTLS tests (test-pki) and the
# WIM negative, check and XPRESS tests (testkit). Never --all-features for
# usgp-image outside the DISM sample check below.
run cargo test --locked -p usgp-crypto --features test-pki
run cargo test --locked -p usgp-image --features testkit
run no_test_features_shipped
run cargo build --locked --workspace --bins
# Start-up contract (plan section 3.6): every binary checks FIPS mode first;
# usgp-relay and usgp-server --self-check exit 0 (inside
# check-fips-linkage.sh), and with no arguments both print usage and exit 2.
run scripts/check-fips-linkage.sh debug
expect_exit 2 cargo run --quiet --locked --bin usgp-relay
expect_exit 2 cargo run --quiet --locked --bin usgp-server
run scripts/check-pure-rust.sh
# The name gate prints which matcher ran. If ripgrep is installed, the grep
# matcher runs as well, so both code paths are exercised (QA-004).
run scripts/check-names.sh
if command -v rg > /dev/null 2>&1; then
  run env NAMES_FORCE_GREP=1 scripts/check-names.sh
fi
run scripts/test-check-names.sh
# REQ-PE-001 (QA-001): no Windows PE / ADK file or WIM image in the
# repository (the artifact half runs with check-artifact-names.sh below).
run scripts/check-pe-files.sh repo
run scripts/test-check-pe-files.sh
run cargo deny --locked check
run cargo audit

# ------------------------------------------ PostgreSQL integration (M2) --

# Plan WU-3b, decisions 0008 and 0012. NOT RUN unless a database is set up
# (USGP_TEST_PG_* exported, e.g. by `scripts/pg-test-setup.sh up` and
# `set -a; . "$dir/pg-test.env"; set +a`). The CI job pg-integration always
# runs them. When the script's container is running, its certificate-only
# configuration check runs too.
# The workspace run includes usgp-db's *_pg tests and usgp-server's e2e_pg.
# SEC-011 / decision 0016: `serve` refuses to start if it can open the admin
# key; the tests make it 0000 while `serve` runs. Root opens it anyway, so as
# root these tests cannot pass: NOT RUN, as in CI (which asserts a non-root
# runner user).
if [ -n "${USGP_TEST_PG_HOST:-}" ] && [ "$(id -u)" -eq 0 ]; then
  skip "running as root; the admin-key (0000 while serving) rule needs a non-root user" \
    "cargo test --workspace --features pg-integration"
elif [ -n "${USGP_TEST_PG_HOST:-}" ]; then
  run cargo test --locked --workspace --features pg-integration
  if scripts/pg-test-setup.sh status 2> /dev/null; then
    run scripts/pg-test-setup.sh check
  fi
else
  skip "no PostgreSQL: USGP_TEST_PG_* unset; see docs/BUILDING.md section 8" \
    "cargo test --workspace --features pg-integration"
fi

# Large upload (plan WU-10): a 10.5 GiB synthetic WIM through the whole M2
# flow. Opt-in (GATES_LARGE=1); needs PostgreSQL, Linux (the RSS bound reads
# /proc/self/status) and 14 GiB free. CI job large-upload runs it weekly.
large_label="cargo test -p usgp-server --release --features pg-integration,large-tests --test large_upload_pg"
large_dir="${TMPDIR:-/tmp}"
if [ "${GATES_LARGE:-}" != 1 ]; then
  skip "GATES_LARGE=1 not set; CI large-upload runs it" "$large_label"
elif [ "$(uname -s)" != Linux ]; then
  skip "not Linux" "$large_label"
elif [ -z "${USGP_TEST_PG_HOST:-}" ]; then
  skip "no PostgreSQL: USGP_TEST_PG_* unset" "$large_label"
elif [ "$(id -u)" -eq 0 ]; then
  skip "running as root; the admin-key rule needs a non-root user" "$large_label"
elif [ ! -f services/usgp-server/tests/large_upload_pg.rs ]; then
  skip "services/usgp-server/tests/large_upload_pg.rs not written yet" "$large_label"
elif [ "$(free_gib "$large_dir")" -lt 14 ]; then
  skip "less than 14 GiB free under $large_dir" "$large_label"
else
  run large_upload
fi

# ------------------------------------------------- DISM samples (M2) --

# Plan WU-W/WU-5: only with a downloaded `wim-samples` artifact (Windows CI
# makes it; it is never committed). The CI wim-samples verify job always runs.
if [ -n "${USGP_WIM_SAMPLES:-}" ]; then
  run cargo test --locked -p usgp-image --features dism-samples
else
  skip "USGP_WIM_SAMPLES unset; the samples come from the wim-samples workflow" \
    "cargo test -p usgp-image --features dism-samples"
fi

# ------------------------------------------- testing/ workspaces (M1) --

host_triple="$(cd testing/uefi-payload && rustc -vV | sed -n 's/^host: //p')"
# UEFI test payload: lint for the UEFI target, unit-test the library on the
# host. The release build itself is `scripts/boot-smoke.sh build` below.
run_in testing/uefi-payload cargo fmt --all --check
run_in testing/uefi-payload cargo clippy --locked --all-targets -- -D warnings
run_in testing/uefi-payload cargo clippy --locked --release -- -D warnings
run_in testing/uefi-payload cargo clippy --locked --target "$host_triple" --lib --tests -- -D warnings
run_in testing/uefi-payload cargo test --locked --target "$host_triple" --lib
# Lab network tools: the socket code is Linux-only, so on other hosts it is
# linted for the Linux target when that target's std is installed.
run_in testing/netlab cargo fmt --all --check
run_in testing/netlab cargo clippy --locked --all-targets -- -D warnings
if [ "$(uname -s)" != Linux ]; then
  # Here-string, not a pipe: `grep -q` exiting early must not SIGPIPE rustup
  # under pipefail and turn a match into a miss.
  if grep -qx x86_64-unknown-linux-gnu <<< "$(cd testing/netlab && rustup target list --installed)"; then
    run_in testing/netlab cargo clippy --locked --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
  else
    skip "rustup target x86_64-unknown-linux-gnu not installed" "netlab clippy for Linux"
  fi
fi
run_in testing/netlab cargo test --locked
run pure_rust_ws testing/uefi-payload
run pure_rust_ws testing/netlab
# Full policy for the testing workspaces (never shipped, but held to the
# product rules). deny.toml is passed explicitly: cargo-deny otherwise looks
# in the current directory.
for ws in testing/uefi-payload testing/netlab; do
  run cargo deny --locked --config deny.toml --manifest-path "$ws/Cargo.toml" check
  run cargo audit --file "$ws/Cargo.lock"
done

# ----------------------------------------------------------------- fuzz --

# Advisories and sources only: the fuzz workspace uses libfuzzer-sys
# (decision 0002), which the main policy bans (as in CI).
run cargo audit --file fuzz/Cargo.lock
run cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories sources
run_in fuzz cargo fmt --all --check
run_in fuzz cargo clippy --locked --all-targets -- -D warnings
# <target>:<max_len>, as the CI fuzz-smoke matrix (impl-notes-wu8, -wu9).
# Build output is target/fuzz (fuzz/.cargo/config.toml, decision 0005).
fuzz_targets="dhcp_packet:1600 tftp_packet:4096 wim_header:1024 wim_xml:16384
  xpress_chunk:70000 wim_lookup:4096 wim_check:262144 api_json:70000"
# QA-003: libFuzzer counts time the host spends asleep against the unit
# being run, so a macOS sleep during a timed run reads as a timeout. On
# Darwin every fuzz run is wrapped in `caffeinate -i` (no idle sleep while
# it runs); elsewhere nothing is added.
keep_awake=()
if [ "$(uname -s)" = Darwin ] && command -v caffeinate > /dev/null 2>&1; then
  keep_awake=(caffeinate -i)
fi
if command -v cargo-fuzz > /dev/null 2>&1; then
  run_in fuzz cargo fuzz build
  for entry in $fuzz_targets; do
    t="${entry%%:*}"
    run_in fuzz ${keep_awake[@]+"${keep_awake[@]}"} \
      cargo fuzz run "$t" "corpus/$t" -- -runs=0 -rss_limit_mb=2048 -timeout=10
  done
  if [ -n "${GATES_FUZZ_SECONDS:-}" ]; then
    fuzz_work="$(mktemp -d "${TMPDIR:-/tmp}/usgp-fuzz.XXXXXX")"
    for entry in $fuzz_targets; do
      t="${entry%%:*}"
      # libFuzzer refuses a corpus directory that does not exist (QA-002).
      mkdir -p "$fuzz_work/$t"
      # Scratch working corpus first, so new inputs (no recorded origin)
      # never land in fuzz/corpus/ (CONTRIBUTING.md test-data rule).
      run_in fuzz ${keep_awake[@]+"${keep_awake[@]}"} \
        cargo fuzz run "$t" "$fuzz_work/$t" "corpus/$t" \
        -- -max_total_time="$GATES_FUZZ_SECONDS" -max_len="${entry#*:}" \
        -rss_limit_mb=2048 -timeout=10
    done
    rm -rf "$fuzz_work"
  else
    skip "GATES_FUZZ_SECONDS unset; CI fuzz-smoke runs 600 s" "fuzz timed runs"
  fi
else
  skip "cargo-fuzz not installed" "cargo fuzz build and seed replay"
fi

# ------------------------------------------------------------- markdown --

run npx --yes markdownlint-cli@0.45.0 "docs/**/*.md" "specs/**/*.md" "fuzz/*.md" \
  "fuzz/corpus/**/*.md" "testing/**/*.md" "*.md"

# ----------------------------------------------------------- boot smoke --

# Plan WU-12: `build` as the normal user, then `all`. Exit 77 (NOT RUN) on
# macOS for every network scenario, and on Linux without root; the CI
# boot-smoke job runs it under sudo.
if [ "$(id -u)" -ne 0 ]; then
  run scripts/boot-smoke.sh build
else
  skip "running as root; boot-smoke build refuses root" "scripts/boot-smoke.sh build"
fi
run scripts/boot-smoke.sh all

# ------------------------------------------------- artifact name scan --

# The name gate skips target/, so the shipped and uploaded artifacts are
# scanned on their own, with no exclusions (CR-303, decision 0005): the
# release relay and cli, both staged .efi payloads, and the boot smoke
# evidence. boot-smoke `build` builds the release binaries only on Linux, so
# build them here too (a no-op when they are up to date).
if [ "$(id -u)" -ne 0 ]; then
  run cargo build --release --locked -p usgp-relay -p usgp-cli
  run scripts/check-artifact-names.sh
  # check-artifact-names.sh covers the relay and the cli; REQ-PE-001 on
  # all four release binaries (QA-001), as the CI fips-linkage job does.
  run cargo build --release --locked --workspace --bins
  rel="${CARGO_TARGET_DIR:-target}/release"
  run scripts/check-pe-files.sh files "$rel/usgp-server" "$rel/usgp-relay" \
    "$rel/usgp-preboot-agent" "$rel/usgp-cli"
else
  skip "running as root; the staged payloads come from boot-smoke build" \
    "scripts/check-artifact-names.sh"
fi

echo
echo "Summary (verdict, exit status, command):"
printf '  %s\n' "${results[@]}"
if [ "$failed" -ne 0 ]; then
  echo "gates: FAIL"
  exit 1
fi
if [ "$not_run" -ne 0 ]; then
  echo "gates: no failures, but some gates were NOT RUN (exit 77; not a PASS)"
  exit 77
fi
echo "gates: PASS"
exit 0
