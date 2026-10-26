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
#   GATES_FUZZ_SECONDS  run each fuzz target for this many seconds (plan
#                       section 10.4 uses 600). Unset: seeds are replayed only.
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

# ------------------------------------------------------- main workspace --

# --locked everywhere (CM-2): a gate run must never rewrite Cargo.lock, and a
# manifest edit without a lockfile update fails here as it does in CI.
run cargo fmt --all --check
run cargo clippy --locked --workspace --all-targets -- -D warnings
run cargo test --locked --workspace
run cargo test --locked --workspace --doc
run cargo build --locked --workspace --bins
# Start-up contract (plan section 3.6): every binary checks FIPS mode first;
# usgp-relay --self-check exits 0 (inside check-fips-linkage.sh), and
# usgp-relay with no arguments prints usage and exits 2.
run scripts/check-fips-linkage.sh debug
expect_exit 2 cargo run --quiet --locked --bin usgp-relay
run scripts/check-pure-rust.sh
# The name gate prints which matcher ran. If ripgrep is installed, the grep
# matcher runs as well, so both code paths are exercised (QA-004).
run scripts/check-names.sh
if command -v rg > /dev/null 2>&1; then
  run env NAMES_FORCE_GREP=1 scripts/check-names.sh
fi
run scripts/test-check-names.sh
run cargo deny --locked check
run cargo audit

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
  if (cd testing/netlab && rustup target list --installed | grep -qx x86_64-unknown-linux-gnu); then
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
if command -v cargo-fuzz > /dev/null 2>&1; then
  run_in fuzz cargo fuzz build
  for t in dhcp_packet tftp_packet; do
    run_in fuzz cargo fuzz run "$t" "corpus/$t" -- -runs=0
  done
  if [ -n "${GATES_FUZZ_SECONDS:-}" ]; then
    fuzz_work="$(mktemp -d "${TMPDIR:-/tmp}/usgp-fuzz.XXXXXX")"
    # libFuzzer refuses a corpus directory that does not exist (QA-002).
    mkdir -p "$fuzz_work/dhcp_packet" "$fuzz_work/tftp_packet"
    # Scratch working corpus first, so new inputs (no recorded origin) never
    # land in fuzz/corpus/ (CONTRIBUTING.md test-data rule).
    run_in fuzz cargo fuzz run dhcp_packet "$fuzz_work/dhcp_packet" corpus/dhcp_packet \
      -- -max_total_time="$GATES_FUZZ_SECONDS" -max_len=1600
    run_in fuzz cargo fuzz run tftp_packet "$fuzz_work/tftp_packet" corpus/tftp_packet \
      -- -max_total_time="$GATES_FUZZ_SECONDS" -max_len=4096
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
