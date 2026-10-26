#!/usr/bin/env bash
# FIPS linkage check (docs/decisions/0001, Amendment 1).
#
# For every shipped binary in target/<profile>/:
#   - the binary links the FIPS AWS-LC module (aws_lc_fips_* symbols present),
#   - it does NOT link the non-FIPS AWS-LC library (no aws_lc_0_* symbols),
#   - no non-FIPS AWS-LC shared library is among its dynamic dependencies,
#   - running it exits 0, i.e. FIPS mode reports active at start-up.
#
# Linux (the shipped and authoritative FIPS platform): the module must be
# linked statically. The script fails if any libaws_lc* shared library is a
# NEEDED entry or if the FIPS symbols are not defined in the binary itself,
# and it runs the binary file directly, exactly as a target host would, so a
# missing runtime library cannot be hidden by Cargo's library search path.
#
# macOS (development only, POAM-2): AWS-LC refuses a static FIPS build there,
# so aws-lc-fips-sys builds libaws_lc_fips_*.dylib, which the binary imports
# without an rpath. The binaries are started through `cargo run`, which puts
# the build output on the dynamic library search path. A macOS pass is
# functional evidence only (POAM-1) and never release evidence.
#
# Any other host OS fails closed.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SC-13 (Cryptographic Protection), CM-2, SI-7
# - docs/decisions/0001-fips-validated-crypto.md, Amendment 1
#
# Usage: scripts/check-fips-linkage.sh [debug|release]  (default: debug)
# The binaries must already be built for that profile.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

profile="${1:-debug}"
target_dir="${CARGO_TARGET_DIR:-target}/$profile"
case "$profile" in
  debug) cargo_profile=dev ;;
  *) cargo_profile="$profile" ;;
esac

host_os="$(uname -s)"
case "$host_os" in
  Darwin | Linux) ;;
  *)
    echo "fips-linkage: FAIL"
    echo "  unsupported host OS '$host_os' (Linux is the release platform; macOS is dev-only)"
    exit 1
    ;;
esac

dynamic_deps() {
  case "$host_os" in
    Darwin) otool -L "$1" ;;
    Linux) readelf -d "$1" | grep NEEDED || true ;;
  esac
}

# Bound each run so a binary that starts serving instead of exiting fails the
# check rather than hanging it (until every binary has a self-check mode).
run_limit=() # empty array; filled only if `timeout` exists
if command -v timeout > /dev/null 2>&1; then
  run_limit=(timeout 60)
fi
bins=(usgp-server usgp-relay usgp-preboot-agent usgp-cli)

# Symbol prefixes AWS-LC applies to its exported symbols. Mach-O adds a
# leading underscore; ELF does not.
fips_re='(^|[[:space:]])_?aws_lc_fips_[0-9]'
nonfips_re='(^|[[:space:]])_?aws_lc_[0-9]+_[0-9]'

failures=()
for b in "${bins[@]}"; do
  path="$target_dir/$b"
  if [ ! -x "$path" ]; then
    failures+=("$b: not built at $path")
    continue
  fi
  syms="$(nm "$path" 2> /dev/null || true)"
  if ! echo "$syms" | grep -qE "$fips_re"; then
    failures+=("$b: no FIPS module symbols (aws_lc_fips_*) found")
  fi
  if echo "$syms" | grep -qE "$nonfips_re"; then
    failures+=("$b: links non-FIPS AWS-LC (aws_lc_<ver>_* symbols)")
  fi
  if dynamic_deps "$path" | grep -qE 'libaws_lc_[0-9]'; then
    failures+=("$b: dynamically links non-FIPS AWS-LC")
  fi
  case "$host_os" in
    Linux)
      # Static linkage: no AWS-LC shared library at all, and the FIPS module
      # symbols are defined in the binary (not merely referenced).
      if dynamic_deps "$path" | grep -qE 'libaws_lc'; then
        failures+=("$b: AWS-LC linked dynamically; the Linux build must be static")
      fi
      if ! nm --defined-only "$path" 2> /dev/null | grep -qE "$fips_re"; then
        failures+=("$b: FIPS module symbols not defined in the binary (not statically linked)")
      fi
      run=("$path")
      ;;
    Darwin)
      run=(cargo run --quiet --locked --profile "$cargo_profile" --bin "$b" --)
      ;;
  esac
  if ! ${run_limit[@]+"${run_limit[@]}"} "${run[@]}" > /dev/null; then
    failures+=("$b: exited non-zero (FIPS mode not active?)")
  fi
done

if [ "${#failures[@]}" -gt 0 ]; then
  echo "fips-linkage: FAIL"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
echo "fips-linkage: OK ($host_os; ${bins[*]})"
