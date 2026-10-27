#!/usr/bin/env bash
# Pure-Rust gate (CLAUDE.md "Pure-Rust Rule"; docs/decisions/0001 with
# Amendment 1; docs/decisions/0002).
#
# 1. Every workspace member except usgp-crypto has no native-code crate
#    (any -sys crate, or a C/C++ build helper: cc, bindgen, cmake,
#    pkg-config, vcpkg, cxx, cxx-build, link-cplusplus, nasm-rs, openssl-src,
#    autotools) in its normal, build, or dev tree (usgp-crypto's subtree is
#    pruned) unless it is on scripts/pure-rust-allowlist.txt. Dev edges are
#    included because a dev-dependency compiles C during `cargo test`.
# 2. usgp-crypto may additionally use the AWS-LC FIPS chain and its
#    build-only tools.
# 3. aws-lc-rs has no dependents other than usgp-crypto and rustls.
# 4. No workspace crate depends on libfuzzer-sys in any edge kind (0002).
#
# Prints "pure-rust: OK" and exits 0, or lists offenders and exits 1.
#
# All cargo calls use --locked so the gate never rewrites Cargo.lock.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

allowlist_file="scripts/pure-rust-allowlist.txt"
crypto_set="aws-lc-fips-sys aws-lc-sys clang-sys cc cmake bindgen pkg-config"
aws_lc_rs_dependents="usgp-crypto rustls rustls-webpki"
pattern='^([A-Za-z0-9_-]+-sys|cc|bindgen|cmake|pkg-config|vcpkg|cxx|cxx-build|link-cplusplus|nasm-rs|openssl-src|autotools) v'

allowed=()
while IFS= read -r line; do
  name="${line%%#*}"
  name="$(echo "$name" | tr -d '[:space:]')"
  [ -n "$name" ] && allowed+=("$name")
done < "$allowlist_file"

in_list() { # needle list...
  local needle=$1
  shift
  local x
  for x in "$@"; do
    [ "$x" = "$needle" ] && return 0
  done
  return 1
}

offenders=()

members=()
for dir in crates/*/ services/*/ tools/*/; do
  [ -f "$dir/Cargo.toml" ] || continue
  m="$(basename "$dir")"
  pkg="$(sed -n 's/^name *= *"\(.*\)"/\1/p' "$dir/Cargo.toml" | sed -n 1p)"
  if [ "$pkg" != "$m" ]; then
    offenders+=("$dir: package name '$pkg' differs from directory name")
    continue
  fi
  members+=("$m")
done

for m in "${members[@]}"; do
  tree="$(cargo tree --locked -p "$m" -e normal,build,dev --target all --prefix none)"
  # `--prune` errors if the spec is not in the member's graph, so prune only
  # members that actually reach usgp-crypto.
  if [ "$m" != "usgp-crypto" ] && grep -qE '^usgp-crypto v' <<< "$tree"; then
    tree="$(cargo tree --locked -p "$m" -e normal,build,dev --target all \
      --prune usgp-crypto --prefix none)"
  fi
  hits="$(echo "$tree" | grep -E "$pattern" | awk '{print $1}' | sort -u || true)"
  for h in $hits; do
    # The `+` form keeps an empty allowlist safe under `set -u` (bash 3.2).
    if in_list "$h" ${allowed[@]+"${allowed[@]}"}; then
      continue
    fi
    # shellcheck disable=SC2086 # word splitting of the set is intended
    if [ "$m" = "usgp-crypto" ] && in_list "$h" $crypto_set; then
      continue
    fi
    offenders+=("$m: depends on $h")
  done
done

# aws-lc-rs must only be reached through usgp-crypto (and rustls inside it).
deps="$(cargo tree --locked -i aws-lc-rs -e normal --target all --depth 1 --prefix none \
  | tail -n +2 | awk '{print $1}' | sort -u)"
for d in $deps; do
  # shellcheck disable=SC2086
  in_list "$d" $aws_lc_rs_dependents || offenders+=("aws-lc-rs: unexpected dependent $d")
done

# Decision 0002: libFuzzer stays in the separate fuzz/ workspace.
# Captured first, then matched: `cargo tree | grep -q` under pipefail fails
# when grep's early exit SIGPIPEs cargo, which would hide a match.
ws_tree="$(cargo tree --locked --workspace -e all --target all --prefix none)"
if grep -qE '^libfuzzer-sys v' <<< "$ws_tree"; then
  offenders+=("workspace: depends on libfuzzer-sys (decision 0002)")
fi

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "pure-rust: FAIL"
  printf '  %s\n' "${offenders[@]}"
  exit 1
fi
echo "pure-rust: OK"
