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
# 5. Decision 0019 item 4: usgp-disk, usgp-deploy and usgp-image stay
#    OS-neutral. Their shipped tree (normal and build edges, every target)
#    has no native-code crate at all, allowlisted or not; only the FIPS chain
#    reached through usgp-crypto is pruned. usgp-winapi's tree may hold
#    windows-sys and nothing else of that kind.
# 6. Decision 0019 item 4: the agent's shipped tree for x86_64-pc-windows-msvc
#    allows only the AWS-LC chain under usgp-crypto and windows-sys under
#    usgp-winapi. With both pruned, nothing of that kind may remain.
# 7. Decision 0019 item 2: every member uses the workspace lints
#    (`unsafe_code = "forbid"`) except usgp-winapi, which sets "deny"; and
#    only crates/usgp-winapi/src/ffi.rs may allow `unsafe_code`.
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
os_neutral="usgp-disk usgp-deploy usgp-image"
win_target="x86_64-pc-windows-msvc"
agent="usgp-preboot-agent"
winapi="usgp-winapi"
winapi_ffi="crates/usgp-winapi/src/ffi.rs"
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
  # Rule 7: the lint table. Other members must inherit the workspace lints.
  if [ "$m" = "$winapi" ]; then
    grep -qE '^unsafe_code *= *"deny"' "$dir/Cargo.toml" \
      || offenders+=("$m: Cargo.toml must set unsafe_code = \"deny\" (decision 0019)")
  else
    lints="$(awk '/^\[lints\]/ { f = 1; next } f && NF { print; exit }' "$dir/Cargo.toml")"
    [ "$lints" = "workspace = true" ] \
      || offenders+=("$m: [lints] must be 'workspace = true' (unsafe_code forbid; decision 0019)")
    if grep -qE '^\[lints\.' "$dir/Cargo.toml"; then
      offenders+=("$m: overrides workspace lints (decision 0019)")
    fi
  fi
done

# member_tree <package> <target> <edges> [prune...]: the package's tree, one
# crate per line, with each named crate pruned if it is in the graph
# (`--prune` errors on a spec that is not).
member_tree() {
  local pkg=$1 target=$2 edges=$3 base p
  shift 3
  local args=()
  base="$(cargo tree --locked -p "$pkg" -e "$edges" --target "$target" --prefix none)"
  for p in "$@"; do
    if [ "$p" != "$pkg" ] && grep -qE "^$p v" <<< "$base"; then
      args+=(--prune "$p")
    fi
  done
  if [ "${#args[@]}" -gt 0 ]; then
    cargo tree --locked -p "$pkg" -e "$edges" --target "$target" --prefix none "${args[@]}"
  else
    echo "$base"
  fi
}

# native_hits: crate names matching the gate pattern, from a tree on stdin.
native_hits() {
  grep -E "$pattern" | awk '{print $1}' | sort -u || true
}

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

# Rule 5 (decision 0019 item 4): OS-neutral crates, no allowlist.
for m in $os_neutral $winapi; do
  if ! in_list "$m" "${members[@]}"; then
    offenders+=("$m: expected workspace member is missing (decision 0019)")
    continue
  fi
  for h in $(member_tree "$m" all normal,build usgp-crypto | native_hits); do
    if [ "$m" = "$winapi" ] && [ "$h" = "windows-sys" ]; then
      continue
    fi
    offenders+=("$m: depends on $h on some target (decision 0019: OS-neutral, no native-code crate)")
  done
done

# Rule 6 (decision 0019 item 4): the agent on the Windows target. The
# allowed crates are checked under their owners by rules 1 and 5.
if in_list "$agent" "${members[@]}"; then
  for h in $(member_tree "$agent" "$win_target" normal,build usgp-crypto "$winapi" | native_hits); do
    offenders+=("$agent ($win_target): depends on $h outside usgp-crypto and $winapi (decision 0019)")
  done
else
  offenders+=("$agent: expected workspace member is missing")
fi

# Rule 7 (decision 0019 item 2): unsafe only in usgp-winapi's ffi.rs.
unsafe_files="$(grep -rlE --include='*.rs' \
  '(allow|expect|warn)[[:space:]]*\([^)]*unsafe_code' crates services tools || true)"
for f in $unsafe_files; do
  if [ "$f" != "$winapi_ffi" ]; then
    offenders+=("$f: allows unsafe_code; only $winapi_ffi may (decision 0019)")
  fi
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
