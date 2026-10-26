#!/usr/bin/env bash
# Negative and positive tests for scripts/check-names.sh (findings CR-011,
# QA-003, QA-004). Each case builds a fresh fake repository in a temp
# directory, plants one file or directory, and runs the gate with every
# available matcher (grep always; rg too if installed). The forbidden name is
# assembled at run time so this file never contains it.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$root/scripts/check-names.sh"

name="tan"
name+="ium"
upper="$(printf '%s' "$name" | tr '[:lower:]' '[:upper:]')"

matchers=(grep)
command -v rg > /dev/null 2>&1 && matchers+=(rg)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=()
count=0

# case <expected: pass|fail> <description> <setup command...>
# The setup command runs inside the fake repository root.
case_() {
  local expect=$1 desc=$2
  shift 2
  local m repo status
  for m in "${matchers[@]}"; do
    repo="$work/repo-$count-$m"
    mkdir -p "$repo/scripts" "$repo/specs" "$repo/crates/a/src"
    cp "$gate" "$repo/scripts/check-names.sh"
    echo "clean" > "$repo/crates/a/src/lib.rs"
    (cd "$repo" && "$@")
    status=0
    if [ "$m" = grep ]; then
      NAMES_FORCE_GREP=1 "$repo/scripts/check-names.sh" > "$repo.out" 2>&1 || status=$?
    else
      NAMES_FORCE_GREP=0 "$repo/scripts/check-names.sh" > "$repo.out" 2>&1 || status=$?
    fi
    if { [ "$expect" = pass ] && [ "$status" -ne 0 ]; } \
      || { [ "$expect" = fail ] && [ "$status" -ne 1 ]; }; then
      failures+=("[$m] expected $expect, got exit $status: $desc")
    fi
  done
  count=$((count + 1))
}

put() { # put <path> <content>
  mkdir -p "$(dirname "$1")"
  printf '%s\n' "$2" > "$1"
}

# Baseline and root-anchored exclusions: must pass.
case_ pass "clean tree" true
case_ pass "root CLAUDE.md" put CLAUDE.md "$name"
case_ pass "root specs/README.md" put specs/README.md "$name"
case_ pass "root .claude/" put .claude/notes.md "$name"
case_ pass "root cleanroom/ (content and path)" put "cleanroom/$name-log.md" "$name"
case_ pass "root target/" put "target/debug/$name.txt" "$name"

# Everything else: must fail.
case_ fail "content in crate source" put crates/a/src/lib.rs "// $name"
case_ fail "uppercase content in hidden root file" put .hidden-note "$upper"
case_ fail "nested CLAUDE.md" put crates/a/CLAUDE.md "$name"
case_ fail "nested specs/README.md" put crates/a/specs/README.md "$name"
case_ fail "nested cleanroom/" put crates/a/cleanroom/x.md "$name"
case_ fail "nested .claude/" put crates/a/.claude/x.md "$name"
case_ fail "nested target/" put fuzz/target/x.txt "$name"
case_ fail "specs/ file other than README.md" put specs/INDEX.md "$name"
case_ fail "vendor-named file, clean content" \
  put "crates/a/tests/${name}_sample.wim" "clean"
case_ fail "vendor-named directory, clean content" \
  put "crates/${upper}-x/lib.rs" "clean"
case_ fail "vendor-named empty directory" mkdir -p "docs/$name"
case_ fail "binary file containing the name" \
  sh -c 'printf "\000\001%s\000" "$1" > crates/a/blob.bin' sh "$name"

# The gate's exclusion list must equal the allowed-location list
# (CLAUDE.md clean-room rule 5 and the clean-room protocol, recorded in
# docs/decisions/0005-names-gate-scope.md). Three copies are compared: the
# list below, the decision record, and the gate's `find` expressions. A new
# exclusion therefore needs a decision record change (CR-302).
expected="$(printf '%s\n' /.claude /.git /CLAUDE.md /cleanroom /specs/README.md /target \
  | LC_ALL=C sort)"
adr="$root/docs/decisions/0005-names-gate-scope.md"
adr_list="$(sed -n '/names-gate-exclusions:begin/,/names-gate-exclusions:end/p' "$adr" \
  | sed -n 's|^[[:space:]]*\(/[^[:space:]]*\)[[:space:]]*$|\1|p' | LC_ALL=C sort)"
gate_all="$(grep -v -E '^[[:space:]]*#' "$gate" | grep -o -E -- '-path \./[^ )]+' \
  | sed 's|^-path \.||')"
gate_list="$(printf '%s\n' "$gate_all" | LC_ALL=C sort -u)"
if [ "$adr_list" != "$expected" ]; then
  failures+=("exclusions in $adr differ from the expected list: $(echo $adr_list)")
fi
if [ "$gate_list" != "$expected" ]; then
  failures+=("exclusions in check-names.sh differ from the expected list: $(echo $gate_list)")
fi
# Both find expressions (paths and files) must skip the same set.
gate_count="$(printf '%s\n' "$gate_all" | grep -c .)"
want_count=$(($(printf '%s\n' "$expected" | grep -c .) * 2))
if [ "$gate_count" -ne "$want_count" ]; then
  failures+=("check-names.sh: path and file listings skip different sets ($gate_count -path tests, want $want_count)")
fi
count=$((count + 1))

if [ "${#failures[@]}" -gt 0 ]; then
  echo "test-check-names: FAIL"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
echo "test-check-names: OK ($count cases x matchers: ${matchers[*]})"
