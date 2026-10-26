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

if [ "${#failures[@]}" -gt 0 ]; then
  echo "test-check-names: FAIL"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
echo "test-check-names: OK ($count cases x matchers: ${matchers[*]})"
