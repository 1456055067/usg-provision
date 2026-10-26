#!/usr/bin/env bash
# Runs every local quality gate in order, printing each command and its exit
# status. Continues past failures so a whole run is recorded; exits 1 if any
# gate failed. See .claude/skills/provision-workflow/references/quality-gates.md.
set -uo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

results=()
failed=0

run() {
  echo "==> $*"
  "$@"
  local status=$?
  echo "<== exit $status: $*"
  results+=("$status  $*")
  [ "$status" -eq 0 ] || failed=1
}

# --locked everywhere (CM-2): a gate run must never rewrite Cargo.lock, and a
# manifest edit without a lockfile update fails here as it does in CI.
run cargo fmt --all --check
run cargo clippy --locked --workspace --all-targets -- -D warnings
run cargo test --locked --workspace
run cargo test --locked --workspace --doc
run cargo build --locked --workspace --bins
run scripts/check-fips-linkage.sh debug
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
run npx --yes markdownlint-cli@0.45.0 "docs/**/*.md" "specs/**/*.md" "fuzz/*.md" "*.md"

echo
echo "Summary (exit status, command):"
printf '  %s\n' "${results[@]}"
exit "$failed"
