#!/usr/bin/env bash
# Clean-room name check (CLAUDE.md clean-room rule 5). The bracketed pattern
# keeps this script from matching itself. Exits 1 if any match is found, and
# fails closed (exit 2) if the tree cannot be fully searched.
#
# Two checks, over one file list:
#   1. paths: no file or directory path contains the name;
#   2. contents: no file contains it, text or binary.
#
# Exclusions are anchored to the repository root and are exactly the places
# the clean-room protocol allows the name: /CLAUDE.md, /specs/README.md,
# /.claude/, /cleanroom/, plus the build output /target/ and VCS metadata
# /.git/. A file or directory with one of those names anywhere else (for
# example crates/x/CLAUDE.md or fuzz/target/) is checked like any other.
# Nested build output is scanned on purpose. A false positive is fixed by
# moving build output under /target/ or by renaming, never by adding an
# exclusion; scripts/test-check-names.sh fails if this list changes without
# docs/decisions/0005-names-gate-scope.md. Shipped artifacts under /target/
# are scanned by scripts/check-artifact-names.sh.
#
# The file list comes from `find`, not from git or ripgrep's ignore rules, so
# the result is the same in a git checkout, an export, or a scratch copy.
# ripgrep (if installed) and grep only match contents over that list, with
# the same semantics (case-insensitive bytes, binary files included). Set
# NAMES_FORCE_GREP=1 to use grep even when rg is installed.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation), CM-7
# - CLAUDE.md clean-room rule 5; clean-room protocol (allowed locations)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pattern='tan[i]um'
export LC_ALL=C

if [ "${NAMES_FORCE_GREP:-0}" != "1" ] && command -v rg > /dev/null 2>&1; then
  matcher="rg"
else
  matcher="grep"
fi

errs="$(mktemp)"
trap 'rm -f "$errs"' EXIT

# All paths under the root except the root-anchored exclusions. `-path ./x`
# matches only the top-level entry, never a nested one.
list_paths() {
  find . \( -path ./.git -o -path ./target -o -path ./cleanroom \
    -o -path ./.claude \) -prune \
    -o \( -path ./CLAUDE.md -o -path ./specs/README.md \) -prune \
    -o ! -path . -print0
}
list_files() {
  find . \( -path ./.git -o -path ./target -o -path ./cleanroom \
    -o -path ./.claude \) -prune \
    -o \( -path ./CLAUDE.md -o -path ./specs/README.md \) -prune \
    -o -type f -print0
}

# 1. Paths (files, directories, symlinks).
path_hits="$(list_paths 2>> "$errs" | tr '\0' '\n' | grep -i -E -- "$pattern" || true)"

# 2. Contents. Both matchers print the names of matching files. /dev/null is
# a fixed first operand so an empty list never makes the tool read stdin.
case "$matcher" in
  rg)
    file_hits="$(list_files 2>> "$errs" \
      | xargs -0 rg --no-config -a -i -l -e "$pattern" -- /dev/null 2>> "$errs" || true)"
    ;;
  grep)
    file_hits="$(list_files 2>> "$errs" \
      | xargs -0 grep -a -i -l -E -e "$pattern" -- /dev/null 2>> "$errs" || true)"
    ;;
esac

if [ -s "$errs" ]; then
  echo "names: ERROR (matcher=$matcher; tree not fully searched, failing closed)"
  cat "$errs"
  exit 2
fi

if [ -n "$path_hits" ] || [ -n "$file_hits" ]; then
  echo "names: FAIL (clean-room rule 5; matcher=$matcher)"
  if [ -n "$path_hits" ]; then
    echo "path names:"
    printf '%s\n' "$path_hits" | sed 's/^/  /'
  fi
  if [ -n "$file_hits" ]; then
    echo "file contents:"
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if grep -I -q -i -E -e "$pattern" -- "$f" 2> /dev/null; then
        grep -I -n -i -E -e "$pattern" -- "$f" | sed "s|^|  $f:|"
      else
        echo "  $f: binary file matches"
      fi
    done <<< "$file_hits"
  fi
  exit 1
fi
echo "names: OK (matcher=$matcher)"
