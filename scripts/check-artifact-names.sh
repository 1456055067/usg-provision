#!/usr/bin/env bash
# Clean-room name check over shipped and uploaded artifacts (CLAUDE.md
# clean-room rule 5; finding CR-303). scripts/check-names.sh skips the root
# target/ directory as build output, so the files that actually leave the
# build host are scanned here instead, with no exclusions of any kind.
#
# Scanned (paths and contents, case-insensitive, binary included):
#   required  $TARGET_DIR/release/usgp-relay       (release binary)
#   required  $TARGET_DIR/release/usgp-cli         (release binary)
#   required  target/boot-smoke/stage/usgp-test-payload.efi
#   required  target/boot-smoke/stage/disk-fallback.efi
#   optional  every file under target/boot-smoke/ (the boot smoke evidence
#             directory CI uploads; scanned whole if present)
# TARGET_DIR is $CARGO_TARGET_DIR if set, else target/ (as in
# scripts/boot-smoke.sh). Build the artifacts first: `cargo build --release
# --locked -p usgp-relay -p usgp-cli` and `scripts/boot-smoke.sh build`.
#
# Exit status: 0 no hit; 1 a hit; 2 a required artifact is missing or a file
# could not be read (fails closed). A false positive is fixed by renaming or
# by changing what goes into the artifact, never by excluding a file
# (docs/decisions/0005-names-gate-scope.md).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation), CM-7
# - CLAUDE.md clean-room rule 5; docs/decisions/0005-names-gate-scope.md
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

pattern='tan[i]um'
export LC_ALL=C

target_dir="${CARGO_TARGET_DIR:-$root/target}"
evidence_dir="$root/target/boot-smoke"
required=(
  "$target_dir/release/usgp-relay"
  "$target_dir/release/usgp-cli"
  "$evidence_dir/stage/usgp-test-payload.efi"
  "$evidence_dir/stage/disk-fallback.efi"
)

missing=0
for f in "${required[@]}"; do
  if [ ! -f "$f" ]; then
    echo "artifact-names: ERROR: required artifact missing: $f"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "artifact-names: ERROR (build the artifacts first; failing closed)"
  exit 2
fi

errs="$(mktemp)"
list="$(mktemp)"
trap 'rm -f "$errs" "$list"' EXIT

# One NUL-separated list: the required files, then everything under the
# evidence directory (it contains the staged payloads again; a duplicate is
# harmless). Path names under the evidence directory are checked too.
printf '%s\0' "${required[@]}" > "$list"
path_hits=""
if [ -d "$evidence_dir" ]; then
  find "$evidence_dir" -type f -print0 >> "$list" 2>> "$errs"
  path_hits="$(find "$evidence_dir" ! -path "$evidence_dir" 2>> "$errs" \
    | grep -i -E -- "$pattern" || true)"
fi

count="$(tr -cd '\0' < "$list" | wc -c | tr -d ' ')"
file_hits="$(xargs -0 grep -a -i -l -E -e "$pattern" -- /dev/null < "$list" 2>> "$errs" || true)"

if [ -s "$errs" ]; then
  echo "artifact-names: ERROR (not every artifact could be read; failing closed)"
  cat "$errs"
  exit 2
fi

if [ -n "$path_hits" ] || [ -n "$file_hits" ]; then
  echo "artifact-names: FAIL (clean-room rule 5)"
  [ -n "$path_hits" ] && printf 'path names:\n%s\n' "$path_hits" | sed '2,$s/^/  /'
  [ -n "$file_hits" ] && printf 'file contents:\n%s\n' "$file_hits" | sed '2,$s/^/  /'
  exit 1
fi
echo "artifact-names: OK ($count files scanned)"
