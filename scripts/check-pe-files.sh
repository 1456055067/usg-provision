#!/usr/bin/env bash
# REQ-PE-001 gate: the product's distribution, and the repository it is
# built from, contain no Windows PE image, no part of Microsoft's ADK or its
# Windows PE add-on, and no file taken from them (finding QA-001; plan
# section 8 row REQ-PE-001; OPEN-PE-LIC).
#
# Usage:
#   check-pe-files.sh repo            every tracked and untracked, not
#                                     ignored file (git ls-files -co
#                                     --exclude-standard)
#   check-pe-files.sh files <path>... the named files, and every file under
#                                     each named directory (shipped and
#                                     uploaded artifacts; no exception)
#
# Rule (a file is a hit if any line applies):
#   N1  its base name, case-insensitively, ends in .wim, .swm or .esd (WIM
#       files, split parts and recovery output: specs/standards/wim.md
#       sections 1 and 10, wim-compression.md section 5), or in .cab or .msu
#       (WinPE optional-component and update packages: winpe.md section 4);
#   N2  its base name, case-insensitively, is boot.sdi or starts with
#       bootmgr (plan section 8), or is startnet.cmd or winpeshl.ini, or its
#       stem is wpeinit, copype or makewinpemedia (winpe.md sections 3, 5);
#   C1  its first 8 bytes are the WIM signature 4d 53 57 49 4d 00 00 00
#       ("MSWIM" and three zero bytes; OBS-001), whatever its name.
# The only exception, in repo mode only: a file under fuzz/corpus/ that hits
# C1 alone (not N1 or N2) and whose bytes 24 to 39 are the ASCII GUID
# "usgp-test-guid-1" that our own test builder writes
# (crates/usgp-image/src/testkit/builder.rs). Such a file is a synthetic
# fuzz seed, not a Microsoft file; a DISM-made WIM carries a GUID DISM
# chose (OBS-016) and is refused even there. Artifact mode has no
# exception. A false positive is fixed by renaming or by changing what is
# shipped or committed, never by widening the exception.
#
# Exit status: 0 no hit; 1 a hit; 2 usage error or a file could not be read
# (fails closed).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-7 (Least Functionality), SA-11 (Developer Testing and
#   Evaluation), CM-10 (Software Usage Restrictions)
# - SPEC: specs/preinstall-env.md#REQ-PE-001
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LC_ALL=C

magic='4d5357494d000000'
test_guid='usgp-test-guid-1'
name_re='\.(wim|swm|esd|cab|msu)$|^(boot\.sdi|bootmgr.*|startnet\.cmd|winpeshl\.ini|(wpeinit|copype|makewinpemedia)(\..*)?)$'

usage() {
  echo "usage: $0 repo | files <path>..." >&2
  exit 2
}

[ $# -ge 1 ] || usage
mode=$1
shift

list="$(mktemp)"
errs="$(mktemp)"
trap 'rm -f "$list" "$errs"' EXIT

case "$mode" in
  repo)
    [ $# -eq 0 ] || usage
    cd "$root"
    if ! git ls-files -z -co --exclude-standard > "$list" 2>> "$errs"; then
      echo "pe-files: ERROR: cannot list repository files (failing closed)"
      cat "$errs"
      exit 2
    fi
    ;;
  files)
    [ $# -ge 1 ] || usage
    for p in "$@"; do
      if [ -d "$p" ]; then
        find "$p" -type f -print0 >> "$list" 2>> "$errs"
      elif [ -f "$p" ]; then
        printf '%s\0' "$p" >> "$list"
      else
        echo "pe-files: ERROR: not a file or directory: $p" >> "$errs"
      fi
    done
    ;;
  *) usage ;;
esac

hits=()
count=0
while IFS= read -r -d '' f; do
  count=$((count + 1))
  # A tracked file deleted in the working tree is not shipped.
  [ "$mode" = repo ] && [ ! -e "$f" ] && continue
  base="$(basename "$f" | tr '[:upper:]' '[:lower:]')"
  if printf '%s\n' "$base" | grep -q -E -- "$name_re"; then
    hits+=("name: $f")
    continue
  fi
  if [ ! -r "$f" ]; then
    echo "pe-files: ERROR: cannot read $f" >> "$errs"
    continue
  fi
  head8="$(head -c 8 -- "$f" 2>> "$errs" | od -An -tx1 | tr -d ' \n')"
  [ "$head8" = "$magic" ] || continue
  if [ "$mode" = repo ] && [[ "$f" == fuzz/corpus/* ]]; then
    guid="$(head -c 40 -- "$f" 2>> "$errs" | tail -c 16)"
    [ "$guid" = "$test_guid" ] && continue
  fi
  hits+=("WIM signature: $f")
done < "$list"

if [ -s "$errs" ]; then
  echo "pe-files: ERROR (not every file could be listed or read; failing closed)"
  cat "$errs"
  exit 2
fi
if [ "${#hits[@]}" -ne 0 ]; then
  echo "pe-files: FAIL (REQ-PE-001: Windows PE / ADK file or WIM image)"
  printf '  %s\n' "${hits[@]}"
  exit 1
fi
echo "pe-files: OK ($mode: $count files checked)"
