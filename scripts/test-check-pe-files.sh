#!/usr/bin/env bash
# Negative and positive tests for scripts/check-pe-files.sh (REQ-PE-001,
# finding QA-001). Each case builds a fresh git repository (repo mode) or
# directory (files mode) in a temp directory, plants one file, and checks
# the gate's exit status.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-11 (Developer Testing and Evaluation)
# - SPEC: specs/preinstall-env.md#REQ-PE-001
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
gate="$root/scripts/check-pe-files.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

failures=()
count=0

# wim <path> <guid16>: a 208-byte file with the WIM signature and a GUID.
wim() {
  mkdir -p "$(dirname "$1")"
  {
    printf 'MSWIM\0\0\0'
    printf '\320\0\0\0'
    head -c 12 /dev/zero
    printf '%s' "$2"
    head -c 168 /dev/zero
  } > "$1"
}

put() { # put <path> <content>
  mkdir -p "$(dirname "$1")"
  printf '%s\n' "$2" > "$1"
}

# case_ <mode: repo|files> <expected exit> <description> <setup cmd...>
case_() {
  local mode=$1 expect=$2 desc=$3
  shift 3
  local dir="$work/case-$count" status=0
  mkdir -p "$dir/scripts"
  cp "$gate" "$dir/scripts/check-pe-files.sh"
  put "$dir/src/lib.rs" "clean"
  (cd "$dir" && "$@")
  if [ "$mode" = repo ]; then
    # Untracked, not ignored files are listed (ls-files -co), so no add.
    (cd "$dir" && git init -q .)
    "$dir/scripts/check-pe-files.sh" repo > "$dir.out" 2>&1 || status=$?
  else
    "$dir/scripts/check-pe-files.sh" files "$dir/src" > "$dir.out" 2>&1 || status=$?
  fi
  if [ "$status" -ne "$expect" ]; then
    failures+=("[$mode] expected exit $expect, got $status: $desc")
    sed 's/^/    /' "$dir.out" >&2
  fi
  count=$((count + 1))
}

guid_ok='usgp-test-guid-1'
guid_dism='0123456789abcdef'

for mode in repo files; do
  case_ "$mode" 0 "clean tree" true
  case_ "$mode" 0 "WIM named in a text file" put src/notes.md "see boot.wim and MSWIM"
  case_ "$mode" 0 "MSWIM not at offset 0" put src/x.bin "xMSWIM"
  case_ "$mode" 1 "file named install.wim" put src/install.wim "x"
  case_ "$mode" 1 "upper-case BOOT.WIM" put src/media/sources/BOOT.WIM "x"
  case_ "$mode" 1 "split part .swm" put src/a2.swm "x"
  case_ "$mode" 1 "recovery .esd" put src/a.esd "x"
  case_ "$mode" 1 "boot.sdi" put src/boot/boot.sdi "x"
  case_ "$mode" 1 "bootmgr" put src/bootmgr "x"
  case_ "$mode" 1 "bootmgr.efi" put src/EFI/bootmgr.efi "x"
  case_ "$mode" 1 "startnet.cmd" put src/Windows/System32/startnet.cmd "x"
  case_ "$mode" 1 "winpeshl.ini" put src/winpeshl.ini "x"
  case_ "$mode" 1 "wpeinit.exe" put src/wpeinit.exe "x"
  case_ "$mode" 1 "copype.cmd" put src/copype.cmd "x"
  case_ "$mode" 1 "MakeWinPEMedia.cmd" put src/MakeWinPEMedia.cmd "x"
  case_ "$mode" 1 "optional component .cab" put src/WinPE-WMI.cab "x"
  case_ "$mode" 1 "update .msu" put src/update.msu "x"
  case_ "$mode" 1 "WIM signature under another name" wim src/payload.bin "$guid_dism"
  case_ "$mode" 1 "our GUID outside fuzz/corpus" wim src/seed.bin "$guid_ok"
done
# The fuzz-seed exception exists in repo mode only.
case_ repo 0 "builder seed in fuzz/corpus" wim fuzz/corpus/wim_check/seed.bin "$guid_ok"
case_ repo 1 "DISM-like GUID in fuzz/corpus" wim fuzz/corpus/wim_check/seed.bin "$guid_dism"
case_ repo 1 ".wim name in fuzz/corpus" wim fuzz/corpus/wim_check/seed.wim "$guid_ok"
case_ files 1 "builder seed in an artifact" wim src/fuzz/corpus/seed.bin "$guid_ok"
# Fails closed.
case_ files 2 "missing artifact path" rm -rf src

if [ "${#failures[@]}" -ne 0 ]; then
  echo "test-check-pe-files: FAIL"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi
echo "test-check-pe-files: OK ($count cases)"
