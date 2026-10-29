#!/usr/bin/env bash
# Reduce a Cargo target profile directory to the third-party dependency
# artifacts before CI saves it to the Actions cache.
#
# Workspace crates always rebuild in CI (a fresh checkout gives every source
# file a new mtime), so their libraries, test and bin executables,
# fingerprints, build-script output and incremental state are dead weight in
# the cache. Only dependency artifacts (the FIPS module build among them) are
# reused across commits. Keeping just those bounds the cache size and the
# disk the restore needs (CI run 40815815025).
#
# Usage: scripts/ci-prune-target.sh [profile]   (default: debug)
# Honours CARGO_TARGET_DIR. Exit 2 on a bad argument or a missing directory.
#
# Removed:
#   <target>/*                     everything except <profile>/ and the
#                                  CACHEDIR.TAG / .rustc_info.json files
#   <profile>/*                    everything except deps/, build/, .fingerprint/
#   deps/   executables without a lib prefix (test and bin executables),
#           libusgp_* and usgp_* (workspace crates)
#   build/, .fingerprint/   usgp-* (workspace packages)
# Kept: dependency rlib/rmeta/proc-macro .so files, their fingerprints and
# build-script output.
#
# COMPLIANCE MAPPING:
# - NIST 800-53: SA-10 (Developer Configuration Management), CM-6
set -euo pipefail

profile="${1:-debug}"
case "$profile" in
  "" | */* | .*) echo "ci-prune-target: bad profile '$profile'" >&2; exit 2 ;;
esac
target="${CARGO_TARGET_DIR:-target}"
dir="$target/$profile"
if [ ! -d "$dir" ]; then
  echo "ci-prune-target: $dir does not exist" >&2
  exit 2
fi

echo "ci-prune-target: before: $(du -sh "$target" | cut -f 1) in $target"

find "$target" -mindepth 1 -maxdepth 1 \
  ! -name "$profile" ! -name CACHEDIR.TAG ! -name .rustc_info.json \
  -exec rm -rf -- {} +
find "$dir" -mindepth 1 -maxdepth 1 \
  ! -name deps ! -name build ! -name .fingerprint \
  -exec rm -rf -- {} +
if [ -d "$dir/deps" ]; then
  find "$dir/deps" -mindepth 1 -maxdepth 1 -type f -perm -100 ! -name 'lib*' -delete
  find "$dir/deps" -mindepth 1 -maxdepth 1 \( -name 'libusgp_*' -o -name 'usgp_*' \) \
    -exec rm -rf -- {} +
fi
for sub in build .fingerprint; do
  if [ -d "$dir/$sub" ]; then
    find "$dir/$sub" -mindepth 1 -maxdepth 1 -name 'usgp-*' -exec rm -rf -- {} +
  fi
done

echo "ci-prune-target: after:  $(du -sh "$target" | cut -f 1) in $target"
