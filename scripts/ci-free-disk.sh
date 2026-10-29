#!/usr/bin/env bash
# Free root-disk space on a GitHub-hosted Ubuntu runner before a job that
# builds the whole workspace (CI run 40815815025: `gates` ran out of disk
# while restoring its cache). Removes large preinstalled toolchains this
# repository never uses, and logs `df -h` before and after.
#
# Nothing listed here is used by any job: Rust comes from rustup and
# rust-toolchain.toml, the FIPS build toolchain (Go, CMake, Clang, Perl) from
# apt (.github/actions/fips-toolchain), PostgreSQL from a digest-pinned
# container. Docker, the runner's own .NET (under the runner directory),
# Node, Python and the hosted Go toolchain are left alone.
#
# Refuses to run anywhere but a GitHub-hosted runner, so it can never delete
# these directories on a developer machine or a self-hosted runner.
# Best effort: a directory that cannot be removed is a warning, not a failure
# (the job's own disk use then decides).
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-6 (Configuration Settings; recorded CI runner baseline),
#   SA-10 (Developer Configuration Management)
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] \
  || [ "${RUNNER_OS:-}" != Linux ]; then
  echo "ci-free-disk: not a GitHub-hosted Linux runner; refusing to delete anything" >&2
  exit 2
fi

show_df() {
  echo "--- df -h ($1)"
  df -h / /mnt 2> /dev/null || df -h /
}

show_df before

candidates=(
  /usr/local/lib/android
  /usr/share/dotnet
  /opt/ghc
  /usr/local/.ghcup
  /opt/hostedtoolcache/CodeQL
  /usr/share/swift
  /usr/local/share/boost
  /usr/local/share/powershell
  /usr/local/share/chromium
  /opt/microsoft
  /opt/google
  /opt/az
  /usr/lib/jvm
  /usr/lib/google-cloud-sdk
)
shopt -s nullglob
candidates+=(/usr/local/julia*)
shopt -u nullglob

present=()
for d in "${candidates[@]}"; do
  if [ -e "$d" ]; then present+=("$d"); fi
done

if [ "${#present[@]}" -eq 0 ]; then
  echo "ci-free-disk: none of the known preinstalled toolchains is present"
else
  echo "ci-free-disk: removing ${present[*]}"
  start=$SECONDS
  if ! printf '%s\0' "${present[@]}" | sudo xargs -0 -n 1 -P 4 rm -rf --; then
    echo "::warning::ci-free-disk: some preinstalled directories could not be removed"
  fi
  echo "ci-free-disk: done in $((SECONDS - start)) s"
fi

show_df after
