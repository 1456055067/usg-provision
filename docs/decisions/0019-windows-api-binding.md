# 0019: Windows API Binding for the Pre-boot Agent

- Status: Accepted (owner, 2026-10-28)
- Date: 2026-10-28
- Decider: project owner
- Amends: CLAUDE.md pure-Rust rule (the `-sys` crate name only), decision 0001
- Resolves: M3 plan question Q2

## Context

The pre-boot agent runs inside Windows PE and must call Windows APIs that
`std` does not wrap: disk enumeration and layout, volume and drive-letter
management, firmware variables, and token privileges. The pure-Rust rule
forbids `-sys` crates because they usually compile C. Microsoft's
`windows-sys` bindings are declarations only. They link through
`windows-link` (`raw-dylib`) and compile no C, and the crate is already on
`scripts/pure-rust-allowlist.txt`.

## Decision

1. `windows-sys` 0.61 (an exact version pin) may be used, and only by the
   new crate `crates/usgp-winapi`. `deny.toml` restricts it to that crate,
   plus the existing transitive paths through tokio, socket2, mio and
   errno.
2. Every `unsafe` call lives in `usgp-winapi/src/ffi.rs`, and each one
   carries a `// SAFETY:` comment. The rest of the crate denies `unsafe`,
   and every other crate keeps `forbid(unsafe_code)`.
3. Where `std` covers an operation, `std` is used. This applies to raw
   disk reads and writes through a device path, file streams, hard links,
   file times and child processes.
4. `usgp-disk`, `usgp-deploy` and `usgp-image` stay OS-neutral and have no
   `-sys` crate. `scripts/check-pure-rust.sh` checks this, and it allows
   only `aws-lc-fips-sys` (under `usgp-crypto`) and `windows-sys` (under
   `usgp-winapi`) in the agent's tree for `x86_64-pc-windows-msvc`.
5. The release engineer flags any other `-sys` crate or C build step. Each
   one needs its own decision.

## Consequences

- The Windows backend is reviewed against Microsoft's API reference
  summary (spec request SR-3).
- Updating `windows-sys` is a reviewed dependency change.
