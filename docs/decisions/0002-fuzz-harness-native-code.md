# 0002: libFuzzer in the Fuzz Workspace

- Status: Accepted
- Date: 2026-10-25
- Decider: project owner

## Context

`cargo fuzz` uses `libfuzzer-sys`, which compiles LLVM libFuzzer (C++). The
pure-Rust rule forbids C/C++ dependencies in shipped code.

## Decision

Allow `libfuzzer-sys` **only** in the separate `fuzz/` Cargo workspace, which
is never built into, linked with, or shipped as part of any product artifact.

## Consequences

- The main workspace's pure-Rust gate does not cover `fuzz/`; CI checks that
  no main-workspace crate depends on `libfuzzer-sys`.
- `fuzz/` pins a nightly toolchain independently of the main workspace.
