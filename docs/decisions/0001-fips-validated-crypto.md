# 0001: FIPS 140-3 Validated Cryptography Exception

- Status: Accepted
- Date: 2026-10-25
- Decider: project owner

## Context

The project is pure Rust (no C/C++ toolchain dependencies). The target ATO
under NIST SP 800-53 Rev 5 requires FIPS 140-3 validated cryptography for
SC-13 (and SC-8/SC-28 where cryptography protects data). No pure-Rust
cryptographic module currently holds a FIPS 140-3 validation.

## Decision

Use a FIPS 140-3 validated module from the start: **`aws-lc-rs` with its
`fips` feature** (AWS-LC FIPS), and **`rustls`** configured with the
aws-lc-rs FIPS crypto provider for all TLS.

This is the **only** permitted exception to the pure-Rust rule. It is
confined to `usgp-crypto`:

- All other crates reach cryptography only through the `CryptoProvider`
  trait and the TLS configuration exported by `usgp-crypto`; none depend on
  `aws-lc-rs`, `aws-lc-fips-sys`, `ring`, or any other crypto crate directly.
- `usgp-crypto` asserts FIPS mode at startup (`rustls` `fips()` check /
  aws-lc-rs FIPS status) and fails closed if it is not active.
- Only FIPS-approved algorithms are exposed by the provider.

## Consequences

- Build hosts need the AWS-LC FIPS toolchain (C compiler, CMake, Go) and the
  build must match the validated module's operational environment and build
  procedure; the release engineer documents this.
- The pure-Rust gate allows `aws-lc-fips-sys` (and its build-only deps such as
  `cc`, `cmake`, `bindgen`) **only** as dependencies of `usgp-crypto`; any other
  `-sys`/C dependency still fails the gate.
- Non-crypto formats that might tempt C libraries (WIM, compression, disk
  images) remain pure Rust.
- Hash functions required by open formats for non-security integrity (e.g.
  SHA-1 resource hashes in WIM) are still computed through the provider;
  SI-7 integrity uses SHA-256 or stronger.

## Amendment 1 (2026-10-25, accepted by project owner)

Enabling the `rustls` `fips` feature also compiles the non-FIPS `aws-lc-sys`
(it is built but not linked into shipped binaries), and the AWS-LC builds need
`bindgen`, `clang-sys`, `cmake`, and `cc` at build time. These are accepted as
**build-only dependencies of `usgp-crypto`**, under the same confinement as
`aws-lc-fips-sys`:

- `deny.toml` restricts each of them (via `wrappers`) to the AWS-LC/rustls
  chain under `usgp-crypto`.
- CI checks that shipped binaries do not link the non-FIPS AWS-LC library
  (no `aws_lc_0_*` non-FIPS symbols) and that FIPS mode reports active.
- Any other `-sys`/C dependency still fails the pure-Rust gate.

## Amendment 2 (2026-10-25, confirmed by project owner)

To hold the module version, `usgp-crypto` depends directly on
`aws-lc-fips-sys` (pinned `=0.14.3`, with `aws-lc-rs =1.18.2`), and
`deny.toml` lists `usgp-crypto` as an allowed parent of that crate. This stays
within this decision's confinement to `usgp-crypto`. The module's CMVP
certificate is not yet confirmed; tracked as POAM-3 (risk accepted).
