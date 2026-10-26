# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project Overview

usg-provision is a **pure-Rust, clean-room implementation** of the capabilities
of an enterprise bare-metal OS provisioning product (functionally equivalent to
Tanium Provision): network boot of bare-metal and existing endpoints, OS image
deployment, driver and configuration injection, distributed image caching on
local subnets, and centrally managed, audited provisioning jobs. It is built
for U.S. Government use and targets an ATO under NIST SP 800-53 Rev 5.

The project is greenfield. The workspace layout below is the intended target;
the architect may refine it through the workflow.

## Clean-Room Rules (non-negotiable)

These rules exist so the code can be shown to be independently created. They
apply to every human and every agent. Full procedure:
[.claude/skills/provision-workflow/references/clean-room-protocol.md](.claude/skills/provision-workflow/references/clean-room-protocol.md).

1. **Two teams, one wall.** Only the `spec-researcher` agent may read
   Tanium-authored material, and only *public* material (published product
   documentation, public release notes, public marketing/datasheets). Its only
   output crossing the wall is functional specs in `specs/`.
2. **Never use**: Tanium source code, binaries, installers, decompiled or
   disassembled output, packet captures of Tanium traffic, license-gated or
   customer-portal content, leaked/NDA material, or anything from a Tanium
   employee or customer under confidentiality. No reverse engineering.
3. **Specs describe behaviour, not implementation.** What the system must do,
   observable inputs/outputs, and requirements. No copied prose, screenshots,
   UI layouts, proprietary file formats, wire formats, schemas, or identifiers.
   Interoperate only through **open standards** (DHCP, PXE, TFTP, HTTP, UEFI,
   GPT, WIM as publicly documented by Microsoft, etc.).
4. **Clean-side agents** (architect, coder, QA, reviewers, scribe, release) read
   only `specs/`, open standards, and this repo. They have no web tools and must
   never search for or open Tanium material. The orchestrator is clean-side too.
5. **No Tanium names in code.** No `tanium` (any case) in identifiers, crate
   names, config keys, paths, comments, or log text. The product name may
   appear only in `specs/README.md` (the statement of intent) and in
   `cleanroom/`.
6. **Provenance.** Every spec requirement cites a source ID; the source log
   lives in `cleanroom/provenance/` and is maintained only by the
   `spec-researcher`. The `clean-room-auditor` checks both sides every run.
7. Model pretraining knowledge of the product is a contamination vector: a spec
   statement without a cited public source is rejected, and clean-side agents
   implement only what a spec says.

## Pure-Rust Rule

- No C/C++ toolchain dependencies: no `-sys` crates, `cc`/`bindgen` build
  scripts, or vendored C (this excludes e.g. `ring`, `aws-lc-rs`, `openssl`,
  `libgit2`, `wimlib`, `libarchive`). Exceptions require a written decision in
  `docs/decisions/` and are flagged by the release engineer.
- `unsafe` only with a `// SAFETY:` comment; prefer `#![forbid(unsafe_code)]`
  per crate.
- Check with `cargo tree -e normal,build | grep -E -- '-sys|cc v|bindgen'`.

**FIPS exception** ([docs/decisions/0001](docs/decisions/0001-fips-validated-crypto.md)):
cryptography uses the FIPS 140-3 validated `aws-lc-rs` (`fips` feature) and
`rustls` on its FIPS provider. This is the only C dependency allowed, and only
inside `usgp-crypto`; every other crate uses the `CryptoProvider` trait and TLS
config exported there. The pure-Rust gate allows `aws-lc-fips-sys` and its
build deps under `usgp-crypto` only.

**Initial OS scope:** Windows client (Windows 10/11 Enterprise) via WIM images
and unattend. Windows Server and Linux come later.

## Target Workspace Layout

```text
specs/                  clean-room functional specs (the only product-derived material)
cleanroom/              provenance log + audit records (spec-researcher / auditor only)
crates/
  usgp-common/          config, errors, ids, time, tracing setup
  usgp-crypto/          CryptoProvider trait, hashing, signing, TLS config
  usgp-audit/           tamper-evident audit log (AU-2/3/9/12)
  usgp-db/              persistence + migrations
  usgp-dhcp/            ProxyDHCP / DHCP option handling for PXE (RFC 2131/2132/4578)
  usgp-tftp/            TFTP server (RFC 1350/2347/2348/2349/7440)
  usgp-httpboot/        UEFI HTTP boot + iPXE script/artifact serving
  usgp-image/           image formats (WIM, raw/sparse), hashing, verification
  usgp-disk/            GPT/MBR partitioning and filesystem layout plans
  usgp-deploy/          task-sequence engine (partition → apply → drivers → config → agent)
  usgp-cache/           subnet cache/relay nodes, content distribution
  usgp-api/             control-plane REST/gRPC API, RBAC
services/
  usgp-server/          control plane
  usgp-relay/           per-subnet boot + content cache service
  usgp-preboot-agent/   agent that runs in the pre-boot environment on the target
tools/usgp-cli/         operator CLI (deployment packages, boot media, jobs)
docs/                   architecture, decisions, compliance (ATO evidence)
```

## Multi-Agent Workflow

Use the `/provision-workflow` skill
(`.claude/skills/provision-workflow/SKILL.md`). The main conversation is the
orchestrator and delegates to the agents in `.claude/agents/`:

- Dirty side: `spec-researcher`
- Wall: `clean-room-auditor`
- Clean side: `provision-architect`, `rust-coder`, `qa-engineer`,
  `security-reviewer`, `nist-800-53-reviewer`, `boot-protocol-reviewer`,
  `compliance-scribe`, `release-engineer`

Modes:

- `/provision-workflow bootstrap` — scaffold the workspace, spec index, roadmap
- `/provision-workflow spec <capability>` — research public docs → `specs/` → audit
- `/provision-workflow <task>` — spec check → plan → build → test →
  parallel review → fix loop → docs → release gate
- `/provision-workflow plan <task>` — plan only
- `/provision-workflow review [base-ref]` — review the current diff only
- `/provision-workflow audit` — clean-room audit of the whole repo

## Development Commands

- `cargo fmt --all` / `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo deny check` and `cargo audit` (supply chain)
- `cargo tree -e normal,build` (pure-Rust check)

## Engineering Rules

- Rust 2024 edition, async on `tokio`, errors via `thiserror` in libraries.
- Every network-facing parser (DHCP, TFTP, HTTP, image headers, partition
  tables) validates lengths and bounds, never panics on input, and gets a fuzz
  target under `fuzz/`.
- Boot and image content is integrity-verified (hash/signature) before it is
  served or written to disk (SI-7). Secure Boot chains are never weakened.
- Secrets (domain-join credentials, local admin passwords, enrollment tokens)
  use `zeroize`, are never logged, and are delivered to targets only over an
  authenticated, encrypted channel, never in cleartext TFTP or unattend files
  at rest without protection.
- Every operator action and every state change of a provisioning job emits an
  audit event (who, what, when, where, outcome).
- Annotate control implementations:

  ```rust
  // COMPLIANCE MAPPING:
  // - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity)
  // - SPEC: specs/image-deployment.md#REQ-IMG-012
  // - RFC 2348 - TFTP blocksize option
  ```

- Known gaps get `// POAM: <description>`.

## Compliance Documentation

Every code change updates `docs/compliance/` (NIST 800-53 mapping, test
evidence, ATO evidence) through the `compliance-scribe`. Claims must be backed
by code and passing tests; never overstate status.
