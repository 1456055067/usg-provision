# Triage Matrix: which roles run

The orchestrator picks the roster from the paths and topics a change touches.
When in doubt, include the reviewer: a skipped reviewer is a silent gap in
evidence, an extra one costs only tokens.

## Always-on for any code change

- `qa-engineer`
- `security-reviewer`
- `nist-800-53-reviewer`
- `clean-room-auditor` (code pass)
- `compliance-scribe`

## Always-on for any spec change

- `clean-room-auditor` (spec pass)

## Path-triggered roles

| Touched path / topic | Add | Focus to flag in the prompt |
|----------------------|-----|-----------------------------|
| `crates/usgp-dhcp/**` | `boot-protocol-reviewer` | ProxyDHCP behaviour, option 43/60/93/94/97 handling, rogue-DHCP risk |
| `crates/usgp-tftp/**` | `boot-protocol-reviewer` | RFC 1350/2347–2349/7440, path traversal, amplification |
| `crates/usgp-httpboot/**`, iPXE script generation | `boot-protocol-reviewer` | UEFI HTTP boot, TLS for boot, script injection |
| Secure Boot, signed boot chain, shim/bootloader handling | `boot-protocol-reviewer` | Chain never weakened, signature checks before serve |
| `crates/usgp-image/**` (WIM, raw/sparse, hashing) | `boot-protocol-reviewer` | Format conformance, decompression bombs, integrity before write |
| `crates/usgp-disk/**` (GPT/MBR) | `boot-protocol-reviewer` | GPT header/CRC, ESP/MSR layout, destructive-op confirmation |
| `crates/usgp-deploy/**` (task sequences) | `boot-protocol-reviewer` | Step ordering, idempotency/resume, secret delivery to target |
| `services/usgp-preboot-agent/**` | `boot-protocol-reviewer` | Target-side trust of server, wipe safety |
| `crates/usgp-cache/**`, `services/usgp-relay/**` | `boot-protocol-reviewer` | Content integrity, relay authn to server |
| `crates/usgp-crypto/**`, TLS setup | (always-on set) | SC-8/SC-12/SC-13, FIPS decision, provider abstraction |
| `crates/usgp-api/**`, RBAC, sessions | (always-on set) | AC-2/AC-3/AC-6/IA-2 |
| `crates/usgp-audit/**` | (always-on set) | AU-9/AU-10 |
| `crates/usgp-db/**`, `migrations/**` | `release-engineer` | Ordered, reversible migrations |
| `Cargo.toml`, `Cargo.lock`, `deny.toml` | `release-engineer` | Pure-Rust rule, licenses, advisories |
| CI files, `Makefile`, packaging, boot-media build | `release-engineer` | Pinned tools, reproducibility, SI-7 |
| `specs/**`, `cleanroom/**` | `clean-room-auditor` (spec pass) only | Provenance, copied text, implementation leakage |
| `fuzz/**`, `tests/**`, `benches/**` only | `qa-engineer` (+ auditor) | |

## Phase skips

| Situation | Skip |
|-----------|------|
| Docs/comments only | Phases 1–4; scribe + markdownlint (+ auditor if `specs/`) |
| Obvious one-file bug fix | Phase 1 may be a short inline `plan.md` by the orchestrator |
| Internal refactor, no behaviour/API change | Phase 6 |
| Open-standards-only task (no product behaviour) | S0–S2 |
| `review` mode | Phases 1–2 |

Record every skipped role or phase, with the reason, in `brief.md`.
