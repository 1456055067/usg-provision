# Report Formats

## Findings file (`findings-<role>.md`)

```markdown
# Findings — <role>

Scope: <base>...<head> (<n> files), plan: <run>/plan.md
Verdict: APPROVE | APPROVE WITH COMMENTS | CHANGES REQUESTED

## <ROLE-PREFIX>-001 [BLOCKER] <one-line title>

- **Location**: `crates/usgp-tftp/src/server.rs:123`
- **Reference**: NIST 800-53 SI-10 | RFC 2348 §2 | REQ-BOOT-004 | CWE-22
- **Problem**: what is wrong, in one or two sentences.
- **Failure scenario**: concrete input/state → concrete bad outcome.
- **Fix**: the smallest change that resolves it.
- **Confidence**: high | medium | low
```

Role prefixes: `SEC` (security), `NIST` (800-53), `BOOT` (boot protocols /
image / disk), `CR` (clean room), `QA` (testing), `REL` (release).

### Severity

| Severity | Meaning | Gate effect |
|----------|---------|-------------|
| BLOCKER | Exploitable vuln, secret exposure, unverified image/boot content served or written, Secure Boot weakened, unintended disk wipe, broken RFC/spec MUST, missing authn/authz, audit bypass, **any clean-room contamination** | Must fix |
| MAJOR | Missing required control/test, spec MUST not met, RFC SHOULD violated without reason, fail-open path, unvalidated input not yet at a sink, `-sys`/C dependency | Must fix |
| MINOR | Hardening, missing annotation, weak test, unclear error | Advisory |
| NIT | Style, naming, comments | Advisory |

A finding without a location and a failure scenario is MINOR at most (except
`CR-` findings, which need a location and the reason it is contamination).

## Fix response (`fixes-round-<n>.md`)

```markdown
| Finding | Action | Change |
|---------|--------|--------|
| SEC-001 | Fixed | `server.rs:120-131` reject `..` and absolute paths before open |
| BOOT-002 | Rebutted | blksize 1468 is the RFC 2348 recommended max for Ethernet MTU |
```

## Gate summary

`gate.md`, written by the orchestrator:

```markdown
# Gate — <task>

Verdict: PASS | PASS WITH POA&M | FAIL

| Gate | Result | Evidence |
|------|--------|----------|
| fmt | PASS | `cargo fmt --all --check` |
| clippy | PASS | `cargo clippy --workspace --all-targets -- -D warnings` |
| unit tests | PASS (128) | `cargo test --workspace` |
| pure Rust | PASS | `cargo tree ... \| grep` empty |
| fuzz smoke | PASS | `tftp_request` 60 s, 0 crashes |
| boot smoke | NOT RUN | OVMF not installed |
| clean-room audit | APPROVE | findings-cleanroom.md (0 open) |
| security review | APPROVE | findings-security.md |
| NIST 800-53 review | APPROVE WITH COMMENTS | findings-nist.md (1 MINOR) |
| boot-protocol review | APPROVE | findings-boot.md |
| spec traceability | REQ-BOOT-001..006 covered | SPEC_TRACEABILITY.md |
| compliance docs | UPDATED | docs-update.md |
| release | CHANGELOG + minor bump suggested | release-notes.md |

## Open items
- NIST-003 [MINOR] ...

## POA&M
- (none) | `// POAM:` at file:line, accepted by user on <date>

## Dropped findings
- SEC-004: not reachable; path already normalised at `server.rs:88`.
```
