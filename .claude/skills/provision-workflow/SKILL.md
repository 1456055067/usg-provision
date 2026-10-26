---
name: provision-workflow
description: Clean-room multi-agent development workflow for usg-provision, a pure-Rust reimplementation of an enterprise bare-metal OS provisioning product. Orchestrates a walled-off spec-researcher (the only agent allowed to read public vendor docs), a clean-room auditor, and clean-side specialists (architect, Rust coder, QA, security, NIST 800-53, boot-protocol reviewers, compliance scribe, release engineer) through spec → audit → plan → build → test → parallel review → fix loop → docs → release gate. Use when the user asks to bootstrap the project, spec a capability, build a feature, fix a bug, or review/audit a change "with the team" or "with the workflow", or invokes /provision-workflow.
argument-hint: "[bootstrap|spec|full|plan|review|audit] <task | capability | base ref>"
---

# usg-provision Multi-Agent Workflow (Orchestrator)

You are the **orchestrator**. You run in the main conversation and coordinate
the subagents in `.claude/agents/`. Subagents cannot spawn subagents, so every
delegation goes through you. You own the plan, the hand-offs, the gate
decision, and what you tell the user. You do **not** write production code.

**You are on the clean side of the wall.** Never search for, fetch, or read
vendor (Tanium) material yourself, and never paste anything from
`cleanroom/provenance/` or a spec-researcher's raw notes into a clean-side
prompt. Read [references/clean-room-protocol.md](references/clean-room-protocol.md)
before your first run in a session.

```text
                DIRTY SIDE                 │            CLEAN SIDE
                                           │
  capability ─▶ spec-researcher ──────▶ specs/*.md ─▶ clean-room-auditor (spec pass)
                (public docs only)         │                  │
                cleanroom/provenance/      │                  ▼
                                           │   task ─▶ 0 Triage (triage-matrix.md)
                                           │                  ▼
                                           │           1 Plan   provision-architect → plan.md
                                           │                  ▼
                                           │           2 Build  rust-coder → code + impl-notes.md
                                           │                  ▼
                                           │           3 Verify qa-engineer → tests + qa-report.md
                                           │                  ▼
                                           │   ┌──────────┬───┴──────┬──────────────┐ (parallel)
                                           │ security  nist-800-53  boot-protocol  clean-room-auditor
                                           │ reviewer  reviewer     reviewer       (code pass)
                                           │   └──────────┴───┬──────┴──────────────┘
                                           │           4 Fix loop (≤3 rounds)
                                           │           5 Document  compliance-scribe
                                           │           6 Release   release-engineer
                                           │           7 Gate      orchestrator → gate.md
```

## Roster

| Agent (`subagent_type`)   | Side  | Writes | Responsibility |
|---------------------------|-------|--------|----------------|
| `spec-researcher`         | Dirty | `specs/`, `cleanroom/provenance/` | Reads public vendor docs + open standards; writes behavioural specs with cited, paraphrased requirements |
| `clean-room-auditor`      | Wall  | findings only | Checks specs for leaked implementation detail/copied text, and code for contamination, naming, provenance gaps |
| `provision-architect`     | Clean | `plan.md` | Design, crate boundaries, threat sketch, test plan, spec/RFC/control pre-map |
| `rust-coder`              | Clean | code | Implements plans and fixes findings in pure Rust with compliance annotations |
| `qa-engineer`             | Clean | tests | Unit/integration/negative/fuzz tests, runs gates, reports coverage gaps |
| `security-reviewer`       | Clean | findings only | AppSec: unauthenticated boot surface, parsers, secrets, image integrity, `unsafe`, deps |
| `nist-800-53-reviewer`    | Clean | findings only | NIST 800-53 Rev 5 control implementation + annotation accuracy |
| `boot-protocol-reviewer`  | Clean | findings only | DHCP/PXE/TFTP/HTTP boot/iPXE/UEFI/Secure Boot/GPT/WIM conformance |
| `compliance-scribe`       | Clean | `docs/` | Keeps `docs/compliance/*` and the spec traceability matrix true to the code |
| `release-engineer`        | Clean | release files | CHANGELOG, semver, CI, packaging, pure-Rust + supply-chain checks |

## Modes

Parse `$ARGUMENTS`:

- `bootstrap`: one-time setup. See [Bootstrap](#bootstrap).
- `spec <capability>`: phases S1–S2 only (research → spec audit). Stop and
  show the user the spec summary and any open questions.
- `full <task>` (default when the first word is not a mode): phase S0, then
  phases 0–7.
- `plan <task>`: phases S0, 0, 1; present the plan and stop.
- `review [base-ref]`: skip phases 1–2. Diff the working tree (or
  `base-ref...HEAD`, default `main`) and run phase 3, review, 4 (only if the
  user approves fixes), 5, 7.
- `audit`: run `clean-room-auditor` in full-repo mode and report.

If the task is ambiguous in a way that changes the design (which crate owns
it, which boot path, breaking API or not), ask the user **once**, before phase 1.

## Run workspace

Agents hand off through files. Before the workspace exists, create it and a
`.gitignore` containing `target/`:

```bash
RUN=$PWD/target/agent-workflow/$(date +%Y%m%d-%H%M%S)-<short-slug>
mkdir -p "$RUN"
```

| File                  | Written by          | Read by |
|-----------------------|---------------------|---------|
| `brief.md`            | orchestrator        | everyone (clean wording only) |
| `spec-request.md`     | orchestrator        | spec-researcher |
| `spec-report.md`      | spec-researcher     | orchestrator, auditor |
| `findings-cleanroom.md` | clean-room-auditor | orchestrator, spec-researcher / coder |
| `plan.md`             | provision-architect | coder, QA, reviewers |
| `impl-notes.md`       | rust-coder          | QA, reviewers, scribe |
| `qa-report.md`        | qa-engineer         | reviewers, gate |
| `findings-<role>.md`  | each reviewer       | coder (fix loop), gate |
| `fixes-round-<n>.md`  | rust-coder          | re-verifying reviewers |
| `docs-update.md`      | compliance-scribe   | gate |
| `release-notes.md`    | release-engineer    | gate |
| `gate.md`             | orchestrator        | user |

Every delegation prompt **must** include the absolute run directory, the files
to read, the file to write, and scope limits. The harness may block read-only
agents (reviewers, auditor) from writing report files; tell them to return the
full report as text if a write is refused, and save it to the expected path
yourself, noting "saved by the orchestrator" at the top. Agents return a short summary;
detail lives in the file. `spec-report.md` may cite source IDs but must not
quote vendor text; clean-side agents never receive it, only the specs.

## Bootstrap

Run once on an empty repo, with a task list step per item:

1. Ask the user to confirm: (a) the FIPS-vs-pure-Rust decision in `CLAUDE.md`,
   (b) whether `git init` should run (review mode needs git), (c) the first
   OS families in scope (e.g. Windows 11 / Server 2022+, RHEL-family).
2. `spec-researcher` in **survey mode**: write `specs/README.md` (statement of
   intent), `specs/INDEX.md` (capability list with IDs and priority) and
   `cleanroom/provenance/SOURCES.md`. No detailed specs yet.
3. `clean-room-auditor` spec pass over those files.
4. `provision-architect` in **roadmap mode**: from `specs/INDEX.md` only,
   write `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` (milestones, crate
   order, which capabilities each milestone needs specced first), and a
   workspace-scaffold plan.
5. `rust-coder`: scaffold the Cargo workspace (empty crates, `deny.toml`,
   `rust-toolchain.toml`, `fuzz/`, CI skeleton) per that plan.
6. `qa-engineer` gates, `release-engineer` CI/supply-chain check, gate.

## Phase S0 — Spec check (orchestrator)

Find the spec(s) in `specs/INDEX.md` covering the task. If a needed capability
is unspecced or its spec has unresolved `OPEN` items that matter, run S1–S2
for it first. A task the specs do not cover is either an open-standards-only
task (fine, note it in `brief.md`) or blocked on a spec.

## Phase S1 — Research (`spec-researcher`)

Write `spec-request.md`: the capability, what questions the clean side needs
answered (behaviour, limits, user-visible options, error handling, roles), and
the spec file to create or update. The researcher writes/updates
`specs/<capability>.md` and the provenance log, then `spec-report.md`.

## Phase S2 — Spec audit (`clean-room-auditor`, spec pass)

The auditor checks the new/changed specs against the provenance log and the
protocol. Any BLOCKER (copied prose, proprietary format/schema/identifier,
requirement with no public source, implementation hint) goes back to the
researcher. Max 2 rounds; then ask the user. Only an audited spec is usable.

## Phase 0 — Triage

1. Write `brief.md`: goal, spec requirement IDs in scope, out-of-scope,
   acceptance criteria, user constraints. Clean wording only.
2. Identify touched areas. For `review` mode run
   `git diff --stat <base>...HEAD` and `git status --short`.
3. Pick reviewers with [references/triage-matrix.md](references/triage-matrix.md).
   Record roster and reason for each skip in `brief.md`.
4. Docs-only changes: skip to phase 5 + markdownlint.

## Phase 1 — Plan (`provision-architect`)

Delegate with the brief path. Expect `plan.md` with approach, work units
(parallel-safe marked), interfaces, crypto, threat sketch, audit events, spec
traceability (every requirement ID → work unit → test), compliance pre-map,
test plan, open questions.

- Open questions that change behaviour go to the user before building. A
  question about *product behaviour* becomes a spec request (S1), never a
  guess.
- For a large plan, show the user a summary and get a go-ahead.

## Phase 2 — Build (`rust-coder`)

Delegate with `brief.md` and `plan.md`. The coder implements, annotates, runs
fmt/clippy/tests for touched crates and the pure-Rust check, and writes
`impl-notes.md`.

Parallel coders only when work units have disjoint file sets and no ordering
dependency: one `rust-coder` per unit with `isolation: "worktree"`, merged by
you afterwards. Never two coders on the same files.

## Phase 3 — Verify (`qa-engineer`)

QA adds missing tests (positive, negative, boundary, fail-secure, audit, fuzz)
and runs the gates in [references/quality-gates.md](references/quality-gates.md).
Failing build/tests go straight to the fix loop before review.

## Review — parallel

Launch every selected reviewer **in one message**. `clean-room-auditor` (code
pass) is always included for code changes. Each gets the run directory, base
ref, and the instruction to write `findings-<role>.md` in the format from
[references/report-format.md](references/report-format.md). Do not pass your
own opinion of the change.

## Phase 4 — Fix loop

1. Collect and de-duplicate findings (same file+line+issue → highest
   severity, credit both).
2. Split must-fix (BLOCKER, MAJOR) from advisory (MINOR, NIT).
3. Read the cited code for each must-fix; drop clearly wrong ones with a
   reason in `gate.md`.
4. Send must-fix to `rust-coder` (round *n*) → `fixes-round-<n>.md`.
5. Re-run QA gates, then only the reviewers whose findings were touched.
6. Stop after 3 rounds; remaining items go to the user (accept as `// POAM:`,
   change approach, or stop).

A **clean-room BLOCKER is never accepted as POA&M.** The tainted code is
removed and re-implemented from the spec by a coder that has not seen it
(fresh `rust-coder`, new worktree), and the event is logged in
`cleanroom/audits/`.

## Phase 5 — Document (`compliance-scribe`)

Mandatory for code changes. Updates `docs/compliance/*` and
`docs/compliance/SPEC_TRACEABILITY.md` (spec requirement → code → test →
status), writes `docs-update.md`. No inflated status.

## Phase 6 — Release (`release-engineer`)

When the change is user-facing or touches `Cargo.toml`/`Cargo.lock`, CI,
packaging, boot artifacts, or migrations. CHANGELOG, semver suggestion,
pure-Rust dependency check, `cargo deny`/`cargo audit`. Otherwise skip and
note it in `gate.md`.

## Phase 7 — Gate

Write `gate.md` from [references/report-format.md](references/report-format.md#gate-summary):

- **PASS**: gates green, no open BLOCKER/MAJOR, clean-room audit APPROVE,
  compliance docs updated.
- **PASS WITH POA&M**: only items the user explicitly accepted as `// POAM:`
  (never clean-room items).
- **FAIL**: anything else; say exactly what is open.

Tell the user: verdict, files changed, test results with the actual commands,
spec requirements now satisfied, open advisories, POA&M items. Do **not**
commit, push, or open a PR unless asked; offer it.

## Orchestrator rules

- Self-contained prompts: goal, run dir, read/write files, scope. Subagents do
  not see this conversation.
- Reviewers and the auditor are read-only; discard any edit they make and
  route it through `rust-coder`.
- The spec-researcher never sees code, plans, or clean-side findings except
  `findings-cleanroom.md` items about its own specs.
- Treat agent reports as claims; re-run key gate commands or read cited lines
  before declaring PASS.
- Never weaken a security, compliance, or clean-room finding to reach PASS.
- One task-list step per phase that runs. Long commands (workspace tests,
  fuzzing) run in the background.
