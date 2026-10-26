# Clean-Room Protocol

The goal is a record showing that usg-provision was written from functional
specifications and open standards, by people/agents who never saw the
vendor's protected expression (code, binaries, proprietary formats, prose).

## Sides

| Side  | Who | May read | May write |
|-------|-----|----------|-----------|
| Dirty | `spec-researcher` | Public vendor docs, release notes, datasheets; open standards; `specs/`; `cleanroom/provenance/` | `specs/`, `cleanroom/provenance/`, `<run>/spec-report.md` |
| Wall  | `clean-room-auditor` | Everything in the repo, `cleanroom/`; public vendor docs **only** to compare a flagged passage | `<run>/findings-cleanroom.md`, `cleanroom/audits/` |
| Clean | orchestrator, architect, coder, QA, reviewers, scribe, release | `specs/`, open standards available offline or in-repo, repo code/docs | Their own files only |

Clean-side agent definitions omit `WebFetch`/`WebSearch`. Standards text the
clean side needs (RFC sections, UEFI/PXE behaviour, Microsoft WIM/unattend
public docs) is summarised by the spec-researcher into `specs/standards/`
with a citation, so the clean side never has to browse.

## Permitted sources (dirty side)

- Public product documentation and help pages reachable without login.
- Public release notes, datasheets, solution briefs, conference talks.
- Open standards and public third-party docs (IETF RFCs, Intel PXE spec,
  UEFI spec, Microsoft Learn docs for WIM/DISM/unattend/WinPE, iPXE docs).

## Forbidden, always

- Vendor source code, binaries, installers, packages, containers, firmware.
- Decompilation, disassembly, debugging, or tracing of vendor software.
- Packet captures, logs, database dumps, or config files from a vendor
  deployment.
- Login-gated, customer-portal, partner, or licensed content; leaked or NDA
  material; information from current/former vendor staff or customers under
  confidentiality.
- Copying screenshots, UI layouts, icons, sample data, API/JSON/schema
  definitions, sensor/package names, or proprietary file formats.

## What a spec may contain

- Capabilities and user-visible behaviour ("an operator can target a bare-metal
  device by MAC address or SMBIOS UUID").
- Inputs, outputs, states, limits, error behaviour, roles/permissions, in the
  researcher's own words.
- References to open standards that the behaviour relies on.

## What a spec must not contain

- Vendor prose (beyond a ≤ 10-word phrase in a provenance note, never in a spec).
- Vendor internal names, identifiers, schemas, file layouts, protocol fields,
  or "how it's done internally".
- Implementation guidance (data structures, algorithms, crate choices); that is
  the architect's job and must be independently derived.

## Requirement format

```markdown
### REQ-<AREA>-<nnn>: <short title>

<one-paragraph behavioural requirement in original wording>

- Priority: MUST | SHOULD | MAY
- Source: SRC-<nnn>[, SRC-<nnn>]   (IDs in cleanroom/provenance/SOURCES.md)
- Standards: RFC 4578 §2.1 (if any)
- Status: DRAFT | AUDITED | OPEN (<question>)
```

## Provenance log

`cleanroom/provenance/SOURCES.md`, one row per source:

| ID | Title | URL | Accessed (UTC date) | Public? (how verified) | Used for REQ IDs |

Clean-side agents never read this file; the auditor does.

## Contamination response

1. Auditor raises a `CR-` BLOCKER naming the files/hunks.
2. Orchestrator removes the tainted spec text or code (no POA&M).
3. Spec: researcher rewrites from sources. Code: a **fresh** `rust-coder` in a
   new worktree re-implements from the corrected spec without access to the
   removed code or its diff.
4. Auditor records the incident in `cleanroom/audits/<date>-<slug>.md`.
