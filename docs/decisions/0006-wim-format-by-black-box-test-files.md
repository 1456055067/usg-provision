# 0006: WIM Format Details from Our Own Test Files

- Status: Accepted (owner, 2026-10-26)
- Date: 2026-10-26
- Decider: project owner
- Drafted by: orchestrator (clean side), from the M2 spec report

## Context

Microsoft's public WIM documentation (`specs/standards/wim.md`) does not
give byte offsets and order for every structure, the layout of the metadata
that carries edition, architecture and version, or how WIM applies XPRESS
and LZX; no public LZMS format exists. M2 must list editions in an uploaded
image and verify its structure.

## Decision

1. Gaps in the public WIM documentation may be filled **only** by black-box
   observation of WIM files that the project itself creates with
   Microsoft's own tools (DISM / the Windows ADK) from content the project
   is licensed to use, plus Microsoft's public documentation.
2. **Never** read, run under a debugger, or derive from third-party WIM,
   XPRESS, LZX or LZMS implementations (for example wimlib or any other
   open-source or proprietary decoder), their source, tests or docs. This
   is in addition to the vendor clean-room rules.
3. Observations are recorded by the clean side in
   `docs/formats/wim-observed.md`: for each claim, the sample file, the
   exact tool and command that produced it, the host and tool versions, and
   the observed bytes. Sample-generation scripts live in the repo; samples
   are regenerated in CI on a Windows runner, never downloaded.
4. Solid (LZMS) WIMs are **unsupported** in M2 and are refused with a clear
   error.

## Consequences

- WIM parsing in M2 depends on a Windows CI job that generates samples.
- Format claims without an observation record or a Microsoft citation are
  rejected in review.
