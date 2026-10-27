# 0017: WIM Header Strictness Rules

- Status: Accepted (owner, 2026-10-27)
- Date: 2026-10-27
- Decider: project owner
- Drafted by: orchestrator (clean side), from the M2 format review
  (findings-boot.md, Spec drift items 1–2) and docs/formats/wim-observed.md
- Refines: decisions 0006, 0014
- Basis: project design (fail closed); not Microsoft text and not described
  product behaviour

## Context

Our standards summary first advised readers to use the header's `cbSize`
field (a [reading], not Microsoft text); Microsoft's WIM paper describes
offset 20 as the file size. Our own DISM-made samples (R1)
always have `cbSize` 208, and offset 20 holds 0 for uncompressed files and
32768 for XPRESS and LZX files (OBS-001, OBS-004). No other values were
observed.

## Decision

Until a sample shows otherwise:

1. The product refuses a WIM whose header `cbSize` is not 208.
2. The product refuses an XPRESS-compressed WIM whose offset-20 value is not
   32768.

Both refusals carry a named reason and are audited. They are revisited when
a new observation record shows a legitimate file that breaks them.

## Consequences

- A future Microsoft format revision with a larger header is refused until
  this decision is revised; this fails closed.
- `specs/standards/wim.md` cites this decision for the two project rules.
