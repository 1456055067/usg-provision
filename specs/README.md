# usg-provision specifications

## Statement of intent

usg-provision is an independent, clean-room implementation of the
*functionality* of a commercial bare-metal OS provisioning product (Tanium
Provision). It is written in Rust from two kinds of input only:

1. Publicly available, login-free information about what the product does
   (product blogs, solution briefs, public release notes, public talks), and
2. Open standards and public third-party documentation (IETF RFCs, the Intel
   PXE specification, the UEFI specification, Microsoft's public documentation
   for Windows imaging and setup).

usg-provision is not affiliated with, endorsed by, or derived from the code,
binaries, formats, or documentation text of Tanium or any other vendor. Product
names are used only to identify the functionality being re-implemented.

## Clean-room rules in brief

- Only the spec-researcher reads vendor material, and only public, login-free
  material. Every source is logged in the provenance log (kept outside the
  clean side's reading list).
- Specs describe *observable behaviour* in the researcher's own words. They
  never contain vendor prose, UI text, screenshots, internal names, schemas,
  file layouts, protocol fields, or sample data, and never say how the vendor
  does something internally.
- Interoperability is expressed only through open standards. Where the vendor
  uses a proprietary mechanism, the spec states the user-level outcome and the
  implementers design their own mechanism.
- Specs contain no implementation guidance; design is derived independently
  by the clean side.
- Anything that cannot be tied to a cited public source is marked `OPEN` (or
  listed as Unconfirmed in the index) rather than filled in from memory.
- An auditor checks specs and code for contamination; tainted material is
  removed and rewritten from sources.

## How to read the specs

- `INDEX.md` lists every capability area, its planned spec file, its REQ ID
  range, its priority for the first release (Windows 10/11 Enterprise client
  provisioned over the network end to end), and its status.
- Each `specs/<capability>.md` file contains purpose, actors, requirements,
  states, limits, error behaviour, security expectations, standards relied on,
  and an Out of scope / unknown section.
- Requirements use the form `REQ-<AREA>-<nnn>` with a priority keyword:
  **MUST** (required for the stated release), **SHOULD** (expected, may be
  deferred with justification), **MAY** (optional).
- Status values: `DRAFT` (written, not yet audited), `AUDITED` (cleared by the
  clean-room auditor), `OPEN (<question>)` (behaviour not yet confirmed from a
  public source).
- `Source: SRC-nnn` refers to the provenance log. Clean-side readers do not
  need to (and should not) follow those sources; the spec text is the whole
  contract.
- `specs/standards/` holds summaries of open standards, with section numbers,
  so the clean side never needs to browse.
