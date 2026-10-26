# Clean-room audit — bootstrap survey

- Date (UTC): 2026-10-25
- Run: `target/agent-workflow/20261025-223537-bootstrap`
- Auditor: clean-room-auditor (spec pass, initial + re-verify round 1)
- Result: **AUDITED**. `specs/README.md`, `specs/INDEX.md`, and `cleanroom/provenance/SOURCES.md` are cleared as the survey baseline. Open: 1 MINOR (CR-009, advisory).

## Scope

Three new files from the bootstrap survey: `specs/README.md`, `specs/INDEX.md` (61 capabilities in 18 areas, no REQ IDs yet), and `cleanroom/provenance/SOURCES.md` (SRC-001 to SRC-010, plus consulted-not-used rows). No code is in scope.

## Method

1. Read the clean-room protocol and all three files in full, in the initial pass and again after fix round 1.
2. Searched the vendor name repo-wide, excluding the allowed paths. In `specs/` it appears only in `specs/README.md`, as intended.
3. Checked each capability row for vendor internal names, terms of art, prose, schemas, UI detail, and implementation guidance, and checked that every cited SRC ID exists in the provenance log.
4. Reviewed each source row for public, login-free access and for any confidentiality concern.
5. For flagged passages only, compared the spec text with the cited public page: SRC-003 (relay section) and SRC-010 (session abstract). Nothing beyond the cited pages was browsed. No vendor text was copied into project files.

## Results

- Initial pass: CHANGES REQUESTED. 0 BLOCKER, 1 MAJOR (CR-001), 4 MINOR, 3 NIT.
- Re-verify round 1: CR-001 to CR-008 resolved. One new MINOR (CR-009: a source citation is missing for the operator-assignment clause in RELAY-1).
- Details: `target/agent-workflow/20261025-223537-bootstrap/findings-cleanroom.md`.

## SRC-009 acceptance decision

SRC-009 is a public personal blog post (dated 2022-03-05). Its author appears to be associated with the vendor: the post gives a first-person-plural account of building the product, is filed under the vendor's category, and refers readers to their vendor representative. **Accepted** as a permitted source, for these reasons:

- It is openly published and readable without login or form.
- It has no confidentiality or NDA marking.
- It was not obtained through private contact with the author or vendor staff.
- It contains no code, binaries, or downloads.

The protocol forbids information from staff given *under confidentiality*. A public, promotional blog post is not that. Conditions:

- BOOT-4 (UEFI HTTP boot) rests on this source alone. The release notes (SRC-004 to SRC-008) were checked and do not mention it. Any requirement derived from BOOT-4 is capped at SHOULD, or marked OPEN, until a second public source confirms it.
- Because the post is dated, it may describe behaviour that has since changed.

## Incident: snippet exposure during fix round 1 (CR-001)

- **What happened**: during fix round 1 the spec-researcher ran a public web search to record how SRC-003 can be reached (CR-007). The search tool's result summary showed snippet text from SRC-003's relay section. This was before RELAY-1 and RELAY-2 were rewritten for CR-001, which was raised because those rows closely paraphrased that same section. The researcher disclosed this in the spec report and logged the search under "Consulted, not used". The researcher states that the snippet was not copied and SRC-003 was not reopened.
- **Assessment**: the material is public, and the researcher is on the dirty side and allowed to read it, so the exposure did not breach the protocol. The risk was that the rewrite would echo the source again. I compared the rewritten RELAY-1 and RELAY-2 with the SRC-003 relay passage. They take a different viewpoint (the booting device), use a different structure (assigned role, then a qualified hardware statement; a conditional local-or-central fallback), and share no distinctive phrasing or clause order. The fallback idea comes from the brief's diagram and from SRC-004.
- **Conclusion**: no contamination. The rows are independent wording. No removal or further rewrite is required, and nothing on the clean side was affected (no clean-side work exists yet).
- **Follow-up**: when the researcher has to rewrite a row flagged for close paraphrase, they should avoid search tools whose summaries may quote the source until the rewrite is done.
