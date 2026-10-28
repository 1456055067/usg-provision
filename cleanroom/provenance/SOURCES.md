# Provenance log

Dirty-side record. Clean-side agents do not read this file.

Public-access verification method for every row: the page was retrieved
anonymously over HTTPS by an automated fetcher with no cookies, credentials,
or session, and the returned content showed no login wall, licence
click-through, or customer-portal gate. SRC-001 to SRC-010 were first
accessed on 2026-10-25 (UTC) during the bootstrap survey.

Rules for later runs (fix round 1, CR-008):

- In survey mode the last column lists area codes. When area specs are
  drafted, replace the area codes with the REQ IDs each source supports.
- If the vendor online user guide becomes readable and is used, take only
  user-visible behaviour from it. Its UI layouts, field and setting names,
  internal component names, and sample values must not reach `specs/`.

Spec run M1 network boot (`target/agent-workflow/20261025-234122-spec-m1-boot`):

- For SRC-003 to SRC-007 and SRC-009, the BOOT area code is replaced by
  REQ IDs. Area codes for areas that are not specced yet stay as they are.
  BOOT capabilities that are not specced yet (BOOT-3, BOOT-4, BOOT-6) are
  listed by capability ID.
- SRC-003 to SRC-007 and SRC-009 were fetched again in this run. Each fetch
  asked for a paraphrase of boot-related behaviour only, with no quotations,
  UI labels, setting names, or component names. SRC-003 is a one-page PDF.
  The fetcher could not extract its text, so the researcher read the
  rendered page directly. Only its general claim about a boot service per
  segment was used, for REQ-BOOT-001. Its relay section was not reworded
  again.
- SRC-011 onward are open standards and public third-party references.
  Access dates come from the session clock: 2026-10-25 until the date
  changed during the run, 2026-10-26 after that.
- The search engine was not used on the vendor or the vendor product in
  this run. Three searches were run on open-standard topics (see
  "Consulted, not used").

M1 network boot, fix round 1 (CR-101 to CR-108):

- "Used for" entries were corrected so that vendor sources are listed only
  for what they state. "(outcome only)", "(indirect)" and "(symptom only)"
  mark rows where the vendor source supports the user-level outcome but
  not the mechanism, which comes from the cited standard.
- Project decisions are now logged as `DEC-nnnn` rows (table below) and
  cited by ID, replacing the earlier "Project decision (M1 spec request)"
  wording, which pointed into the gitignored run directory.
- No new research. Only SRC-018 (draft-henry §3) was fetched again, to
  check how it frames ProxyDHCP for CR-106; paraphrase-only prompt.

M1 network boot, standards notes
(`target/agent-workflow/20261026-003451-m1-network-boot`, 2026-10-26):

- Only open standards and public third-party reference pages were used. No
  vendor source was fetched, and no search named the vendor or its product.
- SRC-011, SRC-012, SRC-013, SRC-015, SRC-018 and SRC-020 were fetched again
  with paraphrase-only prompts. Their "Used for" columns now list the new
  standards files.
- The DMTF SMBIOS PDFs (SRC-043) were downloaded anonymously, but the
  fetch tool could not decompress their text, and no local PDF renderer was
  available. The SMBIOS byte-order points rest on the search engine's
  summary of the DMTF text, restricted to dmtf.org, and are marked
  [primary not read] in `uefi-guid-text.md`.

M1 network boot, standards notes, fix round 1 (CR-201 to CR-206, 2026-10-26):

- No vendor source was fetched, and no search was run.
- The DMTF DSP0134 3.7.1 and 2.6.0 PDFs (SRC-043) were fetched again
  anonymously from dmtf.org. The fetch tool still could not extract their
  text, and the local file reader could not render PDF pages (no renderer
  installed). The fetch tool's reply offered unverified remarks from its
  own general knowledge. Those remarks were not used. The [primary not
  read] markers stay in place.
- SRC-013 (RFC 4578) was fetched again, with a paraphrase-only prompt, to
  check the presence rule in §2.1 to §2.3 for `pxe-dhcp.md` §5.5.
- The pre-2.6 SMBIOS statement drawn from unfetched open-source commit
  summaries was removed from `uefi-guid-text.md` (CR-201). That search row
  now says nothing from it is used.

M1 network boot, boot-protocol standards gaps (same run directory,
2026-10-26):

- Standards only. No vendor source was fetched and no search was run.
- Fetched again with paraphrase-only prompts: SRC-018 (§3.2.3.6, §3.3.1,
  §3.3.2, §3.5 for tag 71), SRC-019 (E.4.20.3), SRC-020 (§24.3.9 type and
  layer values), SRC-011 (§4.3.1 Table 3), SRC-016 (§2.1), SRC-030 (§3,
  §4).
- The PXE 2.1 PDF was not retried; its earlier failures are logged under
  "Consulted, not used". Tag 71 rests on SRC-018 (expired draft) and
  SRC-020, as marked in `pxe-dhcp.md` §6.1.

M1 network boot, boot-protocol standards gaps, fix round 1 (CR-401 to
CR-406, 2026-10-26):

- Marker and label edits only. No vendor source was fetched and no search
  was run.
- RFC 951 (SRC-045) was fetched once, with a paraphrase-only prompt, to
  back the 64-octet vendor area in `pxe-dhcp.md` §3.2 (CR-402).
- SRC-012's "Used for" cell now lists `pxe-dhcp.md` §6.1 (CR-405).

Spec run M2, content store, integrity and operator access
(`target/agent-workflow/20261026-215940-spec-m2`, 2026-10-26):

- Vendor sources fetched again with paraphrase-only prompts (no
  quotations, UI labels, setting, field, file, script or component
  names): SRC-001, SRC-002, SRC-004 (twice), SRC-005, SRC-006, SRC-007,
  SRC-008, SRC-009. Still public with no gate. SRC-002 and SRC-009 gave
  nothing for this run's areas. SRC-006 said nothing about WIM uploads or
  editions in this re-read, so it is no longer cited for IMG-2 (it was
  listed for IMG-2 in the survey).
- The vendor online user guide was tried again and is still an empty
  script-rendered shell (see "Consulted, not used").
- Vendor terms seen in the paraphrases (the product's name for a
  package, for a local boot service, for its kit-preparation tool, and
  for processing states) were not carried into `specs/`. The specs use
  their own words: deployment package, boot service, preparation helper,
  being processed / ready / failed.
- Searches: eight public web searches, all on Microsoft or NIST
  documentation (WIM format paper, WIMGAPI XML, MS-XCA, MS-PATCH, the
  Cabinet LZX document, WinPE redistribution, MS-DTYP byte order). None
  named the vendor or its product. Results are logged under "Consulted,
  not used" where nothing from them was used.
- PDFs: the NIST SP 800-53 Rev. 5 PDF and the MS-XCA PDF were downloaded
  anonymously, but their text could not be extracted and no local PDF
  renderer is installed. They were not used. For NIST documents only the
  public CSRC publication or project pages were used, and the standards
  files mark those points [primary not read]. The Microsoft WIM paper is
  an RTF file; its text was read directly from the downloaded file.
- The Microsoft ADK licence terms were not read: they are a click-through
  shown at install. Redistribution points rest on Microsoft Learn's use
  restriction and one public Microsoft Q&A answer (SRC-063, secondary).

Spec run M2, fix round 1 (CR-501 to CR-510, 2026-10-26):

- No vendor source was fetched. REQ-IMG-001 and the os-images.md
  purpose paragraph were rewritten from the behavioural idea in a new
  structure, without re-reading the SRC-001 passage (CR-501).
- One search, limited to learn.microsoft.com, on the [MS-PATCH] pretree
  section, and paraphrase-only fetches of the [MS-PATCH] landing page
  and of its "Encoding the Trees and Pretrees" page (added to SRC-054)
  to cross-check `wim-compression.md` §4.2 (CR-509). The search query
  did not name the vendor or its product. The page states the opposite
  delta direction from the earlier reading of [CAB-LZX]; both are
  recorded as [reading] in the standards file.
- Owner decisions DEC-0006, DEC-0007, DEC-0009, DEC-0010 and DEC-0011
  were added to the decision table and cited (CR-506, CR-507). DEC-0004
  is no longer cited for image or PE content.
- "Used for" cells of SRC-001, 004, 005, 007, 051, 054, 058, 063, 064,
  065, 068 to 072 and 078 were updated with qualifiers (CR-504). The
  public-check cells of SRC-006 and SRC-007 now record the M2 re-check
  (CR-510).

M2 finalisation (same run, 2026-10-26):

- No research and no fetches. The os-support.md States rule on images
  of unknown status became REQ-OS-009, citing DEC-0009 (CR-511). The
  DEC-0009 row now lists REQ-OS-009. One M1 note line was rewrapped
  (CR-512). Non-OPEN M2 REQs moved from DRAFT to AUDITED after the
  approved re-audit.

Owner decisions 0012 to 0015 (2026-10-27):

- No research and no fetches. The researcher read only the four
  decision records and the dirty-side spec and provenance files.
- DEC-0012 to DEC-0015 were added to the decision table. DEC-0013 to
  DEC-0015 settle the M2 parts of REQ-IMG-015, 038, 043, REQ-PE-005,
  REQ-OS-004, 005, OPEN-OS-2, OPEN-IMG-C1, OPEN-AUD-1 and OPEN-ACC-2,
  and add REQ-AUD-006 and 007. Each is marked "project design, not
  described product behaviour" and is DRAFT pending audit. Post-M2
  questions are kept open as OPEN-IMG-C1 (rest), OPEN-IMG-D1,
  OPEN-IMG-F1, OPEN-OS-2 (rest) and OPEN-ACC-2 (rest).
- Finalisation 2 (2026-10-27, no fetches): after the decisions
  0012-0015 check, the M2 parts above and REQ-AUD-006, 007 moved to
  AUDITED. CR-517: the DEC-0010 row now lists REQ-IMG-015, 043 and
  INDEX IMG-1. CR-516: new REQ-OS-011 (DRAFT) cites DEC-0013.

M2 fix round 1, drift (content-store run
`target/agent-workflow/20261026-225553-m2-content-store`, report in the
M2 spec run directory, 2026-10-27):

- No research, no fetches and no searches. No vendor source and no
  Microsoft page was opened. The researcher read the clean-room
  protocol, the reviewers' drift and clean-room findings, the project's
  observation record `docs/formats/wim-observed.md`, decisions 0006,
  0013, 0014 and 0016, and the dirty-side spec and provenance files.
- The observation record is logged below as a clean-side observation
  source (OBS-001 to OBS-017, run R1). `wim.md` and
  `wim-compression.md` cite it under a new **[observed]** label, kept
  apart from Microsoft text, and mark each point confirmed, contradicted
  or still open. Two header rules (`cbSize` must be 208; offset 20 must
  be 32768 for XPRESS) are recorded as **[project rule, decision
  pending]**, not as Microsoft text.
- REQ-IMG-038 Status notes that OPEN-WIMC-1 is confirmed for R1.
- REQ-OS-011 moved from DRAFT to AUDITED, text unchanged, after the
  auditor's diff check.
- CR-604: INDEX IMG-2 now lists DEC-0010, and the DEC-0010 row lists
  INDEX IMG-2.
- DEC-0016 (separate administrative database role) is not added to the
  decision table: no spec text cites it. It concerns database roles and
  host privileges, which are clean-side design; `operator-access.md`
  already states the M2 outcome (audit records read only with a local
  administrative command on the server host, DEC-0015) and was not
  changed.

M2 fix round 2, part D (content-store run re-verify round 1,
2026-10-27):

- One fetch only: the [MS-XCA] Processing page (SRC-053, §2.2.4),
  public and anonymous, for CR-608. No vendor source, no search.
- The researcher read the clean-room protocol, the "Re-verify round 1"
  section of the content-store run's clean-room findings, and the
  dirty-side spec and provenance files. Decision records, the
  observation record and the boot-protocol findings were not opened
  (outside the researcher's read scope); BOOT-011 to BOOT-014 were
  handled from the orchestrator's task text.
- CR-605: DEC-0017 (Proposed) added to the decision table and cited in
  both wim.md header rules; INDEX topic 9 updated.
- CR-607: wim.md §4 impact note made conditional.
- CR-608: wim-compression.md §3.3 refill rule, own words.
- BOOT-014: wim.md §10 split-part refusal labelled [project rule,
  decision 0014]; one pointer line on further fail-closed rules.
- BOOT-011 to BOOT-013: samples S11, S12 and the bootable PE note
  added to wim.md §13.
- INDEX preamble, topics 9 and 20: "await audit" changed to audited.

DEC-0017 status update (2026-10-27):

- Status-only edit, no research. The owner accepted decision 0017 on
  2026-10-27. The DEC-0017 row, both wim.md §2 header rules and the
  INDEX preamble and topic 9 now say accepted. The CR-605 line above is
  kept as the historical record.

DISM sample run R2 folded into wim.md (2026-10-27):

- No research, no fetches and no searches. No vendor source and no
  Microsoft page was opened. The researcher read the clean-room
  protocol, the dirty-side spec and provenance files, and, at the
  orchestrator's direction (as in the drift round), only the "Runs
  examined" and "Open items" sections and records OBS-018 to OBS-023
  of the observation record `docs/formats/wim-observed.md`. No code,
  decision record or other docs file was opened. The code paths the
  records list as citing them were not followed.
- The observation-record table below now has an R2 row (OBS-018 to
  OBS-023, workflow run 40599556702, commit 5d3c8c7). `wim.md` cites
  the records under the [observed] label, in its own words: Sources and
  label text, §3 (unused space), §5 (R2 lookup-table notes; the R1
  "no gap" note marked contradicted for changed files and the
  reference-count note qualified), §13 (OPEN-WIM-6 settled and open
  parts, status table, never-observed list; S11, S12A and S12B marked
  recorded; S12C, S12D, S11C and S11D still needed) and §14 (stale
  data after delete or commit).
- INDEX preamble and topic 9 updated. The R2 notes were audited on
  2026-10-27 (approve with comments): CR-001 removed the paper's free
  flag from the §3 [observed] note; CR-006 split the §14 inference into
  a separate [derived] note.

Spec run M3, pre-boot agent, disk layout, image apply
(`target/agent-workflow/20261027-234124-spec-m3`, 2026-10-27):

- The researcher read the clean-room protocol, the spec request, INDEX,
  this log, and the spec and standards files being changed. No code,
  decision record, docs file or other run file was opened.
- Vendor sources fetched again with paraphrase-only prompts (no
  quotations, UI labels, setting, field, file or component names):
  SRC-001, SRC-002, SRC-004 (three times, the last two with narrow
  questions on progress display, boot order, device-session
  authentication, cancelling and disk cases), SRC-005, SRC-006, SRC-007,
  SRC-008, SRC-009. All still public with no gate. SRC-007 and SRC-008
  gave nothing used in M3. The vendor user guide was tried again and is
  still an empty script-rendered shell.
- The fetch tool's paraphrases of SRC-004 included vendor terms for
  packages, for the local boot service, for the management agent, for
  log-collection targets, for the content list and for named settings.
  None were carried into `specs/`; the specs use their own words
  (deployment package, boot service, operator-set secret, list of
  content). The 2026 release-note item on device-session authentication
  is used for outcome only (mutual authentication, signed tokens,
  certificate validation, operator-set secrets exist); where those
  secrets are entered is not stated and is left OPEN (D-3).
- Microsoft and UEFI sources added: SRC-080 to SRC-099. SRC-023 (UEFI
  §7.5.7) and SRC-062 were fetched again; §7.5.7 does not name the CRC
  algorithm, so SRC-082 (§4.2.1) is used instead.
- One Microsoft support article about a Microsoft management product
  (SRC-094) was used only for its generic description of Microsoft's
  network boot programs. Its product-specific log extracts, registry
  values and service internals were not used.
- Three public web searches, all limited to learn.microsoft.com, none
  naming the vendor or its product (see "Consulted, not used"). Result
  summaries cited forum threads; none were fetched or used.
- No PDF was needed. All standards pages were HTML.

M3 fix round 1 (CR-001 to CR-007 and DEC-0018, 2026-10-28):

- No fetches and no searches. The orchestrator ruled that the vendor
  pages need not be re-fetched because the rewording makes a comparison
  unnecessary. The researcher read the clean-room findings and the
  dirty-side spec and provenance files only.
- CR-001: the quoted vendor term in REQ-TGT-007 was replaced by a
  generic description.
- CR-002: phrases that might echo vendor setting or UI names were
  replaced with neutral fact statements in targeting.md and progress.md.
- CR-003: Source notes that retold single release-note items were cut
  to "outcome only" notes in targeting.md, progress.md, disk.md and
  preinstall-env.md (PE-014, PE-015, PE-016), and in boot-network.md
  REQ-BOOT-065. The detail stays in the "Used for" cells of SRC-004,
  SRC-006 and SRC-009 above.
- CR-004: unsourced detail was labelled project design (REQ-DISK-009
  read-back; REQ-JOB-007 bound and spacing, values OPEN-JOB-4;
  REQ-JOB-009 linking; REQ-TGT-012 rewritten as "a provisioning
  environment it trusts").
- CR-005: REQ-DISK-013 now cites SRC-004 for download-error behaviour
  only, with the Basis "derived by analogy; project design".
- CR-006: closed by the rewording; no comparison fetch.
- CR-007: the walkthrough's timeout, display order and paths in
  winpe-network-boot.md §5 are labelled as example values.
- DEC-0018 was added to the decision table and cited as a [project
  rule]. After the fix, a grep of `specs/` for the vendor terms noted in
  the M3 run notes found none.

M3 fix round 2 and finalisation (re-audit round 1, approve with
comments, 2026-10-28):

- No fetches and no searches. The researcher read only the "Re-audit
  round 1" section of the clean-room findings and the dirty-side spec
  and provenance files.
- CR-008: REQ-TGT-013 now says the code is short-lived and single-use,
  and that issuing it, using it, approving a device and refusing are
  audit records (DEC-0018 item 1). Wider auditing of device-side choices
  stays OPEN in REQ-TGT-016.
- CR-009: REQ-BOOT-035 has a Basis line citing DEC-0018 item 2 as a
  project rule. It was OPEN, not AUDITED, before M3; only its Status and
  Basis lines changed.
- CR-010: the DEC-0018 row now says accepted in part (items 1 to 4);
  items 5 to 10 are proposed and not citable. The auditor checked items
  1 to 4 against the record.
- CR-011: the leftover "secret or approval" and "device-side secret"
  wording in targeting.md now says "operator-issued code" or "the
  required authorisation". REQ-PE-015's two Basis lines are merged, and
  OPEN-PE-7 now says that no public format exists to parse against.
- CR-012: no change. REQ-PE-017 keeps the owner's implementation choice,
  labelled as such.
- Marked AUDITED (2026-10-28): REQ-TGT-001 to 005, 008, 009, 012 to 015;
  REQ-DISK-001, 003, 004, 007 to 015; REQ-JOB-001 to 009, 011 to 015;
  REQ-PE-011 to 020; REQ-BOOT-035, 063 to 066. Also the standards text
  gpt.md, winpe-network-boot.md, winpe.md §5.1 to §5.3, §8 and §9, and
  uefi-boot-manager.md §9. Still OPEN: REQ-TGT-006, 007, 010, 011, 016;
  REQ-DISK-002, 005, 006, 016; REQ-JOB-010; REQ-BOOT-067.

DEC-0018 items 5 to 10 accepted (2026-10-28):

- No fetches and no searches. The content of items 5 to 10 comes from
  the orchestrator's message; the researcher did not open the decision
  record.
- The DEC-0018 row now says all items 1 to 10 are accepted and citable.
- Settled as [project rule] and set to DRAFT for audit: REQ-TGT-006,
  010, 011, 016; REQ-DISK-002, 005, 006, 016; REQ-BOOT-061 (was OPEN,
  text unchanged), REQ-BOOT-067.
- Changed for consistency and set back from AUDITED to DRAFT:
  REQ-JOB-012 (no *Cancelled* job state; every state change audited;
  item 10) and REQ-BOOT-065 (Basis cites item 9; text unchanged).
- Item 5 is noted against OPEN-BOOT-SB; the choice of signing authority
  stays open. Item 6 has no spec text.
- Still OPEN: REQ-TGT-007, REQ-JOB-010, REQ-BOOT-062. New: OPEN-DISK-4,
  whether a USB-attached disk that reports itself as fixed is eligible.
- The wipe-authorisation record in REQ-DISK-006 is described by its
  behaviour only; the project's internal event name is not used in
  `specs/`.

M3 re-audit round 2 (approve with comments, 2026-10-28):

- No fetches and no searches.
- CR-013: "in release R1" added wherever the wipe confirmation is said
  never to be skipped (REQ-DISK-006, REQ-TGT-006, REQ-TGT-007 status).
- CR-014: REQ-TGT-006 keeps MUST for showing the summary with the
  mandatory wipe confirmation (item 7); the summary's content is
  labelled project design.
- CR-015: showing the refusal reason in REQ-DISK-005 is labelled project
  design.
- CR-016: REQ-TGT-016's Basis also cites item 7. The DEC-0018 row now
  records that the auditor checked items 1 to 10 in rounds 1 and 2.
- Marked AUDITED (2026-10-28): REQ-DISK-002, 005, 006, 016;
  REQ-TGT-006, 010, 011, 016; REQ-JOB-012; REQ-BOOT-061, 065, 067.
  Still OPEN: REQ-TGT-007, REQ-JOB-010, REQ-BOOT-062, and OPEN-DISK-1
  to 4.

M3 build requests
(`target/agent-workflow/20261028-104815-m3-preboot-apply`, 2026-10-28):

- The researcher read the clean-room protocol, the spec request, INDEX,
  this log and the spec and standards files changed. No code, decision
  record, docs file or other run file was opened. DEC-0019 to 0021 are
  recorded from the spec request's text only.
- Vendor sources fetched again with paraphrase-only prompts on Q6 to
  Q8 (disk types refused, device-session expiry, machine identifier):
  SRC-004 (twice) and SRC-006. Still public with no gate. Nothing was
  quoted; no UI label, setting or component name was carried into
  `specs/`. The fetch tool's paraphrase named the vendor's own agent
  identifier; it is not used. The vendor user guide was not retried.
- Open standards and Microsoft pages: SRC-021, SRC-081 (chapter 2)
  re-fetched; SRC-100 to SRC-130 added. All Microsoft pages were HTML
  reference pages; the sample code several of them contain was not
  copied or summarised.
- DMTF DSP0134 3.8.0 (SRC-043) downloaded again; text not extractable.
  One public search limited to dmtf.org, on the System UUID byte order,
  supplied the [primary not read] points in `smbios.md`. The query did
  not name the vendor or its product.
- One guessed Microsoft URL returned 404 (see "Consulted, not used").

M3 build requests, fix round (spec pass, CR-001 to CR-006, 2026-10-28):

- The researcher read only the spec-pass clean-room findings and the
  dirty-side files. Decision content (DEC-0020 items 1 and 5, DEC-0021
  item 4) came from the orchestrator's message and the findings.
- CR-001: REQ-PE-016 note and the DEC-0021 row now state item 4 in full
  (verify all, discard, fetch and verify again, nothing staged).
- CR-002: REQ-PE-010 note and OPEN-PE-6 now say the operator adds the
  program and its public configuration and the product never modifies
  the PE.
- CR-003: SRC-044, SRC-100 and the DEC-0019 to 0021 rows updated.
- CR-005, CR-006: topic 23 §8 reworded; "clean side builds" wording
  removed. One fetch: the DISK_EXTENT page (added to SRC-122), which
  also corrected the topic 23 §7 reading (extents carry no device
  type).
- CR-004 deferred until OPEN-SMB-1 is settled.
- Marked AUDITED 2026-10-28: everything the findings list under Status.
  `smbios.md` §2 and §3 stay [primary not read] and uncited.

M3 follow-up request SR-3b (topic 23 additions, 2026-10-28):

- Microsoft Learn reference pages and UEFI chapter 3 only. No vendor
  source was fetched. SRC-021 re-fetched; SRC-131 to SRC-139 added.
  Sample code on several pages was not copied or summarised.
- Two public searches limited to learn.microsoft.com, neither naming
  the vendor or its product: one on the error the volume-extents
  request returns for volumes not on a disk; one on NT status to
  Win32 error mapping. The result summaries offered inferences and
  links to Microsoft Q&A posts; none was fetched or used. Logged
  under "Consulted, not used". OPEN-WAPI-4 records that no Microsoft
  page states the error.
- New text in topic 23 §13 to §19, OPEN-WAPI-4 to 6, and the Secure
  Boot variables in topic 5 §10.3 were DRAFT pending audit.
- SR-3b audit (pass with conditions, 2026-10-28), fixes CR-001 to
  CR-006: ERROR_MORE_DATA credited to the structure page (SRC-122) and
  the SMB 3.0 remark added as background; SRC-122 and SRC-123 "Used
  for" cells extended; the retry reading trimmed; the no-echo recipe
  trimmed to documented facts; the fail-closed sentence labelled
  [project rule] (REQ-DISK-005, 015; DEC-0018 item 8); SRC-067 and
  SRC-135 cross-referenced. No fetches. All the SR-3b text above, and
  these rows and notes, are AUDITED 2026-10-28; OPEN-WAPI-4 to 6 stay
  open.

DISM sample run R3 folded into wim.md (spec request SR-5, 2026-10-28):

- No research, no fetches and no searches. No vendor source and no
  Microsoft page was opened. The researcher read the clean-room
  protocol, the run's spec request, earlier spec report and spec-pass
  findings, the dirty-side spec and provenance files, and, at the
  orchestrator's direction (as for R2), only the "Runs examined" rows,
  the M-01 to M-23 section and records OBS-024 to OBS-048 of the
  observation record `docs/formats/wim-observed.md`. No code, script,
  decision record or other docs file was opened, and the scripts the
  records name were not followed.
- The observation-record table has a new R3 row (OBS-024 to OBS-048,
  workflow run 40754869824, commit 27f7237). `wim.md` cites the records
  under the [observed] label, in its own words, with no hex dumps,
  sample file names or tree contents copied.
- Main point: OBS-026 contradicts the [derived] 98-byte fixed part of a
  directory entry; the files show 102 bytes. §6 marks the derivation
  contradicted for the R3 files examined (including S01, rebuilt in R3
  with the R1 command), and §6.1 gives the observed positions. Placing
  the four extra bytes before the 8-byte union is labelled [derived]:
  derived from the paper's order and the observed tag position; not
  seen directly.
- EFS refusal is recorded as a [project rule] resting on DEC-0006
  (fail closed); the stored EFS form stays undocumented.
- INDEX topic 9 updated.
- Audit (2026-10-28, approve with comments): CR-R3-001 (EFS rule cites
  DEC-0006), CR-R3-002 ([derived] wording), CR-R3-003 (scope is the R3
  files, S01 rebuilt in R3) and CR-R3-005 (contradiction as its own
  [observed] bullet) applied. The R3 notes in wim.md §3 to §7 and §13,
  and INDEX topic 9, are marked AUDITED 2026-10-28. CR-R3-004, 006
  and 007 concern the observation record and were left to the agent
  fixing it.
- Boot-protocol "Spec drift" (2026-10-28, AUDITED 2026-10-28): the
  researcher read
  only that section of the run's boot-protocol findings. The
  consecutive-raw-chunk point (OBS-046 as corrected, with S14) was
  taken from the coordinator's text; the corrected record was not
  reopened. wim.md §4, §6.1 and §13 gained [observed, DRAFT] notes:
  raw chunks at any position; 8-byte alignment where the paper says 4;
  +92 not always zero; unnamed stream entries; DISM's apply not shown
  to copy or re-base absolute targets (stays open, S13B). New
  OPEN-WIM-12 (product handling of rewritten absolute targets on apply
  to another root or letter; unsourced, so OPEN; refused until
  decided).
- One AUDITED sentence in wim.md §6.1 (that on apply DISM wrote the
  stored reparse bytes back as they were) was withdrawn and replaced
  by a DRAFT note that S16 cannot show copy versus re-base; the
  auditor checked the replacement on 2026-10-28 (NIT-B).
- Re-check (pass with comments): CR-R3-008 applied; the OPEN-WIM-12
  refusal is now a [project rule, pending decision], and the item
  stays OPEN. NIT-C: the R3 row lists OPEN-WIM-12. The new §4, §6.1
  and §13 notes, the M-13 bullet and the OPEN-WIM-12 wording are
  marked AUDITED 2026-10-28.

Reparse data and security descriptors (spec request SR-6, M3,
2026-10-28; AUDITED 2026-10-28):

- Standards summary only; no vendor material was searched for, opened
  or used. The researcher read the clean-room protocol, the run's
  spec report, INDEX, this file, and only `wim.md` §6.1 (reparse and
  descriptor notes) and §13 (OPEN-WIM-7, OPEN-WIM-12), plus the
  sources and labels preamble and §9 to cite the byte order. In the
  first pass no observation record, code or decision record was
  opened.
- Fetched anonymously from learn.microsoft.com: SRC-140 to SRC-153.
  Three searches, limited to learn.microsoft.com, found page URLs; no
  query named the vendor or its product (see "Consulted, not used").
- New file `specs/standards/reparse-and-security-descriptors.md`
  (topic 24) with OPEN-RPSD-1 to 4. Cross-references added to
  `wim.md` §6.1 (reparse points and security descriptors) and §13
  OPEN-WIM-12. OPEN-WIM-7 and OPEN-WIM-12 are not settled. INDEX topic
  24 and header updated.
- Field names, sizes, constants and tag values are Microsoft's, used
  under the Open Specifications notice; wording is the researcher's.
  No sample code (the driver page's structure declaration included)
  was copied. Control-flag masks come from SRC-153 and the reparse-tag
  bit masks are [derived] from the bit diagram and listed values.
- Audit (2026-10-28, pass; 0 BLOCKER, 0 MAJOR, 5 MINOR, 3 NIT).
  For the fixes, at the coordinator's direction, the researcher also
  read records OBS-036, OBS-037 and OBS-038 of
  `docs/formats/wim-observed.md`, and nothing else in that file. No
  bytes or sample names were copied from them.
  - CR-SR6-001: dropped the claim that a rewritten target is no longer
    a full path (OBS-037 shows a full path without the capture root);
    "not shown" became "not recorded in wim.md". OPEN-RPSD-3 stays.
  - CR-SR6-002: topic 24 §2 now quotes `wim.md`'s wording and cites
    OBS-037 for `Reserved` not being stored.
  - CR-SR6-003: the +92 note is its own bullet, about the directory
    entry, and says it is not the symbolic-link `Flags` field.
  - CR-SR6-004: absolute form is the RPC representation and cannot be
    sent as an opaque structure; stored byte order is a [reading].
  - CR-SR6-005: this run note's long line wrapped.
  - CR-SR6-006: SRC-141 paraphrased more closely (symlink exception).
  - CR-SR6-007: the "only the mask matters" note labelled [reading].
  - CR-SR6-008: OBS-038's caveat (descriptors of the 5 reparse points
    not compared) added to topic 24 §9 and to `wim.md` §6.1. The
    `wim.md` addition is a small correction to AUDITED text.
  - Marked AUDITED 2026-10-28: topic 24 (all sections), the `wim.md`
    "See also" notes and correction, INDEX topic 24 and header
    sentence, SRC-140 to SRC-153 and this run note. OPEN-RPSD-1 to 4
    stay open.

## Project decisions cited

These are project design decisions, not product behaviour. They are
recorded in the repository and need no public-access check.

| ID | Title | Repo path | Date | Nature | Used for REQ IDs |
|----|-------|-----------|------|--------|------------------|
| DEC-0003 | Boot service never leases addresses (ProxyDHCP only) | `docs/decisions/0003-proxy-dhcp-only.md` | 2026-10-25 (Accepted) | Project decision, not product behaviour | REQ-BOOT-010, REQ-BOOT-011, REQ-BOOT-012; INDEX BOOT-1 and Unconfirmed (DHCP coexistence); standards/proxy-dhcp.md header |
| DEC-0004 | M1 network-boot scope and per-device boot suppression | `docs/decisions/0004-m1-boot-scope-and-suppression.md` | 2026-10-26 (Accepted by the owner, 2026-10-26) | Project decision, not product behaviour | REQ-BOOT-003 (x86-64 and IPv4 scope), REQ-BOOT-005 (M1 architecture set), REQ-BOOT-007 (operator part), REQ-BOOT-050, REQ-BOOT-051; INDEX BOOT-2, BOOT-5. (M2 citations for REQ-OS-002 and REQ-PE-005 removed in M2 fix round 1, CR-506; those now rest on DEC-0009.) M3: REQ-DISK-011, REQ-PE-020 (UEFI x64 scope) |
| DEC-0006 | WIM format details from our own test files | `docs/decisions/0006-wim-format-by-black-box-test-files.md` | 2026-10-26 (Accepted by owner 2026-10-26) | Project decision, not product behaviour | REQ-IMG-038 (LZMS refused in M2); os-images.md OPEN-IMG-C1; preinstall-env.md OPEN-PE-LIC (counsel question on the method); standards/wim.md §13; standards/wim-compression.md §4.2, §7 (OPEN-WIMC-2, OPEN-WIMC-3); standards/winpe.md §7; method for the [observed] notes in standards/wim.md and wim-compression.md (drift round); standards/wim.md §6.1 and §13 OPEN-WIM-7 (EFS entries refused, fail closed; CR-R3-001); INDEX IMG-2, topic 9 |
| DEC-0007 | Operator authentication by mutual TLS (PIV/CAC) | `docs/decisions/0007-operator-authentication-mtls.md` | 2026-10-26 (Accepted by owner 2026-10-26) | Project decision, not product behaviour | REQ-RBAC-005, REQ-IMG-053, REQ-AUD-001 (unauthenticated requests audited); operator-access.md OPEN-ACC-1, OPEN-ACC-3; INDEX IMG-2, RBAC-2, AUD-2 |
| DEC-0009 | M2 image scope: Windows 11 Enterprise x64 | `docs/decisions/0009-m2-image-scope.md` | 2026-10-26 (Accepted by owner 2026-10-26) | Project decision, not product behaviour | REQ-OS-001, 002, 004, 005, 007, 008, 009 (unknown status blocks readiness; moved from States, CR-511); REQ-PE-005; REQ-AUD-001 (refusals audited); os-support.md Purpose, OPEN-OS-2; INDEX OS-1, PE-1, AUD-2; M3: REQ-TGT-003, REQ-DISK-011, REQ-PE-020 (M3 scope); INDEX TGT-1, DISK-1 |
| DEC-0010 | Every operator action is audited | `docs/decisions/0010-audit-every-operator-action.md` | 2026-10-26 (Accepted by owner 2026-10-26) | Project decision, not product behaviour | REQ-AUD-001, 002, 005; REQ-RBAC-003 (refusal audited); REQ-IMG-015, 043 (auditing); operator-access.md OPEN-AUD-2; INDEX IMG-1, IMG-2 (CR-604), RBAC-2, AUD-2; M3: named in REQ-TGT-016 Basis only to say it does not cover device-side actions (D-M3-8) |
| DEC-0011 | Content integrity and secrets handling baseline | `docs/decisions/0011-content-integrity-and-secrets-baseline.md` | 2026-10-26 (Accepted by owner 2026-10-26) | Project decision, not product behaviour | REQ-IMG-035, 050, 052, 053, 054; REQ-RBAC-006; REQ-AUD-003; INDEX IMG-1, IMG-2, RBAC-2, AUD-2; M3: REQ-TGT-015, REQ-PE-015, REQ-JOB-014 (secrets only over protected channels, never shown); INDEX TGT-1, PE-1, JOB-1 |
| DEC-0012 | PostgreSQL driver and certificate-only database login | `docs/decisions/0012-postgres-driver-certificate-auth.md` | 2026-10-27 (Accepted by owner 2026-10-27) | Project decision, not product behaviour | None (clean-side design; no spec relies on it; recorded for completeness); INDEX header note |
| DEC-0013 | Operator-declared image facts, cross-checked by the product | `docs/decisions/0013-operator-declared-image-facts.md` | 2026-10-27 (Accepted by owner 2026-10-27) | Project decision, not product behaviour | REQ-IMG-043 (M2 items 1 to 4); REQ-PE-005 (M2 items 1 to 4); REQ-OS-004 (Enterprise variants refused in M2, item 3); REQ-OS-005 (declared and read facts, item 3); REQ-OS-011 (when a fact counts as unknown in M2, derived from items 1 to 3; CR-516); os-images.md OPEN-IMG-F1; os-support.md OPEN-OS-2, REQ-OS-010 status note; standards/wim.md §7 and §13 (OPEN-WIM-8 notes, drift round); INDEX PE-1, IMG-2, OS-1 |
| DEC-0014 | M2 WIM compression scope | `docs/decisions/0014-m2-wim-compression-scope.md` | 2026-10-27 (Accepted by owner 2026-10-27) | Project decision, not product behaviour | REQ-IMG-038 (M2 accepted and refused set); REQ-IMG-039 status note; os-images.md OPEN-IMG-C1 (M2 part); standards/wim-compression.md §7 M2 scope note; standards/wim.md §10 (split parts refused in M2, drift round; labelled [project rule] in fix round 2); INDEX IMG-2 |
| DEC-0015 | M2 content and audit operating rules | `docs/decisions/0015-m2-content-and-audit-operating-rules.md` | 2026-10-27 (Accepted by owner 2026-10-27) | Project decision, not product behaviour | REQ-IMG-015 item 1 (item 2 of the decision); REQ-AUD-006 (item 1); REQ-AUD-007 (item 3); REQ-AUD-004, 005 status notes; os-images.md OPEN-IMG-D1; preinstall-env.md States; operator-access.md OPEN-AUD-1, OPEN-ACC-2; INDEX IMG-1, PE-1, RBAC-2, AUD-2 |
| DEC-0017 | WIM header strictness | `docs/decisions/0017-wim-header-strictness.md` | 2026-10-27 (Accepted by owner 2026-10-27) | Project decision, not product behaviour | standards/wim.md §2 "Project rules on the header" (`cbSize` must be 208; offset 20 must be 32768 for XPRESS; CR-605, fix round 2); INDEX header note and topic 9 |
| DEC-0018 | M3 device session and boot content | `docs/decisions/0018-m3-device-session-and-boot-content.md` | 2026-10-28 (Accepted (items 1 to 10) by owner 2026-10-28; all items citable. Items 1 to 4 were accepted first, items 5 to 10 later the same day) | Project decision, not product behaviour. Content taken from the orchestrator's message; the decision record itself was not opened by the researcher (outside its read scope). The clean-room auditor checked items 1 to 10 against the record on 2026-10-28 (re-audit rounds 1 and 2) | Item 1 (session authorised by a short-lived, single-use operator-issued code or by operator approval; on by default; issue, use, approval and refusal audited): REQ-TGT-013, REQ-TGT-014, targeting.md "Security expectations" and "Out of scope". Item 2 (TFTP wrap-around; RFC 2348 large blocks when asked): REQ-BOOT-035 status, REQ-BOOT-064; standards/winpe-network-boot.md §7, OPEN-WPXE-4. Item 3 (operator builds the WinPE boot configuration with Microsoft's tool; the product imports and verifies it, never generates it): REQ-PE-012; standards/winpe-network-boot.md §6, OPEN-WPXE-3. Item 4 (the product applies the image with its own reader): REQ-PE-017. Item 5 (Microsoft's boot program from the operator's kit; no third-party chain-loader; Secure Boot never weakened): boot-network.md OPEN-BOOT-SB note; INDEX Unconfirmed (Secure Boot). Item 6 (check the FIPS module's validated environments for WinPE x64; POA&M if not): no spec text (clean-side compliance). Item 7 (mandatory, separate wipe confirmation, never skipped in R1, durably recorded before any write): REQ-DISK-006, REQ-TGT-006, REQ-TGT-007 status. Item 8 (single disk still confirmed; removable and boot-environment disks refused; no read-out of existing contents): REQ-DISK-002, 005, 016. Item 9 (installed OS's boot entry first, lasting; boot service stops offering once the job succeeded): REQ-BOOT-061, 065, 067. Item 10 (cancel only before the wipe confirmation; afterwards success or persistent error; device-side choices and every job state change audited): REQ-TGT-010, 011, 016; REQ-JOB-012. Item 7 is also cited by REQ-TGT-016 (CR-016). INDEX header, BOOT-1, BOOT-5, PE-1, TGT-1, topic 22 |
| DEC-0019 | Windows API binding | `docs/decisions/0019-windows-api-binding.md` | 2026-10-28 (owner decision, as stated in the M3 build spec request) | Project decision, not product behaviour. Implementation choice. Content taken from the orchestrator's spec request; the record was not opened by the researcher (outside its read scope). Checked by the clean-room auditor 2026-10-28 (spec pass) | No spec text. Named in standards/windows-storage-firmware-api.md header and OPEN-WAPI-1 only to say the binding is a clean-side choice; INDEX header |
| DEC-0020 | Pre-boot agent trust model | `docs/decisions/0020-preboot-agent-trust-model.md` | 2026-10-28 (owner decision, as stated in the M3 build spec request) | Project decision, not product behaviour. Content taken from the spec request; record not opened. Checked by the clean-room auditor 2026-10-28 (spec pass) | Items 1 and 5: the operator adds the agent and its public configuration (server address and trust anchor) to the operator's own WinPE, and the product never modifies the PE (CR-002); the device carries no secret; REQ-TGT-012's trusted environment is met by server-authenticated TLS plus the mandatory code or approval (DEC-0018 item 1) acting as the device credential; a secret embedded in the PE is not built: REQ-PE-010 status note, REQ-PE-015 status note, preinstall-env.md OPEN-PE-6 (settled for the project), REQ-TGT-012 status note; INDEX header, PE-1, TGT-1 |
| DEC-0021 | Minimal relay enrolment for M3 | `docs/decisions/0021-minimal-relay-enrolment-m3.md` | 2026-10-28 (owner decision, as stated in the M3 build spec request) | Project decision, not product behaviour. Content taken from the spec request; record not opened. Checked by the clean-room auditor 2026-10-28 (spec pass) | Manual relay enrolment; relay pulls a signed, generation-numbered boot-policy list; a stop is reversed only by an audited operator command until REQ-BOOT-062 is specced: REQ-BOOT-062 and REQ-BOOT-067 status notes. Item 4 (all content for the chosen package downloaded and verified in full before the wipe, then discarded; fetched and verified again during apply; nothing staged and nothing written before it is verified; OPEN-JOB-3 open only as a product question): REQ-PE-016 status note (corrected for CR-001). INDEX header, BOOT-5, PE-1 |

## Project observation records

Clean-side records of the project's own interoperability tests with
Microsoft's public tools, made under DEC-0006. They are not vendor
material and not Microsoft text, need no public-access check, and are
cited in specs only under the [observed] label.

| ID | Title | Repo path | Run and date | Nature | Used for |
|----|-------|-----------|--------------|--------|----------|
| OBS-001 to OBS-017 (run R1) | WIM format: observations from our own DISM-made files | `docs/formats/wim-observed.md` | Workflow run 40535666995, attempt 1, commit ba23bed (branch of the WIM sample job); DISM 10.0.26100.32860 on Windows build 26100.33650; 2026-10-27 | Clean-side observation of files the project built itself with Microsoft's DISM (DEC-0006); claims hold for R1 files only | standards/wim.md Sources, labels, §2, §3, §4, §5, §7, §8, §9, §10, §12, §13; standards/wim-compression.md Sources, §1, §3, §3.1, §3.3, §3.4, §3.6, §7; REQ-IMG-038 Status (OPEN-WIMC-1 confirmed for R1); INDEX header, topics 9 and 20 |
| OBS-018 to OBS-023 (run R2) | WIM format: observations from our own DISM-made files changed after capture (identical images, append, export, commit, delete) | `docs/formats/wim-observed.md` | Workflow run 40599556702, attempt 1, commit 5d3c8c7 (job `generate`); DISM 10.0.26100.32860 on Windows build 26100.33650 (same as R1); 2026-10-27 | Clean-side observation of files the project built itself with Microsoft's DISM (DEC-0006); claims hold for R2 files only (OBS-020 also notes R1's 12-image file) | standards/wim.md Sources, labels, §3, §5, §13 (OPEN-WIM-6, status table, never-observed list, samples recorded and still needed), §14; INDEX header and topic 9 |
| OBS-024 to OBS-048 (run R3) | WIM format: observations of metadata resources (directory entries, streams, security data), raw chunks, a file over 4 GiB, XML counts and DISM's apply | `docs/formats/wim-observed.md` | Workflow run 40754869824, attempt 1, commit 27f7237 (jobs `generate`, `generate-large`, `generate-metadata`, `reference`); DISM 10.0.26100.32860 on Windows build 26100.33650 (same as R1 and R2); 2026-10-28 | Clean-side observation of files the project built itself with Microsoft's DISM (DEC-0006); claims hold for the R3 files examined (including S01, rebuilt in R3 with the R1 command) only. Records were read from the "Runs examined" rows, the M-01 to M-23 section and the records themselves | standards/wim.md Sources, labels, §3, §4, §5, §6 (fixed part contradicted by OBS-026; new §6.1), §7, §13 (OPEN-WIM-5, 7, 10, status table, never-observed list, samples recorded in R3 and still needed), §13 OPEN-WIM-12 (via OBS-037); INDEX topic 9. EFS refusal: [project rule, DEC-0006]. AUDITED 2026-10-28 (CR-R3-001 to 003, 005 applied). SR-6: OBS-036 to OBS-038 cited in standards/reparse-and-security-descriptors.md §2, §5, §9 and in the wim.md §6.1 descriptor correction (AUDITED 2026-10-28) |

## Sources used

| ID | Title | URL | Accessed (UTC date) | Public? (how verified) | Used for (area codes in survey; REQ IDs once area specs exist) |
|----|-------|-----|---------------------|------------------------|-----------------------------------------|
| SRC-001 | Vendor blog: bare-metal imaging walkthrough (Tech Talks #82) | https://www.tanium.com/blog/bare-metal-imaging-with-tanium-provision-tanium-tech-talks-82/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate (re-checked in M2 run, 2026-10-26) | REQ-IMG-001 (outcome only: a package pairs an image with what installs it; rewritten in M2 fix round 1, CR-501), REQ-IMG-010, REQ-IMG-011, REQ-IMG-030; REQ-PE-006, REQ-PE-007; M3 (re-checked 2026-10-27): REQ-TGT-001, 004, 005 (packages assigned to the boot service in advance; person at the device picks package and disk); REQ-DISK-001, 002, 008 (outcome only), 015; REQ-PE-013 (outcome only), 017 (outcome only); MEDIA, CFG, DOM, SEQ, AGT, RET |
| SRC-002 | Vendor blog: OS imaging for Windows and Linux endpoints | https://www.tanium.com/blog/windows-linux-endpoint-imaging-tanium-provision/ | 2026-10-25 | Yes: anonymous fetch, public marketing blog, no gate (re-checked in M3 run, 2026-10-27) | M3: REQ-JOB-001, 006, 012 (operators track and report deployment status; outcome only); REQ-DISK-014; AGT, RFR, RELAY |
| SRC-003 | Vendor solution brief: bare-metal provisioning (PDF, 2022) | https://site.tanium.com/rs/790-QFJ-925/images/SB-Tanium_Baremetal-provisioning-EN.pdf | 2026-10-25 | Yes: anonymous download of public marketing PDF, no form or gate. Fix round 1 re-check: the URL appears as the top result of an ordinary public web search on the brief's subject; the link goes straight to the PDF and no lead or registration form was shown. The host serves marketing assets that are sometimes form-gated, but this file was not. M1 run: downloaded again anonymously, still no form. | REQ-BOOT-001; MEDIA, DRV, DOM, RELAY |
| SRC-004 | Vendor public knowledge base: cloud release notes for the product (all releases 2022–2026) | https://kb.tanium.com/Tanium_Cloud_Release_Notes_Provision | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run) | REQ-BOOT-001, REQ-BOOT-002, REQ-BOOT-003 (indirect: UEFI network boot), REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-030, REQ-BOOT-034, REQ-BOOT-044 (symptom only), REQ-BOOT-050 (outcome only), REQ-BOOT-052 (missing-content notice), REQ-BOOT-060, REQ-BOOT-061, REQ-BOOT-062; BOOT-3, BOOT-6 (not yet specced). M2 (re-checked 2026-10-26; qualifiers revised in fix round 1): REQ-IMG-001 (outcome only), 002 (limits exist for another operator-defined object; outcome only), 003 (create, upload, edit, delete only; cloning derived), 004 to 006, 010 to 014 (014: single delete only), 017 (removing several files from one package), 020 to 022, 030 to 033, 040, 041 (outcome only: index support; "exactly one" is project design), 042, 050 (hash check before imaging only; "every use" from DEC-0011), 054 (passwords held and kept by clones only; protection from DEC-0011); REQ-OS-001 (outcome only: Windows client targets), 003, 005; REQ-PE-001, 002 (outcome only), 003, 005, 006, 008, 009 (advice to operators only; import warning derived), 010; REQ-RBAC-001 (outcome only), 002, 004, 006; REQ-AUD-003, 004 (outcome only). No longer cited for REQ-OS-002, 004, 007, 008 or REQ-AUD-001 (fix round 1; those rest on DEC-0009 or DEC-0010); IMG-3 to IMG-6, PE-2, PE-3, OS-2, OS-3, RBAC-1, AUD-1 (not yet specced). M3 (re-checked 2026-10-27, three fetches): REQ-TGT-001, 002, 007 (zero-touch exists, undefined), 008, 009 (outcome only), 012 (mutual authentication, signed tokens, certificate validation; outcome only), 013 (operator-set secrets and confirmation code exist; where entered not stated), 015 (outcome only); REQ-DISK-003 (outcome only), 007 (partitions wiped, not only removed), 008 (outcome only), 012, 013; REQ-JOB-001 to 005, 007 to 011, 013, 014; REQ-PE-011, 012, 014, 015, 016, 019 (outcome only where marked); REQ-BOOT-063, 065 (boot order set after network boot; lasting or one-time not stated), 066, 067 (outcome only); MEDIA, DRV, CFG, DOM, SEQ, RFR, RELAY, RET, limits. M3 build (re-checked 2026-10-28, two paraphrase-only fetches on Q6 to Q8): disk.md OPEN-DISK-5 (c) (a past fix for bare-metal installs to eMMC storage; nothing on SD, MMC, read-only, virtual disks or sector sizes); targeting.md OPEN-TGT-1 note (no device-session expiry stated; the only time limits named concern install steps and refresh deployments), OPEN-TGT-3 (serial number gathered, including a past fix for some virtual machines; where it is shown or recorded not stated; MAC and UUID not mentioned) |
| SRC-005 | Vendor public knowledge base: release notes version 1.5 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.5) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 and M2 runs) | REQ-BOOT-001; M2: REQ-IMG-020, 021, 022, 037; REQ-OS-001 (outcome only: Windows client targets; no longer cited for REQ-OS-002, 004, 007 after fix round 1); REQ-PE-004; M3 (re-checked 2026-10-27): REQ-PE-011 (installs by network boot; outcome only); PE-2, OS-2 (not yet specced); MEDIA, DOM, RFR |
| SRC-006 | Vendor public knowledge base: release notes version 1.6 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.6) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run; re-checked in M2 run, 2026-10-26) | REQ-BOOT-002, REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-052 (service status sentence only); BOOT-3 (not yet specced). M2 (re-checked 2026-10-26): REQ-RBAC-001 (outcome only); no longer cited for IMG-2 (see M2 run notes); PE-2, PE-4, OS-2, RBAC-1 (not yet specced). M3 (re-checked 2026-10-27): REQ-TGT-009 (outcome only), 013 (confirmation code); REQ-DISK-003 (outcome only), 012; REQ-JOB-003, 011, 015; DISK-2; DRV, CFG, SEQ, RFR, RELAY, limits. M3 build (re-checked 2026-10-28, one paraphrase-only fetch on Q6 to Q8): disk.md OPEN-DISK-5 (c) (fix for bare-metal installs to eMMC storage); no device-session timeout or machine identifier stated |
| SRC-007 | Vendor public knowledge base: release notes version 1.7 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.7) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M1 run; re-checked in M2 run, 2026-10-26) | REQ-BOOT-002, REQ-BOOT-020 (outcome only), REQ-BOOT-022 (outcome only), REQ-BOOT-053; BOOT-3, BOOT-6 (not yet specced). M2 (re-checked 2026-10-26): REQ-IMG-003 (create, upload, edit, delete only; cloning derived), REQ-IMG-004; IMG-4 (not yet specced); MEDIA, DRV, CFG, SEQ, TGT (TGT-2 to TGT-4), RELAY. Re-checked in M3 run (2026-10-27): nothing used for M3 |
| SRC-008 | Vendor public knowledge base: release notes version 1.8 | https://kb.tanium.com/Release_Notes_Provision_(Version_1.8) | 2026-10-25 | Yes: anonymous fetch of public KB page, no gate (re-checked in M2 run, 2026-10-26) | REQ-PE-005, REQ-PE-009; RET. Re-checked in M3 run (2026-10-27): nothing used for M3 |
| SRC-009 | Public personal blog post (Out of Office Hours, M. Niehaus) describing the product's PXE, HTTP boot, and Wi-Fi/USB flows | https://oofhours.com/?p=3414 | 2026-10-25 | Yes: anonymous fetch of public blog; content readable with no login or form (the site's optional log-in link and subscribe widget do not gate it). Post dated 2022-03-05 (from the post URL), so it may be out of date. Why we treat it as vendor-associated: the author writes in the first person plural about building the product, the post is filed under the vendor's category on the blog, and it sends readers to their vendor representative. The author bio on the page does not name the vendor. No confidentiality or NDA marking. Not obtained through private contact with the author or vendor staff. Contains no code or downloads. Only public source for BOOT-4. In fix round 1, SRC-004 to SRC-008 were checked for HTTP boot and none mention it. M1 run: fetched again; it says little about PXE beyond the device being started into network boot with a firmware key on wired Ethernet. | boot-network.md "Actors" (person at the device: firmware boot key only). Removed from REQ-BOOT-003 and INDEX BOOT-2 in fix round 1 (CR-103). M3 (re-checked 2026-10-27): REQ-TGT-015 (no join credentials typed at the device), REQ-JOB-002 (progress visible; outcome only), REQ-PE-016 (content downloaded first, install runs from the local copy). BOOT-4 (not yet specced); MEDIA, RELAY |
| SRC-010 | Vendor conference (Converge 2024) public session abstract: imaging service replacement | https://converge.tanium.com/2024/session/2475552/a-big-upgrade-for-imaging-services | 2026-10-25 | Yes: anonymous fetch of public session catalogue page, no gate | DOM, AGT |
| SRC-011 | IETF RFC 2131, Dynamic Host Configuration Protocol | https://www.rfc-editor.org/rfc/rfc2131 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-002, REQ-BOOT-006, REQ-BOOT-007 (field facts), REQ-BOOT-020, REQ-BOOT-022, REQ-BOOT-070; standards/pxe-dhcp.md, standards/proxy-dhcp.md §4.1; standards/dhcp-long-options.md §1, §2, §7 (re-fetched 2026-10-26); standards/pxe-dhcp.md §5.5 (§4.3.1, as already summarised in dhcp-long-options.md §7; not re-fetched in fix round 1); standards/pxe-dhcp.md §3.1 (§4.3.1 Table 3, §2 siaddr; re-fetched 2026-10-26, gaps run) |
| SRC-012 | IETF RFC 2132, DHCP Options and BOOTP Vendor Extensions | https://www.rfc-editor.org/rfc/rfc2132 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-004, REQ-BOOT-006; standards/pxe-dhcp.md, standards/proxy-dhcp.md; standards/dhcp-long-options.md §1, §2, §4 (RFC 2132 §9.10), §6, §7 (re-fetched 2026-10-26); standards/pxe-dhcp.md §6.1 (§2 byte order, by comparison; not re-fetched) |
| SRC-013 | IETF RFC 4578, DHCP Options for the Intel PXE | https://www.rfc-editor.org/rfc/rfc4578 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF informational RFC | REQ-BOOT-003, REQ-BOOT-005, REQ-BOOT-007 (field facts), REQ-BOOT-043; standards/pxe-dhcp.md; standards/dhcp-long-options.md §5, §6; standards/uefi-guid-text.md §3 (re-fetched 2026-10-26: checked that it has no RFC 3396 reference, and §2.3 wording); standards/pxe-dhcp.md §5.2 to §5.5 (presence rule in §2.1 to §2.3; §1 purpose; re-fetched again 2026-10-26, fix round 1) |
| SRC-014 | RFC Editor errata for RFC 4578 (erratum 4624, verified) | https://errata.rfc-editor.org/rfc4578 | 2026-10-26 | Yes: anonymous fetch from RFC Editor errata site | REQ-BOOT-003; standards/pxe-dhcp.md §5.2 |
| SRC-015 | IETF RFC 3046, DHCP Relay Agent Information Option | https://www.rfc-editor.org/rfc/rfc3046 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-021, REQ-BOOT-043, REQ-BOOT-045; standards/pxe-dhcp.md §9, §10; standards/dhcp-long-options.md §6, §7 (re-fetched 2026-10-26) |
| SRC-016 | IETF RFC 1542, Clarifications and Extensions for BOOTP (relay agents) | https://www.rfc-editor.org/rfc/rfc1542 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-002, REQ-BOOT-020, REQ-BOOT-022, REQ-BOOT-023; standards/pxe-dhcp.md §9; standards/pxe-dhcp.md §3.2 (§1.2, §2.1, §4.1, §5.1 minimum size and silent discard; re-fetched 2026-10-26, gaps run) |
| SRC-017 | IANA DHCPv6 parameters registry, Processor Architecture Types | https://www.iana.org/assignments/dhcpv6-parameters/dhcpv6-parameters.xhtml | 2026-10-26 | Yes: anonymous fetch of public IANA registry | REQ-BOOT-003; standards/pxe-dhcp.md §5.2 |
| SRC-018 | IETF Internet-Draft draft-henry-remote-boot-protocol-00, Intel Preboot Execution Environment (June 1999, expired) | https://datatracker.ietf.org/doc/html/draft-henry-remote-boot-protocol-00 | 2026-10-25 | Yes: anonymous fetch from IETF Datatracker; an expired individual draft published openly by Intel through the IETF; no gate. Used in place of the PXE 2.1 PDF, which could not be retrieved (see below) | REQ-BOOT-001, REQ-BOOT-004, REQ-BOOT-010, REQ-BOOT-043, REQ-BOOT-045; standards/pxe-dhcp.md, standards/proxy-dhcp.md (§1 limited in fix round 1 to: optional arrangement, PXE clients only, same or separate host). Re-fetched 2026-10-26 for CR-106. Re-fetched again 2026-10-26 (standards-notes run): standards/uefi-guid-text.md §3.1 (§3.2.2 option 61 UUID); standards/dhcp-long-options.md §6 (no repeat rules for option 43). Re-fetched again 2026-10-26 (gaps run): standards/pxe-dhcp.md §6.1 (tag 71 layout, §3.2.3.6, §3.3.1, §3.3.2, §3.3.2.6, §3.5.1, §3.5.2) |
| SRC-019 | UEFI Specification 2.10, Appendix E (Universal Network Driver Interfaces), incl. E.4.20 PXE 2.1 wire-protocol clarifications | https://uefi.org/specs/UEFI/2.10/Apx_E_Universal_Network_Driver_Interfaces.html | 2026-10-25 | Yes: anonymous fetch of HTML specification published by the UEFI Forum; no click-through | REQ-BOOT-011, REQ-BOOT-022, REQ-BOOT-051, REQ-BOOT-070; standards/pxe-dhcp.md, standards/proxy-dhcp.md; standards/pxe-dhcp.md §6.1 (E.4.20.3 tag 71 default; re-fetched 2026-10-26, gaps run) |
| SRC-020 | UEFI Specification 2.10, chapter 24 (Network Protocols: SNP, PXE, BIS), §24.3 PXE Base Code | https://uefi.org/specs/UEFI/2.10/24_Network_Protocols_SNP_PXE_BIS.html | 2026-10-25 | Yes: as SRC-019 | REQ-BOOT-001, REQ-BOOT-012, REQ-BOOT-013, REQ-BOOT-030, REQ-BOOT-031, REQ-BOOT-051; standards/pxe-dhcp.md, standards/tftp.md, standards/uefi-boot-manager.md; standards/uefi-guid-text.md §3, §3.1 (§24.3.1, §24.3.15, §24.7.4.1.1; re-fetched 2026-10-26); standards/pxe-dhcp.md §6.1 (§24.3.9 boot-server type values, layer width, initial layer and layer mask; re-fetched 2026-10-26, gaps run) |
| SRC-021 | UEFI Specification 2.10, chapter 3 (Boot Manager) | https://uefi.org/specs/UEFI/2.10/03_Boot_Manager.html | 2026-10-25 | Yes: as SRC-019 | REQ-BOOT-012, REQ-BOOT-050, REQ-BOOT-051, REQ-BOOT-060, REQ-BOOT-061; boot-network.md "Actors" (boot order); standards/uefi-boot-manager.md; M3 (not re-fetched; existing summary §2, §8 cited): REQ-BOOT-065, REQ-BOOT-067 (standards cites). M3 build (re-fetched 2026-10-28, two paraphrase prompts): standards/uefi-boot-manager.md §10.2 (§3.1.3 load option layout and attribute values), §10.3 (§3.1.1 naming, §3.3 global variable GUID and attributes), §10.5, §10.7 (§3.1.2 Hard Drive short form, UniquePartitionGuid match). SR-3b (re-fetched 2026-10-28, paraphrase prompt): standards/uefi-boot-manager.md §10.3 (Table 3.1 SecureBoot, SetupMode, AuditMode, DeployedMode) |
| SRC-022 | UEFI Specification 2.10, chapter 32 (Secure Boot and Driver Signing) | https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html | 2026-10-25 | Yes: as SRC-019 | standards/uefi-secure-boot.md (background; OPEN-BOOT-SB) |
| SRC-023 | UEFI Specification 2.10, chapter 7 (Boot Services), §7.4 image services | https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html | 2026-10-26 | Yes: as SRC-019 | standards/uefi-secure-boot.md §5, standards/uefi-boot-manager.md §5.1. Fetched again 2026-10-27 (M3) for §7.5.7 CalculateCrc32: it names no CRC algorithm; nothing used (SRC-082 used instead) |
| SRC-024 | Microsoft Learn: PXE clients don't start (DHCP options 60, 66, 67; former KB 259670) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/pxe-clients-not-start-dhcp-60-66-67-option | 2026-10-25 | Yes: anonymous fetch of public Microsoft Learn page (reached by redirect from support.microsoft.com/kb/259670) | REQ-BOOT-002, REQ-BOOT-011, REQ-BOOT-014, REQ-BOOT-023; standards/proxy-dhcp.md §4.2, §5 |
| SRC-025 | Microsoft Learn: Secure boot (OEM guidance) | https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-secure-boot | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn page | standards/uefi-secure-boot.md |
| SRC-026 | IETF RFC 1350, The TFTP Protocol (Revision 2) | https://www.rfc-editor.org/rfc/rfc1350 | 2026-10-25 | Yes: anonymous fetch from RFC Editor; IETF open standard | REQ-BOOT-030, REQ-BOOT-032, REQ-BOOT-033 (sole source), REQ-BOOT-035, REQ-BOOT-040, REQ-BOOT-041, REQ-BOOT-043; standards/tftp.md |
| SRC-027 | IETF RFC 2347, TFTP Option Extension | https://www.rfc-editor.org/rfc/rfc2347 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031; standards/tftp.md §6 |
| SRC-028 | IETF RFC 2348, TFTP Blocksize Option | https://www.rfc-editor.org/rfc/rfc2348 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031, REQ-BOOT-035; standards/tftp.md §7, §8 |
| SRC-029 | IETF RFC 2349, TFTP Timeout Interval and Transfer Size Options | https://www.rfc-editor.org/rfc/rfc2349 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-031 (standards cite); standards/tftp.md §7 |
| SRC-030 | IETF RFC 7440, TFTP Windowsize Option | https://www.rfc-editor.org/rfc/rfc7440 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-032, REQ-BOOT-044 (standards cite); standards/tftp.md §10 (conditional; end-of-transfer statement corrected from §3 and §4, re-fetched 2026-10-26, gaps run) |
| SRC-031 | IETF RFC 1123, Requirements for Internet Hosts (§4.2 TFTP) | https://www.rfc-editor.org/rfc/rfc1123 | 2026-10-25 | Yes: anonymous fetch from RFC Editor | REQ-BOOT-032, REQ-BOOT-040, REQ-BOOT-041, REQ-BOOT-042; standards/tftp.md |
| SRC-032 | IETF RFC 5970, DHCPv6 Options for Network Boot | https://www.rfc-editor.org/rfc/rfc5970 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/pxe-dhcp.md §11 (conditional) |
| SRC-033 | Wikipedia: Preboot Execution Environment (secondary reference) | https://en.wikipedia.org/wiki/Preboot_Execution_Environment | 2026-10-25 | Yes: anonymous fetch of public encyclopedia article. Secondary source; cites PXE 2.1 for the DHCP/ProxyDHCP split. Used only where marked [secondary] | REQ-BOOT-004, REQ-BOOT-010, REQ-BOOT-014; standards/proxy-dhcp.md (§1 and §5 address-division and no-site-change points, §4.1, §4.2; all [secondary]) |
| SRC-034 | Public technical blog post (sysmgr.org, 2010) on PXE discovery control | https://sysmgr.org/blog/2010/06/19/forcing_pxe_clients_not_to_broadcast_for_extra_dhcp_options/ | 2026-10-25 | Yes: anonymous fetch of public blog; no gate. Secondary source; not vendor-related | REQ-BOOT-010; standards/pxe-dhcp.md §6, standards/proxy-dhcp.md |
| SRC-035 | iPXE project public commit message: honour discovery-control skip option | https://github.com/ipxe/ipxe/commit/620b98ee4b9d8fa87c56bfa72b4391c1eed9dce6 | 2026-10-25 | Yes: anonymous fetch of public GitHub page for the open-source iPXE project (not vendor). Only the commit message was used. The fetch was told to ignore the code diff, and no code was copied or summarised | standards/pxe-dhcp.md §6, standards/proxy-dhcp.md §3 (secondary) |
| SRC-036 | IBM Documentation (AIX 7.2): PXE vendor container suboption | https://www.ibm.com/docs/ssw_aix_72/network/tcpip_dhcp_preboot.html | 2026-10-25 | Yes: anonymous fetch of public IBM docs page; no gate. Third-party product documentation, used only to back up the standard port-4011 same-host arrangement | REQ-BOOT-014; standards/proxy-dhcp.md §4.2 |
| SRC-037 | IETF RFC 3396, Encoding Long Options in DHCPv4 | https://www.rfc-editor.org/rfc/rfc3396 | 2026-10-26 | Yes: anonymous fetch from RFC Editor; IETF open standard | standards/dhcp-long-options.md §1 to §5, §8 |
| SRC-038 | IETF RFC 3397, DHCP Domain Search Option | https://www.rfc-editor.org/rfc/rfc3397 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/dhcp-long-options.md §5 (example of a concatenation-requiring option) |
| SRC-039 | IETF RFC 3925, Vendor-Identifying Vendor Options for DHCPv4 | https://www.rfc-editor.org/rfc/rfc3925 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/dhcp-long-options.md §5, §6 (options 60/43 merge when repeated) |
| SRC-040 | UEFI Specification 2.10, Appendix A (GUID and Time Formats) | https://uefi.org/specs/UEFI/2.10/Apx_A_GUID_and_Time_Formats.html | 2026-10-26 | Yes: as SRC-019 | standards/uefi-guid-text.md §1, §1.2, §1.3, §2, §3 |
| SRC-041 | IETF RFC 4122, A UUID URN Namespace (obsoleted by RFC 9562) | https://www.rfc-editor.org/rfc/rfc4122 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/uefi-guid-text.md §1, §1.1, §2 |
| SRC-042 | IETF RFC 9562, Universally Unique IDentifiers (UUIDs) | https://www.rfc-editor.org/rfc/rfc9562 | 2026-10-26 | Yes: anonymous fetch from RFC Editor | standards/uefi-guid-text.md §1, §1.1, §2 |
| SRC-043 | DMTF DSP0134 SMBIOS Reference Specification (2.6.0, 3.6.0, 3.7.1 PDFs; 3.8.0 to 3.10.0 seen in search results) | https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.7.1.pdf (also DSP0134_2.6.0.pdf, DSP0134_3.6.0.pdf, DSP0134_2.7.1.pdf at the same path) | 2026-10-26 | Yes: anonymous HTTPS download from dmtf.org's public standards directory, with no login, form or click-through. **Text not read directly**: the fetch tool could not decompress the PDF streams, and no PDF renderer was available. Content was taken only from the search engine's summary of these documents (a search limited to dmtf.org, with a query on the System UUID byte order). Fix round 1 (2026-10-26): 3.7.1 and 2.6.0 fetched again anonymously; text still not extractable with the available tools (no PDF renderer, fetch tool cannot decompress the streams). Still not read directly. M3 build requests (2026-10-28): 3.8.0 fetched anonymously; text still not extractable (fetch tool cannot decompress; the local reader has no PDF renderer). One more dmtf.org-limited search summary used, as before, for §7.2.1 byte order and the all-FFh/all-00h meanings. Still not read directly. | standards/uefi-guid-text.md §4 ([primary not read]; no REQ may cite these points until confirmed); OPEN-GUID-3, OPEN-GUID-5; M3 build: standards/smbios.md §2, §3 ([primary not read]), OPEN-SMB-1 |
| SRC-044 | Microsoft Learn: SMBIOS (Windows drivers, bring-up) | https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/smbios | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn page | standards/uefi-guid-text.md §4 (type 1 UUID at offset 08h, 16 octets, DSP0134 §7.2.1, RFC 4122 format); M3 build (not re-fetched): standards/smbios.md §1 (same facts) |
| SRC-045 | IETF RFC 951, Bootstrap Protocol (BOOTP) | https://www.rfc-editor.org/rfc/rfc951 | 2026-10-26 | Yes: anonymous fetch from RFC Editor; IETF open standard | standards/pxe-dhcp.md §3.2 (§3 packet format: 64-octet vendor area, field widths totalling 300 octets; reached via RFC 1542 reference [1]; fetched 2026-10-26, gaps run fix round 1) |
| SRC-046 | Microsoft Learn (archive): Windows Imaging File Format (WIM), Windows 7 overview | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-7/dd799284(v=ws.10) | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn archive page | standards/wim.md §1 (six resource kinds; link to the WIM paper) |
| SRC-047 | Microsoft Download Center: "Windows Imaging File Format (WIM)" white paper (listing v1.1, 2024; RTF body 2007, revised 2017) | https://www.microsoft.com/en-us/download/details.aspx?id=13096 (reached from https://go.microsoft.com/fwlink/?linkid=92227); file https://download.microsoft.com/download/f/e/f/fefdc36e-392d-4678-9e4e-771ffa2692ab/Windows%20Imaging%20File%20Format.rtf | 2026-10-26 | Yes: anonymous fetch; the details page shows a direct download with no sign-in, form or licence click-through, and says the content may be used to build WIM tools. The document carries Microsoft's standard copyright and disclaimer notice only. Text read from the downloaded RTF (searched for text lines; embedded images skipped) | standards/wim.md §1 to §14; standards/wim-compression.md §1, §2; REQ-IMG-030, REQ-IMG-037, REQ-IMG-038, REQ-IMG-051; REQ-PE-004 |
| SRC-048 | Microsoft Learn: DISM Image Management Command-Line Options | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/dism-image-management-command-line-options-s14 | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn page | standards/wim.md §1, §8, §10, §11; standards/wim-compression.md §1; REQ-IMG-037, REQ-IMG-038; REQ-PE-004; M3 (not re-fetched): REQ-PE-017 (apply by image index) |
| SRC-049 | Microsoft Learn: Split a Windows image file (.wim) to span across multiple DVDs | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/split-a-windows-image--wim--file-to-span-across-multiple-dvds | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §10, §12; REQ-IMG-038, REQ-IMG-039 |
| SRC-050 | Microsoft Learn: Take Inventory of an Image or Component Using DISM | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/take-inventory-of-an-image-or-component-using-dism | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §7; REQ-IMG-040, REQ-IMG-043 |
| SRC-051 | Microsoft Learn: unattend Microsoft-Windows-Setup ImageInstall OSImage InstallFrom MetaData Key | https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-setup-imageinstall-osimage-installfrom-metadata-key | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §7, §11; REQ-IMG-041 (Source and Standards: Setup selects one image by index, name or description) |
| SRC-052 | Microsoft Learn: WIMSetImageInformation (WIMGAPI) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wim/dd834951(v=msdn.10) | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §7 |
| SRC-053 | Microsoft Open Specifications [MS-XCA] Xpress Compression Algorithm (rev. 10.0, 2024-04-23): landing page with IP notice; LZ77+Huffman Compression Algorithm Details; LZ77 Phase; Final Encoding Phase; Processing | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/a8b7cb0a-92a6-4187-a23b-5e14273b96f8 ; .../c0244bfe-fd96-4fe5-97dd-39b9fc99b801 ; .../75e3628e-e430-4d4e-9ca7-4637256e3755 ; .../c7ec7ba9-ca8f-448f-bb85-027c1516db1c ; .../26db8e62-bbd8-472c-a09e-623f6de10f0b | 2026-10-26 | Yes: anonymous fetch of public Microsoft Open Specifications pages; the IP notice permits copying to build implementations and claims no trade secrets (patent position noted as OPEN-WIMC-4). Processing page (§2.2.4) fetched again anonymously 2026-10-27 (M2 fix round 2, CR-608), same content, no gate | standards/wim-compression.md §3, §6; §3.3 refill rule (fix round 2, CR-608) |
| SRC-054 | Microsoft Open Specifications [MS-PATCH] LZX DELTA Compression and Decompression (rev. 14.1, 2025-08-19): landing page; Structures; Chunk Size; Block Header; Decoding Matches and Literals; Encoding the Trees and Pretrees (added in M2 fix round 1) | https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf ; .../2c64cf78-71a2-48d3-b85f-85ced4a8c36e ; .../ce9bcad1-3205-4d2a-ab6b-8c8dd4b56588 ; .../517e354e-a5c5-4239-ada5-25389cfe3170 ; .../06ee7ce0-730a-4907-be3c-f1f5673b0300 ; .../8b31ee78-6d50-428a-9520-9191238971f4 | 2026-10-26 | Yes: as SRC-053 (landing page and pretree page fetched again anonymously in fix round 1, same IP notice, no gate) | standards/wim-compression.md §4.4 (background only); §4.2 delta-direction cross-check and pretree storage (LZXD, [reading] for WIM; fix round 1, CR-509) |
| SRC-055 | Microsoft Learn (archive): Microsoft Cabinet SDK page, and Microsoft Cabinet Format documentation including "Microsoft LZX Data Compression Format" | https://learn.microsoft.com/en-us/previous-versions/ms974336(v=msdn.10) ; https://learn.microsoft.com/en-us/previous-versions/bb417343(v=msdn.10) | 2026-10-26 | Yes: anonymous fetch of public Microsoft Learn archive pages. The SDK page says the SDK download is gone and points to this documentation. Extracted text lost some exponents and figures (noted in the standards file) | standards/wim-compression.md §4.1 to §4.3, §6, OPEN-WIMC-2 |
| SRC-056 | Microsoft Learn: Using the Compression API (Win32) | https://learn.microsoft.com/en-us/windows/win32/cmpapi/using-the-compression-api | 2026-10-26 | Yes: as SRC-048 | standards/wim-compression.md §1, §5; REQ-IMG-038 |
| SRC-057 | Microsoft Learn: Windows PE (WinPE) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-intro | 2026-10-26 | Yes: as SRC-048 | standards/winpe.md §1, §2, §6, §7; REQ-PE-001; M3 (not re-fetched; existing summary §6 cited): REQ-PE-018, REQ-PE-020; REQ-TGT-003; REQ-DISK-011; standards/winpe.md §9 |
| SRC-058 | Microsoft Learn: Download and Install the Windows ADK (page updated 2026-10-23) | https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install | 2026-10-26 | Yes: as SRC-048. The page itself is public; the kit downloads were not opened | standards/winpe.md §2; os-support.md "Facts"; REQ-PE-001, REQ-PE-005 (32-bit WinPE cannot deploy Windows 11), REQ-OS-010 |
| SRC-059 | Microsoft Learn: WinPE: Create bootable media | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-create-usb-bootable-drive | 2026-10-26 | Yes: as SRC-048 | standards/winpe.md §3 |
| SRC-060 | Microsoft Learn: Copype Command-Line Options | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/copype-command-line-options | 2026-10-26 | Yes: as SRC-048 | standards/winpe.md §3; REQ-PE-002, REQ-PE-005 |
| SRC-061 | Microsoft Learn: WinPE: Mount and Customize | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-mount-and-customize | 2026-10-26 | Yes: as SRC-048 | standards/winpe.md §4, §5; REQ-PE-002 |
| SRC-062 | Microsoft Learn: Wpeinit and Startnet.cmd: Using WinPE Startup Scripts | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wpeinit-and-startnetcmd-using-winpe-startup-scripts | 2026-10-26 | Yes: as SRC-048 (fetched again 2026-10-27, M3) | standards/winpe.md §5, §5.1, §5.2; REQ-PE-013 |
| SRC-063 | Microsoft Q&A: "Commercial distribution of Windows PE with proprietary disk cloning software" (answer of 2026-07-01 by a contributor labelled Microsoft External Staff) | https://learn.microsoft.com/en-us/answers/questions/5933103/commercial-distribution-of-windows-pe-with-proprie | 2026-10-26 | Yes: anonymous fetch; question and answer readable without sign-in. **Secondary, non-authoritative**: not Microsoft's licence text; no disclaimer; not related to the vendor. Used only as a pointer | standards/winpe.md §7 [secondary]; REQ-PE-001 [secondary] (its MUST is a cautious project stance pending counsel, OPEN-PE-LIC) |
| SRC-064 | Microsoft Learn: Windows 11 release information (page dated 2026-10-26) | https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information | 2026-10-26 | Yes: as SRC-048 | os-support.md "Facts"; REQ-OS-008 (release names and dates only); INDEX OS-1 |
| SRC-065 | Microsoft Learn: Windows 10 release information | https://learn.microsoft.com/en-us/windows/release-health/release-information | 2026-10-26 | Yes: as SRC-048 | os-support.md "Facts"; REQ-OS-007 (end-of-support context only; the refusal rests on DEC-0009) |
| SRC-066 | Microsoft Learn: Windows Setup Supported Platforms and Cross-Platform Deployments | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-supported-platforms-and-cross-platform-deployments | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §7; standards/winpe.md §6; os-support.md "Facts"; INDEX OS-1 |
| SRC-067 | Microsoft Learn: SYSTEM_INFO structure (processor architecture values) | https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info | 2026-10-26 | Yes: as SRC-048 | standards/wim.md §7; os-support.md "Facts"; INDEX OS-1; same page fetched again 2026-10-28 under SRC-135 (standards/windows-storage-firmware-api.md §16) |
| SRC-068 | IETF RFC 9110, HTTP Semantics | https://www.rfc-editor.org/rfc/rfc9110 | 2026-10-26 | Yes: anonymous fetch from RFC Editor; IETF open standard | standards/http-tls.md §1 to §5; REQ-IMG-031 (413), REQ-RBAC-003 (403), REQ-RBAC-005 (401) (standards cites) |
| SRC-069 | IETF RFC 8446, TLS 1.3 (obsoleted by RFC 9846) | https://www.rfc-editor.org/rfc/rfc8446 | 2026-10-26 | Yes: as SRC-068 | standards/http-tls.md §6.1 to §6.5; REQ-IMG-053, REQ-RBAC-005 (standards cites) |
| SRC-070 | IETF RFC 9846, TLS 1.3 (2026; obsoletes RFC 8446 and RFC 5246) | https://www.rfc-editor.org/rfc/rfc9846 | 2026-10-26 | Yes: as SRC-068 | standards/http-tls.md §6, §6.6; REQ-IMG-053, REQ-RBAC-005 (standards cites) |
| SRC-071 | NIST CSRC publication page: SP 800-52 Rev. 2, TLS guidelines | https://csrc.nist.gov/pubs/sp/800/52/r2/final | 2026-10-26 | Yes: anonymous fetch of public NIST page. **PDF text not read** (not extractable with the available tools); abstract only | standards/http-tls.md §7 [primary not read]; REQ-IMG-053 (standards cite only, [primary not read]; no longer its Source after fix round 1, CR-507) |
| SRC-072 | IETF RFC 5280, X.509 PKI Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc5280 | 2026-10-26 | Yes: as SRC-068 | standards/security-baseline.md §2; REQ-RBAC-005 (standards cite: path validation) |
| SRC-073 | NIST CSRC: FIPS 186-5 publication page, and Digital Signatures project page | https://csrc.nist.gov/pubs/fips/186-5/final ; https://csrc.nist.gov/projects/digital-signatures | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §1 [primary not read] |
| SRC-074 | NIST CSRC publication page: SP 800-186, elliptic curve domain parameters | https://csrc.nist.gov/pubs/sp/800/186/final | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §1 |
| SRC-075 | NIST CSRC publication page: SP 800-57 Part 1 Rev. 5 | https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §3 [primary not read] |
| SRC-076 | NIST CSRC publication page: FIPS 201-3, PIV | https://csrc.nist.gov/pubs/fips/201-3/final | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §4.1 [primary not read] |
| SRC-077 | NIST CSRC publication page: SP 800-73-5 Part 1, PIV interfaces | https://csrc.nist.gov/pubs/sp/800/73/pt1/5/final | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §4.1 [primary not read] |
| SRC-078 | NIST SP 800-63B, Digital Identity Guidelines: Authentication and Lifecycle Management (HTML edition, page dated 2025-08-26) | https://pages.nist.gov/800-63-4/sp800-63b.html | 2026-10-26 | Yes: anonymous fetch of NIST's public HTML edition. First 100,000 characters read (sections 2 and 3, which hold the cited material) | standards/security-baseline.md §4.2; REQ-RBAC-005 (standards cite, background); operator-access.md OPEN-ACC-1 |
| SRC-079 | NIST CSRC publication page: SP 800-131A Rev. 2 | https://csrc.nist.gov/pubs/sp/800/131/a/r2/final | 2026-10-26 | Yes: as SRC-071. **PDF not read** | standards/security-baseline.md §3 (note on the Rev. 3 draft only) |
| SRC-080 | UEFI Specification 2.10, chapter 5 (GUID Partition Table Disk Layout) | https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html | 2026-10-27 | Yes: as SRC-019 | standards/gpt.md §2 to §8; REQ-DISK-009, REQ-DISK-010 |
| SRC-081 | UEFI Specification 2.10, chapter 1 (Introduction), §1.9.1 data structure byte order; chapter 2 §2.3.1 bit order | https://uefi.org/specs/UEFI/2.10/01_Introduction.html ; https://uefi.org/specs/UEFI/2.10/02_Overview.html | 2026-10-27 | Yes: as SRC-019 | standards/gpt.md §1; M3 build (chapter 2 re-fetched 2026-10-28 for §2.1.1 UEFI images: PE32+ format, machine type values, subsystem values): standards/winpe.md §10; §1.9.1 (not re-fetched; as summarised in gpt.md §1): standards/uefi-boot-manager.md §10.1, winpe.md §10 byte-order reading |
| SRC-082 | UEFI Specification 2.10, chapter 4 (EFI System Table), §4.2.1 CRC algorithm note | https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html | 2026-10-27 | Yes: as SRC-019 | standards/gpt.md §6 (OPEN-GPT-1) |
| SRC-083 | UEFI Specification 2.10, chapter 13 (Protocols: Media Access), §13.3 file system format, partition discovery, system partitions | https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html | 2026-10-27 | Yes: as SRC-019 (first 100,000 characters read; §13.3 was within them) | standards/gpt.md §11, §12 |
| SRC-084 | Microsoft Learn: UEFI/GPT-based hard drive partitions (updated 2026-09-09) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/configure-uefigpt-based-hard-drive-partitions | 2026-10-27 | Yes: as SRC-048 | standards/gpt.md §10; REQ-DISK-004, REQ-DISK-008, REQ-DISK-011 |
| SRC-085 | Microsoft Learn: Windows and GPT FAQ (2017; updated 2022) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-and-gpt-faq | 2026-10-27 | Yes: as SRC-048 | standards/gpt.md §3, §5, §9, §10, §11 (OPEN-GPT-2); REQ-DISK-005 (basis only), REQ-DISK-008, REQ-DISK-009 |
| SRC-086 | Microsoft Learn: PARTITION_INFORMATION_GPT structure (Win32) | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-partition_information_gpt | 2026-10-27 | Yes: as SRC-048 | standards/gpt.md §9; REQ-DISK-008 |
| SRC-087 | Microsoft Learn: Deployment lab sample scripts (Windows 11 view; updated 2025-07-29) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/oem-deployment-of-windows-desktop-editions-sample-scripts | 2026-10-27 | Yes: as SRC-048. Scripts were read for facts only (order, sizes, types, attribute values, confirm-before-erase); no script text was copied | standards/gpt.md §10; REQ-DISK-006, REQ-DISK-007, REQ-DISK-008; REQ-TGT-006 |
| SRC-088 | Microsoft Learn: Capture and Apply Windows using a WIM file (reached from the "apply-images-using-dism" URL; updated 2025-09-04) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/capture-and-apply-windows-using-a-single-wim | 2026-10-27 | Yes: as SRC-048 | standards/uefi-boot-manager.md §9.1; REQ-PE-017; REQ-BOOT-066 |
| SRC-089 | Microsoft Learn: BCDBoot Command-Line Options (updated 2026-03-23) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di | 2026-10-27 | Yes: as SRC-048 | standards/uefi-boot-manager.md §9 (OPEN-UBM-1); REQ-BOOT-065 (basis), REQ-BOOT-066 |
| SRC-090 | Microsoft Learn: BCD System Store Settings for UEFI | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcd-system-store-settings-for-uefi | 2026-10-27 | Yes: as SRC-048 | standards/uefi-boot-manager.md §9.1, §9.2; standards/winpe-network-boot.md §5 (UEFI loader path) |
| SRC-091 | Microsoft Learn: Configure a PXE server to load Windows PE (Windows 10; dated 2022-11-23, updated 2025-06-04) | https://learn.microsoft.com/en-us/windows/deployment/configure-a-pxe-server-to-load-windows-pe | 2026-10-27 | Yes: as SRC-048 | standards/winpe-network-boot.md §1, §2, §3, §5, §8; REQ-PE-011, REQ-PE-012; REQ-BOOT-063, REQ-BOOT-064 |
| SRC-092 | Microsoft Learn (archive, Windows Server 2008): How Booting into a Boot Image Works | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc771845(v=ws.10) | 2026-10-27 | Yes: anonymous fetch of public Microsoft Learn archive page. Old (2012); marked [archive] | standards/winpe-network-boot.md §3, §4; REQ-PE-011; REQ-BOOT-063 |
| SRC-093 | Microsoft Learn (archive, Windows Server 2008/R2): How to Modify the BCD Store Using Bcdedit (Windows Deployment Services) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc731245(v=ws.10) | 2026-10-27 | Yes: as SRC-092. Marked [archive] | standards/winpe-network-boot.md §5 (TFTP block and window size settings and defaults); REQ-BOOT-064 |
| SRC-094 | Microsoft Learn support article: PXE boot in Configuration Manager (dated 2026-03-30) | https://learn.microsoft.com/en-us/troubleshoot/mem/configmgr/os-deployment/understand-pxe-boot | 2026-10-27 | Yes: as SRC-048. Microsoft's documentation of its own product; used only for its generic description of Microsoft's network boot programs (UEFI boot manager role) and the TFTP option example; marked [support article] | standards/winpe-network-boot.md §3, §5; REQ-BOOT-063 |
| SRC-095 | Microsoft Learn: Winpeshl.ini Reference: Launching an app when WinPE starts | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpeshlini-reference-launching-an-app-when-winpe-starts | 2026-10-27 | Yes: as SRC-048 | standards/winpe.md §5.1; REQ-PE-013 |
| SRC-096 | Microsoft Learn: Wpeutil Command-Line Options (updated 2023-08-15) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/wpeutil-command-line-options | 2026-10-27 | Yes: as SRC-048 | standards/winpe.md §5.2, §5.3; REQ-PE-014, REQ-PE-020; REQ-DISK-005 (basis only), REQ-DISK-011 |
| SRC-097 | Microsoft Learn: WinPE Network Drivers: Initializing and adding drivers | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-network-drivers-initializing-and-adding-drivers | 2026-10-27 | Yes: as SRC-048 | standards/winpe.md §5.2; REQ-PE-014 |
| SRC-098 | Microsoft Learn: WinPE: Install on a Hard Drive (Flat Boot or Non-RAM) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/winpe-install-on-a-hard-drive--flat-boot-or-non-ram | 2026-10-27 | Yes: as SRC-048 | standards/winpe.md §5.1 (wpeinit runs automatically), §9 |
| SRC-099 | Microsoft Learn: Windows 11 requirements (dated 2026-07-14) | https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements | 2026-10-27 | Yes: as SRC-048 | standards/gpt.md §13; REQ-DISK-004 |
| SRC-100 | UEFI Specification 2.10, chapter 10 (Device Path Protocol) | https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html | 2026-10-28 | Yes: as SRC-019 (read in two parts, offsets 0 and 100,000) | standards/uefi-boot-manager.md §10.4 (§10.2, §10.3.1), §10.5 (§10.3.5.1, Table 10.54), §10.6 (§10.3.5.4, Table 10.57), §10.7 (§10.4.5), OPEN-UBM-2; §10.5 (UEFI §10.6 text form of the Hard Drive node) |
| SRC-101 | UEFI Specification 2.10, chapter 8 (Services: Runtime Services), §8.2 variable services | https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html | 2026-10-28 | Yes: as SRC-019 | standards/uefi-boot-manager.md §10.3 (attribute bit values, SetVariable rules) |
| SRC-102 | Microsoft Learn: PE Format (Win32) | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format | 2026-10-28 | Yes: as SRC-048 (first 100,000 characters read). The fetch tool's own general-knowledge remark on byte order was not used | standards/winpe.md §10 |
| SRC-103 | Microsoft Learn: SetupDiGetClassDevsW function | https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw | 2026-10-28 | Yes: as SRC-048. Sample code on the page not copied | standards/windows-storage-firmware-api.md §2 |
| SRC-104 | Microsoft Learn: SetupDiGetDeviceInterfaceDetailW function | https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §2 |
| SRC-105 | Microsoft Learn: GUID_DEVINTERFACE_DISK | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §2 |
| SRC-106 | Microsoft Learn: IOCTL_STORAGE_QUERY_PROPERTY | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_query_property | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3 |
| SRC-107 | Microsoft Learn: STORAGE_PROPERTY_QUERY structure | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_property_query | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3 |
| SRC-108 | Microsoft Learn: STORAGE_PROPERTY_ID enumeration | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_property_id | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3 ([enum] value 6) |
| SRC-109 | Microsoft Learn: STORAGE_DEVICE_DESCRIPTOR structure | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_descriptor | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3.1, §11 |
| SRC-110 | Microsoft Learn: STORAGE_BUS_TYPE enumeration | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-storage_bus_type | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3.2, §11 ([enum] values); disk.md OPEN-DISK-4, OPEN-DISK-5 background |
| SRC-111 | Microsoft Learn: STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR structure | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_access_alignment_descriptor | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §3.3 |
| SRC-112 | Microsoft Learn: IOCTL_DISK_GET_DRIVE_GEOMETRY_EX | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_drive_geometry_ex | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §4 |
| SRC-113 | Microsoft Learn: DISK_GEOMETRY_EX structure | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_geometry_ex | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §4 |
| SRC-114 | Microsoft Learn: DISK_GEOMETRY structure | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_geometry | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §4 |
| SRC-115 | Microsoft Learn: MEDIA_TYPE enumeration | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ne-winioctl-media_type | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §4 ([enum] values 11, 12) |
| SRC-116 | Microsoft Learn: IOCTL_DISK_GET_LENGTH_INFO | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_get_length_info | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §4 |
| SRC-117 | Microsoft Learn: IOCTL_DISK_CREATE_DISK, CREATE_DISK and CREATE_DISK_GPT | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_create_disk ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-create_disk ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-create_disk_gpt | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §5 |
| SRC-118 | Microsoft Learn: IOCTL_DISK_SET_DRIVE_LAYOUT_EX | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_set_drive_layout_ex | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §5 |
| SRC-119 | Microsoft Learn: DRIVE_LAYOUT_INFORMATION_EX, DRIVE_LAYOUT_INFORMATION_GPT and PARTITION_INFORMATION_EX structures | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-drive_layout_information_ex ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-drive_layout_information_gpt ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-partition_information_ex | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §5, OPEN-WAPI-3 |
| SRC-120 | Microsoft Learn: IOCTL_DISK_UPDATE_PROPERTIES | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_update_properties | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §5 |
| SRC-121 | Microsoft Learn: IOCTL_DISK_IS_WRITABLE | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_disk_is_writable | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §6, §11, OPEN-WAPI-2 |
| SRC-122 | Microsoft Learn: IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS and VOLUME_DISK_EXTENTS | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_volume_get_volume_disk_extents ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-volume_disk_extents ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-disk_extent (added in the fix round, CR-005 and the boot reviewer note) | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §7 reading, §8; §13 (SR-3b, not re-fetched; the ERROR_MORE_DATA case and the Win32 page's SMB 3.0 remark) |
| SRC-123 | Microsoft Learn: IOCTL_STORAGE_GET_DEVICE_NUMBER and STORAGE_DEVICE_NUMBER | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-ioctl_storage_get_device_number ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_device_number | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §7; §13 (SR-3b, not re-fetched; DeviceType names) |
| SRC-124 | Microsoft Learn: FindFirstVolumeW function | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstvolumew | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §8 |
| SRC-125 | Microsoft Learn: SetVolumeMountPointW function (winbase.h) | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setvolumemountpointw | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §8 |
| SRC-126 | Microsoft Learn: Naming a Volume | https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-volume | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §8 |
| SRC-127 | Microsoft Learn: GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW functions | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariableexw ; https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexw | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §9 |
| SRC-128 | Microsoft Learn: AdjustTokenPrivileges function | https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §10 |
| SRC-129 | Microsoft Learn: Privilege Constants (Winnt.h) | https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants | 2026-10-28 | Yes: as SRC-048. Sample code on the page not copied | standards/windows-storage-firmware-api.md §10 |
| SRC-130 | Microsoft Learn support article: Support policy for 4K sector hard drives (dated 2026-02-12; former KB 2510009) | https://learn.microsoft.com/en-us/troubleshoot/windows-server/backup-and-storage/support-policy-4k-sector-hard-drives | 2026-10-28 | Yes: as SRC-048. Microsoft's support policy for Windows, marked [support article] in use | standards/windows-storage-firmware-api.md §3.3, §11; disk.md OPEN-DISK-5 (b) background |
| SRC-131 | Microsoft Learn (Windows drivers): IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS (ntddvol.h) | https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddvol/ni-ntddvol-ioctl_volume_get_volume_disk_extents | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §13 (buffer status cases; availability by media type), OPEN-WAPI-4 |
| SRC-132 | Microsoft Learn: GetDriveTypeW function | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getdrivetypew | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §13 |
| SRC-133 | Microsoft Learn: FSCTL_LOCK_VOLUME and FSCTL_DISMOUNT_VOLUME | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume ; https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §14, OPEN-WAPI-5 |
| SRC-134 | Microsoft Learn: GetVolumePathNamesForVolumeNameW, DeleteVolumeMountPointW and GetVolumeInformationW functions | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumepathnamesforvolumenamew ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletevolumemountpointw ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §15 |
| SRC-135 | Microsoft Learn: GetNativeSystemInfo, SYSTEM_INFO, GlobalMemoryStatusEx, MEMORYSTATUSEX, GetSystemDirectoryW | https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getnativesysteminfo ; https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info ; https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-globalmemorystatusex ; https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-memorystatusex ; https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw | 2026-10-28 | Yes: as SRC-048. Sample code on the GlobalMemoryStatusEx page not copied. The SYSTEM_INFO page is the same page as SRC-067 (fetched again here) | standards/windows-storage-firmware-api.md §16 |
| SRC-136 | Microsoft Learn: GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH, IP_ADAPTER_UNICAST_ADDRESS_LH, SOCKET_ADDRESS | https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses ; https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh ; https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_unicast_address_lh ; https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-socket_address | 2026-10-28 | Yes: as SRC-048. The long sample programs on two pages were not copied or summarised | standards/windows-storage-firmware-api.md §17 |
| SRC-137 | Microsoft Learn (Windows Console): GetStdHandle, GetConsoleMode, SetConsoleMode | https://learn.microsoft.com/en-us/windows/console/getstdhandle ; https://learn.microsoft.com/en-us/windows/console/getconsolemode ; https://learn.microsoft.com/en-us/windows/console/setconsolemode | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §18 |
| SRC-138 | Microsoft Learn: FindFirstStreamW, FindNextStreamW, WIN32_FIND_STREAM_DATA, FindFirstFileNameW, FindNextFileNameW | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextstreamw ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-win32_find_stream_data ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilenamew ; https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilenamew | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §19, OPEN-WAPI-6 |
| SRC-139 | Microsoft Learn: GetFileSecurityW, ConvertSecurityDescriptorToStringSecurityDescriptorW, GetFileInformationByHandleEx, FILE_ATTRIBUTE_TAG_INFO | https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-getfilesecurityw ; https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsecuritydescriptortostringsecuritydescriptorw ; https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex ; https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info | 2026-10-28 | Yes: as SRC-048 | standards/windows-storage-firmware-api.md §19 |
| SRC-140 | Microsoft Open Specifications: [MS-FSCC] File System Control Codes, landing page (revision 60.0, 2025-11-21; IP rights notice) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/efbfe127-73ad-4140-9967-ec6500e66d5e | 2026-10-28 | Yes: anonymous fetch of public Microsoft Learn page, no login or click-through; the notice permits copies for implementation | standards/reparse-and-security-descriptors.md Sources (AUDITED 2026-10-28) |
| SRC-141 | [MS-FSCC]: Reparse Tags | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4 | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §1 (AUDITED 2026-10-28) |
| SRC-142 | [MS-FSCC]: REPARSE_DATA_BUFFER | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c3a420cb-8a72-4adf-87e8-eee95379d78f | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §2 (AUDITED 2026-10-28) |
| SRC-143 | [MS-FSCC]: Mount Point Reparse Data Buffer (§2.1.2.5) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca069dad-ed16-42aa-b057-b6b207f447cc | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §3, §5 (AUDITED 2026-10-28) |
| SRC-144 | [MS-FSCC]: Symbolic Link Reparse Data Buffer (§2.1.2.4) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/b41f1cbf-10df-4a47-98d4-1c52a833d913 | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §4, §5 (AUDITED 2026-10-28) |
| SRC-145 | [MS-FSCC]: Pathname (§2.1.5) and Dot Directory Names (§2.1.5.1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ffb795f3-027d-4a3c-997d-3085f2332f6f ; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/fccd0313-0364-45bd-b75c-924fd6a5662f | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §5, OPEN-RPSD-2 (AUDITED 2026-10-28) |
| SRC-146 | Microsoft Learn (Windows drivers): REPARSE_DATA_BUFFER structure (ntifs.h) | https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer | 2026-10-28 | Yes: as SRC-048. Structure declaration on the page not copied | standards/reparse-and-security-descriptors.md §2 (third-party form out of scope), §5 (background) (AUDITED 2026-10-28) |
| SRC-147 | Microsoft Learn: FSCTL_SET_REPARSE_POINT control code | https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_reparse_point | 2026-10-28 | Yes: as SRC-048. Sample code not copied | standards/reparse-and-security-descriptors.md §6, OPEN-RPSD-1 (AUDITED 2026-10-28) |
| SRC-148 | Microsoft Open Specifications: [MS-DTYP] Windows Data Types, landing page (revision 42.0, 2024-11-19; IP rights notice) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/cca27429-5689-4a16-b2b4-9325d93e4ba2 | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md Sources (AUDITED 2026-10-28) |
| SRC-149 | [MS-DTYP]: SECURITY_DESCRIPTOR (§2.4.6) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7d4dac05-9cef-4563-a058-f108abecce1d | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md byte order, §9, OPEN-RPSD-4 (AUDITED 2026-10-28) |
| SRC-150 | [MS-DTYP]: SID (§2.4.2), SID packet representation (§2.4.2.2), SID_IDENTIFIER_AUTHORITY | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25 ; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861 ; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §7 (AUDITED 2026-10-28) |
| SRC-151 | [MS-DTYP]: ACL | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428 | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §8 (AUDITED 2026-10-28) |
| SRC-152 | [MS-DTYP]: ACE_HEADER (§2.4.4.1) | https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586 | 2026-10-28 | Yes: as SRC-140 | standards/reparse-and-security-descriptors.md §8 (AUDITED 2026-10-28) |
| SRC-153 | Microsoft Learn (Windows drivers): SECURITY_DESCRIPTOR_CONTROL | https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/security-descriptor-control | 2026-10-28 | Yes: as SRC-048 | standards/reparse-and-security-descriptors.md §9 (flag masks, 0x0040 naming note), §10 (absent DACL) (AUDITED 2026-10-28) |

## Consulted, not used

| Title | URL | Accessed (UTC date) | Reason not used |
|-------|-----|---------------------|-----------------|
| Vendor online user guide (help/resource center) | https://help.tanium.com/bundle/ug_provision_cloud/page/provision/index.html (redirect target of https://docs.tanium.com/provision/provision/index.html) | 2026-10-25 | Page is script-rendered; anonymous fetch returned only an empty shell with no product content. Re-try with a rendering-capable fetch in a later run if still login-free. If it is used, take user-visible behaviour only (see the rules above). Not retried in the M1 run. |
| Vendor privacy datasheet (PDF) | https://site.tanium.com/rs/790-QFJ-925/images/Tanium-Provision-Privacy-Datasheet.pdf | 2026-10-25 | Redirected to vendor home page; content not retrieved. |
| Vendor blog: Tech Talks #55 | https://www.tanium.com/blog/tanium-provision-part-1-tech-talks-55/ | 2026-10-25 | Public, but contained no capability detail (video only). |
| Public web search, fix round 1 (query on the vendor's bare-metal provisioning solution brief) | n/a (search engine results page) | 2026-10-25 | Run only to confirm SRC-003 can be reached from a public search (CR-007). The search tool's result summary included snippet text from SRC-003's relay section. That text was not used. RELAY-1 and RELAY-2 were rewritten in fix round 1 from the behavioural idea, with a new structure, and not from the snippet or the PDF. Disclosed in the run's spec report. |
| Competitor comparison page (ManageEngine) | https://www.manageengine.com/uk/products/desktop-central/endpoint-central-vs-tanium.html | 2026-10-25 | Seen only as a search-result snippet; competitor claim, not authoritative. Not fetched or used. |
| UEFI Forum related-documents page | https://uefi.org/uefi | 2026-10-25 | Used only to find where the UEFI Forum points readers for the PXE 2.1 specification (a third-party copy at pix.net). No behaviour taken from it. |
| Intel PXE Specification 2.1, copy linked by the UEFI Forum | http://www.pix.net/software/pxeboot/archive/pxespec.pdf (also tried over https) | 2026-10-25 | Fetch failed with no response. Not read. |
| Intel PXE Specification 2.1, university wiki copy | https://wiki.cs.umbc.edu/images/3/3d/Pxespec.pdf | 2026-10-25 | TLS certificate rejected; not read. Its origin and redistribution terms are unverified, so it was not pursued further. |
| Intel PXE Specification 2.1, Intel download URL | https://download.intel.com/design/archives/wfm/downloads/pxespec.pdf | 2026-10-25 | HTTP 403. Not read. |
| Internet Archive copy of the pix.net PXE PDF | https://web.archive.org/web/2020id_/http://www.pix.net/software/pxeboot/archive/pxespec.pdf | 2026-10-25 | Fetch tool cannot reach web.archive.org. Not read. |
| IETF draft-viswanathan-remote_boot-protocol-00 (earlier Intel PXE draft) | https://datatracker.ietf.org/doc/html/draft-viswanathan-remote_boot-protocol-00 ; https://potaroo.net/ietf/idref/draft-viswanathan-remote_boot-protocol | 2026-10-25 | 404 and fetch failure. Superseded by SRC-018 in any case. |
| dnsmasq manual page | https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html ; https://dnsmasq.org/docs/dnsmasq-man.html | 2026-10-25 | Fetch failed; not read. |
| ISC DHCP PXE option definitions file (NetBSD and Minix source mirrors) | https://ftp.riken.jp/NetBSD/NetBSD-current/src/external/mpl/dhcp/share/dhcpd/pxe.defs ; https://src.rcs.uwaterloo.ca/xref/minix3/external/bsd/dhcp/share/dhcpd/pxe.defs | 2026-10-25 | Connection refused; not read. A search-result summary described its discovery-control bit list. That summary was not relied on; bit 3 rests on SRC-034 and SRC-035 and is marked secondary. |
| Cisco support document: Understanding and troubleshooting PXE boot (ACI) | https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/application-policy-infrastructure-controller-apic/212041-Understanding-and-Troubleshooting-PXE-bo.html | 2026-10-25 | Public; read. Third-party product-specific detail that added nothing beyond SRC-024. Not used. |
| Public web searches, M1 run (three queries: PXE 2.1 specification copy; ProxyDHCP port 4011 with option 60; PXE discovery-control bit 3) | n/a (search engine results pages) | 2026-10-25 | Used only to find standards copies and public references. No query named the vendor or its product. The result summaries quoted open-source project text (iPXE, ISC DHCP) and Microsoft KB text, not vendor text. Nothing was copied from the summaries. |
| Public web search, standards-notes run (query on the SMBIOS System UUID byte order, not limited to one site) | n/a (search engine results page) | 2026-10-26 | The results were QEMU and FreeBSD commit pages and mailing-list posts (open-source code, not vendor). None were fetched. No code was read or used. Fix round 1 (CR-201): the uefi-guid-text.md §4 statement drawn from this summary was removed, and nothing from this search is used in any spec. |
| Public web search, standards-notes run (dmtf.org only, on the SMBIOS UUID byte-order example) | n/a (search engine results page) | 2026-10-26 | Used only as the content route for SRC-043 (see that row). The summary's example values come from the DMTF text, so they were not copied. uefi-guid-text.md uses its own made-up example. |
| DMTF DSP0268 Redfish Data Model Specification 2023.1 (HTML) | https://www.dmtf.org/sites/default/files/standards/documents/DSP0268_2023.1.html | 2026-10-26 | HTTP 403. Not read. |
| Vendor online user guide, retried in M2 run | https://help.tanium.com/bundle/ug_provision_cloud/page/provision/index.html | 2026-10-26 | Still an empty script-rendered shell (navigation only, no product content). Nothing used. |
| SRC-002 and SRC-009, re-fetched in M2 run | see rows SRC-002, SRC-009 | 2026-10-26 | Paraphrase-only prompts. Neither said anything about images, packages, Windows PE, supported editions, roles or audit. Nothing used in M2. |
| [MS-XCA] PDF (Microsoft Open Specifications download) | https://winprotocoldoc.z19.web.core.windows.net/MS-XCA/%5bMS-XCA%5d.pdf (redirect from the azurefd.net link on the landing page) | 2026-10-26 | Downloaded anonymously, but its text could not be extracted and no PDF renderer is available. The HTML pages (SRC-053) were used instead. |
| NIST SP 800-53 Rev. 5: CSRC publication page and PDF | https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final ; https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf | 2026-10-26 | Public, no login. The PDF text could not be extracted, so no control text was read. Not cited; `operator-access.md` says the audit requirements rest on the project's own requirement, not on this text. |
| Microsoft Learn: Prepare a PXE server for UEFI boot (guessed URL) | https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/prepare-a-pxe-server-for-uefi-boot | 2026-10-26 | HTTP 404. Not read. WinPE network boot left for M3 (`winpe.md` §8). |
| Vendor online user guide, retried in M3 run | https://help.tanium.com/bundle/ug_provision_cloud/page/provision/index.html | 2026-10-27 | Still an empty script-rendered shell (navigation and a search-results heading only). Nothing used. |
| Microsoft Learn: SetVolumeMountPointW under fileapi.h (guessed URL) | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setvolumemountpointw | 2026-10-28 | HTTP 404. The function is documented under winbase.h (SRC-125). |
| DMTF DSP0134 3.8.0 PDF | https://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.8.0.pdf | 2026-10-28 | Public, anonymous download. Text not extractable (fetch tool cannot decompress; no local PDF renderer). Logged under SRC-043; content came only from the dmtf.org-limited search summary. |
| Public web search, M3 build run (dmtf.org only, on the SMBIOS System UUID byte order) | n/a (search engine results page) | 2026-10-28 | Content route for SRC-043 only. The summary's example values come from the DMTF text and were not copied; `smbios.md` refers to the made-up example in `uefi-guid-text.md`. |
| Public web searches, SR-3b (two queries, learn.microsoft.com only: volume-extents error for CD-ROM or RAM-disk volumes; NT status to Win32 error mapping) | n/a (search engine results pages) | 2026-10-28 | No query named the vendor or its product. Summaries contained the search tool's own guesses and links to Microsoft Q&A posts; none were fetched or used. Only the ntddvol driver page found through the first search was fetched (SRC-131). |
| Public web searches, SR-6 (three queries, learn.microsoft.com only: the [MS-FSCC] symbolic-link buffer and relative flag; an [MS-FSCC] byte-order statement; the [MS-DTYP] self-relative descriptor) | n/a (search engine results pages) | 2026-10-28 | No query named the vendor or its product. Used only to find page URLs, which were then fetched (SRC-141 to SRC-153). The summaries also cited [MS-SMB2], [MS-CFB], [MS-ECS] and other pages; none of those were fetched or used. No [MS-FSCC] byte-order statement was found, which is why topic 24 marks the reparse byte order as [reading]. |
| Microsoft Learn: BCDEdit /set (Windows drivers) | https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set | 2026-10-27 | Public. Read for RAM-disk TFTP settings; the page does not document them. Nothing used. |
| Public web searches, M3 run (three queries, all limited to learn.microsoft.com: PXE server for Windows PE with the UEFI boot manager and RAM-disk files; RAM-disk TFTP block and window size; UEFI network boot program file names) | n/a (search engine results pages) | 2026-10-27 | No query named the vendor or its product. Used only to find Microsoft pages, then fetched and logged as SRC-091 to SRC-094. Result summaries also drew on Microsoft Q&A and archived forum threads (community posts, some quoting third-party product settings); none were fetched and nothing from them was used. The block-size defaults in `winpe-network-boot.md` come from SRC-093 itself, not from the summaries. |
| Public web searches, M2 run (eight queries, all on Microsoft or NIST documentation: WIM format paper; WIMGetImageInformation XML; MS-XCA decompression; MS-PATCH LZXD sections (two queries); the Cabinet SDK LZX document; Windows PE redistribution licensing; MS-DTYP DWORD byte order) | n/a (search engine results pages) | 2026-10-26 | No query named the vendor or its product. Used only to find Microsoft pages, which were then fetched and logged as SRC-046 to SRC-063. Some result lists included third-party WIM and LZX tools and open-source decoder code (wimlib documentation, Wine, ReactOS and libmspack sources, a WIM parser crate); none were fetched and nothing from them was used. One result summary mentioned a Microsoft errata page for [MS-XCA] §2.2.4; it was not fetched. The MS-DTYP search found no statement of byte order, which is why `wim.md` §9 is OPEN-WIM-1. |
