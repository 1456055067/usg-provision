# WIM format: observations from our own DISM-made files

This file records facts about the WIM format that Microsoft's public
documentation does not state, observed in WIM files the project builds
itself with Microsoft's DISM (decision
[0006](../decisions/0006-wim-format-by-black-box-test-files.md); M2
scope by decision
[0014](../decisions/0014-m2-wim-compression-scope.md)). It complements
the standards summaries
[specs/standards/wim.md](../../specs/standards/wim.md) and
[specs/standards/wim-compression.md](../../specs/standards/wim-compression.md),
whose OPEN items it settles one record at a time.

**Status: template only. No observation has been recorded yet.** The
records below are placeholders. They are filled in after the
`wim-samples` workflow has run on GitHub and its artifact has been
examined; until then every OPEN item stays open, and parser constants
that depend on one stay marked `// FORMAT: derived, unconfirmed`.

## Contents

- [Provenance rules](#provenance-rules)
- [Method](#method)
- [Record template](#record-template)
- [Runs examined](#runs-examined)
- [Open items and samples](#open-items-and-samples)
- [Observations](#observations)

## Provenance rules

1. **Only our own files.** A record may cite only a sample built by
   `scripts/wim-samples/Build-Samples.ps1` from a tree written by
   `scripts/wim-samples/New-SampleTree.ps1`, on a GitHub-hosted Windows
   runner (or, if stated, a named project Windows machine). Samples are
   never downloaded from anywhere else and never committed.
2. **Only Microsoft's tools and documentation.** No third-party WIM,
   XPRESS, LZX or LZMS implementation, its source, tests or
   documentation may be read, run or compared against (decision 0006
   item 2). A record never cites one.
3. **Bytes, not readings.** Each record quotes the raw bytes (hex) at a
   stated file offset of a stated sample. The labelled fields printed by
   `Dump-WimStructure.ps1` are a reading aid; they rest on the
   [derived] offsets of `wim.md` and are not evidence by themselves.
4. **Full identity of the sample.** Each record gives the sample ID, the
   exact command line from `commands.log`, the host OS build and the
   `Dism.exe` version from `host.txt`, the runner image version, the
   workflow run ID and attempt, and the commit the run built.
5. **One claim per record.** A record settles at most one OPEN item, or
   one part of one. A claim seen in only one sample says so; a claim
   that generalises (for example "all multi-byte fields are
   little-endian") cites every sample it was checked in.
6. **Conclusions stay narrow.** A record states what was observed in
   these files. It does not claim behaviour of other DISM versions,
   other Windows builds, or files made by other tools.
7. **Records are append-only.** A record found wrong is marked
   `Withdrawn` with the reason and the record that replaces it; it is
   never edited away. Parser code citing a withdrawn record is fixed in
   the same change.
8. **Citation from code.** A parser constant or rule that rests on a
   record carries `// FORMAT: OBS-nnn` (or a `wim.md` section). One that
   rests on neither stays `// FORMAT: derived, unconfirmed` and is
   listed in the QA report.
9. **No clean-room names.** Records, samples and dumps must pass the
   name scan; the workflow scans the artifact before upload.

## Method

1. Run the workflow (see
   [scripts/wim-samples/README.md](../../scripts/wim-samples/README.md),
   "Running"):

   ```sh
   gh workflow run wim-samples.yml --ref <branch> -f large=true
   ```

2. Download both artifacts of that run into `target/` (never committed):
   `gh run download <run-id> -n wim-samples` and
   `-n wim-samples-large-observations`.
3. Check `SHA256SUMS` (`sha256sum -c SHA256SUMS`) and that every row of
   `manifest.tsv` is `produced`.
4. Add the run to [Runs examined](#runs-examined) with the identity
   fields from `host.txt`.
5. For each OPEN item in the table below, read the named section of the
   named `.dump.txt` (or the sample file itself, with any hex viewer),
   and write one record per claim using the template. Quote at least
   the bytes the claim depends on.
6. Update the status column of the OPEN-item table to the record IDs.
   Change `wim.md` or `wim-compression.md` only through the spec
   process; this file does not edit specs.
7. When a later run (new runner image or DISM version) shows the same
   bytes, add its run ID to the record's "Also seen in" line; when it
   differs, add a new record and note the difference.

## Record template

Copy this block for each new record. Fields in angle brackets are
required; "n/a" is allowed only where stated.

```text
### OBS-<nnn>: <one-line claim>

- Status:        Recorded | Withdrawn (<reason>, replaced by OBS-<nnn>)
- Settles:       <OPEN-WIM-n / OPEN-WIMC-n, or "partly: <which part>">
- Sample:        <S01..S09> (<file name>, sha256 <hex>)
- Command:       <exact line from commands.log>
- Source tree:   <tree name, seed, profile; file paths from trees.txt if relevant>
- Host:          <OS version string; CurrentBuild.UBR> (host.txt)
- DISM:          <Dism.exe FileVersion> (host.txt)
- Runner image:  <ImageOS ImageVersion> (host.txt; "n/a, local machine <name>" if not CI)
- Run:           <workflow run ID>, attempt <n>, commit <sha>
- Location:      file offset <decimal> (0x<hex>), length <n> bytes
- Bytes:         <hex as in the dump, or a hex dump block below>
- Observation:   <what the bytes show, without interpretation beyond them>
- Conclusion:    <the narrow claim>
- Also seen in:  <other samples / runs, or "none">
- Cited by:      <code paths with // FORMAT: OBS-nnn, or "none yet">
```

## Runs examined

| Run ID | Attempt | Commit | Runner image | OS build | DISM version | Date (UTC) |
|--------|---------|--------|--------------|----------|--------------|------------|
| (none yet) | | | | | | |

## Open items and samples

Status `pending` means no record exists yet. Questions listed here are
those of `wim.md` section 13 and `wim-compression.md` section 7 that
the samples can address; the samples are defined in
[scripts/wim-samples/README.md](../../scripts/wim-samples/README.md).

| Item | Question (short) | Samples | Dump section | Status |
|------|------------------|---------|--------------|--------|
| OPEN-WIM-1 | Byte order of multi-byte fields | S01, S02 | header, lookup | pending |
| OPEN-WIM-2 | Values of the version field | S01, S02, S03, S07 | header (`@12`) | pending |
| OPEN-WIM-3 | What the field at offset 20 holds | S01, S02, S04 | header (`@20`) | pending |
| OPEN-WIM-4 | Flags of `recovery` (`.esd`) output | S07 | header (`@16`), lookup | pending |
| OPEN-WIM-5 | How an incompressible chunk is stored | S09 (with `trees.txt` chunk bytes), S02 | chunks | pending |
| OPEN-WIM-6 | Lookup entry packing; metadata entry to image index | S01, S04 | lookup, metadata, xml | pending |
| OPEN-WIM-7 | Directory entry alignment, short names | S01 | metadata | pending (needed only when applying images; M2 does not) |
| OPEN-WIM-8 | Content of `NAME`, `DESCRIPTION`, `FLAGS`, `WINDOWS` | S04 | xml | pending (our samples hold our files, not a Windows installation; edition, architecture and version facts cannot be observed from them, see decision 0013) |
| OPEN-WIM-9 | How parts of a split set are matched | S06 parts | header (`@24`, `@40`, `@42`) | pending |
| OPEN-WIM-10 | Chunk-table entry width above 4 GB | S08 (large observations artifact) | chunks (width 4 and 8 checks) | pending (S08 is 4.5 GiB, so it shows the width above the threshold, not where the threshold is) |
| OPEN-WIM-11 | Integrity chunk size unit; hashed range | S05 | integrity | pending |
| OPEN-WIMC-1 | WIM XPRESS is [MS-XCA] LZ77+Huffman; block rule; end symbol | S02, S04, S09 | chunks (first chunk: 256-byte table and first symbols) | pending (also needs the WU-X decoder to decode the S02 resources to their lookup SHA-1) |
| LZX flag | Header flag value DISM writes for `max` | S03 | header (`@16`) | pending |
| Split flags | Header and resource flags of `.swm` parts | S06 parts | header, lookup | pending |

## Observations

No observations have been recorded. The first records are expected
after the first `wim-samples` run; their IDs start at OBS-001.

<!--
Placeholder. Replace this comment with records in the template format,
in ID order. Do not invent or pre-fill records: each one must quote
bytes from a sample of a named run.
-->
