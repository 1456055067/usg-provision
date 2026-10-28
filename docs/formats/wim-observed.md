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

**Status: records from three runs (R1 and R2, 2026-10-27; R3,
2026-10-28).** Records OBS-001 to OBS-017 come from run R1, OBS-018 to
OBS-023 from run R2 and OBS-024 to OBS-048 from run R3 of the
`wim-samples` workflow (see [Runs examined](#runs-examined)).
They describe the files of those runs only; rule 6 below applies to
every conclusion. OPEN items not
listed as confirmed stay open, and parser constants that rest on them
stay marked `// FORMAT: derived, unconfirmed`.

## Summary

| Question | Status after R1 | Records |
|----------|-----------------|---------|
| Header signature, `cbSize`, header size 208 ([derived]) | confirmed | OBS-001 |
| OPEN-WIM-1 byte order | confirmed: little-endian in every field checked | OBS-002 |
| OPEN-WIM-2 version field values | partly: `0x00010D00` in every `.wim` and `.swm`, `0x00000E00` in the `.esd`; which values are valid in general stays open | OBS-003 |
| OPEN-WIM-3 field at offset 20 | partly: **not** the file size (contradicts the paper's description); 0 uncompressed, 32768 XPRESS and LZX, 131072 `.esd`; its meaning (chunk size?) is a reading | OBS-004 |
| Header flags for none / fast / max; LZX flag | confirmed: `0x80`, `0x00020082`, `0x00040082`; LZX flag is `0x00040000`; `0x80` is set in every sample | OBS-005 |
| OPEN-WIM-4 `.esd` (recovery) flags | partly: header flag `0x00080000` and resource flag `0x10`, neither defined by the paper; format still undocumented | OBS-006 |
| Resource header layout (§3), 56-bit size ([reading]); header resource locations | confirmed for the lookup, XML and integrity locations; their flag bytes are `0x02`, `0x02`, `0x00` | OBS-007 |
| OPEN-WIM-6 lookup entry packing | confirmed: 50 bytes, packed, field order as §5; hash is SHA-1 of the uncompressed content | OBS-008 |
| OPEN-WIM-6 metadata entry to image index | partly: in S04 the k-th metadata entry is index k; in S12A (R2), where lookup order and file-offset order differ, lookup order gives the index; other layouts open | OBS-009, OBS-021 |
| `wim.md` §13 S11: identical metadata for two images | one resource named by two adjacent lookup entries equal in all 50 bytes (S11A append, S11B export); DISM did not refuse | OBS-018 |
| Reference counts | not a reliable use count (5, 2, 9, 10 seen on one resource) | OBS-019 |
| `wim.md` §13 S12: unused space, stale resources | superseded lookup tables, XML and metadata stay in the file, unnamed; a commit appends | OBS-020, OBS-022 |
| `wim.md` §13 S12: order after commit / delete and append | commit of index 1: its metadata moves after every other resource, entry stays first; delete and append: offsets keep rising | OBS-021, OBS-023 |
| OPEN-WIM-5 incompressible data | partly: whole resources that do not compress are stored raw with flag `0x04` clear, inside an XPRESS file; a raw chunk *inside* a compressed resource was not seen | OBS-010 |
| Chunk table (§4 readings); OPEN-WIM-10 | §4 readings confirmed; width 4 below 4 GiB confirmed; the threshold stays open (needs S08) | OBS-011 |
| OPEN-WIMC-1 codec and block rule | confirmed: [MS-XCA] LZ77+Huffman, one 256-byte table per chunk, all 369 chunk instances decode to the lookup SHA-1 | OBS-012 |
| OPEN-WIMC-1 end symbol; WU-X framing questions 1 to 3 | confirmed: every chunk ends with symbol 256, read exactly when all input is consumed; no read past the input end is needed | OBS-013 |
| OPEN-WIM-8 XML content | partly: UTF-16LE with BOM, no declaration; `NAME` and `DESCRIPTION` as given; no `FLAGS` or `WINDOWS`; edition, architecture and version **cannot be observed** in our samples (decision 0013) | OBS-014 |
| OPEN-WIM-11 integrity table | partly: chunk size 10485760; hashed range is end of header to end of lookup table; only a one-entry table was seen | OBS-015 |
| OPEN-WIM-9 split-set matching | partly: all parts share one GUID at offset 24, new for the set; part and total at 40 and 42 | OBS-016 |
| Split flags and part contents | confirmed for S06; differs from our §10 summary (every part has its own lookup table and full XML; resource flag `0x08` is never set) | OBS-017 |
| OPEN-WIM-7 directory entries (R3) | partly: security block, entry and stream-entry layout, names, short names, alignment, end marker, times, attributes, hard links, reparse points and sibling order recorded for S01, S13 to S15; the fixed part is **102 bytes, not the [derived] 98**; EFS form, the sparse entry's extra block and two union fields stay open (see [M3 metadata questions](#m3-metadata-questions-m-01-to-m-23)) | OBS-024 to OBS-045, OBS-048 |
| OPEN-WIM-5 chunk level (R3) | confirmed for S17 and S14: a chunk that does not shrink is stored as its 32768 plain bytes inside a compressed resource, at any position, including consecutive chunks | OBS-046 |
| OPEN-WIM-10 (R3) | still open: S08's 4.5 GiB pseudorandom file was stored uncompressed, so it has no chunk table; its 7-byte stored size above 2^32 is recorded | OBS-047 |

**Still needed:**

- **A compressible sample over 4 GiB** (OPEN-WIM-10): R3's S08 was
  pseudorandom and DISM stored it uncompressed (OBS-047), so no chunk
  table over 4 GiB exists yet. Text or a repeated pattern over 4 GiB
  with `/Compress:fast` is needed.
- **The M3 metadata gaps** listed under
  [M3 metadata questions](#m3-metadata-questions-m-01-to-m-23).
- **A `/CheckIntegrity` sample over 10 MiB**: more than one integrity
  entry and the chunk boundary rule (OPEN-WIM-11).
- **More serviced layouts** (OPEN-WIM-6): S12A (R2) gave one file whose
  lookup and offset order differ (OBS-021). Not yet seen, with what the
  checker does with each layout until a sample is recorded:
  - a commit of an index between 1 and the last: if DISM moves that
    image's metadata to the end as in OBS-021, the file is refused
    (`wim_metadata_order_not_supported`);
  - a commit of the last index: if its metadata moves to the end,
    offsets still rise and the file is accepted;
  - commits of several indexes: refused unless offsets rise or only
    index 1 moved;
  - three or more images with identical metadata: if DISM names one
    copy from three or more entries, refused (`wim_resource_overlap`);
  - identical images that are not adjacent: if DISM names one copy
    from entries that are not next to each other in the lookup table,
    refused (`wim_resource_overlap`); separate copies are accepted;
  - an export of S04's indexes in reverse order: its layout is
    unknown; accepted if metadata offsets rise in lookup order (or
    only the first entry is moved as in OBS-021), refused otherwise.
- **Edition, architecture, version** (OPEN-WIM-8): only a capture of a
  real Windows installation would show them; our content rules forbid
  that, so these facts stay operator-declared (decision 0013).
- **S10, long runs** (added to the scripts in fix round 1, BOOT-004;
  produced by the next Windows run): 32 KiB and 96 KiB of zero bytes and
  a 300-byte pattern repeated over 96 KiB, `/Compress:fast`, to show the
  16-bit length extension and multi-chunk tables of long matches.
- **A bootable sample** (BOOT-006): how the boot metadata header relates
  to the boot image's lookup entry; waits on OPEN-PE-LIC.
- **Other DISM builds or runner images**: every claim is for R1, R2 or
  R3 (same DISM build and runner image).

## Contents

- [Summary](#summary)
- [Provenance rules](#provenance-rules)
- [Method](#method)
- [Record template](#record-template)
- [Runs examined](#runs-examined)
- [Open items and samples](#open-items-and-samples)
- [M3 metadata questions (M-01 to M-23)](#m3-metadata-questions-m-01-to-m-23)
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

| Run | Run ID | Attempt | Commit | Runner image | OS build | DISM version | Date (UTC) |
|-----|--------|---------|--------|--------------|----------|--------------|------------|
| R1 | 40535666995 | 1 | ba23bedea96e5d1c68c8f77e8bff4ce9cb012825 (branch `m2-wim-samples`, job `generate`) | `win25-vs2026` 20261021.278.1 (windows-2025) | Microsoft Windows NT 10.0.26100.0; `ver` 10.0.26100.33650; CurrentBuild.UBR 26100.33650; 24H2; ServerDatacenter | `Dism.exe` FileVersion and ProductVersion 10.0.26100.32860 (WinBuild.160101.0800); `dism /English /?` banner "Version: 10.0.26100.5074" | 2026-10-27T15:54:56Z |
| R2 | 40599556702 | 1 | 5d3c8c701506ff780ff8a86c5e692f725634a6bd (job `generate`) | `win25-vs2026` 20261021.278.1 (windows-2025) | Microsoft Windows NT 10.0.26100.0; `ver` 10.0.26100.33650; CurrentBuild.UBR 26100.33650; 24H2; ServerDatacenter | `Dism.exe` FileVersion and ProductVersion 10.0.26100.32860 (WinBuild.160101.0800); `dism /English /?` banner "Version: 10.0.26100.5074" | 2026-10-27T23:05:02Z |
| R3 | 40754869824 | 1 | 27f7237d99c67a9cc575268398dd4193ae1fbccf (branch `m3/prebuild`; jobs `generate`, `generate-large`, `generate-metadata`, `reference`) | `win25-vs2026` 20261021.278.1 (windows-2025) | Microsoft Windows NT 10.0.26100.0; `ver` 10.0.26100.33650; CurrentBuild.UBR 26100.33650; 24H2; ServerDatacenter | `Dism.exe` FileVersion and ProductVersion 10.0.26100.32860 (WinBuild.160101.0800); `dism /English /?` banner "Version: 10.0.26100.5074" | 2026-10-28T19:30:25Z to 19:31:14Z |

R1 identity, from `host.txt`: PowerShell 7.6.7, `RUNNER_ARCH` X64.
The DISM file version and the version in DISM's own banner differ;
records quote both.

R1 checks done before any record was written:

- `shasum -a 256 -c SHA256SUMS` (macOS; same format as `sha256sum`):
  all 14 files `OK`.
- `manifest.tsv`: 14 rows, all `produced`. No S08 row: the run had no
  `generate-large` job, so OPEN-WIM-10 is not addressed.
- `commands.log`: every DISM command `EXIT 0`.

R1 sample files (SHA-256 from `SHA256SUMS`, checked):

| Sample | File | Bytes | SHA-256 |
|--------|------|-------|---------|
| S01 | S01.wim | 972691 | a137931caa9f657d234add5fd79b703cb11d602852dfb8ebcfd9cd6c99f05fff |
| S02 | S02.wim | 644868 | 6b3a317d2b4dec470fcfd31e918f34d0c8f2c82d835365b2559b1751544ac836 |
| S03 | S03.wim | 637855 | e17671d9f94e29b71ebcd22621fef337ad3235407c1f4e07652f9bc8eb5d71ef |
| S04 | S04.wim | 6701536 | d59d219ec33c8b1db3ccbe576261b13781046eda9ef58e0b59562c9c3c89b56f |
| S05 | S05.wim | 644920 | 3f1320d8b35d1dfc4510dd195de693a82284091ea161196bdaee0ded097ba3fb |
| S06 part 1 | S06.swm | 938725 | 6ba33de4e6887cff5622f703198e710ce3a53e6eb968b03dd0de953933e5dfd3 |
| S06 part 2 | S062.swm | 985991 | e7bb7ce70976676a0b74b9a135110c0f91425cf57b94fa1dff908dd246a3c39c |
| S06 part 3 | S063.swm | 1021501 | 684c2971d5319854dece48f7612ad153e8924f5811e1010634bda09ce2af8513 |
| S06 part 4 | S064.swm | 1017079 | 8e639eb2f97cac1736243f3a0ddbc5c7c4d0ace93e8673ff6e92d5d0cf943d1c |
| S06 part 5 | S065.swm | 985529 | 806d432921ba2b90d7efbe1cdcb26d99475cd67b24cf198b837c7052d5f1ccd0 |
| S06 part 6 | S066.swm | 887151 | fcd087502d9a74bfaba2bf800f84e7787016b589cf79289d1f7e87a2c8085462 |
| S06 part 7 | S067.swm | 817660 | 8f2d37e269975b2eab62446e51d4607b6dab104496d0f70022c47a6a3c5b4b2a |
| S07 | S07.esd | 634394 | dc0ef20e7836d5e4c380367626be2595006319b492e04a28e97f1be0f7c93b27 |
| S09 | S09.wim | 67232 | 2e5f189c0a3e45aead379d6ba781b13ff971d82873bc5ed086ec6d1b6cef25ee |

R1 commands (from `commands.log`; paths are on the runner):

```text
S01 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S01.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S01-01 /Description:usgp-sample-S01-index-01-uncompressed /Compress:none
S02 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S02.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S02-01 /Description:usgp-sample-S02-index-01-fast /Compress:fast
S03 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S03.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S03-01 /Description:usgp-sample-S03-index-01-max /Compress:max
S04 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S04.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S04-01 /Description:usgp-sample-S04-index-01-fast /Compress:fast
    then, for nn = 02 to 12:
    dism.exe /English /Append-Image /ImageFile:D:\a\_temp\wim-samples\S04.wim /CaptureDir:D:\a\_temp\wim-work\tree-nn /Name:USGP-S04-nn /Description:usgp-sample-S04-index-nn-fast
S05 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S05.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S05-01 /Description:usgp-sample-S05-index-01-fast-integrity /Compress:fast /CheckIntegrity
S06 dism.exe /English /Split-Image /ImageFile:D:\a\_temp\wim-samples\S04.wim /SWMFile:D:\a\_temp\wim-samples\S06.swm /FileSize:1
S07 dism.exe /English /Export-Image /SourceImageFile:D:\a\_temp\wim-samples\S02.wim /SourceIndex:1 /DestinationImageFile:D:\a\_temp\wim-samples\S07.esd /Compress:recovery
S09 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S09.wim /CaptureDir:D:\a\_temp\wim-work\tree-inc /Name:USGP-S09-01 /Description:usgp-sample-S09-index-01-incompressible /Compress:fast
```

Source trees (from `commands.log` and `trees.txt`): `tree-01` to
`tree-12` are the Standard profile with seeds 101 to 112 (21 files and
11 directories each; `tree-01` holds 965911 bytes); `tree-inc` is the
Incompressible profile, seed 201, one file `random-65536.bin`.

How the R1 bytes were examined (clean side, macOS):

- `xxd` and `shasum` for every hex excerpt and hash quoted below.
- Small analysis scripts written for this task from `wim.md` and
  `wim-compression.md` only, committed in fix round 1 (CR-602) under
  `scripts/wim-samples/analysis/`, each with a header naming those two
  files as its only sources and R1 as its run; below the header each is
  byte-for-byte the script used for R1. None consults any other
  implementation (decision 0006 item 2). SHA-256 of the committed files:

  | Script | Use | SHA-256 |
  |--------|-----|---------|
  | `lookup.py` | walks the lookup table (§2, §3, §5 layout) | e48eaeab8a4eebdfe020c8adb81a5c3c5214fa3be4b78e22ee7bb9887077b9f8 |
  | `metamap.py` | metadata entry to source tree (OBS-009) | a0b437de42fe277f4e94b020d0d850f11d810cca1d8aa96a812b2a50eeeb5e8e |
  | `xpr.py` | LZ77+Huffman decoder from `wim-compression.md` §3, instrumented to report how each chunk ends | 35f8a86d24d2c9a387a8daf07d7fd38bb92e450d82aa900861e839f86f914c6a |
  | `xpr2.py` | `xpr.py` plus length-extension counts and end-of-chunk bits | 33586bc77b8b99facecd4773fbc9b65b5045fb76fea45a1f12bd067207fd2e82 |
  | `xpr3.py` | `xpr2.py` plus a count of mid-chunk symbol 256 | f7b115500b0e00a5e0f8db136adfa25151958015cc5f77b45b437d7310cc1181 |

  Re-run on the local copy of the R1 artifact in fix round 1 (Python
  3.15.1, `python3 -I`): `xpr3.py` over the 11 XPRESS files reports 83
  resources, all with the lookup SHA-1, 369 chunks, all ending
  "symbol256 with all input consumed", `ext8` 49236, `ext16` 0 and
  `mid256` 87; `metamap.py` on S04 maps metadata entry k to tree
  k + 1; these are the figures quoted in OBS-009 to OBS-013. The R1
  artifact itself expires 14 days after the run; keeping it (or at
  least `observations.txt` and `SHA256SUMS`) in a retained evidence
  store is an owner action, subject to OPEN-PE-LIC.
- The project's own decoder (`usgp_image::codec::XpressDecoder`, WU-X,
  working tree at commit 55bd6a1 plus uncommitted WU-X files) run
  from a throw-away harness over the same chunks.
  Since fix round 1 the same check is a committed test:
  `crates/usgp-image/tests/dism_samples.rs`
  (`every_dism_compressed_resource_decodes`, feature `dism-samples`)
  decodes every compressed lookup entry of every XPRESS sample through
  the product's resource reader and compares its SHA-1 (83 resources,
  369 chunks for R1).
- Decoded output is checked against the SHA-1 in the lookup entry and
  against the SHA-1 of the source file in `trees.txt`, which the
  scripts did not write.

Results from the scripts are readings; each record therefore also
quotes the raw bytes it rests on.

R2 checks done before any record was written (macOS, local copy of the
artifact of run 40599556702, downloaded by the orchestrator):

- `shasum -a 256 -c SHA256SUMS`: all 19 files `OK`.
- `manifest.tsv`: 19 rows, all `produced` (S11A, S11B, S12A and S12B
  with expected `observe`). No S08 row.
- `commands.log`: 86 DISM commands, every one `EXIT 0` (DISM refused
  no S11 step). `host.txt` identity as in the table above: same OS
  build, DISM version and runner image as R1.
- Before this change the checker refused S11A and S11B with
  `wim_resource_overlap` and S12A with
  `wim_metadata_order_not_supported`, and accepted S12B (12 images),
  as the CI run reported.

R2 sample files used by OBS-018 to OBS-023 (SHA-256 from `SHA256SUMS`,
checked):

| Sample | File | Bytes | SHA-256 |
|--------|------|-------|---------|
| S01 | S01.wim | 972691 | b1d7a9b7626763f730246a5cbaf0ff9c7bfc88100b8cf307c02e5e421c65f594 |
| S02 | S02.wim | 644868 | bbfccc22f6834fe19e64e171f7c23c576effa6668b02659304a157d79b1564c9 |
| S04 | S04.wim | 6701536 | edf3db30578e78b2bd7a61a25970591cf7cd4afa1594d1eabd8ad634a40b3c1e |
| S11A | S11A.wim | 647666 | a62b1c5074edec459e82e83ba0b8a3cfaf32150ce1236fe08b8b2d00376a3ae8 |
| S11B | S11B.wim | 647626 | b4178b296ff73cb7f5d2396a6b5e1eca7019777c4569a7e30f9fe3799a8ac7f6 |
| S12A | S12A.wim | 6763270 | 5db80ce24d971a8ca2ff8b55c056ea0575c798f703e30e77643c601a672d24c7 |
| S12B | S12B.wim | 6742165 | b5f93ddd9840a9f30790e32fcfd6658c79cd57ef393c7c3de0480125bdd92f09 |

R2 commands for these samples (from `commands.log`; S01, S02 and S04
as in R1, with `D:\a\_temp` paths):

```text
S11A dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples\S11A.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S11A-01 /Description:usgp-sample-S11A-index-01-same-tree /Compress:fast
     dism.exe /English /Append-Image /ImageFile:D:\a\_temp\wim-samples\S11A.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S11A-02 /Description:usgp-sample-S11A-index-02-same-tree
S11B dism.exe /English /Export-Image /SourceImageFile:D:\a\_temp\wim-samples\S02.wim /SourceIndex:1 /DestinationImageFile:D:\a\_temp\wim-samples\S11B.wim /Compress:fast
     dism.exe /English /Export-Image /SourceImageFile:D:\a\_temp\wim-samples\S02.wim /SourceIndex:1 /DestinationImageFile:D:\a\_temp\wim-samples\S11B.wim /DestinationName:USGP-S11B-02
S12A copy S04.wim to S12A.wim
     dism.exe /English /Mount-Image /ImageFile:D:\a\_temp\wim-samples\S12A.wim /Index:1 /MountDir:D:\a\_temp\wim-work\mount-S12A
     copy tree-service to mount\usgp-serviced
     dism.exe /English /Unmount-Image /MountDir:D:\a\_temp\wim-work\mount-S12A /Commit
S12B copy S04.wim to S12B.wim
     dism.exe /English /Delete-Image /ImageFile:D:\a\_temp\wim-samples\S12B.wim /Index:1
     dism.exe /English /Append-Image /ImageFile:D:\a\_temp\wim-samples\S12B.wim /CaptureDir:D:\a\_temp\wim-work\tree-01 /Name:USGP-S12B-12 /Description:usgp-sample-S12B-index-12-appended
```

How the R2 bytes were examined: `xxd`, `shasum` and `cmp`; the R1
scripts `lookup.py`, `metamap.py` and `xpr.py` unchanged; and two new
scripts written for R2 from `wim.md` (and, through `xpr.py`,
`wim-compression.md`) only, committed under
`scripts/wim-samples/analysis/` with the same kind of header:

| Script | Use | SHA-256 |
|--------|-----|---------|
| `gaps.py` | sorts every named range, prints unnamed ranges and overlaps (OBS-018, OBS-020 to OBS-022) | 24c970ae539859325db9c2791232d053ba8c93e412999a6da90dd5dbe6079b47 |
| `metahash.py` | decodes each metadata resource, checks its SHA-1, looks for the tree-service hashes, prints XML index and name (OBS-021) | 78516eef8462144ad0940a3c90cb4c2ef47723d95f32f682d6ef9be5314e8f88 |

`metahash.py`'s header lists `wim.md` sections 2 to 5 as its sources;
it also reads the XML index and name, which rests on `wim.md` §7 and
OBS-014. The header is left as run, since the file is hashed above.

The product's own reader confirms the layout facts in a committed
test: `crates/usgp-image/tests/dism_samples.rs`
(`serviced_layouts_match_observations`, feature `dism-samples`).

R3 checks done before any record was written (macOS, local copies of
the four artifacts of run 40754869824, downloaded by the orchestrator;
an earlier attempt, run 40752616665, failed in a script step and is not
used):

- `shasum -a 256 -c SHA256SUMS`: `wim-samples` 19 files, `OK`;
  `wim-samples-metadata` 4 files, `OK`; `wim-samples-reference` 1 file,
  `OK`. `wim-samples-large-observations` has no `SHA256SUMS` (S08 is not
  uploaded; its manifest row gives its length and SHA-256).
- `manifest.tsv`: every row `produced` (S08 `produced (not uploaded)`).
- `commands.log`: every command `EXIT 0` in all four jobs (86, 18, 8
  and 4 commands); no `NOTE` line, so the EFS file was encrypted.
- `host.txt` of all four jobs: the same commit, runner image, OS build
  and DISM version as in the table. The metadata job also records
  `fsutil behavior query disablelastaccess`: `DisableLastAccess = 3
  (System Managed, Last Access Time Updates DISABLED)` and the system
  short-name state `2 (Per volume setting - the default)`; the VHD
  volume had short names enabled by the script (`VHD-META.diskpart.txt`).
- The `reference` job applied S13 after checking its SHA-256 against the
  metadata artifact (`S16 source S13.wim sha256 6d7db6b9...` in its
  `commands.log`). Both VHD volumes were given the letter `R:`.

R3 sample files used by OBS-024 to OBS-048 (SHA-256 from `SHA256SUMS`,
checked; S08 from its manifest row):

| Sample | File | Bytes | SHA-256 |
|--------|------|-------|---------|
| S01 | S01.wim | 972691 | c9a867bf22a6b8ea03361d5b3fe7e8d454c361f5a32430d7fc56078c3be4a431 |
| S08 | S08.wim (not uploaded) | 4831839906 | a7e05acd463be3adc00c1f0fbe8490be9afcb06fe6b793def743bc7876584d4d |
| S13 | S13.wim | 1051069 | 6d7db6b9a24da4a14c408013c046143b6fdf8a440b88baf7083d9b41c3ac634a |
| S14 | S14.wim | 546335 | 57ec13c10c79987f1e849dc062a70869a8842ebeff0b63d077176776e2d3db61 |
| S15 | S15.wim | 1051537 | bc1380fe88df68cae7708c27202aa2be05836d9c0586bda632dce908ad0007cd |
| S16 | S16.manifest.tsv (text) | 830598 | dddc1363f72d755e619b66abc1c356b26e061b3b47391fe4c71d9055215b8a60 |
| S17 | S17.wim | 79678 | 1342001c1e684d482445df136d02f4d89ab9ad863f93b76b143fc8fa6389fbb3 |

R3 commands for these samples (from `commands.log`; S01 as in R1):

```text
S08 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-work-large\S08.wim /CaptureDir:D:\a\_temp\wim-work-large\tree-large /Name:USGP-S08-01 /Description:usgp-sample-S08-index-01-large /Compress:fast
S13 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples-metadata\S13.wim /CaptureDir:R:\tree-meta /Name:USGP-S13-01 /Description:usgp-sample-S13-index-01-metadata-uncompressed /Compress:none
S14 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples-metadata\S14.wim /CaptureDir:R:\tree-meta /Name:USGP-S14-01 /Description:usgp-sample-S14-index-01-metadata-fast /Compress:fast
S15 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples-metadata\S15.wim /CaptureDir:R:\ /Name:USGP-S15-01 /Description:usgp-sample-S15-index-01-volume-root /Compress:none
S16 dism.exe /English /Apply-Image /ImageFile:D:\a\_temp\wim-samples-metadata\S13.wim /Index:1 /ApplyDir:R:\
    (on a fresh NTFS VHD volume, short names enabled; then the tree manifest)
S17 dism.exe /English /Capture-Image /ImageFile:D:\a\_temp\wim-samples-metadata\S17.wim /CaptureDir:D:\a\_temp\wim-work-metadata\tree-mixed /Name:USGP-S17-01 /Description:usgp-sample-S17-index-01-mixed /Compress:fast
```

Source trees: tree-meta is profile Metadata, seed 601, on the VHD
volume `R:` (3033 files and 3057 manifest rows including its root);
tree-mixed is profile Mixed, seed 701 (`trees.txt`); tree-large is
profile Large, seed 301 (one 4831838208-byte file). The tree manifests
(`tree-meta-before.manifest.tsv`, `tree-meta.manifest.tsv`,
`volume-root.manifest.tsv`, `S16.manifest.tsv`), the `dir /x` listings
(`*.dirx.txt`) and the `fsutil reparsepoint query` output
(`*.reparse.txt`) were written on the runner by Windows' own tools, not
by our analysis scripts.

How the R3 bytes were examined: `xxd` and `shasum`; `xpr.py`
unchanged; and four scripts under `scripts/wim-samples/analysis/`,
each with a provenance header naming its only sources:

| Script | Use | SHA-256 |
|--------|-----|---------|
| `dentry.py` | the walker written before R3 from `wim.md` §6 alone (98-byte fixed part); its R3 output is the evidence that the [derived] layout fits no entry (OBS-026) | 498a2efeaff75c6a889e45cf58dbd94aa659c1f2ba53c621bac8693d19c5bfe6 |
| `dentry_r3.py` | walker for the layout the R3 bytes show, checking each assumption per entry; compares entries with a tree manifest; prints reparse resources (OBS-024 to OBS-044, OBS-048) | f2e2686e8b4a25c12a6c5e3557335d6ac7b8e7e9a178ff02bca5124c72c9670a |
| `treecmp.py` | compares two tree manifests column by column (OBS-045) | 88871dbced26aa3b0f0fbde2c82b65795976f04ce219fa60fc4a843799bc3061 |
| `reparsecmp.py` | compares stored reparse resources with `fsutil` output on the source and on DISM's applied tree (OBS-036, OBS-037) | 6e4758b9e5f15a31b80183994678d3f33f10a4d78e37be5dedc9fc12c22ae9cb |

Notes on the headers, which are left as run because the files are
hashed above (CR-R3-004, CR-R3-006):

- `reparsecmp.py`'s header says it was used for OBS-033; it was used
  for OBS-036 and OBS-037.
- `dentry_r3.py` also rests on `wim.md` §4 (chunk tables, for S14) and,
  through `xpr.py`, on `wim-compression.md`; its header lists only
  sections 2, 3, 5 and 6.

Run with Python 3.15.1, `python3 -I`. The figures quoted in the R3
records come from these commands (paths shortened):

```text
python3 -I dentry.py S01.wim | S13.wim | S15.wim; dentry.py --xpr xpr.py S14.wim
python3 -I dentry_r3.py S01.wim
python3 -I dentry_r3.py --resource-hex --manifest tree-meta.manifest.tsv S13.wim
python3 -I dentry_r3.py --manifest tree-meta-before.manifest.tsv S13.wim
python3 -I dentry_r3.py --xpr xpr.py S14.wim
python3 -I dentry_r3.py --manifest volume-root.manifest.tsv S15.wim
python3 -I treecmp.py --strip-links '\tree-meta' tree-meta.manifest.tsv S16.manifest.tsv
python3 -I reparsecmp.py <dentry_r3 S13 output> tree-meta.reparse.txt S16.reparse.txt
python3 -I xpr.py S17.wim
```

`dentry_r3.py` reports for S01, S13, S14 and S15 every entry it read
and every assumption that failed ("MISFIT"); the only misfit in any of
them is the sparse file's entry (OBS-029, OBS-039).

## Open items and samples

Status `pending` means no record exists yet. Questions listed here are
those of `wim.md` section 13 and `wim-compression.md` section 7 that
the samples can address; the samples are defined in
[scripts/wim-samples/README.md](../../scripts/wim-samples/README.md).

| Item | Question (short) | Samples | Dump section | Status |
|------|------------------|---------|--------------|--------|
| OPEN-WIM-1 | Byte order of multi-byte fields | S01, S02 | header, lookup | confirmed little-endian: OBS-002 |
| OPEN-WIM-2 | Values of the version field | S01, S02, S03, S07 | header (`@12`) | partly: OBS-003 (values seen; validity in general open) |
| OPEN-WIM-3 | What the field at offset 20 holds | S01, S02, S04 | header (`@20`) | partly: OBS-004 (not the file size; meaning a reading) |
| OPEN-WIM-4 | Flags of `recovery` (`.esd`) output | S07 | header (`@16`), lookup | partly: OBS-006 (flags recorded; format undocumented) |
| OPEN-WIM-5 | How an incompressible chunk is stored | S09 (with `trees.txt` chunk bytes), S02, S17 | chunks | resource level: OBS-010; chunk level: OBS-046 (R3, S17) |
| OPEN-WIM-6 | Lookup entry packing; metadata entry to image index | S01, S04, S11A, S11B, S12A, S12B | lookup, metadata, xml | packing confirmed: OBS-008; index mapping partly: OBS-009, OBS-018, OBS-021, OBS-023 (lookup order gives the index in every file seen) |
| OPEN-WIM-7 | Directory entry alignment, short names | S01, S13, S14, S15, S16 | metadata (full dump), `dentry_r3.py` | partly: OBS-024 to OBS-045 and OBS-048 (R3); open parts in [M3 metadata questions](#m3-metadata-questions-m-01-to-m-23) |
| OPEN-WIM-8 | Content of `NAME`, `DESCRIPTION`, `FLAGS`, `WINDOWS` | S04 | xml | partly: OBS-014 (no `FLAGS`, no `WINDOWS` in our samples; edition, architecture and version facts cannot be observed from them, see decision 0013) |
| OPEN-WIM-9 | How parts of a split set are matched | S06 parts | header (`@24`, `@40`, `@42`) | partly: OBS-016 (shared GUID) |
| OPEN-WIM-10 | Chunk-table entry width above 4 GB | S08 (large observations artifact) | chunks (width 4 and 8 checks) | still open: R3's S08 was stored uncompressed, no chunk table (OBS-047); width 4 below 4 GiB: OBS-011 |
| OPEN-WIM-11 | Integrity chunk size unit; hashed range | S05 | integrity | partly: OBS-015 (one-entry table only) |
| OPEN-WIMC-1 | WIM XPRESS is [MS-XCA] LZ77+Huffman; block rule; end symbol | S02, S04, S09 | chunks (first chunk: 256-byte table and first symbols) | confirmed for R1: OBS-012, OBS-013 |
| LZX flag | Header flag value DISM writes for `max` | S03 | header (`@16`) | confirmed `0x00040000`: OBS-005 |
| Split flags | Header and resource flags of `.swm` parts | S06 parts | header, lookup | confirmed for S06: OBS-017 |

## M3 metadata questions (M-01 to M-23)

The questions of plan M3 §1.4 (run
`20261028-104815-m3-preboot-apply`), all part of OPEN-WIM-7 unless
noted, with their status after R3. "Answered" means answered for the
R3 files only (rule 6); a WIM layout that no record shows stays
refused by the product.

| ID | Question (short) | Samples | Status after R3 |
|----|------------------|---------|-----------------|
| M-01 | Security block: length includes header? count? 8-byte lengths? padding | S01, S13, S15 | answered: OBS-024 |
| M-02 | Root entry offset; root name and parent fields | S01, S13, S15 | answered: OBS-024 (offset), OBS-025 (root) |
| M-03 | Offsets and values of the fixed part | S01, S13, S15 | answered for positions: OBS-026 (102 bytes, contradicting the [derived] 98); what the always-zero fields at +24, +32 and +84 mean stays open |
| M-04 | Name encoding, length, terminator, non-BMP | S01 `names\` | answered: OBS-027 |
| M-05 | Short name position, length field, terminator | S13 | answered: OBS-028 |
| M-06 | Entry length against bytes used; alignment | S01, S13, S15 | answered: OBS-029 (one exception: the sparse file's entry carries a further block, OBS-039) |
| M-07 | End-of-directory marker; children offset; empty directory | S01, S13 | answered: OBS-030 |
| M-08 | Empty file: zero hash, no lookup entry | S01, S13 | answered: OBS-031 |
| M-09 | Stream entries: layout, unnamed entry, zero-length, on a directory | S01, S13 | answered: OBS-032; the rule behind the order of named streams stays open |
| M-10 | Captured attribute values | S13 | answered: OBS-033; DISM's apply differs for the archive attribute (OBS-045) |
| M-11 | Which time field is which | S13 | answered: OBS-034 |
| M-12 | Hard-link group identifier | S13 | answered: OBS-035 |
| M-13 | Reparse entries: tag, reserved, data location, `RP_FIX` | S13, S16 | partly: OBS-036 (tag, data location), OBS-037 (in-tree absolute targets lose the capture root on capture). Open, **blocking for absolute targets and junctions (S13B)**: what DISM's apply does with them; S16 applied to `R:\` from a capture root on `R:`, so copying the stored bytes and re-basing them give the same result there. Also open: the meaning of the union's last 4 bytes (OBS-036); absolute targets outside the capture root (not sampled) |
| M-14 | Descriptors: self-relative as Windows returns them; stored once; index −1 | S13, S16 | partly: OBS-038 (stored once, shared index; DISM's apply gives the same SDDL on the 3052 rows that have one). Open: byte equality with the descriptor Windows returns (no binary reference was captured); index −1 (never seen); descriptors of reparse points (the manifests hold no SDDL for them) |
| M-15 | Sparse, NTFS-compressed, EFS files | S13, S16 | partly: OBS-039 (sparse and compressed: attributes kept, data stored expanded; the sparse entry's extra block is unexplained), OBS-040 (EFS: stored form is not the plaintext; undocumented, so refused) |
| M-16 | Paths over 260 UTF-16 units | S13, S16 | answered: OBS-041 |
| M-17 | 3000 entries in one directory: sibling order; metadata over many chunks | S13, S14, S15 | answered: OBS-042 (order), OBS-043 (16 chunks) |
| M-18 | XPRESS metadata equals S13's bytes | S14 | answered: OBS-043 |
| M-19 | Volume root capture | S15 | answered: OBS-044 (`$RECYCLE.BIN` did not exist on the volume, so its handling is not shown) |
| M-20 | DISM's apply result as a tree manifest | S16 | answered: OBS-045 |
| M-21 | A chunk that does not shrink inside a compressed resource (OPEN-WIM-5) | S17, S14 | answered: OBS-046 (any position, including consecutive chunks) |
| M-22 | 8-byte chunk-table entries (OPEN-WIM-10) | S08 | open: OBS-047 (S08 stored uncompressed; no chunk table) |
| M-23 | XML `DIRCOUNT` and `FILECOUNT` against entries | S01, S13, S15 | answered for `DIRCOUNT` and `FILECOUNT`: OBS-048; the `HARDLINKBYTES` rule is not determined (one group seen) |

Samples still needed for the open parts (requests for the next run):

- **S13B** (blocking for absolute targets and junctions): tree-meta
  captured from `R:` and applied to a volume with another letter, and to
  a subdirectory (M-13: copy or re-base on apply); the manifests to
  record the SDDL of reparse points too (M-14).
- **S13C**: an absolute symbolic link whose target is outside the
  capture root, with and without `/NoRpFix` (M-13).
- **S13D**: a file with an explicit protected descriptor that has no
  inheritable ACEs, plus a binary dump of the descriptors Windows
  returns for the tree, reparse points included (M-14 byte equality),
  and any file DISM writes with security index −1 if one can be made.
- **S13E**: two more sparse files with one and with three
  deallocated ranges (M-15 sparse block).
- **S13F**: files with three and more named streams created in
  different orders (M-09 order).
- **S08B**: a compressible file over 4 GiB (M-22, OPEN-WIM-10).

## Observations

Records are in ID order. OBS-001 to OBS-017 are from run R1, OBS-018
to OBS-023 from run R2, OBS-024 to OBS-048 from run R3 (identity
line: as R2, but run 40754869824, attempt 1, commit 27f7237). The R2
identity line reads: Windows NT
10.0.26100.0, build 26100.33650; `Dism.exe` 10.0.26100.32860 (banner
10.0.26100.5074); runner image `win25-vs2026` 20261021.278.1; run
40599556702, attempt 1, commit 5d3c8c7; R2 commands and SHA-256 values
are in [Runs examined](#runs-examined). The R1 records' identity line
reads: Windows NT 10.0.26100.0, build 26100.33650;
`Dism.exe` 10.0.26100.32860 (banner 10.0.26100.5074); runner image
`win25-vs2026` 20261021.278.1; run 40535666995, attempt 1, commit
ba23bed. Sample SHA-256 values are given in full in the R1 and R2
sample tables; records quote the first 16 hex digits. Commands are the
R1 and R2 command lines above. Offsets are file offsets, decimal then hex.
Multi-byte values are read little-endian (OBS-002).

### OBS-001: header signature, cbSize 208, header ends at 208

- Status: Recorded
- Settles: `wim.md` §2 [reading] signature and [derived] 208-byte size
- Sample: all 14 R1 files (S01 to S07, S09, all S06 parts)
- Command: R1 commands for S01 to S07 and S09
- Source tree: as per sample
- Host, DISM, runner, run: R1 identity line
- Location: offset 0 (0x0), 12 bytes; offsets 96 to 123 and 148 to 207
- Bytes: identical in all 14 files:

  ```text
  00000000: 4d53 5749 4d00 0000 d000 0000            MSWIM.......
  ```

- Observation: bytes 0 to 7 are ASCII `MSWIM` and three zero bytes;
  bytes 8 to 11 are `d0 00 00 00` (208). Bytes 148 to 207 are all zero
  in all 14 files; bytes 96 to 123 (boot metadata header and boot
  index) are all zero in all 14 files. In S01 the first file resource
  starts at offset 208 (OBS-008).
- Conclusion: in R1 files the signature is the 8 bytes
  `4d 53 57 49 4d 00 00 00`, `cbSize` is 208, and data follows the
  header at offset 208. None of the R1 images is bootable (boot index
  0).
- Also seen in: none (one run)
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/wim/check.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-001` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-002: multi-byte fields are little-endian

- Status: Recorded
- Settles: OPEN-WIM-1
- Sample: S01 (a137931caa9f657d), S02 (6b3a317d2b4dec47), S04
  (d59d219ec33c8b1d), S06 parts 1 and 2 (6ba33de4e6887cff,
  e7bb7ce70976676a)
- Command: R1 commands S01, S02, S04, S06
- Source tree: tree-01 (S01, S02); tree-01 to tree-12 (S04, S06)
- Host, DISM, runner, run: R1 identity line
- Location: header offsets 8, 40, 42, 44, 48 to 71; S01 lookup entry
  at 970829 (0xED04D)
- Bytes:

  ```text
  S04 00000020: 8185 723a 704e 553f 0100 0100 0c00 0000
  S062 00000020: 9ca9 2dab c455 c5f7 0200 0700 0c00 0000
  S01 00000030: 8403 0000 0000 0002 4dd0 0e00 0000 0000
  S01 00000040: 8403 0000 0000 0000 c203 0000 0000 0002
  S01 000ed04d: a812 0000 0000 0002 a5bd 0e00 0000 0000
  ```

- Observation: read little-endian, `cbSize` is 208 (OBS-001); the
  image count at 44 is 12 in S04 (DISM's `/Get-WimInfo` lists 12
  indexes) and 1 in S01; the part number and total at 40 and 42 in
  S06 part 2 are 2 and 7 (seven `.swm` files were produced); the
  lookup table location at 56 in S01 is 970829, and the 50-byte
  records found there carry the SHA-1 values that `trees.txt` lists
  for the source files (OBS-008). Big-endian reading gives values
  that fit none of these (for example `cbSize` 0xD0000000).
- Conclusion: every 16-, 32- and 64-bit field checked in R1 is
  little-endian, including the 7-byte stored size.
- Also seen in: every other R1 file (all header and lookup values used
  in OBS-003 to OBS-017 are read this way and agree with the file
  length and the source hashes)
- Cited by: `crates/usgp-image/src/wim/reshdr.rs`,
  `crates/usgp-image/src/wim/header.rs` (`// FORMAT: OBS-002` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-003: version field values

- Status: Recorded
- Settles: OPEN-WIM-2, partly (values written by this DISM build)
- Sample: S01, S02, S03, S04, S05, S09, S06 parts 1 to 7; S07
  (dc0ef20e7836d5e4)
- Command: R1 commands
- Source tree: as per sample
- Host, DISM, runner, run: R1 identity line
- Location: offset 12 (0xC), 4 bytes
- Bytes:

  ```text
  S01 00000000: 4d53 5749 4d00 0000 d000 0000 000d 0100
  S07 00000000: 4d53 5749 4d00 0000 d000 0000 000e 0000
  ```

- Observation: `00 0d 01 00` (0x00010D00) in all 13 `.wim` and `.swm`
  files, whatever the compression (none, XPRESS, LZX), split or not;
  `00 0e 00 00` (0x00000E00) in the `.esd` file S07.
- Conclusion: this DISM build writes 0x00010D00 in the files R1
  produced with `none`, `fast` and `max`, and 0x00000E00 with
  `recovery`. Which values other tools or builds write, and which a
  reader should accept, stays open.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/testkit/builder.rs`,
  `crates/usgp-image/tests/check.rs` (`// FORMAT: OBS-003` or a comment
  or test naming the record; filled in fix round 1, CR-601)

### OBS-004: field at offset 20 is not the file size

- Status: Recorded
- Settles: OPEN-WIM-3, partly
- Sample: S01, S02, S03, S04, S05, S09, S06 parts, S07
- Command: R1 commands
- Source tree: as per sample
- Host, DISM, runner, run: R1 identity line
- Location: offset 20 (0x14), 4 bytes
- Bytes:

  ```text
  S01 00000010: 8000 0000 0000 0000 ...
  S02 00000010: 8200 0200 0080 0000 ...
  S03 00000010: 8200 0400 0080 0000 ...
  S07 00000010: 8200 0800 0000 0200 ...
  ```

- Observation: the value is 0 in S01 (uncompressed); 0x00008000
  (32768) in every XPRESS and LZX file (S02, S03, S04, S05, S09, all
  S06 parts); 0x00020000 (131072) in S07. The file sizes are 972691,
  644868, 637855 and 634394 respectively; no value equals a file size
  or a stored size.
- Conclusion: in R1 the field does not hold the size of the compressed
  file, contrary to the paper's description. Its values match the
  documented 32 KB chunk size in XPRESS and LZX files and are 0 when
  uncompressed; that it **is** the chunk size is a reading, not
  observed.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-004` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-005: header flags for none, fast and max; LZX flag value

- Status: Recorded
- Settles: "LZX flag" item; confirms the XPRESS flag of `wim.md` §2
- Sample: S01, S02, S03; also S04, S05, S09
- Command: R1 commands S01, S02, S03 (`/Compress:none`, `fast`, `max`)
- Source tree: tree-01
- Host, DISM, runner, run: R1 identity line
- Location: offset 16 (0x10), 4 bytes
- Bytes:

  ```text
  S01 00000010: 8000 0000
  S02 00000010: 8200 0200
  S03 00000010: 8200 0400
  ```

- Observation: S01 0x00000080; S02, S04, S05, S09 0x00020082; S03
  0x00040082. S05 (with `/CheckIntegrity`) has the same flags as S02.
- Conclusion: in R1, `/Compress:none` writes only 0x80
  (`FLAG_HEADER_RP_FIX`); `fast` writes 0x02 + 0x00020000 (XPRESS) +
  0x80; `max` writes 0x02 + 0x00040000 (LZX) + 0x80. The LZX flag DISM
  writes is 0x00040000, as the paper defines. 0x80 is set in every R1
  file, so a reader must accept it. The integrity table sets no header
  flag.
- Also seen in: S06 parts and S07 also carry 0x80 and 0x02 (OBS-006,
  OBS-017)
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-005` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-006: recovery (.esd) output uses flags the paper does not define

- Status: Recorded
- Settles: OPEN-WIM-4, partly (what the flags are; not the format)
- Sample: S07 (S07.esd, dc0ef20e7836d5e4)
- Command: R1 command S07 (`/Export-Image ... /Compress:recovery`)
- Source tree: S02.wim index 1 (tree-01)
- Host, DISM, runner, run: R1 identity line
- Location: offset 16 (0x10), 8 bytes; lookup entries at 632548
  (0x9A6E4) and 632598 (0x9A716), 50 bytes each
- Bytes:

  ```text
  00000010: 8200 0800 0000 0200
  0009a6e4: 0080 0100 0000 0010 0000 0000 0000 0000
  0009a6f4: 0000 0000 0000 0000 0100 0100 0000 0ade
  0009a704: 2ff4 1b8c f256 bed8 e342 9ded cc41 3cc2
  0009a714: 4e04 eea1 0900 0000 0010 d000 0000 0000
  0009a724: 0000 0000 0000 0100 0000 0100 0100 0000
  0009a734: 0000 0000 0000 0000 0000 0000 0000 0000
  0009a744: 0000 0000
  ```

- Observation: header flags 0x00080082: 0x02 and 0x80 as in OBS-005,
  plus 0x00080000, which the paper does not define; the XPRESS and LZX
  flags are clear. The field at 20 is 0x00020000 (OBS-004); the
  version is 0x00000E00 (OBS-003). The lookup table (19 entries) has
  one metadata entry (flags 0x06) and 18 entries with resource flags
  0x10, a value the paper does not define. 17 of those carry a source
  file's SHA-1 with original size 0 and offsets 0, 98304, 98305, ...;
  one (second excerpt) has stored size 631278, offset 208, original
  size 0x100000000 and an all-zero hash.
- Conclusion: DISM's `recovery` output in R1 is recognisable by
  undefined header flag 0x00080000 with no defined compression flag,
  and by resource flag 0x10. Its compression format is not described
  by any Microsoft source read (OPEN-WIMC-3); refusal under decision
  0014 can rest on the header flags alone, before any lookup entry is
  used.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/tests/negative.rs` (`// FORMAT: OBS-006` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-007: header resource headers for lookup, XML and integrity

- Status: Recorded
- Settles: `wim.md` §2 [derived] offsets 48, 72, 124 and §3 layout and
  [reading] 56-bit stored size; flag bytes of the header's resource
  headers
- Sample: S01 (a137931caa9f657d), S02 (6b3a317d2b4dec47), S05
  (3f1320d8b35d1dfc)
- Command: R1 commands S01, S02, S05
- Source tree: tree-01
- Host, DISM, runner, run: R1 identity line
- Location: offsets 48 (0x30), 72 (0x48), 124 (0x7C), 24 bytes each
- Bytes:

  ```text
  S01 00000030: 8403 0000 0000 0002 4dd0 0e00 0000 0000
  S01 00000040: 8403 0000 0000 0000 c203 0000 0000 0002
  S01 00000050: d1d3 0e00 0000 0000 c203 0000 0000 0000
  S05 00000070: .... .... .... .... .... .... 2000 0000
  S05 00000080: 0000 0000 18d7 0900 0000 0000 2000 0000
  S05 00000090: 0000 0000
  ```

- Observation: S01 lookup: stored 900, flags 0x02, offset 970829,
  original 900; XML: stored 962, flags 0x02, offset 971729 (= 970829 +
  900), original 962; 971729 + 962 = 972691, the file length. S02:
  lookup 900 at 643022, XML 946 at 643922, both flags 0x02, stored ==
  original. S05 integrity: stored 32, flags 0x00, offset 644888,
  original 32; 644888 + 32 = 644920, the file length. In every R1 file
  the lookup and XML headers have flag byte 0x02 and stored size equal
  to original size; the XML follows the lookup table directly.
- Conclusion: the header's resource headers are at 48, 72 and 124,
  laid out as `wim.md` §3 (7-byte size, 1 flag byte, 8-byte offset,
  8-byte original size). DISM sets flag 0x02 ("metadata") on the
  lookup and XML headers and 0x00 on the integrity header, and never
  compresses the lookup table or the XML, even in XPRESS files. A
  reader must not treat flag 0x02 in these three headers as marking an
  image's metadata.
- Also seen in: all R1 files (lookup and XML); S05 only (integrity)
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/wim/reshdr.rs`,
  `crates/usgp-image/src/wim/check.rs`,
  `crates/usgp-image/src/testkit/builder.rs`,
  `crates/usgp-image/tests/negative.rs` (`// FORMAT: OBS-007` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-008: lookup entries are 50 packed bytes; hash is SHA-1 of content

- Status: Recorded
- Settles: OPEN-WIM-6, part 1 (packing); `wim.md` §5 field order;
  reference-count meaning
- Sample: S01 (a137931caa9f657d), S02 (6b3a317d2b4dec47), S04
  (d59d219ec33c8b1d)
- Command: R1 commands S01, S02, S04
- Source tree: tree-01; tree-01 to tree-12 for S04
- Host, DISM, runner, run: R1 identity line
- Location: S01 lookup 970829 (0xED04D), 900 bytes; S04 entry 20 at
  6682422 (0x65F736)
- Bytes:

  ```text
  S01 000ed04d: a812 0000 0000 0002 a5bd 0e00 0000 0000
  S01 000ed05d: a812 0000 0000 0000 0100 0100 0000 484d
  S01 000ed06d: cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb b9f8
  S01 000ed07d: c6a5 0100 0000 0000 0000 d000 0000 0000
  S01 000ed08d: 0000 0100 0000 0000 0000 0100 0100 0000
  S01 000ed09d: 3014 0397 fe38 ee61 f01e ff44 b5cf a482
  S01 000ed0ad: 85e4 7889
  S04 0065f736: 4216 0000 0000 0004 fe90 0200 0000 0000
  S04 0065f746: 8175 0000 0000 0000 0100 0c00 0000 7c53
  S04 0065f756: e5d1 eef1 5af4 bd85 2f0d 2427 b69f c404
  S04 0065f766: 09b6
  ```

- Observation: every lookup table size in R1 is a multiple of 50 (S01
  900, S04 9700, S09 100, S07 950, S06 parts 2100, 1300, 1400, 1250,
  1350, 1450, 850). Read as 24-byte resource header, 2-byte part
  number, 4-byte reference count, 20-byte hash with no padding, S01
  entry 1 (second record above) is: stored 1, flags 0, offset 208,
  original 1, part 1, count 1, hash
  `30140397fe38ee61f01eff44b5cfa48285e47889`, which `trees.txt` gives
  as the SHA-1 of `tree-01\bin\random-1.bin` (length 1). Of the 17
  non-metadata entries of S01, 16 carry exactly the 16 distinct SHA-1
  values `trees.txt` lists for non-empty files of `tree-01`; the 17th
  (26 bytes) is the SHA-1 of the 26 bytes stored at its offset, the
  text of the one alternate stream. The empty file has no entry.
  Count 5 is on the entry for the five identical
  `names\*.txt` files; in S04, count 12 is on `shared\common.txt`
  (excerpt) and `shared\common-98304.bin`, present in all 12 trees.
  File resources in S01 follow each other with no gap (offsets 208,
  209, 100209, 300210, ...).
- Conclusion: in R1 a lookup entry is 50 bytes, packed, fields in the
  order of `wim.md` §5; the hash is the SHA-1 of the uncompressed
  content; the reference count counts uses across all images in the
  file; shared content is stored once. Resources are not aligned.
- Also seen in: S02, S05, S09, S07 (metadata entry), S06 parts
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-008` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-009: in S04 the k-th metadata entry belongs to image index k

- Status: Recorded
- Settles: OPEN-WIM-6, part 2, partly
- Sample: S04 (S04.wim, d59d219ec33c8b1d)
- Command: R1 command S04 (capture of tree-01, then 11 appends)
- Source tree: tree-01 to tree-12, seeds 101 to 112
- Host, DISM, runner, run: R1 identity line
- Location: lookup 6681422 (0x65F34E), entries 0 to 11, 50 bytes each
- Bytes (entries 0 and 11):

  ```text
  0065f34e: 1505 0000 0000 0006 b9ca 0900 0000 0000
  0065f35e: a812 0000 0000 0000 0100 0100 0000 484d
  0065f36e: cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb b9f8
  0065f37e: c6a5
  0065f574: 1905 0000 0000 0006 35ee 6500 0000 0000
  0065f584: a812 0000 0000 0000 0100 0100 0000 9474
  0065f594: 5705 2e3f 7ddc a255 9e1b c07a b402 be8a
  0065f5a4: a7ce
  ```

- Observation: the first 12 of 194 entries have flags 0x06
  (metadata + compressed); no other entry has 0x02. Their offsets
  rise with entry number (641721 to 6680117). Each metadata resource
  was decoded (OBS-012) and searched for the SHA-1 of its tree's
  `bin\random-1.bin` (distinct per tree in `trees.txt`): entry k
  (0-based) contains only tree-(k+1)'s hash. `commands.log` captures
  tree-nn as `/Name:USGP-S04-nn`, and the XML gives that name
  `INDEX="nn"` (OBS-014). The same layout (metadata entries first) is
  in S01, S02, S05, S09 and S06 part 1.
- Conclusion: in S04, the k-th lookup entry with the metadata flag is
  the metadata of image index k, and metadata entries come first in
  the table. In S04 lookup order, file-offset order and index order
  are the same, so this sample cannot tell which of them a reader
  should use; that stays open.
- Also seen in: S06 part 1 (same 12 entries, same order)
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/wim/check.rs`,
  `crates/usgp-image/src/testkit/builder.rs`,
  `crates/usgp-image/tests/dism_samples.rs` (`// FORMAT: OBS-009` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-010: whole resources that do not compress are stored raw

- Status: Recorded
- Settles: OPEN-WIM-5, partly (resource level only)
- Sample: S09 (S09.wim, 2e5f189c0a3e45ae), S02 (6b3a317d2b4dec47)
- Command: R1 commands S09 and S02 (both `/Compress:fast`)
- Source tree: tree-inc, seed 201, `random-65536.bin`; tree-01
- Host, DISM, runner, run: R1 identity line
- Location: S09 lookup 66174 (0x1027E), 100 bytes; S09 offsets 208
  (0xD0) and 32976 (0x80D0), 32 bytes each
- Bytes:

  ```text
  0001027e: ae01 0000 0000 0006 d000 0100 0000 0000
  0001028e: 9002 0000 0000 0000 0100 0100 0000 86f1
  0001029e: 3062 752a 0af3 7b0f 3a27 46ca bdfd 8813
  000102ae: a297 0000 0100 0000 0000 d000 0000 0000
  000102be: 0000 0000 0100 0000 0000 0100 0100 0000
  000102ce: 7790 5d56 ebad 050c 24ec febc 658c daf0
  000102de: 71bd dd5f
  000000d0: 4662 4a85 f20e 75a0 2559 1a62 ca5d f721
  000000e0: 5dc9 f60a 0e1c af41 dbec 51ce 7793 70ad
  000080d0: 702f 5e73 2c60 1d56 ffc1 3c6f 74fa c535
  000080e0: 7921 bc82 c81e 69e7 1590 c5a7 0bcb d455
  ```

- Observation: S09's file entry has stored size 65536, flags 0x00,
  offset 208, original 65536, hash
  `77905d56ebad050c24ecfebc658cdaf071bddd5f`, the `trees.txt` SHA-1 of
  `random-65536.bin`. The bytes at 208 and at 208 + 32768 equal the
  bytes `trees.txt` lists for file offsets 0 and 32768. There is no
  chunk table. In S02 (an XPRESS file) 14 of 17 file entries have
  flags 0x00 and stored == original: all pseudorandom files, and every
  file of 59 bytes or less; only three text files (30081, 2335 and
  367034 bytes) and the metadata have 0x04.
- Conclusion: in R1, inside a file whose header says XPRESS, DISM
  stores a resource that did not compress as plain bytes with the
  compressed flag (0x04) clear and no chunk table. A reader must
  accept uncompressed resources in a compressed file and decide per
  resource by flag 0x04. **Not observed:** a resource with flag 0x04
  in which one chunk did not shrink; no compressed chunk in R1 has a
  stored size equal to its expanded size (OBS-012). How such a chunk is
  stored stays open.
- Also seen in: S04, S05, S06 parts (same pattern for the same kinds
  of file)
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/wim/resource.rs`,
  `crates/usgp-image/src/testkit/builder.rs`,
  `crates/usgp-image/tests/check.rs` (`// FORMAT: OBS-010` or a comment
  or test naming the record; filled in fix round 1, CR-601)

### OBS-011: chunk table layout below 4 GiB

- Status: Recorded
- Settles: `wim.md` §4 [reading] items (first chunk has no entry;
  entries relative to the end of the table) and [derived] last-chunk
  size; OPEN-WIM-10 partly (width 4 when original size is below
  2^32; the threshold is not addressed)
- Sample: S02 (6b3a317d2b4dec47)
- Command: R1 command S02
- Source tree: tree-01, `text\words-large.txt` (367034 bytes, SHA-1
  `aa2cf6a6cc3f67648fe40af298323529a8a5cd4c`)
- Host, DISM, runner, run: R1 identity line
- Location: lookup entry 17 at 643872 (0x9D320); resource at 573058
  (0x8BE82), first 44 bytes
- Bytes:

  ```text
  0008be82: 1118 0000 0f30 0000 d847 0000 9b5f 0000
  0008be92: 7577 0000 348f 0000 d4a6 0000 8dbe 0000
  0008bea2: 55d6 0000 40ee 0000 1306 0100 0000 0000
  ```

- Observation: the entry gives stored 68663, flags 0x04, original
  367034, so ceil(367034 / 32768) = 12 chunks. The resource starts
  with 11 four-byte values 6161, 12303, 18392, ..., 60992, 67091,
  then (at 573102) the first chunk. Taking the values as end offsets
  of chunks 0 to 10 measured from the end of the 44-byte table, and
  the last chunk as 68663 - 44 - 67091 = 1528 bytes, each of the 12
  chunks decodes to 32768 bytes (the last to 6586) and the
  concatenation has the SHA-1 above (OBS-012). The same reading
  decodes every compressed resource in R1 (83 resources, 369 chunk
  instances) to its lookup SHA-1; all have original size below 2^32.
- Conclusion: for resources under 2^32 bytes in R1, the chunk table
  has ceil(original / 32768) - 1 entries of 4 bytes; entry i is the
  end of chunk i (start of chunk i + 1) relative to the end of the
  table; chunk 0 starts right after the table; the last chunk runs to
  the end of the stored size. A one-chunk resource has no table.
  Width above 4 GiB and the exact threshold need S08.
- Also seen in: S04, S05, S09, S06 parts
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/wim/resource.rs`,
  `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/tests/dism_samples.rs` (`// FORMAT: OBS-011` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-012: WIM XPRESS is [MS-XCA] LZ77+Huffman, one table per chunk

- Status: Recorded
- Settles: OPEN-WIMC-1, parts 1 and 2 (codec; block rule)
- Sample: S02 (6b3a317d2b4dec47), S04 (d59d219ec33c8b1d), S05
  (3f1320d8b35d1dfc), S09 (2e5f189c0a3e45ae), S06 parts 1 to 7
- Command: R1 commands S02, S04, S05, S09, S06
- Source tree: tree-01 to tree-12, tree-inc
- Host, DISM, runner, run: R1 identity line
- Location: S02 resource of `shared\common.txt` at 168190 (0x290FE),
  stored 5698, original 30081, one chunk; first 272 bytes and last 16
- Bytes:

  ```text
  000290fe: 0000 0000 000b b000 0000 0000 0000 0000
  0002910e: 0800 0000 0000 0000 8978 989a aa09 0000
  0002911e: 0000 0000 0000 0000 0000 0000 0000 0000
  0002912e: 90bc 9bcb 9acc c89b 0c0a c90c 0b00 0000
  0002913e: 0000 0000 0000 0000 0000 0000 0000 0000
  ...
  0002917e: 0b00 0000 0000 0000 0000 0000 0000 0000
  0002918e: 0089 0bab b00b 0000 00ba 890a 0bb0 b000
  ...
  000291ee: 0000 00aa b000 00b0 0000 0000 0000 0000
  000291fe: ecca be7d 37be ab4b d78d 1efb 67bf ed1b
  ...
  0002a730: faf2 540b 0587 c6d8 7d9d ad7f 40f7 0000
  ```

- Observation: each chunk starts with 256 bytes read as 512 4-bit
  code lengths (even symbol in the low nibble); in the excerpt byte
  128 (`0b`) gives symbol 256 length 11 and symbol 257 length 0, and
  the lengths fill the code space exactly (§3.2). Decoding the rest
  with the bit reading, match length and match offset rules of
  `wim-compression.md` §3.3 to §3.5 gives exactly the expected chunk
  size. For all 83 compressed resources in
  the 11 XPRESS files (369 chunk instances; S04 and S06 repeat S02's
  resources), the decoded resource has the SHA-1 of its lookup entry.
  Every chunk used exactly one 256-byte table (one block): no chunk
  expands beyond 32768 bytes. 49236 matches used the one-byte length
  extension (§3.4); none used the 16-bit form or the 32-bit form.
  The project's WU-X decoder (`XpressDecoder::decode_chunk`, run as
  described under R1) returned success for all 369 chunk instances,
  and its output for all 83 resources has the lookup SHA-1.
- Conclusion: in R1, the "XPRESS" of the header flag 0x00020000 is
  [MS-XCA] LZ77+Huffman, applied to each 32 KiB chunk on its own, with
  one Huffman table per chunk; the 65536-byte block rule never splits a
  WIM chunk.
- Also seen in: none (one run)
- Cited by: `crates/usgp-image/src/codec/xpress.rs`,
  `crates/usgp-image/src/wim/resource.rs`,
  `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/testkit/xpress_enc.rs`,
  `crates/usgp-image/tests/dism_samples.rs` (`// FORMAT: OBS-012` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-013: every XPRESS chunk ends with symbol 256 at the input end

- Status: Recorded
- Settles: OPEN-WIMC-1, part 3 (end symbol); WU-X framing questions 1
  to 3 (`impl-notes-wux.md`)
- Sample: S02, S04, S05, S09, S06 parts 1 to 7 (as OBS-012)
- Command: R1 commands S02, S04, S05, S09, S06
- Source tree: as OBS-012
- Host, DISM, runner, run: R1 identity line
- Location: last bytes of chunks; examples: S02 `common.txt` chunk end
  at 173888 (0x2A740); S02 `words-large.txt` chunk 0 end at 579263
  (0x8D6BF); S02 `words-small.txt` end at 373057 (0x5B141); S02
  metadata end at 643022 (0x9CFCE)
- Bytes (last 8 or 16 bytes of each example chunk):

  ```text
  0002a730: faf2 540b 0587 c6d8 7d9d ad7f 40f7 0000
  0008d6b7: f741 7f3b 00b4 0000
  0005b139: 4cde 8998 007a 0000
  0009cfc6: 4721 efc0 5603 0000
  ```

- Observation: decoding with the [MS-XCA] reader of
  `wim-compression.md` §3.3 (two 16-bit units loaded after the table,
  one more each time 16 bits are used), in all 369 chunk instances:
  (a) when the output reaches the expected chunk size, the next symbol
  is 256; (b) at that moment the input position, counting the two
  preloaded units, equals the chunk's stored size exactly; (c) no
  refill ever needed bytes beyond the stored size; (d) the bits left
  in the register after symbol 256 are all zero (0 to 15 of them);
  (e) every chunk's last two bytes are `00 00`; (f) symbol 256 also
  occurs 87 times before the end, where it was decoded as a match
  (length 3 from header 0, offset 1 with 0 extra bits) and the
  resource SHA-1 still matched. The project's WU-X decoder, which
  requires symbol 256 with all input consumed (its rules 2 and 3),
  accepted every chunk and produced the lookup SHA-1 (OBS-012).
- Conclusion: in R1, DISM ends every XPRESS chunk with symbol 256,
  placed so that it is read exactly when all of the chunk's stored
  bytes have been consumed under the [MS-XCA] reading rule. WU-X
  question 1 (lookahead past the end): never needed by these chunks.
  Question 2 ("all input read" = input position equals input length):
  holds in every chunk. Question 3 (output full without symbol 256 is
  an error): every chunk has the end symbol, so the rule refuses none
  of R1's chunks.
- Also seen in: none (one run)
- Cited by: `crates/usgp-image/src/codec/xpress.rs`,
  `crates/usgp-image/src/testkit/xpress_enc.rs` (`// FORMAT: OBS-013` or
  a comment or test naming the record; filled in fix round 1, CR-601)

### OBS-014: XML data content and encoding in our samples

- Status: Recorded
- Settles: OPEN-WIM-8, partly (what DISM writes for non-Windows
  content); `wim.md` §7 [reading] UTF-16 and BOM
- Sample: S01 (a137931caa9f657d), S04 (d59d219ec33c8b1d); also S02,
  S03, S05, S07, S09, S06 parts
- Command: R1 commands S01 and S04
- Source tree: tree-01; tree-01 to tree-12
- Host, DISM, runner, run: R1 identity line
- Location: S01 XML at 971729 (0xED3D1), 962 bytes; S04 XML at
  6691122 (0x661932), 10414 bytes
- Bytes:

  ```text
  S01 000ed3d1: fffe 3c00 5700 4900 4d00 3e00 3c00 5400
  S01 000ed3e1: 4f00 5400 4100 4c00 4200 5900 5400 4500
  S01 000ed783: 4500 3e00 3c00 2f00 5700 4900 4d00 3e00
  S04 00661932: fffe 3c00 5700 4900 4d00 3e00 3c00 5400
  S04 006641d0: 4500 3e00 3c00 2f00 5700 4900 4d00 3e00
  ```

  S01 XML decoded as UTF-16LE after the two-byte mark (one line here;
  the file has no line breaks):

  ```text
  <WIM><TOTALBYTES>971729</TOTALBYTES><IMAGE INDEX="1"><DIRCOUNT>11</DIRCOUNT><FILECOUNT>21</FILECOUNT><TOTALBYTES>965911</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES><CREATIONTIME><HIGHPART>0x01DD662B</HIGHPART><LOWPART>0x861D7446</LOWPART></CREATIONTIME><LASTMODIFICATIONTIME><HIGHPART>0x01DD662B</HIGHPART><LOWPART>0x861EA27E</LOWPART></LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>USGP-S01-01</NAME><DESCRIPTION>usgp-sample-S01-index-01-uncompressed</DESCRIPTION></IMAGE></WIM>
  ```

- Observation: every R1 XML resource starts with `ff fe` and is
  UTF-16LE with no XML declaration, no line breaks and no trailing
  zero unit; its length is even and it ends with `</WIM>`. The only
  element names in any R1 XML (S04 checked in full) are `WIM`,
  `TOTALBYTES`, `IMAGE` (attribute `INDEX`), `DIRCOUNT`, `FILECOUNT`,
  `HARDLINKBYTES`, `CREATIONTIME`, `LASTMODIFICATIONTIME`, `HIGHPART`,
  `LOWPART`, `WIMBOOT`, `NAME` and `DESCRIPTION`, in that order per
  image. S04 has `INDEX="1"` to `"12"` in order, each with the name
  and description of `editions.tsv`. `HIGHPART` and `LOWPART` are
  written as `0x` and eight upper-case hex digits; read as the halves
  of a 100 ns count since 1601-01-01, S01's creation time is
  2026-10-27 15:55:01.07 UTC, inside the S01 capture's
  `commands.log` window (15:55:00.67 to 15:55:01.10). There is no
  `FLAGS` and no `WINDOWS` element. DISM's `/Get-WimInfo /Index:1`
  for S01 reports Architecture, Version, Edition, Installation,
  ProductType and Languages as `<undefined>`. The image `TOTALBYTES`
  equals DISM's reported size and the tree size in `commands.log`
  (965911 for tree-01). The top-level `TOTALBYTES` equals the XML's
  own offset in S01 to S05 and S09, the file length in S07, and S04's
  value (6691122) in every S06 part.
- Conclusion: for content that is not a Windows installation, DISM in
  R1 writes `NAME` and `DESCRIPTION` exactly as given and no `FLAGS`
  or `WINDOWS` element; the file therefore carries no edition,
  architecture, version or language facts, and none can be observed
  from our samples. Where a Windows image records them stays open;
  under decision 0013 those facts are operator-declared. The XML is
  UTF-16LE with a byte-order mark.
- Also seen in: S02, S03, S05, S07, S09, S06 parts (same element set)
- Cited by: `crates/usgp-image/src/wim/xml.rs`,
  `crates/usgp-image/src/facts.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-014` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-015: integrity table: 10 MiB chunks over header end to lookup end

- Status: Recorded
- Settles: OPEN-WIM-11, partly (unit; range; one-entry case only)
- Sample: S05 (S05.wim, 3f1320d8b35d1dfc)
- Command: R1 command S05 (`/Compress:fast /CheckIntegrity`)
- Source tree: tree-01
- Host, DISM, runner, run: R1 identity line
- Location: offset 644888 (0x9D718), 32 bytes (header at 124, OBS-007)
- Bytes:

  ```text
  0009d718: 2000 0000 0100 0000 0000 a000 e11f 998a
  0009d728: 9597 4140 7fca aacf 950d a668 e1d7 129d
  ```

- Observation: table size 32; entry count 1; chunk size 0x00A00000 =
  10485760 = 10 x 2^20; one 20-byte hash
  `e11f998a959741407fcaaacf950da668e1d7129d`. The SHA-1 (computed
  with Python `hashlib`) of file bytes 208 to 643921 (643714 bytes:
  end of header to end of lookup table, lookup at 643022 + 900) is
  exactly that hash.
  SHA-1 of bytes 208 to the end of the XML, or of 0 to the end of the
  lookup table, does not. The hashed length is below one chunk, so
  only one entry exists. Header flags are the same as S02's (OBS-005).
- Conclusion: in R1 the integrity chunk size field is 10485760 (the
  paper's "10MB" is 10 MiB here), the hashed range starts at `cbSize`
  (208) and ends at the end of the lookup table, and the XML is not
  hashed. The split of a range longer than one chunk, and the size of
  the last chunk, were not observed.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/integrity.rs`,
  `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`// FORMAT: OBS-015` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-016: parts of a split set share one GUID

- Status: Recorded
- Settles: OPEN-WIM-9, partly (the field the parts share)
- Sample: S06 parts 1 to 7 (S06.swm to S067.swm); S04 (source)
- Command: R1 command S06 (`/Split-Image ... /FileSize:1`)
- Source tree: S04.wim
- Host, DISM, runner, run: R1 identity line
- Location: offsets 16 to 47 (0x10 to 0x2F)
- Bytes:

  ```text
  S04  00000010: 8200 0200 0080 0000 9cbf bdf0 8c05 f843
  S04  00000020: 8185 723a 704e 553f 0100 0100 0c00 0000
  S06  00000010: 8a00 0200 0080 0000 2870 895f 9500 1f4e
  S06  00000020: 9ca9 2dab c455 c5f7 0100 0700 0c00 0000
  S062 00000010: 8a00 0200 0080 0000 2870 895f 9500 1f4e
  S062 00000020: 9ca9 2dab c455 c5f7 0200 0700 0c00 0000
  S067 00000010: 8a00 0200 0080 0000 2870 895f 9500 1f4e
  S067 00000020: 9ca9 2dab c455 c5f7 0700 0700 0c00 0000
  ```

- Observation: the 16 bytes at 24 are the same in all seven parts and
  differ from S04's. The part number at 40 is 1 to 7 in `S06.swm`,
  `S062.swm`, ... `S067.swm`; the total at 42 is 7 in all; the image
  count at 44 is 12 in all. S04 itself has part 1 of 1.
- Conclusion: in R1 the parts of one split set carry one shared GUID,
  new for the set, with part numbers 1 to N and total N. How DISM
  itself decides that files belong together is not observable; the
  shared GUID plus part and total is what the files offer.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/header.rs` (`// FORMAT: OBS-016`
  or a comment or test naming the record; filled in fix round 1, CR-601)

### OBS-017: split parts: header flag 0x08, no resource flag 0x08

- Status: Recorded
- Settles: "Split flags" item; differs from `wim.md` §10 summary on
  where the lookup table and XML are
- Sample: S06 parts 1 to 7
- Command: R1 command S06
- Source tree: S04.wim
- Host, DISM, runner, run: R1 identity line
- Location: header offset 16; part 1 lookup at 926211 (0xE2203),
  2100 bytes; part 2 lookup at 974277 (0xEDDC5), 1300 bytes
- Bytes:

  ```text
  S06  000e2203: 1505 0000 0000 0006 d000 0000 0000 0000
  S06  000e2213: a812 0000 0000 0000 0100 0100 0000 484d
  S062 000eddc5: 410d 0300 0000 0000 d000 0000 0000 0000
  S062 000eddd5: 410d 0300 0000 0000 0200 0100 0000 93eb
  ```

- Observation: every part has header flags 0x0002008A (S04's flags
  plus 0x08). Every part has its own lookup table and XML; the XML is
  byte-identical in all parts and to S04's (10414 bytes). Each part's
  lookup lists only resources stored in that part, each with part
  number equal to the part's own number (part 1: 42 entries, 2: 26,
  3: 28, 4: 25, 5: 27, 6: 29, 7: 17); together they are S04's 194
  entries with no hash repeated. All 12 metadata entries (flags 0x06)
  are in part 1, at offsets 208 onwards; part 1 also holds 30 file
  resources. No entry in any part has resource flag 0x08; the flags
  seen are 0x00, 0x04 and 0x06. Boot and integrity headers are zero.
- Conclusion: in R1 a split part is marked by header flag 0x08 and a
  total part count above 1, not by resource flags. Unlike our §10
  summary ("later parts hold ... lookup table, XML data"), part 1 also
  has a lookup table and XML, and every part has both. A reader that
  refuses split files (decision 0014) can do so from the header.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/header.rs`,
  `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/tests/negative.rs`,
  `crates/usgp-image/tests/dism_samples.rs` (`// FORMAT: OBS-017` or a
  comment or test naming the record; filled in fix round 1, CR-601)

### OBS-018: two images with identical metadata share one entry's bytes

- Status: Recorded
- Settles: `wim.md` §13 S11 (two resources, one shared range, or a
  DISM refusal: one shared range); OPEN-WIM-6, part 2, for this case
- Sample: S11A (S11A.wim, a62b1c5074edec45), S11B (S11B.wim,
  b4178b296ff73cb7)
- Command: R2 commands S11A (capture of tree-01, then `/Append-Image`
  of tree-01 as `USGP-S11A-02`) and S11B (`/Export-Image` of S02.wim
  index 1 to a new file, then again to the same file with
  `/DestinationName:USGP-S11B-02`)
- Source tree: tree-01, seed 101 (S11B: by way of R2 S02.wim)
- Host, DISM, runner, run: R2 identity line
- Location: S11A lookup 644882 (0x9D712), entries 0 and 1, 100 bytes;
  S11B lookup 644868 (0x9D704), entries 0 and 1, 100 bytes
- Bytes:

  ```text
  S11A 0009d712: 1505 0000 0000 0006 b9ca 0900 0000 0000
  S11A 0009d722: a812 0000 0000 0000 0100 0100 0000 484d
  S11A 0009d732: cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb b9f8
  S11A 0009d742: c6a5 1505 0000 0000 0006 b9ca 0900 0000
  S11A 0009d752: 0000 a812 0000 0000 0000 0100 0100 0000
  S11A 0009d762: 484d cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb
  S11A 0009d772: b9f8 c6a5
  S11B 0009d704: 1505 0000 0000 0006 b9ca 0900 0000 0000
  S11B 0009d714: a812 0000 0000 0000 0100 0100 0000 484d
  S11B 0009d724: cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb b9f8
  S11B 0009d734: c6a5 1505 0000 0000 0006 b9ca 0900 0000
  S11B 0009d744: 0000 a812 0000 0000 0000 0100 0100 0000
  S11B 0009d754: 484d cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb
  S11B 0009d764: b9f8 c6a5
  ```

- Observation: in both files the header records 2 images, and the
  lookup table (19 entries) starts with exactly two entries with flag
  0x02. In each file those two entries are equal in all 50 bytes:
  stored 1301, flags 0x06, offset 641721, original 4776, part 1,
  reference count 1, SHA-1 `484dcebe99b4b4ee93d75cb90dcc35cbb9f8c6a5`
  (the same values as R2 S02's single metadata entry). No other entry
  in either file has flag 0x02. No other byte range in the file holds
  a second copy of that resource: the only ranges named by entries are
  these, 17 file resources, the lookup table and the XML. The 1301
  bytes at 641721 decode to 4776 bytes with that SHA-1 (`metamap.py`
  plus `xpr.py`, and the product's reader in `dism_samples.rs`); the
  decoded data holds tree-01's `bin\random-1.bin` hash. DISM's own
  `/Get-WimInfo` lists index 1 and 2 for both files (S11A:
  `USGP-S11A-01`, `USGP-S11A-02`; S11B: `USGP-S02-01`,
  `USGP-S11B-02`, both with the source's description
  `usgp-sample-S02-index-01-fast`), each 965,911 bytes.
- Conclusion: in S11A and S11B, two images whose metadata is identical
  are written as one metadata resource named by two adjacent lookup
  entries equal in every byte, reference count 1 each. Lookup position
  still gives the index (the XML names two images); DISM did not
  refuse either step. Whether DISM does the same for three or more
  images, or for identical images that are not adjacent in index
  order, was not observed.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/wim/check.rs`,
  `crates/usgp-image/src/error.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`reuse_metadata`),
  `crates/usgp-image/tests/check.rs`,
  `crates/usgp-image/tests/negative.rs`,
  `crates/usgp-image/tests/dism_samples.rs`,
  `fuzz/fuzz_targets/wim_lookup.rs`, `fuzz/fuzz_targets/wim_check.rs`

### OBS-019: file reference counts in S11 do not equal a use count

- Status: Recorded
- Settles: nothing; qualifies the reference-count reading of OBS-008
- Sample: S11A (a62b1c5074edec45), S11B (b4178b296ff73cb7), R2 S02
  (S02.wim, bbfccc22f6834fe1), R1 S02 (6b3a317d2b4dec47)
- Command: R2 commands S11A, S11B, S02; R1 command S02
- Source tree: tree-01, seed 101; `names\*.txt` are five 23-byte files
  with one SHA-1, `6639623d0df61f7ab55eed28a8b1d3c51d3ccd4d`
  (`trees.txt`)
- Host, DISM, runner, run: R2 identity line; R1 identity line for R1
  S02
- Location: S11A entry 7 at 645232 (0x9D870); S11B entry 9 at 645318
  (0x9D8C6); R2 S02 entry 8 at 643422 (0x9D15E); R1 S02 entry 6 at
  643322 (0x9D0FA); S11A entry 2 at 644982 (0x9D776); 50 bytes each
- Bytes:

  ```text
  S11A   0009d870: 1700 0000 0000 0000 d090 0100 0000 0000
  S11A   0009d880: 1700 0000 0000 0000 0100 0900 0000 6639
  S11B   0009d8c6: 1700 0000 0000 0000 7017 0400 0000 0000
  S11B   0009d8d6: 1700 0000 0000 0000 0100 0a00 0000 6639
  R2 S02 0009d15e: 1700 0000 0000 0000 7017 0400 0000 0000
  R2 S02 0009d16e: 1700 0000 0000 0000 0100 0200 0000 6639
  R1 S02 0009d0fa: 1700 0000 0000 0000 d090 0100 0000 0000
  R1 S02 0009d10a: 1700 0000 0000 0000 0100 0500 0000 6639
  S11A   0009d776: 0100 0000 0000 0000 d000 0000 0000 0000
  S11A   0009d786: 0100 0000 0000 0000 0100 0200 0000 3014
  ```

- Observation: every file resource of S11A and S11B has one entry
  (no hash repeated among the 17 file entries), and both images use
  all of them. Every file entry except the `names\*.txt` one has
  reference count 2 (S11A entry 2 above: `bin\random-1.bin`, count 2;
  R2 S02 has count 1 on the same resource). The `names\*.txt` entry has
  count 9 in S11A and 10 in S11B. The same command captured the same
  tree in R1 S02 and R2 S02; that entry has count 5 in R1 S02 and 2 in
  R2 S02. Its offset differs too (102608 in R1, 268144 in R2), so the
  order in which DISM stored the files differs between the two runs.
- Conclusion: in these files a resource used once per image by two
  images has reference count 2, but the count on a resource used
  several times per image is not a stable function of its uses (5, 2,
  9 and 10 for 5, 5, 10 and 10 uses). A reader should not rely on
  reference counts; the checker does not read them except as part of
  the 50-byte equality of OBS-018.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/lookup.rs` (equality includes
  the count; no rule on its value)

### OBS-020: superseded lookup tables and XML stay in the file, unnamed

- Status: Recorded
- Settles: partly `wim.md` §13 S12 ("whether unused space is left in
  the file"): yes. Narrows OBS-008's "no gap" to single-step files
- Sample: S11A, S11B, S12A, S12B (hashes as above), R2 S04 (S04.wim,
  edf3db30578e78b2), R2 S01 (S01.wim, b1d7a9b7626763f7), R2 S02
  (bbfccc22f6834fe1); R1 S04 (d59d219ec33c8b1d)
- Command: R2 commands S01, S02, S04, S11A, S11B, S12A, S12B; R1
  command S04
- Source tree: as each sample
- Host, DISM, runner, run: R2 identity line; R1 identity line for R1
  S04
- Location: S11A 643022 to 644882 (1860 bytes); S11B 643022 to 644868
  (1846 bytes); S04 (R1 and R2) 11 ranges, the first 643022 to 644868;
  S12A 6681422 to 6701536 (20114 bytes); S12B 6681422 to 6720738
  (39316 bytes)
- Bytes: first bytes of the S11A range and of its XML part; the S12A
  range; the three places where the S11B range differs from R2 S02's
  lookup table and XML at the same offsets (S02 line first); the first
  entry, the last entry, the XML start and the XML end of the S12B
  post-delete table (6701536, 9650 bytes = 193 entries; XML 6711186 to
  6720738, 9552 bytes):

  ```text
  S11A 0009cfce: 1505 0000 0000 0006 b9ca 0900 0000 0000
  S11A 0009d352: fffe 3c00 5700 4900 4d00 3e00 3c00 5400
  S12A 0065f34e: 1505 0000 0000 0006 b9ca 0900 0000 0000
  S02  0009d16e: 1700 0000 0000 0000 0100 0200 0000 6639
  S11B 0009d16e: 1700 0000 0000 0000 0100 0500 0000 6639
  S02  0009d376: 3600 3400 3300 3900 3200 3200 3c00 2f00
  S11B 0009d376: 3600 3400 3400 3800 3600 3800 3c00 2f00
  S02  0009d5ce: 3900 4300 3100 4100 3400 3700 3100 3500
  S11B 0009d5ce: 3900 4500 4300 3100 4200 3700 3500 3500
  S12B 006641e0: 1505 0000 0000 0006 810a 1200 0000 0000
  S12B 00666760: 810c 0100 0000 0004 b4e1 6400 0000 0000
  S12B 00666770: f09a 0500 0000 0000 0100 0100 0000 2b2c
  S12B 00666792: fffe 3c00 5700 4900 4d00 3e00 3c00 5400
  S12B 00668cd2: 4500 3e00 3c00 2f00 5700 4900 4d00 3e00
  ```

- Observation: sorting every range the header and lookup table name
  (`gaps.py`) leaves these ranges named by nothing. In S11A the 1860 bytes are
  a 900-byte table of 18 entries (the first equal to the metadata entry of
  OBS-018) followed by 960 bytes of UTF-16LE XML with a BOM naming one image,
  `USGP-S11A-01`: the lookup table and XML of the first step. In S11B the 1846
  bytes are a 900-byte table and 946 bytes of XML naming `USGP-S02-01`; they
  differ from R2 S02's own lookup table and XML in 10 bytes: 1 in entry 8's
  reference count (2 in S02, 5 here), 4 in the digits of the top-level
  `TOTALBYTES` (643922 in S02, 644868 here) and 5 in the digits of a `LOWPART`
  time value. In S04 (both runs) each later image's file resources start after
  such a range, whose size is the previous step's table plus XML (1846, 3508,
  ..., 18452 bytes). In S12A the 20114 bytes are byte-identical to S04's
  lookup table and XML at the same offset. In S12B the 39316 bytes are S04's
  lookup table and XML (20114 bytes, identical), then a 9650-byte table (193
  entries of 50 bytes: S04's without the first metadata entry; its first entry
  names image 2's metadata at 1182337, its last a compressed file resource)
  and 9552 bytes of XML naming 11 images, the state after `/Delete-Image`. No
  range named by the live header or lookup table overlaps another, except
  OBS-018's.
- Conclusion: in these files each append, export, commit or delete
  writes a new lookup table and XML and leaves the old ones in place;
  the file then has unnamed ranges between resources. Single-step
  captures (R2 S01 and S02, by `gaps.py`) have none.
- Also seen in: R1 S04 (same 11 ranges)
- Cited by: `crates/usgp-image/src/wim/lookup.rs` (gaps allowed);
  `crates/usgp-image/tests/dism_samples.rs` (the builder does not write
  them; noted where the S11 layout is compared)

### OBS-021: after a commit of index 1, lookup order gives the index

- Status: Recorded
- Settles: OPEN-WIM-6, part 2, partly: in a file where lookup order and
  file-offset order differ, lookup order gives the index; `wim.md` §13
  S12 (mount and commit)
- Sample: S12A (S12A.wim, 5db80ce24d971a8c)
- Command: R2 command S12A: copy of S04.wim, `/Mount-Image /Index:1`,
  copy of tree-service under `usgp-serviced\`, `/Unmount-Image /Commit`
- Source tree: tree-01 to tree-12 (S04); tree-service, profile Service,
  seed 501: `serviced.txt` (57 bytes, SHA-1 a8ccfd6b...) and
  `serviced-40000.bin` (40000 bytes, SHA-1 880baf1c...) (`trees.txt`)
- Host, DISM, runner, run: R2 identity line
- Location: lookup 6743054 (0x66E40E), 9800 bytes; entries 0 and 1
- Bytes:

  ```text
  0066e40e: b505 0000 0000 0006 59de 6600 0000 0000
  0066e41e: c815 0000 0000 0000 0100 0100 0000 4d2a
  0066e42e: 61c8 4cf4 dc6d 2892 f572 a9d4 1685 09de
  0066e43e: 3017 1505 0000 0000 0006 810a 1200 0000
  0066e44e: 0000 a812 0000 0000 0000 0100 0100 0000
  0066e45e: 8cd0 4fe2 8cb6 18eb 02bd 69b1 9639 3ca7
  ```

- Observation: the table has 196 entries; the first 12 have flag 0x06
  and no other has 0x02. Entry 0 is stored 1461, offset 6741593,
  original 5576, SHA-1 `4d2a61c8...`; entries 1 to 11 are equal in all
  50 bytes to S04's entries 1 to 11 (offsets 1182337 rising to
  6680117). Entry 0's range ends at 6743054, where the lookup table
  starts, and lies after every other range the table names (the two new
  file entries end at 6741593). So in lookup order the metadata offsets
  are 6741593, then 1182337 to 6680117 rising: offset order and lookup
  order differ for entry 0 only. Decoded (`metamap.py`, `xpr.py`,
  `metahash.py`): entry 0 decodes to its SHA-1 and holds tree-01's
  `bin\random-1.bin` hash and the SHA-1 of both tree-service files;
  entry k (k = 1 to 11) holds tree-(k+1)'s
  hash. The XML gives `INDEX="1"` the name `USGP-S04-01` (tree-01,
  the mounted image) and `INDEX="k+1"` `USGP-S04-(k+1)`; DISM's
  `/Get-WimInfo` agrees.
- Conclusion: in S12A, committing index 1 writes that image's new
  metadata after every other resource and keeps its lookup entry
  first; the k-th metadata entry in lookup order is still image index
  k, so lookup order (not file-offset order) gives the index here.
  A commit of another index, or of several, was not observed.
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/src/wim/check.rs`,
  `crates/usgp-image/src/error.rs`,
  `crates/usgp-image/src/testkit/builder.rs` (`move_first_metadata`),
  `crates/usgp-image/tests/check.rs`,
  `crates/usgp-image/tests/negative.rs`,
  `crates/usgp-image/tests/dism_samples.rs`,
  `fuzz/fuzz_targets/wim_lookup.rs`

### OBS-022: a commit appends; the old metadata stays in place, unnamed

- Status: Recorded
- Settles: `wim.md` §13 S12, stale resources after a commit
- Sample: S12A (5db80ce24d971a8c), R2 S04 (edf3db30578e78b2)
- Command: R2 command S12A
- Source tree: as OBS-021
- Host, DISM, runner, run: R2 identity line
- Location: header 48 to 96; 641721 (0x9CAB9), 1301 bytes; 6701536
  (0x6642E0) onwards
- Bytes:

  ```text
  S12A 00000030: 4826 0000 0000 0002 0ee4 6600 0000 0000
  S04  00000030: e425 0000 0000 0002 4ef3 6500 0000 0000
  S12A 0009cab9: 7477 97a9 8898 87a9 87a7 8708 088a a988
  S12A 006709f2: 3900 0000 0000 0000 e041 6600 0000 0000
  S12A 00670a02: 3900 0000 0000 0000 0100 0100 0000 a8cc
  ```

- Observation: the first 6701536 bytes of S12A (S04's length) differ
  from S04 in 12 bytes, all within header offsets 48 to 88 (the lookup
  and XML resource headers). The 1301 bytes at 641721, which S04's
  entry 0 names (image 1's metadata, SHA-1 `484dcebe...`), are still
  there byte for byte; no S12A entry names them. After 6701536 come
  the new file resources (entries 194 and 195: 57 bytes at 6701536,
  `serviced.txt`; 40000 bytes at 6701593, `serviced-40000.bin`), the
  new metadata of OBS-021, the new lookup table and the new XML. All
  other file entries are unchanged.
- Conclusion: in S12A, `/Unmount-Image /Commit` left every existing
  byte except the header in place and appended the changes; the
  replaced metadata is a stale resource that nothing references.
- Also seen in: S12B (S04's image 1 metadata at 641721, unnamed after
  the delete; OBS-023)
- Cited by: `crates/usgp-image/src/testkit/builder.rs`
  (`move_first_metadata` leaves the stale copy),
  `crates/usgp-image/tests/check.rs`,
  `crates/usgp-image/tests/dism_samples.rs`

### OBS-023: delete then append keeps metadata offsets rising

- Status: Recorded
- Settles: `wim.md` §13 S12 (delete then append): lookup, offset and
  index order agree in this file
- Sample: S12B (S12B.wim, b5f93ddd9840a9f3)
- Command: R2 command S12B: copy of S04.wim, `/Delete-Image /Index:1`,
  `/Append-Image` of tree-01 as `USGP-S12B-12`
- Source tree: tree-01 to tree-12
- Host, DISM, runner, run: R2 identity line
- Location: lookup 6722039 (0x6691F7), entries 11 and 12; superseded
  post-delete table (OBS-020) entry 11 at 6702086 (0x664406)
- Bytes (live entries 11 and 12; then the superseded entry 11, whose
  reference count, bytes 26 to 29, is 0):

  ```text
  0066941d: 1505 0000 0000 0006 e28c 6600 0000 0000
  0066942d: a812 0000 0000 0000 0100 0100 0000 484d
  0066943d: cebe 99b4 b4ee 93d7 5cb9 0dcc 35cb b9f8
  0066944f: 0100 0000 0000 0000 d000 0000 0000 0000
  0066945f: 0100 0000 0000 0000 0100 0100 0000 3014
  00664406: 0100 0000 0000 0000 d000 0000 0000 0000
  00664416: 0100 0000 0000 0000 0100 0000 0000 3014
  00664426: 0397 fe38 ee61 f01e ff44 b5cf a482 85e4
  ```

- Observation: 194 entries; entries 0 to 10 are equal to S04's entries
  1 to 11; entry 11 has offset 6720738 and the SHA-1 of S04's deleted
  image 1 metadata (`484dcebe...`), written again rather than pointing
  at the old copy at 641721, which no entry names. Metadata offsets
  rise with lookup order. Decoded, entry k holds tree-(k+2)'s hash for
  k = 0 to 10 and entry 11 tree-01's; the XML names index 1 to 11
  `USGP-S04-02` to `USGP-S04-12` and index 12 `USGP-S12B-12`. Tree-01's
  file resources keep their S04 offsets (entry 12: offset 208, count
  1). The superseded post-delete table (OBS-020) lists those file
  entries with reference count 0.
- Conclusion: in S12B, deleting index 1 and appending the same tree
  renumbers the remaining images, adds new metadata at the end, reuses
  the stored file resources and leaves the deleted metadata unnamed.
  The checker accepted S12B before this change (CI run 40599556702).
- Also seen in: none
- Cited by: `crates/usgp-image/src/wim/lookup.rs`,
  `crates/usgp-image/tests/dism_samples.rs`

### OBS-024: security block length includes its header; root follows

- Status: Recorded
- Settles: OPEN-WIM-7, partly: the security block (M-01) and the root
  entry offset (M-02)
- Sample: S01 (S01.wim, c9a867bf22a6b8ea); S13 (S13.wim,
  6d7db6b9a24da4a1); S15 (S15.wim, bc1380fe88df68ca)
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: tree-01 (seed 101); tree-meta (seed 601); the VHD volume
  root holding tree-meta
- Host, DISM, runner, run: R3 identity line
- Location: start of each metadata resource: S01 file offset 966053
  (0xEBDA5), S13 401545 (0x62089), S15 401665 (0x62101)
- Bytes (S01, then S13):

  ```text
  000ebda5: 8c01 0000 0200 0000 e800 0000 0000 0000  ................
  000ebdb5: 8c00 0000 0000 0000                      ........
  00062089: 4404 0000 0700 0000 e800 0000 0000 0000  D...............
  ```

- Observation: S01: first 4 bytes 396, next 4 bytes 2, then two 8-byte
  values 232 and 140; 8 + 2 × 8 + 232 + 140 = 396, equal to the first
  field. The 4 bytes from 396 to 400 are zero and the root entry starts
  at 400. S13: 1092, 7 descriptors, 8 + 56 + their lengths = 1092, root
  at 1096. S15: 1308, 8 descriptors, sum 1308, root at 1312.
  `dentry_r3.py` reads every descriptor to the computed end without a
  gap in all three.
- Conclusion: in these files the first field is the length of the whole
  security block including its 8-byte header, the second is the
  number of descriptors (the [reading] of `wim.md` §6 is
  **confirmed**), each descriptor length is 8 bytes, the descriptors
  follow with no padding between them, and the root entry starts at the
  next multiple of 8 after the block, with zero bytes in between.
- Also seen in: S14 (decoded metadata, identical to S13: OBS-043)
- Cited by: none yet

### OBS-025: the root entry has an empty name and no parent field

- Status: Recorded
- Settles: OPEN-WIM-7, partly: the root entry (M-02)
- Sample: S01, S13, S15
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: as OBS-024
- Host, DISM, runner, run: R3 identity line
- Location: S01 file offset 966453 (0xEBF35), 104 bytes; S15 file
  offset 402977 (0x62621), 104 bytes
- Bytes (S01 root):

  ```text
  000ebf35: 6800 0000 0000 0000 1000 0000 0000 0000  h...............
  000ebf45: 0002 0000 0000 0000 0000 0000 0000 0000  ................
  000ebf55: 0000 0000 0000 0000 0000 8192 b17a dc01  .............z..
  000ebf65: 0000 8192 b17a dc01 0000 8192 b17a dc01  .....z.......z..
  000ebf75: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  000ebf85: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  000ebf95: 0000 0000 0000 0000                      ........
  ```

- Observation: the root is one entry of length 104 (0x68), not part of
  a list; its name-length field (+100, OBS-026) is 0, followed by two
  zero bytes; its children offset is 512 (0x200), where the top-level
  list starts. No entry in any R3 file has a field that holds its
  parent's offset; the walker rebuilds paths from the lists it walks.
  In S13 the root carries tree-meta's attributes, security and times
  (OBS-033, OBS-034); in S15 the volume root's (OBS-044).
- Conclusion: the root entry has the same layout as any entry, with a
  zero-length name; there is no parent field, so a reader must keep the
  parent path itself (as `wim.md` §6 says: "rebuilt by walking").
- Also seen in: S13 (offset 1096), S14
- Cited by: none yet

### OBS-026: the entry's fixed part is 102 bytes, not the derived 98

- Status: Recorded
- Settles: OPEN-WIM-7, partly: field positions of the fixed part
  (M-03); **contradicts** the [derived] 98-byte fixed part of `wim.md`
  §6
- Sample: S01, S13, S15 (all 33, 3057 and 3058 entries)
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: as OBS-024
- Host, DISM, runner, run: R3 identity line
- Location: S01 entry `bin`, file offset 966565 (0xEBFA5), 112 bytes
- Bytes:

  ```text
  000ebfa5: 7000 0000 0000 0000 1000 0000 0000 0000  p...............
  000ebfb5: d004 0000 0000 0000 0000 0000 0000 0000  ................
  000ebfc5: 0000 0000 0000 0000 0000 8192 b17a dc01  .............z..
  000ebfd5: 0000 8192 b17a dc01 0000 8192 b17a dc01  .....z.......z..
  000ebfe5: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  000ebff5: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  000ec005: 0000 0000 0600 6200 6900 6e00 0000 0000  ......b.i.n.....
  ```

- Observation: the name `bin` (6 bytes) is at entry offset 102, and its
  length (6) at 100. `dentry.py`, which reads `wim.md` §6's 98-byte
  layout (name length at 96), reads every name in S01, S13 and S15 as
  empty and stops on the first stream entry ("length 40 out of range").
  Read with `dentry_r3.py`, every entry fits this layout: +0 length (8),
  +8 attributes (4), +12 security index (4), +16 children offset (8),
  +24 and +32 (8 each, zero in every entry), +40, +48, +56 times (8
  each), +64 hash (20), **+84 four bytes (zero in every entry)**, +88
  the 8-byte reparse or hard-link union (OBS-035, OBS-036), +96 stream
  count (2), +98 short-name length (2), +100 name length (2), +102
  name. The order of the fields named by `wim.md` §6 is unchanged; the
  four bytes at +84 are not in the summary. Placing them before the
  union rather than after it is **[derived]** from the `wim.md` §6
  field order and OBS-036: with the union at +88 the reparse tag is its
  first half, as §6 orders it; read from +84, the tag would fall in the
  second half. Counts of non-zero values
  from `dentry_r3.py`: +24: 0, +32: 0, +84: 0 in each file.
- Conclusion: in these files the fixed part is 102 bytes; four zero
  bytes at +84 (placement before the union [derived]); the [derived] 98
  is wrong for them. What +24, +32 and +84 hold when non-zero is not
  shown (always zero here).
- Also seen in: S14
- Cited by: none yet

### OBS-027: names are UTF-16LE, then a 2-byte zero terminator

- Status: Recorded
- Settles: OPEN-WIM-7, partly: name encoding (M-04)
- Sample: S01 (`names\`), S13
- Command: R1 command S01; R3 command S13
- Source tree: tree-01 `names\` (Standard profile), tree-meta
- Host, DISM, runner, run: R3 identity line
- Location: S01 entry `names\<U+10400>-supplementary.txt`, file offset
  968901 (0xEC8C5), 144 bytes
- Bytes (from +32):

  ```text
  000ec8e5: 0000 0000 0000 0000 0000 8192 b17a dc01  .............z..
  000ec8f5: 0000 8192 b17a dc01 0000 8192 b17a dc01  .....z.......z..
  000ec905: 6639 623d 0df6 1f7a b55e ed28 a8b1 d3c5  f9b=...z.^.(....
  000ec915: 1d3c cd4d 0000 0000 0000 0000 0000 0000  .<.M............
  000ec925: 0000 0000 2800 01d8 00dc 2d00 7300 7500  ....(.....-.s.u.
  000ec935: 7000 7000 6c00 6500 6d00 6500 6e00 7400  p.p.l.e.m.e.n.t.
  000ec945: 6100 7200 7900 2e00 7400 7800 7400 0000  a.r.y...t.x.t...
  ```

- Observation: name length 40 (0x28); the name starts `01 d8 00 dc`,
  the UTF-16LE surrogate pair of U+10400, then `-supplementary.txt`;
  two zero bytes follow; the entry length 144 is exactly 102 + 40 + 2.
  All 33 S01 names (including U+00E9, U+03A9, U+65E5 U+672C and a
  space) and all 3057 S13 names decode as UTF-16LE to the names in the
  source manifests, and every name is followed by two zero bytes.
- Conclusion: the name is UTF-16LE (the [reading] is **confirmed**),
  its length field counts bytes without the terminator, a 2-byte zero
  terminator follows, and characters outside the BMP are stored as
  surrogate pairs.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-028: the short name follows the name's terminator

- Status: Recorded
- Settles: OPEN-WIM-7, partly: short-name placement (M-05)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta `shortnames\` on a volume with short names
  enabled; `dir /x` in `tree-meta.dirx.txt`
- Host, DISM, runner, run: R3 identity line
- Location: entry `shortnames\explicit-short-name-target.txt`, file
  offset 895545 (0xDAA39), 192 bytes; bytes from +96
- Bytes:

  ```text
  000daa99: 0000 1800 3c00 6500 7800 7000 6c00 6900  ....<.e.x.p.l.i.
  000daaa9: 6300 6900 7400 2d00 7300 6800 6f00 7200  c.i.t.-.s.h.o.r.
  000daab9: 7400 2d00 6e00 6100 6d00 6500 2d00 7400  t.-.n.a.m.e.-.t.
  000daac9: 6100 7200 6700 6500 7400 2e00 7400 7800  a.r.g.e.t...t.x.
  000daad9: 7400 0000 4500 5800 5000 4c00 4900 4300  t...E.X.P.L.I.C.
  000daae9: 4900 5400 2e00 5400 5800 5400 0000 0000  I.T...T.X.T.....
  ```

- Observation: +98 holds 24 (0x18), the byte length of `EXPLICIT.TXT`,
  the name set with `fsutil file setshortname`; the short name follows
  the long name's 2-byte terminator and is itself followed by two zero
  bytes. Generated short names (`LONGFI~1.TXT`, `LONGFI~2.TXT`,
  `NAMEWI~1.TXT`, `LONGDI~1`, the 3000 names in `many\`) are stored the
  same way and equal the `dir /x` listing. Names that need no short name
  (`SHORT.TXT`, `lower.txt`, `hard-two.txt`) have 0 at +98 and nothing
  after the name's terminator but padding. S01, captured from a runner
  volume without short names, has 0 at +98 in every entry.
- Conclusion: the short-name length is at +98 in bytes (UTF-16LE,
  without terminator); a non-empty short name is stored after the
  name's terminator, followed by its own 2-byte zero terminator.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-029: entry length is the used size rounded up to 8

- Status: Recorded
- Settles: OPEN-WIM-7, partly: entry alignment (M-06)
- Sample: S01, S13, S15
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: as OBS-024
- Host, DISM, runner, run: R3 identity line
- Location: every entry; examples in OBS-026 to OBS-028
- Bytes: S01 `bin` (OBS-026): 102 + 6 + 2 = 110, length 112, two zero
  bytes of padding; `<U+10400>-supplementary.txt` (OBS-027): 144 = 144,
  no padding; `explicit-short-name-target.txt` (OBS-028): 102 + 60 +
  2 + 24 + 2 = 190, length 192.
- Observation: `dentry_r3.py` checks for each entry that the length
  field equals the used size (fixed part, name, terminator, short name
  and its terminator) rounded up to a multiple of 8 and that the padding
  is zero, and for each stream entry the same with 38 + name + 2. It
  holds for all 33, 3057 and 3058 entries and all stream entries except
  one: the entry of `special\sparse-196608.bin` (S13 and S15), whose
  length is 192 for a used size of 164; the bytes after the padding to
  168 are not zero (OBS-039). Each entry's stream entries start at the
  entry's offset plus its length; the next sibling starts where the
  last stream entry ends; there is no other gap. Every length is a
  multiple of 8, so every entry starts at a multiple of 8.
- Conclusion: entries and stream entries are 8-byte aligned by their
  own length fields; a reader must advance by the length field, not by
  the size it computes, because at least one entry kind (sparse files)
  carries further bytes inside its length.
- Also seen in: S14
- Cited by: none yet

### OBS-030: lists end with 8 zero bytes; empty directories point at one

- Status: Recorded
- Settles: OPEN-WIM-7, partly: end marker, children offset, empty
  directory (M-07)
- Sample: S01, S13
- Command: R1 command S01; R3 command S13
- Source tree: tree-01 `empty-dir\`; tree-meta
- Host, DISM, runner, run: R3 identity line
- Location: S01 entry `empty-dir`, file offset 966677 (0xEC015), and
  bytes 2328 to 2344 of the metadata, file offset 968381 (0xEC6BD)
- Bytes:

  ```text
  000ec015: 8000 0000 0000 0000 1000 0000 0000 0000  ................
  000ec025: 2009 0000 0000 0000                       .......
  000ec6bd: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  ```

- Observation: `empty-dir` has children offset 2336 (0x920); the 8
  bytes at 2336 are zero, and the next list (`names`, offset 2344)
  follows them. Every list in S01 (12), S13 (21) and S15 (22) ends with
  8 zero bytes where the next entry's length would be. Each non-zero
  children offset is the offset, from the start of the metadata
  resource, of the first entry of that directory's list. Files,
  symbolic links and junctions have children offset 0.
- Conclusion: in these files the children offset points at the first
  child entry; a list ends with a 64-bit zero; an empty directory has a
  non-zero children offset that points directly at that zero.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-031: empty content has an all-zero hash and no lookup entry

- Status: Recorded
- Settles: OPEN-WIM-7, partly: empty files and streams (M-08)
- Sample: S01, S13
- Command: R1 command S01; R3 command S13
- Source tree: tree-01 `text\empty.txt`; tree-meta `streams\`
- Host, DISM, runner, run: R3 identity line
- Location: S01 `text\empty.txt` hash, file offset 970117 (0xECD85),
  20 bytes
- Bytes: `0000 0000 0000 0000 0000 0000 0000 0000 0000 0000`
- Observation: `text\empty.txt` (0 bytes) has an all-zero hash, and no
  lookup entry has an all-zero hash. In S13 the unnamed stream entry of
  `streams\empty-main.txt` (empty main stream) and the named stream
  `usgp-zero` (0 bytes) also have all-zero hashes. Every non-zero hash
  in S01, S13 and S15 entries and stream entries names a lookup entry
  (`dentry_r3.py` prints no `NOT IN LOOKUP`).
- Conclusion: empty content, in a main or a named stream, is stored as
  an all-zero hash with no resource (consistent with OBS-008).
- Also seen in: S14, S15
- Cited by: none yet

### OBS-032: stream entries follow the entry; unnamed one carries data

- Status: Recorded
- Settles: OPEN-WIM-7, partly: alternate stream entries (M-09)
- Sample: S01 (`text\with-stream.txt`), S13 (`streams\`)
- Command: R1 command S01; R3 command S13
- Source tree: tree-01; tree-meta `streams\` (`tree-meta.manifest.tsv`
  lists each named stream with its length)
- Host, DISM, runner, run: R3 identity line
- Location: S13 `streams\two-streams.txt` bytes +84 to +104, file
  offset 897733 (0xDB2C5), and its three stream entries, file offset
  897809 (0xDB311), 152 bytes
- Bytes:

  ```text
  000db2c5: 0000 0000 0000 0000 0000 0000 0300 1800  ................
  000db2d5: 1e00 7400                                ..t.
  000db311: 2800 0000 0000 0000 0000 0000 0000 0000  (...............
  000db321: bbad 271f c8d9 ecd5 7404 38d1 f0a5 3423  ..'.....t.8...4#
  000db331: f0ab 899d 0000 0000 3800 0000 0000 0000  ........8.......
  000db341: 0000 0000 0000 0000 b05a d91f 2c48 a44f  .........Z..,H.O
  000db351: 6910 c81d 6ae6 79d5 fa91 333e 1000 7500  i...j.y...3>..u.
  000db361: 7300 6700 7000 2d00 7400 7700 6f00 0000  s.g.p.-.t.w.o...
  000db371: 3800 0000 0000 0000 0000 0000 0000 0000  8...............
  000db381: 76b1 f347 cb55 9200 a35f 25ad 9180 89c8  v..G.U..._%.....
  000db391: 2bd8 8616 1000 7500 7300 6700 7000 2d00  +.....u.s.g.p.-.
  000db3a1: 6f00 6e00 6500 0000                      o.n.e...
  ```

- Observation: the stream count at +96 is 3 for a file with two named
  streams. The entry's own hash is zero; the first stream entry (length
  40) has an empty name and the hash of the 46-byte main stream; then
  `usgp-two` and `usgp-one` (the order they were *not* written in).
  Each stream entry: +0 length (8), +8 (8, zero in every one), +16 hash
  (20), +36 name length (2), +38 name, 2 zero bytes, zero padding to the
  length. Other S13 cases: `empty-main.txt` count 2, unnamed entry with
  a zero hash then `usgp-named`; `zero-length-stream.txt` count 2,
  unnamed with the main data, then `usgp-zero` with a zero hash;
  `dir-with-stream` (a directory) count 1, only `usgp-dir-stream`, no
  unnamed entry. S01 `with-stream.txt`: count 2, unnamed then
  `usgp-sample`. Files without named streams have count 0 and keep
  their data hash in the entry. Every named stream's name and size equal
  the source manifest (3057 of 3057 entries).
- Conclusion: a file with named streams has an unnamed stream entry
  first, which carries the main data's hash (the entry's own hash is
  then zero), and the count includes it; a directory with a named
  stream has no unnamed entry. Which rule orders named streams is not
  shown.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-033: the attributes field holds the attribute value Windows reports

- Status: Recorded
- Settles: OPEN-WIM-7, partly: captured attributes (M-10)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta; `tree-meta.manifest.tsv` `attributes` column
  (read by PowerShell on the runner)
- Host, DISM, runner, run: R3 identity line
- Location: +8 of every entry; for example `attrs\read-only.txt`, file
  offset 405265 (0x62F11): `0100 0000`
- Bytes: values seen at +8, one per kind: `0x01` read-only, `0x02`
  hidden, `0x04` system, `0x10` directory, `0x16` hidden system
  directory, `0x20` archive, `0x30` directory with the archive bit,
  `0x80` none set, `0x220` sparse, `0x410` and `0x420` reparse points,
  `0x820` NTFS-compressed, `0x2000` not content-indexed, `0x4020`
  encrypted
- Observation: for all 3057 entries the 4-byte value at +8 equals the
  `attributes` column of the source manifest (`dentry_r3.py --manifest`:
  equal 3057, differ 0).
- Conclusion: DISM stores the attribute value the file system reports,
  unchanged, including the sparse, compressed, encrypted and reparse
  bits. On apply, DISM did not restore it exactly in every case
  (OBS-045).
- Also seen in: S14, S15 (3058 of 3058 against `volume-root.manifest.tsv`)
- Cited by: none yet

### OBS-034: times at +40, +48, +56 are creation, last access, last write

- Status: Recorded
- Settles: OPEN-WIM-7, partly: time fields (M-11)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta with distinct times per item and field
  (creation in 2021, last access in 2022, last write in 2023, each with
  1234567 extra 100-ns units); manifests store FILETIME values
- Host, DISM, runner, run: R3 identity line
- Location: S13 root, file offset 402681 (0x624F9), 24 bytes
- Bytes: `8756 480c d1df d601 8716 0f85 a2fe d701 87d6 d5fd 731d d901`
- Observation: the root's three values are 132539328001234567,
  132854688001234567 and 133170048001234567, which are the FILETIME
  values of 2021-01-01, 2022-01-01 and 2023-01-01 00:00:00.1234567 UTC
  in the manifest. For all 3057 entries +40 equals the manifest's
  creation time, +48 its last-access time and +56 its last-write time,
  to the 100-ns unit (`tree-meta.manifest.tsv`, taken after the
  captures). Against the manifest taken before any capture, 3055 are
  equal; the two others are hard-link names whose times the "before"
  manifest read differently from the "after" one (OBS-035); the WIM
  agrees with the "after" values. Last-access updates were disabled on
  the runner (`host.txt`).
- Conclusion: +40 is creation, +48 last access and +56 last write, each
  a FILETIME value as Windows reports it.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-035: hard links share a non-zero group value; others hold zero

- Status: Recorded
- Settles: OPEN-WIM-7, partly: hard-link groups (M-12)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta `links\hard-original.txt`, `links\hard-two.txt`
  and `links\sub\hard-three.txt`, three names for one file
  (`hard-links` column of `tree-meta.manifest.tsv`)
- Host, DISM, runner, run: R3 identity line
- Location: +88 of the three entries, file offsets 405937 (0x631B1),
  406105 (0x63259) and 407561 (0x63809); hash at 405913 (0x63199)
- Bytes:

  ```text
  000631b1: 2a00 0000 0000 0100 0000 1800 2200 6800  *...........".h.
  00063259: 2a00 0000 0000 0100 0000 0000 1800 6800  *.............h.
  00063809: 2a00 0000 0000 0100 0000 0000 1c00 6800  *.............h.
  00063199: fd7f 7e7b 963f ecf0 6e61 d43b 6ece 166f  ..~{.?..na.;n..o
  000631a9: b232 3ee5                                .2>.
  ```

- Observation: the three names carry the same 8 bytes at +88
  (0x000100000000002A); each is a full entry with its own name, short
  name and the same hash `fd7f7e7b…` (one 27-byte lookup entry). Every
  other entry without the 0x400 attribute bit has 8 zero bytes there
  (3049 entries in S13, 3050 in S15). The XML gives `HARDLINKBYTES` 54 (OBS-048).
- Conclusion: in this file, names of one hard-linked file share a
  non-zero 8-byte value at +88 and each is a complete entry with the
  same hash; a file with one name has zero. What the value is derived
  from is not shown.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-036: reparse points: tag at +88; data in a resource named by a hash

- Status: Recorded
- Settles: OPEN-WIM-7, partly: reparse entries (M-13)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta `links\`: a junction, symbolic links to a file
  and to a directory, each relative and absolute (in-tree);
  `tree-meta.reparse.txt` (fsutil output)
- Host, DISM, runner, run: R3 identity line
- Location: entry `links\junction`, file offset 406145 (0x63281), 120
  bytes; `links\sym-file-rel.txt` +80, file offset 406881 (0x63561), and
  its stream entries, file offset 406969 (0x635B9)
- Bytes:

  ```text
  00063281: 7800 0000 0000 0000 1004 0000 0000 0000  x...............
  00063291: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  000632a1: 0000 0000 0000 0000 dde5 56cd 1267 dd01  ..........V..g..
  000632b1: dde5 56cd 1267 dd01 dde5 56cd 1267 dd01  ..V..g....V..g..
  000632c1: 1b45 a326 3b8e 882a 7b8c 458e 79c5 fabf  .E.&;..*{.E.y...
  000632d1: 17c4 260d 0000 0000 0300 00a0 0000 0000  ..&.............
  000632e1: 0000 0000 1000 6a00 7500 6e00 6300 7400  ......j.u.n.c.t.
  000632f1: 6900 6f00 6e00 0000                      i.o.n...
  00063561: 0000 0000 0000 0000 0c00 00a0 0000 0100  ................
  000635b9: 2800 0000 0000 0000 0000 0000 0000 0000  (...............
  000635c9: edd9 d6d8 33af d090 6215 ccf8 33b8 b9c4  ....3...b...3...
  000635d9: 923c 6b7f 0000 0000 2800 0000 0000 0000  .<k.....(.......
  000635e9: 0000 0000 0000 0000 0000 0000 0000 0000  ................
  ```

- Observation: with attribute bit 0x400 set, the 4 bytes at +88 hold
  the tag `fsutil` reports (0xA0000003 for the junction, 0xA000000C for
  the four symbolic links). The next 4 bytes are `0000 0100` for the
  two relative links and `0000 0000` for the two absolute links and the
  junction. Directory reparse points (junction, two directory links)
  have stream count 0 and a non-zero entry hash; file symbolic links
  have a zero entry hash and stream count 2: two unnamed stream
  entries, the first with a non-zero hash, the second with a zero hash.
  The resource named by the non-zero hash (entry or first stream)
  holds, for the two relative links, exactly the bytes `fsutil
  reparsepoint query` prints as "Reparse Data" (52 and 72 bytes;
  `reparsecmp.py`: stored==source True); `fsutil` prints the tag and
  the data length separately. Absolute targets: OBS-037.
- Conclusion: in this file a reparse point stores its tag at +88 and its
  reparse data, without tag and length, as a resource named by the
  entry hash (directories) or by the first unnamed stream (files).
  The meaning of the 4 bytes at +92 is not shown; they correlate with
  relative targets in these five entries only.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-037: in-tree absolute targets lose the capture root on capture

- Status: Recorded
- Settles: OPEN-WIM-7, partly: what `RP_FIX` does on capture and apply
  (M-13)
- Sample: S13; S16 (apply of S13 index 1)
- Command: R3 commands S13 and S16
- Source tree: tree-meta `links\` on `R:\tree-meta`; S16 applied to the
  root of another volume, also lettered `R:`
- Host, DISM, runner, run: R3 identity line
- Location: the resources named by `links\junction`,
  `links\sym-dir-abs` and `links\sym-file-abs.txt` (`dentry_r3.py
  --resource-hex`); `tree-meta.reparse.txt`; `S16.reparse.txt`
- Bytes (`links\sym-file-abs.txt`: source, from `fsutil`, then the
  stored resource):

  ```text
  source 0000: 44 00 4c 00 00 00 44 00 00 00 00 00 52 00 3a 00   D.L...D.....R.:.
  source 0010: 5c 00 74 00 72 00 65 00 65 00 2d 00 6d 00 65 00   \.t.r.e.e.-.m.e.
  stored 0000: 00 00 38 00 3a 00 30 00 00 00 00 00 5c 00 3f 00   ..8.:.0.....\.?.
  stored 0010: 3f 00 5c 00 52 00 3a 00 5c 00 6c 00 69 00 6e 00   ?.\.R.:.\.l.i.n.
  ```

- Observation: header flag 0x80 (`RP_FIX`) is set in S13 (`@16 dwFlags
  0x00000080`). For the three reparse points whose targets were absolute
  paths inside the capture directory, the stored data differ from the
  source (136, 136 and 156 bytes on disk; 96, 100 and 120 stored): the
  paths no longer contain `\tree-meta`, so `R:\tree-meta\links\…` is
  stored as `R:\links\…`, and the name strings are laid out
  differently. The two relative links are stored unchanged (OBS-036).
  After DISM's apply (S16), all five reparse points hold exactly the
  stored bytes (`reparsecmp.py`: stored==applied True for 5 of 5), and
  their targets read `R:\links\…`.
- Conclusion: DISM rewrote in-tree absolute targets on capture by
  removing the capture-root part of the path. What its apply does with
  them is **not shown**: S16 applied to `R:\` an image captured from a
  root on `R:`, so copying the stored bytes unchanged and re-basing them
  onto the apply root give the same bytes there. S13B (another letter,
  and a subdirectory) is needed and blocks applying absolute targets
  and junctions. Targets outside the capture root were not sampled.
- Also seen in: S14, S15 (S15 captured the volume root, so `\tree-meta`
  stays in its paths)
- Cited by: none yet

### OBS-038: identical descriptors are stored once and shared by index

- Status: Recorded
- Settles: OPEN-WIM-7, partly: security descriptors (M-14)
- Sample: S13; S16
- Command: R3 commands S13 and S16
- Source tree: tree-meta `acl\` (four `icacls` variants and a twin with
  the same commands); `sddl` columns of `tree-meta.manifest.tsv` and
  `S16.manifest.tsv`
- Host, DISM, runner, run: R3 identity line
- Location: +12 of every entry; security block (OBS-024)
- Bytes: `acl\protected.txt` and `acl\protected-twin.txt` both
  `0500 0000` at +12; `acl\deny-ace.txt` `0100 0000`;
  `acl\owner-system.txt` `0400 0000`; `acl\inherit-dir` `0200 0000`;
  its child `0300 0000`; other files `0600 0000`, other directories
  `0000 0000`
- Observation: S13 holds 7 descriptors with 7 different SHA-256
  values. Joined with the manifest, each index is used by entries with
  exactly one SDDL string, and different indexes by different strings;
  the twin files share index 5. No entry in S01, S13, S14 or S15 has
  index −1 (`security -1: 0`). Every descriptor starts with the bytes
  `01 00 04`. After DISM's apply (S16) the 3052 rows that have an SDDL
  value have the same SDDL as the source; the 5 reparse points have
  none in either manifest (the script does not read it), so their
  descriptors were not compared.
- Conclusion: identical descriptors are stored once and entries refer to
  them by index; DISM's apply reproduces them, as Windows reads them
  back, on every entry compared (reparse points excluded).
  Whether the stored bytes equal the descriptor bytes Windows returns
  was not checked (only SDDL text was captured), and index −1 was never
  seen.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-039: sparse and compressed files: data stored expanded

- Status: Recorded
- Settles: OPEN-WIM-7, partly: sparse and NTFS-compressed files (M-15)
- Sample: S13
- Command: R3 command S13
- Source tree: tree-meta `special\sparse-196608.bin` (196608 bytes,
  range 65536 to 131072 deallocated with `fsutil sparse setrange`) and
  `special\compressed.txt` (`compact /c`)
- Host, DISM, runner, run: R3 identity line
- Location: sparse entry bytes +160 to +192, file offset 897345
  (0xDB141)
- Bytes:

  ```text
  000db141: 4e00 0000 0000 0000 0300 0000 1000 0000  N...............
  000db151: 0000 0100 0000 0000 0000 0200 0000 0000  ................
  ```

- Observation: the two entries keep attributes 0x220 and 0x820
  (OBS-033). Their hashes name resources of 196608 and 121679 bytes
  whose SHA-256 equals the files' content in the manifest (the read
  data, zeros included): DISM stored the expanded content. The sparse
  entry's length is 192; after the short name's terminator and two
  zero bytes (to 168) it holds 24 more bytes: `03000000 10000000`, then
  65536 and 131072 as 8-byte values, equal to the start and end of the
  range deallocated (that they describe it is a [reading]). No other
  entry has bytes there (OBS-029).
- Conclusion: sparse and NTFS-compressed files are stored with their
  attributes and their full expanded data; a sparse file's entry
  carries a further 24-byte block whose last two values equal its
  deallocated range ([reading]).
  The meaning of the first 8 bytes of that block, and its form for
  other ranges, are not shown.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-040: an EFS file is stored in a form that is not its plaintext

- Status: Recorded
- Settles: OPEN-WIM-7, partly: EFS files (M-15)
- Sample: S13; S16
- Command: R3 commands S13 and S16
- Source tree: tree-meta `special\encrypted.txt` (22 bytes, encrypted
  with `File.Encrypt`; attribute 0x4020)
- Host, DISM, runner, run: R3 identity line
- Location: lookup entry 3024, resource at file offset 202846
  (0x3185E), 1844 bytes
- Bytes (first 48 of the resource):

  ```text
  00 01 00 00 52 00 4f 00 42 00 53 00 00 00 00 00
  00 00 00 00 1e 00 00 00 4e 00 54 00 46 00 53 00
  00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00
  ```

- Observation: the entry has attribute 0x4020 and no stream entries;
  its hash names a 1844-byte resource that does not contain the file's
  plaintext and whose SHA-256 differs from the content in the manifest.
  After DISM's apply (S16) on another runner the file exists with
  attribute 0x4020 and length 22, and reading it fails with "Access to
  the path … is denied".
- Conclusion: DISM captured the EFS file in a form other than its
  plaintext, which its own apply turned back into an encrypted file.
- Product rule: refused under decision 0006 ([project rule, DEC-0006]):
  the form is not described in Microsoft's documentation or by any
  observation.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-041: paths over 260 UTF-16 units need nothing special

- Status: Recorded
- Settles: OPEN-WIM-7, partly: long paths (M-16)
- Sample: S13; S16
- Command: R3 commands S13 and S16
- Source tree: tree-meta `longpath\` (six 50-character directories and
  a 34-character file name: 349 units below the root)
- Host, DISM, runner, run: R3 identity line
- Location: `longpath` at metadata offset 1560; the seven entries below
  it at metadata offsets 6208 to 7600 (the last list ends at 7800)
- Bytes: as any entry (OBS-026); each name is one path component
- Observation: each component is its own entry in its parent's list,
  with a 100-byte name and a generated short name; no entry holds a
  full path. The file's content SHA-256, attributes and times equal the
  manifest, and after DISM's apply (S16) the file exists with the same
  content (`treecmp.py`).
- Conclusion: entries hold single components, so path length has no
  effect on the metadata; a reader must build the full path itself and
  handle its length.
- Also seen in: S14, S15
- Cited by: none yet

### OBS-042: sibling order: no-children entries first, by folded name

- Status: Recorded
- Settles: OPEN-WIM-7, partly: sibling order (M-17)
- Sample: S01, S13, S15
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: tree-01; tree-meta `many\` (3000 files with mixed-case
  word prefixes, created in another order) and its other lists
- Host, DISM, runner, run: R3 identity line
- Location: S13 list `many`, metadata offset 7808 onward: `alpha-0000`,
  `alpha-0018`, `alpha-0021`, …
- Bytes: names as in OBS-027
- Observation: `dentry_r3.py` compares each list with candidate orders.
  In all lists of S01 (12), S13 (21) and S15 (22), the order is: entries
  with children offset 0 (files, symbolic links, junctions) first, then
  entries with a children offset, each group sorted by the upper-cased
  name. `many\` is in upper-cased order and not in ordinal order
  (`Bravo`, `Delta`, `Foxtrot`, `Zulu` sort among the lower-case
  words). `links\` lists `junction` and the directory links among the
  files, and `sub` and `target-dir` after them.
- Conclusion: in these files DISM wrote siblings in that order. The
  folding rule was compared only with Python's upper-casing on these
  names; a reader must not depend on the order.
- Also seen in: S14
- Cited by: none yet

### OBS-043: XPRESS metadata decodes to the uncompressed capture's bytes

- Status: Recorded
- Settles: OPEN-WIM-7, partly: compressed metadata (M-17, M-18)
- Sample: S14; S13
- Command: R3 commands S14 and S13
- Source tree: tree-meta (the same tree, captured twice)
- Host, DISM, runner, run: R3 identity line
- Location: lookup entry 0 of each file
- Bytes:

  ```text
  S14 [0] raw: 71 63 02 00 00 00 00 06 b4 9e 03 00 00 00 00 00 28 95 07 00 00 00 00 00
  S13 [0] raw: 28 95 07 00 00 00 00 02 89 20 06 00 00 00 00 00 28 95 07 00 00 00 00 00
  ```

- Observation: S14's metadata entry has flags 0x06 and stored size
  156529 for original size 496936, which is 16 chunks; S13's has flags
  0x02 and 496936 for 496936. Decoded through the chunk table (OBS-011)
  with `xpr.py`, S14's metadata has SHA-1 `563ec27b6c9b587a…`, the same
  as its lookup entry and as S13's metadata; no chunk had stored size
  equal to its expanded size. Every entry line of `dentry_r3.py` is the
  same for both.
- Conclusion: XPRESS-compressed metadata of 16 chunks decodes to the
  same bytes as the uncompressed capture of the same tree.
- Also seen in: none
- Cited by: none yet

### OBS-044: volume-root capture keeps the root's own metadata

- Status: Recorded
- Settles: OPEN-WIM-7, partly: volume-root capture (M-19)
- Sample: S15
- Command: R3 command S15
- Source tree: the VHD volume `R:\` holding tree-meta;
  `volume-root.manifest.tsv`
- Host, DISM, runner, run: R3 identity line
- Location: S15 root, file offset 402977 (0x62621), 104 bytes
- Bytes:

  ```text
  00062621: 6800 0000 0000 0000 1600 0000 0000 0000  h...............
  00062631: 9005 0000 0000 0000 0000 0000 0000 0000  ................
  00062641: 0000 0000 0000 0000 5353 0ecd 1267 dd01  ........SS...g..
  00062651: 1d22 4dcd 1267 dd01 4313 4dcd 1267 dd01  ."M..g..C.M..g..
  ```

- Observation: the root entry has an empty name, attributes 0x16 and
  security index 0, and its times equal the volume root's row in the
  manifest. Descriptor 0 (208 bytes) is new to S15; descriptors 1 to 7
  equal S13's 0 to 6. The top-level list holds only `tree-meta`;
  `System Volume Information`, present on the volume, is not in the
  image (3058 entries against 3059 manifest rows; the one missing is
  that folder). The XML `DIRCOUNT` is 21 (S13: 20).
- Conclusion: capturing a volume root stores the root directory's own
  attributes, descriptor and times in the root entry and leaves out
  `System Volume Information`. `$RECYCLE.BIN` did not exist on the
  volume, so its handling is not shown.
- Also seen in: none
- Cited by: none yet

### OBS-045: DISM's apply of S13 (S16) matches its source but for 10 values

- Status: Recorded
- Settles: OPEN-WIM-7, partly: the apply-fidelity oracle (M-20)
- Sample: S16 (`S16.manifest.tsv`, dddc1363f72d755e; `S16.dirx.txt`,
  `S16.reparse.txt`), against tree-meta's manifest
- Command: R3 command S16
- Source tree: tree-meta, through S13
- Host, DISM, runner, run: R3 identity line (job `reference`)
- Location: n/a (text artifacts); `treecmp.py` output
- Bytes: n/a; the compared values are the manifest columns
- Observation: 3057 paths in both; the applied volume also holds
  `System Volume Information`. Equal for every path: type, the three
  times, length, named streams, SDDL, hard-link names and reparse tag.
  Short names in `dir /x` are equal in every directory, including the
  explicit `EXPLICIT.TXT`. Differences: attributes of 6 paths (the
  volume root kept its own 0x16 instead of 0x10; the five files without
  the archive bit, 0x80, 0x02, 0x04, 0x01 and 0x2000, gained 0x20). The
  volume root's state before the apply was not recorded; after it, the
  root has the image root's times and SDDL but kept its own attributes;
  link targets of the 3 in-tree absolute links (OBS-037); the EFS file
  could not be read (OBS-040). Content SHA-256 is equal for every other
  file.
- Conclusion: S16 is a usable fidelity reference for every column
  listed, except reparse-point SDDL (not recorded), absolute link targets
  (OBS-037), EFS (OBS-040) and the root's attributes; an apply that
  matches DISM sets the archive bit on files, and applies the image
  root's times and SDDL, but not its attributes, to the volume root.
- Also seen in: none
- Cited by: none yet

### OBS-046: a chunk that does not shrink is stored raw

- Status: Recorded
- Settles: OPEN-WIM-5, chunk level (M-21)
- Sample: S17 (S17.wim, 1342001c1e684d48)
- Command: R3 command S17
- Source tree: tree-mixed (seed 701): `mixed-65536.bin` (32768 bytes of
  text, then 32768 pseudorandom bytes) and `mixed-reverse-65536.bin`
  (the halves swapped); SHA-1 in `trees.txt`
- Host, DISM, runner, run: R3 identity line
- Location: lookup entry 1, resource at 208 (0xD0), stored 38954;
  lookup entry 2 at 39162 (0x98FA), stored 38954
- Bytes:

  ```text
  000000d0: 2618 0000                                &...
  000098fa: 0080 0000                                ....
  000018fa: b708 2530 dfc2 c3cd f4d1 d709 98d9 41b8  ..%0..........A.
  ```

- Observation: both resources have flag 0x04 and original size 65536,
  so a one-entry chunk table. Entry 1's table holds 6182: chunk 0 is
  6182 bytes and decodes to 32768 bytes of text; chunk 1 is 38954 − 4 −
  6182 = 32768 bytes. Entry 2's table holds 32768: chunk 0 is 32768
  bytes, chunk 1 is 6182. Taking each 32768-byte chunk as plain bytes
  and decoding the other gives each resource's lookup SHA-1
  (`xpr.py`: `RAW?32768`, `sha1_match=True` for both). The two raw
  chunks are byte-for-byte equal (SHA-1 `6814f417…`); they begin
  `b708 2530 dfc2 c3cd`.
- Conclusion: inside a compressed resource, DISM stores a chunk that
  would not shrink as its 32768 plain bytes, recognisable by a stored
  size equal to the expanded size, at any position, including
  consecutive chunks.
- Also seen in: S14 (S14.wim, 57ec13c10c79987f), lookup entry 3030
  (the sparse file, 196608 bytes, 6 chunks): chunks 0, 1, 4 and 5 are
  raw, 2 and 3 compressed (263 bytes each); `xpr.py` gives the lookup
  SHA-1 (`sha1_match=True`)
- Cited by: none yet

### OBS-047: S08's 4.5 GiB pseudorandom file was stored uncompressed

- Status: Recorded
- Settles: nothing in OPEN-WIM-10 (M-22 stays open); confirms the
  7-byte stored size above 2^32
- Sample: S08 (S08.wim, a7e05acd463be3ad, not uploaded; dump in
  `S08.wim.dump.txt`)
- Command: R3 command S08
- Source tree: tree-large (seed 301), `random-large.bin`, 4831838208
  bytes
- Host, DISM, runner, run: R3 identity line (job `generate-large`)
- Location: lookup entries 0 and 1; the record rests on lines 49 and 50
  of `S08.wim.dump.txt` (`wim-samples-large-observations`), because the
  WIM itself is deleted on the runner
- Bytes:

  ```text
  [1] raw: 00 00 00 20 01 00 00 00 d0 00 00 00 00 00 00 00 00 00 00 20 01 00 00 00
  [0] raw: ae 01 00 00 00 00 00 06 d0 00 00 20 01 00 00 00 90 02 00 00 00 00 00 00
  ```

- Observation: the file's resource has flags 0x00, stored and original
  size 4831838208 (0x120000000; the 7-byte stored size uses its fifth
  byte), offset 208. The metadata (flags 0x06) lies at 4831838416, an
  offset above 2^32. No resource over 4 GiB is compressed, so no chunk
  table over 4 GiB exists in the file.
- Conclusion: with `/Compress:fast`, a pseudorandom file over 4 GiB is
  stored raw (as OBS-010 for smaller files); stored sizes and offsets
  above 2^32 use the 7-byte and 8-byte fields as `wim.md` §3 reads
  them. The 8-byte chunk-table width (OPEN-WIM-10) needs a compressible
  sample over 4 GiB.
- Also seen in: none
- Cited by: none yet

### OBS-048: what `DIRCOUNT`, `FILECOUNT` and `HARDLINKBYTES` count

- Status: Recorded
- Settles: OPEN-WIM-7, partly: XML counts against entries (M-23)
- Sample: S01, S13, S15
- Command: R1 command S01; R3 commands S13 and S15
- Source tree: tree-01; tree-meta; the volume root
- Host, DISM, runner, run: R3 identity line
- Location: XML of each file; entry counts from `dentry_r3.py`
- Bytes: XML values (from `dentry.py`): S01 `DIRCOUNT` 11, `FILECOUNT`
  21, `HARDLINKBYTES` 0; S13 20, 3036, 54; S15 21, 3036, 54
- Observation: S01 has 33 entries: the root, 11 directories and 21
  files. S13 has 3057: the root, 20 directories without the reparse bit,
  3031 files and 5 reparse points (3 of them directories); 3031 + 5 =
  3036. The three hard-link names count as three files. S15 adds the
  `tree-meta` directory. Stream entries are not counted. In S13,
  `HARDLINKBYTES` 54 equals twice the 27-byte size of the hard-linked
  file.
- Conclusion: in these files `DIRCOUNT` is the number of directories
  other than the root and reparse points, and `FILECOUNT` the number of
  all other entries, reparse points included. The `HARDLINKBYTES` rule
  is **not determined**: one hard-link group was seen, and 54 fits more
  than one rule.
- Also seen in: S14 (same as S13)
- Cited by: none yet
