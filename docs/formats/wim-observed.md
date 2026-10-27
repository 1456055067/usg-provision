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

**Status: first records written (run R1, 2026-10-27).** Records
OBS-001 to OBS-017 come from one run of the `wim-samples` workflow (R1
in [Runs examined](#runs-examined)). They describe the files of that
run only; rule 6 below applies to every conclusion. OPEN items not
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
| OPEN-WIM-6 metadata entry to image index | partly: in S04 the k-th metadata entry is index k; lookup order and file-offset order agree there, so which one rules is still open | OBS-009 |
| OPEN-WIM-5 incompressible data | partly: whole resources that do not compress are stored raw with flag `0x04` clear, inside an XPRESS file; a raw chunk *inside* a compressed resource was not seen | OBS-010 |
| Chunk table (§4 readings); OPEN-WIM-10 | §4 readings confirmed; width 4 below 4 GiB confirmed; the threshold stays open (needs S08) | OBS-011 |
| OPEN-WIMC-1 codec and block rule | confirmed: [MS-XCA] LZ77+Huffman, one 256-byte table per chunk, all 369 chunk instances decode to the lookup SHA-1 | OBS-012 |
| OPEN-WIMC-1 end symbol; WU-X framing questions 1 to 3 | confirmed: every chunk ends with symbol 256, read exactly when all input is consumed; no read past the input end is needed | OBS-013 |
| OPEN-WIM-8 XML content | partly: UTF-16LE with BOM, no declaration; `NAME` and `DESCRIPTION` as given; no `FLAGS` or `WINDOWS`; edition, architecture and version **cannot be observed** in our samples (decision 0013) | OBS-014 |
| OPEN-WIM-11 integrity table | partly: chunk size 10485760; hashed range is end of header to end of lookup table; only a one-entry table was seen | OBS-015 |
| OPEN-WIM-9 split-set matching | partly: all parts share one GUID at offset 24, new for the set; part and total at 40 and 42 | OBS-016 |
| Split flags and part contents | confirmed for S06; differs from our §10 summary (every part has its own lookup table and full XML; resource flag `0x08` is never set) | OBS-017 |
| OPEN-WIM-7 directory entries | open (not examined; not needed in M2) | none |

**Still needed:**

- **S08** (large run, `-f large=true`): chunk-table width above 4 GiB
  (OPEN-WIM-10). R1 had no `generate-large` job output.
- **A new sample with a mixed file** (for example 32 KiB of text then
  32 KiB of pseudorandom bytes, `/Compress:fast`): whether a chunk that
  does not shrink is stored raw inside a compressed resource
  (OPEN-WIM-5, chunk level).
- **A `/CheckIntegrity` sample over 10 MiB**: more than one integrity
  entry and the chunk boundary rule (OPEN-WIM-11).
- **A sample whose lookup order differs from offset or index order**
  (for example an export of S04's indexes in reverse order): the
  metadata-entry-to-index rule (OPEN-WIM-6).
- **Edition, architecture, version** (OPEN-WIM-8): only a capture of a
  real Windows installation would show them; our content rules forbid
  that, so these facts stay operator-declared (decision 0013).
- **S10, long runs** (added to the scripts in fix round 1, BOOT-004;
  produced by the next Windows run): 32 KiB and 96 KiB of zero bytes and
  a 300-byte pattern repeated over 96 KiB, `/Compress:fast`, to show the
  16-bit length extension and multi-chunk tables of long matches.
- **A bootable sample** (BOOT-006): how the boot metadata header relates
  to the boot image's lookup entry; waits on OPEN-PE-LIC.
- **Other DISM builds or runner images**: every claim is for R1 only.

## Contents

- [Summary](#summary)
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

| Run | Run ID | Attempt | Commit | Runner image | OS build | DISM version | Date (UTC) |
|-----|--------|---------|--------|--------------|----------|--------------|------------|
| R1 | 40535666995 | 1 | ba23bedea96e5d1c68c8f77e8bff4ce9cb012825 (branch `m2-wim-samples`, job `generate`) | `win25-vs2026` 20261021.278.1 (windows-2025) | Microsoft Windows NT 10.0.26100.0; `ver` 10.0.26100.33650; CurrentBuild.UBR 26100.33650; 24H2; ServerDatacenter | `Dism.exe` FileVersion and ProductVersion 10.0.26100.32860 (WinBuild.160101.0800); `dism /English /?` banner "Version: 10.0.26100.5074" | 2026-10-27T15:54:56Z |

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
| OPEN-WIM-5 | How an incompressible chunk is stored | S09 (with `trees.txt` chunk bytes), S02 | chunks | partly: OBS-010 (resource level); chunk level needs a mixed sample |
| OPEN-WIM-6 | Lookup entry packing; metadata entry to image index | S01, S04 | lookup, metadata, xml | packing confirmed: OBS-008; index mapping partly: OBS-009 |
| OPEN-WIM-7 | Directory entry alignment, short names | S01 | metadata | pending (needed only when applying images; M2 does not) |
| OPEN-WIM-8 | Content of `NAME`, `DESCRIPTION`, `FLAGS`, `WINDOWS` | S04 | xml | partly: OBS-014 (no `FLAGS`, no `WINDOWS` in our samples; edition, architecture and version facts cannot be observed from them, see decision 0013) |
| OPEN-WIM-9 | How parts of a split set are matched | S06 parts | header (`@24`, `@40`, `@42`) | partly: OBS-016 (shared GUID) |
| OPEN-WIM-10 | Chunk-table entry width above 4 GB | S08 (large observations artifact) | chunks (width 4 and 8 checks) | pending (R1 had no S08); width 4 below 4 GiB: OBS-011 |
| OPEN-WIM-11 | Integrity chunk size unit; hashed range | S05 | integrity | partly: OBS-015 (one-entry table only) |
| OPEN-WIMC-1 | WIM XPRESS is [MS-XCA] LZ77+Huffman; block rule; end symbol | S02, S04, S09 | chunks (first chunk: 256-byte table and first symbols) | confirmed for R1: OBS-012, OBS-013 |
| LZX flag | Header flag value DISM writes for `max` | S03 | header (`@16`) | confirmed `0x00040000`: OBS-005 |
| Split flags | Header and resource flags of `.swm` parts | S06 parts | header, lookup | confirmed for S06: OBS-017 |

## Observations

Records are in ID order. Every record below is from run R1; its
identity line reads: Windows NT 10.0.26100.0, build 26100.33650;
`Dism.exe` 10.0.26100.32860 (banner 10.0.26100.5074); runner image
`win25-vs2026` 20261021.278.1; run 40535666995, attempt 1, commit
ba23bed. Sample SHA-256 values are given in full in the R1 sample
table; records quote the first 16 hex digits. Commands are the R1
command lines above. Offsets are file offsets, decimal then hex.
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
