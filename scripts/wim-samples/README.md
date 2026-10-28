# DISM sample WIM files

Scripts that build WIM files with Microsoft's DISM from content we
generate, and dump their structure, so that gaps in Microsoft's public
WIM documentation can be settled by black-box observation (decision
[0006](../../docs/decisions/0006-wim-format-by-black-box-test-files.md),
scope by decision
[0014](../../docs/decisions/0014-m2-wim-compression-scope.md); plan
M2 WU-W). Observations are recorded in
[docs/formats/wim-observed.md](../../docs/formats/wim-observed.md).

## Rules

- **Own content only.** Every capture source is written by
  `New-SampleTree.ps1`: ASCII text it composes and pseudorandom bytes from
  `System.Random` with a fixed seed. No Windows media, no third-party or
  copyrighted files, nothing downloaded.
- **Microsoft tools and documentation only** (decision 0006 item 2). Do
  not read, run or compare against any third-party WIM, XPRESS, LZX or
  LZMS implementation, its source, tests or documentation.
- **Never commit samples, never download them from elsewhere.** They are
  rebuilt on a GitHub-hosted Windows runner by
  `.github/workflows/wim-samples.yml` and kept only as a 14-day workflow
  artifact. Whether the DISM licence permits creating and analysing test
  files is with counsel (plan Q7, OPEN-PE-LIC); the release gate flags
  it.
- **Fail closed.** A failed DISM command, a DISM report that differs from
  the names we asked for, or a file over the 64 MiB upload cap fails the
  build; a sample whose input failed is recorded as `not-produced`.

## Files

| File | Purpose |
|------|---------|
| `New-SampleTree.ps1` | Writes a deterministic source tree (`-Seed`, `-Profile Standard\|Incompressible\|Large\|LongRun\|Service\|Metadata\|Mixed`) |
| `Build-Samples.ps1` | Runs DISM (`/English`, every command logged), `/Get-WimInfo`, the dumps, and writes the manifest (`-Set Standard\|Large\|Metadata\|Reference`); VHD helpers (DiskPart, `fsutil`) and tree manifests for the Metadata and Reference sets |
| `Dump-WimStructure.ps1` | Hex and labelled fields of the header, lookup table, metadata heads, XML, integrity table and chunk tables; the whole of each uncompressed metadata resource (4 MiB cap per resource and in total) with a labelled security-block head; bounded reads only |
| `analysis/*.py` | The R1 analysis scripts (lookup walk, instrumented LZ77+Huffman decoder, metadata-to-tree map) and the R2 scripts (`gaps.py` unnamed ranges, `metahash.py` metadata hashes), written only from `specs/standards/wim.md` and `wim-compression.md`; kept so the OBS claims can be re-run (CR-602). Run with `python3 -I`, sample paths as arguments; see each file's header |
| `analysis/dentry.py` | M3 (WU-W3): walks the security block and directory entries of each metadata resource and prints every field beside its offset, written only from `wim.md` §6 and the sections it relies on; nothing `wim.md` leaves open is assumed (alignment is `--align`, bytes after the name are shown as hex). Compressed metadata needs `--xpr analysis/xpr.py`; a chunk whose stored size equals its expanded size is not decoded (OPEN-WIM-5) |

All three need PowerShell 7.2 or later; `Build-Samples.ps1` needs an
elevated shell on Windows (DISM). `-Profile` is an alias of the
`-TreeProfile` parameter (a parameter named `Profile` would shadow the
automatic `$PROFILE` variable).

## Samples

| ID | DISM command (all with `/English`) | Source | Expected by our parser | Question |
|----|------------------------------------|--------|------------------------|----------|
| S01 | `/Capture-Image /Compress:none` | tree-01 | accept | OPEN-WIM-1, 2, 3, 6 |
| S02 | `/Capture-Image /Compress:fast` | tree-01 | accept | OPEN-WIMC-1, OPEN-WIM-5 |
| S03 | `/Capture-Image /Compress:max` | tree-01 | refuse: LZX | LZX flag value |
| S04 | S02 form, then `/Append-Image` x 11 | tree-01 to tree-12 | accept, 12 editions | REQ-IMG-042, OPEN-WIM-6 |
| S05 | `/Capture-Image /Compress:fast /CheckIntegrity` | tree-01 | accept | OPEN-WIM-11 |
| S06 | `/Split-Image` of S04, `/FileSize:1` | S04.wim | refuse: spanned | split flags |
| S07 | `/Export-Image` of S02 index 1, `/Compress:recovery` | S02.wim | refuse: compression | OPEN-WIM-4 |
| S08 | `/Capture-Image /Compress:fast` | tree-large (4.5 GiB file) | accept | OPEN-WIM-10 |
| S09 | `/Capture-Image /Compress:fast` | tree-inc (64 KiB pseudorandom) | accept | OPEN-WIM-5 |
| S10 | `/Capture-Image /Compress:fast` | tree-long (profile LongRun, seed 401: 32 KiB and 96 KiB of zeros, a 300-byte pattern repeated to 96 KiB) | accept | OPEN-WIMC-1: long matches, 16-bit length extension, multi-chunk tables (BOOT-004; added in M2 fix round 1, first produced by the next run) |
| S11A | S02 form, then `/Append-Image` of the same tree | tree-01 twice | accept | Identical metadata for two images: two resources, one shared range, or a DISM refusal (BOOT-011, wim.md §13 S11, OPEN-WIM-6). Run 40599556702: one shared range, two equal entries (OBS-018) |
| S11B | `/Export-Image` of S02 index 1 to a new file (`/Compress:fast`), then again to the same file (`/DestinationName:USGP-S11B-02`) | S02.wim | accept | As S11A, by export (BOOT-011). Run 40599556702: as S11A (OBS-018); names are DISM's choice, checked against its `/Get-WimInfo` |
| S12A | Copy of S04; `/Mount-Image /Index:1`, add the tree-service files under `usgp-serviced\`, `/Unmount-Image /Commit` | S04.wim, tree-service (profile Service, seed 501) | accept | Metadata order after a commit; unused space (BOOT-012, wim.md §13 S12, OPEN-WIM-6). Run 40599556702: index 1's metadata moved after every other resource, lookup order gives the index, old data left unnamed (OBS-020 to OBS-022) |
| S12B | Copy of S04; `/Delete-Image /Index:1`, then `/Append-Image` of tree-01 as index 12 | S04.wim, tree-01 | accept | Metadata order after delete and append; reuse of the deleted image's resources (BOOT-012). Run 40599556702: offsets rise, file resources reused, deleted metadata unnamed (OBS-023) |

Metadata samples (plan M3 §1.4, WU-W3; artifacts `wim-samples-metadata`
and `wim-samples-reference`, first produced by run R3):

| ID | DISM command (all with `/English`) | Source | Expected by our parser | Question |
|----|------------------------------------|--------|------------------------|----------|
| S13 | `/Capture-Image /Compress:none` | tree-meta | accept | OPEN-WIM-7: security block, entry layout, alignment, short names, streams, attributes, times, hard links, reparse points, descriptors, long paths, a large directory (M-01 to M-17, M-23) |
| S14 | `/Capture-Image /Compress:fast` | tree-meta | accept | XPRESS metadata over many chunks decodes to S13's bytes (M-17, M-18) |
| S15 | `/Capture-Image /Compress:none` of the volume root (`X:\`) | the VHD volume holding tree-meta | accept | Root entry, root security and attributes, folders DISM leaves out (M-02, M-19) |
| S16 | `/Apply-Image` of this run's S13 index 1 to the root of a fresh NTFS VHD volume, then a tree manifest | S13.wim | reference | DISM's apply result as text: the fidelity oracle (M-20, REQ-PE-017) |
| S17 | `/Capture-Image /Compress:fast` | tree-mixed | accept | A chunk that does not shrink inside a compressed resource (OPEN-WIM-5 chunk level, M-21) |

tree-meta is profile Metadata, seed 601, written by `Build-Samples.ps1`
on a fresh 2 GiB expandable VHD (GPT, one NTFS partition, made with
DiskPart) with short-name generation enabled on that volume only
(`fsutil 8dot3name set X: 0`). Its content is listed in
`New-SampleTree.ps1`: hard links, relative and absolute symbolic links to
a file and a directory, a junction, single-attribute files, a hidden and
system directory, four ACL variants on well-known SIDs plus a twin with
the same descriptor, generated and explicit short names, named streams
(two on a file, one on a directory, a zero-length one, one on an empty
main stream), sparse, NTFS-compressed and EFS files, a path over 300
UTF-16 units and a directory of 3000 files. Times differ per item and
per field (creation 2021, last access 2022, last write 2023), so M-11
can be read from the bytes. If EFS is not available on the runner the
file stays plain; `commands.log` then has a `NOTE` line and the tree
manifest shows its real attributes. tree-mixed is profile Mixed, seed
701: `mixed-65536.bin` (32768 bytes of text, then 32768 pseudorandom
bytes) and `mixed-reverse-65536.bin` (the halves swapped).

The VHDs stay in the work directory and are detached at the end; they
are never uploaded. S16 uploads only text. S08 (large) and S10 (long
runs) come from the same run R3 (below).

Image names are `USGP-<ID>-<nn>`, descriptions
`usgp-sample-<ID>-index-<nn>-<variant>` (no spaces, so the logged
command line is exactly what DISM received). Trees: `tree-01` to
`tree-12` use seeds 101 to 112 (Standard profile; `shared/` is the same
in all of them), `tree-inc` seed 201, `tree-large` seed 301.

S11 and S12 (added in M2 fix round 2) asked what DISM writes, so their
rows first carried expected `observe` (the consumer printed the
parser's result without judging it). Run 40599556702 answered; the
results are OBS-018 to OBS-023 and the rows now carry `accept`. The
consumer also judges them as `accept` in an older artifact whose
manifest still says `observe` (`RECORDED` in `dism_samples.rs`). The
checker accepts only the observed layouts: a metadata entry repeated
once, in all 50 bytes, directly after its twin in the lookup table
(S11), and the first metadata entry moved after every other resource,
ending where the lookup table starts, with the rest in rising order
(S12A).
Any other metadata order is still refused as
`wim_metadata_order_not_supported`; the operator remedy (also in the
reason's operator text) is to export each image to a new file with
`/Export-Image` and upload that file. If DISM refuses the second step
of S11A or S11B, the row's status is `dism-refused` and the partial
file is deleted; the verify job then fails, because that contradicts
the record. Tree-service holds `serviced.txt`
and `serviced-40000.bin` (40000 pseudorandom bytes, seed 501).

S08 runs only in the `generate-large` job (manual runs with the `large`
input). Its WIM is dumped on the runner and deleted; only the text
observations are uploaded (artifact `wim-samples-large-observations`).

## Running

On GitHub (the normal way; the first observations need this):

```sh
gh workflow run wim-samples.yml --ref <branch> -f large=true
gh run list --workflow wim-samples.yml --limit 1     # note the run ID
gh run download <run-id> -n wim-samples -D target/wim-samples/<run-id>
gh run download <run-id> -n wim-samples-large-observations \
  -D target/wim-samples/<run-id>-large
```

**Run R3** (plan M3 WU-W3) is a manual run with `-f large=true`, so
one run produces S08 and S10 as well as S13 to S17. Download its two
extra artifacts too:

```sh
gh run download <run-id> -n wim-samples-metadata \
  -D target/wim-samples/<run-id>-metadata
gh run download <run-id> -n wim-samples-reference \
  -D target/wim-samples/<run-id>-reference
python3 -I scripts/wim-samples/analysis/dentry.py \
  target/wim-samples/<run-id>-metadata/S13.wim
python3 -I scripts/wim-samples/analysis/dentry.py \
  --xpr scripts/wim-samples/analysis/xpr.py \
  target/wim-samples/<run-id>-metadata/S14.wim
```

Keep downloads under `target/` (ignored, never committed). Pushes and
pull requests that touch these scripts, the workflow, `crates/usgp-image`
or `Cargo.lock` run the `generate` and `verify` jobs automatically.

On a Windows machine, in an elevated PowerShell 7.2+ session:

```powershell
./scripts/wim-samples/Build-Samples.ps1 -OutDir C:\t\wim-samples -WorkDir C:\t\wim-work
```

Results from a local machine may be recorded only with that machine's
OS build and DISM version; CI runs are preferred because the runner image
is recorded.

## Outputs (`-OutDir`)

| File | Content |
|------|---------|
| `host.txt` | UTC time, OS version and build, `Dism.exe` file version, `dism /English /?` banner, runner image (`ImageOS`, `ImageVersion`), run ID, commit |
| `commands.log` | Each DISM command line with UTC time, then its exit code |
| `trees.txt` | Each source file: path, length, SHA-1, SHA-256, alternate streams; bytes at the two chunk starts of the incompressible file |
| `Sxx.dism.txt` | DISM output of the build commands |
| `Sxx.wiminfo.txt` | `/Get-WimInfo` for the file and for each index |
| `<file>.dump.txt` | `Dump-WimStructure.ps1` output for each sample file or part |
| `manifest.tsv` | One row per sample file (contract below) |
| `editions.tsv` | `id`, `index`, `name`, `description` as DISM reported them |
| `SHA256SUMS` | `sha256sum -c` format, every uploaded sample file |
| `observations.txt` | All of the text files above, concatenated |
| `S01.wim` ... `S10.wim`, `S11A.wim`, `S11B.wim`, `S12A.wim`, `S12B.wim`, `S06*.swm`, `S07.esd` | The samples (Standard set) |
| `S13.wim`, `S14.wim`, `S15.wim`, `S17.wim` | The samples (Metadata set) |
| `tree-meta-before.manifest.tsv` | Metadata set: tree-meta before any capture, no content read (times as written) |
| `tree-meta.manifest.tsv`, `tree-meta.dirx.txt`, `tree-meta.reparse.txt` | Metadata set: tree-meta after the captures, with hashes, streams and SDDL; `dir /x` of each directory; `fsutil reparsepoint query` of each reparse point |
| `volume-root.manifest.tsv` | Metadata set: S15's source, the VHD volume root (no content read; `System Volume Information` and `$RECYCLE.BIN` listed, not entered) |
| `S16.manifest.tsv`, `S16.dirx.txt`, `S16.reparse.txt` | Reference set: DISM's apply of S13 index 1, same forms |
| `VHD-META.diskpart.txt`, `S16.diskpart.txt` | DiskPart and `fsutil` output of the VHD helpers |

## Linux consumer (hand-off to WU-5)

The `verify` job downloads the artifact of the **same run** into a
directory, checks `SHA256SUMS`, and runs:

```sh
USGP_WIM_SAMPLES=<dir> cargo test -p usgp-image --features dism-samples \
  --test dism_samples --locked
```

WU-5 owns `crates/usgp-image/tests/dism_samples.rs` and the
`dism-samples` feature. Until that file exists the job fails with a
"NOT RUN" error, by design. The contract the test must meet:

- `USGP_WIM_SAMPLES` unset or not a directory, with the feature on, is a
  test **failure**, never a skip or a pass.
- Read `manifest.tsv` (UTF-8 without BOM, LF line ends, tab-separated,
  header row first; `editions.tsv` and `SHA256SUMS` likewise). Columns:
  `id`, `file`, `bytes`, `sha256`, `compression`
  (`none`, `xpress`, `lzx`, `recovery`), `images`, `expected`, `status`.
  `expected` is one of `accept`, `refuse:lzx`, `refuse:spanned`,
  `refuse:compression-unsupported`, `observe`; map the `refuse:*` tokens
  to `WimError` reason codes in the test. `status` is `produced`,
  `not-produced`, `produced (not uploaded)` (S08) or `dism-refused`
  (only on `observe` rows, and never on S11A or S11B since their
  record; no file, printed and skipped); any
  `not-produced` row (or a missing file, or a SHA-256 mismatch) fails
  the test.
- For every `accept` row: `check_wim` succeeds, the image count equals
  `images`, and each edition's index, name and description equal the
  rows of `editions.tsv` for that `id` (for S11B, whose names DISM
  chooses, the images listed in `S11B.wiminfo.txt`).
- For every `refuse:*` row: `check_wim` fails with the mapped reason.
  Every S06 part is a row of its own.
- For every `observe` row: `check_wim` runs (no panic) and the result
  is printed; it is not judged. S11A, S11B, S12A and S12B are judged
  by their record even when the manifest says `observe`.
- `serviced_layouts_match_observations`: the byte-level facts of
  OBS-018 and OBS-021 to OBS-023 hold in S11A, S11B, S12A and S12B,
  and the builder's `reuse_metadata` and `move_first_metadata` layouts
  match them (artifacts without S11 or S12 rows print a note).
- `builder_matches_dism` (plan WU-W item 2): compare `WimBuilder` output
  with S01, S02, S05 and S04 (12 images) field by field, for the fields
  the plan names plus metadata order, interleaving and sharing.
- `every_dism_compressed_resource_decodes`: every compressed lookup
  entry of every `xpress` row, split parts included, decodes to its
  SHA-1 (BOOT-004). S10 rows are used when present.

S08 is not in this artifact; its observations are text only, and its
manifest row says `produced (not uploaded)`.

## Metadata artifact (contract for the WU-4 and WU-15 consumers)

`wim-samples-metadata` and `wim-samples-reference` are separate
artifacts, so the Standard artifact and the `verify` job above are
unchanged; no job reads them yet. A consumer written later must:

- Read `manifest.tsv` of each (same format and columns as above). The
  Metadata artifact has rows S13, S14, S15 and S17; the Reference
  artifact has one row, S16, whose `file` is `S16.manifest.tsv`,
  `compression` is S13's (`none`) and `expected` is the new token
  `reference`. A `reference` row is never passed to `check_wim`; it is
  the oracle an apply is compared with. Any `not-produced` row, missing
  file or SHA-256 mismatch fails.
- Treat S17 as `accept` only once its OBS record says how DISM stored the
  pseudorandom chunk. Until then the current decoder may refuse it
  (OPEN-WIM-5 chunk level), which is why S17 is not in the Standard
  artifact.
- Tree manifests (`*.manifest.tsv`): UTF-8 without BOM, LF, tab-separated,
  header row first; columns `path` (relative, `\`-separated, the root
  itself is `.`), `type` (`dir`, `file`, `reparse:<link type>`),
  `attributes` (`0x` and 8 hex digits), `creation`, `last-access`,
  `last-write` (FILETIME integers), `length`, `sha256` (main stream),
  `streams` (`name:length:sha256`, `;`-separated), `sddl`, `link-target`,
  `hard-links` (`|`-separated names as `fsutil hardlink list` prints
  them), `reparse-tag`. `-` means not applicable or not read; a value that
  could not be read is `error: <message>`. Rows are sorted by path,
  ordinal. Short names are not a column; they are in `<tree>.dirx.txt`.
- These manifests are produced by PowerShell and `fsutil`, not by WU-5's
  `tree_manifest` example, which does not exist yet. When it does, the
  Reference set should switch to it and the two forms should be compared
  once on the same volume.

## Recording observations

Follow the method in
[docs/formats/wim-observed.md](../../docs/formats/wim-observed.md):
one `OBS-nnn` record per claim, citing the sample, the exact command from
`commands.log`, the host and DISM versions from `host.txt`, the run ID,
and the offset, length and bytes from the dump. Cite bytes, not the
dump's reading of them.
