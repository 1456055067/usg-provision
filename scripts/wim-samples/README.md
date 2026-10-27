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
| `New-SampleTree.ps1` | Writes a deterministic source tree (`-Seed`, `-Profile Standard\|Incompressible\|Large`) |
| `Build-Samples.ps1` | Runs DISM (`/English`, every command logged), `/Get-WimInfo`, the dumps, and writes the manifest (`-Set Standard\|Large`) |
| `Dump-WimStructure.ps1` | Hex and labelled fields of the header, lookup table, metadata heads, XML, integrity table and chunk tables; bounded reads only |

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

Image names are `USGP-<ID>-<nn>`, descriptions
`usgp-sample-<ID>-index-<nn>-<variant>` (no spaces, so the logged
command line is exactly what DISM received). Trees: `tree-01` to
`tree-12` use seeds 101 to 112 (Standard profile; `shared/` is the same
in all of them), `tree-inc` seed 201, `tree-large` seed 301.

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
| `S01.wim` ... `S09.wim`, `S06*.swm`, `S07.esd` | The samples (Standard set only) |

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
  `refuse:compression-unsupported`; map these to `WimError` reason codes
  in the test. `status` is `produced` or `not-produced`; any
  `not-produced` row (or a missing file, or a SHA-256 mismatch) fails
  the test.
- For every `accept` row: `check_wim` succeeds, the image count equals
  `images`, and each edition's index, name and description equal the
  rows of `editions.tsv` for that `id`.
- For every `refuse:*` row: `check_wim` fails with the mapped reason.
  Every S06 part is a row of its own.
- `builder_matches_dism` (plan WU-W item 2): compare `WimBuilder` output
  with S01 and S02 field by field, for the fields the plan names.

S08 is not in this artifact; its observations are text only, and its
manifest row says `produced (not uploaded)`.

## Recording observations

Follow the method in
[docs/formats/wim-observed.md](../../docs/formats/wim-observed.md):
one `OBS-nnn` record per claim, citing the sample, the exact command from
`commands.log`, the host and DISM versions from `host.txt`, the run ID,
and the offset, length and bytes from the dump. Cite bytes, not the
dump's reading of them.
