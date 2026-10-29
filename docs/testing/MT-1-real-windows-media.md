# MT-1: real Windows 11 Enterprise media (milestone M2, exit 1a)

MT-1 is the manual procedure for M2 exit criterion 1a: a real Windows 11
Enterprise x64 multi-edition `install.wim` over 10 GB goes through the
same flow that CI runs on a synthetic 10.5 GiB WIM (`large_upload_pg`):
upload, check, list editions, declare one, package it with an x64 PE,
reach Ready with signed manifests, and download it again with
verification. It needs licensed Microsoft media, so only the owner runs
it. It is defined in the M2 plan (section 10, "Manual") and tracked as
POAM-33.

**Status: NOT RUN.** M2 is met except exit 1a, so M2 is **not met**
until this is run and recorded. A step that could not be run is recorded
as NOT RUN, never as PASS.

## What you need

- Licensed Windows 11 Enterprise x64 media whose `install.wim` is over
  10 GB and holds several editions.
- A Windows machine with DISM, to inspect and, if needed, re-export the
  image.
- A running `usgp-server` (M2 or later) on PostgreSQL, an enrolled
  operator, and `usgp-cli` with the pinned `--content-key-pub`
  ([server.md](../operations/server.md)).
- An x64 Windows PE `boot.wim` the operator built (`winpe.md` §3), for
  the package's PE.

## Evidence to keep

- The date, the server and CLI commit, the media's name and the SHA-256
  of the file uploaded.
- The server's audit lines for each step (stdout mirror).
- No private key, code or token in any evidence file.

## Steps

| Step | Action | Pass when | Evidence |
|------|--------|-----------|----------|
| 1 | On the Windows machine, run `dism /Get-WimInfo /WimFile:install.wim` and `dism /Get-WimInfo /WimFile:install.wim /Index:n` for each index; keep the output | Output kept | The output; the file's size and SHA-256 |
| 2 | If the image is LZX ("maximum") or an `.esd`, export the wanted indexes to a new `.wim` with `/Compress:fast` (decision 0014: LZX and `.esd` are refused). Record what was exported | A `.wim` over 10 GB, XPRESS or uncompressed | The export command; the new file's size and SHA-256 |
| 3 | `usgp-cli image upload FILE --name NAME` | The content becomes Ready, or fails with a reason code | Upload digest; `content.ready` or `content.failed` with its reason. A refusal is a result: record the code and its remedy ([server.md](../operations/server.md#wim-acceptance-rules-and-reason-codes)) |
| 4 | `usgp-cli image view ID` | Every index and name matches step 1 | The edition list |
| 5 | Declare one edition: `usgp-cli image declare ID --index N --release windows-11 --edition enterprise --arch x64` | Accepted | `edition.declared` record. The fact stays `declared`, never `verified` (POAM-23) |
| 6 | `usgp-cli pe import boot.wim --name NAME --arch x64 --kit-version V` | PE Ready | PE digest |
| 7 | `usgp-cli package create --name N --image ID --index N --pe ID`; wait for Ready | Package Ready | `package.created`, `package.manifest.signed` records |
| 8 | `usgp-cli package manifest ID --out FILE`; `usgp-cli image download ID --out FILE` | Both verify against the pinned key, and the downloaded file's SHA-256 equals the uploaded one | Command output; both digests |
| 9 | `usgp-server audit verify` with the audit public key | `audit chain: intact` | The output |

The `dism /Get-WimInfo` output of step 1 is kept so that a later
observation record can show which documented XML fields, if any, state
the release, edition and architecture (OPEN-WIM-8), which is what would
let a fact move from `declared` to `verified`.

## Document Change History

| Date | Change |
|------|--------|
| 2026-10-29 | First version, written in M3 (WU-16) for the M2 exit 1a procedure that the M2 plan named but that had not been written (POAM-33): needs, evidence rules, steps 1 to 9 with pass criteria, and the `dism /Get-WimInfo` capture. Status NOT RUN. |
