# GPT: observations from our own CI

This file records facts about GPT disks that the public UEFI
specification does not state in full, observed in the project's own CI
on disks the project made itself. It complements the standards summary
[specs/standards/gpt.md](../../specs/standards/gpt.md), whose OPEN-GPT-1
it settles in part (owner acceptance 2026-10-29).

**Status: two records (GPT-OBS-001, GPT-OBS-002).** Each states what was
observed for one tool or firmware build only.

## Summary

| Question | Status | Records |
|----------|--------|---------|
| OPEN-GPT-1: does the project's CRC-32 computation agree with a known-good disk made by Microsoft's tools? | confirmed for DiskPart on one runner image | GPT-OBS-001 |
| OPEN-GPT-1: does independent UEFI firmware accept the CRCs the project writes, and check them? | confirmed for one OVMF build (backup used when primary broken; altered arrays refused) | GPT-OBS-002 |
| OPEN-GPT-1: numeric initial value, reflection, final XOR | still OPEN: not shown by these records | none |

## Provenance rules

1. **Only project-made disks.** Every disk is a fresh virtual disk
   created by a project test or script: GPT-OBS-001's disk is a new VHD
   made by the test and converted by Windows DiskPart; GPT-OBS-002's
   disks are tables written by the project's own partitioning code
   (committed seeds under `fuzz/corpus/gpt_readback/`). No disk image is
   downloaded from anywhere else.
2. **Only Microsoft's tools, the firmware and open tools named here.**
   No other GPT implementation's source is read or compared against.
3. **Conclusions stay narrow.** A record states what was observed with
   the stated tool or firmware build only.
4. **Records are append-only**, as in
   [wim-observed.md](wim-observed.md) rule 7.

## Method

- **GPT-OBS-001.** CI job `windows-agent` runs
  `crates/usgp-winapi/tests/vhd_disk.rs`
  `vhd_raw_io_update_and_volume_letters`: it creates a fresh 1 GiB VHD,
  has DiskPart run `convert gpt` on it, reads the disk's raw blocks and
  passes them to the project's GPT reader, which must accept them. The
  test logs one `GPT-OBS-001` line.
- **GPT-OBS-002.** CI job `boot-smoke` runs `scripts/boot-smoke.sh`
  scenario S10 under QEMU with OVMF and no network card. For each disk,
  S10 rebuilds the table from a committed seed, adds a FAT file system
  made by `mkfs.fat` holding the test payload as the removable-media
  boot file, and boots it. The job summary carries the S10 record
  (`gpt-obs-002.txt`: date, host, QEMU version, firmware SHA-256,
  result, evidence lines).

## Runs examined

| Record | Job | Runs | Runner |
|--------|-----|------|--------|
| GPT-OBS-001 | `windows-agent` | 40910029759, 40928612312, 40958577980, 40962201434, 40974183608, 40980499705 | windows-2025-vs2026, 20261021.278.1 |
| GPT-OBS-002 | `boot-smoke` | passing in 40876728637 and later runs, last 40980499705 | ubuntu-24.04, distribution `ovmf` package (SHA-256 in each run's S10 record) |

## Observations

### GPT-OBS-001: a DiskPart-made GPT is accepted by our reader

- Status:        Recorded
- Settles:       OPEN-GPT-1, partly: agreement of the project's CRC
                 computation with a GPT made by Microsoft's DiskPart
- Disk:          fresh 1 GiB VHD made by the test; `convert gpt` by DiskPart
- Test:          `crates/usgp-winapi/tests/vhd_disk.rs`
                 `vhd_raw_io_update_and_volume_letters`
- Runner image:  windows-2025-vs2026, version 20261021.278.1
- Runs:          40910029759, 40928612312, 40958577980, 40962201434,
                 40974183608, 40980499705
- Logged:

  ```text
  GPT-OBS-001 accepted: entries 128 used 2 of 128 bytes, first/last usable 34/2097118, array LBA 2 (backup 2097119), block 512
  ```

  Note (CR-GPT-002): the label "used 2 of 128 bytes" means 2 entries in
  use, with an entry size of 128 bytes.

- Observation:   the reader accepted the table; 128 entries of 128
                 bytes, 2 in use; usable LBAs 34 to 2097118; primary
                 array at LBA 2, backup header at LBA 2097119; 512-byte
                 blocks.
- Correction (2026-10-29, CR-GPT-001): "backup header at LBA 2097119"
                 above is wrong. The logged "(backup 2097119)" is the
                 backup entry array LBA. The backup header (LBA 2097151,
                 the last LBA of the 1 GiB disk) is not logged.
- Conclusion:    for this DiskPart and Windows build, the project's
                 CRC-32 agrees with DiskPart's, given that the reader
                 accepts a table only when its CRCs pass (`gpt.md` §6,
                 REQ-DISK-009). The logged line does not print CRC
                 values; that the reader checks them is not shown by
                 this record (auditor: check against the reader's tests).
- Also seen in:  every run listed.

### GPT-OBS-002: OVMF boots our GPTs and checks their CRCs

- Status:        Recorded
- Settles:       OPEN-GPT-1, partly: independent firmware accepts the
                 CRCs the project writes and rejects altered ones
- Disks:         the committed seeds `wu14-gpt-512-two-parts.bin`
                 (512-byte blocks) and `wu14-gpt-4096-one-part.bin`
                 (4096-byte blocks), tables written by the project's
                 partitioning code
- Script:        `scripts/boot-smoke.sh` S10; `.github/workflows/ci.yml`
                 job `boot-smoke`
- Runs:          passing in 40876728637 and later runs, last 40980499705
- What S10 asserts (each a PASS condition):
  1. 512-byte disk: entry 0's type is the EFI system partition GUID
     (read with `od`, not our parser).
  2. 512-byte disk: `sgdisk -v` reports no problems in the table as
     written.
  3. 512-byte disk, both copies as written: OVMF starts the payload
     from the partition (payload marker on the serial console).
  4. 512-byte disk with one byte of the primary header changed, so its
     CRC fails: OVMF still starts the payload, so it used the backup
     header and array. Whether OVMF rewrote the primary is recorded as
     information only.
  5. 512-byte disk with one byte of entry 0 changed in both arrays, so
     both array CRCs fail: no payload marker, and OVMF reports that the
     disk boot option failed.
  6. 4096-byte disk, both copies as written: OVMF starts the payload.
- Conclusion:    for this OVMF build, the firmware validates GPT CRCs
                 and accepts those the project writes, at both block
                 sizes, including the backup copy.
- Also seen in:  every passing run listed.
