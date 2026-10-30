# Audit record 2026-10-29: OPEN-GPT-1 closed in part (incidents: none)

Scope:
- specs/standards/gpt.md §6 note and the OPEN-GPT-1 sub-list
- docs/formats/gpt-observed.md
- the CI-GPT-1 row in cleanroom/provenance/SOURCES.md
- specs/INDEX.md topic 8
- specs/disk.md REQ-DISK-009 status line

Method:
- Read the text.
- Pulled the windows-agent logs of all six cited runs and the boot-smoke logs of 40876728637 and 40980499705 with `gh run view --log`.
- Read crates/usgp-disk/src/gpt.rs, crates/usgp-disk/tests/gpt_readback.rs, crates/usgp-winapi/tests/vhd_disk.rs and the S10 code in scripts/boot-smoke.sh.
- No vendor pages fetched.

Verdict: PASS for gpt.md, INDEX.md and disk.md. gpt-observed.md and the CI-GPT-1 row are held on one MINOR. No contamination: no vendor material, behaviour only. The numeric CRC parameters correctly stay OPEN.

## Reader CRC check (researcher's question): confirmed
- gpt.rs line 505 rejects a header whose CRC (field zeroed, over HeaderSize bytes) does not match, with reason "HeaderCRC32".
- gpt.rs line 608 rejects an array whose CRC over count x size bytes does not match, with reason "PartitionEntryArrayCRC32".
- The reader checks both copies (module doc, line 9).
- Tests readback_detects_tamper_primary_header and readback_detects_tamper_primary_array assert those exact errors, and crc_vectors pins the check value 0xCBF43926.
- So "accepted" in GPT-OBS-001 does imply that the CRCs matched. The record's "(auditor: check against the reader's tests)" is answered.

## Evidence checked
- GPT-OBS-001: the identical "accepted" line appears in all six runs.
- GPT-OBS-002: S10 PASSes in 40876728637 and 40980499705. S10 code matches assertions 1 to 6: the ESP GUID is read with od, then sgdisk -v, then a header byte flip at offset 512+56, then entry 0 flipped in both arrays, then the 4096-byte case.

## CR-GPT-001 (MINOR) GPT-OBS-001 misreads the logged backup LBA
The record's Observation says "backup header at LBA 2097119". In vhd_disk.rs, "(backup N)" prints `v.backup_array_lba`, so 2097119 is the backup array's LBA. On a 1 GiB disk with 512-byte blocks the backup header is at 2097151, which is not logged. The records are append-only, so add a correction line to GPT-OBS-001 rather than rewriting it. This does not affect the CRC conclusion.

## CR-GPT-002 (INFO) "used 2 of 128 bytes" is a log-label bug, worth a note
The format string prints `v.entries.len()` (entries in use) and `v.entry_size`, so it should read "2 used, entry size 128 bytes". The record's interpretation ("128 entries of 128 bytes, 2 in use") is correct. Add a one-line note under Logged saying the label is misleading and how to read it. The clean side may fix the format string for future runs, but must keep the quoted line in this record verbatim.

## Marks
- gpt.md §6 note and the OPEN-GPT-1 sub-list are AUDITED.
- INDEX.md topic 8 and REQ-DISK-009 wording ("closed in part (CI-GPT-1, DRAFT)") is accurate. Change DRAFT to AUDITED there once the CI-GPT-1 row is audited.
- gpt-observed.md and the CI-GPT-1 row stay pending CR-GPT-001.

Counts: BLOCKER 0, MAJOR 0, MINOR 1, INFO 1.

## Re-check (2026-10-29)
- CR-GPT-001 resolved. GPT-OBS-001 has a dated correction line identifying 2097119 as the backup entry array's LBA, and stating that the backup header (LBA 2097151) is not logged. The original Observation text is kept, so the record stays append-only.
- CR-GPT-002 resolved. A note under Logged explains the label: 2 entries in use, entry size 128 bytes. The quoted log line is unchanged.
- The CI-GPT-1 row notes both fixes.
- CI-GPT-1 passes. gpt-observed.md passes. The researcher may mark the row AUDITED and update INDEX.md topic 8 and REQ-DISK-009 from DRAFT to AUDITED. No contamination.

Final verdict: PASS. Open findings: BLOCKER 0, MAJOR 0, MINOR 0, INFO 0.
