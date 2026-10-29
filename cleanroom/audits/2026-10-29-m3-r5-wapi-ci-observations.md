# Audit record 2026-10-29: M3 R5 spec pass, CI-WAPI-1 observations (incidents: none)

Scope: specs/standards/windows-storage-firmware-api.md section 12 observation notes under OPEN-WAPI-9, 11, 16; cleanroom/provenance/SOURCES.md row CI-WAPI-1.
Method: diff review; claims checked against `gh run view --log` for runs 40928612312 and 40958577980 and against the project tests that produced them (crates/usgp-winapi/tests/winsink.rs, vhd_disk.rs). No vendor pages fetched (no vendor material involved).

Verdict: PASS WITH MINORS. No contamination. All three items correctly stay OPEN. The notes describe behaviour only, contain no vendor material and no implementation guidance, and are labelled observed and not documentation.

## CR-R5-001 (MINOR) OPEN-WAPI-11 error name is stronger than the log
Log (run 40958577980, synthetic_wim_applies_to_a_vhd_volume) shows `SinkError { op: SetAttributes, kind: InvalidInput }`, a Rust ErrorKind, not a raw Win32 code. It does not show ERROR_INVALID_PARAMETER or 87, which other codes can also map to. Directory plus hidden (0x12) is supported by the test input (winsink.rs ~270). Fix: say "failed with an error classed as invalid input (raw code not logged)", or rerun with the raw code logged and cite that run.

## CR-R5-002 (MINOR) OPEN-WAPI-16 merges two runs into one sequence
Error 87 comes from run 40928612312, where the volume's letters before the call were not logged. The automatic E: and the later success come from run 40958577980 (LETTER-OBS "letters before assign: [E]", then Ok with Q). The removal of E: by DeleteVolumeMountPoint is inferred from code (volume::set_only_letter), not logged. ESP and recovery with no letter (empty lists; recovery attributes 0x8000000000000001) are backed. Fix: credit each claim to its run, and mark the E:-then-87 link and the delete step as inferred from project code.

## CR-R5-003 (MINOR) CI-WAPI-1 row does not record the OS build
The notes say "One OS build", but neither the row nor the notes name it. The logs give runner image windows-2025-vs2026, version 20261021.278.1. Record that (and the Windows build if it is logged) as the OBS rows do. Also add the test names and the commit.

## Confirmed
- OPEN-WAPI-9: fsutil printed "Successfully DISABLED 8dot3name generation"; test short_names_disabled_fail_by_name then got Ok(()) from a SetFileShortNameW-backed set on a new file. Backed. Marked AUDITED in place.
- Product name: not in any changed hunk.

Counts: BLOCKER 0, MAJOR 0, MINOR 3, INFO 0.

## Re-check (2026-10-29)
- CR-R5-001 resolved: the OPEN-WAPI-11 note now names only the Rust error kind InvalidInput and says the raw code was not logged.
- CR-R5-002 resolved: the OPEN-WAPI-16 notes credit each claim to its run, and the DeleteVolumeMountPoint step is marked inferred and not logged.
- CR-R5-003 resolved: the CI-WAPI-1 row now records commits 21c1efb and d900a05 (matching the runs' head SHAs), runner image windows-2025-vs2026 version 20261021.278.1, and test names that exist in the repo and appear in the logs.
- The OPEN-WAPI-11 and 16 notes and the CI-WAPI-1 row are marked AUDITED. All items stay OPEN. No contamination.

Final verdict: PASS. Open findings: BLOCKER 0, MAJOR 0, MINOR 0.
