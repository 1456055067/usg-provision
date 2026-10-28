# Standards summary: SMBIOS system identifiers (type 1 System UUID)

Topic 14 of the standards reading list, first part (SR-4, M3 build
requests, 2026-10-28; AUDITED 2026-10-28, spec pass; §2 and §3 stay
[primary not read] and are cited by no requirement). It covers only
the System UUID in the SMBIOS System Information structure. Serial
number and chassis type (TGT-3, DRV-3) are not summarised yet. The
byte-order detail and the worked comparison with other GUID encodings
are in `specs/standards/uefi-guid-text.md` §1 and §4; this file does
not repeat them.

Sources: DMTF DSP0134 (SMBIOS Reference Specification) §7.2 and §7.2.1,
reached only through a search engine's summary limited to dmtf.org;
Microsoft Learn "SMBIOS" (Windows drivers, bring-up).

Marker: **[primary not read]** means the DMTF PDF was downloaded but
its text could not be extracted (again on 2026-10-28; no PDF renderer
is available to the researcher). The point rests on the search
engine's summary of DSP0134 and must be confirmed against the PDF. No
requirement may cite a [primary not read] point until it is confirmed
(the rule of `uefi-guid-text.md`).

## 1. Where the UUID is

- SMBIOS structure type 1, System Information, holds a 16-byte UUID at
  offset `08h` (Microsoft Learn "SMBIOS", which refers to DSP0134
  §7.2.1). Its format follows RFC 4122 (same source).

## 2. Byte order as DMTF states it [primary not read]

- DSP0134 §7.2.1 (as summarised): RFC 4122 recommends network byte
  order for every field, but the PC industry (ACPI, UEFI, Microsoft)
  stores the first three fields, `time_low`, `time_mid` and
  `time_hi_and_version`, **little-endian**. SMBIOS uses the same
  encoding, which the specification calls the wire format. The last
  eight bytes (`clock_seq_hi_and_reserved`, `clock_seq_low`, `node`)
  stay in text order.
- This is the UEFI buffer order of `uefi-guid-text.md` §1.2. To show
  the stored bytes as text, reverse bytes 0 to 3, reverse bytes 4 and
  5, reverse bytes 6 and 7, and keep bytes 8 to 15 as they are
  (`uefi-guid-text.md` §1.3 has a worked example with a made-up
  value).
- The summary says this wording is the same from DSP0134 2.6.1 to
  3.9.0. What tables from versions before 2.6 do is still not
  confirmed (`uefi-guid-text.md` OPEN-GUID-5).

## 3. Special values [primary not read]

- DSP0134 §7.2.1 (as summarised): all bytes `FFh` means the system has
  no UUID at present but one can be set; all bytes `00h` means the
  system has no UUID.
- **[reading]** Neither value identifies a particular machine. Once
  confirmed, this would settle
  `uefi-guid-text.md` OPEN-GUID-3; until then that point stays open.

## 4. Open points

- **OPEN-SMB-1**: confirm §2 and §3 against the DSP0134 PDF text
  (3.7.1 or later §7.2.1, and 2.6.0) with a PDF text extractor. Same
  question as `uefi-guid-text.md` OPEN-GUID-5.
- Serial number, chassis type and the other type 1 and type 3 fields
  are not summarised (TGT-3, DRV-3).
