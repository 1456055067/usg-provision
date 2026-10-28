# Standards summary: GUID/UUID text and byte order

Scope: UEFI, RFC 4122/9562, PXE option 97, SMBIOS.

This summary is in our own words, written for implementers. Field names
and constants are as the standards define them. Source IDs (SRC-nnn) refer
to the provenance log. Clean-side readers need only the citations given
here.

Primary sources: UEFI Specification 2.10 Appendix A (GUID and time
formats), RFC 9562 (UUIDs; obsoletes RFC 4122), RFC 4122, RFC 4578 §2.3,
UEFI 2.10 chapter 24, and draft-henry-remote-boot-protocol-00 §3.2.2.

Markers:

- **[reading]**: our inference from the cited text; the standard does not
  say it outright.
- **[primary not read]**: the primary document (DMTF SMBIOS, DSP0134) was
  found but its text could not be extracted, either in the first run or
  when tried again in fix round 1. The point rests on a search-engine
  summary of that document and on a Microsoft Learn page. Treat it as
  unconfirmed until someone reads the primary text. No requirement may
  cite a [primary not read] point until it is confirmed.

The example identifier used throughout was made up for this file:
`01234567-89ab-cdef-fedc-ba9876543210`.

## 1. One text form, two byte orders

All the standards below write a GUID/UUID the same way as text: 32
hexadecimal digits in five hyphen-separated groups of 8-4-4-4-12 digits,
36 characters in total (RFC 9562 §4; RFC 4122 §3; UEFI Appendix A,
Table A.2, which calls this the registry format). They differ in how the 16
binary octets relate to that text.

### 1.1 RFC byte order (RFC 9562 §4, §5; RFC 4122 §4.1.2)

The 16 octets are the six fields in sequence, each multi-octet field most
significant octet first (network byte order):

| Field | Octets | Text group |
|-------|--------|------------|
| `time_low` | 0–3 | 1st group (8 digits) |
| `time_mid` | 4–5 | 2nd group (4 digits) |
| `time_hi_and_version` | 6–7 | 3rd group (4 digits) |
| `clock_seq_hi_and_reserved` | 8 | 4th group, first 2 digits |
| `clock_seq_low` | 9 | 4th group, last 2 digits |
| `node` | 10–15 | 5th group (12 digits) |

Here the text, read left to right as octet pairs, is simply octets 0 to 15
in order.

- Version: the high four bits of octet 6 (RFC 9562 §4.2).
- Variant: the high bits of octet 8. RFC 9562 UUIDs use binary 10; the
  other patterns are reserved, one of them for Microsoft backward
  compatibility (RFC 9562 §4.1, Table 1).
- RFC 9562 §4 notes that Microsoft COM GUIDs are stored little-endian in
  binary and treats that as out of scope.

### 1.2 UEFI byte order (UEFI 2.10 Appendix A, Tables A.1 and A.2)

UEFI uses the same six fields and offsets as the RFC (Table A.1: TimeLow
at 0, length 4; TimeMid at 4, length 2; TimeHighAndVersion at 6, length 2;
ClockSeqHighAndReserved at 8; ClockSeqLow at 9; Node at 10, length 6). It
also says GUIDs follow RFC 4122. The difference is that **TimeLow, TimeMid
and TimeHighAndVersion are stored little-endian**. ClockSeqHighAndReserved,
ClockSeqLow and Node are kept in text order.

Table A.2 gives the mapping from the text pairs
`aabbccdd-eeff-gghh-iijj-kkllmmnnoopp` to buffer offsets:

| Text pair | aa | bb | cc | dd | ee | ff | gg | hh | ii | jj | kk–pp |
|-----------|----|----|----|----|----|----|----|----|----|----|-------|
| Buffer offset | 3 | 2 | 1 | 0 | 5 | 4 | 7 | 6 | 8 | 9 | 10–15 in order |

### 1.3 Worked example

For the text `01234567-89ab-cdef-fedc-ba9876543210`:

| Encoding | Octets 0–15 (hex) |
|----------|-------------------|
| RFC byte order (§1.1) | `01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10` |
| UEFI byte order (§1.2) | `67 45 23 01 ab 89 ef cd fe dc ba 98 76 54 32 10` |

To convert between the two, reverse octets 0–3, reverse octets 4–5, and
reverse octets 6–7. Octets 8–15 are unchanged. The conversion is its own
inverse.

**Consequence.** If you read 16 octets with the wrong convention, you get
a different, equally well-formed identifier: the last two groups match but
the first three groups are byte-reversed. Nothing in the octets shows
which convention was used. The context (which standard defines the field)
decides.

## 2. Text-form details

- **Case.** RFC 4122 §3 outputs lowercase and accepts either case on input.
  RFC 9562 §4 allows either case on output and treats letters as
  case-insensitive on input (upper, lower or mixed). UEFI Appendix A does
  not set a case.
  **[reading]** It follows that two text forms that differ only in letter
  case denote the same identifier.
- **Braces and prefixes.** Some implementations, Microsoft's among them,
  write the text inside curly braces (RFC 9562 §4). RFC 4122 §3 shows the
  `urn:uuid:` URN prefix. Neither is part of the 36-character core form.
- **Special values.** Nil (all 128 bits zero) means no UUID value is
  present. Max (all 128 bits one) can serve as a sentinel (RFC 9562 §5.9,
  §5.10; RFC 4122 §4.1.7 for nil). Their text and both binary forms are the
  same, because every octet is identical.

## 3. PXE option 97 (client machine identifier)

- Wire form: code 97, length 17, then a type octet and an identifier. The
  only defined type is 0, meaning a 16-octet GUID (RFC 4578 §2.3;
  `pxe-dhcp.md` §5.4). RFC 4578 §2.3 also sets a presence rule for this
  option, and §2.1 and §2.2 set the same rule for options 93 and 94; see
  the summary in `pxe-dhcp.md` §5.5.
- Layout of the 17 octets:

  | Option data octet | Content |
  |-------------------|---------|
  | 0 | type = 0 |
  | 1–16 | GUID octets 0–15 |

- Byte order. RFC 4578 §2.3 offers the GUID appendix of the EFI
  specification as one definition of the GUID and says nothing more about
  byte order. **[reading]** The EFI definition (§1.2) is a 16-octet buffer whose
  first three fields are little-endian, so the natural reading is that
  octets 1–16 are that buffer. Its text form is then produced with Table
  A.2: reverse octets 1–4, reverse octets 5–6, reverse octets 7–8, and keep
  octets 9–16 in order. For the example in §1.3, octets 1–16 would be
  `67 45 23 01 ab 89 ef cd fe dc ba 98 76 54 32 10`, which displays as
  `01234567-89ab-cdef-fedc-ba9876543210`.
- Not confirmed: whether real client firmware fills option 97 that way. No
  primary source read in this run states the octet order on the wire, or
  where the firmware gets the value (see OPEN-GUID-1, OPEN-GUID-2).
- UEFI 2.10 §24.7.4.1.1 (HTTP boot client broadcast) also lists option 97
  in the client's DHCP Discover. That section does not give the value's
  source either.

### 3.1 Related identifiers a PXE server may also see

- **Option 61 in the PXE draft.** draft-henry §3.2.2 describes the client
  identifier (option 61) carrying a type octet and a 16-octet UUID, length
  17. The text requires type 0, but the draft's own diagram shows a
  different type value, so the draft contradicts itself. It cites the DCE
  RPC specification for the UUID format and gives no byte order. Option 97
  (RFC 4578) is the standardised home for this identifier. A client may
  still send option 61 (`pxe-dhcp.md` §5).
- **`chaddr` may hold the system GUID.** The UEFI PXE Base Code has a
  setting under which the client puts its system GUID, instead of the
  adapter's MAC address, in the hardware-address field of DHCP and discover
  packets. The setting starts off; it can be turned on by software; and
  turning it on when no system GUID can be found is an error (UEFI 2.10
  §24.3.1, SendGUID; §24.3.15, SetParameters). The spec gives no length or
  byte-order details for that case. **[reading]** A server should not assume
  that `chaddr` is always a MAC address. `htype`/`hlen` (`pxe-dhcp.md` §3)
  describe what the client claims to have sent.

## 4. SMBIOS system UUID

- **Location.** The System Information structure (SMBIOS type 1) holds a
  16-octet UUID at offset 08h. The SMBIOS specification describes it in
  §7.2.1 (version 3.1 or later), and the format follows RFC 4122 (SRC-044,
  Microsoft Learn, which points to DMTF DSP0134 §7.2.1).
- **Byte order, SMBIOS 2.6 and later.** **[primary not read]** The first
  three fields (`time_low`, `time_mid`, `time_hi_and_version`) are stored
  little-endian, and the remaining octets are in text order. This is the same
  layout as the UEFI buffer in §1.2, and the specification explains it as
  following PC-industry practice (ACPI, UEFI, Microsoft) rather than
  RFC 4122 network order. DSP0134 2.6 is said to have made this explicit,
  and later editions (3.x) are said to keep it. Source: a search-engine
  summary of the DMTF DSP0134 text (SRC-043).
- **Before SMBIOS 2.6.** Not confirmed. No source read in this run states
  the byte order of tables from earlier SMBIOS versions, or whether 2.6
  was the first edition to state an order (OPEN-GUID-5).
- **Special values.** Whether SMBIOS gives special meanings to an all-FFh
  or an all-00h UUID was **not confirmed** from any source in this run
  (OPEN-GUID-3). The RFC meanings of nil and max (§2) are the only
  confirmed meanings of those bit patterns. (2026-10-28, SR-4: a new
  search summary of DSP0134 gives meanings for both; they are recorded
  in `smbios.md` §3 as [primary not read], so OPEN-GUID-3 stays open.)
- **Relation to option 97.** **[reading]** If firmware copies the SMBIOS
  2.6+ UUID octets into option 97 without change, then the UEFI text form of
  option 97 (§3) and the SMBIOS-defined text form of the system UUID are
  the same string. If firmware converts the value, or the table uses a
  different layout (the order in pre-2.6 tables is not confirmed,
  OPEN-GUID-5), the first three groups would differ. No primary source
  states which of these firmware does (OPEN-GUID-2).
- **What setup screens show.** No primary source found in this run says
  which form a firmware setup screen, or an operating system tool, shows
  to a person (OPEN-GUID-4). The standards fix the text form for a given
  binary layout. They do not control which layout a given display tool
  assumes.

## 5. Practical implications for identifier matching

**[reading]** These implications follow from §1 to §4 and are not
requirements of any standard:

- An identifier taken from option 97 and one typed by an operator (copied
  from a setup screen, an OS tool or an asset record) are equal only if both
  were rendered with the same convention. A mismatch that affects exactly
  the first three groups, byte-reversed, is the signature of a byte-order
  difference.
- Any choice to accept both orderings when matching, or to warn on a near
  match, is a design decision for the clean side. The standards do not
  settle it.

## 6. Open points

- **OPEN-GUID-1**: In what octet order do UEFI x86-64 PXE clients actually
  place the GUID in option 97 octets 1–16? The reading in §3 (UEFI buffer
  order) is not stated in RFC 4578 or in the parts of UEFI 2.10 that were
  read.
- **OPEN-GUID-2**: Where does firmware take the option 97 value from: the
  SMBIOS type 1 UUID, the UEFI system GUID used for `chaddr` (§3.1), or
  somewhere else? Is it converted on the way?
- **OPEN-GUID-3**: What do an all-FFh and an all-00h SMBIOS system UUID mean
  (DSP0134 §7.2.1)? Needs a direct reading of the DMTF PDF. Tried again in
  fix round 1 without success: the fetch tool still could not extract the
  text, so this stays open.
- **OPEN-GUID-4**: In which form (SMBIOS/UEFI text form, or the octets read
  in RFC order) do firmware setup screens and common OS tools display the
  system UUID? There is no primary source for this. It may need empirical
  testing on owned hardware, which is a clean-side or owner decision, not
  research.
- **OPEN-GUID-5**: The SMBIOS byte-order points in §4 rely on a search
  summary of DSP0134. Someone with a PDF text extractor should confirm them
  against DSP0134 3.7.1 §7.2.1 and 2.6.0 §3.3.2.1, and should also record
  what, if anything, DSP0134 says about tables from versions before 2.6.
  The PDFs are public on dmtf.org. The tools available in the first run
  and in fix round 1 could not extract their text.
