# ZIP and cabinet archives (standards topic 25; the M4 spec request's "topic 19")

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, re-check
after CR-M4-002 and 005 fixes). OPEN-ARC-LIC and other OPEN items stay OPEN.
M4 SR-5 (2026-10-29) added A.5a, B.5a, B.5b and OPEN-ARC-4, 5 (AUDITED
2026-10-29; OPEN items stay open).

What a bounded, safe reader of driver archives needs from the public
format documents, in the researcher's own words. INDEX topic 19 is
already used for GUID text form, so this summary is topic 25.

Sources: SRC-183 (PKWARE APPNOTE 6.3.10), SRC-184 (RFC 1951 DEFLATE),
SRC-055 (Microsoft Cabinet Format, archived; fetched again in M4),
SRC-185 ([MS-MCI] MSZIP), SRC-186 (FCI compression type values).
**[reading]** marks the researcher's inference. **[project concern]**
marks a safety point that no source states.

**Licence note.** The APPNOTE says it is PKWARE's property, permits use
to build products that read and write ZIP files, forbids reproducing it
without permission, and says some parts (strong encryption, patching)
are patented and licensed separately. This summary restates facts with
section numbers and copies no text. The Microsoft Open Specifications
notice (SRC-185) permits copies to build implementations and claims no
trade secrets. The archived Cabinet page carries only a 1997 copyright
line. Counsel question: OPEN-ARC-LIC.

## Part A: ZIP (SRC-183)

### A.1 General

- All multi-byte numbers are little-endian (§4.4.1.1). Strings are not
  NUL-terminated (§4.4.1.2).
- Layout (§4.3.6): for each entry, a local header, optional encryption
  header, the data, and an optional data descriptor; then the central
  directory; then, if needed, the Zip64 end record and its locator; then
  the end-of-central-directory record. Central directory order may differ
  from data order (§4.4.1.3).
- The end-of-central-directory record must be present (§4.3.1). It
  has a 22-byte fixed part and a variable comment (§4.3.16). [reading] A
  reader finds it by searching backwards from the end of the file, over
  at most the fixed part plus the largest comment length (65,535 bytes).
- An archive that is only an end record is empty.

### A.2 Records and fixed sizes

| Record | Section | Fixed part | Then |
|--------|---------|-----------|------|
| Local file header | §4.3.7 | 30 bytes | name, extra field |
| Data descriptor | §4.3.9 | CRC-32 and two sizes (sizes 8 bytes each in Zip64); a signature may or may not precede it, readers must accept both (§4.3.9.3) | none |
| Central directory header | §4.3.12 | 46 bytes | name, extra field, comment |
| Zip64 end of central directory | §4.3.14 | holds 8-byte entry counts, size and offset; its own size field excludes the first 12 bytes | optional extensible data |
| Zip64 locator | §4.3.15 | 20 bytes: disk number, 8-byte offset of the Zip64 end record, total disks | none |
| End of central directory | §4.3.16 | 22 bytes | comment |

- Header fields, in order, of a central directory entry (§4.3.12):
  signature, version made by, version needed, flags, method, time, date,
  CRC-32, compressed size, uncompressed size, name length, extra length,
  comment length, starting disk, internal attributes, external
  attributes, local header offset.
- Zip64 (§4.4.1.4, §4.5.3): when a field is too small it is set to all
  ones and the real value is in the Zip64 extra field (header ID 0x0001),
  which holds only the values whose ordinary field is saturated, in a
  fixed order: uncompressed size, compressed size, local header offset,
  starting disk.

### A.3 Flags (§4.4.4)

- Bit 0: encrypted. Bit 6: strong encryption. Bit 13: central directory
  masked (encrypted central directory).
- Bit 3: CRC and sizes are zero in the local header; the real values are
  in the data descriptor and the central directory.
- Bit 11: name and comment are UTF-8 (Appendix D; without it, names use
  the original code page 437). The Info-ZIP extra fields 0x7075 and
  0x6375 may carry UTF-8 copies, to be ignored if their CRC does not
  match (§4.6.8, §4.6.9).
- Bits 1 and 2 are method-specific.

### A.4 Compression methods (§4.4.5)

0 stored; 8 Deflate (RFC 1951, Part C); 9 Deflate64; 12 BZIP2; 14 LZMA;
93 Zstandard; 95 XZ; 98 PPMd; 99 marks AES encryption; 1 to 6 are legacy
methods. Which methods a product must accept is a clean-side decision
(OPEN-ARC-2).

### A.5 Integrity, multi-disk, paths

- CRC-32: standard CRC-32, register starts at all ones, result inverted
  (§4.4.7).
- Archives may span several disks or be split (§4.3.3); disk-number
  fields are §4.4.13, §4.4.19 to §4.4.21.
- Stored paths (§4.4.17.1) must be relative: no drive or device letter,
  no leading slash, forward slashes only.
- Comments are neither encrypted nor authenticated (§4.4.26).

### A.5a Field tables (M4 SR-5; AUDITED)

The offsets are in bytes from the start of the record. Widths and order
are from the cited sections. The offsets are **[derived]** by adding
up the widths, and the labels are our own. All values are
little-endian (A.1). "Var" means variable length.

Local file header (§4.3.7), signature 0x04034B50:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature |
| 4 | 2 | version needed |
| 6 | 2 | flags (A.3) |
| 8 | 2 | method (A.4) |
| 10 | 2 | modification time (DOS) |
| 12 | 2 | modification date (DOS) |
| 14 | 4 | CRC-32 |
| 18 | 4 | compressed size |
| 22 | 4 | uncompressed size |
| 26 | 2 | name length n |
| 28 | 2 | extra length e |
| 30 | n | name |
| 30+n | e | extra field |

Central directory header (§4.3.12), signature 0x02014B50:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature |
| 4 | 2 | version made by |
| 6 | 2 | version needed |
| 8 | 2 | flags |
| 10 | 2 | method |
| 12 | 2 | modification time |
| 14 | 2 | modification date |
| 16 | 4 | CRC-32 |
| 20 | 4 | compressed size |
| 24 | 4 | uncompressed size |
| 28 | 2 | name length n |
| 30 | 2 | extra length e |
| 32 | 2 | comment length c |
| 34 | 2 | starting disk |
| 36 | 2 | internal attributes |
| 38 | 4 | external attributes |
| 42 | 4 | local header offset |
| 46 | n, e, c | name, extra field, comment |

End of central directory (§4.3.16), signature 0x06054B50:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature |
| 4 | 2 | this disk number |
| 6 | 2 | disk where the central directory starts |
| 8 | 2 | entries on this disk |
| 10 | 2 | total entries |
| 12 | 4 | central directory size |
| 16 | 4 | central directory offset |
| 20 | 2 | comment length c |
| 22 | c | comment |

Zip64 end of central directory record (§4.3.14), signature 0x06064B50:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature |
| 4 | 8 | size of the record, excluding these first 12 bytes |
| 12 | 2 | version made by |
| 14 | 2 | version needed |
| 16 | 4 | this disk number |
| 20 | 4 | disk where the central directory starts |
| 24 | 8 | entries on this disk |
| 32 | 8 | total entries |
| 40 | 8 | central directory size |
| 48 | 8 | central directory offset |
| 56 | var | extensible data |

Zip64 locator (§4.3.15), signature 0x07064B50, 20 bytes:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature |
| 4 | 4 | disk holding the Zip64 end record |
| 8 | 8 | offset of the Zip64 end record |
| 16 | 4 | total number of disks |

**[reading]** The locator sits immediately before the ordinary end
record. Section 4.3.6 gives that order.

Zip64 extra field (§4.5.3), header ID 0x0001:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 2 | header ID 0x0001 |
| 2 | 2 | size of the data that follows |
| 4 | 8 | uncompressed size, if present |
| … | 8 | compressed size, if present |
| … | 8 | local header offset, if present |
| … | 4 | starting disk, if present |

- The four values always come in that order. Each is present only when
  the matching ordinary field holds all ones (0xFFFFFFFF, or 0xFFFF for
  the disk). Absent values take no space, so the offset of each later
  value depends on which earlier ones are present.
- In a **local** header, if this field is used it must hold both sizes
  (§4.5.3).

Data descriptor (§4.3.9). Bit 3 of the flags must be set for one to
follow the data (A.3):

| Form | Layout | Total |
|------|--------|-------|
| With signature | 0x08074B50 (4), CRC-32 (4), compressed size (4), uncompressed size (4) | 16 |
| Without signature | CRC-32 (4), compressed size (4), uncompressed size (4) | 12 |
| Zip64, with signature | signature (4), CRC-32 (4), sizes (8 each) | 24 |
| Zip64, without signature | CRC-32 (4), sizes (8 each) | 20 |

- The APPNOTE says the signature is widely used but was not originally
  assigned, and that readers must accept both forms (A.2).
- **[reading]** A reader cannot tell the two forms apart with
  certainty, because a CRC can equal the signature value. Using the
  central directory's values to check is the safer course.
- When the 8-byte sizes apply is decided by Zip64 use for that entry
  (§4.3.9). The exact test is in the parts of §4.3.9 not summarised
  here (**OPEN-ARC-5**).

General-purpose flags (§4.4.4), bit by bit:

| Bit | Meaning (short) |
|-----|-----------------|
| 0 | encrypted |
| 1, 2 | method-specific. Deflate (8, 9): together they pick the compression option. LZMA (14): bit 1 means an end-of-stream marker is used. Implode (6): dictionary size and tree count |
| 3 | CRC and sizes are in the data descriptor; local header values are zero |
| 4 | reserved (enhanced deflate) |
| 5 | compressed patched data |
| 6 | strong encryption |
| 7 to 10 | unused |
| 11 | name and comment are UTF-8 |
| 12 | reserved by PKWARE |
| 13 | central directory encrypted, with local header values masked |
| 14, 15 | reserved by PKWARE |

### A.6 Safety points for a bounded reader

[project concern] The APPNOTE does not address the following; they are
listed for the clean side, which decides the rules:

- names containing `..` segments, backslashes, drive letters, leading
  slashes or device names that would escape the extraction folder
  (A.5 says these forms must not be written; it does not say what a
  reader does when they are present);
- the same name twice; names differing only in case;
- disagreement between the local header and the central directory;
- declared sizes far larger than the archive (expansion bombs), and
  entries whose data ranges overlap;
- encrypted, multi-disk or Zip64 archives, if not supported, refused
  rather than partly read;
- symbolic links or other special entries carried in the external
  attributes (the parts read do not define these; OPEN-ARC-3).

## Part B: Cabinet (SRC-055, SRC-185, SRC-186)

### B.1 General (SRC-055)

- Little-endian; structures packed with no padding. Current format
  version 1.3.
- A cabinet holds a header, folder records, file records and data
  blocks. A folder is a compression unit holding one or more files; a
  folder may span cabinets in a set.

### B.2 Header

- Starts with the 4-byte signature `MSCF`; then fields for total
  cabinet size, offset of the first file record, version, number of
  folders, number of files, flags, a set identifier and the cabinet's
  index in its set.
- Flags: 0x0001 a previous cabinet exists; 0x0002 a next cabinet exists;
  0x0004 reserve sizes are present. Other bits reserved.
- If the reserve flag is set: a header reserve size (0 to 60,000) and
  per-folder and per-data-block reserve sizes (0 to 255 each), then the
  header reserve bytes.
- If the previous or next flag is set: NUL-terminated ASCII cabinet and
  disk names, each at most 255 bytes plus the NUL.
- The document contradicts itself on whether the data-block reserve size
  is present; the header section's rule (present when the flag is set)
  is the one to follow (SRC-055, noted by the researcher).

### B.3 Folder record

Offset of the folder's first data block; number of data blocks in this
cabinet; compression type; optional reserve bytes.

Compression type (SRC-186): 0x0000 none; 0x0001 MSZIP. LZX is chosen
with a window size from 15 to 21 (2^15 to 2^21 bytes), but the numeric
encoding of LZX (and of Quantum) in this field is not given in the pages
read (OPEN-ARC-1).

### B.4 File record

Uncompressed size; uncompressed offset within its folder; folder index,
where 0xFFFD, 0xFFFE and 0xFFFF mean continued from the previous
cabinet, continued to the next, or both; DOS-style date and time
(2-second resolution); attributes (0x01 read-only, 0x02 hidden, 0x04
system, 0x20 archive, 0x40 run after extraction, 0x80 name is UTF-8);
then a NUL-terminated name, which may contain path separators. Records
are ordered by folder, then by offset.

### B.5 Data block

Checksum (zero means none supplied, skip the check); compressed byte
count; uncompressed byte count; optional reserve; data. Each block holds
32,768 uncompressed bytes except the last in a folder. A block split
across cabinets reports zero uncompressed bytes in its first part. An
LZX block may be at most 32,768 + 6,144 compressed bytes.

Checksum: the bytes are taken as little-endian 32-bit words and XORed
into an accumulator; 1 to 3 leftover bytes form a final word. It is
computed over the data with seed 0, then over the block header fields
after the checksum, seeded with the first result.

### B.5a Field tables (M4 SR-5; AUDITED; SRC-055)

All values are little-endian and packed with no padding (B.1). The
offsets are **[derived]** from the published order and widths; the
labels are our own. R_h, R_f and R_d are the header, folder and
data-block reserve sizes. They are zero unless the header flag 0x0004
is set.

Header:

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | signature `MSCF` (0x4D 0x53 0x43 0x46) |
| 4 | 4 | reserved, must be zero |
| 8 | 4 | total cabinet size in bytes |
| 12 | 4 | reserved, must be zero |
| 16 | 4 | absolute offset of the first file record |
| 20 | 4 | reserved, must be zero |
| 24 | 1 | minor version (3) |
| 25 | 1 | major version (1) |
| 26 | 2 | number of folders |
| 28 | 2 | number of files |
| 30 | 2 | flags: 0x0001 previous cabinet, 0x0002 next cabinet, 0x0004 reserve present; other bits reserved |
| 32 | 2 | set identifier |
| 34 | 2 | index in set, from 0 |
| 36 | 2 | R_h, 0 to 60,000 (only if 0x0004) |
| 38 | 1 | R_f, 0 to 255 (only if 0x0004) |
| 39 | 1 | R_d, 0 to 255 (only if 0x0004) |
| 40 | R_h | header reserve bytes (only if 0x0004) |

- Without the reserve flag, the fixed header is 36 bytes. With it, the
  header is 40 + R_h bytes.
- Next come, if 0x0001 is set, the previous cabinet name and previous
  disk name. Then, if 0x0002 is set, the next cabinet name and next
  disk name. Each is a NUL-terminated string of at most 255 bytes plus
  the NUL (B.2).
- The folder records follow, one per folder.

Folder record (8 + R_f bytes):

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | absolute offset of the folder's first data block |
| 4 | 2 | number of data blocks for this folder in this cabinet |
| 6 | 2 | compression type (B.3) |
| 8 | R_f | folder reserve bytes |

File record (16 bytes plus the name; it starts at the offset given in
the header):

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | uncompressed file size |
| 4 | 4 | uncompressed offset within the folder |
| 8 | 2 | folder index, or 0xFFFD / 0xFFFE / 0xFFFF (B.4) |
| 10 | 2 | date: (year − 1980) × 512 + month × 32 + day |
| 12 | 2 | time: hour × 2048 + minute × 32 + seconds ÷ 2 |
| 14 | 2 | attributes (B.4) |
| 16 | var | NUL-terminated name |

- The special folder indexes have these meanings: 0xFFFD continues
  from the previous cabinet and means folder 0; 0xFFFE continues into
  the next cabinet and means the last folder; 0xFFFF means both.

Data block (8 + R_d + compressed count):

| Off | Width | Field |
|-----|-------|-------|
| 0 | 4 | checksum (0 means none) |
| 4 | 2 | compressed byte count |
| 6 | 2 | uncompressed byte count (0 in the first part of a split block) |
| 8 | R_d | data-block reserve bytes |
| 8+R_d | compressed count | data |

- The document's own text has two copy errors here. One says the
  data-block reserve applies when the flag is **not** set. The other
  names the header reserve size where the data-block reserve size is
  meant. The structure and the header rule make the reading above the
  consistent one.
- **Compression type.** The cabinet document says the values are
  defined by each compression format, and gives none. Its MakeCAB
  section names the types MSZIP and LZX, and LZX window settings 15 to
  21 (default 18), but gives no numeric codes. B.3 (SRC-186) gives
  0x0000 none and 0x0001 MSZIP. No document read gives the numeric
  encoding of LZX or Quantum, nor which bits carry the LZX window, so
  **OPEN-ARC-1 stays open**.

### B.5b Data block checksum (M4 SR-5; AUDITED; SRC-055)

This is the published algorithm, restated in our own words. The
document gives it as a short reference routine, and the restatement
follows that routine.

- **Folding a byte run with a seed.** Start the accumulator at the
  seed.
  - Take the run 4 bytes at a time. Make each group of 4 into a 32-bit
    value with the first byte least significant (little-endian), and
    XOR it into the accumulator.
  - If 1 to 3 bytes are left over, make **one** further value with the
    first leftover byte **most** significant among those present, and
    the high bytes zero. With 1 byte the value is that byte. With 2
    bytes it is first × 256 + second. With 3 bytes it is
    first × 65,536 + second × 256 + third. XOR that value in once.
  - **[reading]** The tail is in the opposite byte order to the full
    groups. A reader that assumes little-endian for the tail too will
    get a different result for any length that is not a multiple of 4.
- **What is covered, and in what order.**
  1. Fold the data bytes (the compressed count of them) with seed 0.
  2. Fold the 4 bytes of the block header that follow the checksum
     (the compressed count and the uncompressed count), using the
     result of step 1 as the seed.
  3. The result is the checksum.
- **Reserve bytes.** The reference routine covers neither the
  data-block reserve bytes nor the checksum field. The field
  description, however, says the checksum runs from the compressed
  count through the end of the data. That wording would take in the
  reserve, but the description never mentions the reserve. The
  routine is the precise statement; whether reserve bytes are covered
  is still **OPEN-ARC-4**. **[reading]** Since reserves are normally
  absent (R_d = 0), both readings agree for ordinary cabinets.
- **Split blocks.** The part at the end of one cabinet is checksummed
  over its own partial data, with its header showing the partial
  compressed count and an uncompressed count of 0. The remainder in the
  next cabinet is checksummed over the remaining data, with seed 0.
  Its header gives the full uncompressed count.
- A checksum of 0 means none was supplied, and the check is skipped
  (B.5). **[reading]** A non-zero checksum that by chance works out to
  0 cannot be told apart from "none". The document does not discuss
  this.

### B.6 MSZIP (SRC-185 §2)

Each MSZIP block starts with the two bytes 0x43 0x4B, followed by one or
more RFC 1951 blocks from a single deflate operation, the last marked
final. Decoding trees are discarded after each RFC 1951 block, but the
history (the 32 KB window) is **kept across MSZIP blocks**. Each block
represents at most 32 KB uncompressed and is at most 32 KB + 12 bytes
compressed. MSZIP uses only the stored, fixed-Huffman and
dynamic-Huffman block types (overview).

### B.7 LZX and Quantum

LZX is summarised in `specs/standards/wim-compression.md` §4 (topic 20).
The cabinet document says the LZX window size is not in the compressed
stream and the decoder must be given it (SRC-055). The cabinet-building
API passes it as part of the compression type (SRC-186); how it is
stored in the folder record is not stated in the pages read
(OPEN-ARC-1). No public Quantum format document was found (OPEN-ARC-1).

### B.8 Safety points

[project concern] As for ZIP (A.6): names with path separators or `..`;
folder indexes beyond the folder count; offsets and sizes beyond the
file; multi-cabinet sets; declared uncompressed totals out of proportion
to the data.

## Part C: DEFLATE (SRC-184, RFC 1951)

- Bit order (§3.1.1): bits fill each byte from its least significant
  bit; fixed-width fields start with their least significant bit;
  Huffman codes start with their most significant bit.
- Block header (§3.2.3): a final-block bit and a 2-bit type: 00 stored,
  01 fixed Huffman, 10 dynamic Huffman, 11 reserved (an error).
- Stored block (§3.2.4): skip to a byte boundary, then a length and its
  one's complement, then that many bytes.
- Matches (§3.2.5): length 3 to 258, distance up to 32,768.

## Open items

- **OPEN-ARC-1**: numeric encoding of LZX and Quantum in the cabinet
  compression type; no public Quantum format.
- **OPEN-ARC-2**: which ZIP methods and which cabinet types the product
  must accept (a clean-side or owner decision; no product source says).
- **OPEN-ARC-3**: how ZIP marks symbolic links and other special entries
  (external attributes and host system values are in parts of the
  APPNOTE not summarised here).
- **OPEN-ARC-4** (M4 SR-5): whether the cabinet data-block
  checksum covers the per-block reserve bytes. The reference routine
  does not; the field description is ambiguous (B.5b).
- **OPEN-ARC-5** (M4 SR-5): the exact rule for when a data
  descriptor's sizes are 8 bytes wide (§4.3.9 detail not summarised).
- **OPEN-ARC-LIC**: counsel to confirm that a summary of the APPNOTE in
  the project's own words is consistent with its terms.
