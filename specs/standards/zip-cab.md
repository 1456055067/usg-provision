# ZIP and cabinet archives (standards topic 25; the M4 spec request's "topic 19")

Status: AUDITED (spec run M4, 2026-10-29; clean-room audit 2026-10-29, re-check
after CR-M4-002 and 005 fixes). OPEN-ARC-LIC and other OPEN items stay OPEN.

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
- **OPEN-ARC-LIC**: counsel to confirm that a summary of the APPNOTE in
  the project's own words is consistent with its terms.
