# Standards summary: WIM compression codecs

Topic 20 of the standards reading list (new in spec run M2). This is our
summary of what Microsoft publishes about the codecs a WIM file may use:
XPRESS, LZX and LZMS. Read it with `wim.md` §4 (chunking).

Sources:

- WIM paper (see `wim.md`): names the codecs, does not define them.
- **[MS-XCA]** Xpress Compression Algorithm, Microsoft Open Specifications
  (protocol revision 10.0, 2024-04-23), HTML pages on Microsoft Learn.
- **[CAB-LZX]** "Microsoft LZX Data Compression Format", in the archived
  Microsoft Cabinet Format documentation on Microsoft Learn (Cabinet SDK
  documentation, 1997).
- **[MS-PATCH]** LZX DELTA Compression and Decompression, Microsoft Open
  Specifications (revision 14.1, 2025-08-19), HTML pages on Microsoft
  Learn. Background only.
- Microsoft Learn: "Using the Compression API" (Win32).
- Microsoft Learn: DISM image management options (compression choices).

Both Open Specifications carry Microsoft's IP notice. It lets readers copy
the documents to build implementations, states that Microsoft claims no
trade secrets in them, and says Microsoft patents may apply, with some
documents covered by the Open Specifications Promise or Community
Promise. Whether a promise covers these two documents was not checked
(OPEN-WIMC-4).

Labels: **[derived]** and **[reading]** as in `wim.md`.

## 1. Which codecs WIM uses

- The WIM paper: maximum compression uses **LZX**, fast compression uses
  **XPRESS**, or the file is uncompressed. The paper states that it does
  not define these formats. Header flags select the codec (`wim.md` §2).
- DISM's capture options are `max`, `fast` (the default) and `none`. Its
  export option adds `recovery`, which writes an `.esd` file and gives
  much smaller files (DISM image management).
- The Win32 Compression API offers XPRESS, XPRESS with Huffman encoding,
  MSZIP and LZMS. It describes their properties only, not their bitstream
  formats.
- **No Microsoft source read says which [MS-XCA] variant WIM's "XPRESS"
  is, or which [CAB-LZX] settings WIM's LZX uses** (OPEN-WIMC-1,
  OPEN-WIMC-2).

## 2. Common framing for WIM

From `wim.md` §4: each chunk is compressed on its own and expands to
exactly 32768 bytes, except the last chunk of a resource. So the decoder
always knows the exact expected output size of each chunk before it
starts.

## 3. XPRESS with Huffman ([MS-XCA] "LZ77+Huffman")

Whether this is WIM's XPRESS is OPEN-WIMC-1 **[reading: it is the only
Huffman-based XPRESS variant Microsoft documents; confirm with DISM
files]**. Sections: "LZ77+Huffman Compression Algorithm Details" (§2.1),
"LZ77 Phase" (§2.1.4.1), "Final Encoding Phase", and "Processing"
(§2.2.4, the decoder).

### 3.1 Structure

- Data is handled in **65536-byte blocks** of output. Each block starts
  with a **256-byte table** of Huffman code lengths, then the encoded
  symbols.
- The alphabet has **512 symbols**. Each code length takes 4 bits. The
  length for an even symbol is in the low 4 bits of a byte and the length
  for an odd symbol in the high 4 bits (example in the spec: lengths 5, 6,
  7, 8 for symbols 0 to 3 give bytes 0x65 0x87). A length of 0 means the
  symbol is unused. The maximum code length is **15**.
- Codes are canonical: sorted by length, then by symbol value.
- Symbols **0 to 255** are literal bytes. Symbols **256 to 511** are
  matches. For a match, `s = symbol − 256`; the low 4 bits of `s` are the
  length header and `s / 16` (0 to 15) is the number of extra offset bits.

### 3.2 Building the decoding table (§2.2.4)

- The reference method fills a table of 2^15 entries: for each length 1 to
  15, for each symbol 0 to 511 with that length, write `2^(15 − length)`
  entries for the symbol.
- **The data is invalid** if the table would overflow (more than 2^15
  entries) or is not exactly full when done. An all-zero length table is
  therefore invalid.
- Any decoder must give results equal to this method.

### 3.3 Reading bits (§2.2.4 and "Final Encoding Phase")

- The stream is read mostly in **16-bit units, low byte first**
  **[derived from the encoder pseudocode, which writes the low byte
  first]**. A 32-bit register holds at least the next 16 bits.
- At the start of each block, after the 256-byte table, the decoder loads
  two 16-bit units into the register.
- Each symbol is found from the top 15 bits of the register. The symbol's
  code length is then consumed, and a new 16-bit unit is read when needed.
- Extra length bytes (§3.4) are not part of the bit register. They are
  read straight from the current input position, which is where the
  encoder put them.

### 3.4 Match length

- If the length header is under 15: length = header + 3.
- If it is 15: read one byte `b`.
  - If `b` is under 255: length = `b` + 15 + 3.
  - If `b` is 255: read a 16-bit value `v`. If `v` is under 15 the data is
    invalid. Otherwise length = `v` + 3.
- Minimum match length is 3.
- The encoder pseudocode can also write a 16-bit zero followed by a 32-bit
  length for very long matches. The decoder pseudocode treats a 16-bit
  value under 15 as invalid, so it rejects that form **[reading]**. In a
  32 KB WIM chunk no match can need it (OPEN-WIMC-1).

### 3.5 Match offset

- With `n` extra offset bits (0 to 15): offset = `2^n` + the next `n` bits
  of the stream. Offsets therefore range from 1 to 65535.
- The copy goes from (current output position − offset), one byte at a
  time. The length may exceed the offset (overlapping copy).
- An offset that reaches before the start of the output is an access
  outside the buffer. The spec requires the decoder to report invalid data
  in that case.

### 3.6 Ending (§2.2.4, "Final Encoding Phase")

- Before each block the decoder checks that the remaining input can hold
  a 256-byte table. If not: success if all expected output has been
  written, otherwise invalid data.
- Within a block, decoding stops when 65536 bytes of output have been
  produced for that block.
- Symbol 256 means end of data **only** when all input has been read and
  the expected size has been written. Otherwise it is an ordinary match
  (length 3, offset 1).
- The spec says some decoders fail if no end symbol follows the data, so
  encoders should append symbol 256.
- The spec requires an error on any access outside the input or output
  buffer.

## 4. LZX (Microsoft Cabinet LZX format)

Primary text: "Microsoft LZX Data Compression Format", part of the
archived Microsoft Cabinet Format documentation on Microsoft Learn (the
Cabinet SDK page says the SDK download is gone but its documentation
remains at that location). It is cited below as **[CAB-LZX]** with its
heading names. The extracted text lost some exponents and figures; we
note where.

**Caveat.** [CAB-LZX] describes LZX inside cabinet files. No Microsoft
source read says which window size or preprocessing setting WIM uses, or
how WIM's 32 KB chunks map onto LZX's framing (OPEN-WIMC-2).

### 4.1 Concepts ([CAB-LZX] "Concepts")

- **Bitstream**: a sequence of 16-bit values, each stored low byte first.
  The figure showing bit order inside each value was not in the extracted
  text (OPEN-WIMC-2).
- **Window size**: a power of two from 2^15 (32 KB) to 2^21 (2 MB). It is
  not stored in the data; the decoder must be told it in advance.
- **Position slots per window size**: 32 KB 30, 64 KB 32, 128 KB 34,
  256 KB 36, 512 KB 38, 1 MB 40, 2 MB 42.
- **Trees** are canonical Huffman trees sent as code lengths. Lengths run
  from 0 to 16; 0 means the element is absent. Equal-length elements are
  ordered by element number. A tree with only one used element still uses
  the codes 0 and 1.
- **Tree sizes**: main tree 256 + 8 × (position slots); length tree 249;
  aligned offset tree 8 elements of 3-bit lengths; pretree 20 elements of
  4-bit lengths.
- **Repeated offsets** R0, R1, R2 all start at **1**.
- **Constants**: minimum match 2, maximum match 257, 256 literal
  characters, 249 secondary lengths.

### 4.2 Data format ([CAB-LZX] "LZX Compressed Data Format")

- **Cabinet block size**: each cabinet data block covers exactly 32768
  uncompressed bytes, except the last one in a folder. After every 32768
  uncompressed bytes the output is padded with 0 to 15 zero bits to a
  16-bit boundary. A match may not cross a 32768-byte input boundary. A
  compressed cabinet block is at most 32768 + 6144 bytes. LZX blocks are
  independent of cabinet blocks and can be larger.
- **Header**: one bit. 0 means no preprocessing. 1 is followed by a 32-bit
  translation size, sent as the high 16 bits then the low 16 bits.
- **Preprocessing** (call translation): the encoder may change the 32-bit
  operand after each x86 CALL opcode (0xE8) from relative to absolute, in
  place, within input blocks of 32 KB or less. Values outside the
  translated range are left alone. The last 6 bytes of an input block are
  never translated. Translation stops after the 32768th input frame. The
  decoder must reverse it; the reverse rule's figure was not in the
  extracted text (OPEN-WIMC-2).
- **Block type** (3 bits): 1 verbatim, 2 aligned offset, 3 uncompressed;
  0 and 4 to 7 are undefined. The type is followed by a 24-bit count of
  uncompressed bytes in the block.
- **Uncompressed block**: 1 to 16 bits of zero padding to a 16-bit
  boundary, then R0, R1 and R2 as 4-byte little-endian values, then the
  raw bytes.
- **Verbatim block**, in order: the byte count; a pretree then the code
  lengths for main-tree elements 0 to 255; a pretree then the lengths for
  the remaining main-tree elements; a pretree then the length-tree
  lengths; then the compressed literals and matches.
- **Aligned offset block**: as verbatim, with the aligned offset tree
  (8 × 3 bits) after the main-tree data and before the compressed data.
- **Tree deltas**: each tree is sent as changes from the previous tree of
  the same kind (the first is compared with all zeros). Code 17: read 4
  bits, write 4 + value zero lengths. Code 18: read 5 bits, write 20 +
  value zero lengths. Code 19: read 1 bit, then decode one more code
  (0 to 16) and give its result to the next 4 + bit elements. Each
  pretree is sent first as 20 lengths of 4 bits each.
- **Delta direction, cross-checked (fix round 1)**: the extracted
  [CAB-LZX] text was read as new length = (previous + code) mod 17.
  [MS-PATCH] "Encoding the Trees and Pretrees" (SRC-054) states the
  opposite direction for LZXD: new length = (previous − code + 17)
  mod 17, for codes 0 to 16 and for the code that follows 19. It also
  agrees with the run rules for 17, 18 and 19 above. The minus sign may
  have been lost in the extracted [CAB-LZX] text, but [MS-PATCH] is
  about LZXD, not WIM. Both remain **[reading]** until DISM-made samples
  confirm one (decision 0006).

### 4.3 Decoding a match ([CAB-LZX] decoding section)

- Main-tree element under 256: a literal byte.
- Otherwise: length header = (element − 256) & 7; position slot =
  (element − 256) >> 3.
- Length header 7: length = length-tree element + 7 + 2. Otherwise
  length = header + 2.
- Slots 0, 1, 2 reuse R0, R1, R2; using R1 or R2 swaps it with R0.
- Other slots: formatted offset = base position + footer bits, and match
  offset = formatted offset − 2. In aligned blocks, when the footer has
  more than 3 bits, its low 3 bits come from the aligned tree. The R
  values then shift: R2 ← R1, R1 ← R0, R0 ← new offset.
- Copy `length` bytes from (current position − offset). The copy may
  overlap.
- **Base positions and footer bits**: slots 0 to 3 have bases 0, 1, 2, 3
  and no footer bits. From slot 4 the footer width grows by one bit every
  two slots (slots 4 and 5: 1 bit, bases 4 and 6; slots 6 and 7: 2 bits,
  bases 8 and 12; … slots 34 and 35: 16 bits, bases 131072 and 196608).
  Slots 36 to 49 have 17 footer bits, with bases 262144, 393216, then
  rising by 131072 per slot up to 1966080. The table runs to slot 49
  although the window table lists 42 slots for 2 MB; the text does not
  explain the difference (OPEN-WIMC-2).

### 4.4 [MS-PATCH] LZXD (background only)

[MS-PATCH] specifies **LZXD**, which it describes as derived from the
Cabinet LZX format with changes for delta compression. Its decoding rules
match §4.3, with these documented differences: each 32 KB compressed
chunk carries a 16-bit little-endian size prefix ("Chunk Size"), block
sizes are at most 2^24 − 1 ("Block Header"), an uncompressed block adds a
zero byte when its length is odd ("Uncompressed Block"), and a match
length of 257 is followed by an extra-length prefix code reading 8, 10,
12 or 15 more bits ("Decoding Matches and Literals"). Do not assume these
apply to WIM.

## 5. LZMS and `.esd` files

- The Compression API describes LZMS as suited to data over 2 MB, with a
  high compression ratio, slow compression, fast decompression and medium
  to high memory use. Its block size is configurable up to 64 GB.
- No public Microsoft bitstream specification for LZMS was found
  (OPEN-WIMC-3).
- DISM's `recovery` export writes `.esd` files. The WIM paper does not
  describe that compression (`wim.md` OPEN-WIM-4).

## 6. Bounds a decoder must enforce

Stated by [MS-XCA] for LZ77+Huffman:

- reject Huffman tables that overfill or underfill the code space
  (§3.2);
- reject an extended length value under 15 (§3.4);
- report invalid data on any read or write outside the input or output
  buffer, including offsets before the start of the output (§3.5, §3.6);
- report invalid data when input runs out before the expected output is
  complete (§3.6).

Stated by [CAB-LZX], which a decoder must therefore check:

- block types 0 and 4 to 7 are undefined;
- code lengths lie in 0 to 16;
- a position slot must exist for the window size in use;
- in cabinet framing, no match crosses a 32768-byte input boundary.

**[derived]** from the WIM framing (`wim.md` §4), for any codec:

- the decoder is told the exact expected output size of the chunk and
  never writes past it;
- a chunk that decodes to fewer bytes than expected is invalid;
- the compressed size of each chunk comes from the chunk table and must
  lie inside the resource;
- after a resource is fully decoded, its SHA-1 must equal the hash in its
  lookup entry (`wim.md` §5), or the resource is corrupt.

## 7. Open questions

- **OPEN-WIMC-1**: confirm that WIM's XPRESS is [MS-XCA] LZ77+Huffman,
  whether WIM chunks follow the 65536-byte block rule unchanged (a 32 KB
  chunk fits in one block), and whether a WIM chunk ends with symbol 256.
- **OPEN-WIMC-2**: how WIM uses LZX. Not stated in any Microsoft source
  read: the window size for WIM, whether call translation is on and with
  what translation size, whether each 32 KB WIM chunk is an independent
  LZX stream (fresh trees and R values), and whether WIM chunks carry the
  cabinet padding. Also missing from the extracted [CAB-LZX] text: the
  bit order inside each 16-bit value, the reverse call-translation rule,
  and why the slot table runs past the 2 MB window's 42 slots. Settle by
  testing against files made by Microsoft's DISM, as set by project
  decision 0006
  (`docs/decisions/0006-wim-format-by-black-box-test-files.md`).
- **OPEN-WIMC-3**: LZMS has no public format specification in the sources
  read. LZMS (solid) WIM files are refused in M2 (decision 0006 item 4).
- **OPEN-WIMC-4**: whether the Open Specifications Promise or Community
  Promise covers [MS-XCA] and [MS-PATCH] (patent position, for counsel).

Until these are settled, the product can only decode what is documented.
`specs/os-images.md` REQ-IMG-038 says how the product must behave when it
meets a file it cannot decode.
