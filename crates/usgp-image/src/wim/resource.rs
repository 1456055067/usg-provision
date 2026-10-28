//! Reading one resource's content: uncompressed resources as stored,
//! compressed ones chunk by chunk through the chunk table and the XPRESS
//! decoder (`wim.md` §4).

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - every chunk-table
//   entry is checked against the resource before use; output size per
//   chunk is fixed; memory is two 32 KiB buffers plus the decoder table.
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   decoded content feeds the per-resource SHA-1 check.
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038
// - SPEC: specs/standards/wim.md §4; specs/standards/wim-compression.md §6

use std::io::{Read, Seek};

use super::header::CHUNK_SIZE;
use super::lookup::{chunk_count, chunk_entry_width, chunk_table_len};
use super::reshdr::ResourceHeader;
use super::source::Source;
use crate::codec::XpressDecoder;
use crate::error::WimError;

/// [`CHUNK_SIZE`] as a usize.
const CHUNK: usize = 32768;

/// How a chunk whose stored size is not below its expanded size is
/// treated inside a compressed resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RawChunks {
    /// Refused with [`WimError::RawChunkNotSupported`] (the M2 upload
    /// check keeps this for metadata; its behaviour is unchanged).
    Refuse,
    /// Apply (M3, M-21, M-22): a chunk whose stored size equals its
    /// expanded size (32768, or the remainder for the last chunk) is its
    /// plain bytes, at any position; a stored size of 0 or above the
    /// expanded size is refused. With 8-byte table entries (original size
    /// over 2^32), an entry value or stored size of 2^32 or more is
    /// refused, and an original size of exactly 2^32 is refused.
    // FORMAT: OBS-046 (S17; S14 entry 3030: chunks 0, 1, 4, 5 raw) and
    // OBS-057 (S17B: short final chunks of 100, 5000 and 32767 bytes
    // stored raw).
    // FORMAT: OBS-058 (S08B) - 8-byte entries for an original size over
    // 2^32, every value below 2^32; the exact threshold is open, so 2^32
    // itself is refused.
    Apply,
}

pub(crate) fn read_resource<R: Read + Seek>(
    src: &mut Source<'_, R>,
    rh: &ResourceHeader,
    decoder: Option<&mut XpressDecoder>,
    raw: RawChunks,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), WimError>,
) -> Result<(), WimError> {
    if !rh.is_compressed() {
        if rh.stored_size != rh.original_size {
            return Err(WimError::Malformed {
                what: "resource sizes",
            });
        }
        return src.stream(rh.offset, rh.stored_size, sink);
    }
    let decoder = decoder.ok_or(WimError::Malformed {
        what: "compressed resource in an uncompressed file",
    })?;
    read_compressed(src, rh, decoder, raw, sink)
}

/// The chunk table and chunks of a compressed resource.
// FORMAT: OBS-011 - ceil(original / 32768) - 1 entries; entry i is the
// end of chunk i (start of chunk i + 1) relative to the end of the table;
// chunk 0 starts right after the table; the last chunk runs to the end of
// the stored size; a one-chunk resource has no table (wim.md §4 readings
// confirmed below 2^32).
// FORMAT: OBS-012 - each chunk is one independent [MS-XCA] LZ77+Huffman
// stream that expands to 32768 bytes, the last to the remainder.
fn read_compressed<R: Read + Seek>(
    src: &mut Source<'_, R>,
    rh: &ResourceHeader,
    decoder: &mut XpressDecoder,
    raw: RawChunks,
    sink: &mut dyn FnMut(&[u8]) -> Result<(), WimError>,
) -> Result<(), WimError> {
    let oob = |what| WimError::OutOfBounds { what };
    let n = chunk_count(rh.original_size);
    let table_len = chunk_table_len(rh.original_size).ok_or(WimError::Malformed {
        what: "compressed resource size",
    })?;
    let width = chunk_entry_width(rh.original_size);
    if raw == RawChunks::Apply {
        // M-22: exactly 2^32 is ambiguous (OPEN-WIM-10 threshold); with
        // 8-byte entries the stored size stays below 2^32 (OBS-058).
        let two32 = 1u64 << 32;
        if rh.original_size == two32 || (width == 8 && rh.stored_size >= two32) {
            return Err(WimError::Malformed {
                what: "chunk table width",
            });
        }
    }
    let data_len = rh
        .stored_size
        .checked_sub(table_len)
        .ok_or(oob("chunk table"))?;
    let data_start = rh.offset.checked_add(table_len).ok_or(oob("chunk table"))?;

    let mut stored = vec![0u8; CHUNK];
    let mut out = vec![0u8; CHUNK];
    let mut start: u64 = 0;
    for i in 0..n {
        let end = if i.saturating_add(1) == n {
            data_len
        } else {
            let at = i
                .checked_mul(width)
                .and_then(|o| o.checked_add(rh.offset))
                .ok_or(oob("chunk table"))?;
            let e = read_entry(src, at, width)?;
            // M-22: entry values at or above 2^32 were never seen.
            if raw == RawChunks::Apply && e >= 1u64 << 32 {
                return Err(WimError::Malformed {
                    what: "chunk table entry",
                });
            }
            e
        };
        if end < start || end > data_len {
            return Err(oob("chunk"));
        }
        let comp_len = end.saturating_sub(start);
        let expanded = rh
            .original_size
            .saturating_sub(i.saturating_mul(u64::from(CHUNK_SIZE)))
            .min(u64::from(CHUNK_SIZE));
        if comp_len == 0 {
            return Err(WimError::Malformed { what: "chunk size" });
        }
        let stored_raw = raw == RawChunks::Apply && comp_len == expanded;
        if comp_len > expanded && raw == RawChunks::Apply {
            // M-21: no chunk was stored above its expanded size.
            return Err(WimError::Malformed { what: "chunk size" });
        }
        if comp_len >= expanded && !stored_raw {
            // `Refuse` (the M2 upload check, unchanged): every such chunk
            // is refused, as before.
            return Err(WimError::RawChunkNotSupported);
        }
        // Both fit in 32768 bytes: comp_len <= expanded <= 32768.
        let comp = usize::try_from(comp_len).map_err(|_| oob("chunk"))?;
        let exp = usize::try_from(expanded).map_err(|_| oob("chunk"))?;
        let comp_buf = stored.get_mut(..comp).ok_or(oob("chunk"))?;
        let at = data_start.checked_add(start).ok_or(oob("chunk"))?;
        src.read_at(at, comp_buf)?;
        if stored_raw {
            sink(comp_buf)?;
        } else {
            let out_buf = out.get_mut(..exp).ok_or(oob("chunk"))?;
            decoder.decode_chunk(comp_buf, out_buf)?;
            sink(out_buf)?;
        }
        start = end;
    }
    Ok(())
}

fn read_entry<R: Read + Seek>(
    src: &mut Source<'_, R>,
    at: u64,
    width: u64,
) -> Result<u64, WimError> {
    if width == 8 {
        let mut b = [0u8; 8];
        src.read_at(at, &mut b)?;
        Ok(u64::from_le_bytes(b))
    } else {
        let mut b = [0u8; 4];
        src.read_at(at, &mut b)?;
        Ok(u64::from(u32::from_le_bytes(b)))
    }
}

/// Checks the chunk table of a compressed file resource without decoding
/// it (REQ-IMG-037 bullet 2; BOOT-007), and returns how many of its chunks
/// are stored at or above their expanded size.
///
/// Rules: every entry lies inside the stored size, entries strictly
/// increase (each chunk holds at least one stored byte), and the last
/// chunk holds at least one byte. A chunk whose stored size is not below
/// its expanded size is counted, not refused: how such a chunk is stored
/// is OPEN-WIM-5, and M2 never decodes file resources (metadata resources
/// keep the refusal in [`read_resource`]).
///
/// Reads only the table (at most the stored size; with the lookup scan's
/// no-overlap rule the tables of all resources together stay within the
/// file).
// FORMAT: OBS-011 - table layout as in `read_compressed`.
// FORMAT: derived, unconfirmed - OPEN-WIM-5 (raw-sized chunks counted).
pub(crate) fn check_chunk_table<R: Read + Seek>(
    src: &mut Source<'_, R>,
    rh: &ResourceHeader,
) -> Result<u64, WimError> {
    let oob = |what| WimError::OutOfBounds { what };
    let n = chunk_count(rh.original_size);
    let table_len = chunk_table_len(rh.original_size).ok_or(WimError::Malformed {
        what: "compressed resource size",
    })?;
    let width = chunk_entry_width(rh.original_size);
    let data_len = rh
        .stored_size
        .checked_sub(table_len)
        .ok_or(oob("chunk table"))?;
    let chunk = u64::from(CHUNK_SIZE);
    let mut start: u64 = 0;
    let mut index: u64 = 0;
    let mut raw: u64 = 0;
    // One chunk: (start, end, index) -> raw-sized or error.
    let mut chunk_end = |end: u64, start: &mut u64, index: &mut u64| -> Result<(), WimError> {
        if end < *start || end > data_len {
            return Err(oob("chunk"));
        }
        let comp_len = end.saturating_sub(*start);
        if comp_len == 0 {
            return Err(WimError::Malformed { what: "chunk size" });
        }
        let expanded = rh
            .original_size
            .saturating_sub(index.saturating_mul(chunk))
            .min(chunk);
        if comp_len >= expanded {
            raw = raw.saturating_add(1);
        }
        *start = end;
        *index = index.saturating_add(1);
        Ok(())
    };
    if table_len > 0 {
        let w = usize::try_from(width).map_err(|_| oob("chunk table"))?;
        src.stream(rh.offset, table_len, &mut |piece: &[u8]| {
            // IO pieces are multiples of 8 bytes except the last, and the
            // table is a multiple of the width, so entries never straddle.
            if !piece.len().is_multiple_of(w) {
                return Err(WimError::Malformed {
                    what: "chunk table",
                });
            }
            for e in piece.chunks(w) {
                let end = match <[u8; 8]>::try_from(e) {
                    Ok(b) => u64::from_le_bytes(b),
                    Err(_) => {
                        let b = <[u8; 4]>::try_from(e).map_err(|_| WimError::Malformed {
                            what: "chunk table",
                        })?;
                        u64::from(u32::from_le_bytes(b))
                    }
                };
                chunk_end(end, &mut start, &mut index)?;
            }
            Ok(())
        })?;
    }
    // The last chunk runs to the end of the stored size.
    chunk_end(data_len, &mut start, &mut index)?;
    if index != n {
        return Err(WimError::Malformed {
            what: "chunk table",
        });
    }
    Ok(raw)
}
