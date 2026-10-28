//! CRC-32 for GPT headers and partition entry arrays.
//!
//! UEFI uses the CCITT32 CRC with polynomial `0x04C11DB7` (UEFI 2.10
//! §4.2.1, `specs/standards/gpt.md` §6). The summary does not state the
//! initial value, reflection or final XOR (OPEN-GPT-1). We implement the
//! common reflected form (init `0xFFFFFFFF`, input and output reflected,
//! final XOR `0xFFFFFFFF`), as plan §1.2(c) directs, and confirm it with
//! two independent oracles: a GPT written by Microsoft's DiskPart must
//! parse (GPT-OBS-001, Windows CI) and OVMF must boot a disk we wrote
//! (GPT-OBS-002, QEMU S10).
//!
//! The implementation is bitwise (no lookup table) so that it needs no
//! indexing; GPT arrays are 16 KiB, so speed does not matter.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity)
// - SPEC: specs/disk.md#REQ-DISK-009
// - UEFI 2.10 §4.2.1 - CRC algorithm (specs/standards/gpt.md §6)
//
// POAM: OPEN-GPT-1 - the CRC-32 initial value, reflection and final XOR are
// not stated in the standards summary; the parameters below are confirmed
// only once GPT-OBS-001 (DiskPart-written GPT parses) and GPT-OBS-002 (OVMF
// boots our GPT) are recorded in docs/formats/gpt-observed.md.

/// FORMAT: UEFI 2.10 §4.2.1 - generator polynomial `0x04C11DB7`
/// (`gpt.md` §6), here in its bit-reversed form for the reflected
/// algorithm (plan §1.2(c), OPEN-GPT-1).
const POLY_REFLECTED: u32 = 0x04C1_1DB7_u32.reverse_bits();
/// FORMAT: plan §1.2(c) (OPEN-GPT-1) - initial register value.
const INIT: u32 = 0xFFFF_FFFF;
/// FORMAT: plan §1.2(c) (OPEN-GPT-1) - final XOR value.
const XOR_OUT: u32 = 0xFFFF_FFFF;

/// Incremental CRC-32 state.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    reg: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// A fresh CRC.
    #[must_use]
    pub const fn new() -> Self {
        Self { reg: INIT }
    }

    /// Feeds bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut reg = self.reg;
        for &b in data {
            reg ^= u32::from(b);
            for _ in 0..8 {
                let mask = (reg & 1).wrapping_neg();
                reg = (reg >> 1) ^ (POLY_REFLECTED & mask);
            }
        }
        self.reg = reg;
    }

    /// The CRC of everything fed so far.
    #[must_use]
    pub const fn finish(&self) -> u32 {
        self.reg ^ XOR_OUT
    }
}

/// CRC-32 of `data`.
#[must_use]
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finish()
}
