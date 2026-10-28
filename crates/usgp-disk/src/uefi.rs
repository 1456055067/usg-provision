//! UEFI boot-option bytes: `Boot####` load options, `BootOrder`, and the
//! device path nodes needed to point at a file on a GPT partition.
//!
//! This module only builds and parses bytes. Reading and writing firmware
//! variables is the platform backend's job (`usgp-winapi`, WU-5), and the
//! only names it can be given are those of [`BootVarName`]: `BootOrder` and
//! `Boot####` in the EFI global variable namespace. No Secure Boot variable
//! (PK, KEK, db, dbx, SecureBoot, ...) can be named, so no code path built
//! on this module can change Secure Boot state (DEC-0018 item 5).
//!
//! For REQ-BOOT-065 and DEC-0018 item 9 the deploy engine:
//!
//! 1. builds the Windows Boot Manager option for the ESP we wrote
//!    ([`LoadOption::windows_boot_manager`]), reusing an existing option
//!    that already points there ([`LoadOption::points_to`]) or taking a
//!    free number ([`free_option_number`]);
//! 2. writes `BootOrder` = [`put_first`] of the current order, so the
//!    change lasts across restarts (`BootNext` is one-shot,
//!    `uefi-boot-manager.md` §3, and is deliberately not offered);
//! 3. reads both back and compares.
//!
//! Options we did not write are never re-encoded: unknown or malformed
//! `Boot####` values are only parsed (bounded) to see whether they are
//! ours, and are otherwise left untouched.
//!
//! **Strings (OPEN-UBM-2).** `Description` is 16-bit characters with a
//! 16-bit null (`uefi-boot-manager.md` §10.2). For the File Path node we
//! take the summary's **[reading]** in §10.6: the same 16-bit characters
//! with a 16-bit null. The parser decodes them as UTF-16 and refuses
//! unpaired surrogates. The encoder accepts **printable ASCII only**, where
//! UCS-2 and UTF-16 are byte-identical, so what we write does not depend
//! on how OPEN-UBM-2 is settled.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounded, strict
//   parsers for firmware-provided variable data
// - NIST 800-53: CM-7 (Least Functionality) - only BootOrder and Boot####
//   can be named; no Secure Boot variables
// - NIST 800-53: SI-7 (Software, Firmware, and Information Integrity) -
//   Secure Boot never weakened (DEC-0018 item 5)
// - SPEC: specs/boot-network.md#REQ-BOOT-065 (DEC-0018 item 9)
// - specs/standards/uefi-boot-manager.md §2, §3, §10 (UEFI 2.10 §3.1.1,
//   §3.1.2, §3.1.3, §3.3, §8.2.1, UEFI §10.2, §10.3.1, §10.3.5.1,
//   §10.3.5.4)

use std::fmt;

use crate::bytes;
use crate::error::UefiError;
use crate::guid::Guid;
use crate::layout::Part;

/// FORMAT: uefi-boot-manager.md §10.3 - `EFI_GLOBAL_VARIABLE`
/// `{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}`.
pub const EFI_GLOBAL_VARIABLE: Guid = Guid::from_fields(
    0x8BE4_DF61,
    0x93CA,
    0x11D2,
    [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
);

/// FORMAT: uefi-boot-manager.md §10.3 (UEFI §8.2.1) -
/// `EFI_VARIABLE_NON_VOLATILE`.
pub const VARIABLE_NON_VOLATILE: u32 = 0x1;
/// FORMAT: uefi-boot-manager.md §10.3 (UEFI §8.2.1) -
/// `EFI_VARIABLE_BOOTSERVICE_ACCESS`.
pub const VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x2;
/// FORMAT: uefi-boot-manager.md §10.3 (UEFI §8.2.1) -
/// `EFI_VARIABLE_RUNTIME_ACCESS`.
pub const VARIABLE_RUNTIME_ACCESS: u32 = 0x4;
/// FORMAT: uefi-boot-manager.md §10.3 (UEFI §3.3) - `Boot####` and
/// `BootOrder` are NV + BS + RT (`0x00000007`).
pub const BOOT_VARIABLE_ATTRIBUTES: u32 =
    VARIABLE_NON_VOLATILE | VARIABLE_BOOTSERVICE_ACCESS | VARIABLE_RUNTIME_ACCESS;

/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_ACTIVE`.
pub const LOAD_OPTION_ACTIVE: u32 = 0x0000_0001;
/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_FORCE_RECONNECT`.
pub const LOAD_OPTION_FORCE_RECONNECT: u32 = 0x0000_0002;
/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_HIDDEN`.
pub const LOAD_OPTION_HIDDEN: u32 = 0x0000_0008;
/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_CATEGORY` mask.
pub const LOAD_OPTION_CATEGORY: u32 = 0x0000_1F00;
/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_CATEGORY_BOOT`.
pub const LOAD_OPTION_CATEGORY_BOOT: u32 = 0x0000_0000;
/// FORMAT: uefi-boot-manager.md §10.2 - `LOAD_OPTION_CATEGORY_APP`.
pub const LOAD_OPTION_CATEGORY_APP: u32 = 0x0000_0100;

/// FORMAT: uefi-boot-manager.md §10.4 - node header length.
pub const NODE_HEADER_LEN: usize = 4;
/// FORMAT: uefi-boot-manager.md §10.4 - media device path type.
pub const TYPE_MEDIA: u8 = 0x04;
/// FORMAT: uefi-boot-manager.md §10.4 - end of path type.
pub const TYPE_END: u8 = 0x7F;
/// FORMAT: uefi-boot-manager.md §10.4 - End subtype: end of the whole path.
pub const SUBTYPE_END_ENTIRE: u8 = 0xFF;
/// FORMAT: uefi-boot-manager.md §10.4 - End subtype: end of one instance.
pub const SUBTYPE_END_INSTANCE: u8 = 0x01;
/// FORMAT: uefi-boot-manager.md §10.4 - End node length.
pub const END_NODE_LEN: u16 = 4;
/// FORMAT: uefi-boot-manager.md §10.5 - Hard Drive media subtype.
pub const SUBTYPE_HARD_DRIVE: u8 = 0x01;
/// FORMAT: uefi-boot-manager.md §10.5 - Hard Drive node length.
pub const HARD_DRIVE_NODE_LEN: u16 = 42;
/// FORMAT: uefi-boot-manager.md §10.6 - File Path media subtype.
pub const SUBTYPE_FILE_PATH: u8 = 0x04;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Format `0x01`, MBR.
pub const PARTITION_FORMAT_MBR: u8 = 0x01;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Format `0x02`, GPT.
pub const PARTITION_FORMAT_GPT: u8 = 0x02;
/// FORMAT: uefi-boot-manager.md §10.5 - Signature Type `0x00`, none.
pub const SIGNATURE_TYPE_NONE: u8 = 0x00;
/// FORMAT: uefi-boot-manager.md §10.5 - Signature Type `0x01`, 32-bit MBR
/// signature.
pub const SIGNATURE_TYPE_MBR: u8 = 0x01;
/// FORMAT: uefi-boot-manager.md §10.5 - Signature Type `0x02`, GUID.
pub const SIGNATURE_TYPE_GUID: u8 = 0x02;

// Hard Drive node field offsets (uefi-boot-manager.md §10.5, Table 10.54).
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Number at 4.
const HD_NUMBER: usize = 4;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Start at 8.
const HD_START: usize = 8;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Size at 16.
const HD_SIZE: usize = 16;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Signature at 24.
const HD_SIGNATURE: usize = 24;
/// FORMAT: uefi-boot-manager.md §10.5 - Partition Format at 40.
const HD_FORMAT: usize = 40;
/// FORMAT: uefi-boot-manager.md §10.5 - Signature Type at 41.
const HD_SIG_TYPE: usize = 41;
/// FORMAT: uefi-boot-manager.md §10.5 - the MBR signature uses the first 4
/// bytes of the signature field; the rest is zero.
const HD_MBR_SIG_LEN: usize = 4;

// Load option field offsets (uefi-boot-manager.md §10.2).
/// FORMAT: uefi-boot-manager.md §10.2 - `Attributes` at 0 (UINT32).
const LO_ATTRIBUTES: usize = 0;
/// FORMAT: uefi-boot-manager.md §10.2 - `FilePathListLength` at 4 (UINT16).
const LO_FPL_LEN: usize = 4;
/// FORMAT: uefi-boot-manager.md §10.2 - `Description` starts at 6.
const LO_DESCRIPTION: usize = 6;

/// FORMAT: uefi-boot-manager.md §9.1 - the Windows boot manager on the ESP
/// (UEFI): `\EFI\Microsoft\Boot\bootmgfw.efi`. Backslash separator per
/// §10.6.
pub const WINDOWS_BOOT_MANAGER_PATH: &str = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
/// Design choice: the description we give our option. §9.2 names the
/// entry "Windows Boot Manager"; no exact description text is specified.
pub const WINDOWS_BOOT_MANAGER_DESCRIPTION: &str = "Windows Boot Manager";

/// Bounds applied when parsing variable data from firmware. Design values
/// (not from a standard; plan §6 "malformed firmware variables").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UefiLimits {
    /// Largest `Boot####` value accepted.
    pub max_option_bytes: usize,
    /// Most 16-bit units in `Description`, terminator included.
    pub max_description_units: usize,
    /// Most nodes in a `FilePathList`.
    pub max_nodes: usize,
    /// Most 16-bit units in one File Path node string, terminator included.
    pub max_path_units: usize,
    /// Most entries in `BootOrder`.
    pub max_boot_order_entries: usize,
}

impl Default for UefiLimits {
    /// 64 KiB per option, 1024-unit descriptions, 64 nodes, 1024-unit paths,
    /// 1024 `BootOrder` entries.
    fn default() -> Self {
        Self {
            max_option_bytes: 64 * 1024,
            max_description_units: 1024,
            max_nodes: 64,
            max_path_units: 1024,
            max_boot_order_entries: 1024,
        }
    }
}

/// The only firmware variables this crate can name: `BootOrder` and
/// `Boot####`, both in [`EFI_GLOBAL_VARIABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BootVarName(Kind);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Kind {
    BootOrder,
    Boot(u16),
}

impl BootVarName {
    /// `BootOrder`.
    #[must_use]
    pub const fn boot_order() -> Self {
        Self(Kind::BootOrder)
    }

    /// `Boot####` for option number `n`.
    #[must_use]
    pub const fn boot_option(n: u16) -> Self {
        Self(Kind::Boot(n))
    }

    /// The option number, for a `Boot####` name.
    #[must_use]
    pub fn option_number(&self) -> Option<u16> {
        match self.0 {
            Kind::Boot(n) => Some(n),
            Kind::BootOrder => None,
        }
    }

    /// Parses a variable name. Only `BootOrder` and `Boot` followed by
    /// exactly four `0-9`/`A-F` digits are accepted (§10.3); everything
    /// else, including every Secure Boot variable, is `None`.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        if name == "BootOrder" {
            return Some(Self::boot_order());
        }
        let digits = name.strip_prefix("Boot")?;
        if digits.len() != 4
            || !digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
        {
            return None;
        }
        u16::from_str_radix(digits, 16).ok().map(Self::boot_option)
    }

    /// The vendor GUID: always [`EFI_GLOBAL_VARIABLE`].
    #[must_use]
    pub const fn vendor(&self) -> Guid {
        EFI_GLOBAL_VARIABLE
    }

    /// The attributes to write with: always NV + BS + RT (§10.3).
    #[must_use]
    pub const fn attributes(&self) -> u32 {
        BOOT_VARIABLE_ATTRIBUTES
    }
}

impl fmt::Display for BootVarName {
    /// `BootOrder`, or `Boot` + four upper-case hex digits (§10.3).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Kind::BootOrder => f.write_str("BootOrder"),
            Kind::Boot(n) => write!(f, "Boot{n:04X}"),
        }
    }
}

/// The Hard Drive media node (§10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardDrive {
    /// Partition Number (1-based; 0 = whole disk).
    pub partition_number: u32,
    /// Partition Start, in logical blocks.
    pub start_lba: u64,
    /// Partition Size, in logical blocks.
    pub size_lbas: u64,
    /// Partition Signature (16 bytes; meaning set by `signature_type`).
    pub signature: [u8; 16],
    /// Partition Format.
    pub format: u8,
    /// Signature Type.
    pub signature_type: u8,
}

impl HardDrive {
    /// The node for a GPT partition we planned: GPT format, GUID signature
    /// equal to the partition's UniquePartitionGUID in UEFI byte order
    /// (§10.5 **[reading]**; `gpt.md` §5).
    #[must_use]
    pub fn for_gpt_part(p: &Part) -> Self {
        Self {
            partition_number: p.number,
            start_lba: p.first_lba,
            size_lbas: p.len_lbas(),
            signature: p.unique_guid.0,
            format: PARTITION_FORMAT_GPT,
            signature_type: SIGNATURE_TYPE_GUID,
        }
    }
}

/// One device path node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// Hard Drive media node.
    HardDrive(HardDrive),
    /// File Path media node; the string without its terminator.
    FilePath(String),
    /// End of one instance (`0x7F`/`0x01`).
    EndInstance,
    /// End of the whole path (`0x7F`/`0xFF`).
    EndEntire,
    /// Any other node, kept as type, subtype and data (skipped by length,
    /// §10.4).
    Other {
        /// Type.
        node_type: u8,
        /// SubType.
        sub_type: u8,
        /// Bytes after the header.
        data: Vec<u8>,
    },
}

/// A parsed `Boot####` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOption {
    /// Attributes, as stored (unused bits kept, §10.2).
    pub attributes: u32,
    /// Description, 16-bit units without the terminator.
    pub description: Vec<u16>,
    /// The device paths of `FilePathList`, each ending with
    /// [`Node::EndEntire`].
    pub paths: Vec<Vec<Node>>,
    /// OptionalData.
    pub optional_data: Vec<u8>,
}

impl LoadOption {
    /// The option for Windows Boot Manager on `esp`: ACTIVE, category boot,
    /// other bits zero (§10.2: unused bits zero when created); one device
    /// path Hard Drive → File Path → End (§10.7, short form); no optional
    /// data.
    #[must_use]
    pub fn windows_boot_manager(esp: &Part) -> Self {
        Self {
            attributes: LOAD_OPTION_ACTIVE | LOAD_OPTION_CATEGORY_BOOT,
            description: WINDOWS_BOOT_MANAGER_DESCRIPTION.encode_utf16().collect(),
            paths: vec![vec![
                Node::HardDrive(HardDrive::for_gpt_part(esp)),
                Node::FilePath(WINDOWS_BOOT_MANAGER_PATH.to_owned()),
                Node::EndEntire,
            ]],
            optional_data: Vec::new(),
        }
    }

    /// `true` if this option is active, in the boot category, and its first
    /// device path is a GPT Hard Drive node for exactly `esp` (number,
    /// start, size, GUID signature) followed by the Windows Boot Manager
    /// file (matched ASCII case-insensitively) and the End node.
    #[must_use]
    pub fn points_to(&self, esp: &Part) -> bool {
        let active = self.attributes & LOAD_OPTION_ACTIVE != 0
            && self.attributes & LOAD_OPTION_CATEGORY == LOAD_OPTION_CATEGORY_BOOT;
        match self.paths.first().map(Vec::as_slice) {
            Some([Node::HardDrive(hd), Node::FilePath(f), Node::EndEntire]) => {
                active
                    && *hd == HardDrive::for_gpt_part(esp)
                    && f.eq_ignore_ascii_case(WINDOWS_BOOT_MANAGER_PATH)
            }
            _ => false,
        }
    }

    /// The description, with invalid UTF-16 replaced (display only).
    #[must_use]
    pub fn description_lossy(&self) -> String {
        char::decode_utf16(self.description.iter().copied())
            .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect()
    }

    /// Encodes the option as a `Boot####` value (§10.2).
    ///
    /// # Errors
    /// [`UefiError::Encode`] for a description or path that is not
    /// printable ASCII (see the module note on OPEN-UBM-2), a node that does
    /// not fit its length field, a path not ending in End, or an empty path
    /// list.
    pub fn encode(&self) -> Result<Vec<u8>, UefiError> {
        if self.paths.is_empty() {
            return Err(UefiError::Encode("no device path"));
        }
        let mut fpl = Vec::new();
        for path in &self.paths {
            if path.last() != Some(&Node::EndEntire)
                || path.iter().rev().skip(1).any(|n| *n == Node::EndEntire)
            {
                return Err(UefiError::Encode("device path must end with one End node"));
            }
            for node in path {
                encode_node(node, &mut fpl)?;
            }
        }
        let fpl_len =
            u16::try_from(fpl.len()).map_err(|_| UefiError::Encode("FilePathList too long"))?;
        if self.description.iter().any(|&u| !is_printable_ascii(u)) {
            return Err(UefiError::Encode("description not printable ASCII"));
        }
        let mut out = Vec::new();
        out.extend_from_slice(&self.attributes.to_le_bytes());
        out.extend_from_slice(&fpl_len.to_le_bytes());
        for u in &self.description {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&fpl);
        out.extend_from_slice(&self.optional_data);
        Ok(out)
    }
}

fn is_printable_ascii(u: u16) -> bool {
    (0x20..0x7F).contains(&u)
}

fn push_header(out: &mut Vec<u8>, t: u8, st: u8, len: u16) {
    out.push(t);
    out.push(st);
    out.extend_from_slice(&len.to_le_bytes());
}

fn encode_node(node: &Node, out: &mut Vec<u8>) -> Result<(), UefiError> {
    match node {
        Node::HardDrive(hd) => {
            push_header(out, TYPE_MEDIA, SUBTYPE_HARD_DRIVE, HARD_DRIVE_NODE_LEN);
            out.extend_from_slice(&hd.partition_number.to_le_bytes());
            out.extend_from_slice(&hd.start_lba.to_le_bytes());
            out.extend_from_slice(&hd.size_lbas.to_le_bytes());
            out.extend_from_slice(&hd.signature);
            out.push(hd.format);
            out.push(hd.signature_type);
        }
        Node::FilePath(s) => {
            if s.is_empty() || !s.bytes().all(|b| is_printable_ascii(u16::from(b))) {
                return Err(UefiError::Encode("file path not printable ASCII"));
            }
            // 16-bit units plus a 16-bit null (§10.6 [reading]).
            let units = s.len().checked_add(1).and_then(|n| n.checked_mul(2));
            let len = units
                .and_then(|n| n.checked_add(NODE_HEADER_LEN))
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(UefiError::Encode("file path too long"))?;
            push_header(out, TYPE_MEDIA, SUBTYPE_FILE_PATH, len);
            for u in s.encode_utf16().chain(std::iter::once(0)) {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        Node::EndInstance => push_header(out, TYPE_END, SUBTYPE_END_INSTANCE, END_NODE_LEN),
        Node::EndEntire => push_header(out, TYPE_END, SUBTYPE_END_ENTIRE, END_NODE_LEN),
        Node::Other {
            node_type,
            sub_type,
            data,
        } => {
            if *node_type == TYPE_END {
                return Err(UefiError::Encode("End node with data"));
            }
            let len = data
                .len()
                .checked_add(NODE_HEADER_LEN)
                .and_then(|n| u16::try_from(n).ok())
                .ok_or(UefiError::Encode("node too long"))?;
            push_header(out, *node_type, *sub_type, len);
            out.extend_from_slice(data);
        }
    }
    Ok(())
}

/// Decodes `units` 16-bit little-endian units, which must end with exactly
/// one null (the last unit), as strict UTF-16.
fn decode_c16(raw: &[u8], base: usize, what: &'static str) -> Result<String, UefiError> {
    let bad = |what| UefiError::Malformed { offset: base, what };
    let (pairs, rest) = raw.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(bad(what));
    }
    let units: Vec<u16> = pairs.iter().map(|p| u16::from_le_bytes(*p)).collect();
    match units.split_last() {
        Some((0, body)) if !body.contains(&0) => char::decode_utf16(body.iter().copied())
            .collect::<Result<String, _>>()
            .map_err(|_| bad("unpaired UTF-16 surrogate")),
        _ => Err(bad(what)),
    }
}

/// Parses one node at `off` in `list`; returns the node and its length.
fn parse_node(list: &[u8], off: usize, l: &UefiLimits) -> Result<(Node, usize), UefiError> {
    let trunc = |what| UefiError::Truncated { offset: off, what };
    let bad = |what| UefiError::Malformed { offset: off, what };
    let header = bytes::field(list, off, NODE_HEADER_LEN).ok_or_else(|| trunc("node header"))?;
    let (t, st) = match header {
        [t, st, ..] => (*t, *st),
        _ => return Err(trunc("node header")),
    };
    let len = usize::from(bytes::le_u16(list, off + 2).ok_or_else(|| trunc("node length"))?);
    if len < NODE_HEADER_LEN {
        return Err(bad("node length below header size"));
    }
    let node = bytes::field(list, off, len).ok_or_else(|| trunc("node body"))?;
    let data = node
        .get(NODE_HEADER_LEN..)
        .ok_or_else(|| trunc("node body"))?;
    let parsed = match (t, st) {
        (TYPE_END, SUBTYPE_END_ENTIRE | SUBTYPE_END_INSTANCE) => {
            if len != usize::from(END_NODE_LEN) {
                return Err(bad("End node length"));
            }
            if st == SUBTYPE_END_ENTIRE {
                Node::EndEntire
            } else {
                Node::EndInstance
            }
        }
        (TYPE_END, _) => return Err(bad("unknown End subtype")),
        (TYPE_MEDIA, SUBTYPE_HARD_DRIVE) => {
            if len != usize::from(HARD_DRIVE_NODE_LEN) {
                return Err(bad("Hard Drive node length"));
            }
            let f = |o: usize| UefiError::Truncated {
                offset: off.saturating_add(o),
                what: "Hard Drive field",
            };
            let hd = HardDrive {
                partition_number: bytes::le_u32(node, HD_NUMBER).ok_or_else(|| f(HD_NUMBER))?,
                start_lba: bytes::le_u64(node, HD_START).ok_or_else(|| f(HD_START))?,
                size_lbas: bytes::le_u64(node, HD_SIZE).ok_or_else(|| f(HD_SIZE))?,
                signature: bytes::array(node, HD_SIGNATURE).ok_or_else(|| f(HD_SIGNATURE))?,
                format: *node.get(HD_FORMAT).ok_or_else(|| f(HD_FORMAT))?,
                signature_type: *node.get(HD_SIG_TYPE).ok_or_else(|| f(HD_SIG_TYPE))?,
            };
            check_hard_drive(&hd).map_err(bad)?;
            Node::HardDrive(hd)
        }
        (TYPE_MEDIA, SUBTYPE_FILE_PATH) => {
            if data.len() / 2 > l.max_path_units {
                return Err(UefiError::Limit("file path length"));
            }
            Node::FilePath(decode_c16(data, off, "file path string")?)
        }
        _ => Node::Other {
            node_type: t,
            sub_type: st,
            data: data.to_vec(),
        },
    };
    Ok((parsed, len))
}

/// Value checks from Table 10.54 (§10.5).
fn check_hard_drive(hd: &HardDrive) -> Result<(), &'static str> {
    if !matches!(hd.format, PARTITION_FORMAT_MBR | PARTITION_FORMAT_GPT) {
        return Err("unknown Partition Format");
    }
    match hd.signature_type {
        SIGNATURE_TYPE_NONE if hd.signature != [0; 16] => Err("signature type 0 with signature"),
        SIGNATURE_TYPE_MBR
            if hd
                .signature
                .get(HD_MBR_SIG_LEN..)
                .is_none_or(|t| t.iter().any(|&b| b != 0)) =>
        {
            Err("MBR signature beyond 4 bytes")
        }
        SIGNATURE_TYPE_NONE | SIGNATURE_TYPE_MBR | SIGNATURE_TYPE_GUID => Ok(()),
        _ => Err("unknown Signature Type"),
    }
}

/// Parses a `FilePathList` into device paths (§10.2, §10.4). Every path
/// ends with an End-entire node; the list must be consumed exactly.
fn parse_file_path_list(list: &[u8], l: &UefiLimits) -> Result<Vec<Vec<Node>>, UefiError> {
    let mut paths = Vec::new();
    let mut current = Vec::new();
    let mut off = 0usize;
    let mut count = 0usize;
    while off < list.len() {
        count += 1;
        if count > l.max_nodes {
            return Err(UefiError::Limit("device path nodes"));
        }
        let (node, len) = parse_node(list, off, l)?;
        off = off.checked_add(len).ok_or(UefiError::Limit("offset"))?;
        let end = node == Node::EndEntire;
        current.push(node);
        if end {
            paths.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() || paths.is_empty() {
        return Err(UefiError::Malformed {
            offset: off,
            what: "device path not ended by an End node",
        });
    }
    Ok(paths)
}

/// Parses a `Boot####` value (§10.2), strictly and within `l`.
///
/// # Errors
/// [`UefiError`] naming the offset and the rule broken.
pub fn parse_load_option(b: &[u8], l: &UefiLimits) -> Result<LoadOption, UefiError> {
    if b.len() > l.max_option_bytes {
        return Err(UefiError::Limit("load option size"));
    }
    let attributes = bytes::le_u32(b, LO_ATTRIBUTES).ok_or(UefiError::Truncated {
        offset: LO_ATTRIBUTES,
        what: "Attributes",
    })?;
    let fpl_len = usize::from(bytes::le_u16(b, LO_FPL_LEN).ok_or(UefiError::Truncated {
        offset: LO_FPL_LEN,
        what: "FilePathListLength",
    })?);
    // Description: 16-bit units up to and including the first null.
    let mut description = Vec::new();
    let mut off = LO_DESCRIPTION;
    loop {
        if description.len() >= l.max_description_units {
            return Err(UefiError::Limit("description length"));
        }
        let u = bytes::le_u16(b, off).ok_or(UefiError::Truncated {
            offset: off,
            what: "Description terminator",
        })?;
        off += 2;
        if u == 0 {
            break;
        }
        description.push(u);
    }
    let list = bytes::field(b, off, fpl_len).ok_or(UefiError::Truncated {
        offset: off,
        what: "FilePathList",
    })?;
    if fpl_len == 0 {
        return Err(UefiError::Malformed {
            offset: LO_FPL_LEN,
            what: "empty FilePathList",
        });
    }
    let paths = parse_file_path_list(list, l).map_err(|e| shift(e, off))?;
    let optional_data = b.get(off + fpl_len..).unwrap_or_default().to_vec();
    Ok(LoadOption {
        attributes,
        description,
        paths,
        optional_data,
    })
}

/// Rebases an error offset from the list to the whole value.
fn shift(e: UefiError, by: usize) -> UefiError {
    match e {
        UefiError::Truncated { offset, what } => UefiError::Truncated {
            offset: offset.saturating_add(by),
            what,
        },
        UefiError::Malformed { offset, what } => UefiError::Malformed {
            offset: offset.saturating_add(by),
            what,
        },
        other => other,
    }
}

/// Parses a `BootOrder` value: an array of UINT16 option numbers (§10.3).
/// An empty value is an empty order.
///
/// # Errors
/// [`UefiError::Malformed`] for an odd length; [`UefiError::Limit`] above
/// `l.max_boot_order_entries`.
pub fn parse_boot_order(b: &[u8], l: &UefiLimits) -> Result<Vec<u16>, UefiError> {
    let (pairs, rest) = b.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(UefiError::Malformed {
            offset: b.len().saturating_sub(1),
            what: "BootOrder length not a multiple of 2",
        });
    }
    if pairs.len() > l.max_boot_order_entries {
        return Err(UefiError::Limit("BootOrder entries"));
    }
    Ok(pairs.iter().map(|p| u16::from_le_bytes(*p)).collect())
}

/// Encodes a `BootOrder` value.
#[must_use]
pub fn encode_boot_order(order: &[u16]) -> Vec<u8> {
    order.iter().flat_map(|n| n.to_le_bytes()).collect()
}

/// The new `BootOrder`: `n` first, then the rest of `order` in its
/// existing order with every repeat (and `n` itself) dropped
/// (REQ-BOOT-065; DEC-0018 item 9).
#[must_use]
pub fn put_first(order: &[u16], n: u16) -> Vec<u16> {
    let mut out = Vec::with_capacity(order.len().saturating_add(1));
    out.push(n);
    for &x in order {
        if !out.contains(&x) {
            out.push(x);
        }
    }
    out
}

/// The lowest option number not in `used` (all `Boot####` variables
/// present, not only those in `BootOrder`), or `None` if all 65,536 are
/// taken.
#[must_use]
pub fn free_option_number(used: &[u16]) -> Option<u16> {
    let mut taken = vec![false; usize::from(u16::MAX) + 1];
    for &n in used {
        if let Some(t) = taken.get_mut(usize::from(n)) {
            *t = true;
        }
    }
    (0..=u16::MAX).find(|&n| taken.get(usize::from(n)) == Some(&false))
}
