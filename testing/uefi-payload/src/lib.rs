//! usgp-test-payload: support code for the test-only UEFI payload.
//!
//! The payload is the program the M1 boot smoke loads over the network
//! (plan WU-9, section 10.5). It prints one marker line on the console and
//! shuts the machine down, so a harness can tell "the firmware ran our boot
//! program" from "it fell through to another boot option". It is never
//! shipped, holds no secrets (REQ-BOOT-043), and is unsigned by design: with
//! Secure Boot enforced the firmware must refuse it (M1 exit 5).
//!
//! This library holds the parts that can be checked on the build host: the
//! marker selection and its UCS-2 encoding. Both are evaluated at compile
//! time, so an invalid marker fails the build instead of the boot.
//!
//! COMPLIANCE MAPPING:
//! - NIST 800-53: SA-11 (Developer Testing and Evaluation)
//! - SPEC: specs/boot-network.md#REQ-BOOT-003 (UEFI x86-64 boot program)
//! - SPEC: specs/boot-network.md#REQ-BOOT-043 (no secrets in boot content)
//! - UEFI 2.10 §12.4 - Simple Text Output Protocol, OutputString (UCS-2)

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// Marker printed when `USGP_PAYLOAD_MARKER` is not set at build time.
pub const DEFAULT_MARKER: &str = "USGP-M1-PAYLOAD-OK";

/// Marker used by the disk fallback build (plan section 10.5, S6 and S7).
pub const DISK_FALLBACK_MARKER: &str = "USGP-M1-DISK-FALLBACK-OK";

/// The marker this build prints, chosen at compile time.
pub const MARKER: &str = match option_env!("USGP_PAYLOAD_MARKER") {
    Some(marker) => marker,
    None => DEFAULT_MARKER,
};

/// Longest marker accepted, in bytes (project choice; keeps the line short).
pub const MAX_MARKER_LEN: usize = 64;

/// UCS-2 capacity of a marker line: CR LF, the marker, CR LF and a NUL.
pub const LINE_CAPACITY: usize = MAX_MARKER_LEN + 5;

/// Time the payload waits after printing, so the line reaches the serial
/// port before shutdown (plan WU-9: one second).
pub const STALL_MICROSECONDS: usize = 1_000_000;

/// A NUL-terminated UCS-2 line, as `OutputString` expects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ucs2Line {
    buf: [u16; LINE_CAPACITY],
    /// Code units before the terminating NUL.
    len: usize,
}

impl Ucs2Line {
    /// The code units including the terminating NUL.
    pub fn as_slice(&self) -> &[u16] {
        self.buf.get(..=self.len).unwrap_or(&[])
    }

    /// Pointer for `OutputString`. The buffer is NUL-terminated because
    /// [`encode_line`] always leaves at least one zero unit after the text.
    pub fn as_mut_ptr(&mut self) -> *mut u16 {
        self.buf.as_mut_ptr()
    }
}

/// True for a byte allowed in a marker: visible ASCII, 0x21 to 0x7E. Every
/// such byte has the same value as a UCS-2 code unit.
const fn marker_byte_ok(b: u8) -> bool {
    b >= 0x21 && b <= 0x7e
}

/// Encodes `CR LF marker CR LF NUL`. Returns `None` if the marker is empty,
/// longer than [`MAX_MARKER_LEN`], or contains a byte outside 0x21 to 0x7E.
///
/// The leading CR LF starts the marker on its own line even when earlier
/// firmware output did not end in a newline.
pub const fn encode_line(marker: &str) -> Option<Ucs2Line> {
    let bytes = marker.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_MARKER_LEN {
        return None;
    }
    let mut buf = [0u16; LINE_CAPACITY];
    let mut len = 0;
    {
        let mut cursor: &mut [u16] = &mut buf;
        let mut part = 0;
        while part < 3 {
            let is_marker = part == 1;
            let mut rest: &[u8] = if is_marker { bytes } else { b"\r\n" };
            while let Some((&b, tail)) = rest.split_first() {
                if is_marker && !marker_byte_ok(b) {
                    return None;
                }
                let Some((slot, more)) = cursor.split_first_mut() else {
                    return None;
                };
                // Widening an ASCII byte to a UCS-2 unit is lossless.
                *slot = u16::from_be_bytes([0, b]);
                cursor = more;
                len += 1;
                rest = tail;
            }
            part += 1;
        }
        // At least one zero unit must remain as the terminator.
        if cursor.is_empty() {
            return None;
        }
    }
    Some(Ucs2Line { buf, len })
}

/// The marker line for this build. `None` only if [`MARKER`] is invalid,
/// which the assertion below turns into a build failure.
pub const MARKER_LINE: Option<Ucs2Line> = encode_line(MARKER);

const _: () = assert!(
    MARKER_LINE.is_some(),
    "USGP_PAYLOAD_MARKER must be 1 to 64 visible ASCII characters"
);

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(line: &Ucs2Line) -> String {
        let (nul, text) = line.as_slice().split_last().unwrap();
        assert_eq!(*nul, 0, "line is NUL-terminated");
        String::from_utf16(text).unwrap()
    }

    #[test]
    fn default_marker_line_is_crlf_framed() {
        let line = encode_line(DEFAULT_MARKER).unwrap();
        assert_eq!(decode(&line), "\r\nUSGP-M1-PAYLOAD-OK\r\n");
    }

    #[test]
    fn disk_fallback_marker_encodes() {
        let line = encode_line(DISK_FALLBACK_MARKER).unwrap();
        assert_eq!(decode(&line), "\r\nUSGP-M1-DISK-FALLBACK-OK\r\n");
    }

    #[test]
    fn build_marker_is_valid() {
        assert!(MARKER_LINE.is_some());
        assert_eq!(decode(&MARKER_LINE.unwrap()), format!("\r\n{MARKER}\r\n"));
    }

    #[test]
    fn empty_marker_rejected() {
        assert_eq!(encode_line(""), None);
    }

    #[test]
    fn max_length_marker_fits_with_nul() {
        let marker = "A".repeat(MAX_MARKER_LEN);
        let line = encode_line(&marker).unwrap();
        assert_eq!(line.as_slice().len(), LINE_CAPACITY);
        assert_eq!(decode(&line), format!("\r\n{marker}\r\n"));
    }

    #[test]
    fn overlong_marker_rejected() {
        assert_eq!(encode_line(&"A".repeat(MAX_MARKER_LEN + 1)), None);
    }

    #[test]
    fn non_visible_or_non_ascii_rejected() {
        for bad in ["A B", "A\tB", "A\0B", "A\u{7f}", "caf\u{e9}", "\u{2603}"] {
            assert_eq!(encode_line(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn every_visible_ascii_byte_accepted() {
        for b in 0x21u8..=0x7e {
            let s = String::from(char::from(b));
            assert!(encode_line(&s).is_some(), "{b:#x}");
        }
    }
}
