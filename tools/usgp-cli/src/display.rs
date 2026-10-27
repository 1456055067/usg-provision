//! Terminal-safe rendering of server-supplied text (plan WU-8).
//!
//! Every string that came from the server or from a WIM file (edition
//! names and descriptions are WIM XML text, `WimText`, bounded only by
//! length) is passed through [`esc`] before it reaches the terminal, so a
//! crafted name cannot move the cursor, rewrite earlier output, set the
//! window title or reorder text on screen.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - untrusted text is
//   escaped on output; nothing from the server is written to the terminal
//   raw.
// - NIST 800-53: SI-11 (Error Handling) - server error text is shown
//   escaped and bounded.
// - SPEC: specs/os-images.md#REQ-IMG-040 (edition names and descriptions
//   are shown to the operator)

use std::fmt::Write as _;

/// Whether `c` must not reach a terminal as itself.
///
/// - Unicode `Cc` control characters (C0, DEL, C1), which include ESC and
///   CSI, the start of every terminal control sequence.
/// - Line and paragraph separators (U+2028, U+2029).
/// - Bidirectional formatting characters (U+061C, U+200E, U+200F,
///   U+202A to U+202E, U+2066 to U+2069), which can make text display in
///   a different order from the one stored.
fn must_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// `s` with every character of [`must_escape`] written as `\u{XXXX}` and
/// every backslash doubled, so the escaped form is unambiguous.
#[must_use]
pub fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' {
            out.push_str("\\\\");
        } else if must_escape(c) {
            let _ = write!(out, "\\u{{{:04x}}}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// A UTC timestamp in microseconds since the epoch as RFC 3339 text
/// (`2026-10-27T10:00:00.000000Z`).
#[must_use]
pub fn utc(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Proleptic Gregorian date of `days` since 1970-01-01 (the standard
/// era-based conversion; exact for every `i64` second count we can be
/// given, since `days` is at most about 1.1e8).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_unchanged() {
        assert_eq!(esc("Windows 11 Enterprise"), "Windows 11 Enterprise");
        assert_eq!(esc("Édition ü 日本"), "Édition ü 日本");
    }

    #[test]
    fn control_characters_escaped() {
        assert_eq!(esc("a\x1b[2Jb"), "a\\u{001b}[2Jb");
        assert_eq!(esc("x\ny\rz\t"), "x\\u{000a}y\\u{000d}z\\u{0009}");
        assert_eq!(esc("\u{7f}\u{9b}"), "\\u{007f}\\u{009b}");
        assert_eq!(esc("\0"), "\\u{0000}");
        // OSC title-setting sequence.
        assert_eq!(esc("\x1b]0;pwn\x07"), "\\u{001b}]0;pwn\\u{0007}");
    }

    #[test]
    fn bidi_and_separators_escaped() {
        assert_eq!(esc("a\u{202e}b"), "a\\u{202e}b");
        assert_eq!(esc("\u{2066}\u{2069}"), "\\u{2066}\\u{2069}");
        assert_eq!(esc("\u{2028}"), "\\u{2028}");
    }

    #[test]
    fn backslash_doubled_so_escapes_are_unambiguous() {
        assert_eq!(esc("\\u{001b}"), "\\\\u{001b}");
        assert_ne!(esc("\\u{001b}"), esc("\x1b"));
    }

    #[test]
    fn escaped_output_has_no_control_characters() {
        let all: String = (0u32..0x3000).filter_map(char::from_u32).collect();
        assert!(!esc(&all).chars().any(must_escape));
    }

    #[test]
    fn utc_format() {
        assert_eq!(utc(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(utc(1_000_000 * 951_782_400), "2000-02-29T00:00:00.000000Z");
        assert_eq!(utc(1_793_097_001_123_456), "2026-10-27T10:30:01.123456Z");
        assert_eq!(utc(-1), "1969-12-31T23:59:59.999999Z");
    }
}
