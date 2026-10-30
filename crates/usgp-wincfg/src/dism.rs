//! Driver listing parser for the offline image's driver list
//! (`offline-drivers.md` §7.3), list format: blocks of "Label : value"
//! lines separated by blank lines.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounded input,
//   rows and value lengths; fail closed on any unexpected driver block;
//   CM-7(5) evidence that only the authorized drivers were staged
// - SPEC: specs/standards/offline-drivers.md §7.3 (field names), §7.4
// - Decision 0025 (driver step stops on any check failure)

// POAM: the list layout (separators, block boundaries, whether labels stay
// English) is not published (OPEN-DRVS-4, OPEN-DRVS-5). This parser keys on
// the published field names only and fails closed; it is checked against
// real output by the WU-13 CI observation (DISM-OBS) and the MT-3 lab.

use thiserror::Error;

/// Largest listing accepted, in bytes.
pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
/// Most driver rows.
pub const MAX_ROWS: usize = 10_000;
/// Longest value, in bytes.
pub const MAX_VALUE_BYTES: usize = 1024;

const PUBLISHED: &str = "Published Name";
const ORIGINAL: &str = "Original File Name";
const INBOX: &str = "Inbox";
const CLASS: &str = "Class Name";
const PROVIDER: &str = "Provider Name";
const DATE: &str = "Date";
const VERSION: &str = "Version";
const LABELS: [&str; 7] = [PUBLISHED, ORIGINAL, INBOX, CLASS, PROVIDER, DATE, VERSION];

/// One listed driver package (`offline-drivers.md` §7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverRow {
    /// Store name (`oem<number>.inf` form).
    pub published_name: String,
    /// The INF's own file name.
    pub original_file_name: String,
    /// Inbox driver.
    pub inbox: bool,
    /// Device class friendly name.
    pub class_name: String,
    /// Provider or signer.
    pub provider_name: String,
    /// Driver date, locale-formatted; opaque (OPEN-DRVS-4).
    pub date: String,
    /// Driver version.
    pub version: String,
}

/// Why a listing was refused. Carries labels and line numbers only.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DismParseError {
    /// Input over [`MAX_INPUT_BYTES`].
    #[error("driver listing is too large")]
    TooLarge,
    /// More than [`MAX_ROWS`] drivers.
    #[error("driver listing has too many rows")]
    TooManyRows,
    /// A value over [`MAX_VALUE_BYTES`].
    #[error("value too long at line {line}")]
    ValueTooLong {
        /// 1-based line.
        line: usize,
    },
    /// A line in a driver block that is not "Label : value".
    #[error("unexpected line shape at line {line}")]
    BadLine {
        /// 1-based line.
        line: usize,
    },
    /// A driver block without a required field.
    #[error("driver block ending at line {line} lacks {label}")]
    MissingField {
        /// Missing label.
        label: &'static str,
        /// 1-based line.
        line: usize,
    },
    /// A required field given twice in one block.
    #[error("duplicate {label} at line {line}")]
    DuplicateField {
        /// Repeated label.
        label: &'static str,
        /// 1-based line.
        line: usize,
    },
    /// A required field that is empty or has an unknown value.
    #[error("invalid {label} at line {line}")]
    InvalidField {
        /// Label.
        label: &'static str,
        /// 1-based line.
        line: usize,
    },
}

/// Parses a list-format driver listing.
///
/// Blocks are separated by blank lines. A block holding none of the seven
/// published labels is not a driver block and is skipped (tool banner,
/// status lines). A block holding any of them must hold all seven exactly
/// once, every line must be "Label : value", and Inbox must be Yes or No.
/// Other labels in a driver block are tolerated (§7.3 [reading]).
///
/// # Errors
///
/// A [`DismParseError`]; nothing is guessed.
pub fn parse_driver_table(text: &str) -> Result<Vec<DriverRow>, DismParseError> {
    if text.len() > MAX_INPUT_BYTES {
        return Err(DismParseError::TooLarge);
    }
    let mut rows = Vec::new();
    let mut block: Vec<(usize, &str)> = Vec::new();
    let mut last = 0;
    for (i, line) in text.lines().enumerate() {
        let n = i.saturating_add(1);
        last = n;
        if line.trim().is_empty() {
            finish(&mut block, n, &mut rows)?;
        } else {
            block.push((n, line));
        }
    }
    finish(&mut block, last, &mut rows)?;
    Ok(rows)
}

fn label_index(label: &str) -> Option<usize> {
    LABELS.iter().position(|l| *l == label)
}

fn finish(
    block: &mut Vec<(usize, &str)>,
    end: usize,
    rows: &mut Vec<DriverRow>,
) -> Result<(), DismParseError> {
    let lines = std::mem::take(block);
    let is_driver = lines.iter().any(|(_, l)| {
        l.split_once(':')
            .is_some_and(|(k, _)| label_index(k.trim()).is_some())
    });
    if !is_driver {
        return Ok(());
    }
    let mut fields: [Option<(usize, String)>; 7] = Default::default();
    for (n, line) in lines {
        let (k, v) = line
            .split_once(':')
            .ok_or(DismParseError::BadLine { line: n })?;
        let (k, v) = (k.trim(), v.trim());
        if k.is_empty() {
            return Err(DismParseError::BadLine { line: n });
        }
        if v.len() > MAX_VALUE_BYTES {
            return Err(DismParseError::ValueTooLong { line: n });
        }
        let Some(idx) = label_index(k) else { continue };
        let (Some(slot), Some(label)) = (fields.get_mut(idx), LABELS.get(idx)) else {
            continue;
        };
        if slot.is_some() {
            return Err(DismParseError::DuplicateField { label, line: n });
        }
        *slot = Some((n, v.to_owned()));
    }
    let mut take = |label: &'static str| -> Result<(usize, String), DismParseError> {
        label_index(label)
            .and_then(|i| fields.get_mut(i))
            .and_then(Option::take)
            .ok_or(DismParseError::MissingField { label, line: end })
    };
    let nonempty = |label: &'static str, (n, v): (usize, String)| {
        if v.is_empty() {
            Err(DismParseError::InvalidField { label, line: n })
        } else {
            Ok(v)
        }
    };
    let published_name = nonempty(PUBLISHED, take(PUBLISHED)?)?;
    let original_file_name = nonempty(ORIGINAL, take(ORIGINAL)?)?;
    let (n, inbox) = take(INBOX)?;
    let inbox = match inbox.as_str() {
        "Yes" => true,
        "No" => false,
        _ => {
            return Err(DismParseError::InvalidField {
                label: INBOX,
                line: n,
            });
        }
    };
    let class_name = take(CLASS)?.1;
    let provider_name = take(PROVIDER)?.1;
    let date = take(DATE)?.1;
    let version = nonempty(VERSION, take(VERSION)?)?;
    if rows.len() >= MAX_ROWS {
        return Err(DismParseError::TooManyRows);
    }
    rows.push(DriverRow {
        published_name,
        original_file_name,
        inbox,
        class_name,
        provider_name,
        date,
        version,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    // Synthetic input written for these tests.
    const ONE: &str = "Published Name : oem1.inf\nOriginal File Name : net.inf\nInbox : No\nClass Name : Net\nProvider Name : Example Corp\nDate : 1/2/2026\nVersion : 1.2.3.4\n";

    #[test]
    fn parses_blocks_and_skips_banner() {
        let text = format!(
            "Tool banner\nVersion of tool: 9\n\n{ONE}\n\n{}\nDone.\n",
            ONE.replace("oem1", "oem2").replace("No", "Yes")
        );
        let rows = parse_driver_table(&text).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].published_name, "oem1.inf");
        assert!(!rows[0].inbox);
        assert!(rows[1].inbox);
        assert_eq!(rows[0].date, "1/2/2026");
        assert!(parse_driver_table("").unwrap().is_empty());
    }

    #[test]
    fn tolerates_extra_fields_and_spacing() {
        let text = ONE.replace(" : ", "   :   ") + "Extra Thing : x\nTime : 12:30\n";
        assert_eq!(parse_driver_table(&text).unwrap().len(), 1);
    }

    #[test]
    fn fails_closed() {
        let missing = ONE.replace("Version : 1.2.3.4\n", "");
        assert!(matches!(
            parse_driver_table(&missing),
            Err(DismParseError::MissingField {
                label: "Version",
                ..
            })
        ));
        let dup = format!("{ONE}Inbox : No\n");
        assert!(matches!(
            parse_driver_table(&dup),
            Err(DismParseError::DuplicateField { .. })
        ));
        let badline = format!("{ONE}garbage\n");
        assert_eq!(
            parse_driver_table(&badline),
            Err(DismParseError::BadLine { line: 8 })
        );
        let inbox = ONE.replace("Inbox : No", "Inbox : Ja");
        assert!(matches!(
            parse_driver_table(&inbox),
            Err(DismParseError::InvalidField { .. })
        ));
        let empty = ONE.replace("oem1.inf", "");
        assert!(matches!(
            parse_driver_table(&empty),
            Err(DismParseError::InvalidField { .. })
        ));
        let long = ONE.replace("Net\n", &format!("{}\n", "x".repeat(MAX_VALUE_BYTES + 1)));
        assert!(matches!(
            parse_driver_table(&long),
            Err(DismParseError::ValueTooLong { .. })
        ));
        let big = "x".repeat(MAX_INPUT_BYTES + 1);
        assert_eq!(parse_driver_table(&big), Err(DismParseError::TooLarge));
        let many = format!("{ONE}\n").repeat(MAX_ROWS + 1);
        assert_eq!(parse_driver_table(&many), Err(DismParseError::TooManyRows));
    }
}
