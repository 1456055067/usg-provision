//! Bounded `[Version]` scan of `.inf` files (plan §1.5 "INF list").
//!
//! An INF counts as a driver package only if its `[Version]` section has a
//! `Signature` of `$Windows NT$` or `$Chicago$` (case-insensitive) and at
//! least one `CatalogFile` key (plain or decorated). The caller then checks
//! that every named catalog is present in the INF's folder.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-7 (Least Functionality)
// - SPEC: specs/drivers.md#REQ-DRV-006

/// Most lines read inside `[Version]` before giving up on the file.
const MAX_VERSION_LINES: usize = 4096;

/// What a package INF declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InfPackage {
    /// Catalog file names from every `CatalogFile*` key, as written.
    pub(crate) catalogs: Vec<String>,
}

/// Decodes INF text: UTF-16LE with a BOM, or UTF-8 (with or without a BOM,
/// so ASCII too). Returns `None` for anything else.
fn decode(bytes: &[u8]) -> Option<String> {
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        if rest.len() % 2 != 0 {
            return None;
        }
        let units = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c));
        return char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .ok();
    }
    let rest = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    std::str::from_utf8(rest).ok().map(str::to_owned)
}

/// Removes a `;` comment that is not inside double quotes.
fn strip_comment(line: &str) -> &str {
    let mut quoted = false;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => return line.get(..i).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    v.strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(v)
        .trim()
}

/// Scans one INF. `None` means "not a driver package" (not an error).
pub(crate) fn scan(bytes: &[u8]) -> Option<InfPackage> {
    let text = decode(bytes)?;
    let mut in_version = false;
    let mut seen_version = false;
    let mut lines_in_section = 0usize;
    let mut signature_ok = false;
    let mut catalogs = Vec::new();
    for raw in text.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let name = rest.strip_suffix(']').map(str::trim);
            let is_version = name.is_some_and(|n| n.eq_ignore_ascii_case("version"));
            if in_version && !is_version {
                break;
            }
            if is_version && seen_version && !in_version {
                // A second [Version] section: ambiguous, not a package.
                return None;
            }
            in_version = is_version;
            seen_version |= is_version;
            continue;
        }
        if !in_version {
            continue;
        }
        lines_in_section += 1;
        if lines_in_section > MAX_VERSION_LINES {
            return None;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = unquote(value);
        if key.eq_ignore_ascii_case("signature") {
            signature_ok = value.eq_ignore_ascii_case("$windows nt$")
                || value.eq_ignore_ascii_case("$chicago$");
        } else if key
            .get(..11)
            .is_some_and(|k| k.eq_ignore_ascii_case("catalogfile"))
            && (key.len() == 11 || key.get(11..12) == Some("."))
        {
            catalogs.push(value.to_owned());
        }
    }
    (signature_ok && !catalogs.is_empty()).then_some(InfPackage { catalogs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_ascii_and_utf16() {
        let t = "; comment\r\n[Version]\r\nSignature = \"$Windows NT$\" ; x\r\nClass=Net\r\nCatalogFile.NTamd64 = net.cat\r\n[Manufacturer]\r\nCatalogFile=ignored.cat\r\n";
        let p = scan(t.as_bytes()).unwrap();
        assert_eq!(p.catalogs, vec!["net.cat".to_owned()]);
        let mut u = vec![0xFF, 0xFE];
        for c in t.encode_utf16() {
            u.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(scan(&u).unwrap(), p);
    }

    #[test]
    fn not_packages() {
        assert!(scan(b"[Version]\nSignature=$Windows NT$\n").is_none());
        assert!(scan(b"[Version]\nSignature=$Other$\nCatalogFile=a.cat\n").is_none());
        assert!(scan(b"[Strings]\nSignature=$Windows NT$\nCatalogFile=a.cat\n").is_none());
        assert!(scan(b"[Version]\nSignature=$Chicago$\nCatalogFileX=a.cat\n").is_none());
        assert!(scan(&[0xFF, 0xFE, 0x00]).is_none());
        assert!(scan(&[0xC3, 0x28]).is_none());
        assert!(scan(b"").is_none());
    }
}
