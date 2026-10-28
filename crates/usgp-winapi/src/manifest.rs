//! Canonical tree manifest of a directory tree (plan M-20, §10.2): the
//! fidelity oracle that compares our apply with DISM's on two volumes.
//! Used by `examples/tree_manifest.rs`; the content hash is supplied by
//! the caller, so all hashing stays in `usgp-crypto`.
//!
//! Reads only. Reparse points are listed but never followed; directories
//! are entered only when they are not reparse points.

// COMPLIANCE MAPPING:
// - NIST 800-53: SA-11 (Developer Testing and Evaluation)
// - SPEC: specs/preinstall-env.md REQ-PE-017 (apply fidelity)
// - DECISION: docs/decisions/0019-windows-api-binding.md

use std::fs::Metadata;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
};

use crate::error::{Result, WinApiError};
use crate::fsquery;
use crate::manifest_text::{Field, Kind, Row, sort_rows};

/// Bounds and choices for one manifest.
#[derive(Debug, Clone)]
pub struct ManifestOptions {
    /// Top-level names that are listed but not entered (for example
    /// `System Volume Information` at a volume root), as the PowerShell
    /// manifest's `NoDescend` list does.
    pub no_descend: Vec<String>,
    /// Skip `sha256` and `streams` (no file content is read).
    pub no_content: bool,
    /// Most items listed.
    pub max_entries: usize,
    /// Deepest directory level entered.
    pub max_depth: usize,
}

impl Default for ManifestOptions {
    fn default() -> Self {
        Self {
            no_descend: Vec::new(),
            no_content: false,
            max_entries: 1_000_000,
            max_depth: 256,
        }
    }
}

/// Computes the lowercase hex SHA-256 of the file or stream at a path.
pub type ContentHash<'a> = &'a dyn Fn(&Path) -> std::io::Result<String>;

fn field<T>(r: Result<T>, f: impl FnOnce(T) -> String) -> Field {
    match r {
        Ok(v) => Field::Value(f(v)),
        Err(e) => Field::Error(e.to_string()),
    }
}

fn row_for(
    rel: &str,
    full: &Path,
    md: &Metadata,
    opts: &ManifestOptions,
    hash: ContentHash<'_>,
) -> Row {
    let attrs = md.file_attributes();
    let is_reparse = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;
    let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
    let kind = if is_reparse {
        match fsquery::attributes_and_tag(full) {
            Ok((_, tag)) => Kind::Reparse(tag),
            // The tag is unknown; zero is never a valid tag, so the row
            // shows the failure instead of hiding the item.
            Err(_) => Kind::Reparse(0),
        }
    } else if is_dir {
        Kind::Dir
    } else {
        Kind::File
    };

    let read_content = !opts.no_content && !is_reparse;
    let sha256 = if read_content && !is_dir {
        match hash(full) {
            Ok(h) => Field::Value(h),
            Err(e) => Field::Error(e.to_string()),
        }
    } else {
        Field::None
    };
    let streams = if read_content {
        field(fsquery::named_streams(full), |list| {
            list.iter()
                .map(|s| {
                    let h = hash(&fsquery::stream_path(full, &s.name))
                        .unwrap_or_else(|e| format!("error {e}"));
                    format!("{}:{}:{h}", s.name, s.size)
                })
                .collect::<Vec<_>>()
                .join(";")
        })
    } else {
        Field::None
    };
    let sddl = if is_reparse {
        Field::None
    } else {
        field(fsquery::sddl(full), |s| s)
    };
    let hard_links = if !is_dir && !is_reparse {
        match fsquery::link_names(full) {
            Ok(names) if names.len() > 1 => {
                let mut names = names;
                names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
                Field::Value(names.join("|"))
            }
            Ok(_) => Field::None,
            Err(e) => Field::Error(e.to_string()),
        }
    } else {
        Field::None
    };

    Row {
        path: rel.to_owned(),
        kind,
        attributes: attrs,
        creation: md.creation_time(),
        last_access: md.last_access_time(),
        last_write: md.last_write_time(),
        length: (!is_dir).then(|| md.file_size()),
        sha256,
        streams,
        sddl,
        // Not read: the target's form is not summarised (WU-5 notes).
        link_target: Field::None,
        hard_links,
    }
}

/// Builds the manifest rows of the tree at `root`, sorted.
///
/// A directory that cannot be listed, a name that is not valid UTF-16, or
/// exceeding the bounds fails the whole manifest (an incomplete oracle is
/// worse than none); a single value that cannot be read is an
/// `error: ...` field.
pub fn tree_rows(root: &Path, opts: &ManifestOptions, hash: ContentHash<'_>) -> Result<Vec<Row>> {
    let root = fsquery::verbatim(root)?;
    let md = std::fs::symlink_metadata(&root).map_err(|e| WinApiError::os("read root", e))?;
    let mut rows = vec![row_for(".", &root, &md, opts, hash)];
    let mut stack: Vec<(PathBuf, String, usize)> = Vec::new();
    if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 && md.is_dir() {
        stack.push((root.clone(), String::new(), 0));
    }
    while let Some((dir, rel, depth)) = stack.pop() {
        if depth >= opts.max_depth {
            return Err(WinApiError::LimitExceeded {
                what: "tree depth",
                limit: u64::try_from(opts.max_depth).unwrap_or(u64::MAX),
            });
        }
        let entries = std::fs::read_dir(&dir).map_err(|e| WinApiError::os("list directory", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| WinApiError::os("list directory", e))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| WinApiError::Malformed {
                    op: "file name",
                    source: crate::parse::ParseError::InvalidUtf16,
                })?;
            let child_rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}\\{name}")
            };
            let full = entry.path();
            let md = std::fs::symlink_metadata(&full)
                .map_err(|e| WinApiError::os("read metadata", e))?;
            if rows.len() >= opts.max_entries {
                return Err(WinApiError::LimitExceeded {
                    what: "manifest entries",
                    limit: u64::try_from(opts.max_entries).unwrap_or(u64::MAX),
                });
            }
            rows.push(row_for(&child_rel, &full, &md, opts, hash));
            let attrs = md.file_attributes();
            let skip = depth == 0 && opts.no_descend.contains(&child_rel);
            if !skip
                && attrs & FILE_ATTRIBUTE_DIRECTORY != 0
                && attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0
            {
                stack.push((full, child_rel, depth + 1));
            }
        }
    }
    sort_rows(&mut rows);
    Ok(rows)
}
