//! WIM file structures and the upload check (`specs/standards/wim.md`).
//!
//! Format facts come only from Microsoft's public WIM paper as summarised
//! in `wim.md` and from our own DISM-made samples recorded in
//! `docs/formats/wim-observed.md` (decision 0006). Each constant or rule
//! that rests on them carries a `// FORMAT:` citation; one that rests on
//! neither is marked `// FORMAT: derived, unconfirmed`.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation)
// - SPEC: specs/os-images.md#REQ-IMG-037, #REQ-IMG-038
// - DECISION: docs/decisions/0006-wim-format-by-black-box-test-files.md

pub mod check;
pub mod header;
pub mod integrity;
pub mod lookup;
pub mod reshdr;
pub(crate) mod resource;
pub(crate) mod source;
pub mod xml;

pub use check::{EditionInfo, WimSummary, check_pe, check_wim};
pub use header::Compression;
pub use source::{NoProgress, Progress};
pub use xml::{WimXmlImage, XmlLeaf};
