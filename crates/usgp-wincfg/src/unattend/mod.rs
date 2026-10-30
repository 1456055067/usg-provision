//! Answer-file templates (plan section 1.6, `unattend.md`).
//!
//! A template is an answer file whose text nodes and attribute values may
//! hold `{{name}}` references. It is parsed with a strict, bounded XML
//! reader ([`Template::parse`]), checked against the package values
//! ([`Template::lint`]) and rendered with every reference replaced by its
//! XML-escaped value ([`Template::render`]). No setting that can carry a
//! password, credential or product key is accepted (decisions 0024 and
//! 0025), so the answer file never holds a secret.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation), CM-6
//   (Configuration Settings), IA-5(7) (No Embedded Unencrypted Static
//   Authenticators)
// - SPEC: specs/configuration.md#REQ-CFG-001, #REQ-CFG-002,
//   #REQ-CFG-003, #REQ-CFG-004, #REQ-CFG-005, #REQ-CFG-006,
//   #REQ-CFG-007, #REQ-CFG-009, #REQ-CFG-010
// - SPEC: specs/standards/unattend.md §3.1, §3.2, §4
// - W3C XML 1.0 (Fifth Edition) §2.8, §4.1, §4.6 - no DTD, predefined
//   entities and character references only

mod lint;
mod parse;
mod render;
pub mod values;

use thiserror::Error;

pub use lint::{ComputerNameSource, LintFinding, PackageValues};
pub use render::{MapResolver, Rendered, Resolver};
pub use values::ValueError;

/// The answer-file namespace the root element must be in (`unattend.md`).
pub const UNATTEND_NS: &str = "urn:schemas-microsoft-com:unattend";

/// Parse limits (plan section 1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest input (and rendered output), in bytes.
    pub max_bytes: usize,
    /// Deepest element nesting.
    pub max_depth: usize,
    /// Most elements.
    pub max_elements: usize,
    /// Longest attribute value, in bytes as written.
    pub max_attr_value_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: 1024 * 1024,
            max_depth: 64,
            max_elements: 50_000,
            max_attr_value_bytes: 64 * 1024,
        }
    }
}

/// Why a template was refused. Carries no input text.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TemplateError {
    /// Larger than [`Limits::max_bytes`].
    #[error("answer file is too large")]
    TooLarge,
    /// The bytes are not UTF-8 (a UTF-16 byte-order mark included).
    #[error("answer file is not UTF-8")]
    NotUtf8,
    /// The XML declaration names an encoding other than UTF-8.
    #[error("answer file declares an encoding other than UTF-8")]
    EncodingNotUtf8,
    /// A DOCTYPE (and so a DTD) is present.
    #[error("DOCTYPE and DTD are not allowed")]
    DoctypeRefused,
    /// An entity other than the five predefined ones.
    #[error("entity references other than the predefined ones are not allowed")]
    EntityRefused,
    /// A processing instruction other than the XML declaration.
    #[error("processing instructions are not allowed")]
    ProcessingInstructionRefused,
    /// Not well-formed XML.
    #[error("answer file is not well-formed: {reason}")]
    NotWellFormed {
        /// Fixed reason text.
        reason: &'static str,
    },
    /// Nesting deeper than [`Limits::max_depth`].
    #[error("answer file nesting is too deep")]
    TooDeep,
    /// More elements than [`Limits::max_elements`].
    #[error("answer file has too many elements")]
    TooManyElements,
    /// An attribute value longer than [`Limits::max_attr_value_bytes`].
    #[error("attribute value is too long")]
    AttributeTooLong,
    /// The root is not `unattend` in [`UNATTEND_NS`].
    #[error("root element is not unattend in the answer-file namespace")]
    WrongRoot,
    /// A `{{` that does not start a valid `{{name}}` reference.
    #[error("malformed value reference")]
    BadReference,
}

/// Why a render failed. Carries reference names, never values.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RenderError {
    /// No value for a reference (REQ-CFG-004).
    #[error("unresolved value: {name}")]
    Unresolved {
        /// The reference name.
        name: String,
    },
    /// A value failed its check (REQ-CFG-005/006/007).
    #[error("invalid value for {name}: {source}")]
    InvalidValue {
        /// The reference name.
        name: String,
        /// The failed check.
        source: ValueError,
    },
    /// The rendered output is larger than [`Limits::max_bytes`].
    #[error("rendered answer file is too large")]
    TooLarge,
    /// The rendered output did not parse again.
    #[error("rendered answer file failed its self-check: {0}")]
    SelfCheck(TemplateError),
}

/// One piece of a text node or attribute value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Segment {
    /// Literal text (entities resolved, `{{{{` unescaped).
    Literal(String),
    /// A `{{name}}` reference.
    Ref(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attr {
    pub(crate) name: String,
    pub(crate) value: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Element(Element),
    Text(Vec<Segment>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Element {
    /// Qualified name as written.
    pub(crate) name: String,
    /// Local name (after any prefix).
    pub(crate) local: String,
    pub(crate) attrs: Vec<Attr>,
    pub(crate) children: Vec<Node>,
}

impl Element {
    /// The literal value of attribute `local`, if present and reference-free.
    pub(crate) fn literal_attr(&self, name: &str) -> Option<String> {
        let a = self.attrs.iter().find(|a| a.name == name)?;
        let mut out = String::new();
        for s in &a.value {
            match s {
                Segment::Literal(t) => out.push_str(t),
                Segment::Ref(_) => return None,
            }
        }
        Some(out)
    }
}

/// A parsed, well-formed answer-file template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub(crate) root: Element,
    pub(crate) limits: Limits,
}

impl Template {
    /// Parses and checks a template (on upload and at render).
    ///
    /// # Errors
    ///
    /// A [`TemplateError`] naming the first problem found.
    pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Self, TemplateError> {
        let root = parse::parse(bytes, limits, true)?;
        Ok(Self {
            root,
            limits: *limits,
        })
    }

    /// Every distinct reference name, sorted.
    #[must_use]
    pub fn references(&self) -> Vec<String> {
        let mut set = std::collections::BTreeSet::new();
        collect_refs(&self.root, &mut set);
        set.into_iter().collect()
    }
}

pub(crate) fn collect_refs(e: &Element, out: &mut std::collections::BTreeSet<String>) {
    for a in &e.attrs {
        push_refs(&a.value, out);
    }
    for c in &e.children {
        match c {
            Node::Element(child) => collect_refs(child, out),
            Node::Text(segs) => push_refs(segs, out),
        }
    }
}

fn push_refs(segs: &[Segment], out: &mut std::collections::BTreeSet<String>) {
    for s in segs {
        if let Segment::Ref(n) = s {
            out.insert(n.clone());
        }
    }
}

#[cfg(test)]
mod tests;
