//! Template render (plan section 1.6, "Render").

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - values checked and
//   XML-escaped for their context; output parsed again (self-check);
//   CM-6 (Configuration Settings)
// - SPEC: specs/configuration.md#REQ-CFG-003, #REQ-CFG-004 (unresolved
//   reference stops the install), #REQ-CFG-005, #REQ-CFG-006 (quoted OU
//   carried unchanged), #REQ-CFG-007
// - W3C XML 1.0 (Fifth Edition) §2.4, §3.3.3 - escaping in text and
//   attribute values

use std::collections::BTreeMap;

use super::values::check_for;
use super::{Element, Node, RenderError, Segment, Template, parse};

/// Supplies a value for each reference name. Values are not secrets.
pub trait Resolver {
    /// The value for `name`, or `None` if unresolved.
    fn value(&self, name: &str) -> Option<String>;
}

/// A [`Resolver`] over a map of names to values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapResolver(pub BTreeMap<String, String>);

impl Resolver for MapResolver {
    fn value(&self, name: &str) -> Option<String> {
        self.0.get(name).cloned()
    }
}

/// A rendered answer file (UTF-8, with an XML declaration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    /// The file bytes.
    pub bytes: Vec<u8>,
}

impl Template {
    /// Replaces every reference with its checked, escaped value and parses
    /// the result again.
    ///
    /// # Errors
    ///
    /// [`RenderError::Unresolved`] for the first reference (in name order)
    /// with no value, [`RenderError::InvalidValue`], [`RenderError::TooLarge`]
    /// or [`RenderError::SelfCheck`].
    pub fn render(&self, resolver: &dyn Resolver) -> Result<Rendered, RenderError> {
        let mut values = BTreeMap::new();
        for name in self.references() {
            let v = resolver
                .value(&name)
                .ok_or_else(|| RenderError::Unresolved { name: name.clone() })?;
            check_for(&name, &v).map_err(|source| RenderError::InvalidValue {
                name: name.clone(),
                source,
            })?;
            values.insert(name, v);
        }
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        write_element(&self.root, &values, &mut out);
        if out.len() > self.limits.max_bytes {
            return Err(RenderError::TooLarge);
        }
        parse::parse(out.as_bytes(), &self.limits, false).map_err(RenderError::SelfCheck)?;
        Ok(Rendered {
            bytes: out.into_bytes(),
        })
    }
}

fn write_element(e: &Element, values: &BTreeMap<String, String>, out: &mut String) {
    out.push('<');
    out.push_str(&e.name);
    for a in &e.attrs {
        out.push(' ');
        out.push_str(&a.name);
        out.push_str("=\"");
        write_segments(&a.value, values, true, out);
        out.push('"');
    }
    if e.children.is_empty() {
        out.push_str("/>");
        return;
    }
    out.push('>');
    for c in &e.children {
        match c {
            Node::Element(child) => write_element(child, values, out),
            Node::Text(segs) => write_segments(segs, values, false, out),
        }
    }
    out.push_str("</");
    out.push_str(&e.name);
    out.push('>');
}

fn write_segments(
    segs: &[Segment],
    values: &BTreeMap<String, String>,
    attr: bool,
    out: &mut String,
) {
    for s in segs {
        let text = match s {
            Segment::Literal(t) => t.as_str(),
            // Every reference was resolved before writing began.
            Segment::Ref(n) => values.get(n).map_or("", String::as_str),
        };
        escape(text, attr, out);
    }
}

/// Escapes `& < > " '`; in attributes also tab, line feed and carriage
/// return, so attribute-value normalisation keeps them (XML 1.0 §3.3.3).
/// A carriage return in text is kept the same way (§2.11).
fn escape(s: &str, attr: bool, out: &mut String) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#xD;"),
            '\t' if attr => out.push_str("&#x9;"),
            '\n' if attr => out.push_str("&#xA;"),
            _ => out.push(c),
        }
    }
}
