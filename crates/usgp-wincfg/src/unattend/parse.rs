//! Strict, bounded answer-file reader (plan section 1.6, "Parse").

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - size, depth,
//   element and attribute limits; no DOCTYPE, DTD or entity declarations
//   (no external entities, no entity expansion); UTF-8 only
// - SPEC: specs/configuration.md#REQ-CFG-002
// - W3C XML 1.0 (Fifth Edition) §2.2 (characters), §4.1, §4.6

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use super::{Attr, Element, Limits, Node, Segment, TemplateError, UNATTEND_NS};

const UTF8_BOM: &[u8] = &[0xef, 0xbb, 0xbf];
const MAX_NAME_LEN: usize = 64;

fn bad(reason: &'static str) -> TemplateError {
    TemplateError::NotWellFormed { reason }
}

/// One open element and the text gathered since its last child.
struct Frame {
    el: Element,
    pending: String,
}

impl Frame {
    fn flush(&mut self, refs: bool) -> Result<(), TemplateError> {
        if !self.pending.is_empty() {
            let text = std::mem::take(&mut self.pending);
            self.el.children.push(Node::Text(segments(&text, refs)?));
        }
        Ok(())
    }
}

/// Parses `bytes`. With `refs` false (the render self-check) `{{` is
/// plain text.
pub(crate) fn parse(bytes: &[u8], limits: &Limits, refs: bool) -> Result<Element, TemplateError> {
    if bytes.len() > limits.max_bytes {
        return Err(TemplateError::TooLarge);
    }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        return Err(TemplateError::NotUtf8);
    }
    let body = bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes);
    let text = std::str::from_utf8(body).map_err(|_| TemplateError::NotUtf8)?;

    let mut reader = Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = true;
    cfg.expand_empty_elements = true;
    cfg.allow_unmatched_ends = false;
    cfg.allow_dangling_amp = false;
    cfg.trim_text(false);

    let mut stack: Vec<Frame> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0usize;
    let mut seen_event = false;

    loop {
        let event = reader.read_event().map_err(|_| bad("syntax error"))?;
        let first = !seen_event;
        seen_event = true;
        match event {
            Event::Decl(d) => {
                if !first {
                    return Err(bad("misplaced XML declaration"));
                }
                if let Some(enc) = d.encoding() {
                    let enc = enc.map_err(|_| bad("bad encoding attribute"))?;
                    if !enc.eq_ignore_ascii_case("utf-8") {
                        return Err(TemplateError::EncodingNotUtf8);
                    }
                }
            }
            Event::DocType(_) => return Err(TemplateError::DoctypeRefused),
            Event::PI(_) => return Err(TemplateError::ProcessingInstructionRefused),
            Event::Comment(_) => {}
            Event::Start(e) => {
                if root.is_some() {
                    return Err(bad("content after the root element"));
                }
                if stack.len() >= limits.max_depth {
                    return Err(TemplateError::TooDeep);
                }
                elements = elements.saturating_add(1);
                if elements > limits.max_elements {
                    return Err(TemplateError::TooManyElements);
                }
                let el = element(&e, limits, refs)?;
                if let Some(parent) = stack.last_mut() {
                    parent.flush(refs)?;
                }
                stack.push(Frame {
                    el,
                    pending: String::new(),
                });
            }
            Event::End(_) => {
                let mut frame = stack.pop().ok_or(bad("unmatched end tag"))?;
                frame.flush(refs)?;
                match stack.last_mut() {
                    Some(parent) => parent.el.children.push(Node::Element(frame.el)),
                    None => root = Some(frame.el),
                }
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                add_text(&mut stack, &s)?;
            }
            Event::CData(t) => {
                let s = t.into_inner();
                add_text(&mut stack, &s)?;
            }
            Event::GeneralRef(r) => {
                let resolved: String = match r.resolve_char_ref() {
                    Ok(Some(c)) => c.to_string(),
                    Ok(None) => quick_xml::escape::resolve_predefined_entity(&r)
                        .ok_or(TemplateError::EntityRefused)?
                        .to_owned(),
                    Err(_) => return Err(bad("invalid character reference")),
                };
                if stack.is_empty() {
                    return Err(bad("text outside the root element"));
                }
                add_text(&mut stack, &resolved)?;
            }
            Event::Empty(_) => return Err(bad("unexpected empty element")),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(bad("unexpected end of input"));
    }
    let root = root.ok_or(bad("no root element"))?;
    check_root(&root)?;
    Ok(root)
}

fn add_text(stack: &mut [Frame], s: &str) -> Result<(), TemplateError> {
    if s.chars().any(|c| !is_xml_char(c)) {
        return Err(bad("character not allowed in XML"));
    }
    match stack.last_mut() {
        Some(f) => {
            f.pending.push_str(s);
            Ok(())
        }
        None if s.chars().all(|c| matches!(c, ' ' | '\t' | '\r' | '\n')) => Ok(()),
        None => Err(bad("text outside the root element")),
    }
}

/// XML 1.0 §2.2 `Char`.
pub(crate) fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..)
}

fn element(e: &BytesStart<'_>, limits: &Limits, refs: bool) -> Result<Element, TemplateError> {
    let qname = e.name();
    let name: &str = qname.as_ref();
    if name.is_empty() {
        return Err(bad("empty element name"));
    }
    let local = name.rsplit_once(':').map_or(name, |(_, l)| l).to_owned();
    let mut attrs: Vec<Attr> = Vec::new();
    for attr in e.attributes() {
        let attr = attr.map_err(|_| bad("bad attribute"))?;
        if attr.value.len() > limits.max_attr_value_bytes {
            return Err(TemplateError::AttributeTooLong);
        }
        let key: &str = attr.key.as_ref();
        let key = key.to_owned();
        let v = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|_| TemplateError::EntityRefused)?;
        if v.chars().any(|c| !is_xml_char(c)) {
            return Err(bad("character not allowed in XML"));
        }
        attrs.push(Attr {
            name: key,
            value: segments(&v, refs)?,
        });
    }
    Ok(Element {
        name: name.to_owned(),
        local,
        attrs,
        children: Vec::new(),
    })
}

/// The root is `unattend` and its prefix (or the default) is bound to
/// [`UNATTEND_NS`] on the root itself.
fn check_root(root: &Element) -> Result<(), TemplateError> {
    if root.local != "unattend" {
        return Err(TemplateError::WrongRoot);
    }
    let decl = match root.name.rsplit_once(':') {
        Some((prefix, _)) => format!("xmlns:{prefix}"),
        None => "xmlns".to_owned(),
    };
    match root.literal_attr(&decl) {
        Some(ns) if ns == UNATTEND_NS => Ok(()),
        _ => Err(TemplateError::WrongRoot),
    }
}

/// Splits text into literals and `{{name}}` references.
fn segments(text: &str, refs: bool) -> Result<Vec<Segment>, TemplateError> {
    if !refs {
        return Ok(vec![Segment::Literal(text.to_owned())]);
    }
    let mut out = Vec::new();
    let mut lit = String::new();
    let mut rest = text;
    while let Some((pre, after)) = rest.split_once("{{") {
        lit.push_str(pre);
        if let Some(r) = after.strip_prefix("{{") {
            lit.push_str("{{");
            rest = r;
            continue;
        }
        let (name, r) = after.split_once("}}").ok_or(TemplateError::BadReference)?;
        if !valid_name(name) {
            return Err(TemplateError::BadReference);
        }
        if !lit.is_empty() {
            out.push(Segment::Literal(std::mem::take(&mut lit)));
        }
        out.push(Segment::Ref(name.to_owned()));
        rest = r;
    }
    lit.push_str(rest);
    if !lit.is_empty() {
        out.push(Segment::Literal(lit));
    }
    Ok(out)
}

/// `[a-z][a-z0-9_.]{0,63}` (plan section 1.6).
pub(crate) fn valid_name(name: &str) -> bool {
    let mut b = name.bytes();
    matches!(b.next(), Some(b'a'..=b'z'))
        && name.len() <= MAX_NAME_LEN
        && b.all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
}
