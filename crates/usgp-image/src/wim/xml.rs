//! The XML data resource (`wim.md` §7): image index, name, description and
//! size, plus each image's other elements kept raw for
//! [`crate::facts`]-style cross-checks. Nothing beyond the documented
//! elements is interpreted.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-10 (Information Input Validation) - bounded size,
//   depth, element count and text length; no DOCTYPE, no processing
//   instructions, no entities other than the five predefined ones and
//   character references (no entity expansion attacks).
// - SPEC: specs/os-images.md#REQ-IMG-037 (index, name, description can be
//   read), #REQ-IMG-040 (index, name, description, size as recorded),
//   #REQ-IMG-043 (raw elements kept for documented cross-checks)
// - SPEC: specs/standards/wim.md §7

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

use crate::error::WimError;
use crate::limits::WimLimits;

/// The byte-order mark at the start of the XML data.
// FORMAT: OBS-014 - every R1 XML resource starts with ff fe and is
// UTF-16LE with no declaration and no trailing zero unit (wim.md §7
// [reading] UTF-16 confirmed).
pub const BOM: [u8; 2] = [0xff, 0xfe];

/// Root element (`wim.md` §7).
const EL_WIM: &str = "WIM";
/// Per-image element (`wim.md` §7).
const EL_IMAGE: &str = "IMAGE";
/// Image index attribute (`wim.md` §7).
const ATTR_INDEX: &str = "INDEX";
/// Name element (`wim.md` §7; OBS-014: written as given).
const EL_NAME: &str = "NAME";
/// Description element (`wim.md` §7; OBS-014: written as given).
const EL_DESCRIPTION: &str = "DESCRIPTION";
/// Size element (`wim.md` §7).
const EL_TOTALBYTES: &str = "TOTALBYTES";

/// One element of an `IMAGE` that has no child elements, as found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlLeaf {
    /// Element names below `IMAGE`, joined by `/` (for example
    /// `CREATIONTIME/HIGHPART`).
    pub path: String,
    /// Text content (entities resolved, line ends normalised).
    pub text: String,
}

/// One `IMAGE` element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimXmlImage {
    /// `INDEX` attribute (1-based).
    pub index: u32,
    /// `NAME` text.
    pub name: String,
    /// `DESCRIPTION` text; empty if the element is absent.
    pub description: String,
    /// `TOTALBYTES` of the image, if present.
    pub total_bytes: Option<u64>,
    /// Every leaf element of the image in document order, including
    /// `NAME`, `DESCRIPTION` and `TOTALBYTES`.
    pub elements: Vec<XmlLeaf>,
}

impl WimXmlImage {
    /// Text of the first leaf at `path`, if any.
    #[must_use]
    pub fn leaf(&self, path: &str) -> Option<&str> {
        self.elements
            .iter()
            .find(|l| l.path == path)
            .map(|l| l.text.as_str())
    }
}

/// The parsed XML data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WimXml {
    /// Top-level `TOTALBYTES`, if present.
    pub total_bytes: Option<u64>,
    /// `IMAGE` elements sorted by index.
    pub images: Vec<WimXmlImage>,
}

fn invalid(reason: &'static str) -> WimError {
    WimError::XmlInvalid { reason }
}

/// Decodes the UTF-16LE XML resource (with BOM) to a `String`.
///
/// # Errors
///
/// [`WimError::XmlTooLarge`] over the limit; [`WimError::XmlInvalid`] for
/// a missing BOM, odd length, unpaired surrogates or NUL characters.
pub fn decode_utf16(bytes: &[u8], limits: &WimLimits) -> Result<String, WimError> {
    let len = u64::try_from(bytes.len()).map_err(|_| WimError::XmlTooLarge)?;
    if len > limits.max_xml_bytes {
        return Err(WimError::XmlTooLarge);
    }
    let body = bytes
        .strip_prefix(&BOM)
        .ok_or(invalid("missing byte-order mark"))?;
    let (units, rest) = body.as_chunks::<2>();
    if !rest.is_empty() {
        return Err(invalid("odd length"));
    }
    let mut out = String::with_capacity(units.len());
    for c in char::decode_utf16(units.iter().map(|u| u16::from_le_bytes(*u))) {
        let c = c.map_err(|_| invalid("invalid UTF-16"))?;
        if c == '\0' {
            return Err(invalid("NUL character"));
        }
        out.push(c);
    }
    Ok(out)
}

/// Parses the XML data resource bytes (UTF-16LE with BOM).
///
/// Checks: root `WIM`; each `IMAGE` child of `WIM` has a decimal `INDEX`
/// of at least 1 and one `NAME`; no index repeats; text lengths, depth and
/// element counts within `limits`. The caller checks the indexes against
/// the header's image count.
///
/// # Errors
///
/// [`WimError::XmlInvalid`], [`WimError::XmlTooLarge`],
/// [`WimError::DuplicateIndex`] or [`WimError::LimitExceeded`].
pub fn parse_xml(bytes: &[u8], limits: &WimLimits) -> Result<WimXml, WimError> {
    let text = decode_utf16(bytes, limits)?;
    parse_xml_str(&text, limits)
}

/// One open element.
struct Frame {
    name: String,
    text: String,
    text_chars: usize,
    has_children: bool,
}

/// The image being read.
struct ImageAcc {
    index: u32,
    name: Option<String>,
    description: Option<String>,
    total_bytes: Option<u64>,
    elements: Vec<XmlLeaf>,
}

/// Parses already-decoded XML text; see [`parse_xml`].
///
/// # Errors
///
/// As [`parse_xml`].
pub fn parse_xml_str(text: &str, limits: &WimLimits) -> Result<WimXml, WimError> {
    let mut reader = Reader::from_str(text);
    let cfg = reader.config_mut();
    cfg.check_end_names = true;
    cfg.expand_empty_elements = true;
    cfg.allow_unmatched_ends = false;
    cfg.allow_dangling_amp = false;
    cfg.trim_text(false);

    let mut stack: Vec<Frame> = Vec::new();
    let mut seen_root = false;
    let mut root_total: Option<u64> = None;
    let mut image: Option<ImageAcc> = None;
    let mut images: Vec<WimXmlImage> = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|_| invalid("not well-formed"))?;
        match event {
            Event::Start(e) => {
                if stack.is_empty() && seen_root {
                    return Err(invalid("content after the root element"));
                }
                if stack.len() >= limits.max_xml_depth {
                    return Err(invalid("nesting too deep"));
                }
                let name = element_name(&e)?;
                if let Some(parent) = stack.last_mut() {
                    parent.has_children = true;
                    parent.text.clear();
                    parent.text_chars = 0;
                } else {
                    if name != EL_WIM {
                        return Err(invalid("root element is not WIM"));
                    }
                    seen_root = true;
                }
                if stack.len() == 1 && name == EL_IMAGE {
                    let count = u32::try_from(images.len()).unwrap_or(u32::MAX);
                    if count >= limits.max_images {
                        return Err(WimError::LimitExceeded { what: "images" });
                    }
                    image = Some(ImageAcc {
                        index: image_index(&e)?,
                        name: None,
                        description: None,
                        total_bytes: None,
                        elements: Vec::new(),
                    });
                }
                stack.push(Frame {
                    name,
                    text: String::new(),
                    text_chars: 0,
                    has_children: false,
                });
            }
            Event::End(_) => {
                let frame = stack.pop().ok_or(invalid("unmatched end tag"))?;
                end_element(
                    frame,
                    &stack,
                    limits,
                    &mut image,
                    &mut images,
                    &mut root_total,
                )?;
            }
            Event::Text(t) => {
                let s = t.xml10_content();
                add_text(&mut stack, &s, limits)?;
            }
            Event::CData(t) => {
                let s = t.into_inner();
                add_text(&mut stack, &s, limits)?;
            }
            Event::GeneralRef(r) => {
                let resolved: String = match r.resolve_char_ref() {
                    Ok(Some(c)) => {
                        if c == '\0' {
                            return Err(invalid("NUL character"));
                        }
                        c.to_string()
                    }
                    Ok(None) => quick_xml::escape::resolve_predefined_entity(&r)
                        .ok_or(invalid("undefined entity"))?
                        .to_owned(),
                    Err(_) => return Err(invalid("invalid character reference")),
                };
                if stack.is_empty() {
                    return Err(invalid("text outside the root element"));
                }
                add_text(&mut stack, &resolved, limits)?;
            }
            Event::Comment(_) => {}
            Event::Decl(_) => {
                if seen_root {
                    return Err(invalid("misplaced declaration"));
                }
            }
            Event::DocType(_) => return Err(invalid("DOCTYPE not allowed")),
            Event::PI(_) => return Err(invalid("processing instruction not allowed")),
            Event::Empty(_) => return Err(invalid("not well-formed")),
            Event::Eof => break,
        }
    }
    if !seen_root || !stack.is_empty() {
        return Err(invalid("unexpected end"));
    }
    images.sort_by_key(|i| i.index);
    for pair in images.windows(2) {
        if let [a, b] = pair
            && a.index == b.index
        {
            return Err(WimError::DuplicateIndex { index: a.index });
        }
    }
    Ok(WimXml {
        total_bytes: root_total,
        images,
    })
}

fn element_name(e: &BytesStart<'_>) -> Result<String, WimError> {
    let qname = e.name();
    let name: &str = qname.as_ref();
    if name.is_empty() {
        return Err(invalid("empty element name"));
    }
    Ok(name.to_owned())
}

fn image_index(e: &BytesStart<'_>) -> Result<u32, WimError> {
    let mut index = None;
    for attr in e.attributes() {
        let attr = attr.map_err(|_| invalid("bad attribute"))?;
        if AsRef::<str>::as_ref(&attr.key) == ATTR_INDEX {
            let v = attr
                .normalized_value(quick_xml::XmlVersion::Implicit1_0)
                .map_err(|_| invalid("bad INDEX"))?;
            index = Some(parse_index(&v)?);
        }
    }
    index.ok_or(invalid("IMAGE without INDEX"))
}

/// `INDEX`: ASCII decimal digits only, value 1 to `u32::MAX`.
fn parse_index(v: &str) -> Result<u32, WimError> {
    if v.is_empty() || v.len() > 10 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid("INDEX is not a decimal number"));
    }
    let n: u32 = v.parse().map_err(|_| invalid("INDEX out of range"))?;
    if n == 0 {
        return Err(invalid("INDEX out of range"));
    }
    Ok(n)
}

/// `TOTALBYTES`: ASCII decimal digits only, fits u64.
fn parse_u64(v: &str, what: &'static str) -> Result<u64, WimError> {
    if v.is_empty() || v.len() > 20 || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid(what));
    }
    v.parse().map_err(|_| invalid(what))
}

fn add_text(stack: &mut [Frame], s: &str, limits: &WimLimits) -> Result<(), WimError> {
    let Some(top) = stack.last_mut() else {
        // Only whitespace may appear outside the root.
        return if s.chars().all(char::is_whitespace) {
            Ok(())
        } else {
            Err(invalid("text outside the root element"))
        };
    };
    if top.has_children {
        // Mixed content between child elements is not recorded.
        return Ok(());
    }
    let chars = s.chars().count();
    top.text_chars = top.text_chars.saturating_add(chars);
    if top.text_chars > limits.max_name_chars {
        return Err(invalid("element text too long"));
    }
    top.text.push_str(s);
    Ok(())
}

fn end_element(
    frame: Frame,
    stack: &[Frame],
    limits: &WimLimits,
    image: &mut Option<ImageAcc>,
    images: &mut Vec<WimXmlImage>,
    root_total: &mut Option<u64>,
) -> Result<(), WimError> {
    let depth = stack.len();
    // `WIM/TOTALBYTES`.
    if depth == 1 && frame.name == EL_TOTALBYTES && !frame.has_children {
        if root_total.is_some() {
            return Err(invalid("duplicate TOTALBYTES"));
        }
        *root_total = Some(parse_u64(&frame.text, "TOTALBYTES is not a number")?);
        return Ok(());
    }
    // End of a `WIM/IMAGE`.
    if depth == 1 && frame.name == EL_IMAGE {
        let acc = image.take().ok_or(invalid("unexpected end"))?;
        images.push(WimXmlImage {
            index: acc.index,
            name: acc.name.ok_or(invalid("IMAGE without NAME"))?,
            description: acc.description.unwrap_or_default(),
            total_bytes: acc.total_bytes,
            elements: acc.elements,
        });
        return Ok(());
    }
    // A leaf inside an image: `WIM/IMAGE/...`.
    if depth >= 2
        && !frame.has_children
        && let Some(acc) = image.as_mut()
    {
        let path = stack
            .iter()
            .skip(2)
            .map(|f| f.name.as_str())
            .chain(std::iter::once(frame.name.as_str()))
            .collect::<Vec<_>>()
            .join("/");
        if depth == 2 {
            if frame.name == EL_NAME {
                if acc.name.is_some() {
                    return Err(invalid("duplicate NAME"));
                }
                acc.name = Some(frame.text.clone());
            } else if frame.name == EL_DESCRIPTION {
                if acc.description.is_some() {
                    return Err(invalid("duplicate DESCRIPTION"));
                }
                acc.description = Some(frame.text.clone());
            } else if frame.name == EL_TOTALBYTES {
                if acc.total_bytes.is_some() {
                    return Err(invalid("duplicate TOTALBYTES"));
                }
                acc.total_bytes = Some(parse_u64(&frame.text, "TOTALBYTES is not a number")?);
            }
        }
        if acc.elements.len() >= limits.max_xml_elements_per_image {
            return Err(invalid("too many elements in one IMAGE"));
        }
        acc.elements.push(XmlLeaf {
            path,
            text: frame.text,
        });
    }
    Ok(())
}

/// Encodes text as the XML resource bytes (BOM + UTF-16LE). Used by the
/// test builder and fuzz seeds.
#[must_use]
pub fn encode_utf16(text: &str) -> Vec<u8> {
    let mut out = BOM.to_vec();
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const S01: &str = "<WIM><TOTALBYTES>971729</TOTALBYTES><IMAGE INDEX=\"1\"><DIRCOUNT>11</DIRCOUNT><FILECOUNT>21</FILECOUNT><TOTALBYTES>965911</TOTALBYTES><HARDLINKBYTES>0</HARDLINKBYTES><CREATIONTIME><HIGHPART>0x01DD662B</HIGHPART><LOWPART>0x861D7446</LOWPART></CREATIONTIME><LASTMODIFICATIONTIME><HIGHPART>0x01DD662B</HIGHPART><LOWPART>0x861EA27E</LOWPART></LASTMODIFICATIONTIME><WIMBOOT>0</WIMBOOT><NAME>USGP-S01-01</NAME><DESCRIPTION>usgp-sample-S01-index-01-uncompressed</DESCRIPTION></IMAGE></WIM>";

    fn parse(s: &str) -> Result<WimXml, WimError> {
        parse_xml(&encode_utf16(s), &WimLimits::DEFAULT)
    }

    #[test]
    fn obs_014_document() {
        let x = parse(S01).unwrap();
        assert_eq!(x.total_bytes, Some(971_729));
        let img = x.images.first().unwrap();
        assert_eq!(img.index, 1);
        assert_eq!(img.name, "USGP-S01-01");
        assert_eq!(img.description, "usgp-sample-S01-index-01-uncompressed");
        assert_eq!(img.total_bytes, Some(965_911));
        assert_eq!(img.leaf("CREATIONTIME/HIGHPART"), Some("0x01DD662B"));
        let paths: Vec<_> = img.elements.iter().map(|l| l.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "DIRCOUNT",
                "FILECOUNT",
                "TOTALBYTES",
                "HARDLINKBYTES",
                "CREATIONTIME/HIGHPART",
                "CREATIONTIME/LOWPART",
                "LASTMODIFICATIONTIME/HIGHPART",
                "LASTMODIFICATIONTIME/LOWPART",
                "WIMBOOT",
                "NAME",
                "DESCRIPTION"
            ]
        );
    }

    #[test]
    fn entities_and_refs() {
        let x = parse("<WIM><IMAGE INDEX=\"1\"><NAME>a &amp; b &#x41;&#66;</NAME></IMAGE></WIM>")
            .unwrap();
        assert_eq!(x.images.first().unwrap().name, "a & b AB");
        assert_eq!(
            parse("<WIM><IMAGE INDEX=\"1\"><NAME>&foo;</NAME></IMAGE></WIM>"),
            Err(invalid("undefined entity"))
        );
        assert_eq!(
            parse("<WIM><IMAGE INDEX=\"1\"><NAME>&#0;</NAME></IMAGE></WIM>").err(),
            Some(invalid("invalid character reference"))
        );
    }

    #[test]
    fn refusals() {
        let cases: &[(&str, &str)] = &[
            (
                "<!DOCTYPE WIM [<!ENTITY a \"b\">]><WIM></WIM>",
                "DOCTYPE not allowed",
            ),
            ("<?pi x?><WIM></WIM>", "processing instruction not allowed"),
            ("<X></X>", "root element is not WIM"),
            ("<WIM></WIM><WIM></WIM>", "content after the root element"),
            (
                "<WIM><IMAGE><NAME>a</NAME></IMAGE></WIM>",
                "IMAGE without INDEX",
            ),
            (
                "<WIM><IMAGE INDEX=\"0\"><NAME>a</NAME></IMAGE></WIM>",
                "INDEX out of range",
            ),
            (
                "<WIM><IMAGE INDEX=\"+1\"><NAME>a</NAME></IMAGE></WIM>",
                "INDEX is not a decimal number",
            ),
            (
                "<WIM><IMAGE INDEX=\"1\"></IMAGE></WIM>",
                "IMAGE without NAME",
            ),
            (
                "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME><NAME>b</NAME></IMAGE></WIM>",
                "duplicate NAME",
            ),
            (
                "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE>",
                "unexpected end",
            ),
            ("<WIM><A></B></WIM>", "not well-formed"),
            ("", "unexpected end"),
            ("x<WIM></WIM>", "text outside the root element"),
            (
                "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME><TOTALBYTES>-1</TOTALBYTES></IMAGE></WIM>",
                "TOTALBYTES is not a number",
            ),
        ];
        for (doc, reason) in cases {
            assert_eq!(parse(doc).err(), Some(invalid(reason)), "{doc}");
        }
        assert_eq!(
            parse(
                "<WIM><IMAGE INDEX=\"2\"><NAME>a</NAME></IMAGE>\
                 <IMAGE INDEX=\"2\"><NAME>b</NAME></IMAGE></WIM>"
            ),
            Err(WimError::DuplicateIndex { index: 2 })
        );
    }

    #[test]
    fn encoding_rules() {
        let l = WimLimits::DEFAULT;
        assert_eq!(
            parse_xml(b"<\0W\0", &l),
            Err(invalid("missing byte-order mark"))
        );
        assert_eq!(
            parse_xml(&[0xff, 0xfe, 0x3c], &l),
            Err(invalid("odd length"))
        );
        // Unpaired high surrogate.
        assert_eq!(
            parse_xml(&[0xff, 0xfe, 0x00, 0xd8, 0x3c, 0x00], &l),
            Err(invalid("invalid UTF-16"))
        );
        assert_eq!(
            parse_xml(&[0xff, 0xfe, 0x00, 0x00], &l),
            Err(invalid("NUL character"))
        );
        let small = WimLimits {
            max_xml_bytes: 3,
            ..WimLimits::DEFAULT
        };
        assert_eq!(
            parse_xml(&[0xff, 0xfe, 0, 0], &small),
            Err(WimError::XmlTooLarge)
        );
    }

    #[test]
    fn bounded() {
        let deep = format!("<WIM>{}{}</WIM>", "<A>".repeat(40), "</A>".repeat(40));
        assert_eq!(parse(&deep).err(), Some(invalid("nesting too deep")));
        let long = format!(
            "<WIM><IMAGE INDEX=\"1\"><NAME>{}</NAME></IMAGE></WIM>",
            "n".repeat(1025)
        );
        assert_eq!(parse(&long).err(), Some(invalid("element text too long")));
        let many = format!(
            "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME>{}</IMAGE></WIM>",
            "<X>1</X>".repeat(1024)
        );
        assert_eq!(
            parse(&many).err(),
            Some(invalid("too many elements in one IMAGE"))
        );
        let lim = WimLimits {
            max_images: 1,
            ..WimLimits::DEFAULT
        };
        let two = "<WIM><IMAGE INDEX=\"1\"><NAME>a</NAME></IMAGE>\
                   <IMAGE INDEX=\"2\"><NAME>b</NAME></IMAGE></WIM>";
        assert_eq!(
            parse_xml(&encode_utf16(two), &lim),
            Err(WimError::LimitExceeded { what: "images" })
        );
    }
}
