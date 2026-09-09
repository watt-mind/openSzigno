//! Bounded XML access shared by structural parsing and signature verification.
//!
//! Both `openszigno_core::parse` and `openszigno-verify` must see *exactly* the
//! same tree: a verifier that resolved references in a second, differently
//! parsed tree would be open to the signature-wrapping class of attack this
//! project cares most about. This module is therefore the only place that turns
//! dossier bytes into text and text into a `roxmltree` tree, and the only place
//! that defines the XML ID space.

use std::collections::BTreeMap;

use encoding_rs::Encoding;
use roxmltree::{Document as XmlDocument, Node, ParsingOptions};

use crate::{Error, ErrorCode, Limits};

/// Decoded, pre-scanned dossier text, ready to be parsed into a tree.
///
/// Constructing one applies the input-size limit, the encoding policy, and the
/// pre-parse scan; it never allocates more than a copy of the input text.
#[derive(Clone, Debug)]
pub struct XmlSource {
    text: String,
    encoding: String,
}

impl XmlSource {
    /// Apply the size limit, decode the declared encoding, and run the
    /// pre-parse scan that rejects DTDs, deep nesting, and huge node counts.
    pub fn decode(bytes: &[u8], limits: &Limits) -> Result<Self, Error> {
        if bytes.len() as u64 > limits.max_input_bytes {
            return Err(Error::new(
                ErrorCode::InputTooLarge,
                format!("input exceeds {} bytes", limits.max_input_bytes),
            ));
        }
        let (text, encoding) = decode_xml(bytes)?;
        // Reject DTDs, deep nesting, and huge node counts before the recursive
        // tree parser runs; see `scan.rs` for why this cannot be delegated.
        crate::scan::prescan(&text, limits)?;
        Ok(Self { text, encoding })
    }

    /// The decoded document text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The XML encoding that was applied: `UTF-8` or `ISO-8859-2`.
    pub fn encoding(&self) -> &str {
        &self.encoding
    }

    /// Parse the pre-scanned text with DTDs disabled and a bounded node count.
    pub fn parse_tree(&self, limits: &Limits) -> Result<XmlDocument<'_>, Error> {
        let parsing = ParsingOptions {
            allow_dtd: false,
            // The pre-scan bounds elements; the parser also counts text and
            // comment nodes, so its backstop limit is proportionally larger.
            nodes_limit: u32::try_from(limits.max_xml_nodes.saturating_mul(4)).unwrap_or(u32::MAX),
            ..ParsingOptions::default()
        };
        XmlDocument::parse_with_options(&self.text, parsing).map_err(xml_error)
    }
}

/// The XML ID space of a dossier, keyed by ID value.
///
/// Only unprefixed `Id`/`ID`/`id` attributes take part, matching the structural
/// parser's `OBJREF` resolution. An empty or repeated ID is the hard error
/// `duplicate_id`, so a caller can never resolve a reference ambiguously.
pub fn id_map<'a, 'input>(
    root: Node<'a, 'input>,
) -> Result<BTreeMap<&'a str, Node<'a, 'input>>, Error> {
    let mut ids = BTreeMap::new();
    for node in root.descendants().filter(Node::is_element) {
        for attribute in node
            .attributes()
            .filter(|attribute| attribute.namespace().is_none())
        {
            if !matches!(attribute.name(), "Id" | "ID" | "id") {
                continue;
            }
            if attribute.value().is_empty() || ids.insert(attribute.value(), node).is_some() {
                return Err(Error::new(
                    ErrorCode::DuplicateId,
                    "XML IDs must be non-empty and unique",
                ));
            }
        }
    }
    Ok(ids)
}

fn decode_xml(bytes: &[u8]) -> Result<(String, String), Error> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let label = declared_encoding(bytes)
        .map(|declaration| declaration.label)
        .unwrap_or_else(|| "UTF-8".to_owned());
    let normalized = label.to_ascii_lowercase().replace('_', "-");
    if normalized == "utf-8" || normalized == "utf8" {
        return String::from_utf8(bytes.to_vec())
            .map(|text| (text, "UTF-8".to_owned()))
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding, "input is not valid UTF-8"));
    }
    if normalized != "iso-8859-2" && normalized != "iso8859-2" {
        return Err(Error::new(
            ErrorCode::UnsupportedEncoding,
            "only UTF-8 and ISO-8859-2 XML encodings are supported",
        ));
    }
    let encoding = Encoding::for_label(b"iso-8859-2").expect("encoding_rs has ISO-8859-2");
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        return Err(Error::new(
            ErrorCode::InvalidEncoding,
            "input is not valid ISO-8859-2",
        ));
    }
    Ok((decoded.into_owned(), "ISO-8859-2".to_owned()))
}

/// The `encoding` pseudo-attribute of an XML declaration, and where its value
/// sits in the bytes it was read from.
///
/// The range is the label alone, quotes excluded, so a writer that has to
/// restate the encoding can rewrite exactly those bytes and nothing else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodingDeclaration {
    /// The label exactly as written, neither trimmed nor case-folded.
    pub label: String,
    /// The byte offset of the first byte of the label.
    pub start: usize,
    /// The byte offset one past the last byte of the label.
    pub end: usize,
}

/// Read the `encoding` pseudo-attribute of the XML declaration only.
///
/// The search is bounded to the declaration itself so that comments or
/// content later in the prolog cannot choose how the document is decoded, and
/// it accepts every spelling XML allows there: either quote character, and
/// any whitespace around the `=`. It is the one reading of that declaration
/// this project has: `XmlSource::decode` decides the input encoding with it,
/// and a writer restating the declaration must agree with it byte for byte.
///
/// A leading byte order mark is skipped, and the offsets returned are into
/// `bytes` as given, mark included.
pub fn declared_encoding(bytes: &[u8]) -> Option<EncodingDeclaration> {
    const MARK: &[u8] = &[0xEF, 0xBB, 0xBF];
    let offset = if bytes.starts_with(MARK) {
        MARK.len()
    } else {
        0
    };
    let bytes = &bytes[offset..];
    let prefix = &bytes[..bytes.len().min(512)];
    if !prefix.starts_with(b"<?xml") || !prefix.get(5..)?.first()?.is_ascii_whitespace() {
        return None;
    }
    let end = prefix.windows(2).position(|window| window == b"?>")?;
    let declaration = std::str::from_utf8(&prefix[5..end]).ok()?;
    // Every offset below is relative to `declaration`; `base` turns one into
    // an offset into `bytes` as the caller handed them over.
    let base = offset + 5;
    let mut cursor = 0;
    while let Some(position) = declaration[cursor..].find("encoding") {
        let name_at = cursor + position;
        let preceded_by_space = declaration[..name_at]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);
        cursor = name_at + "encoding".len();
        if !preceded_by_space {
            continue;
        }
        let after = &declaration[cursor..];
        let trimmed = after.trim_start();
        let Some(value) = trimmed.strip_prefix('=') else {
            continue;
        };
        // The label starts after the name, the whitespace, the `=`, more
        // whitespace, and the opening quote.
        let mut at = cursor + (after.len() - trimmed.len()) + 1;
        let trimmed = value.trim_start();
        at += value.len() - trimmed.len();
        let quote = trimmed.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        at += quote.len_utf8();
        let label = &trimmed[quote.len_utf8()..];
        let close = label.find(quote)?;
        return Some(EncodingDeclaration {
            label: label[..close].to_owned(),
            start: base + at,
            end: base + at + close,
        });
    }
    None
}

/// Map a parser error to a stable code without echoing document content.
/// `roxmltree` error messages include element, attribute, and entity names,
/// which may be confidential; only the position is kept.
fn xml_error(error: roxmltree::Error) -> Error {
    match error {
        roxmltree::Error::DtdDetected => Error::new(
            ErrorCode::UnsafeXml,
            "DTD and entity declarations are not allowed",
        ),
        roxmltree::Error::NodesLimitReached
        | roxmltree::Error::AttributesLimitReached
        | roxmltree::Error::NamespacesLimitReached => {
            Error::new(ErrorCode::UnsafeXml, "XML exceeds the node limit")
        }
        other => {
            let position = other.pos();
            Error::new(
                ErrorCode::InvalidXml,
                format!(
                    "XML parsing failed at line {} column {}",
                    position.row, position.col
                ),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A document with a `DOCTYPE` is rejected through the public
    /// `XmlSource::decode` path, which is what `crate::parse` and every
    /// caller actually go through.
    ///
    /// This is caught by `scan::prescan`'s unconditional rejection of any
    /// `<!...>` markup (see `scan.rs`), which runs before `parse_tree` (and
    /// so before `ParsingOptions.allow_dtd`) ever sees the text. The
    /// `allow_dtd: false` wiring in `parse_tree` is deliberate defence in
    /// depth for that same rule, not the only thing enforcing it here.
    #[test]
    fn a_doctype_is_rejected_before_the_tree_parser_runs() {
        let xml = b"<!DOCTYPE a><a/>";
        let error = XmlSource::decode(xml, &Limits::default()).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsafeXml);
    }

    /// Once text has passed the pre-scan (so contains no `<!` markup at
    /// all), `parse_tree` builds a tree from it with `allow_dtd: false`. This
    /// documents that a normal, DTD-free document still parses successfully
    /// through the same options value the DOCTYPE case above never reaches.
    #[test]
    fn a_dtd_free_document_still_parses_with_the_hardened_options() {
        let source = XmlSource::decode(b"<a><b/></a>", &Limits::default()).unwrap();
        let tree = source.parse_tree(&Limits::default()).unwrap();
        assert_eq!(tree.root_element().tag_name().name(), "a");
    }

    /// The label, and the range that names it, for every spelling the
    /// declaration allows.
    #[test]
    fn every_declaration_spelling_yields_the_label_and_its_range() {
        for text in [
            "<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><a/>",
            "<?xml version='1.0' encoding='ISO-8859-2'?><a/>",
            "<?xml version=\"1.0\" encoding = \"ISO-8859-2\"?><a/>",
            "<?xml version=\"1.0\" encoding\t=\n'ISO-8859-2'?><a/>",
        ] {
            let found = declared_encoding(text.as_bytes())
                .unwrap_or_else(|| panic!("{text} declares an encoding"));
            assert_eq!(found.label, "ISO-8859-2", "{text}");
            assert_eq!(&text[found.start..found.end], "ISO-8859-2", "{text}");
        }
    }

    /// A byte order mark shifts the offsets and nothing else.
    #[test]
    fn the_offsets_are_into_the_bytes_as_given() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"<?xml version='1.0' encoding='utf8'?><a/>");
        let found = declared_encoding(&bytes).expect("the declaration is read past the mark");
        assert_eq!(found.label, "utf8");
        assert_eq!(&bytes[found.start..found.end], b"utf8");
    }

    /// Nothing outside the declaration is read, and a declaration that names
    /// no encoding names none.
    #[test]
    fn only_the_declarations_own_encoding_is_read() {
        for text in [
            "<a/>",
            "<?xml version=\"1.0\"?><a/>",
            "<?xml version=\"1.0\"?><!-- encoding=\"ISO-8859-2\" --><a/>",
            // `encoding` has to be a pseudo-attribute of its own, not the
            // tail of another name.
            "<?xml version=\"1.0\" xencoding=\"ISO-8859-2\"?><a/>",
        ] {
            assert_eq!(declared_encoding(text.as_bytes()), None, "{text}");
        }
    }

    /// An upper-case label decodes as the same encoding a lower-case one
    /// does, and both reach the caller as written.
    #[test]
    fn the_label_is_matched_without_regard_to_case() {
        let source = XmlSource::decode(
            "<?xml version='1.0' encoding='ISO-8859-2'?><a/>".as_bytes(),
            &Limits::default(),
        )
        .expect("a single-quoted declaration decodes");
        assert_eq!(source.encoding(), "ISO-8859-2");
        let source = XmlSource::decode(
            "<?xml version=\"1.0\" encoding = \"utf-8\"?><a/>".as_bytes(),
            &Limits::default(),
        )
        .expect("spaces around the equals sign decode");
        assert_eq!(source.encoding(), "UTF-8");
    }
}
