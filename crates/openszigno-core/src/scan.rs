//! Bounded pre-parse scan of the decoded XML text.
//!
//! `roxmltree` builds the whole tree recursively and has no nesting limit, so
//! a deeply nested document can overflow the stack before the tree exists.
//! This single linear pass rejects unsafe markup before the real parser sees
//! it. It only needs to be conservative for well-formed XML: anything it
//! miscounts on malformed input is rejected by `roxmltree` afterwards.

use crate::{Error, ErrorCode, Limits};

/// Summary of the pre-parse scan.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ScanSummary {
    pub(crate) elements: usize,
    pub(crate) max_depth: usize,
}

/// Reject DTD/entity declarations, excessive nesting, and excessive element
/// counts without building a tree. Comments, CDATA sections, and processing
/// instructions are skipped so that markup-like text inside them does not
/// trigger false positives.
pub(crate) fn prescan(xml: &str, limits: &Limits) -> Result<ScanSummary, Error> {
    let bytes = xml.as_bytes();
    let mut summary = ScanSummary::default();
    let mut depth = 0usize;
    let mut i = 0usize;

    while let Some(offset) = memchr(b'<', &bytes[i..]) {
        let start = i + offset;
        let rest = &bytes[start..];
        if rest.starts_with(b"<!--") {
            i = skip_past(bytes, start + 4, b"-->");
        } else if rest.starts_with(b"<![CDATA[") {
            i = skip_past(bytes, start + 9, b"]]>");
        } else if rest.starts_with(b"<?") {
            i = skip_past(bytes, start + 2, b"?>");
        } else if rest.starts_with(b"<!") {
            return Err(Error::new(
                ErrorCode::UnsafeXml,
                "DTD and entity declarations are not allowed",
            ));
        } else if rest.starts_with(b"</") {
            depth = depth.saturating_sub(1);
            i = skip_past(bytes, start + 2, b">");
        } else {
            depth += 1;
            if depth > limits.max_xml_depth {
                return Err(Error::new(
                    ErrorCode::UnsafeXml,
                    format!("XML nesting exceeds {} elements", limits.max_xml_depth),
                ));
            }
            summary.elements += 1;
            if summary.elements > limits.max_xml_nodes {
                return Err(Error::new(
                    ErrorCode::UnsafeXml,
                    format!("XML exceeds {} nodes", limits.max_xml_nodes),
                ));
            }
            summary.max_depth = summary.max_depth.max(depth);
            let (end, self_closing) = scan_start_tag(bytes, start + 1);
            if self_closing {
                depth -= 1;
            }
            i = end;
        }
    }

    Ok(summary)
}

/// Scan a start tag beginning after `<`. Attribute values may legally contain
/// `>`, so quotes are tracked. Returns the index just past the closing `>` and
/// whether the tag was self-closing.
fn scan_start_tag(bytes: &[u8], mut i: usize) -> (usize, bool) {
    let mut quote: Option<u8> = None;
    let mut previous = 0u8;
    while i < bytes.len() {
        let byte = bytes[i];
        match quote {
            Some(open) if byte == open => quote = None,
            Some(_) => {}
            None if byte == b'"' || byte == b'\'' => quote = Some(byte),
            None if byte == b'>' => return (i + 1, previous == b'/'),
            None => {}
        }
        previous = byte;
        i += 1;
    }
    (bytes.len(), false)
}

fn skip_past(bytes: &[u8], from: usize, terminator: &[u8]) -> usize {
    if from >= bytes.len() {
        return bytes.len();
    }
    bytes[from..]
        .windows(terminator.len())
        .position(|window| window == terminator)
        .map_or(bytes.len(), |position| from + position + terminator.len())
}

fn memchr(needle: u8, haystack: &[u8]) -> Option<usize> {
    haystack.iter().position(|byte| *byte == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(depth: usize, nodes: usize) -> Limits {
        Limits {
            max_xml_depth: depth,
            max_xml_nodes: nodes,
            ..Limits::default()
        }
    }

    #[test]
    fn counts_depth_and_elements() {
        let summary = prescan("<a><b/><c><d>x</d></c></a>", &Limits::default()).unwrap();
        assert_eq!(summary.elements, 4);
        assert_eq!(summary.max_depth, 3);
    }

    #[test]
    fn rejects_excess_depth_and_nodes() {
        let error = prescan("<a><b><c/></b></a>", &limits(2, 100)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsafeXml);
        let error = prescan("<a><b/><c/></a>", &limits(100, 2)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsafeXml);
    }

    /// `<a><b/></a>` is exactly 2 deep and exactly 2 elements: right at both
    /// limits, which must pass (the check is `>`, not `>=`).
    #[test]
    fn exactly_at_the_depth_and_node_limits_passes() {
        let summary = prescan("<a><b/></a>", &limits(2, 2)).unwrap();
        assert_eq!(summary.elements, 2);
        assert_eq!(summary.max_depth, 2);
    }

    /// One element or one level of nesting past the limit is rejected, with
    /// the depth and node checks each isolated from the other.
    #[test]
    fn one_past_the_depth_limit_is_rejected() {
        let error = prescan("<a><b/></a>", &limits(1, 100)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsafeXml);
    }

    #[test]
    fn one_past_the_node_limit_is_rejected() {
        let error = prescan("<a><b/></a>", &limits(100, 1)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::UnsafeXml);
    }

    /// A self-closing root element returns depth to zero afterwards, so a
    /// sibling that follows it is only depth 1, not stacked on top.
    #[test]
    fn self_closing_tags_do_not_leave_depth_open_for_siblings() {
        let summary = prescan("<a/><b/>", &limits(1, 10)).unwrap();
        assert_eq!(summary.elements, 2);
        assert_eq!(summary.max_depth, 1);
    }

    #[test]
    fn ignores_markup_inside_comments_cdata_and_instructions() {
        let xml = "<?xml version=\"1.0\"?><!-- <!DOCTYPE x> <a><b> --><a><![CDATA[<!ENTITY x><c><d>]]><?pi <e> ?></a>";
        let summary = prescan(xml, &limits(1, 10)).unwrap();
        assert_eq!(summary.elements, 1);
        assert_eq!(summary.max_depth, 1);
    }

    #[test]
    fn rejects_doctype_and_entity_declarations() {
        assert_eq!(
            prescan("<!DOCTYPE a [<!ENTITY x \"y\">]><a/>", &Limits::default())
                .unwrap_err()
                .code(),
            ErrorCode::UnsafeXml
        );
        assert_eq!(
            prescan("<a><!ENTITY x \"y\"></a>", &Limits::default())
                .unwrap_err()
                .code(),
            ErrorCode::UnsafeXml
        );
    }

    #[test]
    fn tracks_quoted_angle_brackets_in_attributes() {
        let summary = prescan("<a x=\"1>2\" y='<b><c>'><d/></a>", &limits(2, 10)).unwrap();
        assert_eq!(summary.elements, 2);
        assert_eq!(summary.max_depth, 2);
    }

    /// `scan_start_tag` reports self-closing only when the byte immediately
    /// before `>` is `/`, even when the tag carries an attribute whose quoted
    /// value ends in `/` right before the closing quote.
    #[test]
    fn self_closing_is_detected_by_the_byte_immediately_before_the_close() {
        let (end, self_closing) = scan_start_tag(b"a x=\"1\"/>", 0);
        assert!(self_closing);
        assert_eq!(end, 9);

        // The quoted value ends in '/', but the '/' is inside the quotes, so
        // the tag is *not* self-closing: the character right before '>' is
        // the closing quote.
        let (end, self_closing) = scan_start_tag(b"a x=\"1/\">", 0);
        assert!(!self_closing);
        assert_eq!(end, 9);
    }

    #[test]
    fn tolerates_truncated_markup_without_panicking() {
        for text in [
            "<",
            "<a",
            "<!--",
            "<![CDATA[",
            "<?",
            "</",
            "<a x=\"",
            "<a/",
            "",
        ] {
            let _ = prescan(text, &Limits::default());
        }
    }
}
