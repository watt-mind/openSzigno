//! Turning a checked dossier into XML text.
//!
//! The layout is fixed: one element order, two-space indentation, a profile
//! written on one line per field, and no attribute whose value depends on
//! anything but the request. Nothing here consults a clock or a random
//! source, so the same request always renders the same bytes.

use openszigno_core::{ESZIGNO_NAMESPACE, MimeType, XMLDSIG_NAMESPACE};

/// The `E-category` a dossier this crate writes declares.
pub const DOSSIER_CATEGORY: &str = "electronic dossier";
/// The `E-category` every document in it declares.
pub const DOCUMENT_CATEGORY: &str = "electronic data";

/// One document, already checked and encoded, as the renderer needs it.
pub struct RenderedDocument<'a> {
    pub title: &'a str,
    pub created: &'a str,
    pub mime_type: &'a MimeType,
    pub source_size: u64,
    pub transforms: &'a [String],
    pub object_id: &'a str,
    pub profile_id: &'a str,
    pub payload: &'a str,
}

/// Escape XML text content. The title rules already refuse every control
/// character, so only the markup delimiters remain.
///
/// The signer shares this escaper, through `sign::names`, so that one rule
/// covers every string this crate writes into XML.
pub(crate) fn text(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

/// Escape an attribute value: text escaping plus both quote characters.
///
/// The signer shares this escaper too; see [`text`].
pub(crate) fn attribute(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

fn mime_element(mime: &MimeType) -> String {
    let mut element = format!(
        "<es:MIME-Type type=\"{}\" subtype=\"{}\"",
        attribute(&mime.media_type),
        attribute(&mime.subtype)
    );
    if let Some(extension) = &mime.extension {
        element.push_str(&format!(" extension=\"{}\"", attribute(extension)));
    }
    if let Some(charset) = &mime.charset {
        element.push_str(&format!(" charSet=\"{}\"", attribute(charset)));
    }
    element.push_str("/>");
    element
}

fn transforms_element(transforms: &[String]) -> String {
    let mut element = String::from("<es:BaseTransform>");
    for transform in transforms {
        element.push_str(&format!(
            "<es:Transform Algorithm=\"{}\"/>",
            attribute(transform)
        ));
    }
    element.push_str("</es:BaseTransform>");
    element
}

fn document(out: &mut String, item: &RenderedDocument<'_>) {
    out.push_str("    <es:Document>\n");
    out.push_str(&format!(
        "      <es:DocumentProfile Id=\"{}\" OBJREF=\"{}\">\n",
        attribute(item.profile_id),
        attribute(item.object_id)
    ));
    out.push_str(&format!(
        "        <es:Title>{}</es:Title>\n",
        text(item.title)
    ));
    out.push_str(&format!(
        "        <es:E-category>{DOCUMENT_CATEGORY}</es:E-category>\n"
    ));
    out.push_str(&format!(
        "        <es:CreationDate>{}</es:CreationDate>\n",
        text(item.created)
    ));
    out.push_str(&format!(
        "        <es:Format>{}</es:Format>\n",
        mime_element(item.mime_type)
    ));
    out.push_str(&format!(
        "        <es:SourceSize sizeValue=\"{}\" sizeUnit=\"B\"/>\n",
        item.source_size
    ));
    out.push_str(&format!(
        "        {}\n",
        transforms_element(item.transforms)
    ));
    out.push_str("      </es:DocumentProfile>\n");
    out.push_str(&format!(
        "      <ds:Object Id=\"{}\">{}</ds:Object>\n",
        attribute(item.object_id),
        item.payload
    ));
    out.push_str("    </es:Document>\n");
}

/// Render the whole dossier.
pub fn dossier(title: &str, created: &str, documents: &[RenderedDocument<'_>]) -> Vec<u8> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<es:Dossier xmlns:es=\"{ESZIGNO_NAMESPACE}\" xmlns:ds=\"{XMLDSIG_NAMESPACE}\">\n"
    ));
    out.push_str("  <es:DossierProfile Id=\"dossier\" OBJREF=\"documents\">\n");
    out.push_str(&format!("    <es:Title>{}</es:Title>\n", text(title)));
    out.push_str(&format!(
        "    <es:E-category>{DOSSIER_CATEGORY}</es:E-category>\n"
    ));
    out.push_str(&format!(
        "    <es:CreationDate>{}</es:CreationDate>\n",
        text(created)
    ));
    out.push_str("  </es:DossierProfile>\n");
    out.push_str("  <es:Documents Id=\"documents\">\n");
    for item in documents {
        document(&mut out, item);
    }
    out.push_str("  </es:Documents>\n");
    out.push_str("</es:Dossier>\n");
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_delimiters_are_escaped_in_text_and_attributes() {
        assert_eq!(text("a & b < c > d"), "a &amp; b &lt; c &gt; d");
        assert_eq!(attribute("a\"b'c&d"), "a&quot;b&apos;c&amp;d");
    }

    #[test]
    fn an_optional_mime_attribute_is_written_only_when_it_is_known() {
        let bare = MimeType {
            media_type: "application".to_owned(),
            subtype: "pdf".to_owned(),
            extension: None,
            charset: None,
        };
        assert_eq!(
            mime_element(&bare),
            "<es:MIME-Type type=\"application\" subtype=\"pdf\"/>"
        );
        let full = MimeType {
            extension: Some("pdf".to_owned()),
            charset: Some("UTF-8".to_owned()),
            ..bare
        };
        assert_eq!(
            mime_element(&full),
            "<es:MIME-Type type=\"application\" subtype=\"pdf\" extension=\"pdf\" charSet=\"UTF-8\"/>"
        );
    }

    #[test]
    fn every_transform_is_written_in_order() {
        assert_eq!(
            transforms_element(&["zip".to_owned(), "base64".to_owned()]),
            "<es:BaseTransform><es:Transform Algorithm=\"zip\"/>\
             <es:Transform Algorithm=\"base64\"/></es:BaseTransform>"
        );
    }
}
