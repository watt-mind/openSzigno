//! Content sniffing: one case per `DetectedType` and per decision boundary.

use openszigno_core::{DetectedType, sniff};
use serde_json::Value;

const ALL_TYPES: [(DetectedType, &str, Option<&str>); 7] = [
    (DetectedType::Pdf, "pdf", Some("pdf")),
    (DetectedType::Html, "html", Some("html")),
    (DetectedType::Xml, "xml", Some("xml")),
    (DetectedType::Dossier, "dossier", Some("es3")),
    (DetectedType::Zip, "zip", Some("zip")),
    (DetectedType::Text, "text", Some("txt")),
    (DetectedType::Binary, "binary", None),
];

#[test]
fn every_detected_type_has_a_stable_string_and_a_preferred_extension() {
    for (detected, name, extension) in ALL_TYPES {
        assert_eq!(detected.as_str(), name);
        assert_eq!(detected.preferred_extension(), extension);
        assert_eq!(
            serde_json::to_value(detected).expect("a detected type serialises"),
            Value::String(name.to_owned())
        );
    }
}

#[test]
fn detected_types_are_distinct_and_comparable() {
    for (index, (detected, _, _)) in ALL_TYPES.iter().enumerate() {
        for (other, _, _) in &ALL_TYPES[index + 1..] {
            assert_ne!(detected, other);
        }
        assert_eq!(*detected, *detected);
        assert!(format!("{detected:?}").len() > 2);
    }
}

#[test]
fn a_pdf_is_recognised_by_its_header() {
    assert_eq!(sniff(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"), DetectedType::Pdf);
    // Only at the very start: the marker elsewhere is not a PDF.
    assert_ne!(sniff(b"see %PDF-1.7 below"), DetectedType::Pdf);
}

#[test]
fn a_zip_is_recognised_by_its_local_file_header() {
    assert_eq!(sniff(b"PK\x03\x04\x14\x00\x00\x00"), DetectedType::Zip);
    // An empty archive record is not a local file header.
    assert_ne!(sniff(b"PK\x05\x06\x00\x00"), DetectedType::Zip);
}

#[test]
fn html_is_recognised_from_its_leading_tag_in_any_case() {
    for input in [
        "<!DOCTYPE html><html><body>x</body></html>",
        "<!doctype HTML>\n<html>",
        "<HTML><body>x</body></HTML>",
        "<head><title>x</title></head>",
        "<body>x</body>",
        "<meta charset=\"utf-8\">",
        "\u{feff}   \n<html>x</html>",
        "<!-- a notice -->\n<html>x</html>",
        "<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"><body/></html>",
    ] {
        assert_eq!(sniff(input.as_bytes()), DetectedType::Html, "{input:?}");
    }
}

#[test]
fn a_late_html_tag_is_only_xml() {
    // The HTML window is 1024 bytes; a root element beyond it is plain XML.
    let padded = format!("<!--{}-->\n<html><body/></html>", " ".repeat(1100));
    assert_eq!(sniff(padded.as_bytes()), DetectedType::Xml);
}

#[test]
fn xml_is_recognised_with_or_without_a_declaration() {
    for input in [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Acknowledge/>",
        "<Acknowledge xmlns=\"urn:example\"><Id>1</Id></Acknowledge>",
        "<_private/>",
        "<ns:Report/>",
    ] {
        assert_eq!(sniff(input.as_bytes()), DetectedType::Xml, "{input:?}");
    }
}

#[test]
fn a_declaration_with_no_element_in_the_window_is_still_xml() {
    let padded = format!("<?xml version=\"1.0\"?><!--{}", "x".repeat(5000));
    assert_eq!(sniff(padded.as_bytes()), DetectedType::Xml);
}

#[test]
fn a_dossier_root_is_recognised_with_or_without_a_prefix() {
    for input in [
        "<?xml version=\"1.0\"?><Dossier xmlns=\"https://www.microsec.hu/ds/e-szigno30#\"/>",
        "<es:Dossier xmlns:es=\"https://www.microsec.hu/ds/e-szigno30#\"/>",
        "<!-- unsigned -->\n<ec:Dossier xmlns:ec=\"urn:example\"><ec:Documents/></ec:Dossier>",
        "  \n<Dossier/>",
    ] {
        assert_eq!(sniff(input.as_bytes()), DetectedType::Dossier, "{input:?}");
    }
    // The local name is matched exactly; a differently cased root is not one.
    assert_eq!(sniff(b"<dossier/>"), DetectedType::Xml);
    assert_eq!(sniff(b"<DossierProfile/>"), DetectedType::Xml);
}

#[test]
fn a_doctype_other_than_html_does_not_make_a_payload_html() {
    assert_eq!(
        sniff(b"<!DOCTYPE Dossier SYSTEM \"x.dtd\"><Dossier/>"),
        DetectedType::Dossier
    );
}

#[test]
fn text_is_utf8_without_control_characters() {
    for input in [
        "Hello from a synthetic fixture.\n",
        "tabs\tand\r\nnewlines are whitespace",
        "\u{e1}rv\u{ed}zt\u{171}r\u{151} t\u{fc}k\u{f6}rf\u{fa}r\u{f3}g\u{e9}p",
        "",
        "a < b and c > d",
    ] {
        assert_eq!(sniff(input.as_bytes()), DetectedType::Text, "{input:?}");
    }
}

/// Markup must be recognised from the ASCII markup alone: a payload encoded
/// in ISO-8859-2 is not valid UTF-8, and it is still XML or HTML.
#[test]
fn markup_is_recognised_regardless_of_the_payload_encoding() {
    fn latin2(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut bytes = prefix.to_vec();
        // "árvíztűrő" in ISO-8859-2; none of this is valid UTF-8.
        bytes.extend_from_slice(&[0xE1, 0xF5, 0xEC, 0xFB, 0xF8, 0xF5]);
        bytes.extend_from_slice(suffix);
        assert!(
            std::str::from_utf8(&bytes).is_err(),
            "the payload is not UTF-8"
        );
        bytes
    }

    let declaration = b"<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?>";
    assert_eq!(
        sniff(&latin2(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><Acknowledge><Nev>",
            b"</Nev></Acknowledge>",
        )),
        DetectedType::Xml
    );
    assert_eq!(
        sniff(&latin2(b"<html><body>", b"</body></html>")),
        DetectedType::Html
    );
    assert_eq!(
        sniff(&latin2(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><!DOCTYPE html><html><body>",
            b"</body></html>",
        )),
        DetectedType::Html
    );
    assert_eq!(
        sniff(&latin2(
            b"<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?><es:Dossier xmlns:es=\"x\"><t>",
            b"</t></es:Dossier>",
        )),
        DetectedType::Dossier
    );
    // Even the element name itself may be outside ASCII and outside UTF-8.
    let mut named = declaration.to_vec();
    named.extend_from_slice(b"<K\xe9relem/>");
    assert_eq!(sniff(&named), DetectedType::Xml);
    let mut dossier = declaration.to_vec();
    dossier.extend_from_slice(b"<c\xe9g:Dossier/>");
    assert_eq!(sniff(&dossier), DetectedType::Dossier);
}

#[test]
fn markup_that_ends_in_ordinary_text_falls_back_to_the_text_rules() {
    // A comment followed by prose is not markup: no element ever starts.
    assert_eq!(sniff(b"<!-- a notice -->plain prose"), DetectedType::Text);
    assert_eq!(sniff(b"<!-- a notice -->\x00binary"), DetectedType::Binary);
}

#[test]
fn binary_is_anything_else() {
    assert_eq!(sniff(b"\x00\x01\x02\x03"), DetectedType::Binary);
    assert_eq!(sniff(b"text then a NUL\x00"), DetectedType::Binary);
    assert_eq!(sniff(b"\x1b[31mescape"), DetectedType::Binary);
    // Invalid UTF-8 is binary even without control bytes.
    assert_eq!(sniff(&[0xC3, 0x28, 0x41]), DetectedType::Binary);
    // A lone '<' that starts no name falls through to the text/binary rules.
    assert_eq!(sniff(b"<\x00>"), DetectedType::Binary);
}

#[test]
fn only_the_bounded_window_decides_text_from_binary() {
    // A NUL beyond the window does not change the verdict.
    let mut bytes = vec![b'a'; 5000];
    bytes.push(0);
    assert_eq!(sniff(&bytes), DetectedType::Text);

    // A multi-byte character split by the window boundary is not binary.
    let mut split = vec![b'a'; 4095];
    split.extend_from_slice("\u{e9}".as_bytes());
    assert_eq!(sniff(&split), DetectedType::Text);

    // Invalid UTF-8 truly inside the window is binary.
    let mut invalid = vec![b'a'; 10];
    invalid.push(0xFF);
    assert_eq!(sniff(&invalid), DetectedType::Binary);
}

#[test]
fn a_truncated_markup_prefix_never_panics() {
    for input in [
        "<",
        "<!",
        "<!-",
        "<!--",
        "<?",
        "<?xml",
        "<!DOCTYPE",
        "<!DOCTYPE ",
        "</",
        "<a",
        "<a ",
        "<:",
        "<1",
    ] {
        let _ = sniff(input.as_bytes());
    }
}
