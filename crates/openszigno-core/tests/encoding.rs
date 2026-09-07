//! Decoding of the byte stream into XML text: declaration handling, BOMs, and
//! the two supported encodings.

mod common;

use common::PLAIN;
use openszigno_core::{ErrorCode, Limits, parse};

fn iso_8859_2(text: &str) -> Vec<u8> {
    let encoding = encoding_rs::Encoding::for_label(b"iso-8859-2").expect("ISO-8859-2 exists");
    let (encoded, _, had_errors) = encoding.encode(text);
    assert!(!had_errors, "test text must be representable");
    encoded.into_owned()
}

#[test]
fn a_utf8_byte_order_mark_is_stripped_before_parsing() {
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(PLAIN.as_bytes());
    let dossier = parse(&bytes, &Limits::default()).expect("a BOM must not break parsing");
    assert_eq!(dossier.xml_encoding, "UTF-8");
}

#[test]
fn a_byte_order_mark_does_not_hide_the_encoding_declaration() {
    let text = PLAIN
        .replace("encoding=\"UTF-8\"", "encoding=\"ISO-8859-2\"")
        .replace("Unsigned synthetic plain fixture", "Árvíztűrő");
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(&iso_8859_2(&text));
    let dossier = parse(&bytes, &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.xml_encoding, "ISO-8859-2");
    assert_eq!(dossier.title, "Árvíztűrő");
}

#[test]
fn iso_8859_2_bytes_are_decoded_without_a_byte_order_mark() {
    let text = PLAIN
        .replace("encoding=\"UTF-8\"", "encoding='iso_8859-2'")
        .replace("Unsigned synthetic plain fixture", "Árvíztűrő tükörfúrógép");
    let dossier = parse(&iso_8859_2(&text), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.xml_encoding, "ISO-8859-2");
    assert_eq!(dossier.title, "Árvíztűrő tükörfúrógép");
}

#[test]
fn bytes_that_are_not_valid_utf8_are_an_invalid_encoding() {
    let mut bytes = PLAIN.replace("hello.txt", "hello?txt").into_bytes();
    let position = bytes
        .iter()
        .position(|byte| *byte == b'?')
        .expect("marker byte is present");
    bytes[position] = 0xFF;
    let error = parse(&bytes, &Limits::default()).expect_err("invalid UTF-8 must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidEncoding);
    assert!(!error.message().contains("hello"));
}

#[test]
fn an_unsupported_declared_encoding_is_rejected() {
    for label in ["UTF-16", "windows-1250", "ISO-8859-1"] {
        let text = PLAIN.replace("encoding=\"UTF-8\"", &format!("encoding=\"{label}\""));
        let error = parse(text.as_bytes(), &Limits::default()).expect_err("must be rejected");
        assert_eq!(error.code(), ErrorCode::UnsupportedEncoding);
    }
}

#[test]
fn utf8_spellings_of_the_declaration_are_all_accepted() {
    for label in ["UTF-8", "utf-8", "utf8", "UTF_8"] {
        let text = PLAIN.replace("encoding=\"UTF-8\"", &format!("encoding=\"{label}\""));
        let dossier = parse(text.as_bytes(), &Limits::default()).expect("dossier parses");
        assert_eq!(dossier.xml_encoding, "UTF-8");
    }
}

#[test]
fn a_document_without_an_xml_declaration_is_read_as_utf8() {
    let text = PLAIN.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n", "");
    let dossier = parse(text.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.xml_encoding, "UTF-8");
}

#[test]
fn a_declaration_without_an_encoding_pseudo_attribute_is_read_as_utf8() {
    let text = PLAIN.replace(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\"?>",
    );
    let dossier = parse(text.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.xml_encoding, "UTF-8");
}

#[test]
fn a_truncated_declaration_is_not_searched_for_an_encoding() {
    // No `?>` terminator: the scan must give up rather than read on into the
    // document body, and the XML parser then rejects the input.
    let text = PLAIN.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml ");
    let error = parse(text.as_bytes(), &Limits::default()).expect_err("must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidXml);
}

#[test]
fn only_a_quoted_encoding_value_is_honoured() {
    // An unquoted value is ignored, so the input is read as UTF-8 and the XML
    // parser rejects the malformed declaration.
    let text = PLAIN.replace("encoding=\"UTF-8\"", "encoding=UTF-8");
    let error = parse(text.as_bytes(), &Limits::default()).expect_err("must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidXml);
}

#[test]
fn a_declaration_encoding_must_stand_on_its_own() {
    // `xencoding` must not be mistaken for the encoding pseudo-attribute; the
    // real declaration that follows it is the one that counts.
    // `xencoding` is not preceded by a space, and `encoding_hint` is not
    // followed by `=`; neither may select the encoding.
    for declaration in [
        "<?xml version=\"1.0\" xencoding=\"UTF-16\" encoding=\"UTF-8\"?>",
        "<?xml version=\"1.0\" encoding_hint=\"UTF-16\" encoding=\"UTF-8\"?>",
    ] {
        let text = PLAIN.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", declaration);
        let error = parse(text.as_bytes(), &Limits::default()).expect_err("must be rejected");
        assert_eq!(
            error.code(),
            ErrorCode::InvalidXml,
            "an unknown pseudo-attribute is not accepted as XML, but it must \
             not have selected UTF-16 either"
        );
    }
}
