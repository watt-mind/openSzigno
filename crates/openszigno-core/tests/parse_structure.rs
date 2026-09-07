//! Structural parsing rules: one test per rejection path in `parse.rs`.

mod common;

use common::{PLAIN, document, dossier_with};
use openszigno_core::{ErrorCode, Limits, StructuralWarningCode, parse};

fn error_code(xml: &str) -> ErrorCode {
    parse(xml.as_bytes(), &Limits::default())
        .expect_err("this dossier must be rejected")
        .code()
}

fn error_code_with(xml: &str, limits: &Limits) -> ErrorCode {
    parse(xml.as_bytes(), limits)
        .expect_err("this dossier must be rejected")
        .code()
}

#[test]
fn a_dossier_without_a_dossier_profile_is_missing_an_element() {
    let start = PLAIN
        .find("<es:DossierProfile")
        .expect("fixture has a profile");
    let end = PLAIN
        .find("</es:DossierProfile>")
        .expect("fixture has a profile")
        + "</es:DossierProfile>".len();
    let without_profile = format!("{}{}", &PLAIN[..start], &PLAIN[end..]);
    assert_eq!(error_code(&without_profile), ErrorCode::MissingElement);
}

#[test]
fn a_dossier_without_a_documents_element_is_missing_an_element() {
    // The element keeps its Id under another name, so OBJREF resolution still
    // succeeds and the missing-element rule is what rejects the dossier.
    let renamed = PLAIN
        .replace("<es:Documents ", "<es:DocumentsArchive ")
        .replace("</es:Documents>", "</es:DocumentsArchive>");
    assert_eq!(error_code(&renamed), ErrorCode::MissingElement);
}

#[test]
fn a_dossier_without_a_title_is_missing_an_element() {
    let without_title = PLAIN.replace("<es:Title>Unsigned synthetic plain fixture</es:Title>", "");
    assert_eq!(error_code(&without_title), ErrorCode::MissingElement);
}

#[test]
fn an_empty_title_is_missing_an_element() {
    let empty_title = PLAIN.replace(
        "<es:Title>Unsigned synthetic plain fixture</es:Title>",
        "<es:Title>  </es:Title>",
    );
    assert_eq!(error_code(&empty_title), ErrorCode::MissingElement);
}

#[test]
fn a_dossier_without_a_creation_date_is_a_conformance_warning() {
    // Company-court dossiers occur without a dossier-level CreationDate.
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_date = dossier_with(&documents).replace(
        "<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>",
        "</es:DossierProfile>",
    );
    let dossier = parse(without_date.as_bytes(), &Limits::default()).expect("still parses");
    assert_eq!(dossier.creation_date, None);
    assert!(
        dossier
            .warnings
            .iter()
            .any(|warning| warning.code == StructuralWarningCode::CreationDateMissing)
    );
}

#[test]
fn a_document_without_a_document_profile_is_skipped_with_a_warning() {
    // Company-court dossiers carry empty placeholder documents. They are not
    // conformant, so they are reported and skipped rather than counted.
    let documents = format!(
        "{}{}",
        "<es:Document><ds:Object Id=\"DocumentObject1\">eA==</ds:Object></es:Document>",
        document(2, "kept.txt", Some("txt"), 1, &["base64"], "eA=="),
    );
    let dossier = parse(dossier_with(&documents).as_bytes(), &Limits::default())
        .expect("a placeholder document must not fail the dossier");
    assert_eq!(dossier.documents.len(), 1);
    assert_eq!(dossier.documents[0].index, 0);
    assert_eq!(dossier.documents[0].title, "kept.txt");
    assert_eq!(dossier.warnings.len(), 1);
    assert_eq!(
        dossier.warnings[0].code,
        StructuralWarningCode::DocumentWithoutProfile
    );
    assert!(
        dossier.warnings[0].message.contains("position 0"),
        "the warning names the source position"
    );
}

#[test]
fn two_document_profiles_in_one_document_are_invalid_xml() {
    let profile = "<es:DocumentProfile Id=\"P\" OBJREF=\"DocumentObject1\"><es:Title>a.txt</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type=\"text\" subtype=\"plain\"/></es:Format><es:SourceSize sizeValue=\"1\" sizeUnit=\"B\"/><es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform></es:DocumentProfile>";
    let second = profile.replace("Id=\"P\"", "Id=\"Q\"");
    let documents = format!(
        "<es:Document>{profile}{second}<ds:Object Id=\"DocumentObject1\">eA==</ds:Object></es:Document>"
    );
    assert_eq!(error_code(&dossier_with(&documents)), ErrorCode::InvalidXml);
}

#[test]
fn a_document_without_a_format_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_format = dossier_with(&documents).replace(
        "<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>",
        "",
    );
    assert_eq!(error_code(&without_format), ErrorCode::MissingElement);
}

#[test]
fn a_document_without_a_mime_type_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_mime = dossier_with(&documents).replace(
        "<es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/>",
        "",
    );
    assert_eq!(error_code(&without_mime), ErrorCode::MissingElement);
}

#[test]
fn a_document_without_a_source_size_is_read_with_a_warning() {
    // `SourceSize` is optional: company-court dossiers occur without it. See
    // `namespaces.rs` for the full behaviour.
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_size =
        dossier_with(&documents).replace("<es:SourceSize sizeValue=\"1\" sizeUnit=\"B\"/>", "");
    let dossier = parse(without_size.as_bytes(), &Limits::default())
        .expect("a missing SourceSize does not reject the dossier");
    assert_eq!(dossier.documents[0].source_size, None);
    assert_eq!(
        dossier.warnings[0].code,
        StructuralWarningCode::SourceSizeMissing
    );
}

#[test]
fn a_document_without_a_base_transform_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_transform = dossier_with(&documents).replace(
        "<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>",
        "",
    );
    assert_eq!(error_code(&without_transform), ErrorCode::MissingElement);
}

#[test]
fn a_document_without_any_transform_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &[], "eA==");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::MissingElement
    );
}

#[test]
fn a_document_title_that_is_absent_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_title = dossier_with(&documents).replace("<es:Title>hello.txt</es:Title>", "");
    assert_eq!(error_code(&without_title), ErrorCode::MissingElement);
}

#[test]
fn a_document_without_a_creation_date_is_missing_an_element() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let without_date = dossier_with(&documents).replace(
        "<es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format>",
        "<es:Format>",
    );
    assert_eq!(error_code(&without_date), ErrorCode::MissingElement);
}

#[test]
fn a_transform_without_an_algorithm_is_an_invalid_attribute() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("<es:Transform Algorithm=\"base64\"/>", "<es:Transform/>");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_non_numeric_source_size_is_an_invalid_attribute() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("sizeValue=\"1\"", "sizeValue=\"forty-one\"");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_missing_source_size_value_is_an_invalid_attribute() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("sizeValue=\"1\" ", "");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_source_size_unit_other_than_bytes_is_an_invalid_attribute() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("sizeUnit=\"B\"", "sizeUnit=\"kB\"");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_mime_type_without_a_subtype_is_an_invalid_attribute() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace(" subtype=\"plain\"", "");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_declared_source_size_above_the_limit_is_rejected_before_decoding() {
    let documents = document(1, "hello.txt", Some("txt"), 4096, &["base64"], "eA==");
    let limits = Limits {
        max_decoded_document_bytes: 64,
        ..Limits::default()
    };
    assert_eq!(
        error_code_with(&dossier_with(&documents), &limits),
        ErrorCode::DecodedTooLarge
    );
}

#[test]
fn an_encoded_payload_above_the_character_limit_is_rejected_while_parsing() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==");
    let limits = Limits {
        max_base64_chars: 2,
        ..Limits::default()
    };
    assert_eq!(
        error_code_with(&dossier_with(&documents), &limits),
        ErrorCode::DecodedTooLarge
    );
}

#[test]
fn repeated_required_children_are_invalid_xml() {
    let twice = PLAIN.replace(
        "<es:Documents Id=\"Object0\">",
        "<es:Documents Id=\"Object1\"/><es:Documents Id=\"Object0\">",
    );
    assert_eq!(error_code(&twice), ErrorCode::InvalidXml);

    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==").replace(
        "<es:Format>",
        "<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\"/></es:Format><es:Format>",
    );
    assert_eq!(error_code(&dossier_with(&documents)), ErrorCode::InvalidXml);
}

#[test]
fn a_document_without_a_payload_object_is_invalid_xml() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("<ds:Object Id=\"DocumentObject1\">eA==</ds:Object>", "");
    // The OBJREF still resolves, because the profile Id space is unchanged.
    let xml = dossier_with(&documents)
        .replace("OBJREF=\"DocumentObject1\"", "OBJREF=\"DocumentProfile1\"");
    assert_eq!(error_code(&xml), ErrorCode::InvalidXml);
}

#[test]
fn two_direct_payload_objects_are_invalid_xml() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==").replace(
        "</es:Document>",
        "<ds:Object Id=\"Extra\">eA==</ds:Object></es:Document>",
    );
    assert_eq!(error_code(&dossier_with(&documents)), ErrorCode::InvalidXml);
}

#[test]
fn a_payload_object_that_does_not_match_the_objref_is_unresolved() {
    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace(
            "<ds:Object Id=\"DocumentObject1\">",
            "<ds:Object Id=\"Other\">",
        )
        .replace("OBJREF=\"DocumentObject1\"", "OBJREF=\"DocumentProfile1\"");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::UnresolvedObjref
    );
}

#[test]
fn objrefs_may_use_the_fragment_prefix() {
    let hashed = PLAIN
        .replace("OBJREF=\"Object0\"", "OBJREF=\"#Object0\"")
        .replace("OBJREF=\"DocumentObject1\"", "OBJREF=\"#DocumentObject1\"");
    let dossier = parse(hashed.as_bytes(), &Limits::default()).expect("fragment OBJREFs resolve");
    assert_eq!(dossier.documents[0].object_ref, "DocumentObject1");
}

#[test]
fn an_empty_id_attribute_is_a_duplicate_id() {
    let empty = PLAIN.replace("Id=\"DossierProfile1\"", "Id=\"\"");
    assert_eq!(error_code(&empty), ErrorCode::DuplicateId);
}

#[test]
fn a_profile_without_an_id_is_an_invalid_attribute() {
    let without_id = PLAIN.replace(
        "<es:DossierProfile Id=\"DossierProfile1\" ",
        "<es:DossierProfile ",
    );
    assert_eq!(error_code(&without_id), ErrorCode::InvalidAttribute);

    let documents = document(1, "hello.txt", Some("txt"), 1, &["base64"], "eA==")
        .replace("Id=\"DocumentProfile1\" ", "");
    assert_eq!(
        error_code(&dossier_with(&documents)),
        ErrorCode::InvalidAttribute
    );
}

#[test]
fn a_profile_without_an_objref_is_an_invalid_attribute() {
    let without_ref = PLAIN.replace(" OBJREF=\"Object0\"", "");
    assert_eq!(error_code(&without_ref), ErrorCode::InvalidAttribute);

    // An empty or fragment-only reference resolves to nothing, which the
    // global OBJREF check reports first.
    let empty_ref = PLAIN.replace("OBJREF=\"Object0\"", "OBJREF=\"\"");
    assert_eq!(error_code(&empty_ref), ErrorCode::UnresolvedObjref);

    let only_fragment = PLAIN.replace("OBJREF=\"Object0\"", "OBJREF=\"#\"");
    assert_eq!(error_code(&only_fragment), ErrorCode::UnresolvedObjref);
}

#[test]
fn a_documents_element_without_an_id_is_an_invalid_attribute() {
    // The dossier profile points at another existing Id, so the global OBJREF
    // check passes and the Documents Id rule is what rejects the dossier.
    let without_id = PLAIN
        .replace("OBJREF=\"Object0\"", "OBJREF=\"DocumentProfile1\"")
        .replace("<es:Documents Id=\"Object0\">", "<es:Documents>");
    assert_eq!(error_code(&without_id), ErrorCode::InvalidAttribute);
}

#[test]
fn a_dossier_profile_pointing_away_from_documents_is_unresolved() {
    let elsewhere = PLAIN.replace("OBJREF=\"Object0\"", "OBJREF=\"DocumentProfile1\"");
    assert_eq!(error_code(&elsewhere), ErrorCode::UnresolvedObjref);
}

#[test]
fn more_documents_than_the_limit_are_rejected() {
    let documents: String = (0..4)
        .map(|index| document(index, "hello.txt", Some("txt"), 1, &["base64"], "eA=="))
        .collect();
    let limits = Limits {
        max_documents: 3,
        ..Limits::default()
    };
    assert_eq!(
        error_code_with(&dossier_with(&documents), &limits),
        ErrorCode::TooManyDocuments
    );
    assert!(parse(dossier_with(&documents).as_bytes(), &Limits::default()).is_ok());
}

#[test]
fn a_root_element_with_another_name_is_the_wrong_root() {
    let renamed = PLAIN
        .replace("<es:Dossier ", "<es:Envelope ")
        .replace("</es:Dossier>", "</es:Envelope>");
    assert_eq!(error_code(&renamed), ErrorCode::WrongRoot);
}

#[test]
fn a_root_element_in_another_namespace_is_the_wrong_root() {
    let renamespaced = PLAIN.replace(
        "https://www.microsec.hu/ds/e-szigno30#",
        "https://example.invalid/ds/e-szigno30#",
    );
    assert_eq!(error_code(&renamespaced), ErrorCode::WrongRoot);
}

#[test]
fn signatures_and_timestamps_are_counted_but_never_verified() {
    let with_material = PLAIN.replace(
        "</es:Documents>",
        "</es:Documents><ds:Signature Id=\"Signature1\"><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature><es:TimeStamp Id=\"TimeStamp1\"/>",
    );
    let dossier = parse(with_material.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.signatures_present, 1);
    assert_eq!(dossier.timestamps_present, 1);
}

#[test]
fn an_optional_category_is_reported_only_when_it_has_a_value() {
    let dossier = parse(PLAIN.as_bytes(), &Limits::default()).expect("fixture parses");
    assert_eq!(dossier.category.as_deref(), Some("electronic dossier"));

    let empty = PLAIN.replace(
        "<es:E-category>electronic dossier</es:E-category>",
        "<es:E-category></es:E-category>",
    );
    let dossier = parse(empty.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.category, None);

    let absent = PLAIN.replace("<es:E-category>electronic dossier</es:E-category>", "");
    let dossier = parse(absent.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.category, None);
}

#[test]
fn mime_metadata_is_reported_from_either_charset_spelling() {
    let dossier = parse(PLAIN.as_bytes(), &Limits::default()).expect("fixture parses");
    let mime = &dossier.documents[0].mime_type;
    assert_eq!(mime.essence(), "text/plain");
    assert_eq!(mime.extension.as_deref(), Some("txt"));
    assert_eq!(mime.charset.as_deref(), Some("UTF-8"));

    let lowercase = PLAIN.replace("charSet=\"UTF-8\"", "charset=\"UTF-8\"");
    let dossier = parse(lowercase.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(
        dossier.documents[0].mime_type.charset.as_deref(),
        Some("UTF-8")
    );

    let none = PLAIN
        .replace(" charSet=\"UTF-8\"", "")
        .replace(" extension=\"txt\"", "");
    let dossier = parse(none.as_bytes(), &Limits::default()).expect("dossier parses");
    assert_eq!(dossier.documents[0].mime_type.charset, None);
    assert_eq!(dossier.documents[0].mime_type.extension, None);
}

#[test]
fn documents_keep_their_source_order() {
    let documents: String = ["first.txt", "second.txt", "third.txt"]
        .iter()
        .enumerate()
        .map(|(index, title)| document(index, title, Some("txt"), 1, &["base64"], "eA=="))
        .collect();
    let dossier =
        parse(dossier_with(&documents).as_bytes(), &Limits::default()).expect("dossier parses");
    let titles: Vec<&str> = dossier
        .documents
        .iter()
        .map(|document| document.title.as_str())
        .collect();
    assert_eq!(titles, ["first.txt", "second.txt", "third.txt"]);
    assert_eq!(dossier.documents[2].index, 2);
}

#[test]
fn the_parsers_own_node_limit_is_a_backstop_for_non_element_nodes() {
    // The pre-scan counts elements only, so a document made almost entirely of
    // comments has to be stopped by the tree parser's own limit.
    let comments = "<!-- c -->".repeat(64);
    let xml = format!(
        r#"<?xml version="1.0"?><es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#">{comments}<a/><b/></es:Dossier>"#
    );
    let limits = Limits {
        max_xml_nodes: 3,
        ..Limits::default()
    };
    assert_eq!(error_code_with(&xml, &limits), ErrorCode::UnsafeXml);
}
