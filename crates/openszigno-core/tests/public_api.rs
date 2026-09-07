//! The stable surface other tools depend on: error codes, limits, and the
//! serialised shape of the model types.

mod common;

use common::{base64_dossier, document, dossier_with};
use openszigno_core::{
    ESZIGNO_NAMESPACE, ErrorCode, Limits, UnsupportedReason, XMLDSIG_NAMESPACE, parse,
};
use serde_json::{Value, json};

const ALL_CODES: [(ErrorCode, &str); 20] = [
    (ErrorCode::InputTooLarge, "input_too_large"),
    (ErrorCode::UnsupportedEncoding, "unsupported_encoding"),
    (ErrorCode::InvalidEncoding, "invalid_encoding"),
    (ErrorCode::UnsafeXml, "unsafe_xml"),
    (ErrorCode::InvalidXml, "invalid_xml"),
    (ErrorCode::WrongRoot, "wrong_root"),
    (ErrorCode::MissingElement, "missing_element"),
    (ErrorCode::InvalidAttribute, "invalid_attribute"),
    (ErrorCode::DuplicateId, "duplicate_id"),
    (ErrorCode::UnresolvedObjref, "unresolved_objref"),
    (ErrorCode::TooManyDocuments, "too_many_documents"),
    (ErrorCode::InvalidBase64, "invalid_base64"),
    (ErrorCode::DecodedTooLarge, "decoded_too_large"),
    (ErrorCode::SourceSizeMismatch, "source_size_mismatch"),
    (ErrorCode::InvalidZip, "invalid_zip"),
    (ErrorCode::ZipMemberLimit, "zip_member_limit"),
    (ErrorCode::ZipSizeLimit, "zip_size_limit"),
    (ErrorCode::ZipRatioLimit, "zip_ratio_limit"),
    (ErrorCode::UnsafeZipMember, "unsafe_zip_member"),
    (ErrorCode::UnsupportedZipMember, "unsupported_zip_member"),
];

#[test]
fn every_error_code_has_the_documented_stable_string() {
    for (code, expected) in ALL_CODES {
        assert_eq!(code.as_str(), expected);
    }
}

#[test]
fn error_codes_serialise_exactly_as_they_print() {
    for (code, expected) in ALL_CODES {
        assert_eq!(
            serde_json::to_value(code).expect("an error code serialises"),
            Value::String(expected.to_owned()),
        );
    }
}

#[test]
fn error_codes_are_distinct_and_comparable() {
    for (index, (code, _)) in ALL_CODES.iter().enumerate() {
        for (other, _) in &ALL_CODES[index + 1..] {
            assert_ne!(code, other);
        }
        assert_eq!(*code, *code);
        assert!(format!("{code:?}").len() > 2);
    }
}

#[test]
fn an_error_carries_its_code_and_a_message() {
    let error = parse(b"not xml at all", &Limits::default()).expect_err("must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidXml);
    assert!(!error.message().is_empty());
    assert_eq!(error.to_string(), error.message());
    assert!(format!("{error:?}").contains("InvalidXml"));
}

#[test]
fn unsupported_reasons_serialise_in_snake_case() {
    assert_eq!(
        serde_json::to_value(UnsupportedReason::Encrypted).expect("serialises"),
        json!("encrypted")
    );
    assert_eq!(
        serde_json::to_value(UnsupportedReason::TransformChain).expect("serialises"),
        json!("transform_chain")
    );
    assert_eq!(UnsupportedReason::Encrypted, UnsupportedReason::Encrypted);
    assert_ne!(
        UnsupportedReason::Encrypted,
        UnsupportedReason::TransformChain
    );
}

#[test]
fn the_default_limits_serialise_with_their_documented_values() {
    let limits = serde_json::to_value(Limits::default()).expect("limits serialise");
    assert_eq!(
        limits,
        json!({
            "max_input_bytes": 67_108_864u64,
            "max_documents": 256,
            "max_base64_chars": 100_663_296u64,
            "max_decoded_document_bytes": 67_108_864u64,
            "max_total_decoded_bytes": 268_435_456u64,
            "max_zip_members": 16,
            "max_zip_expanded_bytes": 67_108_864u64,
            "max_zip_compression_ratio": 100,
            "max_xml_depth": 128,
            "max_xml_nodes": 1_000_000
        })
    );
}

#[test]
fn limits_can_be_cloned_and_narrowed_for_callers() {
    let limits = Limits {
        max_documents: 1,
        ..Limits::default()
    };
    let clone = limits.clone();
    assert_eq!(clone.max_documents, 1);
    assert_eq!(clone.max_input_bytes, Limits::default().max_input_bytes);
    assert!(format!("{limits:?}").contains("max_documents"));
}

#[test]
fn the_published_namespaces_are_the_e_szigno_and_xmldsig_ones() {
    assert_eq!(ESZIGNO_NAMESPACE, "https://www.microsec.hu/ds/e-szigno30#");
    assert_eq!(XMLDSIG_NAMESPACE, "http://www.w3.org/2000/09/xmldsig#");
}

#[test]
fn a_serialised_document_never_carries_its_payload() {
    let dossier =
        parse(base64_dossier(b"payload").as_bytes(), &Limits::default()).expect("dossier parses");
    let value = serde_json::to_value(&dossier).expect("dossier serialises");
    assert_eq!(value["namespace"], ESZIGNO_NAMESPACE);
    assert_eq!(value["xml_encoding"], "UTF-8");
    assert_eq!(value["signatures_present"], 0);
    assert_eq!(value["timestamps_present"], 0);

    let document = &value["documents"][0];
    assert_eq!(document["index"], 0);
    assert_eq!(document["title"], "payload.txt");
    assert_eq!(document["source_size"], 7);
    assert_eq!(document["object_ref"], "DocumentObject1");
    assert_eq!(document["transforms"], json!(["base64"]));
    assert_eq!(document["mime_type"]["media_type"], "text");
    assert_eq!(document["mime_type"]["subtype"], "plain");
    assert!(
        document.get("payload").is_none(),
        "payload bytes must never be serialised"
    );
    assert!(
        !serde_json::to_string(&dossier)
            .expect("dossier serialises")
            .contains("cGF5bG9hZA"),
        "the encoded payload must not appear in the serialised dossier"
    );
}

#[test]
fn a_mime_essence_joins_the_media_type_and_subtype() {
    let documents = document(1, "payload.bin", None, 1, &["base64"], "eA==").replace(
        "type=\"text\" subtype=\"plain\"",
        "type=\"APPLICATION\" subtype=\"x-custom+xml\"",
    );
    let dossier =
        parse(dossier_with(&documents).as_bytes(), &Limits::default()).expect("dossier parses");
    let mime = dossier.documents[0].mime_type.clone();
    assert_eq!(mime.essence(), "APPLICATION/x-custom+xml");
    assert_eq!(mime.extension, None);
}
