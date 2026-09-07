//! Namespace policy, structural warnings, and nested-dossier detection.

mod common;

use common::{
    CEGELJARAS_2014, COMPATIBLE, NESTED, base64_dossier, document, document_without_source_size,
    dossier_with, in_namespace, nesting_dossier,
};
use openszigno_core::{
    DecodeOutcome, ESZIGNO_NAMESPACE, ErrorCode, KNOWN_COMPATIBLE_NAMESPACES, Limits, ParseOptions,
    StructuralWarningCode, parse, parse_with_options,
};
use serde_json::{Value, json};

fn parsed(xml: &str) -> openszigno_core::Dossier {
    parse(xml.as_bytes(), &Limits::default()).expect("this dossier must parse")
}

#[test]
fn the_known_namespaces_are_the_default_one_and_four_company_court_generations() {
    assert_eq!(KNOWN_COMPATIBLE_NAMESPACES.len(), 5);
    assert_eq!(KNOWN_COMPATIBLE_NAMESPACES[0], ESZIGNO_NAMESPACE);
    for year in ["2007", "2009", "2012", "2014"] {
        let expected = format!("http://www.e-cegjegyzek.hu/{year}/e-cegeljaras#");
        assert!(
            KNOWN_COMPATIBLE_NAMESPACES.contains(&expected.as_str()),
            "{year} must be a known-compatible namespace"
        );
    }
}

#[test]
fn every_known_namespace_is_parsed_and_reported_verbatim() {
    for namespace in KNOWN_COMPATIBLE_NAMESPACES {
        let xml = in_namespace(&base64_dossier(b"payload"), namespace);
        let dossier = parsed(&xml);
        assert_eq!(&dossier.namespace, namespace);
        assert_eq!(dossier.documents.len(), 1);
        assert_eq!(dossier.documents[0].title, "payload.txt");
    }
}

#[test]
fn an_unknown_namespace_is_wrong_root_without_echoing_the_uri() {
    let namespace = "https://example.invalid/secret-tenant-42#";
    let xml = in_namespace(&base64_dossier(b"payload"), namespace);
    let error = parse(xml.as_bytes(), &Limits::default()).expect_err("must be rejected");
    assert_eq!(error.code(), ErrorCode::WrongRoot);
    assert!(
        error.message().contains("namespace") && error.message().contains("not allowed"),
        "the message must say the namespace is not allowed: {}",
        error.message()
    );
    assert!(
        !error.message().contains(namespace),
        "the namespace URI must never be echoed"
    );
}

#[test]
fn another_root_element_is_still_wrong_root() {
    let xml = base64_dossier(b"payload")
        .replace("<es:Dossier ", "<es:Folder ")
        .replace("</es:Dossier>", "</es:Folder>");
    let error = parse(xml.as_bytes(), &Limits::default()).expect_err("must be rejected");
    assert_eq!(error.code(), ErrorCode::WrongRoot);
    assert!(error.message().contains("Dossier"));
}

#[test]
fn a_caller_can_widen_the_allow_list_but_the_defaults_stay() {
    let namespace = "https://example.invalid/private-profile#";
    let xml = in_namespace(&base64_dossier(b"payload"), namespace);
    assert_eq!(
        parse(xml.as_bytes(), &Limits::default())
            .expect_err("the default policy rejects it")
            .code(),
        ErrorCode::WrongRoot
    );

    let mut options = ParseOptions::default();
    options.allowed_namespaces.push(namespace.to_owned());
    assert_eq!(
        parse_with_options(xml.as_bytes(), &options)
            .expect("the widened policy accepts it")
            .namespace,
        namespace
    );
    // The known namespaces still parse under the widened policy.
    assert!(parse_with_options(base64_dossier(b"payload").as_bytes(), &options).is_ok());
}

#[test]
fn an_empty_allow_list_accepts_nothing() {
    let options = ParseOptions {
        limits: Limits::default(),
        allowed_namespaces: Vec::new(),
    };
    assert_eq!(
        parse_with_options(base64_dossier(b"payload").as_bytes(), &options)
            .expect_err("nothing is allowed")
            .code(),
        ErrorCode::WrongRoot
    );
}

#[test]
fn parse_options_carry_the_caller_limits_with_the_known_namespaces() {
    let options = ParseOptions::with_limits(Limits {
        max_documents: 1,
        ..Limits::default()
    });
    assert_eq!(options.limits.max_documents, 1);
    assert_eq!(
        options.allowed_namespaces.len(),
        KNOWN_COMPATIBLE_NAMESPACES.len()
    );
    assert!(format!("{options:?}").contains("allowed_namespaces"));
    assert_eq!(
        options.clone().allowed_namespaces,
        ParseOptions::default().allowed_namespaces
    );
}

#[test]
fn element_lookups_follow_the_dossiers_own_namespace() {
    // A dossier that mixes the default namespace into a company-court dossier
    // is missing the elements it must carry in its own namespace.
    let mixed = in_namespace(&base64_dossier(b"payload"), CEGELJARAS_2014).replace(
        "<es:Documents ",
        "<es:Documents xmlns:es=\"https://www.microsec.hu/ds/e-szigno30#\" ",
    );
    assert_eq!(
        parse(mixed.as_bytes(), &Limits::default())
            .expect_err("the Documents element is in the wrong namespace")
            .code(),
        ErrorCode::MissingElement
    );
}

#[test]
fn a_timestamp_is_counted_in_the_dossiers_own_namespace() {
    let documents = format!(
        "{}<es:TimeStamp>token</es:TimeStamp>",
        document(1, "a.txt", Some("txt"), 1, &["base64"], "eA==")
    );
    let dossier = parsed(&in_namespace(&dossier_with(&documents), CEGELJARAS_2014));
    assert_eq!(dossier.timestamps_present, 1);
}

#[test]
fn a_dangling_reference_outside_the_profiles_is_a_warning() {
    let documents = format!(
        "{}<es:SignatureProfile OBJREF=\"Nothing\"/>",
        document(1, "a.txt", Some("txt"), 1, &["base64"], "eA==")
    );
    let dossier = parsed(&dossier_with(&documents));
    assert_eq!(dossier.documents.len(), 1);
    assert_eq!(dossier.warnings.len(), 1);
    assert_eq!(
        dossier.warnings[0].code,
        StructuralWarningCode::DanglingObjref
    );
    assert!(dossier.warnings[0].message.contains("SignatureProfile"));
}

#[test]
fn a_dangling_reference_on_a_profile_is_still_a_hard_error() {
    let broken =
        base64_dossier(b"payload").replace("OBJREF=\"DocumentObject1\"", "OBJREF=\"Gone\"");
    assert_eq!(
        parse(broken.as_bytes(), &Limits::default())
            .expect_err("a document profile must resolve")
            .code(),
        ErrorCode::UnresolvedObjref
    );
    let broken = base64_dossier(b"payload").replace("OBJREF=\"Object0\"", "OBJREF=\"Gone\"");
    assert_eq!(
        parse(broken.as_bytes(), &Limits::default())
            .expect_err("the dossier profile must resolve")
            .code(),
        ErrorCode::UnresolvedObjref
    );
}

#[test]
fn a_duplicate_id_is_still_a_hard_error_alongside_warnings() {
    let documents = format!(
        "{}<es:SignatureProfile Id=\"DocumentProfile1\" OBJREF=\"Nothing\"/>",
        document(1, "a.txt", Some("txt"), 1, &["base64"], "eA==")
    );
    assert_eq!(
        parse(dossier_with(&documents).as_bytes(), &Limits::default())
            .expect_err("IDs must be unique")
            .code(),
        ErrorCode::DuplicateId
    );
}

#[test]
fn a_warning_never_echoes_an_element_name_that_is_not_a_plain_one() {
    let documents = format!(
        "{}<es:x.y.z-\u{e9}\u{e9} OBJREF=\"Nothing\"/>",
        document(1, "a.txt", Some("txt"), 1, &["base64"], "eA==")
    );
    let dossier = parsed(&dossier_with(&documents));
    assert_eq!(dossier.warnings.len(), 1);
    assert!(
        dossier.warnings[0].message.starts_with("an element "),
        "an unusual element name is not echoed: {}",
        dossier.warnings[0].message
    );
}

/// Some company-court dossiers omit `SourceSize`; the document is still read,
/// and nothing is compared against a size that was never declared.
#[test]
fn a_document_without_a_source_size_is_reported_but_kept() {
    let xml = dossier_with(&document_without_source_size(1, "ruling.txt", b"payload"));
    let dossier = parsed(&xml);
    assert_eq!(dossier.documents.len(), 1);
    assert_eq!(dossier.documents[0].source_size, None);
    assert_eq!(dossier.warnings.len(), 1);
    assert_eq!(
        dossier.warnings[0].code,
        StructuralWarningCode::SourceSizeMissing
    );
    assert!(dossier.warnings[0].message.contains("document 0"));
    assert!(
        !dossier.warnings[0].message.contains("ruling"),
        "the warning must not echo the title"
    );

    let DecodeOutcome::Decoded(decoded) = dossier
        .decode_document(0, &Limits::default())
        .expect("the payload decodes without a declared size")
    else {
        panic!("the payload is not encrypted");
    };
    assert_eq!(decoded.bytes, b"payload");

    let value = serde_json::to_value(&dossier).expect("a dossier serialises");
    assert_eq!(value["documents"][0]["source_size"], Value::Null);
}

#[test]
fn a_declared_source_size_is_still_checked() {
    let dossier = parsed(&base64_dossier(b"payload"));
    assert_eq!(dossier.documents[0].source_size, Some(7));
    assert!(dossier.warnings.is_empty());

    // The declared-size rules are unchanged when the element is present.
    let wrong = base64_dossier(b"payload").replace("sizeValue=\"7\"", "sizeValue=\"8\"");
    let dossier = parsed(&wrong);
    assert_eq!(
        dossier
            .decode_document(0, &Limits::default())
            .expect_err("the declared size is wrong")
            .code(),
        ErrorCode::SourceSizeMismatch
    );

    let unit = base64_dossier(b"payload").replace("sizeUnit=\"B\"", "sizeUnit=\"kB\"");
    assert_eq!(
        parse(unit.as_bytes(), &Limits::default())
            .expect_err("the unit must be B")
            .code(),
        ErrorCode::InvalidAttribute
    );

    let over = base64_dossier(b"payload").replace("sizeValue=\"7\"", "sizeValue=\"999999999999\"");
    assert_eq!(
        parse(over.as_bytes(), &Limits::default())
            .expect_err("the declared size is above the limit")
            .code(),
        ErrorCode::DecodedTooLarge
    );
}

#[test]
fn two_source_size_elements_are_invalid_xml() {
    let duplicated = base64_dossier(b"payload").replace(
        "<es:SourceSize sizeValue=\"7\" sizeUnit=\"B\"/>",
        "<es:SourceSize sizeValue=\"7\" sizeUnit=\"B\"/><es:SourceSize sizeValue=\"7\" sizeUnit=\"B\"/>",
    );
    assert_eq!(
        parse(duplicated.as_bytes(), &Limits::default())
            .expect_err("one SourceSize is allowed")
            .code(),
        ErrorCode::InvalidXml
    );
}

#[test]
fn structural_warnings_serialise_with_their_stable_codes() {
    for (code, expected) in [
        (StructuralWarningCode::DanglingObjref, "dangling_objref"),
        (
            StructuralWarningCode::DocumentWithoutProfile,
            "document_without_profile",
        ),
        (
            StructuralWarningCode::SourceSizeMissing,
            "source_size_missing",
        ),
    ] {
        assert_eq!(code.as_str(), expected);
        assert_eq!(
            serde_json::to_value(code).expect("a warning code serialises"),
            Value::String(expected.to_owned())
        );
    }
    assert_ne!(
        StructuralWarningCode::DanglingObjref,
        StructuralWarningCode::DocumentWithoutProfile
    );
    assert_eq!(
        StructuralWarningCode::DanglingObjref,
        StructuralWarningCode::DanglingObjref
    );
    assert!(format!("{:?}", StructuralWarningCode::DanglingObjref).contains("Dangling"));

    let dossier = parsed(&base64_dossier(b"payload"));
    let value = serde_json::to_value(&dossier).expect("a dossier serialises");
    assert_eq!(value["warnings"], json!([]));
    assert_eq!(value["documents"][0]["nested_dossier"], false);
}

#[test]
fn a_nested_dossier_is_recognised_by_media_type_or_by_extension() {
    let inner = base64_dossier(b"inner");
    for (subtype, extension, nested) in [
        ("nldossier2", None, true),
        ("NLDossier2", None, true),
        ("octet-stream", Some("dosszie"), true),
        ("octet-stream", Some("DOSSZIE"), true),
        ("octet-stream", Some("bin"), false),
        ("octet-stream", None, false),
    ] {
        let dossier = parsed(&nesting_dossier(&inner, subtype, extension));
        assert_eq!(
            dossier.documents[0].nested_dossier, nested,
            "{subtype}/{extension:?} must be {nested}"
        );
    }
}

#[test]
fn the_committed_nesting_fixture_carries_a_dossier_payload() {
    let dossier = parsed(NESTED);
    assert_eq!(dossier.documents.len(), 1);
    assert!(dossier.documents[0].nested_dossier);
    assert_eq!(dossier.documents[0].title, "court.dosszie");
    assert!(dossier.warnings.is_empty());

    let DecodeOutcome::Decoded(decoded) = dossier
        .decode_document(0, &Limits::default())
        .expect("the payload decodes")
    else {
        panic!("the payload is not encrypted");
    };
    assert_eq!(
        openszigno_core::sniff(&decoded.bytes),
        openszigno_core::DetectedType::Dossier
    );
    let inner = parse(&decoded.bytes, &Limits::default()).expect("the inner dossier parses");
    assert_eq!(inner.documents.len(), 1);
    assert_eq!(inner.documents[0].title, "inner.txt");
}

#[test]
fn the_committed_compatible_fixture_parses_with_both_warnings() {
    let dossier = parsed(COMPATIBLE);
    assert_eq!(dossier.namespace, CEGELJARAS_2014);
    assert_eq!(dossier.documents.len(), 1);
    assert_eq!(dossier.documents[0].title, "ruling.txt");
    assert_eq!(dossier.signatures_present, 0);

    let codes: Vec<StructuralWarningCode> = dossier
        .warnings
        .iter()
        .map(|warning| warning.code)
        .collect();
    assert_eq!(
        codes,
        [
            StructuralWarningCode::DanglingObjref,
            StructuralWarningCode::DocumentWithoutProfile
        ]
    );
}

/// The aggregate decode budget is enforced by the caller, so a core-level test
/// shows what a nested tree costs: the payload plus everything inside it.
#[test]
fn a_nested_tree_decodes_to_more_than_the_outer_payload() {
    let inner = base64_dossier(b"inner payload");
    let outer = parsed(&nesting_dossier(&inner, "nldossier2", Some("dosszie")));
    let DecodeOutcome::Decoded(payload) = outer
        .decode_document(0, &Limits::default())
        .expect("the payload decodes")
    else {
        panic!("the payload is not encrypted");
    };
    let nested = parse(&payload.bytes, &Limits::default()).expect("the inner dossier parses");
    let DecodeOutcome::Decoded(leaf) = nested
        .decode_document(0, &Limits::default())
        .expect("the leaf decodes")
    else {
        panic!("the leaf is not encrypted");
    };
    let total = payload.bytes.len() + leaf.bytes.len();
    assert!(total > payload.bytes.len());

    // A budget that fits the outer payload alone is exceeded by the tree.
    let limits = Limits {
        max_total_decoded_bytes: payload.bytes.len() as u64,
        ..Limits::default()
    };
    assert!(total as u64 > limits.max_total_decoded_bytes);
}
