use std::io::Write;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use openszigno_core::{DecodeOutcome, ErrorCode, Limits, UnsupportedReason, parse};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(fixture_path(name)).expect("synthetic fixture must be readable")
}

fn fixture_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

#[test]
fn parses_and_decodes_plain_fixture() {
    let dossier = parse(&fixture("plain-base64.es3"), &Limits::default()).unwrap();
    assert_eq!(dossier.documents.len(), 1);
    assert_eq!(dossier.signatures_present, 0);
    assert_eq!(dossier.xml_encoding, "UTF-8");
    let DecodeOutcome::Decoded(decoded) = dossier.decode_document(0, &Limits::default()).unwrap()
    else {
        panic!("plain fixture must be supported");
    };
    assert_eq!(decoded.bytes, b"Hello from openSzigno synthetic fixture.\n");
}

#[test]
fn reverses_zip_then_base64() {
    let dossier = parse(&fixture("zip-base64.es3"), &Limits::default()).unwrap();
    let DecodeOutcome::Decoded(decoded) = dossier.decode_document(0, &Limits::default()).unwrap()
    else {
        panic!("ZIP fixture must be supported");
    };
    assert_eq!(decoded.bytes, b"Zipped openSzigno synthetic fixture.\n");
}

#[test]
fn rejects_duplicate_ids_and_unresolved_references() {
    let duplicate = parse(&fixture("duplicate-id.es3"), &Limits::default()).unwrap_err();
    assert_eq!(duplicate.code(), ErrorCode::DuplicateId);

    let unresolved = parse(&fixture("unresolved-objref.es3"), &Limits::default()).unwrap_err();
    assert_eq!(unresolved.code(), ErrorCode::UnresolvedObjref);
}

#[test]
fn binds_profiles_to_their_direct_payload_containers() {
    let plain = include_str!("../../../tests/fixtures/plain-base64.es3");
    let wrong_dossier_ref = plain.replacen("OBJREF=\"Object0\"", "OBJREF=\"DocumentObject1\"", 1);
    let error = parse(wrong_dossier_ref.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnresolvedObjref);

    let extra_payload = plain.replace(
        "</es:Document>",
        "<ds:Object Id=\"ExtraObject\">eA==</ds:Object></es:Document>",
    );
    let error = parse(extra_payload.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidXml);
}

#[test]
fn rejects_doctype_before_xml_parsing() {
    let error = parse(&fixture("doctype.es3"), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsafeXml);
}

#[test]
fn rejects_invalid_base64_during_decode() {
    let dossier = parse(&fixture("invalid-base64.es3"), &Limits::default()).unwrap();
    let error = dossier.decode_document(0, &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidBase64);
}

#[test]
fn reports_encryption_without_decoding() {
    let dossier = parse(&fixture("encrypted.es3"), &Limits::default()).unwrap();
    let outcome = dossier.decode_document(0, &Limits::default()).unwrap();
    assert!(matches!(
        outcome,
        DecodeOutcome::Unsupported(UnsupportedReason::Encrypted)
    ));
}

#[test]
fn enforces_input_and_zip_ratio_limits() {
    let limits = Limits {
        max_input_bytes: 8,
        ..Limits::default()
    };
    let error = parse(&fixture("plain-base64.es3"), &limits).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InputTooLarge);

    let dossier = parse(&fixture("zip-base64.es3"), &Limits::default()).unwrap();
    let strict_zip = Limits {
        max_zip_compression_ratio: 0,
        ..Limits::default()
    };
    let error = dossier.decode_document(0, &strict_zip).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ZipRatioLimit);
}

#[test]
fn supports_iso_8859_2_xml_declarations() {
    let utf8 = include_str!("../../../tests/fixtures/plain-base64.es3")
        .replace("encoding=\"UTF-8\"", "encoding=\"ISO-8859-2\"")
        .replace("Unsigned synthetic plain fixture", "Árvíztűrő tükörfúrógép");
    let encoding = encoding_rs::Encoding::for_label(b"iso-8859-2").unwrap();
    let (encoded, _, had_errors) = encoding.encode(&utf8);
    assert!(!had_errors);
    let dossier = parse(&encoded, &Limits::default()).unwrap();
    assert_eq!(dossier.xml_encoding, "ISO-8859-2");
    assert_eq!(dossier.title, "Árvíztűrő tükörfúrógép");
}

#[test]
fn rejects_unsafe_zip_member_paths() {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        writer
            .start_file("../escape.txt", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(b"x").unwrap();
        writer.finish().unwrap();
    }
    let payload = STANDARD.encode(archive.into_inner());
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<es:DossierProfile Id="p0" OBJREF="Object0"><es:Title>test</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0"><es:Document><es:DocumentProfile Id="p1" OBJREF="o1"><es:Title>safe.txt</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain" extension="txt"/></es:Format><es:SourceSize sizeValue="1" sizeUnit="B"/><es:BaseTransform><es:Transform Algorithm="zip"/><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="o1">{payload}</ds:Object></es:Document></es:Documents>
</es:Dossier>"#
    );
    let dossier = parse(xml.as_bytes(), &Limits::default()).unwrap();
    let error = dossier.decode_document(0, &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsafeZipMember);
}
