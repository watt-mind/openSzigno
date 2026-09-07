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

/// Wrap a `zip -> base64` payload in a minimal synthetic dossier.
fn zip_dossier(archive: &[u8], source_size: u64) -> String {
    let payload = STANDARD.encode(archive);
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
<es:DossierProfile Id="p0" OBJREF="Object0"><es:Title>test</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate></es:DossierProfile>
<es:Documents Id="Object0"><es:Document><es:DocumentProfile Id="p1" OBJREF="o1"><es:Title>member.bin</es:Title><es:CreationDate>2026-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="application" subtype="octet-stream" extension="bin"/></es:Format><es:SourceSize sizeValue="{source_size}" sizeUnit="B"/><es:BaseTransform><es:Transform Algorithm="zip"/><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="o1">{payload}</ds:Object></es:Document></es:Documents>
</es:Dossier>"#
    )
}

fn single_member_zip(
    name: &str,
    contents: &[u8],
    options: zip::write::SimpleFileOptions,
) -> Vec<u8> {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        writer.start_file(name, options).unwrap();
        writer.write_all(contents).unwrap();
        writer.finish().unwrap();
    }
    archive.into_inner()
}

#[test]
fn rejects_deep_nesting_before_tree_construction() {
    // Deep enough to overflow the parser's recursion without a pre-scan.
    let depth = 200_000;
    let mut xml = String::from(
        r#"<?xml version="1.0"?><es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#">"#,
    );
    for _ in 0..depth {
        xml.push_str("<a>");
    }
    for _ in 0..depth {
        xml.push_str("</a>");
    }
    xml.push_str("</es:Dossier>");
    let error = parse(xml.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsafeXml);
}

#[test]
fn rejects_excessive_element_counts() {
    let mut xml = String::from(
        r#"<?xml version="1.0"?><es:Dossier xmlns:es="https://www.microsec.hu/ds/e-szigno30#">"#,
    );
    for _ in 0..1_000 {
        xml.push_str("<a/>");
    }
    xml.push_str("</es:Dossier>");
    let limits = Limits {
        max_xml_nodes: 500,
        ..Limits::default()
    };
    let error = parse(xml.as_bytes(), &limits).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsafeXml);
}

#[test]
fn encoding_is_read_only_from_the_xml_declaration() {
    let plain = include_str!("../../../tests/fixtures/plain-base64.es3");
    let spoofed = plain
        .replace(
            r#"<?xml version="1.0" encoding="UTF-8"?>"#,
            r#"<?xml version="1.0"?><!-- encoding='ISO-8859-2' -->"#,
        )
        .replace("Unsigned synthetic plain fixture", "Árvíztűrő tükörfúrógép");
    let dossier = parse(spoofed.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(dossier.xml_encoding, "UTF-8");
    assert_eq!(dossier.title, "Árvíztűrő tükörfúrógép");

    let single_quoted = plain.replace(
        r#"<?xml version="1.0" encoding="UTF-8"?>"#,
        "<?xml version='1.0'  encoding = 'utf-8' ?>",
    );
    assert!(parse(single_quoted.as_bytes(), &Limits::default()).is_ok());

    let unsupported = plain.replace("encoding=\"UTF-8\"", "encoding=\"UTF-16\"");
    let error = parse(unsupported.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsupportedEncoding);
}

#[test]
fn parse_errors_do_not_echo_document_content() {
    let plain = include_str!("../../../tests/fixtures/plain-base64.es3");
    let broken = plain.replace("</es:Title>", "</es:SecretTagName>");
    let error = parse(broken.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidXml);
    assert!(!error.message().contains("Secret"));
    assert!(!error.message().contains("Title"));

    let entity = plain.replace("hello.txt", "&secretentity;");
    let error = parse(entity.as_bytes(), &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::InvalidXml);
    assert!(!error.message().contains("secretentity"));
}

#[test]
fn markup_like_text_inside_cdata_is_not_a_dtd() {
    let plain = include_str!("../../../tests/fixtures/plain-base64.es3");
    let cdata = plain.replace(
        "Unsigned synthetic plain fixture",
        "<![CDATA[<!DOCTYPE note> <!ENTITY x>]]>",
    );
    let dossier = parse(cdata.as_bytes(), &Limits::default()).unwrap();
    assert_eq!(dossier.title, "<!DOCTYPE note> <!ENTITY x>");

    let doctype = parse(&fixture("doctype.es3"), &Limits::default()).unwrap_err();
    assert_eq!(doctype.code(), ErrorCode::UnsafeXml);
}

#[test]
fn prefixed_attributes_do_not_join_the_id_space() {
    let plain = include_str!("../../../tests/fixtures/plain-base64.es3");
    let prefixed = plain.replace(
        "<es:Title>hello.txt</es:Title>",
        "<es:Title es:Id=\"DossierProfile1\">hello.txt</es:Title>",
    );
    assert!(parse(prefixed.as_bytes(), &Limits::default()).is_ok());
}

#[test]
fn zip_ratio_is_checked_on_actual_decoded_bytes() {
    let contents = vec![0u8; 2 * 1024 * 1024];
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut archive = single_member_zip("zeros.bin", &contents, options);
    let compressed_len = archive.len() as u64;
    assert!(compressed_len * 100 < contents.len() as u64);

    // Patch every uncompressed-size field (local header and central directory)
    // down to a value that passes the header-based ratio pre-filter.
    let real = (contents.len() as u32).to_le_bytes();
    let fake = (compressed_len as u32 * 10).to_le_bytes();
    let mut position = 0;
    let mut patched = 0;
    while position + 4 <= archive.len() {
        if archive[position..position + 4] == real {
            archive[position..position + 4].copy_from_slice(&fake);
            patched += 1;
            position += 4;
        } else {
            position += 1;
        }
    }
    assert!(patched >= 2, "uncompressed size fields must be patched");

    let dossier = parse(
        zip_dossier(&archive, contents.len() as u64).as_bytes(),
        &Limits::default(),
    )
    .unwrap();
    let error = dossier.decode_document(0, &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ZipRatioLimit);
}

#[test]
fn encrypted_zip_members_are_reported_as_unsupported() {
    // Set the general-purpose "encrypted" flag in the local header and the
    // central directory of an otherwise ordinary stored member.
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let mut archive = single_member_zip("secret.bin", b"x", options);
    assert_eq!(&archive[..4], b"PK\x03\x04");
    archive[6] |= 1;
    let central = archive
        .windows(4)
        .position(|window| window == b"PK\x01\x02")
        .unwrap();
    archive[central + 8] |= 1;
    let dossier = parse(zip_dossier(&archive, 1).as_bytes(), &Limits::default()).unwrap();
    let error = dossier.decode_document(0, &Limits::default()).unwrap_err();
    assert_eq!(error.code(), ErrorCode::UnsupportedZipMember);
}

#[test]
fn stored_zip_members_decode() {
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    let archive = single_member_zip("stored.txt", b"stored", options);
    let dossier = parse(zip_dossier(&archive, 6).as_bytes(), &Limits::default()).unwrap();
    let DecodeOutcome::Decoded(decoded) = dossier.decode_document(0, &Limits::default()).unwrap()
    else {
        panic!("stored member must decode");
    };
    assert_eq!(decoded.bytes, b"stored");
}
