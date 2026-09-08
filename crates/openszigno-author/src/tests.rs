//! Unit tests for the crate root: the XML a build produces, the bounds it
//! refuses, and the round trip back through the reader.

use super::*;

use openszigno_core::{DecodeOutcome, Limits};

const CREATED: &str = "2026-01-01T00:00:00Z";

fn document(title: &str, bytes: &[u8]) -> DocumentSpec {
    DocumentSpec {
        title: title.to_owned(),
        media_type: None,
        bytes: bytes.to_vec(),
        compress: false,
        encrypt: false,
    }
}

fn spec(documents: Vec<DocumentSpec>) -> DossierSpec {
    DossierSpec {
        title: "Synthetic authoring test".to_owned(),
        created: CREATED.to_owned(),
        documents,
        encryption: None,
    }
}

fn built(documents: Vec<DocumentSpec>) -> BuiltDossier {
    build(&spec(documents), &Limits::default()).expect("the dossier must build")
}

fn text_of(dossier: &BuiltDossier) -> String {
    String::from_utf8(dossier.bytes.clone()).expect("the output is UTF-8")
}

#[test]
fn a_one_document_dossier_has_the_expected_shape() {
    let dossier = built(vec![document("hello.txt", b"hello\n")]);
    let xml = text_of(&dossier);
    assert!(xml.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<es:Dossier "));
    assert!(xml.contains("<es:DossierProfile Id=\"dossier\" OBJREF=\"documents\">"));
    assert!(xml.contains("<es:Documents Id=\"documents\">"));
    assert!(xml.contains("<es:DocumentProfile Id=\"profile0\" OBJREF=\"obj0\">"));
    assert!(xml.contains("<es:Title>hello.txt</es:Title>"));
    assert!(xml.contains(
        "<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>"
    ));
    assert!(xml.contains("<es:SourceSize sizeValue=\"6\" sizeUnit=\"B\"/>"));
    assert!(
        xml.contains("<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>")
    );
    assert!(xml.contains("<ds:Object Id=\"obj0\">aGVsbG8K</ds:Object>"));
    assert!(xml.ends_with("</es:Dossier>\n"));
    assert_eq!(dossier.documents[0].object_ref, "obj0");
    assert_eq!(dossier.documents[0].source_size, 6);
    assert_eq!(dossier.documents[0].transforms, ["base64"]);
    assert!(!dossier.documents[0].nested_dossier);
}

#[test]
fn what_is_built_is_what_the_reader_reads_back() {
    let dossier = built(vec![
        document("hello.txt", b"hello\n"),
        DocumentSpec {
            compress: true,
            ..document(
                "report.pdf",
                b"%PDF-1.4 not really a pdf, but bytes are bytes\n",
            )
        },
    ]);
    let parsed = openszigno_core::parse(&dossier.bytes, &Limits::default()).expect("parses");
    assert_eq!(parsed.title, "Synthetic authoring test");
    assert_eq!(parsed.creation_date.as_deref(), Some(CREATED));
    assert_eq!(parsed.signatures_present, 0);
    assert_eq!(parsed.timestamps_present, 0);
    assert!(parsed.warnings.is_empty(), "no conformance warning");
    assert_eq!(parsed.documents.len(), 2);
    assert_eq!(parsed.documents[1].mime_type.essence(), "application/pdf");
    assert_eq!(parsed.documents[1].transforms, ["zip", "base64"]);
    for (index, expected) in [
        b"hello\n".to_vec(),
        b"%PDF-1.4 not really a pdf, but bytes are bytes\n".to_vec(),
    ]
    .into_iter()
    .enumerate()
    {
        let DecodeOutcome::Decoded(decoded) = parsed
            .decode_document(index, &Limits::default())
            .expect("decodes")
        else {
            panic!("document {index} must decode");
        };
        assert_eq!(decoded.bytes, expected, "document {index} round trips");
        assert!(!decoded.decrypted);
    }
}

#[test]
fn the_same_request_always_produces_the_same_bytes() {
    let documents = || {
        vec![
            document("hello.txt", b"hello\n"),
            DocumentSpec {
                compress: true,
                ..document("note.txt", b"a note that is long enough to deflate\n")
            },
        ]
    };
    assert_eq!(built(documents()).bytes, built(documents()).bytes);
}

#[test]
fn an_embedded_dossier_is_recognised_as_nested() {
    let inner = built(vec![document("inner.txt", b"inner\n")]);
    let outer = built(vec![DocumentSpec {
        title: "inner.dosszie".to_owned(),
        media_type: None,
        bytes: inner.bytes.clone(),
        compress: false,
        encrypt: false,
    }]);
    assert!(outer.documents[0].nested_dossier);
    assert_eq!(
        outer.documents[0].mime_type.essence(),
        "application/nldossier2"
    );
    let parsed = openszigno_core::parse(&outer.bytes, &Limits::default()).expect("parses");
    assert!(parsed.documents[0].nested_dossier);
    let DecodeOutcome::Decoded(decoded) = parsed
        .decode_document(0, &Limits::default())
        .expect("decodes")
    else {
        panic!("the embedded dossier must decode");
    };
    assert_eq!(decoded.bytes, inner.bytes);
}

#[test]
fn a_title_the_extraction_sanitizer_refuses_is_refused_here() {
    for title in ["../escape.txt", "bidi\u{202e}txt.exe", "nul.txt", "."] {
        let error = build(&spec(vec![document(title, b"x")]), &Limits::default())
            .expect_err("this title must be refused");
        assert_eq!(error.code(), ErrorCode::UnsafeDocumentTitle, "{title:?}");
        assert!(
            !error.message().contains(title),
            "the message must not echo the title"
        );
    }
}

#[test]
fn a_dossier_title_that_is_not_usable_metadata_is_refused() {
    for title in ["", "   ", "control\u{7}"] {
        let error = build(
            &DossierSpec {
                title: title.to_owned(),
                created: CREATED.to_owned(),
                documents: vec![document("hello.txt", b"x")],
                encryption: None,
            },
            &Limits::default(),
        )
        .expect_err("this dossier title must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidDossierTitle);
    }
    // Markup in a title is escaped, not refused.
    let dossier = build(
        &DossierSpec {
            title: "Kft. <A & B>".to_owned(),
            created: CREATED.to_owned(),
            documents: vec![document("hello.txt", b"x")],
            encryption: None,
        },
        &Limits::default(),
    )
    .expect("an escapable title builds");
    assert!(text_of(&dossier).contains("<es:Title>Kft. &lt;A &amp; B&gt;</es:Title>"));
    assert_eq!(
        openszigno_core::parse(&dossier.bytes, &Limits::default())
            .expect("parses")
            .title,
        "Kft. <A & B>"
    );
}

/// A title is written in one canonical composition, so the dossier's title
/// and the filename `extract` writes are the same string.
#[test]
fn a_title_is_stored_in_one_canonical_composition() {
    let dossier = built(vec![document("e\u{301}rte\u{301}s.txt", b"x")]);
    assert_eq!(dossier.documents[0].title, "\u{e9}rt\u{e9}s.txt");
    assert!(text_of(&dossier).contains("<es:Title>\u{e9}rt\u{e9}s.txt</es:Title>"));
    let composed = built(vec![document("\u{e9}rt\u{e9}s.txt", b"x")]);
    assert_eq!(dossier.bytes, composed.bytes);
}

#[test]
fn a_dossier_with_no_document_is_refused() {
    let error = build(&spec(Vec::new()), &Limits::default()).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::NoDocuments);
}

#[test]
fn the_document_count_limit_is_enforced() {
    let limits = Limits {
        max_documents: 2,
        ..Limits::default()
    };
    let documents = vec![
        document("a.txt", b"a"),
        document("b.txt", b"b"),
        document("c.txt", b"c"),
    ];
    let error = build(&spec(documents), &limits).expect_err("refused");
    assert_eq!(error.code(), ErrorCode::TooManyDocuments);
}

#[test]
fn the_per_document_and_total_size_limits_are_enforced() {
    let limits = Limits {
        max_decoded_document_bytes: 8,
        max_total_decoded_bytes: 12,
        ..Limits::default()
    };
    let error = build(&spec(vec![document("a.txt", &[b'a'; 9])]), &limits)
        .expect_err("one document over the per-document limit");
    assert_eq!(error.code(), ErrorCode::DecodedTooLarge);

    let error = build(
        &spec(vec![
            document("a.txt", &[b'a'; 8]),
            document("b.txt", &[b'b'; 8]),
        ]),
        &limits,
    )
    .expect_err("two documents over the aggregate limit");
    assert_eq!(error.code(), ErrorCode::TotalSizeLimit);
}

#[test]
fn the_base64_character_limit_is_enforced() {
    let limits = Limits {
        max_base64_chars: 4,
        ..Limits::default()
    };
    let error = build(
        &spec(vec![document("a.txt", b"more than three bytes")]),
        &limits,
    )
    .expect_err("refused");
    assert_eq!(error.code(), ErrorCode::DecodedTooLarge);
}

#[test]
fn a_payload_that_compresses_past_the_ratio_limit_is_refused() {
    let error = build(
        &spec(vec![DocumentSpec {
            compress: true,
            ..document("zeros.txt", &vec![b'0'; 64 * 1024])
        }]),
        &Limits::default(),
    )
    .expect_err("refused");
    assert_eq!(error.code(), ErrorCode::ZipRatioLimit);
}

#[test]
fn a_document_whose_type_cannot_be_determined_is_refused() {
    let error = build(
        &spec(vec![document("payload.bin", b"x")]),
        &Limits::default(),
    )
    .expect_err("refused");
    assert_eq!(error.code(), ErrorCode::UnknownMimeType);
    let dossier = built(vec![DocumentSpec {
        media_type: Some("application/octet-stream".to_owned()),
        ..document("payload.bin", b"x")
    }]);
    assert_eq!(
        dossier.documents[0].mime_type.essence(),
        "application/octet-stream"
    );
}

#[test]
fn a_built_document_serialises_the_documented_fields() {
    let dossier = built(vec![document("hello.txt", b"hello\n")]);
    let value = serde_json::to_value(&dossier.documents[0]).expect("serialises");
    let object = value.as_object().expect("an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "encrypted",
            "index",
            "mime_type",
            "nested_dossier",
            "object_ref",
            "source_size",
            "title",
            "transforms"
        ]
    );
}
