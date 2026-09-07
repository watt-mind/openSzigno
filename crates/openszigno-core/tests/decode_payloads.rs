//! Bounded payload decoding: Base64, ZIP, transform chains, and every limit.

mod common;

use common::{
    base64_dossier, deflated, document, dossier_with, forge_zip_sizes, single_member_zip, stored,
    zip_dossier,
};
use openszigno_core::{DecodeOutcome, Dossier, ErrorCode, Limits, UnsupportedReason, parse};

fn dossier(xml: &str) -> Dossier {
    parse(xml.as_bytes(), &Limits::default()).expect("synthetic dossier must parse")
}

fn decode(xml: &str) -> DecodeOutcome {
    dossier(xml)
        .decode_document(0, &Limits::default())
        .expect("decoding must succeed")
}

fn decode_error(xml: &str) -> ErrorCode {
    dossier(xml)
        .decode_document(0, &Limits::default())
        .expect_err("decoding must fail")
        .code()
}

fn decode_error_with(xml: &str, limits: &Limits) -> ErrorCode {
    dossier(xml)
        .decode_document(0, limits)
        .expect_err("decoding must fail")
        .code()
}

fn decoded_bytes(outcome: DecodeOutcome) -> Vec<u8> {
    match outcome {
        DecodeOutcome::Decoded(decoded) => decoded.bytes,
        DecodeOutcome::Unsupported(reason) => panic!("payload must decode, got {reason:?}"),
    }
}

#[test]
fn base64_payloads_may_be_wrapped_in_whitespace() {
    let payload = "SGVsbG8sIHdvcmxkIQ==";
    let wrapped = format!("\n  {}\n  {}\t\n", &payload[..8], &payload[8..]);
    let xml = dossier_with(&document(
        1,
        "hello.txt",
        Some("txt"),
        13,
        &["base64"],
        &wrapped,
    ));
    assert_eq!(decoded_bytes(decode(&xml)), b"Hello, world!");
}

#[test]
fn a_payload_with_non_canonical_padding_is_invalid_base64() {
    for payload in ["SGVsbG8", "SGVsbG8===", "SGVsbG=8", "a"] {
        let xml = dossier_with(&document(
            1,
            "hello.txt",
            Some("txt"),
            5,
            &["base64"],
            payload,
        ));
        assert_eq!(
            decode_error(&xml),
            ErrorCode::InvalidBase64,
            "{payload} must be rejected"
        );
    }
}

#[test]
fn an_empty_payload_decodes_to_no_bytes() {
    let xml = dossier_with(&document(1, "empty.txt", Some("txt"), 0, &["base64"], ""));
    assert_eq!(decoded_bytes(decode(&xml)), Vec::<u8>::new());
}

#[test]
fn a_decoded_length_other_than_the_declared_source_size_is_a_mismatch() {
    let xml = dossier_with(&document(
        1,
        "hello.txt",
        Some("txt"),
        999,
        &["base64"],
        "SGVsbG8sIHdvcmxkIQ==",
    ));
    assert_eq!(decode_error(&xml), ErrorCode::SourceSizeMismatch);
}

#[test]
fn a_payload_above_the_encoded_character_limit_is_too_large() {
    let xml = base64_dossier(&vec![0u8; 1024]);
    let limits = Limits {
        max_base64_chars: 16,
        ..Limits::default()
    };
    assert_eq!(decode_error_with(&xml, &limits), ErrorCode::DecodedTooLarge);
}

#[test]
fn a_payload_above_the_decoded_size_limit_is_too_large() {
    let xml = base64_dossier(&vec![0u8; 1024]);
    let limits = Limits {
        max_decoded_document_bytes: 64,
        ..Limits::default()
    };
    assert_eq!(decode_error_with(&xml, &limits), ErrorCode::DecodedTooLarge);
}

#[test]
fn an_encrypt_transform_anywhere_in_the_chain_is_unsupported() {
    // The specification fixes the order as `zip? -> encrypt? -> base64`, so
    // only those two chains are encrypted documents. `encrypt` in any other
    // position is not a chain this format defines, and is reported as such
    // rather than as something a decryption key could open.
    for chain in [vec!["encrypt", "base64"], vec!["zip", "encrypt", "base64"]] {
        let xml = dossier_with(&document(1, "secret.bin", Some("bin"), 1, &chain, "eA=="));
        assert!(
            matches!(
                decode(&xml),
                DecodeOutcome::Unsupported(UnsupportedReason::Encrypted)
            ),
            "{chain:?} must be reported as encrypted"
        );
    }
    for chain in [vec!["encrypt"], vec!["base64", "encrypt"]] {
        let xml = dossier_with(&document(1, "secret.bin", Some("bin"), 1, &chain, "eA=="));
        assert!(
            matches!(
                decode(&xml),
                DecodeOutcome::Unsupported(UnsupportedReason::TransformChain)
            ),
            "{chain:?} must be reported as an unsupported chain"
        );
    }
}

#[test]
fn transform_chains_outside_the_supported_set_are_unsupported() {
    for chain in [
        vec!["gzip", "base64"],
        vec!["base64", "zip"],
        vec!["zip"],
        vec!["base64", "base64"],
        vec!["zip", "zip", "base64"],
    ] {
        let xml = dossier_with(&document(1, "payload.bin", Some("bin"), 1, &chain, "eA=="));
        assert!(
            matches!(
                decode(&xml),
                DecodeOutcome::Unsupported(UnsupportedReason::TransformChain)
            ),
            "{chain:?} must be reported as an unsupported chain"
        );
    }
}

#[test]
fn a_payload_that_is_not_an_archive_is_an_invalid_zip() {
    let xml = zip_dossier(b"not a zip archive at all", 1);
    assert_eq!(decode_error(&xml), ErrorCode::InvalidZip);
}

#[test]
fn an_archive_with_two_members_exceeds_the_member_limit() {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;

        let mut writer = zip::ZipWriter::new(&mut archive);
        for name in ["first.txt", "second.txt"] {
            writer.start_file(name, deflated()).expect("member starts");
            writer.write_all(b"payload").expect("member is writable");
        }
        writer.finish().expect("archive finishes");
    }
    let xml = zip_dossier(&archive.into_inner(), 7);
    assert_eq!(decode_error(&xml), ErrorCode::ZipMemberLimit);
}

#[test]
fn an_empty_archive_exceeds_the_member_limit() {
    let mut archive = std::io::Cursor::new(Vec::new());
    zip::ZipWriter::new(&mut archive)
        .finish()
        .expect("archive finishes");
    let xml = zip_dossier(&archive.into_inner(), 0);
    assert_eq!(decode_error(&xml), ErrorCode::ZipMemberLimit);
}

#[test]
fn a_directory_member_is_not_a_regular_file() {
    let mut archive = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut archive);
        writer
            .add_directory("folder", deflated())
            .expect("directory is added");
        writer.finish().expect("archive finishes");
    }
    let xml = zip_dossier(&archive.into_inner(), 0);
    assert_eq!(decode_error(&xml), ErrorCode::UnsafeZipMember);
}

#[test]
fn a_member_inside_a_subdirectory_is_not_a_bare_name() {
    let archive = single_member_zip("nested/payload.txt", b"payload", deflated());
    let xml = zip_dossier(&archive, 7);
    assert_eq!(decode_error(&xml), ErrorCode::UnsafeZipMember);
}

#[test]
fn a_member_above_the_expanded_size_limit_is_rejected_from_its_header() {
    let archive = single_member_zip("payload.bin", &vec![7u8; 4096], stored());
    let limits = Limits {
        max_zip_expanded_bytes: 128,
        ..Limits::default()
    };
    assert_eq!(
        decode_error_with(&zip_dossier(&archive, 4096), &limits),
        ErrorCode::ZipSizeLimit
    );
}

#[test]
fn a_member_claiming_more_than_one_document_may_hold_is_rejected() {
    // A small archive whose header claims a huge expansion: the encoded
    // payload is well inside the Base64 limits, so the ZIP header check
    // against the decoded-document limit is what rejects it.
    let mut archive = single_member_zip("payload.bin", b"payload", stored());
    forge_zip_sizes(&mut archive, None, Some(1_000_000));
    let limits = Limits {
        max_decoded_document_bytes: 512,
        ..Limits::default()
    };
    assert_eq!(
        decode_error_with(&zip_dossier(&archive, 7), &limits),
        ErrorCode::ZipSizeLimit
    );
}

#[test]
fn a_member_that_expands_beyond_its_declared_size_is_stopped_while_reading() {
    // The uncompressed-size fields are forged down to a small value, so the
    // header checks pass and only the bounded read can catch the expansion.
    let contents = vec![0u8; 64 * 1024];
    let mut archive = single_member_zip("zeros.bin", &contents, deflated());
    forge_zip_sizes(&mut archive, None, Some(512));

    let limits = Limits {
        max_zip_expanded_bytes: 1024,
        max_zip_compression_ratio: u64::MAX,
        ..Limits::default()
    };
    assert_eq!(
        decode_error_with(&zip_dossier(&archive, 512), &limits),
        ErrorCode::ZipSizeLimit
    );

    // With generous size limits the ratio check on the real decoded length is
    // what rejects the same archive.
    assert_eq!(
        decode_error(&zip_dossier(&archive, 512)),
        ErrorCode::ZipRatioLimit
    );
}

#[test]
fn a_member_declaring_no_compressed_bytes_exceeds_the_ratio_limit() {
    let mut archive = single_member_zip("payload.bin", b"payload", stored());
    forge_zip_sizes(&mut archive, Some(0), None);
    assert_eq!(
        decode_error(&zip_dossier(&archive, 7)),
        ErrorCode::ZipRatioLimit
    );
}

#[test]
fn a_zip_member_at_the_ratio_limit_still_decodes() {
    let archive = single_member_zip("payload.txt", b"payload bytes", stored());
    let xml = zip_dossier(&archive, 13);
    assert_eq!(decoded_bytes(decode(&xml)), b"payload bytes");
}

#[test]
fn decoding_an_index_outside_the_dossier_is_an_invalid_attribute() {
    let dossier = dossier(&base64_dossier(b"payload"));
    let error = dossier
        .decode_document(7, &Limits::default())
        .expect_err("an out-of-range index must be rejected");
    assert_eq!(error.code(), ErrorCode::InvalidAttribute);
    assert_eq!(error.message(), "document index is out of range");
}

#[test]
fn every_document_of_a_multi_document_dossier_decodes_independently() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let documents = format!(
        "{}{}",
        document(
            0,
            "first.txt",
            Some("txt"),
            5,
            &["base64"],
            &STANDARD.encode(b"first"),
        ),
        document(1, "second.bin", Some("bin"), 1, &["gzip"], "eA=="),
    );
    let dossier = dossier(&dossier_with(&documents));
    assert_eq!(
        decoded_bytes(
            dossier
                .decode_document(0, &Limits::default())
                .expect("first document decodes")
        ),
        b"first"
    );
    assert!(matches!(
        dossier
            .decode_document(1, &Limits::default())
            .expect("second document is classified"),
        DecodeOutcome::Unsupported(UnsupportedReason::TransformChain)
    ));
}

#[test]
fn a_member_whose_local_header_is_corrupt_is_an_invalid_zip() {
    // The central directory still describes one ordinary member, so the
    // archive opens; only reading the member fails.
    let mut archive = single_member_zip("payload.txt", b"payload", stored());
    archive[3] = b'\x05';
    assert_eq!(
        decode_error(&zip_dossier(&archive, 7)),
        ErrorCode::InvalidZip
    );
}
