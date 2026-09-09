//! What the signer writes is what the verifier reads.
//!
//! Every dossier here is built by this crate, signed by this crate, and then
//! handed to `openszigno-verify` — the reader that has to accept it — with a
//! trust store holding the synthetic anchor and nothing else. The point is not
//! that a signature exists but that the shape is the one the e-dossier
//! reference-scope rules mandate: a signature that verifies is the only proof
//! of that worth having.
//!
//! Every key is generated while the test runs. None is committed.

use openszigno_author::sign::{
    SignRequest, SignScope, SignatureAlgorithm, Signer as _, SoftwareSigner, sign,
};
use openszigno_author::{DocumentSpec, DossierSpec};
use openszigno_core::{Limits, ParseOptions};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, RoxmltreeC14n, Verdict, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};

/// A signing time inside the synthetic certificate's validity window.
const AT: &str = "2026-01-02T00:00:00Z";

/// A P-256 key and a self-signed certificate for it.
///
/// Self-signed is enough here: the question these tests answer is what the
/// signer writes, and a chain of one is a chain. Nothing about this makes a
/// verdict mean more than "the anchor this test chose said so".
struct Material {
    key: Vec<u8>,
    certificate: Vec<u8>,
}

fn material() -> Material {
    let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("a P-256 key is generated");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2039, 1, 1);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::ContentCommitment,
        rcgen::KeyUsagePurpose::KeyCertSign,
    ];
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let certificate = params.self_signed(&pair).expect("self-signing succeeds");
    Material {
        key: pair.serialize_der(),
        certificate: certificate.der().to_vec(),
    }
}

fn signer(material: &Material) -> SoftwareSigner {
    SoftwareSigner::load(&material.key, None, Some(&material.certificate), None)
        .expect("the key and its certificate load")
}

/// An unsigned dossier with `count` text documents.
fn dossier(count: usize) -> Vec<u8> {
    let documents = (0..count)
        .map(|index| DocumentSpec {
            title: format!("note{index}.txt"),
            media_type: None,
            bytes: format!("document {index}\n").into_bytes(),
            compress: false,
            // Signing an encrypted payload is signing its ciphertext, which
            // is a different question; these fixtures are in the clear.
            encrypt: false,
        })
        .collect();
    openszigno_author::build(
        &DossierSpec {
            title: "Synthetic signing fixture".to_owned(),
            created: "2026-01-01T00:00:00Z".to_owned(),
            documents,
            encryption: None,
        },
        &Limits::default(),
    )
    .expect("the dossier builds")
    .bytes
}

fn request(scope: SignScope) -> SignRequest {
    SignRequest {
        scope,
        documents: Vec::new(),
        signing_time: AT.to_owned(),
        certificate_values: Vec::new(),
    }
}

/// Verify a signed dossier against one anchor, with no revocation data.
fn run(bytes: &[u8], anchor: &[u8]) -> VerifyReport {
    let trust = MemoryTrustStore::new(vec![anchor.to_vec()], Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    verify(bytes, &options).expect("the signed dossier parses structurally")
}

fn codes(report: &VerifyReport) -> Vec<(String, CheckStatus)> {
    report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .map(|check| (check.code.as_str().to_owned(), check.status))
        .collect()
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    assert!(
        codes(report).contains(&(code.as_str().to_owned(), status)),
        "expected {}={}; got {:?}",
        code.as_str(),
        status.as_str(),
        codes(report)
    );
}

/// Nothing failed. Every check about the signature itself passed, and the only
/// things left open are the ones this run deliberately supplied no evidence
/// for: a timestamp and revocation data.
fn assert_nothing_failed(report: &VerifyReport) {
    let failed: Vec<String> = codes(report)
        .into_iter()
        .filter(|(_, status)| *status == CheckStatus::Failed)
        .map(|(code, _)| code)
        .collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
}

#[test]
fn a_document_signature_verifies_and_covers_its_document() {
    let material = material();
    let signed = sign(
        &dossier(1),
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");

    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(signed.signatures[0].id, "sig-doc0");
    assert_eq!(signed.signatures[0].document_index, Some(0));
    assert!(!signed.signatures[0].timestamped);

    let report = run(&signed.bytes, &material.certificate);
    assert_nothing_failed(&report);
    assert_check(&report, CheckCode::SigStructure, CheckStatus::Passed);
    assert_check(&report, CheckCode::SigPlacement, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    // Every document is covered; the check is `info` rather than `passed`
    // because these runs carry no timestamp and no revocation data, so the
    // covering signature's own verdict is `indeterminate`. The CLI suite is
    // where a run with both reaches `passed`.
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Info);
    // The placement the verifier classifies it at is the document one.
    assert_eq!(
        report.signatures[0].scope,
        openszigno_verify::SignatureScope::Document
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

#[test]
fn every_document_is_signed_when_no_selector_narrows_the_run() {
    let material = material();
    let signed = sign(
        &dossier(3),
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");

    assert_eq!(signed.signatures.len(), 3);
    let report = run(&signed.bytes, &material.certificate);
    assert_nothing_failed(&report);
    assert_eq!(report.signatures.len(), 3);
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Info);
}

#[test]
fn a_selector_signs_exactly_the_documents_it_names() {
    let material = material();
    let mut request = request(SignScope::Document);
    // The same document twice, by index and by object reference, is one
    // signature: the selection is resolved and deduplicated.
    request.documents = vec!["#1".to_owned(), "obj1".to_owned()];
    let signed = sign(
        &dossier(3),
        &ParseOptions::default(),
        &request,
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");

    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(signed.signatures[0].document_index, Some(1));

    let report = run(&signed.bytes, &material.certificate);
    assert_nothing_failed(&report);
    // Two documents nothing covers cap the dossier, which is the point of the
    // coverage rule and is reported rather than hidden.
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
}

#[test]
fn a_selector_that_matches_nothing_is_refused() {
    let material = material();
    let mut request = request(SignScope::Document);
    request.documents = vec!["#7".to_owned()];
    let error = sign(
        &dossier(1),
        &ParseOptions::default(),
        &request,
        &signer(&material),
        None,
    )
    .err()
    .expect("there is no document 7");
    assert_eq!(error.code().as_str(), "document_not_found");
}

#[test]
fn a_dossier_signature_covers_every_document() {
    let material = material();
    let signed = sign(
        &dossier(3),
        &ParseOptions::default(),
        &request(SignScope::Dossier),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");

    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(signed.signatures[0].id, "sig-dossier");
    assert_eq!(signed.signatures[0].document_index, None);

    let report = run(&signed.bytes, &material.certificate);
    assert_nothing_failed(&report);
    assert_eq!(
        report.signatures[0].scope,
        openszigno_verify::SignatureScope::Dossier
    );
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Info);
    // One frame signature reaches all three documents, each through the
    // `es:Documents` element it references.
    assert_eq!(report.documents.len(), 3);
    assert!(
        report
            .documents
            .iter()
            .all(|document| document.covered_by.len() == 1)
    );
}

#[test]
fn signing_the_same_inputs_twice_with_pkcs1_gives_the_same_bytes() {
    // RSA PKCS#1 v1.5 is deterministic; PSS and ECDSA are not, and say so.
    assert!(SignatureAlgorithm::RsaSha256.deterministic());
    assert!(!SignatureAlgorithm::EcdsaP256Sha256.deterministic());

    let material = material();
    let unsigned = dossier(1);
    let once = sign(
        &unsigned,
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");
    let twice = sign(
        &unsigned,
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");

    // Everything except the randomised signature value is byte-identical, so
    // the two differ only inside `ds:SignatureValue`.
    let strip = |bytes: &[u8]| {
        let text = String::from_utf8(bytes.to_vec()).expect("UTF-8");
        let start = text.find("<ds:SignatureValue>").expect("there is one");
        let end = text.find("</ds:SignatureValue>").expect("there is one");
        format!("{}{}", &text[..start], &text[end..])
    };
    assert_eq!(strip(&once.bytes), strip(&twice.bytes));
}

#[test]
fn a_second_signature_can_be_added_to_a_document_that_already_has_one() {
    let first = material();
    let signed = sign(
        &dossier(2),
        &ParseOptions::default(),
        &{
            let mut request = request(SignScope::Document);
            request.documents = vec!["#0".to_owned()];
            request
        },
        &signer(&first),
        None,
    )
    .expect("the first signature is written");

    // A second signature over the same document does not disturb the first:
    // neither one's references reach inside the other.
    let twice = sign(
        &signed.bytes,
        &ParseOptions::default(),
        &{
            let mut request = request(SignScope::Document);
            request.documents = vec!["#1".to_owned()];
            request
        },
        &signer(&first),
        None,
    )
    .expect("the second signature is written");

    let report = run(&twice.bytes, &first.certificate);
    assert_eq!(report.signatures.len(), 2);
    // The first signature's own checks are untouched by the second run:
    // neither reference reaches into the other signature.
    assert_nothing_failed(&report);
    assert_eq!(
        codes(&report)
            .iter()
            .filter(|(code, status)| code == "signature_value_ok" && *status == CheckStatus::Passed)
            .count(),
        2
    );
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Info);
}

#[test]
fn a_document_signature_is_refused_once_a_dossier_signature_covers_the_documents() {
    let material = material();
    let signed = sign(
        &dossier(1),
        &ParseOptions::default(),
        &request(SignScope::Dossier),
        &signer(&material),
        None,
    )
    .expect("the frame signature is written");

    let error = sign(
        &signed.bytes,
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .err()
    .expect("that would break the frame signature");
    assert_eq!(error.code().as_str(), "document_already_signed");
}

#[test]
fn a_timestamp_callback_failure_is_reported_as_a_tsa_failure() {
    let material = material();
    let mut callback = |_: &[u8]| Err("the responder refused the connection".to_owned());
    let error = sign(
        &dossier(1),
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        Some(&mut callback),
    )
    .err()
    .expect("the authority could not be used");
    assert_eq!(error.code().as_str(), "tsa_failed");
    assert!(error.message().contains("refused the connection"));
}

#[test]
fn a_certificate_the_key_did_not_produce_is_never_used_to_sign() {
    let mine = material();
    let other = material();
    let error = SoftwareSigner::load(&mine.key, None, Some(&other.certificate), None)
        .expect_err("the certificate belongs to another key");
    assert_eq!(error.code().as_str(), "signing_key_mismatch");
    // The refusal quotes nothing: not the key, not the certificate.
    assert!(!error.message().contains("BEGIN"));
}

#[test]
fn the_signer_reports_the_certificate_it_will_write() {
    let material = material();
    let signer = signer(&material);
    assert_eq!(signer.certificate(), material.certificate.as_slice());
    assert_eq!(signer.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
}

// ---------------------------------------------------------------------------
// The dossier's own text is never mistaken for the signer's scaffolding
// ---------------------------------------------------------------------------

/// Every placeholder string the signer writes for the first signature of a
/// document-scope run.
fn placeholders() -> Vec<String> {
    let mut all: Vec<String> = [
        "object",
        "document-profile",
        "signature-profile",
        "signed-properties",
    ]
    .iter()
    .map(|what| format!("@@openszigno-digest:ref-sig-doc0-{what}@@"))
    .collect();
    all.push("@@openszigno-value:sig-doc0@@".to_owned());
    all.push("@@openszigno-timestamp:sig-doc0@@".to_owned());
    all
}

/// A dossier whose every document is titled, and filled, with one of those
/// strings.
///
/// The titles are patched into the built text rather than asked for directly,
/// because a placeholder holds a colon and the title rules refuse one: a real
/// dossier this tool did not write is under no such obligation, which is
/// exactly the case this fixture stands in for.
fn dossier_that_reads_like_the_scaffolding() -> (Vec<u8>, Vec<String>) {
    let titles = placeholders();
    let documents = titles
        .iter()
        .enumerate()
        .map(|(index, title)| DocumentSpec {
            title: format!("marker{index}"),
            media_type: Some("text/plain".to_owned()),
            bytes: title.clone().into_bytes(),
            compress: false,
            encrypt: false,
        })
        .collect();
    let bytes = openszigno_author::build(
        &DossierSpec {
            title: "Synthetic signing fixture".to_owned(),
            created: "2026-01-01T00:00:00Z".to_owned(),
            documents,
            encryption: None,
        },
        &Limits::default(),
    )
    .expect("the dossier builds")
    .bytes;
    let mut text = String::from_utf8(bytes).expect("the writer writes UTF-8");
    for (index, title) in titles.iter().enumerate() {
        let marker = format!("marker{index}");
        assert_eq!(
            text.matches(&marker).count(),
            1,
            "exactly one place holds {marker}"
        );
        text = text.replace(&marker, title);
    }
    (text.into_bytes(), titles)
}

/// The titles a reader reads back out of a dossier.
fn titles(bytes: &[u8]) -> Vec<String> {
    openszigno_core::parse_with_options(bytes, &ParseOptions::default())
        .expect("the dossier parses")
        .documents
        .iter()
        .map(|document| document.title.clone())
        .collect()
}

#[test]
fn a_dossier_that_reads_like_a_placeholder_is_signed_and_left_alone() {
    let material = material();
    let (bytes, expected) = dossier_that_reads_like_the_scaffolding();
    let signed = sign(
        &bytes,
        &ParseOptions::default(),
        &request(SignScope::Document),
        &signer(&material),
        None,
    )
    .expect("the dossier is signed");
    assert_eq!(signed.signatures.len(), expected.len());

    // The signature is over what is actually in the file, not over what the
    // file said before a substitution rewrote parts of it.
    let report = run(&signed.bytes, &material.certificate);
    assert_nothing_failed(&report);
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    for signature in &report.signatures {
        for code in [CheckCode::ReferenceDigestOk, CheckCode::SignatureValueOk] {
            assert!(
                signature
                    .checks
                    .iter()
                    .any(|check| check.code == code && check.status == CheckStatus::Passed),
                "signature {} is missing {}",
                signature.index,
                code.as_str()
            );
        }
    }

    // And the documents came through untouched: each title is still the
    // placeholder-shaped text it went in as.
    assert_eq!(titles(&signed.bytes), expected);
}

// ---------------------------------------------------------------------------
// An ISO-8859-2 dossier, whatever its declaration looks like
// ---------------------------------------------------------------------------

/// Encode text as ISO-8859-2, for the characters these fixtures use.
fn iso8859_2(text: &str) -> Vec<u8> {
    text.chars()
        .map(|character| match character {
            'á' => 0xE1,
            'é' => 0xE9,
            'í' => 0xED,
            'ó' => 0xF3,
            'ö' => 0xF6,
            'ü' => 0xFC,
            'ő' => 0xF5,
            'ú' => 0xFA,
            'ű' => 0xFB,
            'Á' => 0xC1,
            'É' => 0xC9,
            'Ó' => 0xD3,
            'Ö' => 0xD6,
            'Ú' => 0xDA,
            'Ü' => 0xDC,
            other if other.is_ascii() => other as u8,
            other => panic!("this fixture has no ISO-8859-2 byte for {other}"),
        })
        .collect()
}

/// A dossier declared and encoded ISO-8859-2, with non-ASCII titles and the
/// declaration spelled `declaration`.
fn latin2_dossier(declaration: &str) -> (Vec<u8>, Vec<String>) {
    let expected = vec![
        "árvíztűrő tükörfúrógép".to_owned(),
        "Éves jelentés".to_owned(),
    ];
    let documents = expected
        .iter()
        .map(|title| DocumentSpec {
            title: title.clone(),
            media_type: Some("text/plain".to_owned()),
            bytes: format!("{title}\n").into_bytes(),
            compress: false,
            encrypt: false,
        })
        .collect();
    let bytes = openszigno_author::build(
        &DossierSpec {
            title: "Árvíztűrő minta".to_owned(),
            created: "2026-01-01T00:00:00Z".to_owned(),
            documents,
            encryption: None,
        },
        &Limits::default(),
    )
    .expect("the dossier builds")
    .bytes;
    let text = String::from_utf8(bytes).expect("the writer writes UTF-8");
    let (written, rest) = text
        .split_once("?>")
        .expect("the writer writes a declaration");
    assert!(written.starts_with("<?xml"), "{written}");
    (iso8859_2(&format!("{declaration}{rest}")), expected)
}

#[test]
fn an_iso_8859_2_dossier_signs_whatever_its_declaration_looks_like() {
    for declaration in [
        "<?xml version=\"1.0\" encoding=\"ISO-8859-2\"?>",
        "<?xml version='1.0' encoding='ISO-8859-2'?>",
        "<?xml version=\"1.0\" encoding = \"ISO-8859-2\"?>",
        "<?xml version='1.0' encoding='iso-8859-2'?>",
    ] {
        let material = material();
        let (bytes, expected) = latin2_dossier(declaration);
        let signed = sign(
            &bytes,
            &ParseOptions::default(),
            &request(SignScope::Document),
            &signer(&material),
            None,
        )
        .unwrap_or_else(|error| panic!("{declaration} is signed: {}", error.message()));

        let report = run(&signed.bytes, &material.certificate);
        assert_nothing_failed(&report);
        assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
        assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);

        // The output is UTF-8 and says so, and the non-ASCII titles survived
        // the re-encoding intact.
        let text = String::from_utf8(signed.bytes.clone()).expect("the output is UTF-8");
        assert!(text.contains("UTF-8"), "{declaration}: {}", &text[..64]);
        assert!(!text.to_ascii_lowercase().contains("8859"), "{declaration}");
        assert_eq!(titles(&signed.bytes), expected, "{declaration}");
    }
}
