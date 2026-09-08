//! End-to-end verification tests over synthetic dossiers.
//!
//! Every check code the crate can emit is exercised with a positive and a
//! negative case, because a verifier that only ever sees valid input is a
//! verifier whose failure paths are untested.

mod common;

use common::{
    C14N_EXC, CertSpec, DossierSpec, ECDSA_SHA256_URI, ENVELOPED_URI, HMAC_SHA256_URI,
    RSA_SHA1_URI, RefSpec, SHA1_URI, SIGNED_PROPERTIES_TYPE, TestKey, XPATH_URI, XSLT_URI, build,
    document_signature, dossier_signature, ecdsa_key, issued_by, keys, rsa_key, self_signed,
    tamper,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    CoverageState, FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RoxmltreeC14n, Verdict,
    VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::{BasicConstraints, GeneralSubtree, IsCa, KeyUsagePurpose, NameConstraints};

/// A fixed validation time inside every synthetic certificate's window, so no
/// test depends on the wall clock.
fn at(text: &str) -> FixedClock {
    FixedClock(parse_rfc3339(text).expect("the fixed time parses"))
}

fn run(xml: &str, anchors: Vec<Vec<u8>>, time: &str) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at(time);
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn run_without_trust(xml: &str, time: &str) -> VerifyReport {
    let trust = NoTrust;
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at(time);
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Every check code emitted anywhere in the report, with its status.
fn codes(report: &VerifyReport) -> Vec<(CheckCode, CheckStatus)> {
    report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .map(|check| (check.code, check.status))
        .collect()
}

fn has(report: &VerifyReport, code: CheckCode, status: CheckStatus) -> bool {
    codes(report).contains(&(code, status))
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    assert!(
        has(report, code, status),
        "expected {} to be {}; got {:?}",
        code.as_str(),
        status.as_str(),
        codes(report)
            .iter()
            .map(|(code, status)| format!("{}={}", code.as_str(), status.as_str()))
            .collect::<Vec<_>>()
    );
}

fn assert_no_failures(report: &VerifyReport) {
    let failed: Vec<&str> = codes(report)
        .iter()
        .filter(|(_, status)| *status == CheckStatus::Failed)
        .map(|(code, _)| code.as_str())
        .collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
}

/// A root, an intermediate, and a signer, plus the keys behind them.
struct Pki {
    /// Kept so a test can issue further certificates from the same root.
    #[allow(dead_code)]
    root_key: TestKey,
    signer_key: TestKey,
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    chain: Vec<Vec<u8>>,
}

fn simple_pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &root,
        &root_key,
    );
    Pki {
        chain: vec![signer.der.clone()],
        root_der: root.der,
        signer_der: signer.der,
        root_key,
        signer_key,
    }
}

// ---------------------------------------------------------------------------
// Positive cases
// ---------------------------------------------------------------------------

/// The whole happy path: a document-level signature whose references cover
/// everything the e-dossier format mandates, verified against a configured
/// anchor. Nothing fails, and the verdict is still only `indeterminate`.
#[test]
fn document_signature_passes_every_implemented_check() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()], "2020-06-01T00:00:00Z");

    assert_no_failures(&report);
    assert_check(&report, CheckCode::SigStructure, CheckStatus::Passed);
    assert_check(&report, CheckCode::SigPlacement, CheckStatus::Passed);
    assert_check(&report, CheckCode::C14nMethodAllowed, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::SignatureAlgorithmAllowed,
        CheckStatus::Passed,
    );
    assert_check(
        &report,
        CheckCode::DigestAlgorithmAllowed,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::TransformsAllowed, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferencesSameDocument,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::ReferencesResolve, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::SignedInfoCanonicalization,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::SigningCertificateAvailable,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::XadesPresent, CheckStatus::Passed);
    // Nothing signed says which certificate signed it, and that is reported
    // rather than assumed away.
    assert_check(
        &report,
        CheckCode::XadesSigningCertificateAbsent,
        CheckStatus::Unknown,
    );
    assert_check(
        &report,
        CheckCode::RevocationNotChecked,
        CheckStatus::Skipped,
    );
    assert_check(
        &report,
        CheckCode::SignatureTimestampAbsent,
        CheckStatus::Unknown,
    );

    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.counts.signatures, 1);
    assert_eq!(report.counts.signatures_valid, 0);
}

/// Phase 1 cannot say `valid`, whatever the input. This is the property the
/// whole release rests on.
#[test]
fn phase_one_never_returns_valid() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        dossier_signature: Some(dossier_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(
        &spec,
        &[("doc", &pki.signer_key), ("frame", &pki.signer_key)],
    );
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    // A frame signature covers the document signature's value, so this also
    // pins the ordering a countersigned dossier depends on.
    assert_no_failures(&report);
    assert_eq!(report.counts.signatures, 2);
    assert_ne!(report.verdict, Verdict::Valid);
    assert!(
        report
            .signatures
            .iter()
            .all(|signature| signature.verdict != Verdict::Valid)
    );
}

/// A frame signature is placed on the dossier and must cover the dossier
/// profile and the document set.
#[test]
fn dossier_level_signature_passes() {
    let pki = simple_pki();
    let spec = DossierSpec {
        dossier_signature: Some(dossier_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("frame", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_eq!(
        report.signatures[0].scope,
        openszigno_verify::SignatureScope::Dossier
    );
}

/// A three-certificate path through an intermediate, with the intermediate
/// supplied in `ds:KeyInfo`.
#[test]
fn path_through_an_intermediate() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let intermediate = issued_by(
        &CertSpec::ca("Intermediate", BasicConstraints::Constrained(0)),
        &intermediate_key,
        &root,
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Signer"),
        &signer_key,
        &intermediate,
        &intermediate_key,
    );
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![
            signer.der.clone(),
            intermediate.der.clone(),
        ])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_eq!(report.signatures[0].chain.len(), 3);
    assert!(report.signatures[0].chain[2].is_trust_anchor);
}

/// ECDSA P-256 with SHA-256, whose XMLDSig signature is the raw `r || s` pair
/// rather than the DER encoding certificates use.
#[test]
fn ecdsa_p256_signature_verifies() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = ecdsa_key(7);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("EC Signer"),
        &signer_key,
        &root,
        &root_key,
    );
    let mut signature = document_signature(vec![signer.der]);
    signature.signature_method = ECDSA_SHA256_URI.to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
}

/// An enveloped signature over the whole document: `URI=""` plus the
/// enveloped-signature transform. It covers everything, so the scope is
/// complete by construction.
#[test]
fn enveloped_signature_over_the_whole_document() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references = vec![RefSpec::to("").with_transforms(&[ENVELOPED_URI, C14N_EXC])];
    signature.include_xades = false;
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::XadesAbsent, CheckStatus::Skipped);
}

/// Name constraints that the signer does not violate must not fail the path.
#[test]
fn name_constraints_that_are_satisfied() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let mut spec = CertSpec::ca("Constrained Root", BasicConstraints::Unconstrained);
    spec.name_constraints = Some(NameConstraints {
        permitted_subtrees: Vec::new(),
        excluded_subtrees: vec![GeneralSubtree::DnsName("example.invalid".to_owned())],
    });
    let root = self_signed(&spec, &root_key);
    let signer = issued_by(&CertSpec::signer("Signer"), &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
}

// ---------------------------------------------------------------------------
// Negative cases: stage A policy
// ---------------------------------------------------------------------------

#[test]
fn an_unsigned_dossier_reports_no_signatures() {
    let xml = include_str!("../../../tests/fixtures/plain-base64.es3");
    let report = run_without_trust(xml, "2026-01-01T00:00:00Z");
    assert_check(&report, CheckCode::NoSignatures, CheckStatus::Unknown);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.counts.signatures, 0);
}

#[test]
fn an_external_reference_is_refused() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("http://example.invalid/payload");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::ReferenceExternal, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

#[test]
fn a_reference_to_an_unknown_id_is_refused() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#not-in-this-document");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::ReferenceUnresolved, CheckStatus::Failed);
}

#[test]
fn an_xslt_transform_is_refused_unconditionally() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#obj0").with_transforms(&[XSLT_URI, C14N_EXC]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::TransformNotAllowed, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

#[test]
fn an_xpath_transform_is_refused() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#obj0").with_transforms(&[XPATH_URI, C14N_EXC]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::TransformNotAllowed, CheckStatus::Failed);
}

#[test]
fn canonical_xml_11_is_reported_as_unsupported() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.c14n = "http://www.w3.org/2006/12/xml-c14n11".to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::C14nUnsupported, CheckStatus::Failed);
}

#[test]
fn a_sha1_signature_method_is_rejected() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.signature_method = RSA_SHA1_URI.to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

#[test]
fn an_hmac_signature_method_is_rejected() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.signature_method = HMAC_SHA256_URI.to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
}

#[test]
fn a_sha1_digest_method_is_rejected() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#obj0").with_digest(SHA1_URI);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
}

/// A signature that verifies cryptographically but omits the mandated
/// `es:DocumentProfile` reference must still fail. This is the container-aware
/// check no generic XMLDSig library can perform.
#[test]
fn a_signature_that_does_not_cover_the_document_profile_fails() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references.remove(1);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// A signature whose XAdES properties exist but are not referenced fails the
/// same check.
#[test]
fn unreferenced_signed_properties_fail_the_scope_check() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references.pop();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
}

/// A wrapping attempt: a copy of the payload is placed in a second, unsigned
/// document. The signature still covers the original, and `resolved_to` shows
/// a caller exactly which node was signed.
///
/// Nothing here fails — the signature is exactly as sound as it was — but the
/// second document is covered by no signature, so the dossier cannot be
/// `valid`: a verdict of `valid` must mean the whole dossier's content is
/// signed. See the architecture document's "Document coverage" section.
#[test]
fn a_duplicated_payload_elsewhere_does_not_change_what_was_signed() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        decoy_object: Some(("obj-decoy".to_owned(), "d29ybGQ=".to_owned())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    let resolved = report.signatures[0].references[0]
        .resolved_to
        .as_deref()
        .expect("the reference resolved");
    assert_eq!(resolved, "Dossier/Documents/Document/Object");
    // The decoy is a document nothing signs, which is now said out loud.
    assert_eq!(report.documents[1].coverage, CoverageState::Uncovered);
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
    assert_ne!(report.verdict, Verdict::Valid);
}

/// The same payload ID in two places is a parse error before verification even
/// starts, which is what makes reference resolution unambiguous.
#[test]
fn a_duplicate_id_is_a_structural_error() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        decoy_object: Some(("obj0".to_owned(), "d29ybGQ=".to_owned())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let trust = MemoryTrustStore::new(vec![pki.root_der], Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at("2020-06-01T00:00:00Z");
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    let error = verify(xml.as_bytes(), &options).expect_err("a duplicate ID must not verify");
    assert_eq!(error.code(), openszigno_core::ErrorCode::DuplicateId);
}

// ---------------------------------------------------------------------------
// Negative cases: stage B cryptography
// ---------------------------------------------------------------------------

#[test]
fn tampering_with_the_payload_breaks_a_reference_digest() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let tampered = tamper(&xml, "<ds:Object Id=\"obj0\">");
    let report = run(&tampered, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceDigestMismatch,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.signatures[0].references[0].status,
        CheckStatus::Failed
    );
}

#[test]
fn tampering_with_the_signature_value_breaks_the_signature() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let tampered = tamper(&xml, "<ds:SignatureValue>");
    let report = run(&tampered, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::SignatureValueInvalid,
        CheckStatus::Failed,
    );
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
}

/// A signature made by a key other than the one in `ds:KeyInfo` must not
/// verify, however well-formed everything else is.
#[test]
fn a_certificate_for_a_different_key_does_not_verify() {
    let pki = simple_pki();
    let other_key = rsa_key(keys::SECOND_RSA2048);
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &other_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::SignatureValueInvalid,
        CheckStatus::Failed,
    );
}

#[test]
fn a_signature_without_key_info_has_no_signing_certificate() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.include_key_info = false;
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::SigningCertificateMissing,
        CheckStatus::Failed,
    );
    assert!(report.signatures[0].signing_certificate.is_none());
}

/// An RSA-1024 signing key is refused by the pinned policy before the
/// signature is even considered.
#[test]
fn an_rsa_1024_signing_key_is_rejected() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let weak_key = rsa_key(keys::WEAK_RSA1024);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Weak Signer"),
        &weak_key,
        &root,
        &root_key,
    );
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &weak_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    assert_eq!(
        report.signatures[0]
            .signing_certificate
            .as_ref()
            .and_then(|certificate| certificate.key_bits),
        Some(1024)
    );
}

// ---------------------------------------------------------------------------
// Negative cases: stage D certificate path
// ---------------------------------------------------------------------------

/// With no trust store the answer is `unknown`, never `untrusted`: the tool
/// does not know, and saying "invalid" would be as wrong as saying "valid".
#[test]
fn without_a_trust_store_the_path_is_unknown() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertPathUnknown, CheckStatus::Unknown);
    assert_no_failures(&report);
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.policy.trust_store, "absent");
}

#[test]
fn a_root_that_is_not_an_anchor_is_untrusted() {
    let pki = simple_pki();
    let other_root_key = rsa_key(keys::SECOND_RSA2048);
    let other_root = self_signed(
        &CertSpec::ca("Unrelated Root", BasicConstraints::Unconstrained),
        &other_root_key,
    );
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![other_root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertPathUntrusted, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

#[test]
fn a_signer_that_had_expired_at_the_validation_time_fails() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut spec = CertSpec::signer("Short-lived Signer");
    spec.not_before = (2019, 1, 1);
    spec.not_after = (2019, 6, 1);
    let signer = issued_by(&spec, &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);

    let inside = run(&xml, vec![root.der.clone()], "2019-03-01T00:00:00Z");
    assert_check(&inside, CheckCode::CertPathOk, CheckStatus::Passed);

    let outside = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&outside, CheckCode::CertExpired, CheckStatus::Failed);
}

#[test]
fn a_signer_that_was_not_yet_valid_fails() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(&CertSpec::signer("Signer"), &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2018-01-01T00:00:00Z");
    assert_check(&report, CheckCode::CertNotYetValid, CheckStatus::Failed);
}

#[test]
fn a_ca_without_key_cert_sign_fails() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut intermediate_spec = CertSpec::ca("Toothless CA", BasicConstraints::Unconstrained);
    intermediate_spec.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let intermediate = issued_by(&intermediate_spec, &intermediate_key, &root, &root_key);
    let signer = issued_by(
        &CertSpec::signer("Signer"),
        &signer_key,
        &intermediate,
        &intermediate_key,
    );
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der, intermediate.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertKeyUsageInvalid, CheckStatus::Failed);
}

#[test]
fn an_issuer_that_is_not_a_ca_fails() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let middle_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut middle_spec = CertSpec::signer("Not A CA");
    middle_spec.is_ca = IsCa::ExplicitNoCa;
    middle_spec.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let middle = issued_by(&middle_spec, &middle_key, &root, &root_key);
    let signer = issued_by(
        &CertSpec::signer("Signer"),
        &signer_key,
        &middle,
        &middle_key,
    );
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der, middle.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::CertBasicConstraintsInvalid,
        CheckStatus::Failed,
    );
}

#[test]
fn a_path_length_constraint_is_enforced() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let first_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let second_key = rsa_key(keys::SECOND_RSA2048);
    let signer_key = rsa_key(keys::THIRD_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let first = issued_by(
        &CertSpec::ca("Constrained CA", BasicConstraints::Constrained(0)),
        &first_key,
        &root,
        &root_key,
    );
    let second = issued_by(
        &CertSpec::ca("Sub CA", BasicConstraints::Unconstrained),
        &second_key,
        &first,
        &first_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Signer"),
        &signer_key,
        &second,
        &second_key,
    );
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der, second.der, first.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::CertPathLengthExceeded,
        CheckStatus::Failed,
    );
}

#[test]
fn a_name_constraint_violation_fails_the_path() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let mut root_spec = CertSpec::ca("Constrained Root", BasicConstraints::Unconstrained);
    let mut permitted = rcgen::DistinguishedName::new();
    permitted.push(rcgen::DnType::OrganizationName, "Some Other Organisation");
    root_spec.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DirectoryName(permitted)],
        excluded_subtrees: Vec::new(),
    });
    let root = self_signed(&root_spec, &root_key);
    let signer = issued_by(&CertSpec::signer("Signer"), &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}

#[test]
fn a_signer_without_a_signing_key_usage_fails() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut spec = CertSpec::signer("Encryption Only");
    spec.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
    let signer = issued_by(&spec, &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::CertKeyUsageInvalid, CheckStatus::Failed);
}

// ---------------------------------------------------------------------------
// Placement and scope edge cases
// ---------------------------------------------------------------------------

/// A signature somewhere the e-dossier format does not describe fails
/// placement; the scope of such a signature is unknown rather than complete.
#[test]
fn a_signature_in_an_undefined_place_fails_placement() {
    let xml = misplaced_signature();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::SigPlacementInvalid, CheckStatus::Failed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeUnknown,
        CheckStatus::Unknown,
    );
}

/// A `Document` without a `DocumentProfile` is non-conformant; the mandated
/// reference set is then undefined, so the honest answer is `unknown`.
#[test]
fn a_document_without_a_profile_makes_the_scope_unknown() {
    let xml = signature_on_a_profileless_document();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeUnknown,
        CheckStatus::Unknown,
    );
}

/// A signature with no `ds:SignedInfo` cannot be examined at all.
#[test]
fn a_malformed_signature_fails_structure() {
    let xml = structurally_broken_signature();
    let report = run_without_trust(&xml, "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::SigStructureInvalid, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

fn misplaced_signature() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>a</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><es:Wrapper><ds:Signature Id="sig-odd">"#.to_owned()
            + &signed_info("#obj0")
            + r#"<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></es:Wrapper></es:Document></es:Documents>"#,
    )
}

fn signature_on_a_profileless_document() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><ds:Object Id="obj0">aGVsbG8=</ds:Object><ds:Signature Id="sig-orphan">"#.to_owned()
            + &signed_info("#obj0")
            + r#"<ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></es:Document></es:Documents>"#,
    )
}

fn structurally_broken_signature() -> String {
    wrap(
        r#"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>a</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><ds:Signature Id="sig-broken"></ds:Signature></es:Document></es:Documents>"#.to_owned(),
    )
}

fn signed_info(uri: &str) -> String {
    format!(
        r#"<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="{C14N_EXC}"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo>"#
    )
}

fn wrap(body: String) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<es:Dossier xmlns:es=\"{}\" xmlns:ds=\"{}\">{body}</es:Dossier>",
        common::ESZIGNO_NS,
        common::DS_NS
    )
}

// ---------------------------------------------------------------------------
// Report shape and helpers
// ---------------------------------------------------------------------------

#[test]
fn the_report_exposes_only_the_documented_certificate_fields() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    let value = serde_json::to_value(&report).expect("the report serialises");
    let certificate = &value["signatures"][0]["signing_certificate"];
    let mut fields: Vec<&String> = certificate.as_object().expect("an object").keys().collect();
    fields.sort();
    assert_eq!(
        fields,
        vec![
            "issuer_cn",
            "key_algorithm",
            "key_bits",
            "not_after",
            "not_before",
            "qualified",
            "serial_hex",
            "sha256_fingerprint",
            "subject_cn",
        ]
    );
    assert_eq!(certificate["subject_cn"], "openSzigno Test Signer");
    assert_eq!(certificate["key_bits"], 2048);
    assert!(certificate["qualified"].is_null());
    assert_eq!(value["verdict"], "indeterminate");
    assert_eq!(value["verification_time"]["source"], "requested");
}

/// No check message may quote a certificate subject, a title, or payload
/// content; only structured fields carry those.
#[test]
fn check_messages_never_quote_signer_data() {
    let pki = simple_pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(pki.chain.clone())),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    for check in report.signatures[0]
        .checks
        .iter()
        .chain(report.checks.iter())
    {
        assert!(
            !check.message.contains("openSzigno Test Signer"),
            "a message quoted the signer: {}",
            check.message
        );
        assert!(
            !check.message.contains("Synthetic signed dossier"),
            "a message quoted a dossier title: {}",
            check.message
        );
    }
}

#[test]
fn rfc3339_round_trips() {
    for text in [
        "1970-01-01T00:00:00Z",
        "2020-06-01T12:34:56Z",
        "2039-12-31T23:59:59Z",
    ] {
        let parsed = parse_rfc3339(text).expect("parses");
        assert_eq!(openszigno_verify::format_rfc3339(parsed), text);
    }
    assert_eq!(
        parse_rfc3339("2020-06-01T12:34:56+02:00"),
        parse_rfc3339("2020-06-01T10:34:56Z")
    );
    assert_eq!(
        parse_rfc3339("2020-06-01T12:34:56.500Z"),
        parse_rfc3339("2020-06-01T12:34:56Z")
    );
    for bad in [
        "",
        "2020-06-01",
        "2020-06-01T12:34:56",
        "2020-13-01T00:00:00Z",
        "2020-06-01T25:00:00Z",
        "2020-06-01T00:00:00+2:00",
        "2020-06-01T00:00:00.Z",
        "20x0-06-01T00:00:00Z",
    ] {
        assert!(parse_rfc3339(bad).is_none(), "{bad} must not parse");
    }
}

/// Calendar validity is checked precisely, not merely bounded to 1..=31:
/// Feb 29 exists only in leap years (divisible by 4, except centuries unless
/// also divisible by 400), and no month runs past its real length.
#[test]
fn rfc3339_rejects_impossible_calendar_dates() {
    // Feb 29 in leap years: 2024 (div 4), 2000 (div 400) both parse.
    for leap in ["2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z"] {
        assert!(parse_rfc3339(leap).is_some(), "{leap} must parse");
    }
    // Feb 29 in non-leap years: 2023 (not div 4), 1900 (div 100, not 400).
    for non_leap in ["2023-02-29T00:00:00Z", "1900-02-29T00:00:00Z"] {
        assert!(
            parse_rfc3339(non_leap).is_none(),
            "{non_leap} must not parse"
        );
    }
    // Feb 30/31 never exist, in any year.
    for bad in ["2024-02-30T00:00:00Z", "2024-02-31T00:00:00Z"] {
        assert!(parse_rfc3339(bad).is_none(), "{bad} must not parse");
    }
    // April has 30 days, not 31; the classic silent-rollover case from the
    // review finding (2026-02-31 must not become 2026-03-03).
    assert!(parse_rfc3339("2026-04-31T00:00:00Z").is_none());
    assert!(parse_rfc3339("2026-02-31T00:00:00Z").is_none());
    // Valid month ends still parse.
    assert!(parse_rfc3339("2026-01-31T00:00:00Z").is_some());
    assert!(parse_rfc3339("2026-04-30T00:00:00Z").is_some());
}

/// Adding a non-passing check can only lower a verdict, never raise it.
#[test]
fn the_verdict_function_is_monotone() {
    use openszigno_verify::codes::{Check, verdict_of};
    let mut checks = vec![Check::passed(CheckCode::SigStructure, "ok")];
    assert_eq!(verdict_of(&checks), Verdict::Valid);
    checks.push(Check::skipped(CheckCode::RevocationNotChecked, "skipped"));
    assert_eq!(verdict_of(&checks), Verdict::Indeterminate);
    checks.push(Check::unknown(CheckCode::CertPathUnknown, "unknown"));
    assert_eq!(verdict_of(&checks), Verdict::Indeterminate);
    checks.push(Check::failed(CheckCode::SignatureValueInvalid, "failed"));
    assert_eq!(verdict_of(&checks), Verdict::Invalid);
    checks.push(Check::passed(CheckCode::SigPlacement, "ok"));
    assert_eq!(verdict_of(&checks), Verdict::Invalid);
}

/// Every declared check code has a distinct stable string.
#[test]
fn check_codes_are_distinct() {
    let mut strings: Vec<&str> = CheckCode::ALL.iter().map(|code| code.as_str()).collect();
    let count = strings.len();
    strings.sort_unstable();
    strings.dedup();
    assert_eq!(strings.len(), count);
}

/// A trust-store file may be PEM or DER; anything else is an error rather than
/// a silently empty store.
#[test]
fn trust_store_files_are_pem_or_der() {
    use openszigno_verify::certs::certificates_from_bytes;
    let pki = simple_pki();
    let der = pki.root_der.clone();
    assert_eq!(certificates_from_bytes(&der).expect("DER parses").len(), 1);

    let pem = pem_rfc7468_encode(&der);
    assert_eq!(
        certificates_from_bytes(pem.as_bytes())
            .expect("PEM parses")
            .len(),
        1
    );
    let two = format!("{pem}{pem}");
    assert_eq!(
        certificates_from_bytes(two.as_bytes())
            .expect("a PEM bundle parses")
            .len(),
        2
    );
    assert!(certificates_from_bytes(b"not a certificate").is_err());
    assert!(certificates_from_bytes(b"-----BEGIN CERTIFICATE-----\nzz\n").is_err());
    let _ = pki.signer_der;
}

fn pem_rfc7468_encode(der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

// ---------------------------------------------------------------------------
// Shapes the private corpus showed
// ---------------------------------------------------------------------------
//
// Real dossiers reference the `es:SignatureProfile` element rather than the
// `ds:Object` around it, place the profile and qualifying-properties objects in
// either order, and use XAdES 1.2.2 with a versioned `SignedProperties` Type.
// Each of those made every corpus signature stop at
// `reference_scope_incomplete` before any digest was recomputed.

/// A reference to the `es:SignatureProfile` element itself satisfies the
/// "own profile object" requirement, exactly as one to the `ds:Object` does.
#[test]
fn referencing_the_signature_profile_element_covers_the_profile_object() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[2] = RefSpec::to("#sigprof-doc");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(
        report.signatures[0].references[2].resolved_to.as_deref(),
        Some("Dossier/Documents/Document/Signature/Object/SignatureProfile")
    );
}

/// The profile object is found by content, so the order of the signature's
/// `ds:Object` children does not matter.
#[test]
fn the_profile_object_is_found_whichever_order_the_objects_are_in() {
    for reversed in [false, true] {
        let pki = simple_pki();
        let mut signature = dossier_signature(pki.chain.clone());
        signature.objects_reversed = reversed;
        let spec = DossierSpec {
            dossier_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("frame", &pki.signer_key)]);
        let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
        assert_no_failures(&report);
        assert_check(
            &report,
            CheckCode::ReferenceScopeComplete,
            CheckStatus::Passed,
        );
    }
}

/// Legacy XAdES 1.2.2, with the versioned `SignedProperties` Type URI, is
/// detected and its properties count as covered.
#[test]
fn legacy_xades_122_is_detected_and_its_signed_properties_are_covered() {
    let pki = simple_pki();
    let mut signature = dossier_signature(pki.chain.clone());
    signature.xades_namespace = common::XADES_NS_122.to_owned();
    signature.references[3] = RefSpec {
        reference_type: Some(common::SIGNED_PROPERTIES_TYPE_122.to_owned()),
        ..RefSpec::to("#sp-frame")
    };
    let spec = DossierSpec {
        dossier_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("frame", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::XadesPresent, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(report.signatures[0].xades_level, Some("detected"));
}

/// Coverage is decided by resolution, not by the `Type` attribute: a reference
/// that declares the SignedProperties type but resolves elsewhere does not
/// satisfy the requirement, and the message says so.
#[test]
fn a_signed_properties_type_cannot_stand_in_for_resolution() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[3] = RefSpec {
        reference_type: Some(SIGNED_PROPERTIES_TYPE.to_owned()),
        ..RefSpec::to("#prof0")
    };
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::ReferenceScopeIncomplete)
        .map(|check| check.message.clone())
        .expect("the check was emitted");
    assert!(
        message.contains("declares the SignedProperties Type"),
        "{message}"
    );
}

/// A reference to the `ds:Object` that wraps the qualifying properties covers
/// the `SignedProperties` inside it.
#[test]
fn a_reference_to_an_ancestor_covers_the_signed_properties() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    // Cover the whole document instead of the individual elements.
    signature.references = vec![RefSpec::to("").with_transforms(&[ENVELOPED_URI, C14N_EXC])];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_no_failures(&report);
    assert_check(&report, CheckCode::XadesPresent, CheckStatus::Passed);
}

/// A caller must always see what each URI resolved to, even when the run
/// stopped before any digest was recomputed.
#[test]
fn resolved_to_is_reported_even_when_the_policy_stage_fails() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] = RefSpec::to("#obj0").with_transforms(&[XSLT_URI, C14N_EXC]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::TransformNotAllowed, CheckStatus::Failed);
    let references = &report.signatures[0].references;
    assert_eq!(references.len(), 4);
    for reference in references {
        assert_eq!(reference.status, CheckStatus::Skipped);
        assert!(
            reference.resolved_to.is_some(),
            "{} resolved to nothing",
            reference.uri
        );
    }
    assert_eq!(
        references[0].resolved_to.as_deref(),
        Some("Dossier/Documents/Document/Object")
    );
}

// ---------------------------------------------------------------------------
// --allow-legacy-algorithms
// ---------------------------------------------------------------------------

fn run_legacy(xml: &str, anchors: Vec<Vec<u8>>, time: &str) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = at(time);
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    options.allow_legacy_algorithms = true;
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// A SHA-1 signature is refused by default and admitted only for diagnosis,
/// and even then the verdict stays `indeterminate`.
#[test]
fn a_sha1_signature_is_refused_by_default_and_diagnosed_with_the_flag() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.signature_method = RSA_SHA1_URI.to_owned();
    signature.references = signature
        .references
        .into_iter()
        .map(|reference| RefSpec {
            digest_uri: SHA1_URI.to_owned(),
            ..reference
        })
        .collect();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);

    let strict = run(&xml, vec![pki.root_der.clone()], "2020-06-01T00:00:00Z");
    assert_check(&strict, CheckCode::AlgorithmRejected, CheckStatus::Failed);
    assert_eq!(strict.verdict, Verdict::Invalid);
    assert!(!strict.policy.legacy_algorithms_allowed);

    let lenient = run_legacy(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &lenient,
        CheckCode::AlgorithmLegacyAllowed,
        CheckStatus::Unknown,
    );
    assert!(!has(
        &lenient,
        CheckCode::AlgorithmRejected,
        CheckStatus::Failed
    ));
    // The digests and the signature value really are recomputed under SHA-1,
    // which is the point of the flag: it diagnoses, it does not excuse.
    assert_check(&lenient, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(&lenient, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_eq!(lenient.verdict, Verdict::Indeterminate);
    assert!(lenient.policy.legacy_algorithms_allowed);
    assert!(lenient.policy.digest_algorithms.contains(&"sha1"));
}

/// The flag never turns a failure into a pass: a SHA-1 signature over tampered
/// content still fails.
#[test]
fn the_legacy_flag_cannot_rescue_a_broken_signature() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.signature_method = RSA_SHA1_URI.to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let tampered = tamper(&xml, "<ds:Object Id=\"obj0\">");
    let report = run_legacy(&tampered, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(
        &report,
        CheckCode::ReferenceDigestMismatch,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// MD5, HMAC, DSA, and short RSA keys stay refused whatever the flag says.
#[test]
fn the_legacy_flag_does_not_admit_md5_hmac_dsa_or_short_keys() {
    let pki = simple_pki();
    for method in [
        HMAC_SHA256_URI,
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
    ] {
        let mut signature = document_signature(pki.chain.clone());
        signature.signature_method = method.to_owned();
        let spec = DossierSpec {
            document_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("doc", &pki.signer_key)]);
        let report = run_legacy(&xml, vec![pki.root_der.clone()], "2020-06-01T00:00:00Z");
        assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
    }

    let root_key = rsa_key(keys::ROOT_RSA2048);
    let weak_key = rsa_key(keys::WEAK_RSA1024);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Weak Signer"),
        &weak_key,
        &root,
        &root_key,
    );
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &weak_key)]);
    let report = run_legacy(&xml, vec![root.der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
}

/// An MD5 digest is refused with the flag too.
#[test]
fn the_legacy_flag_does_not_admit_an_md5_digest() {
    let pki = simple_pki();
    let mut signature = document_signature(pki.chain.clone());
    signature.references[0] =
        RefSpec::to("#obj0").with_digest("http://www.w3.org/2001/04/xmldsig-more#md5");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run_legacy(&xml, vec![pki.root_der], "2020-06-01T00:00:00Z");
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
}
