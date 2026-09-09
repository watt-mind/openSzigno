//! Per-document signature coverage: which modelled documents the signatures
//! in a dossier actually cover.
//!
//! Coverage is decided by what the resolved references digest — the effective
//! node set of each one — and the implemented scope rules,
//! never by where a signature sits, and it is kept apart from every
//! cryptographic outcome. Every dossier here is synthetic and every
//! certificate is minted by the in-tests PKI.

mod common;

use common::{
    C14N_EXC, CertSpec, CrlSpec, DossierSpec, ENVELOPED_URI, ExtraDocumentSpec, RefSpec, SigSpec,
    SigningCertificateSpec, TestKey, TimestampSpec, XSLT_URI, build, build_crl, document_signature,
    dossier_signature, extended_key_usage_extension, issued_by, keys, rsa_key, self_signed, tamper,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    CoverageState, CoverageVia, FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation,
    RoxmltreeC14n, Verdict, VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

/// A validation time inside every synthetic certificate's window and inside
/// the synthetic CRL's freshness window.
const AT: &str = "2020-06-02T00:00:00Z";

struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    tsa_der: Vec<u8>,
}

fn pki() -> Pki {
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
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);
    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key,
        tsa_der: tsa.der,
    }
}

/// Everything a signature needs to reach `valid`: a bound signing certificate
/// and a timestamp whose authority chains to the same root.
fn complete(pki: &Pki, mut signature: SigSpec) -> SigSpec {
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    );
    timestamp.token_certificates = vec![pki.root_der.clone()];
    signature.timestamp = Some(timestamp);
    signature
}

/// A run with trust anchors and fresh revocation data, so `valid` is reachable.
fn run_trusted(xml: &str, pki: &Pki) -> VerifyReport {
    let crl = build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));
    let trust = MemoryTrustStore::new(vec![pki.root_der.clone()], Vec::new());
    let revocation = MemoryRevocationStore::new(vec![crl], Vec::new());
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// A run with no trust material at all, for the cases where only what a
/// signature covers is in question.
fn run_bare(xml: &str) -> VerifyReport {
    let trust = MemoryTrustStore::default();
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    let seen: Vec<String> = report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect();
    assert!(
        seen.contains(&format!("{}={}", code.as_str(), status.as_str())),
        "expected {}={}; got {seen:?}",
        code.as_str(),
        status.as_str()
    );
}

fn states(report: &VerifyReport) -> Vec<CoverageState> {
    report
        .documents
        .iter()
        .map(|document| document.coverage)
        .collect()
}

// ---------------------------------------------------------------------------
// The states
// ---------------------------------------------------------------------------

/// An unsigned dossier: every document is uncovered, and the dossier is
/// `indeterminate` because nothing signs its content.
#[test]
fn an_unsigned_dossier_leaves_every_document_uncovered() {
    let spec = DossierSpec {
        extra_documents: vec![ExtraDocumentSpec::new("obj-second")],
        ..Default::default()
    };
    let report = run_bare(&build(&spec, &[]));

    assert_eq!(
        states(&report),
        vec![CoverageState::Uncovered, CoverageState::Uncovered]
    );
    assert_eq!(report.counts.documents_uncovered, 2);
    assert_eq!(report.counts.documents_covered, 0);
    assert!(
        report
            .documents
            .iter()
            .all(|document| document.covered_by.is_empty())
    );
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// The rule this section exists for: a signature that verifies completely does
/// not make the *dossier* valid while a sibling document is signed by nothing.
/// A verdict of `valid` has to mean the whole dossier's content is signed.
#[test]
fn an_unsigned_sibling_caps_an_otherwise_valid_dossier() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(complete(
            &pki,
            document_signature(vec![pki.signer_der.clone()]),
        )),
        extra_documents: vec![ExtraDocumentSpec::new("obj-second")],
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("doc", &pki.signer_key)]), &pki);

    // The signature itself is beyond reproach; only the coverage of the
    // container is in question.
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_eq!(
        states(&report),
        vec![CoverageState::Covered, CoverageState::Uncovered]
    );
    assert_eq!(report.documents[0].covered_by[0].via, CoverageVia::Direct);
    assert_eq!(report.documents[0].covered_by[0].verdict, Verdict::Valid);
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// A frame signature covers `es:Documents`, so it covers every document under
/// it, and the dossier can then reach `valid`.
#[test]
fn a_frame_signature_covers_every_document() {
    let pki = pki();
    let spec = DossierSpec {
        dossier_signature: Some(complete(
            &pki,
            dossier_signature(vec![pki.signer_der.clone()]),
        )),
        extra_documents: vec![
            ExtraDocumentSpec::new("obj-second"),
            ExtraDocumentSpec::new("obj-third"),
        ],
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("frame", &pki.signer_key)]), &pki);

    assert_eq!(states(&report), vec![CoverageState::Covered; 3]);
    assert_eq!(report.counts.documents_covered, 3);
    assert!(
        report
            .documents
            .iter()
            .all(|document| document.covered_by[0].via == CoverageVia::Frame)
    );
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Passed);
    assert_eq!(report.verdict, Verdict::Valid);
}

/// Document coverage uses the same effective node set the scope check does.
///
/// A frame signature whose one payload reference is `URI=""` with the
/// enveloped-signature transform covers `es:Documents` — that sits outside the
/// `ds:Signature` the transform removes — and so covers every document. Its
/// own profile object and signed properties are inside the removed subtree and
/// need references of their own, which is precisely the split the scope check
/// enforces.
#[test]
fn an_enveloped_frame_signature_covers_the_documents_outside_it() {
    let pki = pki();
    let mut signature = dossier_signature(vec![pki.signer_der.clone()]);
    signature.references = vec![
        RefSpec::to("").with_transforms(&[ENVELOPED_URI, C14N_EXC]),
        RefSpec::to("#sigobj-frame"),
        RefSpec::signed_properties("#sp-frame"),
    ];
    let spec = DossierSpec {
        dossier_signature: Some(complete(&pki, signature)),
        extra_documents: vec![ExtraDocumentSpec::new("obj-second")],
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("frame", &pki.signer_key)]), &pki);

    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(states(&report), vec![CoverageState::Covered; 2]);
    assert!(
        report
            .documents
            .iter()
            .all(|document| document.covered_by[0].via == CoverageVia::Frame)
    );
}

/// A document-level signature covers the document it is placed in and nothing
/// else. Placement never grants coverage on its own, and a copy of a payload
/// somewhere else is not covered by the signature over the original.
#[test]
fn a_document_signature_never_covers_a_sibling() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(complete(
            &pki,
            document_signature(vec![pki.signer_der.clone()]),
        )),
        decoy_object: Some(("obj-decoy".to_owned(), "d29ybGQ=".to_owned())),
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("doc", &pki.signer_key)]), &pki);

    assert_eq!(
        states(&report),
        vec![CoverageState::Covered, CoverageState::Uncovered]
    );
    assert_eq!(report.documents[1].index, Some(1));
    assert_eq!(report.documents[1].object_ref.as_deref(), Some("obj-decoy"));
}

/// Coverage and cryptography are separate answers: a tampered payload leaves
/// the document covered — by a signature that does not verify.
#[test]
fn a_covered_document_whose_signature_fails_is_covered_unverified() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(complete(
            &pki,
            document_signature(vec![pki.signer_der.clone()]),
        )),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run_trusted(&tamper(&xml, "<ds:Object Id=\"obj0\">"), &pki);

    assert_eq!(report.signatures[0].verdict, Verdict::Invalid);
    assert_eq!(states(&report), vec![CoverageState::CoveredUnverified]);
    assert_eq!(report.documents[0].covered_by[0].verdict, Verdict::Invalid);
    assert_eq!(report.counts.documents_covered, 0);
    assert_eq!(report.counts.documents_uncovered, 0);
    // The finding is the signature's, so the coverage check does not repeat
    // it as a second unknown.
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Info);
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// A reference that resolves to nothing means the tool cannot say what the
/// signature covers. That is `undetermined`, not `uncovered`.
#[test]
fn an_unresolved_reference_leaves_coverage_undetermined() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.references[0] = RefSpec::to("#absent");
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let report = run_bare(&build(&spec, &[("doc", &pki.signer_key)]));

    assert_eq!(states(&report), vec![CoverageState::Undetermined]);
    assert_eq!(report.counts.documents_undetermined, 1);
    assert!(
        report.documents[0]
            .reason
            .as_deref()
            .expect("a reason")
            .contains("could not be evaluated")
    );
    assert_check(
        &report,
        CheckCode::DocumentsCoverageUndetermined,
        CheckStatus::Unknown,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// Processing this build refuses — an XSLT transform — leaves coverage
/// undetermined for the same reason: what the reference selects is unknown.
#[test]
fn unsupported_processing_leaves_coverage_undetermined() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.references[0] = RefSpec::to("#obj0").with_transforms(&[XSLT_URI]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let report = run_bare(&build(&spec, &[("doc", &pki.signer_key)]));

    assert_eq!(states(&report), vec![CoverageState::Undetermined]);
    assert_check(
        &report,
        CheckCode::DocumentsCoverageUndetermined,
        CheckStatus::Unknown,
    );
}

/// A document the parser skipped is listed with the parser's own reason, and
/// is counted in none of the three coverage counts: it is not one of the
/// modelled documents.
#[test]
fn a_profile_less_document_is_listed_as_not_modelled() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(complete(
            &pki,
            document_signature(vec![pki.signer_der.clone()]),
        )),
        extra_documents: vec![ExtraDocumentSpec::new("obj-bare").without_profile()],
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("doc", &pki.signer_key)]), &pki);

    assert_eq!(
        states(&report),
        vec![CoverageState::Covered, CoverageState::NotModelled]
    );
    let skipped = &report.documents[1];
    assert_eq!(skipped.index, None);
    assert_eq!(skipped.object_ref, None);
    assert!(
        skipped
            .reason
            .as_deref()
            .expect("the parser's reason")
            .contains("no DocumentProfile")
    );
    assert_eq!(report.counts.documents_covered, 1);
    assert_eq!(report.counts.documents_uncovered, 0);
    assert_eq!(report.counts.documents_undetermined, 0);
    assert_check(&report, CheckCode::DocumentsAllCovered, CheckStatus::Passed);
}

/// An embedded dossier is payload like any other, and covered like any other.
/// This run says nothing whatever about the signatures inside it: there is no
/// implied recursion, and the report states so.
#[test]
fn an_embedded_dossier_is_covered_without_recursion() {
    let pki = pki();
    let spec = DossierSpec {
        dossier_signature: Some(complete(
            &pki,
            dossier_signature(vec![pki.signer_der.clone()]),
        )),
        extra_documents: vec![ExtraDocumentSpec::new("obj-inner").nested()],
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("frame", &pki.signer_key)]), &pki);

    let inner = &report.documents[1];
    assert!(inner.nested_dossier);
    assert_eq!(inner.coverage, CoverageState::Covered);
    assert_eq!(inner.covered_by[0].via, CoverageVia::Frame);
    assert!(
        inner
            .reason
            .as_deref()
            .expect("the no-recursion note")
            .contains("inner signatures are not verified")
    );
    // The inner dossier's own signatures are not counted anywhere.
    assert_eq!(report.counts.signatures, 1);
    assert_eq!(report.verdict, Verdict::Valid);
}

/// A whole-document reference carrying the enveloped-signature transform
/// covers **nothing inside the signature it is written in**, so it satisfies
/// no scope requirement about the signature's own elements and the dossier is
/// left unsigned.
///
/// XMLDSig 1.1 clause 6.6.4: the transform "removes the whole `Signature`
/// element containing T from the digest calculation of the `Reference` element
/// containing T". The `xades:SignedProperties` — which carries the
/// `SigningCertificate` binding — and the signature's own profile `ds:Object`
/// both live there, so neither is in the digested bytes and neither may be
/// credited to the reference. Treating them as covered let unauthenticated
/// XAdES properties reach the later stages, which is what this regression
/// guards.
#[test]
fn an_enveloped_whole_document_reference_covers_nothing_inside_the_signature() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.references = vec![RefSpec::to("").with_transforms(&[ENVELOPED_URI, C14N_EXC])];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let report = run_bare(&build(&spec, &[("doc", &pki.signer_key)]));

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
    assert!(message.contains("xades:SignedProperties"), "{message}");
    assert!(
        message.contains("ds:Signature/ds:Object holding es:SignatureProfile"),
        "{message}"
    );
    // The document's own profile and payload object sit outside the removed
    // subtree, so they stay covered and are not named.
    assert!(!message.contains("es:DocumentProfile"), "{message}");
    assert!(!message.contains("es:Document/ds:Object"), "{message}");
    // And with the mandated set incomplete, the document it is placed in is
    // covered by nothing.
    assert_eq!(states(&report), vec![CoverageState::Uncovered]);
}

/// A frame signature whose mandated set is incomplete covers nothing: the
/// container's own rule for what it must reference was not met.
#[test]
fn an_incomplete_frame_scope_covers_nothing() {
    let pki = pki();
    let mut signature = dossier_signature(vec![pki.signer_der.clone()]);
    // Drop the reference to `es:Documents`.
    signature.references.remove(0);
    let spec = DossierSpec {
        dossier_signature: Some(signature),
        ..Default::default()
    };
    let report = run_bare(&build(&spec, &[("frame", &pki.signer_key)]));

    assert_check(
        &report,
        CheckCode::ReferenceScopeIncomplete,
        CheckStatus::Failed,
    );
    assert_eq!(states(&report), vec![CoverageState::Uncovered]);
}

/// XMLDSig's schema spells the attribute `Id`, but real dossiers also carry
/// `ID` and `id`, and the parser, the reference resolver and the XAdES reader
/// all accept the three spellings. Coverage read only `Id`, so a document
/// whose payload object spelled it `id` was reported as uncovered by the very
/// signature that digests it.
#[test]
fn a_lowercase_payload_id_reports_the_same_coverage() {
    let pki = pki();
    let coverage_of = |attribute: &'static str| {
        let spec = DossierSpec {
            payload_id_attribute: attribute,
            document_signature: Some(complete(
                &pki,
                document_signature(vec![pki.signer_der.clone()]),
            )),
            ..Default::default()
        };
        let report = run_trusted(&build(&spec, &[("doc", &pki.signer_key)]), &pki);
        assert_eq!(
            report.signatures[0].verdict,
            Verdict::Valid,
            "the signature itself is unaffected by how the attribute is spelled"
        );
        (
            states(&report),
            report.documents[0].covered_by[0].via,
            report.verdict,
        )
    };

    assert_eq!(coverage_of("id"), coverage_of("Id"));
    assert_eq!(
        coverage_of("id"),
        (
            vec![CoverageState::Covered],
            CoverageVia::Direct,
            Verdict::Valid
        )
    );
}
