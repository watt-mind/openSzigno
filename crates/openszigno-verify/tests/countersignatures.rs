//! Countersignatures: the two forms a dossier can carry one in, and the
//! boundary between "this build does not support that nesting" and "this
//! signature does not hold".
//!
//! The XAdES enveloped form is ETSI EN 319 132-1 clause 5.2.7.2 (TS 101903
//! clause 7.2.4.2): a `ds:Signature` inside an `xades:CounterSignature` in the
//! countersigned signature's `xades:UnsignedSignatureProperties`, referencing
//! that signature's `ds:SignatureValue`. The e-dossier form is the Microsec
//! specification's own, clauses 3.2.1.3.1 and 3.2.1.3.4.1.3: an ordinary
//! document- or dossier-level signature whose signed `es:SignatureProfile`
//! declares `es:Type` `countersignature` and which references the
//! countersigned `ds:SignatureValue`.
//!
//! Every dossier here is synthetic and every certificate is minted by the
//! in-tests PKI.

mod common;

use common::{
    C14N_EXC, CertSpec, CounterSignatureSpec, CrlSpec, DossierSpec, ENVELOPED_URI,
    ExtraDocumentSpec, RefSpec, SigSpec, SigningCertificateSpec, TestKey, TimestampSpec, build,
    build_crl, countersignature, document_signature, dossier_signature,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed, tamper,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    CoverageState, FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation,
    RoxmltreeC14n, SignatureRole, SignatureScope, Verdict, VerifyOptions, VerifyReport,
    parse_rfc3339, verify,
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
    counter_der: Vec<u8>,
    counter_key: TestKey,
    tsa_der: Vec<u8>,
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let counter_key = rsa_key(keys::SECOND_RSA2048);
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
    let counter = issued_by(
        &CertSpec::signer("openSzigno Test Countersigner"),
        &counter_key,
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
        counter_der: counter.der,
        counter_key,
        tsa_der: tsa.der,
    }
}

/// Everything a signature needs to reach `valid`: a bound signing certificate
/// and a timestamp whose authority chains to the same root.
fn complete(pki: &Pki, certificate: &[u8], mut signature: SigSpec) -> SigSpec {
    signature.signing_certificate = Some(SigningCertificateSpec::v1(certificate.to_vec()));
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    );
    timestamp.token_certificates = vec![pki.root_der.clone()];
    signature.timestamp = Some(timestamp);
    signature
}

/// The countersigned document signature, with an `Id` on its
/// `ds:SignatureValue` so a countersignature can name it.
fn countersigned_document_signature(pki: &Pki) -> SigSpec {
    let mut signature = complete(
        pki,
        &pki.signer_der,
        document_signature(vec![pki.signer_der.clone()]),
    );
    signature.signature_value_id = Some("sigval-doc".to_owned());
    signature
}

/// A well-formed enveloped countersignature over `sigval-doc`.
fn enveloped_countersignature(pki: &Pki) -> SigSpec {
    complete(
        pki,
        &pki.counter_der,
        countersignature("csig", vec![pki.counter_der.clone()], "sigval-doc"),
    )
}

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

fn run_bare(xml: &str) -> VerifyReport {
    let trust = MemoryTrustStore::default();
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn seen(report: &VerifyReport) -> Vec<String> {
    report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .map(|check| format!("{}={}", check.code.as_str(), check.status.as_str()))
        .collect()
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    let seen = seen(report);
    assert!(
        seen.contains(&format!("{}={}", code.as_str(), status.as_str())),
        "expected {}={}; got {seen:?}",
        code.as_str(),
        status.as_str()
    );
}

/// Whether one signature emitted a code, whatever its status.
fn signature_has(report: &VerifyReport, index: usize, code: CheckCode) -> bool {
    report.signatures[index]
        .checks
        .iter()
        .any(|check| check.code == code)
}

// ---------------------------------------------------------------------------
// The XAdES enveloped form
// ---------------------------------------------------------------------------

/// The headline case: a countersignature that references the
/// `ds:SignatureValue` of the signature it is embedded in is verified like any
/// other signature, and both reach `valid`.
#[test]
fn an_enveloped_countersignature_binds_to_the_signature_it_is_embedded_in() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(enveloped_countersignature(&pki))];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let xml = build(
        &spec,
        &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
    );
    let report = run_trusted(&xml, &pki);

    assert_eq!(report.signatures.len(), 2);
    let counter = &report.signatures[1];
    assert_eq!(counter.placement, SignatureScope::Countersignature);
    // The original field name keeps reporting the same value.
    assert_eq!(counter.scope, SignatureScope::Countersignature);
    assert_eq!(counter.role, SignatureRole::Countersignature);
    assert_eq!(counter.parent_signature_index, Some(0));
    assert_eq!(counter.countersigns, vec![0]);
    // A countersignature sits in no document, so it has no document index.
    assert_eq!(counter.document_index, None);

    assert_check(
        &report,
        CheckCode::CountersignatureBindingOk,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::SigPlacement, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::ReferenceScopeComplete,
        CheckStatus::Passed,
    );
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_eq!(counter.verdict, Verdict::Valid);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.counts.signatures_valid, 2);
}

/// The parent signature keeps `role: signature` and gains no countersignature
/// binding of its own, and the nested signature's own profile object and
/// signed properties never satisfy the parent's mandated set.
#[test]
fn the_countersigned_signature_keeps_its_own_role_and_scope() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(enveloped_countersignature(&pki))];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    assert_eq!(report.signatures[0].role, SignatureRole::Signature);
    assert_eq!(report.signatures[0].placement, SignatureScope::Document);
    assert_eq!(report.signatures[0].parent_signature_index, None);
    assert!(report.signatures[0].countersigns.is_empty());
    assert!(!signature_has(
        &report,
        0,
        CheckCode::CountersignatureBindingOk
    ));
    // The nested countersignature is processed, so it is not filed as an
    // unvalidated qualifying property.
    assert!(
        !report.signatures[0]
            .xades
            .unvalidated_properties
            .contains(&"CounterSignature".to_owned())
    );
}

/// A countersignature attests the signature, not the payload: it grants no
/// document coverage, and the coverage of every document is decided exactly as
/// it would be without it.
#[test]
fn a_countersignature_grants_no_document_coverage() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(enveloped_countersignature(&pki))];
    let spec = DossierSpec {
        document_signature: Some(parent),
        extra_documents: vec![ExtraDocumentSpec::new("obj-second")],
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    let states: Vec<CoverageState> = report
        .documents
        .iter()
        .map(|document| document.coverage)
        .collect();
    assert_eq!(
        states,
        vec![CoverageState::Covered, CoverageState::Uncovered]
    );
    // Only the document signature covers anything; the countersignature is in
    // no `covered_by` list.
    assert!(
        report
            .documents
            .iter()
            .flat_map(|document| document.covered_by.iter())
            .all(|entry| entry.signature_index == 0)
    );
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// Tampering with the countersigned `ds:SignatureValue` breaks both: the
/// signature whose value it is, and the countersignature that digested it. The
/// binding itself is structural and still holds, which is what makes the
/// finding readable: the countersignature really does attest signature 0, and
/// what it attested has changed.
#[test]
fn a_tampered_countersigned_value_breaks_the_countersignature_too() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(enveloped_countersignature(&pki))];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let xml = build(
        &spec,
        &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
    );
    let xml = tamper(&xml, "<ds:SignatureValue Id=\"sigval-doc\">");
    let report = run_trusted(&xml, &pki);

    assert_eq!(report.signatures[0].verdict, Verdict::Invalid);
    assert_check(
        &report,
        CheckCode::SignatureValueInvalid,
        CheckStatus::Failed,
    );
    // The countersignature still names signature 0 and nothing else.
    assert_eq!(report.signatures[1].countersigns, vec![0]);
    assert!(signature_has(
        &report,
        1,
        CheckCode::CountersignatureBindingOk
    ));
    // What it signed changed under it, so its own reference digest fails.
    assert!(signature_has(
        &report,
        1,
        CheckCode::ReferenceDigestMismatch
    ));
    assert_eq!(report.signatures[1].verdict, Verdict::Invalid);
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// A nested signature that resolves to a `ds:SignatureValue` other than its
/// lexical parent's is a mismatch, not a countersignature. This is the
/// wrapping shape: the element says "I countersign the signature I am inside",
/// and the reference says otherwise.
#[test]
fn a_countersignature_over_a_foreign_signature_value_is_a_mismatch() {
    let pki = pki();
    let mut nested = enveloped_countersignature(&pki);
    nested.references[0] = RefSpec::countersigned("#sigval-frame");
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(nested)];
    let mut frame = complete(
        &pki,
        &pki.signer_der,
        dossier_signature(vec![pki.signer_der.clone()]),
    );
    frame.signature_value_id = Some("sigval-frame".to_owned());
    let spec = DossierSpec {
        document_signature: Some(parent),
        dossier_signature: Some(frame),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[
                ("doc", &pki.signer_key),
                ("csig", &pki.counter_key),
                ("frame", &pki.signer_key),
            ],
        ),
        &pki,
    );

    let counter = &report.signatures[1];
    assert_eq!(counter.placement, SignatureScope::Countersignature);
    assert_eq!(counter.parent_signature_index, Some(0));
    assert_check(
        &report,
        CheckCode::CountersignatureBindingMismatch,
        CheckStatus::Failed,
    );
    assert_eq!(counter.verdict, Verdict::Invalid);
    // A binding that actually fails is a finding, so it does reach the
    // dossier: this is not the incomplete-support case.
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// A nested signature that references no `ds:SignatureValue` at all is a
/// countersignature with nothing bound, which is `failed` rather than a
/// silently ordinary signature.
#[test]
fn a_nested_signature_that_binds_nothing_is_reported_as_missing() {
    let pki = pki();
    let mut nested = enveloped_countersignature(&pki);
    nested.references[0] = RefSpec::to("#obj0");
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(nested)];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    assert_check(
        &report,
        CheckCode::CountersignatureBindingMissing,
        CheckStatus::Failed,
    );
    assert_eq!(report.signatures[1].verdict, Verdict::Invalid);
}

/// The enveloped-signature transform inside a countersignature cannot take the
/// countersigned `ds:SignatureValue` with it.
///
/// XMLDSig 1.1 clause 6.6.4 removes only "the whole `Signature` element
/// containing T", and an enveloped countersignature sits *inside* the
/// signature it attests, so the parent's `ds:SignatureValue` is never in the
/// removed subtree. The binding therefore still holds, and the transform
/// changes neither the digest nor the effective node set of that reference.
#[test]
fn an_enveloped_transform_in_a_countersignature_still_binds_to_the_parent() {
    let pki = pki();
    let mut nested = enveloped_countersignature(&pki);
    nested.references[0] =
        RefSpec::countersigned("#sigval-doc").with_transforms(&[ENVELOPED_URI, C14N_EXC]);
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(nested)];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    assert_check(
        &report,
        CheckCode::CountersignatureBindingOk,
        CheckStatus::Passed,
    );
    assert_eq!(report.signatures[1].countersigns, vec![0]);
    assert_eq!(report.signatures[1].verdict, Verdict::Valid);
}

/// The other direction is where the removal bites: a signature that references
/// a `ds:SignatureValue` **inside itself** — the one belonging to an enveloped
/// countersignature in its own unsigned properties — and then removes itself
/// with the enveloped-signature transform digests none of that value, so it
/// binds nothing.
///
/// Resolution alone said otherwise, which is exactly the reference-scope
/// finding this file's rule shares with `scope`: the binding is decided by the
/// effective node set, not by where a URI points.
#[test]
fn a_reference_to_a_signature_value_the_enveloped_transform_removes_binds_nothing() {
    let pki = pki();
    let mut nested = enveloped_countersignature(&pki);
    nested.signature_value_id = Some("sigval-csig".to_owned());
    let mut parent = countersigned_document_signature(&pki);
    parent.signature_profile_type = "countersignature".to_owned();
    parent
        .references
        .push(RefSpec::countersigned("#sigval-csig").with_transforms(&[ENVELOPED_URI, C14N_EXC]));
    parent.countersignatures = vec![CounterSignatureSpec::new(nested)];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    // The parent declares the e-dossier countersignature role, and its one
    // candidate reference covers nothing, so the binding is missing rather
    // than satisfied.
    assert!(signature_has(
        &report,
        0,
        CheckCode::CountersignatureBindingMissing
    ));
    assert!(report.signatures[0].countersigns.is_empty());
}

// ---------------------------------------------------------------------------
// Unsupported nesting, which is not invalidity
// ---------------------------------------------------------------------------

/// EN 319 132-1 clause 5.2.7.2 defines `CounterSignatureType` as a sequence of
/// exactly one `ds:Signature`. Two of them leave two candidate parents and no
/// rule for choosing, so nothing is guessed — and, crucially, the signature
/// they were dropped into is not affected.
#[test]
fn two_signatures_in_one_counter_signature_are_unsupported() {
    let pki = pki();
    let mut second = enveloped_countersignature(&pki);
    second.id = "sig-csig2".to_owned();
    second.tag = "csig2".to_owned();
    second.references = vec![
        RefSpec::countersigned("#sigval-doc"),
        RefSpec::to("#sigobj-csig2"),
        RefSpec::signed_properties("#sp-csig2"),
    ];
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::ambiguous(
        enveloped_countersignature(&pki),
        second,
    )];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[
                ("doc", &pki.signer_key),
                ("csig", &pki.counter_key),
                ("csig2", &pki.counter_key),
            ],
        ),
        &pki,
    );

    assert_eq!(report.signatures.len(), 3);
    for index in [1, 2] {
        assert_eq!(report.signatures[index].placement, SignatureScope::Unknown);
        assert_eq!(report.signatures[index].role, SignatureRole::Signature);
        assert!(signature_has(
            &report,
            index,
            CheckCode::SigPlacementInvalid
        ));
    }
    // The parent is told, and keeps its verdict.
    assert!(signature_has(
        &report,
        0,
        CheckCode::NestedSignaturesUnsupported
    ));
    assert_check(
        &report,
        CheckCode::NestedSignaturesUnsupported,
        CheckStatus::Info,
    );
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);

    // Incomplete support caps the dossier at `indeterminate`. It never makes
    // it `invalid`: a nesting this build does not implement is missing
    // support, not evidence of forgery.
    assert_check(
        &report,
        CheckCode::SignaturesUnsupported,
        CheckStatus::Unknown,
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// A signature nested under something that is not an
/// `xades:UnsignedSignatureProperties/xades:CounterSignature` is the same
/// answer: unsupported placement, and the enclosing signature is untouched.
#[test]
fn a_signature_nested_in_an_arbitrary_element_is_unsupported() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::in_wrapper(
        enveloped_countersignature(&pki),
        "xades:SomeOtherProperty",
    )];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );

    assert_eq!(report.signatures[1].placement, SignatureScope::Unknown);
    assert_check(&report, CheckCode::SigPlacementInvalid, CheckStatus::Failed);
    // The message names the reason rather than only saying "not a placement
    // the format defines".
    let message = report.signatures[1]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::SigPlacementInvalid)
        .map(|check| check.message.clone())
        .expect("the placement check is emitted");
    assert!(
        message.contains("xades:CounterSignature"),
        "the message must name the reason; got {message}"
    );
    assert!(signature_has(
        &report,
        0,
        CheckCode::NestedSignaturesUnsupported
    ));
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_check(
        &report,
        CheckCode::SignaturesUnsupported,
        CheckStatus::Unknown,
    );
    assert_ne!(report.verdict, Verdict::Invalid);
}

/// A signature at an undescribed placement that is not nested in another one
/// reaches the same conclusion, and no parent is told about it.
#[test]
fn an_unnested_undescribed_placement_still_only_caps_the_dossier() {
    let xml = misplaced_signature();
    let report = run_bare(&xml);

    assert_eq!(report.signatures[0].placement, SignatureScope::Unknown);
    assert_check(&report, CheckCode::SigPlacementInvalid, CheckStatus::Failed);
    assert_check(
        &report,
        CheckCode::SignaturesUnsupported,
        CheckStatus::Unknown,
    );
    assert!(!seen(&report).contains(&format!(
        "{}={}",
        CheckCode::NestedSignaturesUnsupported.as_str(),
        CheckStatus::Info.as_str()
    )));
    assert_ne!(report.verdict, Verdict::Invalid);
}

fn misplaced_signature() -> String {
    let body = r##"<es:DossierProfile Id="dossier-profile" OBJREF="documents"><es:Title>t</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate></es:DossierProfile><es:Documents Id="documents"><es:Document><es:DocumentProfile Id="prof0" OBJREF="obj0"><es:Title>a</es:Title><es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate><es:Format><es:MIME-Type type="text" subtype="plain"/></es:Format><es:BaseTransform><es:Transform Algorithm="base64"/></es:BaseTransform></es:DocumentProfile><ds:Object Id="obj0">aGVsbG8=</ds:Object><es:Wrapper><ds:Signature Id="sig-odd"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#obj0"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature></es:Wrapper></es:Document></es:Documents>"##;
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<es:Dossier xmlns:es=\"{}\" xmlns:ds=\"{}\">{body}</es:Dossier>",
        common::ESZIGNO_NS,
        common::DS_NS
    )
}

// ---------------------------------------------------------------------------
// The e-dossier form
// ---------------------------------------------------------------------------

/// The Microsec form: a sibling signature at an ordinary placement whose
/// signed `es:SignatureProfile/es:Type` says `countersignature` and whose
/// references include another signature's `ds:SignatureValue`. It verifies
/// exactly as a normal signature, plus the binding.
#[test]
fn an_e_dossier_form_countersignature_is_a_sibling_with_a_role() {
    let pki = pki();
    let mut frame = complete(
        &pki,
        &pki.counter_der,
        dossier_signature(vec![pki.counter_der.clone()]),
    );
    frame.signature_profile_type = "countersignature".to_owned();
    frame.references.push(RefSpec::to("#sigval-doc"));
    let spec = DossierSpec {
        document_signature: Some(countersigned_document_signature(&pki)),
        dossier_signature: Some(frame),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("frame", &pki.counter_key)],
        ),
        &pki,
    );

    let counter = &report.signatures[1];
    // Placement stays what it is: the e-dossier form is a sibling, not a
    // nesting, so only the role changes.
    assert_eq!(counter.placement, SignatureScope::Dossier);
    assert_eq!(counter.role, SignatureRole::Countersignature);
    assert_eq!(counter.parent_signature_index, None);
    assert_eq!(counter.countersigns, vec![0]);
    assert_check(
        &report,
        CheckCode::CountersignatureBindingOk,
        CheckStatus::Passed,
    );
    assert_eq!(counter.verdict, Verdict::Valid);
    assert_eq!(report.verdict, Verdict::Valid);
}

/// The deprecated Hungarian spelling the e-dossier schema keeps for
/// compatibility is recognised too.
#[test]
fn the_deprecated_hungarian_profile_type_is_recognised() {
    let pki = pki();
    let mut frame = complete(
        &pki,
        &pki.counter_der,
        dossier_signature(vec![pki.counter_der.clone()]),
    );
    frame.signature_profile_type = "ellenjegyzés".to_owned();
    frame.references.push(RefSpec::to("#sigval-doc"));
    let spec = DossierSpec {
        document_signature: Some(countersigned_document_signature(&pki)),
        dossier_signature: Some(frame),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("frame", &pki.counter_key)],
        ),
        &pki,
    );

    assert_eq!(report.signatures[1].role, SignatureRole::Countersignature);
    assert_eq!(report.signatures[1].countersigns, vec![0]);
}

/// A profile that declares a countersignature while referencing no other
/// signature's value is missing its binding, which is `failed`: the signed
/// declaration and the signed reference set contradict each other.
#[test]
fn an_e_dossier_form_countersignature_with_nothing_bound_fails() {
    let pki = pki();
    let mut frame = complete(
        &pki,
        &pki.counter_der,
        dossier_signature(vec![pki.counter_der.clone()]),
    );
    frame.signature_profile_type = "countersignature".to_owned();
    let spec = DossierSpec {
        document_signature: Some(countersigned_document_signature(&pki)),
        dossier_signature: Some(frame),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("frame", &pki.counter_key)],
        ),
        &pki,
    );

    assert_check(
        &report,
        CheckCode::CountersignatureBindingMissing,
        CheckStatus::Failed,
    );
    assert_eq!(report.signatures[1].role, SignatureRole::Countersignature);
    assert_eq!(report.signatures[1].verdict, Verdict::Invalid);
}

/// An ordinary signature declares nothing about a role, and gets no binding
/// check at all.
#[test]
fn an_ordinary_signature_carries_no_binding_check() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(complete(
            &pki,
            &pki.signer_der,
            document_signature(vec![pki.signer_der.clone()]),
        )),
        ..Default::default()
    };
    let report = run_trusted(&build(&spec, &[("doc", &pki.signer_key)]), &pki);

    assert_eq!(report.signatures[0].role, SignatureRole::Signature);
    assert!(report.signatures[0].countersigns.is_empty());
    for code in [
        CheckCode::CountersignatureBindingOk,
        CheckCode::CountersignatureBindingMissing,
        CheckCode::CountersignatureBindingMismatch,
    ] {
        assert!(!signature_has(&report, 0, code));
    }
    assert_eq!(report.verdict, Verdict::Valid);
}

// ---------------------------------------------------------------------------
// The JSON contract
// ---------------------------------------------------------------------------

/// The additive fields are present and carry what the architecture document
/// says they carry.
#[test]
fn the_json_carries_the_placement_role_and_parent() {
    let pki = pki();
    let mut parent = countersigned_document_signature(&pki);
    parent.countersignatures = vec![CounterSignatureSpec::new(enveloped_countersignature(&pki))];
    let spec = DossierSpec {
        document_signature: Some(parent),
        ..Default::default()
    };
    let report = run_trusted(
        &build(
            &spec,
            &[("doc", &pki.signer_key), ("csig", &pki.counter_key)],
        ),
        &pki,
    );
    let value = serde_json::to_value(&report).expect("the report serialises");

    let first = &value["signatures"][0];
    assert_eq!(first["placement"], "document");
    assert_eq!(first["scope"], "document");
    assert_eq!(first["role"], "signature");
    assert!(first["parent_signature_index"].is_null());
    assert_eq!(first["countersigns"], serde_json::json!([]));

    let second = &value["signatures"][1];
    assert_eq!(second["placement"], "countersignature");
    assert_eq!(second["scope"], "countersignature");
    assert_eq!(second["role"], "countersignature");
    assert_eq!(second["parent_signature_index"], 0);
    assert_eq!(second["countersigns"], serde_json::json!([0]));
}
