//! Stage C: the XAdES signed properties.
//!
//! The property that decides anything is `SigningCertificate`: it is signed,
//! so it — and not `ds:KeyInfo` — says which certificate signed. Every test
//! here is built from synthetic material generated at test time.

mod common;

use common::{
    CertSpec, DossierSpec, SHA1_URI, SHA512_URI, SigningCertificateSpec, TestKey, build,
    document_signature, issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, RoxmltreeC14n, Verdict, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

fn run(xml: &str, anchors: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-01T00:00:00Z").expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some("2020-06-01T00:00:00Z".to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn codes(report: &VerifyReport) -> Vec<String> {
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
    let seen = codes(report);
    assert!(
        seen.contains(&format!("{}={}", code.as_str(), status.as_str())),
        "expected {}={}; got {seen:?}",
        code.as_str(),
        status.as_str()
    );
}

struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
    /// A second certificate over the *same* key, issued by the same root: the
    /// substitution shape.
    twin_der: Vec<u8>,
    signer_key: TestKey,
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
    // Same key, different certificate: what a substituted `ds:KeyInfo` looks
    // like when the attacker cannot forge a signature but can swap identities.
    let twin = issued_by(
        &CertSpec::signer("openSzigno Test Signer Twin"),
        &signer_key,
        &root,
        &root_key,
    );
    Pki {
        root_der: root.der,
        signer_der: signer.der,
        twin_der: twin.der,
        signer_key,
    }
}

/// One signed dossier whose `SigningCertificate` property is built from `spec`.
fn dossier(pki: &Pki, spec: Option<SigningCertificateSpec>, certificates: Vec<Vec<u8>>) -> String {
    let mut signature = document_signature(certificates);
    signature.signing_certificate = spec;
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&dossier, &[("doc", &pki.signer_key)])
}

// ---------------------------------------------------------------------------
// The binding
// ---------------------------------------------------------------------------

#[test]
fn a_signing_certificate_v1_that_names_the_signer_binds() {
    let pki = pki();
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v1(pki.signer_der.clone())),
        vec![pki.signer_der.clone()],
    );
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
    let binding = report.signatures[0]
        .xades
        .signing_certificate
        .as_ref()
        .expect("the binding is reported");
    assert!(binding.matched);
    assert!(binding.issuer_serial_present);
    assert_eq!(binding.digest_algorithm, Some("sha256"));
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

#[test]
fn a_signing_certificate_v2_that_names_the_signer_binds() {
    let pki = pki();
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v2(pki.signer_der.clone())),
        vec![pki.signer_der.clone()],
    );
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
    assert_eq!(
        report.signatures[0]
            .xades
            .signing_certificate
            .as_ref()
            .map(|binding| binding.form),
        Some(Some(openszigno_verify::xades::SigningCertificateForm::V2))
    );
}

/// A `CertDigest` that matches nothing is a failure, not a shrug.
#[test]
fn a_wrong_certificate_digest_fails() {
    let pki = pki();
    let mut spec = SigningCertificateSpec::v1(pki.signer_der.clone());
    spec.wrong_digest = true;
    let xml = dossier(&pki, Some(spec), vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    assert!(
        !report.signatures[0]
            .xades
            .signing_certificate
            .as_ref()
            .expect("the binding is reported")
            .matched
    );
}

/// The substitution case: the signature verifies under the key of a
/// certificate that is **not** the one the signed property names. The
/// signature value is genuine and the binding still has to fail.
#[test]
fn a_substituted_certificate_with_the_same_key_fails() {
    let pki = pki();
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v1(pki.twin_der.clone())),
        // `ds:KeyInfo` offers the substitute first; both certificates carry the
        // same public key, so the key-based selection alone cannot tell them
        // apart.
        vec![pki.signer_der.clone(), pki.twin_der.clone()],
    );
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
    assert_eq!(report.verdict, Verdict::Invalid);
    // The signer reported is the one the *signed* property designates, so the
    // path was validated for the identity the signature actually claims.
    assert_eq!(report.signatures[0].signing_certificate_index, Some(1));
    assert_eq!(
        report.signatures[0]
            .signing_certificate
            .as_ref()
            .and_then(|summary| summary.subject_cn.clone()),
        Some("openSzigno Test Signer Twin".to_owned())
    );
}

/// A property naming a certificate that is nowhere in the signature fails
/// rather than being ignored.
#[test]
fn a_certificate_absent_from_key_info_fails() {
    let pki = pki();
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v1(pki.twin_der.clone())),
        vec![pki.signer_der.clone()],
    );
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
}

/// The digest binds; a serial that does not belong to the digested certificate
/// still fails, because a verifier must not accept a property that contradicts
/// itself.
#[test]
fn an_issuer_serial_that_contradicts_the_digest_fails() {
    let pki = pki();
    let mut spec = SigningCertificateSpec::v1(pki.signer_der.clone());
    spec.wrong_issuer_serial = true;
    let xml = dossier(&pki, Some(spec), vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
}

#[test]
fn an_issuer_serial_v2_that_names_another_issuer_fails() {
    let pki = pki();
    let mut spec = SigningCertificateSpec::v2(pki.signer_der.clone());
    spec.wrong_issuer_serial = true;
    let xml = dossier(&pki, Some(spec), vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
}

/// A `CertDigest` under SHA-1 is refused by default and admitted only for
/// diagnosis, exactly like every other digest in the pipeline.
#[test]
fn a_sha1_certificate_digest_is_refused_by_default() {
    let pki = pki();
    let mut spec = SigningCertificateSpec::v1(pki.signer_der.clone());
    spec.digest_uri = SHA1_URI.to_owned();
    let xml = dossier(&pki, Some(spec), vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateMismatch,
        CheckStatus::Failed,
    );
}

#[test]
fn a_sha512_certificate_digest_binds() {
    let pki = pki();
    let mut spec = SigningCertificateSpec::v1(pki.signer_der.clone());
    spec.digest_uri = SHA512_URI.to_owned();
    let xml = dossier(&pki, Some(spec), vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
}

/// A signature carrying no `SigningCertificate` is `unknown`, never `passed`:
/// nothing signed says which certificate signed it.
#[test]
fn an_absent_signing_certificate_is_unknown() {
    let pki = pki();
    let xml = dossier(&pki, None, vec![pki.signer_der.clone()]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateAbsent,
        CheckStatus::Unknown,
    );
    assert!(report.signatures[0].xades.signing_certificate.is_none());
}

/// The binding is read in every XAdES namespace, not only 1.3.2: legacy
/// material is exactly where it matters most.
#[test]
fn the_binding_is_read_in_the_legacy_namespace() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    signature.xades_namespace = common::XADES_NS_122.to_owned();
    signature.references[3].reference_type = Some(common::SIGNED_PROPERTIES_TYPE_122.to_owned());
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
}

// ---------------------------------------------------------------------------
// Policy, and what is not validated
// ---------------------------------------------------------------------------

#[test]
fn an_implied_signature_policy_is_reported_and_not_processed() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signature_policy_implied = true;
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::XadesSignaturePolicyImplied,
        CheckStatus::Unknown,
    );
    assert_eq!(
        report.signatures[0].xades.signature_policy,
        Some(openszigno_verify::xades::SignaturePolicy::Implied)
    );
    // Reporting a policy is not applying one, so the verdict cannot improve.
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// An unsigned property this build does not process is named, not ignored.
#[test]
fn an_unprocessed_property_is_named() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.extra_unsigned_property = Some("CompleteCertificateRefs".to_owned());
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(&report, CheckCode::XadesNotValidated, CheckStatus::Skipped);
    assert_eq!(
        report.signatures[0].xades.unvalidated_properties,
        vec!["CompleteCertificateRefs".to_owned()]
    );
}

/// `ArchiveTimeStamp` is out of scope and says so, rather than being silently
/// dropped.
#[test]
fn an_archive_timestamp_is_reported_as_out_of_scope() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.archive_timestamp = true;
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::ArchiveTimestampPresent,
        CheckStatus::Skipped,
    );
    assert_eq!(report.signatures[0].xades.archive_timestamps, 1);
}

/// A bare XMLDSig signature has no qualifying properties at all, and none of
/// the stage C codes may claim otherwise.
#[test]
fn a_signature_without_xades_reports_absence() {
    let pki = pki();
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.include_xades = false;
    signature.references.pop();
    let dossier = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(&report, CheckCode::XadesAbsent, CheckStatus::Skipped);
    assert!(!report.signatures[0].xades.present);
    assert_eq!(report.signatures[0].xades.signature_policy, None);
}

/// The pathological shapes: an unparsable `IssuerSerialV2`, a certificate
/// reference with no digest at all. Neither may panic, and neither may pass.
#[test]
fn malformed_properties_never_pass_and_never_panic() {
    let pki = pki();
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v1(pki.signer_der.clone())),
        vec![pki.signer_der.clone()],
    );
    for (needle, replacement) in [
        (
            "<xades:IssuerSerial>",
            "<xades:IssuerSerialV2>%%%</xades:IssuerSerialV2><xades:IssuerSerial>",
        ),
        ("<ds:DigestValue>", "<ds:DigestValue>not base64!!"),
    ] {
        let broken = xml.replace(needle, replacement);
        let report = run(&broken, vec![pki.root_der.clone()]);
        assert_ne!(report.verdict, Verdict::Valid);
    }
}

/// A dossier that carries a dossier-level `es:TimeStamp` says that it is not
/// validated rather than counting it as verified.
#[test]
fn a_dossier_level_timestamp_is_reported_as_unvalidated() {
    let pki = pki();
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![pki.signer_der.clone()])),
        dossier_timestamp: true,
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let report = run(&xml, vec![pki.root_der.clone()]);

    assert_check(
        &report,
        CheckCode::DossierTimestampNotValidated,
        CheckStatus::Skipped,
    );
    assert_ne!(report.verdict, Verdict::Valid);
}

/// A certificate the property names but that is not a CA is still only a
/// candidate: the binding never grants trust on its own.
#[test]
fn the_binding_does_not_grant_trust() {
    let pki = pki();
    let unrelated_key = rsa_key(keys::SECOND_RSA2048);
    let other_root = self_signed(
        &CertSpec::ca("openSzigno Other Root", BasicConstraints::Constrained(0)),
        &unrelated_key,
    );
    let xml = dossier(
        &pki,
        Some(SigningCertificateSpec::v1(pki.signer_der.clone())),
        vec![pki.signer_der.clone()],
    );
    // The store anchors an unrelated root, so the binding passes and the path
    // still does not.
    let report = run(&xml, vec![other_root.der]);
    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::CertPathUntrusted, CheckStatus::Failed);
}
