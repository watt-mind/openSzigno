//! Stage E: revocation, offline.
//!
//! Every CRL and OCSP response here is generated at test time by a synthetic
//! CA. Nothing is derived from a real dossier, a real CA, or a real responder.

mod common;

use common::{
    CertSpec, CrlSpec, DossierSpec, OcspSpec, OcspStatus, RevokedSpec, SigSpec,
    SigningCertificateSpec, TestKey, TimestampSpec, build, build_crl, build_ocsp,
    document_signature, extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::revocation::{RevocationOrigin, RevocationStatus};
use openszigno_verify::{
    FixedClock, MemoryRevocationStore, MemoryTrustStore, NoRevocation, RoxmltreeC14n, Verdict,
    VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";
const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";

/// The validation time every test uses unless it says otherwise. It sits inside
/// the synthetic CRL's `thisUpdate`/`nextUpdate` window.
const AT: &str = "2020-06-02T00:00:00Z";

/// A root, a signer under it, a timestamp authority under it, and a second,
/// unrelated CA, so that "signed by the wrong issuer" is expressible.
struct Pki {
    root_der: Vec<u8>,
    root_key: TestKey,
    signer_der: Vec<u8>,
    signer_key: TestKey,
    tsa_der: Vec<u8>,
    stranger_der: Vec<u8>,
    stranger_key: TestKey,
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let stranger_key = rsa_key(keys::SECOND_RSA2048);

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
    let stranger = self_signed(
        &CertSpec::ca("openSzigno Unrelated Root", BasicConstraints::Unconstrained),
        &stranger_key,
    );

    Pki {
        root_der: root.der,
        root_key,
        signer_der: signer.der,
        signer_key,
        tsa_der: tsa.der,
        stranger_der: stranger.der,
        stranger_key,
    }
}

/// A document signature that binds its signing certificate and carries a
/// timestamp, which is the shape a `valid` verdict needs.
fn signature(pki: &Pki) -> SigSpec {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
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

/// A signature with no timestamp, for the cases where only the signer chain
/// matters and a second chain would just add noise.
fn plain_signature(pki: &Pki) -> SigSpec {
    let mut signature = document_signature(vec![pki.signer_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    signature
}

fn dossier(signature: SigSpec, key: &TestKey) -> String {
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", key)])
}

fn run(xml: &str, anchors: Vec<Vec<u8>>, crls: Vec<Vec<u8>>, ocsp: Vec<Vec<u8>>) -> VerifyReport {
    run_at(xml, anchors, crls, ocsp, AT)
}

fn run_at(
    xml: &str,
    anchors: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    ocsp: Vec<Vec<u8>>,
    time: &str,
) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = MemoryRevocationStore::new(crls, ocsp);
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(time).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Every check the report emits, including the ones inside a token.
fn codes(report: &VerifyReport) -> Vec<String> {
    report
        .checks
        .iter()
        .chain(report.signatures.iter().flat_map(|signature| {
            signature.checks.iter().chain(
                signature
                    .timestamps
                    .iter()
                    .flat_map(|timestamp| timestamp.checks.iter()),
            )
        }))
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

fn assert_absent(report: &VerifyReport, code: CheckCode) {
    let seen = codes(report);
    assert!(
        !seen
            .iter()
            .any(|entry| entry.starts_with(&format!("{}=", code.as_str()))),
        "expected no {}; got {seen:?}",
        code.as_str()
    );
}

/// A CRL from the root that revokes nothing, covering the whole test window.
fn clean_crl(pki: &Pki) -> Vec<u8> {
    build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ))
}

// ---------------------------------------------------------------------------
// The happy paths, and the one that reaches `valid`
// ---------------------------------------------------------------------------

/// The whole point of phase 3: with a verified timestamp, a bound signing
/// certificate, a path to an anchor, and fresh revocation data for every
/// non-anchor certificate on both chains, a signature is `valid`.
#[test]
fn a_complete_signature_reaches_valid() {
    let pki = pki();
    let xml = dossier(signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![clean_crl(&pki)],
        Vec::new(),
    );

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_eq!(report.verdict, Verdict::Valid);
    assert_eq!(report.counts.signatures_valid, 1);
}

/// Nothing about `valid` is accidental: removing the revocation data alone
/// takes the same dossier back to `indeterminate`.
#[test]
fn without_revocation_data_the_same_signature_is_indeterminate() {
    let pki = pki();
    let xml = dossier(signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

    assert_check(
        &report,
        CheckCode::RevocationStatusUnknown,
        CheckStatus::Unknown,
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// An embedded OCSP response answers for the signer, and the report says the
/// answer came from the signature itself.
#[test]
fn an_embedded_ocsp_response_gives_a_good_status() {
    let pki = pki();
    let response = build_ocsp(&OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));
    let mut signature = plain_signature(&pki);
    signature.revocation_ocsp = vec![response];
    let xml = dossier(signature, &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    let entry = report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .expect("the leaf carries a revocation answer");
    assert_eq!(entry.status, RevocationStatus::Good);
    assert_eq!(entry.source, Some(RevocationOrigin::EmbeddedOcsp));
    assert_eq!(entry.produced_at.as_deref(), Some("2020-05-15T00:00:00Z"));
}

/// An embedded CRL works the same way and is reported with its own origin.
#[test]
fn an_embedded_crl_gives_a_good_status() {
    let pki = pki();
    let mut signature = plain_signature(&pki);
    signature.revocation_crls = vec![clean_crl(&pki)];
    let xml = dossier(signature, &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::EmbeddedCrl)
    );
}

/// The trust anchor is never asked about: its revocation is not a question the
/// PKI it roots can answer.
#[test]
fn the_trust_anchor_is_not_asked_about() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![clean_crl(&pki)],
        Vec::new(),
    );

    let chain = &report.signatures[0].chain;
    let anchor = chain.last().expect("the chain ends at the anchor");
    assert!(anchor.is_trust_anchor);
    assert_eq!(
        anchor
            .revocation
            .as_ref()
            .map(|entry| entry.status)
            .expect("the anchor carries an entry"),
        RevocationStatus::TrustAnchor
    );
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// A certificate revoked before the validation time makes the signature
/// `invalid`. This is the case the whole stage exists for.
#[test]
fn a_certificate_revoked_before_the_validation_time_is_invalid() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z").with_reason(1)),
    );
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    let entry = report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .expect("the leaf carries an answer");
    assert_eq!(entry.status, RevocationStatus::Revoked);
    assert_eq!(
        entry.revocation_time.as_deref(),
        Some("2020-05-10T00:00:00Z")
    );
    assert_eq!(entry.reason, Some("key_compromise"));
}

/// A revocation dated *after* the instant being validated did not apply then.
/// It is not a failure and it is not a pass: it is its own answer.
#[test]
fn a_certificate_revoked_after_the_validation_time_is_not_a_failure() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-06-20T00:00:00Z")),
    );
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(
        &report,
        CheckCode::CertRevokedAfterValidationTime,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::CertRevoked);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// `certificateHold` is a suspension, and a suspended certificate is not a
/// usable one.
#[test]
fn certificate_hold_counts_as_revoked() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z").with_reason(6)),
    );
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.reason),
        Some("certificate_hold")
    );
}

/// A revoked intermediate condemns everything under it, not just itself.
#[test]
fn a_revoked_intermediate_makes_the_chain_invalid() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let intermediate = issued_by(
        &CertSpec::ca(
            "openSzigno Test Issuing CA",
            BasicConstraints::Constrained(0),
        ),
        &intermediate_key,
        &root,
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &intermediate,
        &intermediate_key,
    );

    // The root revokes the intermediate; the intermediate says the leaf is fine.
    let root_crl = build_crl(
        &CrlSpec::new(root.der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&intermediate.der, "2020-05-10T00:00:00Z")),
    );
    let intermediate_crl = build_crl(&CrlSpec::new(
        intermediate.der.clone(),
        rsa_key(keys::INTERMEDIATE_RSA2048),
    ));

    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    signature.certificate_values = vec![intermediate.der.clone()];
    let xml = dossier(signature, &signer_key);
    let report = run(
        &xml,
        vec![root.der],
        vec![root_crl, intermediate_crl],
        Vec::new(),
    );

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    // The leaf itself is fine; the finding is on the intermediate.
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .map(|entry| entry.status),
        Some(RevocationStatus::Good)
    );
    assert_eq!(
        report.signatures[0].chain[1]
            .revocation
            .as_ref()
            .map(|entry| entry.status),
        Some(RevocationStatus::Revoked)
    );
}

/// A revoked TSA certificate must not leave a timestamped signature looking
/// clean.
#[test]
fn a_revoked_tsa_certificate_is_reported_on_the_signature() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.tsa_der, "2020-05-10T00:00:00Z")),
    );
    let xml = dossier(signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
    // The finding is recorded against the token's own chain too.
    let timestamp = &report.signatures[0].timestamps[0];
    assert_eq!(
        timestamp.chain[0]
            .revocation
            .as_ref()
            .map(|entry| entry.status),
        Some(RevocationStatus::Revoked)
    );
}

// ---------------------------------------------------------------------------
// Data that cannot be used
// ---------------------------------------------------------------------------

/// A CRL whose `nextUpdate` has passed says nothing about the validation time.
#[test]
fn expired_revocation_data_is_stale() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.this_update = "2020-01-01T00:00:00Z".to_owned();
    spec.next_update = Some("2020-02-01T00:00:00Z".to_owned());
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataStale,
        CheckStatus::Unknown,
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::StoreCrl)
    );
}

/// A CRL published by some other CA is about some other certificates. It is not
/// an error in this one, so the answer is "nothing was found", not "the data is
/// broken".
#[test]
fn a_crl_from_the_wrong_issuer_is_not_used() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.stranger_der.clone(), rsa_key(keys::SECOND_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z")),
    );
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(
        &report,
        CheckCode::RevocationStatusUnknown,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::CertRevoked);
}

/// A CRL that names the right issuer but was signed by someone else is a
/// forgery attempt, and is refused rather than believed.
#[test]
fn a_crl_signed_by_a_stranger_is_refused() {
    let pki = pki();
    // The issuer *name* is the root's; the signing key is not.
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::SECOND_RSA2048));
    spec.revoked
        .push(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z"));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::CertRevoked);
}

/// A tampered signature is refused the same way.
#[test]
fn a_crl_with_a_broken_signature_is_refused() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.tamper_signature = true;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A delta CRL is meaningless without the base it amends, so it is refused
/// rather than read as if it were complete.
#[test]
fn a_delta_crl_is_refused() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.delta = true;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// An `issuingDistributionPoint` marked `indirectCRL` describes a scope this
/// build does not implement, so the CRL is unusable rather than partly
/// understood. Fail closed.
#[test]
fn an_indirect_issuing_distribution_point_fails_closed() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.issuing_distribution_point = Some((false, false, true, None));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A CRL scoped to CA certificates says nothing about an end-entity one.
#[test]
fn a_ca_only_issuing_distribution_point_does_not_cover_the_leaf() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.issuing_distribution_point = Some((false, true, false, None));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A CRL scoped to end-entity certificates does cover one.
#[test]
fn a_user_only_issuing_distribution_point_covers_the_leaf() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.issuing_distribution_point = Some((true, false, false, None));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

/// A partitioned CRL naming a distribution point the certificate does not name
/// is about a different partition, and a partition is not the whole list.
#[test]
fn a_partitioned_crl_the_certificate_does_not_name_fails_closed() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.issuing_distribution_point = Some((
        false,
        false,
        false,
        Some("http://example.invalid/partition-3.crl".to_owned()),
    ));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A critical CRL extension this build does not implement makes the whole CRL
/// unusable.
#[test]
fn an_unknown_critical_crl_extension_fails_closed() {
    let pki = pki();
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.unknown_critical = true;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&spec)],
        Vec::new(),
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

// ---------------------------------------------------------------------------
// OCSP
// ---------------------------------------------------------------------------

/// A responder certificate the CA issued and marked `id-kp-OCSPSigning` is
/// authorised to answer for it.
#[test]
fn a_delegated_responder_with_the_eku_is_authorised() {
    let pki = pki();
    let responder_key = rsa_key(keys::SECOND_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &pki.root_key,
    );
    let mut responder_spec = CertSpec::signer("openSzigno Test OCSP Responder");
    responder_spec.custom_extensions =
        vec![extended_key_usage_extension(&[ID_KP_OCSP_SIGNING], false)];
    let responder = issued_by(&responder_spec, &responder_key, &root, &pki.root_key);

    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::SECOND_RSA2048),
    );
    spec.responder_der = Some(responder.der);
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::StoreOcsp)
    );
}

/// The same responder without `id-kp-OCSPSigning` is not authorised, however
/// correctly it signs.
#[test]
fn a_delegated_responder_without_the_eku_is_refused() {
    let pki = pki();
    let responder_key = rsa_key(keys::SECOND_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &pki.root_key,
    );
    let responder = issued_by(
        &CertSpec::signer("openSzigno Test OCSP Responder"),
        &responder_key,
        &root,
        &pki.root_key,
    );

    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::SECOND_RSA2048),
    );
    spec.responder_der = Some(responder.der);
    spec.status = OcspStatus::Revoked("2020-05-10T00:00:00Z".to_owned(), Some(1));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
    // And, crucially, its claim of revocation is not acted on either.
    assert_absent(&report, CheckCode::CertRevoked);
}

/// A responder certificate the CA never issued is a stranger, whatever EKU it
/// gave itself.
#[test]
fn an_unauthorised_responder_is_refused() {
    let pki = pki();
    let stranger = self_signed(
        &{
            let mut spec = CertSpec::signer("openSzigno Rogue Responder");
            spec.custom_extensions =
                vec![extended_key_usage_extension(&[ID_KP_OCSP_SIGNING], false)];
            spec
        },
        &pki.stranger_key,
    );
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::SECOND_RSA2048),
    );
    spec.responder_der = Some(stranger.der);
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// The CA may answer for itself, named by the SHA-1 hash of its key rather
/// than by name.
#[test]
fn a_by_key_responder_id_is_matched() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.by_key = true;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

/// A `certID` naming another serial is about another certificate, and is
/// skipped rather than misapplied.
#[test]
fn a_certid_for_another_certificate_is_not_used() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.wrong_serial = true;
    spec.status = OcspStatus::Revoked("2020-05-10T00:00:00Z".to_owned(), None);
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(
        &report,
        CheckCode::RevocationStatusUnknown,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::CertRevoked);
}

/// SHA-256 in the `certID` is accepted alongside RFC 6960's default SHA-1.
#[test]
fn a_sha256_certid_is_matched() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.sha256_cert_id = true;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

/// An OCSP `unknown` status is exactly that: the responder does not know, so
/// neither does the verifier.
#[test]
fn an_ocsp_unknown_status_is_not_a_good_status() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.status = OcspStatus::Unknown;
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_absent(&report, CheckCode::RevocationOk);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}

/// A response whose `OCSPResponseStatus` is not `successful` carries no answer
/// at all, and reading past it would turn a refusal into a verification.
#[test]
fn an_unsuccessful_ocsp_response_carries_no_answer() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.response_status = Some(3);
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// OCSP revocation carries the same before/after rule as a CRL.
#[test]
fn an_ocsp_revocation_before_the_validation_time_is_invalid() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.status = OcspStatus::Revoked("2020-05-10T00:00:00Z".to_owned(), Some(4));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.reason),
        Some("superseded")
    );
}

// ---------------------------------------------------------------------------
// Priority and policy
// ---------------------------------------------------------------------------

/// The signature's own material is consulted before the operator's store, and
/// OCSP before CRLs within a tier. Here the embedded OCSP says revoked and the
/// store's CRL says nothing, so the embedded answer is the one reported.
#[test]
fn embedded_material_is_consulted_before_the_store() {
    let pki = pki();
    let mut ocsp = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    ocsp.status = OcspStatus::Revoked("2020-05-10T00:00:00Z".to_owned(), None);
    let mut signature = plain_signature(&pki);
    signature.revocation_ocsp = vec![build_ocsp(&ocsp)];
    let xml = dossier(signature, &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![clean_crl(&pki)],
        Vec::new(),
    );

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::EmbeddedOcsp)
    );
}

/// With checking switched off the tool says so, and the verdict is capped at
/// `indeterminate` however good everything else is.
#[test]
fn switching_revocation_off_caps_the_verdict() {
    let pki = pki();
    let xml = dossier(signature(&pki), &pki.signer_key);
    let trust = MemoryTrustStore::new(vec![pki.root_der.clone()], Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    let report = verify(xml.as_bytes(), &options).expect("the dossier parses");

    assert_check(
        &report,
        CheckCode::RevocationNotChecked,
        CheckStatus::Skipped,
    );
    assert_eq!(report.verdict, Verdict::Indeterminate);
    assert_eq!(report.policy.revocation, "not_checked");
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .map(|entry| entry.status),
        Some(RevocationStatus::NotChecked)
    );
}

/// The policy actually applied is always visible in the machine output, even
/// when no data was found.
#[test]
fn the_policy_is_always_reported() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

    assert_check(&report, CheckCode::RevocationPolicy, CheckStatus::Info);
    assert_eq!(report.policy.revocation, "offline");
}

/// With no anchors there is no path, so there is no issuer to ask anything
/// against — and the tool says that rather than pretending it checked.
#[test]
fn without_a_path_revocation_is_unknown() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run_at(&xml, Vec::new(), vec![clean_crl(&pki)], Vec::new(), AT);

    assert_check(
        &report,
        CheckCode::RevocationStatusUnknown,
        CheckStatus::Unknown,
    );
}

// ---------------------------------------------------------------------------
// Freshness at the edges, delegated signers, and the store classifier
// ---------------------------------------------------------------------------

/// A CRL with no `nextUpdate` promised nothing about how long its answer
/// holds, so it is good for the instant it was made and anything after it.
#[test]
fn a_crl_with_no_next_update_is_usable_only_from_its_this_update() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);

    let mut later = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    later.this_update = "2020-06-10T00:00:00Z".to_owned();
    later.next_update = None;
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&later)],
        Vec::new(),
    );
    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);

    let mut earlier = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    earlier.this_update = "2020-01-01T00:00:00Z".to_owned();
    earlier.next_update = None;
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_crl(&earlier)],
        Vec::new(),
    );
    assert_check(
        &report,
        CheckCode::RevocationDataStale,
        CheckStatus::Unknown,
    );
}

/// The same rule applies to an OCSP response with no `nextUpdate`.
#[test]
fn an_ocsp_response_with_no_next_update_follows_the_same_rule() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.next_update = None;
    spec.this_update = "2020-01-01T00:00:00Z".to_owned();
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        Vec::new(),
        vec![build_ocsp(&spec)],
    );
    assert_check(
        &report,
        CheckCode::RevocationDataStale,
        CheckStatus::Unknown,
    );
}

/// Every RFC 5280 reason code is reported under its own name.
#[test]
fn every_revocation_reason_is_named() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    for (code, name) in [
        (0u32, "unspecified"),
        (2, "ca_compromise"),
        (3, "affiliation_changed"),
        (4, "superseded"),
        (5, "cessation_of_operation"),
        (9, "privilege_withdrawn"),
        (10, "aa_compromise"),
    ] {
        let crl = build_crl(
            &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048)).revoking(
                RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z").with_reason(code),
            ),
        );
        let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());
        assert_eq!(
            report.signatures[0].chain[0]
                .revocation
                .as_ref()
                .and_then(|entry| entry.reason),
            Some(name),
            "reason code {code}"
        );
    }
}

/// `removeFromCRL` only means anything in a delta CRL, and delta CRLs are
/// refused, so an entry carrying it is incoherent rather than believed.
#[test]
fn a_remove_from_crl_entry_is_incoherent() {
    let pki = pki();
    let crl = build_crl(
        &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
            .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z").with_reason(8)),
    );
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::CertRevoked);
}

/// An entry naming a different certificate issuer is an indirect-CRL entry.
#[test]
fn an_entry_naming_another_certificate_issuer_is_refused() {
    let pki = pki();
    let mut entry = RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z");
    entry.certificate_issuer = true;
    let crl =
        build_crl(&CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048)).revoking(entry));
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], vec![crl], Vec::new());

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A partitioned CRL the certificate *does* name is in scope for it.
#[test]
fn a_partitioned_crl_the_certificate_names_covers_it() {
    const PARTITION: &str = "http://example.invalid/partition-1.crl";
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    signer_spec.custom_extensions = vec![common::crl_distribution_point_extension(PARTITION)];
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);

    let mut spec = CrlSpec::new(root.der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.issuing_distribution_point = Some((false, false, false, Some(PARTITION.to_owned())));

    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    let xml = dossier(signature, &signer_key);
    let report = run(&xml, vec![root.der], vec![build_crl(&spec)], Vec::new());

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

/// A CA that does not assert `cRLSign` may not sign a CRL, whatever else is
/// correct about it.
#[test]
fn a_ca_without_crl_sign_may_not_sign_a_crl() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let mut root_spec = CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained);
    root_spec.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign];
    let root = self_signed(&root_spec, &root_key);
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &root,
        &root_key,
    );

    let crl = build_crl(&CrlSpec::new(root.der.clone(), rsa_key(keys::ROOT_RSA2048)));
    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    let xml = dossier(signature, &signer_key);
    let report = run(&xml, vec![root.der], vec![crl], Vec::new());

    assert_check(
        &report,
        CheckCode::RevocationDataInvalid,
        CheckStatus::Unknown,
    );
}

/// A CRL signer the CA issued, bearing the CA's own name and `cRLSign`, is an
/// authorised delegate: the CRL it signs is believed.
#[test]
fn a_delegated_crl_signer_the_ca_issued_is_authorised() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let delegate_key = rsa_key(keys::SECOND_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    // Same distinguished name as the CA, so the CRL's `issuer` field names it
    // too, but a different key and a certificate the CA issued.
    let delegate = issued_by(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &delegate_key,
        &root,
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &root,
        &root_key,
    );

    let crl = build_crl(&CrlSpec::new(
        root.der.clone(),
        rsa_key(keys::SECOND_RSA2048),
    ));
    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    signature.certificate_values = vec![delegate.der.clone()];
    let xml = dossier(signature, &signer_key);
    let report = run(&xml, vec![root.der], vec![crl], Vec::new());

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

/// The origin names are stable strings the JSON output relies on.
#[test]
fn revocation_origin_names_are_stable() {
    assert_eq!(RevocationOrigin::EmbeddedCrl.as_str(), "embedded_crl");
    assert_eq!(RevocationOrigin::EmbeddedOcsp.as_str(), "embedded_ocsp");
    assert_eq!(RevocationOrigin::StoreCrl.as_str(), "store_crl");
    assert_eq!(RevocationOrigin::StoreOcsp.as_str(), "store_ocsp");
}

/// The revocation-store classifier reads what a file actually holds, in DER or
/// PEM, and refuses anything else rather than skipping it.
#[test]
fn the_store_classifier_reads_der_and_pem() {
    use openszigno_verify::revocation::{RevocationItemKind, classify};

    let pki = pki();
    let crl = clean_crl(&pki);
    let response = build_ocsp(&OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));

    assert_eq!(
        classify(&crl).expect("a DER CRL classifies").0,
        RevocationItemKind::Crl
    );
    assert_eq!(
        classify(&response)
            .expect("a DER OCSP response classifies")
            .0,
        RevocationItemKind::Ocsp
    );
    assert_eq!(
        classify(pem(&crl, "X509 CRL").as_bytes())
            .expect("a PEM CRL classifies")
            .0,
        RevocationItemKind::Crl
    );
    assert_eq!(
        classify(pem(&response, "OCSP RESPONSE").as_bytes())
            .expect("a PEM OCSP response classifies")
            .0,
        RevocationItemKind::Ocsp
    );

    for (bytes, expected) in [
        (b"not DER at all".to_vec(), "neither a CRL nor an OCSP"),
        (
            pem(&crl, "CERTIFICATE").into_bytes(),
            "PEM but not a CRL or an OCSP response",
        ),
        (
            b"-----BEGIN X509 CRL-----\nnot base64\n-----END X509 CRL-----\n".to_vec(),
            "malformed PEM",
        ),
    ] {
        let error = classify(&bytes).expect_err("unusable material is refused");
        assert!(error.contains(expected), "{error}");
    }
}

/// A minimal PEM writer for the classifier test.
fn pem(der: &[u8], label: &str) -> String {
    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("Base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

// ---------------------------------------------------------------------------
// Where embedded validation data actually lives
// ---------------------------------------------------------------------------

/// Real long-term dossiers file almost all of their embedded OCSP responses
/// under `xades141:TimeStampValidationData` rather than directly under
/// `UnsignedSignatureProperties`. Both placements must be harvested, or the
/// tool finds nothing in most real material.
#[test]
fn revocation_values_are_harvested_from_both_placements() {
    let pki = pki();
    let response = build_ocsp(&OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));

    for nested in [false, true] {
        let mut signature = plain_signature(&pki);
        signature.revocation_ocsp = vec![response.clone()];
        signature.revocation_in_validation_data = nested;
        let xml = dossier(signature, &pki.signer_key);
        let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

        assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
        assert_eq!(
            report.signatures[0].chain[0]
                .revocation
                .as_ref()
                .and_then(|entry| entry.source),
            Some(RevocationOrigin::EmbeddedOcsp),
            "nested in TimeStampValidationData: {nested}"
        );
    }
}

/// Certificates encapsulated inside `TimeStampValidationData` are path
/// candidates like any other, so a chain whose intermediate is filed only
/// there still builds.
#[test]
fn certificates_are_harvested_from_validation_data() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let intermediate = issued_by(
        &CertSpec::ca(
            "openSzigno Test Issuing CA",
            BasicConstraints::Constrained(0),
        ),
        &intermediate_key,
        &root,
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &intermediate,
        &intermediate_key,
    );

    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    // The intermediate exists nowhere else: not in ds:KeyInfo, not in a plain
    // CertificateValues, and not in the trust store.
    signature.revocation_in_validation_data = true;
    signature.validation_data_certificates = vec![intermediate.der.clone()];
    signature.revocation_ocsp = vec![build_ocsp(&OcspSpec::new(
        intermediate.der.clone(),
        signer.der.clone(),
        rsa_key(keys::INTERMEDIATE_RSA2048),
    ))];
    let xml = dossier(signature, &signer_key);
    let report = run(
        &xml,
        vec![root.der.clone()],
        vec![build_crl(&CrlSpec::new(
            root.der.clone(),
            rsa_key(keys::ROOT_RSA2048),
        ))],
        Vec::new(),
    );

    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
}

// ---------------------------------------------------------------------------
// Saying which certificate is missing data
// ---------------------------------------------------------------------------

/// "No usable revocation data" is useless without saying *for what*. The
/// message must name the certificate by role and by the public CA names around
/// it, and repeat the CRL distribution point that certificate publishes, so a
/// caller knows which file to fetch.
#[test]
fn the_coverage_message_names_the_certificate_and_its_crl() {
    const CDP: &str = "http://crl.example.invalid/issuing-ca.crl";
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut intermediate_spec = CertSpec::ca(
        "openSzigno Test Issuing CA",
        BasicConstraints::Constrained(0),
    );
    intermediate_spec.custom_extensions = vec![common::crl_distribution_point_extension(CDP)];
    let intermediate = issued_by(&intermediate_spec, &intermediate_key, &root, &root_key);
    let signer = issued_by(
        &CertSpec::signer("openSzigno Test Signer"),
        &signer_key,
        &intermediate,
        &intermediate_key,
    );

    // The signer's status is answered; the intermediate's is not, which is
    // exactly the shape of a real dossier that embeds OCSP for the end entity
    // only.
    let mut signature = document_signature(vec![signer.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    signature.certificate_values = vec![intermediate.der.clone()];
    signature.revocation_ocsp = vec![build_ocsp(&OcspSpec::new(
        intermediate.der.clone(),
        signer.der.clone(),
        rsa_key(keys::INTERMEDIATE_RSA2048),
    ))];
    let xml = dossier(signature, &signer_key);
    let report = run(&xml, vec![root.der], Vec::new(), Vec::new());

    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::RevocationStatusUnknown)
        .map(|check| check.message.clone())
        .expect("the coverage gap is reported");
    assert!(
        message.contains("the intermediate CA openSzigno Test Issuing CA"),
        "the message must name the certificate by role and CA name; got {message}"
    );
    assert!(
        message.contains("issued by openSzigno Test Root"),
        "the message must name the issuer; got {message}"
    );
    assert!(
        message.contains(CDP),
        "the message must repeat the CRL distribution point; got {message}"
    );
}

/// The same naming applies to the end-entity certificate, and its *subject* is
/// never repeated: that is the signer.
#[test]
fn the_coverage_message_never_names_the_signer() {
    let pki = pki();
    let xml = dossier(plain_signature(&pki), &pki.signer_key);
    let report = run(&xml, vec![pki.root_der.clone()], Vec::new(), Vec::new());

    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::RevocationStatusUnknown)
        .map(|check| check.message.clone())
        .expect("the coverage gap is reported");
    assert!(
        message.contains("the end-entity certificate issued by openSzigno Test Root"),
        "got {message}"
    );
    assert!(
        !message.contains("openSzigno Test Signer"),
        "the signer's own subject must never appear in a message; got {message}"
    );
}
