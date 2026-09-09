//! Stage E: how the revocation sources are weighed against each other.
//!
//! The tier order decides which source is *read* first and nothing else. The
//! signature's own `RevocationValues` are supplied by the signer, so a rule
//! that stopped at the first definite answer let a genuine but older embedded
//! OCSP `good` hide the operator's newer CRL revoking the same certificate.
//!
//! Every CRL and OCSP response here is generated at test time by a synthetic
//! CA. Nothing is derived from a real dossier, a real CA, or a real responder.

mod common;

use common::{
    CertSpec, CrlSpec, DossierSpec, OcspSpec, OcspStatus, RevokedSpec, SigSpec,
    SigningCertificateSpec, TestKey, build, build_crl, build_ocsp, document_signature, issued_by,
    keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::revocation::{RevocationOrigin, RevocationStatus};
use openszigno_verify::{
    FixedClock, MemoryRevocationStore, MemoryTrustStore, RoxmltreeC14n, Verdict, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

/// The validation time every test here uses. It sits inside both the embedded
/// OCSP response's window and the store CRL's.
const AT: &str = "2020-06-02T00:00:00Z";

struct Pki {
    root_der: Vec<u8>,
    signer_der: Vec<u8>,
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
    Pki {
        root_der: root.der,
        signer_der: signer.der,
        signer_key,
    }
}

fn signature(pki: &Pki) -> SigSpec {
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

fn run(xml: &str, anchors: Vec<Vec<u8>>, crls: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = MemoryRevocationStore::new(crls, Vec::new());
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
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

/// An embedded OCSP response that says `good`, produced before the store's CRL
/// and still inside its own `nextUpdate` at the validation time.
fn embedded_good_ocsp(pki: &Pki) -> Vec<u8> {
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.produced_at = "2020-05-15T00:00:00Z".to_owned();
    spec.this_update = "2020-05-15T00:00:00Z".to_owned();
    spec.next_update = Some("2020-08-01T00:00:00Z".to_owned());
    build_ocsp(&spec)
}

/// A store CRL, issued after that response, that revokes the signer.
fn store_crl_revoking_the_signer(pki: &Pki) -> Vec<u8> {
    let mut spec = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    spec.this_update = "2020-06-01T00:00:00Z".to_owned();
    spec.next_update = Some("2020-07-01T00:00:00Z".to_owned());
    build_crl(&spec.revoking(RevokedSpec::new(&pki.signer_der, "2020-05-20T00:00:00Z")))
}

/// The regression this suite exists for: the signature embeds a genuine, fresh
/// OCSP `good` produced before the operator's CRL, and the operator's CRL
/// revokes the signing certificate. The embedded tier is attacker-controlled,
/// so the older `good` must not hide the newer revocation.
#[test]
fn a_store_crl_revocation_beats_an_older_embedded_good_ocsp() {
    let pki = pki();
    let mut signature = signature(&pki);
    signature.revocation_ocsp = vec![embedded_good_ocsp(&pki)];
    let xml = dossier(signature, &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![store_crl_revoking_the_signer(&pki)],
    );

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);

    let entry = report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .expect("the leaf carries a revocation answer");
    assert_eq!(entry.status, RevocationStatus::Revoked);
    assert_eq!(entry.source, Some(RevocationOrigin::StoreCrl));
    assert_eq!(
        entry.revocation_time.as_deref(),
        Some("2020-05-20T00:00:00Z")
    );
}

/// The disagreement itself is reported, so a reader learns that the answer
/// they were given was contested and by which sources.
#[test]
fn a_disagreement_between_sources_is_reported() {
    let pki = pki();
    let mut signature = signature(&pki);
    signature.revocation_ocsp = vec![embedded_good_ocsp(&pki)];
    let xml = dossier(signature, &pki.signer_key);
    let report = run(
        &xml,
        vec![pki.root_der.clone()],
        vec![store_crl_revoking_the_signer(&pki)],
    );

    assert_check(
        &report,
        CheckCode::RevocationSourcesDisagree,
        CheckStatus::Info,
    );
    let detail = report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .and_then(|entry| entry.detail.clone())
        .expect("the disagreement is recorded on the certificate too");
    assert!(
        detail.contains("the sources disagree"),
        "unexpected detail: {detail}"
    );
}

/// When every source agrees, the one speaking for the later instant is the one
/// reported: it knew everything the earlier one did.
#[test]
fn among_agreeing_sources_the_later_one_is_reported() {
    let pki = pki();
    let mut signature = signature(&pki);
    signature.revocation_ocsp = vec![embedded_good_ocsp(&pki)];
    let xml = dossier(signature, &pki.signer_key);

    let mut crl = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    crl.this_update = "2020-06-01T00:00:00Z".to_owned();
    crl.next_update = Some("2020-07-01T00:00:00Z".to_owned());
    let report = run(&xml, vec![pki.root_der.clone()], vec![build_crl(&crl)]);

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    let entry = report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .expect("the leaf carries a revocation answer");
    assert_eq!(entry.status, RevocationStatus::Good);
    assert_eq!(entry.source, Some(RevocationOrigin::StoreCrl));
    assert_eq!(entry.this_update.as_deref(), Some("2020-06-01T00:00:00Z"));
    // Agreement is not a disagreement, and nothing says otherwise.
    assert!(
        !codes(&report)
            .iter()
            .any(|code| code.starts_with("revocation_sources_disagree")),
        "agreeing sources must not be reported as disagreeing"
    );
}

/// The embedded tier still answers on its own when it is the only source, and
/// it is still the one reported when it speaks for the later instant.
#[test]
fn the_embedded_answer_still_wins_when_it_is_the_later_one() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.produced_at = "2020-06-01T12:00:00Z".to_owned();
    spec.this_update = "2020-06-01T12:00:00Z".to_owned();
    spec.next_update = Some("2020-08-01T00:00:00Z".to_owned());
    let mut signature = signature(&pki);
    signature.revocation_ocsp = vec![build_ocsp(&spec)];
    let xml = dossier(signature, &pki.signer_key);

    let mut crl = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    crl.this_update = "2020-06-01T00:00:00Z".to_owned();
    crl.next_update = Some("2020-07-01T00:00:00Z".to_owned());
    let report = run(&xml, vec![pki.root_der.clone()], vec![build_crl(&crl)]);

    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::EmbeddedOcsp)
    );
}

/// A revocation the embedded tier records still wins over a later store CRL
/// that says nothing: the direction the fix runs in is "a revocation always
/// beats a good answer", not "the store always beats the signature".
#[test]
fn an_embedded_revocation_beats_a_later_clean_store_crl() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.status = OcspStatus::Revoked("2020-05-10T00:00:00Z".to_owned(), None);
    let mut signature = signature(&pki);
    signature.revocation_ocsp = vec![build_ocsp(&spec)];
    let xml = dossier(signature, &pki.signer_key);

    let mut crl = CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048));
    crl.this_update = "2020-06-01T00:00:00Z".to_owned();
    let report = run(&xml, vec![pki.root_der.clone()], vec![build_crl(&crl)]);

    assert_check(&report, CheckCode::CertRevoked, CheckStatus::Failed);
    assert_eq!(
        report.signatures[0].chain[0]
            .revocation
            .as_ref()
            .and_then(|entry| entry.source),
        Some(RevocationOrigin::EmbeddedOcsp)
    );
}
