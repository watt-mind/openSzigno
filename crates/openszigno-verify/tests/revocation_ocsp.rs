//! Stage E: what an OCSP response says, and when the responder was entitled
//! to say it.
//!
//! Every certificate and every response here is generated at test time by a
//! synthetic CA. Nothing is derived from a real dossier, a real CA, or a real
//! responder.

mod common;

use common::{
    CertSpec, DossierSpec, OcspSpec, OcspStatus, SigSpec, SigningCertificateSpec, TestKey, build,
    build_ocsp, document_signature, issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::revocation::RevocationStatus;
use openszigno_verify::{
    FixedClock, MemoryRevocationStore, MemoryTrustStore, RoxmltreeC14n, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

/// The validation time these tests use unless they say otherwise.
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

fn run_at(xml: &str, anchors: Vec<Vec<u8>>, ocsp: Vec<Vec<u8>>, time: &str) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = MemoryRevocationStore::new(Vec::new(), ocsp);
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(time).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(time.to_owned());
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

/// The one revocation entry the end-entity certificate got.
fn entry(report: &VerifyReport) -> &openszigno_verify::revocation::CertificateRevocation {
    report.signatures[0].chain[0]
        .revocation
        .as_ref()
        .expect("the end-entity certificate has a revocation answer")
}

// ---------------------------------------------------------------------------
// `unknown` is not staleness
// ---------------------------------------------------------------------------

/// RFC 6960 section 2.2: `unknown` means the responder does not know about
/// this certificate. Reporting that as `revocation_data_stale` told an
/// operator to fetch something fresher, when nothing fresher would help: the
/// responder they asked does not serve this certificate at all.
#[test]
fn an_ocsp_unknown_status_is_not_reported_as_staleness() {
    let pki = pki();
    let mut spec = OcspSpec::new(
        pki.root_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    );
    spec.status = OcspStatus::Unknown;
    let xml = dossier(signature(&pki), &pki.signer_key);
    let report = run_at(
        &xml,
        vec![pki.root_der.clone()],
        vec![build_ocsp(&spec)],
        AT,
    );

    assert_check(
        &report,
        CheckCode::RevocationStatusUnknownByResponder,
        CheckStatus::Unknown,
    );
    assert_absent(&report, CheckCode::RevocationDataStale);
    assert_absent(&report, CheckCode::RevocationOk);

    let entry = entry(&report);
    assert_eq!(entry.status, RevocationStatus::Unknown);
    assert_eq!(
        entry.code,
        CheckCode::RevocationStatusUnknownByResponder.as_str()
    );
    let detail = entry
        .detail
        .as_deref()
        .expect("the entry says what happened");
    assert!(
        detail.contains("does not know about this certificate"),
        "{detail}"
    );

    // And the sentence a reader acts on names the responder's answer rather
    // than telling them to fetch fresher data.
    let summary = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::RevocationStatusUnknownByResponder)
        .expect("the summary is present");
    assert!(
        summary
            .message
            .contains("does not know about this certificate"),
        "{}",
        summary.message
    );
}
