//! The AVDH-authenticated shape: what the Hungarian state's identification-based
//! document authentication service leaves behind, and what a reader must keep
//! doing with it.
//!
//! Section 634(15) of the Code of Civil Procedure grandfathers documents
//! authenticated with AVDH up to 31 December 2024, so a verifier meets these
//! structures indefinitely. The shape is an ordinary XAdES signature made by a
//! state seal, carrying a signing time, a signature policy identifier with its
//! hash, claimed roles naming the citizen the state identified, a commitment
//! type, and a second "hitelesitesi zaradek" clause document beside the
//! authenticated one.
//!
//! Nothing in that list is a defect. Every element here must be **reported**
//! and none of it may cost the signature its verdict. These tests pin that.
//!
//! Every byte is synthetic and generated at test time: the keys, the
//! certificates, the CRL and the dossier alike. Nothing is derived from a real
//! AVDH document, and no claim is made that this is byte-for-byte what NISZ
//! emitted.

mod common;

use common::{
    CertSpec, CrlSpec, DossierSpec, ExtraDocumentSpec, SigSpec, SignaturePolicySpec,
    SigningCertificateSpec, TestKey, TimestampSpec, build, build_crl, document_signature,
    extended_key_usage_extension, issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryRevocationStore, MemoryTrustStore, RoxmltreeC14n, Verdict, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::BasicConstraints;

const ID_KP_TIME_STAMPING: &str = "1.3.6.1.5.5.7.3.8";

/// Inside every synthetic certificate window and inside the CRL's.
const AT: &str = "2020-06-02T00:00:00Z";

/// A stand-in for the policy document a signature policy identifier names. It
/// is never fetched; only its digest is claimed, exactly as in real material.
const POLICY_DOCUMENT: &[u8] = b"synthetic signature policy document";

/// A policy OID shaped like the ones Hungarian policy-bearing signatures
/// carry. The value is synthetic: it names nothing real.
const POLICY_OID: &str = "urn:oid:1.3.6.1.4.1.99999.1.1";

/// The commitment type XAdES defines for "proof of origin"
/// (ETSI EN 319 132-1 clause 5.2.9).
const PROOF_OF_ORIGIN: &str = "http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin";

struct Pki {
    root_der: Vec<u8>,
    root_key: TestKey,
    /// The seal that signs on the citizen's behalf, standing in for the
    /// state's AVDH certificate.
    seal_der: Vec<u8>,
    seal_key: TestKey,
    tsa_der: Vec<u8>,
}

fn pki() -> Pki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let seal_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    // The subject is a synthetic stand-in for a state authentication seal, not
    // a copy of any issued certificate.
    let seal = issued_by(
        &CertSpec::signer("openSzigno Test Authentication Seal"),
        &seal_key,
        &root,
        &root_key,
    );
    let mut tsa_spec = CertSpec::signer("openSzigno Test TSA");
    tsa_spec.custom_extensions = vec![extended_key_usage_extension(&[ID_KP_TIME_STAMPING], true)];
    let tsa = issued_by(&tsa_spec, &rsa_key(keys::THIRD_RSA2048), &root, &root_key);
    Pki {
        root_der: root.der,
        root_key,
        seal_der: seal.der,
        seal_key,
        tsa_der: tsa.der,
    }
}

/// The AVDH-shaped signature: the signed properties an authenticated document
/// carries, on top of the ordinary binding and timestamp a `valid` verdict
/// needs.
fn avdh_signature(pki: &Pki) -> SigSpec {
    let mut signature = document_signature(vec![pki.seal_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.seal_der.clone()));
    signature.signing_time = Some("2020-06-01T08:30:00Z".to_owned());
    signature.signature_policy = Some(SignaturePolicySpec::hashed(POLICY_OID, POLICY_DOCUMENT));
    // The claimed roles: the identity the state asserts it authenticated the
    // document for. Synthetic values, and nothing here is validated.
    signature.claimed_roles = vec![
        "Teszt Elek".to_owned(),
        "azonositasra visszavezetett dokumentumhitelesites".to_owned(),
    ];
    signature.commitment_type_ids = vec![PROOF_OF_ORIGIN.to_owned()];
    let mut timestamp = TimestampSpec::new(
        rsa_key(keys::THIRD_RSA2048),
        pki.tsa_der.clone(),
        "2020-06-01T09:00:00Z",
    );
    timestamp.token_certificates = vec![pki.root_der.clone()];
    signature.timestamp = Some(timestamp);
    signature
}

/// The authenticated document on its own.
fn avdh_dossier(signature: SigSpec, key: &TestKey) -> String {
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", key)])
}

/// The authenticated document, plus the "hitelesitesi zaradek" clause
/// document AVDH files beside it.
fn avdh_dossier_with_clause(signature: SigSpec, key: &TestKey) -> String {
    let spec = DossierSpec {
        document_signature: Some(signature),
        extra_documents: vec![ExtraDocumentSpec::new("zaradek")],
        ..Default::default()
    };
    build(&spec, &[("doc", key)])
}

fn run(xml: &str, pki: &Pki) -> VerifyReport {
    let trust = MemoryTrustStore::new(vec![pki.root_der.clone()], Vec::new());
    let crl = build_crl(&CrlSpec::new(
        pki.root_der.clone(),
        rsa_key(keys::ROOT_RSA2048),
    ));
    let revocation = MemoryRevocationStore::new(vec![crl], Vec::new());
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339(AT).expect("the fixed time parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.requested_time = Some(AT.to_owned());
    // The root key is kept only so the fixture reads as one PKI; nothing here
    // signs with it beyond the CRL above.
    let _ = &pki.root_key;
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

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

/// The whole point: an AVDH-shaped signature with a policy identifier, claimed
/// roles and a commitment type reaches the same verdict as any other complete
/// signature. None of that material is a defect, and none of it may cost the
/// signature anything.
#[test]
fn an_avdh_shaped_signature_verifies() {
    let pki = pki();
    let xml = avdh_dossier(avdh_signature(&pki), &pki.seal_key);
    let report = run(&xml, &pki);

    assert_check(
        &report,
        CheckCode::XadesSigningCertificateBound,
        CheckStatus::Passed,
    );
    assert_check(&report, CheckCode::RevocationOk, CheckStatus::Passed);
    let failed: Vec<String> = codes(&report)
        .into_iter()
        .filter(|entry| entry.ends_with("=failed"))
        .collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_eq!(report.verdict, Verdict::Valid);
}

/// The signed properties are reported: the policy by identifier and hash, the
/// claimed roles verbatim, the commitment type by identifier. A reader that
/// dropped them would lose the only statement the structure makes about who
/// the state authenticated the document for.
#[test]
fn the_avdh_signed_properties_are_reported() {
    let pki = pki();
    let xml = avdh_dossier(avdh_signature(&pki), &pki.seal_key);
    let report = run(&xml, &pki);
    let xades = &report.signatures[0].xades;

    assert_eq!(xades.signature_policy_id.as_deref(), Some(POLICY_OID));
    let digest = xades
        .signature_policy_digest
        .as_ref()
        .expect("the policy hash is reported");
    assert_eq!(
        digest.algorithm.as_deref(),
        Some("http://www.w3.org/2001/04/xmlenc#sha256")
    );
    assert!(
        digest
            .value
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        xades.claimed_roles,
        vec![
            "Teszt Elek".to_owned(),
            "azonositasra visszavezetett dokumentumhitelesites".to_owned()
        ]
    );
    assert_eq!(xades.commitment_type_ids, vec![PROOF_OF_ORIGIN.to_owned()]);
    assert_eq!(xades.signing_time.as_deref(), Some("2020-06-01T08:30:00Z"));
}

/// The explicit policy is reported as information, never as a failure and
/// never as a reason to stop. No policy document is fetched or applied.
#[test]
fn an_explicit_signature_policy_is_information_only() {
    let pki = pki();
    let xml = avdh_dossier(avdh_signature(&pki), &pki.seal_key);
    let report = run(&xml, &pki);

    assert_check(
        &report,
        CheckCode::XadesSignaturePolicyExplicit,
        CheckStatus::Info,
    );
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
}

/// `SignerRoleV2` is the EN 319 132-1 spelling of the same property, and it is
/// read the same way.
#[test]
fn a_signer_role_v2_is_read_the_same_way() {
    let pki = pki();
    let mut signature = avdh_signature(&pki);
    signature.signer_role_v2 = true;
    let xml = avdh_dossier(signature, &pki.seal_key);
    let report = run(&xml, &pki);

    assert_eq!(report.signatures[0].xades.claimed_roles.len(), 2);
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
}

/// The JSON these fields reach is additive: a signature that claims none of
/// them reports none of them, and the keys are absent rather than null.
#[test]
fn a_signature_without_the_avdh_properties_reports_none_of_them() {
    let pki = pki();
    let mut signature = avdh_signature(&pki);
    signature.signature_policy = None;
    signature.claimed_roles = Vec::new();
    signature.commitment_type_ids = Vec::new();
    let xml = avdh_dossier(signature, &pki.seal_key);
    let report = run(&xml, &pki);

    let json = serde_json::to_value(&report.signatures[0].xades).expect("the report serialises");
    assert!(json.get("claimed_roles").is_none());
    assert!(json.get("commitment_type_ids").is_none());
    assert!(json.get("signature_policy_digest").is_none());
}

/// The reported shape, as a caller of `--json` sees it.
#[test]
fn the_json_carries_the_policy_the_roles_and_the_commitment() {
    let pki = pki();
    let xml = avdh_dossier(avdh_signature(&pki), &pki.seal_key);
    let report = run(&xml, &pki);
    let json = serde_json::to_value(&report.signatures[0].xades).expect("the report serialises");

    assert_eq!(json["signature_policy"], "explicit");
    assert_eq!(json["signature_policy_id"], POLICY_OID);
    assert_eq!(
        json["signature_policy_digest"]["algorithm"],
        "http://www.w3.org/2001/04/xmlenc#sha256"
    );
    assert_eq!(json["claimed_roles"][0], "Teszt Elek");
    assert_eq!(json["commitment_type_ids"][0], PROOF_OF_ORIGIN);
}

/// The clause document rides beside the authenticated one and is a document of
/// its own. Here it is covered by nothing, and saying exactly that is the
/// whole job: the signature over the authenticated document stays `valid`, the
/// dossier is capped at `indeterminate` because one document is unsigned, and
/// nothing fails. Coverage is reported, never assumed, and never confused with
/// a broken signature.
#[test]
fn the_clause_document_is_reported_beside_the_authenticated_one() {
    let pki = pki();
    let xml = avdh_dossier_with_clause(avdh_signature(&pki), &pki.seal_key);
    let report = run(&xml, &pki);

    assert_eq!(report.documents.len(), 2);
    assert_check(&report, CheckCode::DocumentsUncovered, CheckStatus::Unknown);
    let failed: Vec<String> = codes(&report)
        .into_iter()
        .filter(|entry| entry.ends_with("=failed"))
        .collect();
    assert!(failed.is_empty(), "unexpected failures: {failed:?}");
    assert_eq!(report.signatures[0].verdict, Verdict::Valid);
    assert_eq!(report.verdict, Verdict::Indeterminate);
}
