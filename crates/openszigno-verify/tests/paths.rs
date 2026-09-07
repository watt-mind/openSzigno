//! Certificate-path tests: where candidates come from, how the search is
//! bounded, name-constraint semantics, critical-extension handling, and signer
//! selection.

mod common;

use common::{
    CertSpec, DossierSpec, RefSpec, TestKey, build, document_signature, dossier_signature,
    ecdsa_key, extended_key_usage_extension, issued_by, keys, malformed_extension,
    name_constraints_extension, rsa_key, self_signed,
};
use openszigno_verify::certs::CertificateSource;
use openszigno_verify::codes::{CheckCode, CheckStatus};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, NoTrust, RoxmltreeC14n, VerifyOptions,
    VerifyReport, parse_rfc3339, verify,
};
use rcgen::{BasicConstraints, IsCa, KeyUsagePurpose, SanType};
use x509_cert::ext::pkix::name::GeneralName;

fn run(xml: &str, anchors: Vec<Vec<u8>>, intermediates: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, intermediates);
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-01T00:00:00Z").expect("parses"));
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// Every check emitted anywhere in the report, as `code=status`.
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

/// A leaf, a certificate that issued it, and a self-signed root.
struct Chain {
    root_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
}

fn three_link_chain() -> Chain {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let intermediate = issued_by(
        &CertSpec::ca("openSzigno Test CA", BasicConstraints::Constrained(0)),
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
    Chain {
        root_der: root.der,
        intermediate_der: intermediate.der,
        signer_der: signer.der,
        signer_key,
    }
}

// ---------------------------------------------------------------------------
// Where candidates come from
// ---------------------------------------------------------------------------

/// The shape every real dossier uses: `ds:KeyInfo` holds only the signer, and
/// the intermediate and root travel in `xades:CertificateValues`.
#[test]
fn a_chain_delivered_only_through_certificate_values_is_built() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![chain.signer_der.clone()]);
    signature.certificate_values = vec![chain.intermediate_der.clone(), chain.root_der.clone()];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);
    let report = run(&xml, vec![chain.root_der.clone()], Vec::new());

    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    let entries = &report.signatures[0].chain;
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].source, CertificateSource::KeyInfo);
    assert_eq!(entries[1].source, CertificateSource::CertificateValues);
    // The anchor is the trust store's copy, never the dossier's.
    assert_eq!(entries[2].source, CertificateSource::TrustStore);
    assert!(entries[2].is_trust_anchor);
    assert!(!entries[0].is_trust_anchor);
    assert_eq!(
        entries[0].subject_cn.as_deref(),
        Some("openSzigno Test Signer")
    );
    assert_eq!(entries[0].issuer_cn.as_deref(), Some("openSzigno Test CA"));
    assert!(!entries[0].serial_hex.is_empty());
    assert_eq!(entries[0].not_before, "2019-01-01T00:00:00Z");
    assert_eq!(entries[0].not_after, "2039-01-01T00:00:00Z");
}

/// A self-signed root carried inside the dossier is a candidate, never an
/// anchor. Without a configured store the chain stays unknown, however many
/// certificates the dossier supplies.
#[test]
fn a_root_inside_the_dossier_is_never_a_trust_anchor() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![chain.signer_der.clone()]);
    signature.certificate_values = vec![chain.intermediate_der, chain.root_der.clone()];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);

    let trust = NoTrust;
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-01T00:00:00Z").expect("parses"));
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    let report = verify(xml.as_bytes(), &options).expect("parses");
    assert_check(&report, CheckCode::CertPathUnknown, CheckStatus::Unknown);

    // An unrelated anchor is not enough either: the dossier's own root cannot
    // stand in for it.
    let other_key = rsa_key(keys::SECOND_RSA2048);
    let other = self_signed(
        &CertSpec::ca("Unrelated Root", BasicConstraints::Unconstrained),
        &other_key,
    );
    let untrusted = run(&xml, vec![other.der], Vec::new());
    assert_check(
        &untrusted,
        CheckCode::CertPathUntrusted,
        CheckStatus::Failed,
    );
}

/// A certificate that appears in both `ds:KeyInfo` and `CertificateValues` is
/// deduplicated by DER, and keeps the source it was first seen in.
#[test]
fn a_certificate_in_both_places_is_deduplicated() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![
        chain.signer_der.clone(),
        chain.intermediate_der.clone(),
    ]);
    signature.certificate_values = vec![
        chain.intermediate_der.clone(),
        chain.signer_der.clone(),
        chain.root_der.clone(),
    ];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);
    let report = run(&xml, vec![chain.root_der], Vec::new());

    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    let entries = &report.signatures[0].chain;
    assert_eq!(entries.len(), 3);
    // The intermediate was seen in ds:KeyInfo first, so that is its source.
    assert_eq!(entries[1].source, CertificateSource::KeyInfo);
    let subjects: Vec<_> = entries
        .iter()
        .map(|entry| entry.subject_cn.clone())
        .collect();
    let mut unique = subjects.clone();
    unique.dedup();
    assert_eq!(subjects, unique, "a certificate appears twice in the chain");
}

/// A non-self-signed certificate in the trust store directory is an extra
/// untrusted intermediate, not an anchor.
#[test]
fn an_intermediate_may_come_from_the_trust_store() {
    let chain = three_link_chain();
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![chain.signer_der.clone()])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);

    // Without the intermediate anywhere, the chain cannot be built.
    let missing = run(&xml, vec![chain.root_der.clone()], Vec::new());
    assert_check(&missing, CheckCode::CertPathUntrusted, CheckStatus::Failed);
    let message = missing.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::CertPathUntrusted)
        .map(|check| check.message.clone())
        .expect("the check was emitted");
    assert!(message.contains("candidate certificates"), "{message}");
    assert!(message.contains("openSzigno Test CA"), "{message}");

    // Supplied through the store, it completes the path.
    let supplied = run(
        &xml,
        vec![chain.root_der],
        vec![chain.intermediate_der.clone()],
    );
    assert_check(&supplied, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_eq!(
        supplied.signatures[0].chain[1].source,
        CertificateSource::TrustStore
    );

    // The intermediate on its own is not an anchor: it is not self-signed.
    let no_anchor = run(&xml, vec![chain.intermediate_der], Vec::new());
    assert_check(&no_anchor, CheckCode::CertPathUnknown, CheckStatus::Unknown);
}

// ---------------------------------------------------------------------------
// Bounded search
// ---------------------------------------------------------------------------

/// A bag of same-named CA certificates that never reaches an anchor must not
/// be allowed to burn CPU: the search gives up and says so.
#[test]
fn path_building_gives_up_rather_than_exploring_forever() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let issuer_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let anchor = self_signed(
        &CertSpec::ca("Unrelated Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    // The issuer of the signer, and twenty decoys sharing its exact subject
    // name, none of which chains anywhere.
    let issuer = self_signed(
        &CertSpec::ca("Ambiguous CA", BasicConstraints::Unconstrained),
        &issuer_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Signer"),
        &signer_key,
        &issuer,
        &issuer_key,
    );
    let decoys: Vec<Vec<u8>> = (0..20)
        .map(|seed| {
            let key = ecdsa_key(seed + 20);
            self_signed(
                &CertSpec::ca("Ambiguous CA", BasicConstraints::Unconstrained),
                &key,
            )
            .der
        })
        .collect();

    let mut signature = document_signature(vec![signer.der]);
    signature.certificate_values = decoys;
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);

    let started = std::time::Instant::now();
    let report = run(&xml, vec![anchor.der], Vec::new());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "the bounded search should finish quickly"
    );
    // Giving up is `unknown`, not `failed`: the tool stopped looking, which is
    // not the same as concluding that no path exists.
    assert_check(
        &report,
        CheckCode::CertPathSearchExhausted,
        CheckStatus::Unknown,
    );
    assert_ne!(report.verdict, openszigno_verify::Verdict::Invalid);
}

// ---------------------------------------------------------------------------
// Name constraints
// ---------------------------------------------------------------------------

fn constrained_case(extension: rcgen::CustomExtension, sans: Vec<SanType>) -> VerifyReport {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let mut root_spec = CertSpec::ca("Constrained Root", BasicConstraints::Unconstrained);
    root_spec.custom_extensions = vec![extension];
    let root = self_signed(&root_spec, &root_key);
    let mut signer_spec = CertSpec::signer("Signer");
    signer_spec.subject_alt_names = sans;
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    run(&xml, vec![root.der], Vec::new())
}

fn ia5(value: &str) -> der::asn1::Ia5String {
    der::asn1::Ia5String::new(value).expect("an IA5 string")
}

/// A URI constraint applies to the host, not to any substring: the classic
/// `https://evil.test/example.com` must not satisfy `example.com`.
#[test]
fn a_uri_constraint_matches_the_host_not_a_substring() {
    let permitted = || {
        name_constraints_extension(
            vec![GeneralName::UniformResourceIdentifier(ia5("example.com"))],
            Vec::new(),
        )
    };

    let evil = constrained_case(
        permitted(),
        vec![SanType::URI(
            "https://evil.test/example.com".try_into().expect("a URI"),
        )],
    );
    assert_check(
        &evil,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );

    let good = constrained_case(
        permitted(),
        vec![SanType::URI(
            "https://example.com/path".try_into().expect("a URI"),
        )],
    );
    assert_check(&good, CheckCode::CertPathOk, CheckStatus::Passed);

    // A URI with no host at all cannot be evaluated, so it fails closed.
    let hostless = constrained_case(
        permitted(),
        vec![SanType::URI("urn:example:thing".try_into().expect("a URI"))],
    );
    assert_check(
        &hostless,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}

/// dNSName constraints match on label boundaries: `example.com` covers
/// `host.example.com` but never `notexample.com`.
#[test]
fn dns_constraints_match_on_label_boundaries() {
    let permitted =
        || name_constraints_extension(vec![GeneralName::DnsName(ia5("example.com"))], Vec::new());

    let inside = constrained_case(
        permitted(),
        vec![SanType::DnsName(
            "host.example.com".try_into().expect("a name"),
        )],
    );
    assert_check(&inside, CheckCode::CertPathOk, CheckStatus::Passed);

    let outside = constrained_case(
        permitted(),
        vec![SanType::DnsName(
            "notexample.com".try_into().expect("a name"),
        )],
    );
    assert_check(
        &outside,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );

    // A leading dot means subdomains only.
    let dotted =
        name_constraints_extension(vec![GeneralName::DnsName(ia5(".example.com"))], Vec::new());
    let exact = constrained_case(
        dotted,
        vec![SanType::DnsName("example.com".try_into().expect("a name"))],
    );
    assert_check(
        &exact,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}

/// iPAddress constraints are evaluated as address plus mask, not ignored.
#[test]
fn ip_address_constraints_are_evaluated() {
    let subnet = |bytes: [u8; 8]| {
        name_constraints_extension(
            vec![GeneralName::IpAddress(
                der::asn1::OctetString::new(bytes.to_vec()).expect("an octet string"),
            )],
            Vec::new(),
        )
    };
    // 192.0.2.0/24
    let constraint = [192, 0, 2, 0, 255, 255, 255, 0];

    let inside = constrained_case(
        subnet(constraint),
        vec![SanType::IpAddress(std::net::IpAddr::from([192, 0, 2, 7]))],
    );
    assert_check(&inside, CheckCode::CertPathOk, CheckStatus::Passed);

    let outside = constrained_case(
        subnet(constraint),
        vec![SanType::IpAddress(std::net::IpAddr::from([
            198, 51, 100, 7,
        ]))],
    );
    assert_check(
        &outside,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}

/// A constraint form this validator does not implement must fail the chain
/// rather than be ignored: it may be the only thing standing between the
/// certificate and a name it is not entitled to.
#[test]
fn an_unimplemented_constraint_form_fails_closed() {
    let other_name = GeneralName::RegisteredId("1.3.6.1.4.1.99999.7".parse().expect("an OID"));
    let report = constrained_case(
        name_constraints_extension(vec![other_name], Vec::new()),
        Vec::new(),
    );
    assert_check(
        &report,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}

// ---------------------------------------------------------------------------
// Critical extensions
// ---------------------------------------------------------------------------

fn signer_with_extensions(extensions: Vec<rcgen::CustomExtension>) -> VerifyReport {
    signer_with_usage_and_extensions(
        vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ],
        extensions,
    )
}

/// Verify a dossier signed by a certificate with the given `keyUsage` bits and
/// extra extensions. `ContentCommitment` is X.509's name for `nonRepudiation`.
fn signer_with_usage_and_extensions(
    key_usages: Vec<KeyUsagePurpose>,
    extensions: Vec<rcgen::CustomExtension>,
) -> VerifyReport {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut spec = CertSpec::signer("Signer");
    spec.key_usages = key_usages;
    spec.custom_extensions = extensions;
    let signer = issued_by(&spec, &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    run(&xml, vec![root.der], Vec::new())
}

/// An `extendedKeyUsage` on the signing certificate restricts what the key may
/// be used for whether or not it is marked critical (RFC 5280 section
/// 4.2.1.12). Accepted purposes are `anyExtendedKeyUsage`,
/// `id-kp-documentSigning` (RFC 9336), and Microsoft's older
/// `szOID_KP_DOCUMENT_SIGNING` (1.3.6.1.4.1.311.10.3.12), which is what
/// qualified-signature CAs actually issue.
#[test]
fn an_extended_key_usage_that_permits_document_signing_passes() {
    for critical in [true, false] {
        for oids in [
            vec!["2.5.29.37.0"],
            vec!["1.3.6.1.5.5.7.3.36"],
            vec!["1.3.6.1.4.1.311.10.3.12"],
            // A permitted purpose alongside an unrelated one is still
            // permitted: what matters is that one of them covers this use.
            vec!["1.3.6.1.4.1.311.10.3.12", "1.3.6.1.5.5.7.3.4"],
            vec!["1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.36"],
        ] {
            let report =
                signer_with_extensions(vec![extended_key_usage_extension(&oids, critical)]);
            assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
            assert!(
                !codes(&report).contains(&"cert_key_usage_advisory=unknown".to_owned()),
                "a permitted purpose needs no caveat: {oids:?}"
            );
        }
    }
}

/// Real qualified certificates pair `nonRepudiation` with an `extendedKeyUsage`
/// that says `emailProtection` and nothing else. ETSI EN 319 412-2 makes
/// `nonRepudiation` the key-usage signal for a signing certificate, so calling
/// those signatures invalid over a loosely filled purpose field would be wrong.
/// They are accepted with a caveat that caps the verdict instead.
#[test]
fn an_unrelated_eku_with_nonrepudiation_is_advisory() {
    for critical in [true, false] {
        for oid in [
            "1.3.6.1.5.5.7.3.4", // emailProtection
            "1.3.6.1.5.5.7.3.1", // serverAuth
            "1.3.6.1.5.5.7.3.2", // clientAuth
            "1.3.6.1.5.5.7.3.3", // codeSigning
            "1.3.6.1.5.5.7.3.9", // OCSPSigning
            "1.3.6.1.5.5.7.3.8", // timeStamping, which is for a TSA
        ] {
            let report = signer_with_usage_and_extensions(
                vec![KeyUsagePurpose::ContentCommitment],
                vec![extended_key_usage_extension(&[oid], critical)],
            );
            assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
            assert_check(
                &report,
                CheckCode::CertKeyUsageAdvisory,
                CheckStatus::Unknown,
            );
            // The caveat is blocking, so it can only lower a verdict.
            assert_eq!(report.verdict, openszigno_verify::Verdict::Indeterminate);
        }
    }

    // The advisory names the purposes it found, which are public OIDs.
    let report = signer_with_usage_and_extensions(
        vec![KeyUsagePurpose::ContentCommitment],
        vec![extended_key_usage_extension(&["1.3.6.1.5.5.7.3.4"], false)],
    );
    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::CertKeyUsageAdvisory)
        .map(|check| check.message.clone())
        .expect("the advisory is emitted");
    assert!(
        message.contains("1.3.6.1.5.5.7.3.4"),
        "the advisory must name what it found; got {message}"
    );
}

/// Without `nonRepudiation` there is no signal that this is a signing
/// certificate at all, and an unrelated `extendedKeyUsage` is then a refusal.
#[test]
fn an_unrelated_eku_without_nonrepudiation_fails() {
    for critical in [true, false] {
        let report = signer_with_usage_and_extensions(
            vec![KeyUsagePurpose::DigitalSignature],
            vec![extended_key_usage_extension(
                &["1.3.6.1.5.5.7.3.4"],
                critical,
            )],
        );
        assert_check(&report, CheckCode::CertKeyUsageInvalid, CheckStatus::Failed);
    }
}

/// A `keyUsage` that permits neither `digitalSignature` nor `nonRepudiation`
/// fails whatever the `extendedKeyUsage` says: the key was not issued to sign.
#[test]
fn a_key_usage_that_permits_no_signing_fails() {
    for extensions in [
        Vec::new(),
        vec![extended_key_usage_extension(&["1.3.6.1.5.5.7.3.36"], false)],
    ] {
        let report =
            signer_with_usage_and_extensions(vec![KeyUsagePurpose::KeyEncipherment], extensions);
        assert_check(&report, CheckCode::CertKeyUsageInvalid, CheckStatus::Failed);
    }
}

/// An absent `extendedKeyUsage` imposes no restriction, which is the common
/// shape for a qualified signing certificate.
#[test]
fn an_absent_extended_key_usage_permits_signing() {
    let report = signer_with_extensions(Vec::new());
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
}

/// QCStatements are non-critical in practice; a certificate that marks them
/// critical asks for processing this tool does not implement.
#[test]
fn a_critical_extension_without_implemented_semantics_fails() {
    let qc = signer_with_extensions(vec![malformed_extension(
        &[1, 3, 6, 1, 5, 5, 7, 1, 3],
        true,
    )]);
    assert_check(
        &qc,
        CheckCode::CertUnsupportedCriticalExtension,
        CheckStatus::Failed,
    );

    // Certificate policies are recognised but not processed, so critical
    // policies fail closed too.
    let policies = signer_with_extensions(vec![malformed_extension(&[2, 5, 29, 32], true)]);
    assert_check(
        &policies,
        CheckCode::CertUnsupportedCriticalExtension,
        CheckStatus::Failed,
    );
}

/// A malformed extension is not an absent one: treating a corrupt `keyUsage`
/// as missing would silently drop the check it carries.
#[test]
fn a_malformed_extension_is_reported_rather_than_ignored() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut spec = CertSpec::signer("Signer");
    // Replace the generated keyUsage with bytes that are not a BIT STRING.
    spec.key_usages = Vec::new();
    spec.custom_extensions = vec![malformed_extension(&[2, 5, 29, 15], true)];
    let signer = issued_by(&spec, &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der], Vec::new());
    assert_check(&report, CheckCode::CertMalformed, CheckStatus::Failed);
}

// ---------------------------------------------------------------------------
// Signer selection
// ---------------------------------------------------------------------------

/// XMLDSig imposes no order on `ds:KeyInfo`. Taking the first certificate
/// would turn a good signature into a false failure when the issuer is listed
/// first, which real material does.
#[test]
fn the_signer_is_the_certificate_that_verifies_not_the_first_listed() {
    let chain = three_link_chain();
    let signature = document_signature(vec![
        chain.intermediate_der.clone(),
        chain.signer_der.clone(),
    ]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);
    let report = run(&xml, vec![chain.root_der], Vec::new());

    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_eq!(report.signatures[0].signing_certificate_index, Some(1));
    assert_eq!(
        report.signatures[0]
            .signing_certificate
            .as_ref()
            .and_then(|certificate| certificate.subject_cn.clone())
            .as_deref(),
        Some("openSzigno Test Signer")
    );
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
}

/// When nothing verifies, the failure says how many candidates were tried.
#[test]
fn a_failure_names_the_number_of_candidates_tried() {
    let chain = three_link_chain();
    let other_key = rsa_key(keys::SECOND_RSA2048);
    let signature = document_signature(vec![
        chain.intermediate_der.clone(),
        chain.signer_der.clone(),
    ]);
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    // Signed by a key none of the listed certificates belongs to.
    let xml = build(&spec, &[("doc", &other_key)]);
    let report = run(&xml, vec![chain.root_der], Vec::new());

    assert_check(
        &report,
        CheckCode::SignatureValueInvalid,
        CheckStatus::Failed,
    );
    let message = report.signatures[0]
        .checks
        .iter()
        .find(|check| check.code == CheckCode::SignatureValueInvalid)
        .map(|check| check.message.clone())
        .expect("the check was emitted");
    assert!(message.contains('2'), "{message}");
    assert_eq!(report.signatures[0].signing_certificate_index, None);
}

// ---------------------------------------------------------------------------
// Signing time
// ---------------------------------------------------------------------------

/// The claimed signing time is read and reported, in either XAdES namespace,
/// and never becomes the validation time.
#[test]
fn the_claimed_signing_time_is_read_but_not_trusted() {
    for namespace in [common::XADES_NS, common::XADES_NS_122] {
        let chain = three_link_chain();
        let mut signature = dossier_signature(vec![chain.signer_der.clone()]);
        signature.xades_namespace = namespace.to_owned();
        signature.references[3] = RefSpec::to("#sp-frame");
        signature.certificate_values = vec![chain.intermediate_der.clone()];
        let spec = DossierSpec {
            dossier_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("frame", &chain.signer_key)]);
        let report = run(&xml, vec![chain.root_der.clone()], Vec::new());

        assert_eq!(
            report.signatures[0].signing_time.as_deref(),
            Some("2020-01-01T00:00:00Z"),
            "namespace {namespace}"
        );
        assert_check(&report, CheckCode::SigningTimePresent, CheckStatus::Unknown);
        // The validation time is what the caller asked for, never the claim.
        assert_eq!(report.verification_time.effective, "2020-06-01T00:00:00Z");
    }
}

/// A bare XMLDSig signature has no signing time, and says so.
#[test]
fn an_absent_signing_time_is_reported_as_absent() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![chain.signer_der.clone()]);
    signature.include_xades = false;
    signature.references.pop();
    signature.certificate_values = vec![chain.intermediate_der];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);
    let report = run(&xml, vec![chain.root_der], Vec::new());
    assert!(report.signatures[0].signing_time.is_none());
    assert_check(&report, CheckCode::SigningTimePresent, CheckStatus::Unknown);
}

// ---------------------------------------------------------------------------
// Same-document dereferencing drops comments
// ---------------------------------------------------------------------------

/// XMLDSig 4.4.3.3: a same-document reference selects a node-set whose
/// comments have already been removed, so inserting a comment into a signed
/// element cannot change its digest, even under a with-comments transform.
#[test]
fn inserting_a_comment_does_not_change_a_reference_digest() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![chain.signer_der.clone()]);
    signature.references[0] = RefSpec::to("#obj0")
        .with_transforms(&["http://www.w3.org/2001/10/xml-exc-c14n#WithComments"]);
    signature.certificate_values = vec![chain.intermediate_der];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);
    let clean = run(&xml, vec![chain.root_der.clone()], Vec::new());
    assert_check(&clean, CheckCode::ReferenceDigestOk, CheckStatus::Passed);

    // The same document with a comment inside the signed object still
    // verifies: the comment is not part of what was signed.
    let commented = xml.replace(
        "<ds:Object Id=\"obj0\">aGVsbG8=</ds:Object>",
        "<ds:Object Id=\"obj0\">aGVsbG8=<!-- inserted --></ds:Object>",
    );
    assert_ne!(commented, xml, "the comment must actually be inserted");
    let report = run(&commented, vec![chain.root_der], Vec::new());
    assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
}

/// A leaf whose `IsCa` flag is set is still tried, just last, so an
/// intermediate that happens to hold the signing key is not silently skipped.
#[test]
fn certificate_authorities_are_tried_last_but_are_tried() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let ca_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut ca_spec = CertSpec::ca("Signing CA", BasicConstraints::Unconstrained);
    ca_spec.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = issued_by(&ca_spec, &ca_key, &root, &root_key);
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![ca.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &ca_key)]);
    let report = run(&xml, vec![root.der], Vec::new());
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_eq!(report.signatures[0].signing_certificate_index, Some(0));
    // It is still not a valid signer: a CA-only key usage forbids it.
    assert_check(&report, CheckCode::CertKeyUsageInvalid, CheckStatus::Failed);
}

/// A chain of exactly `max_chain_length` certificates is inside the limit, not
/// outside it: the search must recognise that its last certificate is an anchor
/// before it refuses to expand any further. A limit of three admits three.
#[test]
fn a_chain_of_exactly_the_maximum_length_is_accepted() {
    let chain = three_link_chain();
    let mut signature = document_signature(vec![chain.signer_der.clone()]);
    signature.certificate_values = vec![chain.intermediate_der.clone()];
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &chain.signer_key)]);

    // signer, intermediate, root: exactly three.
    let report = run_with_chain_limit(&xml, vec![chain.root_der.clone()], 3);
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
    assert_eq!(report.signatures[0].chain.len(), 3);

    // One fewer, and the same path no longer fits. It is reported as untrusted
    // rather than as a finding about the certificates themselves.
    let report = run_with_chain_limit(&xml, vec![chain.root_der.clone()], 2);
    assert_check(&report, CheckCode::CertPathUntrusted, CheckStatus::Failed);
}

/// Verify with a custom `max_chain_length`, so the boundary can be exercised
/// without building an eight-certificate hierarchy.
fn run_with_chain_limit(xml: &str, anchors: Vec<Vec<u8>>, max_chain_length: usize) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = RoxmltreeC14n;
    let clock = FixedClock(parse_rfc3339("2020-06-01T00:00:00Z").expect("parses"));
    let mut options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    options.limits.max_chain_length = max_chain_length;
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

/// A CA's `extendedKeyUsage` is advisory unless it is marked critical: real
/// eIDAS hierarchies carry sets there that no path-processing rule in RFC 5280
/// covers, and refusing them would reject correct chains. A CA that marks the
/// extension critical has asked to be taken at its word.
#[test]
fn a_ca_extended_key_usage_is_enforced_only_when_critical() {
    let run_with_ca_extensions = |extensions: Vec<rcgen::CustomExtension>| {
        let root_key = rsa_key(keys::ROOT_RSA2048);
        let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
        let signer_key = rsa_key(keys::SIGNER_RSA2048);
        let root = self_signed(
            &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
            &root_key,
        );
        let mut ca = CertSpec::ca("openSzigno Test CA", BasicConstraints::Unconstrained);
        ca.custom_extensions = extensions;
        let intermediate = issued_by(&ca, &intermediate_key, &root, &root_key);
        let signer = issued_by(
            &CertSpec::signer("openSzigno Test Signer"),
            &signer_key,
            &intermediate,
            &intermediate_key,
        );
        let mut signature = document_signature(vec![signer.der.clone()]);
        signature.certificate_values = vec![intermediate.der.clone()];
        let spec = DossierSpec {
            document_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("doc", &signer_key)]);
        run(&xml, vec![root.der.clone()], Vec::new())
    };

    // Advisory: not enforced, however unrelated the purpose.
    let advisory = run_with_ca_extensions(vec![extended_key_usage_extension(
        &["1.3.6.1.5.5.7.3.1"],
        false,
    )]);
    assert_check(&advisory, CheckCode::CertPathOk, CheckStatus::Passed);

    // Critical and unrelated: refused.
    let critical = run_with_ca_extensions(vec![extended_key_usage_extension(
        &["1.3.6.1.5.5.7.3.1"],
        true,
    )]);
    assert_check(
        &critical,
        CheckCode::CertKeyUsageInvalid,
        CheckStatus::Failed,
    );

    // Critical and covering document signing: accepted.
    let permitted = run_with_ca_extensions(vec![extended_key_usage_extension(
        &["1.3.6.1.5.5.7.3.36"],
        true,
    )]);
    assert_check(&permitted, CheckCode::CertPathOk, CheckStatus::Passed);
}
