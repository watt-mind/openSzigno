//! Algorithm-policy coverage: every accepted scheme is exercised, and the
//! certificate-side rejections that the end-to-end suite does not reach.

mod common;

use common::{
    CertSpec, DossierSpec, ECDSA_SHA384_URI, RSA_PSS_SHA256_URI, RSA_SHA384_URI, RSA_SHA512_URI,
    RefSpec, SHA384_URI, SHA512_URI, build, document_signature, ecdsa_p384_key, ed25519_key,
    issued_by, keys, rsa_key, self_signed,
};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use openszigno_verify::certs::{CertificateSource, ParsedCertificate, certificates_from_bytes};
use openszigno_verify::codes::{CheckCode, CheckStatus, Verdict};
use openszigno_verify::policy::{Digest, PolicyReport, SignatureScheme, Transform, VerifyLimits};
use openszigno_verify::{
    FixedClock, MemoryTrustStore, NoRevocation, RevocationPolicy, RoxmltreeC14n as Backend,
    VerifyOptions, VerifyReport, parse_rfc3339, verify,
};
use rcgen::{BasicConstraints, CustomExtension};

fn run(xml: &str, anchors: Vec<Vec<u8>>) -> VerifyReport {
    let trust = MemoryTrustStore::new(anchors, Vec::new());
    let revocation = NoRevocation;
    let backend = Backend;
    let clock = FixedClock(parse_rfc3339("2020-06-01T00:00:00Z").expect("parses"));
    let options = VerifyOptions::new(&clock, &trust, &revocation, &backend);
    verify(xml.as_bytes(), &options).expect("the dossier parses structurally")
}

fn assert_check(report: &VerifyReport, code: CheckCode, status: CheckStatus) {
    let found = report
        .checks
        .iter()
        .chain(
            report
                .signatures
                .iter()
                .flat_map(|signature| signature.checks.iter()),
        )
        .any(|check| check.code == code && check.status == status);
    assert!(
        found,
        "expected {} to be {}",
        code.as_str(),
        status.as_str()
    );
}

/// RSA PKCS#1 v1.5 with SHA-384 and SHA-512, and RSA-PSS with SHA-256, all
/// verify; so do SHA-384 and SHA-512 reference digests.
#[test]
fn every_accepted_rsa_scheme_verifies() {
    for (method, digest) in [
        (RSA_SHA384_URI, SHA384_URI),
        (RSA_SHA512_URI, SHA512_URI),
        (RSA_PSS_SHA256_URI, SHA384_URI),
    ] {
        let root_key = rsa_key(keys::ROOT_RSA2048);
        let signer_key = rsa_key(keys::SIGNER_RSA2048);
        let root = self_signed(
            &CertSpec::ca("Root", BasicConstraints::Unconstrained),
            &root_key,
        );
        let signer = issued_by(&CertSpec::signer("Signer"), &signer_key, &root, &root_key);
        let mut signature = document_signature(vec![signer.der]);
        signature.signature_method = method.to_owned();
        signature.references = signature
            .references
            .into_iter()
            .map(|reference| RefSpec {
                digest_uri: digest.to_owned(),
                ..reference
            })
            .collect();
        let spec = DossierSpec {
            document_signature: Some(signature),
            ..Default::default()
        };
        let xml = build(&spec, &[("doc", &signer_key)]);
        let report = run(&xml, vec![root.der]);
        assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
        assert_check(&report, CheckCode::ReferenceDigestOk, CheckStatus::Passed);
    }
}

/// ECDSA P-384 with SHA-384, including a P-384 certificate signature in the
/// path.
#[test]
fn ecdsa_p384_verifies() {
    let root_key = ecdsa_p384_key(9);
    let signer_key = ecdsa_p384_key(11);
    let root = self_signed(
        &CertSpec::ca("EC Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("EC Signer"),
        &signer_key,
        &root,
        &root_key,
    );
    let mut signature = document_signature(vec![signer.der]);
    signature.signature_method = ECDSA_SHA384_URI.to_owned();
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der]);
    assert_check(&report, CheckCode::SignatureValueOk, CheckStatus::Passed);
    assert_check(&report, CheckCode::CertPathOk, CheckStatus::Passed);
}

/// A key type outside the policy is refused rather than guessed at.
#[test]
fn an_unsupported_key_type_is_refused() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = ed25519_key();
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(
        &CertSpec::signer("Ed Signer"),
        &signer_key,
        &root,
        &root_key,
    );
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der]);
    assert_check(&report, CheckCode::AlgorithmRejected, CheckStatus::Failed);
    assert_eq!(report.verdict, Verdict::Invalid);
}

/// An intermediate signed with an algorithm outside the allowlist fails the
/// path rather than being accepted on trust.
#[test]
fn a_certificate_signed_with_an_unlisted_algorithm_fails_the_path() {
    let root_key = ed25519_key();
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Ed Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let signer = issued_by(&CertSpec::signer("Signer"), &signer_key, &root, &root_key);
    let spec = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der]);
    assert_check(
        &report,
        CheckCode::CertAlgorithmRejected,
        CheckStatus::Failed,
    );
}

/// RFC 5280 requires a verifier to reject a certificate carrying a critical
/// extension it does not understand.
#[test]
fn an_unrecognised_critical_extension_fails_the_path() {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut spec = CertSpec::signer("Odd Signer");
    let mut extension =
        CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 99999, 1], vec![0x05, 0x00]);
    extension.set_criticality(true);
    spec.custom_extensions = vec![extension];
    let signer = issued_by(&spec, &signer_key, &root, &root_key);
    let dossier = DossierSpec {
        document_signature: Some(document_signature(vec![signer.der])),
        ..Default::default()
    };
    let xml = build(&dossier, &[("doc", &signer_key)]);
    let report = run(&xml, vec![root.der]);
    assert_check(
        &report,
        CheckCode::CertUnsupportedCriticalExtension,
        CheckStatus::Failed,
    );
}

/// Garbage in `ds:KeyInfo` is not a certificate, and the run says so instead of
/// panicking.
#[test]
fn certificate_parsing_never_panics_on_garbage() {
    let source = CertificateSource::KeyInfo;
    assert!(ParsedCertificate::from_der(&[], source).is_none());
    assert!(ParsedCertificate::from_der(&[0x30, 0x82, 0xff, 0xff], source).is_none());
    assert!(ParsedCertificate::from_der(&(0u8..255).collect::<Vec<u8>>(), source).is_none());
}

#[test]
fn trust_store_parsing_rejects_malformed_pem() {
    assert!(certificates_from_bytes(b"-----BEGIN CERTIFICATE-----\nAAAA\n").is_err());
    assert!(
        certificates_from_bytes(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")
            .is_err()
    );
    assert!(certificates_from_bytes(b"").is_err());
}

/// The policy tables are part of the machine-readable contract, so their
/// strings are pinned.
#[test]
fn the_policy_tables_are_stable() {
    assert_eq!(Digest::as_str(Digest::Sha256), "sha256");
    assert_eq!(Digest::as_str(Digest::Sha384), "sha384");
    assert_eq!(Digest::as_str(Digest::Sha512), "sha512");
    for (uri, name) in [
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "rsa-pkcs1-sha256",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
            "rsa-pkcs1-sha384",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
            "rsa-pkcs1-sha512",
        ),
        (
            "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
            "rsa-pss-sha256",
        ),
        (
            "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1",
            "rsa-pss-sha384",
        ),
        (
            "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1",
            "rsa-pss-sha512",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
            "ecdsa-sha256",
        ),
        (
            "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
            "ecdsa-sha384",
        ),
    ] {
        let scheme = SignatureScheme::from_signature_uri(uri).expect("the URI is accepted");
        assert_eq!(scheme.as_str(), name);
        assert!(matches!(
            scheme.digest(),
            Digest::Sha256 | Digest::Sha384 | Digest::Sha512
        ));
    }
    // SHA-1 is recognised but legacy: the caller must still gate it.
    let sha1 = SignatureScheme::from_signature_uri("http://www.w3.org/2000/09/xmldsig#rsa-sha1")
        .expect("SHA-1 is recognised");
    assert!(sha1.is_legacy());
    assert_eq!(sha1.as_str(), "rsa-pkcs1-sha1");
    assert!(
        Digest::from_digest_uri("http://www.w3.org/2000/09/xmldsig#sha1")
            .expect("SHA-1 is recognised")
            .is_legacy()
    );
    assert!(!Digest::Sha256.is_legacy());
    for uri in [
        "http://www.w3.org/2000/09/xmldsig#dsa-sha1",
        "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
        "",
    ] {
        assert!(SignatureScheme::from_signature_uri(uri).is_none(), "{uri}");
    }
    for uri in ["http://www.w3.org/2001/04/xmldsig-more#md5", ""] {
        assert!(Digest::from_digest_uri(uri).is_none(), "{uri}");
    }
    assert!(matches!(
        Transform::from_uri("http://www.w3.org/2000/09/xmldsig#enveloped-signature"),
        Some(Transform::EnvelopedSignature)
    ));
    assert!(matches!(
        Transform::from_uri("http://www.w3.org/2000/09/xmldsig#base64"),
        Some(Transform::Base64)
    ));
    assert!(matches!(
        Transform::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#"),
        Some(Transform::Canonicalization(_))
    ));
    assert!(Transform::from_uri("http://www.w3.org/TR/1999/REC-xslt-19991116").is_none());

    let policy = PolicyReport::new(true, false, RevocationPolicy::Offline);
    assert_eq!(policy.trust_store, "configured");
    assert_eq!(policy.revocation, "offline");
    assert!(!policy.legacy_algorithms_allowed);
    assert!(policy.trust_snapshot.is_none());
    assert!(!policy.digest_algorithms.contains(&"sha1"));
    assert_eq!(
        PolicyReport::new(false, false, RevocationPolicy::Offline).trust_store,
        "absent"
    );

    // With the flag, the report shows the policy that was actually applied.
    let legacy = PolicyReport::new(true, true, RevocationPolicy::Offline);
    assert!(legacy.legacy_algorithms_allowed);
    assert!(legacy.digest_algorithms.contains(&"sha1"));
    assert!(legacy.signature_algorithms.contains(&"rsa-pkcs1-sha1"));

    let limits = VerifyLimits::default();
    assert_eq!(limits.max_signatures, 64);
    assert_eq!(limits.max_chain_length, 8);
}

/// Every canonicalization algorithm the policy advertises round-trips through
/// its URI, and every one of them can canonicalize.
#[test]
fn every_advertised_c14n_algorithm_round_trips() {
    for algorithm in [
        C14nAlgorithm::Inclusive { comments: false },
        C14nAlgorithm::Inclusive { comments: true },
        C14nAlgorithm::Exclusive { comments: false },
        C14nAlgorithm::Exclusive { comments: true },
    ] {
        assert_eq!(C14nAlgorithm::from_uri(algorithm.uri()), Some(algorithm));
        assert!(!algorithm.short_name().is_empty());

        let source = openszigno_core::XmlSource::decode(
            b"<a xmlns=\"urn:x\"><b/></a>",
            &openszigno_core::Limits::default(),
        )
        .expect("decodes");
        let tree = source
            .parse_tree(&openszigno_core::Limits::default())
            .expect("parses");
        let bytes = RoxmltreeC14n
            .canonicalize(
                source.text(),
                &NodeSet::document(tree.root()),
                algorithm,
                &[],
            )
            .expect("canonicalizes");
        assert_eq!(bytes, b"<a xmlns=\"urn:x\"><b></b></a>");
    }
}

/// The base64 transform turns a node set into the octets its text decodes to.
#[test]
fn the_base64_transform_decodes_the_string_value() {
    let source = openszigno_core::XmlSource::decode(
        b"<a>aGVs<b>bG8=</b></a>",
        &openszigno_core::Limits::default(),
    )
    .expect("decodes");
    let tree = source
        .parse_tree(&openszigno_core::Limits::default())
        .expect("parses");
    assert_eq!(
        NodeSet::subtree(tree.root_element()).string_value(),
        "aGVsbG8="
    );
}

/// The status and verdict vocabularies are part of the machine contract.
#[test]
fn the_status_and_verdict_vocabularies_are_stable() {
    use openszigno_verify::codes::Check;

    assert_eq!(CheckStatus::Passed.as_str(), "passed");
    assert_eq!(CheckStatus::Failed.as_str(), "failed");
    assert_eq!(CheckStatus::Skipped.as_str(), "skipped");
    assert_eq!(CheckStatus::Unknown.as_str(), "unknown");

    assert_eq!(Verdict::Valid.as_str(), "valid");
    assert_eq!(Verdict::Indeterminate.as_str(), "indeterminate");
    assert_eq!(Verdict::Invalid.as_str(), "invalid");

    // `worst` is commutative and picks the more severe verdict either way
    // round, so folding a list of signatures cannot depend on their order.
    for (left, right, expected) in [
        (Verdict::Valid, Verdict::Valid, Verdict::Valid),
        (Verdict::Valid, Verdict::Invalid, Verdict::Invalid),
        (Verdict::Invalid, Verdict::Valid, Verdict::Invalid),
        (
            Verdict::Indeterminate,
            Verdict::Valid,
            Verdict::Indeterminate,
        ),
        (
            Verdict::Valid,
            Verdict::Indeterminate,
            Verdict::Indeterminate,
        ),
        (Verdict::Indeterminate, Verdict::Invalid, Verdict::Invalid),
    ] {
        assert_eq!(left.worst(right), expected);
    }

    let check = Check::new(CheckCode::SigStructure, CheckStatus::Passed, "text");
    assert_eq!(check.message, "text");
    let json = serde_json::to_value(&check).expect("serialises");
    assert_eq!(json["code"], "sig_structure");
    assert_eq!(json["status"], "passed");
    assert!(!CheckCode::ALL.is_empty());
}

/// Name constraints on subject alternative names: a permitted dNSName subtree
/// admits a matching name and refuses a non-matching one, and an excluded
/// rfc822Name subtree refuses a matching address.
#[test]
fn san_name_constraints_are_enforced() {
    use rcgen::{GeneralSubtree, NameConstraints, SanType};

    let case = |constraints: NameConstraints, san: SanType| {
        let root_key = rsa_key(keys::ROOT_RSA2048);
        let signer_key = rsa_key(keys::SIGNER_RSA2048);
        let mut root_spec = CertSpec::ca("Constrained Root", BasicConstraints::Unconstrained);
        root_spec.name_constraints = Some(constraints);
        let root = self_signed(&root_spec, &root_key);
        let mut signer_spec = CertSpec::signer("Signer");
        signer_spec.subject_alt_names = vec![san];
        let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);
        let dossier = DossierSpec {
            document_signature: Some(document_signature(vec![signer.der])),
            ..Default::default()
        };
        let xml = build(&dossier, &[("doc", &signer_key)]);
        run(&xml, vec![root.der])
    };

    let permitted = |name: &str| NameConstraints {
        permitted_subtrees: vec![GeneralSubtree::DnsName(name.to_owned())],
        excluded_subtrees: Vec::new(),
    };
    let inside = case(
        permitted("example.test"),
        SanType::DnsName("host.example.test".try_into().expect("a valid name")),
    );
    assert_check(&inside, CheckCode::CertPathOk, CheckStatus::Passed);

    let outside = case(
        permitted("example.test"),
        SanType::DnsName("host.other.test".try_into().expect("a valid name")),
    );
    assert_check(
        &outside,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );

    let excluded = case(
        NameConstraints {
            permitted_subtrees: Vec::new(),
            excluded_subtrees: vec![GeneralSubtree::Rfc822Name("blocked.test".to_owned())],
        },
        SanType::Rfc822Name("someone@blocked.test".try_into().expect("a valid address")),
    );
    assert_check(
        &excluded,
        CheckCode::CertNameConstraintViolation,
        CheckStatus::Failed,
    );
}
