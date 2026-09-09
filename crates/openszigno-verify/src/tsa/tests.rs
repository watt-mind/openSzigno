//! White-box tests for the refusal paths.
//!
//! Every token here is malformed on purpose and is built in-test, so the
//! branches that reject a token are exercised without needing a working
//! timestamp authority. The end-to-end positive cases live in
//! `tests/timestamps.rs`.

use super::imprint::*;
use super::token::*;
use super::*;
use crate::policy::SignatureScheme;
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::CmsVersion;
use cms::content_info::ContentInfo;
use cms::signed_data::SignerIdentifier;
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignerInfo as CmsSignerInfo, SignerInfos,
};
use const_oid::ObjectIdentifier;
use der::Any;
use der::Tag;
use der::asn1::GeneralizedTime;
use der::asn1::SetOfVec;
use sha2::{Digest as _, Sha256};
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

fn oid(text: &str) -> ObjectIdentifier {
    text.parse().expect("a valid OID")
}

fn sha256_algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: OID_SHA256,
        parameters: None,
    }
}

/// A self-signed certificate over a freshly generated P-256 key, which is
/// all these tests need: none of them reaches a signature check that has to
/// succeed.
fn certificate() -> x509_cert::Certificate {
    certificate_with_key_identifier(None)
}

/// A self-signed certificate, optionally carrying the given
/// `subjectKeyIdentifier`.
fn certificate_with_key_identifier(identifier: Option<&[u8]>) -> x509_cert::Certificate {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("a P-256 key is generated");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
    if let Some(identifier) = identifier {
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 14],
            OctetString::new(identifier.to_vec())
                .expect("encodes")
                .to_der()
                .expect("encodes"),
        )];
    }
    let certificate = params.self_signed(&key).expect("self-signing succeeds");
    x509_cert::Certificate::from_der(certificate.der()).expect("the certificate parses")
}

fn tst_info(imprint_oid: ObjectIdentifier) -> Vec<u8> {
    TstInfo {
        version: 1,
        policy: oid("1.3.6.1.4.1.99999.1"),
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifierOwned {
                oid: imprint_oid,
                parameters: None,
            },
            hashed_message: OctetString::new(vec![0u8; 32]).expect("encodes"),
        },
        serial_number: SerialNumber::new(&[1]).expect("encodes"),
        gen_time: GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            1_590_000_000,
        ))
        .expect("encodes"),
        accuracy: Some(Accuracy {
            seconds: None,
            millis: Some(500),
            micros: None,
        }),
        ordering: None,
        nonce: None,
        tsa: None,
        extensions: None,
    }
    .to_der()
    .expect("the TSTInfo encodes")
}

/// A token wrapping `content` as the `SignedData`'s encapsulated content.
fn token(
    econtent_type: ObjectIdentifier,
    econtent: Option<Any>,
    signers: Vec<CmsSignerInfo>,
    certificates: Vec<x509_cert::Certificate>,
) -> Vec<u8> {
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::try_from(vec![sha256_algorithm()]).expect("encodes"),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type,
            econtent,
        },
        certificates: (!certificates.is_empty()).then(|| {
            CertificateSet(
                SetOfVec::try_from(
                    certificates
                        .into_iter()
                        .map(CertificateChoices::Certificate)
                        .collect::<Vec<_>>(),
                )
                .expect("encodes"),
            )
        }),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(signers).expect("encodes")),
    };
    ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: Any::encode_from(&signed_data).expect("encodes"),
    }
    .to_der()
    .expect("encodes")
}

fn attributes(pairs: Vec<(ObjectIdentifier, Any)>) -> Attributes {
    SetOfVec::try_from(
        pairs
            .into_iter()
            .map(|(oid, value)| Attribute {
                oid,
                values: SetOfVec::try_from(vec![value]).expect("one value"),
            })
            .collect::<Vec<_>>(),
    )
    .expect("the attributes encode")
}

fn signer(
    certificate: &x509_cert::Certificate,
    signed_attrs: Option<Attributes>,
    signature_algorithm: ObjectIdentifier,
) -> CmsSignerInfo {
    CmsSignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: certificate.tbs_certificate.issuer.clone(),
            serial_number: certificate.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: sha256_algorithm(),
        signed_attrs,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: signature_algorithm,
            parameters: None,
        },
        signature: OctetString::new(vec![0u8; 32]).expect("encodes"),
        unsigned_attrs: None,
    }
}

/// Verify `bytes` with an empty trust store, and return the codes emitted.
fn outcome(bytes: Vec<u8>) -> TokenOutcome {
    let limits = VerifyLimits::default();
    verify_token(&TokenInput {
        document_index: None,
        kind: TimestampKind::SignatureTimestamp,
        token: bytes,
        imprint_input: b"data".to_vec(),
        anchors: &[],
        extra_certificates: &[],
        limits: &limits,
        allow_legacy_algorithms: false,
        revocation: crate::revocation::RevocationData::default(),
        revocation_policy: crate::trust::RevocationPolicy::Offline,
        claimed_signing_time: None,
    })
}

fn codes(outcome: &TokenOutcome) -> Vec<(&'static str, &'static str)> {
    outcome
        .report
        .checks
        .iter()
        .map(|check| (check.code.as_str(), check.status.as_str()))
        .collect()
}

#[test]
fn an_oversized_token_is_refused_before_parsing() {
    let outcome = outcome(vec![0u8; MAX_TOKEN_BYTES + 1]);
    assert_eq!(codes(&outcome), vec![("timestamp_token_parsed", "failed")]);
}

#[test]
fn bytes_that_are_not_a_content_info_are_refused() {
    for bytes in [Vec::new(), vec![0xff; 8], vec![0x30, 0x00]] {
        let outcome = outcome(bytes);
        assert_eq!(codes(&outcome), vec![("timestamp_token_parsed", "failed")]);
        assert_eq!(outcome.gen_time, None);
    }
}

#[test]
fn a_content_info_that_is_not_signed_data_is_refused() {
    let bytes = ContentInfo {
        content_type: oid("1.2.840.113549.1.7.1"),
        content: Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes"),
    }
    .to_der()
    .expect("encodes");
    assert_eq!(
        codes(&outcome(bytes)),
        vec![("timestamp_token_parsed", "failed")]
    );
}

#[test]
fn a_signed_data_that_does_not_decode_is_refused() {
    let bytes = ContentInfo {
        content_type: OID_SIGNED_DATA,
        content: Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes"),
    }
    .to_der()
    .expect("encodes");
    assert_eq!(
        codes(&outcome(bytes)),
        vec![("timestamp_token_parsed", "failed")]
    );
}

#[test]
fn a_token_over_another_content_type_is_refused() {
    let bytes = token(oid("1.2.840.113549.1.7.1"), None, Vec::new(), Vec::new());
    assert_eq!(
        codes(&outcome(bytes)),
        vec![("timestamp_token_parsed", "failed")]
    );
}

#[test]
fn a_token_without_econtent_is_refused() {
    let bytes = token(OID_CT_TST_INFO, None, Vec::new(), Vec::new());
    assert_eq!(
        codes(&outcome(bytes)),
        vec![("timestamp_token_parsed", "failed")]
    );
}

#[test]
fn an_econtent_that_is_not_a_tst_info_is_refused() {
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, vec![1, 2, 3]).expect("encodes")),
        Vec::new(),
        Vec::new(),
    );
    assert_eq!(
        codes(&outcome(bytes)),
        vec![("timestamp_token_parsed", "failed")]
    );
}

/// A parsed token with no `SignerInfo` still reports its `genTime`, and
/// still fails: nothing signed it.
#[test]
fn a_token_without_a_signer_info_fails_the_signature() {
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
        Vec::new(),
        Vec::new(),
    );
    let outcome = outcome(bytes);
    assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
    assert!(!outcome.report.verified);
    assert!(outcome.report.gen_time.is_some());
    // Sub-second accuracy widens the window to a whole second.
    assert_eq!(outcome.report.accuracy_seconds, Some(1));
    // The token's own checks stay `failed`; the check the signature sees
    // is `unknown`, because a token that did not verify proves nothing
    // either way about the signature.
    assert_eq!(
        summary_check(&outcome.report.checks).status,
        CheckStatus::Unknown
    );
}

#[test]
fn an_imprint_algorithm_outside_the_allowlist_fails() {
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, tst_info(oid("1.2.840.113549.2.5"))).expect("encodes")),
        Vec::new(),
        Vec::new(),
    );
    let outcome = outcome(bytes);
    assert!(codes(&outcome).contains(&("timestamp_imprint_mismatch", "failed")));
    assert_eq!(outcome.report.imprint_algorithm, None);
}

#[test]
fn a_signer_info_naming_no_carried_certificate_fails() {
    let certificate = certificate();
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
        vec![signer(&certificate, None, OID_RSA_ENCRYPTION)],
        Vec::new(),
    );
    let outcome = outcome(bytes);
    assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
    assert!(outcome.report.tsa_certificate.is_none());
}

/// The signed attributes are mandatory, and each of the ways they can be
/// wrong is refused rather than waved through.
#[test]
fn every_shape_of_bad_signed_attributes_fails() {
    let certificate = certificate();
    let content_type =
        |value: ObjectIdentifier| (OID_CONTENT_TYPE, Any::encode_from(&value).expect("encodes"));
    let digest = |bytes: Vec<u8>| {
        (
            OID_MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(bytes).expect("encodes")).expect("encodes"),
        )
    };
    let cases: Vec<Option<Attributes>> = vec![
        // No signed attributes at all.
        None,
        // A content type that is not id-ct-TSTInfo.
        Some(attributes(vec![
            content_type(oid("1.2.840.113549.1.7.1")),
            digest(vec![0u8; 32]),
        ])),
        // No content type.
        Some(attributes(vec![digest(vec![0u8; 32])])),
        // No message digest.
        Some(attributes(vec![content_type(OID_CT_TST_INFO)])),
        // A message digest over something else.
        Some(attributes(vec![
            content_type(OID_CT_TST_INFO),
            digest(vec![9u8; 32]),
        ])),
    ];
    for signed_attrs in cases {
        let bytes = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
            vec![signer(&certificate, signed_attrs, OID_RSA_ENCRYPTION)],
            vec![certificate.clone()],
        );
        let outcome = outcome(bytes);
        assert!(
            codes(&outcome).contains(&("timestamp_signature_invalid", "failed")),
            "expected a signature failure; got {:?}",
            codes(&outcome)
        );
        // The TSA certificate was located, so the certificate checks ran.
        assert!(codes(&outcome).contains(&("timestamp_tsa_certificate_invalid", "failed")));
        // With no anchors configured the path is unknown, never untrusted.
        assert!(codes(&outcome).contains(&("timestamp_tsa_path_unknown", "unknown")));
    }
}

#[test]
fn a_signature_algorithm_outside_the_allowlist_fails() {
    let certificate = certificate();
    let econtent = tst_info(OID_SHA256);
    let signed_attrs = attributes(vec![
        (
            OID_CONTENT_TYPE,
            Any::encode_from(&OID_CT_TST_INFO).expect("encodes"),
        ),
        (
            OID_MESSAGE_DIGEST,
            Any::encode_from(
                &OctetString::new(Sha256::digest(&econtent).to_vec()).expect("encodes"),
            )
            .expect("encodes"),
        ),
    ]);
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, econtent).expect("encodes")),
        vec![signer(
            &certificate,
            Some(signed_attrs),
            // ecdsa-with-SHA512, which this build does not implement.
            oid("1.2.840.10045.4.3.4"),
        )],
        vec![certificate.clone()],
    );
    assert!(codes(&outcome(bytes)).contains(&("timestamp_signature_invalid", "failed")));
}

/// More than one `SignerInfo` is a shape this build does not process, and
/// picking one of them would be a guess.
#[test]
fn more_than_one_signer_info_fails() {
    let first = certificate();
    let second = certificate();
    let bytes = token(
        OID_CT_TST_INFO,
        Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
        vec![
            signer(&first, None, OID_RSA_ENCRYPTION),
            signer(&second, None, OID_RSA_ENCRYPTION),
        ],
        vec![first, second],
    );
    assert!(codes(&outcome(bytes)).contains(&("timestamp_signature_invalid", "failed")));
}

/// A `SignerInfo` may name its certificate by subject key identifier, and
/// an identifier that matches nothing must not fall back to a guess.
#[test]
fn a_subject_key_identifier_selects_or_rejects() {
    let identifier = vec![7u8; 20];
    let certificate = certificate_with_key_identifier(Some(&identifier));
    assert_eq!(
        subject_key_identifier(
            &ParsedCertificate::from_der(
                &certificate.to_der().expect("encodes"),
                CertificateSource::TimestampToken,
            )
            .expect("parses"),
        ),
        Some(identifier.clone())
    );

    for (bytes, expect_certificate) in [(identifier.clone(), true), (vec![0u8; 20], false)] {
        let mut info = signer(&certificate, None, OID_RSA_ENCRYPTION);
        info.sid = SignerIdentifier::SubjectKeyIdentifier(
            x509_cert::ext::pkix::SubjectKeyIdentifier(OctetString::new(bytes).expect("encodes")),
        );
        let token = token(
            OID_CT_TST_INFO,
            Some(Any::new(Tag::OctetString, tst_info(OID_SHA256)).expect("encodes")),
            vec![info],
            vec![certificate.clone()],
        );
        let outcome = outcome(token);
        assert_eq!(outcome.report.tsa_certificate.is_some(), expect_certificate);
        assert!(codes(&outcome).contains(&("timestamp_signature_invalid", "failed")));
    }
}

#[test]
fn the_algorithm_maps_are_pinned() {
    assert_eq!(digest_of_oid(&OID_SHA384, false), Some(Digest::Sha384));
    assert_eq!(digest_of_oid(&OID_SHA512, false), Some(Digest::Sha512));
    // SHA-1 is admitted only for diagnosis, never by default.
    assert_eq!(digest_of_oid(&OID_SHA1, false), None);
    assert_eq!(digest_of_oid(&OID_SHA1, true), Some(Digest::Sha1));
    assert_eq!(digest_of_oid(&oid("1.2.840.113549.2.5"), true), None);

    assert_eq!(
        signature_scheme(&OID_SHA384_RSA, Digest::Sha256),
        Some(SignatureScheme::RsaPkcs1(Digest::Sha384))
    );
    assert_eq!(
        signature_scheme(&OID_SHA512_RSA, Digest::Sha256),
        Some(SignatureScheme::RsaPkcs1(Digest::Sha512))
    );
    assert_eq!(
        signature_scheme(&OID_ECDSA_SHA256, Digest::Sha256),
        Some(SignatureScheme::Ecdsa(Digest::Sha256))
    );
    assert_eq!(
        signature_scheme(&OID_ECDSA_SHA384, Digest::Sha256),
        Some(SignatureScheme::Ecdsa(Digest::Sha384))
    );
    assert_eq!(
        signature_scheme(&OID_ECDSA_SHA512, Digest::Sha256),
        Some(SignatureScheme::Ecdsa(Digest::Sha512))
    );
    // RSASSA-PSS needs its parameters read, which this build does not do.
    assert_eq!(
        signature_scheme(&oid("1.2.840.113549.1.1.10"), Digest::Sha256),
        None
    );
}

#[test]
fn accuracy_is_rounded_up_to_whole_seconds() {
    let accuracy = |seconds, millis, micros| {
        accuracy_seconds(&Accuracy {
            seconds,
            millis,
            micros,
        })
    };
    assert_eq!(accuracy(None, None, None), 0);
    assert_eq!(accuracy(Some(2), None, None), 2);
    assert_eq!(accuracy(Some(2), None, Some(1)), 3);
    // A negative accuracy is not an encoding this build reads as widening.
    assert_eq!(accuracy(Some(-2), None, None), 0);
}

#[test]
fn the_summary_is_never_failed() {
    let passed = vec![Check::passed(CheckCode::TimestampImprintOk, "ok")];
    let unknown = vec![Check::unknown(CheckCode::TimestampTsaPathUnknown, "?")];
    let failed = vec![Check::failed(CheckCode::TimestampImprintMismatch, "no")];
    let mixed = vec![
        Check::passed(CheckCode::TimestampImprintOk, "ok"),
        Check::failed(CheckCode::TimestampTsaPathUntrusted, "no"),
    ];
    assert_eq!(summary_check(&passed).status, CheckStatus::Passed);
    assert_eq!(summary_check(&unknown).status, CheckStatus::Unknown);
    // A failed token yields `unknown` at the signature level: it supplies
    // no proof of existence, which is missing information rather than a
    // finding against the signature (ETSI EN 319 102-1).
    assert_eq!(summary_check(&failed).status, CheckStatus::Unknown);
    assert_eq!(summary_check(&mixed).status, CheckStatus::Unknown);
}

#[test]
fn serial_numbers_are_rendered_as_hex() {
    assert_eq!(hex(&[0x00, 0x2a, 0xff]), "002aff");
    assert_eq!(hex(&[]), "");
}
