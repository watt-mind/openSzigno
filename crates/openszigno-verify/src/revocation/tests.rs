//! White-box tests for the work an OCSP response can make this crate do.
//!
//! The end-to-end OCSP cases live in `tests/revocation.rs` and
//! `tests/revocation_ocsp.rs`; what needs to be tested here is *bounded work*,
//! which no report can show. A response's `certs` field is attacker-supplied
//! and unbounded on the wire, and under the trusted-responder model every
//! entry naming the responder could once drive a whole certification-path
//! search.
//!
//! Every byte here is generated at test time. Nothing is derived from a real
//! dossier, a real CA, or a real responder.

use std::sync::atomic::Ordering;

use der::{Decode, Encode};

use crate::certs::{CertificateSource, ParsedCertificate};
use crate::policy::VerifyLimits;

use super::ocsp::{PATH_SEARCHES, ocsp_answer};
use super::tiers::Answer;

const ID_KP_OCSP_SIGNING: &str = "1.3.6.1.5.5.7.3.9";
const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";

/// A key in both shapes the helper needs: `rcgen`'s, to issue certificates,
/// and the RustCrypto one, to sign a `ResponseData`.
struct Key {
    rcgen: rcgen::KeyPair,
    signing: p256::ecdsa::SigningKey,
}

/// A P-256 key from a fixed scalar, so the suite stays deterministic.
fn key(seed: u8) -> Key {
    use p256::pkcs8::EncodePrivateKey as _;
    let mut scalar = [1u8; 32];
    scalar[31] = seed;
    let secret = p256::SecretKey::from_slice(&scalar).expect("the fixed scalar is in range");
    let pkcs8 = secret.to_pkcs8_der().expect("the P-256 key encodes");
    Key {
        rcgen: rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &pkcs8.as_bytes().into(),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .expect("the key loads"),
        signing: p256::ecdsa::SigningKey::from(&secret),
    }
}

fn params(common_name: &str, ca: bool, ocsp_signing: bool) -> rcgen::CertificateParams {
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
    let mut name = rcgen::DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, common_name);
    name.push(
        rcgen::DnType::OrganizationName,
        "openSzigno synthetic test PKI",
    );
    params.distinguished_name = name;
    params.not_before = rcgen::date_time_ymd(2019, 1, 1);
    params.not_after = rcgen::date_time_ymd(2039, 1, 1);
    params.use_authority_key_identifier_extension = true;
    if ca {
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
    } else {
        params.is_ca = rcgen::IsCa::ExplicitNoCa;
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    }
    if ocsp_signing {
        let usages = vec![const_oid::ObjectIdentifier::new_unwrap(ID_KP_OCSP_SIGNING)];
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[2, 5, 29, 37],
            usages.to_der().expect("the usages encode"),
        )];
    }
    params
}

struct Issued {
    der: Vec<u8>,
    params: rcgen::CertificateParams,
}

fn self_signed(params: rcgen::CertificateParams, key: &Key) -> Issued {
    let certificate = params.self_signed(&key.rcgen).expect("self-signing works");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

fn issued_by(
    params: rcgen::CertificateParams,
    subject: &Key,
    issuer: &Issued,
    issuer_key: &Key,
) -> Issued {
    let authority = rcgen::Issuer::from_params(&issuer.params, &issuer_key.rcgen);
    let certificate = params
        .clone()
        .signed_by(&subject.rcgen, &authority)
        .expect("issuing works");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

fn parse(der: &[u8]) -> ParsedCertificate {
    ParsedCertificate::from_der(der, CertificateSource::OcspResponse)
        .expect("the synthetic certificate parses")
}

fn ocsp_time(seconds: u64) -> x509_ocsp::OcspGeneralizedTime {
    x509_ocsp::OcspGeneralizedTime(
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(seconds))
            .expect("the time encodes"),
    )
}

/// The whole synthetic hierarchy one of these tests needs: a root the caller
/// trusts, the certificate the response is about under its own issuing CA,
/// and a central responder under a root the caller does *not* trust.
///
/// The responder is not the issuing CA and was not issued by it, so only the
/// trusted-responder model can authorise it — which is the model that runs a
/// path search — and its own root is not an anchor, so that search fails.
/// Failing is the point: the loop stops at the first search that succeeds, so
/// it is a responder nothing vouches for that could once be made to drive one
/// full path search per certificate an attacker chose to pack into the
/// response.
struct Central {
    root: ParsedCertificate,
    issuing: ParsedCertificate,
    signer: ParsedCertificate,
    /// Re-issues of one responder certificate: the same public key and the
    /// same subject name every time, a different serial each time, so each is
    /// a distinct DER blob that names the same responder.
    responders: Vec<Vec<u8>>,
    responder_key: p256::ecdsa::SigningKey,
    responder_name: x509_cert::name::Name,
}

fn central(reissues: usize) -> Central {
    let root_key = key(2);
    let foreign_root_key = key(3);
    let issuing_key = key(4);
    let responder_key = key(5);
    let signer_key = key(6);

    let root = self_signed(params("openSzigno Test Root", true, false), &root_key);
    let foreign_root = self_signed(
        params("openSzigno Unrelated Root", true, false),
        &foreign_root_key,
    );
    let issuing = issued_by(
        params("openSzigno Issuing CA", true, false),
        &issuing_key,
        &root,
        &root_key,
    );
    let signer = issued_by(
        params("openSzigno Test Signer", false, false),
        &signer_key,
        &issuing,
        &issuing_key,
    );
    // A distinct serial each time. Without one `rcgen` derives the serial from
    // the public key, so every re-issue would be the same DER blob and the
    // deduplication alone would collapse them.
    let responders: Vec<Vec<u8>> = (0..reissues)
        .map(|index| {
            let mut spec = params("openSzigno Central OCSP Responder", false, true);
            spec.serial_number = Some(rcgen::SerialNumber::from_slice(&[
                0x11,
                u8::try_from(index).expect("a small re-issue count"),
            ]));
            issued_by(spec, &responder_key, &foreign_root, &foreign_root_key).der
        })
        .collect();
    let responder_name = x509_cert::Certificate::from_der(&responders[0])
        .expect("the responder parses")
        .tbs_certificate
        .subject;

    Central {
        root: parse(&root.der),
        issuing: parse(&issuing.der),
        signer: parse(&signer.der),
        responders,
        responder_key: responder_key.signing,
        responder_name,
    }
}

/// A `good` response about the signer, carrying every responder certificate
/// the hierarchy was built with.
fn response(pki: &Central) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    use sha2::{Digest as _, Sha256};

    let key_bytes = pki
        .issuing
        .certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .expect("the issuer key is whole bytes");
    let cert_id = x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: Some(der::asn1::Any::null()),
        },
        issuer_name_hash: der::asn1::OctetString::new(
            Sha256::digest(pki.signer.issuer_der()).to_vec(),
        )
        .expect("the hash encodes"),
        issuer_key_hash: der::asn1::OctetString::new(Sha256::digest(key_bytes).to_vec())
            .expect("the hash encodes"),
        serial_number: pki.signer.certificate.tbs_certificate.serial_number.clone(),
    };
    let response_data = x509_ocsp::ResponseData {
        version: x509_ocsp::Version::V1,
        responder_id: x509_ocsp::ResponderId::ByName(pki.responder_name.clone()),
        produced_at: ocsp_time(PRODUCED_AT),
        responses: vec![x509_ocsp::SingleResponse {
            cert_id,
            cert_status: x509_ocsp::CertStatus::Good(der::asn1::Null),
            this_update: ocsp_time(PRODUCED_AT),
            next_update: Some(ocsp_time(PRODUCED_AT + 30 * 86_400)),
            single_extensions: None,
        }],
        response_extensions: None,
    };
    let message = response_data.to_der().expect("the ResponseData encodes");
    let signature: p256::ecdsa::DerSignature = pki.responder_key.sign(&message);
    x509_ocsp::BasicOcspResponse {
        tbs_response_data: response_data,
        signature_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap(OID_ECDSA_SHA256),
            parameters: None,
        },
        signature: der::asn1::BitString::from_bytes(signature.as_bytes())
            .expect("the signature encodes"),
        certs: Some(
            pki.responders
                .iter()
                .map(|der| x509_cert::Certificate::from_der(der).expect("the responder parses"))
                .collect(),
        ),
    }
    .to_der()
    .expect("the BasicOCSPResponse encodes")
}

/// 2020-05-15T00:00:00Z, inside every synthetic certificate's window.
const PRODUCED_AT: u64 = 1_589_500_800;

/// The smaller certificate bound makes the padded response cheap to build
/// while still exceeding the limit, which is the property under test.
fn limits() -> VerifyLimits {
    VerifyLimits {
        max_certificates: 4,
        ..VerifyLimits::default()
    }
}

fn answer(pki: &Central) -> Answer {
    // The root is an ordinary trust-store anchor: the operator put the file in
    // the directory, and that is the whole statement about it.
    let anchor = crate::trust::TrustAnchor::from_store(pki.root.der.clone());
    let provenance = [(pki.root.der.clone(), &anchor)];
    ocsp_answer(
        &response(pki),
        &pki.signer,
        &pki.issuing,
        &[],
        std::slice::from_ref(&pki.root),
        crate::certs::AnchorStatus::new(&provenance),
        PRODUCED_AT as crate::trust::UnixTime,
        &limits(),
    )
}

/// A response padded with re-issues of one responder certificate costs exactly
/// the work the one-certificate response costs: the list is cut to
/// `max_certificates`, deduplicated by DER, and the path search is run once per
/// distinct responder public key rather than once per certificate.
///
/// Both cases live in one test because the counter is process-wide.
#[test]
fn a_padded_certificate_list_does_not_multiply_the_path_search() {
    let one = central(1);
    PATH_SEARCHES.store(0, Ordering::Relaxed);
    assert!(
        matches!(answer(&one), Answer::Invalid(_)),
        "a responder no configured anchor vouches for authorises nothing"
    );
    let baseline = PATH_SEARCHES.load(Ordering::Relaxed);
    assert_eq!(baseline, 1, "one responder costs one path search");

    let padded = central(limits().max_certificates + 8);
    assert_eq!(
        padded
            .responders
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        padded.responders.len(),
        "the re-issues are distinct DER blobs, so deduplication alone cannot collapse them"
    );
    PATH_SEARCHES.store(0, Ordering::Relaxed);
    assert!(
        matches!(answer(&padded), Answer::Invalid(_)),
        "padding the certificate list does not change the answer"
    );
    assert_eq!(
        PATH_SEARCHES.load(Ordering::Relaxed),
        baseline,
        "max_certificates + 8 responder certificates cost the same path searches as one"
    );
}
