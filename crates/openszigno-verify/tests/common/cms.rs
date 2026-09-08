//! Synthetic revocation material: CRLs and OCSP responses.
//!
//! Hand-built on `x509-cert`'s CRL types and `x509-ocsp`'s response types, the
//! same crates the verifier reads them with. That is deliberate: a fixture
//! built with an independent encoder would test the encoder, and a fixture
//! built with the verifier's own *logic* would test nothing. Only the ASN.1
//! shapes are shared; every rule under test is applied by the crate and
//! asserted here.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use der::Decode as _;
use sha2::{Digest as _, Sha256};

use super::pki::{SigningKey, TestKey};

/// One entry a CRL revokes.
pub struct RevokedSpec {
    pub serial: Vec<u8>,
    pub revocation_time: String,
    /// An RFC 5280 `CRLReason` value, or `None` for no reason extension.
    pub reason: Option<u32>,
    /// Plant a `certificateIssuer` entry extension, which makes the entry an
    /// indirect-CRL entry the verifier must refuse.
    pub certificate_issuer: bool,
}

impl RevokedSpec {
    pub fn new(certificate: &[u8], revocation_time: &str) -> Self {
        let parsed = x509_cert::Certificate::from_der(certificate).expect("the certificate parses");
        Self {
            serial: parsed.tbs_certificate.serial_number.as_bytes().to_vec(),
            revocation_time: revocation_time.to_owned(),
            reason: None,
            certificate_issuer: false,
        }
    }

    pub fn with_reason(mut self, reason: u32) -> Self {
        self.reason = Some(reason);
        self
    }
}

/// How one synthetic CRL should look.
pub struct CrlSpec {
    /// The CA whose subject name becomes the CRL's `issuer`.
    pub issuer_der: Vec<u8>,
    /// The key that signs it, which is normally the CA's own.
    pub signer_key: TestKey,
    pub this_update: String,
    pub next_update: Option<String>,
    pub revoked: Vec<RevokedSpec>,
    /// An `issuingDistributionPoint`, as (`onlyContainsUserCerts`,
    /// `onlyContainsCaCerts`, `indirectCrl`, distribution-point URI).
    pub issuing_distribution_point: Option<(bool, bool, bool, Option<String>)>,
    /// Mark it a delta CRL, which the verifier must refuse.
    pub delta: bool,
    /// Plant a critical extension whose semantics the verifier does not
    /// implement.
    pub unknown_critical: bool,
    /// Corrupt the signature after it is made.
    pub tamper_signature: bool,
}

impl CrlSpec {
    pub fn new(issuer_der: Vec<u8>, signer_key: TestKey) -> Self {
        Self {
            issuer_der,
            signer_key,
            this_update: "2020-05-01T00:00:00Z".to_owned(),
            next_update: Some("2020-07-01T00:00:00Z".to_owned()),
            revoked: Vec::new(),
            issuing_distribution_point: None,
            delta: false,
            unknown_critical: false,
            tamper_signature: false,
        }
    }

    pub fn revoking(mut self, entry: RevokedSpec) -> Self {
        self.revoked.push(entry);
        self
    }
}

fn asn1_time(text: &str) -> x509_cert::time::Time {
    let seconds = openszigno_verify::parse_rfc3339(text).expect("the time parses");
    x509_cert::time::Time::GeneralTime(
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            u64::try_from(seconds).expect("the time is after the epoch"),
        ))
        .expect("the time encodes"),
    )
}

fn extension(oid: &str, critical: bool, value: Vec<u8>) -> x509_cert::ext::Extension {
    x509_cert::ext::Extension {
        extn_id: const_oid::ObjectIdentifier::new_unwrap(oid),
        critical,
        extn_value: der::asn1::OctetString::new(value).expect("the extension value encodes"),
    }
}

/// The `sha256WithRSAEncryption` identifier every synthetic signer uses.
fn sha256_rsa() -> x509_cert::spki::AlgorithmIdentifierOwned {
    x509_cert::spki::AlgorithmIdentifierOwned {
        oid: const_oid::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        parameters: Some(der::asn1::Any::null()),
    }
}

pub(super) fn sign_rsa_sha256(key: &TestKey, message: &[u8]) -> Vec<u8> {
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    match &key.signing {
        SigningKey::Rsa(private) => rsa::pkcs1v15::SigningKey::<Sha256>::new((**private).clone())
            .sign(message)
            .to_vec(),
        _ => panic!("the synthetic revocation authorities sign with RSA"),
    }
}

/// Build one DER-encoded CRL.
pub fn build_crl(spec: &CrlSpec) -> Vec<u8> {
    use der::Encode as _;

    let issuer = x509_cert::Certificate::from_der(&spec.issuer_der).expect("the CA parses");
    let mut extensions: Vec<x509_cert::ext::Extension> = Vec::new();
    // A CRL number is not checked by this build but is what a real CA emits, so
    // the fixture carries one rather than being unrealistically bare.
    extensions.push(extension(
        "2.5.29.20",
        false,
        der::asn1::Uint::new(&[0x07])
            .expect("the CRL number encodes")
            .to_der()
            .expect("the CRL number encodes"),
    ));
    if let Some((user_certs, ca_certs, indirect, point)) = &spec.issuing_distribution_point {
        let names = point.as_ref().map(|uri| {
            x509_cert::ext::pkix::name::DistributionPointName::FullName(vec![
                x509_cert::ext::pkix::name::GeneralName::UniformResourceIdentifier(
                    der::asn1::Ia5String::new(uri.as_str()).expect("the URI encodes"),
                ),
            ])
        });
        let idp = x509_cert::ext::pkix::crl::IssuingDistributionPoint {
            distribution_point: names,
            only_contains_user_certs: *user_certs,
            only_contains_ca_certs: *ca_certs,
            only_some_reasons: None,
            indirect_crl: *indirect,
            only_contains_attribute_certs: false,
        };
        extensions.push(extension(
            "2.5.29.28",
            true,
            idp.to_der().expect("the IDP encodes"),
        ));
    }
    if spec.delta {
        extensions.push(extension(
            "2.5.29.27",
            true,
            der::asn1::Uint::new(&[0x01])
                .expect("the base CRL number encodes")
                .to_der()
                .expect("the base CRL number encodes"),
        ));
    }
    if spec.unknown_critical {
        // A critical extension with no meaning to this build, which must make
        // the whole CRL unusable rather than partly understood.
        extensions.push(extension("1.3.6.1.4.1.99999.7", true, vec![0x05, 0x00]));
    }

    let revoked: Vec<x509_cert::crl::RevokedCert> = spec
        .revoked
        .iter()
        .map(|entry| {
            let mut entry_extensions: Vec<x509_cert::ext::Extension> = Vec::new();
            if let Some(reason) = entry.reason {
                entry_extensions.push(extension(
                    "2.5.29.21",
                    false,
                    der::Encode::to_der(
                        &der::asn1::Uint::new(
                            &[u8::try_from(reason).expect("a small reason code")],
                        )
                        .expect("the reason encodes"),
                    )
                    .map(|bytes| {
                        // CRLReason is ENUMERATED, not INTEGER: retag it.
                        let mut retagged = bytes;
                        retagged[0] = 0x0a;
                        retagged
                    })
                    .expect("the reason encodes"),
                ));
            }
            if entry.certificate_issuer {
                entry_extensions.push(extension("2.5.29.29", true, vec![0x30, 0x00]));
            }
            x509_cert::crl::RevokedCert {
                serial_number: x509_cert::serial_number::SerialNumber::new(&entry.serial)
                    .expect("the serial encodes"),
                revocation_date: asn1_time(&entry.revocation_time),
                crl_entry_extensions: (!entry_extensions.is_empty()).then_some(entry_extensions),
            }
        })
        .collect();

    let tbs = x509_cert::crl::TbsCertList {
        version: x509_cert::Version::V2,
        signature: sha256_rsa(),
        issuer: issuer.tbs_certificate.subject.clone(),
        this_update: asn1_time(&spec.this_update),
        next_update: spec.next_update.as_deref().map(asn1_time),
        revoked_certificates: (!revoked.is_empty()).then_some(revoked),
        crl_extensions: Some(extensions),
    };
    let message = tbs.to_der().expect("the tbsCertList encodes");
    let mut signature = sign_rsa_sha256(&spec.signer_key, &message);
    if spec.tamper_signature {
        signature[0] ^= 0xff;
    }
    x509_cert::crl::CertificateList {
        tbs_cert_list: tbs,
        signature_algorithm: sha256_rsa(),
        signature: der::asn1::BitString::from_bytes(&signature).expect("the signature encodes"),
    }
    .to_der()
    .expect("the CRL encodes")
}

/// What an OCSP response says about the certificate it is asked about.
pub enum OcspStatus {
    Good,
    /// Revoked at this RFC 3339 time, with an optional reason code.
    Revoked(String, Option<u32>),
    Unknown,
}

/// How one synthetic OCSP response should look.
pub struct OcspSpec {
    pub issuer_der: Vec<u8>,
    pub subject_der: Vec<u8>,
    /// The key that signs the response.
    pub responder_key: TestKey,
    /// The responder's own certificate, or `None` when the CA answers for
    /// itself.
    pub responder_der: Option<Vec<u8>>,
    /// Whether the responder certificate travels with the response. A
    /// delegated responder whose certificate is missing cannot be authorised.
    pub include_responder_certificate: bool,
    pub status: OcspStatus,
    pub produced_at: String,
    pub this_update: String,
    pub next_update: Option<String>,
    /// Name the responder by the SHA-1 hash of its key rather than by name.
    pub by_key: bool,
    /// A non-`successful` `OCSPResponseStatus`, which carries no answer at all.
    pub response_status: Option<u8>,
    /// Point the `CertID` at a different serial, so it is about another
    /// certificate.
    pub wrong_serial: bool,
    /// Use SHA-256 in the `CertID` instead of RFC 6960's default SHA-1.
    pub sha256_cert_id: bool,
    pub tamper_signature: bool,
}

impl OcspSpec {
    pub fn new(issuer_der: Vec<u8>, subject_der: Vec<u8>, responder_key: TestKey) -> Self {
        Self {
            issuer_der,
            subject_der,
            responder_key,
            responder_der: None,
            include_responder_certificate: true,
            status: OcspStatus::Good,
            produced_at: "2020-05-15T00:00:00Z".to_owned(),
            this_update: "2020-05-15T00:00:00Z".to_owned(),
            next_update: Some("2020-07-01T00:00:00Z".to_owned()),
            by_key: false,
            response_status: None,
            wrong_serial: false,
            sha256_cert_id: false,
            tamper_signature: false,
        }
    }
}

fn ocsp_time(text: &str) -> x509_ocsp::OcspGeneralizedTime {
    let seconds = openszigno_verify::parse_rfc3339(text).expect("the time parses");
    x509_ocsp::OcspGeneralizedTime(
        der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            u64::try_from(seconds).expect("the time is after the epoch"),
        ))
        .expect("the time encodes"),
    )
}

/// Build one DER-encoded `OCSPResponse`.
pub fn build_ocsp(spec: &OcspSpec) -> Vec<u8> {
    use der::{Encode as _, asn1::Null};

    let issuer = x509_cert::Certificate::from_der(&spec.issuer_der).expect("the CA parses");
    let subject = x509_cert::Certificate::from_der(&spec.subject_der).expect("the subject parses");
    let responder = spec
        .responder_der
        .as_ref()
        .map(|der| x509_cert::Certificate::from_der(der).expect("the responder parses"))
        .unwrap_or_else(|| issuer.clone());

    let name_der = issuer
        .tbs_certificate
        .subject
        .to_der()
        .expect("the issuer name encodes");
    let key_bytes = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .expect("the issuer key is whole bytes");
    let (hash_oid, name_hash, key_hash) = if spec.sha256_cert_id {
        (
            "2.16.840.1.101.3.4.2.1",
            Sha256::digest(&name_der).to_vec(),
            Sha256::digest(key_bytes).to_vec(),
        )
    } else {
        (
            "1.3.14.3.2.26",
            sha1::Sha1::digest(&name_der).to_vec(),
            sha1::Sha1::digest(key_bytes).to_vec(),
        )
    };
    let mut serial = subject.tbs_certificate.serial_number.as_bytes().to_vec();
    if spec.wrong_serial {
        serial[0] ^= 0x7f;
    }

    let cert_id = x509_ocsp::CertId {
        hash_algorithm: x509_cert::spki::AlgorithmIdentifierOwned {
            oid: const_oid::ObjectIdentifier::new_unwrap(hash_oid),
            parameters: Some(der::asn1::Any::null()),
        },
        issuer_name_hash: der::asn1::OctetString::new(name_hash).expect("the hash encodes"),
        issuer_key_hash: der::asn1::OctetString::new(key_hash).expect("the hash encodes"),
        serial_number: x509_cert::serial_number::SerialNumber::new(&serial)
            .expect("the serial encodes"),
    };
    let cert_status = match &spec.status {
        OcspStatus::Good => x509_ocsp::CertStatus::Good(Null),
        OcspStatus::Unknown => x509_ocsp::CertStatus::Unknown(Null),
        OcspStatus::Revoked(time, reason) => {
            x509_ocsp::CertStatus::Revoked(x509_ocsp::RevokedInfo {
                revocation_time: ocsp_time(time),
                revocation_reason: reason.map(|reason| match reason {
                    1 => x509_cert::ext::pkix::CrlReason::KeyCompromise,
                    4 => x509_cert::ext::pkix::CrlReason::Superseded,
                    6 => x509_cert::ext::pkix::CrlReason::CertificateHold,
                    _ => x509_cert::ext::pkix::CrlReason::Unspecified,
                }),
            })
        }
    };

    let responder_id = if spec.by_key {
        let key = responder
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .expect("the responder key is whole bytes");
        x509_ocsp::ResponderId::ByKey(
            der::asn1::OctetString::new(sha1::Sha1::digest(key).to_vec())
                .expect("the key hash encodes"),
        )
    } else {
        x509_ocsp::ResponderId::ByName(responder.tbs_certificate.subject.clone())
    };

    let response_data = x509_ocsp::ResponseData {
        version: x509_ocsp::Version::V1,
        responder_id,
        produced_at: ocsp_time(&spec.produced_at),
        responses: vec![x509_ocsp::SingleResponse {
            cert_id,
            cert_status,
            this_update: ocsp_time(&spec.this_update),
            next_update: spec.next_update.as_deref().map(ocsp_time),
            single_extensions: None,
        }],
        response_extensions: None,
    };
    let message = response_data.to_der().expect("the ResponseData encodes");
    let mut signature = sign_rsa_sha256(&spec.responder_key, &message);
    if spec.tamper_signature {
        signature[0] ^= 0xff;
    }
    let basic = x509_ocsp::BasicOcspResponse {
        tbs_response_data: response_data,
        signature_algorithm: sha256_rsa(),
        signature: der::asn1::BitString::from_bytes(&signature).expect("the signature encodes"),
        certs: spec
            .include_responder_certificate
            .then(|| spec.responder_der.as_ref().map(|_| vec![responder.clone()]))
            .flatten(),
    };
    let response = match spec.response_status {
        None => x509_ocsp::OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: const_oid::db::rfc6960::ID_PKIX_OCSP_BASIC,
                response: der::asn1::OctetString::new(
                    basic.to_der().expect("the BasicOCSPResponse encodes"),
                )
                .expect("the response encodes"),
            }),
        },
        Some(_) => x509_ocsp::OcspResponse::try_later(),
    };
    response.to_der().expect("the OCSPResponse encodes")
}
