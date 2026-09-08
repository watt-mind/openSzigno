//! RFC 3161 timestamp tokens from a synthetic TSA.
//!
//! This is test material only. It exists so the verifier meets tokens it did
//! not itself produce the verification logic for, and it must never move into
//! a shipped crate.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use der::Decode as _;
use sha2::{Digest as _, Sha256};

use super::dossier::TimestampSpec;
use super::pki::SigningKey;

/// Build one RFC 3161 token over `imprint_input`, signed by a synthetic TSA.
///
/// This is test material only. It exists so the verifier meets tokens it did
/// not itself produce the verification logic for, and it must never move into
/// a shipped crate.
pub fn build_timestamp_token(spec: &TimestampSpec, imprint_input: &[u8]) -> Vec<u8> {
    use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo,
        SignerInfos,
    };
    use der::asn1::{Any, OctetString, SetOfVec};
    use der::{Encode as _, Tag};
    use openszigno_verify::tsa::{Accuracy, MessageImprint, TstInfo};
    use x509_cert::attr::{Attribute, Attributes};
    use x509_cert::spki::AlgorithmIdentifierOwned;

    let oid = |text: &str| const_oid::ObjectIdentifier::new_unwrap(text);
    let sha256_algorithm = AlgorithmIdentifierOwned {
        oid: oid("2.16.840.1.101.3.4.2.1"),
        parameters: None,
    };

    let mut imprint = Sha256::digest(imprint_input).to_vec();
    if spec.wrong_imprint {
        imprint[0] ^= 0xff;
    }
    let gen_time = openszigno_verify::parse_rfc3339(&spec.gen_time).expect("the genTime parses");
    let tst_info = TstInfo {
        version: 1,
        policy: oid("1.3.6.1.4.1.99999.1"),
        message_imprint: MessageImprint {
            hash_algorithm: sha256_algorithm.clone(),
            hashed_message: OctetString::new(imprint).expect("the imprint encodes"),
        },
        serial_number: x509_cert::serial_number::SerialNumber::new(&[0x2a])
            .expect("the serial encodes"),
        gen_time: der::asn1::GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(
            u64::try_from(gen_time).expect("the genTime is after the epoch"),
        ))
        .expect("the genTime encodes"),
        accuracy: spec.accuracy_seconds.map(|seconds| Accuracy {
            seconds: Some(seconds),
            millis: None,
            micros: None,
        }),
        ordering: None,
        nonce: None,
        tsa: None,
        extensions: None,
    };
    let econtent = tst_info.to_der().expect("the TSTInfo encodes");

    let tsa = x509_cert::Certificate::from_der(&spec.tsa_der).expect("the TSA certificate parses");
    let attribute = |oid_text: &str, value: Any| Attribute {
        oid: oid(oid_text),
        values: SetOfVec::try_from(vec![value]).expect("one attribute value"),
    };
    let signed_attrs: Attributes = SetOfVec::try_from(vec![
        attribute(
            "1.2.840.113549.1.9.3",
            Any::encode_from(&oid("1.2.840.113549.1.9.16.1.4")).expect("the content type encodes"),
        ),
        attribute(
            "1.2.840.113549.1.9.4",
            Any::encode_from(
                &OctetString::new(Sha256::digest(&econtent).to_vec()).expect("encodes"),
            )
            .expect("the message digest encodes"),
        ),
    ])
    .expect("the signed attributes encode");

    let message = signed_attrs.to_der().expect("the signed attributes encode");
    let signature = match &spec.tsa_key.signing {
        SigningKey::Rsa(private) => {
            use rsa::signature::{SignatureEncoding as _, Signer as _};
            rsa::pkcs1v15::SigningKey::<Sha256>::new((**private).clone())
                .sign(&message)
                .to_vec()
        }
        _ => panic!("the synthetic TSA signs with RSA"),
    };

    let mut certificates = vec![CertificateChoices::Certificate(tsa.clone())];
    for der in &spec.token_certificates {
        certificates.push(CertificateChoices::Certificate(
            x509_cert::Certificate::from_der(der).expect("the certificate parses"),
        ));
    }
    let signed_data = SignedData {
        version: CmsVersion::V3,
        digest_algorithms: SetOfVec::try_from(vec![sha256_algorithm.clone()])
            .expect("one digest algorithm"),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid("1.2.840.113549.1.9.16.1.4"),
            econtent: Some(Any::new(Tag::OctetString, econtent).expect("the eContent encodes")),
        },
        certificates: Some(CertificateSet(
            SetOfVec::try_from(certificates).expect("the certificate set encodes"),
        )),
        crls: None,
        signer_infos: SignerInfos(
            SetOfVec::try_from(vec![SignerInfo {
                version: CmsVersion::V1,
                sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                    issuer: tsa.tbs_certificate.issuer.clone(),
                    serial_number: tsa.tbs_certificate.serial_number.clone(),
                }),
                digest_alg: sha256_algorithm,
                signed_attrs: Some(signed_attrs),
                signature_algorithm: AlgorithmIdentifierOwned {
                    oid: oid("1.2.840.113549.1.1.1"),
                    parameters: Some(Any::null()),
                },
                signature: OctetString::new(signature).expect("the signature encodes"),
                unsigned_attrs: None,
            }])
            .expect("one SignerInfo"),
        ),
    };
    let token = ContentInfo {
        content_type: oid("1.2.840.113549.1.7.2"),
        content: Any::encode_from(&signed_data).expect("the SignedData encodes"),
    };
    match spec.wrap_in_response {
        None => token.to_der().expect("the token encodes"),
        Some(status) => openszigno_verify::tsa::TimeStampResp {
            status: openszigno_verify::tsa::PkiStatusInfo {
                status,
                status_string: None,
                fail_info: None,
            },
            // A rejection carries no token at all, which is the shape a real
            // TSA returns and the one a verifier must not read past.
            time_stamp_token: (status <= 1).then_some(token),
        }
        .to_der()
        .expect("the response encodes"),
    }
}
