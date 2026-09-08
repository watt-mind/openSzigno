//! The RFC 3161 wire formats and the CMS signed-attribute checks.
//!
//! The ASN.1 types are hand-declared rather than pulled from another crate so
//! that exactly what is decoded, and what is refused, is visible here. A
//! `ContentInfo` and a whole `TimeStampResp` are both accepted as the outer
//! shape, the latter only once its `PKIStatus` says a token was issued.

use const_oid::ObjectIdentifier;
use der::asn1::{GeneralizedTime, Int, OctetString};
use der::{Any, Decode, Encode, Sequence};
use x509_cert::attr::Attributes;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifierOwned;

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};

use crate::certs::{ParsedCertificate, verify_with_spki};
use crate::policy::{Digest, SignatureScheme};

use super::MAX_TOKEN_BYTES;
use super::imprint::{digest, digest_of_oid};

pub(super) const OID_SIGNED_DATA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
pub(super) const OID_CT_TST_INFO: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
pub(super) const OID_CONTENT_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
pub(super) const OID_MESSAGE_DIGEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

pub(super) const OID_RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
pub(super) const OID_SHA256_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
pub(super) const OID_SHA384_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
pub(super) const OID_SHA512_RSA: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
pub(super) const OID_ECDSA_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
pub(super) const OID_ECDSA_SHA384: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

pub(super) const OID_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.5.29.14");

/// `MessageImprint`, RFC 3161 section 2.4.1.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct MessageImprint {
    pub hash_algorithm: AlgorithmIdentifierOwned,
    pub hashed_message: OctetString,
}

/// `Accuracy`, RFC 3161 section 2.4.2.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct Accuracy {
    #[asn1(optional = "true")]
    pub seconds: Option<i32>,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    pub millis: Option<i32>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub micros: Option<i32>,
}

/// `TSTInfo`, RFC 3161 section 2.4.2.
///
/// Hand-declared rather than pulled from another crate so that exactly what is
/// decoded, and what is refused, is visible here. `ordering` and `nonce` are
/// decoded as optional rather than defaulted: an absent `ordering` is the DER
/// encoding of `FALSE`, and neither field changes any decision this tool makes.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TstInfo {
    pub version: i32,
    pub policy: ObjectIdentifier,
    pub message_imprint: MessageImprint,
    pub serial_number: SerialNumber,
    pub gen_time: GeneralizedTime,
    #[asn1(optional = "true")]
    pub accuracy: Option<Accuracy>,
    #[asn1(optional = "true")]
    pub ordering: Option<bool>,
    #[asn1(optional = "true")]
    pub nonce: Option<Int>,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub tsa: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    pub extensions: Option<x509_cert::ext::Extensions>,
}

/// `PKIStatusInfo`, RFC 3161 section 2.4.2 (from RFC 2510).
///
/// `statusString` and `failInfo` are decoded but not interpreted: only the
/// status itself decides whether the enclosed token may be looked at.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct PkiStatusInfo {
    pub status: i32,
    #[asn1(optional = "true")]
    pub status_string: Option<Any>,
    #[asn1(optional = "true")]
    pub fail_info: Option<der::asn1::BitString>,
}

/// `TimeStampResp`, RFC 3161 section 2.4.2: the whole response a TSA returns,
/// of which the token is one field.
///
/// XAdES asks for the bare `TimeStampToken`, but producers of the 1.2.2 era
/// embedded the entire response in `xades:EncapsulatedTimeStamp`, and those
/// dossiers still have to verify.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
pub struct TimeStampResp {
    pub status: PkiStatusInfo,
    #[asn1(optional = "true")]
    pub time_stamp_token: Option<ContentInfo>,
}

/// `PKIStatus` values that mean a token was issued (RFC 3161 section 2.4.2).
pub(super) const PKI_STATUS_GRANTED: i32 = 0;
pub(super) const PKI_STATUS_GRANTED_WITH_MODS: i32 = 1;

/// The `ContentInfo` inside an `xades:EncapsulatedTimeStamp`.
///
/// XAdES prescribes a bare RFC 3161 `TimeStampToken`, which is a CMS
/// `ContentInfo`. Older producers embedded the whole `TimeStampResp` instead,
/// so that shape is accepted too — but only after its `PKIStatus` says a token
/// was actually issued: a response that reports a rejection carries no
/// timestamp to believe, and reading its token field anyway would turn a
/// refusal into a verification.
/// Every certificate carried inside one RFC 3161 token, as DER.
///
/// A caller that needs to know *which* certificates a dossier's revocation
/// answers would have to cover has to look inside the tokens too: a TSA's own
/// leaf certificate usually travels nowhere else. Nothing here is trusted or
/// even validated — these are candidates, exactly as they are everywhere else.
pub fn token_certificates(der: &[u8]) -> Vec<Vec<u8>> {
    if der.len() > MAX_TOKEN_BYTES {
        return Vec::new();
    }
    let Ok(content) = content_info(der) else {
        return Vec::new();
    };
    let signed_data = content
        .content
        .to_der()
        .ok()
        .and_then(|der| SignedData::from_der(&der).ok());
    let Some(signed_data) = signed_data else {
        return Vec::new();
    };
    let Some(set) = signed_data.certificates else {
        return Vec::new();
    };
    set.0
        .iter()
        .filter_map(|choice| match choice {
            CertificateChoices::Certificate(certificate) => certificate.to_der().ok(),
            CertificateChoices::Other(_) => None,
        })
        .collect()
}

pub(super) fn content_info(der: &[u8]) -> Result<ContentInfo, String> {
    if let Ok(content) = ContentInfo::from_der(der) {
        return Ok(content);
    }
    let Ok(response) = TimeStampResp::from_der(der) else {
        return Err(format!(
            "the timestamp is neither a CMS ContentInfo nor an RFC 3161 TimeStampResp; its outermost DER tag is {}",
            outer_tag(der)
        ));
    };
    match response.status.status {
        PKI_STATUS_GRANTED | PKI_STATUS_GRANTED_WITH_MODS => {}
        status => {
            return Err(format!(
                "the RFC 3161 response reports PKIStatus {status}, which is neither granted nor grantedWithMods"
            ));
        }
    }
    response
        .time_stamp_token
        .ok_or_else(|| "the RFC 3161 response carries no timestamp token".to_owned())
}

/// The outermost DER tag, named where this build knows the name. The tag of
/// attacker-supplied bytes is public information and is the one thing that
/// makes "this did not parse" actionable.
pub(super) fn outer_tag(der: &[u8]) -> String {
    let Some(byte) = der.first() else {
        return "absent (the input is empty)".to_owned();
    };
    let name = match byte {
        0x02 => " (INTEGER)",
        0x03 => " (BIT STRING)",
        0x04 => " (OCTET STRING)",
        0x05 => " (NULL)",
        0x06 => " (OBJECT IDENTIFIER)",
        0x0c => " (UTF8String)",
        0x30 => " (SEQUENCE)",
        0x31 => " (SET)",
        _ => "",
    };
    format!("0x{byte:02x}{name}")
}

pub(super) fn accuracy_seconds(accuracy: &Accuracy) -> u64 {
    let seconds = u64::try_from(accuracy.seconds.unwrap_or(0)).unwrap_or(0);
    let millis = u64::try_from(accuracy.millis.unwrap_or(0)).unwrap_or(0);
    let micros = u64::try_from(accuracy.micros.unwrap_or(0)).unwrap_or(0);
    // Sub-second accuracy still widens the window by up to a second once the
    // comparison is made in whole seconds, so it is rounded up.
    seconds + u64::from(millis > 0 || micros > 0)
}

pub(super) fn single_signer(signed_data: &SignedData) -> Option<&SignerInfo> {
    let mut signers = signed_data.signer_infos.0.iter();
    let first = signers.next()?;
    signers.next().is_none().then_some(first)
}

/// The certificate the `SignerInfo` names, by issuer and serial or by subject
/// key identifier. Nothing is guessed: a token whose `sid` matches nothing in
/// its own certificate set is rejected rather than verified against whatever
/// certificate happens to be present.
pub(super) fn find_signer_certificate<'a>(
    signer: &SignerInfo,
    certificates: &'a [ParsedCertificate],
) -> Option<&'a ParsedCertificate> {
    match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(identifier) => {
            let issuer = identifier.issuer.to_der().ok()?;
            certificates.iter().find(|candidate| {
                candidate.issuer_der() == issuer
                    && candidate
                        .certificate
                        .tbs_certificate
                        .serial_number
                        .as_bytes()
                        == identifier.serial_number.as_bytes()
            })
        }
        SignerIdentifier::SubjectKeyIdentifier(identifier) => {
            let wanted = identifier.0.as_bytes();
            certificates
                .iter()
                .find(|candidate| subject_key_identifier(candidate).as_deref() == Some(wanted))
        }
    }
}

pub(super) fn subject_key_identifier(certificate: &ParsedCertificate) -> Option<Vec<u8>> {
    let extensions = certificate
        .certificate
        .tbs_certificate
        .extensions
        .as_ref()?;
    let extension = extensions
        .iter()
        .find(|extension| extension.extn_id == OID_SUBJECT_KEY_IDENTIFIER)?;
    OctetString::from_der(extension.extn_value.as_bytes())
        .ok()
        .map(|value| value.as_bytes().to_vec())
}

/// RFC 5652 section 5.4 and RFC 3161 section 2.4.2, in order: the signed
/// attributes must exist, must name the encapsulated content type, must carry
/// a message digest equal to the digest of the eContent, and the signature
/// must verify over the DER `SET OF` encoding of those attributes.
pub(super) fn verify_signer_info(
    signer: &SignerInfo,
    certificate: &ParsedCertificate,
    econtent: &[u8],
    allow_legacy_algorithms: bool,
) -> Result<(), String> {
    let Some(attributes) = signer.signed_attrs.as_ref() else {
        return Err("the SignerInfo carries no signed attributes".to_owned());
    };
    let Some(digest_algorithm) = digest_of_oid(&signer.digest_alg.oid, allow_legacy_algorithms)
    else {
        return Err(
            "the SignerInfo names a digest algorithm outside the pinned allowlist".to_owned(),
        );
    };

    let content_type = attribute_value(attributes, OID_CONTENT_TYPE)
        .and_then(|value| value.decode_as::<ObjectIdentifier>().ok());
    match content_type {
        Some(oid) if oid == OID_CT_TST_INFO => {}
        Some(_) => return Err("the signed content-type attribute is not id-ct-TSTInfo".to_owned()),
        None => return Err("the signed attributes carry no usable content-type".to_owned()),
    }

    let message_digest = attribute_value(attributes, OID_MESSAGE_DIGEST)
        .and_then(|value| value.decode_as::<OctetString>().ok());
    let Some(message_digest) = message_digest else {
        return Err("the signed attributes carry no usable message-digest".to_owned());
    };
    if message_digest.as_bytes() != digest(digest_algorithm, econtent) {
        return Err("the signed message-digest attribute does not match the eContent".to_owned());
    }

    let scheme =
        signature_scheme(&signer.signature_algorithm.oid, digest_algorithm).ok_or_else(|| {
            "the SignerInfo signature algorithm is outside the pinned allowlist".to_owned()
        })?;
    // RFC 5652: the signature is computed over the DER encoding of the signed
    // attributes with the `SET OF` tag, not over the `[0] IMPLICIT` form that
    // appears in the message.
    let message = attributes
        .to_der()
        .map_err(|_| "the signed attributes could not be re-encoded".to_owned())?;
    verify_with_spki(
        &certificate.certificate,
        scheme,
        &message,
        signer.signature.as_bytes(),
        true,
    )
    .map_err(|_| "the signature over the signed attributes did not verify".to_owned())
}

pub(super) fn attribute_value(attributes: &Attributes, oid: ObjectIdentifier) -> Option<&Any> {
    attributes
        .iter()
        .find(|attribute| attribute.oid == oid)
        .and_then(|attribute| attribute.values.iter().next())
}

pub(super) fn signature_scheme(oid: &ObjectIdentifier, digest: Digest) -> Option<SignatureScheme> {
    Some(match *oid {
        // A bare `rsaEncryption` means "PKCS#1 v1.5 with the digest the
        // SignerInfo already named", which is what most TSAs emit.
        OID_RSA_ENCRYPTION => SignatureScheme::RsaPkcs1(digest),
        OID_SHA256_RSA => SignatureScheme::RsaPkcs1(Digest::Sha256),
        OID_SHA384_RSA => SignatureScheme::RsaPkcs1(Digest::Sha384),
        OID_SHA512_RSA => SignatureScheme::RsaPkcs1(Digest::Sha512),
        OID_ECDSA_SHA256 => SignatureScheme::Ecdsa(Digest::Sha256),
        OID_ECDSA_SHA384 => SignatureScheme::Ecdsa(Digest::Sha384),
        _ => return None,
    })
}

pub(super) fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
