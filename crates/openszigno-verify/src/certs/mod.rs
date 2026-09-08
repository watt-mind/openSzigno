//! X.509 parsing, public-key signature verification, and RFC 5280 path
//! validation.
//!
//! There is no general-purpose certification-path-validation crate in Rust that
//! fits eIDAS signing certificates (`rustls-webpki` is Web-PKI shaped and wants
//! a DNS name), so this is hand-written on `x509-cert`. That is a liability and
//! is documented as one: the implemented subset is deliberately narrow, every
//! rule below is explicit, and anything unrecognised is refused rather than
//! ignored.
//!
//! The module is split along what each part decides: `extensions` reads a
//! certificate's extensions, `purpose` holds the `extendedKeyUsage` policy,
//! `names` implements name constraints, and `path` builds and validates a
//! certification path. What stays here is the public shape of a certificate,
//! the RFC 5280 section 6.1 path check that ties the other modules together,
//! and the public-key signature verification every one of them needs.

mod extensions;
mod names;
mod path;
mod purpose;

pub use extensions::{OID_QC_COMPLIANCE, OID_QC_SSCD};
pub use path::{PathOutcome, validate_path};
pub(crate) use path::{SignerPath, verify_signer_path};
pub use purpose::{
    OID_KP_DOCUMENT_SIGNING, OID_KP_OCSP_SIGNING, OID_KP_TIME_STAMPING, OID_MS_DOCUMENT_SIGNING,
};

use std::collections::BTreeSet;

use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::Certificate;
use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, NameConstraints};
use x509_cert::name::Name;

use crate::codes::{Check, CheckCode};
use crate::policy::{Digest as PolicyDigest, MIN_RSA_BITS, SignatureScheme};
use crate::trust::{UnixTime, format_rfc3339};

const OID_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// The public summary of a certificate.
///
/// Deliberately limited: subject and issuer common names, serial, validity,
/// key algorithm and size, and the SHA-256 fingerprint. Full distinguished
/// names, subject alternative names, and any other identifying material stay
/// out of the report, and none of these values is ever interpolated into a
/// check message.
#[derive(Clone, Debug, Serialize)]
pub struct CertificateSummary {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub key_algorithm: Option<&'static str>,
    pub key_bits: Option<u32>,
    pub sha256_fingerprint: String,
    /// Never determined in phase 1; a trusted-list snapshot is phase 3.
    pub qualified: Option<bool>,
}

/// Where a certificate offered for path building came from.
///
/// Only the trust store can supply an anchor. A certificate found in the
/// dossier is always an untrusted candidate, however it is signed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateSource {
    /// `ds:KeyInfo/ds:X509Data/ds:X509Certificate`.
    KeyInfo,
    /// `xades:CertificateValues/xades:EncapsulatedX509Certificate`, and any
    /// other encapsulated certificate under the signature's XAdES properties.
    CertificateValues,
    /// A file in the `--trust-store` directory.
    TrustStore,
    /// The `certificates` set of an RFC 3161 timestamp token.
    TimestampToken,
    /// A delegated responder certificate carried inside an OCSP response.
    OcspResponse,
    /// A service digital identity read from an ETSI TS 119 612 trusted list.
    TrustList,
}

/// What a built path is being validated *for*.
///
/// The purpose decides which critical `extendedKeyUsage` a certificate in the
/// path may carry. It never relaxes anything else: every other rule in
/// `check_path` applies identically.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathPurpose {
    /// A signing certificate for a `ds:Signature`.
    Signing,
    /// A timestamp authority certificate, which RFC 3161 requires to carry a
    /// critical `extendedKeyUsage` of exactly `id-kp-timeStamping`.
    TimeStamping,
    /// An OCSP responder certificate, validated to an anchor under the RFC
    /// 6960 section 2.2 "trusted responder" model. It must carry
    /// `id-kp-OCSPSigning`, which is the whole point of the model: a responder
    /// the relying party trusts directly, rather than one the queried
    /// certificate's own CA delegated to.
    OcspSigning,
}

/// One link of a reported chain.
#[derive(Clone, Debug, Serialize)]
pub struct ChainEntry {
    pub subject_cn: Option<String>,
    pub issuer_cn: Option<String>,
    pub serial_hex: String,
    pub not_before: String,
    pub not_after: String,
    pub is_trust_anchor: bool,
    pub source: CertificateSource,
    /// For the anchor, where the caller's trust in it came from: the
    /// `--trust-store` directory or a `--trust-list` file. `null` on every
    /// other entry.
    pub trust_anchor_origin: Option<crate::trust::TrustAnchorOrigin>,
    /// This certificate's revocation answer. `null` until stage E has run.
    pub revocation: Option<crate::revocation::CertificateRevocation>,
}

/// A parsed certificate plus the DER it came from and where it was found.
#[derive(Clone, Debug)]
pub struct ParsedCertificate {
    pub der: Vec<u8>,
    pub certificate: Certificate,
    pub source: CertificateSource,
}

impl ParsedCertificate {
    pub fn from_der(der: &[u8], source: CertificateSource) -> Option<Self> {
        Certificate::from_der(der).ok().map(|certificate| Self {
            der: der.to_vec(),
            certificate,
            source,
        })
    }

    /// Whether the certificate names itself as its own issuer.
    ///
    /// This is how the trust-store loader tells an anchor from an intermediate
    /// a caller dropped into the same directory. The self-signature itself is
    /// deliberately *not* verified: RFC 5280 does not require it of an anchor,
    /// and demanding it would reject a legitimate root that signed itself with
    /// an algorithm outside this tool's allowlist. It is only a
    /// classification, never a grant of trust: a self-signed certificate found
    /// inside a dossier is never an anchor.
    pub fn is_self_signed(&self) -> bool {
        self.subject_der() == self.issuer_der()
    }

    fn chain_entry(&self, is_trust_anchor: bool) -> ChainEntry {
        let tbs = &self.certificate.tbs_certificate;
        ChainEntry {
            subject_cn: common_name(&tbs.subject),
            issuer_cn: common_name(&tbs.issuer),
            serial_hex: hex(tbs.serial_number.as_bytes()),
            not_before: format_rfc3339(unix_time(tbs.validity.not_before)),
            not_after: format_rfc3339(unix_time(tbs.validity.not_after)),
            is_trust_anchor,
            source: self.source,
            trust_anchor_origin: None,
            revocation: None,
        }
    }

    pub fn summary(&self) -> CertificateSummary {
        let tbs = &self.certificate.tbs_certificate;
        let (algorithm, bits) = key_algorithm(&self.certificate);
        CertificateSummary {
            subject_cn: common_name(&tbs.subject),
            issuer_cn: common_name(&tbs.issuer),
            serial_hex: hex(tbs.serial_number.as_bytes()),
            not_before: format_rfc3339(unix_time(tbs.validity.not_before)),
            not_after: format_rfc3339(unix_time(tbs.validity.not_after)),
            key_algorithm: algorithm,
            key_bits: bits,
            sha256_fingerprint: hex(&Sha256::digest(&self.der)),
            qualified: None,
        }
    }

    pub(crate) fn subject_der(&self) -> Vec<u8> {
        self.certificate
            .tbs_certificate
            .subject
            .to_der()
            .unwrap_or_default()
    }

    /// The DER encoding of the issuer name, which is what "issued by" is
    /// compared on. Never a string comparison: this project implements no RFC
    /// 4518 name preparation, and a lenient comparison can only ever widen
    /// what a chain accepts.
    pub fn issuer_der(&self) -> Vec<u8> {
        self.certificate
            .tbs_certificate
            .issuer
            .to_der()
            .unwrap_or_default()
    }

    /// The DER encoding of the subject name.
    pub fn subject_name_der(&self) -> Vec<u8> {
        self.subject_der()
    }

    /// The subject as a [`name_key`], for comparison against a trusted list's
    /// `X509SubjectName` identity.
    pub fn subject_name_key(&self) -> Vec<u8> {
        name_key(&self.certificate.tbs_certificate.subject)
    }
}

/// A comparison key for a distinguished name: every attribute's OID and its
/// **value octets**, in order, with the ASN.1 string tag left out.
///
/// Everywhere else in this project a name is compared as DER, which is exact
/// and conservative. One place cannot do that, and the reason is worth
/// stating: a trusted list's `X509SubjectName` identity is an RFC 4514
/// *string*, so re-encoding it can reproduce the attribute types, their order
/// and their values, but not which of `PrintableString`, `UTF8String` or
/// `IA5String` the CA happened to choose. A byte-for-byte DER comparison would
/// therefore never match anything, which is a defect dressed up as strictness.
///
/// So the tag — an encoding choice the list cannot express — is dropped, and
/// nothing else is. There is no case folding, no whitespace collapsing, and no
/// RFC 4518 string preparation: two names that differ in a single character,
/// in the order of their attributes, or in the number of them, are still
/// different names. This is deliberately weaker than a certificate identity
/// and is used for one purpose only, deciding `qualified`, where it can never
/// grant trust.
pub fn name_key(name: &Name) -> Vec<u8> {
    let mut key = Vec::new();
    for rdn in name.0.iter() {
        key.push(b'/');
        for attribute in rdn.0.iter() {
            key.extend_from_slice(attribute.oid.as_bytes());
            key.push(b'=');
            key.extend_from_slice(attribute.value.value());
            key.push(b',');
        }
    }
    key
}

/// Read one or more certificates from a PEM or DER buffer.
///
/// A file holding several PEM blocks yields several certificates; a DER file
/// yields exactly one. **Every entry is parsed as an X.509 certificate here**,
/// so a store that loads is a store whose every byte was understood: a
/// half-loaded trust store would silently change what "trusted" means. The
/// error names the entry's ordinal, never the file, because the path may be
/// private.
pub fn certificates_from_bytes(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(bytes).ok();
    if let Some(text) = text.filter(|text| text.contains("-----BEGIN")) {
        let mut certificates = Vec::new();
        let mut rest = text;
        while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
            let tail = &rest[start..];
            let end = tail
                .find("-----END CERTIFICATE-----")
                .ok_or_else(|| "a PEM block is not terminated".to_owned())?;
            let block = &tail[..end + "-----END CERTIFICATE-----".len()];
            let ordinal = certificates.len() + 1;
            let (label, der) = pem_rfc7468::decode_vec(block.as_bytes())
                .map_err(|_| format!("PEM block {ordinal} is malformed"))?;
            if label != "CERTIFICATE" {
                return Err(format!("PEM block {ordinal} is not a certificate"));
            }
            Certificate::from_der(&der)
                .map_err(|_| format!("PEM block {ordinal} is not a valid X.509 certificate"))?;
            certificates.push(der);
            rest = &tail[end + "-----END CERTIFICATE-----".len()..];
        }
        if certificates.is_empty() {
            return Err("no certificate was found in the PEM file".to_owned());
        }
        return Ok(certificates);
    }
    Certificate::from_der(bytes)
        .map(|_| vec![bytes.to_vec()])
        .map_err(|_| "the file is neither PEM nor DER certificate data".to_owned())
}

/// The failure a malformed extension anywhere in the path produces.
pub(super) fn malformed() -> (CheckCode, String) {
    (
        CheckCode::CertMalformed,
        "a certificate in the path carries a malformed extension".to_owned(),
    )
}

/// Apply the implemented subset of RFC 5280 section 6.1 to one built path.
///
/// `path[0]` is the end-entity certificate and the last element is the trust
/// anchor. Every rule is explicit and every unimplemented case fails closed.
fn check_path(
    path: &[&ParsedCertificate],
    time: UnixTime,
    purpose: PathPurpose,
) -> Result<Vec<Check>, (CheckCode, String)> {
    for certificate in path {
        if certificate.unimplemented_critical() {
            return Err((
                CheckCode::CertUnsupportedCriticalExtension,
                "a certificate in the path marks an extension critical whose semantics this validator does not implement"
                    .to_owned(),
            ));
        }
        let validity = &certificate.certificate.tbs_certificate.validity;
        if time < unix_time(validity.not_before) {
            return Err((
                CheckCode::CertNotYetValid,
                "a certificate in the path was not yet valid at the validation time".to_owned(),
            ));
        }
        if time > unix_time(validity.not_after) {
            return Err((
                CheckCode::CertExpired,
                "a certificate in the path had expired at the validation time".to_owned(),
            ));
        }
    }

    let mut advisories: Vec<Check> = Vec::new();
    purpose::check_end_entity_key_usage(path, purpose, &mut advisories)?;
    purpose::check_ca_key_usage(path, purpose)?;

    // Every link's signature, under the algorithm allowlist.
    for window in path.windows(2) {
        verify_certificate_signature(window[0], window[1])?;
    }

    // Every non-leaf must be a CA that may sign certificates, and must respect
    // its own path-length constraint.
    for (position, certificate) in path.iter().enumerate().skip(1) {
        let basic = certificate
            .extension::<BasicConstraints>()
            .map_err(|()| malformed())?;
        match &basic {
            Some(constraints) if constraints.ca => {}
            _ => {
                return Err((
                    CheckCode::CertBasicConstraintsInvalid,
                    "an issuing certificate in the path is not marked as a CA".to_owned(),
                ));
            }
        }
        if let Some(usage) = certificate
            .extension::<KeyUsage>()
            .map_err(|()| malformed())?
            && !usage.key_cert_sign()
        {
            return Err((
                CheckCode::CertKeyUsageInvalid,
                "an issuing certificate in the path does not permit keyCertSign".to_owned(),
            ));
        }
        if let Some(limit) = basic.and_then(|constraints| constraints.path_len_constraint)
            && usize::from(limit) < position - 1
        {
            return Err((
                CheckCode::CertPathLengthExceeded,
                "a CA in the path is followed by more intermediates than its pathLenConstraint allows"
                    .to_owned(),
            ));
        }
    }

    // The signer's own key usage.
    if let Some(usage) = path[0].extension::<KeyUsage>().map_err(|()| malformed())?
        && !(usage.digital_signature() || usage.non_repudiation())
    {
        return Err((
            CheckCode::CertKeyUsageInvalid,
            "the signing certificate permits neither digitalSignature nor nonRepudiation"
                .to_owned(),
        ));
    }

    // Name constraints imposed by any CA apply to everything below it.
    for (position, certificate) in path.iter().enumerate().skip(1) {
        let Some(constraints) = certificate
            .extension::<NameConstraints>()
            .map_err(|()| malformed())?
        else {
            continue;
        };
        for subordinate in &path[..position] {
            names::check_name_constraints(subordinate, &constraints)?;
        }
    }
    Ok(advisories)
}

/// Map an X.509 `AlgorithmIdentifier` OID onto the pinned allowlist.
///
/// SHA-1 is deliberately absent: `--allow-legacy-algorithms` admits SHA-1 for
/// XMLDSig diagnosis, never for a certificate, CRL, or OCSP signature.
pub fn signature_scheme_of(oid: ObjectIdentifier) -> Option<SignatureScheme> {
    match oid {
        OID_SHA256_RSA => Some(SignatureScheme::RsaPkcs1(PolicyDigest::Sha256)),
        OID_SHA384_RSA => Some(SignatureScheme::RsaPkcs1(PolicyDigest::Sha384)),
        OID_SHA512_RSA => Some(SignatureScheme::RsaPkcs1(PolicyDigest::Sha512)),
        OID_ECDSA_SHA256 => Some(SignatureScheme::Ecdsa(PolicyDigest::Sha256)),
        OID_ECDSA_SHA384 => Some(SignatureScheme::Ecdsa(PolicyDigest::Sha384)),
        _ => None,
    }
}

/// Verify a DER-encoded structure's signature with a certificate's key, under
/// the pinned allowlist.
///
/// This is what a CRL, an OCSP response, and a trusted list all need: the same
/// rules as a certificate signature, over a different `tbs` blob.
pub fn verify_der_signature(
    certificate: &Certificate,
    algorithm: ObjectIdentifier,
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let scheme = signature_scheme_of(algorithm).ok_or(VerifyError::UnsupportedKey)?;
    verify_with_spki(certificate, scheme, message, signature, true)
}

/// Whether `issuer` actually signed `subject`, under the allowlist.
///
/// Used where a name match alone would let anyone mint an authorised-looking
/// CRL signer or OCSP responder.
pub fn verify_issued_by(subject: &ParsedCertificate, issuer: &ParsedCertificate) -> bool {
    verify_certificate_signature(subject, issuer).is_ok()
}

fn verify_certificate_signature(
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
) -> Result<(), (CheckCode, String)> {
    let Some(scheme) = signature_scheme_of(subject.certificate.signature_algorithm.oid) else {
        return Err((
            CheckCode::CertAlgorithmRejected,
            "a certificate in the path is signed with an algorithm outside the allowlist"
                .to_owned(),
        ));
    };
    let message = subject.certificate.tbs_certificate.to_der().map_err(|_| {
        (
            CheckCode::CertMalformed,
            "a certificate could not be re-encoded for signature checking".to_owned(),
        )
    })?;
    let signature = subject.certificate.signature.as_bytes().ok_or((
        CheckCode::CertMalformed,
        "a certificate signature is not a whole number of bytes".to_owned(),
    ))?;

    match verify_with_spki(&issuer.certificate, scheme, &message, signature, true) {
        Ok(()) => Ok(()),
        Err(VerifyError::WeakKey) => Err((
            CheckCode::CertAlgorithmRejected,
            "a certificate in the path uses a key below the minimum size".to_owned(),
        )),
        Err(VerifyError::UnsupportedKey) => Err((
            CheckCode::CertAlgorithmRejected,
            "a certificate in the path uses an unsupported public-key type".to_owned(),
        )),
        Err(_) => Err((
            CheckCode::CertSignatureInvalid,
            "a certificate in the path is not correctly signed by its issuer".to_owned(),
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    BadSignature,
    UnsupportedKey,
    WeakKey,
    Malformed,
}

/// Verify `signature` over `message` with the certificate's public key.
///
/// `der_ecdsa` selects the ECDSA signature encoding: X.509 certificates carry a
/// DER `SEQUENCE`, XMLDSig carries the fixed-width `r || s` concatenation.
pub fn verify_with_spki(
    certificate: &Certificate,
    scheme: SignatureScheme,
    message: &[u8],
    signature: &[u8],
    der_ecdsa: bool,
) -> Result<(), VerifyError> {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(VerifyError::Malformed)?;
    match spki.algorithm.oid {
        OID_RSA_ENCRYPTION => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::signature::Verifier;
            use rsa::traits::PublicKeyParts as _;
            let key =
                rsa::RsaPublicKey::from_pkcs1_der(key_bytes).map_err(|_| VerifyError::Malformed)?;
            if u32::try_from(key.n().bits()).unwrap_or(0) < MIN_RSA_BITS {
                return Err(VerifyError::WeakKey);
            }
            match scheme {
                SignatureScheme::RsaPkcs1(digest) => {
                    let signature = rsa::pkcs1v15::Signature::try_from(signature)
                        .map_err(|_| VerifyError::Malformed)?;
                    let verified = match digest {
                        PolicyDigest::Sha1 => rsa::pkcs1v15::VerifyingKey::<Sha1>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha384 => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key)
                            .verify(message, &signature),
                        PolicyDigest::Sha512 => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key)
                            .verify(message, &signature),
                    };
                    verified.map_err(|_| VerifyError::BadSignature)
                }
                SignatureScheme::RsaPss(digest) => {
                    let signature = rsa::pss::Signature::try_from(signature)
                        .map_err(|_| VerifyError::Malformed)?;
                    let verified =
                        match digest {
                            PolicyDigest::Sha1 => {
                                rsa::pss::VerifyingKey::<Sha1>::new(key).verify(message, &signature)
                            }
                            PolicyDigest::Sha256 => rsa::pss::VerifyingKey::<Sha256>::new(key)
                                .verify(message, &signature),
                            PolicyDigest::Sha384 => rsa::pss::VerifyingKey::<Sha384>::new(key)
                                .verify(message, &signature),
                            PolicyDigest::Sha512 => rsa::pss::VerifyingKey::<Sha512>::new(key)
                                .verify(message, &signature),
                        };
                    verified.map_err(|_| VerifyError::BadSignature)
                }
                SignatureScheme::Ecdsa(_) => Err(VerifyError::UnsupportedKey),
            }
        }
        OID_EC_PUBLIC_KEY => {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .ok_or(VerifyError::UnsupportedKey)?;
            let SignatureScheme::Ecdsa(digest) = scheme else {
                return Err(VerifyError::UnsupportedKey);
            };
            match (curve, digest) {
                (OID_PRIME256V1, PolicyDigest::Sha256) => {
                    use p256::ecdsa::signature::Verifier;
                    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| VerifyError::Malformed)?;
                    let signature = if der_ecdsa {
                        p256::ecdsa::Signature::from_der(signature)
                    } else {
                        p256::ecdsa::Signature::from_slice(signature)
                    }
                    .map_err(|_| VerifyError::Malformed)?;
                    key.verify(message, &signature)
                        .map_err(|_| VerifyError::BadSignature)
                }
                (OID_SECP384R1, PolicyDigest::Sha384) => {
                    use p384::ecdsa::signature::Verifier;
                    let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(key_bytes)
                        .map_err(|_| VerifyError::Malformed)?;
                    let signature = if der_ecdsa {
                        p384::ecdsa::Signature::from_der(signature)
                    } else {
                        p384::ecdsa::Signature::from_slice(signature)
                    }
                    .map_err(|_| VerifyError::Malformed)?;
                    key.verify(message, &signature)
                        .map_err(|_| VerifyError::BadSignature)
                }
                // A curve and digest that do not match is an algorithm
                // downgrade attempt, not a curve to guess at.
                _ => Err(VerifyError::UnsupportedKey),
            }
        }
        _ => Err(VerifyError::UnsupportedKey),
    }
}

/// The key algorithm and size a report exposes.
pub fn key_algorithm(certificate: &Certificate) -> (Option<&'static str>, Option<u32>) {
    let spki = &certificate.tbs_certificate.subject_public_key_info;
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else {
        return (None, None);
    };
    match spki.algorithm.oid {
        OID_RSA_ENCRYPTION => {
            use rsa::pkcs1::DecodeRsaPublicKey;
            use rsa::traits::PublicKeyParts as _;
            let bits = rsa::RsaPublicKey::from_pkcs1_der(key_bytes)
                .ok()
                .and_then(|key| u32::try_from(key.n().bits()).ok());
            (Some("rsa"), bits)
        }
        OID_EC_PUBLIC_KEY => {
            let bits = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok())
                .and_then(|curve| match curve {
                    OID_PRIME256V1 => Some(256),
                    OID_SECP384R1 => Some(384),
                    _ => None,
                });
            (Some("ec"), bits)
        }
        _ => (None, None),
    }
}

/// The subject or issuer common name, sanitised.
///
/// Certificate contents are attacker-controlled, so the value is limited in
/// length and stripped of anything that is not printable. It appears only in a
/// structured field, never in a message.
pub fn common_name(name: &Name) -> Option<String> {
    let mut found = None;
    for rdn in name.0.iter() {
        for attribute in rdn.0.iter() {
            if attribute.oid != OID_COMMON_NAME {
                continue;
            }
            let bytes = attribute.value.value();
            let text = std::str::from_utf8(bytes).ok()?;
            found = Some(sanitize(text));
        }
    }
    found
}

fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

pub(crate) fn unix_time(time: x509_cert::time::Time) -> UnixTime {
    time.to_unix_duration().as_secs() as i64
}

/// Certificates that appear in more than one place are deduplicated by DER, so
/// that a repeated `ds:X509Certificate` cannot inflate the path search.
pub fn dedup(certificates: Vec<ParsedCertificate>) -> Vec<ParsedCertificate> {
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    certificates
        .into_iter()
        .filter(|certificate| seen.insert(certificate.der.clone()))
        .collect()
}
