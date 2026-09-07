//! Stage C: the XAdES qualifying properties.
//!
//! Only the *signed* signature properties decide anything here. The one
//! property that changes an outcome is `SigningCertificate` /
//! `SigningCertificateV2`: it is covered by the signature, so it — and not
//! `ds:KeyInfo` — determines which certificate the signer claims to have used.
//! Everything else in this module is read and reported, never believed:
//! `SigningTime` is a claim until a timestamp binds it, and a signature policy
//! is reported by identifier only, because no policy document is processed.
//!
//! Every recognised XAdES namespace is accepted (1.1.1, 1.2.2, 1.3.2 and
//! 1.4.1), because legacy e-dossiers use the older ones and a verifier that
//! only understood 1.3.2 would silently skip the binding on exactly the
//! material that most needs it.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::{Decode, Encode, Sequence};
use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::serial_number::SerialNumber;

use crate::certs::ParsedCertificate;
use crate::dsig::{XADES_NAMESPACES, direct_child, direct_children, text_of};
use crate::policy::Digest;

/// `IssuerSerialV2` (EN 319 132-1): the DER encoding of the `IssuerSerial`
/// type of RFC 5035, carried Base64 inside the XML.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct IssuerSerial {
    issuer: Vec<GeneralName>,
    serial_number: SerialNumber,
}

/// One `xades:Cert` entry: a digest of a certificate, and optionally the
/// issuer and serial that certificate must also have.
#[derive(Clone, Debug)]
pub struct CertReference {
    /// The `ds:DigestMethod/@Algorithm` the entry declares.
    pub digest_uri: String,
    /// The `ds:DigestValue`, still Base64.
    pub digest_value: String,
    /// `xades:IssuerSerial/ds:X509IssuerName`, verbatim.
    pub issuer_name: Option<String>,
    /// `xades:IssuerSerial/ds:X509SerialNumber`, verbatim (a decimal integer).
    pub issuer_serial: Option<String>,
    /// `xades:IssuerSerialV2`, decoded from Base64 but not yet parsed.
    pub issuer_serial_v2: Option<Vec<u8>>,
}

/// Which form of the property was found.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningCertificateForm {
    /// `xades:SigningCertificate`, with `IssuerSerial`.
    V1,
    /// `xades:SigningCertificateV2`, with the DER-encoded `IssuerSerialV2`.
    V2,
}

/// A signature policy identifier, reported and never processed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePolicy {
    Implied,
    Explicit,
}

/// The XAdES properties of one signature, as parsed.
#[derive(Clone, Debug, Default)]
pub struct XadesProperties<'a, 'input> {
    pub qualifying_properties: Option<Node<'a, 'input>>,
    pub signed_properties: Option<Node<'a, 'input>>,
    pub signing_time: Option<String>,
    pub signing_certificate_form: Option<SigningCertificateForm>,
    pub certificate_references: Vec<CertReference>,
    pub signature_policy: Option<SignaturePolicy>,
    /// The policy identifier, sanitised, when the policy is explicit.
    pub signature_policy_id: Option<String>,
    /// `xades:SignatureTimeStamp` elements, in document order.
    pub signature_timestamps: Vec<Node<'a, 'input>>,
    /// `xades:ArchiveTimeStamp` elements, which stay out of scope.
    pub archive_timestamps: usize,
    /// Names of qualifying properties this build does not process.
    pub unprocessed_properties: Vec<String>,
}

/// The bounded number of `xades:Cert` entries considered, since the property is
/// attacker-controlled and every entry costs one digest per candidate.
const MAX_CERT_REFERENCES: usize = 16;

/// Qualifying properties this build processes, so anything else can be named as
/// unprocessed rather than silently ignored.
const PROCESSED_PROPERTIES: &[&str] = &[
    "SigningTime",
    "SigningCertificate",
    "SigningCertificateV2",
    "SignaturePolicyIdentifier",
    "SignatureTimeStamp",
    "ArchiveTimeStamp",
    "CertificateValues",
    "RevocationValues",
];

/// The largest number of encapsulated CRLs or OCSP responses read from one
/// signature's `xades:RevocationValues`. The property is attacker-controlled,
/// and each entry costs a signature verification per certificate in the path.
const MAX_REVOCATION_VALUES: usize = 64;

/// Read the qualifying properties of one `ds:Signature`.
pub fn parse<'a, 'input>(signature: Node<'a, 'input>) -> XadesProperties<'a, 'input> {
    let mut properties = XadesProperties::default();
    let Some(qualifying) = xades_descendant(signature, "QualifyingProperties") else {
        return properties;
    };
    properties.qualifying_properties = Some(qualifying);

    let signed_properties = xades_child(qualifying, "SignedProperties");
    properties.signed_properties = signed_properties;
    let signed_signature_properties =
        signed_properties.and_then(|node| xades_child(node, "SignedSignatureProperties"));

    if let Some(signed) = signed_signature_properties {
        properties.signing_time = xades_child(signed, "SigningTime")
            .and_then(|node| crate::trust::parse_rfc3339(text_of(node).trim()))
            .map(crate::trust::format_rfc3339);

        if let Some(node) = xades_child(signed, "SigningCertificate") {
            properties.signing_certificate_form = Some(SigningCertificateForm::V1);
            properties.certificate_references = cert_references(node);
        } else if let Some(node) = xades_child(signed, "SigningCertificateV2") {
            properties.signing_certificate_form = Some(SigningCertificateForm::V2);
            properties.certificate_references = cert_references(node);
        }

        if let Some(node) = xades_child(signed, "SignaturePolicyIdentifier") {
            if xades_child(node, "SignaturePolicyImplied").is_some() {
                properties.signature_policy = Some(SignaturePolicy::Implied);
            } else if let Some(policy) = xades_child(node, "SignaturePolicyId") {
                properties.signature_policy = Some(SignaturePolicy::Explicit);
                properties.signature_policy_id = xades_child(policy, "SigPolicyId")
                    .and_then(|id| xades_child(id, "Identifier"))
                    .map(|node| sanitize(&text_of(node)));
            }
        }
    }

    // The unsigned properties. Only the timestamps are processed; everything
    // else is named so that a caller can see what was left unvalidated.
    if let Some(unsigned) = xades_child(qualifying, "UnsignedProperties")
        .and_then(|node| xades_child(node, "UnsignedSignatureProperties"))
    {
        for child in unsigned.children().filter(Node::is_element) {
            match child.tag_name().name() {
                "SignatureTimeStamp" => properties.signature_timestamps.push(child),
                "ArchiveTimeStamp" => properties.archive_timestamps += 1,
                _ => {}
            }
        }
    }

    let mut unprocessed: Vec<String> = Vec::new();
    for container in ["SignedSignatureProperties", "SignedDataObjectProperties"] {
        if let Some(node) = signed_properties.and_then(|node| xades_child(node, container)) {
            collect_unprocessed(node, &mut unprocessed);
        }
    }
    if let Some(unsigned) = xades_child(qualifying, "UnsignedProperties")
        .and_then(|node| xades_child(node, "UnsignedSignatureProperties"))
    {
        collect_unprocessed(unsigned, &mut unprocessed);
    }
    unprocessed.sort();
    unprocessed.dedup();
    properties.unprocessed_properties = unprocessed;

    properties
}

/// The DER-encoded CRLs and OCSP responses a signature carries in
/// `xades:RevocationValues`.
///
/// These are **untrusted inputs**, exactly like the certificates in
/// `CertificateValues`: a signer supplies them, so each one is signature-checked
/// against the path before it is believed. Taking them at face value would let a
/// signer prove its own certificate was never revoked.
///
/// Every XAdES namespace is accepted, because dossiers in the wild use v1.1.1
/// through v1.4.1 and a CRL is a CRL in all of them.
pub fn revocation_values(signature: Node<'_, '_>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut crls = Vec::new();
    let mut ocsp = Vec::new();
    for values in signature.descendants().filter(|node| {
        node.is_element()
            && node.tag_name().name() == "RevocationValues"
            && node
                .tag_name()
                .namespace()
                .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
    }) {
        for node in values.descendants().filter(|node| node.is_element()) {
            let target = match node.tag_name().name() {
                "EncapsulatedCRLValue" => &mut crls,
                "EncapsulatedOCSPValue" => &mut ocsp,
                _ => continue,
            };
            if target.len() >= MAX_REVOCATION_VALUES {
                continue;
            }
            if let Some(der) = decode_base64(&text_of(node)) {
                target.push(der);
            }
        }
    }
    (crls, ocsp)
}

fn collect_unprocessed(container: Node<'_, '_>, into: &mut Vec<String>) {
    for child in container.children().filter(Node::is_element) {
        let name = child.tag_name().name();
        if PROCESSED_PROPERTIES.contains(&name) {
            continue;
        }
        into.push(sanitize(name));
    }
}

/// The `xades:Cert` entries of a `SigningCertificate` property.
fn cert_references(property: Node<'_, '_>) -> Vec<CertReference> {
    let mut references = Vec::new();
    for cert in xades_children(property, "Cert").take(MAX_CERT_REFERENCES) {
        let Some(digest) = xades_child(cert, "CertDigest") else {
            continue;
        };
        let digest_uri = direct_child(digest, XMLDSIG_NAMESPACE, "DigestMethod")
            .and_then(|node| node.attribute("Algorithm"))
            .unwrap_or_default()
            .to_owned();
        let digest_value = direct_child(digest, XMLDSIG_NAMESPACE, "DigestValue")
            .map(text_of)
            .unwrap_or_default();
        let issuer_serial = xades_child(cert, "IssuerSerial");
        references.push(CertReference {
            digest_uri,
            digest_value,
            issuer_name: issuer_serial
                .and_then(|node| direct_child(node, XMLDSIG_NAMESPACE, "X509IssuerName"))
                .map(|node| text_of(node).trim().to_owned()),
            issuer_serial: issuer_serial
                .and_then(|node| direct_child(node, XMLDSIG_NAMESPACE, "X509SerialNumber"))
                .map(|node| text_of(node).trim().to_owned()),
            issuer_serial_v2: xades_child(cert, "IssuerSerialV2")
                .and_then(|node| decode_base64(&text_of(node))),
        });
    }
    references
}

/// Why a `xades:Cert` entry did not match a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingFailure {
    /// No entry named a digest algorithm this build accepts.
    DigestAlgorithm,
    /// A digest matched but the accompanying issuer and serial did not.
    IssuerSerial,
    /// No offered certificate digests to any entry's `CertDigest`.
    NoMatch,
}

/// Find the certificate the signed `SigningCertificate` property designates.
///
/// Returns the index into `candidates` of the certificate whose DER digests to
/// one of the `xades:Cert` entries, using the algorithm that entry declares.
/// This is the substitution check: whatever `ds:KeyInfo` offers, the signature
/// itself says which certificate signed it.
pub fn match_certificate(
    references: &[CertReference],
    candidates: &[ParsedCertificate],
    allow_legacy_algorithms: bool,
) -> Result<usize, BindingFailure> {
    let mut usable_algorithm = false;
    let mut digest_matched_wrong_issuer = false;
    for reference in references {
        let Some(algorithm) = Digest::from_digest_uri(&reference.digest_uri)
            .filter(|digest| !digest.is_legacy() || allow_legacy_algorithms)
        else {
            continue;
        };
        usable_algorithm = true;
        let Some(expected) = decode_base64(&reference.digest_value) else {
            continue;
        };
        for (index, candidate) in candidates.iter().enumerate() {
            if digest(algorithm, &candidate.der) != expected {
                continue;
            }
            if issuer_serial_matches(reference, candidate) {
                return Ok(index);
            }
            digest_matched_wrong_issuer = true;
        }
    }
    if !usable_algorithm {
        return Err(BindingFailure::DigestAlgorithm);
    }
    if digest_matched_wrong_issuer {
        return Err(BindingFailure::IssuerSerial);
    }
    Err(BindingFailure::NoMatch)
}

fn digest(algorithm: Digest, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        Digest::Sha1 => Sha1::digest(bytes).to_vec(),
        Digest::Sha256 => Sha256::digest(bytes).to_vec(),
        Digest::Sha384 => Sha384::digest(bytes).to_vec(),
        Digest::Sha512 => Sha512::digest(bytes).to_vec(),
    }
}

/// Whether the entry's issuer and serial, if it carries any, agree with the
/// certificate.
///
/// The digest is the binding; issuer and serial are corroboration, so a form
/// this code cannot compare is not treated as a mismatch. `IssuerSerialV2` is
/// compared by DER, which is exact. The `IssuerSerial` of XAdES 1.3.2 carries
/// the issuer as an RFC 4514 string, which cannot be compared to a DER name
/// without name preparation this project does not implement, so only the
/// serial number — which is unambiguous — is compared there.
fn issuer_serial_matches(reference: &CertReference, candidate: &ParsedCertificate) -> bool {
    if let Some(der) = &reference.issuer_serial_v2 {
        let Ok(parsed) = IssuerSerial::from_der(der) else {
            return false;
        };
        if parsed.serial_number.as_bytes()
            != candidate
                .certificate
                .tbs_certificate
                .serial_number
                .as_bytes()
        {
            return false;
        }
        let issuer_der = candidate.issuer_der();
        return parsed.issuer.iter().any(|name| match name {
            GeneralName::DirectoryName(directory) => {
                directory.to_der().unwrap_or_default() == issuer_der
            }
            _ => false,
        });
    }
    match &reference.issuer_serial {
        Some(serial) => serial_decimal(candidate).is_none_or(|actual| &actual == serial),
        None => true,
    }
}

/// The certificate serial number as the unsigned decimal integer XMLDSig
/// writes into `ds:X509SerialNumber`.
fn serial_decimal(candidate: &ParsedCertificate) -> Option<String> {
    let bytes = candidate
        .certificate
        .tbs_certificate
        .serial_number
        .as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || bytes[0] & 0x80 != 0 {
        // A negative serial is not something this comparison expresses; the
        // digest has already bound the certificate, so the corroboration is
        // simply skipped.
        return None;
    }
    let mut digits: Vec<u8> = vec![0];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut().rev() {
            let value = u32::from(*digit) * 256 + carry;
            *digit = (value % 10) as u8;
            carry = value / 10;
        }
        while carry > 0 {
            digits.insert(0, (carry % 10) as u8);
            carry /= 10;
        }
    }
    while digits.len() > 1 && digits[0] == 0 {
        digits.remove(0);
    }
    Some(
        digits
            .into_iter()
            .map(|digit| char::from(b'0' + digit))
            .collect(),
    )
}

/// A `xades:` child in any recognised XAdES namespace.
pub fn xades_child<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> Option<Node<'a, 'input>> {
    xades_children(node, name).next()
}

/// Every `xades:` child of `node` with this name, in any recognised namespace.
pub fn xades_children<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children().filter(move |child| {
        child.is_element()
            && child.tag_name().name() == name
            && child
                .tag_name()
                .namespace()
                .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
    })
}

fn xades_descendant<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> Option<Node<'a, 'input>> {
    node.descendants().find(|child| {
        child.is_element()
            && child.tag_name().name() == name
            && child
                .tag_name()
                .namespace()
                .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
    })
}

/// A `ds:` child of a XAdES element, which is where the canonicalization
/// method and the digest of a `CertDigest` live.
pub fn ds_child<'a, 'input>(
    node: Node<'a, 'input>,
    name: &'static str,
) -> Option<Node<'a, 'input>> {
    direct_children(node, XMLDSIG_NAMESPACE, name).next()
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64.decode(compact.as_bytes()).ok()
}

/// Text that came from the document, bounded and stripped of control
/// characters before it is reported back.
pub(crate) fn sanitize(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(128)
        .collect()
}
