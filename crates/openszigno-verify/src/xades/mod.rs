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

mod claims;
mod validation_data;

pub use claims::SignaturePolicyDigest;
pub use validation_data::{revocation_values, validation_data_containers};

use crate::certs::ParsedCertificate;
use crate::codes::{Check, CheckCode};
use crate::dsig::{XADES_NAMESPACES, direct_child, direct_children, text_of};
use crate::policy::Digest;
use crate::references::ReferenceScope;
use crate::report::XadesReport;
use crate::scope::owning_signature;

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
    /// The explicit policy's declared digest, when it carries one.
    pub signature_policy_digest: Option<SignaturePolicyDigest>,
    /// `xades:ClaimedRole` values of `SignerRole` or `SignerRoleV2`.
    pub claimed_roles: Vec<String>,
    /// `xades:CommitmentTypeIndication/CommitmentTypeId/Identifier` values.
    pub commitment_type_ids: Vec<String>,
    /// `xades:SignatureTimeStamp` elements, in document order.
    pub signature_timestamps: Vec<Node<'a, 'input>>,
    /// `xades:ArchiveTimeStamp` elements, which stay out of scope.
    pub archive_timestamps: usize,
    /// Names of qualifying properties this build does not process.
    pub unprocessed_properties: Vec<String>,
    /// More than one `xades:QualifyingProperties` belongs to this signature.
    ///
    /// Reported once, because only the covered one is read: a `ds:Object` is
    /// open content that no reference has to cover, so an extra one says
    /// nothing and must change nothing.
    pub extra_qualifying_properties: bool,
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
    "TimeStampValidationData",
    // An enveloped countersignature is verified as a signature in its own
    // right and reported at `data.signatures[]`, so it is not an unvalidated
    // property.
    "CounterSignature",
];

/// Read the qualifying properties of one `ds:Signature`, with no information
/// about what its references cover.
///
/// Used only where no reference was ever resolved — a signature whose
/// structure did not parse — and where the signing-certificate binding is
/// therefore never evaluated. Everywhere else, [`parse_covered`] decides which
/// properties the signature is actually evaluated against.
pub fn parse<'a, 'input>(signature: Node<'a, 'input>) -> XadesProperties<'a, 'input> {
    parse_properties(signature, None)
}

/// Read the qualifying properties one `ds:Signature` is evaluated against,
/// selected by what that signature's own references cover.
///
/// `scopes` is the effective node set of each of this signature's references,
/// in reference order.
///
/// A `ds:Object` is open content: the XMLDSig schema allows any number of them
/// under a `ds:Signature` and nothing requires a reference to cover any given
/// one. Taking the *first* `xades:QualifyingProperties` under the signature
/// therefore let one inserted, unreferenced `ds:Object` decide what stage C
/// read without touching a single signed byte. So the properties this build
/// reads are the ones a reference of this signature actually digests: the
/// `xades:SignedProperties` that lies inside one reference's effective node
/// set, and the `xades:QualifyingProperties` holding it. The
/// `Type="http://uri.etsi.org/01903#SignedProperties"` attribute is
/// corroboration only — an attacker writes it — and never the rule.
///
/// When no reference covers any `SignedProperties` of this signature, none of
/// them is signed: the signed properties are treated as absent, so the
/// `SigningCertificate` binding reports
/// `xades_signing_certificate_absent` rather than believing an unsigned
/// property. The qualifying-properties element itself is still reported as
/// present, and its unsigned properties — which no reference ever covers —
/// are still read, from the covered one when there is one and from the first
/// otherwise.
pub fn parse_covered<'a, 'input>(
    signature: Node<'a, 'input>,
    scopes: &[ReferenceScope],
) -> XadesProperties<'a, 'input> {
    parse_properties(signature, Some(scopes))
}

fn parse_properties<'a, 'input>(
    signature: Node<'a, 'input>,
    scopes: Option<&[ReferenceScope]>,
) -> XadesProperties<'a, 'input> {
    let mut properties = XadesProperties::default();
    let candidates = qualifying_properties_of(signature);
    properties.extra_qualifying_properties = candidates.len() > 1;
    let covered = scopes.and_then(|scopes| covered_signed_properties(&candidates, scopes));
    let Some(qualifying) = covered
        .map(|(node, _)| node)
        .or_else(|| candidates.first().copied())
    else {
        return properties;
    };
    properties.qualifying_properties = Some(qualifying);

    let signed_properties = match (covered, scopes) {
        // The signed properties one of this signature's references digests.
        (Some((_, signed)), _) => Some(signed),
        // Nothing this signature signed says anything, so nothing here does.
        (None, Some(_)) => None,
        // No reference was resolved, so coverage is not a question that has
        // been asked yet; the binding is not evaluated on this path either.
        (None, None) => xades_child(qualifying, "SignedProperties"),
    };
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
                properties.signature_policy_digest =
                    xades_child(policy, "SigPolicyHash").map(claims::policy_digest);
            }
        }

        properties.claimed_roles = claims::claimed_roles(signed);
    }

    properties.commitment_type_ids = signed_properties
        .and_then(|node| xades_child(node, "SignedDataObjectProperties"))
        .map(claims::commitment_type_ids)
        .unwrap_or_default();

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

/// Every `xades:QualifyingProperties` that belongs to this signature, in
/// document order.
///
/// A countersignature nested in this signature's unsigned properties carries
/// qualifying properties of its own; they are that signature's, and reading
/// them here would let a nested element speak for the signature it was dropped
/// into.
fn qualifying_properties_of<'a, 'input>(signature: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    signature
        .descendants()
        .filter(|child| {
            child.is_element()
                && child.tag_name().name() == "QualifyingProperties"
                && child
                    .tag_name()
                    .namespace()
                    .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
                && owning_signature(*child) == Some(signature)
        })
        .collect()
}

/// The first `xades:QualifyingProperties` of this signature holding a
/// `xades:SignedProperties` that lies inside some reference's effective node
/// set, with that element.
fn covered_signed_properties<'a, 'input>(
    candidates: &[Node<'a, 'input>],
    scopes: &[ReferenceScope],
) -> Option<(Node<'a, 'input>, Node<'a, 'input>)> {
    candidates.iter().find_map(|qualifying| {
        xades_children(*qualifying, "SignedProperties")
            .find(|signed| scopes.iter().any(|scope| scope.covers(*signed)))
            .map(|signed| (*qualifying, signed))
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

/// The outcome of stage C, gathered before the report is assembled.
pub(crate) struct StageC {
    pub(crate) checks: Vec<Check>,
    pub(crate) report: XadesReport,
    /// The `ds:KeyInfo` candidate the signed `SigningCertificate` designates,
    /// which overrides the key-based selection when the two disagree.
    pub(crate) signer_override: Option<usize>,
}

/// The part of stage C that needs no cryptography: what the properties are,
/// and what this build did not process.
///
/// Used on its own when the signature failed an earlier stage, because the
/// signing-certificate binding cannot be evaluated against a signature whose
/// references were never resolved.
pub(crate) fn stage_c_presence(properties: &XadesProperties<'_, '_>) -> StageC {
    let mut checks = Vec::new();
    let present = properties.qualifying_properties.is_some();
    if present {
        checks.push(Check::passed(
            CheckCode::XadesPresent,
            "XAdES qualifying properties are present",
        ));
    } else {
        // Blocking, and the one XAdES `skipped` that stays so: with no
        // qualifying properties there is no *signed* statement of which
        // certificate signed, so the `SigningCertificate` binding the policy
        // requires was not performed. That is what `skipped` means.
        checks.push(Check::skipped(
            CheckCode::XadesAbsent,
            "no XAdES qualifying properties were found for this signature, so nothing signed says which certificate signed it",
        ));
    }

    // Informational, and said once. An extra `xades:QualifyingProperties` is
    // an unreferenced `ds:Object` away, and open content the schema allows
    // says nothing about the signature: the properties read are the ones a
    // reference covers, and the rest are ignored. Blocking on this would let
    // anyone who can append a `ds:Object` cap a sound signature at
    // `indeterminate`, which is the same lever this reporting exists to close.
    if properties.extra_qualifying_properties {
        checks.push(Check::info(
            CheckCode::XadesExtraQualifyingProperties,
            "more than one xades:QualifyingProperties belongs to this signature; the one its own references cover is read and the others are ignored",
        ));
    }

    // A signature policy is reported by identifier only: no policy document is
    // fetched, parsed, or applied, so neither form can contribute a `passed`.
    // Informational: a declared policy is a statement about how the signature
    // was made, not a question this build failed to answer. Blocking on it
    // would cap every policy-bearing signature at `indeterminate` for a
    // property that says nothing about whether the signature is sound.
    match properties.signature_policy {
        Some(SignaturePolicy::Implied) => checks.push(Check::info(
            CheckCode::XadesSignaturePolicyImplied,
            "the signature declares an implied signature policy; no policy is processed",
        )),
        Some(SignaturePolicy::Explicit) => checks.push(Check::info(
            CheckCode::XadesSignaturePolicyExplicit,
            "the signature declares an explicit signature policy; its identifier is reported and no policy is processed",
        )),
        None => {}
    }

    // Informational, and emitted only when there is something to name.
    //
    // Everything counted here lives under `xades:UnsignedProperties`, which is
    // not covered by the signature and cannot change what the signature says.
    // ETSI EN 319 102-1 decides validity from the signed properties, the
    // timestamps, and revocation; the remaining unsigned properties are
    // evidence containers, and the ones that carry evidence this build uses —
    // `CertificateValues`, `RevocationValues`, `TimeStampValidationData` — are
    // already consumed and are not counted here. Blocking on the rest would
    // cap a signature at `indeterminate` for carrying *more* evidence than the
    // minimum, which is precisely backwards.
    if !properties.unprocessed_properties.is_empty() {
        checks.push(Check::info(
            CheckCode::XadesNotValidated,
            format!(
                "unsigned qualifying properties this build does not validate are present and are named rather than ignored: {}",
                properties.unprocessed_properties.join(", ")
            ),
        ));
    }
    if properties.archive_timestamps > 0 {
        // Informational: an archive timestamp is additional long-term evidence
        // laid on top of a signature. Not validating it means this build makes
        // no claim about the signature's validity *beyond* the point its other
        // evidence reaches; it does not make the evidence already checked worth
        // less. LTA re-validation is M3.
        checks.push(Check::info(
            CheckCode::ArchiveTimestampPresent,
            "an xades:ArchiveTimeStamp is present and is not validated; this release makes no claim about long-term (B-LTA) re-validation",
        ));
    }

    StageC {
        checks,
        report: XadesReport {
            present,
            signing_time: properties.signing_time.clone(),
            signing_certificate: None,
            signature_policy: properties.signature_policy,
            signature_policy_id: properties.signature_policy_id.clone(),
            signature_policy_digest: properties.signature_policy_digest.clone(),
            claimed_roles: properties.claimed_roles.clone(),
            commitment_type_ids: properties.commitment_type_ids.clone(),
            signature_timestamps: properties.signature_timestamps.len(),
            archive_timestamps: properties.archive_timestamps,
            unvalidated_properties: properties.unprocessed_properties.clone(),
        },
        signer_override: None,
    }
}

/// Stage C in full: the signed `SigningCertificate` binding on top of the
/// presence reporting.
///
/// This is the substitution check. `ds:KeyInfo` is unsigned unless a reference
/// covers it, so the certificate the signature *claims* is the one the signed
/// `CertDigest` names. When the certificate whose key verified the signature is
/// not that one, the check fails: someone swapped the certificate.
pub(crate) fn stage_c_binding(
    properties: &XadesProperties<'_, '_>,
    candidates: &[ParsedCertificate],
    key_signer_index: Option<usize>,
    allow_legacy_algorithms: bool,
    signature_timestamps: usize,
) -> StageC {
    let mut stage = stage_c_presence(properties);
    let _ = signature_timestamps;
    if properties.certificate_references.is_empty() {
        stage.checks.push(Check::unknown(
            CheckCode::XadesSigningCertificateAbsent,
            "the signature carries no xades:SigningCertificate, so nothing signed says which certificate signed it",
        ));
        return stage;
    }
    let form = properties.signing_certificate_form;
    match match_certificate(
        &properties.certificate_references,
        candidates,
        allow_legacy_algorithms,
    ) {
        Ok(position) => {
            let bound = key_signer_index.is_none_or(|index| index == position);
            if bound {
                stage.checks.push(Check::passed(
                    CheckCode::XadesSigningCertificateBound,
                    "the signing certificate matches the digest the signed SigningCertificate property names",
                ));
            } else {
                stage.checks.push(Check::failed(
                    CheckCode::XadesSigningCertificateMismatch,
                    "the certificate whose key verified the signature is not the one the signed SigningCertificate property names",
                ));
            }
            stage.signer_override = Some(position);
            stage.report.signing_certificate = Some(crate::report::SigningCertificateBinding {
                form,
                digest_algorithm: properties
                    .certificate_references
                    .first()
                    .and_then(|reference| {
                        Digest::from_digest_uri(&reference.digest_uri).map(Digest::as_str)
                    }),
                issuer_serial_present: properties.certificate_references.iter().any(|reference| {
                    reference.issuer_serial.is_some() || reference.issuer_serial_v2.is_some()
                }),
                matched: true,
            });
        }
        Err(failure) => {
            let message = match failure {
                BindingFailure::DigestAlgorithm => {
                    "the SigningCertificate property names no digest algorithm inside the pinned allowlist"
                }
                BindingFailure::IssuerSerial => {
                    "a certificate digests to the SigningCertificate property but its issuer and serial do not match"
                }
                BindingFailure::NoMatch => {
                    "no offered certificate digests to the certificate the signed SigningCertificate property names"
                }
            };
            stage.checks.push(Check::failed(
                CheckCode::XadesSigningCertificateMismatch,
                message,
            ));
            stage.report.signing_certificate = Some(crate::report::SigningCertificateBinding {
                form,
                digest_algorithm: properties
                    .certificate_references
                    .first()
                    .and_then(|reference| {
                        Digest::from_digest_uri(&reference.digest_uri).map(Digest::as_str)
                    }),
                issuer_serial_present: properties.certificate_references.iter().any(|reference| {
                    reference.issuer_serial.is_some() || reference.issuer_serial_v2.is_some()
                }),
                matched: false,
            });
        }
    }
    stage
}
