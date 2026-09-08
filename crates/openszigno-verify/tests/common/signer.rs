//! XMLDSig/XAdES signing of synthetic dossiers.
//!
//! Signing lives here and nowhere else. Creating or signing a dossier is a
//! permanent non-goal of the shipped tool; this helper exists only so that the
//! verifier can be tested against material it did not itself produce the
//! verification logic for, and it must never move into a shipped crate.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use der::Decode as _;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use super::dossier::*;
use super::pki::{SigningKey, TestKey};
use super::timestamps::build_timestamp_token;

/// A correctly signed document-level signature over a synthetic dossier.
pub fn document_signature(certificates: Vec<Vec<u8>>) -> SigSpec {
    SigSpec {
        id: "sig-doc".to_owned(),
        tag: "doc".to_owned(),
        c14n: C14N_EXC.to_owned(),
        signature_method: RSA_SHA256_URI.to_owned(),
        references: vec![
            RefSpec::to("#obj0"),
            RefSpec::to("#prof0"),
            RefSpec::to("#sigobj-doc"),
            RefSpec::signed_properties("#sp-doc"),
        ],
        certificates,
        include_key_info: true,
        include_xades: true,
        include_signature_profile: true,
        xades_namespace: XADES_NS.to_owned(),
        objects_reversed: false,
        certificate_values: Vec::new(),
        signing_certificate: None,
        signature_policy_implied: false,
        timestamp: None,
        archive_timestamp: false,
        extra_unsigned_property: None,
        revocation_crls: Vec::new(),
        revocation_ocsp: Vec::new(),
        revocation_in_validation_data: false,
        validation_data_certificates: Vec::new(),
        signature_value_id: None,
        signature_profile_type: "signature".to_owned(),
        countersignatures: Vec::new(),
    }
}

/// A correctly placed frame (dossier-level) signature.
pub fn dossier_signature(certificates: Vec<Vec<u8>>) -> SigSpec {
    SigSpec {
        id: "sig-frame".to_owned(),
        tag: "frame".to_owned(),
        c14n: C14N_EXC.to_owned(),
        signature_method: RSA_SHA256_URI.to_owned(),
        references: vec![
            RefSpec::to("#documents"),
            RefSpec::to("#dossier-profile"),
            RefSpec::to("#sigobj-frame"),
            RefSpec::signed_properties("#sp-frame"),
        ],
        certificates,
        include_key_info: true,
        include_xades: true,
        include_signature_profile: true,
        xades_namespace: XADES_NS.to_owned(),
        objects_reversed: false,
        certificate_values: Vec::new(),
        signing_certificate: None,
        signature_policy_implied: false,
        timestamp: None,
        archive_timestamp: false,
        extra_unsigned_property: None,
        revocation_crls: Vec::new(),
        revocation_ocsp: Vec::new(),
        revocation_in_validation_data: false,
        validation_data_certificates: Vec::new(),
        signature_value_id: None,
        signature_profile_type: "signature".to_owned(),
        countersignatures: Vec::new(),
    }
}

/// An enveloped XAdES countersignature over the `ds:SignatureValue` whose `Id`
/// is `parent_value_id`, for placement in that signature's
/// `xades:UnsignedSignatureProperties`.
pub fn countersignature(tag: &str, certificates: Vec<Vec<u8>>, parent_value_id: &str) -> SigSpec {
    SigSpec {
        id: format!("sig-{tag}"),
        tag: tag.to_owned(),
        references: vec![
            RefSpec::countersigned(&format!("#{parent_value_id}")),
            RefSpec::to(&format!("#sigobj-{tag}")),
            RefSpec::signed_properties(&format!("#sp-{tag}")),
        ],
        ..document_signature(certificates)
    }
}

/// Render the dossier with digest and signature placeholders, then fill them
/// in one signature at a time, innermost first.
///
/// The order matters: a frame signature covers `es:Documents`, which contains
/// the document signature's `ds:SignatureValue`. Filling that value after
/// digesting the frame's references would silently invalidate the frame
/// signature, exactly as it would in a real countersigned dossier.
pub fn build(spec: &DossierSpec, keys: &[(&str, &TestKey)]) -> String {
    let mut xml = render(spec);
    for signature in signatures(spec) {
        let tag = signature.tag.as_str();
        for (index, reference) in signature.references.iter().enumerate() {
            // A reference that resolves to nothing gets a syntactically valid
            // placeholder: the verifier must reject it long before any digest
            // is recomputed.
            let value = reference_digest(&xml, signature, reference)
                .unwrap_or_else(|| "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_owned());
            xml = xml.replace(&format!("@@DIGEST-{tag}-{index}@@"), &value);
        }
        let value = keys
            .iter()
            .find(|(name, _)| *name == tag)
            .map(|(_, key)| sign_signed_info(&xml, signature, key))
            .unwrap_or_default();
        xml = xml.replace(&format!("@@SIGNATURE-{tag}@@"), &value);
        // The token is built last, because a signature timestamp covers the
        // canonicalized `ds:SignatureValue` element, which only exists once the
        // signature value has been filled in.
        if let Some(timestamp) = &signature.timestamp {
            let imprint = canonical_signature_value(&xml, signature);
            let token = match &timestamp.raw_token {
                Some(bytes) => bytes.clone(),
                None => build_timestamp_token(timestamp, &imprint),
            };
            xml = xml.replace(&format!("@@TIMESTAMP-{tag}@@"), &BASE64.encode(&token));
        }
    }
    // Container timestamps come last: a dossier-level one covers `es:Documents`,
    // which holds every document signature's `ds:SignatureValue`. Within them,
    // the inner ones are filled first for the same reason — a dossier
    // timestamp covers the `es:Document` a document timestamp sits in.
    let mut order: Vec<usize> = (0..spec.container_timestamps.len()).collect();
    order.sort_by_key(|index| {
        matches!(
            spec.container_timestamps[*index].placement,
            TimestampPlacement::Dossier
        )
    });
    for index in order {
        let timestamp = &spec.container_timestamps[index];
        let Some(token) = &timestamp.token else {
            continue;
        };
        let mut imprint = canonical_includes(&xml, timestamp);
        if timestamp.wrong_imprint {
            imprint.push(b'!');
        }
        let der = match &token.raw_token {
            Some(bytes) => bytes.clone(),
            None => build_timestamp_token(token, &imprint),
        };
        xml = xml.replace(&format!("@@CONTAINER-TS-{index}@@"), &BASE64.encode(&der));
    }
    xml
}

/// The octets a `xades:SignatureTimeStamp` covers: the canonicalized
/// `ds:SignatureValue` element, start tag to end tag.
pub fn canonical_signature_value(xml: &str, spec: &SigSpec) -> Vec<u8> {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signature_node = tree
        .descendants()
        .find(|node| node.attribute("Id") == Some(spec.id.as_str()))
        .expect("the signature element exists");
    let value = signature_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignatureValue")
        .expect("ds:SignatureValue exists");
    let algorithm = spec
        .timestamp
        .as_ref()
        .and_then(|timestamp| timestamp.c14n.as_deref())
        .and_then(C14nAlgorithm::from_uri)
        .unwrap_or(C14nAlgorithm::Inclusive { comments: false });
    RoxmltreeC14n
        .canonicalize(source.text(), &NodeSet::subtree(value), algorithm, &[])
        .expect("canonicalizes")
}

/// The `xades:SigningCertificate` or `SigningCertificateV2` property.
fn render_signing_certificate(spec: &SigningCertificateSpec) -> String {
    use der::Encode as _;

    let mut digest = match spec.digest_uri.as_str() {
        SHA1_URI => sha1::Sha1::digest(&spec.certificate).to_vec(),
        SHA512_URI => Sha512::digest(&spec.certificate).to_vec(),
        _ => Sha256::digest(&spec.certificate).to_vec(),
    };
    if spec.wrong_digest {
        digest[0] ^= 0xff;
    }
    let certificate =
        x509_cert::Certificate::from_der(&spec.certificate).expect("the certificate parses");
    let mut serial = serial_decimal(certificate.tbs_certificate.serial_number.as_bytes());
    if spec.wrong_issuer_serial {
        serial.push('7');
    }

    let issuer_serial = if !spec.issuer_serial {
        String::new()
    } else if spec.v2 {
        let issuer = if spec.wrong_issuer_serial {
            x509_cert::name::Name::default()
        } else {
            certificate.tbs_certificate.issuer.clone()
        };
        let value = IssuerSerialV2 {
            issuer: vec![x509_cert::ext::pkix::name::GeneralName::DirectoryName(
                issuer,
            )],
            serial_number: certificate.tbs_certificate.serial_number.clone(),
        };
        format!(
            "<xades:IssuerSerialV2>{}</xades:IssuerSerialV2>",
            BASE64.encode(value.to_der().expect("IssuerSerial encodes"))
        )
    } else {
        format!(
            "<xades:IssuerSerial>\
<ds:X509IssuerName>CN=openSzigno Test Root,O=openSzigno synthetic test PKI,C=HU</ds:X509IssuerName>\
<ds:X509SerialNumber>{serial}</ds:X509SerialNumber>\
</xades:IssuerSerial>"
        )
    };
    let element = if spec.v2 {
        "SigningCertificateV2"
    } else {
        "SigningCertificate"
    };
    format!(
        "<xades:{element}><xades:Cert><xades:CertDigest>\
<ds:DigestMethod Algorithm=\"{}\"/><ds:DigestValue>{}</ds:DigestValue>\
</xades:CertDigest>{issuer_serial}</xades:Cert></xades:{element}>",
        spec.digest_uri,
        BASE64.encode(&digest)
    )
}

/// `IssuerSerial`, as `IssuerSerialV2` carries it.
#[derive(der::Sequence)]
struct IssuerSerialV2 {
    issuer: Vec<x509_cert::ext::pkix::name::GeneralName>,
    serial_number: x509_cert::serial_number::SerialNumber,
}

/// A certificate serial number as the decimal string XMLDSig writes.
fn serial_decimal(bytes: &[u8]) -> String {
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
    digits
        .into_iter()
        .map(|digit| char::from(b'0' + digit))
        .collect()
}

pub(super) fn render_signature(spec: &SigSpec, namespace: &str) -> String {
    let tag = spec.tag.as_str();
    let mut out = String::new();
    out.push_str(&format!("<ds:Signature Id=\"{}\">", spec.id));
    out.push_str("<ds:SignedInfo>");
    out.push_str(&format!(
        "<ds:CanonicalizationMethod Algorithm=\"{}\"/>",
        spec.c14n
    ));
    out.push_str(&format!(
        "<ds:SignatureMethod Algorithm=\"{}\"/>",
        spec.signature_method
    ));
    for (index, reference) in spec.references.iter().enumerate() {
        let reference_type = reference
            .reference_type
            .as_ref()
            .map(|value| format!(" Type=\"{value}\""))
            .unwrap_or_default();
        out.push_str(&format!(
            "<ds:Reference URI=\"{}\"{reference_type}>",
            reference.uri
        ));
        if !reference.transforms.is_empty() {
            out.push_str("<ds:Transforms>");
            for transform in &reference.transforms {
                out.push_str(&format!("<ds:Transform Algorithm=\"{transform}\"/>"));
            }
            out.push_str("</ds:Transforms>");
        }
        out.push_str(&format!(
            "<ds:DigestMethod Algorithm=\"{}\"/><ds:DigestValue>@@DIGEST-{tag}-{index}@@</ds:DigestValue></ds:Reference>",
            reference.digest_uri
        ));
    }
    out.push_str("</ds:SignedInfo>");
    let signature_value_id = spec
        .signature_value_id
        .as_ref()
        .map(|id| format!(" Id=\"{id}\""))
        .unwrap_or_default();
    out.push_str(&format!(
        "<ds:SignatureValue{signature_value_id}>@@SIGNATURE-{tag}@@</ds:SignatureValue>"
    ));
    if spec.include_key_info {
        out.push_str("<ds:KeyInfo><ds:X509Data>");
        for certificate in &spec.certificates {
            out.push_str(&format!(
                "<ds:X509Certificate>{}</ds:X509Certificate>",
                BASE64.encode(certificate)
            ));
        }
        out.push_str("</ds:X509Data></ds:KeyInfo>");
    }
    let profile_object = if spec.include_signature_profile {
        format!(
            "<ds:Object Id=\"sigobj-{tag}\">\
<es:SignatureProfile xmlns:es=\"{namespace}\" Id=\"sigprof-{tag}\">\
<es:SignerName>Synthetic Signer</es:SignerName>\
<es:Type>{}</es:Type>\
<es:Generator>openSzigno test helper</es:Generator>\
</es:SignatureProfile></ds:Object>",
            spec.signature_profile_type
        )
    } else {
        String::new()
    };
    // Everything under `xades:UnsignedProperties` lives outside the signed
    // properties, so adding any of it never changes a digest.
    let mut unsigned = String::new();
    if !spec.certificate_values.is_empty() {
        unsigned.push_str("<xades:CertificateValues>");
        for certificate in &spec.certificate_values {
            unsigned.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                BASE64.encode(certificate)
            ));
        }
        unsigned.push_str("</xades:CertificateValues>");
    }
    if let Some(timestamp) = &spec.timestamp {
        unsigned.push_str("<xades:SignatureTimeStamp>");
        if let Some(c14n) = &timestamp.c14n {
            unsigned.push_str(&format!(
                "<ds:CanonicalizationMethod Algorithm=\"{c14n}\"/>"
            ));
        }
        if timestamp.reference_info {
            unsigned.push_str("<xades:ReferenceInfo URI=\"#obj0\"/>");
        }
        for uri in &timestamp.includes {
            unsigned.push_str(&format!(
                "<xades:Include URI=\"{uri}\" referencedData=\"true\"/>"
            ));
        }
        if timestamp.undecodable_token {
            unsigned.push_str(
                "<xades:EncapsulatedTimeStamp>not base64!!</xades:EncapsulatedTimeStamp>",
            );
        } else {
            unsigned.push_str(&format!(
                "<xades:EncapsulatedTimeStamp>@@TIMESTAMP-{tag}@@</xades:EncapsulatedTimeStamp>"
            ));
            if timestamp.duplicate_token {
                unsigned.push_str(&format!(
                    "<xades:EncapsulatedTimeStamp>@@TIMESTAMP-{tag}@@</xades:EncapsulatedTimeStamp>"
                ));
            }
        }
        unsigned.push_str("</xades:SignatureTimeStamp>");
    }
    if spec.archive_timestamp {
        unsigned.push_str(
            "<xades:ArchiveTimeStamp><xades:EncapsulatedTimeStamp>AA==</xades:EncapsulatedTimeStamp></xades:ArchiveTimeStamp>",
        );
    }
    let validation_data = spec.revocation_in_validation_data;
    if validation_data {
        // XAdES 1.4.1 keeps this in its own namespace while the values inside
        // stay in the 1.3.2 one, which is exactly the mix real dossiers use and
        // the reason the harvester matches the inner elements by name alone.
        unsigned.push_str(&format!(
            "<xades141:TimeStampValidationData xmlns:xades141=\"{XADES_NS_141}\">"
        ));
        if !spec.validation_data_certificates.is_empty() {
            unsigned.push_str("<xades:CertificateValues>");
            for certificate in &spec.validation_data_certificates {
                unsigned.push_str(&format!(
                    "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                    BASE64.encode(certificate)
                ));
            }
            unsigned.push_str("</xades:CertificateValues>");
        }
    }
    if !spec.revocation_crls.is_empty() || !spec.revocation_ocsp.is_empty() {
        unsigned.push_str("<xades:RevocationValues>");
        if !spec.revocation_crls.is_empty() {
            unsigned.push_str("<xades:CRLValues>");
            for crl in &spec.revocation_crls {
                unsigned.push_str(&format!(
                    "<xades:EncapsulatedCRLValue>{}</xades:EncapsulatedCRLValue>",
                    BASE64.encode(crl)
                ));
            }
            unsigned.push_str("</xades:CRLValues>");
        }
        if !spec.revocation_ocsp.is_empty() {
            unsigned.push_str("<xades:OCSPValues>");
            for response in &spec.revocation_ocsp {
                unsigned.push_str(&format!(
                    "<xades:EncapsulatedOCSPValue>{}</xades:EncapsulatedOCSPValue>",
                    BASE64.encode(response)
                ));
            }
            unsigned.push_str("</xades:OCSPValues>");
        }
        unsigned.push_str("</xades:RevocationValues>");
    }
    if validation_data {
        unsigned.push_str("</xades141:TimeStampValidationData>");
    }
    if let Some(name) = &spec.extra_unsigned_property {
        unsigned.push_str(&format!("<xades:{name}/>"));
    }
    // Enveloped countersignatures. Everything here is unsigned qualifying
    // material, so nesting one changes no digest of the signature it is
    // nested in.
    for element in &spec.countersignatures {
        let wrapper = element
            .wrapper
            .as_deref()
            .unwrap_or("xades:CounterSignature");
        unsigned.push_str(&format!("<{wrapper}>"));
        for nested in &element.signatures {
            unsigned.push_str(&render_signature(nested, namespace));
        }
        unsigned.push_str(&format!("</{wrapper}>"));
    }
    let unsigned = if unsigned.is_empty() {
        String::new()
    } else {
        format!(
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties>{unsigned}</xades:UnsignedSignatureProperties></xades:UnsignedProperties>"
        )
    };

    let mut signed_properties =
        String::from("<xades:SigningTime>2020-01-01T00:00:00Z</xades:SigningTime>");
    if let Some(certificate) = &spec.signing_certificate {
        signed_properties.push_str(&render_signing_certificate(certificate));
    }
    if spec.signature_policy_implied {
        signed_properties.push_str(
            "<xades:SignaturePolicyIdentifier><xades:SignaturePolicyImplied/></xades:SignaturePolicyIdentifier>",
        );
    }

    let xades_object = if spec.include_xades {
        format!(
            "<ds:Object><xades:QualifyingProperties xmlns:xades=\"{}\" Target=\"#{}\">\
<xades:SignedProperties Id=\"sp-{tag}\"><xades:SignedSignatureProperties>\
{signed_properties}\
</xades:SignedSignatureProperties></xades:SignedProperties>{unsigned}\
</xades:QualifyingProperties></ds:Object>",
            spec.xades_namespace, spec.id
        )
    } else {
        String::new()
    };
    if spec.objects_reversed {
        out.push_str(&xades_object);
        out.push_str(&profile_object);
    } else {
        out.push_str(&profile_object);
        out.push_str(&xades_object);
    }
    out.push_str("</ds:Signature>");
    out
}

/// Compute one reference digest over the current document text.
fn reference_digest(xml: &str, signature: &SigSpec, reference: &RefSpec) -> Option<String> {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signature_node = tree
        .descendants()
        .find(|node| node.attribute("Id") == Some(signature.id.as_str()))
        .expect("the signature element exists");
    let apex = if reference.uri.is_empty() {
        tree.root()
    } else {
        let id = reference.uri.trim_start_matches('#');
        tree.descendants()
            .find(|node| node.attribute("Id") == Some(id))?
    };
    // A same-document reference dereferences to a comment-free node set
    // (XMLDSig 4.4.3.3), so the signer must drop comments too.
    let mut set = if apex.is_root() {
        NodeSet::document(apex)
    } else {
        NodeSet::subtree(apex)
    }
    .without_comments();

    let mut algorithm = C14nAlgorithm::Inclusive { comments: false };
    for transform in &reference.transforms {
        if transform == ENVELOPED_URI {
            set.exclude(signature_node);
        } else if let Some(selected) = C14nAlgorithm::from_uri(transform) {
            algorithm = selected;
        }
    }
    let octets = RoxmltreeC14n
        .canonicalize(source.text(), &set, algorithm, &[])
        .expect("canonicalizes");
    Some(BASE64.encode(digest(&reference.digest_uri, &octets)))
}

fn digest(uri: &str, octets: &[u8]) -> Vec<u8> {
    match uri {
        SHA1_URI => sha1::Sha1::digest(octets).to_vec(),
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => Sha384::digest(octets).to_vec(),
        "http://www.w3.org/2001/04/xmlenc#sha512" => Sha512::digest(octets).to_vec(),
        // An unrecognised URI gets a SHA-256 value: such a fixture only needs a
        // syntactically valid digest, because the policy refuses the algorithm
        // before anything is recomputed.
        _ => Sha256::digest(octets).to_vec(),
    }
}

fn sign_signed_info(xml: &str, spec: &SigSpec, key: &TestKey) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signature_node = tree
        .descendants()
        .find(|node| node.attribute("Id") == Some(spec.id.as_str()))
        .expect("the signature element exists");
    let signed_info = signature_node
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .expect("ds:SignedInfo exists");
    let algorithm =
        C14nAlgorithm::from_uri(&spec.c14n).unwrap_or(C14nAlgorithm::Inclusive { comments: false });
    let canonical = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::subtree(signed_info),
            algorithm,
            &[],
        )
        .expect("canonicalizes");

    let bytes = match &key.signing {
        SigningKey::Rsa(private) => {
            use rsa::signature::{SignatureEncoding as _, Signer as _};
            let private = (**private).clone();
            match spec.signature_method.as_str() {
                RSA_SHA1_URI => rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new(private)
                    .sign(&canonical)
                    .to_vec(),
                RSA_SHA384_URI => rsa::pkcs1v15::SigningKey::<Sha384>::new(private)
                    .sign(&canonical)
                    .to_vec(),
                RSA_SHA512_URI => rsa::pkcs1v15::SigningKey::<Sha512>::new(private)
                    .sign(&canonical)
                    .to_vec(),
                RSA_PSS_SHA256_URI => {
                    use rsa::signature::RandomizedSigner as _;
                    rsa::pss::SigningKey::<Sha256>::new(private)
                        .sign_with_rng(&mut rsa::rand_core::OsRng, &canonical)
                        .to_vec()
                }
                _ => rsa::pkcs1v15::SigningKey::<Sha256>::new(private)
                    .sign(&canonical)
                    .to_vec(),
            }
        }
        SigningKey::EcdsaP256(private) => {
            use p256::ecdsa::signature::Signer as _;
            let signature: p256::ecdsa::Signature = private.sign(&canonical);
            signature.to_bytes().to_vec()
        }
        SigningKey::EcdsaP384(private) => {
            use p384::ecdsa::signature::Signer as _;
            let signature: p384::ecdsa::Signature = private.sign(&canonical);
            signature.to_bytes().to_vec()
        }
        SigningKey::None => Vec::new(),
    };
    BASE64.encode(bytes)
}
