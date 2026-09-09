//! The synthetic dossier: its XML namespaces and algorithm identifiers, the
//! specs that describe what a test wants a dossier to contain, and the XML
//! rendering that is common to signed and unsigned material.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};

use super::pki::TestKey;
use super::signer::render_signature;

pub const ESZIGNO_NS: &str = "https://www.microsec.hu/ds/e-szigno30#";
pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const XADES_NS_122: &str = "http://uri.etsi.org/01903/v1.2.2#";
pub const XADES_NS_141: &str = "http://uri.etsi.org/01903/v1.4.1#";
pub const SIGNED_PROPERTIES_TYPE_122: &str = "http://uri.etsi.org/01903/v1.2.2#SignedProperties";

pub const C14N_EXC: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const C14N_INC: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const RSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const RSA_SHA384_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const RSA_SHA512_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const RSA_PSS_SHA256_URI: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
pub const ECDSA_SHA384_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const SHA384_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const SHA512_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha512";
pub const RSA_SHA1_URI: &str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const HMAC_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
pub const ECDSA_SHA256_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const ENVELOPED_URI: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub const XSLT_URI: &str = "http://www.w3.org/TR/1999/REC-xslt-19991116";
pub const XPATH_URI: &str = "http://www.w3.org/TR/1999/REC-xpath-19991116";
pub const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
/// ETSI EN 319 132-1 clause 5.2.7.1 / TS 101903 clause 7.2.4.1.
pub const COUNTERSIGNED_SIGNATURE_TYPE: &str = "http://uri.etsi.org/01903#CountersignedSignature";
/// One `ds:Reference` to write into `ds:SignedInfo`.
pub struct RefSpec {
    pub uri: String,
    pub reference_type: Option<String>,
    pub transforms: Vec<String>,
    pub digest_uri: String,
}

impl RefSpec {
    pub fn to(uri: &str) -> Self {
        Self {
            uri: uri.to_owned(),
            reference_type: None,
            transforms: vec![C14N_EXC.to_owned()],
            digest_uri: SHA256_URI.to_owned(),
        }
    }

    pub fn signed_properties(uri: &str) -> Self {
        Self {
            reference_type: Some(SIGNED_PROPERTIES_TYPE.to_owned()),
            ..Self::to(uri)
        }
    }

    /// A reference over a countersigned `ds:SignatureValue`, carrying the
    /// `CountersignedSignature` `Type`. The attribute is corroboration only;
    /// what the reference resolves to is what decides.
    pub fn countersigned(uri: &str) -> Self {
        Self {
            reference_type: Some(COUNTERSIGNED_SIGNATURE_TYPE.to_owned()),
            ..Self::to(uri)
        }
    }

    /// Drop the `Type` attribute, so only resolution can decide.
    pub fn untyped(mut self) -> Self {
        self.reference_type = None;
        self
    }

    pub fn with_transforms(mut self, transforms: &[&str]) -> Self {
        self.transforms = transforms.iter().map(|value| (*value).to_owned()).collect();
        self
    }

    pub fn with_digest(mut self, uri: &str) -> Self {
        self.digest_uri = uri.to_owned();
        self
    }
}

/// How one `ds:Signature` should look.
pub struct SigSpec {
    pub id: String,
    /// The placeholder tag `build` fills this signature's digests and value
    /// under, and the suffix of its `sigobj-`/`sp-` element ids. Unique per
    /// signature in one dossier.
    pub tag: String,
    pub c14n: String,
    pub signature_method: String,
    pub references: Vec<RefSpec>,
    pub certificates: Vec<Vec<u8>>,
    pub include_key_info: bool,
    pub include_xades: bool,
    pub include_signature_profile: bool,
    /// The XAdES namespace to declare, so legacy 1.2.2 material can be built.
    pub xades_namespace: String,
    /// Emit the qualifying-properties object before the signature-profile
    /// object, which real dossiers do occasionally.
    pub objects_reversed: bool,
    /// Raw `ds:Object` elements emitted *before* this signature's own profile
    /// and qualifying-properties objects, and covered by no reference.
    ///
    /// The XMLDSig schema allows any number of `ds:Object` children with open
    /// content, so anyone who can append bytes to a dossier can add one. This
    /// is how a test inserts such a decoy: it changes no digest, so a
    /// signature built with one must produce exactly the check list it
    /// produces without it.
    pub decoy_objects: Vec<String>,
    /// Certificates to place in `xades:CertificateValues`, which is where real
    /// dossiers carry the intermediates and usually the root.
    pub certificate_values: Vec<Vec<u8>>,
    /// The signed `SigningCertificate` / `SigningCertificateV2` property.
    pub signing_certificate: Option<SigningCertificateSpec>,
    /// Emit `xades:SignaturePolicyIdentifier/xades:SignaturePolicyImplied`.
    pub signature_policy_implied: bool,
    /// A signature timestamp over this signature's `ds:SignatureValue`.
    pub timestamp: Option<TimestampSpec>,
    /// Emit an `xades:ArchiveTimeStamp`, which is out of scope and must be
    /// reported as such.
    pub archive_timestamp: bool,
    /// An unsigned property this build does not validate, by element name.
    pub extra_unsigned_property: Option<String>,
    /// DER CRLs to encapsulate in `xades:RevocationValues/xades:CRLValues`.
    pub revocation_crls: Vec<Vec<u8>>,
    /// DER OCSP responses for `xades:RevocationValues/xades:OCSPValues`.
    pub revocation_ocsp: Vec<Vec<u8>>,
    /// Wrap the `RevocationValues` (and any `validation_data_certificates`) in
    /// an `xades141:TimeStampValidationData`, in the XAdES 1.4.1 namespace,
    /// which is where real long-term Microsec dossiers put almost all of their
    /// embedded OCSP responses.
    pub revocation_in_validation_data: bool,
    /// Certificates to encapsulate inside the `TimeStampValidationData`.
    pub validation_data_certificates: Vec<Vec<u8>>,
    /// An `Id` on `ds:SignatureValue`, so an `xades:Include` or a
    /// countersignature's `ds:Reference` can name it.
    pub signature_value_id: Option<String>,
    /// The `es:SignatureProfile/es:Type` value, `signature` by default and
    /// `countersignature` for the e-dossier countersignature form
    /// (e-dossier specification clause 3.2.1.3.4.1.3).
    pub signature_profile_type: String,
    /// Enveloped countersignatures placed in this signature's
    /// `xades:UnsignedSignatureProperties`.
    pub countersignatures: Vec<CounterSignatureSpec>,
    /// The `xades:SigningTime` text, verbatim. `None` uses the harness
    /// default (`2020-01-01T00:00:00Z`); `Some` lets a test claim an
    /// arbitrary, possibly calendar-impossible or malformed, string.
    pub signing_time: Option<String>,
}

/// One `xades:CounterSignature` element and the signatures inside it.
///
/// ETSI EN 319 132-1 clause 5.2.7.2 defines `CounterSignatureType` as a
/// sequence of exactly one `ds:Signature`; holding two is the ambiguous shape
/// the verifier must refuse rather than guess at.
pub struct CounterSignatureSpec {
    pub signatures: Vec<SigSpec>,
    /// The element that holds them. `None` is `xades:CounterSignature`; any
    /// other name is a nesting the e-dossier and XAdES rules do not describe.
    pub wrapper: Option<String>,
}

impl CounterSignatureSpec {
    pub fn new(signature: SigSpec) -> Self {
        Self {
            signatures: vec![signature],
            wrapper: None,
        }
    }

    /// Two nested signatures in one `xades:CounterSignature`.
    pub fn ambiguous(first: SigSpec, second: SigSpec) -> Self {
        Self {
            signatures: vec![first, second],
            wrapper: None,
        }
    }

    /// A signature nested under something that is not an
    /// `xades:CounterSignature`.
    pub fn in_wrapper(signature: SigSpec, wrapper: &str) -> Self {
        Self {
            signatures: vec![signature],
            wrapper: Some(wrapper.to_owned()),
        }
    }
}

/// How the signed `SigningCertificate` property should look.
pub struct SigningCertificateSpec {
    /// The certificate the property designates.
    pub certificate: Vec<u8>,
    /// `true` for `SigningCertificateV2`, `false` for the 1.3.2 form.
    pub v2: bool,
    pub digest_uri: String,
    /// Corrupt the digest, so nothing matches it.
    pub wrong_digest: bool,
    /// Emit `IssuerSerial` (v1) or `IssuerSerialV2` (v2).
    pub issuer_serial: bool,
    /// Emit an issuer and serial that do not belong to the certificate.
    pub wrong_issuer_serial: bool,
}

impl SigningCertificateSpec {
    pub fn v1(certificate: Vec<u8>) -> Self {
        Self {
            certificate,
            v2: false,
            digest_uri: SHA256_URI.to_owned(),
            wrong_digest: false,
            issuer_serial: true,
            wrong_issuer_serial: false,
        }
    }

    pub fn v2(certificate: Vec<u8>) -> Self {
        Self {
            v2: true,
            ..Self::v1(certificate)
        }
    }
}

/// How the signature timestamp and its token should look.
pub struct TimestampSpec {
    /// The key the timestamp authority signs with.
    pub tsa_key: TestKey,
    /// The TSA certificate, which the token carries.
    pub tsa_der: Vec<u8>,
    /// Further certificates to place in the token, such as the issuing CA.
    pub token_certificates: Vec<Vec<u8>>,
    /// `genTime`, as an RFC 3339 timestamp.
    pub gen_time: String,
    pub accuracy_seconds: Option<i32>,
    /// Digest something other than the canonicalized `ds:SignatureValue`.
    pub wrong_imprint: bool,
    /// The `ds:CanonicalizationMethod` of the timestamp element, if any.
    pub c14n: Option<String>,
    /// Replace the token with these bytes, for the malformed cases.
    pub raw_token: Option<Vec<u8>>,
    /// `xades:Include` URIs to emit, which is the explicit data-selection
    /// form. Empty means the implicit form.
    pub includes: Vec<String>,
    /// Emit an `xades:ReferenceInfo`, a form this build does not implement.
    pub reference_info: bool,
    /// Wrap the token in an RFC 3161 `TimeStampResp` carrying this
    /// `PKIStatus`, as XAdES 1.2.2-era producers did.
    pub wrap_in_response: Option<i32>,
    /// Emit the token twice, which this build does not process.
    pub duplicate_token: bool,
    /// Emit a token that is not decodable Base64.
    pub undecodable_token: bool,
}

impl TimestampSpec {
    pub fn new(tsa_key: TestKey, tsa_der: Vec<u8>, gen_time: &str) -> Self {
        Self {
            tsa_key,
            tsa_der,
            token_certificates: Vec::new(),
            gen_time: gen_time.to_owned(),
            accuracy_seconds: Some(1),
            wrong_imprint: false,
            c14n: None,
            raw_token: None,
            includes: Vec::new(),
            reference_info: false,
            wrap_in_response: None,
            duplicate_token: false,
            undecodable_token: false,
        }
    }
}

/// Where a container `es:TimeStamp` sits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampPlacement {
    /// A direct child of `es:Dossier`.
    Dossier,
    /// A direct child of the first `es:Document`.
    Document,
    /// A child of `es:Documents`, which the format does not describe.
    Stray,
}

/// One container `es:TimeStamp`, which M3 verifies over the elements its
/// `xades:Include` children name.
pub struct ContainerTimestampSpec {
    pub placement: TimestampPlacement,
    /// The `xades:Include` URIs, in the order they are emitted, which is also
    /// the order their canonical forms are concatenated in.
    pub includes: Vec<String>,
    /// The `ds:CanonicalizationMethod` of the timestamp element, if any.
    pub c14n: Option<String>,
    /// The token, or `None` to emit an undecodable placeholder.
    pub token: Option<TimestampSpec>,
    /// Emit an `xades:ReferenceInfo`, a selection form this build refuses.
    pub reference_info: bool,
    /// Digest something other than the included elements.
    pub wrong_imprint: bool,
}

impl ContainerTimestampSpec {
    pub fn dossier(token: TimestampSpec) -> Self {
        Self {
            placement: TimestampPlacement::Dossier,
            includes: vec!["#dossier-profile".to_owned(), "#documents".to_owned()],
            c14n: None,
            token: Some(token),
            reference_info: false,
            wrong_imprint: false,
        }
    }

    pub fn document(token: TimestampSpec) -> Self {
        Self {
            placement: TimestampPlacement::Document,
            includes: vec!["#prof0".to_owned(), "#obj0".to_owned()],
            token: Some(token),
            c14n: None,
            reference_info: false,
            wrong_imprint: false,
        }
    }
}

/// A further `es:Document` inside `es:Documents`, for the coverage cases.
pub struct ExtraDocumentSpec {
    /// The `Id` of the payload `ds:Object`, which is also the profile's
    /// `OBJREF`.
    pub id: String,
    pub payload: String,
    /// Emit an `es:DocumentProfile`. Without one the core parser skips the
    /// document and reports `document_without_profile`.
    pub profile: bool,
    /// Declare the embedded-dossier MIME type, so the model flags the
    /// document `nested_dossier`.
    pub nested_dossier: bool,
}

impl ExtraDocumentSpec {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.to_owned(),
            payload: BASE64.encode("sibling"),
            profile: true,
            nested_dossier: false,
        }
    }

    pub fn without_profile(mut self) -> Self {
        self.profile = false;
        self
    }

    pub fn nested(mut self) -> Self {
        self.nested_dossier = true;
        self
    }
}

/// The whole synthetic dossier.
pub struct DossierSpec {
    pub namespace: String,
    pub payload: String,
    /// How the signed document's payload `ds:Object` spells its identifier.
    /// XMLDSig's schema is `Id`, but real dossiers also carry `ID` and `id`,
    /// and the parser accepts all three.
    pub payload_id_attribute: &'static str,
    pub document_signature: Option<SigSpec>,
    pub dossier_signature: Option<SigSpec>,
    /// An extra copy of the payload object, placed outside the signed document,
    /// for the signature-wrapping cases.
    pub decoy_object: Option<(String, String)>,
    /// Further documents, in source order after the signed one.
    pub extra_documents: Vec<ExtraDocumentSpec>,
    /// Emit a bare `es:TimeStamp` with no data selection, which is the shape
    /// this build reports as not checked.
    pub dossier_timestamp: bool,
    /// Container `es:TimeStamp` elements with a real `xades:Include` selection.
    pub container_timestamps: Vec<ContainerTimestampSpec>,
}

impl Default for DossierSpec {
    fn default() -> Self {
        Self {
            namespace: ESZIGNO_NS.to_owned(),
            payload: BASE64.encode("hello"),
            payload_id_attribute: "Id",
            document_signature: None,
            dossier_signature: None,
            decoy_object: None,
            extra_documents: Vec::new(),
            dossier_timestamp: false,
            container_timestamps: Vec::new(),
        }
    }
}

/// The identifier of one element, under the three spellings the parser, the
/// reference resolver and the coverage reader all accept.
pub fn id_of<'a>(node: openszigno_core::roxmltree::Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
}

pub(super) fn render(spec: &DossierSpec) -> String {
    let namespace = &spec.namespace;
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(&format!(
        "<es:Dossier xmlns:es=\"{namespace}\" xmlns:ds=\"{DS_NS}\">"
    ));
    out.push_str(
        "<es:DossierProfile Id=\"dossier-profile\" OBJREF=\"documents\">\
<es:Title>Synthetic signed dossier</es:Title>\
<es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate>\
</es:DossierProfile>",
    );
    out.push_str("<es:Documents Id=\"documents\"><es:Document>");
    out.push_str(
        "<es:DocumentProfile Id=\"prof0\" OBJREF=\"obj0\">\
<es:Title>synthetic</es:Title>\
<es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate>\
<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>\
<es:SourceSize sizeValue=\"5\" sizeUnit=\"B\"/>\
<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\
</es:DocumentProfile>",
    );
    out.push_str(&format!(
        "<ds:Object {}=\"obj0\">{}</ds:Object>",
        spec.payload_id_attribute, spec.payload
    ));
    if let Some(signature) = &spec.document_signature {
        out.push_str(&render_signature(signature, namespace));
    }
    if spec.dossier_timestamp {
        out.push_str(
            "<es:TimeStamp><xades:EncapsulatedTimeStamp xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\">AA==</xades:EncapsulatedTimeStamp></es:TimeStamp>",
        );
    }
    for (index, timestamp) in spec.container_timestamps.iter().enumerate() {
        if timestamp.placement == TimestampPlacement::Document {
            out.push_str(&render_container_timestamp(timestamp, index));
        }
    }
    out.push_str("</es:Document>");
    if let Some((id, payload)) = &spec.decoy_object {
        // A second, unsigned document carrying a copy of the payload: the
        // wrapping shape where validation and consumption could disagree.
        out.push_str(&format!(
            "<es:Document>\
<es:DocumentProfile Id=\"prof-decoy\" OBJREF=\"{id}\">\
<es:Title>decoy</es:Title>\
<es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate>\
<es:Format><es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/></es:Format>\
<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\
</es:DocumentProfile>\
<ds:Object Id=\"{id}\">{payload}</ds:Object>\
</es:Document>"
        ));
    }
    for document in &spec.extra_documents {
        let id = &document.id;
        let profile = if document.profile {
            let mime = if document.nested_dossier {
                "<es:MIME-Type type=\"application\" subtype=\"nldossier2\" extension=\"dosszie\"/>"
            } else {
                "<es:MIME-Type type=\"text\" subtype=\"plain\" extension=\"txt\"/>"
            };
            format!(
                "<es:DocumentProfile Id=\"prof-{id}\" OBJREF=\"{id}\">\
<es:Title>sibling</es:Title>\
<es:CreationDate>2020-01-01T00:00:00Z</es:CreationDate>\
<es:Format>{mime}</es:Format>\
<es:BaseTransform><es:Transform Algorithm=\"base64\"/></es:BaseTransform>\
</es:DocumentProfile>"
            )
        } else {
            String::new()
        };
        out.push_str(&format!(
            "<es:Document>{profile}<ds:Object Id=\"{id}\">{}</ds:Object></es:Document>",
            document.payload
        ));
    }
    for (index, timestamp) in spec.container_timestamps.iter().enumerate() {
        if timestamp.placement == TimestampPlacement::Stray {
            out.push_str(&render_container_timestamp(timestamp, index));
        }
    }
    out.push_str("</es:Documents>");
    for (index, timestamp) in spec.container_timestamps.iter().enumerate() {
        if timestamp.placement == TimestampPlacement::Dossier {
            out.push_str(&render_container_timestamp(timestamp, index));
        }
    }
    if let Some(signature) = &spec.dossier_signature {
        out.push_str(&render_signature(signature, namespace));
    }
    out.push_str("</es:Dossier>");
    out
}

/// One container `es:TimeStamp`, with its token left as a placeholder that
/// [`build`] fills in once every signature value exists.
fn render_container_timestamp(spec: &ContainerTimestampSpec, index: usize) -> String {
    let mut out = String::from(
        "<es:TimeStamp xmlns:xades=\"http://uri.etsi.org/01903/v1.3.2#\" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
    );
    if let Some(c14n) = &spec.c14n {
        out.push_str(&format!(
            "<ds:CanonicalizationMethod Algorithm=\"{c14n}\"/>"
        ));
    }
    if spec.reference_info {
        out.push_str("<xades:ReferenceInfo URI=\"#obj0\"/>");
    }
    for uri in &spec.includes {
        out.push_str(&format!(
            "<xades:Include URI=\"{uri}\" referencedData=\"true\"/>"
        ));
    }
    match &spec.token {
        Some(_) => out.push_str(&format!(
            "<xades:EncapsulatedTimeStamp>@@CONTAINER-TS-{index}@@</xades:EncapsulatedTimeStamp>"
        )),
        None => {
            out.push_str("<xades:EncapsulatedTimeStamp>not base64!!</xades:EncapsulatedTimeStamp>")
        }
    }
    out.push_str("</es:TimeStamp>");
    out
}

/// The octets a container `es:TimeStamp` covers: each included element
/// canonicalized on its own, concatenated in `Include` order.
pub fn canonical_includes(xml: &str, spec: &ContainerTimestampSpec) -> Vec<u8> {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let algorithm = spec
        .c14n
        .as_deref()
        .and_then(C14nAlgorithm::from_uri)
        .unwrap_or(C14nAlgorithm::Inclusive { comments: false });
    let mut octets = Vec::new();
    for uri in &spec.includes {
        let id = uri.trim_start_matches('#');
        let Some(node) = tree.descendants().find(|node| id_of(*node) == Some(id)) else {
            continue;
        };
        octets.extend_from_slice(
            &RoxmltreeC14n
                .canonicalize(
                    source.text(),
                    &NodeSet::subtree(node).without_comments(),
                    algorithm,
                    &[],
                )
                .expect("canonicalizes"),
        );
    }
    octets
}

/// Every signature in fill order: each signature before the countersignatures
/// nested in it, and the document signature before the frame.
///
/// The order is load bearing. A countersignature digests the countersigned
/// `ds:SignatureValue`, so that value must already be filled in; and the frame
/// signature covers `es:Documents`, which holds both, so it is filled last.
pub(super) fn signatures(spec: &DossierSpec) -> Vec<&SigSpec> {
    let mut list = Vec::new();
    for signature in [&spec.document_signature, &spec.dossier_signature]
        .into_iter()
        .flatten()
    {
        collect_signatures(signature, &mut list);
    }
    list
}

fn collect_signatures<'a>(signature: &'a SigSpec, into: &mut Vec<&'a SigSpec>) {
    into.push(signature);
    for element in &signature.countersignatures {
        for nested in &element.signatures {
            collect_signatures(nested, into);
        }
    }
}

/// Flip one character right after `needle`, so the Base64 blob that follows
/// decodes to different bytes.
pub fn tamper(text: &str, needle: &str) -> String {
    let start = text.find(needle).expect("the needle occurs");
    let position = start + needle.len();
    let original = text.as_bytes()[position];
    let replacement = if original == b'A' { "B" } else { "A" };
    format!(
        "{}{replacement}{}",
        &text[..position],
        &text[position + 1..]
    )
}
