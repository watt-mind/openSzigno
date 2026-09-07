//! Synthetic test material: a small PKI and an XMLDSig signer.
//!
//! Signing lives here and nowhere else. Creating or signing a dossier is a
//! permanent non-goal of the shipped tool; this helper exists only so that the
//! verifier can be tested against material it did not itself produce the
//! verification logic for, and it must never move into a shipped crate.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

#![allow(dead_code)]

pub mod keys;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, NameConstraints, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
    SubjectPublicKeyInfo,
};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

pub const ESZIGNO_NS: &str = "https://www.microsec.hu/ds/e-szigno30#";
pub const DS_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
pub const XADES_NS: &str = "http://uri.etsi.org/01903/v1.3.2#";
pub const XADES_NS_122: &str = "http://uri.etsi.org/01903/v1.2.2#";
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

/// A signing key in both the shapes the helper needs: `rcgen`'s, for issuing
/// certificates, and the RustCrypto one, for signing `ds:SignedInfo`.
pub enum SigningKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
    EcdsaP384(Box<p384::ecdsa::SigningKey>),
    /// A key that can produce a certificate but never a signature, used for the
    /// weak-key cases the `ring` backend refuses to sign with.
    None,
}

pub struct TestKey {
    pub rcgen: Option<KeyPair>,
    pub signing: SigningKey,
    pub spki_der: Vec<u8>,
}

pub fn rsa_key(pkcs8_base64: &str) -> TestKey {
    let der = decode_key(pkcs8_base64);
    let rcgen = KeyPair::from_pkcs8_der_and_sign_algo(&der.clone().into(), &PKCS_RSA_SHA256).ok();
    let signing = {
        use rsa::pkcs8::DecodePrivateKey as _;
        rsa::RsaPrivateKey::from_pkcs8_der(&der).expect("the embedded RSA key parses")
    };
    let spki_der = {
        use rsa::pkcs8::EncodePublicKey as _;
        rsa::RsaPublicKey::from(&signing)
            .to_public_key_der()
            .expect("the RSA public key encodes")
            .as_bytes()
            .to_vec()
    };
    TestKey {
        rcgen,
        signing: SigningKey::Rsa(Box::new(signing)),
        spki_der,
    }
}

/// A P-384 key derived from a fixed scalar.
pub fn ecdsa_p384_key(seed: u8) -> TestKey {
    use p384::pkcs8::EncodePrivateKey as _;
    let mut scalar = [1u8; 48];
    scalar[47] = seed;
    let secret = p384::SecretKey::from_slice(&scalar).expect("the fixed scalar is in range");
    let pkcs8 = secret.to_pkcs8_der().expect("the P-384 key encodes");
    let rcgen = KeyPair::from_pkcs8_der_and_sign_algo(
        &pkcs8.as_bytes().into(),
        &rcgen::PKCS_ECDSA_P384_SHA384,
    )
    .ok();
    TestKey {
        rcgen,
        signing: SigningKey::EcdsaP384(Box::new(p384::ecdsa::SigningKey::from(&secret))),
        spki_der: Vec::new(),
    }
}

/// An Ed25519 key, whose signature algorithm this tool deliberately does not
/// implement, used to check that an unsupported key type is refused.
pub fn ed25519_key() -> TestKey {
    TestKey {
        rcgen: KeyPair::generate_for(&rcgen::PKCS_ED25519).ok(),
        signing: SigningKey::None,
        spki_der: Vec::new(),
    }
}

/// A P-256 key derived from a fixed scalar, so the suite stays deterministic.
pub fn ecdsa_key(seed: u8) -> TestKey {
    use p256::pkcs8::EncodePrivateKey as _;
    let mut scalar = [1u8; 32];
    scalar[31] = seed;
    let secret = p256::SecretKey::from_slice(&scalar).expect("the fixed scalar is in range");
    let pkcs8 = secret.to_pkcs8_der().expect("the P-256 key encodes");
    let rcgen =
        KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8.as_bytes().into(), &PKCS_ECDSA_P256_SHA256)
            .ok();
    TestKey {
        rcgen,
        signing: SigningKey::EcdsaP256(Box::new(p256::ecdsa::SigningKey::from(&secret))),
        spki_der: Vec::new(),
    }
}

fn decode_key(text: &str) -> Vec<u8> {
    BASE64
        .decode(
            text.chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>(),
        )
        .expect("the embedded key is Base64")
}

/// How one certificate should look.
pub struct CertSpec<'a> {
    pub common_name: &'a str,
    pub not_before: (i32, u8, u8),
    pub not_after: (i32, u8, u8),
    pub is_ca: IsCa,
    pub key_usages: Vec<KeyUsagePurpose>,
    pub name_constraints: Option<NameConstraints>,
    /// Extra extensions, used to plant an unrecognised critical extension.
    pub custom_extensions: Vec<rcgen::CustomExtension>,
    /// Subject alternative names, against which a CA's name constraints for
    /// dNSName, rfc822Name, and URI subtrees are checked.
    pub subject_alt_names: Vec<rcgen::SanType>,
}

impl<'a> CertSpec<'a> {
    pub fn signer(common_name: &'a str) -> Self {
        Self {
            common_name,
            not_before: (2019, 1, 1),
            not_after: (2039, 1, 1),
            is_ca: IsCa::ExplicitNoCa,
            key_usages: vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::ContentCommitment,
            ],
            name_constraints: None,
            custom_extensions: Vec::new(),
            subject_alt_names: Vec::new(),
        }
    }

    pub fn ca(common_name: &'a str, constraints: BasicConstraints) -> Self {
        Self {
            common_name,
            not_before: (2019, 1, 1),
            not_after: (2039, 1, 1),
            is_ca: IsCa::Ca(constraints),
            key_usages: vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign],
            name_constraints: None,
            custom_extensions: Vec::new(),
            subject_alt_names: Vec::new(),
        }
    }

    fn params(&self) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, self.common_name);
        name.push(DnType::OrganizationName, "openSzigno synthetic test PKI");
        name.push(DnType::CountryName, "HU");
        params.distinguished_name = name;
        params.not_before =
            rcgen::date_time_ymd(self.not_before.0, self.not_before.1, self.not_before.2);
        params.not_after =
            rcgen::date_time_ymd(self.not_after.0, self.not_after.1, self.not_after.2);
        params.is_ca = self.is_ca;
        params.key_usages.clone_from(&self.key_usages);
        params.name_constraints.clone_from(&self.name_constraints);
        params.custom_extensions.clone_from(&self.custom_extensions);
        params.subject_alt_names.clone_from(&self.subject_alt_names);
        params.use_authority_key_identifier_extension = true;
        params
    }
}

/// An issued certificate and the parameters it was issued from, so it can act
/// as an issuer in turn.
pub struct Issued {
    pub der: Vec<u8>,
    pub params: CertificateParams,
}

pub fn self_signed(spec: &CertSpec<'_>, key: &TestKey) -> Issued {
    let params = spec.params();
    let pair = key.rcgen.as_ref().expect("this key can issue certificates");
    let certificate = params.self_signed(pair).expect("self-signing succeeds");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

pub fn issued_by(
    spec: &CertSpec<'_>,
    subject_key: &TestKey,
    issuer: &Issued,
    issuer_key: &TestKey,
) -> Issued {
    let params = spec.params();
    let issuer_pair = issuer_key
        .rcgen
        .as_ref()
        .expect("the issuer key can sign certificates");
    let authority = Issuer::from_params(&issuer.params, issuer_pair);
    let certificate = match subject_key.rcgen.as_ref() {
        Some(pair) => params.signed_by(pair, &authority),
        // A key `ring` refuses to load (an RSA-1024 key, say) can still appear
        // as a subject public key: only the issuer has to be able to sign.
        None => {
            let public = SubjectPublicKeyInfo::from_der(&subject_key.spki_der)
                .expect("the subject public key parses");
            params.signed_by(&public, &authority)
        }
    }
    .expect("issuing succeeds");
    Issued {
        der: certificate.der().to_vec(),
        params,
    }
}

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
    /// Certificates to place in `xades:CertificateValues`, which is where real
    /// dossiers carry the intermediates and usually the root.
    pub certificate_values: Vec<Vec<u8>>,
}

/// The whole synthetic dossier.
pub struct DossierSpec {
    pub namespace: String,
    pub payload: String,
    pub document_signature: Option<SigSpec>,
    pub dossier_signature: Option<SigSpec>,
    /// An extra copy of the payload object, placed outside the signed document,
    /// for the signature-wrapping cases.
    pub decoy_object: Option<(String, String)>,
}

impl Default for DossierSpec {
    fn default() -> Self {
        Self {
            namespace: ESZIGNO_NS.to_owned(),
            payload: BASE64.encode("hello"),
            document_signature: None,
            dossier_signature: None,
            decoy_object: None,
        }
    }
}

/// A correctly signed document-level signature over a synthetic dossier.
pub fn document_signature(certificates: Vec<Vec<u8>>) -> SigSpec {
    SigSpec {
        id: "sig-doc".to_owned(),
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
    }
}

/// A correctly placed frame (dossier-level) signature.
pub fn dossier_signature(certificates: Vec<Vec<u8>>) -> SigSpec {
    SigSpec {
        id: "sig-frame".to_owned(),
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
    for (tag, signature) in signatures(spec) {
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
    }
    xml
}

fn render(spec: &DossierSpec) -> String {
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
        "<ds:Object Id=\"obj0\">{}</ds:Object>",
        spec.payload
    ));
    if let Some(signature) = &spec.document_signature {
        out.push_str(&render_signature(signature, "doc", namespace));
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
    out.push_str("</es:Documents>");
    if let Some(signature) = &spec.dossier_signature {
        out.push_str(&render_signature(signature, "frame", namespace));
    }
    out.push_str("</es:Dossier>");
    out
}

fn render_signature(spec: &SigSpec, tag: &str, namespace: &str) -> String {
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
    out.push_str(&format!(
        "<ds:SignatureValue>@@SIGNATURE-{tag}@@</ds:SignatureValue>"
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
<es:Type>signature</es:Type>\
<es:Generator>openSzigno test helper</es:Generator>\
</es:SignatureProfile></ds:Object>"
        )
    } else {
        String::new()
    };
    // `xades:CertificateValues` lives in the *unsigned* properties, so adding
    // certificates never changes a digest.
    let certificate_values = if spec.certificate_values.is_empty() {
        String::new()
    } else {
        let mut values = String::from(
            "<xades:UnsignedProperties><xades:UnsignedSignatureProperties><xades:CertificateValues>",
        );
        for certificate in &spec.certificate_values {
            values.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                BASE64.encode(certificate)
            ));
        }
        values.push_str("</xades:CertificateValues></xades:UnsignedSignatureProperties></xades:UnsignedProperties>");
        values
    };
    let xades_object = if spec.include_xades {
        format!(
            "<ds:Object><xades:QualifyingProperties xmlns:xades=\"{}\" Target=\"#{}\">\
<xades:SignedProperties Id=\"sp-{tag}\"><xades:SignedSignatureProperties>\
<xades:SigningTime>2020-01-01T00:00:00Z</xades:SigningTime>\
</xades:SignedSignatureProperties></xades:SignedProperties>{}\
</xades:QualifyingProperties></ds:Object>",
            spec.xades_namespace, spec.id, certificate_values
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

fn signatures(spec: &DossierSpec) -> Vec<(&'static str, &SigSpec)> {
    let mut list = Vec::new();
    if let Some(signature) = &spec.document_signature {
        list.push(("doc", signature));
    }
    if let Some(signature) = &spec.dossier_signature {
        list.push(("frame", signature));
    }
    list
}

/// A hand-encoded `nameConstraints` extension, so a test can express subtree
/// forms `rcgen` cannot build (URI, otherName) and exact IP address/mask
/// pairs.
pub fn name_constraints_extension(
    permitted: Vec<x509_cert::ext::pkix::name::GeneralName>,
    excluded: Vec<x509_cert::ext::pkix::name::GeneralName>,
) -> rcgen::CustomExtension {
    use der::Encode as _;
    use x509_cert::ext::pkix::constraints::name::GeneralSubtree;

    let subtrees = |names: Vec<x509_cert::ext::pkix::name::GeneralName>| {
        if names.is_empty() {
            None
        } else {
            Some(
                names
                    .into_iter()
                    .map(|base| GeneralSubtree {
                        base,
                        minimum: 0,
                        maximum: None,
                    })
                    .collect::<Vec<_>>(),
            )
        }
    };
    let constraints = x509_cert::ext::pkix::NameConstraints {
        permitted_subtrees: subtrees(permitted),
        excluded_subtrees: subtrees(excluded),
    };
    let mut extension = rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 30],
        constraints.to_der().expect("the constraints encode"),
    );
    extension.set_criticality(true);
    extension
}

/// A hand-encoded `extendedKeyUsage`, so a test can mark it critical.
pub fn extended_key_usage_extension(oids: &[&str], critical: bool) -> rcgen::CustomExtension {
    use der::Encode as _;
    let usages: Vec<const_oid::ObjectIdentifier> = oids
        .iter()
        .map(|oid| oid.parse().expect("a valid OID"))
        .collect();
    let mut extension = rcgen::CustomExtension::from_oid_content(
        &[2, 5, 29, 37],
        usages.to_der().expect("the usages encode"),
    );
    extension.set_criticality(critical);
    extension
}

/// An extension carrying bytes that are not what its OID says they are.
pub fn malformed_extension(oid: &[u64], critical: bool) -> rcgen::CustomExtension {
    let mut extension = rcgen::CustomExtension::from_oid_content(oid, vec![0x2a, 0x2a, 0x2a]);
    extension.set_criticality(critical);
    extension
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
