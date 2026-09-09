//! A synthetic ETSI TS 119 612 trusted list.
//!
//! Deliberately minimal and entirely generated. The real EU and Hungarian
//! lists in `refs/trust` are read only as documentation of the schema; no
//! test here touches them, so the suite has no dependency on a file that
//! changes daily and no risk of asserting something about a real trust
//! service provider.
//!
//! Every byte here is generated. Nothing is derived from a real dossier.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use sha2::{Digest as _, Sha256};

use super::cms::sign_rsa_sha256;
use super::dossier::{C14N_EXC, DS_NS, ENVELOPED_URI, RSA_SHA256_URI, SHA256_URI};
use super::pki::{SigningKey, TestKey};

pub const TSL_NS: &str = "http://uri.etsi.org/02231/v2#";
pub const SVCTYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
pub const SVCTYPE_TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";
pub const STATUS_GRANTED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted";
pub const STATUS_WITHDRAWN: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn";
pub const STATUS_UNDER_SUPERVISION: &str =
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision";
pub const STATUS_ACCREDITED: &str = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited";

/// One `TSPService` to write into a synthetic list.
pub struct TlService {
    pub service_type: String,
    pub name: String,
    /// The DER certificates of the service digital identity.
    pub certificates: Vec<Vec<u8>>,
    pub status: String,
    pub status_starting_time: String,
    /// Earlier `ServiceHistoryInstance` entries, as (status, starting time).
    pub history: Vec<(String, String)>,
    /// Emit a `DigitalId` that names a subject rather than supplying a
    /// certificate, which must contribute no anchor.
    pub subject_name_only: bool,
    /// An `X509SubjectName` identity, as an RFC 4514 string.
    pub subject_name: Option<String>,
    /// An `X509SKI` identity, as raw `subjectKeyIdentifier` octets.
    pub subject_key_identifier: Option<Vec<u8>>,
    /// Extra `ServiceName` entries as (`xml:lang`, name), emitted **before**
    /// the English one, so a test can prove the English name is preferred
    /// rather than merely first.
    pub extra_names: Vec<(String, String)>,
}

impl TlService {
    pub fn ca_qc(name: &str, certificate: Vec<u8>) -> Self {
        Self {
            service_type: SVCTYPE_CA_QC.to_owned(),
            name: name.to_owned(),
            certificates: vec![certificate],
            status: STATUS_GRANTED.to_owned(),
            status_starting_time: "2016-07-01T00:00:00Z".to_owned(),
            history: Vec::new(),
            subject_name_only: false,
            subject_name: None,
            subject_key_identifier: None,
            extra_names: Vec::new(),
        }
    }

    /// A service whose only digital identity is an `X509SKI`.
    pub fn by_ski(name: &str, ski: Vec<u8>) -> Self {
        Self {
            certificates: Vec::new(),
            subject_key_identifier: Some(ski),
            ..Self::ca_qc(name, Vec::new())
        }
    }

    /// A service whose only digital identity is an `X509SubjectName`.
    pub fn by_subject_name(name: &str, subject: &str) -> Self {
        Self {
            certificates: Vec::new(),
            subject_name: Some(subject.to_owned()),
            ..Self::ca_qc(name, Vec::new())
        }
    }
}

/// How one synthetic trusted list should look.
pub struct TrustListSpec {
    /// The `TSLVersionIdentifier` the list states. `6` is TLv6, mandatory in
    /// the EU from 2026-04-29; `5` is the TLv5 every member state published
    /// until 2026-04-28. Both must load.
    pub version: u32,
    pub territory: String,
    pub sequence_number: u32,
    pub issue_date: String,
    pub next_update: String,
    pub services: Vec<TlService>,
    /// Sign the list with this key and certificate, which a test then passes as
    /// `--trust-list-signer`.
    pub signer: Option<(TestKey, Vec<u8>)>,
    /// The `ds:SignatureMethod` the list names. TS 119 612 annex B.1.2 permits
    /// any TS 119 312 algorithm, so a list may be signed with ECDSA as well as
    /// with RSA; the key in `signer` decides what is actually computed.
    pub signature_method: String,
    /// Certificates to name in `PointersToOtherTSL`, which is how the EU list
    /// of trusted lists says who signs each national list.
    pub pointers: Vec<Vec<u8>>,
    /// Corrupt one byte of the list after signing it.
    pub tamper: bool,
    /// Give the list element an `Id` and have the signature reference it by
    /// `#Id` rather than with the empty URI. TS 119 612 annex B.1.0 rule 2
    /// allows either, so both must be accepted as covering the whole list.
    pub reference_list_by_id: bool,
}

impl TrustListSpec {
    pub fn new(services: Vec<TlService>) -> Self {
        Self {
            version: 6,
            territory: "HU".to_owned(),
            sequence_number: 7,
            issue_date: "2020-01-01T00:00:00Z".to_owned(),
            next_update: "2021-01-01T00:00:00Z".to_owned(),
            services,
            signer: None,
            signature_method: RSA_SHA256_URI.to_owned(),
            pointers: Vec::new(),
            tamper: false,
            reference_list_by_id: false,
        }
    }

    /// The same list, stated as TLv5.
    pub fn v5(services: Vec<TlService>) -> Self {
        Self {
            version: 5,
            ..Self::new(services)
        }
    }
}

/// Render, and if a signer was given sign, one synthetic trusted list.
pub fn build_trust_list(spec: &TrustListSpec) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    let list_id = if spec.reference_list_by_id {
        " Id=\"the-trusted-list\""
    } else {
        ""
    };
    out.push_str(&format!(
        "<tsl:TrustServiceStatusList xmlns:tsl=\"{TSL_NS}\" xmlns:ds=\"{DS_NS}\"{list_id}>"
    ));
    out.push_str("<tsl:SchemeInformation>");
    out.push_str(&format!(
        "<tsl:TSLVersionIdentifier>{}</tsl:TSLVersionIdentifier>",
        spec.version
    ));
    out.push_str(&format!(
        "<tsl:TSLSequenceNumber>{}</tsl:TSLSequenceNumber>",
        spec.sequence_number
    ));
    out.push_str(&format!(
        "<tsl:SchemeTerritory>{}</tsl:SchemeTerritory>",
        spec.territory
    ));
    out.push_str(&format!(
        "<tsl:ListIssueDateTime>{}</tsl:ListIssueDateTime>",
        spec.issue_date
    ));
    out.push_str(&format!(
        "<tsl:NextUpdate><tsl:dateTime>{}</tsl:dateTime></tsl:NextUpdate>",
        spec.next_update
    ));
    if !spec.pointers.is_empty() {
        out.push_str("<tsl:PointersToOtherTSL>");
        for certificate in &spec.pointers {
            out.push_str(
                "<tsl:OtherTSLPointer><tsl:ServiceDigitalIdentities><tsl:ServiceDigitalIdentity><tsl:DigitalId>",
            );
            out.push_str(&format!(
                "<tsl:X509Certificate>{}</tsl:X509Certificate>",
                BASE64.encode(certificate)
            ));
            out.push_str(
                "</tsl:DigitalId></tsl:ServiceDigitalIdentity></tsl:ServiceDigitalIdentities></tsl:OtherTSLPointer>",
            );
        }
        out.push_str("</tsl:PointersToOtherTSL>");
    }
    out.push_str("</tsl:SchemeInformation>");
    out.push_str("<tsl:TrustServiceProviderList><tsl:TrustServiceProvider><tsl:TSPServices>");
    for service in &spec.services {
        out.push_str("<tsl:TSPService><tsl:ServiceInformation>");
        out.push_str(&format!(
            "<tsl:ServiceTypeIdentifier>{}</tsl:ServiceTypeIdentifier>",
            service.service_type
        ));
        out.push_str("<tsl:ServiceName>");
        for (lang, name) in &service.extra_names {
            out.push_str(&format!("<tsl:Name xml:lang=\"{lang}\">{name}</tsl:Name>"));
        }
        out.push_str(&format!(
            "<tsl:Name xml:lang=\"en\">{}</tsl:Name></tsl:ServiceName>",
            service.name
        ));
        out.push_str("<tsl:ServiceDigitalIdentity>");
        if service.subject_name_only {
            out.push_str(
                "<tsl:DigitalId><tsl:X509SubjectName>CN=Named Only,C=HU</tsl:X509SubjectName></tsl:DigitalId>",
            );
        }
        if let Some(subject) = &service.subject_name {
            out.push_str(&format!(
                "<tsl:DigitalId><tsl:X509SubjectName>{subject}</tsl:X509SubjectName></tsl:DigitalId>"
            ));
        }
        if let Some(ski) = &service.subject_key_identifier {
            out.push_str(&format!(
                "<tsl:DigitalId><tsl:X509SKI>{}</tsl:X509SKI></tsl:DigitalId>",
                BASE64.encode(ski)
            ));
        }
        for certificate in &service.certificates {
            out.push_str(&format!(
                "<tsl:DigitalId><tsl:X509Certificate>{}</tsl:X509Certificate></tsl:DigitalId>",
                BASE64.encode(certificate)
            ));
        }
        out.push_str("</tsl:ServiceDigitalIdentity>");
        out.push_str(&format!(
            "<tsl:ServiceStatus>{}</tsl:ServiceStatus>",
            service.status
        ));
        out.push_str(&format!(
            "<tsl:StatusStartingTime>{}</tsl:StatusStartingTime>",
            service.status_starting_time
        ));
        out.push_str("</tsl:ServiceInformation>");
        if !service.history.is_empty() {
            out.push_str("<tsl:ServiceHistory>");
            for (status, starting) in &service.history {
                out.push_str("<tsl:ServiceHistoryInstance>");
                out.push_str(&format!(
                    "<tsl:ServiceTypeIdentifier>{}</tsl:ServiceTypeIdentifier>",
                    service.service_type
                ));
                out.push_str(&format!(
                    "<tsl:ServiceName><tsl:Name xml:lang=\"en\">{}</tsl:Name></tsl:ServiceName>",
                    service.name
                ));
                out.push_str("<tsl:ServiceDigitalIdentity>");
                for certificate in &service.certificates {
                    out.push_str(&format!(
                        "<tsl:DigitalId><tsl:X509Certificate>{}</tsl:X509Certificate></tsl:DigitalId>",
                        BASE64.encode(certificate)
                    ));
                }
                out.push_str("</tsl:ServiceDigitalIdentity>");
                out.push_str(&format!("<tsl:ServiceStatus>{status}</tsl:ServiceStatus>"));
                out.push_str(&format!(
                    "<tsl:StatusStartingTime>{starting}</tsl:StatusStartingTime>"
                ));
                out.push_str("</tsl:ServiceHistoryInstance>");
            }
            out.push_str("</tsl:ServiceHistory>");
        }
        out.push_str("</tsl:TSPService>");
    }
    out.push_str("</tsl:TSPServices></tsl:TrustServiceProvider></tsl:TrustServiceProviderList>");

    if spec.signer.is_some() {
        out.push_str("<ds:Signature Id=\"tl-signature\"><ds:SignedInfo>");
        out.push_str(&format!(
            "<ds:CanonicalizationMethod Algorithm=\"{C14N_EXC}\"/>"
        ));
        out.push_str(&format!(
            "<ds:SignatureMethod Algorithm=\"{}\"/>",
            spec.signature_method
        ));
        let uri = if spec.reference_list_by_id {
            "#the-trusted-list"
        } else {
            ""
        };
        out.push_str(&format!("<ds:Reference URI=\"{uri}\"><ds:Transforms>"));
        out.push_str(&format!("<ds:Transform Algorithm=\"{ENVELOPED_URI}\"/>"));
        out.push_str(&format!("<ds:Transform Algorithm=\"{C14N_EXC}\"/>"));
        out.push_str("</ds:Transforms>");
        out.push_str(&format!(
            "<ds:DigestMethod Algorithm=\"{SHA256_URI}\"/><ds:DigestValue>@@TLDIGEST@@</ds:DigestValue>"
        ));
        out.push_str("</ds:Reference></ds:SignedInfo>");
        out.push_str("<ds:SignatureValue>@@TLSIG@@</ds:SignatureValue>");
        out.push_str("</ds:Signature>");
    }
    out.push_str("</tsl:TrustServiceStatusList>");

    let Some((key, _)) = &spec.signer else {
        return out;
    };
    out = out.replace(
        "@@TLDIGEST@@",
        &trust_list_digest(&out, spec.reference_list_by_id),
    );
    let value = trust_list_signature(&out, key);
    out = out.replace("@@TLSIG@@", &value);
    if spec.tamper {
        // Change a byte the signature covers, which must make it fail.
        out = out.replace("<tsl:SchemeTerritory>HU<", "<tsl:SchemeTerritory>SK<");
    }
    out
}

fn trust_list_digest(xml: &str, by_id: bool) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signature = tree
        .descendants()
        .find(|node| node.attribute("Id") == Some("tl-signature"))
        .expect("the signature element exists");
    let mut set = if by_id {
        NodeSet::subtree(tree.root_element())
    } else {
        NodeSet::document(tree.root())
    }
    .without_comments();
    set.exclude(signature);
    let octets = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &set,
            C14nAlgorithm::Exclusive { comments: false },
            &[],
        )
        .expect("canonicalizes");
    BASE64.encode(Sha256::digest(&octets))
}

fn trust_list_signature(xml: &str, key: &TestKey) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let signature = tree
        .descendants()
        .find(|node| node.attribute("Id") == Some("tl-signature"))
        .expect("the signature element exists");
    let signed_info = signature
        .children()
        .find(|node| node.is_element() && node.tag_name().name() == "SignedInfo")
        .expect("ds:SignedInfo exists");
    let canonical = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::subtree(signed_info).without_comments(),
            C14nAlgorithm::Exclusive { comments: false },
            &[],
        )
        .expect("canonicalizes");
    BASE64.encode(match &key.signing {
        SigningKey::EcdsaP521(private) => {
            // P-521 signing here is randomized: this build of `p521` offers
            // no RFC 6979 deterministic signer, and the test only has to
            // produce a signature that verifies.
            use p521::ecdsa::signature::RandomizedSigner as _;
            let signature: p521::ecdsa::Signature =
                private.sign_with_rng(&mut rsa::rand_core::OsRng, &canonical);
            signature.to_bytes().to_vec()
        }
        _ => sign_rsa_sha256(key, &canonical),
    })
}
