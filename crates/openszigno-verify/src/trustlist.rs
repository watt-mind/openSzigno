//! ETSI TS 119 612 trusted lists.
//!
//! A trusted list is how the EU says which CAs are entitled to issue
//! qualified certificates, and *when* each of them was. Reading one gives two
//! things a `--trust-store` directory cannot: trust anchors whose provenance
//! is a published national list rather than a human's copy-and-paste, and the
//! qualified determination itself.
//!
//! # What is read
//!
//! For every `TSPService` whose `ServiceTypeIdentifier` is a CA issuing
//! qualified certificates (`.../Svctype/CA/QC`) or a qualified timestamping
//! authority (`.../Svctype/TSA/QTST`), every X.509 certificate in the service
//! digital identity becomes a trust anchor, carrying the service's status
//! timeline: the current `ServiceStatus` with its `StatusStartingTime`, plus
//! every `ServiceHistoryInstance`. A path that ends at such an anchor is
//! trusted only if the service was granted **at the validation time**, which
//! is what makes a signature made while a CA was supervised still verify after
//! that CA was withdrawn, and a signature made after the withdrawal not.
//!
//! A `DigitalId` that carries only an `X509SubjectName` or an `X509SKI` — both
//! common in real lists — is not an anchor: it identifies a certificate
//! without supplying one, and this build will not go looking. Only
//! `X509Certificate` produces an anchor.
//!
//! # What is deliberately not done
//!
//! Nothing is fetched. A trusted list is a file the operator downloaded and
//! pinned, and `docs/trust.md` describes that workflow. Scheme-level
//! `Qualifications` extensions, which refine qualified status per certificate
//! subset, are read far enough to be *reported* as unprocessed and are never
//! used to widen a determination.

use openszigno_core::roxmltree::Node;
use openszigno_core::{Limits, XmlSource};
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::c14n::{C14nAlgorithm, C14nBackend, NodeSet};
use crate::certs::{CertificateSource, ParsedCertificate};
use crate::codes::{Check, CheckCode};
use crate::policy::{Digest, SignatureScheme, Transform};
use crate::trust::{TrustAnchor, TrustAnchorOrigin, UnixTime, parse_rfc3339};

/// The TS 119 612 namespaces this build recognises. TLv5 and TLv6 share the
/// element namespace; only the content differs.
const TSL_NAMESPACES: &[&str] = &["http://uri.etsi.org/02231/v2#"];

const SVCTYPE_CA_QC: &str = "http://uri.etsi.org/TrstSvc/Svctype/CA/QC";
const SVCTYPE_TSA_QTST: &str = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST";

/// The statuses that mean "this service may be relied on".
///
/// `granted` is the eIDAS status; `recognisedatnationallevel` is the national
/// equivalent a member state may publish. Every other status —
/// `withdrawn`, `supervisionceased`, `deprecated*`, and the pre-eIDAS
/// `undersupervision` and `accredited` — is deliberately absent: this build
/// refuses to guess which historical status was equivalent to which, and
/// reports the service as not granted instead of silently accepting it.
const GRANTED_STATUSES: &[&str] = &[
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted",
    "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel",
];

/// The largest trusted list this build will parse.
pub const MAX_TRUST_LIST_BYTES: usize = 32 * 1024 * 1024;

/// The largest number of anchors one list may contribute.
const MAX_ANCHORS: usize = 4096;

/// The largest number of pointer certificates read from a list of trusted
/// lists, and so the largest number of candidate signers tried for one
/// national list.
const MAX_POINTER_CERTIFICATES: usize = 512;

/// Which kind of service an anchor is the digital identity of.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// A CA issuing qualified certificates.
    CaQc,
    /// A qualified electronic timestamping authority.
    TsaQtst,
}

impl ServiceType {
    fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            SVCTYPE_CA_QC => Some(Self::CaQc),
            SVCTYPE_TSA_QTST => Some(Self::TsaQtst),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CaQc => "ca_qc",
            Self::TsaQtst => "tsa_qtst",
        }
    }
}

/// One entry in a service's status timeline.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatusEntry {
    pub service_type: ServiceType,
    /// The last path segment of the status URI, sanitised.
    pub status: String,
    /// Whether this status means the service may be relied on.
    pub granted: bool,
    /// RFC 3339 UTC, or `null` when the list gave an unparseable time.
    pub starting_time: Option<String>,
    #[serde(skip)]
    starting_unix: Option<UnixTime>,
}

/// One trusted-list service, as far as this build reads it.
#[derive(Clone, Debug, Serialize)]
pub struct ServiceRecord {
    pub service_name: Option<String>,
    pub territory: Option<String>,
    pub sequence_number: Option<u64>,
    /// The status timeline, oldest first. The current `ServiceInformation`
    /// entry and every `ServiceHistoryInstance` are folded into one list, so a
    /// lookup at a validation time is a single scan.
    pub entries: Vec<ServiceStatusEntry>,
}

impl ServiceRecord {
    /// The status in force at `time`: the latest entry whose
    /// `StatusStartingTime` is at or before it.
    ///
    /// An entry with no usable starting time is never in force, because a
    /// status without a date cannot be placed on a timeline and guessing would
    /// mean trusting a CA at an instant nobody stated.
    pub fn status_at(&self, time: UnixTime) -> Option<&ServiceStatusEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.starting_unix.is_some_and(|start| start <= time))
            .max_by_key(|entry| entry.starting_unix)
    }

    /// Whether this service was granted at `time` for the given kind of use.
    pub fn granted_at(&self, time: UnixTime, wanted: ServiceType) -> bool {
        self.status_at(time)
            .is_some_and(|entry| entry.granted && entry.service_type == wanted)
    }
}

/// One loaded trusted list.
#[derive(Clone, Debug)]
pub struct TrustList {
    pub sequence_number: Option<u64>,
    pub territory: Option<String>,
    pub issue_date: Option<String>,
    pub next_update: Option<String>,
    pub anchors: Vec<TrustAnchor>,
    /// The certificates this list names in `PointersToOtherTSL`, which for the
    /// EU list of trusted lists are the signing certificates of the national
    /// lists it points at. Reading them is what lets one out-of-band
    /// certificate — the LOTL's, from the Official Journal — bootstrap the
    /// verification of every member state's list.
    pub pointer_certificates: Vec<Vec<u8>>,
    /// Checks the list itself produced: whether its own signature was
    /// verified, and how many anchors it contributed.
    pub checks: Vec<Check>,
}

/// Read a trusted list, optionally verifying its own XMLDSig signature.
///
/// `signers` are the certificates the list is allowed to have been signed
/// with: the one the caller obtained out of band — for the LOTL, from the
/// Official Journal — and, for a national list, the pointer certificates a
/// verified LOTL named for it. Any one of them verifying is enough, because a
/// scheme operator may publish several and a verifier cannot know which of them
/// signed the copy in hand. An empty slice means the signature is not checked
/// at all, and a blocking `trust_list_unverified` is emitted: a list that could
/// be anyone's is still readable, but it can never contribute to a `valid`
/// verdict.
pub fn load(
    bytes: &[u8],
    signers: &[Vec<u8>],
    backend: &dyn C14nBackend,
) -> Result<TrustList, String> {
    if bytes.len() > MAX_TRUST_LIST_BYTES {
        return Err("the trusted list is larger than this build will parse".to_owned());
    }
    let limits = Limits::default();
    let source =
        XmlSource::decode(bytes, &limits).map_err(|_| "the trusted list is not usable XML")?;
    let tree = source
        .parse_tree(&limits)
        .map_err(|_| "the trusted list is not well-formed XML")?;
    let root = tree.root_element();
    if root.tag_name().name() != "TrustServiceStatusList" || !is_tsl(root) {
        return Err("the file is not an ETSI TS 119 612 trusted list".to_owned());
    }

    let scheme = child(root, "SchemeInformation");
    let sequence_number = scheme
        .and_then(|node| child(node, "TSLSequenceNumber"))
        .and_then(|node| text(node).trim().parse::<u64>().ok());
    let territory = scheme
        .and_then(|node| child(node, "SchemeTerritory"))
        .map(|node| sanitize(&text(node)));
    let issue_date = scheme
        .and_then(|node| child(node, "ListIssueDateTime"))
        .map(|node| sanitize(&text(node)));
    let next_update = scheme
        .and_then(|node| child(node, "NextUpdate"))
        .and_then(|node| child(node, "dateTime"))
        .map(|node| sanitize(&text(node)));

    let mut checks = Vec::new();
    if signers.is_empty() {
        checks.push(Check::unknown(
            CheckCode::TrustListUnverified,
            "the trusted list's own signature was not checked, because no signer certificate was given; its anchors are used but cannot support a valid verdict",
        ));
    } else {
        checks.push(verify_list_signature(&source, root, signers, backend));
    }

    // The pointers are read whatever the signature said, so that a caller can
    // see what a list claims; whether the list was verified is reported
    // separately and is what decides if those pointers may be relied on.
    let mut pointer_certificates: Vec<Vec<u8>> = Vec::new();
    if let Some(scheme) = scheme
        && let Some(pointers) = child(scheme, "PointersToOtherTSL")
    {
        for node in pointers
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "X509Certificate")
        {
            if pointer_certificates.len() >= MAX_POINTER_CERTIFICATES {
                break;
            }
            let Some(der) = decode_base64(&text(node)) else {
                continue;
            };
            if ParsedCertificate::from_der(&der, CertificateSource::TrustList).is_some()
                && !pointer_certificates.contains(&der)
            {
                pointer_certificates.push(der);
            }
        }
    }

    let mut anchors = Vec::new();
    for service in root
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "TSPService" && is_tsl(*node))
    {
        collect_service(service, territory.as_deref(), sequence_number, &mut anchors);
        if anchors.len() >= MAX_ANCHORS {
            break;
        }
    }

    checks.push(Check::info(
        CheckCode::TrustListLoaded,
        format!(
            "the trusted list contributed {} trust anchor(s) from qualified CA and timestamping services",
            anchors.len()
        ),
    ));

    Ok(TrustList {
        sequence_number,
        territory,
        issue_date,
        next_update,
        anchors,
        pointer_certificates,
        checks,
    })
}

/// Read one `TSPService` into zero or more anchors.
fn collect_service(
    service: Node<'_, '_>,
    territory: Option<&str>,
    sequence_number: Option<u64>,
    into: &mut Vec<TrustAnchor>,
) {
    let Some(information) = child(service, "ServiceInformation") else {
        return;
    };
    let mut entries = Vec::new();
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let service_name = child(information, "ServiceName")
        .and_then(|node| child(node, "Name"))
        .map(|node| sanitize(&text(node)));

    read_instance(information, &mut entries, &mut certificates);
    if let Some(history) = child(service, "ServiceHistory") {
        for instance in history
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "ServiceHistoryInstance")
        {
            read_instance(instance, &mut entries, &mut certificates);
        }
    }

    if entries.is_empty() || certificates.is_empty() {
        return;
    }
    entries.sort_by_key(|entry: &ServiceStatusEntry| entry.starting_unix);
    let record = ServiceRecord {
        service_name,
        territory: territory.map(str::to_owned),
        sequence_number,
        entries,
    };
    for der in certificates {
        into.push(TrustAnchor {
            der,
            origin: TrustAnchorOrigin::TrustList,
            service: Some(record.clone()),
        });
    }
}

/// Read the status and digital identity of one `ServiceInformation` or
/// `ServiceHistoryInstance`.
fn read_instance(
    node: Node<'_, '_>,
    entries: &mut Vec<ServiceStatusEntry>,
    certificates: &mut Vec<Vec<u8>>,
) {
    let Some(service_type) = child(node, "ServiceTypeIdentifier")
        .and_then(|node| ServiceType::from_uri(text(node).trim()))
    else {
        return;
    };
    let status_uri = child(node, "ServiceStatus")
        .map(|node| text(node).trim().to_owned())
        .unwrap_or_default();
    let starting = child(node, "StatusStartingTime").map(|node| text(node).trim().to_owned());
    let starting_unix = starting.as_deref().and_then(parse_rfc3339);
    entries.push(ServiceStatusEntry {
        service_type,
        status: sanitize(status_uri.rsplit('/').next().unwrap_or_default()),
        granted: GRANTED_STATUSES.contains(&status_uri.as_str()),
        starting_time: starting_unix.map(crate::trust::format_rfc3339),
        starting_unix,
    });

    for identity in node
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "ServiceDigitalIdentity")
    {
        for certificate in identity
            .descendants()
            .filter(|node| node.is_element() && node.tag_name().name() == "X509Certificate")
        {
            let Some(der) = decode_base64(&text(certificate)) else {
                continue;
            };
            // Parsed here so that a list which loads is one whose every anchor
            // was understood as a certificate.
            if ParsedCertificate::from_der(&der, CertificateSource::TrustList).is_none() {
                continue;
            }
            if !certificates.contains(&der) {
                certificates.push(der);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The list's own XMLDSig signature
// ---------------------------------------------------------------------------

/// Verify the enveloped XMLDSig signature over a trusted list.
///
/// This is the same core the dossier pipeline uses — the same canonicalization
/// backend, the same pinned algorithm and transform allowlists, the same
/// signature verification — applied to a document whose placement rules are
/// TS 119 612's rather than the e-dossier's: exactly one `ds:Signature` as a
/// child of the list element, covering the whole document with the
/// enveloped-signature transform.
fn verify_list_signature(
    source: &XmlSource,
    root: Node<'_, '_>,
    signers: &[Vec<u8>],
    backend: &dyn C14nBackend,
) -> Check {
    let invalid = |message: &str| Check::failed(CheckCode::TrustListSignatureInvalid, message);

    // Any one of the supplied certificates verifying is enough: a scheme
    // operator may publish several, and a verifier cannot know which of them
    // signed the copy in hand.
    let candidates: Vec<ParsedCertificate> = signers
        .iter()
        .filter_map(|der| ParsedCertificate::from_der(der, CertificateSource::TrustStore))
        .collect();
    if candidates.is_empty() {
        return invalid("no supplied trust-list signer is a usable X.509 certificate");
    }
    let signatures: Vec<Node<'_, '_>> = root
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Signature"
        })
        .collect();
    let [signature] = signatures.as_slice() else {
        return invalid("the trusted list does not carry exactly one ds:Signature of its own");
    };
    let Some(signed_info) = ds_child(*signature, "SignedInfo") else {
        return invalid("the trusted list's signature has no ds:SignedInfo");
    };
    let Some(signature_value) = ds_child(*signature, "SignatureValue") else {
        return invalid("the trusted list's signature has no ds:SignatureValue");
    };

    let Some(c14n) = ds_child(signed_info, "CanonicalizationMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(C14nAlgorithm::from_uri)
    else {
        return invalid(
            "the trusted list's signature names a canonicalization method outside the allowlist",
        );
    };
    let Some(scheme) = ds_child(signed_info, "SignatureMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(SignatureScheme::from_signature_uri)
        .filter(|scheme| !scheme.is_legacy())
    else {
        return invalid(
            "the trusted list's signature names a signature method outside the allowlist",
        );
    };

    // Every reference must verify. A trusted list whose signature covers only
    // part of itself is a trusted list an attacker can extend.
    let references: Vec<Node<'_, '_>> = signed_info
        .children()
        .filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Reference"
        })
        .collect();
    if references.is_empty() {
        return invalid("the trusted list's ds:SignedInfo carries no ds:Reference");
    }
    let mut covers_document = false;
    for reference in references {
        match check_reference(source, root, *signature, reference, backend) {
            Ok(whole_document) => covers_document |= whole_document,
            Err(message) => return invalid(&message),
        }
    }
    if !covers_document {
        return invalid(
            "the trusted list's signature does not cover the whole list; a partial reference set would leave the service entries unprotected",
        );
    }

    let Ok(canonical) = backend.canonicalize(
        source.text(),
        &NodeSet::subtree(signed_info).without_comments(),
        c14n,
        &[],
    ) else {
        return invalid("the trusted list's ds:SignedInfo could not be canonicalized");
    };
    let Some(value) = decode_base64(&text(signature_value)) else {
        return invalid("the trusted list's ds:SignatureValue is not Base64");
    };
    let verified = candidates.iter().any(|candidate| {
        crate::certs::verify_with_spki(&candidate.certificate, scheme, &canonical, &value, false)
            .is_ok()
    });
    if verified {
        return Check::passed(
            CheckCode::TrustListSignatureOk,
            format!(
                "the trusted list's own XMLDSig signature verified against one of {} supplied signer certificate(s)",
                candidates.len()
            ),
        );
    }
    invalid(
        "the trusted list's own XMLDSig signature did not verify against any supplied signer certificate",
    )
}

/// Verify one reference of the trusted list's signature.
///
/// Returns whether this reference covers the whole document.
fn check_reference(
    source: &XmlSource,
    root: Node<'_, '_>,
    signature: Node<'_, '_>,
    reference: Node<'_, '_>,
    backend: &dyn C14nBackend,
) -> Result<bool, String> {
    let uri = reference.attribute("URI").unwrap_or("");
    let whole_document = uri.is_empty();
    let apex = if whole_document {
        root.parent().unwrap_or(root)
    } else {
        let id = uri
            .strip_prefix('#')
            .ok_or_else(|| "the trusted list's signature names an external reference".to_owned())?;
        let mut matches = root
            .descendants()
            .filter(|node| node.is_element() && attribute_id(*node) == Some(id));
        let found = matches
            .next()
            .ok_or_else(|| "a reference in the trusted list resolves to nothing".to_owned())?;
        if matches.next().is_some() {
            return Err(
                "a reference in the trusted list resolves to more than one node".to_owned(),
            );
        }
        found
    };

    let mut set = if whole_document {
        NodeSet::document(apex)
    } else {
        NodeSet::subtree(apex)
    }
    .without_comments();
    let mut algorithm = C14nAlgorithm::Inclusive { comments: false };
    let mut enveloped = false;
    if let Some(transforms) = ds_child(reference, "Transforms") {
        for transform in transforms.children().filter(|node| {
            node.is_element()
                && node.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
                && node.tag_name().name() == "Transform"
        }) {
            let uri = transform.attribute("Algorithm").unwrap_or_default();
            match Transform::from_uri(uri) {
                Some(Transform::EnvelopedSignature) => {
                    set.exclude(signature);
                    enveloped = true;
                }
                Some(Transform::Canonicalization(selected)) => algorithm = selected,
                // Base64 has no meaning over an element node set here, and
                // everything else is outside the allowlist on purpose.
                _ => {
                    return Err(
                        "the trusted list's signature uses a transform outside the allowlist"
                            .to_owned(),
                    );
                }
            }
        }
    }
    if whole_document && !enveloped {
        return Err(
            "the trusted list's signature covers the whole document without the enveloped-signature transform, which cannot verify"
                .to_owned(),
        );
    }

    let Some(digest) = ds_child(reference, "DigestMethod")
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(Digest::from_digest_uri)
        .filter(|digest| !digest.is_legacy())
    else {
        return Err("the trusted list's signature names a digest outside the allowlist".to_owned());
    };
    let expected = ds_child(reference, "DigestValue")
        .and_then(|node| decode_base64(&text(node)))
        .ok_or_else(|| "a reference digest in the trusted list is not Base64".to_owned())?;

    let octets = backend
        .canonicalize(source.text(), &set, algorithm, &[])
        .map_err(|_| "a reference in the trusted list could not be canonicalized".to_owned())?;
    let computed = match digest {
        Digest::Sha1 => Sha1::digest(&octets).to_vec(),
        Digest::Sha256 => Sha256::digest(&octets).to_vec(),
        Digest::Sha384 => Sha384::digest(&octets).to_vec(),
        Digest::Sha512 => Sha512::digest(&octets).to_vec(),
    };
    if computed != expected {
        return Err("a reference digest in the trusted list does not match".to_owned());
    }
    Ok(whole_document)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn is_tsl(node: Node<'_, '_>) -> bool {
    node.tag_name()
        .namespace()
        .is_some_and(|namespace| TSL_NAMESPACES.contains(&namespace))
}

fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name && is_tsl(*child))
}

fn ds_child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
            && child.tag_name().name() == name
    })
}

fn attribute_id<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
}

fn text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect()
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()
}

/// Trusted lists are public documents, but their text still reaches the report,
/// so it is bounded and stripped of control characters exactly like every other
/// value the tool echoes.
fn sanitize(text: &str) -> String {
    crate::xades::sanitize(text)
}
