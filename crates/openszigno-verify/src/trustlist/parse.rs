//! Reading a TS 119 612 trusted list: the list frame, the service records and
//! their digital identities, and the pointers to other lists.
//!
//! Everything read here is bounded, and every anchor is parsed as an X.509
//! certificate at the point it is read, so a list that loads is one whose
//! every anchor was understood.

use openszigno_core::roxmltree::Node;
use openszigno_core::{Limits, XmlSource};

use crate::c14n::C14nBackend;
use crate::certs::{CertificateSource, ParsedCertificate};
use crate::codes::{Check, CheckCode};
use crate::trust::{
    ServiceIdentity, TrustAnchor, TrustAnchorOrigin, TrustServiceIdentity, parse_rfc3339,
};

use super::services::{
    GRANTED_STATUSES, PRE_EIDAS_GRANTED_STATUSES, ServiceRecord, ServiceStatusEntry, ServiceType,
};
use super::{MAX_TRUST_LIST_BYTES, verify_list_signature};

/// The TS 119 612 namespaces this build recognises.
///
/// TLv5 and TLv6 share it. ETSI TS 119 612 V2.3.1 and V2.4.1, annex B.0, both
/// name `http://uri.etsi.org/02231/v2#` as the base schema namespace and note
/// that the "02231" in it is kept from ETSI TS 102 231 "for compatibility
/// reasons": the namespace did not move at the TLv6 cut-over, so the version
/// has to be read from `TSLVersionIdentifier` and cannot be inferred from the
/// namespace.
const TSL_NAMESPACES: &[&str] = &["http://uri.etsi.org/02231/v2#"];

/// The `TSLVersionIdentifier` values this build parses.
///
/// `5` is TLv5, the format every EU member state published until 2026-04-28.
/// `6` is TLv6, mandatory from 2026-04-29 with no transition period, and the
/// value ETSI TS 119 612 V2.3.1 and V2.4.1 clause 5.3.1 both require ("It
/// shall be \"6\""). The two share the namespace, the element vocabulary this
/// build reads, and the registered service-type and service-status URIs, so
/// one parser serves both; what a version identifier outside this set means
/// for the parsing rules is precisely what clause 5.3.1's note says the field
/// exists to signal, and guessing is not an option.
const SUPPORTED_TSL_VERSIONS: &[u64] = &[5, 6];

/// The largest number of anchors one list may contribute.
const MAX_ANCHORS: usize = 4096;

/// The largest number of pointer certificates read from a list of trusted
/// lists, and so the largest number of candidate signers tried for one
/// national list.
const MAX_POINTER_CERTIFICATES: usize = 512;

/// One loaded trusted list.
#[derive(Clone, Debug)]
pub struct TrustList {
    /// The `TSLVersionIdentifier` the list states: 5 (TLv5) or 6 (TLv6). A
    /// list stating anything else, or nothing, does not load at all, so this
    /// is always one of the two.
    pub version: u64,
    pub sequence_number: Option<u64>,
    pub territory: Option<String>,
    pub issue_date: Option<String>,
    pub next_update: Option<String>,
    pub anchors: Vec<TrustAnchor>,
    /// Every service digital identity the list records, in all three forms.
    /// Only the `X509Certificate` ones are also anchors; the others can
    /// corroborate a chain's qualified status and nothing else.
    pub service_identities: Vec<TrustServiceIdentity>,
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
    let version = read_version(scheme)?;
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
        checks.extend(verify_list_signature(&source, root, signers, backend));
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
    let mut service_identities = Vec::new();
    for service in root
        .descendants()
        .filter(|node| node.is_element() && node.tag_name().name() == "TSPService" && is_tsl(*node))
    {
        collect_service(
            service,
            territory.as_deref(),
            sequence_number,
            &mut anchors,
            &mut service_identities,
        );
        if anchors.len() >= MAX_ANCHORS || service_identities.len() >= MAX_ANCHORS {
            break;
        }
    }

    checks.push(Check::info(
        CheckCode::TrustListLoaded,
        format!(
            "the trusted list is ETSI TS 119 612 version {version} (TLv{version}) and contributed {} trust anchor(s) from qualified CA and timestamping services",
            anchors.len()
        ),
    ));

    Ok(TrustList {
        version,
        sequence_number,
        territory,
        issue_date,
        next_update,
        anchors,
        service_identities,
        pointer_certificates,
        checks,
    })
}

/// Read and check `SchemeInformation/TSLVersionIdentifier`.
///
/// The field decides which parsing rules apply — that is the whole reason
/// TS 119 612 clause 5.3.1 says it "will only be incremented when the rules for
/// parsing the TL change" — so a list that states a version this build has
/// never seen is refused rather than parsed as if it were one that it has. A
/// list that states no version at all is refused for the same reason: the
/// field "shall be present" in every issue of the specification, and a parser
/// that guessed would be guessing about trust anchors.
///
/// The refusal message names the version, because "which version is this file"
/// is the one question an operator needs answered on the day the EU cut over.
fn read_version(scheme: Option<Node<'_, '_>>) -> Result<u64, String> {
    let Some(stated) = scheme
        .and_then(|node| child(node, "TSLVersionIdentifier"))
        .map(|node| text(node).trim().to_owned())
    else {
        return Err(
            "the trusted list states no TSLVersionIdentifier, which ETSI TS 119 612 requires; without it there is no saying which version's parsing rules apply".to_owned(),
        );
    };
    match stated.parse::<u64>() {
        Ok(version) if SUPPORTED_TSL_VERSIONS.contains(&version) => Ok(version),
        _ => Err(format!(
            "the trusted list states TSLVersionIdentifier \"{}\", which this build does not parse; it reads ETSI TS 119 612 version 5 (TLv5) and version 6 (TLv6, mandatory in the EU from 2026-04-29)",
            sanitize(&stated)
        )),
    }
}

/// Read one `TSPService` into zero or more anchors.
pub(super) fn collect_service(
    service: Node<'_, '_>,
    territory: Option<&str>,
    sequence_number: Option<u64>,
    into: &mut Vec<TrustAnchor>,
    identities_into: &mut Vec<TrustServiceIdentity>,
) {
    let Some(information) = child(service, "ServiceInformation") else {
        return;
    };
    let mut entries = Vec::new();
    let mut identities: Vec<ServiceIdentity> = Vec::new();
    let service_name = child(information, "ServiceName").and_then(preferred_name);

    read_instance(information, &mut entries, &mut identities);
    if let Some(history) = child(service, "ServiceHistory") {
        for instance in history
            .children()
            .filter(|node| node.is_element() && node.tag_name().name() == "ServiceHistoryInstance")
        {
            read_instance(instance, &mut entries, &mut identities);
        }
    }

    if entries.is_empty() || identities.is_empty() {
        return;
    }
    entries.sort_by_key(|entry: &ServiceStatusEntry| entry.starting_unix);
    let record = ServiceRecord {
        service_name,
        territory: territory.map(str::to_owned),
        sequence_number,
        entries,
    };
    for identity in identities {
        if let ServiceIdentity::Certificate(der) = &identity {
            into.push(TrustAnchor {
                der: der.clone(),
                origin: TrustAnchorOrigin::TrustList,
                service: Some(record.clone()),
            });
        }
        identities_into.push(TrustServiceIdentity {
            identity,
            service: record.clone(),
        });
    }
}

/// The service name to report, preferring the English one.
///
/// TS 119 612 makes `ServiceName` a list of `Name` elements distinguished by
/// `xml:lang`, and a national list writes its own language first. Reporting
/// that name back to an operator who does not read it is unhelpful, so the
/// `en` entry wins when the list publishes one and the first entry is used
/// otherwise.
pub(super) fn preferred_name(container: Node<'_, '_>) -> Option<String> {
    let names: Vec<Node<'_, '_>> = container
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "Name" && is_tsl(*node))
        .collect();
    let english = names.iter().find(|node| {
        node.attribute((XML_NAMESPACE, "lang"))
            .is_some_and(|lang| lang.eq_ignore_ascii_case("en"))
    });
    english.or(names.first()).map(|node| sanitize(&text(*node)))
}

/// The XML namespace, which is where `xml:lang` lives.
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

/// Read the status and digital identity of one `ServiceInformation` or
/// `ServiceHistoryInstance`.
pub(super) fn read_instance(
    node: Node<'_, '_>,
    entries: &mut Vec<ServiceStatusEntry>,
    identities: &mut Vec<ServiceIdentity>,
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
        granted_before_eidas: PRE_EIDAS_GRANTED_STATUSES.contains(&status_uri.as_str()),
        starting_time: starting_unix.map(crate::trust::format_rfc3339),
        starting_unix,
    });

    for container in node
        .children()
        .filter(|node| node.is_element() && node.tag_name().name() == "ServiceDigitalIdentity")
    {
        for element in container.descendants().filter(Node::is_element) {
            let found = match element.tag_name().name() {
                "X509Certificate" => decode_base64(&text(element))
                    // Parsed here so that a list which loads is one whose
                    // every anchor was understood as a certificate.
                    .filter(|der| {
                        ParsedCertificate::from_der(der, CertificateSource::TrustList).is_some()
                    })
                    .map(ServiceIdentity::Certificate),
                // An SKI is the raw octets of the subjectKeyIdentifier, Base64
                // encoded. It names a certificate without carrying one.
                "X509SKI" => decode_base64(&text(element))
                    .filter(|bytes| !bytes.is_empty() && bytes.len() <= 64)
                    .map(ServiceIdentity::SubjectKeyIdentifier),
                // An RFC 4514 string, parsed back into a name and kept as DER
                // so that the comparison is exact. A list that writes a name
                // this build cannot parse contributes nothing, which is the
                // safe direction: it can only cost coverage.
                "X509SubjectName" => subject_name_der(&text(element)),
                _ => None,
            };
            if let Some(identity) = found
                && !identities.contains(&identity)
            {
                identities.push(identity);
            }
        }
    }
}

/// Parse an RFC 4514 distinguished name into the comparison key
/// [`crate::certs::name_key`] defines.
///
/// A name written in a form this parser does not accept simply yields no
/// identity. That is the conservative direction: it can lose coverage, never
/// grant it.
pub(super) fn subject_name_der(text: &str) -> Option<ServiceIdentity> {
    use std::str::FromStr as _;

    let name = x509_cert::name::Name::from_str(text.trim()).ok()?;
    Some(ServiceIdentity::SubjectName(crate::certs::name_key(&name)))
}

pub(super) fn is_tsl(node: Node<'_, '_>) -> bool {
    node.tag_name()
        .namespace()
        .is_some_and(|namespace| TSL_NAMESPACES.contains(&namespace))
}

pub(super) fn child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| child.is_element() && child.tag_name().name() == name && is_tsl(*child))
}

pub(super) fn ds_child<'a, 'input>(node: Node<'a, 'input>, name: &str) -> Option<Node<'a, 'input>> {
    node.children().find(|child| {
        child.is_element()
            && child.tag_name().namespace() == Some(openszigno_core::XMLDSIG_NAMESPACE)
            && child.tag_name().name() == name
    })
}

pub(super) fn attribute_id<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
}

pub(super) fn text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect()
}

pub(super) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()
}

/// Trusted lists are public documents, but their text still reaches the report,
/// so it is bounded and stripped of control characters exactly like every other
/// value the tool echoes.
pub(super) fn sanitize(text: &str) -> String {
    crate::xades::sanitize(text)
}
