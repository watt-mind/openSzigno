//! Whole-document reads of the certificates and revocation artefacts a
//! dossier carries.
//!
//! These exist for one caller: the CLI's `--online` fetcher, which has to know
//! what a run might need before it decides whether anything is worth fetching.
//! Nothing returned here is trusted, validated, or placed in a path.

use der::Decode as _;
use openszigno_core::{Error as CoreError, ParseOptions, XmlSource};

use crate::tsa;

/// Every X.509 certificate a dossier carries, as DER, deduplicated.
///
/// This exists for one caller: the CLI's `--online` fetcher, which has to know
/// *which* certificates a run might need revocation data about before it can
/// decide whether anything is worth fetching. It is a read of the document and
/// nothing more — no certificate returned here is trusted, validated, or
/// placed in a path; that all still happens inside [`crate::verify`].
///
/// Three places are read, because between them they hold everything a real
/// dossier carries: `ds:KeyInfo/ds:X509Data/ds:X509Certificate`, every
/// `xades:EncapsulatedX509Certificate` under the qualifying properties
/// (`CertificateValues` and `TimeStampValidationData` alike), and the
/// `certificates` set of every RFC 3161 token, which is usually the only place
/// a timestamp authority's own leaf appears.
pub fn embedded_certificates(
    bytes: &[u8],
    options: &ParseOptions,
) -> Result<Vec<Vec<u8>>, CoreError> {
    use base64::Engine as _;

    let limits = &options.limits;
    let source = XmlSource::decode(bytes, limits)?;
    let tree = source.parse_tree(limits)?;
    let mut certificates: Vec<Vec<u8>> = Vec::new();
    let decode = |text: String| -> Option<Vec<u8>> {
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        base64::engine::general_purpose::STANDARD
            .decode(compact.as_bytes())
            .ok()
    };
    let push = |der: Vec<u8>, certificates: &mut Vec<Vec<u8>>| {
        if certificates.len() < MAX_EMBEDDED_CERTIFICATES
            && x509_cert::Certificate::from_der(&der).is_ok()
            && !certificates.contains(&der)
        {
            certificates.push(der);
        }
    };
    for node in tree.descendants().filter(|node| node.is_element()) {
        let text = || -> String {
            node.children()
                .filter(openszigno_core::roxmltree::Node::is_text)
                .filter_map(|child| child.text())
                .collect()
        };
        match node.tag_name().name() {
            "X509Certificate" | "EncapsulatedX509Certificate" => {
                if let Some(der) = decode(text()) {
                    push(der, &mut certificates);
                }
            }
            "EncapsulatedTimeStamp" => {
                if let Some(token) = decode(text()) {
                    for der in tsa::token_certificates(&token) {
                        push(der, &mut certificates);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(certificates)
}

/// The CRLs and OCSP responses a dossier carries as XAdES validation data, in
/// that order, each item DER.
pub type EmbeddedRevocationValues = (Vec<Vec<u8>>, Vec<Vec<u8>>);

/// Every CRL and OCSP response a dossier carries as XAdES validation data, as
/// DER: the CRLs first, then the OCSP responses.
///
/// Like [`embedded_certificates`], this is a read for the CLI's `--online`
/// fetcher, which must know what the dossier already answers for before it
/// decides whether anything is worth fetching. It is the same harvest
/// [`crate::verify`] performs per signature, widened to the whole document, and it
/// confers no trust on anything: every item is still signature-checked against
/// an authorised issuer inside the verifier before it is believed.
pub fn embedded_revocation_values(
    bytes: &[u8],
    options: &ParseOptions,
) -> Result<EmbeddedRevocationValues, CoreError> {
    let limits = &options.limits;
    let source = XmlSource::decode(bytes, limits)?;
    let tree = source.parse_tree(limits)?;
    let mut crls: Vec<Vec<u8>> = Vec::new();
    let mut ocsp: Vec<Vec<u8>> = Vec::new();
    for node in tree.descendants().filter(|node| node.is_element()) {
        let target = match node.tag_name().name() {
            "EncapsulatedCRLValue" => &mut crls,
            "EncapsulatedOCSPValue" => &mut ocsp,
            _ => continue,
        };
        if target.len() >= MAX_EMBEDDED_CERTIFICATES {
            continue;
        }
        let text: String = node
            .children()
            .filter(openszigno_core::roxmltree::Node::is_text)
            .filter_map(|child| child.text())
            .collect();
        let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
        use base64::Engine as _;
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
            && !target.contains(&der)
        {
            target.push(der);
        }
    }
    Ok((crls, ocsp))
}

/// The largest number of certificates [`embedded_certificates`] will return.
/// The document is attacker-controlled and every entry costs work upstream.
const MAX_EMBEDDED_CERTIFICATES: usize = 256;
