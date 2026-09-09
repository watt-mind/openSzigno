//! The validation data a signature carries: the encapsulated certificates,
//! CRLs and OCSP responses of XAdES-XL, in both placements real dossiers use.
//!
//! Everything gathered here is **untrusted input**. A signer supplies it, so
//! each item is signature-checked against the path before it is believed:
//! taking it at face value would let a signer prove its own certificate was
//! never revoked.

use openszigno_core::roxmltree::Node;

use super::decode_base64;
use crate::dsig::{XADES_NAMESPACES, text_of};

/// The largest number of encapsulated CRLs or OCSP responses read from one
/// signature's `xades:RevocationValues`. The property is attacker-controlled,
/// and each entry costs a signature verification per certificate in the path.
const MAX_REVOCATION_VALUES: usize = 64;

/// Every element under a signature that may hold validation data.
///
/// Two placements matter, and real dossiers use both:
///
/// - `xades:UnsignedSignatureProperties/xades:CertificateValues` and
///   `.../xades:RevocationValues`, the ordinary XAdES-XL shape;
/// - `xades141:TimeStampValidationData`, which XAdES 1.4.1 adds to carry the
///   certificates and revocation data a *timestamp token's* own chain needs.
///   Microsec's long-term dossiers put almost all of their embedded OCSP
///   responses there, so a verifier that only looks at the first placement
///   finds nothing in most real material.
///
/// Whether a given blob was filed as signature validation data or as timestamp
/// validation data changes nothing about how it is treated: every item is
/// untrusted input that must be signature-checked against an authorised issuer
/// before it is believed, so gathering both can only widen what is available,
/// never what is accepted.
pub fn validation_data_containers<'a, 'input>(
    signature: Node<'a, 'input>,
) -> Vec<Node<'a, 'input>> {
    signature
        .descendants()
        .filter(|node| {
            node.is_element()
                && matches!(
                    node.tag_name().name(),
                    "CertificateValues" | "RevocationValues" | "TimeStampValidationData"
                )
                && node
                    .tag_name()
                    .namespace()
                    .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
        })
        // A `TimeStampValidationData` contains its own `RevocationValues`, so
        // both are collected; the harvest below deduplicates by content.
        .collect()
}

/// The DER-encoded CRLs and OCSP responses a signature carries as validation
/// data, from either placement.
///
/// These are **untrusted inputs**, exactly like the certificates in
/// `CertificateValues`: a signer supplies them, so each one is signature-checked
/// against the path before it is believed. Taking them at face value would let a
/// signer prove its own certificate was never revoked.
///
/// Every XAdES namespace is accepted on the container, because dossiers in the
/// wild use v1.1.1 through v1.4.1 and mix them within one signature. Inside a
/// container the encapsulating elements are matched by **name alone**, because
/// real material nests 1.3.2-namespaced values under a 1.4.1-namespaced
/// `TimeStampValidationData` and a CRL is a CRL either way.
pub fn revocation_values(signature: Node<'_, '_>) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut crls: Vec<Vec<u8>> = Vec::new();
    let mut ocsp: Vec<Vec<u8>> = Vec::new();
    for values in validation_data_containers(signature) {
        for node in values.descendants().filter(|node| node.is_element()) {
            let target = match node.tag_name().name() {
                "EncapsulatedCRLValue" => &mut crls,
                "EncapsulatedOCSPValue" => &mut ocsp,
                _ => continue,
            };
            if target.len() >= MAX_REVOCATION_VALUES {
                continue;
            }
            // The same response often appears under both placements; storing it
            // twice would only cost a repeated signature check.
            if let Some(der) = decode_base64(&text_of(node))
                && !target.contains(&der)
            {
                target.push(der);
            }
        }
    }
    (crls, ocsp)
}
