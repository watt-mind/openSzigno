//! The signed claims a XAdES signature makes about itself, read and reported
//! and applied to nothing.
//!
//! A signature policy identifier and its hash, the claimed roles of
//! `xades:SignerRole`/`SignerRoleV2`, and the commitment types of
//! `xades:CommitmentTypeIndication` are all *statements by the signer*. They
//! are covered by the signature, so they are not forgeable after the fact, but
//! none of them is a fact this build can check: no policy document is fetched,
//! no role is looked up anywhere, and a commitment type names an intention.
//!
//! Reporting them rather than ignoring them is what keeps Hungarian
//! AVDH-authenticated material readable. Such a signature carries all three,
//! and section 634(15) of the Code of Civil Procedure keeps those documents in
//! circulation indefinitely: a reader has to be able to see who the state said
//! it identified, under which policy, without any of it being mistaken for a
//! defect.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;
use serde::Serialize;

use super::{sanitize, xades_child, xades_children};
use crate::dsig::{direct_child, text_of};

/// The bounded number of claimed roles and commitment types reported. Both
/// come from attacker-controlled XML and neither decides anything, so a
/// handful is all a reader ever needs.
const MAX_REPORTED_CLAIMS: usize = 8;

/// The `xades:SigPolicyHash` of an explicit signature policy: the digest the
/// signature claims the policy document has.
///
/// Reported and never used. No policy document is fetched, so there is
/// nothing to compare the digest against; it is recorded because a reader
/// checking a signature against its policy by hand needs both the identifier
/// and the hash the signer committed to.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SignaturePolicyDigest {
    /// `ds:DigestMethod/@Algorithm`, verbatim and sanitised.
    pub algorithm: Option<String>,
    /// `ds:DigestValue`, still Base64, sanitised.
    pub value: Option<String>,
}

/// The declared digest of an explicit signature policy, read and not used.
pub(super) fn policy_digest(hash: Node<'_, '_>) -> SignaturePolicyDigest {
    SignaturePolicyDigest {
        algorithm: direct_child(hash, XMLDSIG_NAMESPACE, "DigestMethod")
            .and_then(|node| node.attribute("Algorithm"))
            .map(sanitize),
        value: direct_child(hash, XMLDSIG_NAMESPACE, "DigestValue")
            .map(|node| sanitize(text_of(node).trim())),
    }
}

/// The `xades:ClaimedRole` values of the signed signature properties.
///
/// XAdES 1.3.2 spells the property `SignerRole` and EN 319 132-1 spells it
/// `SignerRoleV2`; both hold the same `ClaimedRoles`, and both are read.
/// Duplicates are collapsed and the list is bounded, because the values come
/// from untrusted XML. A certified role is *not* read here: it is an attribute
/// certificate, which this build does not process.
pub(super) fn claimed_roles(signed_signature_properties: Node<'_, '_>) -> Vec<String> {
    let mut roles: Vec<String> = Vec::new();
    for name in ["SignerRole", "SignerRoleV2"] {
        let Some(property) = xades_child(signed_signature_properties, name) else {
            continue;
        };
        for claimed in xades_children(property, "ClaimedRoles")
            .flat_map(|list| xades_children(list, "ClaimedRole"))
            .take(MAX_REPORTED_CLAIMS)
        {
            let text = sanitize(text_of(claimed).trim());
            if !text.is_empty() && !roles.contains(&text) {
                roles.push(text);
            }
        }
    }
    roles
}

/// The `xades:CommitmentTypeIndication` identifiers of the signed data-object
/// properties: what the signer says they committed to, reported and applied to
/// nothing. This build validates signatures, not the meaning a signer attaches
/// to one.
pub(super) fn commitment_type_ids(signed_data_object_properties: Node<'_, '_>) -> Vec<String> {
    let mut identifiers: Vec<String> = Vec::new();
    for indication in xades_children(signed_data_object_properties, "CommitmentTypeIndication")
        .take(MAX_REPORTED_CLAIMS)
    {
        let Some(identifier) = xades_child(indication, "CommitmentTypeId")
            .and_then(|id| xades_child(id, "Identifier"))
        else {
            continue;
        };
        let text = sanitize(text_of(identifier).trim());
        if !text.is_empty() && !identifiers.contains(&text) {
            identifiers.push(text);
        }
    }
    identifiers
}
