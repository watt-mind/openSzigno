//! `ds:SignedInfo`: the structural read of one signature, and the
//! signature-level algorithm policy applied to it.
//!
//! Stage A1 finds the elements every later stage needs and refuses a signature
//! that is missing one of them. Stages A3 to A8 then decide what the signature
//! *claims*, under the pinned allowlists: the canonicalization method, the
//! signature method, every `ds:DigestMethod`, every transform, whether every
//! reference is same-document, and whether each one resolves in the validated
//! ID space. Nothing here recomputes a digest or verifies a signature value.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::c14n::C14nAlgorithm;
use crate::codes::{Check, CheckCode};
use crate::dsig::{Context, attribute, direct_child, direct_children};
use crate::policy::{Digest, SignatureScheme, Transform};
use crate::references::{Reference, is_known_c14n, parse_reference, resolve_reference};

/// The elements stage A1 requires a `ds:Signature` to carry.
pub(super) struct Structure<'a, 'input> {
    pub(super) signed_info: Node<'a, 'input>,
    pub(super) signature_value_node: Node<'a, 'input>,
    pub(super) c14n_node: Node<'a, 'input>,
    pub(super) method_node: Node<'a, 'input>,
    pub(super) reference_nodes: Vec<Node<'a, 'input>>,
}

/// What the signature-level algorithm policy concluded.
pub(super) struct Policy<'a, 'input> {
    /// The `ds:SignedInfo` canonicalization algorithm, when it is one this
    /// build implements.
    pub(super) signed_info_algorithm: Option<C14nAlgorithm>,
    /// The signature scheme, when it is inside the pinned allowlist.
    pub(super) scheme: Option<SignatureScheme>,
    pub(super) references: Vec<Reference>,
    /// Where each reference resolved, in the same order.
    pub(super) resolved: Vec<Option<Node<'a, 'input>>>,
}

/// Stage A1: check cardinality and order, then read the structure, or say
/// which element is missing.
///
/// The failing check is returned rather than pushed, so the caller reports it
/// exactly where it reported it before.
pub(super) fn parse<'a, 'input>(
    context: &Context<'_, '_, '_>,
    signature: Node<'a, 'input>,
) -> Result<Structure<'a, 'input>, Check> {
    // The cardinality and order pass runs first, so every `direct_child`
    // lookup below reads the one element the schema allows in that position
    // rather than the first of several.
    super::structure::validate(signature)?;
    let signed_info = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo");
    let signature_value_node = direct_child(signature, XMLDSIG_NAMESPACE, "SignatureValue");
    let (Some(signed_info), Some(signature_value_node)) = (signed_info, signature_value_node)
    else {
        return Err(Check::failed(
            CheckCode::SigStructureInvalid,
            "the signature is missing ds:SignedInfo or ds:SignatureValue",
        ));
    };
    let c14n_node = direct_child(signed_info, XMLDSIG_NAMESPACE, "CanonicalizationMethod");
    let method_node = direct_child(signed_info, XMLDSIG_NAMESPACE, "SignatureMethod");
    let reference_nodes: Vec<Node<'_, '_>> =
        direct_children(signed_info, XMLDSIG_NAMESPACE, "Reference").collect();
    let (Some(c14n_node), Some(method_node)) = (c14n_node, method_node) else {
        return Err(Check::failed(
            CheckCode::SigStructureInvalid,
            "ds:SignedInfo is missing its canonicalization or signature method",
        ));
    };
    if reference_nodes.is_empty() {
        return Err(Check::failed(
            CheckCode::SigStructureInvalid,
            "ds:SignedInfo contains no ds:Reference",
        ));
    }
    if reference_nodes.len() > context.limits.max_references_per_signature {
        return Err(Check::failed(
            CheckCode::SigStructureInvalid,
            format!(
                "the signature exceeds {} references",
                context.limits.max_references_per_signature
            ),
        ));
    }
    Ok(Structure {
        signed_info,
        signature_value_node,
        c14n_node,
        method_node,
        reference_nodes,
    })
}

/// Stages A3 to A8: the signature-level algorithm policy and reference
/// resolution.
pub(super) fn algorithm_policy<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    structure: &Structure<'_, '_>,
    checks: &mut Vec<Check>,
) -> Policy<'a, 'input> {
    let c14n_node = structure.c14n_node;
    let method_node = structure.method_node;
    let reference_nodes = &structure.reference_nodes;

    // --- Stage A3: canonicalization method ----------------------------------
    let c14n_uri = attribute(c14n_node, "Algorithm")
        .unwrap_or_default()
        .to_owned();
    let signed_info_algorithm = C14nAlgorithm::from_uri(&c14n_uri);
    match signed_info_algorithm {
        Some(algorithm) => checks.push(Check::passed(
            CheckCode::C14nMethodAllowed,
            format!(
                "ds:SignedInfo uses the {} canonicalization algorithm",
                algorithm.short_name()
            ),
        )),
        None => checks.push(Check::failed(
            CheckCode::C14nUnsupported,
            "the ds:CanonicalizationMethod algorithm is not supported",
        )),
    }

    // --- Stage A4: signature algorithm --------------------------------------
    let method_uri = attribute(method_node, "Algorithm").unwrap_or_default();
    let scheme = SignatureScheme::from_signature_uri(method_uri)
        .filter(|scheme| !scheme.is_legacy() || context.allow_legacy_algorithms);
    match scheme {
        Some(scheme) if scheme.is_legacy() => checks.push(Check::unknown(
            CheckCode::AlgorithmLegacyAllowed,
            format!(
                "ds:SignatureMethod is {}, admitted only because legacy algorithms were allowed; its strength is not vouched for",
                scheme.as_str()
            ),
        )),
        Some(scheme) => checks.push(Check::passed(
            CheckCode::SignatureAlgorithmAllowed,
            format!("ds:SignatureMethod is {}", scheme.as_str()),
        )),
        None => checks.push(Check::failed(
            CheckCode::AlgorithmRejected,
            "the ds:SignatureMethod algorithm is outside the pinned allowlist",
        )),
    }

    // --- Stage A5 to A8: per-reference policy -------------------------------
    let references: Vec<Reference> = reference_nodes
        .iter()
        .enumerate()
        .map(|(position, node)| parse_reference(*node, position))
        .collect();

    let mut digest_ok = true;
    let mut digest_legacy = false;
    for reference in &references {
        match Digest::from_digest_uri(&reference.digest_uri) {
            None => digest_ok = false,
            Some(digest) if digest.is_legacy() => {
                if context.allow_legacy_algorithms {
                    digest_legacy = true;
                } else {
                    digest_ok = false;
                }
            }
            Some(_) => {}
        }
    }
    if !digest_ok {
        checks.push(Check::failed(
            CheckCode::AlgorithmRejected,
            "a ds:DigestMethod algorithm is outside the pinned allowlist",
        ));
    } else if digest_legacy {
        checks.push(Check::unknown(
            CheckCode::AlgorithmLegacyAllowed,
            "a ds:DigestMethod names SHA-1, admitted only because legacy algorithms were allowed; its strength is not vouched for",
        ));
    } else {
        checks.push(Check::passed(
            CheckCode::DigestAlgorithmAllowed,
            "every ds:DigestMethod is inside the pinned allowlist",
        ));
    }

    let mut transforms_ok = true;
    let mut c14n_supported = true;
    for reference in &references {
        if reference.transforms.len() > context.limits.max_transforms_per_reference {
            transforms_ok = false;
            continue;
        }
        for (uri, _) in &reference.transforms {
            if Transform::from_uri(uri).is_some() {
                continue;
            }
            // A known canonicalization algorithm this crate does not implement
            // is reported as unsupported, not as an attack.
            if is_known_c14n(uri) {
                c14n_supported = false;
            } else {
                transforms_ok = false;
            }
        }
    }
    if !c14n_supported {
        checks.push(Check::failed(
            CheckCode::C14nUnsupported,
            "a transform names a canonicalization algorithm this build does not implement",
        ));
    }
    if transforms_ok {
        checks.push(Check::passed(
            CheckCode::TransformsAllowed,
            "every transform is inside the allowlist",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::TransformNotAllowed,
            "a transform is outside the allowlist; XSLT and XPath are refused unconditionally",
        ));
    }

    let mut same_document = true;
    for reference in &references {
        if !(reference.uri.is_empty() || reference.uri.starts_with('#')) {
            same_document = false;
        }
    }
    if same_document {
        checks.push(Check::passed(
            CheckCode::ReferencesSameDocument,
            "every reference is same-document",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::ReferenceExternal,
            "a reference names a URI outside the document; no reference is ever dereferenced",
        ));
    }

    let mut resolved: Vec<Option<Node<'_, '_>>> = Vec::new();
    let mut all_resolve = true;
    for reference in &references {
        let node = resolve_reference(context, reference);
        if node.is_none() && same_document {
            all_resolve = false;
        }
        resolved.push(node);
    }
    if all_resolve {
        checks.push(Check::passed(
            CheckCode::ReferencesResolve,
            "every reference resolves to exactly one node in the validated ID space",
        ));
    } else {
        checks.push(Check::failed(
            CheckCode::ReferenceUnresolved,
            "a reference does not resolve to a node in the validated ID space",
        ));
    }

    Policy {
        signed_info_algorithm,
        scheme,
        references,
        resolved,
    }
}
