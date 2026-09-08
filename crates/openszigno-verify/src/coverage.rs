//! What a signature's resolved references cover.
//!
//! Coverage is decided by resolved references and by the implemented e-dossier
//! scope rules, and is deliberately independent of every cryptographic
//! outcome.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::{Node, NodeId};

use crate::codes::{Check, CheckCode, CheckStatus};
use crate::dsig::{Context, direct_child, direct_children};
use crate::references::{parse_reference, resolve_reference};

/// What one signature contributes to the per-document coverage report.
///
/// Everything here is derived from *resolved* references and from the checks
/// the signature already emitted. Placement alone grants nothing: it decides
/// which mandated set applies, and the mandated set is then either covered or
/// it is not.
pub struct SignatureCoverage {
    /// Every node a `ds:Reference` resolved to. An element is covered when it
    /// is one of these or a descendant of one, which is the same rule the
    /// reference-scope check applies.
    pub resolved: Vec<NodeId>,
    /// Whether `reference_scope_complete` passed. A signature whose mandated
    /// set is incomplete covers nothing: the container's own rule for what it
    /// must reference was not met, so what it did reference is not a
    /// statement about a document.
    pub scope_complete: bool,
    /// Why this signature's coverage could not be evaluated at all, when it
    /// could not. Such a signature makes the documents it *might* cover
    /// `undetermined` rather than leaving them `uncovered`.
    pub undetermined: Option<&'static str>,
}

/// Gather what one signature covers, from its own node and its own checks.
///
/// This is a second, read-only pass over the same references stage A resolved,
/// so the coverage report and the scope check can never disagree about what a
/// URI pointed at.
pub fn signature_coverage(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    checks: &[Check],
) -> SignatureCoverage {
    let resolved = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo")
        .map(|signed_info| {
            direct_children(signed_info, XMLDSIG_NAMESPACE, "Reference")
                .take(context.limits.max_references_per_signature)
                .enumerate()
                .map(|(position, node)| parse_reference(node, position))
                .filter_map(|reference| resolve_reference(context, &reference))
                .map(|node| node.id())
                .collect()
        })
        .unwrap_or_default();
    let undetermined = checks.iter().find_map(|check| {
        match (check.code, check.status) {
            (CheckCode::SigStructureInvalid, CheckStatus::Failed) => {
                Some("the signature's structure could not be read")
            }
            (CheckCode::SigPlacementInvalid, CheckStatus::Failed) => {
                Some("the signature sits at a placement the e-dossier format does not describe")
            }
            (CheckCode::ReferenceExternal, CheckStatus::Failed) => {
                Some("a reference names a URI outside the document, which is never dereferenced")
            }
            (CheckCode::ReferenceUnresolved, CheckStatus::Failed) => {
                Some("a reference does not resolve in the validated ID space")
            }
            (CheckCode::TransformNotAllowed, CheckStatus::Failed) => {
                Some("a transform is outside the allowlist, so what it selects is unknown")
            }
            (CheckCode::C14nUnsupported, CheckStatus::Failed) => Some(
                "a canonicalization algorithm this build does not implement is named, so what the signature covers cannot be reproduced",
            ),
            (CheckCode::ReferenceScopeUnknown, CheckStatus::Unknown) => {
                Some("the mandated reference set is undefined for this signature")
            }
            _ => None,
        }
    });
    SignatureCoverage {
        resolved,
        scope_complete: checks
            .iter()
            .any(|check| check.code == CheckCode::ReferenceScopeComplete),
        undetermined,
    }
}

/// Whether a resolved reference set covers one element: the element itself, or
/// any ancestor of it, is a resolved node.
pub fn covers(resolved: &[NodeId], node: Node<'_, '_>) -> bool {
    node.ancestors()
        .any(|candidate| resolved.contains(&candidate.id()))
}
