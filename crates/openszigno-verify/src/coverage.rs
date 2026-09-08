//! What a signature's references cover.
//!
//! Coverage is decided by the effective node set of each resolved reference —
//! the same [`crate::references::ReferenceScope`] the reference-scope check
//! uses — and by the implemented e-dossier scope rules. It is deliberately
//! independent of every cryptographic outcome.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::codes::{Check, CheckCode, CheckStatus, Verdict};
use crate::dsig::{Context, direct_child, direct_children};
use crate::references::{ReferenceScope, effective_node_set, parse_reference, resolve_reference};
use crate::report::{
    CoverageState, CoverageVia, CoveringSignature, DocumentCoverage, SignatureReport,
    SignatureScope,
};

/// What one signature contributes to the per-document coverage report.
///
/// Everything here is derived from *resolved* references and from the checks
/// the signature already emitted. Placement alone grants nothing: it decides
/// which mandated set applies, and the mandated set is then either covered or
/// it is not.
pub struct SignatureCoverage {
    /// The effective node set of every `ds:Reference` that resolved. An
    /// element is covered when it is inside one of them — ancestor
    /// containment minus what the transforms removed — which is the same rule,
    /// and the same code, the reference-scope check applies.
    pub scopes: Vec<ReferenceScope>,
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
    let scopes = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo")
        .map(|signed_info| {
            direct_children(signed_info, XMLDSIG_NAMESPACE, "Reference")
                .take(context.limits.max_references_per_signature)
                .enumerate()
                .map(|(position, node)| parse_reference(node, position))
                .filter_map(|reference| {
                    let node = resolve_reference(context, &reference)?;
                    Some(effective_node_set(signature, &reference, node))
                })
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
        scopes,
        scope_complete: checks
            .iter()
            .any(|check| check.code == CheckCode::ReferenceScopeComplete),
        undetermined,
    }
}

/// Whether a signature's references cover one element: it lies inside the
/// effective node set of at least one of them.
pub fn covers(scopes: &[ReferenceScope], node: Node<'_, '_>) -> bool {
    scopes.iter().any(|scope| scope.covers(node))
}

/// One signature, as the coverage pass sees it.
struct CoverageSource<'a, 'input> {
    /// The index into `data.signatures`, or `None` for a signature the run
    /// never examined because the dossier is over the signature limit.
    signature_index: Option<usize>,
    node: Node<'a, 'input>,
    scope: SignatureScope,
    verdict: Verdict,
    coverage: SignatureCoverage,
}

/// Which `es:Document` a signature sits inside, if any.
///
/// Used only to decide which documents a signature that could **not** be
/// evaluated might have covered, so an unreadable signature clouds the
/// document it is in rather than the whole container.
fn containing_document<'a, 'input>(
    signature: Node<'a, 'input>,
    namespace: &str,
) -> Option<Node<'a, 'input>> {
    signature.ancestors().find(|node| {
        node.is_element()
            && node.tag_name().namespace() == Some(namespace)
            && node.tag_name().name() == "Document"
    })
}

/// The per-document signature coverage of one dossier, in source order.
///
/// Coverage is decided by **what the resolved references actually digest**
/// and by the implemented e-dossier scope rules. Placement never grants coverage on its own: it
/// selects which mandated set applies, and a signature whose mandated set is
/// incomplete covers nothing. The result is deliberately independent of every
/// cryptographic outcome — a document covered by a signature that does not
/// verify is `covered_unverified`, and the signature's own verdict carries the
/// cryptographic finding.
pub(crate) fn document_coverage<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    root_element: Node<'a, 'input>,
    namespace: &str,
    dossier: &openszigno_core::Dossier,
    signature_nodes: &[Node<'a, 'input>],
    signatures: &[SignatureReport],
) -> Vec<DocumentCoverage> {
    let sources: Vec<CoverageSource<'a, 'input>> = signature_nodes
        .iter()
        .enumerate()
        .map(|(index, node)| match signatures.get(index) {
            Some(report) => CoverageSource {
                signature_index: Some(index),
                node: *node,
                scope: report.scope,
                verdict: report.verdict,
                coverage: signature_coverage(context, *node, &report.checks),
            },
            // Over the signature limit, so it was never examined. It is not
            // evidence of anything, and it is not evidence of nothing either.
            None => CoverageSource {
                signature_index: None,
                node: *node,
                scope: SignatureScope::Unknown,
                verdict: Verdict::Indeterminate,
                coverage: SignatureCoverage {
                    scopes: Vec::new(),
                    scope_complete: false,
                    undetermined: Some(
                        "the signature was not examined because the dossier is over the signature limit",
                    ),
                },
            },
        })
        .collect();

    let Some(documents_node) = direct_child(root_element, namespace, "Documents") else {
        return Vec::new();
    };
    // The parser's own words for the documents it skipped, in source order.
    let mut skipped = dossier
        .warnings
        .iter()
        .filter(|warning| {
            warning.code == openszigno_core::StructuralWarningCode::DocumentWithoutProfile
        })
        .map(|warning| warning.message.clone());

    let mut modelled = 0usize;
    let mut report = Vec::new();
    for node in direct_children(documents_node, namespace, "Document") {
        let Some(profile) = direct_child(node, namespace, "DocumentProfile") else {
            report.push(DocumentCoverage {
                index: None,
                object_ref: None,
                nested_dossier: false,
                coverage: CoverageState::NotModelled,
                covered_by: Vec::new(),
                reason: Some(skipped.next().unwrap_or_else(|| {
                    "the document carries no DocumentProfile and was not modelled".to_owned()
                })),
            });
            continue;
        };
        let Some(document) = dossier.documents.get(modelled) else {
            continue;
        };
        modelled += 1;
        let payload = direct_children(node, openszigno_core::XMLDSIG_NAMESPACE, "Object")
            .find(|object| object.attribute("Id") == Some(document.object_ref.as_str()));

        let mut covered_by = Vec::new();
        for source in &sources {
            if source.coverage.undetermined.is_some() || !source.coverage.scope_complete {
                continue;
            }
            let Some(signature_index) = source.signature_index else {
                continue;
            };
            let scopes = &source.coverage.scopes;
            let via = match source.scope {
                // Direct: placed in *this* document, and its references
                // resolve to this document's profile and payload object.
                SignatureScope::Document
                    if source.node.parent() == Some(node)
                        && covers(scopes, profile)
                        && payload.is_some_and(|object| covers(scopes, object)) =>
                {
                    CoverageVia::Direct
                }
                // Through the frame: the dossier-level signature's references
                // resolve to `es:Documents`, or to an ancestor of it.
                SignatureScope::Dossier if covers(scopes, node) => CoverageVia::Frame,
                _ => continue,
            };
            covered_by.push(CoveringSignature {
                signature_index,
                via,
                verdict: source.verdict,
            });
        }

        let best = covered_by.iter().map(|entry| entry.verdict).min();
        let (coverage, mut reason) = match best {
            Some(Verdict::Valid) => (CoverageState::Covered, None),
            Some(verdict) => (
                CoverageState::CoveredUnverified,
                Some(format!(
                    "no signature covering this document verified; the best verdict among the {} covering signature(s) is {}",
                    covered_by.len(),
                    verdict.as_str()
                )),
            ),
            None => {
                // Nothing covers it. Something might have, had it been
                // evaluable — and "I could not tell" is not "nothing signs it".
                let blocked = sources.iter().find(|source| {
                    source.coverage.undetermined.is_some()
                        && containing_document(source.node, namespace)
                            .is_none_or(|document| document == node)
                });
                match blocked {
                    Some(source) => (
                        CoverageState::Undetermined,
                        Some(format!(
                            "a signature that might cover this document could not be evaluated: {}",
                            source.coverage.undetermined.unwrap_or_default()
                        )),
                    ),
                    None => (
                        CoverageState::Uncovered,
                        Some("no signature's resolved references include this document".to_owned()),
                    ),
                }
            }
        };
        if document.nested_dossier {
            // No implied recursion: an embedded dossier is payload here, and
            // this run says nothing at all about the signatures inside it.
            let note = "this document is an embedded dossier; it is covered like any other payload and its own inner signatures are not verified by this run";
            reason = Some(match reason {
                Some(text) => format!("{text}; {note}"),
                None => note.to_owned(),
            });
        }
        report.push(DocumentCoverage {
            index: Some(document.index),
            object_ref: Some(document.object_ref.clone()),
            nested_dossier: document.nested_dossier,
            coverage,
            covered_by,
            reason,
        });
    }
    report
}

pub(crate) fn coverage_count(documents: &[DocumentCoverage], state: CoverageState) -> usize {
    documents
        .iter()
        .filter(|document| document.coverage == state)
        .count()
}

/// The dossier-level checks the coverage report produces.
///
/// A verdict of `valid` has to mean that the whole dossier's content is
/// signed, so a modelled document nothing covers, or one whose coverage could
/// not be determined, is an open question and blocks with `unknown`. It is
/// never `failed`: an unsigned sibling is missing information about that
/// document, not evidence against any signature that did verify.
pub(crate) fn coverage_checks(documents: &[DocumentCoverage]) -> Vec<Check> {
    let mut checks = Vec::new();
    let uncovered: Vec<String> = documents
        .iter()
        .filter(|document| document.coverage == CoverageState::Uncovered)
        .filter_map(|document| document.index)
        .map(|index| index.to_string())
        .collect();
    let undetermined = coverage_count(documents, CoverageState::Undetermined);
    let unverified = coverage_count(documents, CoverageState::CoveredUnverified);
    let modelled = documents
        .iter()
        .filter(|document| document.coverage != CoverageState::NotModelled)
        .count();

    if uncovered.is_empty() && undetermined == 0 {
        checks.push(if unverified == 0 {
            Check::passed(
                CheckCode::DocumentsAllCovered,
                format!(
                    "every one of the {modelled} modelled document(s) is covered by a signature that verified"
                ),
            )
        } else {
            // Informational, and only because the finding is already
            // elsewhere: the covering signature's own verdict is not `valid`,
            // which has already capped the dossier verdict.
            Check::info(
                CheckCode::DocumentsAllCovered,
                format!(
                    "every one of the {modelled} modelled document(s) is covered, but {unverified} of them only by signatures that did not verify; those signatures' own verdicts carry the finding"
                ),
            )
        });
    }
    if !uncovered.is_empty() {
        checks.push(Check::unknown(
            CheckCode::DocumentsUncovered,
            format!(
                "{} of {modelled} modelled document(s) are covered by no signature; indexes: {}",
                uncovered.len(),
                uncovered.join(", ")
            ),
        ));
    }
    if undetermined > 0 {
        checks.push(Check::unknown(
            CheckCode::DocumentsCoverageUndetermined,
            format!(
                "the coverage of {undetermined} of the {modelled} modelled document(s) could not be determined"
            ),
        ));
    }
    checks
}
