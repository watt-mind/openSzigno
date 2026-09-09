//! Container timestamps: the e-dossier `es:TimeStamp` element.
//!
//! A `xades:SignatureTimeStamp` covers one thing — the canonicalized
//! `ds:SignatureValue` — and the XAdES default data selection says so without
//! anyone having to write it down. An `es:TimeStamp` is different: the
//! Microsec e-dossier specification gives it `xades:TimeStampType` semantics,
//! so it protects **the elements it references**, named by `xades:Include`
//! children, and there is no implicit selection to fall back on. Verifying one
//! therefore needs the same reference resolution, scope enforcement and
//! canonicalization a signature gets, which is why it waited for M3.
//!
//! # What is checked
//!
//! 1. **Placement.** A direct `es:TimeStamp` child of `es:Dossier` is a
//!    dossier timestamp; a direct child of `es:Document` is a document
//!    timestamp. Anywhere else the format does not say what the element is
//!    meant to protect, so nothing is digested.
//! 2. **Resolution.** Every `xades:Include/@URI` must be a same-document
//!    `#id` reference resolving, through the ID space `openszigno-core`
//!    validated, to exactly one element. Nothing is ever dereferenced off the
//!    document, in any mode.
//! 3. **Scope.** The reference-scope rule for timestamps, which is the same
//!    defence against wrapping the signature pipeline applies: a dossier
//!    timestamp must cover `/es:Dossier/es:DossierProfile` and
//!    `/es:Dossier/es:Documents`; a document timestamp must cover its
//!    `es:DocumentProfile` and the document's payload `ds:Object`. A required
//!    element is covered when an `Include` resolves to it or to an ancestor of
//!    it.
//! 4. **Imprint.** Each included element is canonicalized on its own with the
//!    algorithm the timestamp's `ds:CanonicalizationMethod` names — inclusive
//!    C14N 1.0 when it names none, as XAdES 7.1.4.3.1 prescribes — and the
//!    results are concatenated **in `Include` document order**. That octet
//!    string is what the token's `messageImprint` must digest to.
//! 5. **The token.** Verified by exactly the machinery a signature timestamp
//!    uses: CMS parse, imprint, `SignerInfo` signature, the critical
//!    `id-kp-timeStamping` requirement, and a TSA path validated at `genTime`.
//!
//! # What it decides
//!
//! Nothing about any signature. An `es:TimeStamp` is a statement about the
//! container, so it is reported at the dossier level and never folded into a
//! signature's verdict. It can still lower the **dossier** verdict, and only
//! in one direction: an imprint that does not match, a token that will not
//! parse, or a TSA signature that does not verify are evidence *against* the
//! container and yield `..._timestamp_invalid` (`failed`). A gap in the
//! caller's own material — no trust anchors, an unobtainable revocation
//! answer, a data-selection form this build does not implement — is missing
//! information rather than evidence, and yields `..._timestamp_not_checked`
//! (`info`), because carrying more evidence than the minimum must never make a
//! dossier look worse than carrying none.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::c14n::{C14nAlgorithm, NodeSet};
use crate::codes::{Check, CheckCode, CheckStatus};
use crate::dsig::{Context, attribute, direct_child, direct_children, text_of};
use crate::tsa::TimestampKind;
use crate::xades;

/// The largest number of `xades:Include` children read from one container
/// timestamp. The element is attacker-controlled and each entry costs one
/// canonicalization.
const MAX_INCLUDES: usize = 64;

/// Where a container timestamp sits, which decides what it must cover.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerScope {
    /// A direct `es:TimeStamp` child of `es:Dossier`.
    Dossier,
    /// A direct `es:TimeStamp` child of `es:Document`, with its index among
    /// the parsed documents.
    Document(usize),
}

impl ContainerScope {
    const fn kind(self) -> TimestampKind {
        match self {
            Self::Dossier => TimestampKind::DossierTimestamp,
            Self::Document(_) => TimestampKind::DocumentTimestamp,
        }
    }

    const fn document_index(self) -> Option<usize> {
        match self {
            Self::Dossier => None,
            Self::Document(index) => Some(index),
        }
    }

    /// The check codes this scope reports through.
    const fn codes(self) -> (CheckCode, CheckCode, CheckCode) {
        match self {
            Self::Dossier => (
                CheckCode::DossierTimestampVerified,
                CheckCode::DossierTimestampInvalid,
                CheckCode::DossierTimestampNotChecked,
            ),
            Self::Document(_) => (
                CheckCode::DocumentTimestampVerified,
                CheckCode::DocumentTimestampInvalid,
                CheckCode::DocumentTimestampNotChecked,
            ),
        }
    }

    fn describe(self) -> String {
        match self {
            Self::Dossier => "the dossier-level es:TimeStamp".to_owned(),
            Self::Document(index) => format!("the es:TimeStamp of document {index}"),
        }
    }
}

/// One container timestamp, resolved as far as it can be without the token.
pub struct ContainerTimestamp {
    pub scope: ContainerScope,
    /// The DER token, empty when there was none to decode.
    pub token: Vec<u8>,
    /// The octets the imprint must be recomputed over: the canonicalized
    /// included elements, concatenated in `Include` order.
    pub imprint_input: Vec<u8>,
    /// Why this timestamp was not digested, when it was not.
    pub unsupported: Option<String>,
}

impl ContainerTimestamp {
    pub const fn kind(&self) -> TimestampKind {
        self.scope.kind()
    }

    pub const fn document_index(&self) -> Option<usize> {
        self.scope.document_index()
    }
}

/// Find every `es:TimeStamp` in the container and prepare it for verification.
///
/// `document_nodes` are the `es:Document` elements the structural parser
/// accepted, in the order it indexed them, so that a per-document check can
/// name the same index the rest of the report uses.
pub fn collect<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    root_element: Node<'a, 'input>,
    document_nodes: &[Node<'a, 'input>],
) -> Vec<ContainerTimestamp> {
    let namespace = context.namespace;
    let mut found = Vec::new();
    for node in root_element
        .descendants()
        .filter(|node| is_element(*node, namespace, "TimeStamp"))
        .take(context.limits.max_timestamps_per_signature * 4)
    {
        let parent = node.parent();
        let scope = match parent {
            Some(parent) if parent.id() == root_element.id() => Some(ContainerScope::Dossier),
            Some(parent) if is_element(parent, namespace, "Document") => document_nodes
                .iter()
                .position(|document| document.id() == parent.id())
                .map(ContainerScope::Document),
            _ => None,
        };
        let Some(scope) = scope else {
            // A placement the format does not describe: nothing says which
            // elements this timestamp is meant to protect, so nothing is
            // digested. Guessing would be the one mistake worth avoiding here.
            found.push(ContainerTimestamp {
                scope: ContainerScope::Dossier,
                token: Vec::new(),
                imprint_input: Vec::new(),
                unsupported: Some(
                    "an es:TimeStamp sits at a placement the e-dossier format does not describe, so what it protects is undefined"
                        .to_owned(),
                ),
            });
            continue;
        };
        found.push(prepare(context, node, scope, document_nodes));
    }
    found
}

/// Resolve one `es:TimeStamp` into the octets its imprint must cover.
fn prepare<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    node: Node<'a, 'input>,
    scope: ContainerScope,
    document_nodes: &[Node<'a, 'input>],
) -> ContainerTimestamp {
    let unsupported = |reason: &str| ContainerTimestamp {
        scope,
        token: Vec::new(),
        imprint_input: Vec::new(),
        unsupported: Some(reason.to_owned()),
    };

    for child in node.children().filter(Node::is_element) {
        if matches!(
            child.tag_name().name(),
            "ReferenceInfo" | "HashDataInfo" | "XMLTimeStamp"
        ) {
            return unsupported(
                "the timestamp selects its data with a form this build does not implement",
            );
        }
    }

    // --- The included elements, in document order --------------------------
    // Only an `Include` in a recognised XAdES namespace selects data, which is
    // the rule every other XAdES element in this crate is read under. Matching
    // on the local name alone let an element some other vocabulary happens to
    // call `Include` add its target to the imprint, and so change what a
    // container timestamp is taken to cover.
    let includes: Vec<Node<'a, 'input>> = xades::xades_children(node, "Include")
        .take(MAX_INCLUDES)
        .collect();
    if includes.is_empty() {
        return unsupported(
            "the timestamp names no xades:Include, and a container timestamp has no implicit data selection this build could fall back on",
        );
    }
    let mut resolved: Vec<Node<'a, 'input>> = Vec::with_capacity(includes.len());
    for include in &includes {
        let uri = attribute(*include, "URI").unwrap_or_default();
        let Some(id) = uri.strip_prefix('#').filter(|id| !id.is_empty()) else {
            return unsupported(
                "the timestamp includes a URI that is not a same-document reference",
            );
        };
        let Some(target) = context.ids.get(id) else {
            return unsupported("an xades:Include of the timestamp resolves to nothing");
        };
        resolved.push(*target);
    }

    // --- The reference-scope rule for container timestamps -----------------
    if let Some(missing) = missing_scope(context, scope, &resolved, document_nodes) {
        return ContainerTimestamp {
            scope,
            token: Vec::new(),
            imprint_input: Vec::new(),
            unsupported: Some(format!(
                "the timestamp does not cover {missing}, which the e-dossier format requires it to protect"
            )),
        };
    }

    // --- Canonicalization ---------------------------------------------------
    let method = xades::ds_child(node, "CanonicalizationMethod");
    let algorithm = match method {
        None => Some((C14nAlgorithm::Inclusive { comments: false }, Vec::new())),
        Some(method) => attribute(method, "Algorithm")
            .and_then(C14nAlgorithm::from_uri)
            .map(|algorithm| (algorithm, crate::dsig::inclusive_prefixes(method))),
    };
    let Some((algorithm, prefixes)) = algorithm else {
        return unsupported(
            "the timestamp names a canonicalization algorithm this build does not implement",
        );
    };

    // XAdES 7.1.4.3.1: each included element is canonicalized and the results
    // are concatenated in the order the `Include` elements appear.
    let mut imprint_input = Vec::new();
    for target in &resolved {
        let set = NodeSet::subtree(*target).without_comments();
        let Ok(octets) = context
            .backend
            .canonicalize(context.source, &set, algorithm, &prefixes)
        else {
            return unsupported("an included element could not be canonicalized");
        };
        imprint_input.extend_from_slice(&octets);
    }

    // --- The token ----------------------------------------------------------
    let tokens: Vec<Vec<u8>> = xades::xades_children(node, "EncapsulatedTimeStamp")
        .filter_map(|element| decode_base64(&text_of(element)))
        .take(2)
        .collect();
    match tokens.len() {
        1 => ContainerTimestamp {
            scope,
            token: tokens.into_iter().next().unwrap_or_default(),
            imprint_input,
            unsupported: None,
        },
        0 => unsupported("the timestamp carries no decodable xades:EncapsulatedTimeStamp"),
        _ => unsupported(
            "the timestamp carries more than one token, which this build does not process",
        ),
    }
}

/// The first mandated element this timestamp fails to cover, if any.
///
/// A required element is covered when an `Include` resolved to it or to an
/// ancestor of it, which is the same rule the signature pipeline applies to
/// `ds:Reference`.
fn missing_scope<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    scope: ContainerScope,
    resolved: &[Node<'a, 'input>],
    document_nodes: &[Node<'a, 'input>],
) -> Option<&'static str> {
    let namespace = context.namespace;
    let root = context.root.first_element_child()?;
    let required: Vec<(Option<Node<'a, 'input>>, &'static str)> = match scope {
        ContainerScope::Dossier => vec![
            (
                direct_child(root, namespace, "DossierProfile"),
                "the es:DossierProfile",
            ),
            (
                direct_child(root, namespace, "Documents"),
                "the es:Documents element",
            ),
        ],
        ContainerScope::Document(index) => {
            let document = *document_nodes.get(index)?;
            let profile = direct_child(document, namespace, "DocumentProfile");
            let payload = profile
                .and_then(|profile| attribute(profile, "OBJREF"))
                .and_then(|objref| context.ids.get(objref).copied())
                .or_else(|| direct_children(document, XMLDSIG_NAMESPACE, "Object").next());
            vec![
                (profile, "the document's es:DocumentProfile"),
                (payload, "the document's payload ds:Object"),
            ]
        }
    };
    for (element, name) in required {
        // An element the container does not carry cannot be required of the
        // timestamp; the structural parser has already refused the shapes
        // where its absence matters.
        let Some(element) = element else { continue };
        let covered = resolved
            .iter()
            .any(|target| target.id() == element.id() || is_ancestor(*target, element));
        if !covered {
            return Some(name);
        }
    }
    None
}

fn is_ancestor(candidate: Node<'_, '_>, element: Node<'_, '_>) -> bool {
    element
        .ancestors()
        .any(|ancestor| ancestor.id() == candidate.id())
}

/// Fold one verified-or-not container timestamp into the dossier check list.
///
/// The classification is deliberately asymmetric, and the asymmetry is the
/// whole point: a token that contradicts the container makes the dossier
/// `invalid`, while a token this run could not finish judging leaves it
/// exactly where it was. Extra evidence must never cost a dossier its verdict.
pub fn summarise(scope: ContainerScope, checks: &[Check], verified: bool) -> Check {
    let (ok, invalid, not_checked) = scope.codes();
    let what = scope.describe();
    if verified {
        return Check::info(
            ok,
            format!(
                "{what} verified: its imprint covers the elements the format requires and its RFC 3161 token checks out"
            ),
        );
    }
    // Evidence *against* the container: the token contradicts what it protects,
    // or is not a token at all.
    let damning = checks.iter().find(|check| {
        check.status == CheckStatus::Failed
            && matches!(
                check.code,
                CheckCode::TimestampImprintMismatch
                    | CheckCode::TimestampTokenParsed
                    | CheckCode::TimestampSignatureInvalid
                    | CheckCode::TimestampTsaCertificateInvalid
            )
    });
    if let Some(check) = damning {
        return Check::failed(invalid, format!("{what} is invalid: {}", check.message));
    }
    // Everything else is a gap in the caller's material rather than a finding
    // about the dossier.
    let reason = checks
        .iter()
        .find(|check| check.status.blocks())
        .map_or_else(
            || "no token was verified".to_owned(),
            |check| check.message.clone(),
        );
    Check::info(
        not_checked,
        format!("{what} was not fully checked: {reason}"),
    )
}

/// The check for a timestamp this build declined to digest at all.
pub fn unsupported_check(scope: ContainerScope, reason: &str) -> Check {
    let (_, _, not_checked) = scope.codes();
    Check::info(
        not_checked,
        format!("{} was not checked: {reason}", scope.describe()),
    )
}

fn is_element(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node.tag_name().namespace() == Some(namespace)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .ok()
}
