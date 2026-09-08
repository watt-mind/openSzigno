//! One `ds:Reference`: parsing, same-document resolution on the validated ID
//! space, the transform allowlist and its application, and digest
//! recomputation.
//!
//! Resolution is strictly same-document and goes through the ID space
//! `openszigno-core` validated, so a duplicate ID is already a parse error and
//! no reference can ever resolve ambiguously or reach the network or the
//! filesystem.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::{Node, NodeId};
use sha2::{Digest as _, Sha256, Sha384, Sha512};

use crate::c14n::{C14nAlgorithm, NodeSet};
use crate::codes::CheckStatus;
use crate::dsig::{
    Context, attribute, decode_base64, direct_child, direct_children, inclusive_prefixes, text_of,
};
use crate::policy::{Digest, Transform};
use crate::report::ReferenceReport;

/// The parsed shape of one `ds:Reference`.
pub(crate) struct Reference {
    pub(crate) index: usize,
    pub(crate) uri: String,
    pub(crate) reference_type: Option<String>,
    pub(crate) transforms: Vec<(String, Vec<String>)>,
    pub(crate) digest_uri: String,
    pub(crate) digest_value: String,
}

/// The effective node set of one `ds:Reference`: the nodes its digest
/// actually covers, once the transform chain has been applied.
///
/// Resolution alone does not answer that question. A transform can *remove*
/// nodes from the set that was dereferenced, and the enveloped-signature
/// transform always does: XMLDSig 1.1 clause 6.6.4 says it "removes the whole
/// `Signature` element containing T from the digest calculation of the
/// `Reference` element containing T". A reference to the whole document that
/// carries it therefore digests nothing inside its own signature — not the
/// `xades:SignedProperties`, not the signature's profile `ds:Object` — and
/// must never be allowed to satisfy a scope requirement about them.
///
/// This is the one place that rule is expressed. The reference-scope check,
/// the countersignature binding and the document-coverage report all decide
/// coverage through [`ReferenceScope::covers`], so the three cannot disagree.
#[derive(Clone, Debug)]
pub struct ReferenceScope {
    /// The node the reference resolved to, and the root of everything it can
    /// cover. `None` when the transform chain is one this build cannot model,
    /// which covers nothing rather than something guessed.
    apex: Option<NodeId>,
    /// Subtrees the transform chain removed from the set.
    excluded: Vec<NodeId>,
    /// The chain ended as an octet stream over the apex's text (`base64`), so
    /// no element structure below the apex is covered.
    octets: bool,
}

impl ReferenceScope {
    /// A scope that covers nothing at all.
    pub const fn nothing() -> Self {
        Self {
            apex: None,
            excluded: Vec::new(),
            octets: false,
        }
    }

    /// Whether this reference's effective node set contains `node`.
    ///
    /// Containment, minus exclusions: `node` is the apex or a descendant of
    /// it, and no removed subtree lies on the path from `node` to the document
    /// root. An exclusion *above* the apex removes the apex itself, so the
    /// whole ancestor chain is examined, not only its part below the apex.
    pub fn covers(&self, node: Node<'_, '_>) -> bool {
        let Some(apex) = self.apex else {
            return false;
        };
        if node
            .ancestors()
            .any(|candidate| self.excluded.contains(&candidate.id()))
        {
            return false;
        }
        if !node.ancestors().any(|candidate| candidate.id() == apex) {
            return false;
        }
        // A `base64` chain digests the decoded text of the apex, so it binds
        // that node's content and nothing about the structure beneath it: a
        // child element of a base64-referenced object is not covered, because
        // rearranging the element tree inside it need not change the octets.
        !self.octets || node.id() == apex
    }
}

/// The effective node set of one resolved reference.
///
/// `signature` is the `ds:Signature` the reference is written in, which is the
/// element the enveloped-signature transform removes — never some other
/// signature, and never the signature a countersignature attests.
pub(crate) fn effective_node_set(
    signature: Node<'_, '_>,
    reference: &Reference,
    resolved: Node<'_, '_>,
) -> ReferenceScope {
    let mut scope = ReferenceScope {
        apex: Some(resolved.id()),
        excluded: Vec::new(),
        octets: false,
    };
    for (uri, _) in &reference.transforms {
        match Transform::from_uri(uri) {
            Some(Transform::EnvelopedSignature) => scope.excluded.push(signature.id()),
            // Canonicalization chooses how the set is serialized, never which
            // nodes are in it.
            Some(Transform::Canonicalization(_)) => {}
            Some(Transform::Base64) => scope.octets = true,
            // Outside the allowlist. The signature already fails
            // `transform_not_allowed`, and what the chain would have selected
            // is unknown, so it is credited with nothing.
            None => return ReferenceScope::nothing(),
        }
    }
    scope
}

/// The effective node set of every reference that resolved, in reference
/// order, for the scope, binding and coverage rules to share.
pub(crate) fn effective_node_sets(
    signature: Node<'_, '_>,
    references: &[Reference],
    resolved: &[Option<Node<'_, '_>>],
) -> Vec<ReferenceScope> {
    references
        .iter()
        .zip(resolved)
        .map(|(reference, node)| match node {
            Some(node) => effective_node_set(signature, reference, *node),
            None => ReferenceScope::nothing(),
        })
        .collect()
}

/// Recompute one reference digest.
///
/// `Ok(false)` is a mismatch; `Err(())` is a transform or canonicalization
/// failure, which is treated as a mismatch by the caller because an
/// unprocessable reference is not a verified one.
pub(crate) fn digest_reference(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    reference: &Reference,
    node: Node<'_, '_>,
) -> Result<bool, ()> {
    enum Value<'a, 'input> {
        Nodes(NodeSet<'a, 'input>),
        Bytes(Vec<u8>),
    }

    // XMLDSig 4.4.3.3: a same-document reference dereferences to a node-set
    // that has already had its comments removed, so a with-comments transform
    // applied afterwards still sees none.
    let mut value = Value::Nodes(
        if node.is_root() {
            NodeSet::document(node)
        } else {
            NodeSet::subtree(node)
        }
        .without_comments(),
    );

    for (uri, prefixes) in &reference.transforms {
        let transform = Transform::from_uri(uri).ok_or(())?;
        value = match (transform, value) {
            (Transform::EnvelopedSignature, Value::Nodes(mut set)) => {
                // XMLDSig 1.1 clause 6.6.4 removes the whole `ds:Signature`
                // containing this reference. When the reference selected
                // something inside that signature, the removal leaves the
                // empty node set: there is nothing left to digest, and this
                // build refuses such a reference rather than digesting the
                // empty octet string, so that what a reference *digests* and
                // what it *covers* (`ReferenceScope`) never disagree.
                if set
                    .apex()
                    .ancestors()
                    .any(|node| node.id() == signature.id())
                {
                    return Err(());
                }
                set.exclude(signature);
                Value::Nodes(set)
            }
            (Transform::Canonicalization(algorithm), Value::Nodes(set)) => Value::Bytes(
                context
                    .backend
                    .canonicalize(context.source, &set, algorithm, prefixes)
                    .map_err(|_| ())?,
            ),
            (Transform::Base64, Value::Nodes(set)) => {
                Value::Bytes(decode_base64(&set.string_value()).ok_or(())?)
            }
            (Transform::Base64, Value::Bytes(bytes)) => {
                Value::Bytes(decode_base64(std::str::from_utf8(&bytes).map_err(|_| ())?).ok_or(())?)
            }
            // A node-set transform after the octet stream has been produced is
            // not something this profile allows.
            (_, Value::Bytes(_)) => return Err(()),
        };
    }

    let octets = match value {
        Value::Bytes(bytes) => bytes,
        // XMLDSig applies the default canonicalization when a reference ends as
        // a node-set.
        Value::Nodes(set) => context
            .backend
            .canonicalize(
                context.source,
                &set,
                C14nAlgorithm::Inclusive { comments: false },
                &[],
            )
            .map_err(|_| ())?,
    };

    let digest = Digest::from_digest_uri(&reference.digest_uri).ok_or(())?;
    let computed = match digest {
        Digest::Sha1 => sha1::Sha1::digest(&octets).to_vec(),
        Digest::Sha256 => Sha256::digest(&octets).to_vec(),
        Digest::Sha384 => Sha384::digest(&octets).to_vec(),
        Digest::Sha512 => Sha512::digest(&octets).to_vec(),
    };
    let expected = decode_base64(&reference.digest_value).ok_or(())?;
    Ok(computed == expected)
}

/// Resolve one `ds:Reference` URI on the ID space `openszigno-core` validated.
///
/// Strictly same-document: `""` is the document root and `#id` is the single
/// node that ID names. Anything else resolves to nothing and is refused
/// upstream as an external reference. Nothing is ever dereferenced.
pub(crate) fn resolve_reference<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    reference: &Reference,
) -> Option<Node<'a, 'input>> {
    if reference.uri.is_empty() {
        return Some(context.root);
    }
    context.ids.get(reference.uri.strip_prefix('#')?).copied()
}

pub(crate) fn parse_reference(node: Node<'_, '_>, index: usize) -> Reference {
    let transforms = direct_child(node, XMLDSIG_NAMESPACE, "Transforms")
        .map(|list| {
            direct_children(list, XMLDSIG_NAMESPACE, "Transform")
                .map(|transform| {
                    (
                        attribute(transform, "Algorithm")
                            .unwrap_or_default()
                            .to_owned(),
                        inclusive_prefixes(transform),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    Reference {
        index,
        uri: attribute(node, "URI").unwrap_or_default().to_owned(),
        reference_type: attribute(node, "Type").map(str::to_owned),
        transforms,
        digest_uri: direct_child(node, XMLDSIG_NAMESPACE, "DigestMethod")
            .and_then(|method| attribute(method, "Algorithm"))
            .unwrap_or_default()
            .to_owned(),
        digest_value: direct_child(node, XMLDSIG_NAMESPACE, "DigestValue")
            .map(text_of)
            .unwrap_or_default(),
    }
}

pub(crate) fn report_reference(
    reference: &Reference,
    node: Option<Node<'_, '_>>,
    status: CheckStatus,
) -> ReferenceReport {
    ReferenceReport {
        index: reference.index,
        uri: sanitize_uri(&reference.uri),
        resolved_to: node.map(element_path),
        digest_algorithm: Digest::from_digest_uri(&reference.digest_uri)
            .map(|digest| digest.as_str().to_owned()),
        transforms: reference
            .transforms
            .iter()
            .map(|(uri, _)| sanitize_uri(uri))
            .collect(),
        status,
    }
}

/// A reference URI comes from untrusted input, so it is bounded and stripped of
/// control characters before it is reported back.
fn sanitize_uri(uri: &str) -> String {
    uri.chars()
        .filter(|character| !character.is_control())
        .take(256)
        .collect()
}

/// A path of element names, so a caller can see *what* was signed without any
/// content leaving the tool.
fn element_path(node: Node<'_, '_>) -> String {
    let mut parts: Vec<String> = Vec::new();
    for element in std::iter::once(node)
        .chain(node.ancestors().skip(1))
        .filter(|candidate| candidate.is_element())
    {
        let name = element.tag_name().name();
        let plain = !name.is_empty()
            && name.len() <= 64
            && name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            });
        parts.push(if plain {
            name.to_owned()
        } else {
            "element".to_owned()
        });
    }
    parts.reverse();
    if parts.is_empty() {
        return "document".to_owned();
    }
    parts.join("/")
}

pub(crate) fn is_known_c14n(uri: &str) -> bool {
    uri.starts_with("http://www.w3.org/TR/2001/REC-xml-c14n")
        || uri.starts_with("http://www.w3.org/2001/10/xml-exc-c14n")
        || uri.starts_with("http://www.w3.org/2006/12/xml-c14n11")
}
