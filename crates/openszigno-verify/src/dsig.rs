//! The XMLDSig core, as the shared context and the small XML helpers every
//! stage of it is built from.
//!
//! The stages themselves live in the modules this one ties together:
//! [`crate::references`] resolves and digests one `ds:Reference`,
//! [`crate::scope`] classifies placement and enforces the mandated reference
//! set, [`crate::countersign`] decides the countersignature binding,
//! [`crate::signature`] drives one `ds:Signature`, and [`crate::coverage`]
//! reports what a signature covers.
//!
//! Reference resolution is strictly same-document and goes through the ID space
//! `openszigno-core` validated, so a duplicate ID is already a parse error and
//! no reference can ever resolve ambiguously or reach the network or the
//! filesystem.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use openszigno_core::roxmltree::Node;

use crate::c14n::{C14nBackend, EXC_C14N_NAMESPACE};
use crate::codes::{Check, Verdict, verdict_of};
use crate::policy::VerifyLimits;

pub use crate::coverage::{SignatureCoverage, covers, signature_coverage};
pub use crate::signature::{SignatureOutcome, TimestampSource, verify_signature};

/// The XAdES namespaces seen in e-dossiers: 1.3.2 in current material, 1.2.2
/// and 1.1.1 in legacy material, 1.4.1 for the archival extensions.
pub const XADES_NAMESPACES: &[&str] = &[
    "http://uri.etsi.org/01903/v1.3.2#",
    "http://uri.etsi.org/01903/v1.2.2#",
    "http://uri.etsi.org/01903/v1.1.1#",
    "http://uri.etsi.org/01903/v1.4.1#",
];

/// Everything one signature needs, gathered once for the whole dossier.
pub struct Context<'a, 'input, 's> {
    pub source: &'s str,
    pub root: Node<'a, 'input>,
    pub ids: &'a BTreeMap<&'a str, Node<'a, 'input>>,
    pub namespace: &'a str,
    /// Every dossier namespace the caller allows, so an `es:SignatureProfile`
    /// is recognised whichever compatible profile declared it.
    pub allowed_namespaces: &'a [String],
    /// Every `ds:Signature` in the dossier, in document order, so a nested
    /// signature can name the index of the signature it is embedded in.
    pub signatures: &'a [Node<'a, 'input>],
    pub backend: &'a dyn C14nBackend,
    pub limits: &'a VerifyLimits,
    /// Whether `--allow-legacy-algorithms` admits SHA-1 for diagnosis.
    pub allow_legacy_algorithms: bool,
}

impl<'a, 'input> Context<'a, 'input, '_> {
    pub(crate) fn root_element(&self) -> Node<'a, 'input> {
        self.root
            .children()
            .find(Node::is_element)
            .unwrap_or(self.root)
    }
}

/// The `PrefixList` of an `ec:InclusiveNamespaces` child, if present.
pub(crate) fn inclusive_prefixes(node: Node<'_, '_>) -> Vec<String> {
    direct_child(node, EXC_C14N_NAMESPACE, "InclusiveNamespaces")
        .and_then(|element| attribute(element, "PrefixList"))
        .map(|list| {
            list.split_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

pub(crate) fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    BASE64.decode(compact.as_bytes()).ok()
}

pub(crate) fn text_of(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect::<String>()
}

pub(crate) fn id_of<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
}

pub(crate) fn attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name)
}

pub(crate) fn direct_children<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    let namespace = namespace.to_owned();
    node.children().filter(move |child| {
        child.is_element()
            && child.tag_name().namespace() == Some(namespace.as_str())
            && child.tag_name().name() == name
    })
}

pub(crate) fn direct_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> Option<Node<'a, 'input>> {
    direct_children(node, namespace, name).next()
}

/// The per-signature verdict, exposed so the caller can fold in stage D.
pub fn signature_verdict(checks: &[Check]) -> Verdict {
    verdict_of(checks)
}
