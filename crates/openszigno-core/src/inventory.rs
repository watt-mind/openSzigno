//! The bounded, unverified signature inventory built while parsing.
//!
//! Everything this module produces is *claimed* metadata read straight out of
//! the XML: element names, attribute values, and element counts. Nothing here
//! is verified, nothing is decoded, no certificate is parsed, and no reference
//! is ever resolved or dereferenced. A caller that needs a cryptographic
//! statement uses `openszigno-verify`, never this inventory.
//!
//! Every list is bounded, because a dossier is untrusted input: a signature
//! carrying ten thousand references costs the same as one carrying two.

use roxmltree::Node;

use crate::{
    MAX_INVENTORIED_DIGEST_METHODS, MAX_INVENTORIED_REFERENCE_URIS, MAX_INVENTORIED_SIGNATURES,
    MAX_INVENTORIED_TIMESTAMPS, MAX_INVENTORIED_XADES_PROPERTIES, SignatureEvidence,
    SignaturePlacement, SignatureSummary, StructuralWarning, StructuralWarningCode,
    TimestampPlacement, TimestampSummary, XADES_NAMESPACES, XMLDSIG_NAMESPACE,
};

/// The XAdES containers whose element children are qualifying properties.
const PROPERTY_CONTAINERS: &[&str] = &[
    "SignedSignatureProperties",
    "SignedDataObjectProperties",
    "UnsignedSignatureProperties",
    "UnsignedDataObjectProperties",
];

/// Build the inventory of every `ds:Signature` and every `es:TimeStamp`.
///
/// `documents` maps the `es:Document` nodes that produced a parsed document to
/// that document's index, so a document-level signature can name the index a
/// caller sees rather than a source position.
pub(crate) fn build<'a, 'input>(
    root: Node<'a, 'input>,
    namespace: &str,
    documents: &[(Node<'a, 'input>, usize)],
    warnings: &mut Vec<StructuralWarning>,
) -> (Vec<SignatureSummary>, Vec<TimestampSummary>) {
    let signature_nodes: Vec<_> = root
        .descendants()
        .filter(|node| is_signature(*node))
        .collect();
    let truncated_signatures = signature_nodes.len() > MAX_INVENTORIED_SIGNATURES;
    let signatures = signature_nodes
        .into_iter()
        .take(MAX_INVENTORIED_SIGNATURES)
        .map(|node| signature_summary(node, root, namespace, documents))
        .collect();

    let timestamp_nodes: Vec<_> = root
        .descendants()
        .filter(|node| is_element(*node, namespace, "TimeStamp"))
        .collect();
    let truncated_timestamps = timestamp_nodes.len() > MAX_INVENTORIED_TIMESTAMPS;
    let timestamps = timestamp_nodes
        .into_iter()
        .take(MAX_INVENTORIED_TIMESTAMPS)
        .map(|node| timestamp_summary(node, root, namespace, documents))
        .collect();

    if truncated_signatures {
        warnings.push(StructuralWarning {
            code: StructuralWarningCode::SignatureInventoryTruncated,
            message: format!(
                "only the first {MAX_INVENTORIED_SIGNATURES} signatures are described in the inventory"
            ),
        });
    }
    if truncated_timestamps {
        warnings.push(StructuralWarning {
            code: StructuralWarningCode::SignatureInventoryTruncated,
            message: format!(
                "only the first {MAX_INVENTORIED_TIMESTAMPS} timestamps are described in the inventory"
            ),
        });
    }
    (signatures, timestamps)
}

fn signature_summary<'a, 'input>(
    signature: Node<'a, 'input>,
    root: Node<'a, 'input>,
    namespace: &str,
    documents: &[(Node<'a, 'input>, usize)],
) -> SignatureSummary {
    let (placement, document_index, parent_signature_id) =
        signature_placement(signature, root, namespace, documents);

    let signed_info = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo");
    let canonicalization_method = signed_info
        .and_then(|node| direct_child(node, XMLDSIG_NAMESPACE, "CanonicalizationMethod"))
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(plain_uri);
    let signature_method = signed_info
        .and_then(|node| direct_child(node, XMLDSIG_NAMESPACE, "SignatureMethod"))
        .and_then(|node| node.attribute("Algorithm"))
        .and_then(plain_uri);

    let mut reference_count = 0;
    let mut reference_uris = Vec::new();
    let mut digest_methods: Vec<String> = Vec::new();
    if let Some(signed_info) = signed_info {
        for reference in signed_info
            .children()
            .filter(|child| is_element(*child, XMLDSIG_NAMESPACE, "Reference"))
        {
            reference_count += 1;
            if reference_uris.len() < MAX_INVENTORIED_REFERENCE_URIS
                && let Some(uri) = reference.attribute("URI").and_then(same_document_fragment)
            {
                reference_uris.push(uri);
            }
            if let Some(algorithm) = direct_child(reference, XMLDSIG_NAMESPACE, "DigestMethod")
                .and_then(|node| node.attribute("Algorithm"))
                .and_then(plain_uri)
                && digest_methods.len() < MAX_INVENTORIED_DIGEST_METHODS
                && !digest_methods.contains(&algorithm)
            {
                digest_methods.push(algorithm);
            }
        }
    }

    let mut key_info_certificates = 0;
    for key_info in signature
        .children()
        .filter(|child| is_element(*child, XMLDSIG_NAMESPACE, "KeyInfo"))
    {
        walk_own(key_info, &mut |node| {
            if is_dsig(node, "X509Certificate") {
                key_info_certificates += 1;
            }
        });
    }

    let mut xades_namespace = None;
    let mut xades_properties: Vec<String> = Vec::new();
    let mut evidence = SignatureEvidence::default();
    let mut claimed_signing_time = None;
    walk_own(signature, &mut |node| {
        let Some(local) = xades_local_name(node) else {
            return;
        };
        match local {
            "QualifyingProperties" if xades_namespace.is_none() => {
                xades_namespace = node.tag_name().namespace().map(str::to_owned);
            }
            "EncapsulatedX509Certificate" => evidence.certificates += 1,
            "EncapsulatedCRLValue" => evidence.crls += 1,
            "EncapsulatedOCSPValue" => evidence.ocsp_responses += 1,
            "SignatureTimeStamp" => evidence.signature_timestamps += 1,
            "ArchiveTimeStamp" => evidence.archive_timestamps += 1,
            "SigningTime" if claimed_signing_time.is_none() => {
                claimed_signing_time = plain_time(&direct_text(node));
            }
            _ => {}
        }
        if in_property_container(node)
            && let Some(name) = plain_name(local)
            && xades_properties.len() < MAX_INVENTORIED_XADES_PROPERTIES
            && !xades_properties.contains(&name)
        {
            xades_properties.push(name);
        }
    });

    SignatureSummary {
        id: plain_name_of_id(signature),
        placement,
        document_index,
        parent_signature_id,
        canonicalization_method,
        signature_method,
        digest_methods,
        reference_count,
        reference_uris,
        xades_namespace,
        xades_properties,
        evidence,
        claimed_signing_time,
        key_info_certificates,
    }
}

/// Where a `ds:Signature` sits, with the document index or the enclosing
/// signature's Id when the placement names one.
fn signature_placement<'a, 'input>(
    signature: Node<'a, 'input>,
    root: Node<'a, 'input>,
    namespace: &str,
    documents: &[(Node<'a, 'input>, usize)],
) -> (SignaturePlacement, Option<usize>, Option<String>) {
    for ancestor in signature.ancestors().skip(1) {
        if is_signature(ancestor) {
            return (
                SignaturePlacement::NestedInSignature,
                None,
                plain_name_of_id(ancestor),
            );
        }
        if is_element(ancestor, namespace, "Document") {
            return (
                SignaturePlacement::Document,
                document_index(ancestor, documents),
                None,
            );
        }
        if ancestor == root {
            break;
        }
    }
    if signature.parent() == Some(root) {
        return (SignaturePlacement::Dossier, None, None);
    }
    (SignaturePlacement::Other, None, None)
}

fn timestamp_summary<'a, 'input>(
    timestamp: Node<'a, 'input>,
    root: Node<'a, 'input>,
    namespace: &str,
    documents: &[(Node<'a, 'input>, usize)],
) -> TimestampSummary {
    let parent = timestamp.parent();
    let (placement, index) = if parent == Some(root) {
        (TimestampPlacement::Dossier, None)
    } else if let Some(document) = parent.filter(|node| is_element(*node, namespace, "Document")) {
        (
            TimestampPlacement::Document,
            document_index(document, documents),
        )
    } else {
        (TimestampPlacement::Other, None)
    };

    let mut include_count = 0;
    let mut has_token = false;
    walk_own(timestamp, &mut |node| match xades_local_name(node) {
        Some("Include") => include_count += 1,
        Some("EncapsulatedTimeStamp") => has_token |= !direct_text(node).is_empty(),
        _ => {}
    });

    TimestampSummary {
        placement,
        document_index: index,
        include_count,
        has_token,
    }
}

fn document_index<'a, 'input>(
    node: Node<'a, 'input>,
    documents: &[(Node<'a, 'input>, usize)],
) -> Option<usize> {
    documents
        .iter()
        .find(|(document, _)| *document == node)
        .map(|(_, index)| *index)
}

/// Visit every element of `root`'s subtree in document order, without ever
/// descending into a nested `ds:Signature`. A countersignature therefore
/// contributes nothing to the summary of the signature that carries it; it is
/// inventoried in its own right instead.
fn walk_own<'a, 'input>(root: Node<'a, 'input>, visit: &mut impl FnMut(Node<'a, 'input>)) {
    let mut stack: Vec<Node<'a, 'input>> = Vec::new();
    push_children(&mut stack, root);
    while let Some(node) = stack.pop() {
        if is_signature(node) {
            continue;
        }
        visit(node);
        push_children(&mut stack, node);
    }
}

fn push_children<'a, 'input>(stack: &mut Vec<Node<'a, 'input>>, node: Node<'a, 'input>) {
    let start = stack.len();
    stack.extend(node.children().filter(Node::is_element));
    stack[start..].reverse();
}

fn in_property_container(node: Node<'_, '_>) -> bool {
    node.parent()
        .and_then(xades_local_name)
        .is_some_and(|local| PROPERTY_CONTAINERS.contains(&local))
}

/// The local name of an element in one of the recognised XAdES namespaces.
fn xades_local_name<'a>(node: Node<'a, '_>) -> Option<&'a str> {
    if !node.is_element() {
        return None;
    }
    let namespace = node.tag_name().namespace()?;
    XADES_NAMESPACES
        .contains(&namespace)
        .then(|| node.tag_name().name())
}

fn direct_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|child| is_element(*child, namespace, name))
}

fn direct_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn is_signature(node: Node<'_, '_>) -> bool {
    is_dsig(node, "Signature")
}

fn is_dsig(node: Node<'_, '_>, name: &str) -> bool {
    is_element(node, XMLDSIG_NAMESPACE, name)
}

fn is_element(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

fn plain_name_of_id(node: Node<'_, '_>) -> Option<String> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
        .and_then(plain_name)
}

/// An element or ID name is echoed only when it looks like one, so that
/// untrusted input cannot smuggle arbitrary text through the inventory.
fn plain_name(value: &str) -> Option<String> {
    let plain = !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    plain.then(|| value.to_owned())
}

/// An algorithm URI is echoed only when it is a bounded, printable ASCII
/// token, which every algorithm identifier in the relevant specifications is.
fn plain_uri(value: &str) -> Option<String> {
    let plain = !value.is_empty()
        && value.len() <= 255
        && value.chars().all(|character| character.is_ascii_graphic());
    plain.then(|| value.to_owned())
}

/// A claimed signing time is echoed only when it is a bounded token made of
/// the characters an XML dateTime uses. The value is never parsed: it is what
/// the signature claims, not a fact.
fn plain_time(value: &str) -> Option<String> {
    let plain = !value.is_empty()
        && value.len() <= 64
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | ':' | '+' | '.')
        });
    plain.then(|| value.to_owned())
}

/// A same-document reference, and nothing else.
///
/// An empty `URI` (the whole document) is reported as an empty string, a
/// fragment as `#id`. Anything that could name an external resource is left
/// out entirely; `reference_count` still counts it, so a shorter
/// `reference_uris` list is itself the signal that references were not listed.
fn same_document_fragment(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(String::new());
    }
    let fragment = value.strip_prefix('#')?;
    let plain = !fragment.is_empty()
        && fragment.len() <= 128
        && fragment.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':')
        });
    plain.then(|| format!("#{fragment}"))
}
