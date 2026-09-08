//! What a signature's timestamps cover, and the forms this build refuses.
//!
//! A `xades:SignatureTimeStamp` covers the canonicalized `ds:SignatureValue`
//! **element**, not the Base64 text and not its digest. Collecting one means
//! canonicalizing that element under the algorithm the timestamp names, and
//! refusing by name every data-selection form whose target this build cannot
//! compute the imprint over.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::c14n::{C14nAlgorithm, NodeSet};
use crate::dsig::{Context, attribute, decode_base64, direct_child, inclusive_prefixes, text_of};
use crate::tsa::TimestampKind;
use crate::xades::{self, XadesProperties};

/// One timestamp token found in a signature, and the data it covers.
pub struct TimestampSource {
    pub kind: TimestampKind,
    pub token: Vec<u8>,
    /// The canonicalized octets the token's message imprint must match.
    pub imprint_input: Vec<u8>,
    /// Set when the timestamp uses a form this build does not implement, in
    /// which case it is reported as unchecked rather than verified.
    pub unsupported: Option<String>,
}

/// Collect the signature timestamps and canonicalize what each one covers.
///
/// A `xades:SignatureTimeStamp` covers the canonicalized `ds:SignatureValue`
/// **element**, not the Base64 text and not its digest. The canonicalization
/// algorithm is the one the timestamp element names, defaulting to inclusive
/// C14N as XAdES prescribes. The `Include` and `ReferenceInfo` forms select
/// other data and are not implemented, so a timestamp that uses one is
/// reported as unchecked rather than verified against the wrong bytes.
/// Whether a `xades:SignatureTimeStamp` selects data this build cannot compute
/// the imprint over, and why.
///
/// The implicit form — no data-selection child at all — covers the
/// `ds:SignatureValue` element, which is what XAdES prescribes for a signature
/// timestamp. The explicit `xades:Include` form (EN 319 132-1, XAdES 1.3.2 and
/// 1.4.1) is accepted for exactly the case where it says the same thing: every
/// `Include` is a same-document `#id` reference resolving, through the
/// validated ID space, to *this signature's own* `ds:SignatureValue`. The
/// `referencedData` attribute is not consulted, because for this target it
/// cannot change what is digested.
///
/// Any other target set — another element, a URI that does not resolve, an
/// external reference, or the `ReferenceInfo`, `HashDataInfo` and
/// `XMLTimeStamp` forms — is refused by name rather than digested over the
/// wrong bytes.
pub(super) fn unsupported_form(
    context: &Context<'_, '_, '_>,
    timestamp: Node<'_, '_>,
    signature_value: Node<'_, '_>,
) -> Option<String> {
    for child in timestamp.children().filter(Node::is_element) {
        match child.tag_name().name() {
            "ReferenceInfo" | "HashDataInfo" | "XMLTimeStamp" => {
                return Some(
                    "the timestamp selects its data with a form this build does not implement"
                        .to_owned(),
                );
            }
            "Include" => {
                let uri = attribute(child, "URI").unwrap_or_default();
                let Some(id) = uri.strip_prefix('#').filter(|id| !id.is_empty()) else {
                    return Some(
                        "the timestamp includes a URI that is not a same-document reference"
                            .to_owned(),
                    );
                };
                match context.ids.get(id) {
                    Some(node) if node.id() == signature_value.id() => {}
                    _ => {
                        return Some(
                            "the timestamp includes data other than this signature's ds:SignatureValue"
                                .to_owned(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn collect_timestamps(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    properties: &XadesProperties<'_, '_>,
) -> Vec<TimestampSource> {
    let Some(signature_value) = direct_child(signature, XMLDSIG_NAMESPACE, "SignatureValue") else {
        return Vec::new();
    };
    let mut sources = Vec::new();
    for node in properties
        .signature_timestamps
        .iter()
        .take(context.limits.max_timestamps_per_signature)
    {
        let unsupported = unsupported_form(context, *node, signature_value);

        let tokens: Vec<Vec<u8>> = xades::xades_children(*node, "EncapsulatedTimeStamp")
            .filter_map(|element| decode_base64(&text_of(element)))
            .take(2)
            .collect();
        let (token, unsupported) = match (tokens.len(), unsupported) {
            (_, Some(reason)) => (tokens.first().cloned().unwrap_or_default(), Some(reason)),
            (1, None) => (tokens[0].clone(), None),
            (0, None) => (
                Vec::new(),
                Some("the timestamp carries no decodable xades:EncapsulatedTimeStamp".to_owned()),
            ),
            (_, None) => (
                tokens[0].clone(),
                Some(
                    "the timestamp carries more than one token, which this build does not process"
                        .to_owned(),
                ),
            ),
        };

        let algorithm = xades::ds_child(*node, "CanonicalizationMethod")
            .and_then(|method| {
                attribute(method, "Algorithm").map(|uri| (method, C14nAlgorithm::from_uri(uri)))
            })
            .map_or(
                Some((C14nAlgorithm::Inclusive { comments: false }, Vec::new())),
                |(method, algorithm)| {
                    algorithm.map(|algorithm| (algorithm, inclusive_prefixes(method)))
                },
            );
        let (imprint_input, unsupported) = match algorithm {
            Some((algorithm, prefixes)) => {
                match context.backend.canonicalize(
                    context.source,
                    &NodeSet::subtree(signature_value),
                    algorithm,
                    &prefixes,
                ) {
                    Ok(octets) => (octets, unsupported),
                    Err(_) => (
                        Vec::new(),
                        unsupported.or(Some(
                            "the ds:SignatureValue could not be canonicalized for the timestamp"
                                .to_owned(),
                        )),
                    ),
                }
            }
            None => (
                Vec::new(),
                unsupported.or(Some(
                    "the timestamp names a canonicalization algorithm this build does not implement"
                        .to_owned(),
                )),
            ),
        };

        sources.push(TimestampSource {
            kind: TimestampKind::SignatureTimestamp,
            token,
            imprint_input,
            unsupported,
        });
    }
    sources
}
