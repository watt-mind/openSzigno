//! Where a `ds:Signature` sits, and which elements the e-dossier format then
//! mandates that it cover.
//!
//! Placement is classified lexically, before anything is verified, and the
//! mandated reference set that follows from it is this project's strongest
//! defence against XML signature wrapping.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::codes::{Check, CheckCode};
use crate::dsig::{Context, XADES_NAMESPACES, direct_child, direct_children, text_of};
use crate::references::{Reference, effective_node_sets};
use crate::report::SignatureScope;

/// `ds:Reference/@Type` values that announce a `SignedProperties` reference.
///
/// These are corroboration only. Coverage is decided by *what a reference
/// resolves to*, never by what its `Type` attribute claims, because a `Type`
/// an attacker controls must not be able to satisfy a scope requirement, and
/// legacy XAdES 1.2.2 material uses the versioned URI.
const SIGNED_PROPERTIES_TYPES: &[&str] = &[
    "http://uri.etsi.org/01903#SignedProperties",
    "http://uri.etsi.org/01903/v1.1.1#SignedProperties",
    "http://uri.etsi.org/01903/v1.2.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.3.2#SignedProperties",
    "http://uri.etsi.org/01903/v1.4.1#SignedProperties",
];

/// Where one `ds:Signature` sits, and what that placement is bound to.
///
/// The classification is lexical and is made before anything is verified: it
/// decides which mandated reference set applies, and for a nested signature it
/// names the signature that is countersigned.
pub(crate) struct Placement<'a, 'input> {
    pub(crate) scope: SignatureScope,
    /// The enclosing `ds:Signature`, for any nested signature — recognised or
    /// not. `None` for a top-level one.
    pub(crate) enclosing: Option<Node<'a, 'input>>,
    /// The index of `enclosing` in the dossier's signature list.
    pub(crate) enclosing_index: Option<usize>,
    /// Why an unsupported nesting is unsupported, in the tool's own words.
    pub(crate) reason: Option<String>,
}

impl<'a, 'input> Placement<'a, 'input> {
    fn unsupported(
        enclosing: Option<Node<'a, 'input>>,
        enclosing_index: Option<usize>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            scope: SignatureScope::Unknown,
            enclosing,
            enclosing_index,
            reason: Some(reason.into()),
        }
    }

    fn top_level(scope: SignatureScope) -> Self {
        Self {
            scope,
            enclosing: None,
            enclosing_index: None,
            reason: None,
        }
    }
}

/// Enforce the e-dossier reference-scope rule.
///
/// This is the project's strongest defence against signature wrapping and the
/// one check a generic XMLDSig library cannot perform, because it depends on
/// what the container mandates rather than on what the signature claims.
pub(crate) fn reference_scope_check(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    placement: &Placement<'_, '_>,
    xades: Option<Node<'_, '_>>,
    references: &[Reference],
    resolved: &[Option<Node<'_, '_>>],
) -> Check {
    let scope = placement.scope;
    let namespace = context.namespace;
    // Each requirement lists the nodes that would satisfy it. An empty list
    // means the element the container mandates is not in the document at all,
    // which is itself a failure.
    let mut required: Vec<(&'static str, Vec<Node<'_, '_>>)> = Vec::new();
    match scope {
        SignatureScope::Document => {
            let Some(document) = signature.parent() else {
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the signature's containing document could not be determined",
                );
            };
            let profile = direct_child(document, namespace, "DocumentProfile");
            if profile.is_none() {
                // The core parser reports such a document as non-conformant and
                // skips it; without a profile the mandated set is undefined, so
                // the honest answer is that the scope is unknown.
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the containing document has no DocumentProfile, so the mandated reference set is undefined",
                );
            }
            required.push(("es:DocumentProfile", profile.into_iter().collect()));
            required.push((
                "es:Document/ds:Object",
                direct_children(document, XMLDSIG_NAMESPACE, "Object")
                    .find(|object| object.id() != signature.id())
                    .into_iter()
                    .collect(),
            ));
        }
        SignatureScope::Dossier => {
            required.push((
                "es:DossierProfile",
                direct_child(context.root_element(), namespace, "DossierProfile")
                    .into_iter()
                    .collect(),
            ));
            required.push((
                "es:Documents",
                direct_child(context.root_element(), namespace, "Documents")
                    .into_iter()
                    .collect(),
            ));
        }
        SignatureScope::Countersignature => {
            // A countersignature attests the *signature*, not the payload, so
            // its mandated set says nothing about documents: EN 319 132-1
            // clause 5.2.7.2 requires exactly one `ds:Reference` over the
            // embedding signature's `ds:SignatureValue`, and the e-dossier
            // rules for a document or frame signature do not apply to it.
            let Some(parent) = placement.enclosing else {
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the countersigned signature could not be determined",
                );
            };
            let value = direct_child(parent, XMLDSIG_NAMESPACE, "SignatureValue");
            if value.is_none() {
                return Check::unknown(
                    CheckCode::ReferenceScopeUnknown,
                    "the countersigned signature carries no ds:SignatureValue, so the mandated reference set is undefined",
                );
            }
            required.push((
                "the countersigned ds:SignatureValue",
                value.into_iter().collect(),
            ));
        }
        SignatureScope::Unknown => {
            return Check::unknown(
                CheckCode::ReferenceScopeUnknown,
                "the signature placement is not one the e-dossier format defines",
            );
        }
    }

    // The signature's own profile object. Real dossiers reference the
    // `es:SignatureProfile` element itself as often as the `ds:Object` that
    // wraps it, and the profile and qualifying-properties objects occur in
    // either order, so the object is found by content and both nodes satisfy
    // the requirement.
    //
    // A countersignature is required to cover its profile object only when it
    // carries one: the e-dossier format mandates the object for a document or
    // frame signature, and a bare XMLDSIG countersignature under EN 319 132-1
    // has no such element to cover.
    let requires_profile = scope != SignatureScope::Countersignature
        || own_signature_profile(signature, context.allowed_namespaces).is_some();
    if requires_profile {
        required.push((
            "ds:Signature/ds:Object holding es:SignatureProfile",
            signature_profile_nodes(signature, context.allowed_namespaces),
        ));
    }

    if xades.is_some() {
        // Decided by what the references actually digest: a reference whose
        // effective node set contains the `SignedProperties` element covers
        // it, whether it resolved to that element or to an ancestor still
        // holding it after the transforms.
        required.push((
            "xades:SignedProperties",
            signed_properties(signature).into_iter().collect(),
        ));
    }

    // Coverage is membership of a reference's *effective* node set, not of
    // the subtree it resolved to. The enveloped-signature transform removes
    // this signature from the set (XMLDSig 1.1 clause 6.6.4), so a `URI=""`
    // reference carrying it digests nothing inside the signature and covers
    // neither the `xades:SignedProperties` nor the profile object, both of
    // which live there.
    let scopes = effective_node_sets(signature, references, resolved);
    let is_covered = |node: Node<'_, '_>| scopes.iter().any(|scope| scope.covers(node));

    let mut missing: Vec<&'static str> = Vec::new();
    for (name, candidates) in required {
        if !candidates.iter().copied().any(is_covered) {
            missing.push(name);
        }
    }

    if missing.is_empty() {
        return Check::passed(
            CheckCode::ReferenceScopeComplete,
            "every element the e-dossier format requires this signature to cover is covered",
        );
    }
    // A `Type` attribute that announces a SignedProperties reference which does
    // not actually resolve to one is worth saying out loud: it is the shape a
    // wrapping attempt takes.
    let claimed = missing.contains(&"xades:SignedProperties")
        && references.iter().any(|reference| {
            reference
                .reference_type
                .as_deref()
                .is_some_and(|value| SIGNED_PROPERTIES_TYPES.contains(&value))
        });
    let note = if claimed {
        "; a reference declares the SignedProperties Type but does not resolve to one"
    } else {
        ""
    };
    Check::failed(
        CheckCode::ReferenceScopeIncomplete,
        format!("the signature does not cover: {}{note}", missing.join(", ")),
    )
}

/// The nodes that satisfy "the signature's own profile object": the direct
/// `ds:Object` child that contains an `es:SignatureProfile` in any allowed
/// dossier namespace, and that `es:SignatureProfile` element itself.
///
/// Located by content, never by position: the profile object and the
/// qualifying-properties object occur in either order in real dossiers.
fn signature_profile_nodes<'a, 'input>(
    signature: Node<'a, 'input>,
    allowed_namespaces: &[String],
) -> Vec<Node<'a, 'input>> {
    let mut nodes = Vec::new();
    for object in direct_children(signature, XMLDSIG_NAMESPACE, "Object") {
        let profile = object.descendants().find(|node| {
            node.is_element()
                && node.tag_name().name() == "SignatureProfile"
                && node.tag_name().namespace().is_some_and(|namespace| {
                    allowed_namespaces
                        .iter()
                        .any(|allowed| allowed == namespace)
                })
                // A nested countersignature carries its own profile inside
                // this signature's qualifying-properties object; it satisfies
                // that signature's requirement, never this one's.
                && owning_signature(*node) == Some(signature)
        });
        if let Some(profile) = profile {
            nodes.push(object);
            nodes.push(profile);
        }
    }
    if nodes.is_empty() {
        // A bare XMLDSig signature with no `es:SignatureProfile` still has to
        // cover its own object, if it has one.
        nodes.extend(direct_child(signature, XMLDSIG_NAMESPACE, "Object"));
    }
    nodes
}

/// The `xades:SignedProperties` element of this signature, in any XAdES
/// namespace this crate recognises.
fn signed_properties<'a, 'input>(signature: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    signature.descendants().find(|node| {
        node.is_element()
            && node.tag_name().name() == "SignedProperties"
            && node
                .tag_name()
                .namespace()
                .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
            // A countersignature nested in this signature's unsigned
            // properties has signed properties of its own; they are not this
            // signature's, and covering them would satisfy nothing here.
            && owning_signature(*node) == Some(signature)
    })
}

/// Classify one `ds:Signature` by where it sits.
///
/// Four answers, and the fourth is deliberately not a synonym for "invalid":
///
/// - `document` and `dossier` are the two placements the e-dossier
///   specification defines, and are direct children of `es:Document` and
///   `es:Dossier` respectively.
/// - `countersignature` is the XAdES enveloped form: the single `ds:Signature`
///   child of an `xades:CounterSignature` that sits directly in another
///   signature's `xades:UnsignedSignatureProperties`, in any recognised XAdES
///   namespace. ETSI EN 319 132-1 clause 5.2.7.2 (TS 101903 clause 7.2.4.2)
///   defines `CounterSignatureType` as a sequence of exactly one
///   `ds:Signature`, so a `CounterSignature` holding two of them is not a
///   countersignature this build will guess at.
/// - `unknown` is every other nesting: **unsupported placement**, not
///   forgery. The reason is carried so the check message can name it.
pub(crate) fn placement_of<'a, 'input>(
    context: &Context<'a, 'input, '_>,
    signature: Node<'a, 'input>,
) -> Placement<'a, 'input> {
    let enclosing = enclosing_signature(signature);
    let enclosing_index = enclosing.and_then(|node| signature_index(context, node));
    let Some(parent) = signature.parent().filter(Node::is_element) else {
        return Placement::unsupported(
            enclosing,
            enclosing_index,
            "the signature has no element parent",
        );
    };

    if let Some(enclosing) = enclosing {
        return nested_placement(parent, enclosing, enclosing_index);
    }

    if parent.tag_name().namespace() != Some(context.namespace) {
        return Placement::unsupported(
            None,
            None,
            "the signature is not a direct child of es:Document or es:Dossier",
        );
    }
    match parent.tag_name().name() {
        "Document" => Placement::top_level(SignatureScope::Document),
        "Dossier" => Placement::top_level(SignatureScope::Dossier),
        _ => Placement::unsupported(
            None,
            None,
            "the signature is not a direct child of es:Document or es:Dossier",
        ),
    }
}

/// Classify a `ds:Signature` that sits inside another one.
fn nested_placement<'a, 'input>(
    parent: Node<'a, 'input>,
    enclosing: Node<'a, 'input>,
    enclosing_index: Option<usize>,
) -> Placement<'a, 'input> {
    let unsupported =
        |reason: &str| Placement::unsupported(Some(enclosing), enclosing_index, reason.to_owned());
    if !is_xades(parent, "CounterSignature") {
        return unsupported(
            "the signature is nested inside another signature but is not the child of a xades:CounterSignature",
        );
    }
    let siblings = direct_children(parent, XMLDSIG_NAMESPACE, "Signature").count();
    if siblings != 1 {
        // EN 319 132-1 clause 5.2.7.2: `CounterSignatureType` is a sequence of
        // exactly one `ds:Signature`. Two of them leave two candidate parents
        // and no rule for choosing, so nothing is guessed.
        return unsupported(
            "the xades:CounterSignature holds more than one ds:Signature, so which signature each one countersigns is ambiguous",
        );
    }
    let Some(properties) = parent.parent().filter(Node::is_element) else {
        return unsupported("the xades:CounterSignature has no element parent");
    };
    if !is_xades(properties, "UnsignedSignatureProperties") {
        return unsupported(
            "the xades:CounterSignature is not inside a xades:UnsignedSignatureProperties",
        );
    }
    // The properties block has to belong to the signature the countersignature
    // is lexically inside, or the "parent" it names is not the one it sits in.
    if enclosing_signature(properties) != Some(enclosing) {
        return unsupported(
            "the xades:CounterSignature is not inside the enclosing signature's own unsigned properties",
        );
    }
    if enclosing_index.is_none() {
        return unsupported(
            "the countersigned signature was not among the signatures this run examined",
        );
    }
    Placement {
        scope: SignatureScope::Countersignature,
        enclosing: Some(enclosing),
        enclosing_index,
        reason: None,
    }
}

/// The nearest `ds:Signature` strictly above a node.
fn enclosing_signature<'a, 'input>(node: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    node.ancestors().skip(1).find(|candidate| {
        candidate.is_element()
            && candidate.tag_name().namespace() == Some(XMLDSIG_NAMESPACE)
            && candidate.tag_name().name() == "Signature"
    })
}

/// The `ds:Signature` a node belongs to: itself when it is one, else the
/// nearest one above it.
pub(crate) fn owning_signature<'a, 'input>(node: Node<'a, 'input>) -> Option<Node<'a, 'input>> {
    node.ancestors().find(|candidate| {
        candidate.is_element()
            && candidate.tag_name().namespace() == Some(XMLDSIG_NAMESPACE)
            && candidate.tag_name().name() == "Signature"
    })
}

/// This signature's index in the dossier's signature list.
pub(crate) fn signature_index(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
) -> Option<usize> {
    context
        .signatures
        .iter()
        .position(|candidate| candidate.id() == signature.id())
}

/// Whether an element is `name` in any recognised XAdES namespace.
fn is_xades(node: Node<'_, '_>, name: &str) -> bool {
    node.is_element()
        && node.tag_name().name() == name
        && node
            .tag_name()
            .namespace()
            .is_some_and(|namespace| XADES_NAMESPACES.contains(&namespace))
}

/// The signed `es:SignatureProfile/es:Type` of one signature, lowercased.
///
/// Read from the signature's *own* profile object only: a nested
/// countersignature carries its own profile inside the enclosing signature's
/// qualifying-properties object, and letting that answer for the enclosing
/// signature would let a nested element relabel the signature it was dropped
/// into.
pub(crate) fn signature_profile_type(
    signature: Node<'_, '_>,
    allowed_namespaces: &[String],
) -> Option<String> {
    let profile = own_signature_profile(signature, allowed_namespaces)?;
    let node = profile.children().find(|child| {
        child.is_element()
            && child.tag_name().name() == "Type"
            && child.tag_name().namespace() == profile.tag_name().namespace()
    })?;
    Some(text_of(node).trim().to_lowercase())
}

/// The `es:SignatureProfile` element this signature carries in one of its own
/// direct `ds:Object` children, in any allowed dossier namespace.
fn own_signature_profile<'a, 'input>(
    signature: Node<'a, 'input>,
    allowed_namespaces: &[String],
) -> Option<Node<'a, 'input>> {
    direct_children(signature, XMLDSIG_NAMESPACE, "Object").find_map(|object| {
        object.descendants().find(|node| {
            node.is_element()
                && node.tag_name().name() == "SignatureProfile"
                && node.tag_name().namespace().is_some_and(|namespace| {
                    allowed_namespaces
                        .iter()
                        .any(|allowed| allowed == namespace)
                })
                // A profile that belongs to a countersignature nested in this
                // signature's unsigned properties is that signature's, not
                // this one's.
                && owning_signature(*node) == Some(signature)
        })
    })
}
