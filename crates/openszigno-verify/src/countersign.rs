//! Countersignature detection, the binding check, and the role a signature is
//! reported with.
//!
//! Both recognised shapes are decided by *what the references resolve to*,
//! never by an attribute a signer controls.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::codes::{Check, CheckCode};
use crate::dsig::{Context, direct_child};
use crate::references::Reference;
use crate::report::{SignatureRole, SignatureScope};
use crate::scope::{Placement, owning_signature, signature_index, signature_profile_type};

/// `ds:Reference/@Type` values that announce a countersignature reference.
///
/// ETSI EN 319 132-1 clause 5.2.7.1 (and TS 101903 clause 7.2.4.1 before it)
/// define `http://uri.etsi.org/01903#CountersignedSignature` and say its
/// "only purpose ... is to serve as an easy identification of a signature as
/// being a countersignature". It is corroboration only, exactly like the
/// `SignedProperties` `Type`: **resolution decides** what a reference covers,
/// because an attacker writes the attribute. The versioned spellings are
/// listed because legacy material uses them.
const COUNTERSIGNED_SIGNATURE_TYPES: &[&str] = &[
    "http://uri.etsi.org/01903#CountersignedSignature",
    "http://uri.etsi.org/01903/v1.1.1#CountersignedSignature",
    "http://uri.etsi.org/01903/v1.2.2#CountersignedSignature",
    "http://uri.etsi.org/01903/v1.3.2#CountersignedSignature",
    "http://uri.etsi.org/01903/v1.4.1#CountersignedSignature",
];

/// `es:SignatureProfile/es:Type` values that declare a countersignature.
///
/// The e-dossier specification, clause 3.2.1.3.4.1.3, allows `signature` and
/// `countersignature` plus the deprecated Hungarian spellings the schema keeps
/// for compatibility with earlier versions. The declaration is *signed* — the
/// profile object is inside the mandated reference set — but it still only
/// declares a role: the binding is decided by what the references resolve to.
const COUNTERSIGNATURE_PROFILE_TYPES: &[&str] = &["countersignature", "ellenjegyzés"];

/// What the countersignature classification concluded about one signature.
pub(crate) struct Binding {
    pub(crate) role: SignatureRole,
    /// The indexes of every signature whose `ds:SignatureValue` this
    /// signature's references resolve to, ascending and deduplicated.
    pub(crate) countersigns: Vec<usize>,
    /// The `countersignature_binding_*` check, when one applies.
    pub(crate) check: Option<Check>,
}

impl Binding {
    const fn none() -> Self {
        Self {
            role: SignatureRole::Signature,
            countersigns: Vec::new(),
            check: None,
        }
    }
}

/// Decide the countersignature role and the binding check.
///
/// Two shapes are recognised, and both are decided by **what the references
/// resolve to**, never by an attribute:
///
/// - the XAdES enveloped form (`placement: countersignature`), which must
///   reference the `ds:SignatureValue` of the signature it is embedded in;
/// - the e-dossier form, an ordinary document- or dossier-level signature
///   whose signed `es:SignatureProfile/es:Type` says `countersignature` and
///   whose references resolve to another signature's `ds:SignatureValue`
///   (e-dossier specification clauses 3.2.1.3.1 and 3.2.1.3.4.1.3).
pub(crate) fn countersignature_binding(
    context: &Context<'_, '_, '_>,
    signature: Node<'_, '_>,
    placement: &Placement<'_, '_>,
    references: &[Reference],
    resolved: &[Option<Node<'_, '_>>],
) -> Binding {
    // Every other signature whose `ds:SignatureValue` a reference resolved to.
    let mut countersigns: Vec<usize> = Vec::new();
    let mut foreign_values = 0usize;
    let mut parent_value_covered = false;
    let parent_value = placement
        .enclosing
        .and_then(|parent| direct_child(parent, XMLDSIG_NAMESPACE, "SignatureValue"));
    for node in resolved.iter().flatten() {
        if !(node.is_element()
            && node.tag_name().namespace() == Some(XMLDSIG_NAMESPACE)
            && node.tag_name().name() == "SignatureValue")
        {
            continue;
        }
        let Some(owner) = owning_signature(*node) else {
            continue;
        };
        if owner.id() == signature.id() {
            // Its own value. A signature cannot countersign itself.
            continue;
        }
        if parent_value.is_some_and(|value| value.id() == node.id()) {
            parent_value_covered = true;
        } else {
            foreign_values += 1;
        }
        if let Some(index) = signature_index(context, owner)
            && !countersigns.contains(&index)
        {
            countersigns.push(index);
        }
    }
    countersigns.sort_unstable();

    let declared_type = references.iter().any(|reference| {
        reference
            .reference_type
            .as_deref()
            .is_some_and(|value| COUNTERSIGNED_SIGNATURE_TYPES.contains(&value))
    });

    match placement.scope {
        SignatureScope::Countersignature => {
            let parent = placement.enclosing_index.unwrap_or_default();
            let check = if parent_value_covered {
                let note = if declared_type {
                    ", and declares the CountersignedSignature Type"
                } else {
                    ""
                };
                Check::passed(
                    CheckCode::CountersignatureBindingOk,
                    format!(
                        "the countersignature references the ds:SignatureValue of signature {parent}, the signature it is embedded in{note}"
                    ),
                )
            } else if foreign_values > 0 {
                Check::failed(
                    CheckCode::CountersignatureBindingMismatch,
                    format!(
                        "the countersignature resolves to the ds:SignatureValue of another signature, not of signature {parent}, the one it is embedded in"
                    ),
                )
            } else {
                Check::failed(
                    CheckCode::CountersignatureBindingMissing,
                    format!(
                        "the countersignature does not reference the ds:SignatureValue of signature {parent}, the signature it is embedded in"
                    ),
                )
            };
            Binding {
                role: SignatureRole::Countersignature,
                countersigns,
                check: Some(check),
            }
        }
        SignatureScope::Document | SignatureScope::Dossier => {
            let declared_profile = signature_profile_type(signature, context.allowed_namespaces)
                .is_some_and(|value| COUNTERSIGNATURE_PROFILE_TYPES.contains(&value.as_str()));
            if !declared_profile {
                return Binding::none();
            }
            let check = if countersigns.is_empty() {
                Check::failed(
                    CheckCode::CountersignatureBindingMissing,
                    "the signed es:SignatureProfile declares a countersignature, but no reference resolves to another signature's ds:SignatureValue",
                )
            } else {
                Check::passed(
                    CheckCode::CountersignatureBindingOk,
                    format!(
                        "the countersignature references the ds:SignatureValue of {} other signature(s)",
                        countersigns.len()
                    ),
                )
            };
            Binding {
                role: SignatureRole::Countersignature,
                countersigns,
                check: Some(check),
            }
        }
        // The placement already failed; nothing is concluded about a role.
        SignatureScope::Unknown => Binding::none(),
    }
}
