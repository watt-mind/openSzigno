//! Stage A1's structural pass: XMLDSig cardinality and element order.
//!
//! The rest of stage A1 looks each critical child up by name and takes the
//! first match. That is only safe once something has established that there
//! *is* exactly one match, in the position the schema puts it: otherwise a
//! second `ds:SignatureValue` appended after the real one, or a
//! `ds:DigestValue` placed before its `ds:DigestMethod`, would be read by one
//! consumer and ignored by another.
//!
//! This module walks the element children of `ds:Signature`, its
//! `ds:SignedInfo`, and each `ds:Reference` in document order and checks the
//! sequence against the XMLDSig schema:
//!
//! | Element | Required sequence |
//! | --- | --- |
//! | `ds:Signature` | one `ds:SignedInfo`, one `ds:SignatureValue`, at most one `ds:KeyInfo`, then zero or more `ds:Object` |
//! | `ds:SignedInfo` | one `ds:CanonicalizationMethod`, one `ds:SignatureMethod`, then one or more `ds:Reference` |
//! | `ds:Reference` | at most one `ds:Transforms`, one `ds:DigestMethod`, one `ds:DigestValue` |
//!
//! Only duplication, ordering, and unexpected children are decided here. A
//! required element that is simply absent stays the business of
//! [`super::signed_info::parse`], so the messages that case already reports
//! are unchanged.
//!
//! The schema's extension points are respected rather than papered over: the
//! content of `ds:Object` and of `ds:KeyInfo` is open and is never inspected
//! here, the `Id` attribute of `ds:Signature` is untouched, and whitespace
//! text and comments between children are ignored. Foreign-namespace elements
//! are *not* an extension point for the three elements above, so one appearing
//! as their direct child is a structure error.

use openszigno_core::XMLDSIG_NAMESPACE;
use openszigno_core::roxmltree::Node;

use crate::codes::{Check, CheckCode};
use crate::dsig::{direct_child, direct_children};

/// One position in a schema sequence: the element name, and whether the
/// schema lets it repeat there.
struct Slot {
    name: &'static str,
    repeatable: bool,
}

const fn once(name: &'static str) -> Slot {
    Slot {
        name,
        repeatable: false,
    }
}

const fn many(name: &'static str) -> Slot {
    Slot {
        name,
        repeatable: true,
    }
}

const SIGNATURE: &[Slot] = &[
    once("SignedInfo"),
    once("SignatureValue"),
    once("KeyInfo"),
    many("Object"),
];

const SIGNED_INFO: &[Slot] = &[
    once("CanonicalizationMethod"),
    once("SignatureMethod"),
    many("Reference"),
];

const REFERENCE: &[Slot] = &[
    once("Transforms"),
    once("DigestMethod"),
    once("DigestValue"),
];

/// Check the cardinality and order of every XMLDSig core element stage A1
/// goes on to read.
///
/// The failing check is returned rather than pushed, so the caller reports it
/// exactly where it reports every other stage A1 failure.
pub(super) fn validate(signature: Node<'_, '_>) -> Result<(), Check> {
    check_sequence(signature, "ds:Signature", SIGNATURE)?;
    let Some(signed_info) = direct_child(signature, XMLDSIG_NAMESPACE, "SignedInfo") else {
        return Ok(());
    };
    check_sequence(signed_info, "ds:SignedInfo", SIGNED_INFO)?;
    for (index, reference) in
        direct_children(signed_info, XMLDSIG_NAMESPACE, "Reference").enumerate()
    {
        check_sequence(reference, &format!("ds:Reference {index}"), REFERENCE)?;
    }
    Ok(())
}

/// Walk one element's children in document order against `slots`.
///
/// Text and comment nodes are skipped, so whitespace-formatted signatures read
/// the same as compact ones.
fn check_sequence(parent: Node<'_, '_>, label: &str, slots: &[Slot]) -> Result<(), Check> {
    let mut seen = vec![0usize; slots.len()];
    let mut furthest: Option<usize> = None;
    for child in parent.children().filter(Node::is_element) {
        let Some(index) = slot_of(child, slots) else {
            return Err(invalid(format!(
                "{label} has an unexpected child element {}",
                describe(child)
            )));
        };
        if seen[index] > 0 && !slots[index].repeatable {
            return Err(invalid(format!(
                "{label} has more than one ds:{}",
                slots[index].name
            )));
        }
        if furthest.is_some_and(|reached| index < reached) {
            return Err(invalid(format!(
                "{label} has ds:{} out of order",
                slots[index].name
            )));
        }
        seen[index] += 1;
        furthest = Some(index);
    }
    Ok(())
}

fn slot_of(child: Node<'_, '_>, slots: &[Slot]) -> Option<usize> {
    let tag = child.tag_name();
    if tag.namespace() != Some(XMLDSIG_NAMESPACE) {
        return None;
    }
    slots.iter().position(|slot| slot.name == tag.name())
}

/// Name an unexpected element without echoing untrusted input verbatim: the
/// local name goes through the shared display sanitiser, which bounds it and
/// drops every control and format character, and a foreign namespace is
/// reported as such rather than quoted.
fn describe(child: Node<'_, '_>) -> String {
    let tag = child.tag_name();
    let name = openszigno_core::sanitize_display(tag.name(), 64);
    if tag.namespace() == Some(XMLDSIG_NAMESPACE) {
        format!("ds:{name}")
    } else {
        format!("{name}, which is in a foreign namespace")
    }
}

fn invalid(message: String) -> Check {
    Check::failed(CheckCode::SigStructureInvalid, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openszigno_core::{Limits, XmlSource};

    /// Run the pass over a hand-built `ds:Signature`, returning the message of
    /// the failing check when there is one.
    fn check(body: &str) -> Result<(), String> {
        let xml = format!(
            "<ds:Signature xmlns:ds=\"{XMLDSIG_NAMESPACE}\" \
xmlns:x=\"urn:example:other\" Id=\"s1\">{body}</ds:Signature>"
        );
        let limits = Limits::default();
        let source = XmlSource::decode(xml.as_bytes(), &limits).expect("decodes");
        let tree = source.parse_tree(&limits).expect("parses");
        let root = tree
            .root()
            .children()
            .find(Node::is_element)
            .expect("the signature element exists");
        validate(root).map_err(|check| check.message)
    }

    const SIGNED_INFO_BODY: &str = "<ds:SignedInfo><ds:CanonicalizationMethod/>\
<ds:SignatureMethod/><ds:Reference><ds:DigestMethod/><ds:DigestValue/>\
</ds:Reference></ds:SignedInfo>";

    fn signature(extra: &str) -> String {
        format!("{SIGNED_INFO_BODY}<ds:SignatureValue/>{extra}")
    }

    #[test]
    fn the_canonical_shape_passes() {
        check(&signature("")).expect("the canonical signature is well formed");
    }

    #[test]
    fn key_info_objects_and_comments_pass() {
        let body = format!(
            "<!-- lead --> {SIGNED_INFO_BODY} <!-- mid --> <ds:SignatureValue/>\n\
<ds:KeyInfo><x:Anything/></ds:KeyInfo><ds:Object><x:Anything/></ds:Object>\
<!-- tail --><ds:Object/>"
        );
        check(&body).expect("the open content models are accepted");
    }

    #[test]
    fn transforms_are_optional_but_single() {
        check(&signature("")).expect("no ds:Transforms is fine");
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:Reference><ds:Transforms/><ds:Transforms/><ds:DigestMethod/><ds:DigestValue/>\
</ds:Reference></ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("two ds:Transforms are refused");
        assert_eq!(message, "ds:Reference 0 has more than one ds:Transforms");
    }

    #[test]
    fn a_duplicate_signature_value_is_refused() {
        let message = check(&signature("<ds:SignatureValue/>"))
            .expect_err("a second ds:SignatureValue is refused");
        assert_eq!(message, "ds:Signature has more than one ds:SignatureValue");
    }

    #[test]
    fn a_duplicate_signed_info_is_refused() {
        let message = check(&format!(
            "{SIGNED_INFO_BODY}{SIGNED_INFO_BODY}<ds:SignatureValue/>"
        ))
        .expect_err("a second ds:SignedInfo is refused");
        assert_eq!(message, "ds:Signature has more than one ds:SignedInfo");
    }

    #[test]
    fn a_duplicate_key_info_is_refused() {
        let message = check(&signature("<ds:KeyInfo/><ds:KeyInfo/>"))
            .expect_err("a second ds:KeyInfo is refused");
        assert_eq!(message, "ds:Signature has more than one ds:KeyInfo");
    }

    #[test]
    fn an_object_before_key_info_is_out_of_order() {
        let message = check(&signature("<ds:Object/><ds:KeyInfo/>"))
            .expect_err("ds:KeyInfo after ds:Object is refused");
        assert_eq!(message, "ds:Signature has ds:KeyInfo out of order");
    }

    #[test]
    fn a_signature_value_before_signed_info_is_out_of_order() {
        let message = check(&format!("<ds:SignatureValue/>{SIGNED_INFO_BODY}"))
            .expect_err("ds:SignedInfo after ds:SignatureValue is refused");
        assert_eq!(message, "ds:Signature has ds:SignedInfo out of order");
    }

    #[test]
    fn duplicate_signed_info_methods_are_refused() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:CanonicalizationMethod/>\
<ds:SignatureMethod/><ds:Reference><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("two canonicalization methods are refused");
        assert_eq!(
            message,
            "ds:SignedInfo has more than one ds:CanonicalizationMethod"
        );
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:SignatureMethod/><ds:Reference><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("two signature methods are refused");
        assert_eq!(
            message,
            "ds:SignedInfo has more than one ds:SignatureMethod"
        );
    }

    #[test]
    fn a_method_after_a_reference_is_out_of_order() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/>\
<ds:Reference><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
<ds:SignatureMethod/></ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("ds:SignatureMethod after a reference is refused");
        assert_eq!(message, "ds:SignedInfo has ds:SignatureMethod out of order");
    }

    #[test]
    fn duplicate_digest_children_are_refused() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:Reference><ds:DigestMethod/><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("two digest methods are refused");
        assert_eq!(message, "ds:Reference 0 has more than one ds:DigestMethod");
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:Reference><ds:DigestMethod/><ds:DigestValue/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("two digest values are refused");
        assert_eq!(message, "ds:Reference 0 has more than one ds:DigestValue");
    }

    #[test]
    fn a_digest_value_before_its_method_is_out_of_order() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:Reference><ds:DigestValue/><ds:DigestMethod/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("a digest method after its value is refused");
        assert_eq!(message, "ds:Reference 0 has ds:DigestMethod out of order");
    }

    #[test]
    fn the_second_reference_is_named_by_its_index() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<ds:Reference><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
<ds:Reference><ds:DigestMethod/><ds:DigestValue/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("the second reference is checked too");
        assert_eq!(message, "ds:Reference 1 has more than one ds:DigestValue");
    }

    #[test]
    fn a_foreign_child_of_signed_info_is_refused() {
        let message = check(
            "<ds:SignedInfo><ds:CanonicalizationMethod/><ds:SignatureMethod/>\
<x:Extra/><ds:Reference><ds:DigestMethod/><ds:DigestValue/></ds:Reference>\
</ds:SignedInfo><ds:SignatureValue/>",
        )
        .expect_err("a foreign-namespace child of ds:SignedInfo is refused");
        assert_eq!(
            message,
            "ds:SignedInfo has an unexpected child element Extra, \
which is in a foreign namespace"
        );
    }

    #[test]
    fn an_unknown_dsig_child_of_a_signature_is_refused() {
        let message = check(&signature("<ds:Manifest/>"))
            .expect_err("ds:Manifest is not a child of ds:Signature");
        assert_eq!(
            message,
            "ds:Signature has an unexpected child element ds:Manifest"
        );
    }

    #[test]
    fn a_missing_element_is_left_to_the_caller() {
        check("<ds:SignatureValue/>").expect("an absent ds:SignedInfo is not this pass's business");
        check(SIGNED_INFO_BODY).expect("an absent ds:SignatureValue is not this pass's business");
        check("<ds:SignedInfo><ds:CanonicalizationMethod/></ds:SignedInfo>")
            .expect("an absent ds:SignatureMethod is not this pass's business");
    }
}
