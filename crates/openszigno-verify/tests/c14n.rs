//! Canonicalization tests against hand-computed canonical forms.
//!
//! The reference values come from the W3C Canonical XML 1.0 and Exclusive XML
//! Canonicalization 1.0 specifications, adapted where an example depends on a
//! DTD (this project refuses DTDs outright, so those examples cannot be fed to
//! the parser unchanged). Every expectation below is derived from the spec's
//! rules and written out by hand; a canonicalizer that quietly drifts is worse
//! than one that refuses, so these are byte-for-byte comparisons.

use openszigno_core::{Limits, XmlSource, roxmltree::Node};
use openszigno_verify::c14n::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};

fn canonical(xml: &str, algorithm: C14nAlgorithm, prefixes: &[&str]) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let set = NodeSet::document(tree.root());
    let prefixes: Vec<String> = prefixes.iter().map(|value| (*value).to_owned()).collect();
    let bytes = RoxmltreeC14n
        .canonicalize(source.text(), &set, algorithm, &prefixes)
        .expect("canonicalizes");
    String::from_utf8(bytes).expect("canonical XML is UTF-8")
}

fn canonical_subtree(
    xml: &str,
    algorithm: C14nAlgorithm,
    prefixes: &[&str],
    pick: impl Fn(Node<'_, '_>) -> bool,
) -> String {
    let source = XmlSource::decode(xml.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let apex = tree
        .root_element()
        .descendants()
        .find(|node| node.is_element() && pick(*node))
        .expect("the apex element exists");
    let set = NodeSet::subtree(apex);
    let prefixes: Vec<String> = prefixes.iter().map(|value| (*value).to_owned()).collect();
    let bytes = RoxmltreeC14n
        .canonicalize(source.text(), &set, algorithm, &prefixes)
        .expect("canonicalizes");
    String::from_utf8(bytes).expect("canonical XML is UTF-8")
}

const INCLUSIVE: C14nAlgorithm = C14nAlgorithm::Inclusive { comments: false };
const INCLUSIVE_COMMENTS: C14nAlgorithm = C14nAlgorithm::Inclusive { comments: true };
const EXCLUSIVE: C14nAlgorithm = C14nAlgorithm::Exclusive { comments: false };

/// W3C Canonical XML 1.0 example 3.1: processing instructions and comments
/// around the document element, including the newline placement rules.
#[test]
fn w3c_example_3_1_pis_and_comments() {
    let input = "<?xml version=\"1.0\"?>\n\n\
<?xml-stylesheet   href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\n\
<doc>Hello, world!<!-- Comment 1 --></doc>\n\n\
<?pi-without-data     ?>\n\n\
<!-- Comment 2 -->\n\n\
<!-- Comment 3 -->\n";

    assert_eq!(
        canonical(input, INCLUSIVE, &[]),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\
<doc>Hello, world!</doc>\n\
<?pi-without-data?>"
    );
    assert_eq!(
        canonical(input, INCLUSIVE_COMMENTS, &[]),
        "<?xml-stylesheet href=\"doc.xsl\"\n   type=\"text/xsl\"   ?>\n\
<doc>Hello, world!<!-- Comment 1 --></doc>\n\
<?pi-without-data?>\n\
<!-- Comment 2 -->\n\
<!-- Comment 3 -->"
    );
}

/// W3C Canonical XML 1.0 example 3.3, minus the document type declaration
/// this project refuses outright. Dropping the DTD removes only the defaulted
/// `attr="default"` on `e9`; everything else is the specification's canonical
/// form verbatim.
///
/// Covers: empty elements gaining an end tag, whitespace normalization in
/// tags, namespace declarations before attributes, lexicographic ordering of
/// both axes with the namespace URI as the primary attribute key, retention of
/// source prefixes, and elimination of superfluous namespace declarations.
#[test]
fn w3c_example_3_3_start_and_end_tags() {
    let input = r#"<doc>
   <e1   />
   <e2   ></e2>
   <e3   name = "elem3"   id="elem3"   />
   <e4   name="elem4"   id="elem4"   ></e4>
   <e5 a:attr="out" b:attr="sorted" attr2="all" attr="I'm"
      xmlns:b="http://www.ietf.org"
      xmlns:a="http://www.w3.org"
      xmlns="http://example.org"/>
   <e6 xmlns="" xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="" xmlns:a="http://www.w3.org">
            <e9 xmlns="" xmlns:a="http://www.ietf.org"/>
         </e8>
      </e7>
   </e6>
</doc>"#;

    assert_eq!(
        canonical(input, INCLUSIVE, &[]),
        r#"<doc>
   <e1></e1>
   <e2></e2>
   <e3 id="elem3" name="elem3"></e3>
   <e4 id="elem4" name="elem4"></e4>
   <e5 xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out"></e5>
   <e6 xmlns:a="http://www.w3.org">
      <e7 xmlns="http://www.ietf.org">
         <e8 xmlns="">
            <e9 xmlns:a="http://www.ietf.org"></e9>
         </e8>
      </e7>
   </e6>
</doc>"#
    );
}

/// W3C Canonical XML 1.0 example 3.2: all whitespace in document content is
/// retained, clean or dirty, so the canonical form equals the input.
#[test]
fn w3c_example_3_2_whitespace_in_document_content() {
    let input = r#"<doc>
   <clean>   </clean>
   <dirty>   A   B   </dirty>
   <mixed>
      A
      <clean>   </clean>
      B
      <dirty>   A   B   </dirty>
      C
   </mixed>
</doc>"#;
    assert_eq!(canonical(input, INCLUSIVE, &[]), input);
}

/// A default namespace put in scope by an ancestor must be undeclared with
/// `xmlns=""` on a descendant that leaves it, and never re-emitted below.
#[test]
fn default_namespace_is_undeclared_exactly_once() {
    let input = r#"<a xmlns="urn:x"><b xmlns=""><c/></b></a>"#;
    assert_eq!(
        canonical(input, INCLUSIVE, &[]),
        r#"<a xmlns="urn:x"><b xmlns=""><c></c></b></a>"#
    );
}

/// The apex of an inclusive document subset renders every namespace in scope,
/// including ones declared by ancestors outside the subset. Exclusive
/// canonicalization renders only visibly utilised prefixes, which is exactly
/// the difference that matters for a detached `ds:SignedInfo`.
#[test]
fn subtree_namespace_scope_differs_between_inclusive_and_exclusive() {
    let input = r#"<r xmlns:x="urn:x" xmlns:y="urn:y"><x:e a="1">t</x:e></r>"#;
    let pick = |node: Node<'_, '_>| node.tag_name().name() == "e";

    assert_eq!(
        canonical_subtree(input, INCLUSIVE, &[], pick),
        r#"<x:e xmlns:x="urn:x" xmlns:y="urn:y" a="1">t</x:e>"#
    );
    assert_eq!(
        canonical_subtree(input, EXCLUSIVE, &[], pick),
        r#"<x:e xmlns:x="urn:x" a="1">t</x:e>"#
    );
    assert_eq!(
        canonical_subtree(input, EXCLUSIVE, &["y"], pick),
        r#"<x:e xmlns:x="urn:x" xmlns:y="urn:y" a="1">t</x:e>"#
    );
}

/// Canonical XML 1.0 gives the apex of a document subset the `xml:*` attributes
/// of its out-of-set ancestors; Exclusive C14N deliberately does not.
#[test]
fn xml_attributes_are_inherited_only_by_inclusive_c14n() {
    let input = r#"<r xml:lang="hu" xml:space="preserve"><e><f/></e></r>"#;
    let pick = |node: Node<'_, '_>| node.tag_name().name() == "e";

    assert_eq!(
        canonical_subtree(input, INCLUSIVE, &[], pick),
        r#"<e xml:lang="hu" xml:space="preserve"><f></f></e>"#
    );
    assert_eq!(
        canonical_subtree(input, EXCLUSIVE, &[], pick),
        "<e><f></f></e>"
    );
}

/// An `xml:*` attribute on the apex itself wins over the inherited one.
#[test]
fn a_closer_xml_attribute_wins() {
    let input = r#"<r xml:lang="hu"><e xml:lang="en"/></r>"#;
    assert_eq!(
        canonical_subtree(input, INCLUSIVE, &[], |node| node.tag_name().name() == "e"),
        r#"<e xml:lang="en"></e>"#
    );
}

/// Text and attribute escaping follow different rules: `>` is escaped in text
/// but not in attribute values, and `"` the other way round.
#[test]
fn escaping_rules() {
    let input = "<d a=\"x&#xD;y&#9;z&quot;w&lt;\">&lt;&amp;&gt;</d>";
    assert_eq!(
        canonical(input, INCLUSIVE, &[]),
        "<d a=\"x&#xD;y&#x9;z&quot;w&lt;\">&lt;&amp;&gt;</d>"
    );
}

/// Comments inside the document element are kept or dropped according to the
/// algorithm, and a CDATA section is indistinguishable from text.
#[test]
fn comments_and_cdata() {
    let input = "<d><![CDATA[a<b]]><!--c--></d>";
    assert_eq!(canonical(input, INCLUSIVE, &[]), "<d>a&lt;b</d>");
    assert_eq!(
        canonical(input, INCLUSIVE_COMMENTS, &[]),
        "<d>a&lt;b<!--c--></d>"
    );
}

/// Two prefixes bound to the same URI must keep the prefix the source used.
/// Resolving the prefix by looking the URI up in scope would pick the wrong one
/// and silently change the canonical bytes.
#[test]
fn the_source_prefix_is_preserved() {
    let input = r#"<r xmlns:a="urn:same" xmlns:b="urn:same"><b:e/></r>"#;
    assert_eq!(
        canonical_subtree(input, EXCLUSIVE, &[], |node| node.tag_name().name() == "e"),
        r#"<b:e xmlns:b="urn:same"></b:e>"#
    );
}

/// Excluding a subtree is how the enveloped-signature transform is expressed.
#[test]
fn excluding_a_subtree_removes_it_entirely() {
    let input = "<r><a>keep</a><s><deep>drop</deep></s><b>keep</b></r>";
    let source = XmlSource::decode(input.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let mut set = NodeSet::document(tree.root());
    let signature = tree
        .root_element()
        .descendants()
        .find(|node| node.tag_name().name() == "s")
        .expect("the excluded element exists");
    set.exclude(signature);
    let bytes = RoxmltreeC14n
        .canonicalize(source.text(), &set, INCLUSIVE, &[])
        .expect("canonicalizes");
    assert_eq!(
        String::from_utf8(bytes).expect("UTF-8"),
        "<r><a>keep</a><b>keep</b></r>"
    );
}

/// Canonical XML 1.1 is refused rather than approximated with 1.0, because the
/// two differ on `xml:base` and on `xml:*` inheritance.
#[test]
fn canonical_xml_11_is_not_implemented() {
    assert!(C14nAlgorithm::from_uri("http://www.w3.org/2006/12/xml-c14n11").is_none());
    assert!(C14nAlgorithm::from_uri("http://www.w3.org/TR/2001/REC-xml-c14n-20010315").is_some());
    assert!(C14nAlgorithm::from_uri("http://www.w3.org/2001/10/xml-exc-c14n#").is_some());
}

/// XMLDSig 4.4.3.3: same-document reference dereferencing removes comments
/// before any transform runs, so a with-comments canonicalization applied
/// afterwards still sees none. Without this, a comment inserted into a signed
/// element would change its digest.
#[test]
fn a_comment_free_node_set_stays_comment_free() {
    let input = "<r><a>x<!--c--></a></r>";
    let source = XmlSource::decode(input.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let apex = tree
        .root_element()
        .descendants()
        .find(|node| node.tag_name().name() == "a")
        .expect("the element exists");

    let kept = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::subtree(apex),
            INCLUSIVE_COMMENTS,
            &[],
        )
        .expect("canonicalizes");
    assert_eq!(String::from_utf8(kept).expect("UTF-8"), "<a>x<!--c--></a>");

    let dropped = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::subtree(apex).without_comments(),
            INCLUSIVE_COMMENTS,
            &[],
        )
        .expect("canonicalizes");
    assert_eq!(String::from_utf8(dropped).expect("UTF-8"), "<a>x</a>");
    assert!(
        NodeSet::subtree(apex)
            .without_comments()
            .comments_excluded()
    );
}

/// The same rule applies to comments outside the document element.
#[test]
fn a_comment_free_document_node_set_drops_outer_comments() {
    let input = "<!--before--><doc>x</doc><!--after-->";
    let source = XmlSource::decode(input.as_bytes(), &Limits::default()).expect("decodes");
    let tree = source.parse_tree(&Limits::default()).expect("parses");
    let bytes = RoxmltreeC14n
        .canonicalize(
            source.text(),
            &NodeSet::document(tree.root()).without_comments(),
            INCLUSIVE_COMMENTS,
            &[],
        )
        .expect("canonicalizes");
    assert_eq!(String::from_utf8(bytes).expect("UTF-8"), "<doc>x</doc>");
}
