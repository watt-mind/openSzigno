//! The XMLDSig half of a signature: the `ds:SignedInfo` element, its
//! references, and the octets each of them digests.
//!
//! Everything here is written to be reproduced by
//! [`openszigno_verify`](https://docs.rs/openszigno-verify), and it is
//! reproduced with the very same code: the canonicalization backend this
//! module digests through is the verifier's own, over the tree the shared
//! `openszigno_core::XmlSource` built. Two implementations that had to agree
//! about namespace scope is precisely the gap a signature must not sit in.
//!
//! The shape is fixed and small. Exclusive canonicalization for
//! `ds:SignedInfo` and for every reference, SHA-256 digests, one reference per
//! element the e-dossier format mandates, and no enveloped-signature
//! transform anywhere: every reference names a sibling or a child of the
//! signature, so nothing a reference selects ever contains the signature
//! itself.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use openszigno_core::roxmltree::Node;
use openszigno_core::{Limits, XmlSource};
use openszigno_verify::{C14nAlgorithm, C14nBackend, NodeSet, RoxmltreeC14n};
use sha2::{Digest as _, Sha256};

use super::error::SignError;
use super::names::attribute;
use super::signer::SignatureAlgorithm;

/// Exclusive XML Canonicalization 1.0, without comments.
pub(crate) const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
/// SHA-256, the only digest this build writes.
pub(crate) const SHA256_URI: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// The `ds:Reference/@Type` that announces a `SignedProperties` reference.
/// It is corroboration: what the reference resolves to is what binds.
pub(crate) const SIGNED_PROPERTIES_TYPE: &str = "http://uri.etsi.org/01903#SignedProperties";
pub(crate) const XMLDSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";

/// One `ds:Reference` to write.
pub(crate) struct PlannedReference {
    /// The reference's own `Id`, so an `xades:DataObjectFormat` can name it.
    pub(crate) id: String,
    /// The same-document URI, always `#id`. Nothing external is ever written.
    pub(crate) uri: String,
    /// The `Type` attribute, for the `SignedProperties` reference only.
    pub(crate) reference_type: Option<&'static str>,
    /// The declared media type of the data object this reference covers, when
    /// it covers one. It becomes an `xades:DataObjectFormat`.
    pub(crate) mime_type: Option<String>,
}

impl PlannedReference {
    pub(crate) fn to(id: &str, uri_id: &str) -> Self {
        Self {
            id: id.to_owned(),
            uri: format!("#{uri_id}"),
            reference_type: None,
            mime_type: None,
        }
    }

    pub(crate) fn signed_properties(id: &str, uri_id: &str) -> Self {
        Self {
            reference_type: Some(SIGNED_PROPERTIES_TYPE),
            ..Self::to(id, uri_id)
        }
    }

    pub(crate) fn with_mime_type(mut self, mime_type: String) -> Self {
        self.mime_type = Some(mime_type);
        self
    }
}

/// The placeholder a digest is written under until it is computed.
pub(crate) fn digest_placeholder(reference_id: &str) -> String {
    format!("@@openszigno-digest:{reference_id}@@")
}

/// The placeholder a signature value is written under until it is computed.
pub(crate) fn value_placeholder(signature_id: &str) -> String {
    format!("@@openszigno-value:{signature_id}@@")
}

/// Render `ds:SignedInfo`, `ds:SignatureValue` and `ds:KeyInfo`.
///
/// The digest and signature values are placeholders: they are filled in once
/// the whole document exists, because what a reference digests is decided by
/// the document the reference ends up in, not by the fragment being rendered.
pub(crate) fn render_signed_info(
    signature_id: &str,
    algorithm: SignatureAlgorithm,
    references: &[PlannedReference],
    certificate: &[u8],
) -> String {
    let mut out = String::new();
    out.push_str("<ds:SignedInfo>");
    out.push_str(&format!(
        "<ds:CanonicalizationMethod Algorithm=\"{C14N_EXCLUSIVE}\"/>"
    ));
    out.push_str(&format!(
        "<ds:SignatureMethod Algorithm=\"{}\"/>",
        algorithm.uri()
    ));
    for reference in references {
        let declared = reference
            .reference_type
            .map(|value| format!(" Type=\"{value}\""))
            .unwrap_or_default();
        // Every interpolated value is escaped, the reference URI included:
        // it is built from an `Id` the dossier chose, and a value that
        // reached the attribute unescaped would let the dossier write the
        // reference set rather than describe it.
        out.push_str(&format!(
            "<ds:Reference Id=\"{}\" URI=\"{}\"{declared}>\
<ds:Transforms><ds:Transform Algorithm=\"{C14N_EXCLUSIVE}\"/></ds:Transforms>\
<ds:DigestMethod Algorithm=\"{SHA256_URI}\"/>\
<ds:DigestValue>{}</ds:DigestValue></ds:Reference>",
            attribute(&reference.id),
            attribute(&reference.uri),
            digest_placeholder(&reference.id)
        ));
    }
    out.push_str("</ds:SignedInfo>");
    out.push_str(&format!(
        "<ds:SignatureValue>{}</ds:SignatureValue>",
        value_placeholder(signature_id)
    ));
    out.push_str(&format!(
        "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>",
        STANDARD.encode(certificate)
    ));
    out
}

/// A parsed working document, so one parse can answer several questions.
pub(crate) struct Working {
    source: XmlSource,
}

impl Working {
    pub(crate) fn parse(text: &str) -> Result<Self, SignError> {
        let source = XmlSource::decode(text.as_bytes(), &Limits::default())
            .map_err(|error| SignError::failed(error.message().to_owned()))?;
        Ok(Self { source })
    }

    /// Run `body` against the parsed tree.
    ///
    /// The tree borrows the source text, so it cannot be stored alongside it;
    /// handing a closure the tree is what keeps one parse serving several
    /// lookups without a self-referential type.
    pub(crate) fn with_tree<T>(
        &self,
        body: impl FnOnce(&Lookup<'_>) -> Result<T, SignError>,
    ) -> Result<T, SignError> {
        let tree = self
            .source
            .parse_tree(&Limits::default())
            .map_err(|error| SignError::failed(error.message().to_owned()))?;
        body(&Lookup {
            text: self.source.text(),
            tree,
        })
    }

    pub(crate) fn text(&self) -> &str {
        self.source.text()
    }
}

/// The tree of one working document, and the canonicalizations taken from it.
pub(crate) struct Lookup<'input> {
    text: &'input str,
    tree: openszigno_core::roxmltree::Document<'input>,
}

impl<'input> Lookup<'input> {
    /// The one element carrying this `Id`.
    pub(crate) fn by_id(&self, id: &str) -> Option<Node<'_, 'input>> {
        self.tree
            .descendants()
            .find(|node| node.is_element() && node.attribute("Id") == Some(id))
    }

    pub(crate) fn root(&self) -> Node<'_, 'input> {
        self.tree.root_element()
    }

    /// Every `ds:Signature` element in the document, in document order.
    pub(crate) fn signatures(&self) -> Vec<Node<'_, 'input>> {
        self.tree
            .descendants()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "Signature"
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
            })
            .collect()
    }

    /// Where a new `ds:Signature` goes inside `node`: after everything the
    /// element already holds, and before its own end tag.
    ///
    /// The offset is taken from the last child rather than computed from the
    /// element's own range, because the end tag's prefix is whatever the
    /// dossier chose and this module never guesses at spelling.
    pub(crate) fn insert_offset(&self, node: Node<'_, 'input>) -> Result<usize, SignError> {
        node.children()
            .next_back()
            .map(|last| last.range().end)
            .ok_or_else(|| {
                SignError::failed("the element a signature would be written into is empty")
            })
    }

    /// The byte range one signature's element occupies in the working text,
    /// start tag to end tag.
    ///
    /// It is what bounds every substitution a later pass makes: the values a
    /// pass fills in belong to this element, and a dossier is free to hold
    /// text that looks exactly like the placeholder standing in for one.
    pub(crate) fn signature_range(
        &self,
        signature_id: &str,
    ) -> Result<std::ops::Range<usize>, SignError> {
        self.by_id(signature_id)
            .map(|node| node.range())
            .ok_or_else(|| SignError::failed("the signature being written is not readable"))
    }

    /// The `Id` of a direct child of the root `es:Dossier`.
    pub(crate) fn dossier_child_id(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<String, SignError> {
        self.root()
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == name
                    && node.tag_name().namespace() == Some(namespace)
            })
            .and_then(|node| node.attribute("Id"))
            .map(str::to_owned)
            .ok_or_else(|| {
                SignError::failed(format!(
                    "the dossier has no es:{name} with an Id, so nothing can reference it"
                ))
            })
    }

    /// The `Id` of the `es:DocumentProfile` inside one `es:Document`.
    ///
    /// The namespace is required, exactly as it is in [`Self::dossier_child_id`]:
    /// matching on the local name alone let a `DocumentProfile` from a foreign
    /// namespace, placed first, decide what the signature referenced.
    pub(crate) fn document_profile_id(
        &self,
        container: Node<'_, 'input>,
        namespace: &str,
    ) -> Option<String> {
        container
            .children()
            .find(|node| {
                node.is_element()
                    && node.tag_name().name() == "DocumentProfile"
                    && node.tag_name().namespace() == Some(namespace)
            })
            .and_then(|node| node.attribute("Id"))
            .map(str::to_owned)
    }

    /// Whether a signature carries a `ds:Reference` over the whole document.
    ///
    /// Such a reference covers everything outside the signature itself, so
    /// anything added anywhere in the dossier would change what it digests.
    pub(crate) fn has_whole_document_reference(&self, signature: Node<'_, 'input>) -> bool {
        signature
            .descendants()
            .filter(|node| {
                node.is_element()
                    && node.tag_name().name() == "Reference"
                    && node.tag_name().namespace() == Some(XMLDSIG_NS)
            })
            .any(|node| node.attribute("URI").unwrap_or_default().is_empty())
    }

    /// Whether an existing signature already covers the element a new
    /// signature would be written into, or anything containing it.
    ///
    /// Adding a `ds:Signature` changes the canonical form of the element it
    /// goes into and of every ancestor of that element, so any existing
    /// reference resolving to one of them would stop matching. Only the
    /// same-document `#id` form is resolved; a reference this module cannot
    /// resolve may name anything, so it is treated as covering rather than
    /// assumed harmless.
    pub(crate) fn covers_ancestor_or_self(&self, insertion: Node<'_, 'input>) -> bool {
        let chain: Vec<openszigno_core::roxmltree::NodeId> =
            insertion.ancestors().map(|node| node.id()).collect();
        self.signatures().into_iter().any(|signature| {
            signature
                .descendants()
                .filter(|node| {
                    node.is_element()
                        && node.tag_name().name() == "Reference"
                        && node.tag_name().namespace() == Some(XMLDSIG_NS)
                })
                .any(|reference| {
                    match reference
                        .attribute("URI")
                        .and_then(|uri| uri.strip_prefix('#'))
                        .and_then(|id| self.by_id(id))
                    {
                        Some(target) => chain.contains(&target.id()),
                        None => true,
                    }
                })
        })
    }

    /// Whether something at the dossier level already covers `es:Documents`.
    ///
    /// A dossier-level `ds:Signature` and a dossier-level `es:TimeStamp` both
    /// do, and both would stop verifying the moment a signature is added
    /// inside one of the documents.
    pub(crate) fn has_dossier_level_cover(&self) -> bool {
        let root = self.root();
        let namespace = root.tag_name().namespace();
        root.children().filter(Node::is_element).any(|node| {
            let name = node.tag_name().name();
            (name == "Signature" && node.tag_name().namespace() == Some(XMLDSIG_NS))
                || (name == "TimeStamp" && node.tag_name().namespace() == namespace)
        })
    }

    /// The canonical octets of one element's subtree, comments removed.
    ///
    /// A same-document reference dereferences to a comment-free node set
    /// (XMLDSig 4.4.3.3), so the signer drops comments exactly as the verifier
    /// does; a comment inserted afterwards then cannot change a digest.
    pub(crate) fn canonical(&self, node: Node<'_, 'input>) -> Result<Vec<u8>, SignError> {
        self.canonical_with(node, C14nAlgorithm::Exclusive { comments: false })
    }

    fn canonical_with(
        &self,
        node: Node<'_, 'input>,
        algorithm: C14nAlgorithm,
    ) -> Result<Vec<u8>, SignError> {
        RoxmltreeC14n
            .canonicalize(
                self.text,
                &NodeSet::subtree(node).without_comments(),
                algorithm,
                &[],
            )
            .map_err(|_| SignError::failed("an element could not be canonicalized"))
    }

    /// The canonical octets of the element `id` names.
    pub(crate) fn canonical_by_id(&self, id: &str) -> Result<Vec<u8>, SignError> {
        let node = self.by_id(id).ok_or_else(|| {
            SignError::failed("a reference this signature writes resolves to nothing")
        })?;
        self.canonical(node)
    }

    /// The named child of the `ds:Signature` whose `Id` is `signature_id`.
    fn signature_child(
        &self,
        signature_id: &str,
        name: &str,
    ) -> Result<Node<'_, 'input>, SignError> {
        self.by_id(signature_id)
            .and_then(|signature| {
                signature.children().find(|node| {
                    node.is_element()
                        && node.tag_name().name() == name
                        && node.tag_name().namespace() == Some(XMLDSIG_NS)
                })
            })
            .ok_or_else(|| SignError::failed("the signature being written is not readable"))
    }

    /// The octets `ds:SignatureValue` is computed over.
    pub(crate) fn canonical_signed_info(&self, signature_id: &str) -> Result<Vec<u8>, SignError> {
        let node = self.signature_child(signature_id, "SignedInfo")?;
        self.canonical(node)
    }

    /// The octets an `xades:SignatureTimeStamp` covers: the canonicalized
    /// `ds:SignatureValue` element, start tag to end tag.
    ///
    /// Inclusive canonicalization, not the exclusive one every reference uses.
    /// The timestamp element this build writes names no
    /// `ds:CanonicalizationMethod`, and XAdES 7.1.4.3.1 makes inclusive
    /// C14N 1.0 the default for that case, so that is what the verifier
    /// recomputes. Signing the exclusive form instead produces a token over
    /// octets nobody ever computes again: the two differ by exactly the
    /// ancestor namespace declarations the element does not visibly use.
    pub(crate) fn canonical_signature_value(
        &self,
        signature_id: &str,
    ) -> Result<Vec<u8>, SignError> {
        let node = self.signature_child(signature_id, "SignatureValue")?;
        self.canonical_with(node, C14nAlgorithm::Inclusive { comments: false })
    }
}

/// The Base64 SHA-256 digest of some octets, as a `ds:DigestValue` carries it.
pub(crate) fn digest_value(octets: &[u8]) -> String {
    STANDARD.encode(Sha256::digest(octets))
}

/// The SHA-256 digest of some octets, as a hash-only signer is handed one.
pub(crate) fn digest(octets: &[u8]) -> Vec<u8> {
    Sha256::digest(octets).to_vec()
}

/// Base64, the encoding every value in a signature is written in.
pub(crate) fn base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendered_signed_info_carries_one_reference_per_plan_entry() {
        let references = vec![
            PlannedReference::to("ref-0", "obj0"),
            PlannedReference::signed_properties("ref-1", "sp"),
        ];
        let xml = render_signed_info(
            "sig-doc0",
            SignatureAlgorithm::RsaSha256,
            &references,
            b"certificate",
        );
        assert_eq!(xml.matches("<ds:Reference ").count(), 2);
        assert!(xml.contains(&digest_placeholder("ref-0")));
        assert!(xml.contains(&value_placeholder("sig-doc0")));
        assert!(xml.contains(SIGNED_PROPERTIES_TYPE));
        assert!(xml.contains(SignatureAlgorithm::RsaSha256.uri()));
        // Every reference is same-document and canonicalized the one way.
        assert_eq!(xml.matches("URI=\"#").count(), 2);
        assert_eq!(xml.matches(C14N_EXCLUSIVE).count(), 3);
    }

    #[test]
    fn canonicalization_is_taken_from_the_working_document() {
        let working = Working::parse("<a xmlns=\"urn:x\"><b Id=\"one\">text<!-- gone --></b></a>")
            .expect("this parses");
        let octets = working
            .with_tree(|lookup| lookup.canonical_by_id("one"))
            .expect("the element is there");
        let text = String::from_utf8(octets).expect("canonical XML is UTF-8");
        assert!(text.contains("text"));
        assert!(!text.contains("gone"));
        assert_eq!(digest_value(b"").len(), 44);
    }

    /// A `DocumentProfile` from another namespace, placed first, is not the
    /// one a signature references. Matching on the local name alone let a
    /// dossier point the mandated reference wherever it liked.
    #[test]
    fn a_document_profile_from_another_namespace_is_never_the_one_referenced() {
        let working = Working::parse(
            "<Dossier xmlns=\"urn:es\" xmlns:x=\"urn:other\"><Document>\
<x:DocumentProfile Id=\"foreign\"/><DocumentProfile Id=\"real\"/>\
</Document></Dossier>",
        )
        .expect("this parses");
        working
            .with_tree(|lookup| {
                let container = lookup
                    .root()
                    .children()
                    .find(Node::is_element)
                    .expect("the document element is there");
                assert_eq!(
                    lookup.document_profile_id(container, "urn:es"),
                    Some("real".to_owned())
                );
                assert_eq!(lookup.document_profile_id(container, "urn:absent"), None);
                Ok(())
            })
            .expect("the lookup runs");
    }

    #[test]
    fn a_reference_that_resolves_to_nothing_is_a_refusal() {
        let working = Working::parse("<a xmlns=\"urn:x\"/>").expect("this parses");
        let error = working
            .with_tree(|lookup| lookup.canonical_by_id("missing"))
            .expect_err("nothing carries that id");
        assert_eq!(error.code().as_str(), "sign_failed");
    }
}
