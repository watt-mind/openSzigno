//! XML canonicalization behind a swappable backend trait.
//!
//! # Why this is written here rather than borrowed
//!
//! The design (`docs/verify-design.md` §1.3) asks for a canonicalization
//! backend used as a pure function over a node set, with `bergshamra` as the
//! first candidate. Its `bergshamra-c14n` API canonicalizes an
//! `uppsala::Document`, its own parser's tree, and selects document subsets by
//! that tree's own node indices. There is no way to hand it a `roxmltree`
//! subtree: using it would mean parsing every dossier a *second* time with a
//! second parser and then trusting that the two trees agree about namespace
//! scope, attribute identity, and element boundaries. Any disagreement between
//! the tree that resolves references and the tree that produces canonical bytes
//! is precisely the signature-wrapping gap this project exists to close, so the
//! whole-pipeline ownership rule wins and canonicalization is implemented here,
//! over the one tree `openszigno-core` built.
//!
//! Implemented: Canonical XML 1.0 (with and without comments) and Exclusive XML
//! Canonicalization 1.0 (with and without comments). Everything else, including
//! Canonical XML 1.1, is refused with [`C14nError::Unsupported`], which the
//! pipeline reports as `c14n_unsupported`. Refusing to answer is acceptable;
//! answering wrongly is not.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use openszigno_core::roxmltree::{Node, NodeId};

/// The XML namespace, whose `xml` prefix is implicitly declared everywhere and
/// is therefore never emitted as a namespace declaration.
pub const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";

pub const C14N_INCLUSIVE: &str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const C14N_INCLUSIVE_WITH_COMMENTS: &str =
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const C14N_EXCLUSIVE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const C14N_EXCLUSIVE_WITH_COMMENTS: &str =
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
pub const EXC_C14N_NAMESPACE: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";

/// The canonicalization algorithms this crate implements.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C14nAlgorithm {
    Inclusive { comments: bool },
    Exclusive { comments: bool },
}

impl C14nAlgorithm {
    /// Map an algorithm URI onto an implemented algorithm.
    ///
    /// `None` means "not implemented", which the caller reports as
    /// `c14n_unsupported` rather than approximating with a similar algorithm.
    pub fn from_uri(uri: &str) -> Option<Self> {
        match uri {
            C14N_INCLUSIVE => Some(Self::Inclusive { comments: false }),
            C14N_INCLUSIVE_WITH_COMMENTS => Some(Self::Inclusive { comments: true }),
            C14N_EXCLUSIVE => Some(Self::Exclusive { comments: false }),
            C14N_EXCLUSIVE_WITH_COMMENTS => Some(Self::Exclusive { comments: true }),
            _ => None,
        }
    }

    pub const fn uri(self) -> &'static str {
        match self {
            Self::Inclusive { comments: false } => C14N_INCLUSIVE,
            Self::Inclusive { comments: true } => C14N_INCLUSIVE_WITH_COMMENTS,
            Self::Exclusive { comments: false } => C14N_EXCLUSIVE,
            Self::Exclusive { comments: true } => C14N_EXCLUSIVE_WITH_COMMENTS,
        }
    }

    /// The short name used in the machine-readable policy report.
    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Inclusive { comments: false } => "c14n",
            Self::Inclusive { comments: true } => "c14n-with-comments",
            Self::Exclusive { comments: false } => "exc-c14n",
            Self::Exclusive { comments: true } => "exc-c14n-with-comments",
        }
    }

    const fn comments(self) -> bool {
        match self {
            Self::Inclusive { comments } | Self::Exclusive { comments } => comments,
        }
    }

    const fn exclusive(self) -> bool {
        matches!(self, Self::Exclusive { .. })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum C14nError {
    /// The algorithm URI is outside the implemented set.
    Unsupported,
    /// The tree and its source text disagree, which should be impossible for a
    /// tree this crate parsed itself.
    Malformed,
}

impl std::fmt::Display for C14nError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "the canonicalization algorithm is not supported",
            Self::Malformed => "the element could not be canonicalized",
        })
    }
}

/// A document subset: an apex node with zero or more excluded subtrees.
///
/// This is deliberately narrower than the general XPath node-set of the C14N
/// specification. It expresses exactly what a same-document XMLDSig reference
/// can select under this crate's transform allowlist: a whole document or one
/// element subtree, optionally with the enveloped signature removed.
#[derive(Clone, Debug)]
pub struct NodeSet<'a, 'input> {
    apex: Node<'a, 'input>,
    excluded: Vec<NodeId>,
    comments_excluded: bool,
}

impl<'a, 'input> NodeSet<'a, 'input> {
    /// The subtree rooted at one element.
    pub fn subtree(apex: Node<'a, 'input>) -> Self {
        Self {
            apex,
            excluded: Vec::new(),
            comments_excluded: false,
        }
    }

    /// The whole document, including comments and processing instructions
    /// outside the document element.
    pub fn document(root: Node<'a, 'input>) -> Self {
        Self {
            apex: root,
            excluded: Vec::new(),
            comments_excluded: false,
        }
    }

    /// Drop every comment from the node set, whatever the canonicalization
    /// algorithm later asks for.
    ///
    /// XMLDSig 4.4.3.3 requires this of same-document reference
    /// dereferencing: `URI=""` and `URI="#id"` select a node-set that has
    /// already had its comment nodes removed, so a with-comments
    /// canonicalization applied afterwards still sees none. Only the
    /// `#xpointer(...)` forms keep comments, and those are not supported.
    #[must_use]
    pub fn without_comments(mut self) -> Self {
        self.comments_excluded = true;
        self
    }

    /// Whether comments were removed when the node set was built.
    pub fn comments_excluded(&self) -> bool {
        self.comments_excluded
    }

    /// Remove one subtree, which is how the enveloped-signature transform is
    /// expressed.
    pub fn exclude(&mut self, node: Node<'a, 'input>) {
        self.excluded.push(node.id());
    }

    pub fn apex(&self) -> Node<'a, 'input> {
        self.apex
    }

    fn is_excluded(&self, node: Node<'a, 'input>) -> bool {
        self.excluded.contains(&node.id())
    }

    /// The string-value of the node set: the concatenated text of every
    /// included text node, used by the base64 transform.
    pub fn string_value(&self) -> String {
        let mut value = String::new();
        collect_text(self, self.apex, &mut value);
        value
    }
}

fn collect_text<'a, 'input>(set: &NodeSet<'a, 'input>, node: Node<'a, 'input>, out: &mut String) {
    if set.is_excluded(node) {
        return;
    }
    if node.is_text() {
        out.push_str(node.text().unwrap_or_default());
        return;
    }
    for child in node.children() {
        collect_text(set, child, out);
    }
}

/// A canonicalization backend: a pure function from a node set to octets.
pub trait C14nBackend {
    /// Canonicalize `set`, whose nodes must come from a tree parsed from
    /// `source`.
    fn canonicalize(
        &self,
        source: &str,
        set: &NodeSet<'_, '_>,
        algorithm: C14nAlgorithm,
        inclusive_prefixes: &[String],
    ) -> Result<Vec<u8>, C14nError>;
}

/// The in-tree backend, driven by the `roxmltree` tree the core crate builds.
#[derive(Clone, Copy, Debug, Default)]
pub struct RoxmltreeC14n;

impl C14nBackend for RoxmltreeC14n {
    fn canonicalize(
        &self,
        source: &str,
        set: &NodeSet<'_, '_>,
        algorithm: C14nAlgorithm,
        inclusive_prefixes: &[String],
    ) -> Result<Vec<u8>, C14nError> {
        let mut renderer = Renderer {
            source,
            out: Vec::new(),
            algorithm,
            inclusive_prefixes: inclusive_prefixes.iter().cloned().collect(),
        };
        renderer.render_set(set)?;
        Ok(renderer.out)
    }
}

struct Renderer<'s> {
    source: &'s str,
    out: Vec<u8>,
    algorithm: C14nAlgorithm,
    inclusive_prefixes: BTreeSet<String>,
}

/// The namespace declarations rendered so far, innermost last.
type NsStack = Vec<(String, String)>;

fn rendered<'s>(state: &'s NsStack, prefix: &str) -> &'s str {
    state
        .iter()
        .rev()
        .find(|(name, _)| name == prefix)
        .map_or("", |(_, uri)| uri.as_str())
}

impl<'s> Renderer<'s> {
    fn render_set(&mut self, set: &NodeSet<'_, '_>) -> Result<(), C14nError> {
        let apex = set.apex();
        let mut state = NsStack::new();
        if apex.is_root() {
            // Document node: comments and processing instructions on either
            // side of the document element carry the C14N newline rules.
            let mut seen_element = false;
            for child in apex.children() {
                if set.is_excluded(child) {
                    continue;
                }
                if child.is_element() {
                    seen_element = true;
                    self.render_element(set, child, &mut state)?;
                } else if child.is_comment() || child.is_pi() {
                    if child.is_comment() && !(self.algorithm.comments() && !set.comments_excluded)
                    {
                        continue;
                    }
                    if seen_element {
                        self.out.push(b'\n');
                        self.render_misc(child);
                    } else {
                        self.render_misc(child);
                        self.out.push(b'\n');
                    }
                }
            }
            return Ok(());
        }
        self.render_element(set, apex, &mut state)
    }

    fn render_node(
        &mut self,
        set: &NodeSet<'_, '_>,
        node: Node<'_, '_>,
        state: &mut NsStack,
    ) -> Result<(), C14nError> {
        if set.is_excluded(node) {
            return Ok(());
        }
        if node.is_element() {
            return self.render_element(set, node, state);
        }
        if node.is_text() {
            escape_text(node.text().unwrap_or_default(), &mut self.out);
            return Ok(());
        }
        if node.is_comment() {
            if self.algorithm.comments() && !set.comments_excluded {
                self.render_misc(node);
            }
            return Ok(());
        }
        if node.is_pi() {
            self.render_misc(node);
        }
        Ok(())
    }

    fn render_misc(&mut self, node: Node<'_, '_>) {
        if node.is_comment() {
            self.out.extend_from_slice(b"<!--");
            self.out
                .extend_from_slice(node.text().unwrap_or_default().as_bytes());
            self.out.extend_from_slice(b"-->");
            return;
        }
        if let Some(pi) = node.pi() {
            self.out.extend_from_slice(b"<?");
            self.out.extend_from_slice(pi.target.as_bytes());
            let value = pi.value.unwrap_or_default();
            if !value.is_empty() {
                self.out.push(b' ');
                self.out.extend_from_slice(value.as_bytes());
            }
            self.out.extend_from_slice(b"?>");
        }
    }

    fn render_element(
        &mut self,
        set: &NodeSet<'_, '_>,
        node: Node<'_, '_>,
        state: &mut NsStack,
    ) -> Result<(), C14nError> {
        let qname = self.element_qname(node)?;
        let prefix = qname_prefix(qname);
        let declarations = self.namespace_axis(node, prefix, state)?;
        let attributes = self.attribute_axis(set, node)?;

        self.out.push(b'<');
        self.out.extend_from_slice(qname.as_bytes());
        for (declared_prefix, uri) in &declarations {
            self.out.extend_from_slice(b" xmlns");
            if !declared_prefix.is_empty() {
                self.out.push(b':');
                self.out.extend_from_slice(declared_prefix.as_bytes());
            }
            self.out.extend_from_slice(b"=\"");
            escape_attribute(uri, &mut self.out);
            self.out.push(b'"');
        }
        for (_, _, attribute_qname, value) in &attributes {
            self.out.push(b' ');
            self.out.extend_from_slice(attribute_qname.as_bytes());
            self.out.extend_from_slice(b"=\"");
            escape_attribute(value, &mut self.out);
            self.out.push(b'"');
        }
        self.out.push(b'>');

        let depth = state.len();
        state.extend(declarations);
        for child in node.children() {
            self.render_node(set, child, state)?;
        }
        state.truncate(depth);

        self.out.extend_from_slice(b"</");
        self.out.extend_from_slice(qname.as_bytes());
        self.out.push(b'>');
        Ok(())
    }

    /// The namespace declarations this element must render, sorted with the
    /// default namespace first and the rest by prefix.
    fn namespace_axis(
        &self,
        node: Node<'_, '_>,
        prefix: &str,
        state: &NsStack,
    ) -> Result<Vec<(String, String)>, C14nError> {
        let mut candidates: BTreeMap<String, String> = BTreeMap::new();
        if self.algorithm.exclusive() {
            // Exclusive C14N renders only prefixes this element visibly uses,
            // plus any the caller listed in InclusiveNamespaces/@PrefixList.
            let mut visible: BTreeSet<String> = BTreeSet::new();
            visible.insert(prefix.to_owned());
            for attribute in node.attributes() {
                let attribute_prefix = qname_prefix(self.attribute_qname(attribute)?).to_owned();
                if !attribute_prefix.is_empty() {
                    visible.insert(attribute_prefix);
                }
            }
            for listed in &self.inclusive_prefixes {
                visible.insert(if listed == "#default" {
                    String::new()
                } else {
                    listed.clone()
                });
            }
            for name in visible {
                if name == "xml" {
                    continue;
                }
                let uri = in_scope(node, &name);
                candidates.insert(name, uri);
            }
        } else {
            for namespace in node.namespaces() {
                let name = namespace.name().unwrap_or("");
                if name == "xml" && namespace.uri() == XML_NAMESPACE {
                    continue;
                }
                candidates.insert(name.to_owned(), namespace.uri().to_owned());
            }
            // The default namespace always takes part, so that `xmlns=""` is
            // rendered when an ancestor put a non-empty default in scope.
            candidates.entry(String::new()).or_default();
        }

        let mut declarations = Vec::new();
        for (name, uri) in candidates {
            if rendered(state, &name) == uri {
                continue;
            }
            declarations.push((name, uri));
        }
        // BTreeMap iteration is already sorted by prefix and the empty prefix
        // (the default namespace) sorts first, which is the required order.
        Ok(declarations)
    }

    /// The attribute axis, sorted by namespace URI then local name, with
    /// unqualified attributes first.
    #[allow(clippy::type_complexity)]
    fn attribute_axis(
        &self,
        set: &NodeSet<'_, '_>,
        node: Node<'_, '_>,
    ) -> Result<Vec<(String, String, String, String)>, C14nError> {
        let mut attributes: Vec<(String, String, String, String)> = Vec::new();
        for attribute in node.attributes() {
            attributes.push((
                attribute.namespace().unwrap_or("").to_owned(),
                attribute.name().to_owned(),
                self.attribute_qname(attribute)?.to_owned(),
                attribute.value().to_owned(),
            ));
        }
        // Canonical XML 1.0 gives the apex of a document subset the `xml:*`
        // attributes of its out-of-set ancestors. Exclusive C14N deliberately
        // does not inherit them.
        if !self.algorithm.exclusive() && node.id() == set.apex().id() {
            for ancestor in node.ancestors().skip(1).filter(Node::is_element) {
                for attribute in ancestor
                    .attributes()
                    .filter(|attribute| attribute.namespace() == Some(XML_NAMESPACE))
                {
                    if attributes
                        .iter()
                        .any(|(uri, local, _, _)| uri == XML_NAMESPACE && local == attribute.name())
                    {
                        continue;
                    }
                    attributes.push((
                        XML_NAMESPACE.to_owned(),
                        attribute.name().to_owned(),
                        self.attribute_qname(attribute)?.to_owned(),
                        attribute.value().to_owned(),
                    ));
                }
            }
        }
        attributes.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        Ok(attributes)
    }

    /// The element's qualified name exactly as the source spells it.
    ///
    /// `roxmltree` resolves qualified names to (namespace, local name) and does
    /// not keep the source prefix, and recovering it by looking a URI up in
    /// scope picks the wrong prefix when two prefixes bind the same URI. The
    /// source range is authoritative, so it is used instead.
    fn element_qname(&self, node: Node<'_, '_>) -> Result<&'s str, C14nError> {
        let range = node.range();
        let text = self
            .source
            .get(range.start..range.end)
            .ok_or(C14nError::Malformed)?;
        let rest = text.strip_prefix('<').ok_or(C14nError::Malformed)?;
        let end = rest
            .find(|character: char| {
                character.is_whitespace() || character == '>' || character == '/'
            })
            .unwrap_or(rest.len());
        let qname = &rest[..end];
        if qname.is_empty() {
            return Err(C14nError::Malformed);
        }
        Ok(qname)
    }

    fn attribute_qname(
        &self,
        attribute: openszigno_core::roxmltree::Attribute<'_, '_>,
    ) -> Result<&'s str, C14nError> {
        let range = attribute.range_qname();
        self.source
            .get(range.start..range.end)
            .filter(|qname| !qname.is_empty())
            .ok_or(C14nError::Malformed)
    }
}

/// The URI bound to `prefix` in this element's scope, or the empty string.
fn in_scope(node: Node<'_, '_>, prefix: &str) -> String {
    let wanted = if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    };
    node.namespaces()
        .find(|namespace| namespace.name() == wanted)
        .map_or_else(String::new, |namespace| namespace.uri().to_owned())
}

fn qname_prefix(qname: &str) -> &str {
    qname.split_once(':').map_or("", |(prefix, _)| prefix)
}

fn escape_text(text: &str, out: &mut Vec<u8>) {
    for byte in text.bytes() {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'>' => out.extend_from_slice(b"&gt;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            other => out.push(other),
        }
    }
}

fn escape_attribute(value: &str, out: &mut Vec<u8>) {
    for byte in value.bytes() {
        match byte {
            b'&' => out.extend_from_slice(b"&amp;"),
            b'<' => out.extend_from_slice(b"&lt;"),
            b'"' => out.extend_from_slice(b"&quot;"),
            b'\t' => out.extend_from_slice(b"&#x9;"),
            b'\n' => out.extend_from_slice(b"&#xA;"),
            b'\r' => out.extend_from_slice(b"&#xD;"),
            other => out.push(other),
        }
    }
}
