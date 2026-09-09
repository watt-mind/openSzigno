//! Container timestamps: writing the `es:TimeStamp` a dossier carries on its
//! own, without a signature.
//!
//! A `xades:SignatureTimeStamp` says when a signature existed. An
//! `es:TimeStamp` says when a *container* existed: it protects the elements
//! its `xades:Include` children name, and it needs no key, no certificate and
//! no signer at all. One RFC 3161 token over the elements the format mandates
//! is the whole artefact.
//!
//! # What is written, and why exactly this shape
//!
//! The element this module writes is the one
//! [`openszigno_verify::estimestamp`](https://docs.rs/openszigno-verify)
//! already checks, and every choice below is that verifier's rule read
//! backwards:
//!
//! | Choice | The rule it satisfies |
//! | :--- | :--- |
//! | The element is a direct child of `es:Dossier`, or of one `es:Document`. | Anywhere else the format does not say what the timestamp protects, and nothing is digested. |
//! | `xades:Include` names the `es:DossierProfile` and the `es:Documents`, or the document's `es:DocumentProfile` and its payload `ds:Object`. | The reference-scope rule for container timestamps. A timestamp over the payload alone would leave the profile rewritable. |
//! | `ds:CanonicalizationMethod` names exclusive C14N 1.0, and each included element is canonicalized on its own and the results concatenated in `Include` order. | XAdES 7.1.4.3.1, as the verifier recomputes it. The method is written out rather than defaulted so the two sides cannot disagree about what "the default" was. |
//! | The token is an RFC 3161 `TimeStampToken` over the SHA-256 imprint of those octets, base64 in one `xades:EncapsulatedTimeStamp`. | The token machinery a signature timestamp goes through, unchanged. |
//! | Anything else the element carries, `xades:CertificateValues` included, sits outside the `Include` list. | Only what an `Include` names is digested, so evidence added beside the token cannot change what the token attests to. |
//!
//! # Timestamping is not verification
//!
//! Nothing here checks anything about the dossier. What is written says that
//! a timestamp authority the caller named saw this imprint; whether the
//! container is anything, and whether the authority is anybody, are questions
//! only `openszigno verify` answers against trust material the caller
//! supplies.

use openszigno_core::ParseOptions;
use openszigno_core::roxmltree::Node;

use super::dsig::{C14N_EXCLUSIVE, Lookup, Working, XMLDSIG_NS, base64};
use super::error::{SignError, SignErrorCode};
use super::names;
use super::tsa;
use super::xades::XADES_NS;
use super::{FragmentEdit, SignScope, TimestampFn, fill_in};

/// How many identifiers this module will try before giving up.
///
/// A dossier that already holds every candidate is refused rather than
/// searched further; nothing legitimate reaches this.
const MAX_SHARED_IDENTIFIERS: usize = 64;

/// What a container timestamp covers, and therefore where it goes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampScope {
    /// One `es:TimeStamp` on the dossier, covering its `es:DossierProfile`
    /// and every document through `es:Documents`.
    Dossier,
    /// One `es:TimeStamp` per selected document, inside that `es:Document`,
    /// covering its `es:DocumentProfile` and its payload `ds:Object`.
    Document,
}

impl TimestampScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Dossier => "dossier",
        }
    }

    /// The signature scope whose placement rules this one shares.
    ///
    /// Adding an `es:TimeStamp` changes the canonical form of the element it
    /// goes into exactly as adding a `ds:Signature` does, so the refusals are
    /// the same refusals and are made by the same code.
    const fn placement(self) -> SignScope {
        match self {
            Self::Document => SignScope::Document,
            Self::Dossier => SignScope::Dossier,
        }
    }
}

/// What to timestamp.
#[derive(Clone, Debug)]
pub struct TimestampRequest {
    pub scope: TimestampScope,
    /// `--document` selectors: `#<index>`, or a document's `object_ref`. An
    /// empty list means every modelled document, and is meaningless for
    /// [`TimestampScope::Dossier`].
    pub documents: Vec<String>,
    /// Certificates for the timestamp's own `xades:CertificateValues`: the
    /// authority's issuing CAs, so they travel with the dossier. They are not
    /// included in the imprint and say nothing about the token; a token that
    /// carries its own chain, which is what `certReq` asks for, needs none of
    /// them.
    pub certificate_values: Vec<Vec<u8>>,
}

/// One `es:TimeStamp` that was written.
#[derive(Clone, Debug)]
pub struct WrittenTimestamp {
    pub id: String,
    pub scope: TimestampScope,
    /// The index of the document the timestamp sits in, for document scope.
    pub document_index: Option<usize>,
    /// The token's `genTime`, RFC 3339 UTC seconds, as the authority stamped
    /// it. It is read back out of the token this run embedded, and says only
    /// what that token claims.
    pub gen_time: Option<String>,
}

/// The timestamped dossier.
pub struct TimestampedDossier {
    pub bytes: Vec<u8>,
    pub timestamps: Vec<WrittenTimestamp>,
}

/// One `es:TimeStamp` to write, resolved against the dossier.
struct Plan {
    id: String,
    scope: TimestampScope,
    document_index: Option<usize>,
    /// Where the element goes, as a byte offset into the working text.
    insert_at: usize,
    /// The `Id`s the `xades:Include` children name, in the order they are
    /// written, which is the order their canonical octets are concatenated in.
    includes: Vec<String>,
    element: String,
}

/// The placeholder a token is written under until the authority has answered.
fn token_placeholder(id: &str) -> String {
    format!("@@openszigno-container-timestamp:{id}@@")
}

/// Timestamp `bytes`, and return the dossier with the `es:TimeStamp` elements
/// in it.
///
/// `stamp` is called once per timestamp with the DER of an RFC 3161
/// `TimeStampReq` over the imprint, and must return the authority's answer.
/// This crate opens no socket: the destination policy, the timeouts and the
/// size caps belong to the caller that already owns them.
pub fn timestamp(
    bytes: &[u8],
    options: &ParseOptions,
    request: &TimestampRequest,
    stamp: &mut TimestampFn<'_>,
) -> Result<TimestampedDossier, SignError> {
    let dossier = openszigno_core::parse_with_options(bytes, options)
        .map_err(|error| SignError::failed(error.message().to_owned()))?;
    let text = super::normalise_declaration(
        openszigno_core::XmlSource::decode(bytes, &options.limits)
            .map_err(|error| SignError::failed(error.message().to_owned()))?
            .text(),
    );

    let working = Working::parse(&text)?;
    let plans = working.with_tree(|lookup| {
        super::refuse_unsafe_placement(lookup, request.scope.placement())?;
        let targets = super::targets(&dossier, request.scope.placement(), &request.documents)?;
        plan_timestamps(lookup, &dossier, request, &targets)
    })?;

    let text = insert_elements(text, &plans);
    fill_tokens(&text, &plans, stamp)
}

/// Resolve every `es:TimeStamp` this run writes: its identifier, what it
/// includes, and where the element goes.
fn plan_timestamps(
    lookup: &Lookup<'_>,
    dossier: &openszigno_core::Dossier,
    request: &TimestampRequest,
    targets: &[&openszigno_core::Document],
) -> Result<Vec<Plan>, SignError> {
    let namespace = dossier.namespace.as_str();
    // Everything below this line that ends up in the element came out of the
    // dossier, and the dossier is untrusted input.
    names::check_namespace(namespace)?;
    let mut plans = Vec::new();
    match request.scope {
        TimestampScope::Dossier => {
            let profile = lookup.dossier_child_id(namespace, "DossierProfile")?;
            let documents = lookup.dossier_child_id(namespace, "Documents")?;
            plans.push(build_plan(
                lookup,
                namespace,
                PlanSpec {
                    base_id: "ts-dossier".to_owned(),
                    scope: TimestampScope::Dossier,
                    document_index: None,
                    container: lookup.root(),
                    includes: vec![profile, documents],
                    certificate_values: &request.certificate_values,
                },
            )?);
        }
        TimestampScope::Document => {
            for document in targets {
                let node = lookup.by_id(&document.object_ref).ok_or_else(|| {
                    SignError::new(
                        SignErrorCode::DocumentNotSignable,
                        format!(
                            "document {} has no payload ds:Object to timestamp",
                            document.index
                        ),
                    )
                })?;
                let container = node
                    .parent()
                    .filter(|parent| parent.is_element())
                    .ok_or_else(|| {
                        SignError::new(
                            SignErrorCode::DocumentNotSignable,
                            format!("document {} has no es:Document element", document.index),
                        )
                    })?;
                let profile = lookup.document_profile_id(container, namespace).ok_or_else(|| {
                    SignError::new(
                        SignErrorCode::DocumentNotSignable,
                        format!(
                            "document {} has no es:DocumentProfile with an Id, so nothing can reference it",
                            document.index
                        ),
                    )
                })?;
                plans.push(build_plan(
                    lookup,
                    namespace,
                    PlanSpec {
                        base_id: format!("ts-doc{}", document.index),
                        scope: TimestampScope::Document,
                        document_index: Some(document.index),
                        container,
                        includes: vec![profile, document.object_ref.clone()],
                        certificate_values: &request.certificate_values,
                    },
                )?);
            }
        }
    }
    Ok(plans)
}

/// What one timestamp covers, before its XML exists.
struct PlanSpec<'a, 'input, 'certs> {
    base_id: String,
    scope: TimestampScope,
    document_index: Option<usize>,
    /// The element the `es:TimeStamp` becomes the last child of.
    container: Node<'a, 'input>,
    /// The `Id`s the mandated elements carry, in `Include` order.
    includes: Vec<String>,
    /// Certificates to place in the element's `xades:CertificateValues`.
    certificate_values: &'certs [Vec<u8>],
}

/// Assemble one timestamp's element, refusing the placements that would break
/// what is already in the dossier.
fn build_plan(
    lookup: &Lookup<'_>,
    namespace: &str,
    spec: PlanSpec<'_, '_, '_>,
) -> Result<Plan, SignError> {
    let PlanSpec {
        base_id,
        scope,
        document_index,
        container,
        includes,
        certificate_values,
    } = spec;
    for id in &includes {
        names::check_id("Id", id)?;
    }
    refuse_existing_timestamp(container, namespace)?;
    super::refuse_broken_cover(lookup, container)?;
    let id = allocate_id(lookup, &base_id)?;

    let mut element = format!(
        "<es:TimeStamp xmlns:es=\"{}\" xmlns:ds=\"{XMLDSIG_NS}\" xmlns:xades=\"{XADES_NS}\" Id=\"{}\">",
        names::attribute(namespace),
        names::attribute(&id)
    );
    // Written out rather than left to the default. XAdES 7.1.4.3.1 makes
    // inclusive C14N 1.0 the default for a timestamp that names no method,
    // and a reader that took a different view of the default would recompute
    // the imprint over other octets; naming the algorithm removes the
    // question.
    element.push_str(&format!(
        "<ds:CanonicalizationMethod Algorithm=\"{C14N_EXCLUSIVE}\"/>"
    ));
    for include in &includes {
        element.push_str(&format!(
            "<xades:Include URI=\"#{}\"/>",
            names::attribute(include)
        ));
    }
    element.push_str(&format!(
        "<xades:EncapsulatedTimeStamp>{}</xades:EncapsulatedTimeStamp>",
        token_placeholder(&id)
    ));
    if !certificate_values.is_empty() {
        element.push_str("<xades:CertificateValues>");
        for certificate in certificate_values {
            element.push_str(&format!(
                "<xades:EncapsulatedX509Certificate>{}</xades:EncapsulatedX509Certificate>",
                base64(certificate)
            ));
        }
        element.push_str("</xades:CertificateValues>");
    }
    element.push_str("</es:TimeStamp>");

    Ok(Plan {
        id,
        scope,
        document_index,
        insert_at: lookup.insert_offset(container)?,
        includes,
        element,
    })
}

/// Refuse a placement that already carries a container timestamp.
///
/// Two `es:TimeStamp` elements in one place are two statements about the same
/// container, and this build has no way to say which the caller meant to add
/// to. Refusing is the honest answer; the alternative is a file whose second
/// timestamp silently changes what the first one is read alongside.
fn refuse_existing_timestamp(container: Node<'_, '_>, namespace: &str) -> Result<(), SignError> {
    let existing = container.children().any(|child| {
        child.is_element()
            && child.tag_name().name() == "TimeStamp"
            && child.tag_name().namespace() == Some(namespace)
    });
    if existing {
        return Err(SignError::new(
            SignErrorCode::TimestampExists,
            "this dossier already carries an es:TimeStamp at the placement this run would write one",
        ));
    }
    Ok(())
}

/// The `Id` this timestamp gets: the deterministic one, or the first free
/// disambiguation of it.
fn allocate_id(lookup: &Lookup<'_>, base: &str) -> Result<String, SignError> {
    for attempt in 1..=MAX_SHARED_IDENTIFIERS {
        let candidate = if attempt == 1 {
            base.to_owned()
        } else {
            format!("{base}-{attempt}")
        };
        if lookup.by_id(&candidate).is_none() {
            return Ok(candidate);
        }
    }
    Err(SignError::new(
        SignErrorCode::TimestampExists,
        "this dossier already holds every identifier a timestamp here could be given",
    ))
}

/// Splice every element into the text, last offset first so the offsets of the
/// ones still to come stay valid.
fn insert_elements(text: String, plans: &[Plan]) -> String {
    let mut ordered: Vec<&Plan> = plans.iter().collect();
    ordered.sort_by_key(|plan| std::cmp::Reverse(plan.insert_at));
    let mut text = text;
    for plan in ordered {
        text.insert_str(plan.insert_at, &plan.element);
    }
    text
}

/// The second pass: the imprint over the included elements as they now stand,
/// one token per timestamp, and the placeholder replaced inside its own
/// element and nowhere else.
fn fill_tokens(
    text: &str,
    plans: &[Plan],
    stamp: &mut TimestampFn<'_>,
) -> Result<TimestampedDossier, SignError> {
    let working = Working::parse(text)?;
    let prepared = working.with_tree(|lookup| {
        plans
            .iter()
            .map(|plan| {
                // XAdES 7.1.4.3.1: each included element canonicalized on its
                // own, concatenated in `Include` order. `canonical_by_id` is
                // the exclusive C14N the element's own
                // `ds:CanonicalizationMethod` names.
                let mut octets = Vec::new();
                for include in &plan.includes {
                    octets.extend_from_slice(&lookup.canonical_by_id(include)?);
                }
                Ok((octets, lookup.element_range(&plan.id)?))
            })
            .collect::<Result<Vec<_>, SignError>>()
    })?;

    let mut edits = Vec::new();
    let mut written = Vec::new();
    for (plan, (octets, range)) in plans.iter().zip(prepared) {
        let query = tsa::timestamp_request(&octets)?;
        let response = stamp(&query).map_err(|reason| {
            SignError::new(
                SignErrorCode::TsaFailed,
                format!("the timestamp authority could not be used: {reason}"),
            )
        })?;
        let token = tsa::timestamp_token(&response, &octets)?;
        written.push(WrittenTimestamp {
            id: plan.id.clone(),
            scope: plan.scope,
            document_index: plan.document_index,
            gen_time: tsa::token_gen_time(&token),
        });
        edits.push(FragmentEdit {
            range,
            values: vec![(token_placeholder(&plan.id), base64(&token))],
        });
    }
    Ok(TimestampedDossier {
        bytes: fill_in(working.text(), edits).into_bytes(),
        timestamps: written,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scope names are the ones the report and the flag use.
    #[test]
    fn scope_names_are_the_ones_the_report_uses() {
        assert_eq!(TimestampScope::Document.as_str(), "document");
        assert_eq!(TimestampScope::Dossier.as_str(), "dossier");
        assert_eq!(TimestampScope::Dossier.placement(), SignScope::Dossier);
        assert_eq!(TimestampScope::Document.placement(), SignScope::Document);
    }

    #[test]
    fn a_placeholder_is_derived_from_the_identifier_alone() {
        assert_ne!(
            token_placeholder("ts-dossier"),
            token_placeholder("ts-doc0")
        );
        assert!(token_placeholder("ts-doc0").contains("ts-doc0"));
    }

    #[test]
    fn an_identifier_already_in_the_dossier_is_disambiguated() {
        let working =
            Working::parse("<a xmlns=\"urn:x\"><b Id=\"ts-dossier\"/></a>").expect("this parses");
        working
            .with_tree(|lookup| {
                assert_eq!(allocate_id(lookup, "ts-dossier")?, "ts-dossier-2");
                assert_eq!(allocate_id(lookup, "ts-doc0")?, "ts-doc0");
                Ok(())
            })
            .expect("an identifier is available");
    }

    /// A second timestamp at one placement is refused, and a timestamp
    /// somewhere else in the dossier is not that placement.
    #[test]
    fn a_placement_that_already_carries_a_timestamp_is_refused() {
        let working = Working::parse(
            "<Dossier xmlns=\"urn:es\"><DossierProfile Id=\"p\"/><Documents Id=\"d\">\
<Document><TimeStamp/></Document></Documents></Dossier>",
        )
        .expect("this parses");
        working
            .with_tree(|lookup| {
                let root = lookup.root();
                refuse_existing_timestamp(root, "urn:es").expect("the dossier level is free");
                let document = root
                    .children()
                    .filter(Node::is_element)
                    .nth(1)
                    .and_then(|documents| documents.children().find(Node::is_element))
                    .expect("the document is there");
                let error = refuse_existing_timestamp(document, "urn:es")
                    .expect_err("that document already carries one");
                assert_eq!(error.code(), SignErrorCode::TimestampExists);
                // A `TimeStamp` from another vocabulary is not this one.
                refuse_existing_timestamp(document, "urn:other")
                    .expect("a foreign element decides nothing");
                Ok(())
            })
            .expect("the lookup runs");
    }

    /// Elements are spliced last offset first, so every one of them lands
    /// where the plan said it would.
    #[test]
    fn every_element_lands_at_the_offset_the_plan_named() {
        let text = "<a><x/><y/></a>".to_owned();
        let plan = |insert_at: usize, element: &str| Plan {
            id: "id".to_owned(),
            scope: TimestampScope::Dossier,
            document_index: None,
            insert_at,
            includes: Vec::new(),
            element: element.to_owned(),
        };
        let filled = insert_elements(text, &[plan(7, "<p/>"), plan(11, "<q/>")]);
        assert_eq!(filled, "<a><x/><p/><y/><q/></a>");
    }
}
