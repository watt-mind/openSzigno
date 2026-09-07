use roxmltree::Node;

use crate::xml::{XmlSource, id_map};
use crate::{
    Document, Dossier, Error, ErrorCode, Limits, MimeType, ParseOptions, StructuralWarning,
    StructuralWarningCode, XMLDSIG_NAMESPACE,
};

pub(crate) fn parse(bytes: &[u8], options: &ParseOptions) -> Result<Dossier, Error> {
    let limits = &options.limits;
    let source = XmlSource::decode(bytes, limits)?;
    let encoding = source.encoding().to_owned();
    let tree = source.parse_tree(limits)?;
    let root = tree.root_element();
    if root.tag_name().name() != "Dossier" {
        return Err(Error::new(
            ErrorCode::WrongRoot,
            "root element must be Dossier",
        ));
    }
    // A compatible profile may use its own namespace, but only one the caller
    // allows. The URI itself is never echoed: it can come from untrusted input.
    let namespace = root.tag_name().namespace().unwrap_or_default();
    if !options.allows(namespace) {
        return Err(Error::new(
            ErrorCode::WrongRoot,
            "root Dossier is in a namespace that is not allowed",
        ));
    }

    let mut warnings = Vec::new();
    validate_ids_and_objrefs(root, namespace, &mut warnings)?;

    let dossier_profile = required_direct_child(root, namespace, "DossierProfile")?;
    let documents_node = required_direct_child(root, namespace, "Documents")?;
    require_id(dossier_profile, "DossierProfile")?;
    let dossier_ref = require_objref(dossier_profile, "DossierProfile")?;
    let documents_id = require_id(documents_node, "Documents")?;
    if dossier_ref != documents_id {
        return Err(Error::new(
            ErrorCode::UnresolvedObjref,
            "DossierProfile OBJREF must identify the direct Documents element",
        ));
    }

    let document_nodes: Vec<_> = direct_children(documents_node, namespace, "Document").collect();
    if document_nodes.len() > limits.max_documents {
        return Err(Error::new(
            ErrorCode::TooManyDocuments,
            format!("dossier exceeds {} documents", limits.max_documents),
        ));
    }

    let mut documents = Vec::with_capacity(document_nodes.len());
    // Which `es:Document` produced which parsed document, so the signature
    // inventory can name the index a caller sees rather than a source
    // position; documents without a profile are skipped and have no index.
    let mut document_nodes_by_index = Vec::with_capacity(document_nodes.len());
    for (position, node) in document_nodes.into_iter().enumerate() {
        // Every Document must carry a DocumentProfile. One that does not (an
        // empty ds:Object placeholder, in practice) is reported and skipped
        // rather than failing the whole dossier.
        let mut profiles = direct_children(node, namespace, "DocumentProfile");
        let Some(profile) = profiles.next() else {
            warnings.push(StructuralWarning {
                code: StructuralWarningCode::DocumentWithoutProfile,
                message: format!(
                    "Document at source position {position} has no DocumentProfile and was skipped"
                ),
            });
            continue;
        };
        if profiles.next().is_some() {
            return Err(Error::new(
                ErrorCode::InvalidXml,
                "multiple DocumentProfile elements where one is required",
            ));
        }
        let index = documents.len();
        document_nodes_by_index.push((node, index));
        documents.push(parse_document(
            node,
            profile,
            index,
            namespace,
            limits,
            &mut warnings,
        )?);
    }

    let (signatures, timestamps) =
        crate::inventory::build(root, namespace, &document_nodes_by_index, &mut warnings);

    Ok(Dossier {
        title: required_child_text(dossier_profile, namespace, "Title")?,
        category: optional_child_text(dossier_profile, namespace, "E-category"),
        creation_date: dossier_creation_date(dossier_profile, namespace, &mut warnings),
        namespace: namespace.to_owned(),
        xml_encoding: encoding,
        documents,
        signatures_present: root
            .descendants()
            .filter(|node| is_element(*node, XMLDSIG_NAMESPACE, "Signature"))
            .count(),
        timestamps_present: root
            .descendants()
            .filter(|node| is_element(*node, namespace, "TimeStamp"))
            .count(),
        signatures,
        timestamps,
        warnings,
    })
}

fn parse_document(
    node: Node<'_, '_>,
    profile: Node<'_, '_>,
    index: usize,
    namespace: &str,
    limits: &Limits,
    warnings: &mut Vec<StructuralWarning>,
) -> Result<Document, Error> {
    require_id(profile, "DocumentProfile")?;
    let object_ref = require_objref(profile, "DocumentProfile")?;
    let title = required_child_text(profile, namespace, "Title")?;
    let creation_date = required_child_text(profile, namespace, "CreationDate")?;
    let format = required_direct_child(profile, namespace, "Format")?;
    let mime = required_direct_child(format, namespace, "MIME-Type")?;
    let source_size = parse_source_size(profile, index, namespace, limits, warnings)?;

    let base_transform = required_direct_child(profile, namespace, "BaseTransform")?;
    let transforms: Vec<String> = direct_children(base_transform, namespace, "Transform")
        .map(|transform| required_attribute(transform, "Algorithm").map(str::to_owned))
        .collect::<Result<_, _>>()?;
    if transforms.is_empty() {
        return Err(Error::new(
            ErrorCode::MissingElement,
            format!("document {index} has no transforms"),
        ));
    }

    let payload_objects: Vec<_> = direct_children(node, XMLDSIG_NAMESPACE, "Object").collect();
    if payload_objects.len() != 1 {
        return Err(Error::new(
            ErrorCode::InvalidXml,
            format!("document {index} must contain exactly one direct payload object"),
        ));
    }
    let matching_objects: Vec<_> = payload_objects
        .into_iter()
        .filter(|object| id_attribute(*object).as_deref() == Some(object_ref.as_str()))
        .collect();
    if matching_objects.len() != 1 {
        return Err(Error::new(
            ErrorCode::UnresolvedObjref,
            format!("document {index} does not resolve to exactly one direct payload object"),
        ));
    }
    let payload = direct_text(matching_objects[0]);
    if payload.len() > limits.max_base64_chars {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            format!("document {index} encoded payload exceeds the limit"),
        ));
    }

    let mime_type = MimeType {
        media_type: required_attribute(mime, "type")?.to_owned(),
        subtype: required_attribute(mime, "subtype")?.to_owned(),
        extension: optional_attribute(mime, "extension").map(str::to_owned),
        charset: optional_attribute(mime, "charSet")
            .or_else(|| optional_attribute(mime, "charset"))
            .map(str::to_owned),
    };
    let nested_dossier = is_nested_dossier(&mime_type);

    Ok(Document {
        index,
        title,
        creation_date,
        mime_type,
        source_size,
        object_ref,
        transforms,
        nested_dossier,
        payload,
    })
}

/// Read the optional `SourceSize`.
///
/// The element is optional because company-court dossiers occur without it.
/// When it is present the existing `sizeValue`/`sizeUnit` and declared-size
/// rules apply unchanged; when it is absent the omission is reported and the
/// decoded length is simply not checked against a declaration.
/// The dossier-level `CreationDate` is mandatory in the default profile but
/// missing from some company-court dossiers; its absence is a warning.
fn dossier_creation_date(
    profile: Node<'_, '_>,
    namespace: &str,
    warnings: &mut Vec<StructuralWarning>,
) -> Option<String> {
    let value = optional_child_text(profile, namespace, "CreationDate");
    if value.is_none() {
        warnings.push(StructuralWarning {
            code: StructuralWarningCode::CreationDateMissing,
            message: "the DossierProfile declares no CreationDate".to_owned(),
        });
    }
    value
}

fn parse_source_size(
    profile: Node<'_, '_>,
    index: usize,
    namespace: &str,
    limits: &Limits,
    warnings: &mut Vec<StructuralWarning>,
) -> Result<Option<u64>, Error> {
    let mut nodes = direct_children(profile, namespace, "SourceSize");
    let Some(node) = nodes.next() else {
        warnings.push(StructuralWarning {
            code: StructuralWarningCode::SourceSizeMissing,
            message: format!("document {index} declares no SourceSize"),
        });
        return Ok(None);
    };
    if nodes.next().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidXml,
            "multiple SourceSize elements where one is required",
        ));
    }
    let source_size = required_attribute(node, "sizeValue")?
        .parse::<u64>()
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidAttribute,
                format!("document {index} has an invalid source size"),
            )
        })?;
    if source_size > limits.max_decoded_document_bytes {
        return Err(Error::new(
            ErrorCode::DecodedTooLarge,
            format!("document {index} declares a source size above the limit"),
        ));
    }
    if required_attribute(node, "sizeUnit")? != "B" {
        return Err(Error::new(
            ErrorCode::InvalidAttribute,
            format!("document {index} source size unit must be B"),
        ));
    }
    Ok(Some(source_size))
}

/// A document that declares the nested-dossier media type, or the extension
/// company-court dossiers use for it, holds another dossier as its payload.
fn is_nested_dossier(mime: &MimeType) -> bool {
    mime.essence()
        .eq_ignore_ascii_case("application/nldossier2")
        || mime
            .extension
            .as_deref()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("dosszie"))
}

/// Check the XML ID space and every `OBJREF`.
///
/// A duplicate or empty ID stays a hard error, and so does an `OBJREF` on a
/// `DossierProfile` or a `DocumentProfile`, which the structural model relies
/// on. Real company-court dossiers do carry `SignatureProfile` references that
/// resolve to nothing; those are reported as warnings instead of rejecting an
/// otherwise readable dossier.
fn validate_ids_and_objrefs(
    root: Node<'_, '_>,
    namespace: &str,
    warnings: &mut Vec<StructuralWarning>,
) -> Result<(), Error> {
    let ids = id_map(root)?;

    for node in root.descendants().filter(Node::is_element) {
        for attribute in node
            .attributes()
            .filter(|attribute| attribute.namespace().is_none() && attribute.name() == "OBJREF")
        {
            if ids.contains_key(normalize_reference(attribute.value())) {
                continue;
            }
            let local = node.tag_name().name();
            if node.tag_name().namespace() == Some(namespace)
                && (local == "DossierProfile" || local == "DocumentProfile")
            {
                return Err(Error::new(
                    ErrorCode::UnresolvedObjref,
                    "every OBJREF must resolve to exactly one XML ID",
                ));
            }
            warnings.push(StructuralWarning {
                code: StructuralWarningCode::DanglingObjref,
                message: format!(
                    "{} OBJREF does not resolve to any XML ID",
                    reportable_name(local)
                ),
            });
        }
    }
    Ok(())
}

/// Element names are echoed only when they look like a schema name, so that an
/// attacker cannot smuggle arbitrary text out through a warning message.
fn reportable_name(name: &str) -> &str {
    let plain = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if plain { name } else { "an element" }
}

fn direct_children<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |child| is_element(*child, namespace, name))
}

fn required_direct_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &'static str,
) -> Result<Node<'a, 'input>, Error> {
    let mut matches = direct_children(node, namespace, name);
    let child = matches.next().ok_or_else(|| {
        Error::new(
            ErrorCode::MissingElement,
            format!("missing required {name} element"),
        )
    })?;
    if matches.next().is_some() {
        return Err(Error::new(
            ErrorCode::InvalidXml,
            format!("multiple {name} elements where one is required"),
        ));
    }
    Ok(child)
}

fn required_child_text(
    node: Node<'_, '_>,
    namespace: &str,
    name: &'static str,
) -> Result<String, Error> {
    let value = direct_text(required_direct_child(node, namespace, name)?);
    if value.is_empty() {
        return Err(Error::new(
            ErrorCode::MissingElement,
            format!("required {name} value is empty"),
        ));
    }
    Ok(value)
}

fn optional_child_text(node: Node<'_, '_>, namespace: &str, name: &'static str) -> Option<String> {
    direct_children(node, namespace, name)
        .next()
        .map(direct_text)
        .filter(|value| !value.is_empty())
}

fn direct_text(node: Node<'_, '_>) -> String {
    node.children()
        .filter(Node::is_text)
        .filter_map(|child| child.text())
        .collect::<String>()
        .trim()
        .to_owned()
}

fn required_attribute<'a>(node: Node<'a, '_>, name: &str) -> Result<&'a str, Error> {
    optional_attribute(node, name).ok_or_else(|| {
        Error::new(
            ErrorCode::InvalidAttribute,
            format!("missing required {name} attribute"),
        )
    })
}

fn optional_attribute<'a>(node: Node<'a, '_>, name: &str) -> Option<&'a str> {
    node.attribute(name).filter(|value| !value.is_empty())
}

fn require_objref(node: Node<'_, '_>, owner: &str) -> Result<String, Error> {
    optional_attribute(node, "OBJREF")
        .map(normalize_reference)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidAttribute,
                format!("{owner} requires a non-empty OBJREF"),
            )
        })
}

fn require_id(node: Node<'_, '_>, owner: &str) -> Result<String, Error> {
    id_attribute(node)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            Error::new(
                ErrorCode::InvalidAttribute,
                format!("{owner} requires a non-empty Id attribute"),
            )
        })
}

fn normalize_reference(value: &str) -> &str {
    value.strip_prefix('#').unwrap_or(value)
}

fn id_attribute(node: Node<'_, '_>) -> Option<String> {
    node.attribute("Id")
        .or_else(|| node.attribute("ID"))
        .or_else(|| node.attribute("id"))
        .map(str::to_owned)
}

fn is_element(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}
