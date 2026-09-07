use std::collections::HashSet;

use encoding_rs::Encoding;
use roxmltree::{Document as XmlDocument, Node, ParsingOptions};

use crate::{
    Document, Dossier, ESZIGNO_NAMESPACE, Error, ErrorCode, Limits, MimeType, XMLDSIG_NAMESPACE,
};

pub(crate) fn parse(bytes: &[u8], limits: &Limits) -> Result<Dossier, Error> {
    if bytes.len() as u64 > limits.max_input_bytes {
        return Err(Error::new(
            ErrorCode::InputTooLarge,
            format!("input exceeds {} bytes", limits.max_input_bytes),
        ));
    }

    let (xml, encoding) = decode_xml(bytes)?;
    // Reject DTDs, deep nesting, and huge node counts before the recursive
    // tree parser runs; see `scan.rs` for why this cannot be delegated.
    crate::scan::prescan(&xml, limits)?;

    let options = ParsingOptions {
        allow_dtd: false,
        // The pre-scan bounds elements; the parser also counts text and
        // comment nodes, so its backstop limit is proportionally larger.
        nodes_limit: u32::try_from(limits.max_xml_nodes.saturating_mul(4)).unwrap_or(u32::MAX),
        ..ParsingOptions::default()
    };
    let tree = XmlDocument::parse_with_options(&xml, options).map_err(xml_error)?;
    let root = tree.root_element();
    if root.tag_name().name() != "Dossier" || root.tag_name().namespace() != Some(ESZIGNO_NAMESPACE)
    {
        return Err(Error::new(
            ErrorCode::WrongRoot,
            "root must be Dossier in the default Microsec e-Szigno namespace",
        ));
    }

    validate_ids_and_objrefs(root)?;

    let dossier_profile = required_direct_child(root, ESZIGNO_NAMESPACE, "DossierProfile")?;
    let documents_node = required_direct_child(root, ESZIGNO_NAMESPACE, "Documents")?;
    require_id(dossier_profile, "DossierProfile")?;
    let dossier_ref = require_objref(dossier_profile, "DossierProfile")?;
    let documents_id = require_id(documents_node, "Documents")?;
    if dossier_ref != documents_id {
        return Err(Error::new(
            ErrorCode::UnresolvedObjref,
            "DossierProfile OBJREF must identify the direct Documents element",
        ));
    }

    let document_nodes: Vec<_> =
        direct_children(documents_node, ESZIGNO_NAMESPACE, "Document").collect();
    if document_nodes.len() > limits.max_documents {
        return Err(Error::new(
            ErrorCode::TooManyDocuments,
            format!("dossier exceeds {} documents", limits.max_documents),
        ));
    }

    let mut documents = Vec::with_capacity(document_nodes.len());
    for (index, node) in document_nodes.into_iter().enumerate() {
        documents.push(parse_document(node, index, limits)?);
    }

    Ok(Dossier {
        title: required_child_text(dossier_profile, ESZIGNO_NAMESPACE, "Title")?,
        category: optional_child_text(dossier_profile, ESZIGNO_NAMESPACE, "E-category"),
        creation_date: required_child_text(dossier_profile, ESZIGNO_NAMESPACE, "CreationDate")?,
        namespace: ESZIGNO_NAMESPACE.to_owned(),
        xml_encoding: encoding,
        documents,
        signatures_present: root
            .descendants()
            .filter(|node| is_element(*node, XMLDSIG_NAMESPACE, "Signature"))
            .count(),
        timestamps_present: root
            .descendants()
            .filter(|node| is_element(*node, ESZIGNO_NAMESPACE, "TimeStamp"))
            .count(),
    })
}

fn parse_document(node: Node<'_, '_>, index: usize, limits: &Limits) -> Result<Document, Error> {
    let profile = required_direct_child(node, ESZIGNO_NAMESPACE, "DocumentProfile")?;
    require_id(profile, "DocumentProfile")?;
    let object_ref = require_objref(profile, "DocumentProfile")?;
    let title = required_child_text(profile, ESZIGNO_NAMESPACE, "Title")?;
    let creation_date = required_child_text(profile, ESZIGNO_NAMESPACE, "CreationDate")?;
    let format = required_direct_child(profile, ESZIGNO_NAMESPACE, "Format")?;
    let mime = required_direct_child(format, ESZIGNO_NAMESPACE, "MIME-Type")?;
    let source_size_node = required_direct_child(profile, ESZIGNO_NAMESPACE, "SourceSize")?;
    let source_size = required_attribute(source_size_node, "sizeValue")?
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
    if required_attribute(source_size_node, "sizeUnit")? != "B" {
        return Err(Error::new(
            ErrorCode::InvalidAttribute,
            format!("document {index} source size unit must be B"),
        ));
    }

    let base_transform = required_direct_child(profile, ESZIGNO_NAMESPACE, "BaseTransform")?;
    let transforms: Vec<String> = direct_children(base_transform, ESZIGNO_NAMESPACE, "Transform")
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

    Ok(Document {
        index,
        title,
        creation_date,
        mime_type: MimeType {
            media_type: required_attribute(mime, "type")?.to_owned(),
            subtype: required_attribute(mime, "subtype")?.to_owned(),
            extension: optional_attribute(mime, "extension").map(str::to_owned),
            charset: optional_attribute(mime, "charSet")
                .or_else(|| optional_attribute(mime, "charset"))
                .map(str::to_owned),
        },
        source_size,
        object_ref,
        transforms,
        payload,
    })
}

fn decode_xml(bytes: &[u8]) -> Result<(String, String), Error> {
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let label = declared_encoding(bytes).unwrap_or_else(|| "UTF-8".to_owned());
    let normalized = label.to_ascii_lowercase().replace('_', "-");
    if normalized == "utf-8" || normalized == "utf8" {
        return String::from_utf8(bytes.to_vec())
            .map(|text| (text, "UTF-8".to_owned()))
            .map_err(|_| Error::new(ErrorCode::InvalidEncoding, "input is not valid UTF-8"));
    }
    if normalized != "iso-8859-2" && normalized != "iso8859-2" {
        return Err(Error::new(
            ErrorCode::UnsupportedEncoding,
            "only UTF-8 and ISO-8859-2 XML encodings are supported",
        ));
    }
    let encoding = Encoding::for_label(b"iso-8859-2").expect("encoding_rs has ISO-8859-2");
    let (decoded, _, had_errors) = encoding.decode(bytes);
    if had_errors {
        return Err(Error::new(
            ErrorCode::InvalidEncoding,
            "input is not valid ISO-8859-2",
        ));
    }
    Ok((decoded.into_owned(), "ISO-8859-2".to_owned()))
}

/// Read the `encoding` pseudo-attribute of the XML declaration only. The
/// search is bounded to the declaration itself so that comments or content
/// later in the prolog cannot choose how the document is decoded.
fn declared_encoding(bytes: &[u8]) -> Option<String> {
    let prefix = &bytes[..bytes.len().min(512)];
    if !prefix.starts_with(b"<?xml") || !prefix.get(5..)?.first()?.is_ascii_whitespace() {
        return None;
    }
    let end = prefix.windows(2).position(|window| window == b"?>")?;
    let declaration = std::str::from_utf8(&prefix[5..end]).ok()?;
    let mut rest = declaration;
    while let Some(position) = rest.find("encoding") {
        let preceded_by_space = rest[..position]
            .chars()
            .next_back()
            .is_some_and(char::is_whitespace);
        rest = &rest[position + "encoding".len()..];
        if !preceded_by_space {
            continue;
        }
        let after = rest.trim_start();
        let Some(value) = after.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let quote = value.chars().next()?;
        if quote != '\'' && quote != '"' {
            return None;
        }
        let value = &value[quote.len_utf8()..];
        let close = value.find(quote)?;
        return Some(value[..close].to_owned());
    }
    None
}

/// Map a parser error to a stable code without echoing document content.
/// `roxmltree` error messages include element, attribute, and entity names,
/// which may be confidential; only the position is kept.
fn xml_error(error: roxmltree::Error) -> Error {
    match error {
        roxmltree::Error::DtdDetected => Error::new(
            ErrorCode::UnsafeXml,
            "DTD and entity declarations are not allowed",
        ),
        roxmltree::Error::NodesLimitReached
        | roxmltree::Error::AttributesLimitReached
        | roxmltree::Error::NamespacesLimitReached => {
            Error::new(ErrorCode::UnsafeXml, "XML exceeds the node limit")
        }
        other => {
            let position = other.pos();
            Error::new(
                ErrorCode::InvalidXml,
                format!(
                    "XML parsing failed at line {} column {}",
                    position.row, position.col
                ),
            )
        }
    }
}

fn validate_ids_and_objrefs(root: Node<'_, '_>) -> Result<(), Error> {
    let mut ids = HashSet::new();
    let mut refs = Vec::new();
    for node in root.descendants().filter(Node::is_element) {
        // Only unprefixed attributes take part in the ID space, matching the
        // lookups in `id_attribute` and `require_objref`.
        for attribute in node
            .attributes()
            .filter(|attribute| attribute.namespace().is_none())
        {
            match attribute.name() {
                "Id" | "ID" | "id" => {
                    if attribute.value().is_empty() || !ids.insert(attribute.value().to_owned()) {
                        return Err(Error::new(
                            ErrorCode::DuplicateId,
                            "XML IDs must be non-empty and unique",
                        ));
                    }
                }
                "OBJREF" => refs.push(normalize_reference(attribute.value()).to_owned()),
                _ => {}
            }
        }
    }
    if refs.iter().any(|reference| !ids.contains(reference)) {
        return Err(Error::new(
            ErrorCode::UnresolvedObjref,
            "every OBJREF must resolve to exactly one XML ID",
        ));
    }
    Ok(())
}

fn direct_children<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
    name: &'static str,
) -> impl Iterator<Item = Node<'a, 'input>> {
    node.children()
        .filter(move |child| is_element(*child, namespace, name))
}

fn required_direct_child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &'static str,
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
    namespace: &'static str,
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

fn optional_child_text(
    node: Node<'_, '_>,
    namespace: &'static str,
    name: &'static str,
) -> Option<String> {
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
