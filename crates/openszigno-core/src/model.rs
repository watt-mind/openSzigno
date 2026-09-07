use serde::Serialize;

use crate::{DecodeOutcome, Error};

/// Resource limits applied while parsing and decoding a dossier.
///
/// Every limit except `max_total_decoded_bytes` is enforced by this crate.
/// `max_total_decoded_bytes` bounds the aggregate of all decoded documents and
/// must be enforced by the caller that decodes more than one document (the
/// CLI does so during extraction), because `decode_document` works on one
/// document at a time.
#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    /// Maximum size of the raw dossier file in bytes.
    pub max_input_bytes: u64,
    /// Maximum number of `es:Document` elements.
    pub max_documents: usize,
    /// Maximum number of Base64 characters in one payload after whitespace
    /// removal.
    pub max_base64_chars: usize,
    /// Maximum decoded size of one document in bytes.
    pub max_decoded_document_bytes: u64,
    /// Maximum aggregate decoded size across all documents; enforced by the
    /// caller, not by this crate.
    pub max_total_decoded_bytes: u64,
    /// Maximum number of members in a `zip` transform archive. The e-dossier
    /// format stores exactly one member, so this is a defence-in-depth bound.
    pub max_zip_members: usize,
    /// Maximum expanded size of the ZIP member in bytes.
    pub max_zip_expanded_bytes: u64,
    /// Maximum expanded/compressed ratio, checked on actual decoded bytes.
    pub max_zip_compression_ratio: u64,
    /// Maximum XML element nesting depth, checked before tree construction.
    pub max_xml_depth: usize,
    /// Maximum number of XML elements, checked before tree construction and
    /// again by the parser's own node limit.
    pub max_xml_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_documents: 256,
            max_base64_chars: 96 * 1024 * 1024,
            max_decoded_document_bytes: 64 * 1024 * 1024,
            max_total_decoded_bytes: 256 * 1024 * 1024,
            max_zip_members: 16,
            max_zip_expanded_bytes: 64 * 1024 * 1024,
            max_zip_compression_ratio: 100,
            max_xml_depth: 128,
            max_xml_nodes: 1_000_000,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct MimeType {
    pub media_type: String,
    pub subtype: String,
    pub extension: Option<String>,
    pub charset: Option<String>,
}

impl MimeType {
    pub fn essence(&self) -> String {
        format!("{}/{}", self.media_type, self.subtype)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Document {
    pub index: usize,
    pub title: String,
    pub creation_date: String,
    pub mime_type: MimeType,
    pub source_size: u64,
    pub object_ref: String,
    pub transforms: Vec<String>,
    #[serde(skip)]
    pub(crate) payload: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Dossier {
    pub title: String,
    pub category: Option<String>,
    pub creation_date: String,
    pub namespace: String,
    pub xml_encoding: String,
    pub documents: Vec<Document>,
    pub signatures_present: usize,
    pub timestamps_present: usize,
}

impl Dossier {
    pub fn decode_document(&self, index: usize, limits: &Limits) -> Result<DecodeOutcome, Error> {
        crate::decode::decode_document(
            self.documents.get(index).ok_or_else(|| {
                Error::new(
                    crate::ErrorCode::InvalidAttribute,
                    "document index is out of range",
                )
            })?,
            limits,
        )
    }
}
