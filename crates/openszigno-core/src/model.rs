use serde::Serialize;

use crate::{DecodeOutcome, Error};

#[derive(Clone, Debug, Serialize)]
pub struct Limits {
    pub max_input_bytes: u64,
    pub max_documents: usize,
    pub max_base64_chars: usize,
    pub max_decoded_document_bytes: u64,
    pub max_total_decoded_bytes: u64,
    pub max_zip_members: usize,
    pub max_zip_expanded_bytes: u64,
    pub max_zip_compression_ratio: u64,
    pub max_xml_depth: usize,
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
