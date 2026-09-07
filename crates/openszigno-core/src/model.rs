use serde::Serialize;

use crate::{DecodeOutcome, Error, KNOWN_COMPATIBLE_NAMESPACES};

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

/// How a dossier is parsed: the resource limits and the namespaces whose
/// `Dossier` root element is accepted.
///
/// The default accepts [`KNOWN_COMPATIBLE_NAMESPACES`] only. A caller may add
/// further namespaces, but a dossier in an unlisted namespace stays a
/// `wrong_root` error rather than a best-effort parse.
#[derive(Clone, Debug)]
pub struct ParseOptions {
    pub limits: Limits,
    pub allowed_namespaces: Vec<String>,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            allowed_namespaces: KNOWN_COMPATIBLE_NAMESPACES
                .iter()
                .map(|namespace| (*namespace).to_owned())
                .collect(),
        }
    }
}

impl ParseOptions {
    /// The known-compatible namespaces with caller-chosen limits.
    pub fn with_limits(limits: Limits) -> Self {
        Self {
            limits,
            ..Self::default()
        }
    }

    pub(crate) fn allows(&self, namespace: &str) -> bool {
        self.allowed_namespaces
            .iter()
            .any(|allowed| allowed == namespace)
    }
}

/// Stable machine-readable categories of non-fatal structural findings.
///
/// These describe a dossier that parsed but does not conform to the default
/// profile. They never change an exit status by themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralWarningCode {
    DanglingObjref,
    DocumentWithoutProfile,
    SourceSizeMissing,
}

impl StructuralWarningCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DanglingObjref => "dangling_objref",
            Self::DocumentWithoutProfile => "document_without_profile",
            Self::SourceSizeMissing => "source_size_missing",
        }
    }
}

/// One non-fatal structural finding. The message never contains a title, a
/// path, or payload content.
#[derive(Clone, Debug, Serialize)]
pub struct StructuralWarning {
    pub code: StructuralWarningCode,
    pub message: String,
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
    /// The declared decoded size, or `None` when the profile omits
    /// `SourceSize`. Some company-court dossiers do.
    pub source_size: Option<u64>,
    pub object_ref: String,
    pub transforms: Vec<String>,
    /// The declared type marks this document as an embedded dossier.
    pub nested_dossier: bool,
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
    /// Non-fatal deviations from the default profile, in source order.
    pub warnings: Vec<StructuralWarning>,
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
