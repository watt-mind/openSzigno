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
    CreationDateMissing,
    SignatureInventoryTruncated,
}

impl StructuralWarningCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DanglingObjref => "dangling_objref",
            Self::DocumentWithoutProfile => "document_without_profile",
            Self::SourceSizeMissing => "source_size_missing",
            Self::CreationDateMissing => "creation_date_missing",
            Self::SignatureInventoryTruncated => "signature_inventory_truncated",
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

/// The largest number of `ds:Signature` elements the inventory describes.
/// Beyond it the inventory is truncated and `signature_inventory_truncated`
/// is reported; `signatures_present` still counts every signature.
pub const MAX_INVENTORIED_SIGNATURES: usize = 64;
/// The largest number of `es:TimeStamp` elements the inventory describes.
pub const MAX_INVENTORIED_TIMESTAMPS: usize = 64;
/// The largest number of `ds:Reference` URIs listed for one signature.
pub const MAX_INVENTORIED_REFERENCE_URIS: usize = 16;
/// The largest number of XAdES qualifying-property names listed for one
/// signature.
pub const MAX_INVENTORIED_XADES_PROPERTIES: usize = 32;
/// The largest number of distinct digest algorithms listed for one signature.
pub const MAX_INVENTORIED_DIGEST_METHODS: usize = 16;
/// The largest number of `xades:ClaimedRole` values listed for one signature.
pub const MAX_INVENTORIED_CLAIMED_ROLES: usize = 8;
/// The largest number of characters of one claimed role that is echoed.
pub const MAX_INVENTORIED_CLAIMED_ROLE_CHARS: usize = 128;

/// Where a `ds:Signature` sits in the dossier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePlacement {
    /// Inside one `es:Document`; `document_index` names it.
    Document,
    /// A direct child of the root `es:Dossier`.
    Dossier,
    /// Inside another `ds:Signature`, a countersignature in practice.
    NestedInSignature,
    /// Anywhere else. The format does not say what such a signature covers.
    Other,
}

impl SignaturePlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Dossier => "dossier",
            Self::NestedInSignature => "nested_in_signature",
            Self::Other => "other",
        }
    }
}

/// Where an `es:TimeStamp` sits in the dossier.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TimestampPlacement {
    /// A direct child of the root `es:Dossier`.
    Dossier,
    /// A direct child of one `es:Document`; `document_index` names it.
    Document,
    /// Anywhere else.
    Other,
}

impl TimestampPlacement {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dossier => "dossier",
            Self::Document => "document",
            Self::Other => "other",
        }
    }
}

/// How many evidence elements one signature carries. These are **element
/// counts only**: nothing inside a certificate, CRL, OCSP response, or
/// timestamp token is decoded, and carrying evidence says nothing about
/// whether it is valid or even parsable.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SignatureEvidence {
    /// `xades:EncapsulatedX509Certificate` elements.
    pub certificates: usize,
    /// `xades:EncapsulatedCRLValue` elements.
    pub crls: usize,
    /// `xades:EncapsulatedOCSPValue` elements.
    pub ocsp_responses: usize,
    /// `xades:SignatureTimeStamp` elements.
    pub signature_timestamps: usize,
    /// `xades:ArchiveTimeStamp` elements.
    pub archive_timestamps: usize,
}

/// One `ds:Signature`, as the XML claims it.
///
/// Every field is unverified claimed metadata read at parse time. No
/// cryptography is performed, no certificate is decoded, and no reference is
/// resolved or dereferenced. A dossier can claim anything here.
#[derive(Clone, Debug, Serialize)]
pub struct SignatureSummary {
    /// The `Id` attribute, when it is present and looks like an ID.
    pub id: Option<String>,
    pub placement: SignaturePlacement,
    /// The index of the enclosing document, for `document` placement.
    pub document_index: Option<usize>,
    /// The `Id` of the enclosing signature, for `nested_in_signature`.
    pub parent_signature_id: Option<String>,
    /// `ds:CanonicalizationMethod/@Algorithm`, as declared.
    pub canonicalization_method: Option<String>,
    /// `ds:SignatureMethod/@Algorithm`, as declared.
    pub signature_method: Option<String>,
    /// The distinct `ds:DigestMethod/@Algorithm` values of the references, in
    /// document order.
    pub digest_methods: Vec<String>,
    /// Every `ds:Reference` in `ds:SignedInfo` is counted.
    pub reference_count: usize,
    /// Same-document reference URIs only, bounded to
    /// [`MAX_INVENTORIED_REFERENCE_URIS`]. Nothing is ever resolved or read.
    pub reference_uris: Vec<String>,
    /// The namespace of the `xades:QualifyingProperties` element, when the
    /// signature carries one in a recognised XAdES namespace.
    pub xades_namespace: Option<String>,
    /// The local names of the signed and unsigned qualifying properties that
    /// are present, in document order and bounded to
    /// [`MAX_INVENTORIED_XADES_PROPERTIES`]. Presence only: a property is
    /// never validated, and its content is not read.
    pub xades_properties: Vec<String>,
    /// The `xades:ClaimedRole` values of `xades:SignerRole` or
    /// `xades:SignerRoleV2`, as text, bounded to
    /// [`MAX_INVENTORIED_CLAIMED_ROLES`] entries of at most
    /// [`MAX_INVENTORIED_CLAIMED_ROLE_CHARS`] characters each.
    ///
    /// A claim like any other: the role is what the signature says about
    /// itself, and Hungarian AVDH material carries the citizen's asserted
    /// identity here. Nothing is validated, and the field is left out of the
    /// JSON entirely when the signature claims no role.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claimed_roles: Vec<String>,
    pub evidence: SignatureEvidence,
    /// The `xades:SigningTime` text, trimmed and otherwise unparsed. It is
    /// what the signature claims, not when anything happened.
    pub claimed_signing_time: Option<String>,
    /// `ds:X509Certificate` elements under `ds:KeyInfo`. A count; no
    /// certificate is decoded.
    pub key_info_certificates: usize,
}

/// One container `es:TimeStamp`, as the XML claims it. Unverified, like every
/// other part of the inventory.
#[derive(Clone, Debug, Serialize)]
pub struct TimestampSummary {
    pub placement: TimestampPlacement,
    /// The index of the enclosing document, for `document` placement.
    pub document_index: Option<usize>,
    /// `xades:Include` children, counted. None is ever resolved.
    pub include_count: usize,
    /// Whether a non-empty `xades:EncapsulatedTimeStamp` is present. The token
    /// is neither decoded nor verified.
    pub has_token: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Dossier {
    pub title: String,
    pub category: Option<String>,
    /// The declared creation date, or `None` when the `DossierProfile`
    /// omits `CreationDate`. Some company-court dossiers do.
    pub creation_date: Option<String>,
    pub namespace: String,
    pub xml_encoding: String,
    pub documents: Vec<Document>,
    pub signatures_present: usize,
    pub timestamps_present: usize,
    /// The bounded, unverified inventory of every `ds:Signature`, in document
    /// order. Claimed metadata only; see [`SignatureSummary`].
    pub signatures: Vec<SignatureSummary>,
    /// The bounded, unverified inventory of every container `es:TimeStamp`, in
    /// document order. Claimed metadata only; see [`TimestampSummary`].
    pub timestamps: Vec<TimestampSummary>,
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
