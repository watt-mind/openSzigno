use serde::Serialize;
use thiserror::Error;

/// Stable machine-readable categories returned by the core library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    InputTooLarge,
    UnsupportedEncoding,
    InvalidEncoding,
    UnsafeXml,
    InvalidXml,
    WrongRoot,
    MissingElement,
    InvalidAttribute,
    DuplicateId,
    UnresolvedObjref,
    TooManyDocuments,
    InvalidBase64,
    DecodedTooLarge,
    SourceSizeMismatch,
    InvalidZip,
    ZipMemberLimit,
    ZipSizeLimit,
    ZipRatioLimit,
    UnsafeZipMember,
    UnsupportedZipMember,
    InvalidDecryptionKey,
    InvalidDecryptionCertificate,
    DecryptionCertificateRequired,
    DecryptionKeyMismatch,
    InvalidCms,
    DecryptFailed,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputTooLarge => "input_too_large",
            Self::UnsupportedEncoding => "unsupported_encoding",
            Self::InvalidEncoding => "invalid_encoding",
            Self::UnsafeXml => "unsafe_xml",
            Self::InvalidXml => "invalid_xml",
            Self::WrongRoot => "wrong_root",
            Self::MissingElement => "missing_element",
            Self::InvalidAttribute => "invalid_attribute",
            Self::DuplicateId => "duplicate_id",
            Self::UnresolvedObjref => "unresolved_objref",
            Self::TooManyDocuments => "too_many_documents",
            Self::InvalidBase64 => "invalid_base64",
            Self::DecodedTooLarge => "decoded_too_large",
            Self::SourceSizeMismatch => "source_size_mismatch",
            Self::InvalidZip => "invalid_zip",
            Self::ZipMemberLimit => "zip_member_limit",
            Self::ZipSizeLimit => "zip_size_limit",
            Self::ZipRatioLimit => "zip_ratio_limit",
            Self::UnsafeZipMember => "unsafe_zip_member",
            Self::UnsupportedZipMember => "unsupported_zip_member",
            Self::InvalidDecryptionKey => "invalid_decryption_key",
            Self::InvalidDecryptionCertificate => "invalid_decryption_certificate",
            Self::DecryptionCertificateRequired => "decryption_certificate_required",
            Self::DecryptionKeyMismatch => "decryption_key_mismatch",
            Self::InvalidCms => "invalid_cms",
            Self::DecryptFailed => "decrypt_failed",
        }
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct Error {
    code: ErrorCode,
    message: String,
}

impl Error {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
