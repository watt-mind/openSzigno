//! The stable machine-readable categories this crate refuses a build with.
//!
//! Every code here names something about the caller's request, never
//! something about a dossier that was read: this crate reads nothing.

use serde::Serialize;
use thiserror::Error;

/// Stable machine-readable categories returned by the author library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NoDocuments,
    TooManyDocuments,
    DecodedTooLarge,
    TotalSizeLimit,
    ZipRatioLimit,
    ZipFailed,
    UnsafeDocumentTitle,
    InvalidDossierTitle,
    InvalidMimeType,
    UnknownMimeType,
    NoRecipients,
    InvalidRecipientCertificate,
    UnsupportedRecipientKey,
    EncryptFailed,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoDocuments => "no_documents",
            Self::TooManyDocuments => "too_many_documents",
            Self::DecodedTooLarge => "decoded_too_large",
            Self::TotalSizeLimit => "total_size_limit",
            Self::ZipRatioLimit => "zip_ratio_limit",
            Self::ZipFailed => "zip_failed",
            Self::UnsafeDocumentTitle => "unsafe_document_title",
            Self::InvalidDossierTitle => "invalid_dossier_title",
            Self::InvalidMimeType => "invalid_mime_type",
            Self::UnknownMimeType => "unknown_mime_type",
            Self::NoRecipients => "no_recipients",
            Self::InvalidRecipientCertificate => "invalid_recipient_certificate",
            Self::UnsupportedRecipientKey => "unsupported_recipient_key",
            Self::EncryptFailed => "encrypt_failed",
        }
    }
}

/// One refused build. The message names a document by index only: a title, a
/// path, and payload content never appear in it.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_snake_case_string() {
        for code in [
            ErrorCode::NoDocuments,
            ErrorCode::TooManyDocuments,
            ErrorCode::DecodedTooLarge,
            ErrorCode::TotalSizeLimit,
            ErrorCode::ZipRatioLimit,
            ErrorCode::ZipFailed,
            ErrorCode::UnsafeDocumentTitle,
            ErrorCode::InvalidDossierTitle,
            ErrorCode::InvalidMimeType,
            ErrorCode::UnknownMimeType,
            ErrorCode::NoRecipients,
            ErrorCode::InvalidRecipientCertificate,
            ErrorCode::UnsupportedRecipientKey,
            ErrorCode::EncryptFailed,
        ] {
            let text = code.as_str();
            assert!(!text.is_empty());
            assert!(
                text.chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
            );
        }
    }

    #[test]
    fn an_error_reports_its_code_and_message() {
        let error = Error::new(ErrorCode::NoDocuments, "a dossier needs one document");
        assert_eq!(error.code(), ErrorCode::NoDocuments);
        assert_eq!(error.message(), "a dossier needs one document");
        assert_eq!(error.to_string(), "a dossier needs one document");
    }
}
