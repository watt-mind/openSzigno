//! The stable machine-readable categories a refused signing run reports.
//!
//! Every code here names something about the caller's request or about the
//! dossier the caller handed in. None of them ever quotes key material, a
//! passphrase, or anything derived from either: a refusal says which input is
//! unusable and stops there.

use serde::Serialize;
use thiserror::Error;

/// Stable machine-readable categories returned by the signing library.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignErrorCode {
    InvalidSigningKey,
    InvalidSigningCertificate,
    SigningKeyMismatch,
    SigningCertificateRequired,
    DocumentNotFound,
    DocumentNotSignable,
    DocumentAlreadySigned,
    TsaFailed,
    SignFailed,
}

impl SignErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSigningKey => "invalid_signing_key",
            Self::InvalidSigningCertificate => "invalid_signing_certificate",
            Self::SigningKeyMismatch => "signing_key_mismatch",
            Self::SigningCertificateRequired => "signing_certificate_required",
            Self::DocumentNotFound => "document_not_found",
            Self::DocumentNotSignable => "document_not_signable",
            Self::DocumentAlreadySigned => "document_already_signed",
            Self::TsaFailed => "tsa_failed",
            Self::SignFailed => "sign_failed",
        }
    }

    /// The process exit status the CLI reports this refusal with.
    ///
    /// Unusable inputs are exit 4, the status every other command uses for
    /// "the material this run was given cannot be used". A run that got as far
    /// as producing signature material and then could not finish is exit 5.
    pub const fn exit(self) -> u8 {
        match self {
            Self::TsaFailed | Self::SignFailed => 5,
            _ => 4,
        }
    }
}

/// One refused signing run.
///
/// The message names a document by index only, and never carries a title, a
/// path, payload content, a certificate subject, or any byte of key material.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct SignError {
    code: SignErrorCode,
    message: String,
}

impl SignError {
    pub(crate) fn new(code: SignErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn key(message: impl Into<String>) -> Self {
        Self::new(SignErrorCode::InvalidSigningKey, message)
    }

    pub(crate) fn certificate(message: impl Into<String>) -> Self {
        Self::new(SignErrorCode::InvalidSigningCertificate, message)
    }

    pub(crate) fn failed(message: impl Into<String>) -> Self {
        Self::new(SignErrorCode::SignFailed, message)
    }

    pub const fn code(&self) -> SignErrorCode {
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
    fn every_code_has_a_snake_case_string_and_an_exit_status() {
        for code in [
            SignErrorCode::InvalidSigningKey,
            SignErrorCode::InvalidSigningCertificate,
            SignErrorCode::SigningKeyMismatch,
            SignErrorCode::SigningCertificateRequired,
            SignErrorCode::DocumentNotFound,
            SignErrorCode::DocumentNotSignable,
            SignErrorCode::DocumentAlreadySigned,
            SignErrorCode::TsaFailed,
            SignErrorCode::SignFailed,
        ] {
            let text = code.as_str();
            assert!(!text.is_empty());
            assert!(
                text.chars()
                    .all(|character| character.is_ascii_lowercase() || character == '_')
            );
            assert!(matches!(code.exit(), 4 | 5));
        }
        assert_eq!(SignErrorCode::TsaFailed.exit(), 5);
        assert_eq!(SignErrorCode::InvalidSigningKey.exit(), 4);
    }

    #[test]
    fn an_error_reports_its_code_and_message() {
        let error = SignError::key("the signing key could not be read");
        assert_eq!(error.code(), SignErrorCode::InvalidSigningKey);
        assert_eq!(error.message(), "the signing key could not be read");
        assert_eq!(error.to_string(), "the signing key could not be read");
    }
}
