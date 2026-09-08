//! The recipient side of the `encrypt` transform: reading a certificate and
//! deciding whether a document can be addressed to it.
//!
//! A recipient is public material only. This module holds a certificate, the
//! RSA public key inside it, and the `issuerAndSerialNumber` pair that names
//! it in a CMS `KeyTransRecipientInfo`. No private key is ever read here, and
//! nothing this module returns can carry one.

use cms::cert::IssuerAndSerialNumber;
use cms::enveloped_data::RecipientIdentifier;
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::error::{Error, ErrorCode};

/// One certificate a document may be encrypted for.
///
/// It is built from the certificate bytes alone: a recipient is chosen by the
/// caller, never derived from a dossier, and nothing here is secret.
#[derive(Clone, Debug)]
pub struct Recipient {
    certificate: Certificate,
    public: rsa::RsaPublicKey,
}

impl Recipient {
    /// Read one recipient certificate, PEM or DER.
    ///
    /// A file that is not an X.509 certificate is
    /// [`ErrorCode::InvalidRecipientCertificate`]; one whose subject public
    /// key is not RSA is [`ErrorCode::UnsupportedRecipientKey`], because the
    /// only key transport the reader implements is RSA. Neither message
    /// quotes the certificate or the path.
    pub fn from_certificate(bytes: &[u8]) -> Result<Self, Error> {
        use rsa::pkcs8::DecodePublicKey as _;

        let certificate = parse_certificate(bytes)?;
        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let der = spki.to_der().map_err(|_| invalid_certificate())?;
        let public = rsa::RsaPublicKey::from_public_key_der(&der).map_err(|_| {
            Error::new(
                ErrorCode::UnsupportedRecipientKey,
                "a recipient certificate does not carry an RSA public key; \
                 only RSA key transport can be written",
            )
        })?;
        Ok(Self {
            certificate,
            public,
        })
    }

    /// The RSA public key the content-encryption key is wrapped under.
    pub(super) fn public_key(&self) -> &rsa::RsaPublicKey {
        &self.public
    }

    /// How this recipient is named in a `KeyTransRecipientInfo`.
    ///
    /// Always `issuerAndSerialNumber`: it is the form every certificate can
    /// be named by, whereas `subjectKeyIdentifier` needs an extension a
    /// certificate need not carry. The reader accepts both.
    pub(super) fn identifier(&self) -> RecipientIdentifier {
        RecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: self.certificate.tbs_certificate.issuer.clone(),
            serial_number: self.certificate.tbs_certificate.serial_number.clone(),
        })
    }

    /// The instant the certificate stops being valid, as seconds since the
    /// Unix epoch.
    ///
    /// This crate consults no clock, so it only reports the field; deciding
    /// what to do about an expired recipient is the caller's, which is where
    /// the clock lives.
    pub fn not_after_unix(&self) -> i64 {
        i64::try_from(
            self.certificate
                .tbs_certificate
                .validity
                .not_after
                .to_unix_duration()
                .as_secs(),
        )
        .unwrap_or(i64::MAX)
    }
}

fn invalid_certificate() -> Error {
    Error::new(
        ErrorCode::InvalidRecipientCertificate,
        "a recipient certificate is not a readable X.509 certificate; \
         it must be DER, or PEM holding a CERTIFICATE block",
    )
}

/// Read a certificate from DER, or from the first `CERTIFICATE` block of a
/// PEM file.
///
/// DER is tried first because it has no ambiguity; PEM is scanned only when
/// the bytes are text carrying an armour header, so a bundle whose first
/// block is something else, or which carries a trailing comment, still loads.
fn parse_certificate(bytes: &[u8]) -> Result<Certificate, Error> {
    if let Ok(certificate) = Certificate::from_der(bytes) {
        return Ok(certificate);
    }
    let body = first_certificate_block(bytes).ok_or_else(invalid_certificate)?;
    Certificate::from_der(&body).map_err(|_| invalid_certificate())
}

/// The DER body of the first `CERTIFICATE` PEM block in `bytes`.
fn first_certificate_block(bytes: &[u8]) -> Option<Vec<u8>> {
    const HEADER: &str = "-----BEGIN CERTIFICATE-----";
    const FOOTER: &str = "-----END CERTIFICATE-----";

    let text = std::str::from_utf8(bytes).ok()?;
    let start = text.find(HEADER)?;
    let after = &text[start..];
    let end = after.find(FOOTER)? + FOOTER.len();
    pem_rfc7468::decode_vec(after[..end].as_bytes())
        .ok()
        .map(|(_, body)| body)
}

#[cfg(test)]
mod tests {
    //! Unit tests for certificate reading. The round trips, which need a real
    //! key pair, live in `tests/encryption.rs`.

    use super::*;

    #[test]
    fn bytes_that_are_not_a_certificate_are_refused() {
        for bytes in [b"".as_slice(), b"not a certificate", &[0x30, 0x82, 0x01]] {
            let error = Recipient::from_certificate(bytes).expect_err("not a certificate");
            assert_eq!(error.code(), ErrorCode::InvalidRecipientCertificate);
        }
    }

    #[test]
    fn a_pem_file_without_a_certificate_block_is_refused() {
        let armour = format!(
            "-----{}PUBLIC KEY-----\nAAAA\n-----{}PUBLIC KEY-----\n",
            "BEGIN ", "END "
        );
        let error =
            Recipient::from_certificate(armour.as_bytes()).expect_err("no certificate block");
        assert_eq!(error.code(), ErrorCode::InvalidRecipientCertificate);
        assert!(first_certificate_block(armour.as_bytes()).is_none());
    }

    #[test]
    fn a_truncated_certificate_block_is_refused() {
        let armour = format!("-----{}CERTIFICATE-----\nAAAA\n", "BEGIN ");
        assert!(first_certificate_block(armour.as_bytes()).is_none());
    }
}
