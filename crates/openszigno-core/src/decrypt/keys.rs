//! Recipient key loading and certificate matching.
//!
//! This is the half of the `encrypt` transform that never touches a CMS
//! message: loading the recipient's own RSA private key (PKCS#8, DER or PEM,
//! plain or passphrase protected), reading the certificate that names it, and
//! deciding whether a CMS `RecipientIdentifier` names that certificate, by
//! `issuerAndSerialNumber` or by `subjectKeyIdentifier`.

use der::asn1::OctetString;
use der::{Decode, Encode};
use rsa::RsaPrivateKey;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use cms::enveloped_data::RecipientIdentifier;
use const_oid::ObjectIdentifier;

use crate::{Error, ErrorCode};

/// X.509 `id-ce-subjectKeyIdentifier`.
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// The recipient private key `extract` decrypts with, together with the
/// certificate that lets a `RecipientInfo` be recognised as naming it.
///
/// The key bytes never leave this type: it has no accessor for them, no
/// `Debug` that could print them, and every error raised while loading it is
/// a fixed string that quotes nothing.
pub struct RecipientKey {
    /// Visible to the rest of `decrypt` only for the RSA key-transport
    /// unwrap in `cms::unwrap_key`, which needs the key itself rather than
    /// anything this module could compute from it.
    pub(super) private: RsaPrivateKey,
    /// DER of the certificate's `issuer` field, for `issuerAndSerialNumber`.
    issuer_der: Vec<u8>,
    /// DER of the certificate's `serialNumber`, for `issuerAndSerialNumber`.
    serial_der: Vec<u8>,
    /// The certificate's `subjectKeyIdentifier` octets, when it has that
    /// extension. A recipient named by SKI cannot be matched without it.
    subject_key_identifier: Option<Vec<u8>>,
}

impl std::fmt::Debug for RecipientKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecipientKey")
            .finish_non_exhaustive()
    }
}

impl RecipientKey {
    /// Load a recipient key from PKCS#8 bytes and the certificate that
    /// identifies it.
    ///
    /// `key` is PKCS#8 in DER or PEM, plain (`PRIVATE KEY`) or passphrase
    /// protected (`ENCRYPTED PRIVATE KEY`). A PEM file may hold the
    /// certificate alongside the key, in which case `certificate` may be
    /// `None`. `passphrase` is only consulted for an encrypted key.
    ///
    /// Errors carry a stable code and a fixed message. They never quote the
    /// key, the passphrase, the certificate, or anything derived from them,
    /// and they do not distinguish "wrong passphrase" from "not a PKCS#8
    /// file", because both are answered the same way: check the inputs.
    pub fn load(
        key: &[u8],
        passphrase: Option<&[u8]>,
        certificate: Option<&[u8]>,
    ) -> Result<Self, Error> {
        let private = load_private_key(key, passphrase)?;
        let certificate = match certificate {
            Some(bytes) => parse_certificate(bytes)?,
            None => certificate_in_pem(key)?.ok_or_else(|| {
                Error::new(
                    ErrorCode::DecryptionCertificateRequired,
                    "a decryption certificate is required: the key file carries no certificate, so the recipient it belongs to cannot be recognised",
                )
            })?,
        };
        Self::new(private, &certificate)
    }

    fn new(private: RsaPrivateKey, certificate: &Certificate) -> Result<Self, Error> {
        use rsa::pkcs8::DecodePublicKey as _;

        let spki = &certificate.tbs_certificate.subject_public_key_info;
        let certificate_key = rsa::RsaPublicKey::from_public_key_der(
            &spki.to_der().map_err(|_| invalid_certificate())?,
        )
        .map_err(|_| {
            Error::new(
                ErrorCode::InvalidDecryptionCertificate,
                "the decryption certificate does not carry an RSA public key",
            )
        })?;
        if rsa::RsaPublicKey::from(&private) != certificate_key {
            return Err(Error::new(
                ErrorCode::DecryptionKeyMismatch,
                "the decryption certificate does not belong to the decryption key",
            ));
        }
        Ok(Self {
            issuer_der: certificate
                .tbs_certificate
                .issuer
                .to_der()
                .map_err(|_| invalid_certificate())?,
            serial_der: certificate
                .tbs_certificate
                .serial_number
                .to_der()
                .map_err(|_| invalid_certificate())?,
            subject_key_identifier: subject_key_identifier(certificate)?,
            private,
        })
    }

    /// Whether a CMS `RecipientIdentifier` names this key's certificate.
    pub(super) fn matches(&self, rid: &RecipientIdentifier) -> bool {
        match rid {
            RecipientIdentifier::IssuerAndSerialNumber(named) => {
                match (named.issuer.to_der(), named.serial_number.to_der()) {
                    (Ok(issuer), Ok(serial)) => {
                        issuer == self.issuer_der && serial == self.serial_der
                    }
                    _ => false,
                }
            }
            RecipientIdentifier::SubjectKeyIdentifier(identifier) => self
                .subject_key_identifier
                .as_deref()
                .is_some_and(|known| known == identifier.0.as_bytes()),
        }
    }

    /// A key that is never asked to decrypt anything, for tests that only
    /// need a `RecipientKey` value to exist.
    #[cfg(test)]
    pub(super) fn unusable_for_tests() -> Self {
        // A textbook-sized key: it is never asked to decrypt anything here,
        // and embedding a full-size one would only slow the suite.
        RecipientKey {
            private: rsa::RsaPrivateKey::from_components(
                rsa::BigUint::from(3233u32),
                rsa::BigUint::from(17u32),
                rsa::BigUint::from(413u32),
                vec![rsa::BigUint::from(61u32), rsa::BigUint::from(53u32)],
            )
            .expect("the textbook RSA key builds"),
            issuer_der: Vec::new(),
            serial_der: Vec::new(),
            subject_key_identifier: None,
        }
    }
}

fn invalid_certificate() -> Error {
    Error::new(
        ErrorCode::InvalidDecryptionCertificate,
        "the decryption certificate is not a readable X.509 certificate",
    )
}

fn invalid_key() -> Error {
    Error::new(
        ErrorCode::InvalidDecryptionKey,
        "the decryption key could not be read: it must be an RSA private key in PKCS#8 DER or PEM form, and a passphrase must be supplied for an encrypted one",
    )
}

/// Read an RSA private key from PKCS#8 DER or PEM, decrypting it first when it
/// is a passphrase-protected `EncryptedPrivateKeyInfo`.
fn load_private_key(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<RsaPrivateKey, Error> {
    use rsa::pkcs8::DecodePrivateKey as _;

    let der: Zeroizing<Vec<u8>> = match pem_blocks(bytes) {
        Some(blocks) => {
            let (label, body) = blocks
                .into_iter()
                .find(|(label, _)| label == "PRIVATE KEY" || label == "ENCRYPTED PRIVATE KEY")
                .ok_or_else(invalid_key)?;
            match label.as_str() {
                "ENCRYPTED PRIVATE KEY" => decrypt_pkcs8(&body, passphrase)?,
                _ => Zeroizing::new(body),
            }
        }
        None => match RsaPrivateKey::from_pkcs8_der(bytes) {
            Ok(key) => return Ok(key),
            Err(_) => decrypt_pkcs8(bytes, passphrase)?,
        },
    };
    RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| invalid_key())
}

fn decrypt_pkcs8(der: &[u8], passphrase: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let passphrase = passphrase.ok_or_else(invalid_key)?;
    let encrypted = pkcs8::EncryptedPrivateKeyInfo::try_from(der).map_err(|_| invalid_key())?;
    let document = encrypted.decrypt(passphrase).map_err(|_| invalid_key())?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

/// Every PEM block in `bytes` as `(label, DER body)`, or `None` when the input
/// is not PEM at all.
///
/// A malformed block inside otherwise-PEM input is skipped rather than
/// reported, so that a certificate bundle with a trailing comment still loads;
/// the caller fails on "no usable block" instead.
fn pem_blocks(bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("-----BEGIN ") {
        return None;
    }
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start..];
        let Some(header_end) = after.find("-----\n").or_else(|| after.find("-----\r\n")) else {
            break;
        };
        let label = after["-----BEGIN ".len()..header_end].to_owned();
        let footer = format!("-----END {label}-----");
        let Some(end) = after.find(&footer) else {
            break;
        };
        let block = &after[..end + footer.len()];
        if let Ok((_, body)) = pem_rfc7468::decode_vec(block.as_bytes()) {
            blocks.push((label, body));
        }
        rest = &after[end + footer.len()..];
    }
    Some(blocks)
}

/// The first `CERTIFICATE` block of a PEM key file, if there is one.
fn certificate_in_pem(bytes: &[u8]) -> Result<Option<Certificate>, Error> {
    let Some(blocks) = pem_blocks(bytes) else {
        return Ok(None);
    };
    match blocks.iter().find(|(label, _)| label == "CERTIFICATE") {
        Some((_, body)) => Ok(Some(
            Certificate::from_der(body).map_err(|_| invalid_certificate())?,
        )),
        None => Ok(None),
    }
}

fn parse_certificate(bytes: &[u8]) -> Result<Certificate, Error> {
    if let Some(blocks) = pem_blocks(bytes) {
        let (_, body) = blocks
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .ok_or_else(invalid_certificate)?;
        return Certificate::from_der(&body).map_err(|_| invalid_certificate());
    }
    Certificate::from_der(bytes).map_err(|_| invalid_certificate())
}

fn subject_key_identifier(certificate: &Certificate) -> Result<Option<Vec<u8>>, Error> {
    let Some(extensions) = certificate.tbs_certificate.extensions.as_ref() else {
        return Ok(None);
    };
    let Some(extension) = extensions
        .iter()
        .find(|extension| extension.extn_id == ID_CE_SUBJECT_KEY_IDENTIFIER)
    else {
        return Ok(None);
    };
    let octets = OctetString::from_der(extension.extn_value.as_bytes())
        .map_err(|_| invalid_certificate())?;
    Ok(Some(octets.as_bytes().to_vec()))
}

#[cfg(test)]
mod tests {
    //! Unit tests for key loading, PEM scanning, and certificate parsing.

    use super::*;

    /// PEM armour, assembled at run time.
    ///
    /// A finished `BEGIN ... PRIVATE KEY` line never appears as a literal in
    /// this repository. A secret scanner cannot tell a real key block from a
    /// test string that only looks like one, and this project does not
    /// allowlist scanner rules, so the only safe amount of key-shaped text in
    /// the tree is none. See `SECURITY.md`.
    fn armour(label: &str, body: &str) -> String {
        let begin = format!("-----{}{label}-----", "BEGIN ");
        match body {
            // A header with no terminator at all.
            "" => begin,
            _ => format!("{begin}\n{body}\n-----{}{label}-----\n", "END "),
        }
    }

    /// The same, with the closing line left off.
    fn unterminated(label: &str, body: &str) -> String {
        format!("{}\n{body}\n", armour(label, ""))
    }

    #[test]
    fn input_that_is_not_pem_at_all_is_recognised_as_der() {
        assert!(pem_blocks(b"\x30\x82\x01\x00").is_none());
        assert!(pem_blocks(b"plain text with no armour").is_none());
    }

    /// The label every armour test uses, spelled apart from its delimiters.
    const PRIVATE_KEY: &str = "PRIVATE KEY";
    const CERTIFICATE: &str = "CERTIFICATE";

    #[test]
    fn a_truncated_or_unreadable_pem_block_is_skipped_rather_than_reported() {
        // A header with no terminator, an unterminated block, and a block
        // whose body is not base64: each leaves the file with no usable block,
        // which the caller turns into one "unreadable key" answer.
        for input in [
            armour(PRIVATE_KEY, ""),
            unterminated(PRIVATE_KEY, "AAAA"),
            armour(PRIVATE_KEY, "!!!!"),
        ] {
            let blocks = pem_blocks(input.as_bytes()).expect("the input looks like PEM");
            assert!(blocks.is_empty(), "{input:?} yields no usable block");
        }
        assert_eq!(
            load_private_key(armour(PRIVATE_KEY, "").as_bytes(), None)
                .expect_err("no block means no key")
                .code(),
            ErrorCode::InvalidDecryptionKey
        );
    }

    #[test]
    fn a_certificate_that_is_neither_pem_nor_der_is_reported_as_such() {
        for input in [
            b"not a certificate".to_vec(),
            // PEM that holds no certificate block at all.
            armour(PRIVATE_KEY, "").into_bytes(),
        ] {
            assert_eq!(
                parse_certificate(&input)
                    .expect_err("this is not a certificate")
                    .code(),
                ErrorCode::InvalidDecryptionCertificate
            );
        }
        assert!(
            certificate_in_pem(b"\x30\x00")
                .expect("DER input carries no PEM certificate")
                .is_none()
        );
        assert_eq!(
            certificate_in_pem(armour(CERTIFICATE, "AAAA").as_bytes())
                .expect_err("the block is not a certificate")
                .code(),
            ErrorCode::InvalidDecryptionCertificate
        );
    }

    #[test]
    fn the_key_type_never_prints_its_key() {
        let rendered = format!("{:?}", RecipientKey::unusable_for_tests());
        assert_eq!(rendered, "RecipientKey { .. }");
    }
}
