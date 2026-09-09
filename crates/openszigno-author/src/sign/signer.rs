//! What produces a `ds:SignatureValue`, and the one implementation of it that
//! holds a private key in this process.
//!
//! The [`Signer`] seam exists so that the key never has to. A signer is handed
//! the canonicalized `ds:SignedInfo` octets, or their digest, and nothing
//! else: never the document, never a payload, never a certificate to choose
//! from. A remote backend (a Cloud Signature Consortium service, a smart card)
//! implements the same trait with a hash-only call and this crate is unchanged
//! by it, which is exactly why the trait takes what it takes.
//!
//! [`SoftwareSigner`] is the local case: a PKCS#8 private key and the
//! certificate that names it, both supplied as bytes by the caller. It refuses
//! a certificate that does not belong to the key, because a signature the
//! caller cannot bind to a certificate is one no verifier can use.

use der::{Decode as _, Encode as _};
use sha2::{Digest as _, Sha256};
use x509_cert::Certificate;
use zeroize::Zeroizing;

use super::error::{SignError, SignErrorCode};

/// The signature algorithms this build writes.
///
/// The default is RSA PKCS#1 v1.5 with SHA-256 rather than RSA-PSS, because
/// that is the combination Hungarian e-akta verifiers universally accept and
/// the one the private corpus is written with. PSS is offered alongside it and
/// is never chosen implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignatureAlgorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256. Deterministic.
    RsaSha256,
    /// RSASSA-PSS with SHA-256, MGF1-SHA-256 and a 32-byte salt. Randomised.
    RsaPssSha256,
    /// ECDSA on P-256 with SHA-256, written as the raw `r || s` pair
    /// XMLDSig prescribes. Randomised.
    EcdsaP256Sha256,
}

impl SignatureAlgorithm {
    /// The `ds:SignatureMethod/@Algorithm` URI.
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            Self::RsaPssSha256 => "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1",
            Self::EcdsaP256Sha256 => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        }
    }

    /// The name the JSON envelope reports, which is the `--algorithm` value.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RsaSha256 => "rsa-sha256",
            Self::RsaPssSha256 => "rsa-pss-sha256",
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }

    /// Whether two runs with the same key, time and inputs produce the same
    /// bytes. PSS salts and ECDSA nonces are random, so they do not.
    pub const fn deterministic(self) -> bool {
        matches!(self, Self::RsaSha256)
    }

    /// Parse a `--algorithm` value.
    pub fn from_name(value: &str) -> Option<Self> {
        match value {
            "rsa-sha256" => Some(Self::RsaSha256),
            "rsa-pss-sha256" => Some(Self::RsaPssSha256),
            "ecdsa-p256-sha256" => Some(Self::EcdsaP256Sha256),
            _ => None,
        }
    }
}

/// Whatever can turn canonicalized `ds:SignedInfo` octets into a signature.
///
/// The two entry points exist for the two kinds of backend. A local key signs
/// the octets; a hash-only remote service is sent the digest and nothing else.
/// [`Signer::prefers_digest`] says which one the driver should call, so the
/// choice belongs to the implementation rather than to its caller.
pub trait Signer {
    /// The algorithm the signature is written under. It is the signer's own
    /// answer, never a caller's request, so what `ds:SignatureMethod` declares
    /// and what actually signed cannot disagree.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// The signing certificate, DER. It goes into `ds:KeyInfo` and is what the
    /// signed `xades:SigningCertificateV2` property digests.
    fn certificate(&self) -> &[u8];

    /// Whether the driver should call [`Signer::sign_digest`] instead of
    /// [`Signer::sign_bytes`].
    fn prefers_digest(&self) -> bool {
        false
    }

    /// Sign the canonicalized `ds:SignedInfo` octets.
    fn sign_bytes(&self, octets: &[u8]) -> Result<Vec<u8>, SignError>;

    /// Sign a digest that was computed over the canonicalized `ds:SignedInfo`
    /// with this algorithm's own digest function.
    ///
    /// The default refuses rather than guessing: a signer that has not
    /// implemented the hash-only path must not silently be handed one.
    fn sign_digest(&self, _digest: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::failed(
            "this signer does not implement hash-only signing",
        ))
    }
}

/// The private key a [`SoftwareSigner`] holds, in the shape its algorithm
/// needs. The bytes never leave this type: it has no accessor for them and no
/// `Debug` that could print them.
enum PrivateKey {
    Rsa(Box<rsa::RsaPrivateKey>),
    EcdsaP256(Box<p256::ecdsa::SigningKey>),
}

/// A signer holding a private key in this process.
pub struct SoftwareSigner {
    key: PrivateKey,
    certificate: Vec<u8>,
    algorithm: SignatureAlgorithm,
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SoftwareSigner")
            .field("algorithm", &self.algorithm.as_str())
            .finish_non_exhaustive()
    }
}

impl SoftwareSigner {
    /// Load a key and the certificate that names it.
    ///
    /// `key` is PKCS#8 in DER or PEM, plain (`PRIVATE KEY`) or passphrase
    /// protected (`ENCRYPTED PRIVATE KEY`). A PEM file may carry the
    /// certificate alongside the key, in which case `certificate` may be
    /// `None`. `algorithm` picks between the two RSA schemes; `None` is
    /// RSA PKCS#1 v1.5 for an RSA key and ECDSA for a P-256 one.
    ///
    /// Errors carry a stable code and a fixed message that quotes neither the
    /// key nor the passphrase nor anything derived from them, and "not a
    /// PKCS#8 file" is deliberately not told apart from "wrong passphrase":
    /// both are answered the same way.
    pub fn load(
        key: &[u8],
        passphrase: Option<&[u8]>,
        certificate: Option<&[u8]>,
        algorithm: Option<SignatureAlgorithm>,
    ) -> Result<Self, SignError> {
        // The certificate is resolved first: "you gave me no certificate" is
        // a more specific complaint than "this key did not load", and a caller
        // who forgot the flag should hear that rather than a key error.
        let certificate = match certificate {
            Some(bytes) => parse_certificate(bytes)?,
            None => certificate_in_pem(key)?.ok_or_else(|| {
                SignError::new(
                    SignErrorCode::SigningCertificateRequired,
                    "a signing certificate is required: the key file carries none, so nothing binds the signature to a certificate",
                )
            })?,
        };
        let der = pkcs8_der(key, passphrase)?;
        let spki = certificate
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))?;
        let (key, natural) = private_key(&der, &spki)?;
        let algorithm = match (algorithm, &key) {
            (None, _) => natural,
            (Some(requested), PrivateKey::Rsa(_))
                if matches!(
                    requested,
                    SignatureAlgorithm::RsaSha256 | SignatureAlgorithm::RsaPssSha256
                ) =>
            {
                requested
            }
            (Some(SignatureAlgorithm::EcdsaP256Sha256), PrivateKey::EcdsaP256(_)) => {
                SignatureAlgorithm::EcdsaP256Sha256
            }
            (Some(_), _) => {
                return Err(SignError::key(
                    "the requested signature algorithm does not match the signing key's type",
                ));
            }
        };
        Ok(Self {
            key,
            certificate: certificate
                .to_der()
                .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))?,
            algorithm,
        })
    }
}

impl Signer for SoftwareSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate(&self) -> &[u8] {
        &self.certificate
    }

    fn sign_bytes(&self, octets: &[u8]) -> Result<Vec<u8>, SignError> {
        match (&self.key, self.algorithm) {
            (PrivateKey::Rsa(private), SignatureAlgorithm::RsaSha256) => {
                use rsa::signature::{SignatureEncoding as _, Signer as _};
                rsa::pkcs1v15::SigningKey::<Sha256>::new((**private).clone())
                    .try_sign(octets)
                    .map(|signature| signature.to_vec())
                    .map_err(|_| SignError::failed(SIGNING_FAILED))
            }
            (PrivateKey::Rsa(private), SignatureAlgorithm::RsaPssSha256) => {
                use rsa::signature::{RandomizedSigner as _, SignatureEncoding as _};
                rsa::pss::SigningKey::<Sha256>::new((**private).clone())
                    .try_sign_with_rng(&mut rsa::rand_core::OsRng, octets)
                    .map(|signature| signature.to_vec())
                    .map_err(|_| SignError::failed(SIGNING_FAILED))
            }
            (PrivateKey::EcdsaP256(private), SignatureAlgorithm::EcdsaP256Sha256) => {
                use p256::ecdsa::signature::Signer as _;
                let signature: p256::ecdsa::Signature = private
                    .try_sign(octets)
                    .map_err(|_| SignError::failed(SIGNING_FAILED))?;
                // XMLDSig writes the raw `r || s` pair, not the DER SEQUENCE.
                Ok(signature.to_bytes().to_vec())
            }
            _ => Err(SignError::failed(
                "the signing key does not match the signature algorithm",
            )),
        }
    }
}

const SIGNING_FAILED: &str = "the signing operation failed";
const KEY_UNREADABLE: &str = "the signing key could not be read: it must be an RSA or NIST P-256 private key in PKCS#8 DER or PEM form, and a passphrase must be supplied for an encrypted one";
const CERTIFICATE_UNREADABLE: &str =
    "the signing certificate is not a readable X.509 certificate, PEM or DER";

/// Plain PKCS#8 DER, decrypting a passphrase-protected key first.
fn pkcs8_der(bytes: &[u8], passphrase: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, SignError> {
    match pem_blocks(bytes) {
        Some(blocks) => {
            let (label, body) = blocks
                .into_iter()
                .find(|(label, _)| label == "PRIVATE KEY" || label == "ENCRYPTED PRIVATE KEY")
                .ok_or_else(|| SignError::key(KEY_UNREADABLE))?;
            match label.as_str() {
                "ENCRYPTED PRIVATE KEY" => decrypt_pkcs8(&body, passphrase),
                _ => Ok(Zeroizing::new(body)),
            }
        }
        // A plain DER key is already what is wanted; anything else is tried as
        // an encrypted one before it is refused.
        None => match pkcs8::PrivateKeyInfo::try_from(bytes) {
            Ok(_) => Ok(Zeroizing::new(bytes.to_vec())),
            Err(_) => decrypt_pkcs8(bytes, passphrase),
        },
    }
}

fn decrypt_pkcs8(der: &[u8], passphrase: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>, SignError> {
    let passphrase = passphrase.ok_or_else(|| SignError::key(KEY_UNREADABLE))?;
    let encrypted = pkcs8::EncryptedPrivateKeyInfo::try_from(der)
        .map_err(|_| SignError::key(KEY_UNREADABLE))?;
    let document = encrypted
        .decrypt(passphrase)
        .map_err(|_| SignError::key(KEY_UNREADABLE))?;
    Ok(Zeroizing::new(document.as_bytes().to_vec()))
}

/// The private key the PKCS#8 bytes hold, checked against the certificate's
/// own public key, plus the algorithm that key naturally signs under.
fn private_key(der: &[u8], spki: &[u8]) -> Result<(PrivateKey, SignatureAlgorithm), SignError> {
    use p256::pkcs8::DecodePrivateKey as _;

    if let Ok(private) = rsa::RsaPrivateKey::from_pkcs8_der(der) {
        use rsa::pkcs8::DecodePublicKey as _;
        let public = rsa::RsaPublicKey::from_public_key_der(spki)
            .map_err(|_| SignError::new(SignErrorCode::SigningKeyMismatch, MISMATCH))?;
        if rsa::RsaPublicKey::from(&private) != public {
            return Err(SignError::new(SignErrorCode::SigningKeyMismatch, MISMATCH));
        }
        return Ok((
            PrivateKey::Rsa(Box::new(private)),
            SignatureAlgorithm::RsaSha256,
        ));
    }
    if let Ok(secret) = p256::SecretKey::from_pkcs8_der(der) {
        use p256::pkcs8::DecodePublicKey as _;
        let public = p256::PublicKey::from_public_key_der(spki)
            .map_err(|_| SignError::new(SignErrorCode::SigningKeyMismatch, MISMATCH))?;
        if secret.public_key() != public {
            return Err(SignError::new(SignErrorCode::SigningKeyMismatch, MISMATCH));
        }
        return Ok((
            PrivateKey::EcdsaP256(Box::new(p256::ecdsa::SigningKey::from(&secret))),
            SignatureAlgorithm::EcdsaP256Sha256,
        ));
    }
    Err(SignError::key(KEY_UNREADABLE))
}

const MISMATCH: &str = "the signing certificate does not belong to the signing key";

/// Every PEM block in `bytes` as `(label, DER body)`, or `None` when the input
/// is not PEM at all.
///
/// A malformed block inside otherwise-PEM input is skipped rather than
/// reported, so a bundle with a trailing comment still loads; the caller fails
/// on "no usable block" instead.
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
fn certificate_in_pem(bytes: &[u8]) -> Result<Option<Certificate>, SignError> {
    let Some(blocks) = pem_blocks(bytes) else {
        return Ok(None);
    };
    match blocks.iter().find(|(label, _)| label == "CERTIFICATE") {
        Some((_, body)) => {
            Ok(Some(Certificate::from_der(body).map_err(|_| {
                SignError::certificate(CERTIFICATE_UNREADABLE)
            })?))
        }
        None => Ok(None),
    }
}

/// One X.509 certificate from PEM or DER.
pub(crate) fn parse_certificate(bytes: &[u8]) -> Result<Certificate, SignError> {
    if let Some(blocks) = pem_blocks(bytes) {
        let (_, body) = blocks
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .ok_or_else(|| SignError::certificate(CERTIFICATE_UNREADABLE))?;
        return Certificate::from_der(&body)
            .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE));
    }
    Certificate::from_der(bytes).map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))
}

/// Every certificate in a PEM bundle, or the one certificate a DER file holds.
///
/// A chain file routinely carries several, and a caller that had to split one
/// by hand would be doing the tool's work.
pub fn parse_certificates(bytes: &[u8]) -> Result<Vec<Vec<u8>>, SignError> {
    let Some(blocks) = pem_blocks(bytes) else {
        let certificate = parse_certificate(bytes)?;
        return Ok(vec![
            certificate
                .to_der()
                .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))?,
        ]);
    };
    let mut out = Vec::new();
    for (label, body) in blocks {
        if label != "CERTIFICATE" {
            continue;
        }
        let certificate = Certificate::from_der(&body)
            .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))?;
        out.push(
            certificate
                .to_der()
                .map_err(|_| SignError::certificate(CERTIFICATE_UNREADABLE))?,
        );
    }
    if out.is_empty() {
        return Err(SignError::certificate(CERTIFICATE_UNREADABLE));
    }
    Ok(out)
}

/// The SHA-256 digest of a certificate's DER, which is what the signed
/// `xades:SigningCertificateV2` property carries.
pub(crate) fn certificate_digest(der: &[u8]) -> Vec<u8> {
    Sha256::digest(der).to_vec()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    #[test]
    fn algorithm_names_round_trip_and_only_pkcs1_is_deterministic() {
        for algorithm in [
            SignatureAlgorithm::RsaSha256,
            SignatureAlgorithm::RsaPssSha256,
            SignatureAlgorithm::EcdsaP256Sha256,
        ] {
            assert_eq!(
                SignatureAlgorithm::from_name(algorithm.as_str()),
                Some(algorithm)
            );
            assert!(algorithm.uri().starts_with("http://www.w3.org/"));
        }
        assert!(SignatureAlgorithm::RsaSha256.deterministic());
        assert!(!SignatureAlgorithm::RsaPssSha256.deterministic());
        assert!(!SignatureAlgorithm::EcdsaP256Sha256.deterministic());
        assert_eq!(SignatureAlgorithm::from_name("rsa-sha1"), None);
    }

    /// A P-256 key and a self-signed certificate for it, minted here.
    ///
    /// Nothing is committed: a private key never appears in this repository,
    /// synthetic or not, so every test that needs one generates it.
    fn material() -> (Vec<u8>, Vec<u8>) {
        let pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .expect("a P-256 key is generated");
        let params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("no SAN is valid");
        let certificate = params.self_signed(&pair).expect("self-signing succeeds");
        (pair.serialize_der(), certificate.der().to_vec())
    }

    #[test]
    fn a_p256_key_signs_under_ecdsa_and_carries_its_certificate() {
        let (key, certificate) = material();
        let signer =
            SoftwareSigner::load(&key, None, Some(&certificate), None).expect("the key loads");
        assert_eq!(signer.algorithm(), SignatureAlgorithm::EcdsaP256Sha256);
        assert_eq!(signer.certificate(), certificate.as_slice());
        assert!(!signer.prefers_digest());
        // The raw `r || s` pair XMLDSig writes, not a DER SEQUENCE.
        assert_eq!(
            signer.sign_bytes(b"octets").expect("signing works").len(),
            64
        );
        // The default hash-only path refuses rather than guessing.
        assert_eq!(
            signer
                .sign_digest(b"digest")
                .expect_err("not implemented")
                .code(),
            SignErrorCode::SignFailed
        );
        assert!(format!("{signer:?}").contains("ecdsa-p256-sha256"));
    }

    #[test]
    fn a_certificate_for_another_key_is_a_mismatch() {
        let (key, _) = material();
        let (_, other) = material();
        let error =
            SoftwareSigner::load(&key, None, Some(&other), None).expect_err("different keys");
        assert_eq!(error.code(), SignErrorCode::SigningKeyMismatch);
    }

    #[test]
    fn an_rsa_algorithm_asked_of_an_ec_key_is_refused() {
        let (key, certificate) = material();
        let error = SoftwareSigner::load(
            &key,
            None,
            Some(&certificate),
            Some(SignatureAlgorithm::RsaPssSha256),
        )
        .expect_err("the key is not RSA");
        assert_eq!(error.code(), SignErrorCode::InvalidSigningKey);
    }

    #[test]
    fn an_unreadable_key_is_refused_without_quoting_it() {
        let (_, certificate) = material();
        let error = SoftwareSigner::load(b"not a key at all", None, Some(&certificate), None)
            .expect_err("this is not a key");
        assert_eq!(error.code(), SignErrorCode::InvalidSigningKey);
        assert!(!error.message().contains("not a key at all"));
    }

    #[test]
    fn a_certificate_bundle_yields_every_certificate_in_it() {
        let (_, certificate) = material();
        let der = parse_certificates(&certificate).expect("DER holds one certificate");
        assert_eq!(der, vec![certificate.clone()]);
        // PEM wraps its Base64 at 64 characters; a decoder is entitled to
        // insist on that, and this one does.
        let body = base64::engine::general_purpose::STANDARD.encode(&certificate);
        let wrapped: Vec<String> = body
            .as_bytes()
            .chunks(64)
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect();
        let pem = format!(
            "-----{}CERTIFICATE-----\n{}\n-----{}CERTIFICATE-----\n",
            "BEGIN ",
            wrapped.join("\n"),
            "END "
        );
        let bundle = format!("{pem}{pem}");
        assert_eq!(
            parse_certificates(bundle.as_bytes()).expect("a bundle of two"),
            vec![certificate.clone(), certificate]
        );
    }

    #[test]
    fn a_key_file_with_no_certificate_and_no_flag_is_refused() {
        // PEM armour is assembled at run time: a finished private-key armour
        // line never appears as a literal in this repository.
        let armour = format!(
            "-----{}PRIVATE KEY-----\nAAAA\n-----{}PRIVATE KEY-----\n",
            "BEGIN ", "END "
        );
        let error = SoftwareSigner::load(armour.as_bytes(), None, None, None)
            .expect_err("no certificate is available");
        assert_eq!(error.code(), SignErrorCode::SigningCertificateRequired);
    }

    #[test]
    fn an_unreadable_certificate_is_refused() {
        assert_eq!(
            parse_certificate(b"nonsense")
                .expect_err("not a certificate")
                .code(),
            SignErrorCode::InvalidSigningCertificate
        );
        assert_eq!(
            parse_certificates(b"nonsense")
                .expect_err("not a certificate")
                .code(),
            SignErrorCode::InvalidSigningCertificate
        );
    }

    #[test]
    fn pem_scanning_finds_every_block_and_skips_the_rest() {
        let text = format!(
            "# a comment\n-----{}CERTIFICATE-----\nAAAA\n-----{}CERTIFICATE-----\ntrailing text\n",
            "BEGIN ", "END "
        );
        let blocks = pem_blocks(text.as_bytes()).expect("this is PEM");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].0, "CERTIFICATE");
        assert!(pem_blocks(b"\x00\x01binary").is_none());
    }
}
