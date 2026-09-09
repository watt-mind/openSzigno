//! Cloud Signature Consortium API v2, as request bodies and response readers.
//!
//! This module is the protocol half of the remote signing backend and nothing
//! else. It opens no socket, reads no file and holds no token: every function
//! here turns a value into a JSON request body, or a JSON response body into a
//! value, and the caller does the talking. That split is deliberate. The CSC
//! exchange is the part that has to be exactly right and is cheap to test, and
//! the transport is the part that needs a destination policy, a timeout and a
//! size cap, which is the CLI's job and already exists there.
//!
//! # What the protocol asks of a client
//!
//! A CSC service is discovered, not assumed. `POST info` reports `specs`, the
//! `methods` actually implemented, `supportsRar`, `supportedHashTypes` and the
//! signature algorithms on offer, and the three deployments this project
//! surveyed disagree on every one of those fields. See `docs/remote-signing.md`
//! section 3.5: `supportedHashTypes` is the keyword `dtbsr` on one service and
//! the SHA-256 OID on another, and `supportsRar` is true on one and false on
//! the next. So [`ServiceInfo`] keeps what the service said rather than what a
//! vendor profile would have predicted.
//!
//! # What leaves the machine
//!
//! One base64 SHA-256 digest of the canonicalized `ds:SignedInfo`, per
//! signature, in `credentials/authorize` and again in `signatures/signHash`.
//! Never the dossier, never a payload, never a document title. The digest is
//! sent at authorisation time on purpose: Signature Activation Data that is
//! not bound to the hashes it authorises is data that authorises signing
//! anything.
//!
//! # The service signs blind
//!
//! Under `supportedHashTypes: ["dtbsr"]` the service signs the digest it was
//! handed and never sees the document, so a canonicalization mistake yields a
//! syntactically perfect signature over the wrong bytes. That is why
//! [`verify_prehash`] exists and why the caller must run it before anything is
//! written.

use base64::Engine as _;
use der::{Decode as _, Encode as _};
use serde::{Deserialize, Serialize};
use x509_cert::Certificate;

use super::error::{SignError, SignErrorCode};
use super::signer::SignatureAlgorithm;

/// SHA-256, the only digest this backend asks a service for.
pub const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
/// `rsaEncryption`: the RSA key algorithm, used as a `signAlgo` by services
/// that name the key rather than the scheme.
pub const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";
/// `sha256WithRSAEncryption`.
pub const SHA256_WITH_RSA_OID: &str = "1.2.840.113549.1.1.11";
/// `id-RSASSA-PSS`. Needs `signAlgoParams`, which the service supplies.
pub const RSASSA_PSS_OID: &str = "1.2.840.113549.1.1.10";
/// `id-ecPublicKey`: the EC key algorithm, as above.
pub const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
/// `ecdsa-with-SHA256`.
pub const ECDSA_WITH_SHA256_OID: &str = "1.2.840.10045.4.3.2";

/// The `specs` value of the oldest major version this backend speaks. A `1.x`
/// service is refused rather than half-supported.
const MINIMUM_MAJOR: u32 = 2;

fn base64_engine() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

/// Base64 for the wire, standard alphabet with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    base64_engine().encode(bytes)
}

fn decode_base64(text: &str) -> Option<Vec<u8>> {
    base64_engine().decode(text.trim()).ok()
}

fn rejected(what: &str) -> SignError {
    SignError::new(
        SignErrorCode::CscRejected,
        format!("the CSC service answered {what}"),
    )
}

fn unusable(what: impl Into<String>) -> SignError {
    SignError::new(SignErrorCode::CscCredentialUnusable, what)
}

/// The longest one service-supplied value may be in a message.
const MAX_SERVICE_VALUE_CHARS: usize = 64;

/// The most service-supplied values one message lists.
const MAX_SERVICE_VALUES: usize = 16;

/// Spell out a list of values a service sent, safely.
///
/// Nothing a service says is typed by the operator, and every one of these
/// strings ends up in an error message and on a terminal. Each value goes
/// through the shared display sanitiser, which drops control and format
/// characters — an ANSI escape and a bidirectional override alike — and bounds
/// its length; the list itself is bounded too, so no service can turn a
/// refusal into a screenful.
fn service_values(values: &[String]) -> String {
    let mut text = values
        .iter()
        .take(MAX_SERVICE_VALUES)
        .map(|value| openszigno_core::sanitize_display(value, MAX_SERVICE_VALUE_CHARS))
        .collect::<Vec<_>>()
        .join(", ");
    if values.len() > MAX_SERVICE_VALUES {
        text.push_str(", ...");
    }
    text
}

// ---------------------------------------------------------------------------
// info
// ---------------------------------------------------------------------------

/// What `POST info` reported.
///
/// Only `specs` is required. Everything else is optional because the three
/// deployments surveyed for `docs/remote-signing.md` each omit something a
/// reading of the specification would have expected.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct ServiceInfo {
    /// The API version, `2.0.0.2`, `2.1.0.1` or `2.2.0.0` in the wild.
    #[serde(default)]
    pub specs: String,
    #[serde(default)]
    pub name: Option<String>,
    /// The operations the service actually implements.
    #[serde(default)]
    pub methods: Vec<String>,
    /// `oauth2code`, `basic`, `digest` or `external`.
    #[serde(default, rename = "authType")]
    pub auth_type: Vec<String>,
    /// RFC 9396 rich authorization requests, for the interactive flow this
    /// round does not implement. Recorded so the report can say what the
    /// service offered.
    #[serde(default, rename = "supportsRar")]
    pub supports_rar: bool,
    /// Either the keyword `dtbsr` or a digest OID, depending on the vendor.
    #[serde(default, rename = "supportedHashTypes")]
    pub supported_hash_types: Vec<String>,
    #[serde(default, rename = "signAlgorithms")]
    pub sign_algorithms: Option<SignAlgorithms>,
}

/// The `signAlgorithms` object of an `info` response.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct SignAlgorithms {
    #[serde(default)]
    pub algos: Vec<String>,
    /// DER `signAlgoParams`, base64, positionally aligned with `algos`. A
    /// service that needs none sends an empty array.
    #[serde(default, rename = "algoParams")]
    pub algo_params: Vec<String>,
}

impl ServiceInfo {
    /// The major version number of `specs`, or `None` when it is not a version
    /// at all.
    pub fn major(&self) -> Option<u32> {
        self.specs.split('.').next()?.parse().ok()
    }

    /// Whether the service accepts the data-to-be-signed representation, which
    /// is what a XAdES client has: the digest of the canonicalized
    /// `ds:SignedInfo`.
    ///
    /// A service that says `dtbsr` says so by keyword; one that says
    /// `2.16.840.1.101.3.4.2.1` says the same thing with the digest OID; and
    /// one that says nothing at all predates the field, where hash signing was
    /// the only thing `signatures/signHash` did.
    pub fn accepts_digest(&self) -> bool {
        self.supported_hash_types.is_empty()
            || self
                .supported_hash_types
                .iter()
                .any(|value| value.eq_ignore_ascii_case("dtbsr") || value == SHA256_OID)
    }

    /// The `signAlgoParams` the service published for `oid`, if any.
    pub fn params_for(&self, oid: &str) -> Option<String> {
        let algorithms = self.sign_algorithms.as_ref()?;
        let index = algorithms.algos.iter().position(|value| value == oid)?;
        algorithms
            .algo_params
            .get(index)
            .filter(|value| !value.is_empty())
            .cloned()
    }
}

/// The body of `POST info`.
pub fn info_request() -> String {
    r#"{"lang":"en"}"#.to_owned()
}

/// Read an `info` response, and refuse a service this backend cannot speak to.
pub fn parse_info(body: &[u8]) -> Result<ServiceInfo, SignError> {
    let info: ServiceInfo = serde_json::from_slice(body)
        .map_err(|_| rejected("something that is not a CSC info response"))?;
    match info.major() {
        Some(major) if major >= MINIMUM_MAJOR => {}
        _ => {
            return Err(SignError::new(
                SignErrorCode::CscConfigInvalid,
                "this service does not report a CSC API v2 or later `specs` version, and only v2 is implemented",
            ));
        }
    }
    if !info.accepts_digest() {
        return Err(SignError::new(
            SignErrorCode::CscConfigInvalid,
            "this service does not accept a data-to-be-signed representation, so a XAdES digest cannot be signed by it",
        ));
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// credentials/list
// ---------------------------------------------------------------------------

/// The body of `POST credentials/list`.
pub fn credentials_list_request() -> String {
    r#"{"onlyValid":true,"lang":"en"}"#.to_owned()
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CredentialsList {
    #[serde(default, rename = "credentialIDs")]
    credential_ids: Vec<String>,
}

/// The one credential the service offers.
///
/// Two or more is not a thing this command may guess at: which qualified
/// certificate signs is the user's decision, so the refusal lists the
/// identifiers and stops.
pub fn parse_sole_credential(body: &[u8]) -> Result<String, SignError> {
    let list: CredentialsList = serde_json::from_slice(body)
        .map_err(|_| rejected("something that is not a CSC credentials/list response"))?;
    match list.credential_ids.len() {
        1 => Ok(list.credential_ids.into_iter().next().unwrap_or_default()),
        0 => Err(SignError::new(
            SignErrorCode::CscCredentialUnusable,
            "this account holds no usable signing credential",
        )),
        _ => Err(SignError::new(
            SignErrorCode::CscCredentialAmbiguous,
            format!(
                "this account holds several signing credentials; name one with --csc-credential: {}",
                service_values(&list.credential_ids)
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// credentials/info
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CredentialInfoRequest<'a> {
    #[serde(rename = "credentialID")]
    credential_id: &'a str,
    certificates: &'static str,
    #[serde(rename = "certInfo")]
    cert_info: bool,
    #[serde(rename = "authInfo")]
    auth_info: bool,
    lang: &'static str,
}

/// The body of `POST credentials/info`.
///
/// `certificates: "chain"` is asked for so the issuing certificates travel
/// with the signer's own: they become `xades:CertificateValues`, which is what
/// lets a verifier build the path without being handed a chain separately.
pub fn credential_info_request(credential_id: &str) -> String {
    serde_json::to_string(&CredentialInfoRequest {
        credential_id,
        certificates: "chain",
        cert_info: true,
        auth_info: true,
        lang: "en",
    })
    .unwrap_or_default()
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawCredentialInfo {
    #[serde(default)]
    key: RawKey,
    #[serde(default)]
    cert: RawCert,
    #[serde(default, rename = "authMode")]
    auth_mode: Option<String>,
    #[serde(default)]
    auth: Option<RawAuth>,
    #[serde(default, rename = "SCAL")]
    scal: Option<String>,
    #[serde(default)]
    multisign: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawKey {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    algo: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawCert {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    certificates: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct RawAuth {
    #[serde(default)]
    mode: Option<String>,
}

/// How a credential is authorised for one signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthMode {
    /// `credentials/authorize` with a PIN or a one-time password, which this
    /// command can complete without a browser.
    Explicit,
    /// A second OAuth 2.0 round with `scope=credential`, which needs a user
    /// agent and is not implemented in this round.
    OAuth2,
}

/// One credential, as `credentials/info` described it.
#[derive(Clone, Debug)]
pub struct CredentialInfo {
    pub credential_id: String,
    pub auth_mode: AuthMode,
    /// The signing certificate, DER.
    pub certificate: Vec<u8>,
    /// The rest of the chain the service published, DER, issuer-first as it
    /// arrived.
    pub chain: Vec<Vec<u8>>,
    /// The signature algorithm OIDs the key can be used with.
    pub key_algorithms: Vec<String>,
    /// `1` when the key is under sole control at signature level, `2` when the
    /// service binds the authorisation to the hashes.
    pub scal: Option<String>,
    /// How many signatures one authorisation may cover.
    pub multisign: Option<u32>,
}

/// Read a `credentials/info` response.
pub fn parse_credential_info(
    credential_id: &str,
    body: &[u8],
) -> Result<CredentialInfo, SignError> {
    let raw: RawCredentialInfo = serde_json::from_slice(body)
        .map_err(|_| rejected("something that is not a CSC credentials/info response"))?;
    if raw
        .key
        .status
        .as_deref()
        .is_some_and(|status| !status.eq_ignore_ascii_case("enabled"))
    {
        return Err(unusable("this credential's key is not enabled"));
    }
    if raw
        .cert
        .status
        .as_deref()
        .is_some_and(|status| !status.eq_ignore_ascii_case("valid"))
    {
        return Err(unusable(
            "the service reports this credential's certificate as not valid",
        ));
    }
    let mode = raw
        .auth_mode
        .or_else(|| raw.auth.and_then(|auth| auth.mode))
        .unwrap_or_else(|| "oauth2".to_owned());
    let auth_mode = if mode.eq_ignore_ascii_case("explicit") {
        AuthMode::Explicit
    } else {
        AuthMode::OAuth2
    };
    let mut certificates = Vec::new();
    for encoded in &raw.cert.certificates {
        let der = decode_base64(encoded)
            .ok_or_else(|| unusable("this credential's certificate is not readable"))?;
        Certificate::from_der(&der)
            .map_err(|_| unusable("this credential's certificate is not readable"))?;
        certificates.push(der);
    }
    if certificates.is_empty() {
        return Err(unusable("this credential published no certificate"));
    }
    let certificate = certificates.remove(0);
    if raw.key.algo.is_empty() {
        return Err(unusable(
            "this credential publishes no signature algorithm, so nothing says how to sign with it",
        ));
    }
    Ok(CredentialInfo {
        credential_id: credential_id.to_owned(),
        auth_mode,
        certificate,
        chain: certificates,
        key_algorithms: raw.key.algo,
        scal: raw.scal,
        multisign: raw.multisign,
    })
}

// ---------------------------------------------------------------------------
// credentials/authorize
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AuthorizeRequest<'a> {
    #[serde(rename = "credentialID")]
    credential_id: &'a str,
    #[serde(rename = "numSignatures")]
    num_signatures: u32,
    hashes: &'a [String],
    #[serde(rename = "hashAlgorithmOID")]
    hash_algorithm_oid: &'static str,
    #[serde(rename = "PIN", skip_serializing_if = "Option::is_none")]
    pin: Option<&'a str>,
    #[serde(rename = "OTP", skip_serializing_if = "Option::is_none")]
    otp: Option<&'a str>,
}

/// The body of `POST credentials/authorize`.
///
/// The real hashes go in, never a placeholder: an authorisation that is not
/// bound to the data it covers authorises signing anything for its lifetime,
/// and `numSignatures` is the count actually being produced for the same
/// reason.
pub fn authorize_request(
    credential_id: &str,
    hashes: &[String],
    pin: Option<&str>,
    otp: Option<&str>,
) -> String {
    let count = u32::try_from(hashes.len()).unwrap_or(u32::MAX);
    serde_json::to_string(&AuthorizeRequest {
        credential_id,
        num_signatures: count,
        hashes,
        hash_algorithm_oid: SHA256_OID,
        pin,
        otp,
    })
    .unwrap_or_default()
}

#[derive(Deserialize)]
struct AuthorizeResponse {
    #[serde(rename = "SAD")]
    sad: Option<String>,
}

/// The Signature Activation Data a `credentials/authorize` response carries.
pub fn parse_authorize(body: &[u8]) -> Result<String, SignError> {
    let response: AuthorizeResponse = serde_json::from_slice(body)
        .map_err(|_| rejected("something that is not a CSC credentials/authorize response"))?;
    response
        .sad
        .filter(|sad| !sad.is_empty())
        .ok_or_else(|| rejected("an authorisation with no SAD in it"))
}

// ---------------------------------------------------------------------------
// signatures/signHash
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SignHashRequest<'a> {
    #[serde(rename = "credentialID")]
    credential_id: &'a str,
    #[serde(rename = "SAD")]
    sad: &'a str,
    hashes: &'a [String],
    #[serde(rename = "hashAlgorithmOID")]
    hash_algorithm_oid: &'static str,
    #[serde(rename = "signAlgo")]
    sign_algo: &'a str,
    #[serde(rename = "signAlgoParams", skip_serializing_if = "Option::is_none")]
    sign_algo_params: Option<&'a str>,
    #[serde(rename = "operationMode")]
    operation_mode: &'static str,
}

/// The body of `POST signatures/signHash`.
pub fn sign_hash_request(
    credential_id: &str,
    sad: &str,
    hashes: &[String],
    algorithm: &ChosenAlgorithm,
) -> String {
    serde_json::to_string(&SignHashRequest {
        credential_id,
        sad,
        hashes,
        hash_algorithm_oid: SHA256_OID,
        sign_algo: &algorithm.sign_algo,
        sign_algo_params: algorithm.sign_algo_params.as_deref(),
        operation_mode: "S",
    })
    .unwrap_or_default()
}

#[derive(Deserialize)]
struct SignHashResponse {
    #[serde(default)]
    signatures: Vec<String>,
}

/// The single signature a `signatures/signHash` response carries, decoded, and
/// in the encoding XMLDSig writes.
pub fn parse_sign_hash(body: &[u8], algorithm: SignatureAlgorithm) -> Result<Vec<u8>, SignError> {
    let response: SignHashResponse = serde_json::from_slice(body)
        .map_err(|_| rejected("something that is not a CSC signatures/signHash response"))?;
    let [encoded] = response.signatures.as_slice() else {
        return Err(rejected(
            "a signature list that does not hold exactly one signature",
        ));
    };
    let bytes = decode_base64(encoded).ok_or_else(|| rejected("a signature that is not base64"))?;
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 => raw_ecdsa(&bytes),
        _ => Ok(bytes),
    }
}

/// The `r || s` pair XMLDSig writes, from whichever of the two encodings a
/// service returned.
///
/// The CSC specification says "the signature", and deployments disagree about
/// whether an ECDSA signature is the DER `SEQUENCE` or the fixed-width pair.
/// Both are accepted, because guessing wrong here produces a signature that is
/// perfectly formed and verifies nowhere.
fn raw_ecdsa(bytes: &[u8]) -> Result<Vec<u8>, SignError> {
    if bytes.len() == 64 {
        return Ok(bytes.to_vec());
    }
    p256::ecdsa::Signature::from_der(bytes)
        .map(|signature| signature.to_bytes().to_vec())
        .map_err(|_| rejected("an ECDSA signature in neither DER nor raw r||s form"))
}

// ---------------------------------------------------------------------------
// Algorithms
// ---------------------------------------------------------------------------

/// The signature algorithm one signature is produced under, on both sides of
/// the wire: what `ds:SignatureMethod` declares and what `signAlgo` asks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChosenAlgorithm {
    /// What this crate writes into the document.
    pub algorithm: SignatureAlgorithm,
    /// What the service is asked for.
    pub sign_algo: String,
    /// DER `signAlgoParams`, base64, for a scheme that needs them.
    pub sign_algo_params: Option<String>,
}

/// The candidates, in the order they are preferred.
///
/// A scheme OID beats a bare key OID, because a service that names the scheme
/// has said which padding it will apply and one that names the key has not.
/// RSASSA-PSS comes last of the RSA entries for the reason `SignatureAlgorithm`
/// documents: PKCS#1 v1.5 is what Hungarian e-akta verifiers universally
/// accept, so PSS is never chosen while something else is on offer.
const PREFERENCE: [(&str, SignatureAlgorithm, &str); 5] = [
    (
        SHA256_WITH_RSA_OID,
        SignatureAlgorithm::RsaSha256,
        SHA256_WITH_RSA_OID,
    ),
    (
        RSA_ENCRYPTION_OID,
        SignatureAlgorithm::RsaSha256,
        RSA_ENCRYPTION_OID,
    ),
    (
        ECDSA_WITH_SHA256_OID,
        SignatureAlgorithm::EcdsaP256Sha256,
        ECDSA_WITH_SHA256_OID,
    ),
    (
        EC_PUBLIC_KEY_OID,
        SignatureAlgorithm::EcdsaP256Sha256,
        ECDSA_WITH_SHA256_OID,
    ),
    (
        RSASSA_PSS_OID,
        SignatureAlgorithm::RsaPssSha256,
        RSASSA_PSS_OID,
    ),
];

/// Pick the algorithm to sign one hash with.
///
/// The choice is made from the credential's own `key/algo` list, never
/// assumed: `ds:SignatureMethod` in the document has to agree with what the
/// service actually did, and only the credential knows that. The service's
/// `info` supplies `signAlgoParams` where the scheme needs them.
pub fn choose_algorithm(
    credential: &CredentialInfo,
    info: &ServiceInfo,
) -> Result<ChosenAlgorithm, SignError> {
    for (offered, algorithm, sign_algo) in PREFERENCE {
        if !credential
            .key_algorithms
            .iter()
            .any(|value| value == offered)
        {
            continue;
        }
        let params = info
            .params_for(offered)
            .or_else(|| info.params_for(sign_algo));
        if algorithm == SignatureAlgorithm::RsaPssSha256 && params.is_none() {
            // A PSS signature without parameters is a signature whose salt
            // length and MGF this client would be guessing at.
            continue;
        }
        return Ok(ChosenAlgorithm {
            algorithm,
            sign_algo: sign_algo.to_owned(),
            sign_algo_params: params,
        });
    }
    Err(unusable(format!(
        "no signature algorithm this build writes is offered by this credential: {}",
        service_values(&credential.key_algorithms)
    )))
}

// ---------------------------------------------------------------------------
// Verifying what came back
// ---------------------------------------------------------------------------

/// Check that `signature` really is `algorithm` over `digest` under the public
/// key of `certificate`.
///
/// This is not optional and it is not a courtesy. A hash-only service signs
/// the digest it was handed without ever seeing the document, so a wrong
/// signature is indistinguishable from a right one until somebody verifies it
/// — and this tool must never write a file that looks signed and is not. The
/// caller runs this before anything reaches the filesystem.
pub fn verify_prehash(
    certificate: &[u8],
    algorithm: SignatureAlgorithm,
    digest: &[u8],
    signature: &[u8],
) -> Result<(), SignError> {
    let parsed = Certificate::from_der(certificate)
        .map_err(|_| unusable("this credential's certificate is not readable"))?;
    let spki = parsed
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| unusable("this credential's certificate is not readable"))?;
    let bad = || {
        SignError::new(
            SignErrorCode::CscSignatureInvalid,
            "the signature the CSC service returned does not verify against the certificate it published, so nothing was written",
        )
    };
    match algorithm {
        SignatureAlgorithm::RsaSha256 => {
            use rsa::pkcs8::DecodePublicKey as _;
            use rsa::signature::hazmat::PrehashVerifier as _;
            let key = rsa::RsaPublicKey::from_public_key_der(&spki).map_err(|_| bad())?;
            let signature = rsa::pkcs1v15::Signature::try_from(signature).map_err(|_| bad())?;
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(key)
                .verify_prehash(digest, &signature)
                .map_err(|_| bad())
        }
        SignatureAlgorithm::RsaPssSha256 => {
            use rsa::pkcs8::DecodePublicKey as _;
            use rsa::signature::hazmat::PrehashVerifier as _;
            let key = rsa::RsaPublicKey::from_public_key_der(&spki).map_err(|_| bad())?;
            let signature = rsa::pss::Signature::try_from(signature).map_err(|_| bad())?;
            rsa::pss::VerifyingKey::<sha2::Sha256>::new(key)
                .verify_prehash(digest, &signature)
                .map_err(|_| bad())
        }
        SignatureAlgorithm::EcdsaP256Sha256 => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
            use p256::pkcs8::DecodePublicKey as _;
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(&spki).map_err(|_| bad())?;
            let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|_| bad())?;
            key.verify_prehash(digest, &signature).map_err(|_| bad())
        }
    }
}

#[cfg(test)]
mod tests;
