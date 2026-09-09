//! `sign --csc`: signing the digest through a Cloud Signature Consortium
//! service, so a qualified certificate held by a remote QSCD signs the same
//! XAdES structure the software signer produces.
//!
//! # The module map
//!
//! | Module | What it owns |
//! | :--- | :--- |
//! | this one | The flow: discovery, credential resolution, and the [`Signer`] implementation that authorises and signs one digest. |
//! | [`config`] | The `--csc` file: what it may say, what is refused, and where the secrets in it come from. |
//! | [`client`] | One bounded `POST` per operation, through the transport `verify --online` already goes through. |
//!
//! The protocol itself — every request body, every response reader and the
//! algorithm mapping — lives in `openszigno_author::sign::csc`, which opens no
//! socket. This module is what turns those values into requests.
//!
//! # The request sequence
//!
//! Discovery and credential resolution happen while [`CscSigner::open`] runs,
//! before the dossier is touched, because the signing certificate has to be in
//! hand before a `ds:SignedInfo` can be built: the XAdES
//! `xades:SigningCertificateV2` property digests it, so the digest that will
//! be signed does not exist until the certificate does.
//!
//! 1. `POST info` — the service's `specs`, `methods`, `supportsRar`,
//!    `supportedHashTypes` and `signAlgorithms`. A `1.x` service, or one that
//!    will not sign a data-to-be-signed representation, is refused here.
//! 2. `POST credentials/list` — only when no credential was named. Exactly one
//!    is taken; several is `csc_credential_ambiguous` with the identifiers.
//! 3. `POST credentials/info` with `certificates: "chain"` and
//!    `certInfo: true` — the signing certificate, the rest of the chain, the
//!    key's algorithms and the authorisation mode.
//!
//! Then, once per signature, inside [`Signer::sign_digest`]:
//!
//! 4. `POST credentials/authorize` with `numSignatures: 1`, the real base64
//!    SHA-256 digest, `hashAlgorithmOID` `2.16.840.1.101.3.4.2.1`, and the PIN
//!    or one-time password when the credential's mode is `explicit`. The
//!    answer is Signature Activation Data.
//! 5. `POST signatures/signHash` with the credential, the SAD, the same hash,
//!    and the `signAlgo` chosen from the credential's own `key/algo` list.
//! 6. The returned signature is verified locally against the returned
//!    certificate before it is handed back, so a wrong signature is
//!    `csc_signature_invalid` and nothing is written.
//!
//! # What is not implemented
//!
//! A credential whose `authMode` is `oauth2` needs a second OAuth 2.0
//! authorization-code round with `scope=credential`, which needs a browser and
//! a loopback listener. This round is deliberately non-interactive, so such a
//! credential is `csc_authorization_required` and the message says which flow
//! to complete. RFC 9396 `authorization_details`, which `supportsRar`
//! advertises, belongs to that same interactive flow and is documented rather
//! than built; see `docs/remote-signing.md`.
//!
//! # What leaves the machine
//!
//! One base64 SHA-256 digest per signature, the credential identifier, and the
//! bearer token in an `Authorization` header, to the host the configuration
//! named. Never the dossier, never a payload, never a title.

pub(crate) mod client;
pub(crate) mod config;

use openszigno_author::sign::csc::{self, AuthMode, ChosenAlgorithm, CredentialInfo, ServiceInfo};
use openszigno_author::sign::{SignError, SignErrorCode, SignatureAlgorithm, Signer};
use zeroize::Zeroizing;

use crate::online::Fetcher;
use crate::response::{CliError, Notice};

use client::Client;
use config::CscConfig;

/// A signer whose key is held by a remote CSC service.
pub(crate) struct CscSigner {
    client: Client,
    credential: CredentialInfo,
    algorithm: ChosenAlgorithm,
    /// The PIN and one-time password for an `explicit`-mode credential, if the
    /// configuration named files holding them.
    pin: Option<Zeroizing<String>>,
    otp: Option<Zeroizing<String>>,
    /// What `info` reported, kept so the report can say which service version
    /// produced the signature.
    info: ServiceInfo,
}

/// What a `sign --csc` run needs to open one.
pub(crate) struct CscRequest<'a> {
    pub(crate) config: &'a std::path::Path,
    pub(crate) credential: Option<&'a str>,
    pub(crate) proxy: Option<&'a str>,
    pub(crate) allow_private: bool,
}

impl CscSigner {
    /// Run the discovery half of the flow, and return a signer ready to sign
    /// digests.
    ///
    /// Everything that can refuse the run refuses it here, before a byte of
    /// the dossier has been read: a configuration that will not load, a
    /// service this build cannot speak to, a credential that is ambiguous or
    /// unusable, and an `oauth2`-mode credential this round cannot authorise.
    pub(crate) fn open(request: &CscRequest<'_>) -> Result<(Self, Vec<Notice>), CliError> {
        let config = CscConfig::load(request.config)?;
        config::check_scheme(&config.base_url, request.allow_private)
            .map_err(CliError::from_sign)?;
        let fetcher = Fetcher::new(request.proxy, request.allow_private)
            .map_err(|message| CliError::invalid("online_options_invalid", message))?;
        let client = Client::new(fetcher, &config.base_url, config.access_token.clone());
        Self::discover(client, &config, request.credential)
            .map(|signer| (signer, config.warnings))
            .map_err(CliError::from_sign)
    }

    fn discover(
        client: Client,
        config: &CscConfig,
        named: Option<&str>,
    ) -> Result<Self, SignError> {
        let info = csc::parse_info(&client.post("info", &csc::info_request())?)?;
        let credential_id = match named.or(config.credential_id.as_deref()) {
            Some(id) => id.to_owned(),
            None => csc::parse_sole_credential(
                &client.post("credentials/list", &csc::credentials_list_request())?,
            )?,
        };
        let credential = csc::parse_credential_info(
            &credential_id,
            &client.post(
                "credentials/info",
                &csc::credential_info_request(&credential_id),
            )?,
        )?;
        if credential.auth_mode == AuthMode::OAuth2 {
            return Err(SignError::remote(
                SignErrorCode::CscAuthorizationRequired,
                "this credential is authorised through an OAuth 2.0 round with scope=credential, which needs a browser; this build signs only with an explicit-mode credential authorised by a PIN or a one-time password. Complete the credential authorisation with the provider's own flow, or wait for the interactive `openszigno csc login` flow",
            ));
        }
        let algorithm = csc::choose_algorithm(&credential, &info)?;
        Ok(Self {
            client,
            credential,
            algorithm,
            pin: config.pin.clone(),
            otp: config.otp.clone(),
            info,
        })
    }

    /// The certificates that go into `xades:CertificateValues`: the chain the
    /// service published alongside the signing certificate.
    pub(crate) fn chain(&self) -> &[Vec<u8>] {
        &self.credential.chain
    }

    pub(crate) fn credential_id(&self) -> &str {
        &self.credential.credential_id
    }

    /// The `specs` version the service reported, for the report.
    pub(crate) fn specs(&self) -> &str {
        &self.info.specs
    }
}

impl Signer for CscSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm.algorithm
    }

    fn certificate(&self) -> &[u8] {
        &self.credential.certificate
    }

    /// The key is somebody else's; only a digest may be sent.
    fn prefers_digest(&self) -> bool {
        true
    }

    fn sign_bytes(&self, _octets: &[u8]) -> Result<Vec<u8>, SignError> {
        Err(SignError::remote(
            SignErrorCode::CscConfigInvalid,
            "a CSC service signs a digest and never the octets themselves",
        ))
    }

    fn sign_digest(&self, digest: &[u8]) -> Result<Vec<u8>, SignError> {
        let hashes = vec![csc::encode_base64(digest)];
        // The authorisation carries the real hash and `numSignatures: 1`: a
        // SAD bound to neither would authorise signing anything for its
        // lifetime.
        let sad = csc::parse_authorize(&self.client.post(
            "credentials/authorize",
            &csc::authorize_request(
                self.credential_id(),
                &hashes,
                self.pin.as_ref().map(|value| value.as_str()),
                self.otp.as_ref().map(|value| value.as_str()),
            ),
        )?)?;
        let signature = csc::parse_sign_hash(
            &self.client.post(
                "signatures/signHash",
                &csc::sign_hash_request(self.credential_id(), &sad, &hashes, &self.algorithm),
            )?,
            self.algorithm.algorithm,
        )?;
        // The service signed a digest it never saw the document behind, so a
        // canonicalization mistake here would produce a perfectly formed
        // signature over the wrong bytes. It is checked before it is returned,
        // which is before anything reaches the filesystem.
        csc::verify_prehash(
            self.certificate(),
            self.algorithm.algorithm,
            digest,
            &signature,
        )?;
        Ok(signature)
    }
}

impl CliError {
    /// A refusal from the signing library, wherever it was raised.
    pub(crate) fn from_sign(error: SignError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: error.code().exit(),
        }
    }
}
