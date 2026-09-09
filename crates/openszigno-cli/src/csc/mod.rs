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
//! | [`oauth`] | PKCE, the authorization URL, and the loopback listener a redirect comes back to. |
//! | [`tokens`] | The token endpoint, and the two files a login leaves behind. |
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
//! # The `oauth2` credential round
//!
//! A credential whose `authMode` is `oauth2` is not authorised by a PIN. It
//! needs a second OAuth 2.0 authorization-code round with `scope=credential`,
//! bound to the very hashes being signed, whose access token plays the SAD
//! role in step 5. `sign` runs that round itself, between steps 3 and 5,
//! because only `sign` knows the hashes: it prints the authorization URL,
//! waits on a loopback listener, and redeems the code. The parameters go in as
//! query parameters, or as one RFC 9396 `authorization_details` object when
//! the service's `info` reported `supportsRar`.
//!
//! `--no-interactive` refuses that round instead of running it, and refuses it
//! during discovery rather than after the dossier has been read: the run stops
//! with `csc_authorization_required`, which is what every `oauth2` credential
//! did before this flow existed.
//!
//! # What leaves the machine
//!
//! One base64 SHA-256 digest per signature, the credential identifier, and the
//! bearer token in an `Authorization` header, to the host the configuration
//! named. Never the dossier, never a payload, never a title.

pub(crate) mod client;
pub(crate) mod config;
pub(crate) mod oauth;
pub(crate) mod tokens;

use openszigno_author::sign::csc::{self, AuthMode, ChosenAlgorithm, CredentialInfo, ServiceInfo};
use openszigno_author::sign::{SignError, SignErrorCode, SignatureAlgorithm, Signer};
use openszigno_verify::{Clock as _, SystemClock};
use zeroize::Zeroizing;

use crate::online::Fetcher;
use crate::response::{CliError, Notice};

use client::Client;
use config::CscConfig;
use oauth::{AuthorizationRequest, CredentialRound, Listener};
use tokens::Tokens;

/// The OAuth 2.0 endpoints an interactive round goes to.
pub(crate) struct Endpoints {
    pub(crate) authorization: String,
    pub(crate) token: String,
}

impl Endpoints {
    /// What the configuration wrote, and otherwise what the service published.
    ///
    /// A CSC service that delegates to an authorization server names it in
    /// `info` as `oauth2`, and the two endpoints hang off it at the paths the
    /// CSC API v2 specification gives them. A deployment that puts them
    /// somewhere else says so in the configuration, which always wins.
    pub(crate) fn resolve(config: &CscConfig, info: Option<&ServiceInfo>) -> Option<Self> {
        let published = info
            .and_then(|info| info.oauth2.as_deref())
            .map(|base| base.trim_end_matches('/').to_owned());
        let at = |suffix: &str| published.as_ref().map(|base| format!("{base}{suffix}"));
        Some(Self {
            authorization: config
                .authorization_url
                .clone()
                .or_else(|| at("/oauth2/authorize"))?,
            token: config.token_url.clone().or_else(|| at("/oauth2/token"))?,
        })
    }
}

/// The refusal a run gets when it needs OAuth 2.0 endpoints and has none.
pub(crate) fn no_endpoints() -> SignError {
    SignError::remote(
        SignErrorCode::CscConfigInvalid,
        "this run needs the OAuth 2.0 authorization and token endpoints, and neither the configuration's `authorization_url` and `token_url` nor the service's own `info` published them",
    )
}

/// One authorization-code round with PKCE, from the URL a person opens to the
/// tokens the code was exchanged for.
///
/// It is the same code for both scopes. `scope=service` obtains the bearer
/// token every CSC operation carries; `scope=credential` obtains the token
/// that authorises one signature over given hashes, and differs only by the
/// [`CredentialRound`] passed in.
pub(crate) struct Round<'a> {
    pub(crate) fetcher: &'a Fetcher,
    pub(crate) endpoints: &'a Endpoints,
    pub(crate) client_id: &'a str,
    pub(crate) client_secret: Option<&'a str>,
    /// Whether the client secret goes in an HTTP Basic header rather than the
    /// token request body.
    pub(crate) basic: bool,
    /// The `redirect_uri` the configuration named, if any. Only its path and
    /// its port are used; the host is always `127.0.0.1`.
    pub(crate) redirect_uri: Option<&'a str>,
    /// Whether to hand the URL to the platform opener as well as printing it.
    /// Off unless the caller asked, because opening a browser is an action
    /// taken on the user's machine and a printed URL is not.
    pub(crate) open: bool,
}

impl Round<'_> {
    pub(crate) fn run(&self, credential: Option<CredentialRound<'_>>) -> Result<Tokens, SignError> {
        // The listener is bound before the URL is built, because the URL has
        // to name the port it ended up on.
        let listener = Listener::bind(self.redirect_uri)?;
        let pkce = oauth::pkce();
        let state = oauth::random_value();
        let url = AuthorizationRequest {
            endpoint: &self.endpoints.authorization,
            client_id: self.client_id,
            redirect_uri: listener.redirect_uri(),
            state: &state,
            challenge: &pkce.challenge,
            credential,
        }
        .url();
        announce(&url);
        if self.open {
            open_in_browser(&url);
        }
        let code = listener.wait(&state, oauth::REDIRECT_TIMEOUT)?;
        tokens::redeem_code(
            self.fetcher,
            &self.endpoints.token,
            &tokens::Client {
                client_id: self.client_id,
                client_secret: self.client_secret,
                basic: self.basic,
            },
            &code,
            &pkce.verifier,
            listener.redirect_uri(),
        )
    }
}

/// Whether the service takes HTTP Basic client authentication at its token
/// endpoint, as its `info` reported. Without that statement the secret goes in
/// the body, which RFC 6749 section 2.3.1 also permits and which is what the
/// surveyed deployments accept.
pub(crate) fn takes_basic(info: Option<&ServiceInfo>) -> bool {
    info.is_some_and(|info| {
        info.auth_type
            .iter()
            .any(|value| value.eq_ignore_ascii_case("basic"))
    })
}

/// The bearer token this run will use, renewed first if it has expired.
///
/// The renewal happens before anything is contacted, because an expired token
/// fails `info` exactly as it fails `signatures/signHash`, and a refusal that
/// says `csc_rejected` when the remedy is "your token expired" is a refusal
/// nobody can act on. The endpoint comes out of the record the login wrote, so
/// a refresh needs no discovery and no second configuration key.
fn usable_token(
    config: &CscConfig,
    fetcher: &Fetcher,
    warnings: &mut Vec<Notice>,
) -> Result<Zeroizing<String>, SignError> {
    let missing = || {
        SignError::remote(
            SignErrorCode::CscConfigInvalid,
            "the --csc configuration must carry `access_token` or `access_token_file`: run `openszigno csc login` to obtain one, or put a scope=service bearer token there yourself",
        )
    };
    let (Some(path), Some(record)) = (
        config.access_token_path.as_deref(),
        config
            .access_token_path
            .as_deref()
            .map(tokens::load_record)
            .transpose()?
            .flatten(),
    ) else {
        return config.access_token.clone().ok_or_else(missing);
    };
    let now = now();
    if !record.is_expired(now) {
        return config.access_token.clone().ok_or_else(missing);
    }
    let (Some(refresh_token), Some(endpoint)) = (
        record.refresh_token.as_deref(),
        record.token_url.as_deref().or(config.token_url.as_deref()),
    ) else {
        return Err(SignError::remote(
            SignErrorCode::CscTokenUnusable,
            "the stored CSC access token has expired and no refresh token was issued with it; run `openszigno csc login` again",
        ));
    };
    let renewed = tokens::refresh(
        fetcher,
        endpoint,
        &tokens::Client {
            client_id: &config.client_id,
            client_secret: config.client_secret.as_ref().map(|value| value.as_str()),
            basic: false,
        },
        refresh_token,
    )?;
    tokens::store(path, &renewed, endpoint, now)?;
    warnings.push(Notice {
        code: "csc_token_refreshed".to_owned(),
        message: "the stored CSC access token had expired and was renewed with its refresh token"
            .to_owned(),
    });
    Ok(renewed.access_token)
}

/// Print the authorization URL, on stderr.
///
/// stderr, not stdout, for the same reason every other diagnostic goes there:
/// stdout is the JSON envelope, and a run whose output is being parsed must
/// still be able to say what the person at the keyboard has to do. The URL
/// carries no secret: the client identifier is public and the PKCE challenge
/// is a digest of a verifier that never leaves this process.
fn announce(url: &str) {
    crate::render::write_diagnostic(&format!(
        "open this URL to authorise the request, then return here:\n{url}"
    ));
}

/// Hand the URL to the platform's opener. Failure is silent on purpose: the
/// URL has already been printed, so a machine with no opener, or a headless
/// one, loses nothing by the attempt failing.
fn open_in_browser(url: &str) {
    let (program, prefix) = if cfg!(target_os = "macos") {
        ("open", None)
    } else if cfg!(target_os = "windows") {
        ("cmd", Some(["/c", "start", ""]))
    } else {
        ("xdg-open", None)
    };
    let mut command = std::process::Command::new(program);
    for argument in prefix.into_iter().flatten() {
        command.arg(argument);
    }
    let _ = command
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// The current time as whole seconds since the epoch.
pub(crate) fn now() -> u64 {
    u64::try_from(SystemClock.unix_time()).unwrap_or_default()
}

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
    /// What an `oauth2`-mode credential needs to be authorised: the endpoints,
    /// the client, and whether the service takes its parameters as RFC 9396
    /// `authorization_details`. `None` for an `explicit`-mode credential,
    /// which is authorised by a PIN and needs no browser.
    authorizer: Option<Authorizer>,
}

/// The half of an interactive credential round that can be resolved before
/// there is a digest to authorise.
struct Authorizer {
    endpoints: Endpoints,
    client_id: String,
    client_secret: Option<Zeroizing<String>>,
    basic: bool,
    redirect_uri: Option<String>,
    supports_rar: bool,
}

/// What a `sign --csc` run needs to open one.
pub(crate) struct CscRequest<'a> {
    pub(crate) config: &'a std::path::Path,
    pub(crate) credential: Option<&'a str>,
    pub(crate) proxy: Option<&'a str>,
    pub(crate) allow_private: bool,
    /// Whether an `oauth2`-mode credential may be authorised by printing a URL
    /// and waiting on a loopback listener. `--no-interactive` clears it, and
    /// then such a credential is refused during discovery, before the dossier
    /// is touched.
    pub(crate) interactive: bool,
}

impl CscSigner {
    /// Run the discovery half of the flow, and return a signer ready to sign
    /// digests.
    ///
    /// Everything that can refuse the run refuses it here, before a byte of
    /// the dossier has been read: a configuration that will not load, a
    /// service this build cannot speak to, a credential that is ambiguous or
    /// unusable, an expired token with nothing to renew it, and an
    /// `oauth2`-mode credential under `--no-interactive`.
    pub(crate) fn open(request: &CscRequest<'_>) -> Result<(Self, Vec<Notice>), CliError> {
        let mut config = CscConfig::load(request.config)?;
        config::check_scheme(&config.base_url, request.allow_private)
            .map_err(CliError::from_sign)?;
        let fetcher = Fetcher::new(request.proxy, request.allow_private)
            .map_err(|message| CliError::option_invalid("online_options_invalid", message))?;
        let mut warnings = std::mem::take(&mut config.warnings);
        let token = usable_token(&config, &fetcher, &mut warnings).map_err(CliError::from_sign)?;
        let client = Client::new(fetcher, &config.base_url, Some(token));
        Self::discover(client, &config, request)
            .map(|signer| (signer, warnings))
            .map_err(CliError::from_sign)
    }

    fn discover(
        client: Client,
        config: &CscConfig,
        request: &CscRequest<'_>,
    ) -> Result<Self, SignError> {
        let info = csc::parse_info(&client.post("info", &csc::info_request())?)?;
        let credential_id = match request.credential.or(config.credential_id.as_deref()) {
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
        // Whether a browser round may be opened is decided here rather than
        // after the dossier has been read: a run that cannot finish should not
        // have started.
        let authorizer = match (credential.auth_mode, request.interactive) {
            (AuthMode::OAuth2, false) => {
                return Err(SignError::remote(
                    SignErrorCode::CscAuthorizationRequired,
                    "this credential is authorised through an OAuth 2.0 round with scope=credential, which needs a browser, and --no-interactive refused it. Run the command without --no-interactive, or authorise the credential with the provider's own flow",
                ));
            }
            (AuthMode::OAuth2, true) => Some(Authorizer {
                endpoints: Endpoints::resolve(config, Some(&info)).ok_or_else(no_endpoints)?,
                client_id: config.client_id.clone(),
                client_secret: config.client_secret.clone(),
                basic: takes_basic(Some(&info)),
                redirect_uri: config.redirect_uri.clone(),
                supports_rar: info.supports_rar,
            }),
            _ => None,
        };
        let algorithm = csc::choose_algorithm(&credential, &info)?;
        Ok(Self {
            client,
            credential,
            algorithm,
            pin: config.pin.clone(),
            otp: config.otp.clone(),
            info,
            authorizer,
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

    /// The Signature Activation Data that authorises signing `hashes`.
    ///
    /// Under `explicit` mode that is one `credentials/authorize` call with the
    /// PIN. Under `oauth2` it is a browser round bound to these very hashes,
    /// whose access token is what `signatures/signHash` takes in the `SAD`
    /// field. Either way the authorisation covers the hashes actually being
    /// signed and one signature, never a placeholder and never a standing
    /// permission.
    fn activation_data(&self, hashes: &[String]) -> Result<Zeroizing<String>, SignError> {
        let Some(authorizer) = &self.authorizer else {
            return csc::parse_authorize(&self.client.post(
                "credentials/authorize",
                &csc::authorize_request(
                    self.credential_id(),
                    hashes,
                    self.pin.as_ref().map(|value| value.as_str()),
                    self.otp.as_ref().map(|value| value.as_str()),
                ),
            )?)
            .map(Zeroizing::new);
        };
        let tokens = Round {
            fetcher: self.client.fetcher(),
            endpoints: &authorizer.endpoints,
            client_id: &authorizer.client_id,
            client_secret: authorizer
                .client_secret
                .as_ref()
                .map(|secret| secret.as_str()),
            basic: authorizer.basic,
            redirect_uri: authorizer.redirect_uri.as_deref(),
            open: false,
        }
        .run(Some(CredentialRound {
            credential_id: self.credential_id(),
            num_signatures: 1,
            hashes,
            hash_algorithm_oid: csc::SHA256_OID,
            rar: authorizer.supports_rar,
        }))?;
        Ok(tokens.access_token)
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
        let sad = self.activation_data(&hashes)?;
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
