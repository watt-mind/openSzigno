//! `csc login`: obtain the tokens `sign --csc` needs, and store them.
//!
//! This is the one command in the tool that waits for a person. It prints an
//! authorization URL, binds a loopback listener, and finishes when the browser
//! comes back to it; everything it does afterwards is a bounded exchange
//! through the same transport every other request goes through.
//!
//! # What one run does
//!
//! 1. `POST info` on the CSC service, without a token, for `specs`,
//!    `supportsRar` and the authorization server the service delegates to.
//! 2. The `scope=service` authorization-code round, with PKCE `S256` and a
//!    loopback redirect: the URL is printed, the code arrives at the listener,
//!    and the token endpoint turns it into an access token.
//! 3. The token is written to the configuration's `access_token_file`, and the
//!    expiry, the refresh token and the token endpoint into the record beside
//!    it. Both files are created `0600` on Unix.
//! 4. With a credential named, `POST credentials/info` under the fresh token,
//!    so the run says whether signing with it will need a second, interactive
//!    round.
//!
//! # What is never printed
//!
//! The access token, the refresh token, the authorization code, the PKCE
//! verifier and the client secret. Not on stdout, not on stderr, not in the
//! JSON envelope, and none of them in `argv`. What the report carries is the
//! path the token was written to and the instant it expires.

use openszigno_author::sign::csc::{self, AuthMode};
use openszigno_author::sign::{SignError, SignErrorCode};
use openszigno_verify::format_rfc3339;
use serde_json::json;

use crate::args::CscLoginArgs;
use crate::csc::client::Client;
use crate::csc::config::{self, CscConfig};
use crate::csc::{Endpoints, Round, no_endpoints, now, takes_basic, tokens};
use crate::input::InputInfo;
use crate::online::Fetcher;
use crate::response::{CliError, CliResult, Notice, Success, failure};

/// `csc login` reads no dossier, so its envelope has no input to describe.
fn no_input() -> InputInfo {
    InputInfo {
        format: None,
        bytes: None,
    }
}

pub(crate) fn csc_login(args: &CscLoginArgs) -> CliResult {
    run(args).map_err(|error| failure(no_input(), error))
}

fn run(args: &CscLoginArgs) -> Result<Success, CliError> {
    let mut config = CscConfig::load(&args.config)?;
    config::check_scheme(&config.base_url, args.online_allow_private)
        .map_err(CliError::from_sign)?;
    let token_path = config.access_token_path.clone().ok_or_else(|| {
        CliError::from_sign(SignError::remote(
            SignErrorCode::CscConfigInvalid,
            "`csc login` writes the token it obtains into the file `access_token_file` names, so the configuration has to name one; an inline `access_token` is a token somebody else already issued",
        ))
    })?;
    let fetcher = Fetcher::new(args.online_proxy.as_deref(), args.online_allow_private)
        .map_err(|message| CliError::option_invalid("online_options_invalid", message))?;
    let mut warnings = std::mem::take(&mut config.warnings);

    // `info` is the one operation a CSC service answers without a token, which
    // is what makes it the right first call here: this run has no token yet,
    // and the answer is what says where the authorization server is.
    let mut client = Client::new(fetcher, &config.base_url, None);
    let discovered = client
        .post("info", &csc::info_request())
        .map_err(CliError::from_sign)?;
    let info = csc::parse_info(&discovered).map_err(CliError::from_sign)?;
    let endpoints = Endpoints::resolve(&config, Some(&info))
        .ok_or_else(|| CliError::from_sign(no_endpoints()))?;

    let tokens = Round {
        fetcher: client.fetcher(),
        endpoints: &endpoints,
        client_id: &config.client_id,
        client_secret: config.client_secret.as_ref().map(|value| value.as_str()),
        basic: takes_basic(Some(&info)),
        redirect_uri: config.redirect_uri.as_deref(),
        open: args.open,
    }
    .run(None)
    .map_err(CliError::from_sign)?;

    let now = now();
    let record =
        tokens::store(&token_path, &tokens, &endpoints.token, now).map_err(CliError::from_sign)?;
    if record.refresh_token.is_none() {
        warnings.push(Notice {
            code: "csc_no_refresh_token".to_owned(),
            message:
                "the service issued no refresh token, so this login has to be repeated when the access token expires"
                    .to_owned(),
        });
    }

    // The credential round is the signing run's business, because only it
    // knows the hashes. What this command can do is say, now rather than
    // mid-signature, whether one will be needed.
    client.set_token(tokens.access_token.clone());
    let credential = args
        .credential
        .as_deref()
        .or(config.credential_id.as_deref())
        .map(|id| describe(&client, id))
        .transpose()?;

    Ok(Success {
        input: no_input(),
        data: json!({
            "base_url": config.base_url,
            "specs": openszigno_core::sanitize_display(&info.specs, openszigno_core::MAX_DISPLAY_CHARS),
            "supports_rar": info.supports_rar,
            "token_file": token_path.to_string_lossy(),
            "expires_at": record
                .expires_at
                .and_then(|at| i64::try_from(at).ok())
                .map(format_rfc3339),
            "refresh_token_stored": record.refresh_token.is_some(),
            "credential": credential,
        }),
        warnings,
        payload: None,
        exit: 0,
    })
}

/// What `credentials/info` says about the credential this login was for.
fn describe(client: &Client, credential_id: &str) -> Result<serde_json::Value, CliError> {
    let credential = csc::parse_credential_info(
        credential_id,
        &client
            .post(
                "credentials/info",
                &csc::credential_info_request(credential_id),
            )
            .map_err(CliError::from_sign)?,
    )
    .map_err(CliError::from_sign)?;
    let interactive = credential.auth_mode == AuthMode::OAuth2;
    Ok(json!({
        "credential_id": openszigno_core::sanitize_display(
            &credential.credential_id,
            openszigno_core::MAX_DISPLAY_CHARS,
        ),
        "auth_mode": if interactive { "oauth2" } else { "explicit" },
        // What the next `sign --csc` run will do: an `oauth2` credential needs
        // a second authorization round, bound to the hashes, that only the
        // signing run can perform.
        "interactive_signature_required": interactive,
    }))
}
