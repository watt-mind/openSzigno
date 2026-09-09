//! The `--csc` configuration file: what it may say, and what is refused.
//!
//! The file is a small, flat TOML table. openSzigno reads a deliberately
//! narrow subset of TOML — comments, blank lines, and `key = "value"` with a
//! basic (`"…"`) or literal (`'…'`) string — because everything this
//! configuration holds is a string and a parser that accepted more would be a
//! parser with more to get wrong. A table header, an array, a number or a bare
//! value is refused by name rather than ignored, so a configuration that means
//! something this build does not read never looks as if it worked.
//!
//! # What may be in it
//!
//! | Key | What it is |
//! | :--- | :--- |
//! | `base_url` | Required. The CSC API base, ending in `/csc/v2`. |
//! | `client_id` | Required. The OAuth 2.0 client the token was issued to. |
//! | `client_secret`, `client_secret_file` | Optional, and unused in this round: they belong to the interactive `csc login` flow. |
//! | `redirect_uri` | Optional, likewise reserved. Must be a loopback URI. |
//! | `access_token`, `access_token_file` | One of the two is required: the bearer token for `scope=service`, obtained out of band. |
//! | `credential_id` | Optional. `--csc-credential` overrides it. |
//! | `pin_file`, `otp_file` | Optional. Read only for an `explicit`-mode credential. |
//!
//! # Secrets
//!
//! A token, a PIN, a one-time password and a client secret are read from this
//! file or from a file it names, never from `argv`, and every buffer holding
//! one zeroes itself when it is dropped. None of them reaches a message, a
//! warning, a log line or the JSON envelope: the refusals below name the key
//! that is wrong and never quote its value. The file's permissions are not
//! enforced, because a mode this tool refused would be a mode somebody worked
//! around, but a world-readable file earns a warning.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use openszigno_author::sign::{SignError, SignErrorCode};
use zeroize::Zeroizing;

use crate::key_material::read_file;
use crate::response::{CliError, Notice};

/// The largest configuration file that will be read. This one holds a handful
/// of short strings; anything near the cap is already the wrong file.
const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// A `--csc` configuration, loaded and checked.
pub(crate) struct CscConfig {
    /// The CSC API base URL, without a trailing slash.
    pub(crate) base_url: String,
    /// The credential named in the file, if any. `--csc-credential` wins.
    pub(crate) credential_id: Option<String>,
    /// The bearer token for `scope=service`.
    pub(crate) access_token: Zeroizing<String>,
    /// The PIN for an `explicit`-mode credential.
    pub(crate) pin: Option<Zeroizing<String>>,
    /// The one-time password for an `explicit`-mode credential.
    pub(crate) otp: Option<Zeroizing<String>>,
    /// What the run should warn about: a world-readable file, and the keys
    /// that are reserved for the interactive login this round does not have.
    pub(crate) warnings: Vec<Notice>,
}

/// A `Debug` that cannot print a secret.
///
/// It is written by hand rather than derived because three of the fields hold
/// one, and a derived `Debug` is exactly how a token ends up in a panic
/// message or a test failure.
impl std::fmt::Debug for CscConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CscConfig")
            .field("base_url", &self.base_url)
            .field("credential_id", &self.credential_id)
            .finish_non_exhaustive()
    }
}

fn invalid(message: impl Into<String>) -> CliError {
    CliError {
        code: SignErrorCode::CscConfigInvalid.as_str(),
        message: message.into(),
        exit: SignErrorCode::CscConfigInvalid.exit(),
    }
}

impl CscConfig {
    /// Read and check a configuration file.
    pub(crate) fn load(path: &Path) -> Result<Self, CliError> {
        let bytes = read_file(path, "CSC configuration")?;
        if bytes.len() > MAX_CONFIG_BYTES {
            return Err(invalid("the --csc configuration file is too large"));
        }
        let text = Zeroizing::new(
            String::from_utf8(bytes.to_vec())
                .map_err(|_| invalid("the --csc configuration file is not UTF-8"))?,
        );
        let table = parse_flat_toml(&text)?;
        let mut warnings = world_readable_warning(path);
        Self::from_table(&table, path, &mut warnings)
    }

    /// Build a configuration from an already-parsed table.
    fn from_table(
        table: &BTreeMap<String, Zeroizing<String>>,
        path: &Path,
        warnings: &mut Vec<Notice>,
    ) -> Result<Self, CliError> {
        for key in table.keys() {
            if !KNOWN_KEYS.contains(&key.as_str()) {
                return Err(invalid(format!(
                    "the --csc configuration names an unknown key `{key}`"
                )));
            }
        }
        let base_url = required(table, "base_url")?
            .trim_end_matches('/')
            .to_owned();
        if !base_url.starts_with("https://") && !base_url.starts_with("http://") {
            return Err(invalid("the --csc `base_url` must be an http or https URL"));
        }
        // `client_id` is required even though this round never sends it: a
        // configuration that cannot complete the login it will need next is a
        // configuration the user should hear about now, not later.
        if required(table, "client_id")?.is_empty() {
            return Err(invalid("the --csc `client_id` is empty"));
        }
        if let Some(uri) = table.get("redirect_uri") {
            if !is_loopback_redirect(uri) {
                return Err(invalid(
                    "the --csc `redirect_uri` must be a loopback URI (RFC 8252), such as http://127.0.0.1:0/callback",
                ));
            }
            warnings.push(reserved("redirect_uri"));
        }
        for key in ["client_secret", "client_secret_file"] {
            if let Some(value) = table.get(key) {
                if value.is_empty() {
                    return Err(invalid(format!("the --csc `{key}` is empty")));
                }
                warnings.push(reserved(key));
            }
        }

        let base = path.parent().unwrap_or(Path::new("."));
        let access_token = secret(table, base, "access_token", "CSC access token")?
            .ok_or_else(|| {
                invalid(
                    "the --csc configuration must carry `access_token` or `access_token_file`: obtain a scope=service bearer token from the provider out of band",
                )
            })?;
        if access_token.is_empty() {
            return Err(invalid("the --csc access token is empty"));
        }
        Ok(Self {
            base_url,
            credential_id: table
                .get("credential_id")
                .map(|value| value.to_string())
                .filter(|value| !value.is_empty()),
            access_token,
            pin: secret_file(table, base, "pin_file", "CSC PIN")?,
            otp: secret_file(table, base, "otp_file", "CSC one-time password")?,
            warnings: std::mem::take(warnings),
        })
    }
}

/// Every key this build reads or knowingly reserves.
const KNOWN_KEYS: [&str; 10] = [
    "base_url",
    "client_id",
    "client_secret",
    "client_secret_file",
    "redirect_uri",
    "access_token",
    "access_token_file",
    "credential_id",
    "pin_file",
    "otp_file",
];

fn reserved(key: &str) -> Notice {
    Notice {
        code: "csc_key_unused".to_owned(),
        message: format!(
            "the --csc `{key}` is reserved for the interactive `csc login` flow and is not used by this run"
        ),
    }
}

fn required<'a>(
    table: &'a BTreeMap<String, Zeroizing<String>>,
    key: &str,
) -> Result<&'a str, CliError> {
    table
        .get(key)
        .map(|value| value.as_str())
        .ok_or_else(|| invalid(format!("the --csc configuration is missing `{key}`")))
}

/// A secret given either inline or in a file the configuration names.
fn secret(
    table: &BTreeMap<String, Zeroizing<String>>,
    base: &Path,
    key: &str,
    what: &str,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let file_key = format!("{key}_file");
    if table.contains_key(key) && table.contains_key(&file_key) {
        return Err(invalid(format!(
            "the --csc configuration gives both `{key}` and `{file_key}`"
        )));
    }
    if let Some(value) = table.get(key) {
        return Ok(Some(value.clone()));
    }
    read_secret_file(table, base, &file_key, what)
}

fn secret_file(
    table: &BTreeMap<String, Zeroizing<String>>,
    base: &Path,
    key: &str,
    what: &str,
) -> Result<Option<Zeroizing<String>>, CliError> {
    read_secret_file(table, base, key, what)
}

/// Read a secret out of a file the configuration names.
///
/// A relative path is resolved against the configuration file's own directory,
/// so a configuration and the token beside it move together. One trailing line
/// ending is stripped, for the same reason `--passphrase-file` strips one: it
/// is what an editor leaves behind and nobody means it.
fn read_secret_file(
    table: &BTreeMap<String, Zeroizing<String>>,
    base: &Path,
    key: &str,
    what: &str,
) -> Result<Option<Zeroizing<String>>, CliError> {
    let Some(value) = table.get(key) else {
        return Ok(None);
    };
    let named = PathBuf::from(value.as_str());
    let path = if named.is_absolute() {
        named
    } else {
        base.join(named)
    };
    let bytes = read_file(&path, what)?;
    let mut text = String::from_utf8(bytes.to_vec())
        .map_err(|_| invalid(format!("the {what} file is not UTF-8")))?;
    if text.ends_with('\n') {
        text.pop();
        if text.ends_with('\r') {
            text.pop();
        }
    }
    Ok(Some(Zeroizing::new(text)))
}

/// RFC 8252 says a native application's redirect goes to the loopback
/// interface. Nothing else is accepted, because a redirect that leaves the
/// machine is a redirect that hands somebody else an authorization code.
fn is_loopback_redirect(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once(':')
        .map_or(authority, |(host, _)| host);
    host == "127.0.0.1" || host == "localhost" || host == "[::1]" || host == "::1"
}

/// Warn when the configuration file is readable by anyone on the machine.
///
/// It is a warning and not a refusal on purpose: a mode this tool rejected
/// would be a mode somebody chmod-ed around, and the file may legitimately
/// hold no secret at all when the token lives in a separate
/// `access_token_file`. On a platform without POSIX modes there is nothing to
/// look at and nothing is said.
fn world_readable_warning(path: &Path) -> Vec<Notice> {
    #[cfg(unix)]
    return {
        use std::os::unix::fs::PermissionsExt as _;

        let Ok(metadata) = std::fs::metadata(path) else {
            return Vec::new();
        };
        if metadata.permissions().mode() & 0o077 == 0 {
            return Vec::new();
        }
        vec![Notice {
            code: "csc_config_permissive".to_owned(),
            message:
                "the --csc configuration file is readable by other users on this machine; it may hold a bearer token, so consider `chmod 600`"
                    .to_owned(),
        }]
    };
    #[cfg(not(unix))]
    {
        let _ = path;
        Vec::new()
    }
}

/// The flat `key = "value"` subset of TOML this configuration is written in.
///
/// Values are kept in `Zeroizing` buffers because one of them is a bearer
/// token, and a parser that handed them out as plain `String`s would leave
/// copies behind in freed memory.
fn parse_flat_toml(text: &str) -> Result<BTreeMap<String, Zeroizing<String>>, CliError> {
    let mut table = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |what: &str| {
            invalid(format!(
                "the --csc configuration line {} {what}",
                number + 1
            ))
        };
        if line.starts_with('[') {
            return Err(at(
                "opens a table; this configuration is one flat table of strings",
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(at("is not `key = \"value\"`"));
        };
        let key = key.trim().to_owned();
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(at("does not begin with a bare key"));
        }
        let value = strip_comment(value.trim());
        let value = parse_string(value).ok_or_else(|| {
            at("does not hold a quoted string; every value in this configuration is one")
        })?;
        if table.insert(key, Zeroizing::new(value)).is_some() {
            return Err(at("repeats a key given earlier"));
        }
    }
    Ok(table)
}

/// Drop a trailing `# comment` that sits outside the quoted value.
fn strip_comment(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut quote = None;
    for (index, byte) in bytes.iter().enumerate() {
        match (quote, byte) {
            (None, b'"' | b'\'') => quote = Some(*byte),
            (Some(open), _) if *byte == open => quote = None,
            (None, b'#') => return value[..index].trim_end(),
            _ => {}
        }
    }
    value
}

/// One TOML basic or literal string. A literal string has no escapes at all;
/// a basic one has the four that matter here.
fn parse_string(value: &str) -> Option<String> {
    if let Some(body) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return (!body.contains('\'')).then(|| body.to_owned());
    }
    let body = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = String::with_capacity(body.len());
    let mut characters = body.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            if character == '"' {
                return None;
            }
            out.push(character);
            continue;
        }
        out.push(match characters.next()? {
            '\\' => '\\',
            '"' => '"',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            _ => return None,
        });
    }
    Some(out)
}

/// Refuse a service the destination policy would only reach with a flag the
/// caller did not give.
///
/// `https` is required for a CSC exchange, and for a reason narrower than
/// "TLS is good": the bearer token travels in a request header, so plaintext
/// hands it to anyone on the path. The one exception is
/// `--online-allow-private`, which already exists for an operator's own
/// network and is what this project's own test suite serves a mock CSC service
/// from.
pub(crate) fn check_scheme(base_url: &str, allow_private: bool) -> Result<(), SignError> {
    if base_url.starts_with("https://") || allow_private {
        return Ok(());
    }
    Err(SignError::remote(
        SignErrorCode::CscConfigInvalid,
        "a CSC service must be reached over https, because the bearer token travels in a request header; pass --online-allow-private only for a service on your own machine or network",
    ))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod tests;
