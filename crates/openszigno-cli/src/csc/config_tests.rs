//! What the `--csc` configuration accepts, and what it refuses by name.
//!
//! No file here holds a real token: every value is a synthetic string written
//! into a temporary directory that the test removes.

use super::*;

/// Write `text` as a configuration file and load it.
fn load(text: &str) -> Result<CscConfig, CliError> {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("csc.toml");
    std::fs::write(&path, text).expect("the configuration is written");
    // Owner-only, so the permission warning is a separate test's subject and
    // not a stray entry in every other one's expectations.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("the mode is set");
    }
    CscConfig::load(&path)
}

/// The access token a configuration carries, if it carries one.
fn token(config: &CscConfig) -> Option<&str> {
    config.access_token.as_deref().map(String::as_str)
}

const MINIMAL: &str = concat!(
    "base_url = \"https://qtsp.example/csc/v2\"\n",
    "client_id = \"openszigno-cli\"\n",
    "access_token = \"service-token\"\n"
);

#[test]
fn a_minimal_configuration_loads_and_keeps_only_what_it_said() {
    let config = load(MINIMAL).expect("a usable configuration");
    assert_eq!(config.base_url, "https://qtsp.example/csc/v2");
    assert_eq!(token(&config), Some("service-token"));
    assert_eq!(config.credential_id, None);
    assert!(config.pin.is_none() && config.otp.is_none());
    // Not even a debug print may carry the token.
    let printed = format!("{config:?}");
    assert!(!printed.contains("service-token"));
    assert!(printed.contains("qtsp.example"));
}

#[test]
fn a_trailing_slash_comments_and_both_string_forms_are_all_read() {
    let config = load(
        "# a comment line\n\
         \n\
         base_url = 'https://qtsp.example/csc/v2/'  # trailing comment\n\
         client_id = \"openszigno-cli\"\n\
         access_token = \"tok\\ten\"\n\
         credential_id = \"cred-1a2b3c\"\n",
    )
    .expect("a usable configuration");
    // The base URL is joined to an operation name, so one trailing slash must
    // not become two.
    assert_eq!(config.base_url, "https://qtsp.example/csc/v2");
    assert_eq!(token(&config), Some("tok\ten"));
    assert_eq!(config.credential_id.as_deref(), Some("cred-1a2b3c"));
}

#[test]
fn a_secret_may_live_in_a_file_beside_the_configuration() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    std::fs::write(directory.path().join("token"), "file-token\n").expect("written");
    std::fs::write(directory.path().join("pin"), "1234\n").expect("written");
    let path = directory.path().join("csc.toml");
    std::fs::write(
        &path,
        "base_url = \"https://qtsp.example/csc/v2\"\n\
         client_id = \"openszigno-cli\"\n\
         access_token_file = \"token\"\n\
         pin_file = \"pin\"\n",
    )
    .expect("written");
    let config = CscConfig::load(&path).expect("a usable configuration");
    // A relative path is resolved against the configuration's own directory,
    // and one trailing line ending is what an editor leaves behind.
    assert_eq!(token(&config), Some("file-token"));
    // The path is kept as well, because `csc login` writes the token there.
    assert_eq!(
        config.access_token_path.as_deref(),
        Some(directory.path().join("token").as_path())
    );
    assert_eq!(config.pin.as_deref().map(String::as_str), Some("1234"));
}

#[test]
fn a_configuration_that_cannot_be_used_is_refused_by_name() {
    for (text, expected) in [
        ("client_id = \"a\"\naccess_token = \"t\"\n", "base_url"),
        (
            "base_url = \"https://q/csc/v2\"\naccess_token = \"t\"\n",
            "client_id",
        ),
        (
            "base_url = \"ftp://q/csc/v2\"\nclient_id = \"a\"\naccess_token = \"t\"\n",
            "base_url",
        ),
        (
            "base_url = \"https://q/csc/v2\"\nclient_id = \"\"\naccess_token = \"t\"\n",
            "client_id",
        ),
        (
            "base_url = \"https://q/csc/v2\"\nclient_id = \"a\"\naccess_token = \"\"\n",
            "access token",
        ),
        (
            "base_url = \"https://q/csc/v2\"\nclient_id = \"a\"\ntoken_url = \"ftp://q/t\"\n",
            "token_url",
        ),
        (
            "base_url = \"https://q/csc/v2\"\nclient_id = \"a\"\ncredential_id = \"\"\n",
            "credential_id",
        ),
    ] {
        let error = load(text).expect_err("unusable");
        assert_eq!(error.code, "csc_config_invalid");
        assert_eq!(error.exit, 4);
        assert!(error.message.contains(expected), "{}", error.message);
    }
}

#[test]
fn a_token_given_twice_and_an_unknown_key_are_both_refused() {
    let error = load(&format!("{MINIMAL}access_token_file = \"token\"\n"))
        .expect_err("both forms of the same secret");
    assert!(error.message.contains("access_token_file"));
    let error = load(&format!("{MINIMAL}scope = \"service\"\n")).expect_err("an unknown key");
    assert!(error.message.contains("`scope`"));
}

#[test]
fn only_the_flat_string_subset_of_toml_is_accepted() {
    for text in [
        // A table header: this configuration is one flat table.
        "[service]\nbase_url = \"https://q\"\n",
        // An array, a number and a boolean are not strings.
        "base_url = [\"https://q\"]\n",
        "base_url = 3\n",
        "base_url = true\n",
        // Not `key = value` at all, and a key that is not bare.
        "base_url\n",
        "\"base url\" = \"https://q\"\n",
        // An unknown escape, and a repeated key.
        "base_url = \"https://q\\qq\"\n",
        "base_url = \"https://q\"\nbase_url = \"https://r\"\n",
    ] {
        let error = load(text).expect_err("outside the subset");
        assert_eq!(error.code, "csc_config_invalid", "{text}");
        // The refusal points at the line, so it can be acted on.
        assert!(error.message.contains("line"), "{}", error.message);
    }
}

/// A configuration with no token at all is what `csc login` starts from, so
/// it loads: the token is what that command is about to write.
#[test]
fn a_configuration_without_a_token_loads_because_login_is_what_writes_one() {
    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("csc.toml");
    std::fs::write(
        &path,
        "base_url = \"https://qtsp.example/csc/v2\"\n\
         client_id = \"openszigno-cli\"\n\
         access_token_file = \"not-written-yet\"\n",
    )
    .expect("written");
    let config = CscConfig::load(&path).expect("a configuration to log in with");
    assert_eq!(token(&config), None);
    assert_eq!(
        config.access_token_path.as_deref(),
        Some(directory.path().join("not-written-yet").as_path())
    );
}

/// The keys the login round needs are read rather than warned about, and a
/// redirect that leaves the machine is refused: it would hand somebody else an
/// authorization code.
#[test]
fn the_login_keys_are_read_and_only_a_loopback_redirect_is_accepted() {
    let config = load(&format!(
        "{MINIMAL}redirect_uri = \"http://127.0.0.1:0/callback\"\n\
         client_secret = \"synthetic-client-secret\"\n\
         authorization_url = \"https://as.example/oauth2/authorize\"\n\
         token_url = \"https://as.example/oauth2/token\"\n"
    ))
    .expect("a usable configuration");
    assert!(config.warnings.is_empty());
    assert_eq!(
        config.redirect_uri.as_deref(),
        Some("http://127.0.0.1:0/callback")
    );
    assert_eq!(
        config.client_secret.as_deref().map(String::as_str),
        Some("synthetic-client-secret")
    );
    assert_eq!(
        config.authorization_url.as_deref(),
        Some("https://as.example/oauth2/authorize")
    );
    assert_eq!(
        config.token_url.as_deref(),
        Some("https://as.example/oauth2/token")
    );
    // Nor does a debug print carry the secret.
    assert!(!format!("{config:?}").contains("synthetic-client-secret"));

    let error = load(&format!(
        "{MINIMAL}redirect_uri = \"https://example.com/cb\"\n"
    ))
    .expect_err("not a loopback redirect");
    assert!(error.message.contains("loopback"));
    assert!(is_loopback_redirect("http://localhost:8642/callback"));
    assert!(is_loopback_redirect("http://[::1]:0/callback"));
    assert!(!is_loopback_redirect("http://192.168.1.4/cb"));
}

#[cfg(unix)]
#[test]
fn a_world_readable_configuration_is_warned_about_and_still_loads() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("a temporary directory");
    let path = directory.path().join("csc.toml");
    std::fs::write(&path, MINIMAL).expect("written");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let config = CscConfig::load(&path).expect("a permissive file still loads");
    assert!(
        config
            .warnings
            .iter()
            .any(|notice| notice.code == "csc_config_permissive")
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    let config = CscConfig::load(&path).expect("the configuration loads");
    assert!(config.warnings.is_empty());
}

#[test]
fn plaintext_is_refused_unless_the_caller_asked_for_a_private_destination() {
    // The bearer token travels in a request header, so http hands it to
    // anyone on the path.
    let error = check_scheme("http://qtsp.example/csc/v2", false).expect_err("plaintext");
    assert_eq!(error.code().as_str(), "csc_config_invalid");
    assert!(error.message().contains("https"));
    check_scheme("http://127.0.0.1:8080/csc/v2", true).expect("an opt-in private destination");
    check_scheme("https://qtsp.example/csc/v2", false).expect("https needs no flag");
}

#[test]
fn a_comment_marker_inside_a_quoted_value_is_part_of_the_value() {
    assert_eq!(strip_comment(r#""a#b"  # tail"#), r#""a#b""#);
    assert_eq!(strip_comment(r#""plain""#), r#""plain""#);
    // An escaped quote is part of the value; a bare one ends it early.
    assert_eq!(parse_string(r#""a\"b""#).as_deref(), Some("a\"b"));
    assert_eq!(parse_string(r#""a"b""#), None);
    assert_eq!(parse_string("'liter\\al'").as_deref(), Some("liter\\al"));
}
