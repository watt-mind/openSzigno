//! The transport's own rules, tested where they are decided.
//!
//! The redirect rules are a pure function over three strings, so they are
//! exercised directly rather than through a server: a rule that has no socket
//! cannot be tested into contacting one. The credential rule is exercised
//! through the real [`Fetcher`], against names and ports nothing answers on,
//! because what it promises is that nothing is contacted at all.

use super::*;

#[test]
fn a_failure_names_the_url_and_its_class() {
    let check = failure("http://crl.example/ca.crl", FailureClass::Timeout);
    assert_eq!(check.code, CheckCode::OnlineFetchFailed);
    // Informational: whether the certificate ended up covered is the
    // verifier's answer to give, on the chain that needed the data.
    assert_eq!(check.status, openszigno_verify::CheckStatus::Info);
    assert!(check.message.contains("http://crl.example/ca.crl"));
    assert!(check.message.contains("timeout"));
    let check = failure("http://crl.example/ca.crl", FailureClass::HttpStatus(404));
    assert!(check.message.contains("http status 404"));
}

/// The class is a stable token a caller can match on, and the reason after
/// it is what tells them which rule refused the destination.
#[test]
fn a_refused_destination_names_the_class_and_the_rule() {
    let check = failure(
        "http://127.0.0.1/ca.crl",
        FailureClass::DestinationRefused("the host is a loopback address"),
    );
    assert_eq!(check.code, CheckCode::OnlineFetchFailed);
    assert_eq!(check.status, openszigno_verify::CheckStatus::Info);
    assert!(check.message.contains("destination_refused"));
    assert!(check.message.contains("loopback"));
}

/// A peer that answers an `https` request with a `302` to `http://` on the
/// same host is asking for the next request, and everything it carries, to
/// go out in the clear. It is refused here, in a function that has no
/// socket, so the refusal happens before anything is contacted.
#[test]
fn a_redirect_that_downgrades_https_to_http_is_refused() {
    let refusal = redirect_target(
        "https://csc.example/csc/v2/info",
        "http://csc.example/csc/v2/info",
        "csc.example",
    )
    .expect_err("a downgrade is refused");
    assert_eq!(
        refusal,
        FailureClass::DestinationRefused(REFUSED_REDIRECT_DOWNGRADE)
    );
    assert!(refusal.describe().contains("redirect_downgrade"));
}

/// A root-relative `Location` inherits the scheme it was served under, so
/// this one cannot downgrade; an absolute one that names `http` can, and
/// the rule is on the resolved URL rather than on the header text.
#[test]
fn the_downgrade_rule_is_applied_to_the_resolved_target() {
    assert_eq!(
        redirect_target("https://crl.example/a.crl", "/b.crl", "crl.example"),
        Ok("https://crl.example/b.crl".to_owned())
    );
    assert_eq!(
        redirect_target("https://crl.example/a.crl", "b.crl", "crl.example"),
        Ok("https://crl.example/b.crl".to_owned())
    );
    assert_eq!(
        redirect_target(
            "https://crl.example/a.crl",
            "  http://crl.example/b.crl  ",
            "crl.example"
        ),
        Err(FailureClass::DestinationRefused(REFUSED_REDIRECT_DOWNGRADE))
    );
}

/// The plain revocation path is not affected: a same-host, same-scheme
/// redirect is still followed, and an upgrade onto `https` is fine too.
#[test]
fn a_same_scheme_redirect_and_an_upgrade_are_still_followed() {
    assert_eq!(
        redirect_target(
            "http://crl.example/a.crl",
            "http://crl.example/b.crl",
            "crl.example"
        ),
        Ok("http://crl.example/b.crl".to_owned())
    );
    assert_eq!(
        redirect_target(
            "http://crl.example/a.crl",
            "https://crl.example/b.crl",
            "crl.example"
        ),
        Ok("https://crl.example/b.crl".to_owned())
    );
}

/// Leaving the host stays the older, coarser refusal, downgrade or not:
/// the authority for the URL is the certificate, and it named one host.
#[test]
fn a_redirect_to_another_host_is_still_a_redirect_failure() {
    assert_eq!(
        redirect_target(
            "https://crl.example/a.crl",
            "http://evil.example/a.crl",
            "crl.example"
        ),
        Err(FailureClass::Redirect)
    );
}

/// Credentials need TLS on the first hop as well as on every later one,
/// and the refusal happens before the host is even resolved: a plaintext
/// URL that would carry a bearer token is not looked up, let alone dialled.
#[test]
fn credentials_over_plain_http_are_refused_before_anything_is_contacted() {
    let fetcher = Fetcher::new(None, false).expect("the agent is built");
    // A name reserved by RFC 6761 for exactly this: it resolves nowhere.
    // If the rule ever moved after resolution, this would report
    // `transport` instead.
    let refusal = fetcher
        .post_json(
            "http://service.invalid/csc/v2/info",
            "synthetic-token",
            "{}",
            1024,
            true,
        )
        .map(|_| ())
        .expect_err("a plaintext credential request is refused");
    assert!(refusal.contains("credentials_require_https"), "{refusal}");
}

/// A revocation `POST` carries nothing secret, so `http` stays fine for it
/// and the credential rule does not narrow what `--online` may fetch.
#[test]
fn a_plain_revocation_post_over_http_is_not_refused_for_its_scheme() {
    let fetcher = Fetcher::new(None, true).expect("the agent is built");
    let refusal = fetcher
        .post_der(
            "http://127.0.0.1:1/ocsp",
            "application/ocsp-request",
            "application/ocsp-response",
            b"",
            1024,
        )
        .expect_err("nothing is listening there");
    assert!(!refusal.contains("credentials_require_https"), "{refusal}");
}

/// The one exemption: a loopback service under `--online-allow-private`,
/// which is what this project's own test servers are. The request gets as
/// far as the socket, and fails there rather than on the rule.
#[test]
fn a_loopback_service_under_the_opt_in_may_carry_credentials_over_http() {
    let fetcher = Fetcher::new(None, true).expect("the agent is built");
    let refusal = fetcher
        .post_json(
            "http://127.0.0.1:1/csc/v2/info",
            "synthetic-token",
            "{}",
            1024,
            true,
        )
        .map(|_| ())
        .expect_err("nothing is listening on port 1");
    assert!(!refusal.contains("credentials_require_https"), "{refusal}");
    assert!(!refusal.contains("synthetic-token"), "{refusal}");
}

/// A request that carries credentials says so, whichever half carries
/// them, and a plain revocation `POST` carries none.
#[test]
fn a_post_says_whether_it_carries_credentials() {
    let plain = Post {
        media_type: "application/ocsp-request",
        accept: "application/ocsp-response",
        bytes: b"",
        authorization: None,
        sensitive: false,
    };
    assert!(!plain.carries_credentials());
    assert!(
        Post {
            authorization: Some("Bearer x"),
            ..plain
        }
        .carries_credentials()
    );
    assert!(
        Post {
            sensitive: true,
            ..plain
        }
        .carries_credentials()
    );
}

/// The size cap the fetcher enforces is the verifier's own, so nothing
/// this fetches can be too large for the code that has to judge it.
#[test]
fn the_fetch_cap_is_the_verifiers_own_limit() {
    assert_eq!(MAX_CRL_BYTES, MAX_REVOCATION_ITEM_BYTES as u64);
    let check = failure("http://crl.example/ca.crl", FailureClass::TooLarge(16));
    assert!(check.message.contains("too large"));
    assert!(check.message.contains("16-byte"));
}

#[test]
fn a_control_character_never_reaches_a_message() {
    let check = failure("http://crl.example/\u{7}a.crl", FailureClass::Invalid);
    assert!(!check.message.contains('\u{7}'));
}
