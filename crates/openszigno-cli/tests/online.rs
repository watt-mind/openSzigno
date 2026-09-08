//! `--online`: fetching revocation data over HTTP, against a local server.
//!
//! What is being held honest here is the transport policy, because that is the
//! part `openszigno-verify` structurally cannot enforce: the size caps, the
//! refusal to follow a redirect to another host, the bounded timeout, and —
//! most important — that a fetched artefact is still judged by the offline
//! rules and is not believed merely because a server served it.
//!
//! Who may be fetched for at all, where a fetch is allowed to connect, and how
//! the cache is written are the neighbouring suite's, in `online_policy.rs`.
//! The server and the synthetic PKI both suites use live in
//! `online_support/mod.rs`.

mod online_support;

use std::time::{Duration, Instant};

use online_support::common::{CrlSpec, RevokedSpec, build_crl, keys, rsa_key};
use online_support::{
    AT, Reply, checks, dossier, end_entity_source, good_crl, good_ocsp, json, pki, reserved, run,
    scratch, serve_on, unauthorised_ocsp, verify_online, with_urls, write_all,
};

// ---------------------------------------------------------------------------
// The happy paths
// ---------------------------------------------------------------------------

#[test]
fn a_crl_fetched_from_a_distribution_point_answers_the_certificate() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_crl"),
        "{:?}",
        checks(&report)
    );
    assert_eq!(
        report["data"]["policy"]["revocation"].as_str(),
        Some("online")
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_ok=passed")),
        "{:?}",
        checks(&report)
    );
    // The policy check says, in so many words, what the run was allowed to do.
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_policy=info") && check.contains("--online")),
        "{:?}",
        checks(&report)
    );
}

#[test]
fn an_ocsp_response_fetched_from_an_aia_responder_answers_the_certificate() {
    let (_pki, dossier_path, store, _fixture) = with_urls(None, Some("/ocsp"), |pki| {
        vec![("/ocsp", Reply::Body(good_ocsp(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_ocsp"),
        "{:?}",
        checks(&report)
    );
}

#[test]
fn the_online_cache_makes_a_later_offline_run_reproduce_the_answer() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let cache = directory.join("cache");

    let online = verify_online(
        &dossier_path,
        &store,
        &["--online-cache", cache.to_str().expect("a UTF-8 path")],
    );
    assert_eq!(end_entity_source(&online).as_deref(), Some("online_crl"));
    assert!(
        cache.join("crls").is_dir(),
        "the cache holds a crls/ directory"
    );

    // The same run with no network at all, taking the cache as an ordinary
    // revocation store, reaches the same answer through `store_crl`.
    let offline = json(&run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--revocation-store",
        cache.to_str().expect("a UTF-8 path"),
    ]));
    assert_eq!(end_entity_source(&offline).as_deref(), Some("store_crl"));
    assert_eq!(
        offline["data"]["policy"]["revocation"].as_str(),
        Some("offline")
    );
}

#[test]
fn nothing_is_fetched_for_a_certificate_the_offline_store_already_covers() {
    // The server answers `500` for everything. If the run fetched anyway the
    // report would carry a `http status 500` failure; it must not, because the
    // revocation store already answers for the certificate.
    let (pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(500))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let offline_store = directory.join("revocation");
    std::fs::create_dir_all(offline_store.join("crls")).expect("the crls directory is created");
    std::fs::write(offline_store.join("crls/ca.crl"), good_crl(&pki)).expect("the CRL is written");

    let report = verify_online(
        &dossier_path,
        &store,
        &[
            "--revocation-store",
            offline_store.to_str().expect("a UTF-8 path"),
        ],
    );
    assert_eq!(end_entity_source(&report).as_deref(), Some("store_crl"));
    assert!(
        !checks(&report)
            .iter()
            .any(|check| check.contains("http status")),
        "no fetch was attempted: {:?}",
        checks(&report)
    );
}

/// The shape of the OCSP request itself, asserted at the server.
///
/// This is the regression guard for a Windows-only CI failure. The request
/// carries a body, and a body whose end the peer has to infer — a chunked
/// request, or one the server answers before reading — is exactly the shape
/// that behaves differently on different platforms: closing a socket with
/// unread received data makes Windows send an RST, which the client sees as a
/// transport error rather than as an HTTP answer. So the request must arrive
/// whole, with one `Content-Length` and no chunking, and the server must read
/// all of it before replying.
#[test]
fn the_ocsp_request_arrives_whole_with_a_declared_length() {
    let (_pki, dossier_path, store, fixture) = with_urls(None, Some("/ocsp"), |pki| {
        vec![("/ocsp", Reply::Body(good_ocsp(pki)))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(end_entity_source(&report).as_deref(), Some("online_ocsp"));

    let seen = fixture.server.seen();
    let request = seen
        .iter()
        .find(|request| request.path == "/ocsp")
        .expect("the responder was asked");
    assert_eq!(request.method, "POST");
    assert!(!request.chunked, "the request must not be chunked");
    assert_eq!(
        request.content_length_headers, 1,
        "exactly one Content-Length: {request:?}"
    );
    assert_eq!(
        request.declared_length,
        Some(request.body_length),
        "the whole body arrived and was read before the answer: {request:?}"
    );
    assert!(request.body_length > 0, "{request:?}");
    // A CRL fetch carries no body at all, and must not claim one.
    assert!(
        seen.iter()
            .filter(|request| request.method == "GET")
            .all(|request| request.body_length == 0),
        "{seen:?}"
    );
}

/// The case the corpus hit, end to end: the responder answers, its answer
/// cannot be authorised, and the CRL two tiers down has to be fetched anyway.
///
/// A run that stopped at "the server replied" would never fetch the CRL and
/// would leave the certificate uncovered, which is exactly what made 50 real
/// responses look like a dead end.
#[test]
fn an_unusable_ocsp_answer_does_not_stop_the_crl_from_being_fetched() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), Some("/ocsp"), |pki| {
        vec![
            ("/ocsp", Reply::Body(unauthorised_ocsp(pki))),
            ("/ca.crl", Reply::Body(good_crl(pki))),
        ]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_crl"),
        "{:?}",
        checks(&report)
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("revocation_ok=passed") && check.contains("refused")),
        "the refused answer stays visible: {:?}",
        checks(&report)
    );
}

// ---------------------------------------------------------------------------
// The transport policy
// ---------------------------------------------------------------------------

#[test]
fn a_body_over_the_size_cap_is_refused() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Bulk(17 * 1024 * 1024))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.contains("too large") && check.contains("/ca.crl")),
        "{checks:?}"
    );
    // The limit is named, so a reader learns what "too large" was measured
    // against. It is the verifier's own limit, not a second one the fetcher
    // invented: a CRL that squeezed past a larger download cap and was then
    // skipped by the tier walk is the bug this names away.
    assert!(
        checks
            .iter()
            .any(|check| check.contains(&format!("{}-byte", 16 * 1024 * 1024))),
        "{checks:?}"
    );
    assert_ne!(end_entity_source(&report).as_deref(), Some("online_crl"));
}

#[test]
fn a_redirect_to_another_host_is_refused() {
    // The redirect target is a different port on the same address, which the
    // policy counts as another host: the certificate named one endpoint.
    let (listener, address) = reserved();
    let other = serve_on(listener, address, vec![("/ca.crl", Reply::Status(500))]);
    let elsewhere = other.url("/ca.crl");
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, move |_| {
        vec![("/ca.crl", Reply::Redirect(elsewhere.clone()))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("redirect")),
        "{checks:?}"
    );
}

#[test]
fn a_server_that_never_answers_is_bounded_rather_than_hung() {
    let (_pki, dossier_path, store, _fixture) =
        with_urls(Some("/ca.crl"), None, |_| vec![("/ca.crl", Reply::Silence)]);

    let started = Instant::now();
    let report = verify_online(&dossier_path, &store, &[]);
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(35),
        "the fetch was bounded, not hung: {elapsed:?}"
    );
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("timeout")),
        "{checks:?}"
    );
}

/// A failed fetch is a fact about the network, not about a certificate, so it
/// is reported as `info` and decides nothing on its own. Whether the gap
/// mattered is answered by the chain that needed the data — here it did, and
/// the signature says so.
#[test]
fn a_failed_fetch_is_informational_and_the_chain_reports_the_gap() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(503))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("online_fetch_failed=info")
                && check.contains("http status 503")),
        "{checks:?}"
    );
    // The blocking is done once, in the right place: on the chain that is
    // short of data.
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("revocation_status_unknown=unknown")),
        "{checks:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));
}

#[test]
fn an_http_error_is_reported_with_its_status() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(404))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("http status 404")),
        "{checks:?}"
    );
}

// ---------------------------------------------------------------------------
// A fetched artefact is still judged offline
// ---------------------------------------------------------------------------

#[test]
fn a_crl_from_the_wrong_issuer_is_fetched_and_then_rejected() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        // A perfectly well-formed CRL, signed by a CA that issued nothing in
        // this chain. Serving it must change nothing.
        let crl = build_crl(&CrlSpec::new(
            pki.other_root_der.clone(),
            rsa_key(keys::SECOND_RSA2048),
        ));
        vec![("/ca.crl", Reply::Body(crl))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_ne!(end_entity_source(&report).as_deref(), Some("online_crl"));
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("revocation_status_unknown=unknown")),
        "{checks:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));
}

#[test]
fn a_fetched_crl_that_revokes_the_certificate_is_believed() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        let crl = build_crl(
            &CrlSpec::new(pki.root_der.clone(), rsa_key(keys::ROOT_RSA2048))
                .revoking(RevokedSpec::new(&pki.signer_der, "2020-05-10T00:00:00Z")),
        );
        vec![("/ca.crl", Reply::Body(crl))]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        report["data"]["signatures"][0]["chain"][0]["revocation"]["status"].as_str(),
        Some("revoked"),
        "{:?}",
        checks(&report)
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("invalid"));
}

#[test]
fn a_server_that_answers_with_something_that_is_not_a_crl_is_refused() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![(
            "/ca.crl",
            Reply::Body(b"<html>captive portal</html>".to_vec()),
        )]
    });

    let report = verify_online(&dossier_path, &store, &[]);
    let checks = checks(&report);
    assert!(
        checks.iter().any(|check| check.contains("invalid")),
        "{checks:?}"
    );
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

#[test]
fn online_and_no_revocation_cannot_be_combined() {
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki(None, None)), &[]);
    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
        "--no-revocation",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn an_unusable_online_proxy_is_reported_rather_than_ignored() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |_| {
        vec![("/ca.crl", Reply::Status(500))]
    });
    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
        "--online-proxy",
        "not a proxy",
    ]);
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn the_online_flags_require_online() {
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki(None, None)), &[]);
    for extra in [
        vec!["--online-cache", "/tmp/nowhere"],
        vec!["--online-proxy", "http://127.0.0.1:1/"],
    ] {
        let mut arguments = vec![
            "verify",
            dossier_path.to_str().expect("a UTF-8 path"),
            "--json",
            "--trust-store",
            store.to_str().expect("a UTF-8 path"),
        ];
        arguments.extend(extra);
        assert_eq!(run(&arguments).status.code(), Some(2));
    }
}
