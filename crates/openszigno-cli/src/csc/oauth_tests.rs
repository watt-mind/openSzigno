//! The parts of the browser round that can be checked without a browser: the
//! encodings, the URL, and what the loopback listener accepts.

use super::*;

/// A `GET` of `target` against the listener, answered on another thread so
/// the listener and the client are not the same one.
fn request(address: std::net::SocketAddr, target: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("the listener is up");
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
        .expect("the request is written");
    let mut answer = String::new();
    let _ = stream.read_to_string(&mut answer);
    answer
}

#[test]
fn base64url_matches_the_rfc_4648_vectors_and_never_pads() {
    // RFC 4648 section 10, in the URL alphabet: the padding is dropped and
    // `+` and `/` are `-` and `_`.
    assert_eq!(base64url(b""), "");
    assert_eq!(base64url(b"f"), "Zg");
    assert_eq!(base64url(b"fo"), "Zm8");
    assert_eq!(base64url(b"foo"), "Zm9v");
    assert_eq!(base64url(b"foob"), "Zm9vYg");
    assert_eq!(base64url(&[0xfb, 0xff, 0xfe]), "-__-");
    assert!(!base64url(b"foobar").contains('='));
}

/// RFC 7636 appendix B: the challenge is the base64url of the SHA-256 of the
/// verifier's ASCII bytes, and nothing else.
#[test]
fn the_pkce_challenge_is_the_s256_of_the_verifier() {
    let first = pkce();
    assert_eq!(
        first.challenge,
        base64url(&Sha256::digest(first.verifier.as_bytes()))
    );
    // 32 random bytes, base64url, is 43 characters: inside RFC 7636's 43..128.
    assert_eq!(first.verifier.len(), 43);
    assert_ne!(*first.verifier, *pkce().verifier);
}

#[test]
fn a_service_round_carries_pkce_the_state_and_nothing_about_a_credential() {
    let url = AuthorizationRequest {
        endpoint: "https://as.example/oauth2/authorize",
        client_id: "openszigno cli",
        redirect_uri: "http://127.0.0.1:4711/callback",
        state: "st4te",
        challenge: "ch4llenge",
        credential: None,
    }
    .url();
    assert!(url.starts_with("https://as.example/oauth2/authorize?"));
    assert!(url.contains("scope=service"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("code_challenge=ch4llenge"));
    assert!(url.contains("state=st4te"));
    // Every value is percent-encoded, so a space or a slash cannot become a
    // parameter separator.
    assert!(url.contains("client_id=openszigno%20cli"));
    assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A4711%2Fcallback"));
    assert!(!url.contains("credentialID"));
    assert!(!url.contains("authorization_details"));
}

#[test]
fn a_credential_round_takes_the_query_form_or_the_rar_form() {
    let hashes = vec!["aGFzaA==".to_owned()];
    let round = |rar| {
        AuthorizationRequest {
            endpoint: "https://as.example/oauth2/authorize?tenant=1",
            client_id: "client",
            redirect_uri: "http://127.0.0.1:1/callback",
            state: "s",
            challenge: "c",
            credential: Some(CredentialRound {
                credential_id: "cred-1",
                num_signatures: 1,
                hashes: &hashes,
                hash_algorithm_oid: "2.16.840.1.101.3.4.2.1",
                rar,
            }),
        }
        .url()
    };
    let plain = round(false);
    assert!(plain.contains("scope=credential"));
    // The endpoint already had a query string, so the parameters are appended
    // rather than starting a second one.
    assert!(plain.contains("tenant=1&response_type=code"));
    assert!(plain.contains("credentialID=cred-1"));
    assert!(plain.contains("numSignatures=1"));
    assert!(plain.contains("hashes=aGFzaA%3D%3D"));
    assert!(plain.contains("hashAlgorithmOID=2.16.840.1.101.3.4.2.1"));
    assert!(!plain.contains("authorization_details"));

    let rich = round(true);
    assert!(rich.contains("authorization_details="));
    assert!(!rich.contains("&credentialID="));
    let details = rich
        .split("authorization_details=")
        .nth(1)
        .expect("the parameter is there");
    let decoded: serde_json::Value =
        serde_json::from_str(&decode(details)).expect("it is a JSON array");
    assert_eq!(decoded[0]["type"], "credential");
    assert_eq!(decoded[0]["credentialID"], "cred-1");
    assert_eq!(decoded[0]["documentDigests"][0]["hash"], "aGFzaA==");
    assert_eq!(decoded[0]["hashAlgorithmOID"], "2.16.840.1.101.3.4.2.1");
}

#[test]
fn percent_coding_round_trips_and_a_plus_decodes_as_a_space() {
    for value in ["", "plain", "a b&c=d/e?f#g", "árvíztűrő"] {
        assert_eq!(decode(&encode(value)), value);
    }
    assert_eq!(decode("a+b"), "a b");
    // A truncated escape is data, not a panic.
    assert_eq!(decode("a%"), "a%");
    assert_eq!(decode("a%zz"), "a%zz");
}

#[test]
fn a_configured_redirect_decides_the_path_and_only_a_real_port() {
    assert_eq!(
        split("http://127.0.0.1:0/callback"),
        (0, "/callback".into())
    );
    assert_eq!(split("http://127.0.0.1:8081/cb"), (8081, "/cb".into()));
    assert_eq!(split("http://localhost/"), (0, "/callback".into()));
    assert_eq!(split("http://127.0.0.1:9/a/b?x=1"), (9, "/a/b".into()));
}

/// The listener binds an ephemeral loopback port and names it in the
/// `redirect_uri` it will send, whatever host the configuration wrote.
#[test]
fn the_listener_binds_loopback_and_reports_the_port_it_got() {
    let listener = Listener::bind(Some("http://localhost:0/cb")).expect("a port is available");
    let uri = listener.redirect_uri().to_owned();
    assert!(uri.starts_with("http://127.0.0.1:"), "{uri}");
    assert!(uri.ends_with("/cb"), "{uri}");
    assert!(!uri.contains(":0/"), "{uri}");
}

#[test]
fn the_code_arrives_only_under_the_state_this_run_issued() {
    let listener = Listener::bind(None).expect("a port is available");
    let address = listener.listener.local_addr().expect("the port is known");

    // A request to another path is not the redirect, and the listener keeps
    // waiting rather than treating it as one.
    let waiting = std::thread::spawn(move || {
        let listener = listener;
        listener.wait("the-state", Duration::from_secs(20))
    });
    assert!(request(address, "/favicon.ico").contains("404"));
    assert!(request(address, "/callback?code=c0de&state=the-state").contains("200 OK"));
    let code = waiting
        .join()
        .expect("the listener thread finished")
        .expect("the code arrived");
    assert_eq!(*code, "c0de");
}

#[test]
fn a_state_that_was_never_issued_discards_the_code() {
    let listener = Listener::bind(None).expect("a port is available");
    let address = listener.listener.local_addr().expect("the port is known");
    let waiting = std::thread::spawn(move || listener.wait("mine", Duration::from_secs(20)));
    let answer = request(address, "/callback?code=somebody-elses&state=theirs");
    assert!(answer.contains("400"));
    let error = waiting
        .join()
        .expect("the listener thread finished")
        .expect_err("the state did not match");
    assert_eq!(error.code(), SignErrorCode::CscStateMismatch);
    // The code that arrived is not in the message, because it is not this
    // run's to use or to print.
    assert!(!error.message().contains("somebody-elses"));
}

#[test]
fn an_authorization_error_stops_the_round_with_the_servers_own_identifier() {
    let listener = Listener::bind(None).expect("a port is available");
    let address = listener.listener.local_addr().expect("the port is known");
    let waiting = std::thread::spawn(move || listener.wait("s", Duration::from_secs(20)));
    assert!(request(address, "/callback?error=access_denied&state=s").contains("400"));
    let error = waiting
        .join()
        .expect("the listener thread finished")
        .expect_err("the round was refused");
    assert_eq!(error.code(), SignErrorCode::CscLoginFailed);
    assert!(error.message().contains("access_denied"));
}

#[test]
fn a_redirect_without_a_code_is_a_failure_and_not_an_empty_code() {
    let listener = Listener::bind(None).expect("a port is available");
    let address = listener.listener.local_addr().expect("the port is known");
    let waiting = std::thread::spawn(move || listener.wait("s", Duration::from_secs(20)));
    assert!(request(address, "/callback?state=s&code=").contains("400"));
    let error = waiting
        .join()
        .expect("the listener thread finished")
        .expect_err("no code arrived");
    assert_eq!(error.code(), SignErrorCode::CscLoginFailed);
}

/// A login nobody completes ends rather than waiting forever.
#[test]
fn the_listener_gives_up_on_its_deadline() {
    let listener = Listener::bind(None).expect("a port is available");
    let error = listener
        .wait("s", Duration::from_millis(120))
        .expect_err("nothing arrived");
    assert_eq!(error.code(), SignErrorCode::CscLoginFailed);
    assert!(error.message().contains("--no-interactive"));
}
