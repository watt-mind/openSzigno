//! `--online`: who a URL may be fetched for, where a fetch may connect, how
//! many requests one question costs, and how the cache is written.
//!
//! The neighbouring `online.rs` holds the transport itself honest. This suite
//! holds honest the rules *around* the transport — the ones a hostile dossier
//! would attack first, because they decide whether it gets to choose what this
//! machine connects to at all.

mod online_support;

use std::path::Path;

use online_support::common::{
    CertSpec, CrlSpec, DossierSpec, OcspSpec, OcspStatus, SigningCertificateSpec, TestKey,
    authority_info_access_extension, build, build_crl, build_ocsp,
    crl_distribution_point_extension, document_signature, issued_by, keys, rsa_key, self_signed,
};
use online_support::{
    AT, Reply, checks, dossier, end_entity_source, good_crl, good_ocsp, json, pki, reserved, run,
    scratch, serve_on, verify_online, verify_with, with_urls, write_all,
};
use rcgen::BasicConstraints;
use serde_json::Value;

// ---------------------------------------------------------------------------
// The trust gate: who a URL may be fetched for at all
// ---------------------------------------------------------------------------

/// The finding this suite exists for. A dossier carries its own certificates,
/// including the "issuer" that signed the signer, so "an embedded issuer
/// signed this" is a statement the dossier's author wrote on both sides. Until
/// a path to a *configured* anchor exists, a CRL distribution point in that
/// dossier is an attacker-chosen destination, and contacting it lets any file
/// handed to the tool decide who the tool talks to.
///
/// So: no anchor, no request — asserted on the listener, which is the only
/// witness that cannot be talked round — and the report says why. The same
/// dossier, with the same server, fetches as soon as an anchor is configured.
#[test]
fn nothing_is_fetched_for_a_dossier_that_reaches_no_configured_anchor() {
    let (_pki, dossier_path, store, fixture) = with_urls(Some("/ca.crl"), Some("/ocsp"), |pki| {
        vec![
            ("/ca.crl", Reply::Body(good_crl(pki))),
            ("/ocsp", Reply::Body(good_ocsp(pki))),
        ]
    });

    // --- no trust store at all ---------------------------------------------
    let report = verify_with(&dossier_path, None, &["--online-allow-private"]);
    assert!(
        fixture.server.seen().is_empty(),
        "not one request may leave: {:?}",
        fixture.server.seen()
    );
    assert_eq!(
        report["data"]["policy"]["revocation"].as_str(),
        Some("online_no_anchors"),
        "{:?}",
        checks(&report)
    );
    let checks_without = checks(&report);
    assert!(
        checks_without
            .iter()
            .any(|check| check.starts_with("revocation_policy=info")
                && check.contains("no trust anchors were configured")),
        "{checks_without:?}"
    );
    // The explanation reaches the check a reader acts on, not only the policy
    // line at the top of the report.
    assert!(
        checks_without.iter().any(
            |check| check.starts_with("revocation_status_unknown=unknown")
                && check.contains("--online fetched nothing because no trust anchors")
        ),
        "{checks_without:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));

    // --- the same dossier, the same server, with the anchor configured -----
    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        report["data"]["policy"]["revocation"].as_str(),
        Some("online")
    );
    assert!(
        !fixture.server.seen().is_empty(),
        "the anchored run fetches: {:?}",
        checks(&report)
    );
    assert!(
        matches!(
            end_entity_source(&report).as_deref(),
            Some("online_ocsp" | "online_crl")
        ),
        "{:?}",
        checks(&report)
    );
}

/// An anchor that is configured but is not *this* dossier's anchor is not a
/// licence to fetch either: the certificate still sits on no path the operator
/// vouches for.
#[test]
fn nothing_is_fetched_when_the_configured_anchor_is_a_stranger() {
    let (pki, dossier_path, _store, fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let stranger = directory.join("stranger");
    std::fs::create_dir_all(stranger.join("anchors")).expect("the anchors directory is created");
    std::fs::write(stranger.join("anchors/other.der"), &pki.other_root_der)
        .expect("the anchor is written");

    let report = verify_online(&dossier_path, &stranger, &[]);
    assert!(
        fixture.server.seen().is_empty(),
        "not one request may leave: {:?}",
        fixture.server.seen()
    );
    // The chain says why: it reaches no anchor, which is the same fact the
    // fetcher declined to act on.
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("cert_path_untrusted=failed")),
        "{:?}",
        checks(&report)
    );
}

/// The reviewer's case, stated exactly: a synthetic **two-certificate chain**
/// nothing trusts — the signer and the self-signed root that issued it, both
/// carried by the dossier — must never have its CRL or its OCSP URL requested.
/// A self-signed certificate inside a dossier is a candidate like any other
/// and can never make itself an anchor, so neither certificate is on a path
/// this run validated.
#[test]
fn an_untrusted_two_certificate_chain_never_has_its_urls_requested() {
    let (listener, address) = reserved();
    let url = |path: &str| format!("http://{address}{path}");
    let pki = pki(Some(&url("/ca.crl")), Some(&url("/ocsp")));
    // The dossier carries the whole chain, root included.
    let mut signature = document_signature(vec![pki.signer_der.clone(), pki.root_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &pki.signer_key)]);
    let server = serve_on(
        listener,
        address,
        vec![
            ("/ca.crl", Reply::Body(good_crl(&pki))),
            ("/ocsp", Reply::Body(good_ocsp(&pki))),
        ],
    );
    let directory = scratch();
    // The configured anchor is a stranger to this chain.
    let (dossier_path, store) = write_all(directory.path(), &xml, &pki.other_root_der);

    let report = verify_online(&dossier_path, &store, &[]);
    assert!(
        server.seen().is_empty(),
        "neither the CRL nor the OCSP URL may be requested: {:?}",
        server.seen()
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("cert_path_untrusted=failed")),
        "{:?}",
        checks(&report)
    );
}

/// A certificate that chains to the configured anchor but that no signature or
/// timestamp under evaluation needed — one parked alongside the signer in
/// `ds:KeyInfo` — is not on a validated path and cannot generate traffic of
/// its own. Only the URLs of the path the run actually built are requested.
#[test]
fn a_certificate_the_run_did_not_validate_a_path_for_generates_no_traffic() {
    let (listener, address) = reserved();
    let url = |path: &str| format!("http://{address}{path}");
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let bystander_key = rsa_key(keys::THIRD_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    signer_spec
        .custom_extensions
        .push(crl_distribution_point_extension(&url("/ca.crl")));
    let signer = issued_by(&signer_spec, &signer_key, &root, &root_key);
    // Issued by the very same anchor, so it *is* reachable — and still must
    // not be fetched for, because nothing was validating it.
    let mut bystander_spec = CertSpec::signer("openSzigno Test Bystander");
    bystander_spec
        .custom_extensions
        .push(crl_distribution_point_extension(&url("/bystander.crl")));
    let bystander = issued_by(&bystander_spec, &bystander_key, &root, &root_key);

    let mut signature = document_signature(vec![signer.der.clone(), bystander.der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(signer.der.clone()));
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    let xml = build(&spec, &[("doc", &signer_key)]);
    let crl = build_crl(&CrlSpec::new(root.der.clone(), rsa_key(keys::ROOT_RSA2048)));
    let server = serve_on(
        listener,
        address,
        vec![
            ("/ca.crl", Reply::Body(crl.clone())),
            ("/bystander.crl", Reply::Body(crl)),
        ],
    );
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &xml, &root.der);

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_crl"),
        "{:?}",
        checks(&report)
    );
    let paths: Vec<String> = server
        .seen()
        .into_iter()
        .map(|request| request.path)
        .collect();
    assert!(paths.contains(&"/ca.crl".to_owned()), "{paths:?}");
    assert!(
        !paths.contains(&"/bystander.crl".to_owned()),
        "a certificate no signature needed must not be fetched for: {paths:?}"
    );
}

// ---------------------------------------------------------------------------
// Writing the cache
// ---------------------------------------------------------------------------

/// One cached file's name, so the tests below can tamper with exactly the file
/// a re-run will try to write.
fn cached_crl_name(cache: &Path) -> String {
    let mut names: Vec<String> = std::fs::read_dir(cache.join("crls"))
        .expect("the crls directory exists")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names.pop().expect("the cache holds a CRL")
}

/// Fetch once into `cache`, and return the fixture so the caller can run
/// again against the same server.
fn cached_run(cache: &Path, dossier: &Path, store: &Path) -> Value {
    verify_online(
        dossier,
        store,
        &["--online-cache", cache.to_str().expect("a UTF-8 path")],
    )
}

/// Caching the same artefact twice writes one file and reports nothing. This
/// is also what two runs racing each other look like from inside: the second
/// `O_EXCL` creation fails, the bytes match, and that is success.
#[test]
fn caching_the_same_artefact_twice_is_idempotent() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let cache = dossier_path.parent().expect("a parent").join("cache");

    cached_run(&cache, &dossier_path, &store);
    let name = cached_crl_name(&cache);
    let first = std::fs::read(cache.join("crls").join(&name)).expect("the cached file is read");

    let report = cached_run(&cache, &dossier_path, &store);
    assert!(
        !checks(&report)
            .iter()
            .any(|check| check.contains("cache_collision")),
        "{:?}",
        checks(&report)
    );
    let second = std::fs::read(cache.join("crls").join(&name)).expect("the cached file is read");
    assert_eq!(first, second);
    assert_eq!(
        std::fs::read_dir(cache.join("crls"))
            .expect("the crls directory exists")
            .count(),
        1,
        "one artefact, one file"
    );
}

/// An existing file under a name this run would write is **never** truncated
/// or replaced. It is reported, and the bytes on disk are the bytes that were
/// there.
#[test]
fn an_existing_cache_file_is_never_truncated() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let cache = dossier_path.parent().expect("a parent").join("cache");

    cached_run(&cache, &dossier_path, &store);
    let name = cached_crl_name(&cache);
    let squatter = b"not a CRL, and not this run's to destroy".to_vec();
    std::fs::write(cache.join("crls").join(&name), &squatter).expect("the file is replaced");

    let report = cached_run(&cache, &dossier_path, &store);
    assert_eq!(
        std::fs::read(cache.join("crls").join(&name)).expect("the file is read"),
        squatter,
        "the existing file must be left exactly as it was"
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.starts_with("online_fetch_failed=info")
                && check.contains("cache_collision")),
        "{:?}",
        checks(&report)
    );
    // The verification itself is unaffected: the artefact was fetched, and
    // failing to cache a copy of it decides nothing.
    assert_eq!(end_entity_source(&report).as_deref(), Some("online_crl"));
}

/// A symlink anywhere in the cache path is refused rather than followed. The
/// tool is told to write into a directory; writing through a link is writing
/// somewhere else.
#[cfg(unix)]
#[test]
fn a_symlinked_cache_component_is_refused() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let real = directory.join("real");
    std::fs::create_dir_all(&real).expect("the real directory is created");
    let link = directory.join("link");
    std::os::unix::fs::symlink(&real, &link).expect("the symlink is created");

    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--online",
        "--online-allow-private",
        "--online-cache",
        link.join("cache").to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(3));
    let report = json(&output);
    assert_eq!(
        report["errors"][0]["code"].as_str(),
        Some("online_cache_invalid")
    );
    assert!(
        std::fs::read_dir(&real)
            .expect("the real directory exists")
            .next()
            .is_none(),
        "nothing may be written through the link"
    );
}

/// A dangling symlink standing where a cache file would go is not a place to
/// write: `O_CREAT | O_EXCL | O_NOFOLLOW` refuses it, the link's target is
/// never created, and the run says so.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_in_the_cache_is_never_followed() {
    let (_pki, dossier_path, store, _fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });
    let directory = dossier_path.parent().expect("a parent").to_owned();
    let cache = directory.join("cache");

    cached_run(&cache, &dossier_path, &store);
    let name = cached_crl_name(&cache);
    let file = cache.join("crls").join(&name);
    std::fs::remove_file(&file).expect("the cached file is removed");
    let elsewhere = directory.join("elsewhere.der");
    std::os::unix::fs::symlink(&elsewhere, &file).expect("the symlink is created");

    let report = cached_run(&cache, &dossier_path, &store);
    assert!(
        !elsewhere.exists(),
        "the symlink target must never be created"
    );
    assert!(
        std::fs::symlink_metadata(&file)
            .expect("the entry is still there")
            .file_type()
            .is_symlink(),
        "the symlink itself must be left alone"
    );
    assert!(
        checks(&report)
            .iter()
            .any(|check| check.contains("cache_collision")),
        "{:?}",
        checks(&report)
    );
}

// ---------------------------------------------------------------------------
// The destination policy
// ---------------------------------------------------------------------------

/// Without `--online-allow-private` the loopback listener this whole suite
/// serves from is refused, and refused *before* a socket is opened: the
/// listener sees nothing.
#[test]
fn a_loopback_destination_is_refused_without_the_flag() {
    let (_pki, dossier_path, store, fixture) = with_urls(Some("/ca.crl"), None, |pki| {
        vec![("/ca.crl", Reply::Body(good_crl(pki)))]
    });

    let report = verify_with(&dossier_path, Some(&store), &[]);
    assert!(
        fixture.server.seen().is_empty(),
        "nothing may be contacted: {:?}",
        fixture.server.seen()
    );
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("online_fetch_failed=info")
                && check.contains("destination_refused")
                && check.contains("--online-allow-private")),
        "{checks:?}"
    );
    // The refusal decides nothing on its own; the chain that wanted the data
    // is what blocks, exactly as for any other failed fetch.
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("revocation_status_unknown=unknown")),
        "{checks:?}"
    );
    assert_eq!(report["data"]["verdict"].as_str(), Some("indeterminate"));

    // And with the flag the very same URL is fetched.
    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(end_entity_source(&report).as_deref(), Some("online_crl"));
}

/// Userinfo is refused whatever the flags say. It is a way of writing a URL
/// that reads as one host and names another, and it is credential material
/// this tool has no business sending anywhere.
#[test]
fn a_url_with_userinfo_is_refused_even_with_the_flag() {
    let (listener, address) = reserved();
    let pki = pki(
        Some(&format!("http://operator:secret@{address}/ca.crl")),
        None,
    );
    let server = serve_on(
        listener,
        address,
        vec![("/ca.crl", Reply::Body(good_crl(&pki)))],
    );
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki), &pki.root_der);

    let report = verify_online(&dossier_path, &store, &[]);
    assert!(
        server.seen().is_empty(),
        "nothing may be contacted: {:?}",
        server.seen()
    );
    let checks = checks(&report);
    assert!(
        checks
            .iter()
            .any(|check| check.starts_with("online_fetch_failed=info")
                && check.contains("destination_refused")
                && check.contains("userinfo")),
        "{checks:?}"
    );
}

// ---------------------------------------------------------------------------
// One request per question
// ---------------------------------------------------------------------------

/// Two certificates, one responder. An OCSP response answers about **one**
/// certificate, so these are two questions; deduplicating by URL asked the
/// first and silently never asked the second, which left it uncovered for a
/// reason nothing in the report named.
#[test]
fn two_certificates_behind_one_responder_ask_two_distinct_questions() {
    let (listener, address) = reserved();
    let url = format!("http://{address}/ocsp");
    let pki = chained_pki(&url);
    let server = serve_on(
        listener,
        address,
        vec![("/ocsp", Reply::Body(chained_ocsp(&pki)))],
    );
    let directory = scratch();
    let (dossier_path, store) = write_all(directory.path(), &chained_dossier(&pki), &pki.root_der);

    let report = verify_online(&dossier_path, &store, &[]);
    assert_eq!(
        end_entity_source(&report).as_deref(),
        Some("online_ocsp"),
        "{:?}",
        checks(&report)
    );

    let asked: Vec<Vec<u8>> = server
        .seen()
        .into_iter()
        .filter(|request| request.method == "POST" && request.path == "/ocsp")
        .map(|request| request.body)
        .collect();
    assert_eq!(
        asked.len(),
        2,
        "one request per certificate, not per URL: {:?}",
        server.seen()
    );
    assert!(asked.iter().all(|body| !body.is_empty()));
    // Different certIDs, which is what makes them different questions: the
    // request is DER whose only varying part is the certID.
    assert_ne!(
        asked[0], asked[1],
        "the two requests ask about the same certificate"
    );
}

// ---------------------------------------------------------------------------
// One size limit, everywhere, said out loud
// ---------------------------------------------------------------------------

/// The store loader used to refuse an oversized file with three words. The
/// size and the limit are both public facts about material the operator put
/// there themselves, and without them "too large" is not something anyone can
/// act on.
#[test]
fn an_oversized_revocation_store_file_names_its_size_and_the_limit() {
    let directory = scratch();
    let pki = pki(None, None);
    let (dossier_path, store) = write_all(directory.path(), &dossier(&pki), &pki.root_der);
    let revocation = directory.path().join("revocation");
    std::fs::create_dir_all(revocation.join("crls")).expect("the crls directory is created");
    let oversized = 17 * 1024 * 1024_usize;
    std::fs::write(revocation.join("crls/huge.crl"), vec![0_u8; oversized])
        .expect("the oversized file is written");

    let output = run(&[
        "verify",
        dossier_path.to_str().expect("a UTF-8 path"),
        "--json",
        "--at",
        AT,
        "--trust-store",
        store.to_str().expect("a UTF-8 path"),
        "--revocation-store",
        revocation.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(output.status.code(), Some(3));
    let report = json(&output);
    let message = report["errors"][0]["message"]
        .as_str()
        .expect("the error names a message")
        .to_owned();
    assert!(message.contains(&oversized.to_string()), "{message}");
    assert!(
        message.contains(&(16 * 1024 * 1024_usize).to_string()),
        "{message}"
    );
    assert_eq!(
        report["errors"][0]["code"].as_str(),
        Some("revocation_store_invalid")
    );
}

// ---------------------------------------------------------------------------
// A three-level PKI, for the one-responder-two-certificates case
// ---------------------------------------------------------------------------

struct ChainedPki {
    root_der: Vec<u8>,
    intermediate_der: Vec<u8>,
    signer_der: Vec<u8>,
    signer_key: TestKey,
}

/// A root, an intermediate CA, and a signer, where the intermediate and the
/// signer both name the same OCSP responder — which is what a real CA
/// hierarchy looks like, and which is exactly the shape that produced one
/// request where two were owed.
fn chained_pki(ocsp_url: &str) -> ChainedPki {
    let root_key = rsa_key(keys::ROOT_RSA2048);
    let intermediate_key = rsa_key(keys::INTERMEDIATE_RSA2048);
    let signer_key = rsa_key(keys::SIGNER_RSA2048);
    let root = self_signed(
        &CertSpec::ca("openSzigno Test Root", BasicConstraints::Unconstrained),
        &root_key,
    );
    let mut intermediate_spec = CertSpec::ca(
        "openSzigno Test Issuing CA",
        BasicConstraints::Constrained(0),
    );
    intermediate_spec
        .custom_extensions
        .push(authority_info_access_extension(ocsp_url));
    let intermediate = issued_by(&intermediate_spec, &intermediate_key, &root, &root_key);
    let mut signer_spec = CertSpec::signer("openSzigno Test Signer");
    signer_spec
        .custom_extensions
        .push(authority_info_access_extension(ocsp_url));
    let signer = issued_by(&signer_spec, &signer_key, &intermediate, &intermediate_key);
    ChainedPki {
        root_der: root.der,
        intermediate_der: intermediate.der,
        signer_der: signer.der,
        signer_key,
    }
}

fn chained_dossier(pki: &ChainedPki) -> String {
    let mut signature =
        document_signature(vec![pki.signer_der.clone(), pki.intermediate_der.clone()]);
    signature.signing_certificate = Some(SigningCertificateSpec::v1(pki.signer_der.clone()));
    let spec = DossierSpec {
        document_signature: Some(signature),
        ..Default::default()
    };
    build(&spec, &[("doc", &pki.signer_key)])
}

/// The one answer the responder gives, which is about the signer. The
/// intermediate's own question goes unanswered, and that is fine: what is
/// under test is that it was *asked*.
fn chained_ocsp(pki: &ChainedPki) -> Vec<u8> {
    let mut spec = OcspSpec::new(
        pki.intermediate_der.clone(),
        pki.signer_der.clone(),
        rsa_key(keys::INTERMEDIATE_RSA2048),
    );
    spec.include_responder_certificate = false;
    spec.status = OcspStatus::Good;
    build_ocsp(&spec)
}
