//! `--online`: fetching revocation data the caller does not already have.
//!
//! The verifier is network-free by construction: `openszigno-verify` opens no
//! socket, and revocation data reaches it only through the injected
//! `RevocationSource`. That property is the reason this module exists here and
//! not there. Everything below is transport — obtaining bytes — and every byte
//! obtained is then handed to exactly the same offline code path that judges a
//! CRL a human copied into `--revocation-store`.
//!
//! # The policy, and why each part of it is there
//!
//! - **Only URLs the certificates themselves publish.** A CRL distribution
//!   point and an AIA OCSP responder are fields a CA wrote into a certificate
//!   that a trust anchor signed. No URL is ever taken from the dossier's XML,
//!   from a redirect to another host, or from the environment.
//! - **The scheme is what the certificate said.** `http` and `https` are both
//!   fetched and neither is rewritten. Upgrading `http` to `https` would be a
//!   guess about a host's configuration, and downgrading is obviously worse.
//!   Confidentiality is not the point: the artefacts are public documents and
//!   every one of them is signature-checked before it is believed, so TLS adds
//!   nothing that the verification does not already provide.
//! - **Strict, small bounds.** Five seconds to connect, twenty in total, at
//!   most three redirects and never to another host, 16 MiB for a CRL and
//!   64 KiB for an OCSP response. A fetch that exceeds any of them is a
//!   failure with a named class, never a hang.
//! - **No proxy from the environment.** `HTTP_PROXY` and friends are ignored
//!   unless `--online-proxy` names one explicitly. A verifier that silently
//!   routed its revocation traffic through whatever the shell happened to set
//!   would be handing an attacker who controls that variable a way to feed it
//!   chosen bytes — bytes that would still have to verify, but that is not a
//!   reason to accept the ambiguity.
//! - **Fetching only fills gaps.** Nothing is fetched for a certificate the
//!   caller's own material already answers for, which is decided by asking the
//!   verifier's own offline code, not by a cheaper approximation of it.
//! - **A failure is `revocation_status_unknown`, never a crash.** Every
//!   failure is reported with the URL and a failure class — `timeout`,
//!   `http status`, `too large`, `redirect`, `invalid`, `transport` — so a
//!   caller can tell "the CA's server was down" apart from "the CA served
//!   something that is not a CRL".

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use openszigno_verify::certs::{CertificateSource, ParsedCertificate, dedup};
use openszigno_verify::revocation::{
    RevocationData, RevocationItemKind, classify, is_covered, ocsp_request,
};
use openszigno_verify::{Check, CheckCode, VerifyLimits};

/// How long to wait for the connection itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one whole fetch may take, connection included.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest CRL that will be read. Real national CA CRLs run to megabytes.
const MAX_CRL_BYTES: u64 = 16 * 1024 * 1024;
/// The largest OCSP response that will be read. A response about one
/// certificate is a few kilobytes; anything near this cap is already wrong.
const MAX_OCSP_BYTES: u64 = 64 * 1024;
/// How many redirects one fetch may follow, none of them to another host.
const MAX_REDIRECTS: usize = 3;
/// The largest number of certificates one run will fetch for, and the largest
/// number of URLs tried per certificate. Both bound how much traffic opening
/// one dossier can generate.
const MAX_CERTIFICATES: usize = 32;
const MAX_URLS_PER_CERTIFICATE: usize = 4;

/// What one run fetched, and what it could not.
#[derive(Debug, Default)]
pub struct Fetched {
    pub crls: Vec<Vec<u8>>,
    pub ocsp: Vec<Vec<u8>>,
    /// One `revocation_status_unknown` per failure, naming the URL and the
    /// failure class.
    pub checks: Vec<Check>,
}

/// Why one fetch did not produce a usable artefact.
///
/// The class is part of the report because the remedies differ: a timeout is
/// somebody else's outage, a `404` is a stale URL in an old certificate, and
/// "not a CRL" is a server answering with an HTML error page — which is what a
/// captive portal or a misconfigured proxy looks like from here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureClass {
    Timeout,
    HttpStatus(u16),
    TooLarge,
    Redirect,
    Invalid,
    Transport,
}

impl FailureClass {
    fn describe(self) -> String {
        match self {
            Self::Timeout => "timeout".to_owned(),
            Self::HttpStatus(status) => format!("http status {status}"),
            Self::TooLarge => "too large".to_owned(),
            Self::Redirect => "redirect".to_owned(),
            Self::Invalid => "invalid".to_owned(),
            Self::Transport => "transport".to_owned(),
        }
    }
}

/// The transport, configured once so that every fetch in a run is bounded the
/// same way.
pub struct Fetcher {
    agent: ureq::Agent,
}

impl Fetcher {
    /// Build the agent. `proxy` is the `--online-proxy` value; without one, no
    /// proxy is used at all — in particular, none from the environment.
    pub fn new(proxy: Option<&str>) -> Result<Self, String> {
        let proxy = match proxy {
            Some(value) => Some(
                ureq::Proxy::new(value)
                    .map_err(|_| "the --online-proxy value is not a usable proxy URL".to_owned())?,
            ),
            None => None,
        };
        let config = ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT_TIMEOUT))
            .timeout_global(Some(TOTAL_TIMEOUT))
            // Redirects are followed by hand below, so that a redirect to
            // another host can be refused rather than merely counted.
            .max_redirects(0)
            .proxy(proxy)
            .http_status_as_error(false)
            .user_agent("openszigno")
            .build();
        Ok(Self {
            agent: config.new_agent(),
        })
    }

    /// Fetch whatever the caller's own material does not already cover.
    ///
    /// `certificates` is every certificate the dossier and the trust material
    /// carry; the issuer of each is looked up among them, because a
    /// certificate whose issuer is not to hand cannot have a CRL or an OCSP
    /// response checked against it anyway.
    pub fn fill_gaps(
        &self,
        certificates: &[Vec<u8>],
        anchors: &[Vec<u8>],
        data: &RevocationData<'_>,
        time: i64,
        limits: &VerifyLimits,
    ) -> Fetched {
        let parsed = dedup(
            certificates
                .iter()
                .filter_map(|der| ParsedCertificate::from_der(der, CertificateSource::KeyInfo))
                .collect(),
        );
        // The trust anchors, which are what the RFC 6960 section 2.2 trusted
        // responder model rests on. Coverage has to be asked with them, or a
        // response a run *will* accept would look uncovered here and provoke a
        // fetch nobody needed.
        let anchors: Vec<ParsedCertificate> = anchors
            .iter()
            .filter_map(|der| ParsedCertificate::from_der(der, CertificateSource::TrustStore))
            .collect();
        let mut fetched = Fetched::default();
        let mut tried: BTreeSet<String> = BTreeSet::new();
        let mut budget = MAX_CERTIFICATES;

        for subject in &parsed {
            if budget == 0 {
                break;
            }
            // A self-signed certificate is a root: its revocation is not a
            // question the PKI it roots can answer, and the verifier never
            // asks, so fetching for it would be traffic for nothing.
            if subject.is_self_signed() {
                continue;
            }
            let Some(issuer) = parsed.iter().find(|candidate| {
                candidate.subject_name_der() == subject.issuer_der()
                    && openszigno_verify::certs::verify_issued_by(subject, candidate)
            }) else {
                continue;
            };
            if is_covered(subject, issuer, &parsed, &anchors, data, time, limits) {
                continue;
            }
            budget -= 1;

            // OCSP first: it answers about this certificate, where a CRL is a
            // list that may run to megabytes.
            if let Some(request) = ocsp_request(subject, issuer) {
                for url in subject
                    .ocsp_responder_urls()
                    .into_iter()
                    .take(MAX_URLS_PER_CERTIFICATE)
                {
                    if !tried.insert(url.clone()) {
                        continue;
                    }
                    match self.fetch(&url, Some(&request), MAX_OCSP_BYTES) {
                        Ok(bytes) => match classify(&bytes) {
                            Ok((RevocationItemKind::Ocsp, der)) => {
                                fetched.ocsp.push(der);
                                break;
                            }
                            _ => fetched.checks.push(failure(&url, FailureClass::Invalid)),
                        },
                        Err(class) => fetched.checks.push(failure(&url, class)),
                    }
                }
            }
            // Obtaining a response is not the same as being answered by one.
            // A well-formed response this build cannot authorise, one about
            // another certificate, or a stale one leaves the certificate
            // exactly as uncovered as it was — so the question is put to the
            // verifier's own code again, with what was just fetched, before
            // the CRL is skipped. Stopping at "the server replied" is what
            // made a central responder look like a dead end.
            if is_covered(
                subject,
                issuer,
                &parsed,
                &anchors,
                &probe(data, &fetched),
                time,
                limits,
            ) {
                continue;
            }
            for url in subject
                .crl_distribution_urls()
                .into_iter()
                .take(MAX_URLS_PER_CERTIFICATE)
            {
                if !tried.insert(url.clone()) {
                    continue;
                }
                match self.fetch(&url, None, MAX_CRL_BYTES) {
                    Ok(bytes) => match classify(&bytes) {
                        Ok((RevocationItemKind::Crl, der)) => {
                            fetched.crls.push(der);
                            break;
                        }
                        _ => fetched.checks.push(failure(&url, FailureClass::Invalid)),
                    },
                    Err(class) => fetched.checks.push(failure(&url, class)),
                }
            }
        }
        fetched
    }

    /// One bounded fetch, following at most [`MAX_REDIRECTS`] redirects and
    /// never leaving the host the certificate named.
    fn fetch(&self, url: &str, body: Option<&[u8]>, limit: u64) -> Result<Vec<u8>, FailureClass> {
        let origin = host_of(url).ok_or(FailureClass::Invalid)?;
        if !matches!(scheme_of(url), Some("http" | "https")) {
            // The scheme is whatever the CA published; anything that is not
            // HTTP is not something this build speaks, and it is certainly not
            // something to rewrite into one that it does.
            return Err(FailureClass::Invalid);
        }
        let mut current = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            let response = match body {
                Some(bytes) => self
                    .agent
                    .post(&current)
                    .header("content-type", "application/ocsp-request")
                    .header("accept", "application/ocsp-response")
                    .send(bytes),
                None => self.agent.get(&current).call(),
            };
            let mut response = response.map_err(classify_transport)?;
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                let location = response
                    .headers()
                    .get("location")
                    .and_then(|value| value.to_str().ok())
                    .ok_or(FailureClass::Redirect)?;
                let next = resolve(&current, location).ok_or(FailureClass::Redirect)?;
                // A redirect across hosts is refused rather than followed: the
                // authority for this URL is the certificate, and the
                // certificate named one host.
                if host_of(&next).as_deref() != Some(origin.as_str()) {
                    return Err(FailureClass::Redirect);
                }
                if !matches!(scheme_of(&next), Some("http" | "https")) {
                    return Err(FailureClass::Redirect);
                }
                current = next;
                continue;
            }
            if status != 200 {
                return Err(FailureClass::HttpStatus(status));
            }
            // `limit` is enforced by the reader, so a server that lies about
            // `Content-Length`, or omits it, cannot make this allocate more.
            let bytes = response
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map_err(|error| match error {
                    ureq::Error::BodyExceedsLimit(_) => FailureClass::TooLarge,
                    other => classify_transport(other),
                })?;
            return Ok(bytes);
        }
        Err(FailureClass::Redirect)
    }
}

fn classify_transport(error: ureq::Error) -> FailureClass {
    match error {
        ureq::Error::Timeout(_) => FailureClass::Timeout,
        ureq::Error::BodyExceedsLimit(_) => FailureClass::TooLarge,
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => FailureClass::Redirect,
        ureq::Error::StatusCode(status) => FailureClass::HttpStatus(status),
        _ => FailureClass::Transport,
    }
}

/// The check a failed fetch contributes.
///
/// It is `unknown`, which blocks: a fetch that did not happen leaves the
/// certificate exactly as uncovered as it was, and `--online` must never be
/// able to turn an unanswered question into a passed one. The URL is public
/// CA material — it came out of a certificate — so naming it is safe and is
/// the one thing that makes the failure actionable.
fn failure(url: &str, class: FailureClass) -> Check {
    Check::unknown(
        CheckCode::RevocationStatusUnknown,
        format!(
            "fetching revocation data from {} failed ({})",
            sanitize_url(url),
            class.describe()
        ),
    )
}

/// `data` widened with everything fetched so far, so coverage can be asked
/// again without re-reading anything from disk.
fn probe<'a>(data: &RevocationData<'a>, fetched: &'a Fetched) -> RevocationData<'a> {
    RevocationData {
        online_crls: &fetched.crls,
        online_ocsp: &fetched.ocsp,
        ..*data
    }
}

/// Bound and strip a URL before it reaches a message, exactly as every other
/// value taken from input is bounded.
fn sanitize_url(url: &str) -> String {
    url.chars()
        .filter(|character| !character.is_control())
        .take(200)
        .collect()
}

fn scheme_of(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    if rest.is_empty() {
        return None;
    }
    Some(scheme)
}

/// The authority of a URL, lower-cased, which is what "the same host" means
/// here. The port is part of it: a redirect to another port on the same name
/// is another endpoint.
fn host_of(url: &str) -> Option<String> {
    let (_, rest) = url.split_once("://")?;
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    Some(authority.to_ascii_lowercase())
}

/// Resolve a `Location` header against the URL it came from.
///
/// Only the two forms a real CA server uses are handled — an absolute URL and
/// a root-relative path — because anything else would be guesswork, and a
/// redirect this function refuses to resolve is reported rather than followed.
fn resolve(base: &str, location: &str) -> Option<String> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if location.contains("://") {
        return Some(location.to_owned());
    }
    let (scheme, rest) = base.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    if let Some(path) = location.strip_prefix('/') {
        return Some(format!("{scheme}://{authority}/{path}"));
    }
    let directory = rest
        .split(['?', '#'])
        .next()
        .and_then(|path| path.rfind('/').map(|index| &path[..index]))
        .unwrap_or(authority);
    Some(format!("{scheme}://{directory}/{location}"))
}

/// Write fetched artefacts into a `--revocation-store` shaped directory, so
/// that a later run with `--revocation-store DIR` and no `--online` reproduces
/// this run's answer without touching the network.
///
/// Files are named by the SHA-256 of their own bytes, so re-running is
/// idempotent and two artefacts never collide. Nothing is ever deleted: the
/// cache only grows, and an operator who wants it pruned knows more about
/// their retention policy than this tool does.
pub fn write_cache(directory: &Path, fetched: &Fetched) -> Result<(), String> {
    use sha2::{Digest as _, Sha256};

    for (subdirectory, items) in [("crls", &fetched.crls), ("ocsp", &fetched.ocsp)] {
        if items.is_empty() {
            continue;
        }
        let path = directory.join(subdirectory);
        fs::create_dir_all(&path)
            .map_err(|_| "the online cache directory could not be created".to_owned())?;
        for item in items {
            let name = hex(&Sha256::digest(item));
            let file = path.join(format!("{name}.der"));
            if file.exists() {
                continue;
            }
            fs::write(&file, item)
                .map_err(|_| "an online cache file could not be written".to_owned())?;
        }
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_redirect_to_another_host_is_not_resolved_as_the_same_host() {
        let base = "http://crl.example/ca.crl";
        let next = resolve(base, "http://evil.example/ca.crl").expect("resolves");
        assert_ne!(host_of(&next), host_of(base));
    }

    #[test]
    fn a_root_relative_redirect_stays_on_the_same_host() {
        let base = "http://crl.example/pki/ca.crl";
        let next = resolve(base, "/other.crl").expect("resolves");
        assert_eq!(next, "http://crl.example/other.crl");
        assert_eq!(host_of(&next), host_of(base));
    }

    #[test]
    fn a_relative_redirect_is_resolved_against_the_directory() {
        let next = resolve("http://crl.example/pki/ca.crl", "new.crl").expect("resolves");
        assert_eq!(next, "http://crl.example/pki/new.crl");
    }

    #[test]
    fn a_different_port_is_a_different_host() {
        assert_ne!(
            host_of("http://crl.example/a"),
            host_of("http://crl.example:8080/a")
        );
    }

    #[test]
    fn only_http_schemes_are_recognised() {
        assert_eq!(scheme_of("ldap://directory.example/cn=ca"), Some("ldap"));
        assert_eq!(scheme_of("not a url"), None);
    }

    #[test]
    fn a_failure_names_the_url_and_its_class() {
        let check = failure("http://crl.example/ca.crl", FailureClass::Timeout);
        assert_eq!(check.code, CheckCode::RevocationStatusUnknown);
        assert!(check.message.contains("http://crl.example/ca.crl"));
        assert!(check.message.contains("timeout"));
        let check = failure("http://crl.example/ca.crl", FailureClass::HttpStatus(404));
        assert!(check.message.contains("http status 404"));
    }

    #[test]
    fn a_control_character_never_reaches_a_message() {
        let check = failure("http://crl.example/\u{7}a.crl", FailureClass::Invalid);
        assert!(!check.message.contains('\u{7}'));
    }
}
