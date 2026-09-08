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
//! - **Only for certificates the run actually trusts the shape of.** A URL is
//!   contacted only for a certificate that sits on a candidate path ending at
//!   a configured trust anchor. Checking that an embedded issuer signed an
//!   embedded certificate proves nothing — an attacker who writes the dossier
//!   writes both — so without this rule any file handed to the tool could
//!   choose the tool's next network destination. With no anchors configured
//!   nothing is fetched at all, and the report says so.
//! - **Only URLs the certificates themselves publish.** A CRL distribution
//!   point and an AIA OCSP responder are fields a CA wrote into a certificate
//!   that a trust anchor signed. No URL is ever taken from the dossier's XML,
//!   from a redirect to another host, or from the environment.
//! - **A destination policy on top of that.** `http` and `https` only, no
//!   userinfo, and no loopback, private, link-local or unique-local address —
//!   by literal *or* by what the name resolves to — unless
//!   `--online-allow-private` is given. See [`destination`].
//! - **Strict, small bounds.** Five seconds to connect, twenty in total, at
//!   most three redirects and never to another host,
//!   [`MAX_REVOCATION_ITEM_BYTES`] for a CRL and 64 KiB for an OCSP response.
//!   A fetch that exceeds any of them is a failure with a named class, never a
//!   hang.
//! - **No proxy from the environment.** `HTTP_PROXY` and friends are ignored
//!   unless `--online-proxy` names one explicitly. A verifier that silently
//!   routed its revocation traffic through whatever the shell happened to set
//!   would be handing an attacker who controls that variable a way to feed it
//!   chosen bytes — bytes that would still have to verify, but that is not a
//!   reason to accept the ambiguity.
//! - **Fetching only fills gaps.** Nothing is fetched for a certificate the
//!   caller's own material already answers for, which is decided by asking the
//!   verifier's own offline code, not by a cheaper approximation of it.
//! - **One request per question, not per URL.** CRLs are deduplicated by URL,
//!   because a CRL is a list and one copy answers for everyone on it. OCSP is
//!   deduplicated by responder *and* `certID`, because a response answers
//!   about one certificate: two certificates behind one responder are two
//!   questions, and asking only the first left the second uncovered.
//! - **A failure is `revocation_status_unknown`, never a crash.** Every
//!   failure is reported with the URL and a failure class — `timeout`,
//!   `http status`, `too large`, `redirect`, `invalid`, `transport`,
//!   `destination_refused` — so a caller can tell "the CA's server was down"
//!   apart from "the CA served something that is not a CRL".

mod destination;

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use openszigno_verify::certs::{CertificateSource, ParsedCertificate, dedup};
use openszigno_verify::revocation::{
    RevocationData, RevocationItemKind, classify, is_covered, ocsp_cert_id, ocsp_request,
};
use openszigno_verify::{Check, CheckCode, MAX_REVOCATION_ITEM_BYTES, VerifyLimits};

use destination::{Refusal, host_of, permitted, resolve, scheme_of};

/// How long to wait for the connection itself.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one whole fetch may take, connection included.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest CRL that will be read. Real national CA CRLs run to megabytes.
/// It is the verifier's own limit, so that nothing this fetches can be too
/// large for the code that has to judge it.
const MAX_CRL_BYTES: u64 = MAX_REVOCATION_ITEM_BYTES as u64;
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
/// The largest number of issuer-signature checks the trust reachability scan
/// will perform, so that a bag of name-matching certificates cannot turn the
/// scan itself into the expensive part of a run.
const MAX_ANCHOR_LINK_CHECKS: usize = 256;
/// How far the reachability scan will walk away from an anchor. It matches the
/// verifier's own `max_chain_length`.
const MAX_ANCHOR_DEPTH: usize = 8;

/// What one run fetched, and what it could not.
#[derive(Debug, Default)]
pub struct Fetched {
    pub crls: Vec<Vec<u8>>,
    /// DER OCSP responses, in the order they were fetched.
    pub ocsp: Vec<Vec<u8>>,
    /// The hex SHA-256 of the DER `CertID` each entry of `ocsp` was asked
    /// about, in the same order. Kept alongside rather than inside so that
    /// `ocsp` stays the `&[Vec<u8>]` the verifier's own coverage code takes;
    /// the only reader is [`write_cache`], which names a cached response by
    /// the question it answers.
    ocsp_cert_ids: Vec<String>,
    /// One `online_fetch_failed` per failure, naming the URL and the failure
    /// class.
    pub checks: Vec<Check>,
}

impl Fetched {
    fn push_ocsp(&mut self, der: Vec<u8>, cert_id: String) {
        self.ocsp.push(der);
        self.ocsp_cert_ids.push(cert_id);
    }
}

/// Why one fetch did not produce a usable artefact.
///
/// The class is part of the report because the remedies differ: a timeout is
/// somebody else's outage, a `404` is a stale URL in an old certificate, and
/// "not a CRL" is a server answering with an HTML error page — which is what a
/// captive portal or a misconfigured proxy looks like from here. A refused
/// destination is different again: nothing was contacted at all, and the
/// reason names the rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureClass {
    Timeout,
    HttpStatus(u16),
    TooLarge(u64),
    Redirect,
    Invalid,
    Transport,
    DestinationRefused(&'static str),
}

impl FailureClass {
    fn describe(self) -> String {
        match self {
            Self::Timeout => "timeout".to_owned(),
            Self::HttpStatus(status) => format!("http status {status}"),
            Self::TooLarge(limit) => format!("too large: over the {limit}-byte cap"),
            Self::Redirect => "redirect".to_owned(),
            Self::Invalid => "invalid".to_owned(),
            Self::Transport => "transport".to_owned(),
            Self::DestinationRefused(reason) => format!("destination_refused: {reason}"),
        }
    }
}

/// The transport, configured once so that every fetch in a run is bounded the
/// same way.
pub struct Fetcher {
    agent: ureq::Agent,
    /// `--online-allow-private`: whether loopback and private destinations may
    /// be contacted. It exists for two real cases — an internal CA that
    /// publishes on the operator's own network, and this project's own test
    /// suite, which serves a synthetic PKI from `127.0.0.1` — and it is opt-in
    /// because the default has to be safe for a dossier nobody wrote.
    allow_private: bool,
}

impl Fetcher {
    /// Build the agent. `proxy` is the `--online-proxy` value; without one, no
    /// proxy is used at all — in particular, none from the environment.
    pub fn new(proxy: Option<&str>, allow_private: bool) -> Result<Self, String> {
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
            allow_private,
        })
    }

    /// Fetch whatever the caller's own material does not already cover.
    ///
    /// `certificates` is every certificate the dossier and the trust material
    /// carry; the issuer of each is looked up among them, because a
    /// certificate whose issuer is not to hand cannot have a CRL or an OCSP
    /// response checked against it anyway.
    ///
    /// `anchors` is what makes any of it happen. A certificate is fetched for
    /// only when a candidate path from it reaches one of them, so a dossier
    /// that chains to nothing the operator configured produces no traffic
    /// whatsoever — not even a DNS lookup.
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
        if anchors.is_empty() {
            // Nothing to reach, so nothing to fetch. The report says why,
            // through `revocation_policy` and every
            // `revocation_status_unknown` message.
            return fetched;
        }
        let trusted = anchored_certificates(&parsed, &anchors);
        let mut crls_tried: BTreeSet<String> = BTreeSet::new();
        let mut ocsp_tried: BTreeSet<(String, String)> = BTreeSet::new();
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
            // The gate. Everything below this line contacts the network on
            // behalf of this certificate, so this certificate has to be one
            // the caller's own trust material vouches for.
            if !trusted.contains(&subject.der) {
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
            if let (Some(request), Some(cert_id)) =
                (ocsp_request(subject, issuer), ocsp_cert_id(subject, issuer))
            {
                let cert_id = hex(&sha256(&cert_id));
                for url in subject
                    .ocsp_responder_urls()
                    .into_iter()
                    .take(MAX_URLS_PER_CERTIFICATE)
                {
                    // Two certificates from one CA name one responder and are
                    // two different questions. Deduplicating by URL alone
                    // asked the first question and dropped the second.
                    if !ocsp_tried.insert((url.clone(), cert_id.clone())) {
                        continue;
                    }
                    match self.fetch(&url, Some(&request), MAX_OCSP_BYTES) {
                        Ok(bytes) => match classify(&bytes) {
                            Ok((RevocationItemKind::Ocsp, der)) => {
                                fetched.push_ocsp(der, cert_id.clone());
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
                // A CRL is a list: one copy answers for every certificate on
                // it, so the URL is the whole question and fetching it twice
                // would be waste.
                if !crls_tried.insert(url.clone()) {
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
        let mut current = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            // The destination policy is applied to every URL actually
            // contacted, the redirect targets included: a redirect stays on
            // the host the certificate named, but "the same name" and "the
            // same address" are not the same statement.
            permitted(&current, self.allow_private).map_err(|refusal| match refusal {
                Refusal::Refused(reason) => FailureClass::DestinationRefused(reason),
                Refusal::Unresolvable => FailureClass::Transport,
            })?;
            let response = match body {
                // The body is passed as a slice, which `ureq` sends with a
                // known length: an explicit `Content-Length` and no chunked
                // transfer encoding. That matters beyond tidiness — a
                // responder that does not implement chunked requests answers a
                // chunked `POST` with a `400`, and a request whose end the
                // peer has to infer is the shape that behaves differently on
                // different platforms. RFC 6960 Appendix A.1 describes exactly
                // this: a `POST` of the DER request with its content type.
                Some(bytes) => self
                    .agent
                    .post(&current)
                    .header("content-type", "application/ocsp-request")
                    .header("accept", "application/ocsp-response")
                    .header("content-length", bytes.len().to_string())
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
                    ureq::Error::BodyExceedsLimit(_) => FailureClass::TooLarge(limit),
                    other => classify_transport(other),
                })?;
            return Ok(bytes);
        }
        Err(FailureClass::Redirect)
    }
}

/// Every certificate that sits on a candidate path ending at a configured
/// trust anchor.
///
/// This is deliberately *not* the verifier's `validate_path`: that answers
/// about one leaf, for one purpose, and would refuse a timestamp authority's
/// certificate under the signing purpose and vice versa. The question here is
/// narrower and is only ever used to decide whether a URL may be contacted: is
/// there a chain of real issuer signatures from this certificate up to
/// something the operator configured? Whether the path is *acceptable* stays
/// the verifier's answer to give, offline, afterwards.
///
/// The walk goes downwards from the anchors so that each issuer signature is
/// checked at most once per candidate, and it is bounded twice over: by depth,
/// and by the total number of signature checks.
fn anchored_certificates(
    parsed: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
) -> BTreeSet<Vec<u8>> {
    let mut trusted: BTreeSet<Vec<u8>> = anchors.iter().map(|anchor| anchor.der.clone()).collect();
    let mut frontier: Vec<&ParsedCertificate> = anchors.iter().collect();
    let mut checks = 0usize;
    for _ in 0..MAX_ANCHOR_DEPTH {
        let mut next: Vec<&ParsedCertificate> = Vec::new();
        for issuer in &frontier {
            for candidate in parsed {
                if trusted.contains(&candidate.der) {
                    continue;
                }
                if candidate.issuer_der() != issuer.subject_name_der() {
                    continue;
                }
                checks += 1;
                if checks > MAX_ANCHOR_LINK_CHECKS {
                    return trusted;
                }
                if openszigno_verify::certs::verify_issued_by(candidate, issuer) {
                    trusted.insert(candidate.der.clone());
                    next.push(candidate);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    trusted
}

fn classify_transport(error: ureq::Error) -> FailureClass {
    match error {
        ureq::Error::Timeout(_) => FailureClass::Timeout,
        ureq::Error::BodyExceedsLimit(limit) => FailureClass::TooLarge(limit),
        ureq::Error::TooManyRedirects | ureq::Error::RedirectFailed => FailureClass::Redirect,
        ureq::Error::StatusCode(status) => FailureClass::HttpStatus(status),
        _ => FailureClass::Transport,
    }
}

/// The check a failed fetch contributes.
///
/// It is **`info`**, and the reason is worth being precise about, because the
/// obvious alternative is wrong in a way that took a corpus run to notice.
///
/// A failed fetch is a fact about the network, not about any certificate. It
/// cannot make a verdict better: whether a certificate ended up covered is
/// decided by the verifier, from the data it actually holds, and a fetch that
/// did not happen leaves it exactly as uncovered as it was — which the chain's
/// own `revocation_status_unknown` reports, and which blocks. So the blocking
/// is already done, in the right place, by the check that knows *which* chain
/// is short of data.
///
/// Emitting a second, blocking check per failed URL at the **dossier** level
/// adds nothing there and does real harm: a fetch attempted for a certificate
/// no verdict depended on — an over-fetch, or the TSA of a container
/// `es:TimeStamp`, whose chain is deliberately not allowed to decide anything
/// — would drag a dossier whose every signature is `valid` down to
/// `indeterminate`. That is exactly backwards: it makes carrying more evidence
/// cost a dossier its verdict.
///
/// The URL is public CA material — it came out of a certificate — so naming it
/// is safe and is the one thing that makes the failure actionable.
fn failure(url: &str, class: FailureClass) -> Check {
    Check::info(
        CheckCode::OnlineFetchFailed,
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

/// Write fetched artefacts into a `--revocation-store` shaped directory, so
/// that a later run with `--revocation-store DIR` and no `--online` reproduces
/// this run's answer without touching the network.
///
/// A CRL is named by the SHA-256 of its own bytes: it is a list, it stands on
/// its own, and two runs that fetch it twice write one file. An OCSP response
/// is named by the `certID` it answers about **and** by its own bytes, because
/// a responder's answer is only meaningful next to the question — two
/// certificates behind one responder produce two files whose names say which
/// is which, and a re-run that fetches a fresher answer for the same question
/// adds a file rather than being mistaken for the old one.
///
/// Nothing is ever deleted: the cache only grows, and an operator who wants it
/// pruned knows more about their retention policy than this tool does.
pub fn write_cache(directory: &Path, fetched: &Fetched) -> Result<(), String> {
    let ocsp_names: Vec<String> = fetched
        .ocsp
        .iter()
        .zip(&fetched.ocsp_cert_ids)
        .map(|(item, cert_id)| format!("{cert_id}-{}", hex(&sha256(item))))
        .collect();
    let crl_names: Vec<String> = fetched.crls.iter().map(|item| hex(&sha256(item))).collect();

    for (subdirectory, items, names) in [
        ("crls", &fetched.crls, &crl_names),
        ("ocsp", &fetched.ocsp, &ocsp_names),
    ] {
        if items.is_empty() {
            continue;
        }
        let path = directory.join(subdirectory);
        fs::create_dir_all(&path)
            .map_err(|_| "the online cache directory could not be created".to_owned())?;
        for (item, name) in items.iter().zip(names) {
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

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes).into()
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
}
