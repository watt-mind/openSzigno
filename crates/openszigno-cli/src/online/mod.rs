//! `--online`: fetching revocation data the caller does not already have.
//!
//! The verifier is network-free by construction: `openszigno-verify` opens no
//! socket, and revocation data reaches it only through the injected
//! `RevocationSource`. That property is the reason this module exists here and
//! not there. Everything below is transport — obtaining bytes — and every byte
//! obtained is then handed to exactly the same offline code path that judges a
//! CRL a human copied into `--revocation-store`.
//!
//! # The module map
//!
//! | Module | What it decides |
//! | :--- | :--- |
//! | this one | The transport and its bounds: the agent, one fetch with its redirect loop, the failure classes, and `--online-cache` writing. |
//! | [`gaps`] | What to fetch and for whom: the trust gate, coverage at each path's own validation time, and the URL order. |
//! | [`destination`] | Where a socket may be opened to, by scheme, userinfo and address range. |
//! | [`pinned`] | Making that approval binding, by resolving to the addresses the policy approved and nothing else. |
//!
//! The policy below is one policy; it is written here, in full, because no one
//! part of it is safe on its own.
//!
//! # The policy, and why each part of it is there
//!
//! - **Only for certificates the run actually validated a path for.** A URL is
//!   contacted only for a certificate on a certification path the verifier
//!   built to a **configured trust anchor**, for a signature or a timestamp it
//!   was evaluating: the set
//!   `VerifyReport::validated_path_certificates_at` returns from an
//!   offline-style pass. Checking that an embedded issuer signed
//!   an embedded certificate proves nothing — whoever writes the dossier
//!   writes both — so without this rule any file handed to the tool could
//!   choose the tool's next network destination, and a certificate parked
//!   somewhere else in the XML could generate traffic of its own. With no
//!   anchors configured nothing is fetched at all, and the report says so.
//! - **Only URLs the certificates themselves publish.** A CRL distribution
//!   point and an AIA OCSP responder are fields a CA wrote into a certificate
//!   that a trust anchor signed. No URL is ever taken from the dossier's XML,
//!   from a redirect to another host, or from the environment.
//! - **A destination policy on top of that, bound to the socket.** `http` and
//!   `https` only, no userinfo, and no loopback, private, link-local or
//!   unique-local address — by literal *or* by what the name resolves to —
//!   unless `--online-allow-private` is given. See [`destination`]. The
//!   addresses the policy approved are then the only ones the request may be
//!   sent to: they are pinned for `ureq` through [`pinned`], for the first URL
//!   and for every redirect target, so the check and the connection cannot
//!   disagree. The name is untouched, so TLS still verifies the certificate
//!   against the host the URL named.
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
//! - **Fetching only fills gaps, at the time that matters.** Nothing is
//!   fetched for a certificate the caller's own material already answers for,
//!   which is decided by asking the verifier's own offline code, not by a
//!   cheaper approximation of it. The question is asked at the validation time
//!   each path was evaluated at, because coverage is a statement about an
//!   instant: a CRL that expired years ago still covers a signer path a
//!   verified timestamp pins to an instant inside its window.
//! - **In bounded rounds.** Evidence fetched for one path can create another,
//!   so the caller alternates verification and fetching a bounded number of
//!   times and hands each round only the certificates that round made
//!   eligible. See `commands::verify`.
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
mod gaps;
mod pinned;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use openszigno_verify::{Check, CheckCode, MAX_REVOCATION_ITEM_BYTES};

use destination::{Refusal, host_of, permitted, resolve, scheme_of};
pub use gaps::{EligibleCertificate, Fetched, GapRequest};
use pinned::{PinnedResolver, SharedResolver};

use crate::extract::output_dir::{OpenError, OutputDir};

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
/// one dossier can generate. The certificate budget is the caller's, because
/// a run fetches over several rounds and the cap is on the run.
pub const MAX_CERTIFICATES: usize = 32;
const MAX_URLS_PER_CERTIFICATE: usize = 4;

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
    /// The resolver the agent connects through. Every hop writes the addresses
    /// the destination policy just approved into it, so the socket goes where
    /// the policy looked and nowhere else.
    resolver: Arc<PinnedResolver>,
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
        let proxied = proxy.is_some();
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
        // The agent is built from parts for one reason: the resolver. The
        // default one looks a name up when it connects, which would be a second
        // lookup that need not agree with the one the destination policy made,
        // and a hostile zone only has to disagree once. This one answers from
        // what the policy approved and refuses everything else. See [`pinned`].
        let resolver = Arc::new(PinnedResolver::new(proxied));
        let agent = ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::new(),
            SharedResolver(Arc::clone(&resolver)),
        );
        Ok(Self {
            agent,
            resolver,
            allow_private,
        })
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
            let vetted =
                permitted(&current, self.allow_private).map_err(|refusal| match refusal {
                    Refusal::Refused(reason) => FailureClass::DestinationRefused(reason),
                    Refusal::Unresolvable => FailureClass::Transport,
                })?;
            // The approval is made binding here: these addresses, and only
            // these, are what the agent may open a socket to for this hop. The
            // URL is passed on unchanged, so the `Host` header and the TLS
            // host-name verification still use the name the certificate
            // published.
            self.resolver.pin(&vetted);
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
/// # How it is written, and why not with `fs::write`
///
/// The cache directory is a path an operator gives on the command line, and
/// the tool may be running unattended next to something that can write there.
/// Path-based writing gets all three of the following wrong:
///
/// - a component of the path, or the final file, may be a **symlink**, and
///   `create_dir_all` and `fs::write` follow both — a dangling symlink named
///   after a content hash turns "write the cache" into "write wherever that
///   points";
/// - checking `Path::exists` and then writing is a **time-of-check /
///   time-of-use** gap, and `fs::write` **truncates** whatever it finds, so
///   losing the race means destroying a file;
/// - two runs caching the same artefact at the same time must both succeed.
///
/// So the cache is written the way an extraction is: the directory is opened
/// once with `O_DIRECTORY | O_NOFOLLOW`, walked one component at a time so no
/// component is resolved through a link, and every file is created relative to
/// that descriptor with `O_CREAT | O_EXCL | O_NOFOLLOW`. **Nothing is ever
/// truncated or replaced.** A name that already holds exactly these bytes is
/// the idempotent case and is left alone — which is also what a concurrent
/// writer looks like from here. A name that holds something else, or that
/// cannot be read back because it is a symlink, is reported as one
/// `online_fetch_failed` with the class `cache_collision` and the run
/// continues: a cache is an optimisation, and a strange file in it is not a
/// reason to fail a verification that has already been done.
///
/// Nothing is ever deleted: the cache only grows, and an operator who wants it
/// pruned knows more about their retention policy than this tool does.
pub fn write_cache(directory: &Path, fetched: &Fetched) -> Result<Vec<Check>, String> {
    let ocsp_names: Vec<String> = fetched
        .ocsp
        .iter()
        .zip(&fetched.ocsp_cert_ids)
        .map(|(item, cert_id)| format!("{cert_id}-{}", hex(&sha256(item))))
        .collect();
    let crl_names: Vec<String> = fetched.crls.iter().map(|item| hex(&sha256(item))).collect();
    if fetched.crls.is_empty() && fetched.ocsp.is_empty() {
        return Ok(Vec::new());
    }

    let root = OutputDir::open(directory).map_err(|error| match error {
        OpenError::Unsafe(reason) => format!("the online cache path is not usable: {reason}"),
        OpenError::Io(_) => "the online cache directory could not be created".to_owned(),
    })?;
    let mut notes = Vec::new();
    for (subdirectory, items, names) in [
        ("crls", &fetched.crls, &crl_names),
        ("ocsp", &fetched.ocsp, &ocsp_names),
    ] {
        if items.is_empty() {
            continue;
        }
        let target =
            root.open_or_create_subdirectory(subdirectory)
                .map_err(|error| match error {
                    OpenError::Unsafe(reason) => {
                        format!("the online cache path is not usable: {reason}")
                    }
                    OpenError::Io(_) => {
                        "the online cache directory could not be created".to_owned()
                    }
                })?;
        for (item, name) in items.iter().zip(names) {
            let name = format!("{name}.der");
            match target.create_new_file(&name) {
                Ok(mut file) => {
                    use std::io::Write as _;

                    file.write_all(item)
                        .map_err(|_| "an online cache file could not be written".to_owned())?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // Either this artefact is already cached — the ordinary,
                    // idempotent case, and what a concurrent writer looks like
                    // — or the name holds something else. Only the bytes can
                    // tell the two apart, and they are compared without
                    // following a link.
                    if target
                        .read_file(&name)
                        .is_ok_and(|existing| existing == *item)
                    {
                        continue;
                    }
                    notes.push(collision());
                }
                Err(_) => {
                    return Err("an online cache file could not be written".to_owned());
                }
            }
        }
    }
    Ok(notes)
}

/// The check a refused cache write contributes.
///
/// `info`, like every other `online_fetch_failed`: the artefact was fetched
/// and is in this run's answer, and failing to write a copy of it changes no
/// verdict. No path is named, because a cache path may be private.
fn collision() -> Check {
    Check::info(
        CheckCode::OnlineFetchFailed,
        "caching a fetched revocation artefact failed (cache_collision: the cache already holds a different file, or a symlink, under that name; nothing was overwritten)",
    )
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
