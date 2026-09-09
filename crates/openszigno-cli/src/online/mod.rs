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

use destination::{
    REFUSED_PLAINTEXT_CREDENTIALS, REFUSED_REDIRECT_DOWNGRADE, Refusal, host_of, loopback_only,
    permitted, resolve, scheme_of,
};
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

/// What one HTTP answer was, when the caller has to read a non-`200` body.
///
/// The revocation path has no use for this — a CRL that came back as a `404`
/// is simply a failed fetch — but a CSC service reports a refusal *in* the
/// body, as a JSON `error` string next to the status, and a refusal a user
/// cannot read is a refusal they cannot act on.
pub struct Answer {
    pub status: u16,
    pub body: Vec<u8>,
}

/// A request body and the media types that describe it.
///
/// RFC 6960 Appendix A.1 for OCSP and RFC 3161 section 3.4 for timestamping
/// both describe exactly this: a `POST` of a DER request under its own content
/// type, with a known length.
#[derive(Clone, Copy)]
pub struct Post<'a> {
    media_type: &'a str,
    accept: &'a str,
    bytes: &'a [u8],
    /// The value of the `Authorization` header, when the peer needs one. It is
    /// a bearer token for a CSC service and `None` for everything else, and it
    /// exists here rather than at a call site because a header is the *only*
    /// place this tool ever puts one: never in a URL, never in a body, never in
    /// a log line and never in the JSON envelope.
    authorization: Option<&'a str>,
    /// Whether the *body* is credential material, as the caller sees it. A CSC
    /// `credentials/authorize` body carries the PIN and the one-time password
    /// that authorise a signature, which are secrets the header rule knows
    /// nothing about, so the caller says so here and the transport applies the
    /// same rule to both.
    sensitive: bool,
}

impl Post<'_> {
    /// Whether this request carries anything that must not cross a plaintext
    /// hop: a bearer token in the header, or a body the caller flagged.
    fn carries_credentials(&self) -> bool {
        self.authorization.is_some() || self.sensitive
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

    /// One bounded `POST` of a DER request body, for a caller outside this
    /// module.
    ///
    /// It is the same transport, the same destination policy and the same
    /// bounds a revocation fetch goes through: the only thing that differs is
    /// the media type, and a second HTTP client in this binary would be a
    /// second place for those rules to drift out of agreement. The failure is
    /// returned as the class's own words, so `sign` can name why nothing was
    /// contacted.
    pub fn post_der(
        &self,
        url: &str,
        media_type: &str,
        accept: &str,
        body: &[u8],
        limit: u64,
    ) -> Result<Vec<u8>, String> {
        self.fetch(
            url,
            Some(Post {
                media_type,
                accept,
                bytes: body,
                authorization: None,
                sensitive: false,
            }),
            limit,
        )
        .map_err(FailureClass::describe)
    }

    /// One bounded `POST` of a JSON request body under a bearer token, which
    /// is what a Cloud Signature Consortium operation is.
    ///
    /// It differs from [`Fetcher::post_der`] in exactly two ways, and both are
    /// the CSC protocol's doing. The token travels in the `Authorization`
    /// header and nowhere else. And the status is returned rather than turned
    /// into a failure, because a CSC service answers a refusal with a JSON
    /// body naming it and the caller has to read that body to say why the run
    /// stopped. Everything else — the destination policy, the pinned
    /// addresses, the timeouts, the redirect rules and the size cap — is the
    /// same transport `verify --online` goes through. `sensitive` says whether
    /// the body is credential material as well, which a CSC
    /// `credentials/authorize` body is: it carries the PIN and the one-time
    /// password. Either way a request that carries credentials has to be
    /// `https` on every hop, and is refused before a socket is opened
    /// otherwise.
    pub fn post_json(
        &self,
        url: &str,
        bearer: &str,
        body: &str,
        limit: u64,
        sensitive: bool,
    ) -> Result<Answer, String> {
        let authorization = format!("Bearer {bearer}");
        self.request(
            url,
            Some(Post {
                media_type: "application/json",
                accept: "application/json",
                bytes: body.as_bytes(),
                authorization: Some(&authorization),
                sensitive,
            }),
            limit,
            true,
        )
        .map(|(status, body)| Answer { status, body })
        .map_err(FailureClass::describe)
    }

    /// One bounded fetch, following at most [`MAX_REDIRECTS`] redirects and
    /// never leaving the host the certificate named.
    fn fetch(
        &self,
        url: &str,
        body: Option<Post<'_>>,
        limit: u64,
    ) -> Result<Vec<u8>, FailureClass> {
        self.request(url, body, limit, false)
            .map(|(_, bytes)| bytes)
    }

    /// The fetch itself. `any_status` says whether a non-`200` answer is a
    /// failure class or a body the caller wants to read.
    ///
    /// Every hop is vetted before it is contacted, and the order is the point:
    /// the destination policy, then the credential-scheme rule, then the
    /// address pin, and only then a request built with its `Authorization`
    /// header. A target that failed any of those checks is never sent the
    /// header, because the header is not attached until the target has passed
    /// all of them.
    fn request(
        &self,
        url: &str,
        body: Option<Post<'_>>,
        limit: u64,
        any_status: bool,
    ) -> Result<(u16, Vec<u8>), FailureClass> {
        let origin = host_of(url).ok_or(FailureClass::Invalid)?;
        let credentials = body.is_some_and(|post| post.carries_credentials());
        let mut current = url.to_owned();
        for _ in 0..=MAX_REDIRECTS {
            // A request that carries credentials needs TLS on *this* hop, the
            // first one included. A revocation fetch does not: a CRL is public
            // and is signature-checked either way. The one exception is a
            // loopback service under `--online-allow-private`, which is what
            // this project's own test servers are and where the bytes never
            // leave the machine — and even that is granted on the *vetted*
            // addresses below, not on the host text. Without the flag the
            // refusal comes first, so a plaintext credential URL is not even
            // looked up.
            let insecure_credentials = credentials && scheme_of(&current) != Some("https");
            if insecure_credentials && !self.allow_private {
                return Err(FailureClass::DestinationRefused(
                    REFUSED_PLAINTEXT_CREDENTIALS,
                ));
            }
            // The destination policy is applied to every URL actually
            // contacted, the redirect targets included: a redirect stays on
            // the host the certificate named, but "the same name" and "the
            // same address" are not the same statement.
            let vetted =
                permitted(&current, self.allow_private).map_err(|refusal| match refusal {
                    Refusal::Refused(reason) => FailureClass::DestinationRefused(reason),
                    Refusal::Unresolvable => FailureClass::Transport,
                })?;
            if insecure_credentials && !loopback_only(&vetted) {
                return Err(FailureClass::DestinationRefused(
                    REFUSED_PLAINTEXT_CREDENTIALS,
                ));
            }
            // The approval is made binding here: these addresses, and only
            // these, are what the agent may open a socket to for this hop. The
            // URL is passed on unchanged, so the `Host` header and the TLS
            // host-name verification still use the name the certificate
            // published.
            self.resolver.pin(&vetted);
            let mut response = self
                .send(&current, body.as_ref())
                .map_err(classify_transport)?;
            let status = response.status().as_u16();
            if (300..400).contains(&status) {
                current = self.next_hop(&current, &response, &origin)?;
                continue;
            }
            if status != 200 && !any_status {
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
            return Ok((status, bytes));
        }
        Err(FailureClass::Redirect)
    }

    /// Issue one hop that has already passed every check, and attach the
    /// `Authorization` header here, at the last possible moment.
    ///
    /// This is the only place in the binary that puts a bearer token on the
    /// wire, and it is reached only from the vetted branch of [`Fetcher::request`].
    fn send(
        &self,
        url: &str,
        body: Option<&Post<'_>>,
    ) -> Result<ureq::http::Response<ureq::Body>, ureq::Error> {
        // The body is passed as a slice, which `ureq` sends with a known
        // length: an explicit `Content-Length` and no chunked transfer
        // encoding. That matters beyond tidiness — a responder that does not
        // implement chunked requests answers a chunked `POST` with a `400`,
        // and a request whose end the peer has to infer is the shape that
        // behaves differently on different platforms. RFC 6960 Appendix A.1
        // describes exactly this: a `POST` of the DER request with its content
        // type.
        let Some(post) = body else {
            return self.agent.get(url).call();
        };
        let mut request = self
            .agent
            .post(url)
            .header("content-type", post.media_type)
            .header("accept", post.accept)
            .header("content-length", post.bytes.len().to_string());
        if let Some(value) = post.authorization {
            request = request.header("authorization", value);
        }
        request.send(post.bytes)
    }

    /// Where a `3xx` answer points, once it has passed the redirect rules.
    ///
    /// A redirect is the peer's choice, so it is bounded twice over: it may
    /// not leave the host the certificate named, and it may not move an
    /// `https` exchange onto `http`. The downgrade refusal happens here,
    /// before the loop comes round and opens a socket, so nothing is ever
    /// contacted at the downgraded target.
    fn next_hop(
        &self,
        current: &str,
        response: &ureq::http::Response<ureq::Body>,
        origin: &str,
    ) -> Result<String, FailureClass> {
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .ok_or(FailureClass::Redirect)?;
        redirect_target(current, location, origin)
    }
}

/// The redirect rules themselves, as one decision over three strings.
///
/// It is a free function, and pure, because these are the rules a redirect has
/// to satisfy *before* the loop comes round: nothing here has a socket, so
/// there is no shape of this code in which a refused target is contacted
/// first.
fn redirect_target(current: &str, location: &str, origin: &str) -> Result<String, FailureClass> {
    let next = resolve(current, location).ok_or(FailureClass::Redirect)?;
    // A redirect across hosts is refused rather than followed: the authority
    // for this URL is the certificate, and the certificate named one host.
    if host_of(&next).as_deref() != Some(origin) {
        return Err(FailureClass::Redirect);
    }
    let next_scheme = scheme_of(&next);
    if !matches!(next_scheme, Some("http" | "https")) {
        return Err(FailureClass::Redirect);
    }
    // The downgrade. Same host, same certificate, and yet the next request
    // would go out in the clear, carrying whatever the first one carried: a
    // bearer token, a PIN, a one-time password. Refused for every request
    // kind, because a plaintext hop is not something a peer gets to choose for
    // this tool even when there is nothing secret on this particular one.
    if scheme_of(current) == Some("https") && next_scheme == Some("http") {
        return Err(FailureClass::DestinationRefused(REFUSED_REDIRECT_DOWNGRADE));
    }
    Ok(next)
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
#[path = "mod_tests.rs"]
mod tests;
