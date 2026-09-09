//! Certification-path building: the candidate pool, the bounded depth-first
//! search that completes a chain at a configured trust anchor, and stage D's
//! entry point.
//!
//! Only trust the caller configured can end a path — a `--trust-store` file or
//! a trusted-list service digital identity. A certificate found inside a
//! dossier is a candidate like any other and can never make itself trusted,
//! self-signed or not.
//!
//! Following ETSI TS 119 615, a trusted list's service digital identity ends a
//! path **where the list speaks**, which in a real national list is the
//! *issuing* CA rather than the root above it: the Hungarian list records
//! NetLock's qualified issuing CAs as CA/QC services and the root that signed
//! them only as a QTST service. A path that had to climb past the issuing CA
//! to a self-signed root would then be judged by an entry that says nothing
//! about issuing qualified certificates. See [`AnchorStatus::terminates`].
//!
//! A trusted-list identity may end a path only at a time its service was
//! *granted*: a withdrawn, supervision-ceased or deprecated CA/QC or TSA/QTST
//! service is a service the list has stopped vouching for, and honouring it
//! would make the status timeline decorative. See [`AnchorStatus`].

use crate::codes::{Check, CheckCode, CheckStatus};
use crate::policy::VerifyLimits;
use crate::trust::{ServiceIdentity, TrustAnchor, TrustServiceIdentity, UnixTime};
use crate::trustlist::{ServiceRecord, ServiceType};

use super::{ChainEntry, ParsedCertificate, PathPurpose, check_path, common_name, dedup};

/// The largest number of candidate expansions one path search may perform.
///
/// The per-path and per-length bounds are not enough on their own: a bag of
/// certificates whose subject and issuer names all match, and which never
/// reaches an anchor, produces no completed paths at all while the search
/// explores exponentially many prefixes. This bounds the work itself.
const MAX_PATH_EXPANSIONS: usize = 256;

/// What the caller knows about each configured trust anchor beyond its bytes.
///
/// A trusted-list anchor is the digital identity of a service whose status
/// timeline says *when* the list vouched for it, so a path may end there only
/// at a time that service was granted for the use the path is being built for:
/// a CA/QC service for a signing or OCSP-signing path, a TSA/QTST service for a
/// timestamping one. A trust-store anchor carries no such timeline — the
/// operator put the file in the directory, and that is the whole statement — so
/// it is unaffected.
///
/// The service identities are carried alongside the anchors because they also
/// decide *where* a path may end: see [`AnchorStatus::terminates`].
///
/// [`AnchorStatus::none`] records no provenance at all, which is what a caller
/// with only a trust store has: every anchor is then usable at every time,
/// exactly as before.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorStatus<'a> {
    anchors: &'a [(Vec<u8>, &'a TrustAnchor)],
    services: &'a [TrustServiceIdentity],
}

impl<'a> AnchorStatus<'a> {
    /// The provenance of each configured anchor, keyed by its DER. The same
    /// DER may appear more than once, because one certificate can be both a
    /// trust-store file and a trusted-list service identity.
    pub const fn new(anchors: &'a [(Vec<u8>, &'a TrustAnchor)]) -> Self {
        Self {
            anchors,
            services: &[],
        }
    }

    /// Add the trusted-list service digital identities, which is what lets a
    /// path end at a listed issuing CA rather than only at a self-signed root.
    #[must_use]
    pub const fn with_services(self, services: &'a [TrustServiceIdentity]) -> Self {
        Self {
            anchors: self.anchors,
            services,
        }
    }

    /// No provenance is known, so nothing is withheld.
    pub const fn none() -> Self {
        Self {
            anchors: &[],
            services: &[],
        }
    }

    /// Whether any trusted-list service supplies a certificate at all.
    ///
    /// A list that names its services only by `X509SKI` or `X509SubjectName`
    /// supplies no key and so can end no path; it says `false` here, and a run
    /// with no store anchors either is still "no trust was configured".
    pub fn has_listed(&self) -> bool {
        self.services
            .iter()
            .any(|service| matches!(service.identity, ServiceIdentity::Certificate(_)))
    }

    /// Whether a path may *terminate* at this certificate because a trusted
    /// list records it as the digital identity of a service.
    ///
    /// This is the ETSI TS 119 615 model and the reason it matters is
    /// concrete: in a real national list the CA/QC identities are the issuing
    /// CAs, which are intermediates, and the root above them may be listed
    /// under some other service kind, or not at all. Climbing past the issuing
    /// CA to reach a self-signed anchor means judging the path by an entry
    /// that was never about issuing certificates. So a listed certificate is a
    /// trust anchor for any path that reaches it, self-signed or not — subject
    /// to [`may_anchor`](Self::may_anchor), exactly as a self-signed listed
    /// anchor is.
    ///
    /// Whether the *nearest* listed certificate is preferred is the search's
    /// business, not this predicate's; see [`validate_path_at`].
    pub fn terminates(&self, der: &[u8]) -> bool {
        self.services.iter().any(|service| {
            matches!(&service.identity, ServiceIdentity::Certificate(bytes) if bytes.as_slice() == der)
        })
    }

    /// Every statement the caller's trust material makes about `der`.
    ///
    /// `None` stands for a trust-store anchor, whose statement is
    /// unconditional; `Some(record)` is one trusted-list service. One
    /// certificate can be several of both at once.
    fn records(&self, der: &[u8]) -> Vec<Option<&'a ServiceRecord>> {
        let mut records: Vec<Option<&'a ServiceRecord>> = self
            .anchors
            .iter()
            .filter(|(bytes, _)| bytes.as_slice() == der)
            .map(|(_, anchor)| anchor.service.as_ref())
            .collect();
        records.extend(
            self.services
                .iter()
                .filter(|service| {
                    matches!(&service.identity, ServiceIdentity::Certificate(bytes) if bytes.as_slice() == der)
                })
                .map(|service| Some(&service.service)),
        );
        records
    }

    /// Whether this anchor may end a path built for `purpose` at `time`.
    ///
    /// An anchor with no recorded provenance, and any anchor a trust store
    /// supplied, may always end one: the caller trusted the bytes directly,
    /// and when the same certificate arrives both ways that unconditional
    /// statement is the one that stands — the operator asked for that
    /// certificate by name.
    ///
    /// For a trusted-list anchor the list has to still be vouching for it at
    /// `time`, and the rule is applied where the list actually speaks:
    ///
    /// 1. a service of the kind this path needs — CA/QC for a signing or
    ///    OCSP-signing path, TSA/QTST for a timestamping one — that was
    ///    granted at `time` lets the path end here;
    /// 2. a service of that kind that was **not** granted then refuses it,
    ///    which is the whole point: `withdrawn`, `supervisionceased` and the
    ///    `deprecated*` family stop a path the moment they take effect;
    /// 3. when the list records this certificate only under some *other* kind
    ///    of service, it has said nothing about this use, so the anchor is
    ///    treated as it would be if it came from a trust store — provided some
    ///    service it does record was granted at `time`. A national list that
    ///    names a root under its CA/QC services and nowhere else still vouches
    ///    for that root when a timestamp authority under it is checked; what it
    ///    does not do is vouch for a certificate every one of whose services
    ///    has been withdrawn.
    pub fn may_anchor(&self, der: &[u8], time: UnixTime, purpose: PathPurpose) -> bool {
        let wanted = wanted(purpose);
        let records = self.records(der);
        // Nothing is known about this certificate, so nothing is withheld:
        // this is what `AnchorStatus::none` means, and it keeps a caller that
        // has only a trust store behaving exactly as it did before provenance
        // was recorded at all.
        if records.is_empty() {
            return true;
        }
        let mut speaks = false;
        let mut vouches = false;
        for record in records {
            let Some(record) = record else {
                return true;
            };
            if record
                .entries
                .iter()
                .any(|entry| entry.service_type == wanted)
            {
                speaks = true;
            }
            if record.granted_at(time, wanted) {
                return true;
            }
            if record.granted_at(time, ServiceType::CaQc)
                || record.granted_at(time, ServiceType::TsaQtst)
            {
                vouches = true;
            }
        }
        !speaks && vouches
    }

    /// The sentence explaining why this anchor could not end a path.
    fn refusal(&self, der: &[u8], time: UnixTime, purpose: PathPurpose) -> String {
        let wanted = wanted(purpose);
        let records = || self.records(der).into_iter().flatten().cloned();
        // Name the service that actually decided, which is one of the kind the
        // path needed whenever the list records one.
        let record = records()
            .find(|record| {
                record
                    .entries
                    .iter()
                    .any(|entry| entry.service_type == wanted)
            })
            .or_else(|| records().next());
        let named = record
            .as_ref()
            .and_then(|record| record.service_name.clone())
            .map(|name| format!(" ({name})"))
            .unwrap_or_default();
        let status = record
            .as_ref()
            .and_then(|record| record.status_name_at(time).map(str::to_owned))
            .map(|status| format!(", recorded as {status} then"))
            .unwrap_or_else(|| ", which has no status in force at that instant".to_owned());
        format!(
            "a path was built and validated, but it ends at a trusted-list anchor whose service{named} the list does not record as {} granted at the validation time{status}; a service the list has stopped vouching for cannot anchor a path, which is a gap in the trust that was configured rather than a finding against the signature",
            wanted_name(purpose)
        )
    }
}

/// Which kind of trusted-list service has to be granted for a path built for
/// this purpose.
const fn wanted(purpose: PathPurpose) -> ServiceType {
    match purpose {
        PathPurpose::Signing | PathPurpose::OcspSigning => ServiceType::CaQc,
        PathPurpose::TimeStamping => ServiceType::TsaQtst,
    }
}

/// Why a pool entry may end a path, and whether the search should look past it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Termination {
    /// An ordinary untrusted candidate: it can only ever be a link.
    None,
    /// A trusted-list service digital identity. It ends a path — and the
    /// search still climbs past it, because a listed certificate whose service
    /// was not granted at the validation time must not shadow a store anchor
    /// or a listed CA above it.
    Listed,
    /// A configured trust anchor. Nothing above it is looked at: it is the
    /// top of the path by construction.
    Anchor,
}

const fn wanted_name(purpose: PathPurpose) -> &'static str {
    match purpose {
        PathPurpose::Signing | PathPurpose::OcspSigning => {
            "a CA issuing qualified certificates (CA/QC)"
        }
        PathPurpose::TimeStamping => "a qualified timestamping authority (TSA/QTST)",
    }
}

/// The result of building and validating a certification path.
pub struct PathOutcome {
    pub code: CheckCode,
    pub message: String,
    pub chain: Vec<ChainEntry>,
    /// The certificates the reported chain is made of, leaf first and anchor
    /// last, so that stage E can ask about each link. Empty unless a path was
    /// actually built and validated — which includes the one built to an
    /// anchor whose trusted-list service was not granted, since that path is
    /// sound and only its anchor's standing is missing.
    pub path: Vec<ParsedCertificate>,
    /// Non-blocking observations about the path the caller must still report:
    /// checks that are `unknown` rather than `failed`, so they cap the verdict
    /// without condemning the signature.
    pub advisories: Vec<Check>,
}

/// Build a path from `leaf` to one of `anchors` and validate it.
///
/// `candidates` are untrusted certificates offered for path building: the ones
/// in `ds:KeyInfo`, the ones encapsulated in the signature's XAdES
/// `CertificateValues`, and any non-self-signed file in the trust store.
/// **Only `anchors` can end a path.** A self-signed certificate found inside a
/// dossier is a candidate like any other and can never make itself trusted.
///
/// With no anchors configured the answer is `cert_path_unknown`, not
/// `cert_path_untrusted`: the tool does not know, and saying "invalid" would be
/// as wrong as saying "valid".
///
/// This entry point knows nothing about where the anchors came from, so every
/// one of them may end a path at any time. A caller holding trusted-list
/// anchors must use [`validate_path_at`] instead, so that a service the list
/// has stopped vouching for cannot anchor a path.
pub fn validate_path(
    leaf: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    time: UnixTime,
    limits: &VerifyLimits,
    purpose: PathPurpose,
) -> PathOutcome {
    validate_path_at(
        leaf,
        candidates,
        anchors,
        AnchorStatus::none(),
        time,
        limits,
        purpose,
    )
}

/// [`validate_path`], told what the caller knows about each anchor.
///
/// `status` decides two things.
///
/// **Where a path may end.** Besides `anchors`, any certificate a trusted list
/// records as a service digital identity terminates a path, self-signed or
/// not: that is where the list actually speaks, and in a real national list it
/// is the issuing CA rather than the root. The nearest such certificate along
/// a chain is preferred, so a root listed only as a QTST service cannot
/// override the granted CA/QC entry of the issuing CA below it — the search
/// records the shorter path first and still climbs past the listed
/// intermediate, so that a listed certificate whose service was not granted
/// then falls through to whatever store anchor or listed CA sits above it.
///
/// **Whether it may end there.** A trusted-list anchor whose service was not
/// granted at `time` yields [`CheckCode::TrustListServiceNotGranted`] rather
/// than [`CheckCode::CertPathOk`], and the search carries on to the other
/// candidate paths first, because another anchor may still be entitled to end
/// one.
///
/// The refusal is not evidence against the signature. It says the trust the
/// caller configured does not reach this certificate at this instant, which is
/// the same kind of statement `cert_path_unknown` makes, so its callers report
/// it as `unknown` and the verdict is capped at `indeterminate` rather than
/// pushed to `invalid`.
pub fn validate_path_at(
    leaf: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    status: AnchorStatus<'_>,
    time: UnixTime,
    limits: &VerifyLimits,
    purpose: PathPurpose,
) -> PathOutcome {
    let leaf_only = vec![leaf.chain_entry(false)];
    if anchors.is_empty() && !status.has_listed() {
        return PathOutcome {
            code: CheckCode::CertPathUnknown,
            message: "no trust anchors were configured, so the chain could not be checked"
                .to_owned(),
            chain: leaf_only,
            path: Vec::new(),
            advisories: Vec::new(),
        };
    }

    let mut pool: Vec<(&ParsedCertificate, Termination)> = Vec::new();
    for certificate in candidates.iter().take(limits.max_certificates) {
        // The leaf is never its own issuer candidate, and a certificate the
        // trust store already anchors is used in that role only: otherwise a
        // dossier's copy of an anchor would appear twice in the same path.
        let is_anchor = anchors.iter().any(|anchor| anchor.der == certificate.der);
        if certificate.der != leaf.der && !is_anchor {
            // A candidate a trusted list names is also a place a path may
            // end, while staying an ordinary link for the paths that climb
            // past it.
            let termination = if status.terminates(&certificate.der) {
                Termination::Listed
            } else {
                Termination::None
            };
            pool.push((certificate, termination));
        }
    }
    for certificate in anchors.iter().take(limits.max_certificates) {
        pool.push((certificate, Termination::Anchor));
    }
    let considered = pool.len();

    let mut paths: Vec<Vec<usize>> = Vec::new();
    let mut chain = vec![usize::MAX];
    let mut expansions = 0usize;
    // `usize::MAX` marks the leaf, which is not in the pool.
    let exhausted = build_paths(leaf, &pool, &mut chain, &mut paths, limits, &mut expansions);

    if paths.is_empty() {
        if exhausted {
            return PathOutcome {
                code: CheckCode::CertPathSearchExhausted,
                message: format!(
                    "path building gave up after {MAX_PATH_EXPANSIONS} expansions over {considered} candidate certificates"
                ),
                chain: leaf_only,
                path: Vec::new(),
                advisories: Vec::new(),
            };
        }
        // CA names are public information a caller needs in order to fix a
        // trust store, so the issuer that could not be chained is named. No
        // end-entity detail beyond the subject CN already reported is added.
        let dangling = dangling_issuer(leaf, &pool, limits);
        let named = dangling
            .map(|name| format!("; the highest certificate reached names issuer CN {name}"))
            .unwrap_or_default();
        return PathOutcome {
            code: CheckCode::CertPathUntrusted,
            message: format!(
                "no path from the signing certificate to a configured trust anchor was found after considering {considered} candidate certificates{named}"
            ),
            chain: leaf_only,
            path: Vec::new(),
            advisories: Vec::new(),
        };
    }

    let mut first_failure: Option<PathOutcome> = None;
    // A path that validated but ended at a service the list no longer vouches
    // for. It is kept aside rather than returned, so that another path to
    // another anchor still gets its chance; it is preferred over
    // `first_failure` when nothing better turns up, because a path that
    // validated says more than one that did not.
    let mut not_granted: Option<PathOutcome> = None;
    for path in paths {
        let certificates: Vec<&ParsedCertificate> = std::iter::once(leaf)
            .chain(path.iter().skip(1).map(|index| pool[*index].0))
            .collect();
        let entries: Vec<ChainEntry> = certificates
            .iter()
            .enumerate()
            .map(|(position, certificate)| {
                certificate.chain_entry(position + 1 == certificates.len())
            })
            .collect();
        match check_path(&certificates, time, purpose) {
            Ok(advisories) => {
                let anchor = certificates.last().expect("a completed path has an anchor");
                if !status.may_anchor(&anchor.der, time, purpose) {
                    if not_granted.is_none() {
                        not_granted = Some(PathOutcome {
                            code: CheckCode::TrustListServiceNotGranted,
                            message: status.refusal(&anchor.der, time, purpose),
                            chain: entries,
                            // The path really was built and validated, and is
                            // reported in full: what is missing is the list's
                            // word that this anchor could be relied on then.
                            path: certificates.iter().map(|entry| (*entry).clone()).collect(),
                            advisories,
                        });
                    }
                    continue;
                }
                return PathOutcome {
                    code: CheckCode::CertPathOk,
                    message: format!(
                        "path of length {} built to a configured trust anchor",
                        certificates.len()
                    ),
                    chain: entries,
                    path: certificates.iter().map(|entry| (*entry).clone()).collect(),
                    advisories,
                };
            }
            Err((code, message)) => {
                if first_failure.is_none() {
                    first_failure = Some(PathOutcome {
                        code,
                        message,
                        chain: entries,
                        path: Vec::new(),
                        advisories: Vec::new(),
                    });
                }
            }
        }
    }
    not_granted.or(first_failure).unwrap_or(PathOutcome {
        code: CheckCode::CertPathUntrusted,
        message: "no acceptable path to a configured trust anchor was found".to_owned(),
        chain: leaf_only,
        path: Vec::new(),
        advisories: Vec::new(),
    })
}

/// Depth-first path building, bounded by chain length, candidate count, and —
/// crucially — the total number of expansions.
///
/// Returns whether the expansion budget ran out, which is a distinct outcome
/// from "no path exists": the tool stopped looking rather than concluded.
///
/// A completed path is recorded **before** the search climbs any further, so
/// the nearest place a chain may end comes first in `paths` and is the one
/// [`validate_path_at`] prefers.
fn build_paths(
    leaf: &ParsedCertificate,
    pool: &[(&ParsedCertificate, Termination)],
    chain: &mut Vec<usize>,
    paths: &mut Vec<Vec<usize>>,
    limits: &VerifyLimits,
    expansions: &mut usize,
) -> bool {
    if paths.len() >= limits.max_paths {
        return false;
    }
    let current = chain
        .last()
        .and_then(|index| (*index != usize::MAX).then(|| pool[*index].0))
        .unwrap_or(leaf);
    // Completion is checked *before* the length bound, so a chain of exactly
    // `max_chain_length` certificates that ends at an anchor is a path rather
    // than one the search refused to look at: a limit of 8 admits 8, not 7.
    let termination = if chain.len() > 1 {
        pool[*chain.last().expect("chain is not empty")].1
    } else {
        Termination::None
    };
    if termination != Termination::None {
        paths.push(chain.clone());
        // A configured anchor is the top of the path by construction, and
        // nothing above it is looked at. A trusted-list identity that is not
        // one is a link as well as a terminus: the search climbs past it, so
        // that a service the list was not vouching for at the validation time
        // still falls through to whatever anchor sits above.
        if termination == Termination::Anchor || paths.len() >= limits.max_paths {
            return false;
        }
    }
    if chain.len() >= limits.max_chain_length {
        return false;
    }
    let issuer_der = current.issuer_der();
    let mut exhausted = false;
    for (index, (candidate, _)) in pool.iter().enumerate() {
        if chain.contains(&index) {
            continue;
        }
        if candidate.subject_der() != issuer_der {
            continue;
        }
        *expansions += 1;
        if *expansions > MAX_PATH_EXPANSIONS {
            return true;
        }
        chain.push(index);
        exhausted |= build_paths(leaf, pool, chain, paths, limits, expansions);
        chain.pop();
        if exhausted || paths.len() >= limits.max_paths {
            return exhausted;
        }
    }
    exhausted
}

/// Follow one greedy chain upwards and report the issuer CN of the highest
/// certificate reached, which is the name a caller needs to add to the store.
fn dangling_issuer(
    leaf: &ParsedCertificate,
    pool: &[(&ParsedCertificate, Termination)],
    limits: &VerifyLimits,
) -> Option<String> {
    let mut current = leaf;
    let mut seen: Vec<Vec<u8>> = vec![leaf.der.clone()];
    while seen.len() < limits.max_chain_length {
        let issuer_der = current.issuer_der();
        let next = pool
            .iter()
            .map(|(certificate, _)| *certificate)
            .find(|candidate| {
                candidate.subject_der() == issuer_der && !seen.contains(&candidate.der)
            });
        match next {
            Some(next) => {
                seen.push(next.der.clone());
                current = next;
            }
            None => break,
        }
    }
    common_name(&current.certificate.tbs_certificate.issuer)
}

/// The validated path of one signing certificate, as stage D leaves it for
/// stage E.
pub(crate) struct SignerPath {
    /// The validated path, end-entity first and trust anchor last. Empty when
    /// no path was built.
    pub(crate) path: Vec<ParsedCertificate>,
    /// The chain as it will be reported, still to be told about revocation.
    pub(crate) chain: Vec<ChainEntry>,
    /// The untrusted certificates the path was built from, which stage E
    /// offers as CRL signers and OCSP responders.
    pub(crate) candidates: Vec<ParsedCertificate>,
}

/// Stage D: build a path from the signing certificate to a configured anchor,
/// validate it at this signature's validation time, and report the anchor's
/// provenance and the chain's qualified status.
pub(crate) fn verify_signer_path(
    context: &crate::Context<'_, '_, '_, '_>,
    signer: &ParsedCertificate,
    extra_certificates: &[ParsedCertificate],
    signature_time: UnixTime,
    report: &mut crate::report::SignatureReport,
) -> SignerPath {
    // Candidates: the signature's own certificates (ds:KeyInfo and the XAdES
    // CertificateValues) plus the trust store's intermediates.
    let mut candidates = extra_certificates.to_vec();
    candidates.extend(context.store_intermediates.iter().cloned());
    let candidates = dedup(candidates);
    let path = validate_path_at(
        signer,
        &candidates,
        &context.anchors,
        context.anchor_status(),
        signature_time,
        &context.options.limits,
        PathPurpose::Signing,
    );
    let mut chain = path.chain;
    report.checks.extend(path.advisories);
    let status = match path.code {
        CheckCode::CertPathOk => CheckStatus::Passed,
        // Giving up is not a finding: an exhausted search means the tool
        // stopped looking, not that no path exists. Neither is an anchor whose
        // trusted-list service was not granted: the path is sound and the list
        // simply offers no trust for it at that instant, which is a gap rather
        // than evidence against the signature.
        CheckCode::CertPathUnknown
        | CheckCode::CertPathSearchExhausted
        | CheckCode::TrustListServiceNotGranted => CheckStatus::Unknown,
        _ => CheckStatus::Failed,
    };
    report
        .checks
        .push(Check::new(path.code, status, path.message));

    // --- The anchor's provenance, and what the chain makes it -------------
    if let Some(anchor) = path.path.last() {
        // When the same certificate is both a store anchor and a trusted-list
        // identity, the list is the stronger provenance and the one worth
        // reporting: it says *who* vouches for the CA, where a directory only
        // says that somebody copied it in.
        let listed = context.services.iter().any(|service| {
            matches!(&service.identity, crate::trust::ServiceIdentity::Certificate(der) if *der == anchor.der)
        });
        let provenance = context
            .anchor_provenance
            .iter()
            .find(|(der, _)| *der == anchor.der)
            .map(|(_, anchor)| *anchor);
        if let Some(entry) = chain.last_mut() {
            entry.trust_anchor_origin = if listed {
                Some(crate::trust::TrustAnchorOrigin::TrustList)
            } else {
                provenance.map(|anchor| anchor.origin)
            };
        }
        let outcome = crate::trustlist::qualification(context.services, &path.path, signature_time);
        report.qualified = outcome.qualified;
        report.qualified_signature_device = outcome.device;
        report.qualified_service = outcome.service.clone();
        if let Some(certificate) = report.signing_certificate.as_mut() {
            certificate.qualified = outcome.qualified;
        }
        report.checks.push(outcome.check);
    }
    SignerPath {
        path: path.path,
        chain,
        candidates,
    }
}
