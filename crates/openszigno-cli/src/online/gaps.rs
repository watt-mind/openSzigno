//! What to fetch, and for whom: the gap between the caller's own revocation
//! material and what this run's certification paths need.
//!
//! The neighbouring [`super`] module is the transport, and
//! [`super::destination`] is where a socket may be opened to. This module is
//! the decision that precedes both: which certificates a URL may be contacted
//! for at all, whether the caller's own material already answers for them, and
//! which of the URLs they publish is worth trying first. Nothing here opens a
//! connection; it calls [`super::Fetcher::fetch`] when the decision is yes.
//!
//! Two rules carry the weight, and both are stated where they are enforced in
//! [`Fetcher::fill_gaps`]:
//!
//! - **The trust gate.** A URL is contacted only for a certificate in
//!   `GapRequest::eligible`, the set the verifier said it validated a path to
//!   a configured trust anchor for. Being carried by the dossier is not a
//!   licence to fetch.
//! - **Coverage at the time that matters.** A certificate is only a gap when
//!   the run's own material fails to answer for it at a validation time one of
//!   its paths was actually evaluated at, which is not one global instant.

use std::collections::BTreeSet;

use openszigno_verify::certs::{CertificateSource, ParsedCertificate, dedup};
use openszigno_verify::revocation::{
    RevocationData, RevocationItemKind, classify, is_covered, ocsp_cert_id, ocsp_request,
};
use openszigno_verify::{Check, VerifyLimits};

use super::{
    FailureClass, Fetcher, MAX_CRL_BYTES, MAX_OCSP_BYTES, MAX_URLS_PER_CERTIFICATE, failure, hex,
    sha256,
};

/// What one run fetched, and what it could not.
#[derive(Debug, Default)]
pub struct Fetched {
    pub crls: Vec<Vec<u8>>,
    /// DER OCSP responses, in the order they were fetched.
    pub ocsp: Vec<Vec<u8>>,
    /// The hex SHA-256 of the DER `CertID` each entry of `ocsp` was asked
    /// about, in the same order. Kept alongside rather than inside so that
    /// `ocsp` stays the `&[Vec<u8>]` the verifier's own coverage code takes;
    /// the only reader is [`super::write_cache`], which names a cached
    /// response by the question it answers and lives with the rest of the
    /// cache writing, one module up.
    pub(super) ocsp_cert_ids: Vec<String>,
    /// One `online_fetch_failed` per failure, naming the URL and the failure
    /// class.
    pub checks: Vec<Check>,
    /// How much of the caller's certificate budget this run consumed: one for
    /// every certificate it actually opened a connection on behalf of. The
    /// caller carries the remainder into the next round, so the cap on how
    /// much traffic one dossier can generate is a cap on the whole run rather
    /// than on each round of it.
    pub spent: usize,
}

impl Fetched {
    fn push_ocsp(&mut self, der: Vec<u8>, cert_id: String) {
        self.ocsp.push(der);
        self.ocsp_cert_ids.push(cert_id);
    }

    /// Take everything another round fetched into this accumulator, keeping
    /// each OCSP response next to the question it answers.
    pub fn absorb(&mut self, other: Self) {
        let Self {
            crls,
            ocsp,
            ocsp_cert_ids,
            checks,
            spent,
        } = other;
        self.crls.extend(crls);
        self.ocsp.extend(ocsp);
        self.ocsp_cert_ids.extend(ocsp_cert_ids);
        self.checks.extend(checks);
        self.spent += spent;
    }
}

/// One certificate a URL may be fetched for, with every validation time a
/// validated path carrying it was evaluated at.
///
/// The times matter because coverage is a question about an instant: a CRL
/// that expired in 2021 still covers a signer path a verified timestamp pins
/// to 2020, and a CRL issued today does not. Judging every certificate at one
/// global time both fetches for certificates a run already covers and, worse,
/// calls a certificate covered by data that does not apply at the instant the
/// verdict rests on.
#[derive(Clone, Debug)]
pub struct EligibleCertificate {
    pub der: Vec<u8>,
    /// Every validation time this certificate is needed at, deduplicated. An
    /// empty list means no time this run can name, and nothing is fetched.
    pub times: Vec<i64>,
}

impl EligibleCertificate {
    /// Group the `(certificate, validation time)` pairs
    /// [`openszigno_verify::VerifyReport::validated_path_certificates_at`]
    /// returns, so each certificate is considered once and carries every time
    /// it is needed at.
    pub fn group(pairs: Vec<(Vec<u8>, i64)>) -> Vec<Self> {
        let mut out: Vec<Self> = Vec::new();
        for (der, time) in pairs {
            match out.iter_mut().find(|entry| entry.der == der) {
                Some(entry) => {
                    if !entry.times.contains(&time) {
                        entry.times.push(time);
                    }
                }
                None => out.push(Self {
                    der,
                    times: vec![time],
                }),
            }
        }
        out
    }
}

/// What one `--online` run may fetch, and for whom.
#[derive(Clone, Copy)]
pub struct GapRequest<'a> {
    /// Every certificate the run has: the dossier's, the trust store's
    /// anchors, and its intermediates. Used to find an issuer and to ask the
    /// verifier's own coverage question, never as a licence to fetch.
    pub certificates: &'a [Vec<u8>],
    /// The only certificates a URL may be fetched for: those on a path the
    /// verifier validated to a configured trust anchor, for a signature or a
    /// timestamp under evaluation, each with the validation time that path was
    /// evaluated at. See
    /// [`openszigno_verify::VerifyReport::validated_path_certificates_at`].
    pub eligible: &'a [EligibleCertificate],
    /// The configured trust anchors, needed for the RFC 6960 section 2.2
    /// trusted-responder model when coverage is asked.
    pub anchors: &'a [Vec<u8>],
    pub data: &'a RevocationData<'a>,
    /// How many certificates this call may still fetch for. The caller owns
    /// the budget, because it spans every round of a run.
    pub budget: usize,
    pub limits: &'a VerifyLimits,
}

impl Fetcher {
    /// Fetch whatever the caller's own material does not already cover.
    ///
    /// `request.certificates` is every certificate the dossier and the trust
    /// material carry; the issuer of each is looked up among them, because a
    /// certificate whose issuer is not to hand cannot have a CRL or an OCSP
    /// response checked against it anyway. Being in that pool is *not* a
    /// licence to fetch: only `request.eligible` is, and that is the set this
    /// round's own offline-style pass says the verifier validated a path for,
    /// with the times those paths were evaluated at.
    pub fn fill_gaps(&self, request: &GapRequest<'_>) -> Fetched {
        let GapRequest {
            certificates,
            eligible,
            anchors,
            data,
            mut budget,
            limits,
        } = *request;
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
        if anchors.is_empty() || eligible.is_empty() {
            // No anchor, or no path validated to one: nothing may be fetched
            // for anything, and not one DNS lookup leaves the process. The
            // report says why, through `revocation_policy` and every
            // `revocation_status_unknown` message.
            return fetched;
        }
        let mut crls_tried: BTreeSet<String> = BTreeSet::new();
        let mut ocsp_tried: BTreeSet<(String, String)> = BTreeSet::new();

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
            // the verifier put on a path it validated to a configured anchor,
            // for a signature or a timestamp it was actually evaluating.
            let Some(entry) = eligible.iter().find(|entry| entry.der == subject.der) else {
                continue;
            };
            let Some(issuer) = parsed.iter().find(|candidate| {
                candidate.subject_name_der() == subject.issuer_der()
                    && openszigno_verify::certs::verify_issued_by(subject, candidate)
            }) else {
                continue;
            };
            // Coverage is asked once per validation time this certificate is
            // needed at, and one uncovered instant is enough to fetch: an
            // answer that is fresh at the clock says nothing about the
            // instant a verified timestamp pins a historical path to.
            if covered_at_every_time(entry, subject, issuer, &parsed, &anchors, data, limits) {
                continue;
            }
            budget -= 1;
            fetched.spent += 1;

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
                    match self.fetch(
                        &url,
                        Some(super::Post {
                            media_type: "application/ocsp-request",
                            accept: "application/ocsp-response",
                            bytes: &request,
                            authorization: None,
                            // An OCSP request names a certificate serial and nothing
                            // else. It is not credential material, so it does not
                            // demand TLS the way a CSC body does.
                            sensitive: false,
                        }),
                        MAX_OCSP_BYTES,
                    ) {
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
            if covered_at_every_time(
                entry,
                subject,
                issuer,
                &parsed,
                &anchors,
                &probe(data, &fetched),
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
}

/// Whether `data` already answers for this certificate at **every** validation
/// time a path carrying it was evaluated at.
///
/// One uncovered instant is a gap: the verdict rests on each of these times,
/// so data that covers the certificate at one of them and not at another
/// leaves a question this run still has to answer. A certificate with no time
/// at all is treated as covered, because there is no instant to fetch for.
fn covered_at_every_time(
    entry: &EligibleCertificate,
    subject: &ParsedCertificate,
    issuer: &ParsedCertificate,
    candidates: &[ParsedCertificate],
    anchors: &[ParsedCertificate],
    data: &RevocationData<'_>,
    limits: &VerifyLimits,
) -> bool {
    entry
        .times
        .iter()
        .all(|time| is_covered(subject, issuer, candidates, anchors, data, *time, limits))
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

#[cfg(test)]
mod tests {
    use super::EligibleCertificate;

    /// One certificate on two validated paths is one question asked at two
    /// instants, not two questions.
    #[test]
    fn grouping_keeps_every_time_a_certificate_is_needed_at() {
        let grouped = EligibleCertificate::group(vec![
            (vec![1], 100),
            (vec![2], 100),
            (vec![1], 200),
            (vec![1], 100),
        ]);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].der, vec![1]);
        assert_eq!(grouped[0].times, vec![100, 200]);
        assert_eq!(grouped[1].times, vec![100]);
    }
}
