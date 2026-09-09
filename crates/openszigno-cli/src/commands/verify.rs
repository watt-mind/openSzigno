//! `verify`: assemble the trust, revocation, and clock material the verifier
//! needs, run it, and turn its verdict into an exit status.

use openszigno_verify::{
    MemoryRevocationStore, NoRevocation, RoxmltreeC14n, TrustListSnapshot, Verdict, VerifyOptions,
    verify as verify_dossier,
};

use std::collections::BTreeSet;

use crate::args::VerifyArgs;
use crate::commands::structural_warnings;
use crate::input::{load, valid_input};
use crate::response::{CliError, CliResult, Success, failure};
use crate::trust::{load_signer, load_trust_list, snapshot_of};
use crate::{online, revocation_store, sanitize, trust};

/// How many verification/fetch rounds one `--online` run may take.
///
/// Three is enough for every shape this build can produce, and the bound is
/// what keeps a crafted dossier from turning "fetch what is missing" into an
/// unbounded loop. Round one fetches for the paths the caller's own material
/// already validates, typically a timestamp authority's. Round two fetches for
/// whatever that evidence made eligible, typically a historical signer path a
/// now verified timestamp restored. Round three is the confirming pass: it
/// finds nothing new and stops. A run that would need a fourth stops with the
/// data it has, and the certificates it could not cover are reported by the
/// verifier as uncovered, exactly as they would be offline.
const MAX_ONLINE_ROUNDS: usize = 3;

/// What one `--online` run carries from round to round.
struct OnlineState {
    /// Everything fetched so far, and the `online_fetch_failed` checks of
    /// every fetch that failed.
    fetched: online::Fetched,
    /// How many certificates may still be fetched for. The budget belongs to
    /// the run rather than to a round, so several rounds cannot multiply the
    /// traffic one dossier can generate.
    budget: usize,
}

/// The caller's own revocation material, widened with everything the rounds
/// have fetched so far.
///
/// It exists so that each round's pass sees the evidence the previous rounds
/// obtained without any of it being copied, and so that fetched artefacts stay
/// in the online tier: they are judged by exactly the same offline rules, and
/// the report has to be able to say an answer came from the network.
struct RoundStore<'a> {
    base: &'a MemoryRevocationStore,
    crls: &'a [Vec<u8>],
    ocsp: &'a [Vec<u8>],
}

impl openszigno_verify::RevocationSource for RoundStore<'_> {
    fn policy(&self) -> openszigno_verify::RevocationPolicy {
        self.base.policy()
    }

    fn crls(&self) -> &[Vec<u8>] {
        openszigno_verify::RevocationSource::crls(self.base)
    }

    fn ocsp_responses(&self) -> &[Vec<u8>] {
        openszigno_verify::RevocationSource::ocsp_responses(self.base)
    }

    fn online_crls(&self) -> &[Vec<u8>] {
        self.crls
    }

    fn online_ocsp_responses(&self) -> &[Vec<u8>] {
        self.ocsp
    }
}

/// Drive the bounded verification/fetch rounds, and return how many rounds
/// actually fetched.
///
/// `eligible` runs a pass over the state accumulated so far and returns the
/// certificates the run validated a path for, each with the validation times
/// that path was evaluated at. `fetch` is given only what is new: a
/// certificate already fetched for at a given time is never fetched for again,
/// which is both the stop condition and the guarantee that the rounds cannot
/// repeat a request. The loop stops as soon as a round turns up nothing new,
/// so the ordinary run costs one pass more than it fetches, and it stops in
/// any case once `bound` rounds have fetched.
fn fetch_rounds<S, E>(
    bound: usize,
    state: &mut S,
    mut eligible: impl FnMut(&S) -> Result<Vec<online::EligibleCertificate>, E>,
    mut fetch: impl FnMut(&mut S, &[online::EligibleCertificate]) -> Result<(), E>,
) -> Result<usize, E> {
    let mut seen: BTreeSet<(Vec<u8>, i64)> = BTreeSet::new();
    let mut rounds = 0;
    for _ in 0..bound {
        let fresh: Vec<online::EligibleCertificate> = eligible(state)?
            .into_iter()
            .filter_map(|candidate| {
                let der = candidate.der;
                let times: Vec<i64> = candidate
                    .times
                    .into_iter()
                    .filter(|time| seen.insert((der.clone(), *time)))
                    .collect();
                (!times.is_empty()).then_some(online::EligibleCertificate { der, times })
            })
            .collect();
        if fresh.is_empty() {
            break;
        }
        rounds += 1;
        fetch(state, &fresh)?;
    }
    Ok(rounds)
}

/// Verify the XMLDSig signatures of a dossier.
///
/// A structural failure still exits 4, so a caller can tell "this is not a
/// dossier" apart from "this dossier's signatures do not verify". A completed
/// run exits 0 when every signature is `valid`, 6 when any signature is
/// `invalid`, and 7 when the overall verdict is `indeterminate`.
pub(crate) fn verify_command(args: &VerifyArgs) -> CliResult {
    let options = args.parse_options();
    let (bytes, dossier) = load(&args.file, &options)?;
    let input = valid_input(bytes.len());

    let backend = RoxmltreeC14n;
    let store;
    let empty = openszigno_verify::NoTrust;
    let mut snapshots: Vec<TrustListSnapshot> = Vec::new();
    let trust: &dyn openszigno_verify::TrustSource =
        if args.trust_store.is_some() || !args.trust_list.is_empty() || args.lotl.is_some() {
            let mut loaded = match &args.trust_store {
                Some(directory) => trust::load_store(directory).map_err(|message| {
                    failure(
                        input.clone(),
                        CliError {
                            code: "trust_store_invalid",
                            message,
                            exit: 3,
                        },
                    )
                })?,
                None => openszigno_verify::MemoryTrustStore::default(),
            };
            let unusable = |message: String| {
                failure(
                    input.clone(),
                    CliError {
                        code: "trust_list_invalid",
                        message,
                        exit: 3,
                    },
                )
            };
            let mut signers: Vec<Vec<u8>> = Vec::new();
            if let Some(path) = &args.trust_list_signer {
                signers.push(load_signer(path).map_err(unusable)?);
            }
            // The LOTL is verified first, against whatever out-of-band
            // certificate the caller has, and only then are its pointers added
            // to the signer pool. Its own `trust_list_unverified` check still
            // blocks when it could not be verified, so pointers taken from an
            // unverified list cannot quietly support a `valid` verdict.
            if let Some(path) = &args.lotl {
                let lotl = load_trust_list(path, &signers, &backend).map_err(unusable)?;
                snapshots.push(snapshot_of(&lotl));
                for check in &lotl.checks {
                    loaded.push_check(check.clone());
                }
                signers.extend(lotl.pointer_certificates);
            }
            for path in &args.trust_list {
                let list = load_trust_list(path, &signers, &backend).map_err(unusable)?;
                snapshots.push(snapshot_of(&list));
                for check in list.checks {
                    loaded.push_check(check);
                }
                loaded.extend_anchors(list.anchors);
                // The `X509SKI` and `X509SubjectName` identities never become
                // anchors, but they can still say that a chain some other
                // anchor validated is covered by a granted CA/QC service.
                loaded.extend_services(list.service_identities);
            }
            store = loaded;
            &store
        } else {
            &empty
        };

    let system = openszigno_verify::SystemClock;
    let fixed;
    let clock: &dyn openszigno_verify::Clock = match &args.at {
        Some(time) => {
            fixed = openszigno_verify::FixedClock(time.unix);
            &fixed
        }
        None => &system,
    };

    let disabled = NoRevocation;
    let offline;
    let mut online_checks: Vec<openszigno_verify::Check> = Vec::new();
    let revocation: &dyn openszigno_verify::RevocationSource = if args.no_revocation {
        &disabled
    } else {
        let mut store = match &args.revocation_store {
            Some(directory) => revocation_store::load(directory).map_err(|message| {
                failure(
                    input.clone(),
                    CliError {
                        code: "revocation_store_invalid",
                        message,
                        exit: 3,
                    },
                )
            })?,
            None => MemoryRevocationStore::default(),
        };
        if args.online {
            // Everything the run already has, so that nothing is fetched for a
            // certificate the caller's own material already answers for. The
            // question is put to the verifier's own offline code path, not to
            // a cheaper approximation of it.
            let (embedded_crls, embedded_ocsp) =
                openszigno_verify::embedded_revocation_values(&bytes, &options)
                    .map_err(|error| failure(input.clone(), CliError::structure(error)))?;
            let mut certificates = openszigno_verify::embedded_certificates(&bytes, &options)
                .map_err(|error| failure(input.clone(), CliError::structure(error)))?;
            certificates.extend(trust.anchors().iter().map(|anchor| anchor.der.clone()));
            certificates.extend(trust.intermediates().iter().cloned());
            let data = openszigno_verify::revocation::RevocationData {
                embedded_crls: &embedded_crls,
                embedded_ocsp: &embedded_ocsp,
                store_crls: openszigno_verify::RevocationSource::crls(&store),
                store_ocsp: openszigno_verify::RevocationSource::ocsp_responses(&store),
                online_crls: &[],
                online_ocsp: &[],
            };
            let fetcher =
                online::Fetcher::new(args.online_proxy.as_deref(), args.online_allow_private)
                    .map_err(|message| {
                        failure(
                            input.clone(),
                            CliError {
                                code: "online_options_invalid",
                                message,
                                exit: 3,
                            },
                        )
                    })?;
            let limits = openszigno_verify::VerifyLimits::default();
            let anchors: Vec<Vec<u8>> = trust
                .anchors()
                .iter()
                .map(|anchor| anchor.der.clone())
                .collect();
            // Bounded verification/fetch rounds. Each round runs an entirely
            // offline-style pass over the caller's own material, widened with
            // everything earlier rounds fetched, whose only product is the
            // list of certificates this run actually validated a path to a
            // configured anchor for, each with the time that path was
            // evaluated at. Fetching is allowed for those and for nothing
            // else, so a certificate parked elsewhere in the XML cannot make
            // this process open a connection, however well it is signed by
            // another certificate in the same file.
            //
            // One pass is not enough, because evidence fetched for one path
            // can create another. A signer whose certificate has expired has
            // no validated path at the clock, so nothing is fetched for it;
            // fetching the revocation evidence its signature timestamp's TSA
            // needed can verify that timestamp, which moves the signer's
            // validation time back to the proven instant and restores its
            // path. With a single pass that discovery arrives after fetching
            // has finished and the signer's own revocation data is never
            // fetched. Rounds close that gap and stop as soon as a round makes
            // nothing new eligible.
            let mut state = OnlineState {
                fetched: online::Fetched::default(),
                budget: online::MAX_CERTIFICATES,
            };
            // The round count is deliberately not reported: a new check would
            // change what every consumer parses, and the fetch checks already
            // say what was obtained.
            fetch_rounds(
                MAX_ONLINE_ROUNDS,
                &mut state,
                |state| {
                    let widened = RoundStore {
                        base: &store,
                        crls: &state.fetched.crls,
                        ocsp: &state.fetched.ocsp,
                    };
                    let mut pass = VerifyOptions::new(clock, trust, &widened, &backend);
                    pass.parse = args.parse_options();
                    pass.requested_time = args.at.as_ref().map(|time| time.text.clone());
                    pass.allow_legacy_algorithms = args.allow_legacy_algorithms;
                    let report = verify_dossier(&bytes, &pass)
                        .map_err(|error| failure(input.clone(), CliError::structure(error)))?;
                    Ok(online::EligibleCertificate::group(
                        report.validated_path_certificates_at(),
                    ))
                },
                |state, fresh| {
                    let data = openszigno_verify::revocation::RevocationData {
                        online_crls: &state.fetched.crls,
                        online_ocsp: &state.fetched.ocsp,
                        ..data
                    };
                    let round = fetcher.fill_gaps(&online::GapRequest {
                        certificates: &certificates,
                        eligible: fresh,
                        anchors: &anchors,
                        data: &data,
                        budget: state.budget,
                        limits: &limits,
                    });
                    state.budget = state.budget.saturating_sub(round.spent);
                    state.fetched.absorb(round);
                    Ok(())
                },
            )?;
            let mut fetched = state.fetched;
            online_checks = std::mem::take(&mut fetched.checks);
            if let Some(directory) = &args.online_cache {
                let notes = online::write_cache(directory, &fetched).map_err(|message| {
                    failure(
                        input.clone(),
                        CliError {
                            code: "online_cache_invalid",
                            message,
                            exit: 3,
                        },
                    )
                })?;
                online_checks.extend(notes);
            }
            // With no anchor configured nothing was fetched and nothing could
            // have been: revocation data is only fetched for a certificate on
            // a path to one. The reported policy says that rather than a bare
            // `online`, so a caller who got no data learns why.
            store = if anchors.is_empty() {
                store.into_online_without_anchors()
            } else {
                store.extend_online(fetched.crls, fetched.ocsp);
                store.into_online()
            };
        }
        offline = store;
        &offline
    };
    let mut verify_options = VerifyOptions::new(clock, trust, revocation, &backend);
    verify_options.parse = options;
    verify_options.requested_time = args.at.as_ref().map(|time| time.text.clone());
    verify_options.allow_legacy_algorithms = args.allow_legacy_algorithms;

    let mut report = verify_dossier(&bytes, &verify_options)
        .map_err(|error| failure(input.clone(), CliError::structure(error)))?;
    report.policy.trust_lists = snapshots;
    // Informational, and deliberately not folded into the verdict. A fetch
    // that did not happen leaves the certificate exactly as uncovered as it
    // was, and that is reported — and blocks — on the chain that needed the
    // data, by the verifier, which is the only thing that knows whether the
    // gap mattered. Blocking here as well would let a fetch attempted for a
    // certificate no verdict depended on sink a dossier whose every signature
    // is valid.
    report.checks.extend(online_checks);
    let exit = match report.verdict {
        Verdict::Invalid => 6,
        Verdict::Indeterminate => 7,
        Verdict::Valid => 0,
    };
    let mut data = serde_json::to_value(&report).map_err(|_| {
        failure(
            input.clone(),
            CliError::io("the result could not be serialised"),
        )
    })?;
    // A certificate's subject and issuer common names are text a CA wrote and
    // this run never chose, and a hostile dossier can carry any certificate it
    // likes. They reach the envelope and the human summary through this value
    // and nowhere else, so one pass over it covers both.
    sanitize::data(&mut data);

    Ok(Success {
        input,
        data,
        // `cryptographic_verification_not_performed` is deliberately absent:
        // verification *was* attempted here, and the verdict says how it went.
        warnings: structural_warnings(&dossier),
        payload: None,
        exit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(byte: u8, times: &[i64]) -> online::EligibleCertificate {
        online::EligibleCertificate {
            der: vec![byte],
            times: times.to_vec(),
        }
    }

    /// The ordinary run: one round fetches, the next finds the same
    /// certificates and stops. Nothing new became eligible, so there is
    /// nothing left to fetch, and the loop does not spend the rest of its
    /// bound proving that again.
    #[test]
    fn the_rounds_stop_when_a_pass_makes_nothing_new_eligible() {
        let mut per_round: Vec<usize> = Vec::new();
        let rounds = fetch_rounds::<_, ()>(
            MAX_ONLINE_ROUNDS,
            &mut per_round,
            |_| Ok(vec![certificate(1, &[10]), certificate(2, &[10])]),
            |state, fresh| {
                state.push(fresh.len());
                Ok(())
            },
        )
        .expect("the rounds succeed");
        assert_eq!(rounds, 1);
        assert_eq!(per_round, vec![2]);
    }

    /// A pass that keeps finding more is stopped by the bound rather than by
    /// the stop condition, and the pass after the last round never runs.
    #[test]
    fn the_bound_stops_a_run_that_keeps_finding_more() {
        let mut per_round: Vec<usize> = Vec::new();
        let mut passes = 0_u8;
        let rounds = fetch_rounds::<_, ()>(
            MAX_ONLINE_ROUNDS,
            &mut per_round,
            |_| {
                passes += 1;
                Ok((0..=passes).map(|byte| certificate(byte, &[10])).collect())
            },
            |state, fresh| {
                state.push(fresh.len());
                Ok(())
            },
        )
        .expect("the rounds succeed");
        assert_eq!(rounds, MAX_ONLINE_ROUNDS);
        assert_eq!(per_round, vec![2, 1, 1]);
        assert_eq!(usize::from(passes), MAX_ONLINE_ROUNDS);
    }

    /// A certificate a later round needs at a *new* validation time is a new
    /// question, and only that question is asked again: the time it was
    /// already fetched for is not.
    #[test]
    fn a_new_validation_time_is_a_new_question() {
        let mut per_round: Vec<Vec<i64>> = Vec::new();
        let mut passes = 0_u8;
        let rounds = fetch_rounds::<_, ()>(
            MAX_ONLINE_ROUNDS,
            &mut per_round,
            |_| {
                passes += 1;
                Ok(vec![certificate(
                    1,
                    if passes == 1 { &[10] } else { &[10, 20] },
                )])
            },
            |state, fresh| {
                state.push(fresh[0].times.clone());
                Ok(())
            },
        )
        .expect("the rounds succeed");
        assert_eq!(rounds, 2);
        assert_eq!(per_round, vec![vec![10], vec![20]]);
    }

    /// A pass that fails stops the run and the failure reaches the caller.
    #[test]
    fn a_failed_pass_stops_the_rounds() {
        let mut per_round: Vec<usize> = Vec::new();
        let outcome = fetch_rounds::<_, &str>(
            MAX_ONLINE_ROUNDS,
            &mut per_round,
            |_| Err("the dossier stopped parsing"),
            |state, fresh| {
                state.push(fresh.len());
                Ok(())
            },
        );
        assert_eq!(outcome, Err("the dossier stopped parsing"));
        assert!(per_round.is_empty());
    }
}
