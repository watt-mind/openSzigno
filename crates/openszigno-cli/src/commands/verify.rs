//! `verify`: assemble the trust, revocation, and clock material the verifier
//! needs, run it, and turn its verdict into an exit status.

use openszigno_verify::{
    MemoryRevocationStore, NoRevocation, RoxmltreeC14n, TrustListSnapshot, Verdict, VerifyOptions,
    verify as verify_dossier,
};

use crate::args::VerifyArgs;
use crate::commands::structural_warnings;
use crate::input::{load, valid_input};
use crate::response::{CliError, CliResult, Success, failure};
use crate::trust::{load_signer, load_trust_list, snapshot_of};
use crate::{online, revocation_store, trust};

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
                online::Fetcher::new(args.online_proxy.as_deref()).map_err(|message| {
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
            let fetched =
                fetcher.fill_gaps(&certificates, &anchors, &data, clock.unix_time(), &limits);
            if let Some(directory) = &args.online_cache {
                online::write_cache(directory, &fetched).map_err(|message| {
                    failure(
                        input.clone(),
                        CliError {
                            code: "online_cache_invalid",
                            message,
                            exit: 3,
                        },
                    )
                })?;
            }
            online_checks = fetched.checks;
            store.extend_online(fetched.crls, fetched.ocsp);
            store = store.into_online();
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
    let data = serde_json::to_value(&report).map_err(|_| {
        failure(
            input.clone(),
            CliError::io("the result could not be serialised"),
        )
    })?;

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
