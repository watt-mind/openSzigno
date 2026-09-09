//! `timestamp`: write a copy of a dossier carrying a container
//! `es:TimeStamp`, and say nothing about whether it verifies.
//!
//! A container timestamp is the one piece of evidence this tool can produce
//! without a key: no signer, no certificate, no passphrase, just an RFC 3161
//! token over the elements the e-dossier format says a timestamp at that
//! placement must protect. The element itself, what it includes and what its
//! imprint covers belong to the author crate; this module owns the file, the
//! socket the run may open to the authority the caller named, and the
//! envelope.
//!
//! The transport is the one `sign --tsa` uses, deliberately and to the letter:
//! the same destination policy, the same pinned resolution, the same timeouts
//! and the same size cap. A timestamp request is the only thing that makes
//! this command touch the network.
//!
//! Nothing here checks anything. The run warns
//! `timestamped_dossier_unverified` on every success, because obtaining a
//! token is not evidence about it: `openszigno verify`, against trust material
//! the caller supplies, is the only thing in this tool that judges one.

use openszigno_author::sign::{
    TimestampRequest, TimestampScope, parse_certificates, timestamp as timestamp_dossier,
};
use openszigno_core::ParseOptions;
use serde_json::json;

use crate::args::TimestampArgs;
use crate::commands::create::write_new_file;
use crate::input::valid_input;
use crate::key_material::read_file;
use crate::online::Fetcher;
use crate::response::{CliError, CliResult, Notice, Success, failure};

/// The largest RFC 3161 response that will be read. A token about one imprint
/// is a few kilobytes; anything near this cap is already wrong. It is the cap
/// `sign --tsa` reads a response under, because it is the same exchange.
const MAX_TIMESTAMP_BYTES: u64 = 64 * 1024;

pub(crate) fn timestamp(args: &TimestampArgs) -> CliResult {
    let options = args.parse_options();
    // The dossier is parsed before anything is asked of the authority, so a
    // file this tool cannot read back is refused with the parser's own
    // structural code and no socket is opened for it.
    let (bytes, _) = crate::input::load(&args.file, &options)?;
    run(args, &options, &bytes).map_err(|error| failure(valid_input(bytes.len()), error))
}

fn run(args: &TimestampArgs, options: &ParseOptions, bytes: &[u8]) -> Result<Success, CliError> {
    let request = TimestampRequest {
        scope: if args.scope_is_dossier() {
            TimestampScope::Dossier
        } else {
            TimestampScope::Document
        },
        documents: args.document.clone(),
        certificate_values: certificate_values(args)?,
    };
    let fetcher = Fetcher::new(args.online_proxy.as_deref(), args.online_allow_private)
        .map_err(|message| CliError::option_invalid("online_options_invalid", message))?;
    let mut stamp = |query: &[u8]| -> Result<Vec<u8>, String> {
        fetcher.post_der(
            &args.tsa,
            openszigno_author::sign::TIMESTAMP_QUERY_TYPE,
            openszigno_author::sign::TIMESTAMP_REPLY_TYPE,
            query,
            MAX_TIMESTAMP_BYTES,
        )
    };
    // The author crate builds the `TimeStampReq`; this closure only carries
    // it to the authority and brings the answer back, which is what keeps the
    // imprint and the socket in different crates.
    let stamped =
        timestamp_dossier(bytes, options, &request, &mut stamp).map_err(CliError::from_sign)?;

    write_new_file(&args.output, &stamped.bytes)?;
    let timestamps: Vec<serde_json::Value> = stamped
        .timestamps
        .iter()
        .map(|written| {
            json!({
                "id": written.id,
                "scope": written.scope.as_str(),
                "document_index": written.document_index,
                "gen_time": written.gen_time,
            })
        })
        .collect();
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "output": args.output.to_string_lossy(),
            "bytes": stamped.bytes.len(),
            "timestamps": timestamps,
        }),
        warnings: vec![Notice {
            code: "timestamped_dossier_unverified".to_owned(),
            message:
                "this run embedded a timestamp token and verified nothing; run verify with your own trust material to judge it"
                    .to_owned(),
        }],
        payload: None,
        exit: 0,
    })
}

/// The certificates that go into the timestamp's own
/// `xades:CertificateValues`.
///
/// They travel with the dossier and are digested by nothing: only what an
/// `xades:Include` names is in the imprint. A token obtained through this
/// command already carries the authority's own certificate, because the
/// request asks for it, so these are the issuing CAs above it.
fn certificate_values(args: &TimestampArgs) -> Result<Vec<Vec<u8>>, CliError> {
    let mut values: Vec<Vec<u8>> = Vec::new();
    for path in &args.tsa_cert {
        let bytes = read_file(path, "TSA certificate")?;
        for certificate in parse_certificates(&bytes).map_err(CliError::from_sign)? {
            if !values.contains(&certificate) {
                values.push(certificate);
            }
        }
    }
    Ok(values)
}
