//! `sign`: write a signed copy of a dossier, and say nothing about whether it
//! verifies.
//!
//! This module owns everything `openszigno-author` deliberately does not: the
//! files, the key material, the clock, and the one socket a run may open, to a
//! timestamp authority the caller named. The signing itself — what a signature
//! covers, where the element sits, and what it digests — belongs to the author
//! crate, and is reached through one call.
//!
//! Nothing here checks anything. The run warns `signed_dossier_unverified` on
//! every success, because producing a signature is not evidence about it:
//! `openszigno verify`, against trust material the caller supplies, is the
//! only thing in this tool that judges one.

use std::io::Write as _;
use std::path::Path;

use openszigno_author::sign::{
    SignError, SignRequest, SignScope, SignatureAlgorithm, SoftwareSigner, parse_certificates,
    sign as sign_dossier, timestamp_request,
};
use openszigno_core::ParseOptions;
use openszigno_verify::{Clock, SystemClock, format_rfc3339};
use serde_json::json;

use crate::args::SignArgs;
use crate::extract::output_dir::OutputDir;
use crate::input::valid_input;
use crate::key_material::{passphrase, read_file};
use crate::online::Fetcher;
use crate::response::{CliError, CliResult, Notice, Success, failure};

/// The largest RFC 3161 response that will be read. A token about one imprint
/// is a few kilobytes; anything near this cap is already wrong.
const MAX_TIMESTAMP_BYTES: u64 = 64 * 1024;

pub(crate) fn sign(args: &SignArgs) -> CliResult {
    let options = args.parse_options();
    // The dossier is parsed before anything is signed, so a file this tool
    // cannot read back is refused with the parser's own structural code.
    let (bytes, _) = crate::input::load(&args.file, &options)?;
    run(args, &options, &bytes).map_err(|error| failure(valid_input(bytes.len()), error))
}

fn run(args: &SignArgs, options: &ParseOptions, bytes: &[u8]) -> Result<Success, CliError> {
    // The key is loaded before the dossier is touched, so unusable material
    // fails the run without anything having been signed.
    let signer = load_signer(args)?;
    let request = SignRequest {
        scope: if args.scope_is_dossier() {
            SignScope::Dossier
        } else {
            SignScope::Document
        },
        documents: args.document.clone(),
        signing_time: args.signing_time.as_ref().map_or_else(
            || format_rfc3339(SystemClock.unix_time()),
            |time| time.0.clone(),
        ),
        certificate_values: certificate_values(args)?,
    };

    let signed = match args.tsa.as_deref() {
        None => sign_dossier(bytes, options, &request, &signer, None),
        Some(url) => {
            let fetcher = Fetcher::new(args.online_proxy.as_deref(), args.online_allow_private)
                .map_err(|message| CliError::invalid("online_options_invalid", message))?;
            let mut stamp = |octets: &[u8]| -> Result<Vec<u8>, String> {
                let query =
                    timestamp_request(octets).map_err(|error| error.message().to_owned())?;
                fetcher.post_der(
                    url,
                    openszigno_author::sign::TIMESTAMP_QUERY_TYPE,
                    openszigno_author::sign::TIMESTAMP_REPLY_TYPE,
                    &query,
                    MAX_TIMESTAMP_BYTES,
                )
            };
            sign_dossier(bytes, options, &request, &signer, Some(&mut stamp))
        }
    }
    .map_err(CliError::signing)?;

    write_new_file(&args.output, &signed.bytes)?;
    let signatures: Vec<serde_json::Value> = signed
        .signatures
        .iter()
        .map(|signature| {
            json!({
                "id": signature.id,
                "scope": signature.scope.as_str(),
                "document_index": signature.document_index,
                "algorithm": signature.algorithm.as_str(),
                "signing_time": signature.signing_time,
                "timestamped": signature.timestamped,
            })
        })
        .collect();
    Ok(Success {
        input: valid_input(bytes.len()),
        data: json!({
            "output": args.output.to_string_lossy(),
            "bytes": signed.bytes.len(),
            "signatures": signatures,
        }),
        warnings: vec![Notice {
            code: "signed_dossier_unverified".to_owned(),
            message:
                "this run produced a signature and verified nothing; run verify with your own trust material to judge it"
                    .to_owned(),
        }],
        payload: None,
        exit: 0,
    })
}

/// Load the signing key and the certificate that names it.
fn load_signer(args: &SignArgs) -> Result<SoftwareSigner, CliError> {
    let key = read_file(&args.key, "signing key")?;
    let certificate = args
        .cert
        .as_deref()
        .map(|path| read_file(path, "signing certificate"))
        .transpose()?;
    let secret = passphrase(args.passphrase_file.as_deref(), "signing passphrase")?;
    let algorithm = args
        .algorithm
        .as_deref()
        .map(|name| {
            SignatureAlgorithm::from_name(name).ok_or_else(|| {
                CliError::invalid("invalid_signing_key", "unknown --algorithm value")
            })
        })
        .transpose()?;
    SoftwareSigner::load(
        &key,
        secret.as_deref().map(|bytes| &bytes[..]),
        certificate.as_deref().map(|bytes| &bytes[..]),
        algorithm,
    )
    .map_err(CliError::signing)
}

/// The certificates that go into `xades:CertificateValues`: the signer's
/// issuing CAs and the timestamp authority's, so a verifier can build both
/// paths from the dossier alone.
fn certificate_values(args: &SignArgs) -> Result<Vec<Vec<u8>>, CliError> {
    let mut values = Vec::new();
    for (paths, what) in [
        (&args.chain, "chain certificate"),
        (&args.tsa_cert, "TSA certificate"),
    ] {
        for path in paths {
            let bytes = read_file(path, what)?;
            for certificate in parse_certificates(&bytes).map_err(CliError::signing)? {
                if !values.contains(&certificate) {
                    values.push(certificate);
                }
            }
        }
    }
    Ok(values)
}

/// Write `bytes` to `path`, refusing to replace anything already there, and
/// removing what this run created if the write fails.
///
/// The same descriptor-relative machinery `create` and `extract` write
/// through, so the same rules hold: an existing destination is
/// `output_exists`, a path component that is a symlink or is not a directory
/// is `unsafe_output_directory`, and a half-written file is removed rather
/// than left behind looking like a signed dossier.
fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            CliError::invalid(
                "invalid_output_path",
                "the output path does not name a file",
            )
        })?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let directory = OutputDir::open(parent).map_err(CliError::from)?;
    let mut file = directory.create_new_file(name).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            CliError::unsafe_output(
                "output_exists",
                "an output file already exists or cannot be created safely",
            )
        } else {
            CliError::io("could not create the output file")
        }
    })?;
    if let Err(error) = file
        .write_all(bytes)
        .and_then(|()| file.flush())
        .map_err(|_| CliError::io("could not write the signed dossier"))
    {
        let removed = directory.remove_file(name).is_ok();
        return Err(if removed {
            error
        } else {
            CliError {
                code: error.code,
                message: format!("{}; the partial output may remain", error.message),
                exit: error.exit,
            }
        });
    }
    Ok(())
}

impl CliError {
    /// A refusal from the author crate's signing library. The code and exit
    /// status are the library's own, so the CLI adds no policy of its own to
    /// what "unusable signing material" means.
    fn signing(error: SignError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: error.code().exit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_output_path_that_names_no_file_is_refused() {
        let error = write_new_file(Path::new(".."), b"x").expect_err("no filename");
        assert_eq!(error.code, "invalid_output_path");
        assert_eq!(error.exit, 4);
    }

    #[test]
    fn an_existing_output_is_never_overwritten() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let path = temporary.path().join("signed.es3");
        std::fs::write(&path, b"already here").expect("the file is written");
        let error = write_new_file(&path, b"new").expect_err("the file exists");
        assert_eq!(error.code, "output_exists");
        assert_eq!(error.exit, 5);
        assert_eq!(
            std::fs::read(&path).expect("still readable"),
            b"already here"
        );
    }

    #[test]
    fn a_signing_refusal_keeps_the_library_code_and_exit_status() {
        let error = CliError::signing(
            SoftwareSigner::load(b"not a key", None, Some(b"not a certificate"), None)
                .expect_err("neither loads"),
        );
        assert_eq!(error.code, "invalid_signing_certificate");
        assert_eq!(error.exit, 4);
    }
}
