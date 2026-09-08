//! The `openszigno` binary: parse the command line, run the command it names,
//! write the one response that command produced, and exit with the status the
//! response maps to.

mod args;
mod commands;
mod extract;
mod input;
mod online;
mod render;
mod response;
mod revocation_store;
mod trust;

use std::process::ExitCode;

use clap::Parser;
use openszigno_core::DecryptOptions;
use serde_json::Value;

use crate::args::{Cli, Command, MAX_NESTING_DEPTH};
use crate::commands::extract::{extract, load_recipient_key};
use crate::commands::inspect::inspect;
use crate::commands::list::list;
use crate::commands::skill::skill;
use crate::commands::validate::validate_structure;
use crate::commands::verify::verify_command;
use crate::extract::ExtractRequest;
use crate::input::InputInfo;
use crate::render::human::write_human_success;
use crate::render::json::write_json;
use crate::render::{write_diagnostic, write_payload};
use crate::response::{Notice, Response, SCHEMA_VERSION, failure};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => return usage_failure(error),
    };
    // `skill` writes the embedded document and nothing else: no envelope,
    // no diagnostics, and no dossier is read.
    if matches!(cli.command, Command::Skill) {
        return match skill() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(3),
        };
    }
    let (command, json_mode, result) = match cli.command {
        Command::Inspect(args) => {
            let result = inspect(&args.file, &args.parse_options());
            ("inspect", args.json, result)
        }
        Command::List(args) => {
            let result = list(&args.file, &args.parse_options());
            ("list", args.json, result)
        }
        Command::Extract(args) => {
            let options = args.parse_options();
            let request = ExtractRequest {
                selectors: &args.document,
                to_stdout: args.stdout,
                recursive: !args.no_recursive,
                max_depth: args.max_depth.min(MAX_NESTING_DEPTH),
            };
            // The key is loaded before the dossier is touched, so an unusable
            // key fails the run without having decoded anything.
            let result = match load_recipient_key(&args) {
                Ok(key) => {
                    let decrypt = DecryptOptions {
                        key: key.as_ref(),
                        allow_legacy_ciphers: args.allow_legacy_ciphers,
                    };
                    extract(
                        &args.file,
                        args.output.as_deref(),
                        &options,
                        &request,
                        decrypt,
                    )
                }
                Err(error) => Err(failure(
                    InputInfo {
                        format: None,
                        bytes: None,
                    },
                    error,
                )),
            };
            ("extract", args.json, result)
        }
        Command::ValidateStructure(args) => {
            let result = validate_structure(&args.file, &args.parse_options());
            ("validate-structure", args.json, result)
        }
        Command::Verify(args) => {
            let result = verify_command(&args);
            ("verify", args.json, result)
        }
        // Handled above, before any envelope machinery is set up.
        Command::Skill => unreachable!("skill is handled before the dispatch"),
    };

    match result {
        Ok(success) => {
            let response = Response {
                schema_version: SCHEMA_VERSION,
                ok: true,
                command,
                input: success.input,
                data: success.data,
                warnings: success.warnings,
                errors: Vec::new(),
            };
            let written = if json_mode {
                write_json(&response)
            } else if let Some(payload) = &success.payload {
                // Payload mode: stdout carries the document's bytes and
                // nothing else, so every diagnostic goes to stderr.
                write_payload(payload).inspect(|()| {
                    for warning in &response.warnings {
                        write_diagnostic(&format!(
                            "warning [{}]: {}",
                            warning.code, warning.message
                        ));
                    }
                })
            } else {
                write_human_success(command, &response)
            };
            match written {
                Ok(()) => ExitCode::from(success.exit),
                Err(_) => ExitCode::from(3),
            }
        }
        Err(failure) => {
            let response = Response {
                schema_version: SCHEMA_VERSION,
                ok: false,
                command,
                input: failure.input,
                data: Value::Null,
                warnings: Vec::new(),
                errors: vec![Notice {
                    code: failure.error.code.to_owned(),
                    message: failure.error.message.clone(),
                }],
            };
            let written = if json_mode {
                write_json(&response)
            } else {
                write_diagnostic(&format!(
                    "error [{}]: {}",
                    failure.error.code, failure.error.message
                ));
                Ok(())
            };
            match written {
                Ok(()) => ExitCode::from(failure.error.exit),
                Err(_) => ExitCode::from(3),
            }
        }
    }
}

/// Report a `clap` parse failure.
///
/// In JSON mode the caller still gets exactly one envelope on stdout. The
/// message is deliberately static: `clap`'s own text can quote argument
/// values, which may be private paths.
fn usage_failure(error: clap::Error) -> ExitCode {
    use clap::error::ErrorKind;

    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    ) {
        error.exit();
    }
    if !std::env::args_os().any(|argument| argument == "--json") {
        error.exit();
    }
    let response = Response {
        schema_version: SCHEMA_VERSION,
        ok: false,
        command: "usage",
        input: InputInfo {
            format: None,
            bytes: None,
        },
        data: Value::Null,
        warnings: Vec::new(),
        errors: vec![Notice {
            code: "usage_error".to_owned(),
            message: "invalid command-line usage".to_owned(),
        }],
    };
    match write_json(&response) {
        Ok(()) => ExitCode::from(2),
        Err(_) => ExitCode::from(3),
    }
}
