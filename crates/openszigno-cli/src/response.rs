//! The JSON envelope and the error type behind it: what every command
//! returns, and the exit status each failure maps to.

use openszigno_core::Error as CoreError;
use serde::Serialize;
use serde_json::Value;

use crate::extract::output_dir::OpenError;
use crate::input::InputInfo;

pub(crate) const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Notice {
    pub(crate) code: String,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct Response {
    pub(crate) schema_version: u32,
    pub(crate) ok: bool,
    pub(crate) command: &'static str,
    pub(crate) input: InputInfo,
    pub(crate) data: Value,
    pub(crate) warnings: Vec<Notice>,
    pub(crate) errors: Vec<Notice>,
}

#[derive(Debug)]
pub(crate) struct CliError {
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) exit: u8,
}

impl CliError {
    pub(crate) fn io(message: impl Into<String>) -> Self {
        Self {
            code: "io_error",
            message: message.into(),
            exit: 3,
        }
    }

    pub(crate) fn structure(error: CoreError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: 4,
        }
    }

    pub(crate) fn extraction(error: CoreError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: 5,
        }
    }

    /// A problem with the caller's own decryption material rather than with
    /// the dossier. Exit 4 is the "the inputs to this run are unusable"
    /// status; nothing about the dossier has been judged.
    pub(crate) fn decrypt_material(error: CoreError) -> Self {
        Self {
            code: error.code().as_str(),
            message: error.message().to_owned(),
            exit: 4,
        }
    }

    pub(crate) fn invalid(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit: 4,
        }
    }

    pub(crate) fn unsafe_output(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit: 5,
        }
    }
}

impl From<OpenError> for CliError {
    fn from(error: OpenError) -> Self {
        match error {
            OpenError::Unsafe(message) => Self::unsafe_output("unsafe_output_directory", message),
            OpenError::Io(message) => Self::io(message),
        }
    }
}

pub(crate) struct Success {
    pub(crate) input: InputInfo,
    pub(crate) data: Value,
    pub(crate) warnings: Vec<Notice>,
    /// Raw bytes to write to stdout instead of a human summary, set only by
    /// `extract --stdout`. Never combined with `--json`, which `clap` refuses.
    pub(crate) payload: Option<Vec<u8>>,
    /// The process exit status for a completed run. `0` for every command
    /// except `verify`, which reports its verdict through statuses 6 and 7.
    pub(crate) exit: u8,
}

pub(crate) struct Failure {
    pub(crate) input: InputInfo,
    pub(crate) error: CliError,
}

pub(crate) type CliResult = Result<Success, Failure>;

pub(crate) fn failure(input: InputInfo, error: CliError) -> Failure {
    Failure { input, error }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_errors_carry_the_documented_exit_status() {
        assert_eq!(CliError::io("x").exit, 3);
        assert_eq!(CliError::invalid("input_too_large", "x").exit, 4);
        assert_eq!(CliError::unsafe_output("output_exists", "x").exit, 5);
        assert_eq!(CliError::io("x").code, "io_error");

        let unsafe_directory = CliError::from(OpenError::Unsafe("not a directory"));
        assert_eq!(unsafe_directory.code, "unsafe_output_directory");
        assert_eq!(unsafe_directory.exit, 5);
        let io = CliError::from(OpenError::Io("cannot inspect"));
        assert_eq!(io.code, "io_error");
        assert_eq!(io.exit, 3);
    }
}
