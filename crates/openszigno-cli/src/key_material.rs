//! Reading the caller's own key material: private keys, certificates, and
//! passphrases.
//!
//! One module, because `extract --decrypt-key` and `sign --key` make the same
//! promise and it must not be kept twice. A key, a certificate and a
//! passphrase come from a file the caller names, or the passphrase from one
//! environment variable, and never from `argv`; the buffers zero themselves
//! when they are dropped; and nothing read here — not one byte of a key or a
//! passphrase, nor anything derived from either — ever reaches a message, a
//! warning, or the JSON envelope. The paths may appear, because the caller
//! typed them and they are how a failure is acted on. The contents never do.

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::response::CliError;

/// The one environment variable this tool takes a passphrase from.
///
/// It keeps its `DECRYPT` name because it is the same variable, documented and
/// shipped, that `extract --decrypt-key` has always read: a second variable
/// would be a second place for a secret to be left set.
pub(crate) const PASSPHRASE_ENV: &str = "OPENSZIGNO_DECRYPT_PASSPHRASE";

/// The largest key, certificate, or passphrase file that will be read. A
/// PKCS#8 key and a certificate chain are kilobytes; anything near this cap is
/// already the wrong file.
pub(crate) const MAX_KEY_FILE_BYTES: u64 = 1024 * 1024;

/// Read one small piece of key material.
///
/// `what` names the kind of file in the error, never the path's contents. The
/// buffer zeroes itself when it is dropped, so key and passphrase bytes do not
/// linger in freed memory.
pub(crate) fn read_file(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError::io(format!("the {what} file could not be inspected")))?;
    if !metadata.is_file() {
        return Err(CliError::io(format!(
            "the {what} path is not a regular file"
        )));
    }
    if metadata.len() > MAX_KEY_FILE_BYTES {
        return Err(CliError::io(format!("the {what} file is too large")));
    }
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| CliError::io(format!("the {what} file could not be read")))
}

/// The passphrase for an encrypted key: the file if one was named, otherwise
/// the environment variable, otherwise none.
///
/// A file's single trailing newline is stripped, because that is what an
/// editor or `echo` leaves behind and no user means it to be part of the
/// secret. Nothing else is trimmed: a passphrase may legitimately begin or end
/// with a space.
pub(crate) fn passphrase(
    file: Option<&Path>,
    what: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, CliError> {
    if let Some(path) = file {
        let mut bytes = read_file(path, what)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        return Ok(Some(bytes));
    }
    Ok(std::env::var_os(PASSPHRASE_ENV).map(|value| {
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStrExt as _;
            value.as_os_str().as_bytes().to_vec()
        };
        #[cfg(not(unix))]
        let bytes = value.to_string_lossy().into_owned().into_bytes();
        Zeroizing::new(bytes)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_file_is_an_io_error_that_names_only_the_kind() {
        let error = read_file(Path::new("/nonexistent/openszigno/key.pem"), "signing key")
            .expect_err("the file is not there");
        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
        assert!(error.message.contains("signing key"));
        assert!(!error.message.contains("/nonexistent"));
    }

    #[test]
    fn a_directory_is_not_a_key_file() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let error =
            read_file(temporary.path(), "signing key").expect_err("a directory is not a file");
        assert_eq!(error.code, "io_error");
    }

    #[test]
    fn one_trailing_newline_is_stripped_from_a_passphrase_file() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let path = temporary.path().join("pass");
        fs::write(&path, b"secret \r\n").expect("the file is written");
        let value = passphrase(Some(&path), "signing passphrase")
            .expect("the file reads")
            .expect("there is a passphrase");
        // The trailing space is part of the secret; only the line ending is not.
        assert_eq!(&value[..], b"secret ");
    }
}
