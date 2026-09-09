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

use std::path::Path;

use zeroize::Zeroizing;

use crate::input::{BoundedReadError, read_bounded_file};
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
///
/// The file is opened once and judged through that one descriptor, so neither
/// the symlink refusal nor the cap can be walked past by replacing or growing
/// the file after a check and before the read.
pub(crate) fn read_file(path: &Path, what: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    read_bounded_file(path, MAX_KEY_FILE_BYTES)
        .map(Zeroizing::new)
        .map_err(|error| match error {
            BoundedReadError::Inspect => {
                CliError::io(format!("the {what} file could not be inspected"))
            }
            BoundedReadError::NotRegular { .. } => {
                CliError::io(format!("the {what} path is not a regular file"))
            }
            BoundedReadError::TooLarge { .. } => {
                CliError::io(format!("the {what} file is too large"))
            }
            BoundedReadError::Read => CliError::io(format!("the {what} file could not be read")),
        })
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

    use std::fs;

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

    /// The cap is inclusive: a key file of exactly the documented maximum is
    /// read, and one byte more is refused.
    #[test]
    fn the_key_file_cap_is_inclusive_and_holds_one_byte_past_it() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let at_the_cap = temporary.path().join("at-the-cap");
        fs::write(&at_the_cap, vec![b'x'; MAX_KEY_FILE_BYTES as usize])
            .expect("the file is written");
        let bytes = read_file(&at_the_cap, "signing key").expect("a file at the cap is read");
        assert_eq!(bytes.len(), MAX_KEY_FILE_BYTES as usize);

        let over_the_cap = temporary.path().join("over-the-cap");
        fs::write(&over_the_cap, vec![b'x'; MAX_KEY_FILE_BYTES as usize + 1])
            .expect("the file is written");
        let error = read_file(&over_the_cap, "signing key").expect_err("one byte too many");
        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
        assert_eq!(error.message, "the signing key file is too large");
    }

    /// A symlink standing where a key file would be is refused rather than
    /// followed, and it is refused by the open itself, so replacing the file
    /// with a link after a check would not help an attacker either.
    #[cfg(unix)]
    #[test]
    fn a_symlink_is_never_read_as_key_material() {
        let temporary = tempfile::tempdir().expect("a temporary directory");
        let target = temporary.path().join("real-key.pem");
        fs::write(&target, b"not really a key").expect("the file is written");
        let link = temporary.path().join("link.pem");
        std::os::unix::fs::symlink(&target, &link).expect("the symlink is created");

        let error = read_file(&link, "signing key").expect_err("a symlink is not a key file");
        assert_eq!(error.code, "io_error");
        assert_eq!(error.message, "the signing key path is not a regular file");
    }
}
