//! Trust material: the `--trust-store DIR` loader, and the ETSI TS 119 612
//! trusted lists that `--trust-list` and `--lotl` name.
//!
//! # The `--trust-store DIR` loader
//!
//! Layout, per `docs/verify-design.md` §4:
//!
//! ```text
//! <dir>/anchors/*        trust anchors, PEM or DER, one or more certs per file
//! <dir>/intermediates/*  optional extra CA certificates for path building
//! ```
//!
//! Both directories are read the same way and the split is a convention, not a
//! grant: the verifier classifies what it is given. A **self-signed**
//! certificate is a trust anchor; anything else is an extra untrusted
//! intermediate offered for path building. Dropping an intermediate into
//! `anchors/` therefore does not make it trusted.
//!
//! A directory holding certificate files directly, with no `anchors`
//! subdirectory, is read as a bag of anchors, because that is what a caller who
//! just dropped a root certificate somewhere expects.
//!
//! A file that does not parse fails the run rather than being skipped: a
//! partially loaded trust store would silently change what "trusted" means.
//! Messages never name a file, because the path may be private.

use std::fs;
use std::path::Path;

use openszigno_verify::certs::certificates_from_bytes;
use openszigno_verify::{MemoryTrustStore, RoxmltreeC14n, TrustListSnapshot};

use crate::input::{BoundedReadError, read_bounded_file};

/// The largest trust-store file this loader will read, so that a store pointed
/// at a huge file cannot exhaust memory.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The largest number of files read from one directory.
const MAX_FILES: usize = 1024;

/// The largest a whole trust store may be, across every file of both its
/// directories.
///
/// The per-file cap above bounds one certificate file; without this one, a
/// store of a thousand files each just under it is a gigabyte of allocation
/// the loader would make before it decided anything. 64 MiB is far more
/// certificate material than any real store holds — a national trusted list
/// is a few megabytes — and it is a refusal, not a truncation: a partially
/// loaded trust store would silently change what "trusted" means.
const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

/// A running total of the bytes one store has read, against a cap.
struct Budget {
    remaining: u64,
    what: &'static str,
}

impl Budget {
    fn spend(&mut self, bytes: u64) -> Result<(), String> {
        self.remaining = self.remaining.checked_sub(bytes).ok_or_else(|| {
            format!(
                "the {} holds more than the {MAX_STORE_BYTES}-byte total this loader will read",
                self.what
            )
        })?;
        Ok(())
    }
}

pub(crate) fn load_store(directory: &Path) -> Result<MemoryTrustStore, String> {
    load_store_within(directory, MAX_STORE_BYTES)
}

fn load_store_within(directory: &Path, budget: u64) -> Result<MemoryTrustStore, String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "the trust store directory could not be inspected".to_owned())?;
    if !metadata.is_dir() {
        return Err("the trust store path is not a directory".to_owned());
    }

    let mut budget = Budget {
        remaining: budget,
        what: "trust store",
    };
    // Both directories are read before either is parsed, so that a store over
    // the aggregate cap is refused for its size rather than for whatever the
    // first file over it happened to contain.
    let anchors_directory = directory.join("anchors");
    let (anchors, intermediates) = if anchors_directory.is_dir() {
        (
            read_directory(&anchors_directory, &mut budget)?,
            match directory.join("intermediates") {
                path if path.is_dir() => read_directory(&path, &mut budget)?,
                _ => Vec::new(),
            },
        )
    } else {
        (read_directory(directory, &mut budget)?, Vec::new())
    };
    let anchors = parse_all(anchors)?;
    let intermediates = parse_all(intermediates)?;

    if anchors.is_empty() {
        return Err("the trust store contains no certificates".to_owned());
    }
    Ok(MemoryTrustStore::new(anchors, intermediates))
}

/// Parse every file read from a store as X.509 certificate material, so a
/// store that loads is one whose every byte was understood.
fn parse_all(files: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    for bytes in files {
        certificates.extend(
            certificates_from_bytes(&bytes)
                .map_err(|reason| format!("a trust store file is not usable: {reason}"))?,
        );
    }
    Ok(certificates)
}

/// Read every regular file in one directory as certificate material.
///
/// Symlinks and subdirectories are skipped rather than followed, matching the
/// extractor's no-symlink policy. The bytes are returned unparsed: the whole
/// store is read, and bounded, before any of it is interpreted.
fn read_directory(directory: &Path, budget: &mut Budget) -> Result<Vec<Vec<u8>>, String> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .map_err(|_| "a trust store directory could not be read".to_owned())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    // Deterministic order, so the same store always builds the same paths.
    names.sort();
    if names.len() > MAX_FILES {
        return Err("the trust store directory holds too many files".to_owned());
    }

    let mut files = Vec::new();
    for path in names {
        // The entry kind is checked twice on purpose. This one only decides
        // what to skip; the read below opens the file once and refuses a
        // symlink, a directory and an over-cap file through that one open
        // descriptor, so nothing here is a security decision a race could
        // undo.
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "a trust store file could not be inspected".to_owned())?;
        if !metadata.is_file() {
            continue;
        }
        let bytes = match read_bounded_file(&path, MAX_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(BoundedReadError::NotRegular) => continue,
            Err(BoundedReadError::TooLarge { .. }) => {
                return Err("a trust store file is too large".to_owned());
            }
            Err(BoundedReadError::Inspect) => {
                return Err("a trust store file could not be inspected".to_owned());
            }
            Err(BoundedReadError::Read) => {
                return Err("a trust store file could not be read".to_owned());
            }
        };
        // The whole store is bounded, not only each file in it.
        budget.spend(bytes.len() as u64)?;
        files.push(bytes);
    }
    Ok(files)
}

/// Read a `--trust-list-signer` certificate, PEM or DER.
///
/// Exactly one certificate: a file holding several would leave "which one
/// signed the list" ambiguous, and a verifier must not pick.
pub(crate) fn load_signer(path: &Path) -> Result<Vec<u8>, String> {
    let bytes = read_bounded(path, 4 * 1024 * 1024)?;
    let certificates = openszigno_verify::certs::certificates_from_bytes(&bytes)
        .map_err(|reason| format!("the trust-list signer certificate is not usable: {reason}"))?;
    match certificates.len() {
        1 => Ok(certificates.into_iter().next().expect("one certificate")),
        _ => Err("the trust-list signer file must hold exactly one certificate".to_owned()),
    }
}

pub(crate) fn load_trust_list(
    path: &Path,
    signers: &[Vec<u8>],
    backend: &RoxmltreeC14n,
) -> Result<openszigno_verify::TrustList, String> {
    let bytes = read_bounded(
        path,
        openszigno_verify::trustlist::MAX_TRUST_LIST_BYTES as u64,
    )?;
    openszigno_verify::trustlist::load(&bytes, signers, backend)
}

/// The policy block's citation of one list, so a result names exactly which
/// snapshot it relied on.
pub(crate) fn snapshot_of(list: &openszigno_verify::TrustList) -> TrustListSnapshot {
    TrustListSnapshot {
        version: list.version,
        territory: list.territory.clone(),
        sequence_number: list.sequence_number,
        issue_date: list.issue_date.clone(),
        next_update: list.next_update.clone(),
        anchors: list.anchors.len(),
        signature_verified: list
            .checks
            .iter()
            .any(|check| check.code == openszigno_verify::CheckCode::TrustListSignatureOk),
    }
}

/// Read a regular file, refusing symlinks and anything over `limit` bytes.
///
/// One open, one `fstat` on that descriptor, and a cap on the bytes that
/// arrived, so a file replaced or grown after a check cannot be read past the
/// limit. The message never names the path, because it may be private.
fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    read_bounded_file(path, limit).map_err(|error| {
        match error {
            BoundedReadError::Inspect => "a trust material file could not be inspected",
            BoundedReadError::NotRegular => "a trust material path is not a regular file",
            BoundedReadError::TooLarge { .. } => "a trust material file is too large",
            BoundedReadError::Read => "a trust material file could not be read",
        }
        .to_owned()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A store is bounded in total, not only file by file. The cap is passed
    /// in so the test does not have to write 64 MiB to reach it; the shipped
    /// value is `MAX_STORE_BYTES`.
    #[test]
    fn a_store_whose_files_add_up_past_the_cap_is_refused() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        for name in ["a.pem", "b.pem"] {
            fs::write(directory.path().join(name), vec![b'x'; 32]).expect("the file is written");
        }
        let error = load_store_within(directory.path(), 48)
            .expect_err("two 32-byte files exceed a 48-byte store budget");
        assert!(
            error.contains("holds more than"),
            "the refusal must say the store is too large in total: {error}"
        );
        assert!(
            !error.contains("a.pem") && !error.contains("b.pem"),
            "the refusal must not name a file: {error}"
        );
    }

    /// The cap is on the total, so a store that fits is still read — and then
    /// refused for what it holds, not for how big it is.
    #[test]
    fn a_store_inside_the_cap_is_read_and_judged_on_its_contents() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        fs::write(directory.path().join("a.pem"), vec![b'x'; 32]).expect("the file is written");
        let error =
            load_store_within(directory.path(), 1024).expect_err("the bytes are not a certificate");
        assert!(
            error.contains("not usable"),
            "the file is read and then refused for its contents: {error}"
        );
    }

    /// The aggregate cap counts both directories of a split store, so a store
    /// cannot be padded out by splitting it.
    #[test]
    fn the_cap_spans_the_anchors_and_intermediates_directories() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        for sub in ["anchors", "intermediates"] {
            let path = directory.path().join(sub);
            fs::create_dir(&path).expect("the directory is created");
            fs::write(path.join("cert.pem"), vec![b'x'; 32]).expect("the file is written");
        }
        let error = load_store_within(directory.path(), 48)
            .expect_err("the two directories together exceed the budget");
        assert!(error.contains("holds more than"), "{error}");
    }
}
