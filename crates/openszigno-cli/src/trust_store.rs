//! The `--trust-store DIR` loader.
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

use openszigno_verify::MemoryTrustStore;
use openszigno_verify::certs::certificates_from_bytes;

/// The largest trust-store file this loader will read, so that a store pointed
/// at a huge file cannot exhaust memory.
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;

/// The largest number of files read from one directory.
const MAX_FILES: usize = 1024;

pub fn load(directory: &Path) -> Result<MemoryTrustStore, String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "the trust store directory could not be inspected".to_owned())?;
    if !metadata.is_dir() {
        return Err("the trust store path is not a directory".to_owned());
    }

    let anchors_directory = directory.join("anchors");
    let (anchors, intermediates) = if anchors_directory.is_dir() {
        (
            read_directory(&anchors_directory)?,
            match directory.join("intermediates") {
                path if path.is_dir() => read_directory(&path)?,
                _ => Vec::new(),
            },
        )
    } else {
        (read_directory(directory)?, Vec::new())
    };

    if anchors.is_empty() {
        return Err("the trust store contains no certificates".to_owned());
    }
    Ok(MemoryTrustStore::new(anchors, intermediates))
}

/// Read every regular file in one directory as certificate material.
///
/// Symlinks and subdirectories are skipped rather than followed, matching the
/// extractor's no-symlink policy.
fn read_directory(directory: &Path) -> Result<Vec<Vec<u8>>, String> {
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

    let mut certificates = Vec::new();
    for path in names {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "a trust store file could not be inspected".to_owned())?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("a trust store file is too large".to_owned());
        }
        let bytes =
            fs::read(&path).map_err(|_| "a trust store file could not be read".to_owned())?;
        // Every entry is parsed as an X.509 certificate here, so a store that
        // loads is one whose every byte was understood.
        let parsed = certificates_from_bytes(&bytes)
            .map_err(|reason| format!("a trust store file is not usable: {reason}"))?;
        certificates.extend(parsed);
    }
    Ok(certificates)
}
