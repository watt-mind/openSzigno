//! The `--revocation-store DIR` loader.
//!
//! Layout:
//!
//! ```text
//! <dir>/crls/*   DER or PEM CRLs
//! <dir>/ocsp/*   DER OCSP responses
//! ```
//!
//! A directory holding files directly, with no `crls` or `ocsp` subdirectory,
//! is read as a bag of both: each file is classified by what it actually
//! contains, not by where it sits or what it is called. The split is a
//! convenience for humans, never a claim the loader believes.
//!
//! A file that is neither a CRL nor an OCSP response fails the run rather than
//! being skipped. "No revocation data" is itself an answer that changes a
//! verdict, so a store that quietly dropped half its contents would be worse
//! than no store at all. Messages never name a file, because the path may be
//! private.

use std::fs;
use std::path::Path;

use openszigno_verify::MemoryRevocationStore;
use openszigno_verify::revocation::{RevocationItemKind, classify};

/// The largest revocation-store file this loader will read.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// The largest number of files read from one directory.
const MAX_FILES: usize = 4096;

pub fn load(directory: &Path) -> Result<MemoryRevocationStore, String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "the revocation store directory could not be inspected".to_owned())?;
    if !metadata.is_dir() {
        return Err("the revocation store path is not a directory".to_owned());
    }

    let mut crls = Vec::new();
    let mut ocsp = Vec::new();
    let crls_directory = directory.join("crls");
    let ocsp_directory = directory.join("ocsp");
    if crls_directory.is_dir() || ocsp_directory.is_dir() {
        if crls_directory.is_dir() {
            read_directory(&crls_directory, &mut crls, &mut ocsp)?;
        }
        if ocsp_directory.is_dir() {
            read_directory(&ocsp_directory, &mut crls, &mut ocsp)?;
        }
    } else {
        read_directory(directory, &mut crls, &mut ocsp)?;
    }
    Ok(MemoryRevocationStore::new(crls, ocsp))
}

/// Read every regular file in one directory as revocation material.
///
/// Symlinks and subdirectories are skipped rather than followed, matching the
/// extractor's and the trust store's no-symlink policy.
fn read_directory(
    directory: &Path,
    crls: &mut Vec<Vec<u8>>,
    ocsp: &mut Vec<Vec<u8>>,
) -> Result<(), String> {
    let mut names: Vec<_> = fs::read_dir(directory)
        .map_err(|_| "a revocation store directory could not be read".to_owned())?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    // Deterministic order, so the same store always yields the same answer.
    names.sort();
    if names.len() > MAX_FILES {
        return Err("the revocation store directory holds too many files".to_owned());
    }

    for path in names {
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "a revocation store file could not be inspected".to_owned())?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > MAX_FILE_BYTES {
            return Err("a revocation store file is too large".to_owned());
        }
        let bytes =
            fs::read(&path).map_err(|_| "a revocation store file could not be read".to_owned())?;
        match classify(&bytes)? {
            (RevocationItemKind::Crl, der) => crls.push(der),
            (RevocationItemKind::Ocsp, der) => ocsp.push(der),
        }
    }
    Ok(())
}
