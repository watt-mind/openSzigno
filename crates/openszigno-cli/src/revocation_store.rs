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

use openszigno_verify::revocation::{RevocationItemKind, classify};
use openszigno_verify::{MAX_REVOCATION_ITEM_BYTES, MemoryRevocationStore};

use crate::input::{BoundedReadError, read_bounded_file};

/// The largest revocation-store file this loader will read.
///
/// It is the verifier's own limit, deliberately: a store that accepted a file
/// the verifier would then decline to parse would load evidence that answers
/// nothing, which is exactly the silence this constant exists to prevent. The
/// message names the size and the limit, because "too large" without either is
/// not something an operator can act on.
const MAX_FILE_BYTES: u64 = MAX_REVOCATION_ITEM_BYTES as u64;

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
        // The entry kind is checked twice on purpose. This one only decides
        // what to skip; the read below opens the file once and refuses a
        // symlink, a directory and an over-cap file through that one open
        // descriptor, so nothing here is a security decision a race could
        // undo.
        let metadata = fs::symlink_metadata(&path)
            .map_err(|_| "a revocation store file could not be inspected".to_owned())?;
        if !metadata.is_file() {
            continue;
        }
        let bytes = match read_bounded_file(&path, MAX_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(BoundedReadError::NotRegular { .. }) => continue,
            Err(BoundedReadError::TooLarge { declared }) => return Err(too_large(declared)),
            Err(BoundedReadError::Inspect) => {
                return Err("a revocation store file could not be inspected".to_owned());
            }
            Err(BoundedReadError::Read) => {
                return Err("a revocation store file could not be read".to_owned());
            }
        };
        match classify(&bytes)? {
            (RevocationItemKind::Crl, der) => crls.push(der),
            (RevocationItemKind::Ocsp, der) => ocsp.push(der),
        }
    }
    Ok(())
}

/// The refusal for an over-cap file. The size is named when the open
/// descriptor reported one, because "too large" without a number is not
/// something an operator can act on; a file that grew past the cap while it
/// was being read has no size this process ever learned, and the message says
/// only what the limit was.
fn too_large(declared: Option<u64>) -> String {
    match declared {
        Some(size) => format!(
            "a revocation store file is too large: {size} bytes, over the {MAX_FILE_BYTES}-byte limit on one CRL or OCSP response"
        ),
        None => format!(
            "a revocation store file is too large: it grew past the {MAX_FILE_BYTES}-byte limit on one CRL or OCSP response while it was being read"
        ),
    }
}
