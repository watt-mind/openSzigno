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

/// The largest a whole revocation store may be, across every file of both its
/// directories.
///
/// The per-file cap above bounds one CRL or OCSP response; without this one, a
/// store of four thousand files each just under it is sixty gigabytes the
/// loader would try to hold in memory before it answered anything. 256 MiB is
/// far more than any real store holds — the largest public CRLs are tens of
/// megabytes — and it is a refusal, not a truncation: "no revocation data" is
/// itself an answer that changes a verdict, so a store that quietly dropped
/// half its contents would be worse than no store at all.
const MAX_STORE_BYTES: u64 = 256 * 1024 * 1024;

pub fn load(directory: &Path) -> Result<MemoryRevocationStore, String> {
    load_within(directory, MAX_STORE_BYTES)
}

fn load_within(directory: &Path, budget: u64) -> Result<MemoryRevocationStore, String> {
    let metadata = fs::symlink_metadata(directory)
        .map_err(|_| "the revocation store directory could not be inspected".to_owned())?;
    if !metadata.is_dir() {
        return Err("the revocation store path is not a directory".to_owned());
    }

    // Every directory is read before any file is classified, so that a store
    // over the aggregate cap is refused for its size rather than for whatever
    // the first file over it happened to contain.
    let mut files = Vec::new();
    let mut remaining = budget;
    let crls_directory = directory.join("crls");
    let ocsp_directory = directory.join("ocsp");
    if crls_directory.is_dir() || ocsp_directory.is_dir() {
        if crls_directory.is_dir() {
            read_directory(&crls_directory, &mut files, &mut remaining)?;
        }
        if ocsp_directory.is_dir() {
            read_directory(&ocsp_directory, &mut files, &mut remaining)?;
        }
    } else {
        read_directory(directory, &mut files, &mut remaining)?;
    }

    let mut crls = Vec::new();
    let mut ocsp = Vec::new();
    for bytes in files {
        match classify(&bytes)? {
            (RevocationItemKind::Crl, der) => crls.push(der),
            (RevocationItemKind::Ocsp, der) => ocsp.push(der),
        }
    }
    Ok(MemoryRevocationStore::new(crls, ocsp))
}

/// Read every regular file in one directory as revocation material.
///
/// Symlinks and subdirectories are skipped rather than followed, matching the
/// extractor's and the trust store's no-symlink policy. The bytes are returned
/// unclassified: the whole store is read, and bounded, before any of it is
/// interpreted.
fn read_directory(
    directory: &Path,
    files: &mut Vec<Vec<u8>>,
    remaining: &mut u64,
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
            Err(BoundedReadError::NotRegular) => continue,
            Err(BoundedReadError::TooLarge { declared }) => return Err(too_large(declared)),
            Err(BoundedReadError::Inspect) => {
                return Err("a revocation store file could not be inspected".to_owned());
            }
            Err(BoundedReadError::Read) => {
                return Err("a revocation store file could not be read".to_owned());
            }
        };
        // The whole store is bounded, not only each file in it.
        *remaining = remaining
            .checked_sub(bytes.len() as u64)
            .ok_or_else(too_large_in_total)?;
        files.push(bytes);
    }
    Ok(())
}

/// The refusal for a store whose files add up past the aggregate cap. The
/// files read so far are dropped: a partially loaded store answers a
/// revocation question with less than the operator gave it, which is exactly
/// the silence the loader refuses elsewhere.
fn too_large_in_total() -> String {
    format!(
        "the revocation store is too large: its files exceed the \
         {MAX_STORE_BYTES}-byte total this loader will read"
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A store is bounded in total, not only file by file. The cap is passed
    /// in so the test does not have to write 256 MiB to reach it; the shipped
    /// value is `MAX_STORE_BYTES`.
    #[test]
    fn a_store_whose_files_add_up_past_the_cap_is_refused() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        for name in ["a.crl", "b.crl"] {
            fs::write(directory.path().join(name), vec![b'x'; 32]).expect("the file is written");
        }
        let error = load_within(directory.path(), 48)
            .expect_err("two 32-byte files exceed a 48-byte store budget");
        assert!(
            error.contains("too large"),
            "the refusal must say the store is too large in total: {error}"
        );
        assert!(
            !error.contains("a.crl") && !error.contains("b.crl"),
            "the refusal must not name a file: {error}"
        );
    }

    /// The aggregate cap counts both directories of a split store.
    #[test]
    fn the_cap_spans_the_crl_and_ocsp_directories() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        for sub in ["crls", "ocsp"] {
            let path = directory.path().join(sub);
            fs::create_dir(&path).expect("the directory is created");
            fs::write(path.join("item.der"), vec![b'x'; 32]).expect("the file is written");
        }
        let error = load_within(directory.path(), 48)
            .expect_err("the two directories together exceed the budget");
        assert!(error.contains("too large"), "{error}");
    }

    /// Inside the cap the file is read and then judged on what it holds.
    #[test]
    fn a_store_inside_the_cap_is_read_and_judged_on_its_contents() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        fs::write(directory.path().join("a.crl"), vec![b'x'; 32]).expect("the file is written");
        let error =
            load_within(directory.path(), 1024).expect_err("the bytes are neither CRL nor OCSP");
        assert!(!error.contains("too large"), "{error}");
    }
}
