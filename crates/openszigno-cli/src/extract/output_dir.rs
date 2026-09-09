//! Race-resistant creation of extraction output files.
//!
//! Checking the output directory by path and then opening every file by full
//! path is a time-of-check/time-of-use bug: another process can replace the
//! directory with a symlink between the two steps. On Unix the directory is
//! therefore opened once with `O_DIRECTORY | O_NOFOLLOW` and every output file
//! is created relative to that descriptor; the directory itself is reached by
//! opening each path component relative to the previous one with
//! `O_NOFOLLOW`, so no component is ever resolved through a symlink. On other
//! platforms the path-based
//! no-clobber approach is kept, hardened with an explicit reparse-point
//! (symlink and junction) rejection for every path component.

use std::io;
use std::path::Path;

/// How much of an existing file [`OutputDir::read_file`] will read.
///
/// Its only caller compares the bytes against an artefact it already holds,
/// which the fetch cap keeps at or below the verifier's own item limit, so a
/// longer file is by definition not equal to what is being written and there
/// is nothing to gain by reading on.
const MAX_COMPARED_BYTES: u64 = openszigno_verify::MAX_REVOCATION_ITEM_BYTES as u64 + 1;

/// Why an output directory could not be prepared.
///
/// The messages are stable strings and never contain a path.
#[derive(Debug)]
pub enum OpenError {
    /// The output path is not a real directory (symlink, junction, ...).
    Unsafe(&'static str),
    /// The name is already taken. Creating an extraction subdirectory is a
    /// no-clobber operation like creating an output file, so an existing entry
    /// is `output_exists` and not a failure of the filesystem.
    Exists(&'static str),
    /// The output directory could not be created or inspected.
    Io(&'static str),
}

/// The one wording an existing output entry is reported with, whether it is a
/// file or an extraction subdirectory.
const EXISTS_MESSAGE: &str = "an output file already exists or cannot be created safely";

/// Reject a path whose components are, or contain, links.
///
/// This is defence in depth: on Unix the descriptor-relative I/O below is what
/// actually closes the race, and this check only rejects obviously unsafe
/// destinations early.
fn reject_link_components(path: &Path) -> Result<(), OpenError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        // A drive or UNC prefix and the root directory cannot be links and
        // cannot always be inspected on their own (for example `\\?\C:`).
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            continue;
        }
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(OpenError::Unsafe(
                    "output directory path must not contain symlinks; pass a resolved path",
                ));
            }
            Ok(metadata) => reject_reparse_point(&metadata)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(OpenError::Io(
                    "could not safely inspect the output directory path",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn reject_reparse_point(metadata: &std::fs::Metadata) -> Result<(), OpenError> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(OpenError::Unsafe(
            "output directory path must not contain symlinks; pass a resolved path",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &std::fs::Metadata) -> Result<(), OpenError> {
    Ok(())
}

/// Create the output directory by path (non-Unix platforms only; Unix walks
/// and creates components relative to descriptors instead).
#[cfg(not(unix))]
fn create_directory(path: &Path) -> Result<(), OpenError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .create(path)
        .map_err(|_| OpenError::Io("could not create the output directory"))
}

#[cfg(unix)]
mod imp {
    use super::{EXISTS_MESSAGE, OpenError, reject_link_components};

    use std::ffi::OsStr;
    use std::fs::File;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::{Component, Path};

    use rustix::fs::{AtFlags, FileType, Mode, OFlags};

    /// An opened output directory. Every file is created relative to the
    /// descriptor, so replacing the directory afterwards cannot redirect a
    /// write outside it.
    #[derive(Debug)]
    pub struct OutputDir {
        directory: OwnedFd,
    }

    fn to_io_error(errno: rustix::io::Errno) -> io::Error {
        io::Error::from_raw_os_error(errno.raw_os_error())
    }

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    fn open_component(parent: &OwnedFd, name: &OsStr) -> Result<OwnedFd, OpenError> {
        rustix::fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(
            |errno| match errno {
                rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                    OpenError::Unsafe("output must be a real directory, not a symlink")
                }
                _ => OpenError::Io("could not inspect the output directory"),
            },
        )
    }

    /// Walk `path` one component at a time, creating missing directories with
    /// mode `0700`, and return a descriptor for the final directory.
    fn walk_and_create(path: &Path) -> Result<OwnedFd, OpenError> {
        let mut current = rustix::fs::open(".", DIRECTORY_FLAGS, Mode::empty())
            .map_err(|_| OpenError::Io("could not inspect the output directory"))?;
        for component in path.components() {
            let name: &OsStr = match component {
                Component::RootDir => {
                    current = rustix::fs::open("/", DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|_| OpenError::Io("could not inspect the output directory"))?;
                    continue;
                }
                Component::CurDir => continue,
                Component::ParentDir => OsStr::new(".."),
                Component::Normal(name) => name,
                Component::Prefix(_) => {
                    return Err(OpenError::Unsafe("output directory path is not supported"));
                }
            };
            current = match open_component(&current, name) {
                Ok(next) => next,
                Err(OpenError::Io(_)) if !exists_at(&current, name) => {
                    rustix::fs::mkdirat(&current, name, Mode::RWXU)
                        .map_err(|_| OpenError::Io("could not create the output directory"))?;
                    open_component(&current, name)?
                }
                Err(error) => return Err(error),
            };
        }
        Ok(current)
    }

    fn exists_at(parent: &OwnedFd, name: &OsStr) -> bool {
        rustix::fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW).is_ok()
    }

    impl OutputDir {
        /// Open (creating if needed) the output directory without ever letting
        /// the kernel follow a symlink in any path component. Each component is
        /// opened relative to the previous descriptor with `O_NOFOLLOW`, so a
        /// component swapped for a link after the path-based pre-checks is
        /// rejected instead of being traversed.
        pub fn open(path: &Path) -> Result<Self, OpenError> {
            reject_link_components(path)?;
            let directory = walk_and_create(path)?;
            let stat = rustix::fs::fstat(&directory)
                .map_err(|_| OpenError::Io("could not inspect the output directory"))?;
            if !FileType::from_raw_mode(stat.st_mode).is_dir() {
                return Err(OpenError::Unsafe(
                    "output must be a real directory, not a symlink",
                ));
            }
            Ok(Self { directory })
        }

        /// Create one new file in the directory, failing if the name is taken.
        pub fn create_new_file(&self, name: &str) -> io::Result<File> {
            rustix::fs::openat(
                &self.directory,
                name,
                OFlags::CREATE | OFlags::EXCL | OFlags::WRONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR | Mode::WUSR,
            )
            .map(File::from)
            .map_err(to_io_error)
        }

        /// Create one new subdirectory and return a descriptor for it.
        ///
        /// The directory is made and reopened relative to this descriptor, so
        /// a nested extraction level cannot be redirected outside the tree.
        pub fn create_subdirectory(&self, name: &str) -> Result<Self, OpenError> {
            rustix::fs::mkdirat(&self.directory, name, Mode::RWXU).map_err(|errno| {
                match errno {
                    // The name was taken between the plan's existence check
                    // and this creation. That is the no-clobber rule doing its
                    // job, not an I/O failure: it is reported exactly as an
                    // existing output *file* is.
                    rustix::io::Errno::EXIST => OpenError::Exists(EXISTS_MESSAGE),
                    _ => OpenError::Io("could not create the output directory"),
                }
            })?;
            // A directory that was made but cannot be opened is removed again,
            // so a failure never leaves an unrecorded entry behind.
            match open_component(&self.directory, OsStr::new(name)) {
                Ok(directory) => Ok(Self { directory }),
                Err(error) => {
                    let _ = self.remove_directory(name);
                    Err(error)
                }
            }
        }

        /// Open one subdirectory, creating it only if it is not there.
        ///
        /// `create_subdirectory` above is for an extraction tree, where a name
        /// that already exists is a collision and must fail. A cache is the
        /// other case: `crls/` and `ocsp/` are expected to survive between
        /// runs, and two concurrent runs may both find them missing. The
        /// directory is still opened with `O_NOFOLLOW` relative to this
        /// descriptor, so an existing entry that is a symlink is refused
        /// rather than followed.
        pub fn open_or_create_subdirectory(&self, name: &str) -> Result<Self, OpenError> {
            let name = OsStr::new(name);
            match open_component(&self.directory, name) {
                Ok(directory) => Ok(Self { directory }),
                Err(OpenError::Io(_)) if !exists_at(&self.directory, name) => {
                    match rustix::fs::mkdirat(&self.directory, name, Mode::RWXU) {
                        // A concurrent run that won the race made it first,
                        // which is the outcome this wanted anyway.
                        Ok(()) | Err(rustix::io::Errno::EXIST) => {}
                        Err(_) => {
                            return Err(OpenError::Io("could not create the output directory"));
                        }
                    }
                    open_component(&self.directory, name).map(|directory| Self { directory })
                }
                Err(error) => Err(error),
            }
        }

        /// Read one file from the directory without following a final symlink.
        pub fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
            use std::io::Read as _;

            let file = rustix::fs::openat(
                &self.directory,
                name,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map(File::from)
            .map_err(to_io_error)?;
            let mut bytes = Vec::new();
            // Bounded by the caller, which only ever compares against material
            // it already holds.
            (&file)
                .take(super::MAX_COMPARED_BYTES)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        }

        /// Remove one file from the directory.
        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            rustix::fs::unlinkat(&self.directory, name, AtFlags::empty()).map_err(to_io_error)
        }

        /// Remove one empty subdirectory of this directory.
        pub fn remove_directory(&self, name: &str) -> io::Result<()> {
            rustix::fs::unlinkat(&self.directory, name, AtFlags::REMOVEDIR).map_err(to_io_error)
        }

        /// Report whether an entry with this name already exists, without
        /// following a final symlink.
        pub fn exists(&self, name: &str) -> io::Result<bool> {
            match rustix::fs::statat(&self.directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => Ok(true),
                Err(rustix::io::Errno::NOENT) => Ok(false),
                Err(errno) => Err(to_io_error(errno)),
            }
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{OpenError, create_directory, reject_link_components, reject_reparse_point};

    use std::fs::{File, OpenOptions};
    use std::io;
    use std::path::{Path, PathBuf};

    /// An output directory addressed by path. Descriptor-relative creation is
    /// not available here, so every write re-validates the path components.
    #[derive(Debug)]
    pub struct OutputDir {
        path: PathBuf,
    }

    impl OutputDir {
        pub fn open(path: &Path) -> Result<Self, OpenError> {
            reject_link_components(path)?;
            // Match the Unix walk, which reports an existing non-directory as
            // unsafe rather than as a creation failure.
            if let Ok(existing) = std::fs::symlink_metadata(path)
                && !existing.file_type().is_dir()
            {
                return Err(OpenError::Unsafe(
                    "output must be a real directory, not a symlink",
                ));
            }
            create_directory(path)?;
            reject_link_components(path)?;

            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| OpenError::Io("could not inspect the output directory"))?;
            reject_reparse_point(&metadata)?;
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                return Err(OpenError::Unsafe(
                    "output must be a real directory, not a symlink",
                ));
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }

        fn revalidate(&self) -> io::Result<()> {
            match reject_link_components(&self.path) {
                Ok(()) => Ok(()),
                Err(_) => Err(io::Error::other("unsafe output directory path")),
            }
        }

        pub fn create_new_file(&self, name: &str) -> io::Result<File> {
            self.revalidate()?;
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
        }

        pub fn create_subdirectory(&self, name: &str) -> Result<Self, OpenError> {
            self.revalidate()
                .map_err(|_| OpenError::Unsafe("output must be a real directory, not a symlink"))?;
            let path = self.path.join(name);
            std::fs::create_dir(&path).map_err(|error| match error.kind() {
                io::ErrorKind::AlreadyExists => OpenError::Exists(super::EXISTS_MESSAGE),
                _ => OpenError::Io("could not create the output directory"),
            })?;
            Self::open(&path)
        }

        pub fn open_or_create_subdirectory(&self, name: &str) -> Result<Self, OpenError> {
            self.revalidate()
                .map_err(|_| OpenError::Unsafe("output must be a real directory, not a symlink"))?;
            let path = self.path.join(name);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_dir() => return Self::open(&path),
                Ok(_) => {
                    return Err(OpenError::Unsafe(
                        "output must be a real directory, not a symlink",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(OpenError::Io("could not inspect the output directory")),
            }
            match std::fs::create_dir(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(OpenError::Io("could not create the output directory")),
            }
            Self::open(&path)
        }

        pub fn read_file(&self, name: &str) -> io::Result<Vec<u8>> {
            use std::io::Read as _;

            self.revalidate()?;
            let path = self.path.join(name);
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(io::Error::other("refusing to read through a symlink"));
            }
            super::reject_reparse_point(&metadata)
                .map_err(|_| io::Error::other("refusing to read through a reparse point"))?;
            let file = std::fs::File::open(&path)?;
            let mut bytes = Vec::new();
            file.take(super::MAX_COMPARED_BYTES)
                .read_to_end(&mut bytes)?;
            Ok(bytes)
        }

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            std::fs::remove_file(self.path.join(name))
        }

        pub fn remove_directory(&self, name: &str) -> io::Result<()> {
            std::fs::remove_dir(self.path.join(name))
        }

        pub fn exists(&self, name: &str) -> io::Result<bool> {
            match std::fs::symlink_metadata(self.path.join(name)) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(error),
            }
        }
    }
}

pub use imp::OutputDir;

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory under a fully resolved base path: `OutputDir`
    /// refuses a path containing a symlink, and the platform temporary
    /// directory is one on some systems.
    fn scratch() -> tempfile::TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory must resolve");
        tempfile::tempdir_in(base).expect("a temporary directory must be available")
    }

    /// The extraction plan checks that no output name is taken before
    /// anything is written, but the check and the creation cannot be one
    /// operation: another process can take the name in between. The `mkdir`
    /// that then fails with `EEXIST` is the no-clobber rule working, so it is
    /// reported as `output_exists` (exit 5) — the same answer an existing
    /// output *file* gets — and not as `io_error`, which would have told an
    /// operator their filesystem was broken.
    #[test]
    fn an_existing_subdirectory_name_is_reported_as_output_exists() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        std::fs::create_dir(temporary.path().join("court.dosszie.d"))
            .expect("the name is taken first");

        let error = directory
            .create_subdirectory("court.dosszie.d")
            .expect_err("the name is already taken");

        assert!(
            matches!(error, OpenError::Exists(_)),
            "an existing name is Exists, not {error:?}"
        );
        let reported = crate::response::CliError::from(error);
        assert_eq!(reported.code, "output_exists");
        assert_eq!(reported.exit, 5);
    }

    /// An existing *file* under the subdirectory's name is the same answer:
    /// the name is taken, whatever holds it.
    #[test]
    fn an_existing_file_under_the_subdirectory_name_is_output_exists_too() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        std::fs::write(temporary.path().join("taken.d"), b"x").expect("the name is taken first");

        let error = directory
            .create_subdirectory("taken.d")
            .expect_err("the name is already taken");

        assert_eq!(crate::response::CliError::from(error).code, "output_exists");
    }
}
