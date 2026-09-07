//! Race-resistant creation of extraction output files.
//!
//! Checking the output directory by path and then opening every file by full
//! path is a time-of-check/time-of-use bug: another process can replace the
//! directory with a symlink between the two steps. On Unix the directory is
//! therefore opened once with `O_DIRECTORY | O_NOFOLLOW` and every output file
//! is created relative to that descriptor. On other platforms the path-based
//! no-clobber approach is kept, hardened with an explicit reparse-point
//! (symlink and junction) rejection for every path component.

use std::io;
use std::path::Path;

/// Why an output directory could not be prepared.
///
/// The messages are stable strings and never contain a path.
#[derive(Debug)]
pub enum OpenError {
    /// The output path is not a real directory (symlink, junction, ...).
    Unsafe(&'static str),
    /// The output directory could not be created or inspected.
    Io(&'static str),
}

/// Reject a path whose components are, or contain, links.
///
/// This is defence in depth: on Unix the descriptor-relative I/O below is what
/// actually closes the race, and this check only rejects obviously unsafe
/// destinations early.
fn reject_link_components(path: &Path) -> Result<(), OpenError> {
    let mut current = std::path::PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(OpenError::Unsafe(
                    "output directory path must not contain symlinks",
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
            "output directory path must not contain symlinks",
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_metadata: &std::fs::Metadata) -> Result<(), OpenError> {
    Ok(())
}

/// Create the output directory, without following links.
///
/// Directories created by this run are private to the user; directories that
/// already exist keep their own mode.
fn create_directory(path: &Path) -> Result<(), OpenError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| OpenError::Io("could not create the output directory"))
}

#[cfg(unix)]
mod imp {
    use super::{OpenError, create_directory, reject_link_components};

    use std::fs::File;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::Path;

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

    impl OutputDir {
        pub fn open(path: &Path) -> Result<Self, OpenError> {
            reject_link_components(path)?;
            create_directory(path)?;
            reject_link_components(path)?;

            let directory = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|errno| match errno {
                rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => {
                    OpenError::Unsafe("output must be a real directory, not a symlink")
                }
                _ => OpenError::Io("could not inspect the output directory"),
            })?;
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

        /// Remove one file from the directory.
        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            rustix::fs::unlinkat(&self.directory, name, AtFlags::empty()).map_err(to_io_error)
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

        pub fn remove_file(&self, name: &str) -> io::Result<()> {
            std::fs::remove_file(self.path.join(name))
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
