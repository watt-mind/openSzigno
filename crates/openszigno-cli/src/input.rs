//! The one bounded reader every command takes its input through, the bounded
//! reader every other caller-supplied file is read with, and the `InputInfo`
//! block the JSON envelope reports about it.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use openszigno_core::{Dossier, Limits, ParseOptions};
use serde::Serialize;

use crate::response::{CliError, Failure, failure};

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InputInfo {
    pub(crate) format: Option<&'static str>,
    pub(crate) bytes: Option<u64>,
}

/// The one bounded reader every command takes its input through.
///
/// `path` is either a regular file or `-`, which means standard input. Both
/// paths read at most `max_input_bytes + 1` bytes and reject the input when
/// that many arrive, so the cap holds without trusting filesystem metadata —
/// which a pipe has none of, and which a file can change under us anyway. The
/// whole dossier is buffered in memory either way; that is inherent to the
/// format, whose XML must be parsed as one tree.
fn read_input(path: &Path, limits: &Limits) -> Result<Vec<u8>, Failure> {
    let unknown = || InputInfo {
        format: None,
        bytes: None,
    };
    if path != Path::new("-") {
        return read_bounded_file_following_links(path, limits.max_input_bytes).map_err(|error| {
            match error {
                BoundedReadError::Inspect => {
                    failure(unknown(), CliError::io("could not inspect the input file"))
                }
                BoundedReadError::NotRegular => {
                    failure(unknown(), CliError::io("input is not a regular file"))
                }
                BoundedReadError::TooLarge { declared } => failure(
                    InputInfo {
                        format: None,
                        bytes: declared,
                    },
                    too_large(limits),
                ),
                BoundedReadError::Read => {
                    failure(unknown(), CliError::io("could not read the input"))
                }
            }
        });
    }

    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(limits.max_input_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| failure(unknown(), CliError::io("could not read the input")))?;
    if bytes.len() as u64 > limits.max_input_bytes {
        // The true size is unknown: reading stopped one byte past the cap. The
        // envelope says so rather than reporting the truncated length as if it
        // were the input size.
        return Err(failure(unknown(), too_large(limits)));
    }
    Ok(bytes)
}

/// Why a bounded read refused. Each caller words its own message: the kinds
/// of file this tool reads are told apart in what an operator is told, never
/// in how they are read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedReadError {
    /// The path could not be opened or its type could not be established.
    Inspect,
    /// The open descriptor is not a regular file: a directory, a device, or a
    /// symlink, which is refused rather than followed. No size is carried:
    /// a directory's own length is not a byte count of anything a caller
    /// asked for, and what it would report differs between platforms.
    NotRegular,
    /// More bytes than the cap allows. `declared` is the size the open
    /// descriptor reported when that is what refused it, and `None` when the
    /// file grew past the cap while it was being read, where the true size is
    /// not something this process ever learned.
    TooLarge { declared: Option<u64> },
    /// The bytes could not be read.
    Read,
}

/// Read one caller-supplied file, at most `limit` bytes of it.
///
/// The file is opened **once** and every check is made against that one open
/// descriptor: `O_NOFOLLOW` on Unix, so a symlink is refused by the kernel
/// rather than followed, the type and size come from `fstat` on the
/// descriptor, and the bytes are read through `Read::take(limit + 1)` so the
/// cap holds on the bytes that actually arrived. Nothing is decided on
/// metadata read from the path separately, because a path can be replaced or
/// a file grown between such a check and the read that follows it.
pub(crate) fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    read_bounded(open_without_following(path)?, limit)
}

/// Whether a path may be opened through a final symlink.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Links {
    /// Refuse a final symlink (`O_NOFOLLOW`). Everything but the dossier.
    Refuse,
    /// Resolve a final symlink. The dossier the caller named itself.
    Follow,
}

/// Read one caller-supplied file the same way, but resolving a symlink on the
/// path rather than refusing it.
///
/// This is for the dossier the caller named on the command line, which has
/// always been readable through a link and where the link is the caller's own.
/// Every other check is the one above: one open, one `fstat` on that
/// descriptor, and a cap on the bytes that arrived.
pub(crate) fn read_bounded_file_following_links(
    path: &Path,
    limit: u64,
) -> Result<Vec<u8>, BoundedReadError> {
    read_bounded(open_following(path)?, limit)
}

fn read_bounded(mut file: File, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let metadata = file.metadata().map_err(|_| BoundedReadError::Inspect)?;
    if !metadata.is_file() {
        return Err(BoundedReadError::NotRegular);
    }
    // The open above is non-blocking on Unix, so that naming a FIFO cannot
    // park the process before the type check above ever runs. A regular file
    // is read blocking, which is what `read_to_end` expects, so the flag is
    // cleared now that the descriptor is known to be one.
    clear_nonblocking(&file)?;
    let declared = metadata.len();
    if declared > limit {
        return Err(BoundedReadError::TooLarge {
            declared: Some(declared),
        });
    }
    let mut bytes = Vec::with_capacity(declared.min(1024 * 1024) as usize);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| BoundedReadError::Read)?;
    if bytes.len() as u64 > limit {
        return Err(BoundedReadError::TooLarge { declared: None });
    }
    Ok(bytes)
}

/// Open a file for reading without resolving a final symlink.
///
/// On Unix that is `O_NOFOLLOW`, which fails with `ELOOP` on a symlink;
/// `ELOOP` and `ENOTDIR` are reported as [`BoundedReadError::NotRegular`], so
/// a caller that walks a directory skips such an entry exactly as it skipped
/// it before. On Windows the file is opened with
/// `FILE_FLAG_OPEN_REPARSE_POINT`, which opens the reparse point itself, and
/// the `fstat` that follows then refuses it for not being a regular file.
fn open_without_following(path: &Path) -> Result<File, BoundedReadError> {
    open_for_read(path, Links::Refuse)
}

/// The same, resolving a final symlink rather than refusing it.
fn open_following(path: &Path) -> Result<File, BoundedReadError> {
    open_for_read(path, Links::Follow)
}

/// Open a caller-named path for reading, non-blocking.
///
/// `O_NONBLOCK` is the point of this function on Unix. Without it, naming a
/// FIFO parks the process inside `open(2)` until somebody opens the other end
/// — which the caller controls and this tool does not — so the "is it a
/// regular file?" check below could never run, and a `--decrypt-key` or an
/// input path pointed at a FIFO would hang instead of being refused. With it
/// the open returns at once, `fstat` refuses the FIFO as not a regular file,
/// and [`clear_nonblocking`] puts the descriptor back into blocking mode
/// before a single byte is read. On a regular file the flag changes nothing.
#[cfg(unix)]
fn open_for_read(path: &Path, links: Links) -> Result<File, BoundedReadError> {
    use rustix::fs::{Mode, OFlags};
    use rustix::io::Errno;

    let mut flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
    if links == Links::Refuse {
        flags |= OFlags::NOFOLLOW;
    }
    match rustix::fs::open(path, flags, Mode::empty()) {
        Ok(descriptor) => Ok(File::from(descriptor)),
        Err(Errno::LOOP | Errno::NOTDIR) if links == Links::Refuse => {
            Err(BoundedReadError::NotRegular)
        }
        // `O_NONBLOCK` on a device with no reader or writer on the other end
        // is refused rather than parked; it is not a regular file either way.
        Err(Errno::NXIO) => Err(BoundedReadError::NotRegular),
        Err(_) => Err(BoundedReadError::Inspect),
    }
}

/// On Windows the order is the one this module has always used: `std`'s open,
/// then the `fstat` that follows refuses anything that is not a regular file.
/// There is no `O_NONBLOCK` to ask for, and a named pipe is not opened by the
/// path syntax an operator passes here.
#[cfg(windows)]
fn open_for_read(path: &Path, links: Links) -> Result<File, BoundedReadError> {
    use std::os::windows::fs::OpenOptionsExt as _;

    /// `FILE_FLAG_OPEN_REPARSE_POINT`: open the link, never its target.
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    if links == Links::Refuse {
        options.custom_flags(OPEN_REPARSE_POINT);
    }
    options.open(path).map_err(|_| BoundedReadError::Inspect)
}

#[cfg(not(any(unix, windows)))]
fn open_for_read(path: &Path, _links: Links) -> Result<File, BoundedReadError> {
    File::open(path).map_err(|_| BoundedReadError::Inspect)
}

/// Put a descriptor opened with `O_NONBLOCK` back into blocking mode.
#[cfg(unix)]
fn clear_nonblocking(file: &File) -> Result<(), BoundedReadError> {
    use rustix::fs::OFlags;

    let flags = rustix::fs::fcntl_getfl(file).map_err(|_| BoundedReadError::Inspect)?;
    rustix::fs::fcntl_setfl(file, flags & !OFlags::NONBLOCK).map_err(|_| BoundedReadError::Inspect)
}

#[cfg(not(unix))]
fn clear_nonblocking(_file: &File) -> Result<(), BoundedReadError> {
    Ok(())
}

fn too_large(limits: &Limits) -> CliError {
    CliError::invalid(
        "input_too_large",
        format!("input exceeds {} bytes", limits.max_input_bytes),
    )
}

pub(crate) fn load(path: &Path, options: &ParseOptions) -> Result<(Vec<u8>, Dossier), Failure> {
    let bytes = read_input(path, &options.limits)?;
    let dossier = openszigno_core::parse_with_options(&bytes, options).map_err(|error| {
        failure(
            InputInfo {
                format: None,
                bytes: Some(bytes.len() as u64),
            },
            CliError::structure(error),
        )
    })?;
    Ok((bytes, dossier))
}

pub(crate) fn valid_input(bytes: usize) -> InputInfo {
    InputInfo {
        format: Some("microsec-es3"),
        bytes: Some(bytes as u64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file of exactly the cap is read in full: the limit is inclusive, and
    /// a store or a key sized to the documented maximum still loads.
    #[test]
    fn a_file_exactly_at_the_cap_is_read() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("at-the-cap");
        std::fs::write(&path, vec![b'x'; 64]).expect("the file is written");
        let bytes = read_bounded_file(&path, 64).expect("the file is at the cap, not over it");
        assert_eq!(bytes.len(), 64);
    }

    #[test]
    fn a_file_over_the_cap_is_refused_with_the_size_it_reported() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("over-the-cap");
        std::fs::write(&path, vec![b'x'; 65]).expect("the file is written");
        assert_eq!(
            read_bounded_file(&path, 64),
            Err(BoundedReadError::TooLarge { declared: Some(65) })
        );
    }

    /// The cap is enforced on the bytes that arrive, not on the size the
    /// descriptor reported, so a file whose length is not the truth is still
    /// bounded. A `/proc` file is the portable-enough stand-in on Linux: it
    /// is a regular file that reports a length of zero and then delivers
    /// content, exactly as a file grown between the `fstat` and the read
    /// would.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_whose_reported_size_is_not_the_truth_is_still_bounded() {
        let path = Path::new("/proc/self/cmdline");
        if !path.exists() {
            return;
        }
        assert_eq!(
            std::fs::metadata(path).expect("the file stats").len(),
            0,
            "the stand-in only works while /proc reports a zero length"
        );
        assert_eq!(
            read_bounded_file(path, 0),
            Err(BoundedReadError::TooLarge { declared: None })
        );
        // And a cap the content fits inside still reads it.
        assert!(
            !read_bounded_file(path, 4096)
                .expect("the content reads")
                .is_empty()
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_refused_rather_than_followed() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let target = directory.path().join("target");
        std::fs::write(&target, b"secret").expect("the file is written");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).expect("the symlink is created");

        assert_eq!(
            read_bounded_file(&link, 1024),
            Err(BoundedReadError::NotRegular)
        );
        // The same link is readable when links are deliberately followed,
        // which is what the dossier path does and nothing else does.
        assert_eq!(
            read_bounded_file_following_links(&link, 1024).expect("the link resolves"),
            b"secret".to_vec()
        );
    }

    #[test]
    fn a_directory_is_not_a_file_to_read() {
        let directory = tempfile::tempdir().expect("a temporary directory");
        let error =
            read_bounded_file(directory.path(), 1024).expect_err("a directory is not a file");
        assert!(matches!(
            error,
            BoundedReadError::NotRegular | BoundedReadError::Inspect
        ));
    }

    #[test]
    fn a_missing_file_is_an_inspect_failure() {
        assert_eq!(
            read_bounded_file(Path::new("/nonexistent/openszigno/input.es3"), 1024),
            Err(BoundedReadError::Inspect)
        );
    }
}
