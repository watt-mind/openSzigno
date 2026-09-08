//! Writing a planned tree to disk, and undoing it when a write fails.

use std::io::{self, Write};

use serde_json::{Value, json};

use crate::extract::output_dir::OutputDir;
use crate::extract::plan::PlanDir;
use crate::response::CliError;

/// One entry this run created, so that a failure can undo it.
pub(crate) enum Undo {
    File(usize, String),
    Directory(usize, String),
}

/// Writes a planned tree, remembering what it created.
pub(crate) struct Writer {
    pub(crate) directories: Vec<OutputDir>,
    pub(crate) created: Vec<Undo>,
    pub(crate) extracted: Vec<Value>,
}

impl Writer {
    pub(crate) fn write_directory(
        &mut self,
        directory: usize,
        plan: &PlanDir,
    ) -> Result<(), CliError> {
        for entry in &plan.entries {
            let mut file = self.directories[directory]
                .create_new_file(&entry.file.name)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        CliError::unsafe_output(
                            "output_exists",
                            "an output file already exists or cannot be created safely",
                        )
                    } else {
                        CliError::io("could not create an output file")
                    }
                })?;
            self.created
                .push(Undo::File(directory, entry.file.name.clone()));
            file.write_all(&entry.file.bytes)
                .and_then(|()| file.flush())
                .map_err(|_| CliError::io("could not write an extracted document"))?;
            self.extracted.push(json!({
                "document_index": entry.file.document_index,
                "dossier_path": entry.file.dossier_path,
                "filename": entry.file.name,
                "path": entry.file.path,
                "bytes": entry.file.bytes.len(),
                "detected_type": entry.file.detected_type,
                "declared_type": entry.file.declared_type,
                "decrypted": entry.file.decrypted
            }));

            if let Some(nested) = &entry.subdirectory {
                let handle = self.directories[directory]
                    .create_subdirectory(&nested.name)
                    .map_err(CliError::from)?;
                self.created
                    .push(Undo::Directory(directory, nested.name.clone()));
                self.directories.push(handle);
                let child = self.directories.len() - 1;
                self.write_directory(child, nested)?;
            }
        }
        Ok(())
    }

    /// Undo everything this run created, deepest entry first, so a partial
    /// extraction is never left behind.
    ///
    /// Every recorded entry is attempted exactly once, in reverse creation
    /// order, even after an earlier removal fails: a directory that turns out
    /// non-empty (because a later file under it could not be removed) must
    /// not stop the files created before it, in other directories, from being
    /// cleaned up too.
    pub(crate) fn roll_back(&self, error: CliError) -> CliError {
        let mut removed = true;
        for entry in self.created.iter().rev() {
            let ok = match entry {
                Undo::File(directory, name) => {
                    self.directories[*directory].remove_file(name).is_ok()
                }
                Undo::Directory(directory, name) => {
                    self.directories[*directory].remove_directory(name).is_ok()
                }
            };
            removed &= ok;
        }
        if removed {
            return error;
        }
        CliError {
            code: error.code,
            message: format!("{}; some extracted files may remain", error.message),
            exit: error.exit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory under a fully resolved base path.
    ///
    /// `OutputDir` refuses a path containing a symlink, and the platform
    /// temporary directory is itself a symlink on some systems (macOS resolves
    /// `/var` to `/private/var`), so the base is canonicalized first.
    fn scratch() -> tempfile::TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory must resolve");
        tempfile::tempdir_in(base).expect("a temporary directory must be available")
    }

    /// A mid-run failure must not leave a half-extracted directory behind.
    #[test]
    fn roll_back_removes_the_files_and_directories_this_run_created() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let nested = directory
            .create_subdirectory("nested.d")
            .expect("subdirectory is created");
        for name in ["first.txt", "second.txt"] {
            let mut file = directory.create_new_file(name).expect("file is created");
            file.write_all(b"payload").expect("file is writable");
        }
        let mut inner = nested
            .create_new_file("inner.txt")
            .expect("file is created");
        inner.write_all(b"payload").expect("file is writable");

        let writer = Writer {
            directories: vec![directory, nested],
            created: vec![
                Undo::File(0, "first.txt".to_owned()),
                Undo::File(0, "second.txt".to_owned()),
                Undo::Directory(0, "nested.d".to_owned()),
                Undo::File(1, "inner.txt".to_owned()),
            ],
            extracted: Vec::new(),
        };
        let error = writer.roll_back(CliError::io("could not write an extracted document"));

        assert_eq!(error.code, "io_error");
        assert_eq!(error.message, "could not write an extracted document");
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("output directory is readable")
                .count(),
            0
        );
    }

    /// A failed cleanup keeps the code but says so, so a caller never assumes
    /// the destination is clean.
    #[test]
    fn roll_back_reports_that_files_may_remain() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let writer = Writer {
            directories: vec![directory],
            created: vec![Undo::File(0, "never-created.txt".to_owned())],
            extracted: Vec::new(),
        };

        let error = writer.roll_back(CliError::io("could not write an extracted document"));

        assert_eq!(error.code, "io_error");
        assert_eq!(error.exit, 3);
        assert!(error.message.ends_with("; some extracted files may remain"));
    }

    /// `roll_back` used to fold over the entries with `Iterator::all`, which
    /// short-circuits on the first `false` and never even calls the closure
    /// for what comes after. Recorded entries are undone in reverse creation
    /// order, so that bug meant: the moment the *last*-created entry failed
    /// to remove, every earlier entry was left on disk untouched. This forces
    /// exactly that: the last-created (so first-undone) entry never actually
    /// exists, and asserts the two real files created before it are still
    /// removed.
    #[test]
    fn roll_back_keeps_removing_after_an_early_reverse_order_failure() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        for name in ["first.txt", "second.txt"] {
            let mut file = directory.create_new_file(name).expect("file is created");
            file.write_all(b"payload").expect("file is writable");
        }
        // Recorded as created, but never actually written: its removal fails
        // and, in reverse order, fails first.
        let writer = Writer {
            directories: vec![directory],
            created: vec![
                Undo::File(0, "first.txt".to_owned()),
                Undo::File(0, "second.txt".to_owned()),
                Undo::File(0, "never-created.txt".to_owned()),
            ],
            extracted: Vec::new(),
        };

        let error = writer.roll_back(CliError::io("could not write an extracted document"));

        assert!(error.message.ends_with("; some extracted files may remain"));
        for name in ["first.txt", "second.txt"] {
            assert!(
                !temporary.path().join(name).exists(),
                "{name} must still be removed despite the earlier-undone entry failing"
            );
        }
    }

    /// The same, but forced with a real filesystem failure instead of a
    /// never-created file: a non-empty directory refuses to remove on every
    /// platform, and it is the last entry undone (first attempted, since undo
    /// walks in reverse) while the directory it holds a file it does not
    /// track was itself created earlier and must still be removed.
    #[cfg(unix)]
    #[test]
    fn roll_back_keeps_removing_after_a_real_removal_failure() {
        let temporary = scratch();
        let directory = OutputDir::open(temporary.path()).expect("output directory opens");
        let mut first = directory
            .create_new_file("first.txt")
            .expect("file is created");
        first.write_all(b"payload").expect("file is writable");
        let nested = directory
            .create_subdirectory("nested.d")
            .expect("subdirectory is created");
        // A file this run did not track, left inside the recorded directory,
        // so removing the directory fails with a real ENOTEMPTY.
        std::fs::write(
            temporary.path().join("nested.d").join("untracked.txt"),
            b"x",
        )
        .expect("the untracked file is written");

        let writer = Writer {
            directories: vec![directory, nested],
            created: vec![
                Undo::File(0, "first.txt".to_owned()),
                Undo::Directory(0, "nested.d".to_owned()),
            ],
            extracted: Vec::new(),
        };

        let error = writer.roll_back(CliError::io("could not write an extracted document"));

        assert!(error.message.ends_with("; some extracted files may remain"));
        assert!(
            !temporary.path().join("first.txt").exists(),
            "first.txt must still be removed despite the directory removal failing"
        );
        assert!(
            temporary.path().join("nested.d").exists(),
            "the non-empty directory is the one expected to remain"
        );
    }
}
