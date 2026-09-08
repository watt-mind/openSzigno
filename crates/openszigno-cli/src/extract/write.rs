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
    pub(crate) fn roll_back(&self, error: CliError) -> CliError {
        let removed = self.created.iter().rev().all(|entry| match entry {
            Undo::File(directory, name) => self.directories[*directory].remove_file(name).is_ok(),
            Undo::Directory(directory, name) => {
                self.directories[*directory].remove_directory(name).is_ok()
            }
        });
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
}
