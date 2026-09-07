use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use openszigno_core::{DecodeOutcome, ErrorCode, Limits, UnsupportedReason};
use tempfile::tempdir;

static PANIC_HOOK_LOCK: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct CorpusAggregate {
    files: u64,
    parsed: u64,
    documents: u64,
    decoded: u64,
    encrypted: u64,
    unsupported_transform: u64,
    parse_errors: BTreeMap<&'static str, u64>,
    decode_errors: BTreeMap<&'static str, u64>,
    infrastructure_errors: BTreeMap<&'static str, u64>,
    panics: u64,
}

impl CorpusAggregate {
    fn record(map: &mut BTreeMap<&'static str, u64>, code: &'static str) {
        *map.entry(code).or_default() += 1;
    }

    fn render(&self) -> String {
        format!(
            "files={} parsed={} documents={} decoded={} encrypted={} \
             unsupported_transform={} parse_errors={} decode_errors={} \
             infrastructure_errors={} panics={}",
            self.files,
            self.parsed,
            self.documents,
            self.decoded,
            self.encrypted,
            self.unsupported_transform,
            render_buckets(&self.parse_errors),
            render_buckets(&self.decode_errors),
            render_buckets(&self.infrastructure_errors),
            self.panics,
        )
    }

    fn is_success(&self) -> bool {
        self.files > 0
            && self.parsed > 0
            && self.decode_errors.is_empty()
            && self.infrastructure_errors.is_empty()
            && self.panics == 0
    }
}

fn render_buckets(buckets: &BTreeMap<&'static str, u64>) -> String {
    if buckets.is_empty() {
        return "none".to_owned();
    }
    buckets
        .iter()
        .map(|(code, count)| format!("{code}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[test]
fn opt_in_private_fixture_smoke() {
    let Some(fixture) = std::env::var_os("ES3_TEST_FIXTURE") else {
        return;
    };

    // Held for the whole test: the corpus test replaces the process-wide panic
    // hook, and a panic here must not be swallowed by it (or leak a path).
    let _panic_hook_guard = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Resolve symlinks (e.g. macOS /var -> /private/var in TMPDIR): the tool
    // rejects symlinked output components by design. Aggregate-only handling.
    let _output_directory = tempdir().expect("temporary output directory must be available");
    let output_directory = _output_directory
        .path()
        .canonicalize()
        .expect("temporary output path resolves");
    let commands = ["inspect", "list", "validate-structure"];
    for command in commands {
        let output = Command::new(env!("CARGO_BIN_EXE_openszigno"))
            .arg(command)
            .arg(&fixture)
            .arg("--json")
            .output()
            .expect("private smoke command must start");
        assert!(output.status.success(), "private aggregate command failed");
        let response: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("private result must be JSON");
        assert_eq!(response["ok"], true, "private aggregate parse failed");
        assert!(response["input"]["bytes"].as_u64().is_some());
    }

    let output = Command::new(env!("CARGO_BIN_EXE_openszigno"))
        .arg("extract")
        .arg(&fixture)
        .arg("--output")
        .arg(&output_directory)
        .arg("--json")
        .output()
        .expect("private extraction smoke must start");
    assert!(
        output.status.success(),
        "private aggregate extraction failed"
    );
    let response: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("private extraction result must be JSON");
    assert_eq!(response["ok"], true, "private aggregate extraction failed");
    let extracted = response["data"]["extracted_count"]
        .as_u64()
        .expect("private extraction count must be numeric");
    assert!(
        extracted > 0,
        "private fixture had no extractable documents"
    );
    let files_written = std::fs::read_dir(&output_directory)
        .expect("private temporary output must be readable")
        .filter(|entry| {
            entry
                .as_ref()
                .ok()
                .and_then(|entry| entry.file_type().ok())
                .is_some_and(|file_type| file_type.is_file())
        })
        .count() as u64;
    assert_eq!(
        files_written, extracted,
        "private aggregate output mismatch"
    );
}

#[test]
fn opt_in_private_corpus_smoke() {
    let Some(root) = std::env::var_os("ES3_TEST_CORPUS_DIR") else {
        return;
    };

    let _panic_hook_guard = PANIC_HOOK_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));

    let result = std::panic::catch_unwind(|| audit_corpus(Path::new(&root)));
    std::panic::set_hook(previous_hook);

    let aggregate = match result {
        Ok(aggregate) => aggregate,
        Err(_) => CorpusAggregate {
            panics: 1,
            ..CorpusAggregate::default()
        },
    };
    let report = aggregate.render();
    println!("private corpus aggregate: {report}");
    assert!(
        aggregate.is_success(),
        "private corpus aggregate failed: {report}"
    );
}

fn audit_corpus(root: &Path) -> CorpusAggregate {
    let limits = Limits::default();
    let mut aggregate = CorpusAggregate::default();
    let files = collect_corpus_files(root, &mut aggregate);

    for path in files {
        aggregate.files += 1;
        let Some(bytes) = read_bounded(&path, &limits, &mut aggregate) else {
            continue;
        };
        let dossier = match openszigno_core::parse(&bytes, &limits) {
            Ok(dossier) => dossier,
            Err(error) => {
                CorpusAggregate::record(&mut aggregate.parse_errors, error.code().as_str());
                continue;
            }
        };
        aggregate.parsed += 1;
        aggregate.documents += dossier.documents.len() as u64;

        for document in &dossier.documents {
            match dossier.decode_document(document.index, &limits) {
                Ok(DecodeOutcome::Decoded(_)) => aggregate.decoded += 1,
                Ok(DecodeOutcome::Unsupported(UnsupportedReason::Encrypted)) => {
                    aggregate.encrypted += 1;
                }
                Ok(DecodeOutcome::Unsupported(UnsupportedReason::TransformChain)) => {
                    aggregate.unsupported_transform += 1;
                }
                Err(error) => {
                    CorpusAggregate::record(&mut aggregate.decode_errors, error.code().as_str());
                }
            }
        }
    }

    aggregate
}

fn collect_corpus_files(root: &Path, aggregate: &mut CorpusAggregate) -> Vec<PathBuf> {
    const MAX_DIRECTORIES: usize = 10_000;
    const MAX_DEPTH: usize = 32;

    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(_) => {
            CorpusAggregate::record(
                &mut aggregate.infrastructure_errors,
                "corpus_root_unreadable",
            );
            return Vec::new();
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        CorpusAggregate::record(
            &mut aggregate.infrastructure_errors,
            "corpus_root_not_directory",
        );
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut directories = vec![(root.to_path_buf(), 0usize)];
    let mut visited = 0usize;
    while let Some((directory, depth)) = directories.pop() {
        visited += 1;
        if visited > MAX_DIRECTORIES {
            CorpusAggregate::record(&mut aggregate.infrastructure_errors, "directory_limit");
            break;
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => {
                CorpusAggregate::record(
                    &mut aggregate.infrastructure_errors,
                    "directory_unreadable",
                );
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => {
                    CorpusAggregate::record(
                        &mut aggregate.infrastructure_errors,
                        "entry_unreadable",
                    );
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => {
                    CorpusAggregate::record(
                        &mut aggregate.infrastructure_errors,
                        "entry_type_unreadable",
                    );
                    continue;
                }
            };
            if file_type.is_symlink() {
                CorpusAggregate::record(&mut aggregate.infrastructure_errors, "symlink_ignored");
            } else if file_type.is_dir() {
                if depth >= MAX_DEPTH {
                    CorpusAggregate::record(&mut aggregate.infrastructure_errors, "depth_limit");
                } else {
                    directories.push((entry.path(), depth + 1));
                }
            } else if file_type.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("es3"))
            {
                files.push(entry.path());
            }
        }
    }
    files
}

fn read_bounded(path: &Path, limits: &Limits, aggregate: &mut CorpusAggregate) -> Option<Vec<u8>> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => {
            CorpusAggregate::record(
                &mut aggregate.infrastructure_errors,
                "input_not_regular_file",
            );
            return None;
        }
        Err(_) => {
            CorpusAggregate::record(
                &mut aggregate.infrastructure_errors,
                "input_metadata_unreadable",
            );
            return None;
        }
    };
    if metadata.len() > limits.max_input_bytes {
        CorpusAggregate::record(
            &mut aggregate.parse_errors,
            ErrorCode::InputTooLarge.as_str(),
        );
        return None;
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            CorpusAggregate::record(&mut aggregate.infrastructure_errors, "input_unreadable");
            return None;
        }
    };
    let mut bytes = Vec::with_capacity(metadata.len().min(usize::MAX as u64) as usize);
    if file
        .take(limits.max_input_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        CorpusAggregate::record(&mut aggregate.infrastructure_errors, "input_read_failed");
        return None;
    }
    Some(bytes)
}
