# Fixture and test-data policy

## Public fixtures

The repository will contain only synthetic, redistributable test dossiers.
They will be authored by this project, carry no personal/company data, and be
dedicated to the public domain (CC0-1.0) where that is legally effective.

Initial fixtures:

| Fixture | Purpose |
| --- | --- |
| `plain-base64.es3` | One unsigned UTF-8 text payload; baseline parsing, metadata, list, and extraction. |
| `zip-base64.es3` | One unsigned ZIP-compressed payload; transform reversal and ZIP limits. |
| malformed variants | Duplicate ID, unresolved `OBJREF`, invalid Base64, traversal title, unsupported encryption, and DOCTYPE cases. |

Limit cases that need large or binary-patched inputs (deep nesting, node
counts, ZIP size and ratio bombs, encrypted ZIP members, unsafe ZIP paths,
unsafe output names) are generated inside the test code rather than committed
as fixtures.

Synthetic dossiers must be labeled **unsigned test data**. They must never be
presented as authentic, qualified, or interoperable signature evidence.
The committed fixtures and their expected outcomes live under
`tests/fixtures/` and are dedicated under CC0-1.0.

## Real-world corpus

No real `.es3` or `.et3` dossiers may be committed to the public repository
unless their provenance, privacy status, and redistribution permission are
documented and approved. A developer may point an opt-in integration test at a
locally supplied fixture through an environment variable; the test must not
log the path, filename, contents, hashes, metadata, certificate subjects, or
signature values.

Public `.es3` samples were not located during initial research. This is not a
reason to scrape or republish dossiers from official filings: e-dossiers can
contain sensitive documents and are not automatically licensed for test-data
redistribution.

## Compatibility testing later

Before claiming compatibility beyond synthetic files, collect consented test
fixtures covering UTF-8 and ISO-8859-2 XML, document-level signatures,
dossier-level signatures, timestamps, document comments, multiple payloads,
ZIP, encryption markers, and custom compatible namespaces. Keep fixture
provenance and expected behavior in a private test-corpus manifest.

## Running tests

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

To run the privacy-preserving compatibility smoke test against a locally held
dossier, set `ES3_TEST_FIXTURE` for the test process. The test captures CLI
output and asserts aggregate success only; it does not print the value of the
variable or dossier-derived data:

```sh
ES3_TEST_FIXTURE=/private/path/input.es3 cargo test \
  -p openszigno-cli --test private_smoke
```

For a private recursive corpus, set `ES3_TEST_CORPUS_DIR`. The harness calls
the core library directly, bounds file and directory traversal, suppresses
panic payloads, and discards path-bearing I/O errors. Its only output is an
aggregate of file/document outcomes and stable error-code buckets:

```sh
ES3_TEST_CORPUS_DIR=/private/path/corpus cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_corpus_smoke \
  -- --nocapture
```

Neither private test logs paths, filenames, payloads, hashes, metadata,
certificate subjects, signer data, or signature values. The fixture smoke test
extracts into a temporary directory that is removed when the test finishes;
if the test process is killed, the extracted files remain under the system
temporary directory and must be removed by hand. A corpus failure
reports aggregate bucket counts only. Unsupported namespaces and malformed
non-dossiers remain visible as parse-error buckets but do not fail the harness;
infrastructure failures, panics, supported-payload decode failures, an empty
corpus, or zero supported dossiers do fail it.
