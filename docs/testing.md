# Testing, fixtures, and test-data policy

## Test layout

| Location | Kind | What it covers |
| --- | --- | --- |
| `crates/openszigno-core/src/*.rs` (`#[cfg(test)]`) | Unit tests | Internals that are not reachable through the public API, such as the pre-parse scan's depth and node counting, comment/CDATA/processing-instruction handling, and truncated-markup tolerance. |
| `crates/openszigno-core/tests/*.rs` | Core integration tests | The public `parse` and `decode_document` API, split by concern: structural parsing rules, XML decoding and encodings, bounded payload decoding (transform chains, Base64 and ZIP limits, ZIP bombs, unsafe members), and the stable public surface of codes, limits, and serialised types. Shared builders for synthetic dossiers live in `tests/common/mod.rs`. |
| `crates/openszigno-cli/src/main.rs` (`#[cfg(test)]`) | Unit tests | CLI internals, currently the roll-back of files created by a failed extraction. |
| `crates/openszigno-cli/tests/cli.rs` | CLI integration tests | The built binary, run as a subprocess: the JSON envelope for every command, human-mode output and its verification-boundary lines, exit statuses, unsafe output names and Unicode collisions, symlinked output directories and intermediate components, file modes, closed stdout, and JSON usage errors. |
| `crates/openszigno-cli/tests/private_smoke.rs` | Private opt-in tests | Compatibility smoke tests against locally held real dossiers. They do nothing unless the relevant environment variable is set. |
| `tests/fixtures/` | Fixture data | Synthetic, unsigned, CC0-dedicated `.es3` files used by both integration suites. |

The CLI integration tests exercise the real binary rather than calling library
functions, because the JSON envelope, exit statuses, and stdout/stderr split
are part of the public contract and can only be checked end to end.

## Running the tests

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Coverage

Coverage is measured with `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov
cargo llvm-cov --workspace
```

For a browsable report, or for an LCOV file to upload from CI:

```sh
cargo llvm-cov --workspace --html
cargo llvm-cov --workspace --lcov --output-path lcov.info
```

Coverage runs must never be pointed at the private corpus: the opt-in tests
stay inert unless their environment variables are set, so leave them unset.

## Public fixtures

The repository contains only synthetic, redistributable test dossiers. They
were authored by this project, carry no personal or company data, and are
dedicated to the public domain (CC0-1.0) where that is legally effective.

| Fixture | Purpose |
| --- | --- |
| `plain-base64.es3` | One unsigned UTF-8 text payload; baseline parsing, metadata, list, and extraction. |
| `zip-base64.es3` | One unsigned ZIP-compressed payload; transform reversal and ZIP limits. |
| `duplicate-id.es3` | Rejected as `duplicate_id`. |
| `unresolved-objref.es3` | Rejected as `unresolved_objref`. |
| `invalid-base64.es3` | Parses structurally; extraction rejects `invalid_base64`. |
| `traversal-title.es3` | Parses structurally; extraction rejects `unsafe_output_name`. |
| `encrypted.es3` | Parses and reports the document as encrypted and unsupported. |
| `doctype.es3` | Rejected as `unsafe_xml`. |

Limit cases that need large or binary-patched inputs (deep nesting, node
counts, ZIP size and ratio bombs, encrypted ZIP members, unsafe ZIP paths,
unsafe output names) are generated inside the test code rather than committed
as fixtures.

Synthetic dossiers are **unsigned test data**. They must never be presented as
authentic, qualified, or interoperable signature evidence. The fixtures and
their expected outcomes live under `tests/fixtures/`; see
`tests/fixtures/README.md`.

## Real-world corpus

No real `.es3` or `.et3` dossier may be committed to the public repository
unless its provenance, privacy status, and redistribution permission are
documented and approved. A developer may point an opt-in integration test at a
locally supplied file through an environment variable; the test must not log
the path, filename, contents, hashes, metadata, certificate subjects, or
signature values.

Public `.es3` samples were not located during initial research. That is not a
reason to scrape or republish dossiers from official filings: e-dossiers can
contain sensitive documents and are not automatically licensed for test-data
redistribution.

## Private opt-in smoke tests

Both tests below are no-ops when their environment variable is unset, so they
are safe to leave in the default `cargo test --workspace` run.

Single fixture. The test runs the CLI, captures its output, and asserts
aggregate success only; it never prints the variable's value or any
dossier-derived data:

```sh
ES3_TEST_FIXTURE=/private/path/input.es3 cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_fixture_smoke
```

Recursive corpus. The harness calls the core library directly, bounds file and
directory traversal, suppresses panic payloads, and discards path-bearing I/O
errors. Its only output is an aggregate of file and document outcomes and
stable error-code buckets:

```sh
ES3_TEST_CORPUS_DIR=/private/path/corpus cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_corpus_smoke \
  -- --nocapture
```

Neither test logs paths, filenames, payloads, hashes, metadata, certificate
subjects, signer data, or signature values. The fixture smoke test extracts
into a temporary directory that is removed when the test finishes; if the test
process is killed, the extracted files remain under the system temporary
directory and must be removed by hand.

A corpus failure reports aggregate bucket counts only. Unsupported namespaces
and malformed non-dossiers remain visible as parse-error buckets but do not
fail the harness; infrastructure failures, panics, supported-payload decode
failures, an empty corpus, or zero supported dossiers do fail it.

The maintainer rules for handling that corpus, including how to report
findings, are in [roadmap.md](roadmap.md#private-corpus-policy-for-maintainers).

## Compatibility testing later

Before claiming compatibility beyond synthetic files, collect consented test
fixtures covering UTF-8 and ISO-8859-2 XML, document-level signatures,
dossier-level signatures, timestamps, document comments, multiple payloads,
ZIP, encryption markers, and custom compatible namespaces. Keep fixture
provenance and expected behaviour in a private test-corpus manifest.
