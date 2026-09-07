# Testing, fixtures, and test-data policy

## Test layout

| Location | Kind | What it covers |
| --- | --- | --- |
| `crates/openszigno-core/src/*.rs` (`#[cfg(test)]`) | Unit tests | Internals that are not reachable through the public API, such as the pre-parse scan's depth and node counting, comment/CDATA/processing-instruction handling, and truncated-markup tolerance. |
| `crates/openszigno-core/tests/*.rs` | Core integration tests | The public `parse` and `decode_document` API, split by concern: structural parsing rules, XML decoding and encodings, bounded payload decoding (transform chains, Base64 and ZIP limits, ZIP bombs, unsafe members), namespace policy with structural warnings and nested-dossier detection, content sniffing, and the stable public surface of codes, limits, and serialised types. Shared builders for synthetic dossiers live in `tests/common/mod.rs`. |
| `crates/openszigno-verify/tests/c14n.rs` | Canonicalization tests | Canonical XML 1.0 and Exclusive C14N 1.0 against hand-computed canonical forms: the W3C specification's processing-instruction and start-tag examples, namespace scope for a document subset, `xml:*` attribute inheritance, default-namespace undeclaration, escaping, comments and CDATA, source-prefix fidelity, and subtree exclusion. Byte-for-byte comparisons: a canonicalizer that quietly drifts is worse than one that refuses. |
| `crates/openszigno-verify/tests/verify.rs` | Verification integration tests | Every check code with a positive and a negative case: document- and dossier-level signatures, ECDSA and enveloped signatures, digest and signature-value tampering, external and unresolved references, XSLT and XPath transforms, SHA-1 and HMAC methods, RSA-1024, missing `ds:KeyInfo`, reference-scope omissions, wrapping attempts, untrusted and expired chains, key-usage, basic-constraints, path-length and name-constraint violations, the report shape, and the rule that no message quotes signer data. |
| `crates/openszigno-verify/tests/vectors.rs` | Independent vectors | Material openSzigno did not produce: canonical forms transcribed from Canonical XML 1.0 (whitespace, character modifications, UTF-8 encoding) and Exclusive XML Canonicalization 1.0 (re-enveloping), and a complete signed dossier from `tests/fixtures/xmldsig/` whose digests and signature value were computed by OpenSSL and Python over hand-written canonical octets. Every other suite signs with the helper that shares the canonicalizer under test; these do not. |
| `crates/openszigno-verify/tests/xades.rs` | Verification integration tests | Stage C: the signed `SigningCertificate` and `SigningCertificateV2` binding in v1 and V2 form and in the legacy namespace, a wrong `CertDigest`, a contradicting `IssuerSerial` and `IssuerSerialV2`, a substituted certificate over the same key, a SHA-1 `CertDigest`, an absent property, an implied signature policy, unprocessed properties, `ArchiveTimeStamp`, a dossier-level `es:TimeStamp`, and malformed properties that must neither pass nor panic. |
| `crates/openszigno-verify/tests/timestamps.rs` | Verification integration tests | Stage F, including the `TimeStampResp` wrapper (granted, grantedWithMods, and every rejected status) and DER of an unknown shape: a token that verifies end to end, explicit inclusive and exclusive canonicalization of `ds:SignatureValue`, a wrong imprint, a TSA with no, a non-critical, or the wrong `extendedKeyUsage`, an untrusted and an unknown TSA chain, a `genTime` before the claimed `SigningTime`, malformed and garbage tokens, forms this build does not process, and the validation time: a verified token moving it into the past so an expired signer still chains, `--at` overriding it, and an unverified token moving nothing. |
| `crates/openszigno-verify/src/tsa.rs` (unit tests) | Verification unit tests | The refusal paths of RFC 3161 token parsing: an oversized token, bytes that are not a `ContentInfo`, a non-`SignedData` content type, an undecodable `SignedData`, a wrong encapsulated content type, a missing eContent, an undecodable `TSTInfo`, an imprint algorithm outside the allowlist, missing or contradictory signed attributes, more than one `SignerInfo`, subject-key-identifier selection, and the pinned algorithm maps. |
| `crates/openszigno-verify/tests/revocation.rs` | Verification integration tests | Stage E: a good status from an embedded OCSP response and from an embedded CRL, revocation before and after the validation time, `certificateHold`, a revoked intermediate, a revoked TSA certificate, stale and absent data, a CRL from the wrong issuer, one signed by a stranger and one with a broken signature, delta CRLs, every `issuingDistributionPoint` form the build refuses and the two it accepts, unknown critical CRL extensions, delegated CRL signers and OCSP responders with and without the required EKU, `byKey` responder identity, `certID` matching including SHA-256, unsuccessful and `unknown` OCSP responses, source priority, `--no-revocation`, and the revocation-store classifier. |
| `crates/openszigno-verify/tests/trustlist.rs` | Verification integration tests | ETSI TS 119 612 trusted lists: anchor loading and its origin, list metadata, digital identities that supply no certificate, service status resolved at the validation time across a history, withdrawn and pre-eIDAS statuses, qualified determination with and without `QcCompliance`, the `QcSSCD` claim, a trust-store anchor leaving qualified undetermined, and the list's own signature — verified, tampered, signed by the wrong key, absent, and every structural rule of its `ds:Signature` reported separately. |
| `crates/openszigno-verify/tests/algorithms.rs` | Verification integration tests | Every accepted signature scheme and digest, P-384, unsupported key types, unrecognised critical extensions, name constraints on subject alternative names, malformed certificate and trust-store input, and the pinned policy tables. |
| `crates/openszigno-verify/tests/common/` | Test helper | A synthetic PKI built with `rcgen`, an XMLDSig signer built on the crate's own canonicalization backend plus `rsa`/`p256`, a synthetic timestamp authority that builds RFC 3161 tokens with `cms`/`der`, a synthetic CA that issues CRLs and OCSP responses with `x509-cert`'s CRL types and `x509-ocsp`, and a synthetic ETSI TS 119 612 trusted list. The real EU and Hungarian lists in the gitignored `refs/trust/` cache are read only as documentation of the schema and are never touched by a test: they change daily, and asserting anything about a real trust service provider would make the suite a statement about that provider. Signing a dossier is a permanent non-goal of the shipped tool, so this helper lives in `tests/` and must never move into a shipped crate. The RSA keys in `common/keys.rs` are generated, committed test material and must never be used for anything. |
| `crates/openszigno-cli/tests/verify.rs` | CLI integration tests | The `verify` process contract: the envelope, exit statuses 6 and 7, a structural failure still exiting 4, trust-store layouts and failures, `--at` as a usage error, and the human output's verdict and policy lines. |
| `crates/openszigno-cli/tests/end_to_end.rs` | CLI integration tests | The exit-status contract over a dossier that actually verifies: a complete signature exiting `0` with `verdict: "valid"`, the same dossier exiting `6` with its signer revoked, `--no-revocation` and missing revocation data both exiting `7`, an unusable revocation-store file and an unusable trusted list failing the run, and a trusted list supplying a qualified anchor. It includes `crates/openszigno-verify/tests/common/mod.rs` by path rather than copying it, so there stays exactly one place in the repository that can sign anything. |
| `crates/openszigno-cli/src/main.rs` (`#[cfg(test)]`) | Unit tests | CLI internals, currently the roll-back of files created by a failed extraction. |
| `crates/openszigno-cli/tests/nesting.rs` | CLI integration tests | The namespace allow-list and `--allow-namespace`, conformance warnings in every command, content sniffing and the extension fallback, and recursive extraction: subdirectory layout, `dossier_path` values, `--no-recursive`, `--max-depth`, depth-limit and invalid-nested warnings, and name collisions with a `<file>.d` directory. |
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
