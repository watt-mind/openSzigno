# Claude handoff: finalize the openSzigno Rust MVP

## Mission

Finalize and independently review the first openSzigno MVP: an MIT-licensed,
agent-friendly Rust CLI for safely inspecting, listing, structurally validating,
and extracting Hungarian Microsec e-Szignó `.es3` dossiers.

Work in the repository root. Do not commit, stage, push, publish, or release
unless the operator explicitly authorizes it.

## Current state

The repository has no commits yet; all project files are currently untracked.
The implementation is present and builds as a two-crate workspace:

- `crates/openszigno-core`: bounded XML parsing, dossier model, Base64/ZIP
  decoding, limits, and stable core error codes.
- `crates/openszigno-cli`: `openszigno` binary, human output, JSON protocol,
  safe extraction policy, and stable CLI errors/exit statuses.

Implemented commands:

```text
openszigno inspect FILE.es3 --json
openszigno list FILE.es3 --json
openszigno extract FILE.es3 --output DIR --json
openszigno validate-structure FILE.es3 --json
```

Implemented format scope:

- default Microsec namespace `https://www.microsec.hu/ds/e-szigno30#`;
- UTF-8 and ISO-8859-2 XML declarations;
- Base64 payloads and `zip -> base64` transform chains;
- strict ID/`OBJREF` checks;
- DTD/DOCTYPE rejection, depth/input/decoded-size/ZIP limits;
- output-name, traversal, symlink, collision, and no-clobber checks;
- signature/timestamp presence reporting only.

The tool intentionally does **not** verify XMLDSig/XAdES signatures,
certificate trust, revocation, timestamps, or legal authenticity. It must not
claim that a signature or dossier is valid.

## Read first

1. `README.md`
2. `docs/research.md`
3. `docs/architecture.md`
4. `docs/testing.md`
5. `Cargo.toml`
6. `crates/openszigno-core/src/`
7. `crates/openszigno-cli/src/main.rs`
8. Tests under both crates

The primary format sources are linked from `docs/research.md`. The Microsec
prose specification is authoritative over its XSD.

## Private-data boundary — mandatory

`samples/` contains private real-world dossiers and is intentionally ignored.
There is one standalone sample and a recursive corpus of 63 additional files
(about 67 MB). Never commit or modify any of them.

Do not print, enumerate, hash, or include in command diagnostics, test output,
reports, patches, or chat:

- private paths or filenames;
- dossier/document titles or metadata;
- payload contents or hashes;
- certificate subjects, signer data, or signature values.

This applies to failure paths too. Avoid commands such as `find samples`, shell
loops that echo filenames, or subprocess exceptions that render command
arguments. Use the privacy-preserving tests through environment variables and
report aggregate results only.

```sh
ES3_TEST_FIXTURE=/private/input.es3 cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_fixture_smoke

ES3_TEST_CORPUS_DIR=/private/corpus cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_corpus_smoke \
  -- --nocapture
```

Do not reproduce the real paths in your report.

Current aggregate corpus baseline:

- 63 corpus inputs;
- 51 parsed as supported dossiers;
- 12 safely rejected during parsing;
- 62 supported documents decoded;
- no supported-document decode failures, infrastructure errors, or panics.

Treat this only as a baseline. Determine through aggregate stable error-code
buckets whether the 12 rejections are expected out-of-scope cases or reveal an
in-scope compatibility bug. Do not weaken security checks merely to increase
the parse count.

## Your task

1. Perform an independent correctness and security review of the actual code,
   especially namespace handling, ID/reference binding, XML decoding, Base64
   limits, ZIP-bomb defenses, and extraction filesystem races.
2. Fix concrete issues that are inside the documented extraction-only MVP.
   Preserve stable JSON behavior and the cryptographic-verification boundary.
3. Review the private smoke/corpus harness for path leakage on every failure
   path. Errors derived from private inputs must be converted to stable codes
   before aggregation.
4. Reconcile documentation with implementation. The parser currently uses a
   bounded whole-document approach (`roxmltree`), not the earlier suggested
   `quick-xml` streaming design; document the actual safety model or change it
   only when there is a demonstrated need.
5. Confirm synthetic fixtures are unsigned, redistributable, and covered by
   `tests/fixtures/LICENSE`. Never derive public fixtures from private files.
6. Leave release automation and cryptographic `verify` out of this pass unless
   the operator explicitly expands scope.

## Acceptance criteria

- All four commands work in human and `--json` modes on committed synthetic
  fixtures.
- JSON mode writes exactly one deterministic object to stdout; diagnostics do
  not contaminate stdout.
- Malformed XML, unsafe references, invalid Base64, ZIP bombs, traversal,
  symlinks, collisions, and unsupported encryption fail or warn explicitly.
- Extraction never overwrites an existing file.
- No code path labels cryptographic material as valid.
- Private tests disclose aggregate counts and stable error buckets only.
- The private corpus has no supported-payload decode failures or panics; any
  changed parse/rejection totals are explained at aggregate error-code level.
- No private dossier is tracked or staged.

Run:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --release --locked
git diff --check --no-index /dev/null README.md
git status --short
```

Also exercise each command manually against synthetic fixtures and compare
extracted synthetic bytes with their expected public test payloads.

## Known deferred work / residual risks

- XMLDSig/XAdES, certificate-chain, revocation, and timestamp verification;
- encrypted document decryption;
- custom compatible e-dossier namespaces;
- cross-platform CI and release binary automation;
- fully race-resistant filesystem extraction on every supported platform;
- broader consented interoperability corpus and vendor differential testing.

## Required final report

Return:

1. findings and fixes, ranked by severity;
2. changed files;
3. commands run and exit codes;
4. synthetic-test evidence;
5. private testing as aggregate totals/error buckets only;
6. remaining risks and any decision needing operator approval;
7. confirmation that no files were staged and no private samples were changed
   or exposed.
