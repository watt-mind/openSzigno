# Contributing to openSzigno

Thank you for helping. openSzigno handles untrusted input and makes explicit
promises about what it does *not* do, so changes are reviewed with those two
things in mind first.

Read [docs/architecture.md](docs/architecture.md) before changing behaviour,
and [SECURITY.md](SECURITY.md) before changing anything that touches parsing,
decoding, or filesystem output.

## Branch model

| Branch | Role |
| --- | --- |
| `develop` | Default integration branch. All pull requests target it. |
| `master` | Stable branch. Only release merges from `develop` land here. |
| `feat/...`, `fix/...`, `docs/...` | Short-lived feature branches, cut from `develop`. |

```sh
git switch develop
git pull
git switch -c fix/zip-ratio-check
```

Open the pull request against `develop`. Keep it focused: one behavioural
change per pull request, with its tests.

## Reporting issues

- Search existing issues and pull requests first.
- Use the bug or feature template; blank issues are disabled.
- Never attach a real dossier or include private paths, titles, payload
  data, or signer details. Reproduce with a synthetic input.
- Report vulnerabilities privately per [SECURITY.md](SECURITY.md), never as a
  public issue.

## Commit messages

Use Conventional Commits. The type is required; the scope is optional and is
`core`, `author`, `cli`, or `verify`.

```text
<type>(<scope>): <imperative summary, lowercase, no trailing period>

<body: what changed and why, wrapped at 72 columns>
```

| Type | Use for |
| --- | --- |
| `feat` | New user-visible capability. |
| `fix` | Bug or security fix. |
| `docs` | Documentation only. |
| `test` | Tests and fixtures only. |
| `ci` | Workflow and automation changes. |
| `chore` | Dependencies, tooling, housekeeping. |

Examples:

```text
fix(core): check the ZIP compression ratio on actual decoded bytes
feat(cli): report the detected namespace in inspect output
feat(verify): bind the signing certificate through xades:SigningCertificate
docs: document the stable error codes and their exit statuses
```

CI's `hygiene` job enforces this shape on every commit subject in a pull
request's range (`scripts/commit-msg.sh`, the same check the local
commit-msg hook runs), skipping merge commits and commits authored by
`dependabot[bot]` or `github-actions[bot]`. On a release pull request into
`master` only commits not already on `develop` are checked, since every
commit on `develop` passed this job on the pull request that landed it.
It also requires the pull
request body to contain a line starting `Fixes LAB-<n>`, `Closes LAB-<n>`,
or `Refs LAB-<n>` (case-insensitive), so every change traces to a Linear
ticket; a bot-authored pull request is exempt, and a human-authored one
with no ticket can opt out by adding the `no-ticket` label. The job only
runs on `pull_request`, since only a pull request has a range and a body to
check; existing commits on `develop` (older merge commits, `Merge pull
request ...` subjects predating this rule) are unaffected.

## Required checks

Run these locally before opening a pull request. CI runs the same checks on
Linux, macOS, and Windows, plus an MSRV build against Rust 1.88.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI's `lint` job also runs [`cargo-machete`](https://github.com/bnjbvr/cargo-machete)
(`cargo machete`) to catch a dependency declared in a manifest but never
used. If it flags a dependency that is only reached through a macro or a
feature it cannot see, add it to that crate's
`[package.metadata.cargo-machete] ignored = [...]` with a comment
explaining why, rather than removing something still needed.

`clippy::too_many_lines` is a workspace lint (`Cargo.toml`); `clippy.toml`
sets `too-many-lines-threshold`. The ticket's target is 150, but the
threshold is currently 484, the smallest value that passes today, because
lowering it further means restructuring functions that are logic-adjacent
work for other tickets. Lower the threshold whenever a change shrinks the
function that set it; do not raise it to admit a new long function.

Before a release build, also confirm:

```sh
cargo build --release --locked
```

CI additionally runs, on every pull request:

| Check | Command |
| --- | --- |
| Markdown lint and relative links | `npx markdownlint-cli2` over every tracked `*.md`, then `python3 scripts/check-doc-links.py` |
| Prose style (no em-dashes) | `python3 scripts/check-prose.py` |
| Rustdoc | `cargo doc --workspace --no-deps --locked` with `RUSTDOCFLAGS=-D warnings` |
| Unused dependencies | `cargo machete` |
| Licences and advisories | `cargo deny check --all-features` |
| Crate manifests | `cargo package -p <crate> --no-verify --locked` for all four crates |
| Release container | `docker build .`, then the CLI subcommands inside the image |
| Workflow lint | `actionlint` with `SHELLCHECK_OPTS=--severity=warning` |
| Commit and PR hygiene (pull requests only) | `git log --format=%s origin/<base>..HEAD` through `scripts/commit-msg.sh -`, plus a `Fixes\|Closes\|Refs LAB-<n>` line in the pull request body |
| Source file length | `python3 scripts/check-file-length.py` |
| Golden output contract | `python3 scripts/golden.py check --bin target/release/openszigno` |
| Semver checks (`openszigno-core` and `openszigno-verify` against the version published on crates.io) | `cargo semver-checks -p <crate>` |
| Coverage quality gate | `python3 scripts/coverage_gate.py --lcov lcov.info --base origin/develop` |
| Mutation testing (nightly, not a required check) | `cargo mutants -p <crate> --timeout-multiplier 2 -j 2` then `python3 scripts/mutants_gate.py --dir mutants.out --crate <crate>` |
| Fuzzing (nightly, not a required check) | `cargo +nightly fuzz run <target> -- -max_total_time=600 -jobs=1`; see [docs/testing.md](docs/testing.md#fuzzing) |

Any of these can be reproduced locally with the same command. The
container job runs `inspect`, `list`, `validate-structure`, `extract`, and
`verify` against `tests/fixtures/` inside the scratch image, so a change
that breaks the shipped image fails on the pull request.

### Golden output contract

`tests/golden/` holds the captured stdout and exit status of every command
over every fixture in `tests/fixtures/`, in both `--json` and human mode.
The CI `golden` job builds the release binary and compares; a difference
fails the pull request.

```sh
cargo build --release --locked -p openszigno-cli
python3 scripts/golden.py check --bin target/release/openszigno
```

A diff is not a broken test. It is a change to what every consumer parses,
so decide what kind of change it is before accepting it: an added field,
warning code, check code, or human line is additive and keeps
`schema_version` at `1`; a removed or renamed field, a changed type, or a
changed exit status for an existing outcome needs a `schema_version` bump
and an update to [docs/architecture.md](docs/architecture.md#json-envelope).
Either way the change gets a `CHANGELOG.md` entry under Unreleased. Then
regenerate:

```sh
python3 scripts/golden.py update --bin target/release/openszigno
```

The script masks exactly two values, both times that cannot be stable; the
rules are in [tests/golden/README.md](tests/golden/README.md). Never widen
the masking to hide a real difference.

When changing anything under `.github/workflows/`, pin every third-party
action to a full commit SHA with a `# vX.Y.Z` comment after it. Dependabot
reads that comment and keeps the pin current; a floating tag would not be
reviewable. `.github/workflows/release.yml` is generated by `dist` and is
never edited by hand, including its pins: see
[docs/releasing.md](docs/releasing.md#pinned-actions-in-the-generated-workflow).

Coverage is reported by CI; to reproduce it locally see
[docs/testing.md](docs/testing.md#coverage).

### Coverage quality gate

`scripts/coverage_gate.py` reads the lcov report `cargo llvm-cov` produces
and enforces, in the CI `coverage` job:

- **Every crate is reported on.** A crate directory under `crates/` that
  produces no coverage records at all fails the job. A crate absent from
  the report is unmeasured, not fully covered, and used to leave the gate
  silently.
- **Per-crate floor.** Every crate (`crates/<name>`) must be at or above
  90% line coverage. A crate with no instrumented lines scores 0, not 100.
- **Patch coverage.** Lines added or modified by the pull request, under
  `crates/*/src/`, must be at or above 80% covered, whenever the change
  touches at least 20 instrumentable lines; smaller changes skip this
  check rather than fail it.
- **Ratchet.** `scripts/coverage-floors.txt` records each crate's (and the
  workspace's) coverage at the time it was last updated. A crate that
  drops more than 1.0 point below its recorded value fails the job, the
  same ratchet model as the file-length guardrail above: the floor exists
  to catch regressions, not to require every change to raise coverage.

The workspace-wide `--fail-under-lines 85` check also still runs, as a
coarse backstop after the script's finer-grained gates.

On a pull request, the `coverage` job posts (and on a later push, refreshes
in place) one PR comment marked `<!-- coverage-gate -->` with the same
Markdown summary that appears in the job's step summary.

To update the ratchet floors after a change that legitimately raises or
lowers coverage, run coverage locally and rewrite the file:

```sh
cargo llvm-cov --workspace --lcov --output-path lcov.info
python3 scripts/coverage_gate.py --lcov lcov.info --update-floors
```

Commit the updated `scripts/coverage-floors.txt` alongside the change that
caused the shift. CI never rewrites this file itself.

The script carries its own unit tests for the `-U0` diff parser behind
patch coverage, where the edge cases live (an added source line beginning
with `++` is not a `+++ b/path` file header). Run them with:

```sh
python3 scripts/coverage_gate.py --self-test
```

### Mutation testing gate

`.github/workflows/mutants.yml` runs `cargo-mutants` nightly (and on manual
dispatch) over `openszigno-core` and `openszigno-verify`, and
`scripts/mutants_gate.py` enforces, per crate:

- **Ratchet only.** `scripts/mutants-floors.txt` records each crate's
  caught-mutant percentage (`caught / (caught + missed)`) at the time it was
  last updated. A crate that drops more than 2.0 points below its recorded
  value fails the job, the same ratchet model the coverage and file-length
  guardrails use.
- **No minimum floor.** Unlike the coverage gate, there is no fixed
  percentage every crate must clear; a low-but-stable score is not itself a
  failure, only a decline past the tolerance is.

This is a nightly job, not a pull-request check: a full run is tens of
minutes per crate, too slow for every push. A gate failure opens or
refreshes a single tracking issue titled "Mutation testing: survivors"
instead of blocking a merge. See
[docs/testing.md](docs/testing.md#mutation-testing) for how to run it
locally, read a survivor, and update the floors file.

## Documentation

Documentation is part of the product: agents and people read it before they
run anything. Every change that alters behaviour updates the documentation in
the same pull request, and CI lints the Markdown and checks relative links.

- **Where things live.** `README.md` is the front door and stays short.
  `docs/architecture.md` is the canonical contract (envelope, stable codes,
  limits, exit statuses); `docs/roadmap.md` holds plans and residual risks;
  `docs/testing.md` explains the test layout; `docs/references.md` indexes
  the specifications. Every file under `docs/` is listed in `docs/index.md`.
- **Style.** Plain, precise English in the present tense. Sentence-case
  headings. Wrap prose at 80 columns (tables, code, and URLs may run longer).
  No em-dashes. Use tables for parallel facts and fenced blocks for every
  command, path, and JSON example. Real output over invented output: capture
  it from the binary and keep it current.
- **Stable names.** A code, flag, field, or exit status appears in the docs
  in the same pull request that adds it, and `CHANGELOG.md` gets an entry
  under Unreleased in Keep a Changelog form.
- **File length.** Keep files under 800 lines; allowlisted files may only
  shrink. `scripts/check-file-length.py` fails a `*.rs` file under
  `crates/*/src` that exceeds 800 physical lines, or one under
  `crates/*/tests` that exceeds 1500, unless it is named in
  `scripts/file-length-allowlist.txt` with the size it was allowlisted at;
  an allowlisted file that grows past that recorded size fails too, even
  while still under its own limit. The allowlist exists only for files
  that already exceeded the limit before the guardrail was added and whose
  reduction is logic-adjacent work tracked elsewhere; it is not a way to
  admit a new oversized file.
- **Never claim validity.** No sentence may state or imply that a signature,
  timestamp, certificate, or dossier is valid unless the code that proves it
  exists and is tested.
- **Privacy.** No real dossier names, titles, hashes, or signer data, not
  even as examples.

Check locally before pushing:

```sh
npx --yes markdownlint-cli2@0.18.1 "**/*.md" "#target" "#refs" "#tmp" \
  "#samples" "#node_modules" "#fuzz/target"
python3 scripts/check-doc-links.py
python3 scripts/check-prose.py
python3 scripts/check-file-length.py
```

## Local hooks

One-time install (requires the [lefthook](https://lefthook.dev) binary):

```sh
lefthook install
```

Pre-commit then runs `cargo fmt --all` (re-staged automatically) and
`cargo clippy --workspace --all-targets --locked -- -D warnings`; commit-msg
enforces the Conventional Commits subject shape above via
`scripts/commit-msg.sh "{1}"`, lefthook's placeholder for the message file
git passes to the hook. Same checks run in CI, so a red hook is a red build.

## Tests and fixtures

- Every behavioural change needs a test. A security fix needs a regression
  test that fails before the fix.
- Public fixtures must be **synthetic**, authored for this project, free of
  personal or company data, and dedicated under CC0-1.0 in
  `tests/fixtures/LICENSE`. They are unsigned unless a test needs a signature,
  in which case it is made by a synthetic test PKI whose private keys are
  never committed, as `tests/fixtures/xmldsig/` is.
- Never derive a public fixture from a real dossier, even by editing it.
- Prefer generating limit cases (deep nesting, node counts, ZIP bombs,
  unsafe names) inside the test code instead of committing large binaries.
- New stable codes must be added to the tables in
  [docs/architecture.md](docs/architecture.md#stable-codes) in the same pull
  request.

## Privacy rule for real dossiers

Real `.es3` dossiers routinely contain personal data, so they are private
integration inputs and never test data.

- Do not commit or stage a real dossier. `samples/` is gitignored for this
  reason.
- Never include a private path, filename, dossier or document title, payload
  content or hash, certificate subject, signer detail, or signature value in
  code, tests, logs, error messages, issues, pull requests, or CI output.
  This applies on failure paths too.
- Use the opt-in tests described in
  [docs/testing.md](docs/testing.md#private-opt-in-smoke-tests), which take
  their input through an environment variable and report aggregate counts and
  stable error-code buckets only.
- Report compatibility findings as aggregate buckets, never per file.

## Proposing a format-compatibility change

If openSzigno rejects a dossier you believe is in scope, or accepts something
it should not:

1. Cite the rule from the Microsec e-dossier specification, with the section,
   version, and the exact requirement. The prose specification is
   authoritative over the XSD. Links to the primary sources are in
   [docs/research.md](docs/research.md#primary-sources).
2. Describe the observed behaviour as a stable code and exit status, not as a
   quotation of your private file.
3. Add a synthetic fixture, or a test-generated input, that reproduces the
   case without any private data.
4. State the security impact. A change that widens what is accepted must
   explain why it cannot widen what an attacker can do.

Never weaken a limit, a name check, or a structural rule merely to make more
files parse. If a limit genuinely blocks a legitimate dossier, say so in the
issue and propose the new value with reasoning.

## Scope reminder

`verify` performs cryptographic checks: XMLDSig canonicalization, reference
digests and signature values, the e-dossier reference-scope rules, the XAdES
signed `SigningCertificate` binding, RFC 3161 signature and container
timestamps, certificate paths, revocation, and ETSI TS 119 612 trusted lists.
It reports `valid` only when every check it makes passed at the stated
validation time, against trust material the caller supplied; any required
check it could not perform caps the verdict at `indeterminate`. `--online`
fetches revocation data only, only for certificates on a path to a configured
anchor, and is off by default. `extract --decrypt-key` reverses the `encrypt`
transform. `sign` writes a signature and checks nothing, not even the one it
just wrote. The other five commands verify nothing at all, and no command
determines a document's legal effect.

What is still unimplemented is listed in
[docs/roadmap.md](docs/roadmap.md#not-yet-implemented) and, with the code-level
detail, in
[docs/architecture.md](docs/architecture.md#not-yet-implemented). No
contribution may add wording or output that states or implies that a
signature, timestamp, certificate, or dossier is valid unless the code that
proves it exists and is tested.

## License of contributions

Contributions are accepted under the [MIT License](LICENSE); fixtures under
`tests/fixtures/` are accepted under CC0-1.0.
