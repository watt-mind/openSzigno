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
  data, or signer details — reproduce with a synthetic input.
- Report vulnerabilities privately per [SECURITY.md](SECURITY.md), never as a
  public issue.

## Commit messages

Use Conventional Commits. The type is required; the scope is optional and is
`core` or `cli`.

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
docs: document the stable error codes and their exit statuses
```

## Required checks

Run these locally before opening a pull request. CI runs the same checks on
Linux, macOS, and Windows, plus an MSRV build against Rust 1.88.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Before a release build, also confirm:

```sh
cargo build --release --locked
```

Coverage is reported by CI; to reproduce it locally see
[docs/testing.md](docs/testing.md#coverage).

## Local hooks

One-time install (requires the [lefthook](https://lefthook.dev) binary):

```sh
lefthook install
```

Pre-commit then runs `cargo fmt --all` (re-staged automatically) and
`cargo clippy --workspace --all-targets --locked -- -D warnings`; commit-msg
enforces the Conventional Commits subject shape above via
`scripts/commit-msg.sh`. Same checks run in CI, so a red hook is a red build.

## Tests and fixtures

- Every behavioural change needs a test. A security fix needs a regression
  test that fails before the fix.
- Public fixtures must be **synthetic and unsigned**, authored for this
  project, free of personal or company data, and dedicated under CC0-1.0 in
  `tests/fixtures/LICENSE`.
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

The current release performs structural validation and bounded extraction
only. Signature, certificate, timestamp, and decryption support are planned
milestones in [docs/roadmap.md](docs/roadmap.md). Until that code exists, no
contribution may add wording or output that states or implies that a
signature, timestamp, certificate, or dossier is valid.

## License of contributions

Contributions are accepted under the [MIT License](LICENSE); fixtures under
`tests/fixtures/` are accepted under CC0-1.0.
