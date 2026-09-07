# openSzigno

openSzigno is an open-source, agent-first Rust CLI for inspecting, listing,
structurally validating, extracting, and verifying the signatures of Hungarian
Microsec e-Szignó `.es3` e-dossiers. Three-crate workspace:
`crates/openszigno-core` (bounded XML parsing, dossier model, Base64/ZIP
decoding, limits), `crates/openszigno-verify` (canonicalization, XMLDSig,
certificate paths; no I/O except through injected traits), and
`crates/openszigno-cli` (the `openszigno` binary, human + stable `--json`
output, safe extraction). See `README.md`, `docs/architecture.md`,
`docs/roadmap.md`, `CONTRIBUTING.md`, and `SECURITY.md`.

## Issue tracking (Linear)

Team **`LAB`**, project **`openSzigno`**. Full protocol:
`~/Develop/hdkiller/docs/orgs/linear.md` — read before claiming or filing tickets.
Follow-ups discovered mid-work → file a Linear issue in `Triage` (do not expand the
current ticket's scope). PR body: `Fixes LAB-XX`.

## Public intake (GitHub Issues)

This is a public repo: external contributors file GitHub Issues (templates in
`.github/ISSUE_TEMPLATE/`, auto-labeled `type:*` + `source:human`).
Maintainers mirror accepted public issues into Linear (same team/project as
above, `source:human`, link back to the GitHub issue) and work them there.
The GitHub issue stays the public face — close it with a link when done, and
never paste Linear internals, private paths, or maintainer-local details into
GitHub comments, commits, or PR descriptions (Linear protocol §11).
Triage rule: vulnerability → the `SECURITY.md` private flow, never a public
issue; anything involving a real dossier → ask for a synthetic reproducer
before anything else.

## Non-negotiables

- **Private-data boundary.** `samples/` holds private real-world dossiers and is
  git-ignored. Never print, enumerate, hash, or include in diagnostics, tests,
  patches, or chat: private paths/filenames, titles, metadata, payload contents
  or hashes, certificate subjects, signer data, or signature values. Report
  private-corpus results as aggregate counts and stable error-code buckets only.
- **Verification boundary.** Only `verify` performs cryptographic checks:
  XMLDSig canonicalization, reference digests and signature values, the
  e-dossier reference-scope rules, the XAdES signed `SigningCertificate`
  binding, RFC 3161 signature timestamps, certificate paths, revocation
  (embedded and store-supplied CRL/OCSP), and trusted lists with qualified
  status. It reports `valid` only when every required check passed against
  the trust material the caller supplied, and any unperformed required check
  caps the verdict at `indeterminate`. The other four commands verify nothing
  at all. Never claim validity outside that path, never let a change relax a
  check without tests, and never present a `valid` verdict as a statement of
  legal effect (see `docs/architecture.md#verification-boundary`).
- **Synthetic fixtures only.** Public fixtures under `tests/fixtures/` are
  unsigned, redistributable, and covered by `tests/fixtures/LICENSE`. Never
  derive public fixtures from private files.
- **Extraction safety is load-bearing.** Never weaken size/depth/ratio limits,
  no-clobber behavior, or name sanitization to raise a parse count.
- Never commit secrets or `.env` files. Prefer logical, Conventional Commits
  (`CONTRIBUTING.md`).

## Commands

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --locked
./target/release/openszigno inspect tests/fixtures/plain-base64.es3 --json
```

Local hooks: `lefthook install` (one-time), then pre-commit runs
`cargo fmt` + `clippy -D warnings` and commit-msg checks the subject shape.

Private smoke tests (opt-in, aggregate output only):

```sh
ES3_TEST_FIXTURE=/private/input.es3 cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_fixture_smoke
ES3_TEST_CORPUS_DIR=/private/corpus cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_corpus_smoke -- --nocapture
```

## Layout

| Path | What lives there |
| :--- | :--- |
| `crates/openszigno-core/src/` | `parse.rs`, `decode.rs`, `model.rs`, `scan.rs`, `error.rs` |
| `crates/openszigno-verify/src/` | `c14n.rs`, `dsig.rs`, `certs.rs`, `policy.rs`, `codes.rs`, `trust.rs`, `report.rs` |
| `crates/openszigno-verify/tests/` | Synthetic PKI and the in-tests XMLDSig signer (`common/`), which must never move into a shipped crate |
| `crates/openszigno-cli/src/` | `main.rs` (commands, JSON protocol), `output_dir.rs` (safe extraction), `trust_store.rs` (`--trust-store` loader) |
| `tests/fixtures/` | Synthetic `.es3` fixtures + `LICENSE` + `README.md` |
| `docs/` | `architecture.md` (CLI contract), `research.md` (sources), `testing.md` (fixture policy), `roadmap.md` (milestones, risks) |
| `samples/` | Private dossiers, ignored — see boundary above |
| `.github/workflows/` | `ci.yml` (fmt/clippy/3-OS tests/MSRV/coverage/deny), `security.yml` (Gitleaks, workflow lint, gated CodeQL), `release.yml` (tag-triggered binaries) |

## Concurrency (no worktree script)

This repo ships no `bin/worktree-*.sh` / Worktrunk config, and needs none yet:
stateless CLI, no dev server ports, no database, no generated `.env` files —
Cargo serializes shared `target/` access itself. Do not hand-roll port or env
schemes; if concurrent dispatch becomes routine, revisit a `wt` config. One
ticket, one branch, as always.
