# openSzigno

openSzigno is an open-source, agent-first Rust CLI for inspecting, listing,
structurally validating, and extracting Hungarian Microsec e-Szignó
`.es3` e-dossiers. Two-crate workspace: `crates/openszigno-core` (bounded
XML parsing, dossier model, Base64/ZIP decoding, limits) and
`crates/openszigno-cli` (the `openszigno` binary, human + stable `--json`
output, safe extraction). See `README.md`, `docs/architecture.md`,
`docs/roadmap.md`, `CONTRIBUTING.md`, and `SECURITY.md`.

## Issue tracking (Linear)

Team **`LAB`**, project **`openSzigno`**. Full protocol:
`~/Develop/hdkiller/docs/orgs/linear.md` — read before claiming or filing tickets.
Follow-ups discovered mid-work → file a Linear issue in `Triage` (do not expand the
current ticket's scope). PR body: `Fixes LAB-XX`.

## Non-negotiables

- **Private-data boundary.** `samples/` holds private real-world dossiers and is
  git-ignored. Never print, enumerate, hash, or include in diagnostics, tests,
  patches, or chat: private paths/filenames, titles, metadata, payload contents
  or hashes, certificate subjects, signer data, or signature values. Report
  private-corpus results as aggregate counts and stable error-code buckets only.
- **Verification boundary.** This tool performs structural validation and bounded
  extraction only. It does **not** verify XMLDSig/XAdES signatures, timestamps,
  certificate trust, or legal authenticity — never claim a signature or dossier
  is valid (see `docs/architecture.md#verification-boundary`).
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
| `crates/openszigno-cli/src/` | `main.rs` (commands, JSON protocol), `output_dir.rs` (safe extraction) |
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
