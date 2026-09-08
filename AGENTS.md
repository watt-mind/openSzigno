# openSzigno

openSzigno is an open-source, agent-first Rust CLI for inspecting, listing,
structurally validating, extracting, creating, and verifying the signatures of
Hungarian Microsec e-Szignó `.es3` e-dossiers. Four-crate workspace:
`crates/openszigno-core` (bounded XML parsing, dossier model, Base64/ZIP
decoding, limits), `crates/openszigno-author` (the deterministic writer
behind `create`), `crates/openszigno-verify` (canonicalization, XMLDSig,
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
  binding, RFC 3161 signature and container timestamps, certificate paths,
  revocation (embedded, store-supplied, or fetched under the opt-in
  `--online`), and trusted lists with qualified status. It reports `valid`
  only when every required check passed against
  the trust material the caller supplied, and any unperformed required check
  caps the verdict at `indeterminate`. The other five commands verify nothing
  at all, `create` included: it writes an unsigned dossier and says so.
  Never claim validity outside that path, never let a change relax a
  check without tests, and never present a `valid` verdict as a statement of
  legal effect (see `docs/architecture.md#verification-boundary`).
- **Synthetic fixtures only.** Public fixtures under `tests/fixtures/` are
  redistributable and covered by `tests/fixtures/LICENSE`. All are unsigned
  except `tests/fixtures/xmldsig/`, whose one signature comes from a synthetic
  test PKI with no committed private key. Never derive public fixtures from
  private files.
- **Extraction safety is load-bearing.** Never weaken size/depth/ratio limits,
  no-clobber behavior, or name sanitization to raise a parse count.
- **Key material never leaves the process.** `extract --decrypt-key` takes the
  key, its certificate, and its passphrase from files (or the passphrase from
  `OPENSZIGNO_DECRYPT_PASSPHRASE`) and never from `argv`. Key bytes, the
  passphrase, and anything derived from them must never appear in a log,
  message, warning, JSON field, or fixture, and `decrypt_failed` must stay one
  undifferentiated message. **Never commit a private key or a complete PEM
  private-key armour line, synthetic or not** — tests generate keys at run
  time — and never allowlist a secret-scanner rule. See `SECURITY.md`.
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
| `crates/openszigno-core/src/` | `lib.rs`, `parse.rs`, `xml.rs`, `model.rs`, `sniff.rs`, `scan.rs`, `decode.rs`, `decrypt/`, `inventory.rs`, `error.rs` |
| `crates/openszigno-author/src/` | The writer side, used only by `create`: `lib.rs` (spec and limit checks), `render.rs` (the XML text), `mime.rs`, `title.rs`, `archive.rs`, `encrypt/` (the CMS `EnvelopedData` an `encrypt` document carries), `error.rs`. Reads no file and calls no clock; only `encrypt/` draws on a random source. |
| `crates/openszigno-verify/src/` | `lib.rs`, `c14n.rs`, `dsig.rs`, `references.rs`, `scope.rs`, `countersign.rs`, `signature/`, `coverage.rs`, `xades.rs`, `certs/`, `revocation/`, `tsa/`, `estimestamp.rs`, `trustlist/`, `policy.rs`, `codes.rs`, `trust.rs`, `report.rs`, `embedded.rs` |
| `crates/openszigno-verify/tests/` | Synthetic PKI and the in-tests XMLDSig signer (`common/`), which must never move into a shipped crate |
| `crates/openszigno-cli/src/` | `main.rs` (dispatch), `args.rs`, `input.rs`, `response.rs`, `render/`, `commands/` (`inspect`, `list`, `extract`, `validate`, `verify`, `skill`), `extract/` (planning, naming, `output_dir.rs`), `trust.rs`, `revocation_store.rs`, `online/` (`mod.rs` transport and cache, `gaps.rs` what to fetch and for whom, `destination.rs`, `pinned.rs`) |
| `tests/fixtures/` | Synthetic `.es3` fixtures + `LICENSE` + `README.md` |
| `docs/` | `index.md` lists them all: `architecture.md` (CLI contract), `trust.md` (trust and revocation material), `testing.md` (test layout, fixture policy), `roadmap.md` (milestones, risks), `releasing.md`, `es3-specification.md`, `references.md`, `research.md`, `verify-design.md` |
| `crates/openszigno-cli/skills/openszigno/SKILL.md` | The agent skill the binary embeds and `openszigno skill` prints; it ships inside the published crate |
| `samples/` | Private dossiers, ignored — see boundary above |
| `.github/workflows/` | `ci.yml` (fmt/clippy/docs/3-OS tests/golden/MSRV/semver/coverage/deny/package/container), `security.yml` (Gitleaks, actionlint, weekly advisories, CodeQL), `mutants.yml` and `fuzz.yml` (nightly, non-blocking), `release.yml` (generated by `dist`) calling `smoke-test.yml`, `publish-crates.yml`, `container.yml` |

## Concurrency (no worktree script)

This repo ships no `bin/worktree-*.sh` / Worktrunk config, and needs none yet:
stateless CLI, no dev server ports, no database, no generated `.env` files —
Cargo serializes shared `target/` access itself. Do not hand-roll port or env
schemes; if concurrent dispatch becomes routine, revisit a `wt` config. One
ticket, one branch, as always.
