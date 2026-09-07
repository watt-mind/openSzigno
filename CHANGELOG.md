# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, the JSON envelope is versioned separately by its
`schema_version` field, which is `1`.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-09-07

### Fixed

- CI hygiene: `retention-days: 1` on all artifact uploads, and the baseline
  `concurrency` pattern in `ci.yml` so stale PR commits cancel.
- Added `security.yml`: Gitleaks secret scan and workflow lint on push/PR plus
  a weekly run, with CodeQL gated on `vars.CODEQL_ENABLED` until Rust support
  is confirmed.
- Added Rust-appropriate local hooks (`lefthook.yml`, pre-commit fmt+clippy,
  commit-msg Conventional Commits check) and documented the one-time install.
- Added `AGENTS.md` (team LAB, project openSzigno) with thin `CLAUDE.md` /
  `GEMINI.md` pointers and a documented no-worktree concurrency position.
- Fixed the test harness passing unresolved temporary paths on macOS
  (`/var -> /private/var` in `TMPDIR`), which the output-directory guard
  rejects by design. No product behavior changed.

Initial MVP: a bounded, agent-friendly CLI for inspecting, listing,
structurally validating, and extracting Microsec e-Szignó `.es3` dossiers.
This release performs no cryptographic verification of any kind.

### Added (M1: compatible namespaces and nested dossiers)

- `openszigno-core`: `KNOWN_COMPATIBLE_NAMESPACES` and `ParseOptions`, so a
  dossier rooted at `Dossier` in the default Microsec namespace or in any of
  the four Hungarian company-court (e-cégeljárás) generations parses. Every
  structural lookup uses the dossier's own namespace, `Dossier.namespace`
  reports it verbatim, and an unlisted namespace is still `wrong_root` with a
  message that never echoes the URI. `parse(bytes, &limits)` is kept as a
  compatibility wrapper meaning "known namespaces only".
- `openszigno-core`: `StructuralWarning` / `StructuralWarningCode` and
  `Dossier.warnings`, reporting the two deviations real company-court dossiers
  show instead of rejecting them: `dangling_objref` for an `OBJREF` outside
  the dossier and document profiles that resolves to nothing, and
  `document_without_profile` for a `Document` with no `DocumentProfile`, which
  is skipped and not counted. Profile `OBJREF`s and duplicate IDs remain hard
  errors.
- `openszigno-core`: `Document.nested_dossier` for a document declaring
  `application/nldossier2` or the `dosszie` extension, and `sniff` /
  `DetectedType` (`pdf`, `html`, `xml`, `dossier`, `zip`, `text`, `binary`)
  with `as_str` and `preferred_extension`, classifying a payload from a
  bounded prefix of its bytes.
- `openszigno-cli`: `--allow-namespace <URI>` on every command, repeatable and
  additive on top of the known-compatible namespaces.
- `openszigno-cli`: structural warnings surfaced by every command with their
  core codes, and `validate-structure` data gains `conformance_warnings`.
  `valid_structure` stays `true` whenever parsing succeeded.
- `openszigno-cli`: `list` and `inspect` documents gain `nested_dossier`, and
  the `dossier` object gains `nested_dossiers`.
- `openszigno-cli`: recursive extraction of embedded dossiers, on by default,
  with `--no-recursive` and `--max-depth <N>` (default 3, hard cap 8). A
  nested dossier is written as a payload file *and* expanded into a
  `<file>.d` subdirectory created relative to the parent's directory
  descriptor. The aggregate decode budget is shared across the whole tree, all
  names, collisions, and destination checks cover the tree before anything is
  written, and a rollback removes every file and subdirectory the run created,
  deepest first. A nested parse failure is the warning `nested_dossier_invalid`
  and keeps the raw file; exceeding the depth is `nested_dossier_depth_limit`.
- `openszigno-cli`: `extract` entries gain `dossier_path`, `path`,
  `detected_type`, and `declared_type`, and the data gains
  `nested_dossiers_extracted`; `skipped_count` now counts skipped documents
  across the whole tree.
- `openszigno-cli`: a sniffed extension is appended when the sanitised title
  carries none and the dossier declares none.
- Fixtures `tests/fixtures/nested-dossier.es3` and
  `tests/fixtures/compatible-namespace.es3`, both synthetic and unsigned.
- `openszigno-core`: the structural warning `source_size_missing`, reported
  when a `DocumentProfile` omits `SourceSize`, and `creation_date_missing`,
  reported when the `DossierProfile` omits `CreationDate` (the dossier
  `creation_date` is then `null`).
- `openszigno-cli`: the warning `output_name_deduplicated`, reported for each
  output renamed because its name was already taken in its directory.

### Changed (M1)

- `SourceSize` is now optional in a `DocumentProfile`, because company-court
  dossiers occur without it. `Document.source_size` is `Option<u64>` and
  serialises as `null` when absent; the `sizeValue`/`sizeUnit` and
  declared-size-limit rules are unchanged when it is present, and the
  `source_size_mismatch` check is simply skipped when it is not. Two
  `SourceSize` elements in one profile are `invalid_xml`. Human `list` prints
  `?` for an unknown size.
- Repeated output names no longer fail extraction. Real dossiers reuse
  document titles, so a name already taken in its directory is renamed
  deterministically by inserting `-<document index>` before the extension
  (`ruling.txt`, then `ruling-1.txt`), with `<file>.d` subdirectories
  following their payload file. The comparison stays NFC-normalised and
  case-insensitive, every rename is reported as `output_name_deduplicated`,
  and `output_name_collision` remains as the residual error for a name that
  still collides after renaming.
- Content sniffing no longer depends on UTF-8 validity: after the `pdf` and
  `zip` magic checks, a payload that starts with markup is classified from the
  ASCII markup alone, so an ISO-8859-2 encoded XML or HTML document is no
  longer reported as `binary`. Element names are compared byte-wise.
- The two closed-stdout CLI tests now close the read end of the pipe before
  spawning the process, so a response small enough to fit the pipe buffer can
  no longer make them flake.
- A `Document` without a `DocumentProfile` no longer fails the whole dossier
  with `missing_element`; it is skipped with a `document_without_profile`
  warning. Two `DocumentProfile` elements in one `Document` remain
  `invalid_xml`.
- Human `list` output marks a document that embeds a dossier, human `extract`
  output prints the path relative to the output root and the detected type,
  and human `validate-structure` output prints the conformance-warning count.

### Added (MVP)

- `openszigno-core`: namespace-aware structural parsing of dossiers rooted at
  `Dossier` in `https://www.microsec.hu/ds/e-szigno30#`, with UTF-8 and
  ISO-8859-2 XML decoding, strict ID uniqueness and `OBJREF` binding, a
  document model, and stable `ErrorCode` categories.
- `openszigno-core`: bounded payload decoding for the `base64` and
  `zip -> base64` transform chains, with a declared-`SourceSize` match and
  explicit reporting of encrypted or otherwise unsupported chains.
- `openszigno-cli`: the `openszigno` binary with `inspect`, `list`,
  `validate-structure`, and `extract` commands, each in a human-readable mode
  and a `--json` mode that emits exactly one JSON object on stdout.
- Stable JSON envelope (`schema_version`, `ok`, `command`, `input`, `data`,
  `warnings`, `errors`) with stable error and warning codes, and stable exit
  status categories 0, 2, 3, 4, and 5.
- Safe extraction: title sanitization, collision detection, no-clobber file
  creation, output-directory symlink and reparse-point rejection, and
  aggregate decoded-size limits.
- Documented compile-time limits for input size, document count, Base64
  length, decoded and total decoded bytes, ZIP members, ZIP expanded size and
  compression ratio, XML depth, and XML node count, reported by `inspect`.
- Synthetic, unsigned, CC0-dedicated fixtures under `tests/fixtures/`, core
  and CLI integration test suites, and privacy-preserving opt-in smoke tests
  for a locally held dossier or corpus.
- Project documentation: README, architecture and CLI contract, research and
  source register, testing and fixture policy, roadmap, contributing guide,
  and security policy.

### Changed (hardening during the MVP)

- Added a linear pre-parse scan that rejects DTD and entity declarations,
  nesting deeper than `max_xml_depth`, and more than `max_xml_nodes` elements
  before `roxmltree` builds the tree, so deeply nested input can no longer
  overflow the stack. Comments, CDATA sections, and processing instructions no
  longer cause DOCTYPE false positives.
- Dropped the per-node depth map, which roughly doubled peak memory.
- Read the `encoding` pseudo-attribute only from the XML declaration, so a
  comment can no longer choose how the document is decoded.
- Checked the ZIP compression ratio against actual decoded bytes instead of
  attacker-controlled header sizes, which previously allowed roughly 1000:1
  amplification within the absolute cap.
- Limited the XML ID space to unprefixed attributes, matching the lookups.
- Extraction on Unix now opens the output path one component at a time
  relative to the previous descriptor with `O_NOFOLLOW` and creates files with
  `O_CREAT|O_EXCL|O_NOFOLLOW`, closing the directory-swap race. Windows keeps
  path-based no-clobber creation and additionally rejects reparse points.
- Extracted files are created with mode `0600` and new directories with
  `0700` on Unix.
- Files created by a failed extraction run are removed, so a partial result is
  never left behind; the error says so if the clean-up itself fails.
- Output-name rules now reject titles starting with `.` or `-`,
  non-ASCII-space whitespace, and Unicode format, bidirectional, invisible,
  and private-use characters; names are NFC-normalised and collisions are
  detected on the normalised, lowercased form.
- A closed or failing stdout is reported as exit status 3 instead of panicking.
- An invalid command line with `--json` present now produces the standard
  envelope with `command: "usage"` and the code `usage_error`.

### Fixed

- Mapped unsupported ZIP compression methods and encrypted ZIP members to
  `unsupported_zip_member` instead of `invalid_zip`.
- Mapped output-file creation failures by kind, so only `AlreadyExists` is
  `output_exists` and other failures are `io_error`.
- Kept only the position from `roxmltree` parse errors, so element, attribute,
  and entity names from confidential input are never echoed.

### Security

- Untrusted `.es3` input is bounded at every stage: file size, XML depth and
  node count, Base64 length, decoded document size, ZIP member count, expanded
  size and compression ratio, and aggregate extraction size.
- DTDs, DOCTYPE declarations, and entity declarations are rejected, so
  external-entity and entity-expansion attacks do not apply.
- Messages, warnings, and errors never contain input paths, document titles,
  or payload content.
- No code path labels cryptographic material as valid. Signature and timestamp
  material is counted for reporting only.

[0.1.0]: https://github.com/watt-mind/openSzigno/releases/tag/v0.1.0
[Unreleased]: https://github.com/watt-mind/openSzigno/compare/v0.1.0...develop
