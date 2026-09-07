# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, the JSON envelope is versioned separately by its
`schema_version` field, which is `1`.

## [Unreleased]

Nothing yet.

## [0.2.0] - 2026-09-07

### Added (M2 phase 1: `verify` for XMLDSig signatures)

- New crate `openszigno-verify`: canonicalization, the XMLDSig core, the pinned
  algorithm policy, and RFC 5280 certificate-path validation. Pure Rust,
  `forbid(unsafe_code)`, no network, and no I/O except through the injected
  `Clock`, `TrustSource`, and `RevocationSource` traits.
- `openszigno verify FILE [--json] [--trust-store DIR] [--at RFC3339]
  [--allow-namespace URI]`. It verifies every `ds:Signature`: canonicalization,
  reference digests, `ds:SignatureValue`, the mandated e-dossier reference
  scope, and the certificate path to a configured anchor.
- **This release can never report a signature as `valid`.** Revocation and
  timestamps are emitted as blocking `skipped` checks
  (`revocation_not_checked`, `timestamp_not_checked`), which caps every verdict
  at `indeterminate`. `invalid` is reachable and meaningful; `indeterminate`
  means "nothing that was checked failed", not "trustworthy". The human output
  says so on every run, and a test asserts it.
- Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, each with and
  without comments, implemented in-tree behind a `C14nBackend` trait over the
  `roxmltree` tree `openszigno-core` already builds. Canonical XML 1.1 and any
  other algorithm are refused with `c14n_unsupported` rather than approximated.
- Pinned algorithm policy: SHA-256/384/512 digests; RSA PKCS#1 v1.5 and RSA-PSS
  with those digests and a modulus of at least 2048 bits; ECDSA P-256 with
  SHA-256 and P-384 with SHA-384. SHA-1, MD5, DSA, every HMAC method, short RSA
  keys, and a curve that does not match the named digest are rejected rather
  than warned about (`algorithm_rejected`).
- Transform allowlist: enveloped-signature, the four canonicalization
  algorithms, and base64. XSLT, XPath, and XPath Filter 2.0 are refused
  unconditionally (`transform_not_allowed`).
- Strictly same-document reference resolution through the ID space
  `openszigno-core` validates, so a duplicate ID stays a parse error and no
  reference can reach the network or the filesystem (`reference_external`,
  `reference_unresolved`).
- Reference-scope enforcement against the e-dossier placement rules
  (`reference_scope_complete` / `reference_scope_incomplete` /
  `reference_scope_unknown`), the container-aware defence against XML signature
  wrapping. Each reference's resolved location is reported as a path of element
  names in `resolved_to`.
- Hand-written certificate-path validation on `x509-cert`: bounded path
  building, link signatures under the algorithm allowlist, validity at the
  validation time, `basicConstraints`, `pathLenConstraint`, `keyUsage`, name
  constraints, and rejection of unrecognised critical extensions. With no trust
  store the answer is `cert_path_unknown` (status `unknown`), never
  `untrusted`.
- `--trust-store DIR` reading `anchors/*` and optional `intermediates/*` as PEM
  or DER; a directory of certificates with no `anchors` subdirectory is read as
  anchors. A file that does not parse, or a store with no anchor, is
  `trust_store_invalid` (exit 3) rather than a silently partial store.
- `--at <RFC3339>` sets the validation time; both the requested and the
  effective time are reported.
- Exit statuses `6` (at least one signature is `invalid`) and `7` (nothing
  invalid, overall verdict `indeterminate`). A structural failure during
  `verify` still exits 4.
- `--allow-legacy-algorithms` admits SHA-1 digests and RSA-SHA1 signature
  methods for diagnosis only, because Hungarian dossiers span 2007 to today.
  They emit `algorithm_legacy_allowed` with status `unknown` rather than a
  passed check, so the verdict stays capped at `indeterminate` and the flag can
  only ever lower a verdict. MD5, DSA, every HMAC method, and RSA keys below
  2048 bits stay refused whatever it is set to, and certificate-path validation
  is not loosened at all.
- Reference-scope matching follows what real dossiers contain: the signature's
  own profile object is located by content and satisfied by a reference to
  either the `ds:Object` holding an `es:SignatureProfile` (in any allowed
  dossier namespace) or to that element itself, in either object order; and
  `xades:SignedProperties` coverage is decided by what a reference *resolves
  to* — the element in any recognised XAdES namespace (1.1.1, 1.2.2, 1.3.2,
  1.4.1) or an ancestor of it — with the `Type` attribute as corroboration
  only, since an attacker controls it. A reference that declares the
  `SignedProperties` `Type` without resolving to one is named in the failure
  message.
- `references[].resolved_to` is populated by the resolution stage, so a caller
  sees what every URI pointed at even when the run stopped at a policy failure
  before any digest was recomputed.
- Candidate certificates are harvested from `xades:CertificateValues` (and any
  other `xades:EncapsulatedX509Certificate` under the signature's XAdES
  properties, in every recognised namespace) as well as `ds:KeyInfo`, which is
  what real dossiers need: they carry only the signer in `ds:KeyInfo` and the
  intermediates and root in `CertificateValues`. **Only the trust store can
  supply an anchor** — a self-signed root found inside a dossier is an
  untrusted candidate like any other. A non-self-signed file in the trust store
  is an extra untrusted intermediate; the `anchors/` and `intermediates/` split
  is a convention, and the verifier classifies what it is given.
- Each `chain` entry now reports `subject_cn`, `issuer_cn`, `serial_hex`,
  `not_before`, `not_after`, `is_trust_anchor`, and `source` (`key_info`,
  `certificate_values`, or `trust_store`). A `cert_path_untrusted` failure says
  how many candidates were considered and names the issuer CN that could not be
  chained, which is the public CA name a caller needs to add to their store.
- The signing certificate is selected as the `ds:KeyInfo` candidate whose key
  actually verifies `ds:SignatureValue`, not the first one listed: XMLDSig
  imposes no order and real material lists the issuer first, which used to
  cause a false `signature_value_invalid`. The choice is reported as
  `signing_certificate_index`, and a total failure says how many were tried.
- `xades:SigningTime` is extracted into `signatures[].signing_time`, normalised
  to RFC 3339 UTC, with the new `signing_time_present` check. It is a *claim*:
  it never becomes the validation time, which stays `--at` or the clock, and it
  is unauthenticated until phase 2 binds it to a timestamp.
- Same-document reference dereferencing now removes comments before transforms
  run, as XMLDSig 4.4.3.3 requires, so a with-comments transform cannot let an
  inserted comment change a digest.
- Path building is bounded by a hard budget of 256 total search expansions, not
  just by completed paths: a bag of same-named certificates that never reaches
  an anchor used to be explored exponentially. Hitting the budget is the new
  `cert_path_search_exhausted`, which says the tool stopped looking rather than
  that no path exists.
- Name constraints follow RFC 5280 section 4.2.1.10 and fail closed. URI
  subtrees are matched against the URI's *host* rather than by substring, so
  `https://evil.test/example.com` no longer satisfies `example.com`; dNSName
  and rfc822Name match on label boundaries; `iPAddress` subtrees are evaluated
  as address and mask instead of ignored; and an unimplemented constraint form,
  an unevaluable name, or a permitted subtree of a type the certificate carries
  but does not match are all violations.
- Critical extensions are accepted only where their semantics are implemented:
  `basicConstraints`, `keyUsage`, `nameConstraints`, `subjectAltName`, and
  `extendedKeyUsage`. `certificatePolicies`, QCStatements,
  `cRLDistributionPoints`, and `authorityInfoAccess` marked critical now fail
  closed. A critical `extendedKeyUsage` must contain `anyExtendedKeyUsage`,
  since no standard EKU authorises document signing.
- A malformed extension is `cert_malformed` rather than an absent one: a
  corrupt `keyUsage` or `nameConstraints` no longer silently vanishes.
- Trust-store entries are parsed as X.509 certificates at load time, so one
  malformed entry among good ones fails the whole store, matching the
  documented all-or-nothing behaviour. The message names the entry's ordinal,
  never the file.
- `openszigno-core`: `XmlSource` and `id_map` are public, and `roxmltree` is
  re-exported, so the verifier resolves references in exactly the tree the
  structural parser saw. `parse` is refactored onto the same entry point with
  no behaviour change.

### Changed (M2)

- `AGENTS.md`, `README.md`, `SECURITY.md`, `docs/architecture.md`, and
  `docs/roadmap.md` state the new boundary: `verify` may report `invalid` but
  never `valid`. The warning `cryptographic_verification_not_performed` keeps
  its meaning for `inspect`, `list`, `extract`, and `validate-structure`, and
  is deliberately not emitted by `verify`.
- `deny.toml` ignores RUSTSEC-2023-0071 with a written reason: the Marvin-attack
  advisory covers `rsa`'s non-constant-time *private-key* operation, no fixed
  release exists, and openSzigno never holds an RSA private key — signing is a
  permanent non-goal and only the public-key verification path is shipped. No
  license allowlist change was needed; every new dependency is MIT, Apache-2.0,
  BSD-3-Clause, ISC, Unicode-3.0, or Zlib.

### Added

- Distribution channels for the CLI: a shell installer, a PowerShell
  installer, a Homebrew formula in the `watt-mind/homebrew-tap` tap,
  `cargo binstall` support through `[package.metadata.binstall]`, and a
  `ghcr.io/watt-mind/openszigno` container image built `FROM scratch` for
  `linux/amd64` and `linux/arm64` with a build-provenance attestation.
- `docs/releasing.md`, describing how a release is cut, what each workflow
  produces, the required secrets, and how to rehearse a release with a
  prerelease tag.
- crates.io metadata (`readme`, `homepage`, `documentation`, `keywords`,
  `categories`) on all three crates, and `publish-crates.yml`, which
  publishes `openszigno-core`, `openszigno-verify`, and `openszigno-cli` in
  that order and skips itself with a notice when `CARGO_REGISTRY_TOKEN` is
  absent.

### Changed

- `.github/workflows/release.yml` is now generated by dist 0.32.0 from
  `dist-workspace.toml` instead of being hand-written. The same five
  targets are built; archives are now named
  `openszigno-cli-<target>.tar.gz` (`.zip` on Windows) and unpack to a
  directory of the same name. A pull request runs only the planning job,
  and a custom job smoke-tests the built musl binary on a synthetic
  fixture before anything is uploaded.
- The crates.io and container publishes now run inside the dist release
  workflow as custom publish jobs (`./publish-crates` and `./container`),
  called as reusable workflows, with `workflow_dispatch` kept for a manual
  rerun after a failed publish.

### Fixed

- The crates.io and container publishes never ran for 0.1.0. GitHub reads a
  `release`-event workflow from the tagged commit, which predated both
  workflows, and dist undrafts the release with `GITHUB_TOKEN`, whose events
  do not trigger any other workflow. Both publishes moved into the release
  workflow itself.

## [0.1.0] - 2026-09-07

### Fixed (M1)

- CI hygiene: `retention-days: 1` on all artifact uploads, and the baseline
  `concurrency` pattern in `ci.yml` so stale PR commits cancel.
- Added `security.yml`: Gitleaks secret scan and workflow lint on push/PR plus
  a weekly run, with CodeQL gated on `vars.CODEQL_ENABLED` until Rust support
  is confirmed.
- Added Rust-appropriate local hooks (`lefthook.yml`, pre-commit fmt+clippy,
  commit-msg Conventional Commits check) and documented the one-time install.
- Added GitHub issue templates (`bug_report`, `feature_request`) modeled on
  the factory set, with matching `type:*` / `source:human` repo labels, plus
  public-intake rules in `CONTRIBUTING.md` and `AGENTS.md` (maintainers mirror
  accepted public issues into Linear; the GitHub issue stays the public face).
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
[0.2.0]: https://github.com/watt-mind/openSzigno/compare/v0.1.0...v0.2.0
[Unreleased]: https://github.com/watt-mind/openSzigno/compare/v0.2.0...develop
