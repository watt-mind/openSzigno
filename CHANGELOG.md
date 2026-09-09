# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

While the project is pre-1.0, the JSON envelope is versioned separately by its
`schema_version` field, which is `1`.

## [Unreleased]

### Changed

- `openszigno-verify`'s reported vocabulary is now open. `CheckCode`,
  `CheckStatus`, `Verdict`, `TrustAnchorOrigin`, and `RevocationPolicy` are
  `#[non_exhaustive]`, so a release that learns to check something new can add
  a code without a semver-breaking change; adding `CheckCode::OcspResponderTrusted`
  is what forced the 0.7.1 retarget to 0.8.0. `CheckCode::ALL` still lists
  every code the linked build knows and the test pinning it is unchanged.
  **This is itself a breaking change for downstream Rust code**: an existing
  `match` on any of the five enums without a wildcard arm stops compiling, so
  it needs a 0.9.0 release rather than a patch. Nothing in the JSON envelope
  changes and `schema_version` stays `1`; the documented rule that a consumer
  must treat an unrecognised code as blocking unless its status is `passed` is
  now enforced by the type system as well as by the documentation.

### Fixed

- `online_options_invalid` (an unusable `--online-proxy` value) now exits
  `3` from `sign --tsa` and `sign --csc`, the same status `verify --online`
  already reported for it. Exit `4` is "invalid, unsafe, or unsupported
  dossier structure, or unusable decryption material"; an unusable option is
  about the caller's own invocation, not the dossier or the key material, so
  `3` ("input/output error") is the documented category. `docs/architecture.md`
  no longer lists this code as "3 or 4".
- An OCSP response could evict the certificates a run already held from
  trusted-responder path building. Path building considers at most
  `max_certificates` candidates, and the pool put the response's own `certs`
  ahead of the run's material, so a response padded up to that bound pushed the
  responder's issuing CA out of the pool and a central responder the caller
  genuinely trusts came back as one nothing vouched for
  (`revocation_data_invalid`). The run's own candidates — `ds:KeyInfo`,
  `xades:CertificateValues`, the trust store — now come first and the
  response's certificates fill the remainder. The bound and the
  per-public-key deduplication are unchanged, so the work one response can ask
  for is bounded exactly as before.
- RFC 6960 section 2.2's trusted-responder model was skipped whenever no
  trust-store anchor was configured, so a run whose only trust is trusted-list
  service identities that are not self-signed never used it. That is the shape
  a national list has: the CA/QC entries name the issuing CAs, which are
  intermediates, so a central responder running under one of them authorised
  nothing and its answers came back `revocation_data_invalid`. The model now
  consults listed identities as path terminators too, exactly as every other
  path does, and is skipped only when nothing whatsoever was configured.

## [0.8.0] - 2026-09-09

### Added

- `openszigno_core::declared_encoding`, which reads the XML declaration's
  `encoding` pseudo-attribute and reports the label together with the byte
  range holding it, so a writer restating the declaration agrees with the
  decoder byte for byte. Additive; `schema_version` stays `1`.
- Two fuzz targets for code that had none. `extract_plan` drives the CLI's
  extraction planner with arbitrary document titles and declared extensions
  and asserts that no planned name is a path, that no two names in one
  directory collide, and that planning is idempotent; `destination_url`
  drives the `--online` destination policy and asserts that it never hands
  the fetcher an address its own verdict refuses, that a non-HTTP scheme and
  userinfo are refused whatever `--online-allow-private` says, and that a
  relative redirect stays on the base URL's authority. Both include the
  shipped module by `#[path]`, because the `openszigno` binary crate has no
  library target to depend on, so what is fuzzed is the real source.
  `decode_payload` now also drives the two `encrypt` chains with no
  decryption key, through `decode_document_with`.
- The golden output contract captures stderr. `scripts/golden.py` kept only
  stdout, so every human-mode golden for a fixture that fails was an empty
  file: the wording of every error and warning an operator actually reads was
  pinned nowhere, and the "no golden may carry a machine-local path" check
  never looked at the stream those messages go to. Each case now writes a
  `<case>.stderr.txt` beside its stdout golden and its `.exit`, the leak check
  runs over both streams, and an `extract --stdout` case pins the one output
  that is not an envelope at all. This adds files and changes none: every
  golden committed before this ran is byte-identical after it. The matrix is
  run by both the CI `golden` job and the release smoke test, unchanged.
- `openszigno_core::declared_encoding`, which reads the XML declaration's
  `encoding` pseudo-attribute and reports the label together with the byte
  range holding it, so a writer restating the declaration agrees with the
  decoder byte for byte. Additive; `schema_version` stays `1`.

### Fixed

- A delegated OCSP responder's certificate is checked for validity at the
  response's `producedAt` rather than at the validation time, matching the
  trusted-responder model beside it and the documented rule. Asking at the
  validation time discarded every archived response whose responder
  certificate has since expired — the certificate was in force when the
  responder spoke, which is what RFC 6960's delegation is about — and it
  admitted one that was not yet in force then. `schema_version` stays `1`.
- A container `es:TimeStamp` selects its data only through an `xades:Include`
  in a recognised XAdES namespace. The element was matched on its local name
  alone, so an element another vocabulary happens to call `Include` added its
  target to the imprint and changed what the timestamp was taken to cover.
  Every other XAdES element in the crate was already read this way.
  `schema_version` stays `1`.
- An OCSP `unknown` status is no longer reported as stale revocation data.
  RFC 6960 section 2.2 gives it its own meaning — the responder does not know
  about this certificate — and calling that staleness told an operator to
  fetch something newer when the responder they asked does not serve the
  certificate at all. It now reports the new check code
  `revocation_status_unknown_by_responder` (`unknown`), which blocks exactly as
  `revocation_data_stale` did. Additive: a new code keeps `schema_version` at
  `1`, and no committed fixture emits it, so no golden file changed.
- A certificate whose outer `signatureAlgorithm` differs from
  `tbsCertificate.signature` is refused with `cert_malformed`. RFC 5280
  section 4.1.1.2 requires the two to be the same algorithm identifier, and
  only the inner one is covered by the CA's signature, so a reader that
  consults the outer field was verifying under an algorithm the CA never
  attested to. An absent `parameters` field and an explicit `NULL` still count
  as agreeing, which is the difference real CAs actually emit.
  `schema_version` stays `1`.
- `--allow-legacy-algorithms` no longer lets an RFC 3161 timestamp token
  report itself as verified on SHA-1. A SHA-1 `messageImprint` emitted
  `timestamp_imprint_ok` (`passed`) and a SHA-1 `SignerInfo` digest emitted
  `timestamp_signature_ok` (`passed`), so the token reached `verified: true`
  and its `genTime` became the validation time — under a flag that exists for
  diagnosis and everywhere else caps the verdict. Both now emit
  `algorithm_legacy_allowed` (`unknown`) instead, so the token stays
  unverified and the verdict stays `indeterminate`. Without the flag both are
  refused exactly as before. `schema_version` stays `1`.
- Document coverage finds the payload `ds:Object` whatever the dossier spells
  its identifier attribute. The parser, the reference resolver and the XAdES
  reader accept `Id`, `ID` and `id`; coverage read only `Id`, so a document
  whose payload object used one of the other two spellings was reported
  `uncovered` by the very signature that digests it, and the dossier's verdict
  was capped at `indeterminate`. `schema_version` stays `1`.
- An OCSP response can no longer make `verify` do unbounded work. The `certs`
  field of a `BasicOCSPResponse` is attacker-supplied and was read in full, and
  every certificate in it naming the responder drove a signature verification
  and, under the trusted-responder model, a whole certification-path search.
  At most `max_certificates` certificates are now read from a response, the
  list is deduplicated by DER, and the path search runs at most once per
  distinct responder public key. No verdict changes: the same responses are
  authorised by the same models, and `schema_version` stays `1`.
- A certification path may now end at any trusted-list service digital
  identity, not only at a self-signed one. In a real national list the CA/QC
  identities are the *issuing* CAs: the Hungarian list records NetLock's
  qualified issuing CAs as CA/QC services with `undersupervision` from 2003 and
  `granted` from 2016-06-30, and records the root that signed them only as a
  QTST service granted from 2018. A path had to climb past the issuing CA to
  the self-signed root and was then judged by that timestamping entry, so a
  2014 signature under a plainly listed qualified CA was refused with
  `trust_list_service_not_granted`. Following ETSI TS 119 615, the nearest
  listed certificate along a chain is now the trust anchor for that path,
  self-signed or not, when its service was granted at the validation time —
  nothing above it is validated, it is the chain's last entry with
  `trust_anchor_origin: "trust_list"`, and `qualified` derives from that
  service as before. When the nearest one's service was not granted then, the
  search still climbs upward and refuses only if no listed certificate and no
  `--trust-store` anchor above it will end the path. `--trust-store` anchors
  and self-signed list entries are unchanged, no field names change, and
  `schema_version` stays `1`.
- Text a dossier chose no longer reaches a terminal or the JSON envelope
  unfiltered. The dossier title, document titles, MIME type halves, the
  declared extension and character set, object references, transform names and
  signature ids were printed and serialised exactly as the input wrote them, so
  a title of `OK<U+202E>txt.exe` displayed as `OKexe.txt` in a `list` and
  `inspect --json` carried the override through to whatever read it, and a
  `subtype` — which nothing in the format bounds — printed in full at any
  length. The C0 and C1 controls were never reachable, because the bounded XML
  parser refuses them; the Unicode `Cf` class and length were. Every command
  that reads a dossier now runs one pass over its finished `data` value, and
  the human summary is rendered from that same value, so both channels are
  covered by the same filter: `Cc` and `Cf` characters are dropped, titles are
  bounded to 256 characters and every other dossier-derived value to 128, each
  cut short value ending in `...` inside its cap. Warnings and errors go
  through the filter too, and `verify` reports a certificate's subject and
  issuer common names the same way. Field names and types are unchanged,
  `schema_version` stays `1`, and no golden file changed: no committed fixture
  carries such a character or exceeds a bound. An extracted file's `path` is
  deliberately untouched — the extraction name rules already refuse a control,
  invisible or formatting character in a title and bound the result, and the
  envelope has to keep naming the file that was written.
- `sign` refuses, with `document_already_signed`, to write a signature into an
  element an existing signature already covers. Only a `URI=""` reference and
  dossier-level cover were detected, so an existing signature whose reference
  resolved to an ancestor-or-self of the insertion point, such as an
  `es:Document` carrying an `Id` of its own referenced by `URI="#doc0"`, was
  broken by a run that reported success. Every existing `ds:Reference` is now
  resolved in the same-document `#id` form, for both scopes, and a reference
  this tool cannot resolve counts as covering.
- `sign` can add a second signature to a document it has already signed. Every
  identifier was derived from the document index, so the second run collided
  with its own first signature and reported `sign_failed` (exit 5) while the
  documentation said co-signing was supported. A base identifier already in
  the dossier is now disambiguated (`sig-doc0-2`, `signed-props-sig-doc0-2`,
  and the rest), and the first signature is left exactly as it was. See
  [Signing a dossier that is already signed](docs/architecture.md#signing-a-dossier-that-is-already-signed).
- `create --zip` names the ZIP member with the trimmed NFC title it writes to
  `es:Title`, not with the raw title. A decomposed or padded spelling put one
  string in the archive and another in the profile, and `extract` names the
  file it writes from the archive member.
- `sign --tsa` treats a negative RFC 3161 `PKIStatus` as a refusal. The
  comparison was `status > 1`, so a negative status read as granted and
  whatever the answer carried was embedded.
- A signature's mandated `es:DocumentProfile` reference is resolved in the
  dossier's own namespace. The lookup matched on the local name alone, so a
  `DocumentProfile` from a foreign namespace, placed first, decided what the
  reference pointed at.
- A named pipe given where a regular file is expected is refused instead of
  waited on. The bounded reader opened the path and only then asked whether it
  was a regular file, and opening a FIFO for reading blocks inside `open(2)`
  until somebody opens the writing end — which is whoever laid the pipe, not
  this tool — so `inspect /path/to/fifo`, or a `--decrypt-key` pointing at one,
  parked the process indefinitely before the check that would have refused it
  could run. On Unix the open now passes `O_NONBLOCK` and the flag is cleared
  on the descriptor once `fstat` has established it is a regular file; the
  refusal is the `io_error` (exit 3) it always should have been. Windows keeps
  the order it had.
- `extract` no longer abandons a whole dossier over one crafted title. Output
  name deduplication produced exactly one candidate, `stem-<document index>`,
  so a dossier holding a repeated title plus a document titled precisely the
  name that deduplication would reach for raised `output_name_collision` and
  wrote nothing at all — every innocent document in the dossier included.
  The candidates now count upwards, `stem-<index>-2`, `-3` and on, up to 64
  per name; `output_name_collision` is kept for the case where all 64 are
  taken. The first candidate, and so every name a dossier that does not
  collide on purpose produces, is unchanged.
- The `--online` destination policy refuses seven more address ranges, each of
  which reaches somewhere no certificate legitimately publishes: carrier-grade
  NAT (`100.64.0.0/10`), IETF protocol assignments (`192.0.0.0/24`),
  benchmarking (`198.18.0.0/15`), the deprecated IPv6 site-local prefix
  (`fec0::/10`), and the three prefixes that carry an IPv4 destination inside
  an IPv6 address — 6to4 (`2002::/16`), Teredo (`2001::/32`) and the
  well-known NAT64 prefix (`64:ff9b::/96`), which were a way of writing a
  private IPv4 destination the IPv4 rules never saw. The IPv4-compatible form
  `::a.b.c.d` is now judged by the address it carries, as the IPv4-mapped
  `::ffff:a.b.c.d` form already was, so `::169.254.169.254` is refused as the
  metadata address it is. `--online-allow-private` waives the new rules
  exactly as it waives the old ones.
- `extract` compares output names with a real case fold. The key was NFC plus
  `to_lowercase`, which is not case folding: it leaves U+017F (`ſ`, long s)
  and U+00DF (`ß`, sharp s) exactly as written, so `ſ.txt` and `s.txt`, or
  `straße.txt` and `STRASSE.txt`, compared as two distinct names — while
  NTFS, which upper-cases to compare, maps each pair onto one file, and the
  second write would have overwritten the first. The key is now NFC, the full
  uppercase mapping, then the full lowercase mapping, which folds both. No new
  dependency: the round trip through uppercase is what expands `ſ` to `s` and
  `ß` to `ss`. It errs towards more names comparing equal than any one
  filesystem merges, which costs a deduplicated name and a warning rather than
  a document.
- A `--trust-store` and a `--revocation-store` are bounded in total, not only
  file by file. Each file had a cap (4 MiB and 16 MiB) and each directory a
  file count (1024 and 4096), which still let a store of a thousand
  just-under-cap files ask the loader for gigabytes before it decided anything.
  The aggregate caps are 64 MiB for a trust store and 256 MiB for a revocation
  store, counted across both of a store's directories so splitting a store does
  not double them, and refused with the store's own code
  (`trust_store_invalid`, `revocation_store_invalid`, exit 3). Every file is
  now read before any of it is parsed or classified, so a store over the total
  is refused for its size rather than for whatever the file that crossed the
  line happened to contain.
- `extract` reports a `<file>.d` subdirectory whose name was taken between the
  plan's existence check and the write as `output_exists` (exit 5), the answer
  an existing output file already got. `mkdir`'s `EEXIST` was mapped to
  `io_error` (exit 3), which told an operator their filesystem had failed when
  in fact the no-clobber rule had worked.
- `scripts/coverage_gate.py` no longer lets a crate or a patch line leave the
  gate quietly. A crate under `crates/` that produced no coverage records
  vanished from the totals altogether, and `pct(covered, 0)` scored 100, so an
  unmeasured crate read as a fully covered one; both are failures now. The
  `-U0` diff behind patch coverage is parsed with a state machine keyed on
  `diff --git` and `@@` rather than by line prefix, so an added source line
  beginning with `++` is no longer read as a `+++ b/path` file header — which
  silently repointed or dropped every line after it — and the diff is taken
  with explicit `--src-prefix`/`--dst-prefix`, so a contributor's
  `diff.noprefix` cannot change what the parser strips.
  `--self-test` runs the parser's unit tests, and CI runs it before the
  measurement it guards.
- `sign` no longer rewrites the dossier's own text when it fills a signature
  in. The digest, signature-value and timestamp placeholders were substituted
  over the whole document, so a document whose title or payload read like one
  of them was rewritten after the digest over it had been taken: the run
  reported success and `verify` then reported `reference_digest_mismatch`.
  Each pass now substitutes inside the byte range of the `ds:Signature` it is
  filling in and nowhere else.
- `sign` accepts every XML declaration the reader accepts when it restates the
  encoding. Only `encoding="..."` was recognised, so a dossier declared with
  single quotes or with spaces around the `=` was decoded to UTF-8 and then
  still declared ISO-8859-2. The declaration is now read with the reader's own
  parser, `openszigno_core::declared_encoding`, and only the label's own bytes
  are replaced.
- Every file the CLI reads because a caller named it now goes through one
  bounded reader. The key, certificate, passphrase, trust-store and
  revocation-store loaders checked a path's size and type and then read the
  path a second time, so replacing or growing the file in between bypassed
  both checks. The file is now opened once, with `O_NOFOLLOW` on Unix and
  `FILE_FLAG_OPEN_REPARSE_POINT` on Windows, its type and size come from an
  `fstat` on that descriptor, and the bytes are read through a cap that stops
  one byte past the limit. Every code, message and cap is what it was; a file
  of exactly the cap is still read. An input that is not a regular file is
  still `io_error` (exit 3), and now reports `input.bytes` as `null` on every
  operating system rather than a directory's own length, which meant different
  things on different platforms and was never a payload size. See
  [Bounded file reads](docs/architecture.md#bounded-file-reads).
- Strings a remote Cloud Signature Consortium service chose are sanitised
  before they reach human output, an error message or the JSON envelope:
  credential identifiers, the reported `specs` version, the published key
  algorithms and the `error` string of a refusal. Unicode `Cc` and `Cf`
  characters, which is where ANSI escapes and bidirectional overrides live,
  are dropped, and the value is bounded. A service can no longer move the
  cursor or reorder what is printed around it. The filter is
  `openszigno_core::sanitize_display`, which the XMLDSig structure pass now
  shares.

### Security

- `sign` no longer lets the dossier being signed choose what the operator's
  key signs. The `OBJREF` and `Id` attributes a reference points at, the
  declared media type an `xades:DataObjectFormat` carries and the root
  namespace the signature profile object declares were interpolated into the
  signature XML unescaped, and every digest is computed after the values are
  already in the document, so a hostile dossier could write an
  attacker-supplied `ds:Reference` with no transforms or a forged
  `xades:CommitmentTypeIndication` into what was signed, and `verify` would
  then accept all of it. Both halves are fixed: an `Id` or `OBJREF` that is
  not an XML NCName, a media type outside the characters a media type may
  use, and a namespace URI holding a markup delimiter, a quote character or a
  control character are all refused with `document_not_signable`; and every
  remaining interpolation goes through the writer's attribute and text
  escapers, so no dossier-derived string reaches signature XML unescaped.
- `verify` now selects the XAdES qualifying properties a signature is
  evaluated against by what that signature's own references cover, rather than
  by taking the first `xades:QualifyingProperties` (stage C) and the first
  `xades:SignedProperties` (the reference-scope check) under the signature. A
  `ds:Object` is open content the XMLDSig schema allows any number of, and no
  reference has to cover one, so a single inserted decoy object changed the
  verdict without touching a signed byte: an empty
  `<ds:Object><xades:QualifyingProperties/></ds:Object>` prepended to a
  certificate-substitution dossier turned `xades_signing_certificate_mismatch`
  (`failed`, so `invalid`) into `xades_signing_certificate_absent` (`unknown`,
  so `indeterminate`), and a decoy carrying an unsigned
  `xades:SignedProperties` turned a sound signature into
  `reference_scope_incomplete` and its document into `documents_uncovered`.
  Every `SignedProperties` a signature owns now satisfies the scope
  requirement, stage C reads the covered one, a signature covering none of its
  own reports `xades_signing_certificate_absent` as before, and a second
  `xades:QualifyingProperties` is reported once as the new
  `xades_extra_qualifying_properties` (`info`) and otherwise ignored. Real
  XAdES signatures reference their `SignedProperties`, so the rule is a no-op
  for conformant material; `schema_version` stays `1`.
- Revocation no longer stops at the first source that gives a definite answer.
  The signature's own `RevocationValues` were read first, so a genuine but
  older embedded OCSP `good` still inside its own `nextUpdate` hid the newer
  CRL in `--revocation-store` that revoked the same certificate: the run
  reported `revocation_ok`, a chain entry sourced `embedded_ocsp`, and a
  `valid` verdict. Every source is now asked about every certificate and the
  answers are weighed: a revocation from any source beats `good` from any
  other, and among answers that say the same thing the one speaking for the
  later `producedAt` or `thisUpdate` is the one reported. The freshness rules
  and the revocation-after-validation-time rule are unchanged. A new
  `revocation_sources_disagree` check (`info`, non-blocking) reports a
  disagreement and names both sides, and the same sentence is added to that
  certificate's `chain[].revocation.detail`. Additive; `schema_version` stays
  `1`. See [Which answer wins](docs/architecture.md#which-answer-wins).
- A trusted-list anchor no longer ends a certification path at a time its
  service was not granted. The anchor set was built from every configured
  anchor with no status filter and a path ended at any of them, so a
  `withdrawn`, `supervisionceased` or `deprecated*` CA/QC or TSA/QTST service
  still produced `cert_path_ok` at a validation time after the withdrawal;
  `granted_at` reached only the informational `qualified` flag, and the
  `trust_list_service_not_granted` code was declared but never emitted. A
  completed path now consults the anchor's `ServiceRecord` — CA/QC for a
  signing or OCSP-signing path, TSA/QTST for a timestamping one — and a
  non-granted anchor yields `trust_list_service_not_granted` (`unknown`,
  blocking) instead of `cert_path_ok`, after the other candidate paths have
  been tried. It is `unknown` rather than `failed`, because missing trust is
  not evidence against a signature: the verdict is capped at `indeterminate`
  and is never `invalid` for this reason. A `--trust-store` anchor is
  unaffected, and where a list records a certificate only under a service of
  another kind it is treated as a trust-store anchor would be, provided some
  service it does record was granted then. See [A path may only end at a
  service that was granted
  then](docs/architecture.md#a-path-may-only-end-at-a-service-that-was-granted-then).
- `sign` no longer lets the dossier being signed choose what the operator's
  key signs. The `OBJREF` and `Id` attributes a reference points at, the
  declared media type an `xades:DataObjectFormat` carries and the root
  namespace the signature profile object declares were interpolated into the
  signature XML unescaped, and every digest is computed after the values are
  already in the document, so a hostile dossier could write an
  attacker-supplied `ds:Reference` with no transforms or a forged
  `xades:CommitmentTypeIndication` into what was signed, and `verify` would
  then accept all of it. Both halves are fixed: an `Id` or `OBJREF` that is
  not an XML NCName, a media type outside the characters a media type may
  use, and a namespace URI holding a markup delimiter, a quote character or a
  control character are all refused with `document_not_signable`; and every
  remaining interpolation goes through the writer's attribute and text
  escapers, so no dossier-derived string reaches signature XML unescaped.
- The release workflow no longer pipes the cargo-dist installer script into a
  shell. `.github/workflows/release.yml` runs with `contents: write`, so a
  tampered installer asset would have run with a token that can rewrite the
  GitHub release and the binaries published from it. Both jobs that install
  dist from the network, `plan` and each leg of `build-local-artifacts`
  (`irm | iex` on Windows), now use `.github/actions/install-dist`, a
  composite action that downloads the prebuilt cargo-dist archive for the
  runner's target from the same release, checks its SHA-256 against a
  checksum pinned in the action, and only then unpacks the binary. A mismatch
  fails the step. The other jobs already reused the binary cached by `plan`.
  See [Installing dist in CI](docs/releasing.md#installing-dist-in-ci) and
  [Bumping dist](docs/releasing.md#bumping-dist), which also records the exact
  diff to reapply after `dist generate` rewrites the workflow.
- The online transport refuses a redirect that leaves `https` for `http`, for
  every request kind, as `destination_refused` with the rule
  `redirect_downgrade`. A redirect could previously stay on the host the
  certificate or the configuration named and change the scheme, and the next
  hop then went out in the clear carrying whatever the first one carried.
- A request that carries credentials — a bearer token in the `Authorization`
  header, or a body the caller marked sensitive, which every `sign --csc`
  request now is — requires `https` on every hop, the first included, and is
  refused as `destination_refused` with the rule `credentials_require_https`
  otherwise. The one exemption is a loopback service under
  `--online-allow-private`, granted on the addresses the destination policy
  approved rather than on the host text. A refusal reaches `sign --csc` as
  `csc_unreachable` naming the rule, and nothing is contacted.
- The `Authorization` header is attached only after a target has passed the
  destination policy, the credential rule and the address pin, so a target
  that failed any check is never sent one.

## [0.7.0] - 2026-09-09

### Added

- `docs/remote-signing.md`, the research behind this milestone's authoring
  commands: the Cloud Signature Consortium API versions and the hash-signing
  flow a client would run, the EUDI Wallet rQES reference components and how
  to run one locally, a remote QSCD provider table, RFC 3161 timestamp
  authorities and whether they need an account, what Hungarian courts and the
  company registry accept, a recommended first backend, and everything that
  could not be verified. Indexed in `docs/index.md` and `docs/references.md`.
  Documentation only; no behaviour changes.
- `openszigno create`, the first command that writes a dossier: it builds one
  new, unsigned `es:Dossier` from files on disk, with
  `--document PATH[::TITLE[::MIME]]`, `--zip`, `--embed`, `--created`, and
  `--json`. Output is deterministic (fixed element order, positional
  `obj<n>`/`profile<n>` identifiers, a pinned ZIP modification time), so the
  same inputs with the same `--created` produce a byte-identical file; the
  one exception is `--encrypt-for` below, which must draw on a random source.
  Every
  parser limit bounds it, every document title is checked against the rules
  `extract` applies to a filename, an existing output file is `output_exists`
  rather than an overwrite, and every run warns `created_dossier_unsigned`.
  See [The create command](docs/architecture.md#the-create-command).
- `openszigno-author`, a new published crate holding that writer. It reads no
  file, opens no socket, and calls no clock; `openszigno-core` stays
  read-only. It depends on `openszigno-verify` for canonicalisation and
  `openszigno-cli` depends on it, so it is published after
  `openszigno-verify` and before `openszigno-cli`.
- Stable codes for authoring: the errors `no_documents`,
  `unsafe_document_title`, `invalid_dossier_title`, `unknown_mime_type`,
  `invalid_mime_type`, `zip_failed`, and `invalid_output_path`, and the
  warning `created_dossier_unsigned`. `too_many_documents`,
  `decoded_too_large`, `total_size_limit`, and `zip_ratio_limit` are reused
  with their existing meanings. Additive: `schema_version` stays `1`.
- `tests/fixtures/created.es3`, the dossier `create` builds from the two new
  synthetic inputs under `tests/fixtures/create/`, plus a `create` case in
  the golden matrix.
- `openszigno create --encrypt-for CERT`, repeatable, which writes every
  `--document` payload as a CMS `EnvelopedData` addressed to each recipient
  certificate (PEM or DER), the forward direction of
  `extract --decrypt-key`. AES-256-CBC content encryption with a fresh
  content key and initialisation vector per document, and RSAES-OAEP with
  SHA-256 and MGF1-SHA-256 key transport per recipient, named by
  `issuerAndSerialNumber`; `--legacy-key-transport` writes RSAES-PKCS1-v1_5
  instead. DES-EDE3-CBC is never written. `--zip` under encryption makes the
  ZIP the plaintext (`zip -> encrypt -> base64`); an `--embed` dossier stays
  in the clear. `create` output is not deterministic with `--encrypt-for`,
  because a content key must be unpredictable. Each `create` document now
  reports `encrypted` in the JSON envelope, the human summary marks such a
  document `| encrypted`, and the new codes are the errors
  `invalid_recipient_certificate`, `unsupported_recipient_key`,
  `no_recipients`, and `encrypt_failed` (exit 4) and the warning
  `recipient_certificate_expired`. Additive: `schema_version` stays `1`.
  See [Encrypting for a recipient](docs/architecture.md#encrypting-for-a-recipient).
- `openszigno sign`, which writes a signed copy of a dossier: one enveloped
  XMLDSig/XAdES signature per document, or one over the dossier with
  `--scope dossier`. It writes the reference set the e-dossier scope rules
  mandate, exclusive canonicalization and SHA-256 throughout,
  `xades:SigningTime` and `xades:SigningCertificateV2` in the signed
  properties, `xades:CertificateValues` from `--chain` and `--tsa-cert`, and
  the signer certificate in `ds:KeyInfo`. Flags: `--output`, `--key`,
  `--cert`, `--passphrase-file`, `--chain`, `--scope`, `--document`, `--tsa`,
  `--tsa-cert`, `--signing-time`, `--algorithm`, `--online-allow-private`,
  `--online-proxy`, and `--json`. RSA PKCS#1 v1.5 with SHA-256 is the default
  and is deterministic given the same key, time and inputs; `rsa-pss-sha256`
  and `ecdsa-p256-sha256` are offered and are randomised. The key, its
  certificate and its passphrase come from files or from the existing
  `OPENSZIGNO_DECRYPT_PASSPHRASE`, never from `argv`. Signing verifies
  nothing, and every successful run warns `signed_dossier_unverified`. See
  [The sign command](docs/architecture.md#the-sign-command).
- `--tsa URL` on `sign`, which posts an RFC 3161 `TimeStampReq` and embeds the
  token as an `xades:SignatureTimeStamp`. It is the only thing that makes
  `sign` open a socket, and it goes through the same transport, destination
  policy, address pinning, timeouts and size caps `verify --online` uses;
  `--online-allow-private` and `--online-proxy` mean there what they mean
  there.
- The signing library in `openszigno-author` (`sign` module): the `Signer`
  trait a later remote backend implements, `SoftwareSigner` for a local
  PKCS#8 key, the XMLDSig and XAdES rendering, and RFC 3161 requests and
  responses as bytes in and bytes out. The crate still reads no file and
  opens no socket.
- Stable codes for signing: `invalid_signing_key`,
  `invalid_signing_certificate`, `signing_certificate_required`,
  `signing_key_mismatch`, `document_not_signable`, `document_already_signed`,
  `tsa_failed`, and `sign_failed`, plus the warning
  `signed_dossier_unverified`. `document_not_found`, `invalid_output_path`,
  `output_exists`, `unsafe_output_directory` and `io_error` are reused with
  their existing meanings. Additive: `schema_version` stays `1`.
- A `sign` refusal in the golden matrix. A successful signing run cannot be a
  golden: it needs a private key, and this repository commits none.
- `openszigno sign --csc CONFIG.toml`, a second signing backend: the digest of
  the canonicalised `ds:SignedInfo` is signed by a Cloud Signature Consortium
  API v2 service, so a qualified certificate held by a remote signature
  creation device, or in an EUDI Wallet, produces the same XAdES structure the
  software signer does. Only the digest ever leaves the machine. The run does
  `info`, `credentials/list` when no credential is named, `credentials/info`
  with `certificates: "chain"`, then per signature `credentials/authorize`
  with the real hash and `numSignatures: 1` and `signatures/signHash`; the
  returned signature is verified locally against the returned certificate
  before anything is written. Discovery is read from `info` rather than
  compiled in, the algorithm comes from the credential's own `key/algo` list,
  and the chain the service publishes becomes `xades:CertificateValues` so
  `--chain` stays optional. `--csc-credential ID` picks one credential; the
  requests go through the same bounded transport `verify --online` uses, and
  the bearer token travels in the `Authorization` header and nowhere else.
  This round is non-interactive: an `oauth2`-mode credential is
  `csc_authorization_required`, and the OAuth 2.0 rounds it needs are the
  follow-up `openszigno csc login`. See
  [Signing through a CSC service](docs/architecture.md#signing-through-a-csc-service).
- Stable codes for that backend: the errors `csc_config_invalid`,
  `csc_unreachable`, `csc_rejected`, `csc_credential_ambiguous`,
  `csc_credential_unusable`, `csc_authorization_required` and
  `csc_signature_invalid`, and the warnings `csc_config_permissive` and
  `csc_key_unused`. `sign`'s JSON `data.signatures[]` entries gain `signer`
  (`software` or `csc`), and a `csc` entry also carries `credential_id` and
  `csc_specs`.

### Changed

- The extraction title sanitizer takes its rules from `openszigno-author`, so
  a title `create` refuses is exactly a title `extract` would refuse. No
  behaviour of `extract` changed.
- `author` is an accepted Conventional Commits scope
  (`scripts/commit-msg.sh`, `CONTRIBUTING.md`).

## [0.6.0] - 2026-09-08

### Added

- `crates/openszigno-cli/skills/openszigno/SKILL.md`, an Agent Skills
  document that tells an AI agent how to drive the CLI on a dossier: the
  always-`--json` rule, exit statuses, the inspect, list, extract, decrypt
  and verify workflow, the trust-material recipe, the check codes behind
  most `indeterminate` verdicts, and how to report a result without
  overstating it. Linked from the README and the documentation index.
- `openszigno skill`, which writes that document to stdout byte for byte
  and nothing else, so the single distributed binary carries the skill:
  `openszigno skill > .claude/skills/openszigno/SKILL.md` installs it with
  no checkout. It takes no `FILE` and no `--json`, and emits no JSON
  envelope.
  A `.gitattributes` rule keeps Markdown at LF on every checkout, so the
  embedded bytes are the same whichever host built the binary.

## [0.5.1] - 2026-09-08

### Fixed

- The CI `hygiene` job no longer re-checks commits that are already on
  `develop` when a release pull request promotes `develop` to `master`;
  those passed the check on the pull request that landed them, and two
  older commits predate the rule.

### Security

- `verify` stage A1 now enforces the cardinality and order the XMLDSig
  schema fixes for `ds:Signature`, `ds:SignedInfo` and each `ds:Reference`
  before any critical child is read by name. Previously each child was
  located by a first-match lookup, so a signature carrying a second
  `ds:SignatureValue`, `ds:SignedInfo`, canonicalization or signature
  method, `ds:Transforms`, `ds:DigestMethod` or `ds:DigestValue`, or one
  whose children appeared out of order, was accepted: openSzigno read the
  first copy and reported a passed `signature_value_ok` while another
  consumer could read the other. Such a signature now fails
  `sig_structure_invalid`, with a message naming the element and whether it
  is a duplicate, out of order, or a child the schema does not allow there,
  and the verdict is `invalid`. The schema's extension points stay open:
  `ds:Object` and `ds:KeyInfo` content is unconstrained, so XAdES
  qualifying properties are unaffected, and whitespace and comments between
  children are ignored. See
  [docs/architecture.md](docs/architecture.md#xmldsig-structural-rules).
- `extract --decrypt-key` no longer reports that a PKCS#1 v1.5 wrapped
  content-encryption key failed to unpad. The RSA key transport now rejects
  **implicitly**, the mitigation OpenSSL 3.2+ ships as
  `RSA_PKCS1_IMPLICIT_REJECTION` and RFC 5246 section 7.4.7.1 prescribes: the
  blinded private operation runs once, the block is unpadded in constant time
  against the announced content cipher's key length, and any fault is answered
  with a deterministic synthetic key derived from a per-key secret over the
  ciphertext, after which content decryption runs unconditionally. A bad
  wrapped key now fails as the content cipher does, with the same
  `decrypt_failed` code and `decryption failed` message as a tampered body, so
  a caller who submits chosen dossiers can no longer read a
  Bleichenbacher/Marvin padding oracle (RUSTSEC-2023-0071) off the outcome,
  the error, or the coarse timing. RSAES-OAEP takes the same shape. What
  remains is `rsa` 0.9's non-constant-time private exponentiation, which
  blinding masks and `rsa` 0.10 will retire; the `deny.toml` ignore now covers
  only that. See
  [SECURITY.md](SECURITY.md#rsa-key-transport-decryption-implicit-rejection)
  and
  [docs/architecture.md](docs/architecture.md#rsa-key-transport-implicit-rejection).
  One consequence: an unusable wrapped key is decrypted under the synthetic
  key, so the failure surfaces further down. Almost always that is the content
  cipher's padding, as `decrypt_failed`; roughly once in 256 the padding of
  garbage is valid by chance and the answer is `source_size_mismatch` instead.
  Decryption never asserted authenticity.

## [0.5.0] - 2026-09-08

### Added

- The CI `semver` job runs `cargo-semver-checks` for `openszigno-core` and
  `openszigno-verify` against the version already published on crates.io,
  failing on a breaking API change unless the crate's `Cargo.toml` version
  was bumped to cover it. See
  [docs/releasing.md](docs/releasing.md#semver-checks) for how this applies
  to the pre-1.0 `0.x` crates here. The `openszigno-verify` step ran as
  advisory until this release, because `develop` carried breaking API
  changes relative to the published `0.4.0` (new public fields on
  `SignatureCoverage` and `ChainEntry`, a new `RevocationPolicy` variant,
  and a renamed `SignatureCoverage` field); the `0.5.0` bump covers them
  and both steps block again.
- The CI `hygiene` job, on pull requests only, runs `scripts/commit-msg.sh`
  (now reusable with a file path or `-` for stdin, in addition to its
  original hook mode) over every commit subject in the pull request's
  range, skipping merge commits and `dependabot[bot]`/`github-actions[bot]`
  commits, and requires the pull request body to contain a
  `Fixes`/`Closes`/`Refs LAB-<n>` line unless the pull request is
  bot-authored or labelled `no-ticket`. See
  [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).
- The CI `lint` job now runs `cargo machete` to catch dependencies declared
  in a manifest but never used. See
  [CONTRIBUTING.md](CONTRIBUTING.md#required-checks) for how to reproduce it
  locally and how to record a dependency that is only reachable through a
  macro or a feature.
- Nightly fuzzing of the parsers with `cargo-fuzz`: a `fuzz/` package (LAB-268,
  excluded from the workspace so it never touches the stable MSRV build) with
  ten targets covering dossier parsing, payload decoding, CMS decryption,
  C14N canonicalization, and CRL, OCSP, RFC 3161 timestamp, trusted-list, and
  certificate parsing, each asserting only that the function under it never
  panics. `.github/workflows/fuzz.yml` runs every target nightly and on
  manual dispatch; a crash uploads the minimised reproducer and opens or
  refreshes a tracking issue. See
  [docs/testing.md](docs/testing.md#fuzzing).
- Golden output contract tests under `tests/golden/`: the stdout and exit
  status of `inspect`, `list`, `validate-structure`, `verify` and `extract`
  over every fixture in `tests/fixtures/`, in `--json` and human mode, plus
  two trusted `verify` runs over the signed XMLDSig vector.
  `scripts/golden.py check --bin <binary>` diffs the built binary against
  them and `update` regenerates them; the new CI `golden` job and the release
  smoke test both run `check`. Only two clock-dependent times are masked. A
  diff is a change to the JSON envelope contract and is reviewed under the
  `schema_version` rule; see
  [tests/golden/README.md](tests/golden/README.md).
- `--online-allow-private` on `verify`, which permits `--online` to contact
  loopback, private, link-local and unique-local destinations and the name
  `localhost`. It requires `--online`, waives the address rules and nothing
  else, and exists for an internal CA that really does publish on the
  operator's own network.
- `policy.revocation` has a fourth value, `online_no_anchors`, for a run given
  `--online` with no trust anchor configured: nothing was fetched, and both the
  `revocation_policy` check and every `revocation_status_unknown` message now
  say why rather than leaving the caller with an unexplained gap.
- `scripts/check-file-length.py`, run in CI's Documentation job, fails a
  tracked `crates/*/src/*.rs` file over 800 physical lines or a
  `crates/*/tests/*.rs` file over 1500, with a shrink-only allowlist in
  `scripts/file-length-allowlist.txt` for files that already exceeded the
  limit before the guardrail was added. See
  [CONTRIBUTING.md](CONTRIBUTING.md#documentation).
- `clippy::too_many_lines` is now a workspace lint, with `clippy.toml`
  setting `too-many-lines-threshold`. See
  [CONTRIBUTING.md](CONTRIBUTING.md#required-checks) for the current
  threshold and the plan to lower it.
- `scripts/coverage_gate.py`, run in CI's Coverage job, enforces a 90%
  per-crate line-coverage floor, 80% patch coverage on lines a pull
  request adds or modifies under `crates/*/src/` (when at least 20
  instrumentable lines changed), and a ratchet against
  `scripts/coverage-floors.txt` so a crate cannot silently drop more than
  1.0 point below its recorded coverage. The job posts and refreshes a
  single PR comment with the summary. See
  [CONTRIBUTING.md](CONTRIBUTING.md#coverage-quality-gate).
- `.github/workflows/mutants.yml`, a nightly (and manually dispatchable)
  `cargo-mutants` run over `openszigno-core` and `openszigno-verify`.
  `scripts/mutants_gate.py` enforces a ratchet against
  `scripts/mutants-floors.txt`, the same model as the coverage floors: a
  crate's caught-mutant percentage cannot drop more than 2.0 points below
  its recorded value. It is not a required pull-request check; a gate
  failure opens or refreshes a single "Mutation testing: survivors" issue
  instead. See [docs/testing.md](docs/testing.md#mutation-testing).

### Tests

- Behavioural tests for the first batch of `cargo-mutants` survivors from the
  LAB-267 seeding pass: `decode.rs`'s compression-ratio boundary and ZIP
  symlink guard, `scan.rs`'s depth/node-limit and self-closing-tag
  arithmetic, `inventory.rs`'s first-occurrence match guards,
  `trust.rs`'s `TrustSource`/`RevocationSource` accessors and further
  `parse_rfc3339` boundaries, and `scope.rs`'s signature-profile
  node-ownership guard. Raised the `openszigno-core` mutation floor from
  89.46% to 91.12% (full-crate run) and `openszigno-verify` from 70.59% to
  78.99% (the same `--shard 1/4` slice it was seeded from). See
  [docs/testing.md](docs/testing.md#mutation-testing).

### Changed

- `README.md` restructured from 536 lines to a scannable front door. "Why and
  for whom" now sits directly under the security boundary instead of behind
  the installation block, and states what the tool offers agents, people, and
  anyone handling hostile input. Installation is one block per channel, the
  quick start is one human, one `--json`, and one `verify` example, and the
  command reference is a single table with each command's exit statuses. The
  reference material moved out of it, deduplicated: the flag tables, the
  global and `extract` flags, and the full `verify` flag table are now in
  [docs/architecture.md](docs/architecture.md), which already held the JSON
  envelope, the stable codes, the exit statuses, and the limits; the
  "what is not supported yet" list is now a "Not yet implemented" section in
  [docs/roadmap.md](docs/roadmap.md), refreshed because M2 phase 2, M2 phase 3,
  and M3 have all shipped since it was written. The README's LEGAL section no
  longer claims that verification can report "only `invalid` or
  `indeterminate`", which stopped being true when revocation checking landed.
- Internal module split of the CLI crate: `crates/openszigno-cli/src/main.rs`
  became `args`, `input`, `response`, `render/`, `commands/`, `extract/`, and
  `trust`, and each unit test moved next to the code it covers. No behaviour
  change — every flag, help text, message, stable code, exit status, and byte
  of JSON and human output is what it was. See
  [docs/architecture.md](docs/architecture.md#module-map-openszigno-cli).
- `openszigno-verify` was split into one module per pipeline stage: internal
  module split, no behaviour change. `dsig.rs` became `references`, `scope`,
  `countersign`, `signature` and `coverage`; `lib.rs` now reads as the
  documented stages A to F with one `Context` threaded through them. Every
  check code, status, message, ordering and JSON field is unchanged, and the
  crate's public API keeps the paths it had. See
  [docs/architecture.md](docs/architecture.md#module-map).
- Second-round internal split of the five remaining oversized
  `openszigno-verify` sources, moving code verbatim with no behaviour change:
  `certs.rs` became `certs/` (`extensions`, `purpose`, `names`, `path`),
  `revocation.rs` became `revocation/` (`crl`, `ocsp`, `tiers`), `tsa.rs`
  became `tsa/` (`token`, `imprint`, `path`, `tests`), `signature.rs` gained
  `signed_info` and `collect`, and `trustlist.rs` became `trustlist/`
  (`parse`, `services`, `qualified`). Every check code, status, message,
  ordering and JSON field is unchanged, and every public item keeps its old
  path through `pub use` re-exports. No `openszigno-verify` source file is
  named in `scripts/file-length-allowlist.txt` any more. See
  [docs/architecture.md](docs/architecture.md#module-map).
- `crates/openszigno-verify/tests/common/mod.rs` (2394 lines) was split into
  `pki.rs`, `dossier.rs`, `signer.rs`, `timestamps.rs`, `cms.rs` and
  `trustlist.rs`, with `mod.rs` reduced to module declarations and `pub use`
  re-exports; every existing `use common::{...}` import keeps compiling
  unchanged. Code moved verbatim, no behaviour change. See
  [docs/testing.md](docs/testing.md#test-layout).
- `crates/openszigno-core/src/decrypt.rs` (1008 lines) was split into
  `decrypt/mod.rs`, `cms.rs`, `ciphers.rs` and `keys.rs`, one module per
  concern of the `encrypt` transform: CMS `ContentInfo`/`EnvelopedData`/
  `RecipientInfo` parsing and key unwrap, content-cipher identification and
  AES/3DES-CBC decryption, and recipient key loading and certificate
  matching. Code moved verbatim; `DecryptOptions` and `RecipientKey` keep
  their `openszigno_core::` paths, and every error code, message and test is
  unchanged. Removed from `scripts/file-length-allowlist.txt`. See
  [docs/architecture.md](docs/architecture.md#module-map-openszigno-core).

### Fixed

- `--online` ran one offline pre-pass and then one fetch, so evidence a fetch
  produced could not open a path the pre-pass had ruled out. A signer whose
  certificate has expired has no validated path at the clock, and so nothing
  may be fetched for it; fetching the revocation evidence its signature
  timestamp's authority needed can verify that timestamp, move the signer's
  validation time back to the instant the token proves and restore its path,
  but by then fetching had finished and the signer's own revocation data was
  never requested. Fetching now runs in at most three bounded rounds: each
  round verifies with everything fetched so far and fetches only for the
  certificates that round made eligible, stopping as soon as a round turns up
  nothing new. Coverage is judged at the validation time each path was
  actually evaluated at rather than at one global time, so evidence that is
  fresh at a proven historical instant is no longer re-requested for being
  stale at the clock. The certificate budget (32) is a budget for the run, the
  trust gate, the destination policy, `--online-cache` and the
  `online_fetch_failed` checks are unchanged, and the JSON envelope is
  unchanged. `VerifyReport::validated_path_certificates_at` is the new
  verify-crate method the CLI reads the set and its times from; the existing
  `validated_path_certificates` keeps its signature and its meaning.
- `--online` deduplicated fetches by URL alone, so two certificates issued by
  the same CA — which name the same AIA responder — produced one OCSP request
  and left the second certificate uncovered for a reason nothing in the report
  named. OCSP is now deduplicated by responder URL **and** `certID`, and CRLs
  by URL, which is the right key for a list. `--online-cache` names a cached
  OCSP response by the `certID` it answers about as well as by its own bytes,
  so two answers from one responder stay distinguishable.
- Revocation evidence had three size limits: downloads and the
  `--revocation-store` loader accepted 16 MiB while the tier walk silently
  skipped anything over 8 MiB, so a CRL between the two figures loaded, was
  stored, and then answered nothing. There is now one constant,
  `openszigno_verify::MAX_REVOCATION_ITEM_BYTES` (16 MiB), used by the verifier,
  the fetch cap and the store loader, and oversized evidence is reported —
  as `revocation_data_invalid` in the tier walk, as a store-loading error, and
  as an `online_fetch_failed` — naming the size and the limit instead of being
  passed over in silence.
- `parse_rfc3339` (the RFC 3339 parser shared by `--at`, trusted-list dates,
  and `xades:SigningTime`) bounded the day of month to 1..=31 regardless of
  the month, so a calendar-impossible date like `2026-02-31T00:00:00Z` parsed
  and silently became `2026-03-03`. It now validates real month lengths and
  Gregorian leap years. `--at` with such a date is now a usage error (exit
  2); a `SigningTime` with one still parses to `None`, which every caller
  already treats as an absent, unauthenticated claim.
- `extract`'s rollback of a partially written output tree used
  `Iterator::all`, which stops at the first failed removal and never even
  attempts the entries after it. It now attempts every recorded entry once,
  in the same reverse creation order, regardless of earlier failures, and
  still reports "files may remain" if any removal failed.
- `extract --decrypt-key`'s RSA key-transport decryption now uses
  `RsaPrivateKey::decrypt_blinded` instead of plain `decrypt`, closing the
  timing side-channel on the private-key modular exponentiation
  (RUSTSEC-2023-0071). The `deny.toml` ignore rationale for that advisory is
  corrected: the RSA ciphertext being decrypted comes from the dossier under
  analysis, not the operator, so a service that decrypts many
  attacker-submitted dossiers against one key is exposed to a
  Bleichenbacher/Marvin-style chosen-ciphertext attack; direct local use is
  not. See [SECURITY.md](SECURITY.md) and
  [docs/architecture.md](docs/architecture.md#decryption).

### Security

- `--online` now connects to the addresses its destination policy actually
  vetted. The policy resolved a host, judged the addresses it got back, and
  then handed the *name* to `ureq`, which resolved it a second time; a zone
  answering with a public address first and a private one second walked past
  the address rules through the gap between the check and the socket.
  `permitted` now returns the endpoint it approved together with its
  addresses, and the fetcher pins exactly those as the resolution for that
  host and port through a `ureq` `Resolver` that answers from the pinned map
  and refuses every other name rather than falling back to system DNS. Every
  hop is pinned in its own right, so a redirect target is dialled on its own
  vetted addresses. Only the address is pinned: the URL is sent as published,
  so the `Host` header, the TLS SNI value and the certificate host-name
  verification still use the name the certificate published. A host that
  resolves to nothing is reported as `transport` and nothing is contacted. No
  new refusal rule and no output change. With `--online-proxy` the request is
  sent to the proxy and the proxy resolves the destination, so the destination
  policy still checks the URL but the proxy is what opens the socket; that is
  now stated in [docs/trust.md](docs/trust.md#online-fetching),
  [docs/architecture.md](docs/architecture.md) and
  [SECURITY.md](SECURITY.md).
- `--online` no longer fetches revocation data for a certificate the run does
  not trust. A URL is contacted only for a certificate on a certification path
  the verifier **validated to a configured trust anchor**, from `--trust-store`
  or from a trusted list, for a signature or a timestamp under evaluation; the
  set comes from an offline verification pre-pass
  (`VerifyReport::validated_path_certificates`), so a certificate embedded
  elsewhere in the XML generates no traffic even when it chains to an anchor.
  With no anchors configured nothing is fetched at all. Previously the fetcher
  only checked that an embedded issuer had signed the certificate — a statement
  whoever wrote the dossier wrote on both sides of — so a synthetic dossier
  with no trust store configured was enough to make openszigno open a
  connection of the dossier's choosing.
- `--online` now applies a destination policy before it opens a socket, to the
  published URL and to every redirect target alike: `http` and `https` only, no
  userinfo in a URL, and none of loopback, RFC 1918 private, link-local,
  unique-local, unspecified, broadcast, multicast, the cloud instance metadata
  addresses `169.254.169.254` and `fd00:ec2::254`, or the names `localhost` and
  `*.localhost`, unless the new `--online-allow-private` is given. The host's
  resolved addresses are re-checked against the same list before connecting, so
  a public name that resolves inwards — DNS rebinding — is refused too, and an
  IPv4-mapped IPv6 address is judged as the IPv4 address it carries. Refusals
  are reported as `online_fetch_failed` (`info`) with the class
  `destination_refused` and the rule that refused them, and nothing is
  contacted. See [SECURITY.md](SECURITY.md#network-exposure) and
  [docs/trust.md](docs/trust.md#online-fetching).
- `--online-cache` is written with the same descriptor-relative machinery as
  `extract`: the directory is opened with `O_DIRECTORY | O_NOFOLLOW` and walked
  component by component, and every file is created with
  `O_CREAT | O_EXCL | O_NOFOLLOW`. It previously used `create_dir_all`,
  `Path::exists` and `fs::write`, which follow symlinked components and final
  files, check existence separately from writing, and truncate. Nothing is now
  ever truncated or replaced: a name already holding exactly the artefact being
  cached is left as it is — which is also what two concurrent runs look like —
  and a name holding anything else, or a symlink, is reported as
  `online_fetch_failed` with the class `cache_collision` while the run
  continues, because caching is an optimisation and never changes a verdict.
- A signature relying on a whole-document enveloped reference could pass the
  reference-scope check while its `xades:SignedProperties` — including the
  `SigningCertificate` binding — and its signature profile object were
  unsigned, feeding unauthenticated XAdES properties to the later stages. The
  check read coverage off the resolved node and its ancestors and ignored the
  transform chain, so a reference to the whole document (`URI=""`), or to any
  ancestor, carrying the enveloped-signature transform was credited with
  covering elements inside the `ds:Signature` that transform removes from the
  digest calculation (XMLDSig 1.1 clause 6.6.4), and so absent from the
  digested bytes. Coverage is now membership of the reference's effective node
  set: ancestor containment minus the subtrees the transforms removed, with
  canonicalization changing nothing and `base64` covering the resolved node's
  content but no element structure beneath it. The rule lives in one function,
  which the reference-scope check, the countersignature binding and the
  document-coverage report all use, so the three agree by construction. Such a
  signature is now `reference_scope_incomplete`, naming both elements, and
  covers no document; a reference whose enveloped transform removes everything
  it selected is refused rather than digested as the empty octet string.
  Signatures that reference those elements directly, as real dossiers do, are
  unaffected. No check code, status name or JSON field changed. See
  [docs/architecture.md](docs/architecture.md#the-effective-node-set).

## [0.4.0] - 2026-09-08

### Added (M4: decryption of encrypted payloads)

- **`extract --decrypt-key FILE`** decrypts documents whose transform chain
  contains `encrypt`. The specification calls that transform "S/MIME
  encryption" and names no algorithm; Microsec's own `eszigno3` reference CLI
  documents its `cm_decrypt` as RFC 5652 CMS and exports per-recipient
  encrypted keys, so the decoded payload is read as a DER `ContentInfo`
  carrying `id-envelopedData`. The supported subset is
  `KeyTransRecipientInfo` recipients named by `issuerAndSerialNumber` or
  `subjectKeyIdentifier`, RSAES-PKCS1-v1_5 and RSAES-OAEP (MGF1 with
  SHA-1/256/384/512) key transport, and AES-128/192/256-CBC content
  encryption. See
  [docs/architecture.md](docs/architecture.md#decryption).

  ```sh
  openszigno extract encrypted.es3 --output ./out \
    --decrypt-key recipient.key.pem --decrypt-cert recipient.cert.pem
  ```

- **`--decrypt-cert FILE`**, PEM or DER, is the certificate that makes a CMS
  recipient recognisable; it may be omitted when a PEM key file carries the
  certificate alongside the key. It is checked against the key, and a
  certificate that does not belong to it is `decryption_key_mismatch`.
- **`--decrypt-passphrase-file FILE`** and the environment variable
  `OPENSZIGNO_DECRYPT_PASSPHRASE` supply the passphrase of an encrypted
  PKCS#8 key; the file wins when both are set, and one trailing newline is
  stripped from the file. **No flag takes a key or a passphrase as an argument
  value**, because `argv` is readable by other processes and lands in shell
  history. All three of key, certificate, and passphrase files are capped at
  1 MiB.
- **`--allow-legacy-ciphers`** additionally decrypts DES-EDE3-CBC content.
  It is off by default because 3DES is weak, and available because it is what
  the Microsec reference tool encrypted with by default; without the flag such
  a document is `document_skipped_legacy_cipher`, with the OID named.
- **New JSON.** Each `extract` `extracted` entry gains `decrypted`, and
  `extract --stdout` gains the same field in its `data`. It is `true` when an
  `encrypt` transform was reversed. `schema_version` stays `1`; both are
  additive.
- **New error codes.** `invalid_decryption_key`,
  `invalid_decryption_certificate`, `decryption_certificate_required`, and
  `decryption_key_mismatch` (exit 4, raised before the dossier is decoded);
  `invalid_cms` and `decrypt_failed` (exit 5). `decrypt_failed` carries the
  fixed message `decryption failed` and never says which step failed, because
  telling a bad RSA unwrap from bad padding is what a padding oracle is made
  of.
- **New warning codes.** `document_skipped_no_matching_recipient`,
  `document_skipped_unsupported_cipher`, and
  `document_skipped_legacy_cipher`. All three are skips at exit 0: a dossier
  may legitimately hold documents addressed to several people, and `extract`
  gives the caller the ones they can read.
- **Key handling guarantees**, stated in
  [SECURITY.md](SECURITY.md#how-key-material-is-handled) and covered by a test:
  key bytes, the passphrase, and anything derived from them appear on neither
  stdout nor stderr nor in the JSON envelope, on a successful or a failing run;
  key and passphrase buffers are zeroed on drop; nothing is ever transmitted.

### Changed (M4)

- **`capabilities.encrypted_extraction` in `inspect --json` is now the string
  `"with_key"`, not `false`.** `inspect` is never given a key, so it can only
  report that the tool can decrypt when `extract` is given one. A consumer that
  tested the field for truthiness now sees a truthy value, which is the correct
  answer; one that compared it to `false` must compare it to `"with_key"`.
  `schema_version` stays `1`: the field kept its name and its meaning, and the
  other capability fields stay boolean.
- **`encrypt` is now only recognised in the position the specification puts
  it.** The forward chain is fixed as `zip? -> encrypt? -> base64`, so
  `encrypt -> base64` and `zip -> encrypt -> base64` are encrypted documents
  and `encrypt` anywhere else is `unsupported_transform_chain` /
  `document_skipped_unsupported_transform` rather than
  `encrypted_document_unsupported` / `document_skipped_encrypted`. Nothing
  becomes extractable that was not before.
- **`encrypted_document_unsupported` is not emitted by a run that holds a
  decryption key**, because it would be untrue; what happened to each document
  is reported per document instead. Its message now points at
  `extract --decrypt-key` rather than saying the document cannot be extracted.
- **The `RUSTSEC-2023-0071` note in `deny.toml`** was rewritten: the tool now
  does perform an RSA private-key operation, locally, with a key the operator
  supplied, for the length of one `extract` run. Exploiting the advisory needs
  an attacker who can time that run on the operator's own machine, which is
  outside the threat model; the ignore is still to be revisited when `rsa` 0.10
  is stable.
- **New dependencies**, all MIT OR Apache-2.0: `aes`, `cbc`, `cipher`, `cms`
  (already used by `openszigno-verify`), `des`, `pkcs8` with `encryption`
  (which brings `pkcs5`, `pbkdf2`, `scrypt`, `salsa20`), and `zeroize`.
  `rand_chacha` and `rand_core` are test-only. `cargo deny check` passes.
- **The decryption tests generate their RSA keys at run time**, from a fixed
  seed through `ChaCha20Rng`, once per test binary. No private key, in any
  encoding, is committed to this repository, and no line of it spells a
  complete PEM private-key armour header: a secret scanner cannot tell a
  synthetic key from a real one, so the project stores none and allowlists no
  scanner rule.
- **`rsa`, `num-bigint-dig`, `scrypt`, `salsa20`, and `sha2` are built at
  `opt-level = 3` in the dev profile.** Generating an RSA key and running a
  PKCS#8 key derivation unoptimized costs seconds each, which is what
  generating test keys at run time would otherwise have added to every test
  run. The code under test is not optimized, and release builds are unchanged.

### Not implemented, deliberately (M4)

- **PKCS#12 (`.p12`/`.pfx`) keystores.** Convert with `openssl` first; the
  commands are in
  [docs/architecture.md](docs/architecture.md#key-material). A keystore parser
  is attack surface for a step the operator does once.
- **PKCS#11.** A key on a smart card or HSM cannot be used.
- **`RecipientInfo` forms other than `ktri`.** A key-agreement (`kari`)
  recipient reads as no matching recipient rather than as a named unsupported
  algorithm.
- **RFC 5083 `AuthEnvelopedData` (AES-GCM).** Recognised only to be skipped.
  Nothing in the specification or the reference CLI suggests it is produced.
- **MIME-wrapped CMS.** No available source says whether any producer wraps the
  message in MIME headers instead of emitting bare DER under the Base64
  transform. Bare DER is what is read; anything else is `invalid_cms` rather
  than a guess.
- **`es:RecipientCertificateList`.** The element is optional and advisory; the
  authoritative recipient list is the CMS `RecipientInfos`, which is what the
  matching uses.

### Added (M3: container timestamps, online revocation, trusted-list identities)

- **Unverified signature inventory in `inspect` and `list`.** The structural
  model now describes every `ds:Signature` and container `es:TimeStamp` a
  dossier carries, built at parse time from the XML alone. Per signature:
  `id`, `placement` (`document`, `dossier`, `nested_in_signature`, `other`),
  `document_index`, `parent_signature_id`, `canonicalization_method`,
  `signature_method`, `digest_methods`, `reference_count`, `reference_uris`
  (same-document fragments, at most 16), `xades_namespace`,
  `xades_properties` (at most 32), `evidence` (element counts of certificates,
  CRLs, OCSP responses, signature timestamps, and archive timestamps),
  `claimed_signing_time`, and `key_info_certificates`. Per container
  timestamp: `placement`, `document_index`, `include_count`, and `has_token`.
  It appears as `dossier.signature_inventory` in both commands' JSON, always
  beside `"verified": false`, and human `inspect` prints one `(unverified)`
  line per entry. **None of it is verified**: no cryptography is performed,
  nothing is decoded, no certificate value is read, and no reference is
  resolved. It reports what a dossier claims, never whether the claim is true;
  `verify` remains the only command that answers that. `signatures_present`
  and `timestamps_present` are unchanged, and `verify` is untouched. The
  inventory describes at most 64 signatures and 64 container timestamps; a
  dossier with more produces the new structural warning
  `signature_inventory_truncated`, which, like every structural warning,
  changes no exit status.
- **`extract --document <SELECTOR>`**, repeatable, extracts only the documents
  it names. A selector is either `#<index>` in source XML order or an exact
  `object_ref` — the `ds:Object` `Id` the `DocumentProfile` `OBJREF` points at.
  Matching is exact; a prefix matches nothing, so a selector cannot change
  meaning as a dossier grows. An unmatched selector is `document_not_found`
  (exit 4) and one matching several documents is `document_ambiguous`
  (exit 4). Selectors never reach into an embedded dossier: a selector shaped
  like a `dossier_path` (`2/0`) is refused with a message saying to extract
  the embedded dossier and run `extract` on the resulting file. Everything
  else is unchanged for the selected documents — the limits, naming and
  deduplication, no-clobber semantics, all-or-nothing rollback, and recursion
  into a selected embedded dossier. `skipped_count` counts only documents
  skipped for capability reasons among the selection.
- **`extract --stdout`** writes one document's decoded payload bytes to
  standard output, byte for byte, with nothing else on the stream and every
  diagnostic on stderr; no file is written. It needs exactly one resolved,
  decodable document: anything else is `stdout_requires_single_document`
  (exit 4), including a selected embedded dossier while recursion is on, which
  `--no-recursive` resolves. An encrypted or unsupported document is
  `document_not_extractable` (exit 5). `--stdout` with `--json` or with
  `--output` is a usage error (exit 2); the JSON envelope is never moved to
  stderr. A closed stdout stays exit 3.

  ```sh
  openszigno extract file.es3 --document '#0' --stdout > payload.pdf
  ```

- **`FILE` may be `-`** on every command, reading the dossier from standard
  input through the one bounded reader the CLI uses for files. At most
  `max_input_bytes + 1` bytes are read and reaching that is the usual
  `input_too_large` (exit 4), with `input.bytes` `null` because the true size
  of a stream that was not read to its end is unknown. The cap no longer
  relies on filesystem metadata for either input. The dossier is buffered in
  memory in full, which the format requires. stdin and stdout are independent,
  so `-` and `--stdout` combine.
- **New JSON.** `extract` gains `data.selected`: the resolved selection as an
  array of `{index, object_ref}` in source order, or `null` when no
  `--document` was given. `schema_version` stays `1`; the field is additive.
- **Per-document signature coverage in `verify`.** For every `es:Document` in
  `es:Documents`, in source order, the report now says which signatures cover
  it and how: `direct` for a document-level signature placed in that document
  whose reference scope is complete and whose references resolve to the
  document's `es:DocumentProfile` and payload `ds:Object`, `frame` for a
  dossier-level signature with a complete scope covering `es:Documents`.
  Coverage is decided by resolved references and the implemented scope rules;
  placement alone never grants it. States: `covered`, `covered_unverified`,
  `uncovered`, `undetermined`, and `not_modelled` for a profile-less document
  the parser skipped, listed with the parser's own reason. An embedded dossier
  is covered like any other payload, and the report states that its own inner
  signatures are **not** verified by this run: there is no implied recursion.
- **New codes** `documents_all_covered` (`passed`, or `info` when a document is
  covered only by signatures that did not verify), `documents_uncovered`
  (`unknown`) and `documents_coverage_undetermined` (`unknown`). The two
  blocking ones cap the **dossier** verdict at `indeterminate`, so a dossier
  with an unsigned sibling document can no longer be `valid` however sound its
  other signatures are: a verdict of `valid` has to mean the whole dossier's
  content is signed. They are `unknown`, never `failed` — an unsigned sibling
  is missing information, not evidence against a signature that did verify —
  and they change no signature's own checks or verdict.
- **New JSON.** `data.documents[]` carries `index`, `object_ref` (never a
  title), `nested_dossier`, `coverage`, `covered_by[]` with each covering
  signature's index, route and verdict, and an optional `reason`;
  `data.counts` gains `documents_covered`, `documents_uncovered` and
  `documents_undetermined`. Human output gains one coverage line per document.
  `schema_version` stays `1`: every addition is additive and no existing field
  changed meaning.
- **Countersignatures in `verify`.** Both forms a dossier can carry one in are
  now classified and verified. The XAdES enveloped form (ETSI EN 319 132-1
  clause 5.2.7.2, ETSI TS 101903 V1.4.1 clause 7.2.4.2) is a `ds:Signature`
  inside an `xades:CounterSignature` in the countersigned signature's
  `xades:UnsignedSignatureProperties`; it gets its own placement,
  `countersignature`, and is verified like any other signature. The e-dossier
  form (e-dossier specification clauses 3.2.1.3.1 and 3.2.1.3.4.1.3) is an
  ordinary sibling signature whose signed `es:SignatureProfile/es:Type` says
  `countersignature`, including the deprecated Hungarian spelling; it keeps its
  `document` or `dossier` placement and gains the role. Before this, a nested
  countersignature reached the invalid-placement path, so a valid dossier could
  be reported as carrying a signature at an undescribed placement.
- **The countersignature reference scope and binding.** A countersignature
  must cover the countersigned `ds:SignatureValue`, its own
  `xades:SignedProperties`, and its own signature-profile object when it
  carries one — and nothing about documents, because a countersignature
  attests the parent signature and not the payload. It grants no document
  coverage: coverage stays with the signature it attests. The
  `CountersignedSignature` `ds:Reference/@Type` is corroboration only;
  resolution decides.
- **New codes** `countersignature_binding_ok` (`passed`),
  `countersignature_binding_missing` (`failed`),
  `countersignature_binding_mismatch` (`failed`, the countersignature-wrapping
  check), `nested_signatures_unsupported` (`info`, on the countersigned
  signature) and `signatures_unsupported` (`unknown`, on the dossier).
- **Unsupported nesting is `unknown`-class, never `invalid`.** A signature
  nested in a shape this build does not support — two `ds:Signature` elements
  in one `xades:CounterSignature`, or a signature under something that is not
  `xades:UnsignedSignatureProperties` — keeps its `sig_placement_invalid` with
  a message that names the reason, but its verdict is left out of the dossier
  verdict, which is capped at `indeterminate` by `signatures_unsupported`
  instead. The signature it was dropped into is **not** affected: it records
  `nested_signatures_unsupported` (`info`) and keeps its own verdict, because
  it does not cover its own unsigned properties and nothing put there can
  change what it says. A binding check that actually fails is still a finding
  and still makes its signature `invalid`.
- **New JSON.** `data.signatures[].placement` (`document`, `dossier`,
  `countersignature`, `unknown`), `role` (`signature` or `countersignature`),
  `parent_signature_index` and `countersigns`. The existing `scope` field is
  kept as an alias of `placement` and always carries the same value, so no
  consumer breaks. Human output names the countersigned signature:
  `countersignature of signature 0`. `schema_version` stays `1`.

- **`--online` revocation fetching**, implemented in the CLI. The
  `openszigno-verify` crate stays network-free and structurally cannot open a
  socket; everything fetched reaches it through the same `RevocationSource` a
  `--revocation-store` file arrives through, and is judged by exactly the same
  offline rules. CRLs come from the certificate's own `cRLDistributionPoints`
  and OCSP responses from its `authorityInfoAccess` responders — never from a
  URL in the dossier's XML — with the scheme exactly as published, a 5 s
  connect and 20 s total timeout, 16 MiB and 64 KiB size caps, at most three
  redirects and **none across hosts**, and no proxy from the environment unless
  `--online-proxy URL` names one. OCSP requests are RFC 6960 `OCSPRequest`
  bodies posted as `application/ocsp-request`, with a SHA-256 `certID` and no
  nonce. Nothing is fetched for a certificate the caller's own material already
  covers. New sources `online_crl` and `online_ocsp` in
  `chain[].revocation.source`; `policy.revocation` reads `online`. A failed
  fetch is one `revocation_status_unknown` (blocking) naming the URL and the
  failure class — `timeout`, `http status <code>`, `too large`, `redirect`,
  `invalid`, `transport` — never a panic and never a hang.
- **`--online-cache DIR`** writes every fetched artefact into a
  `--revocation-store` shaped directory, named by the SHA-256 of its own bytes,
  so a later run with `--revocation-store DIR` and no `--online` reproduces the
  result with no network at all.
- **Container `es:TimeStamp` validation**, dossier-level and document-level.
  Each `xades:Include` is resolved on the parser's ID space, the
  reference-scope rule for timestamps is enforced (a dossier timestamp must
  cover `es:DossierProfile` and `es:Documents`; a document timestamp its
  `es:DocumentProfile` and the payload `ds:Object`), each included element is
  canonicalized with the declared method and the results concatenated in
  `Include` order per XAdES 7.1.4.3.1, and the token is verified by the
  existing RFC 3161 machinery including the TSA path, its revocation, and
  trust. New codes `dossier_timestamp_verified` (`info`),
  `dossier_timestamp_invalid` (`failed`), `dossier_timestamp_not_checked`
  (`info`) and the matching `document_timestamp_*` set. These never change a
  signature's checks or verdict; an `_invalid` lowers the **dossier** verdict,
  because an imprint that does not match is evidence the container was altered
  after it was stamped.
- **New JSON.** `data.timestamps[]` holds one entry per container
  `es:TimeStamp` with its `kind`, `document_index`, token details and own
  `checks`; `data.counts.timestamps_verified` counts the ones that verified
  completely. `signatures[].timestamps[]` entries gain a `document_index`
  field, always `null` for a signature timestamp. `schema_version` stays `1`:
  every addition is additive and no existing field changed meaning.
- **Trusted lists: the identity forms a real national list actually uses.**
  `X509SKI` and `X509SubjectName` service digital identities are now read. They
  contribute **no trust anchor** — an identity that names a certificate without
  supplying one cannot grant trust — but they can decide `qualified` over a
  chain some other anchor has already validated. An SKI is matched against a
  certificate's `subjectKeyIdentifier`; a subject name is matched attribute by
  attribute against the certificate's subject, exactly as written, with only
  the ASN.1 string tag dropped because an RFC 4514 string cannot express it. No
  case folding and no RFC 4518 preparation. Both are documented as weaker than
  a certificate identity.
- **Pre-eIDAS trusted-list statuses.** `undersupervision` and `accredited`
  count as granted at a validation time **before 2016-07-01**, when eIDAS began
  to apply, and never after it. The status that was honoured is named in the
  `certificate_qualified` message, so an eIDAS `granted` and a historical
  `accredited` are never reported as the same statement. This is what lets a
  pre-2016 Hungarian signature report a qualified status instead of
  `certificate_not_qualified` for a reason unrelated to the signature.
- `ServiceName` now prefers the `xml:lang="en"` entry over document order.
- `ureq` 3.4 (MIT OR Apache-2.0) with rustls, in the CLI only, for `--online`.
  Its `gzip` and platform-proxy features are off. This pulls in `webpki-roots`,
  whose licence `CDLA-Permissive-2.0` was added to `deny.toml`: it is Mozilla's
  CA root *data*, permissive, with no reciprocity or source-disclosure
  obligation.

### Changed (M3)

- **OCSP responders are now authorised under all three RFC 6960 models.**
  Alongside the issuing CA answering for itself and a responder that CA
  delegated to, a **trusted responder** (section 2.2) is accepted: one whose
  certificate carries `id-kp-OCSPSigning` and whose own path validates to a
  configured trust anchor — trust store or trusted list — at the response's
  `producedAt`, even though the queried certificate's issuer never delegated to
  it. Central responders are how real national hierarchies are built: one
  responder answers for every CA the operator runs, issued by a sibling CA, and
  a verifier implementing only the delegation model rejected every one of those
  answers. The authority is the caller's own trust material, checked by a full
  path validation, so this can never admit a response whose signer the operator
  had not already chosen to trust; the issuer and delegated models keep
  precedence. Which model applied is reported in
  `chain[].revocation.responder_model` (`issuer`, `delegated`, `trusted`), and
  the new `ocsp_responder_trusted` (`info`) check names the third one when it
  is used.
- **A refused source no longer ends the search.** An OCSP response no model
  authorises, a delta CRL, an out-of-scope CRL — any source that is found and
  refused — is recorded and the remaining tiers are tried, so an unusable OCSP
  answer followed by a good CRL now ends as `good` from the CRL.
  `revocation_data_invalid` and `revocation_status_unknown` are reported only
  after every tier has been exhausted. The refusal stays visible: the new
  `chain[].revocation.detail` field says what was refused, why, and which
  source answered instead, and the path summary repeats it. The
  `revocation_data_invalid` message now names the cause instead of listing
  every possible one.
- **A failed `--online` fetch is now `online_fetch_failed` (`info`), not a
  blocking dossier-level `revocation_status_unknown`.** A failed fetch is a
  fact about the network, not about a certificate; whether the missing data
  mattered is answered by the chain that needed it, which still reports
  `revocation_status_unknown` and still blocks. Emitting a second blocking
  check per URL added nothing there and did harm: a fetch attempted for a
  certificate no verdict depended on — an over-fetch, or the timestamp
  authority of a container `es:TimeStamp` — dragged dossiers whose every
  signature was `valid` down to `indeterminate` and exit `7`.
- **Container-timestamp findings never block the dossier verdict.** Revocation,
  path and trust findings about a container `es:TimeStamp`'s timestamp
  authority live on that timestamp's entry in `data.timestamps[]`, with its own
  `checks` and `verified: false`, and surface at the dossier level only as
  `dossier_timestamp_not_checked` / `document_timestamp_not_checked` (`info`)
  naming the cause. The aggregation is now stated explicitly in
  `docs/architecture.md`: `valid` when every signature is `valid`, `invalid`
  when any signature is — or when a container timestamp's imprint or token
  contradicts the container — and `indeterminate` otherwise.
- The `--online` OCSP `POST` now sets `Content-Length` explicitly. `ureq` sent
  a sized, unchunked body already — the request is passed as a slice — but a
  request whose end the peer has to infer is the shape that behaves
  differently on different platforms, and a responder that does not implement
  chunked requests answers one with a `400`. The test suite now asserts at the
  server that exactly one `Content-Length` arrives, that nothing is chunked,
  and that the whole body is read before the answer.
- Under `--online`, a fetched OCSP response no longer stops the CRL from being
  fetched. Obtaining a response is not the same as being answered by one, so
  coverage is re-tested with what was just fetched before the CRL is skipped.
- `revocation_status_unknown` is now also emitted per failed `--online` fetch,
  with the URL and failure class in the message. It remains `unknown` and
  blocking either way.
- `revocation_policy` reports `online` for a run given `--online`.

### Removed (M3)

- The `dossier_timestamp_not_validated` check code, which existed only to say
  that container timestamps were not validated yet. They are now validated, and
  the `dossier_timestamp_*` / `document_timestamp_*` codes above replace it.

### Not implemented, deliberately (M3)

- `xades:ArchiveTimeStamp` verification. It remains `archive_timestamp_present`
  (`info`). The XAdES 1.4.1 clause 8.2.1 imprint is under-specified in ways
  only interoperability evidence can settle, this project has no consented
  real-world B-LTA material to check an implementation against, and a synthetic
  fixture generated by the same code that verifies it would prove only that the
  implementation agrees with itself. No `poe_times` are recorded and an archive
  timestamp does not extend the validation-time reasoning. The reasoning is in
  `docs/architecture.md`, "Archive timestamps".

## [0.3.0] - 2026-09-07

### Added (M2 phase 3: revocation and EU trusted lists)

- **`verify` can now report a signature `valid`, and exits `0` when it does.**
  Reaching it needs all of: a structurally sound signature whose references and
  signature value verify under the pinned policy, a signed
  `SigningCertificate` binding, a path to a configured anchor at the validation
  time, a fully verified `xades:SignatureTimeStamp`, and fresh non-revoked
  status for every non-anchor certificate on both the signer's and each
  timestamp authority's chain. `valid` means every check this build makes
  passed at the stated validation time; it is not a legal opinion. See
  `SECURITY.md` and `docs/architecture.md`.
- Offline revocation checking (stage E). Data is taken from the signature's own
  `xades:RevocationValues` (`CRLValues`/`EncapsulatedCRLValue` and
  `OCSPValues`/`EncapsulatedOCSPValue`, in every recognised XAdES namespace)
  and from `--revocation-store DIR`, in that order, with OCSP asked before CRLs
  within each tier. Embedded data is untrusted input: every CRL and every OCSP
  response is signature-checked against an authorised issuer before it is
  believed.
  - CRLs per RFC 5280 section 6.3: issuer match, signature by the issuing CA or
    by a delegate that CA issued which asserts `cRLSign`, `thisUpdate` and
    `nextUpdate` against the validation time with **no grace period**, and
    scope via `issuingDistributionPoint`. Delta CRLs, indirect CRLs, scopes
    restricted to reasons or attribute certificates, partitioned CRLs the
    certificate does not name, entries carrying `certificateIssuer`, and any
    other critical CRL extension all fail closed. `certificateHold` counts as
    revoked.
  - OCSP per RFC 6960: response status, responder identity `byName` or `byKey`,
    authorisation as the issuing CA or a delegate carrying `id-kp-OCSPSigning`,
    signature under the pinned allowlist, `certID` matching, and freshness. The
    nonce is deliberately ignored, because offline validation replays a
    response produced for someone else's request. SHA-1 is accepted in the
    `certID` and nowhere else, documented in `docs/architecture.md`.
  - A revocation dated *after* the validation time yields the distinct
    `cert_revoked_after_validation_time` (`unknown`), not `cert_revoked`.
  - New codes: `revocation_policy` (`info`), `revocation_ok` (`passed`),
    `cert_revoked` (`failed`), `cert_revoked_after_validation_time`,
    `revocation_status_unknown`, `revocation_data_stale`,
    `revocation_data_invalid` (all `unknown`). `revocation_not_checked` now
    means only "the caller passed `--no-revocation`".
- ETSI TS 119 612 trusted lists via `--trust-list FILE` (repeatable). Every
  `X509Certificate` in the service digital identity of a granted CA/QC or
  TSA/QTST service becomes a trust anchor carrying the service's status
  timeline, and the status **in force at the validation time** decides whether
  a path ending there is trusted. `--trust-list-signer CERT` verifies the
  list's own enveloped XMLDSig signature with the same core, backend and
  allowlists a dossier gets; without it `trust_list_unverified` (`unknown`)
  blocks a `valid` verdict. Nothing is fetched. New codes:
  `trust_list_loaded`, `trust_list_unverified`, `trust_list_signature_ok`,
  `trust_list_signature_invalid`, `certificate_qualified`,
  `certificate_not_qualified`, `certificate_qualified_unknown`.
- `--lotl FILE` reads the EU list of trusted lists and takes the national
  lists' signing certificates from its `PointersToOtherTSL` entries, so one
  out-of-band certificate bootstraps the verification of every `--trust-list`.
  The LOTL is verified against `--trust-list-signer` first, and only then are
  its pointers trusted; its own `trust_list_unverified` check still blocks when
  it could not be verified. The LOTL contributes no trust anchors of its own.
- Qualified status is determined **over the whole validated chain**, not over
  its anchor: a chain is qualified when some certificate in it is, or was
  issued by, the service digital identity of a granted CA/QC service. Real
  trusted lists name the issuing CAs, which are intermediates, while the root
  is usually a certificate the operator pinned into `--trust-store`, so an
  anchor-only rule answers "not determined" for every real dossier. The signer's
  `QCStatements` may then contradict the list: a post-eIDAS certificate whose
  extension is present but omits `QcCompliance`, or will not parse, yields
  `false`; one carrying no such extension denies nothing and rests on the list.
  `qualified_service` names the service that matched. `null`, never `false`,
  when no trusted list was consulted.
- New flags: `--trust-list FILE`, `--lotl FILE`, `--trust-list-signer CERT`,
  `--revocation-store DIR`, `--no-revocation`. New error codes
  `trust_list_invalid` and `revocation_store_invalid` (exit 3).
- New JSON fields: `policy.trust_lists[]` (territory, sequence number, issue
  date, next update, anchor count, whether the list's signature was verified);
  `signatures[].qualified` and `signatures[].qualified_signature_device`;
  `signatures[].qualified_service`; `chain[].trust_anchor_origin`
  (`trust_store` or `trust_list`, preferring `trust_list` when a certificate is
  both); and `chain[].revocation` with `status`, `code`, `source` (`embedded_crl`,
  `embedded_ocsp`, `store_crl`, `store_ocsp`), `revocation_time`, `reason`,
  `this_update`, `next_update`, and `produced_at`. `schema_version` stays `1`:
  these are additions, and no existing field's contract changed.
- `docs/trust.md`: how to obtain, pin and lay out trust anchors, trusted lists,
  CRLs and OCSP responses, how qualified status is decided, and what makes
  revocation data unusable.

### Changed (M2 phase 3)

- **New check status `info`**, for checks that report rather than decide. It is
  the only non-blocking status, which makes "`unknown` always blocks" true
  without exception. Consumers must treat an unrecognised code as blocking
  unless its status is `passed` or `info`. Moved from `unknown` or `skipped` to
  `info`: `signing_time_present`, `cert_key_usage_advisory`,
  `signature_timestamp_present`, `xades_signature_policy_implied`,
  `xades_signature_policy_explicit`, `xades_not_validated`,
  `archive_timestamp_present` and `dossier_timestamp_not_validated`.
- **`skipped` now means only "a check the policy requires was not performed"**,
  and nothing else is filed under it. A property this build reads but does not
  act on, and evidence it declines to re-verify, are `info`: they did not fail
  to answer a required question. Blocking on them capped a signature at
  `indeterminate` for carrying *more* evidence than the minimum, which is
  precisely backwards — an unsigned qualifying property cannot change what a
  signature says, an archive timestamp is laid on top of one, and a
  dossier-level `es:TimeStamp` is a statement about the container rather than
  about any signature in it. The three remaining `skipped` emitters are
  `xades_absent`, `timestamp_not_checked` and `revocation_not_checked`.
  `xades_not_validated` and `archive_timestamp_present` are omitted entirely
  when there is nothing to report.
- `cert_revoked_after_validation_time` is `info` when the validation time was
  **proven** by a fully verified `xades:SignatureTimeStamp`, and `unknown` when
  it was merely asserted by `--at` or the clock. This is the ETSI EN 319 102-1
  best-signature-time rule: a signature that demonstrably existed at an instant
  is not undone by a certificate being withdrawn afterwards, whereas a caller
  can pass any `--at` they like. Never `passed` either way; the time and reason
  are always reported, and the chain entry's own status reads
  `revoked_after_validation_time`. A timestamp authority's chain is always
  treated as asserted, because the instant it is validated at is the `genTime`
  the token itself claims.
- Revocation summary messages now name **which chain** they are about — the
  signer's or a timestamp authority's — since a signature emits one per chain
  under the same code.
- Embedded validation data is now harvested from
  `xades141:TimeStampValidationData` as well as from a plain
  `xades:RevocationValues` / `xades:CertificateValues`, for both CRLs, OCSP
  responses and certificates. Real long-term Microsec dossiers file almost all
  of their embedded OCSP responses in the former, so the previous reader found
  nothing in most real material.
- The revocation coverage message now names *which* certificate lacks data, by
  role and by the public CA names around it, and repeats that certificate's CRL
  distribution point when it publishes one. The end-entity certificate's own
  subject is still never repeated.
- `timestamp_verified` now summarises a token's checks **excluding** its
  revocation checks, which are folded into the signature's verdict separately
  so they are counted once. An unobtainable revocation answer for a TSA no
  longer stops its `genTime` from becoming the validation time; a TSA
  certificate that was actually revoked still sinks the signature.
- `TrustSource::anchors` now yields `TrustAnchor` values carrying their origin
  and any trusted-list service record, and `RevocationSource` gained `crls`
  and `ocsp_responses`. Both are breaking changes to the `openszigno-verify`
  public API.

### Added (M2 phase 2: XAdES signed properties and RFC 3161 timestamps)

- `crates/openszigno-verify/tests/vectors.rs` and
  `tests/fixtures/xmldsig/`: verification vectors this project did not
  produce. Canonical forms transcribed from Canonical XML 1.0 (sections 3.2,
  3.4, 3.6) and Exclusive XML Canonicalization 1.0 (section 2.2) with the
  section cited at each, plus a complete signed dossier whose reference
  digests and `ds:SignatureValue` were computed by OpenSSL and Python over
  canonical octets written out by hand. The in-tests signer shares the
  canonicalizer under test, so a shared mistake cancels out there; here it
  cannot. The generator and its exact commands are committed; the private keys
  are not.

- XAdES `SigningCertificate` and `SigningCertificateV2` binding, in every
  recognised namespace (1.1.1, 1.2.2, 1.3.2, 1.4.1). The certificate the
  *signed* `CertDigest` names is the certificate the signature claims, so a
  signature whose key-verifying certificate is not the digested one now fails
  with `xades_signing_certificate_mismatch`. `IssuerSerialV2` is compared by
  DER; the older `IssuerSerial` contributes its serial number only. New codes:
  `xades_signing_certificate_bound`, `xades_signing_certificate_mismatch`,
  `xades_signing_certificate_absent`.
- `SignaturePolicyIdentifier` reported as `xades_signature_policy_implied` or
  `xades_signature_policy_explicit`, both `unknown`. No policy document is
  fetched, parsed, or enforced.
- RFC 3161 signature timestamps: every `xades:SignatureTimeStamp` token is
  parsed as CMS `SignedData` over a `TSTInfo`, its imprint recomputed over the
  canonicalized `ds:SignatureValue` element, the TSA `SignerInfo` signature
  verified over its signed attributes, the TSA certificate required to carry a
  critical `extendedKeyUsage` of exactly `id-kp-timeStamping`, and its path
  validated to a configured anchor at the token's `genTime`. New codes:
  `timestamp_token_parsed`, `timestamp_imprint_ok`/`_mismatch`,
  `timestamp_signature_ok`/`_invalid`,
  `timestamp_tsa_certificate_ok`/`_invalid`,
  `timestamp_tsa_path_ok`/`_untrusted`/`_unknown`,
  `timestamp_before_signing_time`, `timestamp_verified`, and per signature
  `signature_timestamp_present`/`_absent`.
- Proof of existence: with no `--at`, a signature whose timestamp verified
  completely is path-validated at the earliest such `genTime` instead of at
  the current time, which is what lets a historical dossier chain under a
  signing certificate that has since expired. `--at` always overrides, and a
  token that did not fully verify moves nothing. Reported per signature as
  `validation_time` and `validation_time_source`
  (`timestamp` | `at_flag` | `current_time`).
- Additive `verify --json` fields on each signature: `xades` (presence, the
  binding, the policy, the counts, and the properties this build does not
  validate), `timestamps[]` (one entry per token, each with its own `checks`,
  `gen_time`, `accuracy_seconds`, TSA certificate and chain, and `verified`),
  `validation_time`, and `validation_time_source`. `chain[].source` gains
  `timestamp_token`. `schema_version` stays `1`: no existing field changed its
  contract.
- Out-of-scope material is named rather than ignored:
  `archive_timestamp_present` (`skipped`) for `xades:ArchiveTimeStamp`,
  `dossier_timestamp_not_validated` (`skipped`) for dossier-level
  `es:TimeStamp`, and `timestamp_not_checked` (`skipped`) for a timestamp that
  uses an `Include`-style data selection, carries no decodable token or more
  than one, or names a canonicalization algorithm this build does not
  implement.
- New verification limit `max_timestamps_per_signature` (8), a fixed cap of 16
  `xades:Cert` entries, and a fixed 512 KiB cap on one timestamp token.

### Changed (M2 phase 2)

- Signing certificates are accepted when their `extendedKeyUsage` names
  Microsoft's `szOID_KP_DOCUMENT_SIGNING` (`1.3.6.1.4.1.311.10.3.12`), the
  private-arc purpose that predates RFC 9336 and that qualified-signature CAs
  actually issue.
- New `cert_key_usage_advisory` (`unknown`): when a signing certificate
  asserts `nonRepudiation` — the ETSI EN 319 412-2 signal for a signing
  certificate — but its `extendedKeyUsage` names only unrelated purposes, the
  path passes with a caveat naming the OIDs found instead of failing.
  `cert_key_usage_invalid` is kept for a `keyUsage` that permits neither
  `digitalSignature` nor `nonRepudiation`, and for an unrelated
  `extendedKeyUsage` without `nonRepudiation`. There is no advisory downgrade
  for a CA or a TSA certificate.
- An `xades:EncapsulatedTimeStamp` may carry a whole RFC 3161 `TimeStampResp`
  rather than the bare `TimeStampToken`, as XAdES 1.2.2-era producers emitted.
  The response is unwrapped only when its `PKIStatus` is `granted` or
  `grantedWithMods`; any other status, or a response with no token, stays
  `timestamp_token_parsed` (`failed`) with the status named. DER that is
  neither shape now names the outermost tag it saw.

- **A timestamp that does not verify no longer makes a signature `invalid`.**
  Following ETSI EN 319 102-1, a token that fails for any reason — malformed,
  wrong imprint, bad TSA signature, TSA certificate problem, untrusted or
  unknown TSA path — supplies no proof of existence, which is missing
  information rather than evidence against the signature. The token keeps its
  own `failed` checks and `verified: false`; the signature-level
  `timestamp_verified` is now `unknown` and never `failed`, the validation
  time falls back to `--at` or the clock, and the verdict is capped at
  `indeterminate`. Only checks about the signature itself — digests, signature
  value, algorithm policy, reference scope, the `SigningCertificate` binding,
  and the signer's own chain — can still make it `invalid`.
- The TSA certificate path is built from the union of the token's own
  `SignedData` certificates, the enclosing signature's `ds:KeyInfo` and
  `xades:CertificateValues` candidates, and the trust store's intermediates.
  Real dossiers carry the TSA's issuing CA in the signature's
  `CertificateValues` and put only the TSA leaf in the token, so the previous
  token-only search reported chain breaks that were not there. Anchors still
  come from the trust store alone.
- The explicit `xades:Include` data-selection form is implemented for the case
  where every `Include` resolves, same-document and by ID, to this signature's
  own `ds:SignatureValue`; `referencedData` is not consulted, because for that
  target it cannot change what is digested. Any other target set, and the
  `ReferenceInfo`, `HashDataInfo` and `XMLTimeStamp` forms, stay
  `timestamp_not_checked`.
- `extendedKeyUsage` on the signing certificate is now enforced whether or not
  it is marked critical, as RFC 5280 section 4.2.1.12 requires, and
  `id-kp-documentSigning` (RFC 9336) is accepted alongside
  `anyExtendedKeyUsage`. A certificate whose EKU names only unrelated purposes
  — `emailProtection`, `serverAuth`, `clientAuth`, `codeSigning`,
  `OCSPSigning` — now fails `cert_key_usage_invalid` even when the extension
  is advisory. A CA's EKU is still enforced only when critical.
- `cert_path_search_exhausted` is reported as `unknown` rather than `failed`:
  hitting the expansion budget means the tool stopped looking, not that no
  path exists, so it no longer makes a signature `invalid`.
- Path building checks whether a chain has reached an anchor *before* refusing
  to expand further, so `max_chain_length` is inclusive: a limit of 8 admits a
  path of 8 certificates, where it previously admitted only 7.

- `xades_not_validated` now means "qualifying properties this build does not
  validate are present", and names them in the message and in
  `xades.unvalidated_properties`. It is no longer emitted for every signature.
- `timestamp_not_checked` no longer means "timestamps are out of scope"; it is
  emitted only for a timestamp whose form this build does not process. A
  signature carrying no timestamp reports `signature_timestamp_absent`
  instead.
- `verify` human output prints each signature's validation time and source and
  each token's outcome, and its closing line now says that revocation alone is
  what keeps a signature from being reported as valid.
- New dependency `cms` 0.2 (Apache-2.0 OR MIT), version-coherent with
  `x509-cert` 0.2 and `der` 0.7. `TSTInfo` itself is hand-declared on `der` so
  the ASN.1 this build accepts is visible in one place. No license allowlist
  change was needed.
- The Conventional Commits scope allowlist gains `verify`, in
  `CONTRIBUTING.md` and `scripts/commit-msg.sh`.

`valid` remained unreachable at that point: `revocation_not_checked` was still
emitted as a blocking `skipped` check on every signature, and a test asserted
it. Phase 3 lifted that.

### Changed

- The GitHub release is now uploaded and undrafted in the `announce` job
  rather than in `host` (`github-release = "announce"` in
  `dist-workspace.toml`). The release page becomes public only after the
  Homebrew, crates.io, and container jobs have all succeeded, so a failed
  publish can no longer leave a public, partially distributed release.
- `publish-crates.yml` is idempotent. Each crate is looked up in the
  crates.io sparse index before publishing and skipped if that exact
  version is already there, and each publish is followed by a wait for
  index visibility. A rerun after a partial success now completes the
  remaining crates instead of failing on the first one. A `concurrency`
  group keyed on the release tag serialises runs for the same release, and
  `container.yml` gained the same guard.
- The release smoke test runs `inspect`, `list`, `validate-structure`,
  `extract` (byte-checking the extracted payload) and `verify` (asserting
  exit status 7) against the packaged musl binary, instead of `inspect`
  alone.
- CodeQL analysis is enabled unconditionally for Rust with build mode
  `none`, replacing the `CODEQL_ENABLED` repository-variable gate. CodeQL
  Rust support went generally available on 2025-10-14.
- Every third-party action in the workflows is pinned to a full commit SHA
  with a version comment, including the ones in the dist-generated
  `release.yml` (through `[dist.github-action-commits]`). The `gitleaks`
  and `actionlint` binaries are verified against the checksums files
  published in their releases before they run.
- Every workflow job has a `timeout-minutes`, and `security.yml` cancels
  superseded runs.

### Added

- `ci.yml` job `package`: `cargo package --no-verify --locked` for all
  three crates, so a manifest a registry would reject fails on the pull
  request instead of halfway through a release.
- `ci.yml` job `container`: builds the release `Dockerfile` for
  `linux/amd64` and runs the CLI subcommands inside the scratch image
  against the synthetic fixtures.
- `security.yml` job `advisories`: a weekly and on-demand
  `cargo deny check advisories` run, so a newly published advisory against
  an unchanged dependency tree turns the repository red without a commit.
  `security.yml` also accepts `workflow_dispatch`.

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
[Unreleased]: https://github.com/watt-mind/openSzigno/compare/v0.8.0...develop
[0.8.0]: https://github.com/watt-mind/openSzigno/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/watt-mind/openSzigno/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/watt-mind/openSzigno/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/watt-mind/openSzigno/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/watt-mind/openSzigno/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/watt-mind/openSzigno/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/watt-mind/openSzigno/compare/v0.2.0...v0.3.0
