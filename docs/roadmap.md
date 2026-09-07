# Roadmap, residual risks, and maintainer policy

This document lists planned work beyond the current extraction-only release,
the risks that remain in the shipped code, and the maintainer rules for the
private test corpus.

Nothing here changes the rule stated in
[architecture.md](architecture.md#verification-boundary): until the code for a
milestone exists, no openSzigno output may claim or imply that a signature,
timestamp, certificate, or dossier is valid.

## Format and verification milestones

The milestones are ordered. Each one is expected to keep the JSON envelope
stable, or to raise `schema_version` if it cannot.

### M1: custom compatible e-dossier namespaces — done

Shipped. openSzigno accepts e-dossier profiles in a compatible namespace other
than the default `https://www.microsec.hu/ds/e-szigno30#`, including the four
Hungarian company-court (e-cégeljárás) generations. See
[architecture.md](architecture.md#namespace-policy) for the contract. What
landed:

- an explicit allow-list (`KNOWN_COMPATIBLE_NAMESPACES`), resolved
  namespace-aware at the root element, never by file extension, widened per
  invocation by the repeatable `--allow-namespace <URI>` flag;
- every structural lookup performed in the dossier's own namespace, with an
  unknown namespace still a `wrong_root` error rather than a best-effort
  parse, and the URI never echoed in the message;
- `inspect` and `list` continue to report the detected `namespace` verbatim;
- the two real-world deviations reported as conformance warnings instead of
  rejections: `dangling_objref` (typically a `SignatureProfile` pointing at
  nothing) and `document_without_profile` (an empty placeholder `Document`);
- nested dossiers (`application/nldossier2`, extension `dosszie`) detected by
  declared type and by content sniffing, and expanded recursively by `extract`
  into `<file>.d` subdirectories under a shared decode budget, bounded by
  `--max-depth` (default 3, hard cap 8) and disabled by `--no-recursive`;
- content sniffing (`sniff`/`DetectedType`) reported per extracted file as
  `detected_type` alongside the unreliable `declared_type`, and used as a
  last-resort filename extension.

Residuals deliberately left out of M1:

- **No per-namespace structural profiles.** All allowed namespaces are held to
  the default profile's structure. If a generation genuinely differs beyond the
  two deviations above, it will surface as a hard error rather than as a
  profile-specific rule; the Microsec prose specification stays the authority.
- **Nested dossiers are the only recursion.** A payload that is a dossier but
  is neither declared nor sniffable as one (an encrypted or `zip`-wrapped
  dossier, say) is written as a file and not expanded.
- **Sniffing is coarse and prefix-only.** It bounds itself to the first 4096
  bytes and answers with a category, not a media type; a caller that needs
  certainty must still open the file.
- **The subdirectory name is derived, not declared.** `<payload file>.d` can
  collide with a sibling document's filename; that is reported as
  `output_name_collision` and the run writes nothing, which is safe but means
  such a dossier cannot be extracted without renaming.
- **Nested extraction shares one aggregate budget but not one plan cost.**
  Every level is decoded in memory before anything is written, so peak memory
  grows with the size of the whole tree, not of the largest single dossier.

### M2: `verify` for XMLDSig/XAdES signatures — phase 2 done

The design is [verify-design.md](verify-design.md), which splits M2 into three
phases. **Phases 1 and 2 have shipped**; phase 3 remains.

#### Phase 1 (shipped): the XMLDSig core and certificate paths

- new `openszigno-verify` crate: pure Rust, `forbid(unsafe_code)`, no network,
  and no I/O except through the injected `Clock`, `TrustSource`, and
  `RevocationSource` traits;
- Canonical XML 1.0 and Exclusive C14N 1.0 (each with and without comments)
  implemented in-tree behind a `C14nBackend` trait, over the same `roxmltree`
  tree the structural parser built. Canonical XML 1.1 and everything else is
  refused with `c14n_unsupported` rather than approximated;
- strict same-document reference resolution through the existing ID space, so
  duplicate IDs remain a parse error and no reference can reach the network or
  the filesystem;
- a pinned algorithm policy: SHA-256/384/512, RSA PKCS#1 v1.5 and PSS at 2048
  bits or more, ECDSA P-256/P-384 with a matching digest. SHA-1, MD5, DSA,
  HMAC, and short RSA keys are rejected rather than warned about;
- an allowlist of transforms; XSLT, XPath, and XPath Filter 2.0 refused
  unconditionally;
- reference-scope enforcement against the e-dossier placement rules, which is
  the container-aware defence against signature wrapping;
- reference digests, `ds:SignedInfo` canonicalization, and `ds:SignatureValue`
  verification;
- hand-written RFC 5280 path validation on `x509-cert`: link signatures,
  validity at the validation time, `basicConstraints`, `pathLenConstraint`,
  `keyUsage`, name constraints, and rejection of unrecognised critical
  extensions, bounded by chain length and candidate count;
- `--trust-store DIR` with a documented `anchors/` and `intermediates/`
  layout, `--at <RFC3339>`, the `verify` JSON shape, and exit statuses 6 and 7.

Deliberately left to later phases, and the reason the verdict can never be
`valid`: revocation is reported as `revocation_not_checked` and timestamps as
`timestamp_not_checked`, both blocking `skipped` checks.

#### Phase 2 (shipped): XAdES signed properties and timestamps

- the XAdES `SigningCertificate` and `SigningCertificateV2` digest binding, in
  every recognised namespace (1.1.1, 1.2.2, 1.3.2, 1.4.1), so the signing
  certificate is determined by *signed* data rather than by whatever
  `ds:KeyInfo` happens to hold. A key that verifies a certificate the signed
  property does not name is a failure, not a preference: this is the
  certificate-substitution check;
- `SignaturePolicyIdentifier` reported as implied or explicit, informational
  only, with no policy processing;
- RFC 3161 token verification on `cms` plus a hand-declared `TSTInfo`: imprint
  binding over the canonicalized `ds:SignatureValue`, the TSA `SignerInfo`
  signature over its signed attributes, the critical `id-kp-timeStamping`
  requirement of RFC 3161 section 2.3, and the TSA path validated to an anchor
  at the token's `genTime`;
- the validation time moved to the earliest fully verified `genTime`, which is
  what lets a historical dossier chain under a signing certificate that has
  since expired. `--at` still overrides it, and an unverified token moves
  nothing;
- `ArchiveTimeStamp`, dossier-level `es:TimeStamp`, and every unprocessed
  qualifying property named and reported as `skipped` rather than ignored.

Level detection (B-B, B-T, B-LT, B-LTA) was deliberately left out: reporting a
level implies a determination this build does not make, and `xades_level`
stays the `"detected"` placeholder until it does.

#### Phase 3 (remaining): revocation and the EU trusted lists

Stage E in full — CRL and OCSP verification, embedded `RevocationValues`,
freshness rules, and `--online` fetching under a strict transport policy — plus
importing a pinned LOTL and Hungarian trusted-list snapshot into the trust
store so that `certificate_qualified_status` can be determined and cited.

#### Residual risks carried by phases 1 and 2

- **The path validator is hand-written.** There is no general RFC 5280 path
  validator in Rust that fits eIDAS certificates, so this is net-new
  cryptographic logic. The implemented subset is narrow and documented, and
  every rule has a negative test, but it is the largest correctness risk in
  the project after canonicalization. A differential CI check against
  `openssl verify` on generated chains is not yet in place.
- **Canonicalization is also in-tree.** It matches the W3C examples and the
  hand-computed cases in `crates/openszigno-verify/tests/c14n.rs`, and
  `tests/vectors.rs` now checks it against specification-transcribed canonical
  forms and against a document whose digests and signature OpenSSL produced
  over hand-written canonical octets. The differential backend the design
  calls for (`xml_c14n` or `bergshamra` as a CI oracle) has still not been
  added, so there is no second implementation running over arbitrary input.
- **Distinguished names are compared by DER**, with no RFC 4518 string
  preparation. That is conservative: it can only reject a chain a lenient
  comparison would have accepted, never the other way round.
- **A signature with no `SigningCertificate` property still leans on
  `ds:KeyInfo`.** The binding can only decide when the signature carries the
  signed property; without one, `xades_signing_certificate_absent` is
  `unknown` and the key-based selection stands. The reference-scope check is
  what limits the damage there: a signature that does not cover what the
  container mandates fails regardless of which certificate it names.
- **The `TSTInfo` decoder is hand-declared** on `der`, rather than taken from
  a timestamping crate, so the ASN.1 this build accepts is visible in one
  place. It is net-new parsing of attacker-supplied DER, mitigated by a size
  cap, `forbid(unsafe_code)`, and negative tests over malformed tokens.
- **`IssuerSerial` issuer names are not compared**, only serial numbers: the
  XAdES 1.3.2 form carries an RFC 4514 string, and comparing it to a DER name
  needs name preparation this project does not implement. The `CertDigest` is
  the binding, and `IssuerSerialV2` is compared by DER.
- **No real-dossier interoperability evidence.** Everything is tested against
  synthetic material generated in `tests/`; whether real Microsec dossiers
  verify is only knowable through the private opt-in smoke tests.

Until phase 3 lands, `verify` reports `invalid` or `indeterminate` and nothing
else.

### M3: dossier-level timestamp verification

M2 phase 2 built the RFC 3161 machinery — token parsing, imprint comparison,
TSA certificate and path validation — and `xades:SignatureTimeStamp` uses it
today. What remains for M3 is the dossier-level `es:TimeStamp`, whose imprint
is taken over the elements it *references* rather than over a
`ds:SignatureValue`, so it needs the reference-resolution and canonicalization
step a signature already has. Until then such an element is counted and
reported as `dossier_timestamp_not_validated` (`skipped`), and
`timestamps_present` stays presence-only in `inspect` and `list`.

### M4: encrypted payload decryption

Extract documents whose transform chain contains `encrypt`, using key material
supplied by the user. Scope:

- key and passphrase input through a file or an environment variable, never a
  command-line argument that would land in the process table or shell history;
- key material excluded from every log line, error message, and JSON field;
- the same bounded decoding limits applied to decrypted output as to any other
  payload;
- decryption reported as a distinct capability flag, and never conflated with
  signature verification.

Until this ships, an encrypted document is reported with
`encrypted_document_unsupported` and skipped by `extract` with
`document_skipped_encrypted`.

## Field observations from the private corpus

Aggregate findings from the maintainers' private corpus (see the policy
below), recorded here because they shape priorities. No individual dossier is
identified.

- Roughly four in five dossiers use the default Microsec namespace; the rest
  are company-court (e-cégeljárás) dossiers in four namespace generations
  (2007, 2009, 2012, 2014). Those carry many more documents per dossier
  (up to a dozen or more), all `base64` without `zip`, and some embed a
  nested dossier declared as `application/nldossier2` whose payload is itself
  a default-namespace `Dossier`. Milestone M1 handles all of this.
- Payloads are overwhelmingly PDF and small HTML notices, with a few XML
  documents (including a Microsec `Acknowledge` receipt). About half of the
  PDFs have no text layer and are image-only scans, so text extraction from
  payloads is out of scope for this tool and belongs to the calling agent.
- Declared MIME types are not reliable: `application/octet-stream` payloads
  turned out to be PDF and HTML, and a `text/xml` payload was HTML. M1 added
  the `detected_type` sniffing hint alongside the declared type, so an agent
  can choose a reader without opening the file blind.
- Every parsed dossier carried signature material and a minority carried
  timestamps, which is why `verify` is the next milestone after M1.
- Inputs with the `.es3` suffix that are not XML at all occur in practice
  (tiny Base64-like text fragments); the `invalid_xml` rejection is correct.

### Verification evidence from the private corpus

Aggregate results of `verify` phase 1 over the maintainers' private corpus
(62 signed dossiers, one signature each, no individual dossier identified):

- With the strict algorithm policy, 56 signatures pass reference digests,
  `SignedInfo` canonicalization, and signature-value verification; with
  `--allow-legacy-algorithms` all 62 digests and 60 signature values pass,
  and the remaining 2 are 1024-bit RSA signers, refused by policy.
- Intermediates and roots travel in XAdES `CertificateValues`, not in
  `KeyInfo`; with the two current Microsec roots as anchors, 53 chains build
  to three or four certificates and 13 validate fully at the current time.
  40 fail only on expiry, which is expected for historical dossiers until
  phase 2 binds the validation time to a trusted timestamp. 9 chain to CAs
  outside the two-root store (NetLock, KGYHSZ, and the pre-2009 Microsec
  root), which the trusted-list work in phase 3 will cover.

With phase 2 (XAdES signed properties and RFC 3161 signature timestamps),
the same corpus with the two Microsec roots as anchors and the legacy
algorithm flag gives, in aggregate: `SigningCertificate` bound for all 62
signatures; 59 signatures carry a signature timestamp and 56 of those verify
fully, so the validation time comes from a trusted timestamp for 56
signatures; 52 signer chains validate at that time; and 49 of the 62
signatures pass every implemented check and are blocked only by
`revocation_not_checked`, which phase 3 addresses. The remaining ones chain to
CAs outside the two-root store, use 1024-bit RSA, or carry advisory extended
key usages.

## Engineering items

These are not format milestones; they can land in any order.

| Item | Why it matters |
| --- | --- |
| Windows extraction race | On Unix the output path is walked descriptor-relative with `O_NOFOLLOW`, which closes the directory-swap race. On Windows and other non-Unix targets, files are created by path with no-clobber semantics and reparse-point rejection, so a directory swapped between the check and the create remains a residual risk. Closing it needs platform-specific handle-relative creation. |
| Configurable limits | Limits are compile-time defaults today. They should be settable per invocation, with the effective values still reported in `inspect` output and a documented ceiling so that a flag cannot disable a bound entirely. |
| Streaming extraction | Every document is decoded in memory before any file is written, which is what makes the all-or-nothing extraction guarantee cheap, but it makes peak memory a multiple of the input size. Streaming decode to a temporary file inside the output directory, then atomically linking on success, would lower peak memory while keeping the guarantee. |
| Documentation site | The Markdown under `docs/` is the source of truth. Publishing it with mdBook to GitHub Pages from the release branch would give readers navigation and search without moving content out of review. |
| Distribution channels | Mostly done. `dist` builds five targets and generates the shell, PowerShell, and Homebrew installers; `cargo binstall` metadata points at the same archives; a `scratch` container image goes to GHCR with a provenance attestation; both crates go to crates.io. See [releasing.md](releasing.md). Still open: a winget manifest, `.deb` and `.rpm` packages, provenance attestations for the archives themselves, and a documentation site. |
| Broader interoperability corpus | Vendor differential testing against consented real dossiers covering UTF-8 and ISO-8859-2, document-level and dossier-level signatures, timestamps, multiple payloads, ZIP, and encryption markers. |

## Residual risks in the current release

- **Memory.** Peak memory is roughly a small multiple of the input size. The
  64 MiB input cap and the 256 MiB aggregate decode cap bound it, but a caller
  running many instances in parallel must budget for that.
- **Non-Unix filesystem races.** See the Windows item above.
- **Parser surface.** Safety rests on the pre-parse scan plus `roxmltree` with
  DTDs disabled. The pre-parse scan is deliberately conservative and only has
  to be correct for well-formed input; anything it miscounts on malformed
  input is rejected by the tree parser afterwards. Changes to either side need
  matching regression tests.
- **Recursive extraction breadth.** A dossier tree is decoded entirely in
  memory before any file is written, and the `<file>.d` naming scheme can
  collide with a sibling filename. Both are described under M1's residuals.
- **Compatibility gaps.** Dossiers in unsupported namespaces or with
  unsupported transform chains are rejected or skipped. A rejection is not
  evidence that a dossier is malformed; it may simply be out of the currently
  supported profile.
- **No positive cryptographic assurance.** `verify` can now say that a
  signature is `invalid`, which is a real finding, but it cannot say that one
  is valid: revocation, timestamps, and the XAdES signing-certificate binding
  are not checked. A dossier that parses cleanly, or that reaches
  `indeterminate`, may still be forged. This is the single most important
  thing for a downstream caller to internalise.

## Private-corpus policy for maintainers

Maintainers may hold real-world `.es3` dossiers locally for compatibility
testing. They are private integration inputs, never fixtures.

- `samples/` is gitignored except for its `.gitkeep`. Never commit, stage, or
  modify anything in it, and never derive a public fixture from it.
- Never print, enumerate, hash, or otherwise disclose private paths or
  filenames, dossier or document titles and metadata, payload contents or
  hashes, or certificate subjects, signer data, and signature values. This
  applies to failure paths, patches, issue reports, CI logs, and chat
  transcripts alike.
- Avoid commands that echo private filenames, such as directory listings over
  the corpus or shell loops that print paths. Use the opt-in tests, which take
  their input through an environment variable and report aggregate results
  only. See [testing.md](testing.md#private-opt-in-smoke-tests).
- Report compatibility findings as aggregate counts and stable error-code
  buckets. A useful finding reads "N inputs bucketed to `wrong_root`", never
  "file X failed".
- Never weaken a security check merely to raise the number of dossiers that
  parse. If a rejection turns out to be an in-scope compatibility bug, fix the
  format handling and add a synthetic fixture that reproduces it.
- Before accepting any real dossier into the public repository, its
  provenance, privacy status, and redistribution permission must be documented
  and approved. Keep provenance and expected behaviour in a private test-corpus
  manifest, not in the repository.
