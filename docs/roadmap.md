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

### M2: `verify` for XMLDSig/XAdES signatures — complete

The design is [verify-design.md](verify-design.md), which splits M2 into three
phases. **All three have shipped.**

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

Deliberately left to later phases, and the reason the verdict could not be
`valid` at the time: revocation was reported as `revocation_not_checked` and
timestamps as `timestamp_not_checked`, both blocking `skipped` checks.

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

#### Phase 3 (shipped): revocation and the EU trusted lists

- Stage E offline: CRL verification per RFC 5280 section 6.3 and OCSP per RFC
  6960, consuming the signature's own `xades:RevocationValues` first and a
  `--revocation-store DIR` second, with every item signature-checked against
  the issuing CA or a properly authorised delegate before it is believed.
  Delta CRLs, indirect CRLs, unimplemented `issuingDistributionPoint` forms and
  unknown critical CRL extensions all fail closed;
- freshness with **no grace period**: data whose `nextUpdate` has passed at the
  validation time is `revocation_data_stale`, and a revocation dated after the
  validation time is the distinct, non-fatal
  `cert_revoked_after_validation_time`;
- every certificate in the signer's chain and in each TSA's chain except the
  anchors is checked, with the answer and its source reported per chain entry;
- ETSI TS 119 612 trusted lists via `--trust-list FILE`, with service status
  history evaluated at the validation time, the list's own XMLDSig signature
  verified against a `--trust-list-signer` certificate obtained out of band,
  and the qualified determination (`qualified`,
  `qualified_signature_device`) carried into the report;
- a new `info` check status for purely informational checks, so that `unknown`
  now blocks without exception — and `valid` became reachable, with exit
  status `0`.

Deliberately deferred to M3, and shipped there: `--online` fetching from CRL
distribution points and AIA. Everything needed for it already existed — the
`RevocationSource` injection point, the store loader, the classifier — and only
the transport policy was missing, which is network code that belongs in the
CLI.

#### Residual risks carried by M2

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
- **The trusted-list reader is narrow on purpose.** Only `X509Certificate`
  digital identities become anchors, and scheme-level `Qualifications`
  extensions are not processed. M3 added `X509SKI` and `X509SubjectName` as
  *service identities* that can decide qualified status without granting trust;
  see the M3 section below.
- **Revocation depends on what the caller supplies.** With no
  `RevocationValues` in the dossier, no `--revocation-store` and no `--online`,
  the answer is `revocation_status_unknown` and the verdict `indeterminate`.
  M3 added `--online`; the manual workflow in [trust.md](trust.md) is still the
  reproducible one.

### M3: container timestamps and online revocation fetching — done

Shipped. Four things landed.

**Container `es:TimeStamp` validation.** A dossier-level or document-level
`es:TimeStamp` carries `xades:TimeStampType` semantics, so it protects the
elements its `xades:Include` children name rather than a `ds:SignatureValue`.
Each `Include` is resolved on the parser's ID space, the reference-scope rule
for timestamps is enforced (a dossier timestamp must cover `es:DossierProfile`
and `es:Documents`; a document timestamp its `es:DocumentProfile` and the
payload `ds:Object`), each included element is canonicalized with the declared
method and the results concatenated in `Include` order, and the resulting
imprint is checked against a token verified by the existing RFC 3161 machinery
— TSA path, revocation and trust included. The outcome is reported at the
dossier level as `dossier_timestamp_verified` / `dossier_timestamp_invalid` /
`dossier_timestamp_not_checked` and the per-document `document_timestamp_*`
set, in a new `data.timestamps` array with a `data.counts.timestamps_verified`
count. None of it touches a signature's verdict. See
[architecture.md](architecture.md#container-timestamps).

**`--online` revocation fetching.** In the CLI only; the verify crate stays
network-free and structurally cannot open a socket. CRLs come from the
certificate's own distribution points and OCSP responses from its AIA
responders, with the scheme exactly as published, a 5 s connect and 20 s total
timeout, 16 MiB and 64 KiB size caps, at most three redirects and none across
hosts, no proxy from the environment unless `--online-proxy` names one, and
every fetched artefact validated by the offline code path before use. Nothing
is fetched for a certificate the caller's own material already covers.
`--online-cache DIR` writes what was fetched in the `--revocation-store`
layout, so a later offline run reproduces the result. Sources are reported as
`online_crl` / `online_ocsp`. See
[architecture.md](architecture.md#online-revocation-fetching) and
[trust.md](trust.md#online-fetching).

**Trusted-list reader gaps.** `X509SKI` and `X509SubjectName` service digital
identities are read and can decide qualified status over a chain some anchor
already validated; neither becomes an anchor, and both are documented as weaker
than a certificate identity. The pre-eIDAS statuses `undersupervision` and
`accredited` count as granted for their historical window — a validation time
before 2016-07-01, when eIDAS began to apply — with the honoured status named
in the report. `ServiceName` prefers the `xml:lang="en"` entry.

**Archive timestamps — deliberately not implemented.** `xades:ArchiveTimeStamp`
is still `archive_timestamp_present` (`info`) and is not verified. The XAdES
1.4.1 clause 8.2.1 imprint is under-specified in ways only interoperability
evidence can settle — the namespace context each unsigned property is
canonicalized in, how properties added after the timestamp are excluded,
whether the qualifying-properties `ds:Object` participates, and how the 1.3.2
and 1.4.1 forms differ in all three — and this project has no consented
real-world B-LTA material to check an implementation against. A synthetic
fixture generated by the same code that verifies it would only assert that the
implementation agrees with itself. Reporting `archive_timestamp_verified` on
that basis is exactly the unearned assurance this project refuses, so the
element is named and left unverified, no `poe_times` are recorded, and an
archive timestamp does not extend the validation-time reasoning. The reasoning
is written out in
[architecture.md](architecture.md#archive-timestamps).

#### Residual risks carried by M3

- **Countersignatures have been implemented against the specifications, not
  against real material.** Both forms — the XAdES enveloped
  `xades:CounterSignature` of EN 319 132-1 clause 5.2.7.2 and the e-dossier
  `es:SignatureProfile/es:Type` form of e-dossier clause 3.2.1.3.4.1.3 — are
  read from the prose and exercised only against synthetic dossiers this
  project signs itself. Long explicit chains of countersignatures, where each
  one references the `ds:SignatureValue` of the previous `CounterSignature`,
  are permitted by the specification and are classified by the same rules, but
  no real Microsec dossier carrying one has been verified. A nesting outside
  the recognised shape is reported as an unsupported placement rather than
  guessed at, so the failure mode of a wrong reading is a dossier capped at
  `indeterminate`, not one called `invalid`.
- **A countersignature's own document coverage is deliberately nil.** If real
  material turns out to use a countersignature to add coverage of a document
  the countersigned signature does not reach, this build would report that
  document as uncovered. That is the conservative direction, but it is a
  reading of the format and not a proof.
- **Archive timestamps are still unverified**, so this build makes no claim
  about long-term (B-LTA) re-validation. Closing it needs consented real
  archive-timestamped material or a second implementation to differ against.
- **A container timestamp's imprint rule has no real-world evidence either.**
  The `xades:Include` concatenation of XAdES 7.1.4.3.1 is unambiguous where the
  archive-timestamp rule is not, and the scope rule follows the e-dossier
  placement rules the signature pipeline already enforces — but no real
  Microsec dossier carrying an `es:TimeStamp` has been verified with it. An
  imprint mismatch on real material would surface as a dossier-level `invalid`,
  which is the correct reading of "the container changed after it was stamped"
  and would be the wrong reading of "this implementation misread the
  specification". If field evidence shows the latter, the fix is the imprint
  rule, not the severity.
- **`--online` widens the attack surface to whatever a CA's server answers
  with.** Every artefact is still signature-checked against an authorised
  issuer before it is believed, so the worst a hostile responder can do is
  refuse to answer — but the DER it serves is parsed, and parsing
  attacker-supplied DER is the risk `--online` adds that offline verification
  did not have. It is off by default for that reason.
- **An OCSP request tells the responder who is asking about what.** The
  `certID` names the certificate's serial number, so a CA can see that someone
  is validating that certificate now. `--online-cache` plus a later offline run
  is the workflow for anyone who cares.
- **The trusted-responder model rests on the caller's trust store.** Accepting
  a responder the issuing CA never delegated to is what RFC 6960 section 2.2
  provides for and what real central responders need, but it does move part of
  the authority from the PKI to the operator's configuration. An operator who
  anchors a root has, by that act, accepted every OCSP responder under it that
  carries `id-kp-OCSPSigning`. The check is a full path validation with the
  EKU required and the path validated at `producedAt`, and the model is tried
  last, but the widening is real and is reported through
  `ocsp_responder_trusted` so it is never silent.
- **The `certID` uses SHA-256 only.** RFC 6960 makes SHA-1 the default and some
  responders answer only about a SHA-1 `certID`. Those simply yield no usable
  answer and the certificate stays `revocation_status_unknown`, which is the
  same place it was before anything was fetched. Asking with SHA-1 would mean
  this build *generating* a legacy digest, which is a different thing from
  accepting one in an archived response it did not create.
- **`X509SKI` and `X509SubjectName` identities are weaker evidence.** They can
  recognise a certificate already in a validated chain but cannot state an
  issuing relationship, and the subject-name comparison drops the ASN.1 string
  tag because an RFC 4514 string cannot express it. Neither can grant trust;
  both can only decide `qualified`, a legal category.
- **The pre-eIDAS window is a judgement call.** Treating `undersupervision` and
  `accredited` as granted before 2016-07-01 is this project's reading of the
  eIDAS transition, not something a trusted list states. The honoured status is
  always named so a reader can disagree with the reading and see exactly what
  it rested on.

### M4: encrypted payload decryption — done

Shipped. `extract --decrypt-key` reverses the `encrypt` transform. See
[architecture.md](architecture.md#decryption) for the full contract. What
landed:

- **What `encrypt` actually is, established from the sources.** The
  specification says only "S/MIME encryption" and names no algorithm. Microsec's
  own `eszigno3` reference CLI documents `cm_decrypt` as RFC 5652 CMS and
  `export_recipient_infos` as exporting the recipients' certificates and
  encrypted keys, so the decoded payload is read as a DER `ContentInfo`
  carrying `id-envelopedData`.
- **A named subset**: `KeyTransRecipientInfo` recipients identified by
  `issuerAndSerialNumber` or `subjectKeyIdentifier`, RSAES-PKCS1-v1_5 and
  RSAES-OAEP (MGF1, SHA-1/256/384/512) key transport, AES-128/192/256-CBC
  content encryption, and DES-EDE3-CBC only behind `--allow-legacy-ciphers`.
- **No key material in the repository.** The tests generate their RSA keys at
  run time from a fixed seed rather than committing them, and no line of the
  tree spells a complete PEM private-key armour header, so a secret scanner has
  nothing to find and no rule has to be allowlisted.
- **Key material never on the command line**: `--decrypt-key`,
  `--decrypt-cert`, `--decrypt-passphrase-file`, or
  `OPENSZIGNO_DECRYPT_PASSPHRASE`. Key bytes, the passphrase, and anything
  derived from them appear in no log line, message, warning, JSON field, or
  fixture, which a test asserts over stdout, stderr, and the envelope.
- **The same bounds as any other payload**, plus a plaintext bounded before
  allocation by the ciphertext length and re-checked against
  `max_decoded_document_bytes` afterwards, with the ZIP rules applied to a
  `zip` transform underneath unchanged.
- **A capability, not a verdict**: `inspect` reports
  `encrypted_extraction: "with_key"`, `extract` marks a decrypted document
  `decrypted: true`, and nothing about the verification boundary moves.
- **Skips, not failures**, for reasons about one document:
  `document_skipped_no_matching_recipient`,
  `document_skipped_unsupported_cipher`, and
  `document_skipped_legacy_cipher`, each naming the algorithm OID where there
  is one. `decrypt_failed` carries the fixed message `decryption failed` so
  that the tool cannot be used as a padding oracle.

Residuals deliberately left out of M4:

- **The framing could not be confirmed.** No source available here says whether
  a producer ever wraps the CMS message in MIME headers rather than emitting
  bare DER under the Base64 transform. Bare DER is what is implemented; a
  MIME-wrapped payload is reported as `invalid_cms` rather than guessed at.
- **Neither could the recipient-identifier form in the wild.** The
  specification is silent and the maintainers' private corpus holds no
  encrypted document to check against, so both `issuerAndSerialNumber` and
  `subjectKeyIdentifier` are implemented and neither is known to be the one
  Microsec emits.
- **No PKCS#12.** A `.p12`/`.pfx` keystore has to be converted with `openssl`
  first, which
  [architecture.md](architecture.md#key-material) shows. Adding a keystore
  parser would widen the attack surface for a step the operator can do once.
- **No PKCS#11.** A key on a smart card or HSM cannot be used. The reference
  CLI supports it; openSzigno would need a module loader, which is a large
  dependency for a case no one has asked for yet.
- **`RecipientInfo` forms other than `ktri` are ignored**, so a `kari`
  (key-agreement, ECDH) recipient reads as no matching recipient rather than as
  an unsupported algorithm. Naming it would mean parsing structures that
  cannot be acted on.
- **`es:RecipientCertificateList` is not read.** The element is optional and
  advisory; the authoritative recipient list is the CMS `RecipientInfos`,
  which is what the matching uses.
- **No AEAD.** RFC 5083 `AuthEnvelopedData` (AES-GCM) is recognised only to be
  skipped. Nothing in the specification or the reference CLI suggests it is
  produced; the reference CLI's cipher list is OpenSSL `enc` names, which are
  CBC-era.
- **Timing.** The RSA private-key operation runs through `rsa` 0.9, whose
  non-constant-time behaviour is RUSTSEC-2023-0071. That advisory is accepted
  in `deny.toml` on the grounds that the tool never held a private key; M4
  makes it hold one for the length of one `extract` run. The exposure needs a
  local attacker who can time that run, which is outside the threat model in
  [SECURITY.md](../SECURITY.md), but the note in `deny.toml` was updated and
  the ignore should be revisited when `rsa` 0.10 is stable.

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
  root), which a trusted list covering those CAs would cover.

With phase 2 (XAdES signed properties and RFC 3161 signature timestamps),
the same corpus with the two Microsec roots as anchors and the legacy
algorithm flag gives, in aggregate: `SigningCertificate` bound for all 62
signatures; 59 signatures carry a signature timestamp and 56 of those verify
fully, so the validation time comes from a trusted timestamp for 56
signatures; 52 signer chains validate at that time; and 49 of the 62
signatures pass every implemented check and are blocked only by revocation.
The remaining ones chain to CAs outside the two-root store, use 1024-bit RSA,
or carry advisory extended key usages. With phase 3 those 49 become reachable
`valid` results, but only for a caller who supplies revocation data that covers
the validation time; the private corpus has not been re-measured with one.

With phase 3 (revocation and trusted lists), the same corpus verified with the
Hungarian trusted list (its signature checked against the NMHH signer taken
from the EU list of trusted lists), the two Microsec roots, and a revocation
store holding the public Microsec CA CRLs gives, in aggregate: 54 of 62
signatures `valid` with exit status 0, 43 of them qualified with the matching
CA/QC service named; 7 `invalid` (1024-bit RSA signers, signatures without a
timestamp whose certificates have expired, one genuinely revoked certificate,
one chain to a CA outside the trust set); 1 `indeterminate` capped by the
legacy-algorithm flag. Real Microsec dossiers embed OCSP responses for the
end-entity certificate only, so the CA CRLs must be supplied through the
revocation store, or fetched with `--online`, which M3 added. The corpus has
not been re-measured with `--online`.

With M3 (`--online`), the same corpus verified with the Hungarian trusted list,
the two Microsec roots, and online CRL and OCSP fetching, and no hand-built
revocation store, gives in aggregate: 54 of 62 dossiers `valid` with exit
status 0, 7 `invalid`, 1 `indeterminate`, the same outcome as the store-based
run. Microsec answers OCSP from a central responder that is not issued by the
queried certificate's CA, which the RFC 6960 trusted-responder model accepts
when the responder chains to a configured anchor; 12 container timestamps
verified and 2 did not. Container-timestamp findings never changed a verdict.

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
- **`valid` is narrower than it sounds.** It says that every check this build
  makes passed at the stated validation time, against trust and revocation
  material the caller chose. It is not a statement that the signer is who the
  certificate claims, and it is never a legal judgement. A dossier that reaches
  `indeterminate` may still be forged. This is the single most important thing
  for a downstream caller to internalise.
- **Network exposure with `--online`.** Off by default. With it, the CLI
  connects only to URLs published inside the certificates being validated, and
  parses whatever DER those servers answer with. See `SECURITY.md`.

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
