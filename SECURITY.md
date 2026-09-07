# Security policy

## The one thing to know first

**`valid` means every check openSzigno makes passed. It does not mean the
dossier is authentic, and it never means it is legally valid.**

`openszigno verify` checks XMLDSig canonicalization, reference digests,
signature values, the e-dossier reference-scope rules, the XAdES signed
`SigningCertificate` binding, RFC 3161 signature timestamps, certificate paths
against trust material you supply, and revocation from revocation data you
supply. A verdict of `invalid` is a real cryptographic finding and should be
taken seriously.

A verdict of `valid` is a narrower statement than it sounds. It says: at the
validation time reported alongside it, this signature verified, its certificate
chained to an anchor **you chose to trust**, and revocation data **you
supplied** said no certificate in the chain was revoked. It does not say the
signer is who the certificate claims, that the trust material you supplied was
the right material, or that anything about the dossier satisfies a legal
requirement. Declaring a dossier legally valid is a legal judgement and a
permanent non-goal of this tool.

`valid` is also easy to fail to reach for benign reasons. No trust store, a
trusted list whose own signature was not checked, no revocation data, a CRL
that expired before the validation time, or `--no-revocation` all yield
`indeterminate`, which means "nothing that was checked failed" — not "this is
authentic", and not "this is forged".

**Extraction is not verification.** `inspect`, `list`, `extract`, and
`validate-structure` check nothing cryptographic at all; `signatures_verified`
and `cryptographic_verification_performed` stay `false` for them. A dossier
that openSzigno parses, lists, and extracts without complaint may be entirely
forged.

Equally, a rejection is not proof of forgery: the pinned algorithm policy
refuses SHA-1, RSA below 2048 bits, and other weak algorithms outright, which
will reject some genuine older dossiers.

`xades:ArchiveTimeStamp` is reported but not verified; see
[docs/roadmap.md](docs/roadmap.md).

**Decryption is not verification either.** `extract --decrypt-key` can undo the
`encrypt` transform, which shows that the supplied key could unwrap the
payload. It establishes nothing about who produced the document, and it does
not change any command's verdict.

## How key material is handled

`extract --decrypt-key` is the only place openSzigno touches a private key.

- **Never from the command line.** The key, its certificate, and its passphrase
  all come from files, or the passphrase from the environment variable
  `OPENSZIGNO_DECRYPT_PASSPHRASE`. There is no flag that takes a passphrase as
  an argument value, because `argv` is readable by other processes on most
  systems and lands in shell history.
- **Never in any output.** Key bytes, the passphrase, and anything derived from
  them never appear in a log line, an error message, a warning, the JSON
  envelope, or a test fixture. The file paths the caller typed may appear,
  because that is how a failure is acted on. A test asserts the absence of key
  and passphrase material on stdout, on stderr, and in the envelope, on both a
  successful and a failing run.
- **Zeroed after use.** Key and passphrase buffers are zeroed when they are
  dropped.
- **None of it lives in this repository.** No private key, in any encoding, is
  committed here, synthetic or not. The decryption tests generate their keys at
  run time from a fixed seed, so the suite stays deterministic without storing
  key material, and no line of this repository spells a complete PEM
  private-key armour header. A secret scanner cannot tell a synthetic key from
  a real one, so the project stores none and allowlists no scanner rule.
- **Never sent anywhere.** Decryption is entirely local. `--online` is a
  `verify` flag and fetches only revocation data; no command ever transmits key
  material.
- **Read-only and bounded.** Key, certificate, and passphrase files are opened
  read-only and capped at 1 MiB each.
- **Failures say nothing useful to an attacker.** A failed decryption is the
  fixed message `decryption failed`, which does not distinguish a failed RSA
  unwrap from a bad content-key length from bad padding — that distinction is
  what a padding oracle is built out of. A wrong passphrase and a malformed key
  are likewise the same answer.

openSzigno never creates, signs, timestamps, or encrypts anything, so it holds
a private key only for the duration of one `extract` run.

## Network exposure

**openSzigno makes no network connection unless you pass `--online` to
`verify`.** Without that flag it opens no socket at all, in any command, and
the `openszigno-verify` crate structurally cannot: it performs no I/O except
through injected traits, and revocation data reaches it only as bytes the
caller already has.

With `--online`, the CLI — never the verify crate — may connect to exactly one
class of destination: **URLs found inside the certificates being validated**,
namely the `cRLDistributionPoints` URIs and the `authorityInfoAccess`
`id-ad-ocsp` access locations. Those are fields a CA wrote into a certificate
that a trust anchor signed. No URL is ever taken from the dossier's XML, no
reference in a dossier is ever dereferenced with or without the flag, and trust
anchors and trusted lists are never fetched in any mode.

The requests are `GET` for a CRL and a `POST` of an RFC 6960 `OCSPRequest` for
OCSP. They carry no data about the dossier beyond the certificate serial number
the OCSP request necessarily names, which is a privacy consideration worth
knowing about: it tells the CA's responder that someone is validating that
certificate now. The transport is bounded — 5 s to connect, 20 s per fetch,
16 MiB per CRL, 64 KiB per OCSP response, at most three redirects and never to
another host — and no proxy is taken from the environment; `--online-proxy` is
the only way to introduce one. Everything fetched is judged by exactly the
offline rules before it is believed, so `--online` can widen where evidence
comes from and can never relax a rule.
[docs/trust.md](docs/trust.md#online-fetching) has the details.

## Threat model

The assumed attacker supplies the `.es3` input and controls every byte of it,
including its XML structure, declared sizes, transform chain, payload bytes,
and document titles. The operator runs openSzigno on that input, possibly
unattended, possibly as part of an agent pipeline, and extracts into a
directory the attacker cannot write to but may race against.

openSzigno aims to guarantee that a hostile input cannot:

- exhaust memory, stack, or disk beyond the documented limits, including
  through XML nesting, node counts, Base64 length, or ZIP compression ratios;
- cause a panic, an unbounded read, or an unhandled crash instead of a stable
  error code;
- read or fetch anything outside the input file, in particular through DTDs,
  external entities, or entity expansion, all of which are rejected;
- write outside the requested output directory, through a path in a document
  title, a ZIP member path, an absolute path, or a symlink or reparse point in
  the output path;
- overwrite, truncate, or replace an existing file;
- leave a partial extraction behind after a mid-run failure;
- smuggle content into the machine-readable channel, since JSON mode emits
  exactly one object on stdout and all diagnostics go to stderr;
- cause openSzigno to disclose input paths, document titles, or payload
  content in an error message;
- learn anything about a decryption key from how a decryption failed, or cause
  key or passphrase material to reach stdout, stderr, the JSON envelope, or an
  extracted file;
- cause openSzigno to make a network connection without `--online`, or, with
  it, to any destination other than a URL published inside a certificate being
  validated — including through a redirect, an environment proxy, or a scheme
  the certificate did not name;
- cause `verify` to report a signature as anything better than it is: to
  resolve a reference to a node other than the one the container semantics
  require (signature wrapping), to reach the network or the filesystem while
  resolving a reference, to have a weak or unlisted algorithm accepted, to have
  a certificate path accepted without a configured anchor, to have revocation
  data believed that the issuing CA did not authorise (including a CRL or OCSP
  response the *signer* embedded in the dossier's own `RevocationValues`, or
  one a server answered with under `--online`), to
  have expired or out-of-scope revocation data treated as covering the
  validation time, to have a trusted-list anchor accepted for a service that
  was not granted at the validation time, or to reach a `valid` verdict while
  any check is `failed`, `unknown`, or `skipped`.

The last of those is the load-bearing one now that `valid` is reachable: the
only non-blocking check status is `info`, which is reserved for checks that
report rather than decide. A path from an `unknown` to a `valid` verdict would
be a vulnerability in this tool.

`verify --json` output can contain personal data of signers: the signing
certificate's subject and issuer common names, its serial, and its
fingerprint. Those are signature metadata a caller needs, so they appear in
structured fields and never in a free-text message. Treat the output
accordingly.

The safety mechanisms behind these are documented in
[docs/architecture.md](docs/architecture.md#parser-safety-model) and
[docs/architecture.md](docs/architecture.md#extraction-policy).

## In scope for a report

- Memory exhaustion, stack overflow, unbounded allocation, or a panic reached
  from a crafted `.es3` input.
- Any escape from the documented limits, including ZIP-bomb amplification and
  Base64 or decoded-size bypasses.
- XML external entity, DTD, or entity-expansion processing that is not
  rejected.
- Path traversal, symlink or reparse-point following, file overwrite, or any
  write outside the requested output directory.
- Time-of-check/time-of-use races in output handling on Unix, where the
  descriptor-relative implementation is meant to close them.
- Disclosure of an input path, document title, or payload content in a
  message, warning, error, or diagnostic.
- Disclosure of `--decrypt-key` material or its passphrase in any output, or a
  distinguishable failure that turns openSzigno into a padding oracle for a
  key the operator supplied.
- Any output that states or implies that a signature, timestamp, certificate,
  or dossier is valid.
- Contamination of stdout in `--json` mode, or an exit status that
  contradicts the documented category.

## Out of scope

- The absence of `xades:ArchiveTimeStamp` imprint verification, or of CMS
  recipient and cipher forms outside the subset in
  [docs/architecture.md](docs/architecture.md#decryption). Both are documented
  behaviour — see
  [docs/architecture.md](docs/architecture.md#archive-timestamps) for why the
  archive-timestamp imprint was left unimplemented rather than guessed at — and
  are tracked as roadmap items, not vulnerabilities.
- The weakness of DES-EDE3-CBC itself. It is refused unless
  `--allow-legacy-ciphers` is given, and the flag exists because it is what the
  Microsec reference tool encrypted with by default.
- An `indeterminate` verdict on a dossier you believe is good, when the cause
  is trust or revocation material you did not supply. Supplying it is the
  operator's job, and [docs/trust.md](docs/trust.md) describes how.
- A dossier that openSzigno refuses to parse because it uses an unsupported
  namespace, encoding, or transform chain. Report that as a compatibility
  issue; see
  [CONTRIBUTING.md](CONTRIBUTING.md#proposing-a-format-compatibility-change).
- Resource use within the documented limits, for example peak memory that is a
  multiple of a 64 MiB input.
- Directory-swap races on non-Unix platforms, which are a documented residual
  risk in [docs/roadmap.md](docs/roadmap.md#engineering-items). A report that
  demonstrates a *new* class of failure there is still welcome.
- Vulnerabilities in Microsec products, in third-party dossier viewers, or in
  a dependency where the correct venue is that project's own security process.
  Tell us anyway if openSzigno's use of the dependency makes it exploitable.

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting for this
repository:

1. Open <https://github.com/watt-mind/openSzigno/security/advisories>.
2. Choose **Report a vulnerability**.

Please do not open a public issue, and do not disclose the problem publicly
until a fix is available.

Include:

- affected version or commit, and platform;
- what happens and what should happen instead;
- a **synthetic** reproducer. Never attach a real dossier, a private path, a
  document title, payload bytes, a certificate subject, or a signature value.
  If the trigger comes from a real file, describe it structurally and, where
  possible, rebuild it as synthetic data.

We aim to acknowledge a report within seven days and to agree a disclosure
timeline with the reporter. Fixes land on `develop`, are merged to `master`,
and are noted in [CHANGELOG.md](CHANGELOG.md) with credit if the reporter
wants it.

## Supported versions

The project is pre-1.0. Only the latest release and the current `develop`
branch receive security fixes.
