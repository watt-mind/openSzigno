# Security policy

## The one thing to know first

**`valid` means every check openSzigno makes passed. It does not mean the
dossier is authentic, and it never means it is legally valid.**

`openszigno verify` checks XMLDSig canonicalization, reference digests,
signature values, the e-dossier reference-scope rules, the XAdES signed
`SigningCertificate` binding, RFC 3161 signature and container timestamps,
certificate paths against trust material you supply, and revocation from
revocation data you supply or that the opt-in `--online` fetched for a
certificate on a path to one of your anchors. A verdict of `invalid` is a real
cryptographic finding and should be taken seriously.

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

**Extraction is not verification.** `inspect`, `list`, `extract`,
`validate-structure`, `create`, and `sign` check nothing cryptographic at all;
`signatures_verified` and `cryptographic_verification_performed` stay `false`
for them. A dossier that openSzigno parses, lists, and extracts without
complaint may be entirely forged.

**Writing is not verification.** `create` and `sign` produce material; they
assert nothing about it. `create` writes an unsigned dossier and warns
`created_dossier_unsigned` on every run. `sign` writes a signature with the key
it was given and checks none of it: not the key, not the certificate, not the
chain, not the token a `--tsa` returned beyond that it stamps the right
imprint. Every successful run warns `signed_dossier_unverified`. Running
`verify` on what `sign` wrote, against trust material you supply, is the only
way to learn whether it holds, and a `valid` verdict there means exactly what
this section already says it means. It is not a qualified electronic
signature: that needs a key on a qualified device, which by construction is
not a key this process can hold. See
[docs/remote-signing.md](docs/remote-signing.md).

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

`extract --decrypt-key` is the only place openSzigno holds a private key.
`sign --key` holds one too, under exactly the same rules; `sign --csc` holds
none at all, because the key stays in the remote signature creation device and
only a digest is sent to it.

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
- **Never sent anywhere.** Decryption and local signing are entirely local. No
  command ever transmits key material, and `sign --csc` transmits a digest
  rather than the data it was taken over.
- **Read-only and bounded.** Key, certificate, and passphrase files are opened
  read-only and capped at 1 MiB each.
- **Failures say nothing useful to an attacker.** A failed decryption is the
  fixed message `decryption failed`, which does not distinguish a failed RSA
  unwrap from a bad content-key length from bad padding — that distinction is
  what a padding oracle is built out of. The RSA half does not even raise it:
  it rejects implicitly, so a bad wrapped key fails as the content cipher, not
  as itself. A wrong passphrase and a malformed key are likewise the same
  answer.

A private key is held only for the duration of the one run that needs it.

### The `--csc` bearer token

`sign --csc` carries one more secret: the bearer token that reaches the Cloud
Signature Consortium service. It is handled the way a passphrase is.

- **Never from the command line.** It comes from the `--csc` configuration
  file, or from a file that configuration names, and there is no flag that
  takes it as an argument value. The same is true of the PIN and the one-time
  password an `explicit`-mode credential is authorised with.
- **Never in any output.** The token, the PIN and the one-time password never
  appear in a message, a warning, the JSON envelope, or the dossier that is
  written. A refusal from the service quotes the HTTP status and the service's
  own `error` string; `error_description` is free text a provider writes and is
  never printed. The `Debug` of the loaded configuration is written by hand so
  that a panic cannot print one. A test asserts the token's absence on stdout,
  on stderr and in the signed file, on a successful run and on a refused one.
- **Zeroed after use**, like every other secret buffer.
- **Sent to one place, in one way.** In the `Authorization` header of a request
  to the host `base_url` names, over `https` unless `--online-allow-private`
  was given. Never in a URL and never in a body.
- **The configuration's own permissions are reported, not enforced.** A
  world-readable file earns the `csc_config_permissive` warning. A mode this
  tool refused would be a mode somebody worked around, and the file may hold no
  secret at all when the token lives in a separate `access_token_file`.

### RSA key-transport decryption: implicit rejection

`extract --decrypt-key` unwraps the CMS `RecipientInfo`'s encrypted
content-encryption key with the operator's RSA private key. The RSA
*ciphertext* being decrypted there is not something the operator chose: it is
bytes read straight out of the untrusted `.es3` dossier. That is the textbook
setup for a Bleichenbacher/Marvin-style chosen-ciphertext attack
(RUSTSEC-2023-0071) against PKCS#1 v1.5 key transport, where an attacker who
can submit many crafted dossiers to the same key and learn, per dossier,
whether the padding checked out recovers the plaintext one dossier at a time.

openSzigno never gives that answer. It rejects **implicitly**, the mitigation
OpenSSL 3.2+ ships as `RSA_PKCS1_IMPLICIT_REJECTION`, Go's `crypto/rsa`
applies unconditionally, and RFC 5246 section 7.4.7.1 prescribes for the same
problem in TLS. In `openszigno-core`'s `decrypt/keytrans.rs`:

- the blinded RSA private operation runs **once** and yields the raw plaintext
  block, which openSzigno unpads itself rather than letting the `rsa` crate
  report a padding error;
- every PKCS#1 v1.5 type 2 check (the leading `0x00 0x02`, a padding run of at
  least eight non-zero bytes, the `0x00` separator, and a payload of exactly
  the length the announced content cipher's key needs) accumulates into a
  single constant-time flag, with no early return and no branch on a plaintext
  byte;
- a block that fails any of those is replaced by a **synthetic**
  content-encryption key of the right length, derived with HMAC-SHA-256 from a
  per-key secret over the ciphertext and selected in constant time, so both
  outcomes execute the same instructions;
- decryption then continues into the content cipher unconditionally, and a
  substituted key surfaces as the same `decryption failed` a tampered content
  ciphertext produces.

The substitute is deterministic for one `(private key, ciphertext)` pair and
unpredictable to whoever submitted the ciphertext, so resubmitting a dossier
tells an attacker nothing a single submission did not, and no substitution can
be recognised by precomputation. A test asserts that a tampered wrapped key and
a tampered content body reach the caller as the same code and the same message,
across every supported cipher and both key-transport algorithms.

**What this removes**: the padding oracle carried by control flow, by the error
surface, and by the coarse timing difference between stopping at the unpadding
step and running the whole content cipher.

**What remains**: `rsa` 0.9's modular exponentiation is not constant-time, and
neither is its big-integer to byte-string conversion, whose length follows the
plaintext's leading zero bytes. Decryption stays blinded with an `OsRng`-seeded
factor, which masks the exponentiation by randomising the value it operates on;
removing the residual outright needs `rsa` 0.10 and its constant-time
crypto-bigint backend, which has no stable release yet. This is a fine-grained
timing residual on a local, one-shot CLI, not an oracle a caller can read off
the result. See `deny.toml`'s `RUSTSEC-2023-0071` entry for the full analysis
and [docs/architecture.md](docs/architecture.md#decryption).

One consequence is worth stating plainly: because a bad key transport is no
longer distinguishable, a dossier whose wrapped key is unusable is decrypted
under a synthetic key and the failure surfaces further down. Almost always
that is the content cipher's PKCS#7 padding, reported as `decryption failed`.
Roughly once in 256 the padding of garbage is valid by chance, and the answer
is then `source_size_mismatch`, because the document's declared source size no
longer matches what came out. Only if that length matched too would openSzigno
write the garbage, which needs both accidents at once. Decryption asserts
nothing about authenticity in any case, which is the point made under
"Decryption is not verification either" above; verify a signature if you need
to know that content is genuine.

## Network exposure

**openSzigno opens a socket only when you ask it to, with one of three
flags: `verify --online`, `sign --tsa`, or `sign --csc`.** Without one of
them it opens no socket at all, in any command, and the `openszigno-verify`
crate structurally cannot: it performs no I/O except through injected traits,
and revocation data reaches it only as bytes the caller already has. All three
go through one transport, with one destination policy, one set of timeouts and
one set of size caps; a second HTTP client in this binary would be a second
place for those rules to drift.

With `--online`, the CLI — never the verify crate — may connect to exactly one
class of destination: **URLs found inside the certificates being validated**,
namely the `cRLDistributionPoints` URIs and the `authorityInfoAccess`
`id-ad-ocsp` access locations. Those are fields a CA wrote into a certificate
that a trust anchor signed. No URL is ever taken from the dossier's XML, no
reference in a dossier is ever dereferenced with or without the flag, and trust
anchors and trusted lists are never fetched in any mode.

Two further rules bound that class, because a certificate inside a dossier is
attacker-supplied until something the operator configured vouches for it:

- **Trust-gated.** A URL is contacted only for a certificate on a
  certification path openszigno **validated to a configured trust anchor** —
  from `--trust-store`, or from a trusted list — for a signature or a timestamp
  it was evaluating. A certificate embedded elsewhere in the XML generates no
  traffic even when it chains to a configured anchor, because no signature
  needed it. With no anchors configured **nothing is fetched at all**, and the
  report says so (`policy.revocation` reads `online_no_anchors`). Without this
  rule, "an issuer in the dossier signed this certificate" — a statement
  whoever wrote the dossier wrote on both sides of — was enough to make the
  tool open a connection of the dossier's choosing.
- **A destination policy**, applied to the published URL and to every redirect
  target alike. Only `http` and `https`, exactly as published. A URL carrying
  userinfo is always refused. Refused unless `--online-allow-private` is given:
  loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), unique-local
  (`fc00::/7`), unspecified (`0.0.0.0/8`, `::`), broadcast
  (`255.255.255.255`), multicast (`224.0.0.0/4`, `ff00::/8`), and the cloud
  instance metadata addresses `169.254.169.254` and `fd00:ec2::254`, plus the
  names `localhost` and `*.localhost`. An IPv4-mapped IPv6 address is judged as
  the IPv4 address it carries. The host's *resolved* addresses are checked
  against the same list before connecting, so a public name that resolves
  inwards is refused too. Refusals are reported as `online_fetch_failed`
  (`info`) with the class `destination_refused` and the rule that refused the
  destination, and nothing is contacted.
- **No downgrade on a redirect** (`redirect_downgrade`). A redirect that leaves
  `https` for `http` is refused for every request kind, even on the host the
  certificate named. A redirect is the peer's choice, and a peer does not get
  to move an exchange that started under TLS into the clear, carrying whatever
  the first request carried. The refusal is decided before the next hop is
  opened, so nothing is contacted at the downgraded target.
- **Credentials require `https` on every hop** (`credentials_require_https`).
  A request carrying a bearer token in the `Authorization` header, or a body
  the caller marked sensitive, is refused unless the URL is `https`, the first
  hop included. `--online-allow-private` waives it only for a loopback service,
  and only on the addresses the policy approved. A revocation fetch carries no
  credentials and is unaffected: a CRL is public and is signature-checked
  either way.
- **The `Authorization` header goes on last.** It is attached only after the
  target has passed the destination policy, the credential rule and the address
  pin, in the one place in this binary that puts a bearer token on the wire, so
  a target that failed any check is never sent one.
- **The check is bound to the connection.** The addresses the policy approved
  are pinned as the resolution for that host and port, so the socket goes where
  the policy looked; a name that was not vetted for the fetch in hand does not
  resolve at all, and there is no fallback to the system resolver. A zone that
  answers with a public address and then with a private one therefore has no
  window between the check and the socket. Only the address is pinned: the URL
  is sent as published, so the `Host` header, the TLS SNI value and the
  certificate host-name verification still use the name the certificate
  published. A host that resolves to nothing is reported as `transport` and
  nothing is contacted. With `--online-proxy` the request is sent to the proxy
  and the proxy resolves the destination, so the destination policy still
  checks the URL but the proxy is what opens the socket.
- **The cache is written without following links.** `--online-cache` opens the
  directory with `O_DIRECTORY | O_NOFOLLOW`, walks it one component at a time,
  and creates each file with `O_CREAT | O_EXCL | O_NOFOLLOW`. No existing file
  is ever truncated or replaced, a symlink standing where a cache file would go
  is refused rather than followed, and two runs caching the same artefact at
  once both succeed. A name already taken by different bytes is reported as
  `online_fetch_failed` with the class `cache_collision`.

The requests are `GET` for a CRL and a `POST` of an RFC 6960 `OCSPRequest` for
OCSP. They carry no data about the dossier beyond the certificate serial number
the OCSP request necessarily names, which is a privacy consideration worth
knowing about: it tells the CA's responder that someone is validating that
certificate now. Each certificate is asked about once per responder — OCSP
requests are deduplicated by responder *and* `certID`, not by URL — so a run
neither repeats a question nor skips one. The transport is bounded — 5 s to
connect, 20 s per fetch, 16 MiB per CRL (the same limit the verifier will
parse), 64 KiB per OCSP response, at most three redirects and never to another
host — and no proxy is taken from the environment; `--online-proxy` is the only
way to introduce one, and with it the proxy rather than openSzigno resolves and
connects to the destination. Everything fetched is judged by exactly the
offline rules before it is believed, so `--online` can widen where evidence
comes from and can never relax a rule.
[docs/trust.md](docs/trust.md#online-fetching) has the details.

### What `sign --csc` sends

`sign --csc` contacts exactly one host: the one `base_url` names in the
configuration file the caller passed. It is not a URL taken from a dossier or
from a certificate, so the trust gate above does not apply to it; the operator
chose it.

**What leaves the machine is one base64 SHA-256 digest per signature, the
credential identifier, and the bearer token.** Nothing else. Not the dossier,
not a payload, not a document title, not a file name, not a hash of anything
but the canonicalised `ds:SignedInfo` the signature covers. The digest goes out
twice, in `credentials/authorize`, so the authorisation is bound to the data
it covers, and in `signatures/signHash`, and that binding is why it is sent at
authorisation time rather than a placeholder.

The remaining rules are the ones `--online` already imposes: the destination
policy, the pinned address resolution, 5 s to connect and 20 s per request, at
most three redirects, never to another host and never from `https` to `http`,
no proxy from the environment, and a 256 KiB cap on a response. `https` is
required on every hop, the first included, because the token is in a header
and a `credentials/authorize` body carries the PIN and the one-time password
as well; every CSC request is marked sensitive for that reason. The one
exemption is a loopback service under `--online-allow-private`. A refusal
reaches the caller as `csc_unreachable` naming the rule, and nothing is
contacted.

What comes back is not trusted on the strength of having come back. The
signature the service returns is verified locally, against the certificate the
service itself published, before the signed dossier reaches the filesystem. A
service in hash-only mode signs a digest it never sees the document behind, so
a wrong signature is perfectly well formed; a signature that does not verify is
`csc_signature_invalid` and no file is written.

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
- put a bearer token, a PIN or a one-time password on a plaintext hop, whether
  by naming an `http` service or by answering a request with a redirect that
  downgrades one, or make openSzigno send an `Authorization` header to a
  destination any check refused;
- cause openSzigno to make a network connection without `--online`, or, with
  it, to any destination other than a URL published inside a certificate that
  reaches a configured trust anchor — including through a redirect, a redirect
  that leaves `https` for `http` on the same host, an
  environment proxy, a scheme the certificate did not name, userinfo in a URL,
  a name that resolves to a loopback, private, link-local, unique-local,
  multicast or cloud-metadata address while `--online-allow-private` is absent,
  a second name lookup that disagrees with the one the destination policy
  checked, or a certificate no signature or timestamp under evaluation had a
  validated path to;
- cause openSzigno to follow a symlink out of an `--online-cache` directory, or
  to truncate or replace any file already in it;
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

## Fuzzing

The parser safety model above is a claim about every hostile input, not just
the ones covered by a handwritten unit test. `fuzz/` fuzzes the crates'
public parsing surface with `cargo-fuzz`/libFuzzer against exactly the
threat-model bullet that says a crafted input must never reach a panic,
an unbounded read, or an unhandled crash instead of a stable error code:
dossier parsing and payload decoding, CMS decryption, C14N canonicalization,
and CRL, OCSP, RFC 3161 timestamp, trusted-list, and certificate parsing all
have a target. Every target asserts only "never panics" — a target that
returns `Err` for malformed input is working as designed.

`.github/workflows/fuzz.yml` runs every target nightly and on manual
dispatch; a crash uploads the minimised reproducer and opens or refreshes a
single tracking issue. See [docs/testing.md](docs/testing.md#fuzzing) for how
to run a target locally, reproduce a crash artifact, and add a new target. A
panic a fuzzing run finds is exactly the kind of finding described under
[In scope for a report](#in-scope-for-a-report) below; report it the same way
you would one found by hand.

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
  or dossier is valid when the checks that would establish it did not all
  pass: a `valid` verdict reached with a required check unperformed, a
  `passed` check whose underlying test did not run, or human or JSON wording
  that reads as a legal determination.
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
