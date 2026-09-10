# Testing, fixtures, and test-data policy

## Test layout

| Location | Kind | What it covers |
| --- | --- | --- |
| `crates/openszigno-core/src/*.rs` (`#[cfg(test)]`) | Unit tests | Internals that are not reachable through the public API, such as the pre-parse scan's depth and node counting, comment/CDATA/processing-instruction handling, truncated-markup tolerance, and the decryption decisions a cooperating sender never exercises: the RSAES-OAEP parameter subset, the content-cipher table, the CBC key/IV/block-length checks, PEM block scanning, and the CMS container types. |
| `crates/openszigno-author/src/*.rs` (`#[cfg(test)]`) | Unit tests | The writer: the XML a build renders, MIME derivation from an extension, the title rules extraction shares, the one-member ZIP and its compression-ratio refusal, every limit a build is bounded by, and the round trip back through `openszigno-core`. Under `src/sign/`: the rendered `ds:SignedInfo` and qualifying properties, the signing-key and certificate loading and its refusals, the RFC 3161 request and the response shapes a refusal must not be read past (a token that does not decode reporting no `genTime` among them), and the encoding declaration rewrite. `sign/stamp.rs` covers the container-timestamp writer's own decisions: the scope names, the identifier disambiguation, the refusal of a placement that already carries an `es:TimeStamp` and of a `TimeStamp` from a foreign namespace deciding anything, and the splicing of several elements at once. `sign/csc/tests.rs` covers the CSC protocol module on its own: the request bodies, the discovery and credential readers, the algorithm mapping from a credential's `key/algo` list, and the responses a refusal must not be read past. |
| `crates/openszigno-author/tests/sign.rs` | Integration tests | The signer against the reader that has to accept it: a dossier is built, signed, and handed to `openszigno-verify`, which must report every check about the signature itself as passed. Document and dossier scope, the selector and its deduplication, a second signature added beside an existing one, the refusal to break a frame signature, a timestamp callback failure, and the determinism of everything outside `ds:SignatureValue`. Every key is generated while the test runs. |
| `crates/openszigno-cli/tests/sign.rs` | CLI integration tests | `sign` end to end through the built binary: two documents signed and then verified against a trust store built seconds earlier, which is `indeterminate` for exactly `signature_timestamp_absent` and `revocation_status_unknown` without a timestamp, and `valid` with a loopback RFC 3161 authority and a CRL for both chains; `--scope dossier` covering every document; the RSA-PSS and ECDSA P-256 variants; the mismatch, missing-key, refused-destination, malformed-token, no-clobber and unknown-selector refusals; that no key byte or passphrase reaches any stream; and the byte-for-byte determinism of two RSA PKCS#1 v1.5 runs. The loopback timestamp authority reads the imprint out of the request and stamps it, as a real one does. |
| `crates/openszigno-cli/tests/timestamp.rs` | CLI integration tests | `timestamp` end to end through the built binary, with no signing key anywhere in the suite: a dossier-level timestamp whose element shape (placement, `Include` order, canonicalization method, one token) is asserted and which then verifies as `dossier_timestamp_verified` while the dossier's verdict and exit status stay exactly what they were without it; a document-level timestamp reported against the document it sits in; every document timestamped without a selector; a dossier edited after timestamping reported `dossier_timestamp_invalid` with the verdict `invalid`; and the refusals, each asserted at the loopback listener to have contacted nothing: a second timestamp at one placement (`timestamp_exists`), a document timestamp under a dossier-level one (`document_already_signed`), an unknown selector (`document_not_found`), a refused destination (`tsa_failed`), and an existing output (`output_exists`). The loopback authority is the one `sign.rs` uses: it reads the imprint out of the request and stamps it. |
| `crates/openszigno-cli/tests/csc.rs` | CLI integration tests | `sign --csc` end to end against the loopback mock service: each of the three surveyed discovery shapes producing a signature this tool then verifies, the chain the service published becoming the path the verifier builds, an `explicit` credential authorised with a PIN from a file, several credentials never guessed between and one named with `--csc-credential`, a returned signature that does not verify refused with nothing written, the bearer token appearing in no stream and in no output file, `--csc` and a local key mutually exclusive, an unusable configuration refused before anything is contacted, a plaintext service refused without `--online-allow-private`, a service that is not there reported `csc_unreachable`, and a `--tsa` timestamped remote signature verifying end to end. |
| `crates/openszigno-cli/tests/csc_support/mod.rs` | Shared test plumbing | The loopback mock Cloud Signature Consortium service, in the three personalities `docs/remote-signing.md` section 3.5 recorded from live deployments, so discovery is exercised rather than hard-coded to one vendor. It signs in `explicit` mode; its `oauth2` personality exists to be refused. Everything is synthetic and local, and no private key is committed. Not a test target of its own. |
| `crates/openszigno-author/tests/encryption.rs` | Author integration tests | The `encrypt` transform round-tripped through `openszigno-core`'s decryption: both key transports, a plain and a `zip -> encrypt -> base64` payload, several recipients each reading the same document, a key that names none of them, the declared source size staying the plaintext length, the refusal codes for an unreadable and a non-RSA certificate, and the proof that encryption makes two runs differ while a run without recipients stays byte-identical. Its keys are generated at run time from a fixed seed and never stored. |
| `crates/openszigno-cli/tests/create_encrypt.rs` | CLI integration tests | `create --encrypt-for` through the built binary: the round trip to `extract --decrypt-key` byte for byte with and without `--zip`, two recipients each reading the document while an unnamed key is `document_skipped_no_matching_recipient`, `--legacy-key-transport`, `list`/`inspect`/`validate-structure` reporting the result exactly as they report the committed encrypted fixture, `invalid_recipient_certificate` and `unsupported_recipient_key` at exit 4 with nothing written, the `recipient_certificate_expired` warning, and the guarantee that no key material reaches stdout, stderr, or the envelope. |
| `crates/openszigno-cli/tests/create.rs` | CLI integration tests | `create` end to end: the committed `tests/fixtures/created.es3` reproduced byte for byte, determinism, `list`/`validate-structure`/`inspect` over the result, `extract` reproducing every input through `--zip` and `--embed`, the no-clobber refusal, the usage and refusal codes, and the human summary. |
| `crates/openszigno-core/tests/*.rs` | Core integration tests | The public `parse` and `decode_document` API, split by concern: structural parsing rules, XML decoding and encodings, bounded payload decoding (transform chains, Base64 and ZIP limits, ZIP bombs, unsafe members), namespace policy with structural warnings and nested-dossier detection, content sniffing, and the stable public surface of codes, limits, and serialised types. Shared builders for synthetic dossiers live in `tests/common/mod.rs`. `decryption.rs` covers the `encrypt` transform: every supported cipher and key transport, both recipient namings, `zip -> encrypt -> base64`, a wrong key, malformed CMS, an oversize plaintext, a stranger's recipient, and the legacy-cipher refusal. |
| `crates/openszigno-verify/tests/c14n.rs` | Canonicalization tests | Canonical XML 1.0 and Exclusive C14N 1.0 against hand-computed canonical forms: the W3C specification's processing-instruction and start-tag examples, namespace scope for a document subset, `xml:*` attribute inheritance, default-namespace undeclaration, escaping, comments and CDATA, source-prefix fidelity, and subtree exclusion. Byte-for-byte comparisons: a canonicalizer that quietly drifts is worse than one that refuses. |
| `crates/openszigno-verify/tests/verify.rs` | Verification integration tests | Every check code with a positive and a negative case: document- and dossier-level signatures, ECDSA and enveloped signatures, digest and signature-value tampering, external and unresolved references, XSLT and XPath transforms, SHA-1 and HMAC methods, RSA-1024, missing `ds:KeyInfo`, untrusted and expired chains, key-usage, basic-constraints, path-length and name-constraint violations, the report shape, and the rule that no message quotes signer data. |
| `crates/openszigno-verify/tests/structure.rs` | Verification integration tests | XMLDSig cardinality and order over a dossier that verified before each edit: a duplicated `ds:SignedInfo`, `ds:SignatureValue`, `ds:CanonicalizationMethod`, `ds:SignatureMethod`, `ds:Transforms`, `ds:DigestMethod`, `ds:DigestValue` and `ds:KeyInfo`, the out-of-order forms (`ds:SignatureValue` before `ds:SignedInfo`, `ds:DigestValue` before its `ds:DigestMethod`, `ds:KeyInfo` after a `ds:Object`), and a foreign-namespace child of `ds:Signature`, `ds:SignedInfo` and `ds:Reference`. Each must report `sig_structure_invalid`, reach the `invalid` verdict, and never emit a passed `signature_value_ok`. The positive case keeps the schema's extension points open: `ds:KeyInfo`, two extra `ds:Object` elements and comments between children still verify. |
| `crates/openszigno-verify/tests/verify_scope.rs` | Verification integration tests | The container's own rules, split out of `verify.rs`: placement a signature may not sit at, a `Document` with no `DocumentProfile` and a structurally broken signature leaving the mandated set unknown, and the shapes the private corpus showed: a reference to the `es:SignatureProfile` element itself, the profile and qualifying-properties objects in either order, legacy XAdES 1.2.2 with its versioned `SignedProperties` `Type`, a `Type` attribute that cannot stand in for resolution, coverage through a `ds:Object` ancestor the transforms leave in place, and `resolved_to` being reported even when the policy stage failed. Drives the same harness as `verify.rs`. |
| `crates/openszigno-verify/tests/coverage.rs` | Verification integration tests | Per-document signature coverage, split out of `verify.rs`: an unsigned dossier leaving every document uncovered, an unsigned sibling capping an otherwise `valid` dossier at `indeterminate`, a dossier-level frame signature covering every document, an enveloped frame signature covering the documents outside it, a document signature never covering a sibling, `covered_unverified` when the covering signature fails, coverage left undetermined by an unresolved reference or by processing this build does not support, a profile-less document listed as not modelled, an embedded dossier covered without recursion, and an enveloped whole-document reference covering nothing inside the signature. |
| `crates/openszigno-verify/tests/paths.rs` | Verification integration tests | Certificate-path building, split out of `verify.rs`: a chain delivered only through `xades:CertificateValues`, a root inside the dossier never becoming an anchor, deduplication of a certificate present in both places, intermediates from the trust store, the expansion budget giving up rather than searching forever, RFC 5280 name constraints (URI, DNS label boundaries, IP, and an unimplemented form failing closed), the `keyUsage` and `extendedKeyUsage` policy including the advisory case, malformed and unimplemented critical extensions, and signer selection by the key that verifies rather than by document order. |
| `crates/openszigno-verify/tests/vectors.rs` | Independent vectors | Material openSzigno did not produce: canonical forms transcribed from Canonical XML 1.0 (whitespace, character modifications, UTF-8 encoding) and Exclusive XML Canonicalization 1.0 (re-enveloping), and a complete signed dossier from `tests/fixtures/xmldsig/` whose digests and signature value were computed by OpenSSL and Python over hand-written canonical octets. Every other suite signs with the helper that shares the canonicalizer under test; these do not. |
| `crates/openszigno-verify/tests/avdh.rs` | Verification integration tests | The AVDH-authenticated shape: a synthetic dossier whose signature carries an explicit signature policy with its hash, claimed roles in both the `SignerRole` and `SignerRoleV2` spellings, a commitment type, a signing time, and a clause document beside the authenticated one. Pins that it reaches `valid`, that the policy, the roles and the commitment reach the JSON, that the fields are absent when the signature claims none, and that an uncovered clause document caps the dossier at `indeterminate` without failing anything. |
| `crates/openszigno-verify/tests/xades.rs` | Verification integration tests | Stage C: the signed `SigningCertificate` and `SigningCertificateV2` binding in v1 and V2 form and in the legacy namespace, a wrong `CertDigest`, a contradicting `IssuerSerial` and `IssuerSerialV2`, a substituted certificate over the same key, a SHA-1 `CertDigest`, an absent property, an implied signature policy, unprocessed properties, `ArchiveTimeStamp`, a bare `es:TimeStamp` with no data selection, and malformed properties that must neither pass nor panic. |
| `crates/openszigno-verify/tests/timestamps.rs` | Verification integration tests | Stage F, including the `TimeStampResp` wrapper (granted, grantedWithMods, and every rejected status) and DER of an unknown shape: a token that verifies end to end, explicit inclusive and exclusive canonicalization of `ds:SignatureValue`, a wrong imprint, a TSA with no, a non-critical, or the wrong `extendedKeyUsage`, an untrusted and an unknown TSA chain, a `genTime` before the claimed `SigningTime`, malformed and garbage tokens, forms this build does not process, and the validation time: a verified token moving it into the past so an expired signer still chains, `--at` overriding it, and an unverified token moving nothing. |
| `crates/openszigno-verify/src/tsa/tests.rs` | Verification unit tests | The refusal paths of RFC 3161 token parsing: an oversized token, bytes that are not a `ContentInfo`, a non-`SignedData` content type, an undecodable `SignedData`, a wrong encapsulated content type, a missing eContent, an undecodable `TSTInfo`, an imprint algorithm outside the allowlist, missing or contradictory signed attributes, more than one `SignerInfo`, subject-key-identifier selection, and the pinned algorithm maps. |
| `crates/openszigno-verify/tests/revocation.rs` | Verification integration tests | Stage E: a good status from an embedded OCSP response and from an embedded CRL, revocation before and after the validation time, `certificateHold`, a revoked intermediate, a revoked TSA certificate, stale and absent data, a CRL from the wrong issuer, one signed by a stranger and one with a broken signature, delta CRLs, every `issuingDistributionPoint` form the build refuses and the two it accepts, unknown critical CRL extensions, delegated CRL signers and OCSP responders with and without the required EKU, the RFC 6960 section 2.2 trusted-responder model (a central responder under a configured anchor accepted, the same responder without the EKU refused, one under an untrusted root refused, and the issuer and delegated models keeping precedence), tier fallback from an unauthorised OCSP answer to a usable CRL, `byKey` responder identity, `certID` matching including SHA-256, unsuccessful and `unknown` OCSP responses, source priority, `--no-revocation`, and the revocation-store classifier. |
| `crates/openszigno-verify/tests/trustlist.rs` | Verification integration tests | ETSI TS 119 612 trusted lists: anchor loading and its origin, list metadata, digital identities that supply no certificate, service status resolved at the validation time across a history, withdrawn statuses, the pre-eIDAS statuses honoured before eIDAS applied and refused after it, `X509SKI` and `X509SubjectName` service identities matching and failing to match, the preference for the `xml:lang="en"` service name, qualified determination with and without `QcCompliance`, the `QcSSCD` claim, a trust-store anchor leaving qualified undetermined, and the list's own signature: verified, tampered, signed by the wrong key, absent, and every structural rule of its `ds:Signature` reported separately. |
| `crates/openszigno-verify/tests/countersignatures.rs` | Verification integration tests | Both countersignature forms and the support boundary: a XAdES `xades:CounterSignature` that binds to the signature it is embedded in and reaches `valid` alongside it, the countersigned signature keeping its own role and mandated set, a countersignature granting no document coverage, a tampered countersigned `ds:SignatureValue` breaking both, a nested signature resolving to a foreign `ds:SignatureValue` (mismatch) and to none at all (missing), two `ds:Signature` elements in one `xades:CounterSignature` and a signature under a non-`CounterSignature` element both being unsupported with the enclosing signature unaffected, an unsupported placement capping the dossier at `indeterminate` rather than sinking it, the e-dossier `es:SignatureProfile/es:Type` form including the deprecated Hungarian spelling and its missing-binding case, and the additive JSON fields. |
| `crates/openszigno-verify/tests/container_timestamps.rs` | Verification integration tests | Stage G, the container `es:TimeStamp`: a dossier-level and a document-level timestamp verifying end to end, an explicit exclusive canonicalization, an imprint mismatch making the **dossier** `invalid` while every signature keeps its own verdict, `Include` order being part of what is digested, an unparseable token, a scope the format mandates that the timestamp does not cover, an `Include` that resolves to nothing, an external `Include` that is never dereferenced, `ReferenceInfo` and no-`Include` selection forms, an undecodable token, a placement the format does not describe, and a missing trust store being a gap rather than a finding, a dossier whose signature is `valid` staying `valid` when it also carries a timestamp whose TSA chain cannot be judged, and the standing property that no container-timestamp check ever blocks at the dossier level except the `_invalid` codes. |
| `crates/openszigno-cli/tests/online.rs` | CLI integration tests | `--online`, against a `std::net::TcpListener` bound to a loopback port the operating system picked, with certificates minted seconds earlier naming that port. A CRL and an OCSP response fetched and used, `--online-cache` making a later offline run reproduce the answer through `store_crl`, nothing fetched when the store already covers the certificate, a 17 MiB body refused, a redirect to another host refused, a server that never answers bounded rather than hung, an HTTP error reported with its status, a well-formed CRL from the wrong CA fetched and then rejected, a fetched CRL that revokes the certificate believed, an unauthorised OCSP answer not stopping the CRL from being fetched, a failed fetch reported as `online_fetch_failed` (`info`) while the chain that needed the data still blocks, the OCSP `POST` asserted at the server to arrive whole with exactly one `Content-Length` and no chunking, an HTML error page refused, and the flag combinations. Every run sets `HTTP_PROXY` to an address nothing listens on, so a run that quietly picked a proxy up from the environment would fail. The server reads each request in full (headers and `Content-Length` body) before answering, replies with an explicit length and `Connection: close`, drains and shuts the write side down, and keeps its listener bound from before the certificate names the port until the test ends. That is not tidiness: a server that answers before reading the body leaves unread bytes in the socket, and closing in that state makes Windows send an RST, which the client sees as a transport error rather than an HTTP answer. The failure appeared only on Windows and only for the request with a body. |
| `crates/openszigno-cli/tests/online_policy.rs` | CLI integration tests | The rules *around* the transport, all against the same loopback server: a dossier reaching no configured anchor produces zero requests (asserted on the listener) while the same dossier fetches once an anchor is configured; a configured anchor that is a stranger to the chain, and an untrusted two-certificate chain the dossier carries whole, are likewise never fetched for; a certificate embedded beside the signer that chains to the anchor but that no signature needed generates no traffic; a loopback destination is refused without `--online-allow-private` and fetched with it; a URL with userinfo is refused whatever the flags say; two certificates behind one responder produce two OCSP `POST`s with distinct bodies; an oversized revocation-store file is refused with its size and the limit; and the cache is idempotent, never truncates an existing file, refuses a symlinked path component, and never follows a dangling symlink standing where a cache file would go. |
| `crates/openszigno-cli/tests/online_support/mod.rs` | Shared test plumbing | The loopback HTTP server, the synthetic PKI, and the CLI runners both `--online` suites use. Not a test target of its own. |
| `crates/openszigno-cli/src/online/` (unit tests) | CLI unit tests | The URL and destination rules the transport rests on: redirect resolution against a base, a different port counting as a different host, non-HTTP schemes, userinfo, every refused address range including the cloud metadata addresses and IPv4-mapped forms, and a failure message naming its URL and class with no control character in it. |
| `crates/openszigno-verify/tests/algorithms.rs` | Verification integration tests | Every accepted signature scheme and digest, P-384, unsupported key types, unrecognised critical extensions, name constraints on subject alternative names, malformed certificate and trust-store input, and the pinned policy tables. |
| `crates/openszigno-verify/tests/common/` | Test helper | A synthetic PKI built with `rcgen`, an XMLDSig signer built on the crate's own canonicalization backend plus `rsa`/`p256`, a synthetic timestamp authority that builds RFC 3161 tokens with `cms`/`der`, a synthetic CA that issues CRLs and OCSP responses with `x509-cert`'s CRL types and `x509-ocsp`, and a synthetic ETSI TS 119 612 trusted list. The real EU and Hungarian lists in the gitignored `refs/trust/` cache are read only as documentation of the schema and are never touched by a test: they change daily, and asserting anything about a real trust service provider would make the suite a statement about that provider. `openszigno-author` now signs, but only the one XAdES shape a producer should write; this helper stays in `tests/` because its job is the signatures a *verifier* must cope with, including the malformed and the deliberately wrong, and it must never move into a shipped crate. `mod.rs` only declares the submodules below and re-exports their items, so every `use common::{...}` import elsewhere is unaffected by which file holds what: `keys.rs` (the committed synthetic RSA keys, which are generated test material and must never be used for anything), `pki.rs` (keys, certificates, and certificate extension builders), `dossier.rs` (namespace/algorithm constants, the specs describing a synthetic dossier, and its unsigned rendering), `signer.rs` (the XMLDSig/XAdES signer), `timestamps.rs` (the RFC 3161 token builder), `cms.rs` (the CRL and OCSP builders), `trustlist.rs` (the synthetic trusted list), and `harness.rs` (the end-to-end verification harness the `verify.rs` and `verify_scope.rs` suites share: the runs with and without a trust store, the check-code assertions, and the small PKI they sign with). |
| `crates/openszigno-cli/tests/verify.rs` | CLI integration tests | The `verify` process contract: the envelope, exit statuses 6 and 7, a structural failure still exiting 4, trust-store layouts and failures, `--at` as a usage error, and the human output's verdict and policy lines. |
| `crates/openszigno-cli/tests/end_to_end.rs` | CLI integration tests | The exit-status contract over a dossier that actually verifies: a complete signature exiting `0` with `verdict: "valid"`, the same dossier exiting `6` with its signer revoked, `--no-revocation` and missing revocation data both exiting `7`, an unusable revocation-store file and an unusable trusted list failing the run, a dossier with an unjudgeable container `es:TimeStamp` still exiting `0`, and a trusted list supplying a qualified anchor. It includes `crates/openszigno-verify/tests/common/mod.rs` by path rather than copying it, so there stays exactly one place in the repository that can sign anything. |
| `crates/openszigno-cli/src/` (`#[cfg(test)]`) | Unit tests | CLI internals, each beside the module it covers: output filename safety and deduplication (`extract/names.rs`), `--document` selector resolution (`extract/select.rs`), skip notices (`extract/plan.rs`), the roll-back of files created by a failed extraction (`extract/write.rs`), capability warnings (`commands/mod.rs`), the `create` document-selector, bounded-read and output-path handling (`commands/create.rs`), the `sign` output-path and no-clobber handling and its mapping of a signing refusal onto an exit status (`commands/sign.rs`), the key, certificate and passphrase file reading shared by `extract` and `sign` (`key_material.rs`), the `--csc` configuration subset, its refusals and its two warnings (`csc/config_tests.rs`), the exit status of each `CliError` (`response.rs`), and the human renderer's missing-value placeholder (`render/human.rs`). |
| `crates/openszigno-cli/tests/nesting.rs` | CLI integration tests | The namespace allow-list and `--allow-namespace`, conformance warnings in every command, content sniffing and the extension fallback, and recursive extraction: subdirectory layout, `dossier_path` values, `--no-recursive`, `--max-depth`, depth-limit and invalid-nested warnings, and name collisions with a `<file>.d` directory. |
| `crates/openszigno-cli/tests/selection.rs` | CLI integration tests | `extract --document` selection by `object_ref` and by index, the `document_not_found` cases including a selector shaped like a nested `dossier_path`, `data.selected`, `skipped_count` within a selection, recursion into a selected embedded dossier, the `--stdout` payload mode byte for byte for plain and ZIP payloads and its refusals, and reading the dossier from stdin on every command including an over-cap stream. |
| `crates/openszigno-cli/tests/cli.rs` | CLI integration tests | The built binary, run as a subprocess: the JSON envelope for every command, human-mode output and its verification-boundary lines, exit statuses, unsafe output names and Unicode collisions, symlinked output directories and intermediate components, file modes, closed stdout, and JSON usage errors. |
| `crates/openszigno-cli/tests/skill.rs` | CLI integration tests | The `skill` command: its stdout is the committed `crates/openszigno-cli/skills/openszigno/SKILL.md` byte for byte, with the Agent Skills frontmatter intact, nothing on stderr and exit `0`; and `skill --json` is a usage error (exit 2), since the command emits no envelope. |
| `crates/openszigno-core/tests/common/envelope.rs` | Test helper | A synthetic CMS `EnvelopedData` encryptor and the two throwaway RSA-2048 keys it uses. **The keys are generated at run time, never stored.** No private key in any encoding lives in this repository: a secret scanner cannot tell a synthetic key from a real one, and this project does not allowlist scanner rules, so the only safe amount of key material in the tree is none. They are still deterministic (a fixed seed through `ChaCha20Rng`, generated once per test binary behind a `LazyLock`), so a failure reproduces exactly. Passphrase-protected keys are encrypted here too, under both PBES2 key derivations (`PBKDF2-SHA-256`, what `openssl pkcs8 -topk8` writes, and scrypt). `openszigno-author` now writes the `encrypt` transform, but only the narrow subset a producer should emit; this encryptor stays in `tests/` because its job is the messages a *reader* must cope with and a producer must never write (DES-EDE3-CBC, unsupported algorithm identifiers, deliberately damaged framing), and it must never move into a shipped crate. `crates/openszigno-cli/tests/decrypt.rs` and `create_encrypt.rs` include this file by path rather than copying it. |
| `crates/openszigno-cli/tests/decrypt.rs` | CLI integration tests | `extract --decrypt-key` through the built binary: a decrypted document and its `decrypted: true`, a bundled PEM key and certificate, a bare key refused for want of one, a stranger's recipient and a legacy cipher as skip warnings, malformed CMS as exit 5, the passphrase coming from a file and from the environment but from no flag, the capability string, and the guarantee that no key or passphrase byte reaches stdout, stderr, or the envelope on a successful or a failing run. Every key it writes to a temporary file was generated seconds earlier by the helper above. |
| `crates/openszigno-cli/tests/private_smoke.rs` | Private opt-in tests | Compatibility smoke tests against locally held real dossiers. They do nothing unless the relevant environment variable is set. |
| `tests/fixtures/` | Fixture data | Synthetic, unsigned, CC0-dedicated `.es3` files used by both integration suites. |
| `tests/golden/` | Golden contract files | The captured stdout and exit status of every command over every fixture, in `--json` and human mode, plus two trusted `verify` runs over the signed XMLDSig vector, one `create` case that builds a dossier from `tests/fixtures/create/`, two `sign` refusals, and one `timestamp` refusal. Compared by `scripts/golden.py`; see [Golden output contract](#golden-output-contract). |

The CLI integration tests exercise the real binary rather than calling library
functions, because the JSON envelope, exit statuses, and stdout/stderr split
are part of the public contract and can only be checked end to end.

## Running the tests

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The CI `docs` job also lints every tracked `*.md`: `npx markdownlint-cli2`,
`scripts/check-doc-links.py` for relative links and anchors,
`scripts/check-prose.py` for the "no em-dashes" rule from
[CONTRIBUTING.md](../CONTRIBUTING.md#documentation), and
`scripts/check-file-length.py`.

## Golden output contract

The suites above check behaviour from inside. `tests/golden/` checks the
output itself: for every fixture under `tests/fixtures/`, the stdout and exit
status of `inspect`, `list`, `validate-structure`, `verify` and `extract` in
`--json` mode, and of `inspect`, `list`, `validate-structure` and `verify` in
human mode. The signed vector `tests/fixtures/xmldsig/openssl-rsa-sha256.es3`
additionally gets two `verify` runs with a trust store holding its committed
synthetic anchor and `--at` pinning the validation time. Two cases are not
driven by a fixture: `create` builds a dossier at a pinned `--created`, and
`sign` captures two refusals, since a successful signing run would need a
private key and this repository commits none.

`scripts/golden.py` runs that matrix. It builds nothing, takes the binary
from `--bin`, reaches no network, orders every case deterministically, and
extracts into throwaway directories under the system temporary directory that
it removes when it finishes.

```sh
cargo build --release --locked -p openszigno-cli
python3 scripts/golden.py check  --bin target/release/openszigno
python3 scripts/golden.py update --bin target/release/openszigno
```

`check` prints a unified diff per mismatching file and exits 1 on any
difference, a golden that is not committed, or a committed golden no case
produces. CI runs it in the `golden` job, and the release smoke test runs it
against the packaged binary.

Exactly two values are masked, both clock-dependent:
`data.verification_time.effective` and the human `Validation time:` line
always, and a signature's `validation_time` only when its
`validation_time_source` is `current_time`. Nothing else is normalised, so
byte counts, certificate dates, and array order are compared as produced.

A diff is a change to the output contract, not a broken test. What to do
about one, and the `schema_version` rule it is judged under, is in
[tests/golden/README.md](../tests/golden/README.md) and
[CONTRIBUTING.md](../CONTRIBUTING.md#golden-output-contract).

## Coverage

Coverage is measured with `cargo-llvm-cov`:

```sh
cargo install cargo-llvm-cov
cargo llvm-cov --workspace
```

For a browsable report, or for an LCOV file to upload from CI:

```sh
cargo llvm-cov --workspace --html
cargo llvm-cov --workspace --lcov --output-path lcov.info
```

`crates/openszigno-cli/tests/online.rs` and `online_policy.rs` bind loopback
sockets, and one test waits out the 20-second fetch timeout, so the CLI suite
takes about half a minute longer than the rest. Neither ever leaves the
loopback interface (the destination policy refuses that by default), so the
runs that expect to fetch pass `--online-allow-private` and the ones holding
that rule honest deliberately do not.

Coverage runs must never be pointed at the private corpus: the opt-in tests
stay inert unless their environment variables are set, so leave them unset.

CI enforces coverage with `scripts/coverage_gate.py`, run against the lcov
file above:

```sh
cargo llvm-cov --workspace --lcov --output-path lcov.info
python3 scripts/coverage_gate.py --lcov lcov.info --base origin/develop
```

It reads `lcov.info` and checks four things: every crate directory under
`crates/` appears in the report at all; every crate (`crates/<name>`) is at
or above 90% line coverage, where a crate with no instrumented lines scores
0 rather than 100; lines added or modified since `--base`
under `crates/*/src/` are at or above 80% covered, when the change touches
at least 20 instrumentable lines; and no crate has dropped more than 1.0
point below the value recorded for it in `scripts/coverage-floors.txt`.

`python3 scripts/coverage_gate.py --self-test` runs the script's own unit
tests for the `-U0` diff parser that patch coverage rests on: the part
whose edge cases (an added line beginning with `++`, a removed one
beginning with `--`, a hunk header without counts) a coverage report cannot
show. The
workspace's `--fail-under-lines 85` check in CI stays as a coarse backstop
after this gate. See
[CONTRIBUTING.md](../CONTRIBUTING.md#coverage-quality-gate) for the ratchet
rule and how to update the floors file after a legitimate coverage change.

## Mutation testing

Coverage says a line ran; it says nothing about whether a test would notice
if the line did the wrong thing. `.github/workflows/mutants.yml` runs
[cargo-mutants](https://mutants.rs/) nightly to measure that instead: it
rewrites `openszigno-core` and `openszigno-verify`, one small change at a
time (`>` to `>=`, `&&` to `||`, a function body to a fixed placeholder, and
so on), rebuilds, and runs the crate's test suite against each mutated copy.
A mutant the suite still passes against is a **survivor**: some behaviour
changed and no test caught it.

This is deliberately not a pull-request check. A full run is tens of minutes
even at `-j 2` (roughly 8 minutes for `openszigno-core`'s 559 mutants on the
host this was seeded on; on a GitHub runner that crate's now 694 mutants took
49 minutes, and `openszigno-verify`'s 1,756 extrapolate to about two hours),
which is too slow and too resource-hungry to run on every push. It runs
nightly instead, plus on manual dispatch, and a gate failure
opens or refreshes a tracking issue rather than blocking a merge, so a
declining mutation score is never simply lost.

### Running it locally

```sh
cargo install cargo-mutants --locked
cargo mutants -p openszigno-core --timeout-multiplier 2 -j 2 --output mutants-core
cargo mutants -p openszigno-verify --timeout-multiplier 2 -j 2 --output mutants-verify
```

`--output <dir>` writes a `mutants.out` subdirectory there with a log per
mutant, `caught.txt`/`missed.txt`/`timeout.txt`/`unviable.txt` listings, and
`outcomes.json`, which the gate script below reads. On a memory- or
time-constrained machine, `--shard 1/4` (or `--file crates/.../src/foo.rs`)
bounds a single crate's run to a slice of its mutants; `cargo mutants --list
-p <crate>` shows how many mutants a crate currently has without running any
of them.

`.cargo/mutants.toml` sets the default `timeout_multiplier` (a mutant is
killed once it runs past that multiple of the unmutated baseline's time,
which is how an infinite-loop mutant is caught rather than hung forever) and
`exclude_re`, a short, individually justified list of mutants that are
trivially uncatchable rather than gaps in the tests. It excludes exactly one
entry today: `C14nError`'s `Display` impl, which only formats two fixed
sentences of human-readable prose (see the comment in the file for the
reasoning). A survivor is a prompt to strengthen a test, never a reason to
add to that list.

### Reading survivors

```sh
python3 scripts/mutants_gate.py --dir mutants-core/mutants.out --crate openszigno-core
```

prints a Markdown table of every surviving (missed) mutant: its file, line,
and the mutation applied (for example, "replace > with >= in decode_base64"
means the test suite passed whether or not that comparison used `>` or
`>=`, which is worth a boundary-value test). Timeouts and unviable mutants
(ones whose mutated code did not even compile) are reported separately and
do not count as either caught or missed.

### Exit statuses, and what actually fails the nightly run

`cargo mutants` distinguishes several outcomes by exit status. The list below
is [its own](https://mutants.rs/exit-codes.html), for the pinned 27.1.0:

| Status | Meaning | Nightly verdict |
| --- | --- | --- |
| 0 | every viable mutant that was tested was caught | run completed |
| 1 | usage error, such as bad arguments | job fails |
| 2 | some mutants were missed, that is they survived | run completed |
| 3 | some tests timed out | run completed |
| 4 | the unmutated baseline tests already fail | job fails |
| 5 | the `--in-diff` diff does not match the tree | job fails |
| 6 | the `--in-diff` diff could not be parsed | job fails |
| 70 | internal cargo-mutants error | job fails |

Only 0, 2 and 3 mean the run finished and `outcomes.json` describes every
mutant. For those three the score decides, not the exit status, and
`scripts/mutants_gate.py` computes it; the workflow's own check exists purely
to catch the other statuses, where there is no report to score. Two of those
statuses are easy to misread. 3 does not mean failure: a mutant that hangs is
neither proof the tests caught it nor proof of a gap, so the gate leaves
timeouts out of `caught / (caught + missed)` on both sides, exactly as the
floors in `scripts/mutants-floors.txt` were seeded, and a run whose only
blemish is timeouts passes. And 4 is a failing baseline, not "some mutants
were unviable": unviable mutants are recorded in `outcomes.json` and never
change the exit status at all, so 4 always means no mutant was tested.

A job killed by its own `timeout-minutes` reports neither an exit status nor
a score, because it never reaches the gate step. The workflow's reporting job
watches for a `cancelled` result as well as a `failure` one and says so in
the tracking issue's title, so an incomplete run is never mistaken for a
declining mutation score.

### Updating the floors

`scripts/mutants-floors.txt` records each crate's caught percentage
(`caught / (caught + missed)`) the way `scripts/coverage-floors.txt` records
coverage: a nightly run fails if a crate drops more than 2.0 points below
its recorded value. After a change that legitimately raises or lowers a
crate's mutation score, rerun `cargo mutants` for that crate and update its
floor:

```sh
cargo mutants -p openszigno-core --timeout-multiplier 2 -j 2 --output mutants-core
python3 scripts/mutants_gate.py --dir mutants-core/mutants.out --crate openszigno-core --update-floors
```

Commit the updated `scripts/mutants-floors.txt` alongside the change that
caused the shift. CI never rewrites this file itself. The `openszigno-verify`
floor seeded in this repository today was measured from a quarter of that
crate's mutants (`--shard 1/4`), not a full run, because of the host time
budget available when it was seeded; the first nightly run replaces it with
the true value, and the ratchet tolerance absorbs the difference until then.

LAB-274 turned the first batch of survivors from that seeding pass into
behavioural tests: boundary tests for `decode.rs`'s compression-ratio check
and its ZIP symlink guard, exact-limit and deep-offset cases for `scan.rs`'s
depth/node counting, `inventory.rs`'s first-occurrence match guards,
`trust.rs`'s trust/revocation accessors and further `parse_rfc3339`
boundaries beyond LAB-273's, and `scope.rs`'s node-ownership guard so that
covering one signature's own profile object never satisfies a different
signature's requirement. One survivor turned out to be effectively
unreachable through the public API rather than a gap: `xml.rs`'s `allow_dtd`
wiring is defence in depth behind `scan::prescan`, which already rejects any
`<!` markup before a tree is ever built. Not every survivor from the seeding
pass is gone; the rest are left for a later pass.

## Fuzzing

`fuzz/` is a [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) package,
excluded from the root workspace (`[workspace] exclude` in the root
`Cargo.toml`) with its own `Cargo.lock`, so its nightly toolchain and
libFuzzer/AddressSanitizer instrumentation never touch the stable,
MSRV-pinned build the rest of the workspace is held to. Coverage, not a
crash count, is the yardstick: every target below asserts only that the
function under it never panics, which is the property `docs/architecture.md`
promises of anything that reads a hostile `.es3` input, a certificate, a CRL,
an OCSP response, a timestamp token, or a trusted list.

| Target | Exercises |
| --- | --- |
| `parse_dossier` | `openszigno_core::parse`, with both `Limits::default()` and a deliberately tiny `Limits`, so early limit-check bailouts get their own coverage. |
| `sniff` | `openszigno_core::sniff`. |
| `decode_payload` | The document decode chains (`base64`, `zip -> base64`, and the two `encrypt` chains with no decryption key) through a synthetic minimal dossier wrapping the fuzzed bytes as one document's payload, driven through both `decode_document` and `decode_document_with`. Asserts that a decode without a key never reports a decryption. |
| `decrypt_cms` | The CMS `encrypt` transform decrypt path, through `decode_document_with` with a synthetic RSA recipient key and self-signed certificate generated at run time from a fixed seed (never committed; see the doc comment on `fuzz/fuzz_targets/decrypt_cms.rs`). |
| `extract_plan` | The CLI's extraction planner: `extract/names.rs` and `extract/plan.rs`, driven with arbitrary titles and declared extensions through a synthetic dossier. Asserts that no planned name is a path, that no two names in one directory collide, and that planning the same dossier twice yields the same names. Both modules are included by `#[path]` over a small `response` stand-in, because the `openszigno` binary crate has no library target to depend on. |
| `destination_url` | The `--online` destination policy, `online/destination.rs`, likewise included by `#[path]`. Asserts that `permitted` never hands back an address its own `verdict` refuses, that a non-HTTP scheme and userinfo are refused whatever `--online-allow-private` says, and that a relative `Location` resolved by `resolve` stays on the base URL's authority. No input reaches the network: `permitted` is called only for a host the policy answers without a lookup. |
| `c14n` | `openszigno_verify::c14n`: parses arbitrary bytes as XML, then canonicalizes the whole document with every implemented `C14nAlgorithm` variant (inclusive/exclusive, with/without comments). |
| `crl_parse` | CRL parsing via `openszigno_verify::revocation::classify`, the function a revocation store loader runs over every file. |
| `ocsp_parse` | OCSP response parsing via the same `classify` function. |
| `tsa_token` | RFC 3161 token parsing via `openszigno_verify::tsa::token_certificates`. |
| `trustlist_parse` | `openszigno_verify::trustlist::load`, called with no signer certificates (the fully offline, `trust_list_unverified` mode). |
| `certificate_parse` | X.509 candidate parsing via `openszigno_verify::certs::certificates_from_bytes`, exactly what a trust or revocation store loader runs over every file. |

Every target bounds its own work (an oversized input is rejected before any
parsing starts) and every target under this crate's own limits finishes
comfortably under 2 seconds per input, so a hang is itself a finding.

### Prerequisites

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked
```

### Running a target locally

```sh
cargo +nightly fuzz run <target> -- -max_total_time=60 -jobs=1
```

Build every target without running one (useful as a fast compile check):

```sh
cargo +nightly fuzz build
```

On a memory-constrained machine, cap the build's parallelism:

```sh
CARGO_BUILD_JOBS=4 cargo +nightly fuzz run <target> -- -max_total_time=60 -jobs=1
```

### Reproducing a crash artifact

A crashing input is written to `fuzz/artifacts/<target>/`. Replay it directly:

```sh
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash-file>
```

Minimise it before filing or committing it:

```sh
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/<crash-file>
```

A crash is a bug in the crate under test, never in the fuzz target: this
project's policy is "never panics", so a found panic is fixed in
`crates/openszigno-core` or `crates/openszigno-verify`, not worked around in
`fuzz/fuzz_targets/`. See [SECURITY.md](../SECURITY.md#in-scope-for-a-report)
for how a panic reached from a crafted input is reported when it is found
outside this repository's own nightly run.

### Corpus

`fuzz/corpus/<target>/` holds a small, committed seed corpus (well under the
2 MiB the project keeps it under), generated deterministically from
`tests/fixtures/` and from small hand-built ASN.1 and XML seeds, never from
`samples/` or any private corpus. Regenerate it with:

```sh
fuzz/seed.sh
```

which runs the generator at `fuzz/seeds/src/main.rs`
(`cargo run --manifest-path fuzz/seeds/Cargo.toml`). The generator is
idempotent: rerunning it overwrites the same fixed filenames rather than
accumulating files, so a libFuzzer-discovered addition to a target's own
`fuzz/corpus/<target>/` directory (from a local run) survives a reseed.

### Adding a target

1. Add a `fuzz_targets/<name>.rs` using `libfuzzer_sys::fuzz_target!`, bound
   its input size, and call only the crate's public API. See the existing
   targets for the pattern of "parse a fixed-shape wrapper around the fuzzed
   bytes, then call the function under test".
2. Add a matching `[[bin]]` section to `fuzz/Cargo.toml`.
3. Add seeds for it in `fuzz/seeds/src/main.rs` and run `fuzz/seed.sh`.
4. Add a row to the CI matrix in `.github/workflows/fuzz.yml`.
5. Add a row to the table above.

### Continuous fuzzing

`.github/workflows/fuzz.yml` runs every target nightly (`-max_total_time=600`,
one job per target, a 20-minute budget each) and on manual dispatch with a
chosen target and duration. Each job builds the target first and runs it only
if that build succeeded, so the two outcomes are reported apart: a crash
uploads the artifact and opens or refreshes the `Fuzzing: crashes` issue,
while anything else (a target that would not compile, a timeout) opens or
refreshes `Fuzzing: build failed` instead. Only a target that actually wrote
a crashing input is ever reported as a crash. See that workflow for the exact
schedule and permissions.

CI passes `--target x86_64-unknown-linux-gnu` explicitly. cargo-fuzz defaults
`--target` to the triple its own binary was built for, not the host's, so a
prebuilt musl cargo-fuzz otherwise asks for a statically linked target that
AddressSanitizer refuses. A locally built `cargo install cargo-fuzz` already
defaults to the host triple, so the flag is not needed by hand.

## Public fixtures

The repository contains only synthetic, redistributable test dossiers. They
were authored by this project, carry no personal or company data, and are
dedicated to the public domain (CC0-1.0) where that is legally effective.

| Fixture | Purpose |
| --- | --- |
| `plain-base64.es3` | One unsigned UTF-8 text payload; baseline parsing, metadata, list, and extraction. |
| `zip-base64.es3` | One unsigned ZIP-compressed payload; transform reversal and ZIP limits. |
| `duplicate-id.es3` | Rejected as `duplicate_id`. |
| `unresolved-objref.es3` | Rejected as `unresolved_objref`. |
| `invalid-base64.es3` | Parses structurally; extraction rejects `invalid_base64`. |
| `traversal-title.es3` | Parses structurally; extraction rejects `unsafe_output_name`. |
| `encrypted.es3` | Parses and reports the document as encrypted and unsupported. |
| `doctype.es3` | Rejected as `unsafe_xml`. |
| `nested-dossier.es3` | One `application/nldossier2` document whose Base64 payload is a complete dossier; recursive extraction and `--no-recursive`. |
| `two-documents.es3` | Two `base64` text documents; `--document` selection and the `--stdout` refusal when more than one document is in scope. |
| `compatible-namespace.es3` | A 2014 e-cégeljárás-namespace dossier; parses with the `dangling_objref` and `document_without_profile` conformance warnings. |
| `xmldsig/openssl-rsa-sha256.es3` | The only signed fixture: an independent XMLDSig vector whose digests and signature value were produced outside this project, with its synthetic anchor `xmldsig/root.pem`. |

Every fixture and its expected behaviour is listed in
[tests/fixtures/README.md](../tests/fixtures/README.md), which is the
authoritative list.

Limit cases that need large or binary-patched inputs (deep nesting, node
counts, ZIP size and ratio bombs, encrypted ZIP members, unsafe ZIP paths,
unsafe output names) are generated inside the test code rather than committed
as fixtures.

Synthetic dossiers are **test data**. All but one are unsigned; the exception,
`xmldsig/openssl-rsa-sha256.es3`, is signed by a synthetic test PKI whose
private keys are not committed. None of them must ever be presented as
authentic, qualified, or interoperable signature evidence. The fixtures and
their expected outcomes live under `tests/fixtures/`; see
`tests/fixtures/README.md`.

## Real-world corpus

No real `.es3` or `.et3` dossier may be committed to the public repository
unless its provenance, privacy status, and redistribution permission are
documented and approved. A developer may point an opt-in integration test at a
locally supplied file through an environment variable; the test must not log
the path, filename, contents, hashes, metadata, certificate subjects, or
signature values.

Public `.es3` samples were not located during initial research. That is not a
reason to scrape or republish dossiers from official filings: e-dossiers can
contain sensitive documents and are not automatically licensed for test-data
redistribution.

## Private opt-in smoke tests

Both tests below are no-ops when their environment variable is unset, so they
are safe to leave in the default `cargo test --workspace` run.

Single fixture. The test runs the CLI, captures its output, and asserts
aggregate success only; it never prints the variable's value or any
dossier-derived data:

```sh
ES3_TEST_FIXTURE=/private/path/input.es3 cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_fixture_smoke
```

Recursive corpus. The harness calls the core library directly, bounds file and
directory traversal, suppresses panic payloads, and discards path-bearing I/O
errors. Its only output is an aggregate of file and document outcomes and
stable error-code buckets:

```sh
ES3_TEST_CORPUS_DIR=/private/path/corpus cargo test \
  -p openszigno-cli --test private_smoke opt_in_private_corpus_smoke \
  -- --nocapture
```

Neither test logs paths, filenames, payloads, hashes, metadata, certificate
subjects, signer data, or signature values. The fixture smoke test extracts
into a temporary directory that is removed when the test finishes; if the test
process is killed, the extracted files remain under the system temporary
directory and must be removed by hand.

A corpus failure reports aggregate bucket counts only. Unsupported namespaces
and malformed non-dossiers remain visible as parse-error buckets but do not
fail the harness; infrastructure failures, panics, supported-payload decode
failures, an empty corpus, or zero supported dossiers do fail it.

The maintainer rules for handling that corpus, including how to report
findings, are in [roadmap.md](roadmap.md#private-corpus-policy-for-maintainers).

## Compatibility testing later

Before claiming compatibility beyond synthetic files, collect consented test
fixtures covering UTF-8 and ISO-8859-2 XML, document-level signatures,
dossier-level signatures, timestamps, document comments, multiple payloads,
ZIP, encryption markers, and custom compatible namespaces. Keep fixture
provenance and expected behaviour in a private test-corpus manifest.
