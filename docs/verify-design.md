# M2 `verify` design: XMLDSig/XAdES validation for openSzigno

Status: design proposal, no code written. Prepared 2026-09-07.

Scope: `openszigno verify FILE --json` reporting, per signature, XMLDSig
reference and signature-value validity, XAdES signed-properties
consistency, certificate path building to a trust anchor, revocation
status, and (optionally, with M3 able to split it out) timestamp
verification. The tool must never report `valid` unless every check
passed, and every check must emit a stable code.

The existing rules in `docs/architecture.md` ("Verification boundary")
and `docs/roadmap.md` (M2 scope) are treated as binding constraints, not
as suggestions to be relaxed.

---

## 1. Rust ecosystem for XMLDSig and canonicalization

This is the single riskiest dependency decision in M2, because
canonicalization is where XMLDSig implementations historically diverge
and where a subtly wrong implementation silently turns "invalid" into
"valid".

### 1.1 Candidates

| Crate | Version / date | License | Approach | Verdict |
| --- | --- | --- | --- | --- |
| `bergshamra` | 0.9.0 on crates.io, updated 2026-09-02 (README claims 0.10.1, Aug 2026); created 2026-02-22 | BSD-2-Clause | Pure Rust, `forbid(unsafe_code)`, RustCrypto or AWS-LC provider | Best pure-Rust candidate, but very young |
| `xml-sec` | 0.1.16, updated 2026-08-29; created 2026-03-15 | Apache-2.0 | Pure Rust, quick-xml + RustCrypto + x509-parser | Author says "should not yet be used in production" |
| `xml_c14n` | 0.3.0, last release 2023-11-29 | MIT OR Apache-2.0 | Thin safe wrapper over libxml2 C14N | C14N only, unmaintained-ish, needs libxml2 |
| `xmlsec1` bindings (libxml2 + xmlsec1 FFI) | n/a, no well-maintained Rust binding found | MIT (xmlsec1) | FFI to the reference C implementation | Correctness gold standard, portability cost |

Sources:

- <https://crates.io/crates/bergshamra>,
  <https://github.com/kushaldas/bergshamra>
- <https://crates.io/crates/xml-sec>,
  <https://github.com/structured-world/xml-sec>
- <https://crates.io/crates/xml_c14n>,
  <https://gitlab.com/reinis-mazeiks/xml_c14n>
- W3C Exclusive C14N: <https://www.w3.org/TR/xml-exc-c14n/>
- Practical C14N notes: <https://di-mgt.com.au/xmldsig-c14n.html>

### 1.2 Assessment

`bergshamra` is the strongest option on paper. Its README claims all six
W3C C14N variants (inclusive and exclusive, with and without comments,
1.0 and 1.1), document-subset filtering via XPath, enveloped, enveloping
and detached signatures, RSA PKCS#1 v1.5 and RSA-PSS, ECDSA P-256/384/521,
EdDSA, a selectable crypto provider, and 1,148 passing tests from the
xmlsec compatibility suite. It also advertises exactly the hardening
openSzigno needs: duplicate-ID rejection, a strict verification mode,
trusted-keys-only enforcement, and HMAC truncation protection. MSRV 1.88.

The honest caveat: the crate is roughly seven months old, at 0.x, with a
single primary maintainer and no third-party security audit that could be
found. Its own XML parser (`uppsala`) is likewise new, which matters
because canonicalization correctness depends on the parser preserving
namespace declarations, attribute order inputs, and whitespace exactly.
For a tool whose entire value proposition is "does not lie about
validity", adopting a young library wholesale is a real risk.

`xml-sec` is disqualified for now by its own README.

Binding to `libxml2` + `xmlsec1` would buy the reference implementation's
canonicalization behaviour, but it costs the project's core promise of a
portable single binary: a C toolchain in CI for every target, cross
compilation pain for Windows and macOS, static-linking work, and a much
larger memory-unsafe attack surface parsing hostile XML. Since hostile
input is the explicit threat model, pulling in libxml2 to parse it after
the project deliberately built a bounded, safe, `roxmltree`-based parser
would be a regression in the security posture, not an improvement.

### 1.3 Recommended structure: own the pipeline, borrow the C14N

Do not hand a whole `.es3` file to a third-party XMLDSig library and ask
"is it valid". That inverts the trust relationship: the library then owns
reference resolution, transform handling and the algorithm policy, which
are exactly the parts where openSzigno has stricter rules than any
general-purpose library.

Instead:

1. openSzigno keeps ownership of parsing (`roxmltree`, already bounded and
   hardened), of ID resolution, of reference-scope enforcement against the
   e-dossier placement rules, and of the algorithm allowlist.
2. A canonicalization backend is used only as a pure function:
   `(node subtree or node-set, c14n algorithm, inclusive-prefix list) ->
   canonical octets`.
3. Digesting, signature verification, certificate handling, revocation and
   timestamps are done directly on RustCrypto crates, which are mature.

That makes the C14N backend a swappable trait (`C14nBackend`) with two
implementations behind Cargo features:

- `c14n-bergshamra` (default): pure Rust, single binary.
- `c14n-libxml2` (optional, off by default): `xml_c14n` or direct FFI, used
  in CI as a differential oracle rather than as a shipped default.

Differential testing between the two backends over a synthetic corpus
(namespace redeclaration, default-namespace inheritance, xml:* attribute
inheritance for C14N 1.1, attribute ordering, CDATA, comments, PI
handling, entity-free text with CR/LF normalisation) is the concrete
mitigation for "the pure-Rust C14N is young". If the two disagree on any
fixture, that is a build-blocking bug.

There is also a fallback worth naming honestly: if the C14N backend proves
unreliable, `verify` can ship with a restricted canonicalization profile
(exclusive C14N without comments only, refusing anything else with a
distinct `c14n_unsupported` code) rather than shipping something that
might quietly canonicalize wrongly. Refusing to answer is acceptable;
answering wrongly is not.

---

## 2. Certificate and crypto crates

The X.509 and CMS side of the Rust ecosystem is far more mature than the
XML side. Recommended set, all pure Rust:

| Purpose | Crate | Version / date | License |
| --- | --- | --- | --- |
| Certificate parsing, CRL types, DER | `x509-cert` | 0.3.0, 2026-07-09 | Apache-2.0 OR MIT |
| DER/PEM primitives | `der`, `pem-rfc7468`, `const-oid` | with `x509-cert` | Apache-2.0 OR MIT |
| CMS SignedData (RFC 3161 tokens) | `cms` | 0.2.x stable; 0.3.0-pre.2 as of 2026-01-25 | Apache-2.0 OR MIT |
| OCSP request/response | `x509-ocsp` | 0.2.1, 2024-01-08 | Apache-2.0 OR MIT |
| RSA PKCS#1 v1.5 and PSS | `rsa` | current 0.9.x line | Apache-2.0 OR MIT |
| ECDSA P-256/P-384 | `p256`, `p384`, `ecdsa` | current | Apache-2.0 OR MIT |
| Digests | `sha2`, `sha1` (verification only) | current | Apache-2.0 OR MIT |
| Test-only cert generation | `rcgen` | current | MIT OR Apache-2.0 |

Sources: <https://crates.io/crates/x509-cert>,
<https://github.com/RustCrypto/formats/tree/master/cms>,
<https://crates.io/crates/x509-ocsp>,
<https://crates.io/crates/x509-tsp>,
<https://github.com/rustls/rcgen>,
<https://crates.io/crates/x509-parser>.

Notes and gaps:

- **`x509-cert` vs `x509-parser`.** Both parse. `x509-cert` is the
  RustCrypto `der`-based family and shares types with `cms`, `x509-ocsp`
  and `x509-tsp`, which avoids converting between two X.509 object models.
  Prefer `x509-cert` and use `x509-parser` only if a specific extension
  accessor is missing.
- **RFC 3161 tokens.** A timestamp token is a CMS `ContentInfo` wrapping
  `SignedData` whose `eContentType` is `id-ct-TSTInfo`. `cms` parses the
  envelope; `x509-tsp` provides the `TSTInfo` structure. `cms` at
  0.3.0-pre means either pinning 0.2.x or accepting a pre-release; pin the
  stable line and revisit.
- **The real gap: path validation.** There is no mature, general-purpose
  RFC 5280 certification-path-validation crate in Rust.
  `rustls-webpki` implements RFC 5280 path building but is deliberately
  shaped for the Web PKI: it wants a DNS name or IP, applies TLS-oriented
  EKU rules, and its trust anchors are TLS trust anchors
  (<https://github.com/rustls/webpki>, <https://docs.rs/rustls-webpki>).
  Using it for eIDAS signing certificates means fighting the API and
  risks both false accepts (wrong EKU semantics) and false rejects
  (missing SAN). `x509-verify` (<https://crates.io/crates/x509-verify>)
  only checks a single signature, not a path.

  Therefore **openSzigno must implement its own path validation** on top
  of `x509-cert`. This is the largest single piece of net-new
  cryptographic logic in M2. The required subset of RFC 5280 section 6.1
  is:

  - build candidate chains from the end-entity certificate to a
    configured trust anchor, matching issuer DN to subject DN and,
    when present, authority key identifier to subject key identifier;
  - bound chain length (`max_chain_length`, propose 8) and the number of
    candidate paths explored (`max_paths`, propose 32) to avoid
    combinatorial blowup on a hostile bag of certificates;
  - verify each certificate's signature with the issuer's public key
    under the algorithm allowlist;
  - check validity periods against the validation time (see `--at`);
  - require `basicConstraints` cA=true and `pathLenConstraint`
    compliance on every non-leaf;
  - require `keyUsage` `digitalSignature` or `nonRepudiation` on the leaf
    and `keyCertSign` on CAs;
  - process `nameConstraints` (permitted and excluded subtrees for
    directoryName, dNSName, rfc822Name, uniformResourceIdentifier, and
    iPAddress) and reject a chain that violates them;
  - reject unrecognised critical extensions;
  - optional but recommended: certificate policies and
    `policyConstraints` only to the extent of surfacing QCStatements
    (RFC 3739 / ETSI EN 319 412-5) for qualified-status reporting, not as
    a pass/fail gate in M2.

  Be honest in the docs: a hand-rolled path validator is a liability.
  Mitigate with (a) a narrow, explicitly documented subset, (b) heavy
  synthetic testing including negative cases, and (c) an optional
  differential-check mode in CI against OpenSSL's `openssl verify` on
  generated chains.

- **Algorithms actually needed.** Hungarian dossiers span roughly 2007 to
  today, so expect SHA-1 with RSA PKCS#1 v1.5 in older material, SHA-256
  with RSA PKCS#1 v1.5 in most, RSA-PSS and ECDSA P-256 in newer. SHA-1
  and RSA-1024 must be *rejected by default* under the pinned algorithm
  policy (roadmap M2 says "rejected rather than warned about") with an
  explicit opt-in flag that changes the verdict to `indeterminate`, never
  to `valid`.

- **CRL support.** `x509-cert` provides `CertificateList` / `TbsCertList`
  types. Verifying a CRL means: signature by the issuing CA (or a
  properly delegated indirect CRL issuer with `cRLSign`), `thisUpdate <=
  validation time`, `nextUpdate` present and not in the past, scope
  matching via `issuingDistributionPoint` and the certificate's
  `cRLDistributionPoints`, and no unhandled critical CRL extensions.
  Delta CRLs should be refused (`crl_unsupported`) rather than
  half-handled.

---

## 3. XAdES specifics and the e-dossier profile

### 3.1 Standards

- XAdES structure and baseline levels B-B, B-T, B-LT, B-LTA:
  ETSI EN 319 132-1 V1.3.1 (2024-07),
  <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
- Legacy XAdES (what e-dossier actually cites): ETSI TS 101 903, W3C note
  <https://www.w3.org/TR/XAdES/>
- Validation model and status vocabulary: ETSI EN 319 102-1 V1.4.1
  (2024-06),
  <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>

Relevant EN 319 132-1 rule: `SigningCertificateV2` shall be present if the
signing certificate is not in `ds:KeyInfo`, or is in `ds:KeyInfo` but not
covered by the signature; and references should not include
`IssuerSerialV2`. Practically, a verifier must treat "which certificate
signed this" as determined by the *signed* `SigningCertificate` /
`SigningCertificateV2` digest, not by whatever `ds:KeyInfo` happens to
contain, unless `ds:KeyInfo` is itself referenced by the signature.

### 3.2 What Microsec e-dossier prescribes

From the e-dossier specification at <https://srv.e-szigno.hu/edossier>:

- Signatures are placed by location, and location plus the references in
  `//ds:Signature/ds:SignedInfo` together define what the signature
  applies to. A **document-level** signature sits at
  `//es:Document/ds:Signature`; a **frame (dossier-level)** signature sits
  at `//es:Dossier/ds:Signature`.
- A document-level signature must reference: the document payload
  (`//es:Document/ds:Object`), the signature's own profile object
  (`//es:Document/ds:Signature/ds:Object`), the document profile
  (`//es:Document/es:DocumentProfile`), the XAdES `SignedProperties`, and,
  for a countersignature, the `ds:SignatureValue` of each countersigned
  signature.
- A frame signature must reference: `/es:Dossier/es:Documents`, its own
  signature-profile object, `/es:Dossier/es:DossierProfile`, the XAdES
  `SignedProperties`, and countersigned `ds:SignatureValue` elements where
  applicable.
- `es:SignatureProfile` carries `es:SignerName`, `es:Type` (`signature` or
  `countersignature`), `es:Generator`, and optional `es:Comment` (with a
  `Type` attribute such as `clause` or `opinion`), `es:SDPresented`, and
  `es:CustomData`. It lives inside the signature's `ds:Object` and is
  itself referenced, so the signer's declared name and the signature's
  role are signed data, not decoration.
- `es:TimeStamp` behaves like a signature: it references the same elements
  it protects (`//es:Document/ds:Object` and
  `//es:Document/es:DocumentProfile` for a document timestamp) and its
  datatype is `xades:TimeStampType`, i.e. the RFC 3161 token lives in an
  `xades:EncapsulatedTimeStamp` and the canonicalization method for the
  timestamped data is given by the XAdES `ds:CanonicalizationMethod` child.
- XAdES namespace is primarily `http://uri.etsi.org/01903/v1.3.2#`
  (XAdES 1.3.2), with legacy 1.2.2 also occurring.
- Critically: "the present specification doesn't define constraints on the
  XAdES signatures" and "the e-dossier format doesn't imply restrictions
  on the signature". The container spec does **not** pin canonicalization,
  digest, or signature algorithms. openSzigno must therefore supply its
  own algorithm policy; the format will not do it.

Level expectation: in practice Microsec e-Szigno produces signatures at
XAdES-BES/EPES plus a signature timestamp (T), and long-term forms with
`CompleteCertificateRefs`/`CompleteRevocationRefs` and
`CertificateValues`/`RevocationValues` (XL, i.e. modern LT) where
long-term validity was requested; `ArchiveTimeStamp` (A / LTA) appears in
archival dossiers. Design for: B-B always, B-T commonly, B-LT sometimes,
B-LTA rarely. Treat `ArchiveTimeStamp` as out of M2 scope and report it as
`skipped` with an explicit code rather than ignoring it. See also
<https://www.microsec.hu/en/pki-blog/xades-signature-types> and the
e-cégeljárás background at <https://en.wikipedia.org/wiki/XAdES>.

A key consequence for openSzigno: because the container spec mandates
*which elements* must be referenced, the verifier can and should enforce
**reference-scope completeness**. A signature that verifies
cryptographically but omits a mandated reference (for example, does not
cover `es:DocumentProfile`) must fail a distinct check. This is the
project's strongest defence against signature wrapping, and it is a check
most generic XMLDSig libraries cannot perform because they do not know the
container semantics.

---

## 4. Trust: EU trusted lists and the offline store

- The EU List of Trusted Lists is an XML file, per ETSI TS 119 612
  (current V2.4.1, 2025-08,
  <https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf>),
  published at <https://ec.europa.eu/tools/lotl/eu-lotl.xml> and pointing
  at 31 national lists, refreshed daily. Overview:
  <https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109149/eSignature+List+of+Trusted+Lists>
- The LOTL is itself XAdES-signed; its legitimate signing certificates are
  published out of band in the Official Journal of the EU, which is the
  only trustworthy way to bootstrap. A verifier that fetches the LOTL and
  trusts whatever signed it has gained nothing.
- The Hungarian trusted list is operated by NMHH; human-readable version at
  <https://nmhh.hu/tl/pub/HU_TL.pdf>, machine-readable at
  <https://nmhh.hu/tl/pub/HU_TL.xml>. Dashboard view:
  <https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/HU>
- Qualified status is not a property of a certificate alone. It is derived
  from the TL: the service digital identity must match the CA, the
  `ServiceTypeIdentifier` must be a QC service (for example
  `.../Svctype/CA/QC`), the `ServiceStatus` must have been "granted" at the
  relevant time (per `StatusStartingTime` and the service history), and
  `ServiceInformationExtensions` qualifiers (`QCStatement`, `QCForESig`,
  `QCWithSSCD`/`QCWithQSCD`, `NotQualified`) must be applied. Certificate
  QCStatements alone are a claim, not a determination.
- Microsec's own CA hierarchy, CRLs and OCSP responder certificates are
  published at <https://e-szigno.hu/en/pki-services/ca-certificates.html>;
  roots include Microsec e-Szigno Root CA 2009
  (<http://www.e-szigno.hu/rootca2009.crt>, also in Mozilla NSS via
  <https://bugzilla.mozilla.org/show_bug.cgi?id=557904>) and e-Szigno Root
  CA 2017.

**Offline trust store design.** M2 ships no compiled-in trust anchors.
`--trust-store DIR` points at a directory containing:

```text
<dir>/anchors/*.pem        # trust anchors, one or more certs per file
<dir>/intermediates/*.pem  # optional extra CA certs for path building
<dir>/crls/*.crl           # optional DER or PEM CRLs
<dir>/store.toml           # optional metadata: provenance, fetch time
```

Rules: files are read with the same descriptor-relative, no-symlink policy
the extractor already uses; parse failures are reported per file and the
run fails rather than silently trusting a partial store; an empty or
missing store makes every chain check `unknown` and the verdict
`indeterminate`, never `valid`. Phase 3 adds a `openszigno trust update`
style importer that converts a pinned LOTL/HU TL snapshot into this
directory format, recording the TL sequence number and issue date, so the
verification result can cite exactly which trust snapshot was used.

---

## 5. RFC 3161 verification and its XAdES binding

RFC 3161 (<https://www.rfc-editor.org/rfc/rfc3161>) token verification
steps, in order:

1. Parse the token as CMS `ContentInfo` / `SignedData`; require
   `eContentType == id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4).
2. Parse the encapsulated `TSTInfo`: version, policy, `messageImprint`
   (algorithm + hashed message), `serialNumber`, `genTime`, optional
   `accuracy`, `ordering`, `nonce`, `tsa`.
3. Recompute the imprint over the data being timestamped with the
   algorithm named in `messageImprint` and require byte equality. This is
   the binding step and the one most often skipped.
4. Check the imprint hash algorithm against the algorithm allowlist.
5. Locate the TSA certificate: normally in `SignedData.certificates`,
   selected by `SignerInfo.sid`.
6. Require the TSA certificate to carry `extendedKeyUsage` with
   `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) **marked critical**, and
   nothing else in the EKU. RFC 3161 is explicit about this and it is a
   common real-world failure to skip it.
7. Verify `SignerInfo`: the signed attributes must include a
   `messageDigest` equal to the digest of the eContent and a
   `content-type` attribute; verify the signature over the DER encoding of
   the `SignedAttributes` SET.
8. Validate the TSA certificate path to a trust anchor, with the
   validation time set to `genTime` (a timestamp is meant to prove
   existence at `genTime`, so the TSA cert must have been valid then).
9. Only then may `genTime` be used as a validation time for the signature
   the timestamp protects.

**XAdES binding.** A `xades:SignatureTimeStamp` covers the canonicalized
`ds:SignatureValue` **element** (start tag, content, end tag), not the raw
base64 bytes and not the digest. The canonicalization algorithm is taken
from the `ds:CanonicalizationMethod` child of the timestamp element, with
the XAdES default applying when absent. Getting this wrong yields
"timestamp does not match" on every real dossier, so it needs a dedicated
fixture. `xades:SignatureTimeStamp` moves the trusted validation time
from "now" to `genTime`, which is what lets an expired signing certificate
still yield a `valid` verdict. `ArchiveTimeStamp` covers a much larger,
version-dependent set of data and is deliberately out of M2/M3 scope.

---

## 6. Threat model and the policy to adopt

Threats, and the adopted policy for each:

| Threat | Policy |
| --- | --- |
| XML signature wrapping (attacker adds a copy of the signed element elsewhere so validation and consumption see different nodes) | Resolve every reference to a node, and require that the *resolved node identity* is the same node the container semantics expect. Enforce the e-dossier mandated reference set from section 3.2. Report the resolved location of every reference in the JSON so a caller can see what was signed. Refs: <https://arxiv.org/pdf/2106.10460>, <https://pentesterlab.com/glossary/xml-signature-wrapping> |
| Duplicate / ambiguous IDs | Already rejected by the parser (`duplicate_id`, non-empty and unique across the whole document, unprefixed `Id`/`ID`/`id` only). `verify` reuses that ID space and does no independent, laxer lookup. |
| External references (`URI` to http/file/relative paths) | Only same-document references are accepted: `URI=""` (whole document) and `URI="#id"`. Anything else is `reference_external` and fails. No network or filesystem access during reference resolution, ever, in any mode including `--online`. |
| Transform abuse (XSLT, XPath, XPath Filter 2.0) | Allowlist of transforms only: enveloped-signature, C14N 1.0/1.1 (with and without comments), exclusive C14N (with and without comments), and base64. XSLT is refused unconditionally. XPath and XPath Filter 2.0 are refused in M2 (`transform_not_allowed`); if the private corpus shows they are needed, they get a separate, bounded, opt-in implementation later. |
| Algorithm downgrade | Pinned allowlist. Digests: SHA-256, SHA-384, SHA-512. Signatures: RSA PKCS#1 v1.5 and RSA-PSS with those digests and modulus >= 2048 bits, ECDSA P-256/P-384/P-521 with matching digest. Refused by default: MD5, SHA-1, RSA < 2048, DSA, HMAC-based `SignatureMethod` (an HMAC "signature" in a dossier is nonsense and is a known attack shape). `--allow-legacy-algorithms` enables SHA-1 and RSA-1024 for *diagnosis only*, caps the verdict at `indeterminate`, and emits `algorithm_legacy_allowed`. |
| HMAC truncation / `HMACOutputLength` | HMAC signature methods refused outright, which removes the class. |
| Canonicalization edge cases | Restricted C14N allowlist, differential testing against libxml2 in CI, and a hard refusal (`c14n_unsupported`) for anything outside the list. Never "best effort" canonicalize. |
| Key substitution (attacker supplies their own cert in `ds:KeyInfo`) | The signing certificate is determined by the signed XAdES `SigningCertificate`/`SigningCertificateV2` digest where present. `ds:KeyInfo` is only a hint; if it disagrees with the signed digest, that is a failure, not a preference. If neither exists, the chain check is `unknown` and the verdict is `indeterminate`. |
| Certificate chain pitfalls (cross-certs, expired anchors, EKU confusion, name-constraint bypass, path explosion) | Bounded path building (chain length and candidate count), explicit name-constraint processing, explicit keyUsage/basicConstraints checks, unrecognised critical extensions rejected, validation time made explicit and reported. |
| Resource exhaustion via many signatures/references | New limits: `max_signatures` (64), `max_references_per_signature` (32), `max_transforms_per_reference` (8), `max_certificates` (64), `max_crl_bytes` (16 MiB). Reported in `inspect --json` under `data.limits` alongside the existing ones. |
| Information disclosure in output | The existing rule holds: messages never contain input paths, titles, or payload content. Certificate subject/issuer DNs and serials *are* signature metadata a caller needs; expose them in structured fields (`data.signatures[].signing_certificate`), never interpolated into free-text messages, and document that `verify --json` output can contain personal data of signers. |

---

## 7. Proposed crate layout

```text
crates/
  openszigno-core/      # unchanged: XML model, bounded decoding, codes
  openszigno-verify/    # new: crypto, C14N, XAdES, paths, revocation
  openszigno-cli/       # clap, human output, JSON protocol, exit codes
```

A separate crate, not a module, for four reasons: the heavy crypto
dependency tree stays out of anyone who only wants parsing; the
`c14n-libxml2` / `c14n-bergshamra` feature split has a natural home; the
verification code can be fuzzed and audited as a unit; and `openszigno-core`
keeps its current very small dependency surface.

`openszigno-verify` depends on `openszigno-core` (for the parsed tree,
the ID space, limits, and `ErrorCode`) and re-exports nothing that would
let a caller bypass the algorithm policy.

Internal modules:

```text
openszigno-verify/src/
  lib.rs          # VerifyOptions, VerifyReport, entry point
  policy.rs       # algorithm allowlist, transform allowlist, limits
  c14n/           # C14nBackend trait + backends
  dsig/           # SignedInfo, References, transforms, signature value
  xades/          # SignedProperties, SigningCertificate(V2), levels
  certs/          # parsing, path building, name constraints, KU/EKU
  revocation/     # CRL, OCSP, cached/offline sources, policy
  tsa/            # RFC 3161 token parsing and verification
  trust/          # trust store loading, TL snapshot import (phase 3)
  codes.rs        # CheckCode enum, one place, stable strings
  report.rs       # serde types for the JSON shape
```

`openszigno-verify` never does I/O except through injected traits:
`TrustSource`, `RevocationSource`, `Clock`. The CLI supplies filesystem
and (in `--online` mode) network implementations. That keeps the crate
unit-testable and makes "offline by default" structurally true rather
than a runtime flag someone can forget to check.

---

## 8. Verification pipeline and stable codes

Ordered steps. Each step emits one or more checks. A check has
`status` in `passed | failed | skipped | unknown`. Codes are stable
strings, namespaced by area, and never reused with a changed meaning.

Global preconditions (structural, reusing M0/M1 machinery): the file
parses, IDs are unique, `OBJREF`s resolve. A structural failure aborts
before any signature is examined and reports the existing structural error
codes with the existing exit statuses.

Then, per `ds:Signature` in document order:

### Stage A: structure and policy (no crypto)

| # | Check code | Fails when |
| --- | --- | --- |
| A1 | `sig_structure` | `ds:SignedInfo`, `ds:SignatureValue`, or a required child is missing or malformed, appears more than the schema allows, appears out of the schema's order, or is a child the schema does not put there |
| A2 | `sig_placement` | The signature is not at `//es:Document/ds:Signature` or `//es:Dossier/ds:Signature` |
| A3 | `c14n_method_allowed` | `ds:CanonicalizationMethod` is outside the allowlist (`c14n_unsupported` for known-but-unsupported) |
| A4 | `signature_algorithm_allowed` | `ds:SignatureMethod` is outside the allowlist; `algorithm_legacy_allowed` warning when `--allow-legacy-algorithms` admits it |
| A5 | `digest_algorithm_allowed` | Any `ds:DigestMethod` is outside the allowlist |
| A6 | `transforms_allowed` | Any transform is outside the allowlist (`transform_not_allowed`; XSLT always) |
| A7 | `references_same_document` | Any `ds:Reference/@URI` is not `""` or `#id` (`reference_external`) |
| A8 | `references_resolve` | Any `#id` does not resolve to exactly one node in the core ID space |
| A9 | `reference_scope_complete` | The mandated e-dossier reference set for this signature's placement is not fully covered (section 3.2) |
| A10 | `signature_count_within_limits` | `max_signatures` or per-signature limits exceeded |

Any Stage A failure means the signature's verdict is `invalid` and later
stages are `skipped`. There is no point digesting a reference chain the
policy already refused.

### Stage B: XMLDSig cryptographic core

| # | Check code | Meaning |
| --- | --- | --- |
| B1 | `reference_digests` | Every `ds:Reference` digest recomputes correctly after applying its transform chain and canonicalizing. Per-reference detail is reported in `references[]`. |
| B2 | `signedinfo_canonicalization` | `ds:SignedInfo` canonicalized without error |
| B3 | `signature_value` | `ds:SignatureValue` verifies over canonical `ds:SignedInfo` under the signing public key |

### Stage C: XAdES qualifying properties

| # | Check code | Meaning |
| --- | --- | --- |
| C1 | `xades_present` | A `xades:QualifyingProperties` for this signature exists; `skipped` for a bare XMLDSig with an explicit note |
| C2 | `xades_signed_properties_referenced` | `SignedProperties` is covered by a `ds:Reference` with `Type` = `...#SignedProperties` |
| C3 | `xades_signing_certificate` | `SigningCertificate`/`SigningCertificateV2` digest matches the certificate actually used; `unknown` if neither is present |
| C4 | `xades_signing_time` | `SigningTime` parses and is plausible (not after the earliest trusted timestamp, not absurdly out of range); informational, never the sole basis of a `valid` |
| C5 | `xades_signature_policy` | `SignaturePolicyIdentifier` handled: implied policy accepted, explicit policy reported and its digest checked only if the policy document is in the trust store, else `unknown` |
| C6 | `xades_level` | Detected level reported (`B-B`, `B-T`, `B-LT`, `B-LTA`, `unknown`); informational |
| C7 | `xades_unsupported_property` | An unsupported qualifying property marked as required is present (for example `ArchiveTimeStamp` in M2): `skipped` with the property named |

### Stage D: certificate path

| # | Check code | Meaning |
| --- | --- | --- |
| D1 | `signing_certificate_available` | The signing certificate was found (in `ds:KeyInfo`, `CertificateValues`, or the trust store) |
| D2 | `certificate_chain` | A path to a configured trust anchor was built and every link's signature, validity period, basicConstraints, keyUsage and name constraints check out at the validation time |
| D3 | `certificate_validity_at_time` | The leaf was within its validity window at the validation time |
| D4 | `certificate_key_usage` | Leaf keyUsage permits `digitalSignature` or `nonRepudiation` |
| D5 | `certificate_algorithm_strength` | Every certificate in the path uses an allowlisted signature algorithm and key size |
| D6 | `certificate_qualified_status` | Qualified status determined from a TL snapshot; `unknown` without one (phase 3) |

`unknown` (not `failed`) when no trust store is configured: the tool does
not know, and saying "invalid" would be as wrong as saying "valid".

### Stage E: revocation

| # | Check code | Meaning |
| --- | --- | --- |
| E1 | `revocation_policy` | Reports the policy actually applied: `offline`, `online`, or `offline-required`; always `passed`, exists so the policy is visible in the machine output |
| E2 | `revocation_status` | `passed` when every certificate in the path has fresh, verified, non-revoked status; `failed` on any revocation; `unknown` when status could not be obtained under the active policy |
| E3 | `revocation_freshness` | The CRL/OCSP data covers the validation time (`thisUpdate <= t`, `nextUpdate > t`, or OCSP `thisUpdate`/`nextUpdate`) |
| E4 | `revocation_source` | Where the data came from: embedded `RevocationValues`, trust-store CRL, or (only with `--online`) a fetched CRL/OCSP |

Offline-first policy: by default nothing is fetched. Revocation data is
taken from the dossier's own XAdES `RevocationValues` (verified, not
trusted blindly: the CRL or OCSP response must itself be signature-checked
against the path) and from `<trust-store>/crls`. If neither yields a
verdict, `revocation_status` is `unknown` and the overall verdict is
`indeterminate`. `--online` permits AIA/CDP fetching with a fixed timeout,
a size cap, no redirects across schemes, http and https only, and the
fetched URLs recorded in the output. `--require-revocation` promotes an
`unknown` to a `failed`.

### Stage F: timestamps (M2 partial, M3 completes)

| # | Check code | Meaning |
| --- | --- | --- |
| F1 | `timestamp_token_parse` | The RFC 3161 token parses as CMS SignedData with `id-ct-TSTInfo` |
| F2 | `timestamp_imprint` | Recomputed imprint over the canonicalized `ds:SignatureValue` (or, for `es:TimeStamp`, over the referenced elements) matches `messageImprint` |
| F3 | `timestamp_signature` | The TSA `SignerInfo` signature verifies over the signed attributes |
| F4 | `timestamp_tsa_eku` | TSA certificate has critical `id-kp-timeStamping` and nothing else |
| F5 | `timestamp_tsa_chain` | TSA certificate path validates to a trust anchor at `genTime` |
| F6 | `timestamp_time_applied` | The validation time used for the signature was moved to `genTime`; reports the resulting time |

**Verdict rule.** Per signature:

- `valid` requires every emitted check to be `passed`. One `failed`, one
  `unknown`, or one `skipped` that is not explicitly classified as
  non-blocking, and the verdict is not `valid`.
- `invalid` when any check is `failed` (maps to ETSI TOTAL-FAILED).
- `indeterminate` when nothing failed but something is `unknown` or a
  blocking check was `skipped` (maps to ETSI INDETERMINATE).
- `valid` maps to ETSI TOTAL-PASSED.

Dossier-level verdict is the worst of the per-signature verdicts, with
`invalid` worse than `indeterminate` worse than `valid`, and
`indeterminate` when there are no signatures at all (there is nothing to
be valid). Terminology follows ETSI EN 319 102-1.

---

## 9. JSON result shape

`schema_version` stays at 1 if the existing envelope is unchanged and
`verify` only adds a new `command` value plus its own `data`; adding
`signatures_verified: true` as a possible value of an existing field is
a semantic change to that field's contract, so bump to 2 if the reviewers
consider it one. The envelope fields (`schema_version`, `ok`, `command`,
`input`, `data`, `warnings`, `errors`) are unchanged.

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "verify",
  "input": { "format": "microsec-es3", "bytes": 51234 },
  "data": {
    "verdict": "indeterminate",
    "verification_time": {
      "requested": null,
      "effective": "2026-09-07T10:00:00Z",
      "source": "system_clock"
    },
    "policy": {
      "revocation": "offline",
      "trust_store": "configured",
      "trust_snapshot": null,
      "legacy_algorithms_allowed": false,
      "digest_algorithms": ["sha256", "sha384", "sha512"],
      "signature_algorithms": [
        "rsa-pkcs1-sha256", "rsa-pss-sha256", "ecdsa-sha256"
      ],
      "c14n_algorithms": ["c14n11", "exc-c14n"],
      "transforms": ["enveloped-signature", "c14n11", "exc-c14n", "base64"]
    },
    "counts": {
      "signatures": 2,
      "signatures_valid": 1,
      "signatures_invalid": 0,
      "signatures_indeterminate": 1,
      "timestamps": 1
    },
    "signatures": [
      {
        "index": 0,
        "scope": "document",
        "document_index": 0,
        "signature_id": "sig-1",
        "verdict": "valid",
        "xades_level": "B-T",
        "signing_time": "2019-04-02T08:12:03Z",
        "signing_certificate": {
          "subject": "CN=...,O=...,C=HU",
          "issuer": "CN=...,O=Microsec Ltd.,C=HU",
          "serial_hex": "01a2b3",
          "not_before": "2018-01-01T00:00:00Z",
          "not_after": "2021-01-01T00:00:00Z",
          "sha256_fingerprint": "…",
          "key_algorithm": "rsa",
          "key_bits": 2048,
          "qualified": null
        },
        "chain": [
          { "subject": "…", "is_trust_anchor": false },
          { "subject": "…", "is_trust_anchor": true }
        ],
        "references": [
          {
            "index": 0,
            "uri": "#doc-1-object",
            "resolved_to": "es:Document[0]/ds:Object",
            "digest_algorithm": "sha256",
            "transforms": ["exc-c14n"],
            "status": "passed"
          }
        ],
        "timestamps": [
          {
            "kind": "signature-timestamp",
            "gen_time": "2019-04-02T08:12:05Z",
            "tsa_subject": "CN=…",
            "verdict": "valid"
          }
        ],
        "checks": [
          { "code": "sig_structure", "status": "passed",
            "message": "signature structure is well formed" },
          { "code": "reference_scope_complete", "status": "passed",
            "message": "all elements required for a document signature are covered" },
          { "code": "reference_digests", "status": "passed",
            "message": "4 of 4 reference digests matched" },
          { "code": "signature_value", "status": "passed",
            "message": "signature value verified" },
          { "code": "certificate_chain", "status": "passed",
            "message": "path of length 3 built to a configured trust anchor" },
          { "code": "revocation_status", "status": "unknown",
            "message": "no revocation data available in offline mode" }
        ]
      }
    ]
  },
  "warnings": [],
  "errors": []
}
```

Notes on the shape:

- `checks` is ordered by pipeline stage, so a consumer reading top to
  bottom sees the same order the tool evaluated.
- `message` is human text and is not stable; only `code` and `status` are.
- Absent data is `null`, never an optimistic default. `qualified: null`
  means "not determined", which is different from `false`.
- Because a `checks` entry may be added in a later version, consumers must
  treat an unknown `code` as blocking-if-not-passed. Document that.

**Exit statuses.** `0` when the run completed and the verdict is `valid`.
The roadmap asks for a distinct category for cryptographic failure:

| Status | Meaning |
| --- | --- |
| 6 | At least one signature verdict is `invalid` (cryptographic failure) |
| 7 | No signature is `invalid` but the overall verdict is `indeterminate` |

Existing statuses 2 to 5 keep their meanings; a structural failure during
`verify` still exits 4, so callers can distinguish "this file is not a
dossier" from "this dossier's signatures do not verify".

---

## 10. CLI

```text
openszigno verify FILE [--json]
    --trust-store DIR          # anchors, intermediates, CRLs
    --offline                  # default; no network at all
    --online                   # permit AIA/CDP/OCSP fetching
    --require-revocation       # unknown revocation becomes a failure
    --at <RFC3339>             # validation time; default: now
    --allow-legacy-algorithms  # SHA-1/RSA-1024; caps verdict at indeterminate
    --signature <INDEX>        # verify only one signature
    --max-signatures <N>       # override the limit, within a hard ceiling
```

- `--offline` and `--online` are mutually exclusive; offline is the
  default and is the only mode in which the tool makes no outbound
  connections at all.
- `--at` sets the validation time explicitly, which is essential for
  reproducible testing and for asking "was this valid on the day it was
  signed". When a trusted signature timestamp is present, the effective
  time may move to `genTime`; both requested and effective times are
  reported.
- No flag can turn a `failed` check into a `passed` one. The only flags
  that loosen policy (`--allow-legacy-algorithms`) explicitly cap the
  verdict below `valid`.

---

## 11. What can be unit-tested with synthetic material

Everything except real-world interoperability. The private corpus stays
out of the repository; all public fixtures are generated.

Generated with `rcgen` at test time (or once, into
`tests/fixtures/generated/`, with the generator committed):

- a self-signed test root, an intermediate with `basicConstraints`
  cA=true and a `pathLenConstraint`, and leaves with various keyUsage,
  EKU, validity windows, and key sizes;
- negative chains: expired leaf, expired intermediate, wrong keyUsage,
  missing basicConstraints, path length violated, name-constraint
  violation (permitted and excluded subtrees), unknown critical
  extension, RSA-1024 leaf, SHA-1-signed intermediate;
- a TSA leaf with critical `id-kp-timeStamping` and a decoy without it.

Synthetic dossiers built by a small in-repo signing helper (this does not
violate the "never sign" non-goal, which is about the shipped tool, but
the helper must live in `tests/` and not in any shipped crate):

- a correctly signed document-level XAdES-BES dossier;
- the same with a frame signature;
- signature wrapping: a duplicated payload element placed elsewhere with a
  colliding ID (must be caught by `duplicate_id` at parse time) and a
  variant with a distinct ID where the signature still references the
  original (must be caught by `reference_scope_complete` or by the
  consumer-visible `resolved_to`);
- a reference-scope omission: a signature that verifies but does not cover
  `es:DocumentProfile`;
- an external reference (`URI="http://..."`, `URI="file:///..."`);
- an XSLT transform and an XPath transform;
- SHA-1 digest and MD5 digest variants;
- an HMAC `SignatureMethod`;
- a flipped byte in the payload (reference digest fails) and in
  `ds:SignatureValue` (signature value fails);
- a `SigningCertificateV2` digest that does not match the `ds:KeyInfo`
  certificate;
- a signature timestamp over the canonicalized `ds:SignatureValue`,
  correct and imprint-mismatched;
- an embedded CRL in `RevocationValues` marking the leaf revoked, and one
  that is stale relative to `--at`;
- ISO-8859-2-encoded dossier with non-ASCII signer names, to catch
  canonicalization and encoding interactions.

C14N differential tests: a corpus of small XML documents exercising
namespace redeclaration, default namespaces, `xml:lang`/`xml:base`
inheritance (C14N 1.1 differs from 1.0 here), attribute ordering, empty
elements, comments, PIs, and CR/LF normalisation, canonicalized by both
backends and compared byte for byte, plus against the W3C C14N test
vectors.

Property tests: reference resolution never resolves outside the document;
the verdict function is monotone (adding any non-`passed` check can only
lower the verdict); parsing arbitrary bytes as a certificate or CRL never
panics (fuzz targets for `certs`, `tsa`, `revocation`).

What cannot be unit-tested: whether real Microsec dossiers verify. That
needs the private opt-in smoke tests, reporting aggregate counts and
stable check-code buckets only, per the existing corpus policy.

---

## 12. Phased delivery and effort

Estimates are for one experienced Rust developer working with reasonable
focus, and assume the C14N backend decision is made early. They are wide
because path validation and canonicalization both have long tails.

**Phase 1: XMLDSig core plus certificate chain against a user-supplied
trust store.** Roughly 4 to 6 weeks.

- New `openszigno-verify` crate, `C14nBackend` trait plus the pure-Rust
  backend and the libxml2 differential backend behind a feature.
- Stage A (structure and policy), Stage B (reference digests and
  signature value), Stage D (path validation, hand-written on
  `x509-cert`), the trust-store loader, the JSON shape, the CLI, the new
  exit statuses.
- XAdES is only detected, not validated: C1 reports presence and the rest
  of Stage C is `skipped`. Revocation is `unknown`. Verdict therefore
  tops out at `indeterminate` for any real dossier, which is the correct
  and honest outcome for a phase-1 release.
- The path validator is the schedule risk. Budget a full week for name
  constraints and negative tests alone.

**Phase 2: XAdES qualifying properties plus timestamps.** Roughly 3 to 4
weeks.

- Stage C in full, including `SigningCertificate`/`SigningCertificateV2`
  digest checking and level detection.
- Stage F: RFC 3161 token parsing on `cms` + `x509-tsp`, imprint binding
  over the canonicalized `ds:SignatureValue`, TSA EKU and chain checks,
  and moving the effective validation time to `genTime`.
- `es:TimeStamp` elements handled with the same machinery, which is what
  lets M3 be a thin follow-on rather than a separate project.
- `ArchiveTimeStamp` explicitly out of scope, reported as `skipped`.

**Phase 3: EU trusted list integration and revocation.** Roughly 4 to 6
weeks.

- Stage E in full: CRL verification, OCSP request/response with
  `x509-ocsp`, embedded `RevocationValues` consumption, freshness rules,
  `--online` fetching with strict transport policy.
- Trusted-list import: parse LOTL and the Hungarian TL per ETSI TS 119 612
  into a pinned local snapshot, with OJ-published LOTL signer certificates
  as the bootstrap anchor, service-status history handling, and qualified
  determination feeding `certificate_qualified_status`.
- TL parsing is itself XML signature verification over a much larger and
  more variable document than a dossier, so it reuses the phase-1 core,
  but the TL schema variability (TLv5 to TLv6 migration) is real work.

**Cross-cutting, spread across all phases:** roughly 2 to 3 weeks for
fuzz targets, the C14N differential corpus, documentation updates to
`architecture.md` (new codes, limits, exit statuses, and lifting the
verification boundary section by section), and the private-corpus smoke
test harness.

Total: roughly 13 to 19 weeks of focused work for the full M2 plus M3
scope. Phase 1 alone is a shippable, honest increment because it can only
ever report `indeterminate` or `invalid`, never a false `valid`.

---

## 13. Honest summary of ecosystem gaps

1. **No mature pure-Rust XMLDSig stack.** `bergshamra` looks good and is
   seven months old; `xml-sec` says do not use it. Mitigate by owning the
   pipeline, using C14N as a swappable pure function, and differential
   testing against libxml2 in CI.
2. **No general RFC 5280 path validator.** `rustls-webpki` is Web-PKI
   shaped. openSzigno must write its own, which is the largest
   correctness risk in the project after canonicalization.
3. **No XAdES library at all.** All qualifying-property handling is
   bespoke. This is tractable, since XAdES is DOM-shaped work over
   material the tool already parses, but it is not free.
4. **`cms` is at 0.3.0-pre.** Pin the 0.2.x stable line and plan a
   migration.
5. **`x509-ocsp` last released January 2024.** Usable and part of
   RustCrypto, but not actively evolving; budget for reading its source.
6. **The e-dossier spec deliberately does not constrain algorithms or
   canonicalization**, so nothing in the format prevents a weak signature.
   The tool's own pinned policy is the only defence, and it will reject
   some genuine older dossiers. That is the correct trade and must be
   documented so a rejection is not misread as "forged".

---

## Sources

- <https://srv.e-szigno.hu/edossier>
- <https://e-szigno.hu/en/pki-services/ca-certificates.html>
- <https://www.microsec.hu/en/pki-blog/xades-signature-types>
- <https://bugzilla.mozilla.org/show_bug.cgi?id=557904>
- <https://www.w3.org/TR/xml-exc-c14n/>
- <https://www.w3.org/TR/XAdES/>
- <https://di-mgt.com.au/xmldsig-c14n.html>
- <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf>
- <https://www.etsi.org/deliver/etsi_en/319100_319199/31910201/01.04.01_60/en_31910201v010401p.pdf>
- <https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf>
- <https://www.rfc-editor.org/rfc/rfc3161>
- <https://ec.europa.eu/tools/lotl/eu-lotl.xml>
- <https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109149/eSignature+List+of+Trusted+Lists>
- <https://nmhh.hu/tl/pub/HU_TL.pdf>
- <https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/HU>
- <https://github.com/kushaldas/bergshamra> and
  <https://crates.io/crates/bergshamra>
- <https://github.com/structured-world/xml-sec> and
  <https://crates.io/crates/xml-sec>
- <https://crates.io/crates/xml_c14n>
- <https://crates.io/crates/x509-cert>
- <https://github.com/RustCrypto/formats/tree/master/cms>
- <https://crates.io/crates/x509-ocsp>
- <https://crates.io/crates/x509-tsp>
- <https://crates.io/crates/x509-verify>
- <https://crates.io/crates/x509-parser>
- <https://github.com/rustls/webpki> and <https://docs.rs/rustls-webpki>
- <https://github.com/rustls/rcgen>
- <https://arxiv.org/pdf/2106.10460>
- <https://pentesterlab.com/glossary/xml-signature-wrapping>
