# Trust and revocation material

`openszigno verify` fetches nothing by default. Trust anchors, trusted lists,
CRLs and OCSP responses are all files you supply, and this document describes
how to obtain them, how to lay them out, and what each one does to a verdict.

That is a deliberate trade. A verifier that downloads its own trust anchors has
gained nothing: whoever can answer the download decides what is trusted. Pinning
the material yourself is more work and is the only version of the job that means
anything.

The one exception is `--online`, which lets the CLI fetch **revocation data**,
and only revocation data, from the URLs the certificates themselves publish.
Trust anchors and trusted lists are never fetched, in any mode. See
[Online fetching](#online-fetching).

## The short version

```bash
openszigno verify dossier.es3 --json \
  --trust-store   ./trust \
  --lotl          ./trust-lists/eu-lotl.xml \
  --trust-list    ./trust-lists/HU_TL.xml \
  --trust-list-signer ./trust-lists/lotl-signer.pem \
  --revocation-store ./revocation
```

- Without `--trust-store` and `--trust-list`, every chain check is `unknown`
  and the verdict is `indeterminate`.
- Without revocation material, `revocation_status_unknown` keeps the verdict at
  `indeterminate` too.
- `--no-revocation` switches the check off and is documented as producing at
  most `indeterminate`.
- A verdict of `valid` needs all of it: a path to an anchor, fresh revocation
  data for every non-anchor certificate on the signer's chain and on each
  timestamp authority's chain, and a fully verified signature timestamp.

## The trust store

```text
<dir>/anchors/*        trust anchors, PEM or DER, one or more certificates per file
<dir>/intermediates/*  optional extra CA certificates for path building
```

A directory holding certificate files directly, with no `anchors`
subdirectory, is read the same way. The split is a convention, not a grant:
**a certificate in this directory is a trust anchor if and only if it is
self-signed**, so dropping an intermediate into `anchors/` makes it an extra
untrusted path candidate rather than a trusted one. A trusted list is the other
way round: a certificate it names anchors a path whether or not it is
self-signed, because the list says so.

Every file is parsed at load time. One malformed entry fails the whole store
(`trust_store_invalid`, exit 3), because a half-loaded store would silently
change what "trusted" means.

The store is bounded twice: 4 MiB per file, 1024 files per directory, and
**64 MiB across the whole store**, counting `anchors/` and `intermediates/`
together so a store cannot be padded out by splitting it. Every file is read
before any of it is parsed, so a store over the total is refused for its size,
not for whatever the file that crossed the line held. Exceeding it is the same
`trust_store_invalid` refusal, and a refusal it stays: nothing is truncated.

### Where the Hungarian roots come from

Microsec publishes its CA certificates at
<https://e-szigno.hu/en/pki-services/ca-certificates.html>. The two roots most
Hungarian e-dossiers chain to are:

| Certificate | URL |
| --- | --- |
| Microsec e-Szigno Root CA 2009 | <http://www.e-szigno.hu/rootca2009.crt> |
| Microsec e-Szigno Root CA 2017 | <http://www.e-szigno.hu/rootca2017.crt> |

Download them over HTTPS from the CA-certificates page rather than over the
plain-HTTP direct links, verify the fingerprints against the ones the page
publishes, and record where and when you fetched them. `docs/references.md`
lists the URLs and the checksums of the copies in the gitignored `refs/` cache.

Documents authenticated with AVDH, the Hungarian state's identification-based
document authentication service, are signed by a state seal rather than by the
citizen, and section 634(15) of the Code of Civil Procedure keeps the ones
issued up to 31 December 2024 in circulation indefinitely. The published
service description says the seal is an advanced electronic seal on a
**qualified certificate**, accompanied by a qualified timestamp
([SZEUSZ](https://szeusz.gov.hu/szeusz/avdh-dhsz)), which means its chain ends
at a Hungarian qualified trust service provider on the national trusted list,
and loading the Hungarian trusted list is therefore the way to validate one.
**Which** provider issued the seal certificate could not be established from a
public source: the service's own terms of service were not reachable from this
environment, and no published certificate profile was found. Read the issuer
off a document you actually hold rather than assuming a root here. Nothing in
openSzigno special-cases such a certificate; it is path-validated like any
other, and what the read path does with the rest of the structure is described
in [architecture.md](architecture.md#avdh-authenticated-documents).

## Trusted lists

An ETSI TS 119 612 trusted list is how an EU member state says which CAs are
entitled to issue qualified certificates, and *when* each of them was. Loading
one gives two things a directory of certificates cannot:

- anchors whose provenance is a published national list rather than somebody's
  copy-and-paste, reported as `trust_anchor_origin: "trust_list"`;
- the qualified determination itself, reported per signature as
  `qualified: true | false | null`.

### Getting the files

| List | Machine-readable | Human-readable |
| --- | --- | --- |
| EU list of trusted lists (LOTL) | <https://ec.europa.eu/tools/lotl/eu-lotl.xml> | <https://ec.europa.eu/digital-building-blocks/sites/spaces/DIGITAL/pages/467109149/eSignature+List+of+Trusted+Lists> |
| Hungarian trusted list | <https://nmhh.hu/tl/pub/HU_TL.xml> | <https://nmhh.hu/tl/pub/HU_TL.pdf> |

Both are served over HTTPS, and both should be fetched that way: the Hungarian
list moved off plain HTTP at the TLv6 cut-over (see below), and a trusted list
fetched over HTTP is a trusted list whoever answers the request chose for you.
The signature check is what actually decides, that is the whole point of
`--trust-list-signer`, but there is no reason to hand an attacker the first
move.

The lists are refreshed daily. Fetch a snapshot, record its
`TSLSequenceNumber` and `ListIssueDateTime`, and keep it under version control
or in an archive alongside whatever you verified with it; the report's
`policy.trust_lists` block cites exactly those fields, plus the `version` the
list stated, so a result can be reproduced later.

```bash
mkdir -p trust-lists
curl --proto '=https' --tlsv1.2 -sSf \
  https://nmhh.hu/tl/pub/HU_TL.xml -o trust-lists/HU_TL.xml
```

### TLv5 and TLv6

On **2026-04-29** every EU trusted list moved from TLv5 to TLv6, with **no
transition period**: until 2026-04-28 all member-state lists were version 5,
and from that date only version 6 is published or accepted. openSzigno reads
both, because an archived snapshot taken before the cut-over is still a TLv5
file and still the right list to verify a signature made back then against.

`SchemeInformation/TSLVersionIdentifier` says which version a file is ,
ETSI TS 119 612 clause 5.3.1 requires the field and says it is incremented
exactly when the rules for parsing the list change. A list stating `5` or `6`
loads; anything else, and a list stating nothing, is refused as
`trust_list_invalid` (exit 3) with a message naming what it stated. That is
deliberate: a parser that guessed at an unknown version would be guessing about
trust anchors. The version read is reported twice, as
`policy.trust_lists[].version` in the machine-readable report and in the
`trust_list_loaded` check message, so a run always says which format it read.

What TLv6 actually changed, and what it did not:

| Aspect | TLv5 | TLv6 | Effect here |
| --- | --- | --- | --- |
| Specification | ETSI TS 119 612 V2.1.1 | V2.3.1 (2024-11), now V2.4.1 (2025-08) | n/a |
| `TSLVersionIdentifier` | `5` | `6` | The one thing branched on. |
| Schema namespace | `http://uri.etsi.org/02231/v2#` | unchanged | Nothing to branch on. Annex B.0 of both issues names the same three namespaces and notes the `02231` is kept from ETSI TS 102 231 "for compatibility reasons". |
| Service status URIs | the `.../Svcstatus/...` set | unchanged | The granted/pre-eIDAS/terminal rules below are untouched. |
| Service type URIs | the `.../Svctype/...` set | extended (wallet-era types such as `.../Svctype/EAA/Q`, `.../Svctype/Ledgers/Q`) | Additive. This build reads `CA/QC` and `TSA/QTST` and ignores the rest, exactly as before. |
| `ServiceDigitalIdentity` | `X509Certificate`, `X509SubjectName`, `X509SKI`, `ds:KeyValue` | unchanged | All three forms are read as before. |
| `PointersToOtherTSL` | names the national lists' signers | unchanged | The LOTL bootstrap is unaffected. |
| Signature format | XAdES-BES (TS 101 903) | XAdES-B-B (EN 319 132-1) | Both are an enveloped `ds:Signature` over the whole list; the difference is in the signed properties, which this build does not require. `xades:SigningCertificateV2` is now the mandated signed property. |
| Signature reference | `URI=""` in practice | unchanged in practice | Annex B.1.0 rule 2 permits a same-document `#Id` naming `TrustServiceStatusList` instead, and this build now accepts both. |
| Canonicalization | exclusive c14n | unchanged | Already the only algorithm real lists use, and inside the allowlist. |
| Signature algorithms | XML-Signature's set, plus ECDSA and SHA-2 | unchanged wording (annex B.1.2), constrained by ETSI TS 119 312 tables 4, 6 and 7 to a key usable for at least three years | Covered: see below. |
| `ServiceSupplyPoint` | URIs | each URI may now carry a type attribute | Not read here; supply points contribute no trust. |
| `ElectronicAddress` | e-mail or web address | may also carry a telephone number | Not read here. |

The signature algorithms the live lists actually use are inside the pinned
allowlist: the EU LOTL signs with `rsa-sha512` (RSA PKCS#1 v1.5) and the
Hungarian list with `ecdsa-sha256` over a P-256 key. The allowlist is RSA
PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512, and ECDSA with SHA-256 and
SHA-384 (P-256 and P-384). SHA-1 is refused in a trusted list's own signature
whatever `--allow-legacy-algorithms` says.

#### TLv6 caveats

Points established from the specification text and from the live lists, but
worth knowing they were not proven against every member state's file:

- **Only the EU LOTL and the Hungarian list were exercised end to end.** Both
  are TLv6 today and both parse, and the Hungarian list's signature verifies
  through the LOTL's pointer certificates. The other 26 member-state lists were
  not fetched.
- **Whether every TLv6 list is version-tagged the way the two checked ones
  are.** The specification requires the field; a list that omits it is refused
  here rather than assumed to be TLv6.
- **ECDSA with SHA-512 (typically P-521) is not in the allowlist.**
  TS 119 312 permits it and TS 119 612 annex B.1.2 does not exclude it, so a
  member state could in principle sign with it; such a list would be reported
  `trust_list_signature_invalid` for naming "a signature method outside the
  allowlist". Neither list checked uses it.
- **XAdES-B-B's signed properties are not required, only tolerated.** The
  extra `ds:Reference` over `xades:SignedProperties` must still verify, and
  does, but this build does not check `xades:SigningCertificateV2` against the
  signer, nor the TLSO certificate restrictions of clause 5.7.1 (self-signed
  or listed issuer, `id-tsl-kp-tslSigning`, `BasicConstraints` CA=false). The
  caller supplies the signer certificate out of band and that is what is
  believed.
- **`Qualifications` and other scheme extensions are still not processed**, in
  either version, and are reported as unprocessed rather than used to widen a
  determination.

### Bootstrapping national lists from the LOTL

The LOTL's `PointersToOtherTSL` entries name the signing certificates of the
national lists. `--lotl FILE` reads them, so **one** out-of-band certificate
(the LOTL's, from the Official Journal) verifies the LOTL, and the LOTL's
pointers then verify each `--trust-list`:

```bash
curl --proto '=https' --tlsv1.2 -sSf \
  https://ec.europa.eu/tools/lotl/eu-lotl.xml -o trust-lists/eu-lotl.xml
```

The order is what makes it sound: the LOTL is verified against
`--trust-list-signer` *first*, and only then are its pointer certificates
trusted to verify anything. If the LOTL could not be verified its own
`trust_list_unverified` check still blocks, so pointers taken from an
unverified list cannot quietly support a `valid` verdict. The LOTL itself
contributes no trust anchors: it names no CA/QC services, only pointers.

### Verifying the list's own signature

A trusted list is itself XMLDSig-signed, and the whole point of a trusted list
evaporates if you believe whatever signed the copy you downloaded. The
legitimate LOTL signing certificates are published **out of band in the
Official Journal of the European Union**, which is the only trustworthy way to
bootstrap; a national list's signer is named by the LOTL entry that points at
it.

Pass that certificate as `--trust-list-signer CERT` (PEM or DER, exactly one
certificate). openSzigno then verifies the list's enveloped signature with the
same XMLDSig core it uses on a dossier (the same canonicalization backend, the
same pinned algorithm and transform allowlists) and requires the signature to
cover the whole document.

Any one of the supplied certificates verifying is enough: the one from
`--trust-list-signer` plus, when `--lotl` was given, every pointer certificate
it named, because a scheme operator may publish several and a verifier cannot
know which of them signed the copy in hand.

- Signature verifies: `trust_list_signature_ok` (`passed`).
- Signature does not verify against any supplied certificate, or the list
  carries none while one was demanded: `trust_list_signature_invalid`
  (`failed`); the run is `invalid`.
- No signer certificate at all: `trust_list_unverified` (`unknown`). The list's
  anchors are still used, but the run can never reach `valid`.

### What is read, and what is not

For every `TSPService` whose `ServiceTypeIdentifier` is:

- `http://uri.etsi.org/TrstSvc/Svctype/CA/QC`: a CA issuing qualified
  certificates, or
- `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST`: a qualified timestamping
  authority,

every `X509Certificate` in the service digital identity becomes a trust anchor,
carrying the service's status timeline: the current `ServiceStatus` with its
`StatusStartingTime`, plus every `ServiceHistoryInstance`.

**A listed certificate anchors a path whether or not it is self-signed.** In a
real national list the CA/QC identities are the *issuing* CAs, which are
intermediates: the Hungarian list records NetLock's qualified issuing CAs as
CA/QC services with pre-eIDAS history, and the root that signed them only as a
qualified timestamping service granted from 2018. Following ETSI TS 119 615,
the path ends where the list speaks (at the issuing CA) rather than climbing
to the root and being judged by an entry that was never about issuing
certificates. The nearest listed certificate along a chain wins, so a root's
entry cannot override the issuing CA's below it; when the nearest one's service
was not granted at the validation time, the search carries on upward, and only
refuses if no listed certificate and no `--trust-store` anchor above it will
end the path either. The terminating certificate is the trust anchor: nothing
above it is validated, it is the last entry of the reported `chain` with
`trust_anchor_origin: "trust_list"`, its revocation is not checked (an anchor's
never is), and `qualified` follows from its service exactly as for a listed
root.

A path that ends at such an anchor is trusted only if the service was granted
**at the validation time**. That is what lets a signature made while a CA was
supervised still verify after that CA was withdrawn, and stops a signature made
after the withdrawal from doing so: the path then reports
`trust_list_service_not_granted` instead of `cert_path_ok`, and every other
candidate path is tried before that is concluded. The check is `unknown`, not
`failed`: trust you no longer have is not evidence against a signature, so
the run is capped at `indeterminate` and is never `invalid` for this reason
alone. A `--trust-store` anchor is unaffected.

The kind of service has to match the use: a CA/QC service for a signing path
(and for an OCSP responder's own path), a TSA/QTST service for a timestamping
one. Where a list records a certificate only under some *other* kind of
service, it has said nothing about that use, and the anchor is treated as a
trust-store one would be, provided some service it does record was granted
then. A certificate every one of whose listed services has been withdrawn
anchors nothing.

The statuses treated as granted are:

- `.../Svcstatus/granted`
- `.../Svcstatus/recognisedatnationallevel`

Two further statuses are honoured for a bounded window:

- `.../Svcstatus/undersupervision`
- `.../Svcstatus/accredited`

These are the pre-eIDAS vocabulary, and they count as granted **only at a
validation time before 2016-07-01**, when eIDAS began to apply. Before that
line they were exactly what a member state published for a CA entitled to issue
qualified certificates. After it, a service left at a pre-eIDAS status has not
been granted under the new vocabulary, so the window closes. Whichever status
was honoured is named in the `certificate_qualified` message, so you can always
tell an eIDAS `granted` from a historical `accredited`.

Every terminal status (`withdrawn`, `supervisionceased`, the `deprecated*`
family) is never treated as granted.

Service digital identities are read in all three forms a real list uses, but
they are not equally strong:

| Form | What it can do |
| --- | --- |
| `X509Certificate` | Becomes a **trust anchor** (self-signed or not, so a listed issuing CA ends a path) and can establish that a chain certificate *was issued by* the listed service: a verified signature, not a name match. |
| `X509SKI` | Recognises a certificate already in the validated chain by its `subjectKeyIdentifier`. Contributes **no anchor** and grants no trust; it can only decide `qualified`. |
| `X509SubjectName` | The same, matched attribute by attribute against the certificate's subject, exactly as written, no case folding, no normalisation. The weakest form. |

If a national list names its CAs only by SKI or subject name, you still need
the certificates themselves in `--trust-store` for a path to be built; the list
then supplies the qualified determination on top.

Deliberately not read:

- Scheme-level `Qualifications` extensions, which refine qualified status per
  certificate subset. They are never used to *widen* a determination.
- Trusted lists themselves, over the network. There is no
  `openszigno trust update`, and `--online` does not fetch lists, only
  revocation data.

### How `qualified` is decided

**Over the whole chain, not over its anchor.** This matters in practice: the
Hungarian list names the *issuing* CAs (the "Qualified e-Szigno CA" style
services) as its CA/QC service identities, while the Microsec roots that end
the chain are certificates you pinned into `--trust-store` yourself. A rule that
looked only at the anchor would answer "not determined" for every real dossier.

Two things must both hold:

1. some certificate in the validated chain **is**, or was **issued by**, the
   service digital identity of a CA/QC service the list records as granted at
   the validation time. "Issued by" is a verified signature, not a name match;
   and
2. the signing certificate's own `QCStatements` do not contradict it. A
   certificate issued on or after 2016-07-01, when eIDAS began to apply, whose
   `qcStatements` extension is present but omits `QcCompliance`
   (`0.4.0.1862.1.1`), or will not parse, contradicts the list and yields
   `false`.

A post-eIDAS certificate carrying no `qcStatements` extension at all denies
nothing, and the determination rests on the trusted list alone. That is the
looser reading, taken deliberately: the list is the authority on which CA may
issue qualified certificates, and an issuer that omitted an assertion has not
denied it.

`qualified_service` names the service that matched, so you can look the
determination up in the list yourself. `qualified_signature_device` reports the
`QcSSCD`/QSCD statement (`0.4.0.1862.1.4`) separately. Both are claims by the
issuer that the trusted list makes meaningful; neither is read as a
determination on its own.

The answer is `null`, never `false`, when no trusted list was consulted;
`false` when one was and nothing in the chain is covered. "Not determined" and
"determined not to be qualified" are different statements and the report keeps
them apart.

When the same certificate is both a `--trust-store` anchor and a trusted-list
service identity, the chain entry reports `trust_anchor_origin: "trust_list"`:
the list is the stronger provenance.

## The revocation store

```text
<dir>/crls/*   DER or PEM CRLs
<dir>/ocsp/*   DER OCSP responses
```

A directory holding files directly, with no `crls` or `ocsp` subdirectory, is
read as a bag of both: each file is classified by what it actually contains,
not by where it sits or what it is called. A file that is neither a CRL nor an
OCSP response fails the run (`revocation_store_invalid`, exit 3): "no
revocation data" is itself an answer that changes a verdict, so a store that
quietly dropped half its contents would be worse than no store at all.

The store is bounded twice: `MAX_REVOCATION_ITEM_BYTES` (16 MiB) per file,
4096 files per directory, and **256 MiB across the whole store**, counting
`crls/` and `ocsp/` together. Every file is read before any of it is
classified, so a store over the total is refused for its size rather than for
the contents of whichever file crossed the line, with the same
`revocation_store_invalid` code.

### Where the data comes from, and which answer wins

1. The signature's own validation data (`CRLValues` and `OCSPValues`) from
   **either** placement: directly under
   `xades:UnsignedSignatureProperties/xades:RevocationValues`, or nested inside
   an `xades141:TimeStampValidationData`. Real long-term Microsec dossiers put
   almost all of their embedded OCSP responses in the second one, so both are
   harvested; the container is matched in any recognised XAdES namespace and the
   encapsulating elements inside it by name alone, because real dossiers nest
   1.3.2-namespaced values under a 1.4.1-namespaced container.
2. `--revocation-store DIR`.

Within each tier OCSP is read first, because it answers about *this*
certificate rather than about a list.

That order is about where the tool looks first, **not** about what it
believes. Every source is asked about every certificate, and the answers are
then weighed:

- A revocation from any source beats `good` from any other. The signature's own
  `RevocationValues` are supplied by the signer, so an older embedded OCSP
  `good` that is still inside its own `nextUpdate` cannot hide the newer CRL in
  your store that revokes the same certificate.
- Among answers that say the same thing, the one speaking for the later instant
  is reported: the later `producedAt` where the source stated one, otherwise the
  later `thisUpdate`. `chain[].revocation.source` says which source that was.
- Freshness is unchanged: a stale source answers nothing at all, whatever it
  says.

When the usable sources did not agree, `revocation_sources_disagree` (`info`)
says so and names both sides, and the same sentence appears in that
certificate's `chain[].revocation.detail`. It never blocks: the disagreement is
already settled by the rules above.

### What real dossiers actually embed, and what you still have to fetch

**A real Microsec dossier embeds an OCSP response for the end-entity
certificate only.** Its issuing CA and the root above that carry no embedded
status at all. Since every non-anchor certificate in the chain needs a status
(a revoked intermediate condemns everything under it, so exempting CAs would
make the check worth much less than it looks), a `valid` verdict on real
material needs the **CA CRLs** in `--revocation-store`, or online fetching once
M3 ships.

The tool tells you exactly which certificate is missing data. The message names
it by role and by the public CA names around it, and repeats the CRL
distribution point that certificate publishes, for example:

```text
revocation_status_unknown: no usable revocation data covers the intermediate CA
Qualified e-Szigno CA 2009 issued by Microsec e-Szigno Root CA 2009: neither the
signature's own RevocationValues nor the revocation store covers it; it
publishes its CRL at http://...
```

Fetch that URL into `<store>/crls/` and re-run. The end-entity certificate's own
subject is never repeated in a message, because that is the signer.

Embedded data is **untrusted input**, exactly like the certificates in
`CertificateValues`: the signer supplied it. Every CRL is signature-checked
against the issuing CA (or an authorised delegate) and every OCSP response
against an authorised responder before anything in it is believed. Taking them
at face value would let a signer prove its own certificate was never revoked.

### Fetching CRLs by hand

Read the distribution point out of the certificate and fetch it yourself:

```bash
openssl x509 -in signer.pem -noout -text | grep -A2 'CRL Distribution'
curl -sSf http://crl.e-szigno.hu/some-ca.crl -o revocation/crls/some-ca.crl
```

Fetch a CRL that was current **at the validation time you intend to use**, not
merely the newest one. A CRL whose `nextUpdate` has already passed at that
instant is stale and yields `revocation_data_stale`, because a newer CRL may
carry a revocation this one predates.

There is no grace period, on purpose. A grace period is a decision to accept
data that has expired, which is exactly the decision a verifier must not make
silently.

### Which OCSP responders are believed

RFC 6960 gives three ways for a responder to be authorised, and openSzigno
accepts all three, in this order:

1. **The issuing CA answered for itself.** Nothing else is needed.
2. **A responder that CA delegated to**: a certificate the CA issued, carrying
   `id-kp-OCSPSigning`. The CA's signature over that certificate is the
   delegation.
3. **A responder you trust directly.** Its certificate carries
   `id-kp-OCSPSigning` and its own path validates to an anchor in your
   `--trust-store` or `--trust-list`, at the response's `producedAt`.

The third one is what makes a real Hungarian dossier verify. Microsec, like
most national CA operators, runs **one** OCSP responder for every CA it
operates, and that responder's certificate is issued by a sibling CA rather
than by whichever CA issued the certificate being asked about. Until M3 this
tool implemented only the first two models and refused every one of those
responses as unauthorised; supplying the operator's root as an anchor now
covers the responder as well as the CAs.

A `--trust-list` on its own is enough. A list ends a path wherever it speaks,
at a listed issuing CA as readily as at a self-signed root, so a run with a
list and no `--trust-store` still has trust material for the responder's path
to reach. The third model is skipped only when nothing at all was configured:
no store anchor, and no listed service that supplies a certificate.

The report says which model applied, in
`chain[].revocation.responder_model` (`issuer`, `delegated`, `trusted`), and
emits `ocsp_responder_trusted` (`info`) when the third one was used. Nothing
about the third model is looser than the other two: a responder that reaches no
anchor **you** configured authorises nothing, so it can only accept a signer you
had already chosen to trust.

### One unusable answer is not the end

A source that is found but refused does not stop the search: every other source
is still read, and only when they are all exhausted is the certificate reported
as uncovered. An OCSP
response this build cannot authorise, followed by the CA's own CRL, ends as
`good` from the CRL.

The refusal stays in the report either way. `chain[].revocation.detail` says
what was refused and why, and which source answered instead, and the path
summary repeats it, so a `revocation_ok` that was rescued by a CRL still tells
you your responder was not usable, which is the thing worth fixing.

### What makes data unusable

| Situation | Code | Status |
| --- | --- | --- |
| A CRL signed by someone the CA did not authorise, or an OCSP response no responder model above accepts | `revocation_data_invalid` | `unknown` |
| A delta CRL, an indirect CRL, a scope restricted to reasons or attribute certificates | `revocation_data_invalid` | `unknown` |
| A partitioned CRL naming a distribution point the certificate does not | `revocation_data_invalid` | `unknown` |
| A critical CRL extension this build does not implement | `revocation_data_invalid` | `unknown` |
| An OCSP response whose `OCSPResponseStatus` is not `successful` | `revocation_data_invalid` | `unknown` |
| Data whose `nextUpdate` has passed at the validation time | `revocation_data_stale` | `unknown` |
| No data at all covers a certificate | `revocation_status_unknown` | `unknown` |

All of them are `unknown`, never `failed`: unusable data means the tool could
not answer, which is a different statement from "this certificate was revoked".
Each is reported only after every source has been tried, and the message names
the cause rather than saying only that something was wrong.

### A revocation dated after the signature

Certificates are routinely superseded or withdrawn *after* a signature was
made, and a CRL you fetch today records that. Whether it counts depends on
whether the validation time is proven:

- If the signature carries a **fully verified** `xades:SignatureTimeStamp`, the
  validation time is that token's `genTime` and the signature demonstrably
  existed then. A revocation dated afterwards is reported as
  `cert_revoked_after_validation_time` with status `info`, and the signature can
  still be `valid`. This is the ETSI EN 319 102-1 best-signature-time rule and
  it is why long-term signatures carry timestamps.
- If you pass `--at`, or let the clock decide, the time is *asserted* rather
  than proven (a caller can pass any `--at`), so the same finding stays
  `unknown` and blocks.

Either way the revocation is reported in full, with its time and reason, and
the certificate's own `status` in the chain entry reads
`revoked_after_validation_time`. Nothing is hidden.

## Online fetching

`--online` lets the CLI fetch revocation data the material you supplied does
not cover. It is the only thing that makes openszigno touch the network, and
`openszigno-verify` still cannot: the crate opens no socket in any mode, and
everything fetched reaches it through the same `RevocationSource` a
`--revocation-store` file arrives through.

```bash
openszigno verify dossier.es3 --json \
  --trust-store ./trust \
  --revocation-store ./revocation \
  --online \
  --online-cache ./revocation-cache
```

### What it will and will not do

- **Only for certificates your trust material vouches for.** A URL is
  contacted only for a certificate on a path openszigno *validated* to a trust
  anchor you configured (with `--trust-store` or through a trusted list) for
  a signature or a timestamp it was checking. A certificate sitting elsewhere
  in the XML generates no traffic even if it chains to your anchor, because
  nothing was validating it. **Without an anchor nothing is fetched at all**: a
  dossier carries its own certificates, including the "issuer" that signed the
  signer, so acting on a URL out of one would let any file you were handed
  choose what your machine connects to. When that happens `policy.revocation`
  reads `online_no_anchors` and both the `revocation_policy` check and every
  `revocation_status_unknown` message say so: configure trust material and the
  same run fetches.
- **Only URLs the certificates publish.** The `cRLDistributionPoints` URIs and
  the `authorityInfoAccess` OCSP responders, read out of the certificates
  themselves. Nothing is taken from the dossier's XML, and no reference in the
  dossier is ever dereferenced.
- **Only gaps, judged at the time that matters.** A certificate your own
  material already answers for is never fetched for, and the question is put
  to the verifier's own offline code, not to an approximation of it. Opening a
  dossier you already have data for generates no traffic at all. The question
  is asked at the validation time each path was evaluated at: the `genTime` a
  verified timestamp proves, for a historical signer path; the `genTime` a
  token asserts, for the timestamp authority's own path; `--at` or the clock
  otherwise. A CRL that expired in 2021 still covers a signature a verified
  timestamp pins to 2020, so nothing is fetched for it, and the same CRL says
  nothing about a path validated today, so that gap is fetched.
- **In bounded rounds.** Evidence fetched for one path can create another. A
  signer whose certificate has expired has no validated path at all until its
  signature timestamp is verified, and verifying that timestamp can itself
  need the timestamp authority's revocation data. So one `--online` run
  alternates verification and fetching for at most three rounds: each round
  verifies with everything fetched so far, fetches only for the certificates
  that round made eligible, and the run stops as soon as a round turns up
  nothing new. Every limit below is a limit on the run, not on a round.
- **Only revocation data.** Never trust anchors, never trusted lists.
- **The scheme the CA published.** `http` and `https` are the only two schemes
  fetched, and neither is rewritten. TLS is not what makes the answer
  trustworthy; the artefact's own signature is, and it is checked either way.
- **No downgrade on a redirect.** A redirect that leaves `https` for `http` is
  refused, for every request kind, as `destination_refused` with the rule
  `redirect_downgrade`. Not rewriting a published `http` URL is one thing; a
  peer moving an exchange that had already started under TLS into the clear is
  another, and it is the peer's choice rather than the CA's. The refusal is
  decided before the next hop is opened, so nothing is contacted at the
  downgraded target.
- **Credentials need TLS on every hop.** A request that carries a bearer token
  in the `Authorization` header, or a body the caller marked sensitive, is
  refused unless the URL is `https` (on the first hop as well as on every
  later one) with the rule `credentials_require_https`. A revocation fetch
  carries no credentials and is unaffected; `sign --csc` carries both, and
  this is the transport half of the rule its configuration already states.
  The one exemption is a loopback service under `--online-allow-private`, and
  it is granted on the addresses the policy approved rather than on the host
  text. Without the flag the refusal comes before the host is even resolved.
- **The `Authorization` header goes on last.** It is attached only after the
  target has passed the destination policy, the credential rule and the
  address pin, so a target that failed any check is never sent one.
- **Only public destinations, by default.** A URL carrying userinfo
  (`http://user:secret@host/…`) is always refused. So is one naming any of
  these, whether it names them directly or *resolves* to them: the resolved
  addresses are checked before connecting, and **the socket is then opened to
  exactly those addresses**, so DNS rebinding does not walk past the rule, and
  every redirect target is checked and pinned again:

  | Refused | Range |
  | --- | --- |
  | loopback | `127.0.0.0/8`, `::1` |
  | private (RFC 1918) | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
  | link-local | `169.254.0.0/16`, `fe80::/10` |
  | unique-local | `fc00::/7` |
  | unspecified | `0.0.0.0/8`, `::` |
  | broadcast | `255.255.255.255` |
  | multicast | `224.0.0.0/4`, `ff00::/8` |
  | carrier-grade NAT | `100.64.0.0/10` |
  | IETF protocol assignments | `192.0.0.0/24` |
  | benchmarking | `198.18.0.0/15` |
  | site-local (deprecated) | `fec0::/10` |
  | 6to4 | `2002::/16` |
  | Teredo | `2001::/32` |
  | NAT64 (well-known prefix) | `64:ff9b::/96` |
  | cloud instance metadata | `169.254.169.254`, `fd00:ec2::254` |
  | by name | `localhost`, `*.localhost` |

  The last four IPv6 rows are there because each carries an IPv4 destination
  inside the address, which the IPv4 rules above would otherwise never see.

  An IPv4-mapped IPv6 address (`::ffff:127.0.0.1`) and the IPv4-compatible
  form (`::127.0.0.1`) are both judged as the IPv4 address they carry.
  `--online-allow-private` waives these address rules, and only these, for an
  internal CA that really does publish on your own network.
- **The check is bound to the connection.** The addresses the policy approved
  are the only ones the request may be sent to: they are handed to the HTTP
  client as the resolution for that host and port, and a name that was not
  vetted for the fetch in hand does not resolve at all. There is no second
  lookup that could return something else. Only the address is pinned: the URL
  is sent as published, so the `Host` header, the TLS SNI value and the
  certificate host-name verification all still use the name the CA wrote into
  the certificate. A host the policy cannot turn into an address is a
  `transport` failure and nothing is contacted.
- **With `--online-proxy`, the proxy connects.** The destination policy still
  runs on the URL (scheme, userinfo, the name, and the addresses it resolves
  to), but the request is sent to the proxy and the proxy resolves the
  destination for itself, so what the policy vetted is not what opens the
  socket. That is inherent in delegating the connection, and it is one reason
  the flag is opt-in and no proxy is ever taken from the environment.
- **One request per question.** CRLs are deduplicated by URL; OCSP by responder
  URL *and* `certID`, because a response answers about one certificate and two
  certificates behind one responder are two questions.
- **Bounded.** 5 s to connect, 20 s per fetch, 16 MiB for a CRL (the same
  limit the verifier itself will parse), 64 KiB for an OCSP response, at most 3
  redirects, **never to another host** and **never from `https` to `http`**,
  at most 32 certificates per run, rounds included.
- **Judged offline.** Every fetched artefact goes through exactly the rules in
  [What makes data unusable](#what-makes-data-unusable). A CRL from the wrong
  CA, a stale one, or an HTML error page changes nothing.

Online material is consulted **last**, after the signature's own
`RevocationValues` and the revocation store, so it can only fill a gap and can
never displace an answer you already had. `chain[].revocation.source` reads
`online_crl` or `online_ocsp` when an answer came from the network, and
`policy.revocation` reads `online` for the whole run, or `online_no_anchors`
when the flag was given with no anchor to gate fetching on.

### When a fetch fails

Each failure adds one `online_fetch_failed` naming the URL and the failure
class: `timeout`, `http status <code>`, `too large` (with the limit it went
over), `redirect`, `invalid`, `transport`, `destination_refused` (with the rule
that refused it, in which case nothing was contacted at all), or
`cache_collision` (the artefact was fetched and used, but `--online-cache`
already held a different file under its name). Nothing hangs and nothing
panics.

That check is `info`, and it is not the thing that decides anything. A fetch
that did not happen leaves the certificate exactly as uncovered as it was, and
*that* is reported on the chain which needed the data, as
`revocation_status_unknown`, which blocks. So `--online` still cannot turn an
unanswered question into a passed one; the answer is the verifier's to give,
not the fetcher's. The split matters in practice: a fetch attempted for a
certificate no verdict depended on, such as the timestamp authority of a
container `es:TimeStamp`, no longer drags a dossier whose every signature is
`valid` down to `indeterminate`.

The class tells you what to do next. A `timeout` or a `5xx` is the CA's outage;
retry later. A `404` is a stale URL in an old certificate: fetch the CRL from
the CA's current publication point and drop it into `--revocation-store` by
hand. `invalid` means the server answered with something that is not a CRL or
an OCSP response, which is what a captive portal or an intercepting proxy looks
like from here. `destination_refused` means the URL named a destination the
policy does not permit, and the rule after it says which: fix the
certificate's publication point, or, if it is an internal CA on your own
network and you meant it, pass `--online-allow-private`.
`redirect_downgrade` is the server answering with a redirect from `https` to
`http`, which is a misconfigured publication point at best, and
`credentials_require_https` is a request that would have carried credentials
over something other than `https`; neither is waived by
`--online-allow-private` except for a loopback service, and neither contacts
the refused target.

### The cache workflow

`--online-cache DIR` writes everything fetched into `DIR/crls/` and
`DIR/ocsp/`. A CRL is named by the SHA-256 of its own bytes; an OCSP response
is named by the `certID` it answers about and then by its own bytes, so two
answers from one responder stay distinguishable. That is the
`--revocation-store` layout, so:

```bash
# Once, with the network:
openszigno verify dossier.es3 --json \
  --trust-store ./trust --online --online-cache ./revocation-cache

# Afterwards, anywhere, with no network at all:
openszigno verify dossier.es3 --json \
  --trust-store ./trust --revocation-store ./revocation-cache
```

The second run reaches the same answer, with `chain[].revocation.source`
reading `store_crl` or `store_ocsp` instead of the `online_*` form. This is the
recommended way to use `--online`: fetch once, pin what you got, and make every
later verification reproducible and offline. Remember that revocation data
expires: a cache that was fresh at the validation time you used stays valid
for *that* validation time, which is the whole point of pinning it. Nothing is
ever deleted from the cache; pruning is your retention policy, not the tool's.

Nothing in the cache is ever overwritten either. Files are created relative to
an opened directory descriptor, so a symlink in the path (or standing where a
cache file would go) is refused rather than followed, and an existing file is
never truncated: if a name already holds exactly the artefact being cached the
write is skipped, which is also what two runs caching the same thing at once
look like, and if it holds anything else the run reports
`online_fetch_failed` with the class `cache_collision` and leaves the file
alone. Caching is an optimisation; it never changes a verdict.

### Proxies

No proxy is used unless you name one:

```bash
openszigno verify dossier.es3 --online --online-proxy http://proxy.internal:3128
```

`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lower-case spellings are
**deliberately ignored**. A verifier that silently routed its revocation
traffic through whatever the environment happened to set would hand anyone who
can write that variable a way to feed it chosen bytes. Those bytes would still
have to verify (that is the point of checking everything offline), but the
ambiguity is not worth accepting, and a proxy is the sort of thing an operator
should have to say out loud.

`--online` and `--no-revocation` cannot be combined, and `--online-cache`,
`--online-proxy` and `--online-allow-private` all require `--online`.
