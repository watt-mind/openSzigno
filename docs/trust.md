# Trust and revocation material

`openszigno verify` never fetches anything. Trust anchors, trusted lists, CRLs
and OCSP responses are all files you supply, and this document describes how to
obtain them, how to lay them out, and what each one does to a verdict.

That is a deliberate trade. A verifier that downloads its own trust anchors has
gained nothing: whoever can answer the download decides what is trusted. Pinning
the material yourself is more work and is the only version of the job that means
anything.

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
**a certificate is a trust anchor if and only if it is self-signed**, so
dropping an intermediate into `anchors/` makes it an extra untrusted path
candidate rather than a trusted one.

Every file is parsed at load time. One malformed entry fails the whole store
(`trust_store_invalid`, exit 3), because a half-loaded store would silently
change what "trusted" means.

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

The lists are refreshed daily. Fetch a snapshot, record its
`TSLSequenceNumber` and `ListIssueDateTime`, and keep it under version control
or in an archive alongside whatever you verified with it; the report's
`policy.trust_lists` block cites exactly those fields so a result can be
reproduced later.

```bash
mkdir -p trust-lists
curl --proto '=https' --tlsv1.2 -sSf \
  https://nmhh.hu/tl/pub/HU_TL.xml -o trust-lists/HU_TL.xml
```

### Bootstrapping national lists from the LOTL

The LOTL's `PointersToOtherTSL` entries name the signing certificates of the
national lists. `--lotl FILE` reads them, so **one** out-of-band certificate —
the LOTL's, from the Official Journal — verifies the LOTL, and the LOTL's
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
same XMLDSig core it uses on a dossier — the same canonicalization backend, the
same pinned algorithm and transform allowlists — and requires the signature to
cover the whole document.

Any one of the supplied certificates verifying is enough — the one from
`--trust-list-signer` plus, when `--lotl` was given, every pointer certificate
it named — because a scheme operator may publish several and a verifier cannot
know which of them signed the copy in hand.

- Signature verifies: `trust_list_signature_ok` (`passed`).
- Signature does not verify against any supplied certificate, or the list
  carries none while one was demanded: `trust_list_signature_invalid`
  (`failed`) — the run is `invalid`.
- No signer certificate at all: `trust_list_unverified` (`unknown`). The list's
  anchors are still used, but the run can never reach `valid`.

### What is read, and what is not

For every `TSPService` whose `ServiceTypeIdentifier` is:

- `http://uri.etsi.org/TrstSvc/Svctype/CA/QC` — a CA issuing qualified
  certificates, or
- `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST` — a qualified timestamping
  authority,

every `X509Certificate` in the service digital identity becomes a trust anchor,
carrying the service's status timeline: the current `ServiceStatus` with its
`StatusStartingTime`, plus every `ServiceHistoryInstance`.

A path that ends at such an anchor is trusted only if the service was granted
**at the validation time**. That is what lets a signature made while a CA was
supervised still verify after that CA was withdrawn, and stops a signature made
after the withdrawal from doing so. The statuses treated as granted are:

- `.../Svcstatus/granted`
- `.../Svcstatus/recognisedatnationallevel`

Every other status — `withdrawn`, `supervisionceased`, the `deprecated*`
family, and the pre-eIDAS `undersupervision` and `accredited` — is **not**
treated as granted. This build refuses to guess which historical status was
equivalent to which; the honest answer is that it does not know, and it reports
`certificate_not_qualified` rather than quietly accepting.

Deliberately not read:

- A `DigitalId` carrying only an `X509SubjectName` or an `X509SKI`. It
  identifies a certificate without supplying one, and this build will not go
  looking.
- Scheme-level `Qualifications` extensions, which refine qualified status per
  certificate subset. They are never used to *widen* a determination.
- Anything at all over the network. There is no `openszigno trust update`.

### How `qualified` is decided

**Over the whole chain, not over its anchor.** This matters in practice: the
Hungarian list names the *issuing* CAs — the "Qualified e-Szigno CA" style
services — as its CA/QC service identities, while the Microsec roots that end
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
   (`0.4.0.1862.1.1`) — or will not parse — contradicts the list and yields
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
OCSP response fails the run (`revocation_store_invalid`, exit 3) — "no
revocation data" is itself an answer that changes a verdict, so a store that
quietly dropped half its contents would be worse than no store at all.

### Where the data comes from, in priority order

1. The signature's own validation data — `CRLValues` and `OCSPValues` — from
   **either** placement: directly under
   `xades:UnsignedSignatureProperties/xades:RevocationValues`, or nested inside
   an `xades141:TimeStampValidationData`. Real long-term Microsec dossiers put
   almost all of their embedded OCSP responses in the second one, so both are
   harvested; the container is matched in any recognised XAdES namespace and the
   encapsulating elements inside it by name alone, because real dossiers nest
   1.3.2-namespaced values under a 1.4.1-namespaced container.
2. `--revocation-store DIR`.

Within each tier OCSP is asked first, because it answers about *this*
certificate rather than about a list.

### What real dossiers actually embed, and what you still have to fetch

**A real Microsec dossier embeds an OCSP response for the end-entity
certificate only.** Its issuing CA and the root above that carry no embedded
status at all. Since every non-anchor certificate in the chain needs a status —
a revoked intermediate condemns everything under it, so exempting CAs would
make the check worth much less than it looks — a `valid` verdict on real
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

### What makes data unusable

| Situation | Code | Status |
| --- | --- | --- |
| A CRL or response signed by someone the CA did not authorise | `revocation_data_invalid` | `unknown` |
| A delta CRL, an indirect CRL, a scope restricted to reasons or attribute certificates | `revocation_data_invalid` | `unknown` |
| A partitioned CRL naming a distribution point the certificate does not | `revocation_data_invalid` | `unknown` |
| A critical CRL extension this build does not implement | `revocation_data_invalid` | `unknown` |
| An OCSP response whose `OCSPResponseStatus` is not `successful` | `revocation_data_invalid` | `unknown` |
| Data whose `nextUpdate` has passed at the validation time | `revocation_data_stale` | `unknown` |
| No data at all covers a certificate | `revocation_status_unknown` | `unknown` |

All of them are `unknown`, never `failed`: unusable data means the tool could
not answer, which is a different statement from "this certificate was revoked".

## Online fetching

Not implemented. `--online` fetching of CRL distribution points and OCSP from
AIA is an M3 residual, tracked in `roadmap.md`. Until it ships, the workflow
above — fetch by hand, pin, record — is the whole story, and the verify crate
structurally cannot open a socket: revocation data reaches it only through the
injected `RevocationSource`.
