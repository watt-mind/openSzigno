# Remote signing research

Research date: 2026-09-09. Ticket: LAB-287.

This document surveys the remote signature ecosystem openSzigno would have to
join once the planned `create` and `sign` commands exist. It is research, not
a specification: nothing here is implemented, and nothing here asserts that
any signature, certificate, or dossier produced by a listed service is valid.

Every external link in this document is also recorded in
[references.md](references.md#remote-signing-and-cloud-signature-apis).
Claims that could not be confirmed from a primary source are marked
"unverified" in place and collected again in
[What was not verified](#what-was-not-verified).

## Table of contents

- [Why remote signing at all](#why-remote-signing-at-all)
- [1. The CSC API](#1-the-csc-api)
- [2. The EUDI Wallet reference implementation](#2-the-eudi-wallet-reference-implementation)
- [3. Remote QSCD providers](#3-remote-qscd-providers)
- [4. Timestamp authorities](#4-timestamp-authorities)
- [5. Hungarian acceptance](#5-hungarian-acceptance)
- [6. Recommendation](#6-recommendation)
- [What was not verified](#what-was-not-verified)

## Why remote signing at all

An ES3 dossier carries XAdES signatures. Producing one needs a private key
that, for a qualified signature, lives in a qualified signature creation
device. A command-line tool cannot hold such a key. The only route open to a
CLI is to build the `ds:SignedInfo`, hand its digest to a remote service that
controls the key, and place the returned signature value back into the
document. That is exactly the shape of the Cloud Signature Consortium (CSC)
`signatures/signHash` operation, which is why the CSC API, and not any
vendor-specific protocol, is the axis of this survey.

## 1. The CSC API

### 1.1 Versions

The Cloud Signature Consortium publishes its API specification from a single
download page.

| Version | Published | Where |
| --- | --- | --- |
| API V1.0.3.0 | 13 December 2018 | [CSC_API_V1_1.0.3.0.pdf](https://cloudsignatureconsortium.org/wp-content/uploads/2020/05/CSC_API_V1_1.0.3.0.pdf) |
| API V1.0.4.0 | 28 June 2019 | [CSC_API_V1_1.0.4.0.pdf](https://cloudsignatureconsortium.org/wp-content/uploads/2020/01/CSC_API_V1_1.0.4.0.pdf) |
| API V2.0 (2.0.0.2) | 20 April 2023 | [csc-api-v2.0.0.2.pdf](https://cloudsignatureconsortium.org/wp-content/uploads/2023/04/csc-api-v2.0.0.2.pdf) |
| API V2.1.0.1 | 22 January 2025 | [download page](https://cloudsignatureconsortium.org/resources/download-api-specifications/) |
| API V2.2 | 6 November 2025 | [CSC API V2.2](https://cloudsignatureconsortium.org/resources/csc-api-v2-2/) |

The version list, dates, and the two direct PDF links above come from the
consortium's own
[download page](https://cloudsignatureconsortium.org/resources/download-api-specifications/).
V2.1.0.1 and V2.2 are behind a form, so their text was not read for this
document.

The relationship to ETSI is one of reference, not identity. ETSI TS 119 432
"Protocols for remote digital signature creation" defines protocols that
reference CSC API JSON constructs alongside OASIS DSS-X XML constructs, and
specifies additional elements where alignment was not possible; see
[ETSI TS 119 432 V1.1.1](https://www.etsi.org/deliver/etsi_ts/119400_119499/119432/01.01.01_60/ts_119432v010101p.pdf).
Version 1.2.1 of that standard refers to CSC API 1.0.3.0, while deployed
services were already on later CSC versions; the EUDI Wallet standards
tracker records
[ETSI TS 119 432 V1.3.1 (2026-03)](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/issues/68)
as the current edition. Which CSC version V1.3.1 references was not read
and is unverified.

### 1.2 The shape of the API

CSC API V2 concatenates its operations onto a base URI ending in `/csc/v2`.
The operation set is `info`, `auth/login`, `auth/revoke`, `oauth2/authorize`,
`oauth2/token`, `credentials/list`, `credentials/info`,
`credentials/authorize`, `credentials/authorizeCheck`,
`credentials/extendTransaction`, `signatures/signHash`,
`signatures/signDoc`, and `signatures/timestamp`
([CSC API v2.0.0.2](https://cloudsignatureconsortium.org/wp-content/uploads/2023/04/csc-api-v2.0.0.2.pdf)).
A client discovers which of these a given service actually implements from
the `methods` array in the `info` response, so `info` is the first call any
implementation makes.

Two access decisions are distinct and both have to be made:

- **Service access.** Either the CSC-native `auth/login` (a service access
  token from credentials the client holds) or OAuth 2.0 with `scope=service`.
  The `authType` array in `info` says which the service offers.
- **Credential authorisation.** The `authMode` field of a credential, from
  `credentials/info`, is `explicit` or `oauth2`. Under `explicit` the client
  calls `credentials/authorize` with the credential identifier, the number of
  signatures to authorise, the hashes, and a one-time password or PIN, and
  receives Signature Activation Data (SAD). Under `oauth2` the client instead
  runs a second OAuth 2.0 authorization code round with `scope=credential`,
  and the resulting access token plays the SAD role.

Two parameters carry the anti-abuse guarantee in both modes. `numSignatures`
caps how many signatures the authorisation covers, and the hash list binds
the authorisation to specific data. A SAD that is not bound to the hashes it
authorises is a SAD that can sign anything, so a client must send the real
hashes at authorisation time, not placeholders.

### 1.3 A concrete hash-signing sequence

The sequence below is what openSzigno would run against a CSC V2 service in
`oauth2` credential authorisation mode. All values are synthetic. The request
shapes follow the wallet-driven flow documented by the EUDI reference QTSP
([rqes-walledriven.md](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java/blob/main/docs/rqes-walledriven.md)),
which implements CSC API V2.

Step 1, discover the service. The response below is the real, unedited body
returned by the EUDI reference deployment on 2026-09-09; only whitespace was
added.

```http
POST /csc/v2/info HTTP/1.1
Host: walletcentric.signer.eudiw.dev
Content-Type: application/json

{"lang": "en"}
```

```json
{
  "specs": "2.2.0.0",
  "name": "remote Qualifies Electronic Signature QTSP",
  "region": "EU",
  "lang": "en-US",
  "description": "This is a test Qualified Trust Service Provider",
  "authType": ["oauth2code"],
  "oauth2": "https://walletcentric.signer.eudiw.dev",
  "asynchronousOperationMode": false,
  "methods": ["oauth2/authorize", "oauth2/token", "credentials/list",
              "credentials/info", "credentials/create", "credentials/delete",
              "signatures/signHash"],
  "validationInfo": false,
  "signAlgorithms": {
    "algos": ["1.2.840.10045.2.1", "1.2.840.10045.4.3.2"],
    "algoParams": []
  },
  "signature_formats": {
    "formats": ["P", "X", "C", "J"],
    "envelope_properties": [["Enveloped"],
      ["Enveloped", "Enveloping", "Detached", "Internally detached"],
      ["Enveloping", "Detached"], ["Enveloping", "Detached"]]
  },
  "conformance_levels": ["Ades-B-B", "Ades-B-T", "Ades-B-LT", "Ades-B-LTA"],
  "supportsRar": true,
  "supportedHashTypes": ["dtbsr"]
}
```

Three facts in that response drive the rest of the design. `authType` is
`oauth2code` only, so there is no `auth/login` path. `signAlgorithms` offers
ECDSA with SHA-256 (`1.2.840.10045.4.3.2`) over EC keys
(`1.2.840.10045.2.1`), not RSA. And `supportedHashTypes` is `dtbsr`: the
value the client sends is the data-to-be-signed representation, which for
XAdES is the digest of the canonicalised `ds:SignedInfo`.

Step 2, service access token, OAuth 2.0 authorization code with PKCE and
`scope=service`.

```http
GET /oauth2/authorize?response_type=code
    &client_id=openszigno-cli
    &redirect_uri=http://127.0.0.1:8642/callback
    &scope=service
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
    &state=8f2c1a7e HTTP/1.1
Host: qtsp.example
```

```http
HTTP/1.1 302 Found
Location: http://127.0.0.1:8642/callback?code=SPLxlOBeZQQY&state=8f2c1a7e
```

```http
POST /oauth2/token HTTP/1.1
Host: qtsp.example
Authorization: Basic b3BlbnN6aWdubzpzM2NyZXQ=
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SPLxlOBeZQQY
&client_id=openszigno-cli
&redirect_uri=http%3A%2F%2F127.0.0.1%3A8642%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiJ9.svc.token",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Step 3, enumerate and inspect the credentials.

```http
POST /csc/v2/credentials/list HTTP/1.1
Host: qtsp.example
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.svc.token
Content-Type: application/json

{"credentialInfo": true, "certificates": "chain", "certInfo": true,
 "authInfo": true, "onlyValid": true, "lang": "en"}
```

```json
{
  "credentialIDs": ["cred-1a2b3c"],
  "credentialInfos": [{
    "credentialID": "cred-1a2b3c",
    "key": {"status": "enabled", "algo": ["1.2.840.10045.4.3.2"],
            "curve": "1.2.840.10045.3.1.7", "len": 256},
    "cert": {"status": "valid",
             "certificates": ["MIIB...signer", "MIIC...issuing-ca"],
             "subjectDN": "CN=Test Signer,C=HU",
             "validFrom": "20260101000000Z",
             "validTo": "20270101000000Z"},
    "authMode": "oauth2",
    "SCAL": "2",
    "multisign": 1,
    "lang": "en"
  }]
}
```

Step 4, authorise the credential for exactly these hashes. `openszigno`
first builds the XAdES `ds:SignedInfo`, canonicalises it, and takes its
SHA-256 digest; that base64 digest is the only thing that leaves the machine.

```http
GET /oauth2/authorize?response_type=code
    &client_id=openszigno-cli
    &redirect_uri=http://127.0.0.1:8642/callback
    &code_challenge=nTn7dEUvcVDNBFmZ1nQ4wcpKzXMCwqoK5m5Xp2xNKmA
    &code_challenge_method=S256
    &authorization_details=%7B%22type%22%3A%22credential%22%2C...%7D HTTP/1.1
Host: qtsp.example
```

The `authorization_details` value, before URL encoding:

```json
{
  "type": "credential",
  "credentialID": "cred-1a2b3c",
  "signatureQualifier": "eu_eidas_qes",
  "documentDigests": [
    {"hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
     "label": "dossier signature 1"}
  ],
  "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
}
```

The equivalent without rich authorization requests is the plain query form
`scope=credential&credentialID=cred-1a2b3c&numSignatures=1&hash=<base64>`.
A service advertises support for the structured form through `supportsRar`
in `info`; the EUDI reference deployment returns `true`.

Step 5, exchange the second code for the credential token, which is the SAD.

```http
POST /oauth2/token HTTP/1.1
Host: qtsp.example
Authorization: Basic b3BlbnN6aWdubzpzM2NyZXQ=
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=Kd9pQ2mXaL
&client_id=openszigno-cli
&redirect_uri=http%3A%2F%2F127.0.0.1%3A8642%2Fcallback
&code_verifier=IrY9nQ0lFtEwl2Yy5nJ7d0f-2bC3Kx1oP4qRs6TuVwY
&authorization_details=%7B%22type%22%3A%22credential%22%2C...%7D
```

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiJ9.sad.token",
  "token_type": "Bearer",
  "expires_in": 300
}
```

Step 6, sign the hash. In CSC V1 the field was `hash`; in V2 it is `hashes`,
and `signAlgo` became explicit.

```http
POST /csc/v2/signatures/signHash HTTP/1.1
Host: qtsp.example
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.sad.token
Content-Type: application/json

{
  "credentialID": "cred-1a2b3c",
  "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
  "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
  "signAlgo": "1.2.840.10045.4.3.2",
  "signAlgoParams": "",
  "operationMode": "S"
}
```

```json
{
  "signatures": ["MEUCIQD3n1kQvVYq6l0GmT1sQwJ8kQ0k1TQ4Uu5oQm3rXwIhAP..."]
}
```

Under `explicit` mode, steps 4 and 5 collapse into one call:

```http
POST /csc/v2/credentials/authorize HTTP/1.1
Host: qtsp.example
Authorization: Bearer eyJhbGciOiJFUzI1NiJ9.svc.token
Content-Type: application/json

{
  "credentialID": "cred-1a2b3c",
  "numSignatures": 1,
  "hashes": ["sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="],
  "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1",
  "OTP": "738291"
}
```

```json
{"SAD": "_TiHRG-bAH3XlFQZ3ndFhkXf9P24_CImWlqjmYPtBhE", "expiresIn": 300}
```

and `signatures/signHash` then carries `"SAD": "..."` in the body instead of
a bearer credential token.

The older V1 field names, and the `token_type: "SAD"` idiom on the second
token response, are visible in a deployed V1 service's public documentation,
[ZealiD's CSC API walkthrough](https://developer.zealid.com/docs/csc-api-in-detail).
A client that wants to speak both versions has to branch on `specs` from
`info`.

### 1.4 Algorithm identifiers

`hashAlgorithmOID` names the digest, `signAlgo` names the signature
algorithm, and `signAlgoParams` carries DER-encoded parameters where the
algorithm needs them, notably RSASSA-PSS.

| Purpose | OID |
| --- | --- |
| SHA-256 | `2.16.840.1.101.3.4.2.1` |
| SHA-384 | `2.16.840.1.101.3.4.2.2` |
| SHA-512 | `2.16.840.1.101.3.4.2.3` |
| RSA (PKCS#1 v1.5 key algorithm) | `1.2.840.113549.1.1.1` |
| sha256WithRSAEncryption | `1.2.840.113549.1.1.11` |
| RSASSA-PSS | `1.2.840.113549.1.1.10` |
| EC public key | `1.2.840.10045.2.1` |
| ecdsa-with-SHA256 | `1.2.840.10045.4.3.2` |

The SHA-256, sha256WithRSAEncryption and ecdsa-with-SHA256 values appear in
the EUDI reference material cited above and, for the EC pair, in the live
`info` response quoted in section 1.3. The RSA, RSASSA-PSS and SHA-384/512
rows are the standard registry values rather than values read out of the CSC
PDF; the specification's own algorithm tables could not be extracted from
the PDF in this environment and are unverified.

### 1.5 Placing the result into a XAdES signature

The CSC service returns the raw signature value, base64-encoded. XMLDSig
wants exactly that, base64-encoded, as the text of `ds:SignatureValue`
([XML Signature Syntax and Processing](https://www.w3.org/TR/xmldsig-core1/)),
so the placement itself is a copy. The work is entirely on the client side,
and the order matters:

1. Build every `ds:Reference` with its transforms and `ds:DigestValue`.
2. Build the XAdES `xades:SignedProperties`, including
   `xades:SigningCertificate` or `xades:SigningCertificateV2`, whose digest
   needs the signing certificate, which is why `credentials/info` runs
   before hashing and not after.
3. Add the `ds:Reference` over `xades:SignedProperties` with
   `Type="http://uri.etsi.org/01903#SignedProperties"`.
4. Canonicalise `ds:SignedInfo` with the algorithm named in
   `ds:CanonicalizationMethod`, digest it, and base64 the digest. This is
   the data-to-be-signed representation, matching `supportedHashTypes:
   ["dtbsr"]` in the `info` response.
5. Send that value as the single element of `hashes`.
6. Insert the returned string verbatim as the content of
   `ds:SignatureValue`.

Two traps follow from this. `ds:SignatureMethod` in the document has to
agree with the `signAlgo` the service actually used, so `signAlgo` must be
chosen from the credential's `key.algo` list rather than assumed. And a
service in `dtbsr` mode signs the digest it was handed without seeing the
document, so any canonicalisation mistake produces a well-formed signature
over the wrong bytes. That failure is invisible until verification.

### 1.6 Wallet-driven versus RP-centric

The two flow shapes differ in who holds the Signature Creation Application
(SCA), the component that turns a document into a hash and later reassembles
the signed document.

| | Wallet-driven | RP-centric |
| --- | --- | --- |
| Who starts the flow | The wallet, or any user-side application | The relying party's web page |
| Where the SCA runs | Beside the user-side application, as an external service | Inside the relying party's environment |
| What the user-side component drives | The whole CSC exchange with the QTSP | Authentication and consent only |
| EUDI reference server | [walletdriven-signer-external-sca-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-signer-external-sca-java) | [rpcentric-signer-sca-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-sca-java) |

openSzigno is structurally a wallet-driven client without a wallet: it is the
user-side application, it would hold its own SCA logic in Rust, and it would
drive the CSC exchange itself. The RP-centric shape is not applicable, since
there is no relying party web page in a CLI.

## 2. The EUDI Wallet reference implementation

### 2.1 The rQES repositories

The [eu-digital-identity-wallet](https://github.com/eu-digital-identity-wallet)
organisation holds 85 repositories as of 2026-09-09. The following are the
remote qualified electronic signature (rQES) components; the names,
descriptions, languages and licences were read from the GitHub organisation
API on that date.

| Repository | What it is | Language | Licence |
| --- | --- | --- | --- |
| [eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-rpcentric-signer-qtsp-java) | The QTSP itself: a CSC API V2.0 server with OpenID4VP authentication, serving both flows | Java | Apache-2.0 |
| [eudi-srv-web-walletdriven-signer-external-sca-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-signer-external-sca-java) | Wallet-driven external SCA: `calculate_hash` and `obtain_signed_doc` | Java | Apache-2.0 |
| [eudi-srv-web-rpcentric-signer-sca-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-sca-java) | RP-centric SCA, `/signatures/doc` and `/signatures/callback`, port 8088 | Java | Apache-2.0 |
| [eudi-srv-web-trustprovider-signer-java](https://github.com/eu-digital-identity-wallet/eudi-srv-web-trustprovider-signer-java) | TrustProvider Signer: a CSC-compliant RSSP backend, a signature application backend, and a React client | Java | Apache-2.0 |
| [eudi-lib-jvm-rqes-csc-kt](https://github.com/eu-digital-identity-wallet/eudi-lib-jvm-rqes-csc-kt) | CSC protocol client, wallet's role, Kotlin | Kotlin | Apache-2.0 |
| [eudi-lib-ios-rqes-csc-swift](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-rqes-csc-swift) | CSC protocol client, wallet's role, Swift | Swift | Apache-2.0 |
| [eudi-lib-android-rqes-core](https://github.com/eu-digital-identity-wallet/eudi-lib-android-rqes-core) | Android rQES core kit | Kotlin | Apache-2.0 |
| [eudi-lib-ios-rqes-kit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-rqes-kit) | iOS rQES kit | Swift | Apache-2.0 |
| [eudi-lib-android-rqes-ui](https://github.com/eu-digital-identity-wallet/eudi-lib-android-rqes-ui) | Android rQES user interface library | Kotlin | Apache-2.0 |
| [eudi-lib-ios-rqes-ui](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-rqes-ui) | iOS rQES user interface library | Swift | Apache-2.0 |
| [eudi-app-web-walletdriven-tester-py](https://github.com/eu-digital-identity-wallet/eudi-app-web-walletdriven-tester-py) | Wallet tester web service for the wallet-driven release | Python | Apache-2.0 |
| [eudi-srv-web-walletdriven-signer-relyingparty-py](https://github.com/eu-digital-identity-wallet/eudi-srv-web-walletdriven-signer-relyingparty-py) | Wallet-driven relying party test site | Python | Apache-2.0 |
| [eudi-srv-web-rpcentric-signer-relyingparty-py](https://github.com/eu-digital-identity-wallet/eudi-srv-web-rpcentric-signer-relyingparty-py) | RP-centric relying party test site | Python | Apache-2.0 |

The single most useful of these for openSzigno is the QTSP, because it is
the server side of the protocol a Rust client has to speak. The two Kotlin
and Swift CSC client libraries are the closest thing to a reference client
and are worth reading for their request shapes, but they cover a subset:
`eudi-lib-jvm-rqes-csc-kt` documents support for `info`, `credentials/list`,
`credentials/info` and `signatures/signHash`, and explicitly not
`auth/login`, `credentials/authorize`, `signatures/signDoc`, or
`signatures/timestamp`, and it targets CSC API V2.2.

### 2.2 Which CSC version and which OAuth 2.0 flow

The QTSP README states CSC API v2.0 with OpenID4VP-based authentication and
the scopes `service` and `credential`, exposing `/oauth2/authorize`,
`/oauth2/token`, `/csc/v2/info`, `/csc/v2/credentials/list`,
`/csc/v2/credentials/info` and `/csc/v2/signatures/signHash`. The live
deployment at `walletcentric.signer.eudiw.dev` reports `"specs":
"2.2.0.0"`, so the deployed build is ahead of the README. The Kotlin client
library also targets V2.2.

The flow is authorization code with PKCE (`code_challenge_method=S256`),
twice: once with `scope=service` for the service token, once for the
credential. The credential round accepts either the plain query parameters
(`scope=credential`, `credentialID`, `numSignatures`, `hash`) or a rich
authorization request in `authorization_details` with `"type":
"credential"`, `credentialID`, `signatureQualifier`, `documentDigests` (each
entry a `hash` and a `label`) and `hashAlgorithmOID`. The
`authorization_details` value is repeated on the token request.

What makes this flow specific to the wallet ecosystem is what happens
between the authorize request and the redirect: rather than a password form,
the QTSP returns an OpenID4VP deep link of the form
`eudi-openid4vp://verifier.example.com?client_id=...&request_uri=...`, and
the user presents Person Identification Data from a wallet. This is the part
a CLI cannot perform on its own; see section 6.

### 2.3 Running it locally

Both server components ship a `docker-compose.yml` and are documented as
locally deployable. The QTSP additionally needs MySQL, an OpenID4VP verifier
backend for authentication, and, in its documented configuration, EJBCA for
certificate issuance and an HSM (tested with a Utimaco vHSM). TrustProvider
Signer is the softer target: it too runs under `docker compose up --build`,
requires MySQL, but treats both the HSM and EJBCA as optional, falling back
to Bouncy Castle and a locally generated CA certificate.

A hosted instance is also available and answers without credentials. On
2026-09-09 the following returned the JSON quoted in section 1.3:

```sh
curl -s -X POST https://walletcentric.signer.eudiw.dev/csc/v2/info \
  -H 'Content-Type: application/json' -d '{"lang":"en"}'
```

Whether that host will accept an OAuth 2.0 client registration from an
arbitrary third party, and whether it is intended to stay up, was not
established and is unverified. The `info` endpoint being open says nothing
about the rest of the flow.

### 2.4 What a command-line client needs

To talk to this server, openSzigno would need, at minimum:

- A registered `client_id` and `client_secret`, sent as HTTP Basic on the
  token endpoint.
- A redirect URI it can actually receive on. For a CLI that means a
  short-lived loopback listener, `http://127.0.0.1:<port>/callback`, in the
  style of RFC 8252 for native applications.
- A PKCE implementation, S256.
- A browser handoff: the authorize URL must be opened in the user's browser,
  because the QTSP drives an OpenID4VP wallet interaction there.
- JSON over HTTPS with TLS 1.2 or better; CSC API V2 requires services to
  support TLS 1.2 and notes TLS 1.3 as current.
- XAdES construction and canonicalisation in Rust, since the client is its
  own SCA. Nothing on the server side will build the `ds:SignedInfo`.

### 2.5 The ARF and the eIDAS 2 obligation

The Architecture and Reference Framework treats remote signing as a
first-class role. Chapter 2, "EUDI Wallet functionalities", states that a
Wallet Unit can connect to a remote qualified signature creation device
managed by a qualified trust service provider, and that qualified electronic
signatures are provided by default and free of charge within the Wallet Unit
([chapter 2](https://eudi.dev/latest/main/02-eudi-wallet-functionalities/)).
Chapter 3 defines the Qualified Electronic Signature Remote Creation (QESRC)
Provider as an ecosystem role, and describes a Remote Signing or Sealing
Interface (RSI) between the Wallet Unit and a QESRC Provider
([chapter 3](https://eudi.dev/latest/main/03-roles-within-the-eudi-wallet-ecosystem/)).
Annex 4 carries a dedicated flow diagram,
[Remote QES: creating a signature channeled by the EUDI Wallet](https://eudi.dev/latest/annexes/annex-4/annex-4.08-remote-qes-creating-a-signature-channeled-by-eudi-wallet.pdf).
The most recent ARF tag in the source repository,
[eudi-doc-architecture-and-reference-framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework),
is `v3.0.0`. The section numbers 2.4, 3.9 and 4.3.3 for these topics were
read from the 2.4.0 rendering
([eudi.dev/2.4.0](https://eudi.dev/2.4.0/architecture-and-reference-framework-main/));
whether they still carry those numbers in v3.0.0, and whether the ARF binds
a specific CSC API version, were not confirmed and are unverified.

The legal driver is Regulation (EU) 2024/1183, which amends Regulation (EU)
No 910/2014. In the consolidated text, Article 5a(5)(g) requires wallets to
"offer all natural persons the ability to sign by means of qualified
electronic signatures by default and free of charge", with Member States
permitted to impose proportionate restrictions keeping the free use to
non-professional purposes, and Article 5a(13) provides that issuance, use
and revocation of the wallets is free of charge to all natural persons
([consolidated 910/2014](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:02014R0910-20240520),
[Regulation (EU) 2024/1183](https://eur-lex.europa.eu/eli/reg/2024/1183/oj)).
Recital 20 of 2024/1183 states the same principle in policy terms. The
practical consequence for this project is that the population able to
produce a qualified signature through a CSC-style API is about to grow a
great deal, which is an argument for building against the wallet ecosystem's
protocol rather than a vendor's.

## 3. Remote QSCD providers

### 3.1 How to read this table

"CSC API version" records what the provider itself states publicly. A
provider that is a Cloud Signature Consortium member is not thereby a
provider with a CSC endpoint a third party can call, and several members
document only a proprietary REST API. Pricing is "on request" unless a
figure is actually published; nothing here is estimated.

The consortium publishes a
[members list](https://cloudsignatureconsortium.org/about-us/our-members/)
but no conformance or certified-implementation registry, so there is no
authoritative way to check a claim of CSC conformance short of calling the
service. Neither Microsec nor NetLock appears on that members list.

### 3.2 Hungarian providers

| Provider | Country | Certificate type | Enrolment | CSC API version | Sandbox | Pricing | Documentation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Microsec (e-Szigno) | HU | Natural person and seal | Video identification for e-Szigno mobile; registration authority | Proprietary; no public cloud signing API found | Unknown | On request | [e-Szigno Hitelesito Szerver](https://srv.e-szigno.hu/doc/eszigno_hitelesito_szerver/eszigno_hitelesito_szerver.html), [MicroSigner](https://eszigno.microsigner.com/esign/) |
| NetLock | HU | Natural person and seal | Video identification; mobile registration authority | Proprietary REST, not documented publicly | Unknown; a demo portal exists | Public price list PDF; API tier on request | [NETLOCK Sign Enterprise](https://netlock.hu/termekek/netlock-sign-enterprise/), [price tables](https://netlock.hu/dijtablazatok/) |

Microsec matters more to this project than any other provider, because ES3
is their format, so it deserves a direct answer: there is no publicly
documented remote signing API from Microsec that a third-party CLI could
call. What is public is the
[e-Szigno Hitelesito Szerver](https://srv.e-szigno.hu/doc/eszigno_hitelesito_szerver/eszigno_hitelesito_szerver.html)
REST interface, with operations such as `xadessign` and `padessign`, but
that is an on-premise product signing with locally held keys, not a cloud
signature service. The MicroSigner product routes hash signing through a
Microsec-hosted proxy server to a key that may be a remote key approved
through e-Szigno Mobil, which is architecturally the right shape, but its
developer documentation was not found on a Microsec domain. Treat
"Microsec offers a third-party remote signing API" as unverified and, on
present evidence, as requiring a sales conversation rather than a signup.

NetLock's NETLOCK Sign Enterprise product page states that all functions,
including signing, are reachable through a REST API and that a hash-only
hybrid mode exists, which is the relevant capability, but no API
documentation is public.

### 3.3 Other providers

| Provider | Country | Certificate type | Enrolment | CSC API version | Sandbox | Pricing | Documentation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Swisscom Trust Services (All-in Signing Service) | CH | Natural person and seal | Registration authority app, video ident, German eID, auto ident | Proprietary REST and SOAP | Yes, a documented 90-day trial claimed identity | On request | [downloads and documents](https://trustservices.swisscom.com/en/esignature-hub/downloads-and-documents), [GitHub](https://github.com/SwisscomTrustServices) |
| InfoCert (GoSign, Sign API) | IT | Natural person and seal | Onboarding platform, eID gateway | CSC, version not stated | Unknown | On request | [CSC API product page](https://developers.infocert.digital/e-signature-and-e-sealing/csc-api/) |
| Namirial (eSignAnyWhere) | IT | Natural person and seal | Video ident, eID, own registration authority | CSC, version not stated | Yes, public Swagger on a demo host | On request | [docs.namirial.app](https://docs.namirial.app/), [demo API](https://demo.esignanywhere.net/Api) |
| Intesi Group (PkBox Remote, Time4Mind) | IT | Natural person, seal, timestamp | Unknown | CSC, version not stated | On request, development trial licence | On request | [integration page](https://www.intesigroup.com/en/digital-signature-integration/) |
| D-Trust (sign-me, seal-me) | DE | sign-me natural person; seal-me seals | German eID, VideoIdent, point of sale | CSC, version not stated | Unknown | Portal coins published: 100 for EUR 34.90, 500 for EUR 139.90 including VAT, QES 5 coins | [sign-me API](https://www.d-trust.net/en/solutions/sign-me-api) |
| Evrotrust | BG | Natural person and seal | Remote document scan with liveness; operator fallback | Proprietary REST | Yes, a named sandbox host | On request | [docs.evrotrust.com](https://docs.evrotrust.com/docs/integration) |
| Certinomis (Docaposte) | FR | Natural person and seal | ANSSI substantial level identity | CSC, version not stated | Unknown | On request | [CSC member page](https://cloudsignatureconsortium.org/member/certinomis/), [certinomis.fr](https://www.certinomis.fr/) |
| Entrust (Remote Signing Service, Signing Automation Service) | US, EU operations | RSS natural person; SAS organisational seals | In-workflow identity verification plus an authenticator app | CSC 0.1.7.9 for RSS, CSC 1.0.4.0 for the Remote Signing Engine | Unknown | On request | [RSS datasheet](https://www.entrust.com/sites/default/files/documentation/datasheets/remote-signing-service-ds.pdf), [SAS user guide](https://api.managed.entrust.com/sas/Entrust_Signing_Automation_Service_-_User_Guide.pdf) |
| GlobalSign (Digital Signing Service) | BE | Natural person and organisation identities | Organisation vetted once, identities minted by API | Proprietary REST | Unknown | On request | [DSS API documentation](https://www.globalsign.com/en/resources/apis/api-documentation/digital-signing-service-api-documentation.html), [docs.globalsign.com](https://docs.globalsign.com/solutions/services/dss) |
| Ascertia (SigningHub, ADSS) | UK | Depends on the connected trust service provider | Delegated; OTP, PIN or OAuth 2.0 at signing | CSC 1.0.4.0 in SigningHub; ADSS also exposes a CSC server interface | Yes, a free trial tier | Tiers published but rendered client side | [CSC product page](https://www.ascertia.com/products/cloud-signature-consortium/) |
| PrimeSign (Cryptas) | AT | Natural person, EC keys | German eID, ID Austria, or a primeSign account | CSC 1.0.4.0 and 2.1.0.1 | Yes, an open test host with a Postman collection | On request | [hash signing API](https://primesign.cryptas.com/en/hash-signing-api), [developer page](https://primesign.cryptas.com/en/developer) |
| Cleverbase (Vidua) | NL | v1 qualified natural person; v2 beta non-qualified | Vidua app; v2 beta needs wallet person identification data | CSC 1.0.4.0 for v1, CSC 2.2.0.0 for the v2 beta | Yes, a reachable lab host with OpenAPI | On request | [signing API reference](https://cleverbase.com/en/dev-docs/signing/api-reference/), [v2 beta](https://cleverbase.com/en/dev-docs/signing-v2-beta/) |
| Buypass | NO | Natural person, short-lived keys | Through a contracted identity proofing provider | CSC 2.0, stated as parts of the REST API | Yes, a formal test and quality assurance onboarding | On request | [developer space](https://buypassdev.atlassian.net/wiki/spaces/BCSS/pages/3413311489/) |
| A-Trust | AT | Natural person | ID Austria | CSC 1.4 per the vendor's sample client | Yes, the sample repository ships test credentials | On request | [CSC_HashSignClient](https://github.com/A-Trust/CSC_HashSignClient) |
| Digidentity | NL, UK | Natural person | Digidentity app, push and PIN | CSC v1, patch version unknown | Unknown | On request | [CSC flow documentation](https://connect.digidentity.com/flows/CSC/) |
| Universign (Signaturit) | FR | Natural person and seal | OTP; prevalidated identity for qualified | Proprietary REST | Yes, an alpha API host | On request | [API documentation](https://apps.universign.com/docs/api/) |
| Uanataca (Namirial) | ES, IT | Natural person and seal | Registration authority officer through an API | Proprietary | Yes, a test mode and playground | On request | [developers.uanataca.com](https://developers.uanataca.com/) |
| certSIGN | RO | Natural person | Remote video identification | CSC, version not stated | Unknown | On request | [remote electronic signature](https://www.certsign.ro/en/products/eidas-trust-services/remote-electronic-signature/) |
| Trans Sped | RO | Natural person and seal | Unknown | CSC, version not stated | On request | On request | [CSC member page](https://cloudsignatureconsortium.org/member/trans-sped/) |
| TrustPro | IE, IT | Natural person and qualified seal | Unknown | CSC member, version not stated | Unknown | Published: free 1 signature per 10 days; EUR 13 per month for 5; EUR 28 per year for 100; EUR 48 per year unlimited | [electronic signature page](https://www.trustpro.eu/electronic-signature/) |
| Camerfirma (InfoCert) | ES | Natural person | Online video identification with an operator | Unknown; signing through GoSign | Unknown | Published: EUR 83 excluding VAT for three years | [remote signature certificate](https://www.camerfirma.com/certificados-digitales/certificado-digital-firma-remota/) |
| SK ID Solutions (Smart-ID) | EE | Natural person | Smart-ID application | Not CSC; own relying party REST API | A demo environment exists, not verified | On request | [digital signing for e-services](https://www.smart-id.com/e-service-providers/smart-id-digital-signing-for-your-e-service/) |
| Halcom One | SI | Natural person | Bank branch or registration authority, mobile app | Proprietary XML over POST | Unknown | On request | [integration page](https://one.halcom.si/en/halcom-one-integration) |
| Bit4id (SignCloud) | ES, IT | Unknown | Own credential management system | Proprietary | Unknown | On request | [SignCloud](https://www.bit4id.com/en/solutions/signcloud/) |
| CertEurope (Oodrive) | FR | Signature, server seal, timestamp | Unknown | Proprietary SignAPI | Unknown | On request | [signature API](https://www.certeurope.fr/solutions-sur-mesure/api-de-signature/) |
| Izenpe | ES | Cloud certificate for professionals | Public administration registration authority | Unknown | Unknown | On request | [technical documentation](https://www.izenpe.eus/descarga-de-certificados/webize01-cndoctecnica/es/) |
| ANF AC | ES | Signature and seal | Unknown | Proprietary signature API | None mentioned | On request | [API de Firma](https://www.anf.ac/api-firma/) |
| DigiSign | RO | Qualified certificates | Unknown | Unknown, no public API documentation | Unknown | On request | [electronic signature](https://digisign.ro/products-services/electronic-signature/) |

### 3.4 The shortlist that actually matters

Filtering for a provider that publishes a CSC version number, documents the
API without a sales call, and offers a reachable sandbox leaves a short
list:

1. **PrimeSign**, CSC 1.0.4.0 and 2.1.0.1, open test host, Postman
   collection. The only provider found that names two CSC versions and
   recommends one.
2. **Cleverbase**, CSC 1.0.4.0 in production and CSC 2.2.0.0 in a beta with
   a reachable lab host and an OpenAPI description. The CSC 2.2 beta matches
   the version the EUDI reference deployment reports.
3. **Buypass**, CSC 2.0, public developer documentation, formal test
   onboarding.

A-Trust and Digidentity are useful for CSC v1 compatibility testing.
Everything Hungarian is behind a sales conversation.
