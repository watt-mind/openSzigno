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
`info` response quoted in section 1.3. RSASSA-PSS with a populated
`signAlgoParams` was observed first-hand in the PrimeSign test service's
`info` response (section 3.5), which pairs `1.2.840.113549.1.1.10` with a
base64 DER `RSASSA-PSS-params` structure. The SHA-384 and SHA-512 rows are
the standard registry values rather than values read out of the CSC PDF; the
specification's own algorithm tables could not be extracted from the PDF in
this environment and are unverified.

### 1.5 Placing the result into a XAdES signature

The CSC service returns the raw signature value, base64-encoded. XMLDSig
wants exactly that, base64-encoded, as the text of `ds:SignatureValue`
([XML Signature Syntax and Processing](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/)),
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

The `info` endpoint being open says nothing about the rest of the flow. An
unauthenticated authorize request against the same host on 2026-09-09
returned `302` to the redirect URI with
`error=invalid_request&error_description=ClientId test from the request not
found`, and `POST /connect/register` returned `404`. So the client has to be
registered out of band; there is no dynamic client registration on the
hosted instance. Whether the operators will register a third-party client at
all, and whether the host is intended to stay up, was not established and is
unverified. Running the QTSP locally sidesteps the question, at the cost of
standing up MySQL and an OpenID4VP verifier.

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

### 3.5 Sandboxes reached directly

Two of the three shortlisted sandboxes answer `info` without credentials.
Both were called on 2026-09-09; the values below are from the live
responses.

| Field | PrimeSign `qs.primesign-test.com` | Cleverbase `signing.lab.cleverbase.io` |
| --- | --- | --- |
| `specs` | `2.1.0.1` | `2.2.0.0` |
| `name` | `primesign MOBILE` | `Cleverbase CSC V2 Testbed` |
| `region` | `AT` | `NL` |
| `authType` | `["oauth2code"]` | `["oauth2code"]` |
| `oauth2` | `https://id.primesign-test.com/realms/qs-staging/` | `https://signing.lab.cleverbase.io/idp` |
| `supportsRar` | `true` | `false` |
| `supportedHashTypes` | `["dtbsr"]` | `["2.16.840.1.101.3.4.2.1"]` |
| `methods` | `credentials/list`, `credentials/info`, `signatures/signHash` | `oauth2/authorize`, `oauth2/pushed_authorize`, `credentials/list`, `credentials/info`, `signatures/signHash` |
| Signature algorithms | ECDSA over SHA-256/384/512, several SHA-3 variants, RSASSA-PSS with DER `signAlgoParams`, and `0.4.0.127.0.7.1.1.4.1` | ECDSA with SHA-256 only |

Three differences here are exactly the interoperability surface a client has
to handle. `supportedHashTypes` is a keyword on one service and an OID on
the other. `supportsRar` is true on one and false on the other, so a client
needs both the `authorization_details` form and the plain query form.
Cleverbase advertises `oauth2/pushed_authorize`, which the CSC method list
in section 1.2 does not contain, so the `methods` array can carry
service-specific extensions. None of this is discoverable without calling
`info` first.

The reproduction commands:

```sh
curl -s -X POST https://qs.primesign-test.com/csc/v2/info \
  -H 'Content-Type: application/json' -d '{}'
curl -s -X POST https://signing.lab.cleverbase.io/csc/v2/info \
  -H 'Content-Type: application/json' -d '{"lang":"en"}'
```

## 4. Timestamp authorities

### 4.1 What "qualified" means operationally

Under eIDAS a timestamp authority is qualified only if a Member State's
trusted list carries a `QTST` service entry for it with status `granted`.
That list, not a vendor page, is the authority. The machine-readable
entry points are the
[EU list of trusted lists](https://ec.europa.eu/tools/lotl/eu-lotl.xml),
the
[trusted list browser](https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls)
with its
[Hungarian view](https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls/tl/HU),
and the Hungarian list published by the supervisory body NMHH at
[HU_TL.xml](https://www.nmhh.hu/tl/pub/HU_TL.xml) (also as
[HU_TL.pdf](https://www.nmhh.hu/tl/pub/HU_TL.pdf)). This matches the trust
material model already described in [trust.md](trust.md).

Parsing the Hungarian list gives exactly four providers with granted
qualified timestamp services: Microsec, NETLOCK, Magyar Telekom and NISZ.

### 4.2 Endpoints

Every "granted" or HTTP status below was observed on 2026-09-09 by posting
a real RFC 3161 `TimeStampReq` with `Content-Type:
application/timestamp-query`. "Granted" means the response carried
`Status: Granted`; it says nothing about whether the token would satisfy
any particular legal requirement.

Qualified and EU services:

| TSA | Country | Qualified | Endpoint | Credentials | Observed |
| --- | --- | --- | --- | --- | --- |
| Microsec e-Szigno, client certificate | HU | Yes, HU trusted list | `https://tsa.e-szigno.hu/tsa` | TLS client certificate | Handshake failure without a client certificate |
| Microsec e-Szigno, basic auth | HU | Yes | `https://btsa.e-szigno.hu/tsa` | Account | HTTP 401 anonymously |
| Microsec e-Szigno test service | HU | No, test unit | `https://bteszt.e-szigno.hu/tsa` | `test` / `test` | Granted; policy `1.3.6.1.4.1.21528.2.2.99`, unit `CN=Test e-Szigno TSA 2025 01` |
| NETLOCK | HU | Yes | Not published | Paid contract; URL issued on signing | Not reachable to test |
| Magyar Telekom, NISZ | HU | Yes | Not published | Contract | Not reachable to test |
| Sectigo qualified | ES, UK | Yes | `http://timestamp.sectigo.com/qualified` | None | Granted; policy `0.4.0.2023.1.1` |
| FPS BOSA | BE | Yes | `http://tsa.belgium.be/connect` | None | Granted; policy `2.16.56.13.6.3.1.1000`; terms restrict it to non-commercial use |
| DigiCert Europe (QuoVadis) | NL | Yes | `http://ts.quovadisglobal.com/eu` | Docs ask for IP registration | Granted anonymously in the probe |
| APED | GR | Yes | `https://timestamp.aped.gov.gr/qtss` | None | Granted; policy `1.2.300.0.110001.2.1.2` |
| ACCV | ES | Yes | `http://tss.accv.es:8318/tsa` | None | Granted; policy `1.3.6.1.4.1.8149.3.100.2.0` |
| Izenpe | ES | Yes | `http://tsa.izenpe.com` | None documented | Granted; policy `1.3.6.1.4.1.14777.300.1` |
| Cartao de Cidadao | PT | Yes | `http://ts.cartaodecidadao.pt/tsa/server` | None | Granted; policy `0.4.0.2023.1.1` |
| SK ID Solutions, production | EE | Yes | `http://tsa.sk.ee/ecc`, `http://tsa.sk.ee/rsa` | Contract | HTTP 403 |
| SK ID Solutions, demo | EE | No | `http://tsa.demo.sk.ee/tsa` | None | Granted; policy `0.4.0.2023.1.1` |
| Actalis | IT | Company is a QTSP; this endpoint's status unknown | `http://timestamp.actalis.com` | None | Granted; policy `1.3.159.8.2.1` |
| Namirial | IT | Yes | `https://timestamp.namirialtsp.com` | Account | HTTP 401 |
| Uanataca | ES | Yes | `https://tsa.uanataca.com/tsa/tss02`, sandbox `https://tsa.sandbox.uanataca.com/tsa/tss03` | Account | HTTP 401 |
| InfoCert | IT | Yes | `https://digitaltimestamp.infocert.it/idts-rest/dts/timestamp` | Paid | HTTP 401 |
| ANF AC | ES | Yes | `https://tsu.anf.es/TimeStampServer/ANFTimeServer` | Account | HTTP 401 |
| Evrotrust | BG | Yes | `http://ts.evrotrust.com/tsa` | Policy says anonymous for private non-commercial use | Returned `TSA Response error.`; not usable anonymously on the day |
| D-Trust | DE | Yes | `https://timestamp.d-trust.net` | Paid contract | HTTP 401 |
| GlobalSign qualified | BE | Yes | Not published | Contract | Not reachable to test |
| Certum qualified | PL | Yes | Sold through the vendor's shop | Paid | Not reachable to test |
| TrustPro | IE | Yes | Not published | Paid | Not reachable to test |
| SwissSign | CH | Swiss ZertES qualified, not EU | `http://tsa.swisssign.net` | Contractually customers only, IP checked | Granted; policy `2.16.756.1.89.1.1.3.5` |

Free and non-qualified services, useful for tests:

| TSA | Endpoint | Credentials | Observed and terms |
| --- | --- | --- | --- |
| freetsa.org | `https://freetsa.org/tsr` | None | Granted; the only stated condition is not to abuse it. No code-signing or non-commercial clause found |
| DigiCert | `http://timestamp.digicert.com` | None | Granted; policy `2.16.840.1.114412.7.1`. No timestamp-specific terms published |
| Sectigo | `http://timestamp.sectigo.com` | None | Granted; policy `1.3.6.1.4.1.6449.2.1.1`. Documented guidance to wait 15 seconds or more between scripted requests |
| Certum | `http://time.certum.pl` | None | Granted; policy text says free for private, commercial and non-commercial customers |
| DFN-Verein | `http://zeitstempel.dfn.de` | None | Granted; usable only within the DFN statutes, so non-commercial only |
| Apple | `http://timestamp.apple.com/ts01` | None | Granted; no public terms, documentation assumes Apple code signing |
| SSL.com | `http://ts.ssl.com` | None in practice | Granted; free tier documented at 10000 timestamps per year |
| Entrust | `http://timestamp.entrust.net/TSS/RFC3161sha2TS` | None | Granted, but the responding unit was `Sectigo Public Time Stamping Signer R37` |
| GlobalSign | `http://timestamp.globalsign.com/tsa/r6advanced1` | None in practice | Granted; marketed for code signing customers, issuance at the vendor's discretion |
| Microsoft | `http://timestamp.acs.microsoft.com` | None | Granted; intended for Trusted Signing customers |
| IdenTrust | `http://timestamp.identrust.com` | None | Granted; policy `2.16.840.1.113839.0.6.13.3` |
| CESNET | `http://tsa.cesnet.cz:3161/tsa` | None | Granted; academic network, so likely non-commercial |
| Lex Persona | `http://tsa.lex-persona.com/tsa` | None | Granted; policy `1.3.6.1.4.1.22542.3.2.0` |
| rfc3161.ai.moda | `http://rfc3161.ai.moda` | None | Granted, but it is a proxy that returned tokens from different issuers on different paths; unsuitable when the issuer must be known |

### 4.3 What this means for openSzigno

The Hungarian answer is clean and useful. Microsec runs a test timestamp
service at `https://bteszt.e-szigno.hu/tsa` that answers with `test` /
`test` and issues tokens under a test policy OID from a unit whose subject
says "Test". That is the right fixture for a timestamping test in this
project: it is Microsec's own service, it is unambiguously a test unit, and
it cannot be mistaken for a qualified token. Production Microsec
timestamping needs either a client certificate or an account, so it is not
something a contributor can exercise.

For non-Hungarian tests, `https://freetsa.org/tsr` is the least
encumbered endpoint found: it is the only widely used free service with no
non-commercial clause and no implied tie to the operator's own
certificates. `http://timestamp.sectigo.com/qualified` is the only endpoint
found that is both on a trusted list and answers anonymously, which makes
it the cheapest way to obtain a real qualified token for a shape check.

Two cautions. First, the absence of a published restriction is not
permission: DigiCert and Sectigo publish no timestamp-specific terms at
all, so their free endpoints should be recorded as unknown rather than
allowed. Second, a timestamp is a second, independent dependency with its
own account model, and it decides more about what a `sign` command can
produce than the signer does; an ES3 signature that needs a timestamp
cannot be completed by a CSC credential alone.

## 5. Hungarian acceptance

This section is research into what Hungarian systems accept. It is not legal
advice, and nothing in it says that a document openSzigno produces would be
accepted anywhere. Hungarian law was read at `net.jogtar.hu` and
`njt.jog.gov.hu`; `njt.hu` itself was not reachable from this environment.
On `njt.jog.gov.hu` a bare `/jogszabaly/<id>` path returns the current
consolidation while a trailing `.0` returns the first time state, which is
an easy way to read a repealed version by accident.

### 5.1 The 2024 reset

The legal baseline moved in 2024, and any design premised on the older
framework is out of date. The electronic administration act, 2015. evi
CCXXII. torveny, was repealed with effect from 1 September 2024 by section
121 of the digital state act, 2023. evi CIII. torveny, referred to below as
the Daptv.
([repealed act](https://njt.jog.gov.hu/jogszabaly/2015-222-00-00),
[Daptv.](https://net.jogtar.hu/jogszabaly?docid=a2300103.tv)). The Code of
Civil Procedure now routes its electronic contact rules through the Daptv.,
and AVDH, the identification-based document authentication service that was
the free option for a citizen without a certificate, is gone for ordinary
users.

| Date | What changed | Source |
| --- | --- | --- |
| 2024-09-01 | 2015. evi CCXXII. repealed; DAP eAlairas and eAzonositas go live | Daptv. sections 119(1) and 121 |
| 2024-12-31 | Last day AVDH had to be offered on the personalised administration surface; documents authenticated with AVDH up to this date keep full probative force | Daptv. section 119(2); Pp. section 634(15) |
| 2025-01-01 | Citizen AVDH ceases; survives only inside organisations and through ePapir | Daptv. section 119(2); [kormanyhivatalok.hu](https://kormanyhivatalok.hu/hirek/januar-1-tol-az-avdh-hitelesites-az-epapir-szolgaltatasban-erheto-el) |
| 2025-10-31 | Last day AVDH may be offered integrated with the support service | Daptv. section 119(2) |
| 2025-11-01 | FEDOR replaces it in ePapir; the exact date is inferred and unverified | [szeusz.gov.hu](https://szeusz.gov.hu/szeusz/FEDOR) |
| 2026-04-29 | EU trusted lists move from TLv5 to TLv6 with no transition period; the Hungarian list is republished as v6 and moves from HTTP to HTTPS | [NMHH notice](https://nmhh.hu/cikk/258606/Tajekoztatas_a_Bizalmi_lista_uj_verziojara_TLv6_valo_atallasrol) |

The last row is the one that touches existing code rather than future code.
A validator that hard-codes TLv5 parsing, or an `http` trusted-list URL,
starts failing after 29 April 2026. That belongs in
[trust.md](trust.md) and on the roadmap, independently of anything in this
document.

### 5.2 Courts

Filing is by iFORM form on the personalised administration surface, sent
through the citizen, company or authority gateway; signed documents ride as
attachments
([birosag.hu](https://birosag.hu/ugyfeleknek/elektronikus-ugyintezes/elektronikus-kapcsolattartas-birosagokkal)).
Sections 605(1) and 608(1) of the Code of Civil Procedure, 2016. evi CXXX.
torveny, require submission in the manner set by the Daptv. and its
implementing decrees, and section 618(1)(b) supplies the sanction: filed
electronically but not in the prescribed manner means a statement of claim
is rejected and any other submission's declaration is ineffective
([Pp.](https://net.jogtar.hu/jogszabaly?docid=A1600130.TV)).

The court service's own IT guidance names the accepted attachment
containers verbatim:

> Az űrlaphoz .dosszie, .dossier, .es3, .etv, .eak, .et3, .nsack, .pdf,
> .asic, illetve .asice formátumban csatolható melléklet.

Inside an e-akta the permitted file types are `.odt`, `.doc`, `.docx`,
`.pdf`, `.txt`, `.xlsx`, `.ods`, `.tif`, `.tiff`, `.bmp`, `.jpg`, `.jpeg`,
`.png`, `.mp4`, `.m4a`, `.avi`, `.mp3` and `.wav`. The caps are 150 MB per
file and 300 MB in total, with an `.xcz` helper application for anything
larger. The same page describes the return direction:

> A bíróság a kézbesítési rendszer útján megküldött bírósági iratokat
> tömörített, összecsomagolt formában (.zip állományban) és ezen belül az
> egyes iratokat szervezeti elektronikus aláírással ellátva e-aktában
> (.dosszie állományban) vagy .pdf fájlban küldi meg. Az e-akta
> megnyitásához … telepítve kell lennie a Microsec e-Szigno vagy a NetLock
> MOKKA programok valamelyikének.

([informatikai segedlet](https://birosag.hu/ugyfeleknek/elektronikus-ugyintezes/elektronikus-kapcsolattartas-birosagokkal/e-per/e-kapcsolattartas-az-egyes-ugytipusokban/polgari-gazdasagi-munkaugyi-es-kozigazgatasi-ugyek/informatikai-segedlet-az-elektronikus-beadvanyok)).
That sentence is the plainest statement of why this project exists: the
Hungarian courts hand citizens a signed `.dosszie` and name two proprietary
Windows programs as the way to open it.

What level of signature a private party needs is set by section 12(1) of
451/2016. (XII. 19.) Korm. rendelet, still in force
([current text](https://njt.jog.gov.hu/jogszabaly/2016-451-20-22)). A
document is authentic if it qualifies as a private document of full
probative force, or bears at least an advanced electronic signature or seal
of the declarant, or is in the document validity register, or was
authenticated through AVDH, or was recorded in the body's closed system, or
by other statutory means, with a timestamp added where a statute requires
one. Section 12(5) lets a specific statute demand a qualified signature, or
an advanced one on a qualified certificate. So the courts do not
categorically demand a qualified signature: advanced is the floor, and the
company registry is where the ceiling is raised.

The court service's electronic litigation FAQ says the same operationally:

> Amennyiben a nyomtatványt és valamennyi mellékletét is minősített vagy
> minősített tanúsítványon alapuló fokozott biztonságú elektronikus
> aláírással vagy elektronikus bélyegzővel látta el, úgy nem szükséges
> egyéb dokumentumhitelesítési szolgáltatással történő hitelesítés.

It adds that the judge in the case checks whether the signature is present
and calls for correction if it is not, so acceptance is decided per case
rather than by an automated gate
([e-per GYIK](https://birosag.hu/ugyfeleknek/elektronikus-ugyintezes/elektronikus-kapcsolattartas-birosagokkal/e-per/gyik)).

Two Hungarian specifics matter for a reader as much as for a signer. First,
section 634(15) of the Code of Civil Procedure grandfathers documents
authenticated with AVDH up to 31 December 2024: they remain private
documents of full probative force. A verifier will keep meeting AVDH
structures indefinitely, so nothing on the read path should treat them as
obsolete. Second, section 325(3a) of the same code and sections 8(40) to
8(42) and 105 to 107 of the Daptv. introduce a role certificate,
`szerepkor-tanusitvany`, as a way to prove the signer's role at the moment
of signing. That is a signature attribute mechanism with no eIDAS-standard
equivalent, and it is worth knowing about before designing anything that
reports "who signed".

### 5.3 The company registry

Here the requirement is statutory and strict. Section 36(2) of the
Companies Act, 2006. evi V. torveny
([Ctv.](https://net.jogtar.hu/jogszabaly?docid=a0600005.tv)):

> A cégbejegyzési (változásbejegyzési) eljárás során az elektronikus úton
> küldött okiratokat minősített elektronikus aláírással és minősített
> időbélyegzővel kell ellátni, oly módon, hogy az időbélyegző alapján a
> minősített elektronikus aláírás használatára való jogosultság - az okirat
> aláírásának időpontjában való - fennállása megállapítható legyen. A jogi
> képviselő e kötelezettséget úgy is teljesítheti, ha a cégbejegyzési
> (változásbejegyzési) kérelmet látja el minősített elektronikus aláírással
> és minősített időbélyegzővel.

A qualified signature and a qualified timestamp, both, arranged so the right
to use the signature can be established as of the signing time. The
paragraph also allows an attorney or chamber legal counsel to use the
signature and seal defined in the Attorneys Act, and states that a document
sent by the company court is a public document. Section 36(1) makes
electronic filing mandatory. The implementing decree, 24/2006. (V. 18.) IM
rendelet, repeats the requirement in section 6
([decree](https://net.jogtar.hu/jogszabaly?docid=a0600024.im)).

The Ministry of Justice company information service publishes the accepted
attachment formats:

> A csatolt okiratok formátuma sima szöveg (text) és PDF lehet, vagy olyan
> ES3, illetve DOSSZIE kiterjesztésű elektronikus akta, amelyben az
> előzőleg felsorolt formátumú iratok szerepelnek.

with scanning rules of at least 300 dpi, black and white rather than colour
or greyscale, PDF, no blank pages, and a total of about 25 MB
([kerelem tartalma](https://ceginformaciosszolgalat.kormany.hu/kerelem-tartalma-iratok)).
The same service's page on the authority gateway channel is the single most
actionable page found in this whole survey:

> A cégbíróságra küldendő beadványt a CEGSZOLG rövid nevű (602744715 KRID)
> hivatali kapun keresztül egy elektronikusan aláírt e-aktában kell
> beküldeni. Az e-aktában szerepelnie kell a sémadefiníciónak megfelelő 1
> darab XML fájlnak, amennyiben szükséges további PDF dokumentumok
> csatolható(ak). Az e-aktát legalább XAdES-T típusú (időbélyeges) fokozott
> biztonságú vagy minősített keretaláírással kell ellátni. Az aláíró
> tanúsítvány lehet az EIDAS szerinti személyes aláíró tanúsítvány is,
> illetve az EIDAS szerinti bélyegző (szervezeti) tanúsítvány is. Az
> aláírásnak érvényesnek kell lennie. Az e-aktát közvetlenül, további
> átalakítás, vagy csomagolás nélkül kell feladni a hivatali kapun
> keresztül.

If what arrives is not an e-akta the submission is rejected outright;
otherwise an automated check runs and returns a delivery receipt with any
errors in an attached HTML file
([hivatali kapu channel](https://ceginformaciosszolgalat.kormany.hu/cegbirosagi-elektronikus-kommunikacio-hivatali-kapun-keresztul)).
That page also links a binding
[certificate profile](https://ceginformaciosszolgalat.kormany.hu/download/7/24/82000/tanusitvanyprofil_1_0_vegleges.pdf)
for accepted end-user certificates, referencing RFC 5280, RFC 4043
permanent identifiers, and ETSI EN 319 412-1, -2 and -5, and constraining
algorithms, key sizes and subject fields. Its field-level detail was not
recovered reliably and is unverified.

An older, now unreachable version of the same guidance made the format
mapping explicit; the live URL returns HTTP 400, and the text is from the
Internet Archive snapshot of 2023-09-23
([archived page](https://web.archive.org/web/20230923035747/https://www.e-cegjegyzek.hu/e-cegeljaras/e_cegeljaras_technika.htm)):

> A Ctv. 36. § (2) bekezdés alapján a cégeljárásban az elektronikusan
> küldött okiratokat minősített elektronikus aláírással és időbélyeggel kell
> ellátni. Ez XAdES-T típusú aláírást jelent, amit az e-Szignó vagy Mokka
> aláíró programban kell beállítani. A XAdES-T-nél több információt
> tartalmazó, a későbbi ellenőrzést megkönnyítő aláírás is alkalmazható
> (XAdES-X-L és XAdES-A típusú).

One tension is worth flagging rather than resolving. The Companies Act says
qualified; the channel page says advanced or qualified. The channel page is
best read as the transport-layer minimum and the Act as the substantive
obligation, but no source reconciling the two was found, so that reading is
unverified.

AVDH is unusable in company proceedings, because section 36(2) demands a
qualified signature and AVDH is an organisational seal over an identity
attestation rather than the signer's own signature, and because the Daptv.
sunset removed it. No express provision excluding AVDH from company
proceedings was found, so the exclusion is inferred.

### 5.4 Public administration, and what replaced AVDH

Section 112(4) of 451/2016 gave AVDH its legal weight: a document issued
under that section is a private document of full probative force. Section
112(1) describes the mechanism, an identity attestation placed in or
alongside the document and authenticated with a qualified or
qualified-certificate-based advanced electronic seal plus a qualified
timestamp. Section 113 is the organisation-side variant, and section 113(4)
makes such a document a public document when issued by a court, notary,
prosecutor or authority. Both sections are still in the current text of
451/2016; the sunset was done in the Daptv. transitional rules, not by
repealing them.

Three services now occupy the space:

| Service | What it produces | Legal weight | Source |
| --- | --- | --- | --- |
| DAP eAlairas | A qualified electronic signature for a natural person, free of charge | Daptv. section 54(2): capable of creating a private document of full probative force and a public document | [hiteles.gov.hu](https://hiteles.gov.hu/cikk/165/dap_ealairas_szolgaltatas), [services.gov.hu](https://services.gov.hu/dap-keretszolgaltatasok/ealairas) |
| FEDOR | An identity attestation attached to the document, sealed by the provider with an advanced seal on a qualified certificate plus a qualified timestamp | Authentic, but explicitly not a private document of full probative force | [szeusz.gov.hu](https://szeusz.gov.hu/szeusz/FEDOR), [322/2024. (XI. 6.) Korm. rendelet](https://net.jogtar.hu/jogszabaly?docid=A2400322.KOR) |
| AVDH, organisation-side remnant | Authentication of a declaration by a person acting for an administration body | 451/2016 section 113(4) | [451/2016](https://njt.jog.gov.hu/jogszabaly/2016-451-20-22) |

Section 54(7) of the Daptv. sets the operational limit on DAP eAlairas:

> A felhasználó az eAláírást magánszemélyként használja. Az eAláírás nem
> tanúsít attribútumot.

Read precisely, that says the user signs as a natural person and the
signature certifies no attribute. It does not forbid a director or an
attorney from using it; it means the signature evidences the person and
never the capacity, which has to be proved separately, for instance through
the role certificate track. That is why DAP eAlairas does not substitute
for an attorney's qualified certificate in company proceedings. Section
8(38) of the Daptv. defines the qualified electronic signature by reference
to Article 3(12) of eIDAS, and sections 8(36) and 8(37) do the same for
qualified trust services and providers.

FEDOR is not a signature at all. Its service page says so:

> A FEDOR Szolgáltatója minősített tanúsítványon alapuló fokozott
> biztonságú elektronikus bélyegzővel és minősített időbélyegzővel
> hitelesíti az eredeti dokumentumot és a hozzá kapcsolt igazolást. A
> FEDOR-ral hitelesített elektronikus dokumentum hiteles, de nem minősül
> teljes bizonyító erejű magánokiratnak.

Sections 72/A and 72/B of 322/2024 add that the attestation may prove the
user's right to make the declaration but does not extend to proving
authority to represent anyone. The substantive downgrade against AVDH is the
point: AVDH produced a private document of full probative force, FEDOR does
not.

For openSzigno, none of the three is a CSC endpoint. DAP eAlairas is the
most likely qualified signature a Hungarian natural person will hold and it
is free, but it is delivered through a mobile application and no
third-party API for it was found. That is unverified rather than ruled out,
and it is the single question most worth asking a Hungarian authority
directly.

### 5.5 Formats

The format anchor is EU law. Section 7(c) of 137/2016. (VI. 13.) Korm.
rendelet requires a signature or seal to meet the requirements of
Commission Implementing Decision (EU) 2015/1506
([137/2016](https://njt.jog.gov.hu/jogszabaly/2016-137-20-22.0)). That
decision requires Member States to recognise XAdES, CAdES and PAdES
advanced signatures and seals at conformance level B, T or LT, and
signatures using an Associated Signature Container, against ETSI TS 103171,
103173, 103172 and 103174 respectively
([Decision (EU) 2015/1506](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32015D1506)).
So all four families are legally recognised; what varies by venue is the
container and the level.

| Venue | Container | Signature |
| --- | --- | --- |
| Courts, iFORM attachments | `.dosszie`, `.dossier`, `.es3`, `.etv`, `.eak`, `.et3`, `.nsack`, `.pdf`, `.asic`, `.asice` | At least advanced, per 451/2016 section 12(1)(b) |
| Courts to a party | `.zip` containing `.dosszie` or `.pdf` | Organisational electronic seal |
| Company registry, attachments | Plain text, `.pdf`, or an ES3 or DOSSZIE e-akta wrapping those | Qualified signature and qualified timestamp, Ctv. section 36(2) |
| Company registry, CEGSZOLG gateway | One e-akta holding one schema-conformant XML plus optional PDFs, sent unwrapped | At least a XAdES-T frame signature, advanced or qualified, personal or seal certificate |

The `.es3` and `.dosszie` e-akta is a Microsec format and is XAdES
underneath: the
[e-akta specification v1.5](http://static.e-szigno.hu/e-akta/e-akta_specifikacio_v1.5.pdf)
defines its structure by reference to XAdES, and the
[e-Szigno CLI reference](https://download.e-szigno.hu/eszigno/docs/eszigno3_ref.html)
shows the same tool also building and verifying ASiC. `.eak` and `.nsack`
are the NetLock MOKKA equivalents.

One asymmetry is worth stating plainly, because it decides a default. The
courts accept `.asic` and `.asice`; the company registry attachment list
does not mention ASiC at all. A tool that emits ASiC by default works for
court filings and fails for company proceedings. Whether ASiC is in fact
accepted in company proceedings is unverified.

The safest single target for Hungarian practice is therefore a XAdES-T or
higher frame signature over an e-akta, with a qualified certificate and a
qualified timestamp. That one shape satisfies the Companies Act, the
CEGSZOLG channel specification, and the courts' advanced floor at once.

### 5.6 Cross-border acceptance under eIDAS

Article 25 of Regulation (EU) No 910/2014
([original text](https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:32014R0910)):

> 1. An electronic signature shall not be denied legal effect and
>    admissibility as evidence in legal proceedings solely on the grounds
>    that it is in an electronic form or that it does not meet the
>    requirements for qualified electronic signatures.
> 2. A qualified electronic signature shall have the equivalent legal
>    effect of a handwritten signature.
> 3. A qualified electronic signature based on a qualified certificate
>    issued in one Member State shall be recognised as a qualified
>    electronic signature in all other Member States.

Hungarian law receives this by reference rather than by re-legislating it:
section 8(38) of the Daptv. defines the qualified electronic signature as
the eIDAS Article 3(12) concept, with no nationality qualifier. So
"minositett elektronikus alairas" in section 36(2) of the Companies Act is
the eIDAS concept, and the answer to the question as asked is yes: a
qualified signature from a qualified trust service provider in another
Member State has, in Hungary, the legal effect of a handwritten signature.
The CEGSZOLG channel page says as much on its face, accepting an eIDAS
personal signing certificate or an eIDAS seal certificate without naming a
country.

The friction is formal, not national, and it is where a foreign signature
actually fails:

- Section 36(2) also requires a qualified timestamp bound to the signature.
  A foreign qualified signature delivered as a plain PAdES-B with no
  qualified timestamp does not satisfy it, whatever Article 25 says about
  the signature.
- The company registry path requires an e-akta. A perfect foreign qualified
  signature in a perfect ASiC container is rejected by the CEGSZOLG channel
  for the container alone.
- The company information service's certificate profile constrains subject
  fields and algorithms. Whether a conforming foreign qualified certificate
  passes that profile in practice could not be established and is
  unverified.

No primary source was found for any Hungarian system rejecting foreign
trusted-list issuers, and none was found asserting one either. The absence
of a found rule is not evidence that none exists.

## 6. Recommendation

### 6.1 Build one backend: CSC API v2, hash signing only

openSzigno should implement a single remote signing backend speaking CSC
API v2 `signatures/signHash`, and nothing else, for four reasons.

1. It is the only protocol with more than one independent server-side
   implementation reachable without a contract. Section 3.5 shows two live
   sandboxes from different vendors, plus the EUDI reference deployment,
   all answering `info` today.
2. It is the protocol the EU wallet ecosystem is standardising on. The
   reference QTSP, both mobile rQES kits, and both wallet-role client
   libraries are CSC clients (section 2.1), and the ARF defines a Remote
   Signing or Sealing Interface for exactly this role (section 2.5).
3. `signHash` keeps the document on the user's machine. Only a digest
   leaves. That matches this project's existing posture, where a dossier is
   private data and the tool is offline by default.
4. It leaves openSzigno owning the XAdES construction, which is the part
   that has to be right anyway for `create`, rather than delegating it to
   `signatures/signDoc` on a server whose XAdES output the project cannot
   control or test.

The corollary is what not to build. No `signatures/signDoc`, because the
server would then decide the XAdES profile, and section 5.3 shows the
profile is exactly what Hungarian practice constrains. No CSC v1 support in
the first release: `info` reports `specs`, so a v1 service can be detected
and refused with a clear message rather than half-supported. No
vendor-specific protocols, which would mean one adapter per provider with no
shared surface.

### 6.2 The target output shape

Section 5 settles what `sign` has to produce for Hungarian use, and it is
more than a signature. The target is a XAdES-T or higher frame signature
over an e-akta, with a qualified certificate and a qualified timestamp.
Three consequences follow:

- A CSC credential alone is not enough. Without a timestamp there is no
  XAdES-T, and without XAdES-T there is no company-registry filing. The
  timestamp backend is not a later refinement; it is half the feature.
- The frame signature model, one signature over the whole e-akta rather
  than one per document, is what section 36(2) of the Companies Act permits
  and what the CEGSZOLG channel expects. It is also the cheaper thing to
  build, since it needs one `signHash` call rather than one per attachment.
- ASiC output would be accepted by the courts and rejected by the company
  registry. If only one container is built, it should be the e-akta.

### 6.3 Which services to test against

Test against three, in this order.

| Target | Why | Cost of setup |
| --- | --- | --- |
| EUDI reference QTSP, run locally with `docker compose` | The reference implementation of the flow, Apache-2.0, inspectable when something disagrees | MySQL plus an OpenID4VP verifier; the heaviest of the three |
| PrimeSign test service | `specs` 2.1.0.1, `supportsRar` true, `dtbsr` hashes, RSASSA-PSS and ECDSA; the closest match to what a European signer would meet at a commercial QTSP | Request access codes from the vendor |
| Cleverbase testbed | `specs` 2.2.0.0, `supportsRar` false, hash type given as an OID; the deliberate opposite of PrimeSign on every discovery field | Vendor onboarding, extent unknown |

Two commercial sandboxes rather than one is not redundancy. PrimeSign and
Cleverbase disagree on `supportsRar` and on the encoding of
`supportedHashTypes`, so a client that works against both has actually
exercised its discovery logic instead of hard-coding one vendor's answers.

For the timestamp half, `https://bteszt.e-szigno.hu/tsa` with `test` /
`test` is the right fixture: Microsec's own test unit, unambiguously not
qualified, and reachable by any contributor. `https://freetsa.org/tsr` is
the least encumbered non-Hungarian alternative.

Hungarian signing providers are not on this list, because neither Microsec
nor NetLock publishes an API a client could be written against (section
3.2). That is a finding, not an oversight. If openSzigno is to sign for
Hungarian use, someone has to ask Microsec directly whether their remote
signing is reachable over CSC or any other third-party API, and ask the
same about DAP eAlairas, which is the qualified signature most Hungarian
natural persons will actually hold.

### 6.4 What a sandbox test needs

- A registered OAuth 2.0 client. The EUDI reference host has no dynamic
  client registration, and its authorize endpoint rejects an unknown
  `client_id` (section 2.3), so every target needs credentials obtained out
  of band.
- A loopback redirect listener bound to `127.0.0.1` on an ephemeral port,
  in the RFC 8252 native-application style, plus PKCE with S256.
- A way to open a browser and a way to work without one. A signer on a
  headless machine still needs to see the consent screen, so the fallback
  is to print the authorize URL and read the redirect back from the user.
- A test dossier from `tests/fixtures/` and a synthetic hash path, so the
  first end-to-end run signs something the project already knows how to
  parse.
- A recorded transcript. The `info` response of every target should be
  captured as a fixture, because the whole design branches on it and it
  changes without notice: the EUDI QTSP's README says CSC v2.0 while the
  deployment reports `2.2.0.0`.
- A verification step that closes the loop. A signature is evidence that
  the flow worked only if `openszigno verify` can be pointed at the result.
  Until the produced XAdES verifies against the existing pipeline, a
  successful `signatures/signHash` call proves only that the network call
  succeeded.

### 6.5 Open risks

| Risk | Why it matters | What reduces it |
| --- | --- | --- |
| Canonicalisation error under `dtbsr` | The service signs the digest handed to it and never sees the document, so a C14N mistake yields a syntactically perfect signature over the wrong bytes | Verify every signature the tool produces with the project's own verifier before reporting success; treat an unverifiable output as a failure of `sign`, not a warning |
| Discovery drift | `specs`, `supportsRar` and `supportedHashTypes` vary per vendor and change per deployment | Branch on `info` at run time; never compile a vendor profile into the code |
| No Hungarian backend | The format is Microsec's, but no Microsec or NetLock API is documented, and DAP eAlairas has no known third-party interface | Ask the vendors and the authority; do not design around an assumed API |
| Qualified status cannot be asserted by this tool | Producing a signature through a qualified provider does not let openSzigno claim the result is a qualified signature, and this project's rules forbid claiming validity that is not proven in code | Report what the service returned and what the verifier checked, and nothing more |
| SAD scope | A credential authorisation not bound to the real hashes authorises signing anything for its lifetime | Always send the actual hashes, and `numSignatures` equal to the number of signatures being produced |
| Timestamping is a second dependency | Without it there is no XAdES-T, and without XAdES-T there is no company-registry filing; production Hungarian timestamping needs a client certificate or an account | Decide the TSA before the signer, not after |
| Trusted list format change | EU trusted lists move to TLv6 on 2026-04-29 with no transition, and the Hungarian list moves to HTTPS | Track it as a verify-path item independent of signing; see section 5.1 |
| Legacy AVDH structures persist | Documents authenticated with AVDH up to 2024-12-31 keep full probative force indefinitely | Nothing on the read path may treat AVDH structures as obsolete |

## What was not verified

Marked in place above, collected here.

On the CSC API:

- The text of CSC API V2.1.0.1 and V2.2. Both are behind a form on the
  consortium's download page and were not read.
- The algorithm tables in the CSC API V2.0.0.2 PDF. The PDF could not be
  converted to text in this environment, so the SHA-384 and SHA-512 rows in
  section 1.4 are standard registry values rather than values read from the
  specification.
- Which CSC API version ETSI TS 119 432 V1.3.1 references. Only the
  V1.1.1 text and secondary reporting on V1.2.1 were consulted.

On the EUDI reference implementation:

- Whether the operators of `walletcentric.signer.eudiw.dev` will register a
  third-party OAuth 2.0 client, and whether the host is intended to remain
  available. Only the open `info` endpoint and the rejection of an unknown
  `client_id` were observed.
- Whether the ARF binds a specific CSC API version, and whether the section
  numbers 2.4, 3.9 and 4.3.3 still apply in ARF v3.0.0. The chapter pages
  were read at `eudi.dev/latest`, the section numbering at the 2.4.0
  rendering.
- No EUDI code was run, built, or audited. Every statement about these
  repositories comes from their README files and, for the deployed
  instance, from its `info` response.

On providers:

- Whether Microsec offers any third-party remote signing API. No public
  developer documentation for one was found. The MicroSigner proxy server
  documentation was not found on a Microsec domain.
- NetLock's REST API documentation, its CSC conformance, its sandbox terms,
  and the figures in its price list.
- Exact CSC version numbers for InfoCert, Namirial, Intesi Group, D-Trust,
  Certinomis, certSIGN, Trans Sped, TrustPro and Digidentity, and whether
  Entrust's Remote Signing Service has moved beyond CSC 0.1.7.9.
- Sandbox availability for InfoCert, D-Trust, Entrust, GlobalSign,
  Certinomis, Digidentity and most Iberian and Romanian providers.
- Published pricing for every provider except D-Trust portal coins,
  TrustPro and Camerfirma.
- Whether SK ID Solutions is a Cloud Signature Consortium member. A member
  subpage was reported but the name was not on the members index that was
  fetched.
- Beyond `info`, no authenticated CSC call was made against any service.
  No credential was obtained, and no hash was signed.

On timestamp authorities:

- Endpoint URLs for NETLOCK, D-Trust, GlobalSign qualified, Certum
  qualified, TrustPro and Buypass. None publishes one.
- Microsec's production policy OIDs, and the URL paths on the `tsa2`,
  `tsa3`, `atsa` and `timestamp.e-szigno.hu` hosts named in the vendor's
  service address list.
- SwissSign's terms of use, which returned HTTP 403.
- Whether `timestamp.actalis.com` issues qualified or only code-signing
  timestamps.
- Timestamp-specific terms of use for DigiCert and Sectigo. Neither
  publishes any, so their free endpoints are recorded as unknown rather
  than permitted.
- Rate limits for every service except Sectigo and WoTrus, both of which
  document a 15 second interval.

On Hungarian acceptance:

- The exact entry into force of section 72/A of 322/2024, the FEDOR rule.
  1 November 2025 is inferred from the AVDH sunset.
- The text of 320/2024. (XI. 6.) Korm. rendelet designating the FEDOR
  provider.
- Whether ASiC is accepted in company proceedings. The company information
  service's page lists only text, PDF, ES3 and DOSSZIE.
- Whether foreign-issued qualified certificates pass the company
  information service's certificate profile in practice, and whether any
  Hungarian system filters by the issuer's trusted-list country. No primary
  source was found either way.
- The field-level content of that certificate profile PDF; its text
  extraction was lossy.
- How the Companies Act's demand for a qualified signature is reconciled
  with the CEGSZOLG channel page allowing an advanced one. No source
  reconciling the two was found.
- Any express provision excluding AVDH from company proceedings. The
  exclusion is inferred.
- The current status and profile of the eID card's signing certificate.
- The content of the government offices' notice on the end of AVDH in
  ePapir, which returns HTTP 403. The dates come from the statute instead.
- The current replacement for the company registry technical page, whose
  URL now returns HTTP 400; its text was read from a 2023 archive snapshot.
- The detailed electronic contact rules of the Code of Civil Procedure
  beyond sections 605, 608, 618, 325 and 634.

Finally, nothing in this document has been tested against a real signing
service end to end, and no claim here should be read as saying that any
signature, timestamp, certificate or dossier is valid.
