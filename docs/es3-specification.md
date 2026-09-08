# ES3 specification and implementation map

Reviewed against openSzigno commit `8311590` on 2026-09-07.

This is an independently written engineering guide, not the official ES3
specification, a translation, or a claim of complete conformance. It connects
the published sources to this repository's implementation and tests. The
upstream specifications remain authoritative for their respective formats;
[architecture.md](architecture.md) defines openSzigno's own API and policy.

## Sources and version scope

| ID | Source | Scope |
| --- | --- | --- |
| ES3-EN | [Microsec English specification](https://srv.e-szigno.hu/edossier), v1.2, 2011-02-04 | Baseline container reference used by this implementation. Section numbers below refer to this version. |
| ES3-HU | [Hungarian e-akta specification](https://static.e-szigno.hu/e-akta/e-akta_specifikacio_v1.5.pdf), v1.5, 2015-02-20 | Selected version differences checked below; a requirement-by-requirement comparison with ES3-EN remains outstanding. |
| XSD | [Default schema](https://www.microsec.hu/ds/e-szigno30.xsd) | Structural reference; does not replace the prose requirements. |
| MIME | [IANA registration](https://www.iana.org/assignments/media-types/application/vnd.eszigno3+xml) | Media type, extensions, and encoding declarations. |
| DSIG | [XML Signature 1.1](https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/) | Reference processing, transforms, and signature verification. |
| PKIX | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | Certificate-path requirements. |
| EKU | [RFC 9336](https://www.rfc-editor.org/rfc/rfc9336.html) | Document-signing extended key usage. |

[references.md](references.md) records additional XAdES, canonicalization,
timestamp, revocation, and company-court sources and cached-file checksums.
Its [Microsec SDK and standards register](references.md#microsec-sdk-and-standards-discovery)
adds vendor comparison caveats and relevant certificate/timestamp profiles.
Checksums identify downloaded bytes; they do not establish correctness,
currency, authenticity, or permission to redistribute a document.

No equivalence between the English v1.2 and Hungarian v1.5 texts is assumed.
An entry below is not evidence of conformance to every published ES3 profile.

### Confirmed version differences

ES3-HU's change log records additional XAdES coverage, metadata clarifications,
special-purpose schemas, and exceptions. Section 5 explicitly accommodates a
`Document` containing only an empty `ds:Object`, without `DocumentProfile`.
That narrow case should not be described as inherently nonconformant to v1.5.

Our parser skips any profile-less document, a broader behavior than that
exception, and emits `document_without_profile`. The warning contract remains
unchanged here. Compare the exact shape before classifying a warning as a
format violation. See ES3-HU pp. 2 and 19; the full version audit is pending.

## Container orientation

The container is XML rooted at `es:Dossier`. It groups document payloads,
profiles, signatures, and timestamps. Profiles connect metadata to content
through identifiers and references. Payload encoding applies optional ZIP,
optional encryption, then mandatory Base64; decoding reverses that order.
Signatures use XMLDSig/XAdES. The container specifies placement and coverage,
while those standards define the underlying signature machinery.
See ES3-EN §§2–3, especially §§3.2.1.1.6, 3.2.1.2, and 3.2.1.3.

The default namespace is `https://www.microsec.hu/ds/e-szigno30#`. Prefix
spelling is not namespace identity. Profile-specific namespaces require
separate consideration. The prose takes precedence over the deliberately
more permissive XSD. See ES3-EN §§2–3.

## Implementation traceability

IDs below are repository identifiers, not upstream clause numbers. They
remain stable when entries are edited. **Implemented** means the stated
behavior has code and related tests, not that all upstream requirements have
been audited. **Partial** identifies an intentional subset or an unresolved
gap. Test links are navigation aids, not an exhaustive conformance suite.

| ID | Source locator | Current openSzigno behavior | Status | Code | Related tests |
| --- | --- | --- | --- | --- | --- |
| ES3-001 | MIME; ES3-EN §3 | Decodes UTF-8/ISO-8859-2, then checks the root's local name and allowed namespace. | Implemented | [xml.rs](../crates/openszigno-core/src/xml.rs), [parse.rs](../crates/openszigno-core/src/parse.rs) | [encoding.rs](../crates/openszigno-core/tests/encoding.rs), [namespaces.rs](../crates/openszigno-core/tests/namespaces.rs) |
| ES3-002 | ES3-EN §§3.1, 3.2.1.1 | Resolves dossier and document profile references to the expected direct child content; rejects duplicate IDs. | Implemented | [xml.rs](../crates/openszigno-core/src/xml.rs), [parse.rs](../crates/openszigno-core/src/parse.rs) | [parse_structure.rs](../crates/openszigno-core/tests/parse_structure.rs) |
| ES3-003 | ES3-EN §§3.1, 3.2.1.1 | Reads selected metadata fields; does not validate every category, custom metadata schema, or profile-specific rule. | Partial | [parse.rs](../crates/openszigno-core/src/parse.rs), [model.rs](../crates/openszigno-core/src/model.rs) | [core.rs](../crates/openszigno-core/tests/core.rs), [namespaces.rs](../crates/openszigno-core/tests/namespaces.rs) |
| ES3-004 | ES3-EN §§3.2.1.1.6, 3.2.1.2 | Decodes Base64 and ZIP-plus-Base64; reports encryption and other transform chains as unsupported. | Partial | [decode.rs](../crates/openszigno-core/src/decode.rs) | [decode_payloads.rs](../crates/openszigno-core/tests/decode_payloads.rs) |
| ES3-005 | ES3-EN §3.2.1.1.5 | Checks declared source size against decoded bytes when a declaration is present. | Implemented | [decode.rs](../crates/openszigno-core/src/decode.rs) | [namespaces.rs](../crates/openszigno-core/tests/namespaces.rs), [decode_payloads.rs](../crates/openszigno-core/tests/decode_payloads.rs) |
| ES3-006 | ES3-EN §3; compatible schemas in reference index | Uses a namespace allowlist and one common structural parser; no separate validator for each profile generation. | Partial | [lib.rs](../crates/openszigno-core/src/lib.rs), [parse.rs](../crates/openszigno-core/src/parse.rs) | [namespaces.rs](../crates/openszigno-core/tests/namespaces.rs) |
| ES3-007 | ES3-EN §3 signature provisions; DSIG §4.4.3 | Checks document/frame placement and reference coverage under the implemented scope rules. Full signature-profile semantics are not established by this check. | Partial | [scope.rs](../crates/openszigno-verify/src/scope.rs), `reference_scope_check` | [verify.rs](../crates/openszigno-verify/tests/verify.rs) |
| ES3-008 | DSIG §§3.2, 4.4.3, 6 | Recomputes reference digests and checks signature values using an explicit algorithm/transform subset. | Partial | [dsig.rs](../crates/openszigno-verify/src/dsig.rs), [policy.rs](../crates/openszigno-verify/src/policy.rs), [c14n.rs](../crates/openszigno-verify/src/c14n.rs) | [algorithms.rs](../crates/openszigno-verify/tests/algorithms.rs), [c14n.rs](../crates/openszigno-verify/tests/c14n.rs), [verify.rs](../crates/openszigno-verify/tests/verify.rs) |
| ES3-009 | PKIX §6; EKU | Builds bounded paths to supplied trust anchors; the handwritten validator has known gaps listed below. | Partial | [certs.rs](../crates/openszigno-verify/src/certs/mod.rs) | [paths.rs](../crates/openszigno-verify/tests/paths.rs), [verify.rs](../crates/openszigno-verify/tests/verify.rs) |
| ES3-010 | XAdES, RFC 3161, RFC 5280, RFC 6960 in reference index | Detects qualifying properties and reports claimed signing time; full XAdES, timestamp, and revocation checks remain unimplemented. | Partial | [lib.rs](../crates/openszigno-verify/src/lib.rs), [dsig.rs](../crates/openszigno-verify/src/dsig.rs) | [paths.rs](../crates/openszigno-verify/tests/paths.rs), [verify.rs](../crates/openszigno-verify/tests/verify.rs) |

## Project policy and compatibility behavior

These decisions belong to openSzigno and must not be presented as general
ES3 format requirements:

- Input, node, depth, decompression, and aggregate extraction limits protect
  resources. DTD rejection, filename sanitization, no-clobber writes, and
  output-directory safety are security policy.
- Missing document profiles, missing dossier creation dates, missing source
  sizes, and some dangling references produce documented compatibility
  warnings. Some cases have a v1.5 basis as noted above; warning-based
  acceptance is not proof of upstream conformance.
- The algorithm allowlist, offline trust inputs, same-document-only reference
  resolution, and refusal of XPath/XSLT are verification policy choices.
- Nested-dossier detection and recursive extraction are CLI behavior, with
  their own depth and aggregate-size budgets.
- `validate-structure` does not run comprehensive XSD or signature validation.
  Only `verify` performs cryptographic checks. Its verdict ceiling remains
  `indeterminate`; it cannot report `valid`.

The detailed contracts remain in
[architecture.md](architecture.md#verification-boundary), including
[namespace warnings](architecture.md#conformance-warnings) and the algorithm
and extraction policies. Keep numerical limits there rather than duplicating
them in this guide.

## Known gaps and evidence still needed

The following describes the reviewed commit, not a promise that the existing
tests expose every defect:

- ES3-009: EKU handling currently checks critical extensions only and accepts
  only `anyExtendedKeyUsage`; review noncritical restrictions and
  `id-kp-documentSigning` against RFC 5280 §4.2.1.12 and RFC 9336.
- ES3-009: reaching the path-search expansion limit currently produces a
  failed check, and the chain-length limit is tested before anchor completion.
  Add boundary cases and distinguish incomplete search from disproven trust.
- ES3-008/009: synthetic signing helpers reuse the production canonicalizer.
  Existing examples and round trips need independent canonicalization,
  signature, and certificate-path comparison vectors.
  [Related documentation and test resources](references.md#related-documentation-and-test-resources)
  identifies W3C, NIST, DSS, Santuario, and OpenSSL starting points.
- ES3-003/006/007: an exhaustive clause inventory, Hungarian v1.5 comparison,
  profile-generation comparison, and full signature-profile/countersignature
  audit remain outstanding. Unmapped clauses are unassessed, not satisfied.
- ES3-010: signed certificate binding, timestamps, revocation, and qualified
  status are future work; see [roadmap.md](roadmap.md).

## Maintaining this guide

For each behavior change, identify the upstream source/version and clause,
update the corresponding ES3 ID, and link a synthetic positive or negative
test where appropriate. Label a deliberate stricter rule as project policy
and a tolerated deviation as compatibility behavior. Do not silently turn
observed tool behavior into a normative requirement.

Record source revisions and cache checksums in [references.md](references.md).
Downloaded upstream documents stay in the gitignored `refs/` cache unless
their redistribution terms have been established. This guide does not grant
rights to those documents. Use synthetic examples only; never include private
corpus paths, metadata, certificate identities, or payloads in this mapping.

For a conformance claim, first close the unmapped-clause and version gaps and
establish independent evidence. A green project test suite alone is not that
claim.
