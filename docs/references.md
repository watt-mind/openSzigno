# Reference library index

Last built: 2026-09-07

This file indexes the local reference-document cache under `refs/`
(gitignored; not committed). Every file was fetched with
`curl -L --fail --retry 3` and a normal User-Agent, then checked by content
type, size, and first lines to rule out HTML error pages. Checksums are
`sha256sum` of the file exactly as stored under `refs/`.

To reproduce the cache: re-run the download commands with the canonical
URLs below, or refresh this index from the same sources. Nothing here is
committed to git except this index file itself.

## How to read this table

- **Local path** is relative to the repository root (`refs/...`).
- **Licence / redistribution** is the source's own terms as far as could be
  determined from the page; treat anything unspecified as "all rights
  reserved, kept locally for research only, not for redistribution".
- Entries with no local path record why the fetch was not possible; none of
  these were fabricated.

---

## 1. `es3/` — Microsec e-dossier

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| e-Szignó CA — Specification of the e-Dossier Format (HTML landing page) | v1.2 (English), page undated | <https://srv.e-szigno.hu/edossier> | `refs/es3/edossier-spec.html` | `a9df6bf99d8753b956336cff5c9eaae680464259132a4eaa0cf4678ce694d0fe` | © Microsec Ltd., publicly published spec page; no explicit redistribution licence found | Primary prose specification for `.es3`; states its verbal requirements are authoritative over the XSD. No separate PDF link was found on the page itself (only a link out to the XSD and to the unrelated NMHH trusted-list PDF). |
| Az e-akta formátum specifikációja (e-akta format specification) | v1.5 | <http://static.e-szigno.hu/e-akta/e-akta_specifikacio_v1.5.pdf> | `refs/es3/e-akta_specifikacio_v1.5.pdf` | `63e5759c0fe70e6f2a4c7c4a781759f92ea2c507c8086c1c0e95f56a68330390` | © Microsec Ltd., publicly hosted PDF; no explicit redistribution licence found | Hungarian-language companion/underlying spec for the e-akta (e-dossier) container; directly relevant to `es:Dossier`/`es:Document` structure and to cross-checking the English `edossier-spec.html` prose. |
| e-Szignó default e-dossier XSD (`e-szigno30#` namespace) | schema `version="3.0"`-family, undated | <https://www.microsec.hu/ds/e-szigno30.xsd> | `refs/es3/e-szigno30.xsd` | `7a3fd72e480cd032cebfeb01ab820c82d8c233bc3747e5a04001249cb710e716` | Published as a normative machine-readable artefact by Microsec; no explicit licence text found | The default namespace XSD (`https://www.microsec.hu/ds/e-szigno30#`) the project's root-element/namespace check is built against; deliberately permissive, so used only as a shape check, not sole validator. |
| IANA media-type registration: `application/vnd.eszigno3+xml` | registration record, created 2007-07-31 | <https://www.iana.org/assignments/media-types/application/vnd.eszigno3+xml> | `refs/es3/iana-eszigno3.txt` | `d930a430ffbdbabcdfe9b550e534b18ccfa60e8a63c43fe16edf28e902e1ee94` | US Government work / IANA registry data, public domain in practice | Registers `application/vnd.eszigno3+xml`, `.es3`/`.et3` extensions, and confirms UTF-8/ISO-8859-2 as the only expected encodings — used to validate the extractor's MIME/extension assumptions. |
| Microsec `eszigno3` CLI reference ("eszigno3 használati útmutató") | undated (Hungarian-titled, English-content usage guide) | <https://download.e-szigno.hu/eszigno/docs/eszigno3_ref.html> | `refs/es3/eszigno3_ref.html` | `c4993089fa01980b71cdd201f6982c06654b6e87db267f869bedda82931e7c65` | © Microsec Ltd., publicly published reference page; no explicit redistribution licence found | Compatibility evidence for practical CLI operations (list/export/validate/encrypt/decrypt) against real e-Szignó tooling behaviour; not an open-source dependency. |
| Aláírási szabályzatok (SZIGORÍTOTT / EGYSZERŰSÍTETT aláírási szabályzat — signature policies, strict and simplified) | undated | <https://static.e-szigno.hu/anyagok/alairasi_szabalyzatok.pdf> | `refs/es3/alairasi_szabalyzatok.pdf` | `c1303b67bc4200a04ac7ac6363625cc16e82a32e7094240a0659e304ddc8038e` | © Microsec Ltd., publicly hosted PDF; no explicit redistribution licence found | Microsec's own signature-policy documents (Hungarian: "aláírási szabályzat"), relevant background for `es:SignatureProfile`/policy handling and for understanding what "signature profile" means operationally at Microsec, not only in the container XSD. |
| Older/other e-Szignó XSD versions on microsec.hu | — | tried `e-szigno20.xsd`, `e-szigno.xsd`, `e-akta.xsd` under `https://www.microsec.hu/ds/` | — (not found) | — | — | All returned HTTP 404; no other reachable XSD version was found under that path. Only `e-szigno30.xsd` is currently published there. |
| e-szigno.hu "e-dosszié 3.0" secondary page | — | <http://www.e-szigno.hu/?lap=edossier30> | — (not found) | — | — | Returned HTTP 404 (old CMS path, page retired); the current canonical page is `srv.e-szigno.hu/edossier` above. |

## 2. `cegeljaras/` — Hungarian company-court e-dossier schemas

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| e-cégeljárás XSD, namespace `.../2007/e-cegeljaras#` | 2007 | <https://www.e-cegjegyzek.hu/schema/2007/e-cegeljaras2007.xsd> | `refs/cegeljaras/e-cegeljaras2007.xsd` | `e9822e5f6fb6c37f1e0742299ad1257071ca49db2724d5b7825e1c87dc7c13a5` | Published by the Hungarian Company Information Service (state body); no explicit redistribution licence found | Confirms and pins the 2007 compatible non-default e-dossier namespace mentioned in `docs/research.md`, needed for M1 non-default-namespace support. |
| e-cégeljárás XSD, namespace `.../2009/e-cegeljaras#` | 2009 | <https://www.e-cegjegyzek.hu/schema/2009/e-cegeljaras2009.xsd> | `refs/cegeljaras/e-cegeljaras2009.xsd` | `8cd13c4205e4e70585739f8a18082ffd735601edaecebea603d7ff790e20221c` | Same as above | Same as above, 2009 revision. |
| e-cégeljárás XSD, namespace `.../2012/e-cegeljaras#` | 2012 | <https://www.e-cegjegyzek.hu/schema/2012/e-cegeljaras2012.xsd> | `refs/cegeljaras/e-cegeljaras2012.xsd` | `fda74708f032057ac4a0b19dc2c974eae7d0c72b9bed51fe2dc1b58aafef7d7b` | Same as above | Same as above, 2012 revision. |
| e-cégeljárás XSD, namespace `.../2014/e-cegeljaras#` | 2014 | <https://www.e-cegjegyzek.hu/schema/2014/e-cegeljaras2014.xsd> | `refs/cegeljaras/e-cegeljaras2014.xsd` | `094726db95c10bf0e98cca43f19b4c777a235b1bc5d44805465eb9daa150ca73` | Same as above | Same as above, 2014 revision — the last version explicitly named in the task. |
| e-cégeljárás XSD, namespace `.../2023/e-cegeljaras#` (bonus: current version found while searching) | 2023 | <https://www.e-cegjegyzek.hu/schema/2023/e-cegeljaras2023.xsd> | `refs/cegeljaras/e-cegeljaras2023.xsd` | `ecedbbd67ffce774dc189040dc437fcfca916d72905707ba6f7ffbd842df761c` | Same as above | Not requested explicitly but confirms the naming/versioning pattern is still alive and current; useful if the tool ever needs to support a newer cégeljárás dossier. |
| Céginformációs Szolgálat "cégnyomtatvány" 2007 form schema (related but distinct schema, namespace `.../schema/2007/cegnyomtatvany2007#`) | 2007, `version="3.0"` | <http://www.e-cegjegyzek.hu/schema/2007/cegnyomtatvany2007.xsd> | `refs/cegeljaras/cegnyomtatvany2007.xsd` | `50a99050f0699f66fce341042d195d94d34bc5f52691450e98a62f448545d8d8` | Same as above | Turned up while searching for the e-cegeljaras namespace; it is a *different* schema (company registration form data, not the e-dossier container) — kept for completeness/disambiguation, not as an e-dossier schema. |
| MUSZ_specifikacio (company-court technical specification, "Automatikusan bejegyzendő cégadatok" family) | v1.2.2 | <https://cevr.e-cegjegyzek.hu/downloads/MUSZ_specifikacio_v1.2.2.pdf> | `refs/cegeljaras/MUSZ_specifikacio_v1.2.2.pdf` | `5f0340c1949a25fa2b86647cd173e54c917e3d4d32f4e724c49a4d9f2fbd6b6d` | Published by Microsec for the Hungarian company-court e-filing system; no explicit redistribution licence found | Prose technical specification accompanying the e-cégeljárás XML/XSD family; useful cross-check against the raw XSDs above. |
| Direct namespace URLs (`http://www.e-cegjegyzek.hu/2007/e-cegeljaras`, `/2009/...`, `/2012/...`, `/2014/...`) | — | as listed | — (not fetchable as documents) | — | — | Each returns HTTP 400 when dereferenced directly (they are XML namespace identifiers, not retrievable resources) — expected behaviour, not a failure; the actual schema documents were found instead under `e-cegjegyzek.hu/schema/<year>/e-cegeljaras<year>.xsd` and are listed above. |
| `birosag.hu` / `igazsagugyi informaciok` e-cégeljárás documentation | — | (searched; no distinct XSD/doc source found beyond e-cegjegyzek.hu and cevr.e-cegjegyzek.hu above) | — (not found) | — | — | No separate authoritative schema or documentation page distinct from the Céginformációs Szolgálat (e-cegjegyzek.hu) domain family was located. |

## 3. `xmldsig/` — W3C XML Signature and Canonicalization

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| XML Signature Syntax and Processing (Second Edition) | REC, 2008-06-10 | <https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/> | `refs/xmldsig/xmldsig-core2-20080610.html` | `be7abe6228142da3d187415a84380a85ec74b5c2fd60e41e7db731647a4a9b21` | W3C Document License (permissive, attribution required) | The XMLDSig 1.0 normative reference; base for reference/signature processing rules the verifier implements independently of any third-party library. |
| XML Signature Syntax and Processing Version 1.1 | REC, 2013-04-11 | <https://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/> | `refs/xmldsig/xmldsig-core1-20130411.html` | `4924a334deb880e7e18b54cd6db037aa6b4d0186e626a26d636c124f8a2e07a3` | W3C Document License | XMLDSig 1.1, adds RSA-PSS/ECDSA and C14N 1.1 references relevant to modern e-Szignó signatures. |
| Canonical XML (Version 1.0) | REC, 2001-03-15 | <https://www.w3.org/TR/2001/REC-xml-c14n-20010315> | `refs/xmldsig/xml-c14n-20010315.html` | `09c02ef3bc0f8364b00b16fb06092637c08e8f38cf223d47a5862eacc2956bc0` | W3C Document License | Canonical XML 1.0 spec — one of the two C14N algorithms the design doc's `C14nBackend` trait must support. |
| Canonical XML Version 1.1 | REC, 2008-05-02 | <https://www.w3.org/TR/2008/REC-xml-c14n11-20080502/> | `refs/xmldsig/xml-c14n11-20080502.html` | `d91a016ac03391255c64bd5f90035b292f1ee97c3ad4076ea8b33ef11fd9673f` | W3C Document License | C14N 1.1, fixes the xml:* attribute inheritance defect in 1.0; needed for the differential-testing corpus described in `docs/verify-design.md` section 1.3. |
| Exclusive XML Canonicalization Version 1.0 | REC, 2002-07-18 | <https://www.w3.org/TR/2002/REC-xml-exc-c14n-20020718/> | `refs/xmldsig/xml-exc-c14n-20020718.html` | `10b1ec71542db546b311a3e600589339505b9099bc60affafa4204ece31807e3` | W3C Document License | Exclusive C14N — the algorithm most commonly used by real-world XMLDSig/XAdES signatures (including e-Szignó output) because it tolerates being embedded in other documents. |
| XML Signature Best Practices | W3C Note, 2013-04-11 | <https://www.w3.org/TR/2013/NOTE-xmldsig-bestpractices-20130411/> | `refs/xmldsig/xmldsig-bestpractices-20130411.html` | `f2e97d3da2a095ffd9444756998b8f4ba99f0c3f61fb16bb1ec5da17a0c265c7` | W3C Document License | Directly informs the threat-model section of `docs/verify-design.md` (signature wrapping, algorithm confusion, reference counting) — the project's own threat table cites the same concerns. |
| W3C Canonical XML test vectors | — | (searched under `w3.org/TR/xml-c14n` interoperability/test-case sections) | — (not found as a separate downloadable package) | — | — | The REC itself (`xml-c14n-20010315.html`, above) contains its worked examples inline; no separate standalone test-vector archive could be located at an official W3C URL. Differential-testing fixtures will need to be hand-built or sourced from library test suites (e.g. Apache Santuario), which is out of scope for this reference cache. |

## 4. `xades/` — ETSI XAdES / CAdES / validation model / trusted lists

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| ETSI EN 319 132-1 — XAdES digital signatures, Part 1: Building blocks and baseline signatures | V1.3.1, 2024-07 | <https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf> | `refs/xades/en_31913201v010301p_XAdES-319132-1.pdf` | `83fc87ee09de90274131a1f60cb73edb742cebc7cd8961342586ed06133664c5` | ETSI deliverables are free to download and use; ETSI retains copyright, redistribution of the PDF itself is restricted (cite/link rather than republish) | Current XAdES B-B/B-T/B-LT/B-LTA baseline-signature normative reference; primary basis for the M2 XAdES validation logic. |
| ETSI EN 319 132-2 — XAdES digital signatures, Part 2: Extended XAdES signatures | V1.1.1, 2016-04 | <https://www.etsi.org/deliver/etsi_en/319100_319199/31913202/01.01.01_60/en_31913202v010101p.pdf> | `refs/xades/en_31913202v010101p_XAdES-319132-2.pdf` | `72aac0d51fa383dd763d9bfbcdbcda3be5ff56f00818581a29f3751b49f08847` | Same ETSI terms | Extended-form XAdES (older extended forms beyond the baseline profile); relevant to interoperating with legacy e-Szignó output. |
| ETSI TS 101 903 — XML Advanced Electronic Signatures (XAdES) | V1.4.1, 2009-06 | <https://www.etsi.org/deliver/etsi_ts/101900_101999/101903/01.04.01_60/ts_101903v010401p.pdf> | `refs/xades/ts_101903v010401p_XAdES-TS101903-v1.4.1.pdf` | `22624f603d423849e6c4e926abf45a46779835dd60a315a1b4bb949985f0feb9` | Same ETSI terms | The legacy XAdES spec that the e-dossier format and the IANA registration both explicitly cite (as v1.2.2 semantics); needed because e-Szignó dossiers use the older `xades` namespaces (1.2.2/1.3.2), not the current EN 319 132 vocabulary directly. |
| ETSI EN 319 102-1 — Procedures for Creation and Validation of AdES Digital Signatures, Part 1 | V1.4.1, 2024-06 (`.../01.04.01_60/...`) — see note | see Local path note | `refs/xades/en_31910201v010401p_319102-1.pdf` | `11168f0059997cb58915c83ec1347fc66fdbabcd827e5ca7c23ecaf3cf457b3d` | Same ETSI terms | Defines the signature validation model, status vocabulary (`TOTAL-PASSING`/`TOTAL-FAILING`/`INDETERMINATE`) and building-block procedures that `docs/verify-design.md` builds its own verdict codes on top of. Note: the actual URL used, `.../31910201/01.04.01_60/en_31910201v010401p.pdf`, resolved successfully; treat the exact point version as authoritative from the PDF's own cover page rather than from this filename. |
| ETSI TS 119 612 — Trusted Lists | V2.4.1, 2025-08 | <https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf> | `refs/xades/ts_119612v020401p_TrustedLists.pdf` | `83285a1069e369d225cf16a0051a46b1f9d8961b6ad5d66bb7650351309a5196` | Same ETSI terms | Defines the LOTL/national-trusted-list XML schema and the qualification-status derivation rules used by `docs/verify-design.md` section 4. |
| ETSI EN 319 122-1 — CAdES digital signatures, Part 1 | V1.3.1, 2023-06 | <https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf> | `refs/xades/en_31912201v010301p_CAdES-319122-1.pdf` | `e99e76e519d9bd8e1410775bccedb1a588021e5e7c705c9fcc1f91c6a6227c21` | Same ETSI terms | CMS/CAdES structure background for RFC 3161 timestamp-token content (a TST is a CMS `SignedData`), used as context alongside RFC 3161/5652. |

## 5. `ietf/` — RFCs (plain text from rfc-editor.org)

| Title | RFC | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| Internet X.509 Public Key Infrastructure Time-Stamp Protocol (TSP) | RFC 3161 | <https://www.rfc-editor.org/rfc/rfc3161.txt> | `refs/ietf/rfc3161.txt` | `39fd17644ff2d654bc83814a78b1c5b5e7517f496741f34ead5064943eb98240` | IETF Trust legal provisions (free to copy/republish per RFC boilerplate) | Core RFC 3161 timestamp-token structure and verification steps enumerated in `docs/verify-design.md` section 5. |
| ESSCertIDv2 Update for RFC 3161 | RFC 5816 | <https://www.rfc-editor.org/rfc/rfc5816.txt> | `refs/ietf/rfc5816.txt` | `9a3eba6ecf14afc7820c51034a608d54d188344a43e9189b0e023d4a6a98f649` | Same IETF terms | Updates RFC 3161's signing-certificate identification to allow non-SHA-1 hash algorithms — relevant to the algorithm-allowlist policy. |
| Internet X.509 PKI Certificate and CRL Profile | RFC 5280 | <https://www.rfc-editor.org/rfc/rfc5280.txt> | `refs/ietf/rfc5280.txt` | `a2f2628c0a83b873fc4786abd921f9b2c02395954b655d190bf16b831633345d` | Same IETF terms | The normative basis for the hand-rolled RFC 5280 §6.1 path-validation subset `docs/verify-design.md` section 2 commits to implementing. |
| Cryptographic Message Syntax (CMS) | RFC 5652 | <https://www.rfc-editor.org/rfc/rfc5652.txt> | `refs/ietf/rfc5652.txt` | `dbd209ae7844031f51722c4d9e2d1fa3fff3081319851d581f914f5f0147f918` | Same IETF terms | CMS `SignedData`/`ContentInfo` structure that both RFC 3161 tokens and CAdES signatures are built on. |
| X.509 Internet PKI Online Certificate Status Protocol (OCSP) | RFC 6960 | <https://www.rfc-editor.org/rfc/rfc6960.txt> | `refs/ietf/rfc6960.txt` | `7e63ffa1ea2ce2737d9aaf895a63776e9105ddbdfc97b8ae4029e3e825b4cdea` | Same IETF terms | Revocation-checking normative reference alongside CRLs. |
| (Extensible Markup Language) XML-Signature Syntax and Processing | RFC 3275 | <https://www.rfc-editor.org/rfc/rfc3275.txt> | `refs/ietf/rfc3275.txt` | `822169ad00c4b1de47fc2435c014e171c9bdc1aafb5049a7f80fecff6194d576` | Same IETF terms | RFC counterpart/precursor to the W3C XMLDSig REC; explicitly cited by the IANA `vnd.eszigno3+xml` registration as one of the two format references. |
| Additional XML Security Uniform Resource Identifiers (URIs) | RFC 4051 | <https://www.rfc-editor.org/rfc/rfc4051.txt> | `refs/ietf/rfc4051.txt` | `4cb72c3ca467d4a82c8e1d046d09eb05cbbe74b249f94fc2a81bcfed9e6eb8e3` | Same IETF terms | Defines extra digest/MAC/signature/canonicalization URIs (e.g. SHA-256 for XMLDSig) not in the original XMLDSig REC, relevant to the algorithm allowlist. |
| Additional XML Security URIs (updates RFC 4051 with more algorithms) | RFC 6931 | <https://www.rfc-editor.org/rfc/rfc6931.txt> | `refs/ietf/rfc6931.txt` | `65d2eb41a34abc0b08f70040bc9d63622a1fa7fc0c63a7e2aa284fbe9d44cb55` | Same IETF terms | Newer algorithm URIs (SHA-3, ECDSA variants, etc.) that may appear in modern signatures. |
| PKCS #1: RSA Cryptography Specifications Version 2.2 | RFC 8017 | <https://www.rfc-editor.org/rfc/rfc8017.txt> | `refs/ietf/rfc8017.txt` | `1e72dc473d18df3fc5598cdc12795a9f18f36f1aef15abc23a55eb0d58151d11` | Same IETF terms | RSA PKCS#1 v1.5 and RSA-PSS signature schemes used across the certificate chain and XMLDSig `SignatureValue`. |
| Asymmetric Key Packages (PKCS #8 successor) | RFC 5958 | <https://www.rfc-editor.org/rfc/rfc5958.txt> | `refs/ietf/rfc5958.txt` | `82778b9ce7b34f02b5ae9777bfb9e42579744aebd2e1479f476513864525af67` | Same IETF terms | Kept for completeness per the task list; mainly relevant if the project ever needs to parse private-key material (test fixtures, `rcgen` output), not for verification itself. |
| PKCS #8: Private-Key Information Syntax Specification | RFC 5208 | <https://www.rfc-editor.org/rfc/rfc5208.txt> | `refs/ietf/rfc5208.txt` | `89f7338cf546abaee1d14eef7357440f4fc45e579d47dd4b436c29533abafc2e` | Same IETF terms | Legacy PKCS#8 format, same rationale as RFC 5958. |
| PKCS #7: Cryptographic Message Syntax Version 1.5 | RFC 2315 | <https://www.rfc-editor.org/rfc/rfc2315.txt> | `refs/ietf/rfc2315.txt` | `154610a11c76a8b499d8453c0190d4ff8ee354dd6a203f40d8252840747cb4e0` | Same IETF terms | Historical precursor to CMS (RFC 5652); some older signed blobs in the wild still use PKCS#7 framing. |

## 6. `trust/` — eIDAS trust infrastructure and Microsec CA material

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| EU List of Trusted Lists (LOTL) | live document, fetched 2026-09-07 | <https://ec.europa.eu/tools/lotl/eu-lotl.xml> | `refs/trust/eu-lotl.xml` | `df4f4ccaa8f7ac464ab940d5589e6bc8caf9626ac56050b52f90cf9ee8766f42` | European Commission public data; the LOTL is meant to be fetched/used programmatically | The root of the eIDAS trust-anchor bootstrap chain described in `docs/verify-design.md` section 4; this snapshot is a point-in-time copy only — a real deployment must refetch and re-verify it, never trust this cached copy blindly. |
| Hungarian Trusted List (machine-readable) | fetched 2026-09-07; internal generation timestamp 2026-07-15 10:42:53 CEST (per XML comment) | <https://www.nmhh.hu/tl/pub/HU_TL.xml> | `refs/trust/HU_TL.xml` | `aa2dabaaea6266d907e12c4225d4173262466b9c6add91776776a00dd6c528a3` | Published by NMHH (state regulator), public data | The Hungarian national trusted list pointed to by the LOTL; needed to determine Microsec's/other Hungarian CAs' qualified status per ETSI TS 119 612 semantics. |
| Hungarian Trusted List (human-readable) | fetched 2026-09-07 | <https://www.nmhh.hu/tl/pub/HU_TL.pdf> | `refs/trust/HU_TL.pdf` | `1615502c441f7498da707e0926357f5557444b8863136d751e04c5d7e1a19fb4` | Published by NMHH, public data | Human-readable companion to `HU_TL.xml`, useful for manually cross-checking parsed trusted-list entries. |
| Microsec e-Szignó Root CA 2009 (root certificate) | issued 2009-06-16, expires 2029-12-30 | <http://www.e-szigno.hu/rootca2009.crt> | `refs/trust/rootca2009.crt` | file SHA-256: `3c5f81fea5fab82c64bfa2eaecafcde8e077fc8620a7cae537163df36edbf378`; certificate SHA-256 fingerprint (verified with `openssl x509 -fingerprint -sha256`): `3C:5F:81:FE:A5:FA:B8:2C:64:BF:A2:EA:EC:AF:CD:E8:E0:77:FC:86:20:A7:CA:E5:37:16:3D:F3:6E:DB:F3:78` | Public root certificate, published by Microsec for exactly this kind of distribution/pinning use | One of the two Microsec root CAs the project's `--trust-store` design (section 4 of `docs/verify-design.md`) would pin as a trust anchor for real e-Szignó signature chains. |
| e-Szigno Root CA 2017 (root certificate) | issued (see cert), CN "e-Szigno Root CA 2017" | <http://www.e-szigno.hu/rootca2017.crt> | `refs/trust/rootca2017.crt` | file SHA-256: `beb00b30839b9bc32c32e4447905950641f26421b15ed089198b518ae2ea1b99`; certificate SHA-256 fingerprint: `BE:B0:0B:30:83:9B:9B:C3:2C:32:E4:44:79:05:95:06:41:F2:64:21:B1:5E:D0:89:19:8B:51:8A:E2:EA:1B:99` | Same as above | The newer Microsec root, needed alongside the 2009 root for full CA-hierarchy coverage across the ~2007–present dossier date range mentioned in `docs/verify-design.md`. |
| e-szigno.hu "CA certificates and CA hierarchy" page | fetched 2026-09-07 | <https://e-szigno.hu/ca-certificates> | `refs/trust/ca-certificates.html` | `be274002aea0d9acb729b88e259e9c70c275301a1edbf6184f4bd308797eb15b` | © Microsec Ltd. | **Caveat:** this page is a JavaScript single-page-app shell (4.4 KB, no cert links present in the static HTML); it was saved as-is for completeness but does not itself contain the certificate list — the actual root certificates were found and verified via their direct, stable `.crt` URLs above instead. |
| `srv.e-szigno.hu` CA hierarchy page (`?lap=english_ca_hierarchy`) | — | `http://srv.e-szigno.hu/menu/index.php?lap=english_ca_hierarchy` | — (not found) | — | — | Returned HTTP 404 (old CMS path retired); superseded by the current `e-szigno.hu/ca-certificates` SPA above, which itself doesn't expose static links — see caveat above. |
| `www.e-szigno.hu/?lap=edossier30` | — | `http://www.e-szigno.hu/?lap=edossier30` | — (not found) | — | — | Returned HTTP 404 (old CMS path retired). |

## 7. `other/` — Existing implementations and background material

| Title | Version / date | Canonical URL | Local path | SHA-256 | Licence / redistribution | Why it matters |
| --- | --- | --- | --- | --- | --- | --- |
| `gyim/eszigno` — README | fetched 2026-09-07, `master` branch | <https://raw.githubusercontent.com/gyim/eszigno/master/README.md> | `refs/other/gyim-eszigno-README.md` | `5e5126113dba8f4a111055d6cce005040d9c8bd75e8eaa291645879c9db0ac35` | MIT (see LICENSE file below) | Documents the behaviour of a minimal, non-validating `.es3` extractor cited as a comparison baseline in `docs/research.md`. |
| `gyim/eszigno` — LICENSE | 2020, Ákos Gyimesi | <https://raw.githubusercontent.com/gyim/eszigno/master/LICENSE> | `refs/other/gyim-eszigno-LICENSE.txt` | `5e4ecf9dc866ab9a9a10a6ca542e01b946ca81fd7cb1bd3e5920e77f16059fd5` | MIT License | Confirms the MIT licence terms already asserted in `docs/research.md`. |
| `berkitamas/eakta-viewer` — README | fetched 2026-09-07, `main` branch | <https://raw.githubusercontent.com/berkitamas/eakta-viewer/main/README.md> | `refs/other/eakta-viewer-README.md` | `33e15b4207a30597bf33b4d1fac8d266198f12aaa945b0c58dc53269faa3baad` | No licence file found in the repo (per `docs/research.md`); treat as all-rights-reserved, research lead only — source code was deliberately not fetched | Describes the macOS viewer's stated capabilities (open/preview/validate/export `.es3`); a design lead, not an authority, per the existing research notes. |
| `berkitamas/eakta-viewer` — AGENTS.md | fetched 2026-09-07, `main` branch | <https://raw.githubusercontent.com/berkitamas/eakta-viewer/main/AGENTS.md> | `refs/other/eakta-viewer-AGENTS.md` | `bdddb6eb8663a12f22fecc43b06b86a5f91b25a27de287cbc1ae2f5eeb0c6740` | Same as above (no licence found) | Project/architecture guide (not source code) that documents the verification design that guided `docs/research.md`'s note about a "broad verification design"; kept as prose documentation only. |
| "Nagy e-Szignó könyv" (comprehensive Hungarian e-signature handbook) | undated, university course-material mirror | <https://www.tilb.sze.hu/tilb/targyak/NGB_TA0028_1/nagy_e-szigno_konyv.pdf> (mirror; original at `mek.oszk.hu/22400/22433/22433.pdf` could not be fetched, see note) | `refs/other/nagy-eszigno-konyv.pdf` | `b217ac2791c7d79894cd086137ca463d67271248ce45bb315f8ba913b9e2bbe7` | Hosted by the Hungarian National Széchényi Library's electronic collection (MEK) and mirrored for a university course; treat as reference/study material only, not for redistribution | Academic/reference-book-length background on Hungarian e-signature practice, useful context for e-akta/es3 structure and terminology beyond Microsec's own docs. **Note:** the canonical MEK URL (`https://www.mek.oszk.hu/22400/22433/22433.pdf`) failed with repeated `curl` HTTP/2 and empty-reply errors from this environment; the file actually stored here was fetched from the university mirror URL above instead, which returned a valid PDF. |
| MUSZ_specifikacio_v1.2.2.pdf | see `cegeljaras/` table (row 6.2) | — | see `refs/cegeljaras/MUSZ_specifikacio_v1.2.2.pdf` | — | — | Cross-referenced from `cegeljaras/`; not duplicated here. |

---

## Summary of gaps and failures (nothing fabricated)

- **`es3/`**: no PDF companion to the English `edossier-spec.html` page was
  found (it links out only to the XSD and to an unrelated NMHH PDF); no
  older/other XSD versions exist at `microsec.hu/ds/` besides `e-szigno30.xsd`
  (all guesses 404); `www.e-szigno.hu/?lap=edossier30` is a dead CMS link.
- **`cegeljaras/`**: the raw namespace URIs
  (`http://www.e-cegjegyzek.hu/2007/e-cegeljaras#` etc.) are not fetchable
  documents by design (HTTP 400) — the actual schema documents live under
  `e-cegjegyzek.hu/schema/<year>/e-cegeljaras<year>.xsd` and were all four
  obtained successfully (2007, 2009, 2012, 2014), plus a bonus 2023 version.
- **`xmldsig/`**: no standalone official W3C Canonical XML test-vector package
  could be located; the REC's own inline examples are the only official source
  found.
- **`trust/`**: the `e-szigno.hu/ca-certificates` page is a client-rendered SPA
  shell with no certificate links in the static HTML; the two root certificates
  were instead obtained directly from their stable, documented `.crt` URLs and
  their SHA-256 fingerprints were computed and recorded independently (not just
  re-copied from a webpage) for verification.
- **`other/`**: the canonical MEK library URL for the e-signature handbook
  failed outright (HTTP/2 stream errors, then empty replies) from this
  environment; a university-hosted mirror of the same PDF was used instead and
  is flagged as such in the table.

## Verification method used for every download

For every file: (1) `curl -L --fail --retry 3` with a descriptive User-Agent
identifying this as a research fetch; (2) `file` and/or `head -c` inspection
to confirm the content type matches expectations (PDF magic bytes, real XML
declarations, real XSD `targetNamespace`, real RFC boilerplate, real ETSI/W3C
title tags) rather than an HTML error/redirect page; (3) size sanity-checked
against `ls -l`; (4) `sha256sum` recorded above. All root certificates were
additionally parsed with `openssl x509` to confirm subject and compute an
independent SHA-256 fingerprint.
