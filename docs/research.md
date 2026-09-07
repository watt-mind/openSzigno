# `.es3` e-dossier research

Last reviewed: 2026-09-09

## What an `.es3` file is

For this project, `.es3` means the Hungarian Microsec e-Szignó **electronic
dossier** (e-akta) format, not another unrelated format that happens to use
the same file extension. It is an XML document, normally rooted at
`es:Dossier`, which contains document payloads, metadata, signatures and/or
timestamps. Payloads are Base64 encoded even when the original payload is
text or XML.

The default e-Szignó namespace is:

```text
https://www.microsec.hu/ds/e-szigno30#
```

Special-purpose dossiers may use another compatible e-dossier namespace.
The tool must identify a dossier by a namespace-aware root-element check, not
by extension alone.

## Primary sources

| Source | Why it matters |
| --- | --- |
| [Microsec e-dossier specification, v1.2 (English)](https://srv.e-szigno.hu/edossier) | Primary prose specification. It says its verbal requirements are authoritative over the XSD. |
| [Default e-dossier XSD](https://www.microsec.hu/ds/e-szigno30.xsd) | Machine-readable shape of the default schema; deliberately permissive for compatibility, so it is not the only validator. |
| [IANA media-type registration](https://www.iana.org/assignments/media-types/application/vnd.eszigno3+xml) | Registers `application/vnd.eszigno3+xml`, `.es3`/`.et3`, and UTF-8 or ISO-8859-2 XML declarations. |
| [Microsec `eszigno3` CLI reference](https://download.e-szigno.hu/eszigno/docs/eszigno3_ref.html) | Compatibility evidence for practical operations: list, export, validate, encrypt, and decrypt. Not an open-source dependency. |

## Container model relevant to the MVP

For each `es:Document` under `es:Documents`, the MVP needs to read:

- `es:DocumentProfile`: title, creation time, MIME type, declared source size,
  and `OBJREF`;
- the matching `ds:Object` payload identified by `OBJREF`;
- `es:BaseTransform/es:Transform` in declared order.

The documented transform chain is:

```text
zip? -> encrypt? -> base64
```

Extraction reverses that chain. The initial implementation supports only
`base64` and `zip -> base64`; it must report `encrypt` as encrypted/unsupported
rather than treating it as a corrupt payload or attempting ad-hoc decryption.

The dossier can additionally hold document-level and dossier-level XMLDSig /
XAdES signatures and timestamps. Their presence is metadata for the MVP; it
is **not** evidence of a valid signature.

## Existing implementations found

- [`gyim/eszigno`](https://github.com/gyim/eszigno) (MIT) is a compact Python
  list/extract utility. Its README explicitly says that it does not validate
  signatures and is not security-complete. It is useful as behavioral
  comparison for simple extraction, not as a validation authority.
- [`berkitamas/eakta-viewer`](https://github.com/berkitamas/eakta-viewer) is a
  macOS viewer that documents a broad verification design. At review time it
  has no stated software license and intentionally does not commit real
  dossiers. Do not copy source code from it; its public design can only be
  treated as a research lead.

## Security conclusions

`.es3` inputs must be treated as hostile. The initial parser/extractor needs
to reject or safely bound at least:

- XML external entities, DTDs, entity expansion, and excessive nesting;
- duplicate or unresolved XML IDs / `OBJREF` values;
- oversized XML, Base64 output, ZIP members, aggregate extraction, and
  compression ratios (ZIP bombs);
- archive path traversal, absolute paths, symlinks, and output-name
  collisions;
- unsupported transforms and unknown namespaces without an explicit opt-in.

Signature verification is a separate security-sensitive feature. It requires
strict same-document ID resolution, reference-scope enforcement,
canonicalization, algorithm policy, certificate-path and revocation checking,
and timestamp validation. Until all of those are implemented and tested,
commands may report *signature material present*, but must not report
*signature valid*.

## Language decision

Rust is the preferred implementation language: it supports one native binary,
portable release artifacts, bounded streaming parsers, and an agent-friendly
CLI without requiring a VM/runtime. Go remains a viable fallback, but Rust is
the default unless a later validation-library evaluation reverses the choice.
