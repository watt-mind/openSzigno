# `.es3` e-dossier research

Last reviewed: 2026-09-07

## Primary sources

The maintained format guide is
[ES3 specification and implementation map](es3-specification.md). It records
source versions, requirement IDs, code/test links, and unassessed areas.
The full source inventory and local-cache checksums are in
[references.md](references.md).

The implementation has used the English v1.2 prose as its baseline. The
Hungarian v1.5 text needs a full comparison before that baseline can be
considered complete. The guide records the confirmed empty-document exception
and keeps project compatibility choices separate from format requirements.

Compatible namespaces (M1) and the first verification phase (M2 phase 1) have
shipped. Current behavior belongs in [architecture.md](architecture.md), and
remaining work in [roadmap.md](roadmap.md).

## Additional implementation research

The [related documentation register](references.md#related-documentation-and-test-resources)
adds official W3C interoperability cases, NIST PKITS, European Commission DSS,
Apache Santuario, OpenSSL verification options, and the document-signing EKU
and distinguished-name matching RFCs. These provide candidate independent
checks; none is an ES3 conformance oracle by itself.

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

Signature verification is a separate security-sensitive feature. M2 phase 1
checks reference digests, signature values, scope, and a certificate-path
subset. Full XAdES, revocation, and timestamp checks remain unfinished.
`verify` can report `invalid` or `indeterminate`, never `valid`; the other
commands perform no cryptographic verification.

## Language decision

Rust is the preferred implementation language: it supports one native binary,
portable release artifacts, a bounded whole-document XML parser (input-size,
depth, and node-count limited; see `docs/architecture.md`), and an
agent-friendly CLI without requiring a VM/runtime. Go remains a viable
fallback, but Rust is the default unless a later validation-library evaluation
reverses the choice.
