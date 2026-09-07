# Architecture and CLI contract

This document is the canonical reference for the openSzigno JSON envelope,
stable codes, limits, parser safety model, and extraction policy. Anything
described here is intended to be stable for a given `schema_version`.

## Goals

- Provide distributable, cross-platform binaries.
- Be safe by default when handling untrusted dossiers.
- Make every operation usable by agents: deterministic exit statuses and a
  documented JSON result.
- Separate **structural parsing/extraction** from **cryptographic validation**.

## Not yet implemented

The current release does not do the following. The first three are planned
milestones, described in [roadmap.md](roadmap.md); until the corresponding
code exists, no output may claim or imply that a signature, timestamp,
certificate, or dossier is valid.

- the XAdES qualifying properties (`SigningCertificate`, `SigningTime`,
  signature policy, level detection), revocation checking, and trusted-list
  based qualified-status determination that complete M2. `verify` ships the
  M2 phase-1 subset described below and can never return `valid`;
- timestamp verification (M3);
- decryption of encrypted payloads (M4).

Permanent non-goals for this tool:

- creating, editing, signing, timestamping, or encrypting dossiers;
- declaring a dossier legally valid, which is a legal judgement rather than a
  cryptographic result;
- silently accepting arbitrary XML that merely has an `.es3` suffix.

## Crate shape

```text
crates/
  openszigno-core/    # XML model, bounded decoding, transforms, stable codes
  openszigno-verify/  # canonicalization, XMLDSig, certificate paths
  openszigno-cli/     # clap commands, human output, JSON protocol, exit codes
```

`openszigno-core` does not write files or print output. The CLI owns all
filesystem policy and serialisation. This keeps the parser testable and makes
future library use possible without weakening CLI safety.

`openszigno-verify` is a separate crate, not a module, so that the crypto
dependency tree stays out of anyone who only wants parsing, and so that the
verification code can be audited as a unit. It performs no I/O of its own:
the clock, the trust store, and (from phase 3) revocation data all arrive
through the injected `Clock`, `TrustSource`, and `RevocationSource` traits,
which makes "offline by default" a structural property rather than a runtime
flag someone can forget to check. It owns the whole verification pipeline —
reference resolution, the transform and algorithm allowlists, canonicalization,
and path validation — because a general-purpose XMLDSig library would own
exactly the decisions this project has stricter rules about.

Both crates read the dossier through one shared entry point,
`openszigno_core::XmlSource`, so the tree that resolves references is
byte-for-byte the tree the structural parser saw. Two parsers that disagree
about namespace scope or element boundaries is precisely the signature-wrapping
gap `verify` exists to close.

The MVP uses `roxmltree` after bounded UTF-8/ISO-8859-2 decoding for
namespace-aware XML parsing, `base64` and `zip` for bounded payload decoding,
`rustix` for descriptor-relative output on Unix, `clap` for command parsing,
and `serde`/`serde_json` for the protocol. Dependency versions and licenses
are captured by `Cargo.lock` and Cargo metadata.

## Format scope

- Root element `Dossier` in an allowed namespace, checked namespace-aware
  rather than by file extension. See [Namespace policy](#namespace-policy).
- XML declarations naming UTF-8 or ISO-8859-2; an absent declaration is
  treated as UTF-8. A UTF-8 byte order mark is stripped.
- Transform chains `base64` and `zip -> base64`. A chain containing `encrypt`
  is reported as encrypted and skipped; any other chain is reported as an
  unsupported transform chain.
- Signature and timestamp material is counted for reporting only:
  `ds:Signature` elements in the XMLDSig namespace and `TimeStamp` elements in
  the dossier's own namespace.
- A document whose declared media type is `application/nldossier2`
  (case-insensitively) or whose declared extension is `dosszie` embeds another
  complete dossier; it is reported as `nested_dossier` and, by default,
  expanded recursively by `extract`.

## Namespace policy

The specification allows a dossier profile to use its own namespace as long as
it stays compliant with the default schema. openSzigno accepts an explicit
allow-list, exposed as `openszigno_core::KNOWN_COMPATIBLE_NAMESPACES`:

| Namespace | Profile |
| --- | --- |
| `https://www.microsec.hu/ds/e-szigno30#` | Default Microsec e-Szignó. |
| `http://www.e-cegjegyzek.hu/2007/e-cegeljaras#` | Hungarian company court, 2007. |
| `http://www.e-cegjegyzek.hu/2009/e-cegeljaras#` | Hungarian company court, 2009. |
| `http://www.e-cegjegyzek.hu/2012/e-cegeljaras#` | Hungarian company court, 2012. |
| `http://www.e-cegjegyzek.hu/2014/e-cegeljaras#` | Hungarian company court, 2014. |

Rules:

- The root element must be `Dossier` in one of the allowed namespaces.
  Anything else is `wrong_root`. The rejection message never echoes the
  namespace URI, which comes from untrusted input.
- Every structural lookup (`DossierProfile`, `Documents`, `Document`,
  `DocumentProfile`, `Title`, `CreationDate`, `Format`, `MIME-Type`,
  `SourceSize`, `BaseTransform`, `Transform`, `E-category`, `TimeStamp`) uses
  the dossier's *own* namespace, never the default one. `ds:Object` and
  `ds:Signature` stay in the XMLDSig namespace.
- `inspect` and `list` report the detected `namespace` verbatim, so a caller
  can tell which profile was applied.
- `--allow-namespace <URI>` (repeatable, accepted by every command) adds a
  namespace to the list. It is additive: the known-compatible namespaces are
  always accepted as well, so a flag can widen the policy but never narrow it.

### Conformance warnings

A dossier that parses but deviates from the default profile is reported
through structural warnings rather than being rejected, because real
company-court dossiers routinely deviate in these ways. The warnings carry
the codes `dangling_objref`, `document_without_profile`,
`source_size_missing`, and `creation_date_missing`, and never change an exit
status by themselves.

- Every `Document` must carry a `DocumentProfile`; one holding only a
  `ds:Object` is non-conformant. Such a document is skipped, is not counted in
  `documents`, and produces `document_without_profile` naming its source
  position among `Document` elements.
- `SourceSize` is optional in a `DocumentProfile`; company-court dossiers
  occur without it. When it is present the `sizeValue`/`sizeUnit` and
  declared-size-limit rules apply unchanged and the decoded length must match
  it (`source_size_mismatch`). When it is absent the document is still read,
  `source_size` is `null`, nothing is compared against a declaration, and
  `source_size_missing` names the document index.
- `CreationDate` is optional in the `DossierProfile`; when absent the
  dossier `creation_date` is `null` and `creation_date_missing` is reported.
  A `DocumentProfile` must still carry its `CreationDate`.
- The `DossierProfile` and every `DocumentProfile` `OBJREF` must still resolve
  exactly as before; a failure is the hard error `unresolved_objref`. Any
  other dangling `OBJREF` (a `SignatureProfile` pointing at nothing, for
  example) produces `dangling_objref` naming only the owning element's local
  name. Duplicate or empty IDs remain the hard error `duplicate_id`.

### Content sniffing

Declared MIME types are unreliable in practice, so every decoded document is
classified from a bounded prefix of its bytes by `openszigno_core::sniff`.
`pdf` and `zip` are decided by magic bytes; then, if the payload (after an
optional BOM and leading whitespace) starts with markup, the category comes
from the ASCII markup alone, so an ISO-8859-2 document is still `xml`, `html`,
or `dossier` even though its later bytes are not valid UTF-8. Only non-markup
content falls through to the UTF-8 text/binary test. The categories are
`pdf`, `html`, `xml`, `dossier`,
`zip`, `text`, and `binary`; each has a preferred extension except `binary`.
Sniffing reads at most the first 4096 bytes (1024 for a leading HTML tag),
never allocates a copy of the payload, and reports nothing about the content
beyond the category.

## Parser safety model

The parser is a bounded whole-document parser, not a streaming one. Untrusted
input passes through these stages, each with an explicit limit:

1. **Input size.** The file is read with a hard cap (`max_input_bytes`,
   64 MiB). The CLI also refuses a path that is not a regular file. Larger
   inputs fail with `input_too_large` before parsing.
2. **Encoding.** Only the `encoding` pseudo-attribute of the XML declaration
   itself is consulted; comments or later content cannot select an encoding.
   UTF-8 and ISO-8859-2 are decoded strictly; anything else is
   `unsupported_encoding` or `invalid_encoding`.
3. **Pre-parse scan.** A linear scan over the decoded text rejects any
   `<!...>` construct outside comments, CDATA sections, and processing
   instructions (`unsafe_xml`, which covers DOCTYPE and entity declarations),
   element nesting deeper than `max_xml_depth` (128), and more than
   `max_xml_nodes` (1,000,000) elements. This runs before the recursive tree
   parser, so deep nesting cannot exhaust the stack.
4. **Tree parse.** `roxmltree` parses with DTDs disabled and its own node
   limit as a backstop. Parse failures report only a line and column; element,
   attribute, and entity names from the input are never echoed.
5. **Structure.** Root element and namespace, unique non-empty unprefixed
   `Id`/`ID`/`id` attributes, `OBJREF` resolution to the direct `Documents`
   element and to exactly one direct `ds:Object` per document, required
   profile elements and attributes, and `max_documents` (256). A `SourceSize`
   that is present is bounded by `max_decoded_document_bytes` here; one that is
   absent leaves the decoded size bounded by the payload limits alone.
6. **Payload decoding.** Base64 is decoded strictly (canonical padding) with
   `max_base64_chars` and `max_decoded_document_bytes` (64 MiB) limits. ZIP
   payloads must contain exactly one regular-file member with a bare name;
   the expanded size is capped while reading, and the compression ratio
   (`max_zip_compression_ratio`, 100:1) is checked on the actual decoded
   length, not on header fields. Encrypted or non-deflate ZIP members are
   reported as `unsupported_zip_member`. The decoded length must equal the
   declared `SourceSize`.
7. **Aggregate output.** The CLI enforces `max_total_decoded_bytes` (256 MiB)
   across all documents of one extraction, counting every level of an embedded
   dossier tree against the same budget. Nesting itself is bounded by
   `--max-depth` (default 3, hard cap 8); every other limit applies unchanged
   at each level.

Peak memory is roughly a small multiple of the input size (the raw bytes, the
decoded text, the tree, and the decoded payloads are all held at once).

## Limits

The limits are compile-time defaults, reported verbatim by `inspect --json`
under `data.limits`. They are not yet configurable on the command line; see
[roadmap.md](roadmap.md).

| Limit | Default | Enforced by | Purpose |
| --- | --- | --- | --- |
| `max_input_bytes` | 67108864 (64 MiB) | core and CLI | Raw dossier file size. |
| `max_documents` | 256 | core | `es:Document` elements per dossier. |
| `max_base64_chars` | 100663296 (96 MiB) | core | Base64 characters in one payload after whitespace removal. |
| `max_decoded_document_bytes` | 67108864 (64 MiB) | core | Decoded size of one document. |
| `max_total_decoded_bytes` | 268435456 (256 MiB) | CLI | Aggregate decoded size of one extraction, across the whole embedded-dossier tree. |
| `max_zip_members` | 16 | core | Members in a `zip` transform archive; the format stores exactly one, so this is defence in depth. |
| `max_zip_expanded_bytes` | 67108864 (64 MiB) | core | Expanded size of the ZIP member. |
| `max_zip_compression_ratio` | 100 | core | Expanded/compressed ratio, checked on actual decoded bytes. |
| `max_xml_depth` | 128 | core | Element nesting depth, checked before tree construction. |
| `max_xml_nodes` | 1000000 | core | Element count, checked before tree construction and again by the parser's node limit. |

## Command contract

| Command | Function | Mutates input? |
| --- | --- | --- |
| `inspect FILE` | Identify the format; return dossier metadata, limits, and capability warnings. | No |
| `list FILE` | Return deterministic document records and signature/timestamp presence. | No |
| `extract FILE --output DIR` | Decode supported documents, and the dossiers they embed, into a new or existing directory without overwriting files. | No |
| `validate-structure FILE` | Apply the project's strict structural rules without validating signatures. | No |
| `verify FILE` | Verify every `ds:Signature`: canonicalization, reference digests, the signature value, the e-dossier reference-scope rules, and the certificate path. Cannot report a signature as `valid` in this release. | No |

`verify` additionally accepts `--trust-store <DIR>` and `--at <RFC3339>`; see
[The `verify` command](#the-verify-command).

All commands accept `--json` and `--allow-namespace <URI>` (repeatable).
`extract` additionally accepts `--no-recursive`, which writes an embedded
dossier as a plain payload file instead of expanding it, and
`--max-depth <N>` (default 3), which bounds the nesting levels expanded;
values above the hard cap of 8 are clamped to 8. In JSON mode, stdout contains
exactly one JSON
object and diagnostics go to stderr. Document ordering is the source XML
order. No command writes XML payload bytes to stdout.

## JSON envelope

The envelope fields are always present:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, `verify`, or `usage`. |
| `input` | object | `format` is `"microsec-es3"` or `null`; `bytes` is the input size or `null`. |
| `data` | object or null | Command-specific; `null` on failure. |
| `warnings` | array | Objects with stable `code` and human `message`. |
| `errors` | array | Objects with stable `code` and human `message`. |

Messages never contain input paths, document titles, or payload content. On
failure `data` is `null`, `warnings` is empty, and `input.format` is `null`
when the input could not be parsed as a dossier.

Example, from `inspect --json` on `tests/fixtures/plain-base64.es3`. The tool
writes one compact line; this is pretty-printed:

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "inspect",
  "input": { "format": "microsec-es3", "bytes": 1109 },
  "data": {
    "capabilities": {
      "base64_extraction": true,
      "cryptographic_verification": false,
      "encrypted_extraction": false,
      "structural_validation": true,
      "zip_base64_extraction": true
    },
    "dossier": {
      "category": "electronic dossier",
      "creation_date": "2026-01-01T00:00:00Z",
      "documents": 1,
      "namespace": "https://www.microsec.hu/ds/e-szigno30#",
      "nested_dossiers": 0,
      "signatures_present": 0,
      "signatures_verified": false,
      "timestamps_present": 0,
      "title": "Unsigned synthetic plain fixture",
      "xml_encoding": "UTF-8"
    },
    "limits": {
      "max_base64_chars": 100663296,
      "max_decoded_document_bytes": 67108864,
      "max_documents": 256,
      "max_input_bytes": 67108864,
      "max_total_decoded_bytes": 268435456,
      "max_xml_depth": 128,
      "max_xml_nodes": 1000000,
      "max_zip_compression_ratio": 100,
      "max_zip_expanded_bytes": 67108864,
      "max_zip_members": 16
    }
  },
  "warnings": [],
  "errors": []
}
```

`data` is command-specific:

| Command | `data` fields |
| --- | --- |
| `inspect` | `dossier`, `limits`, `capabilities`. |
| `list` | `dossier`, plus `documents`: an array in source order with `index`, `title`, `creation_date`, `mime_type` (`media_type`, `subtype`, `extension`, `charset`), `source_size`, `object_ref`, `transforms`, and `nested_dossier`. `source_size` is `null` when the profile omits `SourceSize`. |
| `extract` | `extracted` (array of `document_index`, `dossier_path`, `filename`, `path`, `bytes`, `detected_type`, `declared_type`), `extracted_count`, `skipped_count`, `nested_dossiers_extracted`. |
| `validate-structure` | `valid_structure`, `documents`, `conformance_warnings`, `cryptographic_verification_performed` (always `false`). |
| `verify` | `verdict`, `verification_time`, `policy`, `limits`, `counts`, `checks`, `signatures`. See [The `verify` command](#the-verify-command). |

`valid_structure` stays `true` whenever parsing succeeded;
`conformance_warnings` counts the structural deviations, which are listed
individually in `warnings`.

Each `extracted` entry describes one written file:

| Field | Meaning |
| --- | --- |
| `document_index` | Index of the document within its own dossier. |
| `dossier_path` | Position in the dossier tree: `"0"` for top-level document 0, `"2/0"` for document 0 inside nested document 2. |
| `filename` | Basename of the written file. |
| `path` | Path relative to the output root, `/`-separated, e.g. `court.dosszie.d/ruling.pdf`. |
| `bytes` | Decoded size. |
| `detected_type` | Content-sniffing result: `pdf`, `html`, `xml`, `dossier`, `zip`, `text`, or `binary`. |
| `declared_type` | The MIME essence the dossier declares, which is often wrong. |

`extracted_count` counts every file written across the tree, `skipped_count`
every document skipped across the tree, and `nested_dossiers_extracted` the
embedded dossiers that were expanded.

The `dossier` object carries `title`, `category` (or `null`), `creation_date`
(or `null`),
`namespace`, `xml_encoding`, `documents` (a count), `nested_dossiers` (a count
of documents that embed a dossier), `signatures_present`, `timestamps_present`,
and `signatures_verified`, which is always `false`.

Example of a failure envelope, from `inspect --json` on
`tests/fixtures/doctype.es3` (exit status 4):

```json
{
  "schema_version": 1,
  "ok": false,
  "command": "inspect",
  "input": { "format": null, "bytes": 366 },
  "data": null,
  "warnings": [],
  "errors": [
    {
      "code": "unsafe_xml",
      "message": "DTD and entity declarations are not allowed"
    }
  ]
}
```

## Exit statuses

Exit statuses are stable at the category level:

| Status | Meaning |
| --- | --- |
| `0` | Operation completed (possibly with explicit skipped-document warnings). |
| `2` | Command-line usage error, emitted by `clap`. |
| `3` | Input/output error. |
| `4` | Invalid, unsupported, or unsafe dossier structure. |
| `5` | Payload decoding or safe-extraction failure. |
| `6` | `verify` completed and at least one signature verdict is `invalid`. |
| `7` | `verify` completed, no signature is `invalid`, and the overall verdict is `indeterminate`. |

Statuses 6 and 7 describe a run that *completed*: the dossier parsed, the
signatures were examined, and the tool is reporting what it found. A structural
failure during `verify` still exits 4, so a caller can tell "this is not a
dossier" apart from "this dossier's signatures do not verify". Because this
release checks neither revocation nor timestamps, a dossier that carries
signatures can never exit 0.

Failures have `ok: false`, stable machine-readable error codes, and a nonzero
exit status. An unsupported encrypted document is a successful parse with an
explicit capability warning; malformed or unsafe input is an error.

Usage errors (exit 2) are produced before a command runs. Without `--json`
they are `clap`'s human text on stderr with empty stdout. When `--json` is
present on the command line, the standard envelope is written instead with
`command: "usage"` and the error code `usage_error`; the message is a fixed
string, because `clap`'s own text can quote argument values that may be
private paths. `--help` and `--version` always print plain text. If stdout
cannot be written (for example a closed pipe), the process exits with status 3
without printing a panic.

## Stable codes

Error codes and the exit status they map to. Codes marked *core* come from
`openszigno_core::ErrorCode`; codes marked *CLI* are produced by the CLI's
I/O and extraction policy.

| Code | Origin | Exit | Meaning |
| --- | --- | --- | --- |
| `usage_error` | CLI | 2 | Invalid command line (JSON mode only). |
| `io_error` | CLI | 3 | The input could not be inspected, opened, or read; or output could not be created or written for a reason other than a pre-existing file. |
| `input_too_large` | core, CLI | 4 | Input exceeds `max_input_bytes`. |
| `unsupported_encoding` | core | 4 | The XML declaration names an encoding other than UTF-8 or ISO-8859-2. |
| `invalid_encoding` | core | 4 | Bytes are not valid for the declared encoding. |
| `unsafe_xml` | core | 4 | DTD/entity declaration, nesting depth, or node count limit. |
| `invalid_xml` | core | 4 | Not well-formed XML, or a required element occurs more than once where one is required. |
| `wrong_root` | core | 4 | Root is not `Dossier`, or its namespace is not allowed. |
| `missing_element` | core | 4 | A required element is absent or empty. |
| `invalid_attribute` | core | 4 | A required attribute is absent or malformed. |
| `duplicate_id` | core | 4 | An XML ID is empty or repeated. |
| `unresolved_objref` | core | 4 | An `OBJREF` does not resolve to exactly one ID, or not to the expected element. |
| `too_many_documents` | core | 4 | More than `max_documents` documents. |
| `decoded_too_large` | core | 4 or 5 | A declared or decoded payload exceeds a size limit (4 when detected during parsing, 5 during extraction). |
| `invalid_base64` | core | 5 | Payload is not canonical Base64. |
| `source_size_mismatch` | core | 5 | Decoded length differs from the declared `SourceSize`. |
| `invalid_zip` | core | 5 | ZIP payload is malformed or cannot be expanded. |
| `zip_member_limit` | core | 5 | The archive does not contain exactly one member. |
| `zip_size_limit` | core | 5 | The ZIP member exceeds the expanded-size limit. |
| `zip_ratio_limit` | core | 5 | The ZIP member exceeds the compression-ratio limit. |
| `unsafe_zip_member` | core | 5 | The member is a directory, a symlink, or has a non-basename path. |
| `unsupported_zip_member` | core | 5 | The member uses encryption or an unsupported compression method. |
| `unsafe_output_name` | CLI | 5 | A document title or declared extension cannot be used as a filename, or the derived `<file>.d` directory name would be too long. |
| `output_name_collision` | CLI | 5 | Residual: two outputs still map to the same name in one directory after deduplication. |
| `output_exists` | CLI | 5 | A destination file already exists or cannot be created safely. |
| `trust_store_invalid` | CLI | 3 | `--trust-store` does not name a readable directory, holds a file that is not PEM or DER certificate data, or holds no trust anchor. A partially loaded store would silently change what "trusted" means, so the run fails instead. |
| `unsafe_output_directory` | CLI | 5 | The output path contains a symlink or reparse point, or is not a real directory. |
| `total_size_limit` | CLI | 5 | Aggregate decoded size exceeds `max_total_decoded_bytes`. |

Warning codes. Warnings never change the exit status by themselves:

| Code | Emitted by | Meaning |
| --- | --- | --- |
| `cryptographic_verification_not_performed` | all commands | Signature or timestamp material is present but was not verified. |
| `encrypted_document_unsupported` | all commands | A document declares the `encrypt` transform. |
| `unsupported_transform_chain` | all commands | A document uses a transform chain other than `base64` or `zip -> base64`. |
| `document_skipped_encrypted` | `extract` | An encrypted document was not extracted. |
| `document_skipped_unsupported_transform` | `extract` | A document with an unsupported transform chain was not extracted. |
| `dangling_objref` | all commands | An `OBJREF` outside the dossier and document profiles resolves to no XML ID. |
| `document_without_profile` | all commands | A `Document` has no `DocumentProfile` and was skipped. |
| `source_size_missing` | all commands | A `DocumentProfile` declares no `SourceSize`, so the decoded length is not checked against one. |
| `creation_date_missing` | all commands | The `DossierProfile` declares no `CreationDate`; the dossier `creation_date` is `null`. |
| `output_name_deduplicated` | `extract` | A document's output name was already taken in its directory, so it was renamed. |
| `nested_dossier_depth_limit` | `extract` | An embedded dossier was kept as a file because `--max-depth` was reached. |
| `nested_dossier_invalid` | `extract` | An embedded dossier could not be parsed; the raw payload was kept and the run continued. |

## The `verify` command

`verify` is the M2 milestone. This release ships **phase 1**: the XMLDSig
core plus certificate-path validation against a caller-supplied trust store.
XAdES qualifying properties are detected but not validated, and revocation and
timestamps are reported as `skipped`. That caps every verdict at
`indeterminate`: **phase 1 cannot return `valid`**, by construction and by
test. A caller that sees `indeterminate` has learned that nothing failed, not
that anything is trustworthy.

```text
openszigno verify FILE [--json]
    --trust-store DIR           # anchors, and optional extra CA certificates
    --at <RFC3339>              # validation time; default: now
    --allow-legacy-algorithms   # admit SHA-1 for diagnosis only
    --allow-namespace URI       # as on every other command, repeatable
```

`--offline` is not a flag because offline is the only mode: the verifier
performs no network or filesystem access of its own, in any mode. Reference
resolution is strictly same-document, and the trust store is the only external
material a run consults.

### Verification pipeline

Per `ds:Signature`, in document order, stopping early where continuing would be
meaningless:

1. **Structure and policy.** `ds:SignedInfo` and `ds:SignatureValue` are
   present; the signature sits at `//es:Document/ds:Signature` or
   `//es:Dossier/ds:Signature`; the canonicalization, signature, and digest
   algorithms are inside the pinned allowlist; every transform is inside the
   transform allowlist; every reference URI is `""` or `#id`; every `#id`
   resolves to exactly one node in the ID space `openszigno-core` validated;
   and the mandated e-dossier reference set is covered. Any failure here makes
   the verdict `invalid` and the later stages are not attempted — there is no
   point digesting a reference chain the policy already refused.
2. **Cryptography.** Each reference is resolved to a node set, its transform
   chain applied, the result canonicalized, and its digest recomputed and
   compared. `ds:SignedInfo` is canonicalized and `ds:SignatureValue` verified
   against the signing certificate (see
   [Signing-certificate selection](#signing-certificate-selection)).

   A same-document reference dereferences to a node set **with its comments
   already removed**, as XMLDSig 4.4.3.3 requires, so a with-comments transform
   applied afterwards still sees none and inserting a comment into a signed
   element cannot change its digest. The `#xpointer(...)` forms that would keep
   comments are not supported and are refused as external references.
3. **XAdES.** Presence is reported; nothing is validated (phase 2).
4. **Certificate path.** The signing certificate is chosen from `ds:KeyInfo`,
   then a path is built from it through the other candidate certificates to a
   configured anchor and validated.
5. **Revocation and timestamps.** Reported as `skipped`, never silently
   omitted.

### Reference scope

Because the e-dossier specification mandates *which elements* a signature must
reference, `verify` enforces reference-scope completeness. This is the
strongest defence against XML signature wrapping, and it is a check a generic
XMLDSig library cannot perform, because it depends on the container's
semantics rather than on what the signature claims about itself.

| Placement | Must cover |
| --- | --- |
| `//es:Document/ds:Signature` | the document's `es:DocumentProfile`, the document's payload `ds:Object`, the signature's own signature-profile object, and, when XAdES qualifying properties are present, the `xades:SignedProperties`. |
| `//es:Dossier/ds:Signature` | `/es:Dossier/es:DossierProfile`, `/es:Dossier/es:Documents`, the signature's own signature-profile object, and the same `xades:SignedProperties`. |

A reference covers a required element when the element is the resolved node or
a descendant of it, so a `URI=""` reference covers everything, and a reference
to a `ds:Object` covers what it wraps. Two rules follow from what real
dossiers actually contain:

- **The signature-profile object is located by content, never by position.**
  The requirement is satisfied by a reference that resolves either to the
  direct `ds:Object` child holding an `es:SignatureProfile` — in any dossier
  namespace the run allows — or to that `es:SignatureProfile` element itself.
  Both spellings occur, and the profile and qualifying-properties objects
  appear in either order, so neither the wrapper nor the child position can be
  assumed.
- **`SignedProperties` coverage is decided by resolution, not by `@Type`.** The
  requirement is satisfied by a reference that resolves to a
  `SignedProperties` element in any recognised XAdES namespace (1.1.1, 1.2.2,
  1.3.2, 1.4.1) or to an ancestor of it. The `Type` attribute is corroboration
  only: an attacker controls it, so it must never be able to satisfy a scope
  requirement on its own. Both `http://uri.etsi.org/01903#SignedProperties` and
  the versioned forms are recognised, and a reference that declares one but
  resolves elsewhere is called out in the failure message, because that is the
  shape a wrapping attempt takes.

Where the specification does not define the mandated set — a signature in a
placement the format does not describe, or one inside a `Document` that carries
no `DocumentProfile` — the answer is `reference_scope_unknown` (status
`unknown`), not a guess in either direction.

Every reference's resolved location is reported in
`data.signatures[].references[].resolved_to` as a path of element names, so a
caller can see exactly what was signed without any content leaving the tool.

### Algorithm policy

The e-dossier container specification deliberately places no constraint on
canonicalization, digest, or signature algorithms, so this pinned policy is the
only defence against an algorithm downgrade. It is not configurable in phase 1.

| Kind | Accepted | Refused |
| --- | --- | --- |
| Digest | SHA-256, SHA-384, SHA-512 | SHA-1 by default, MD5 always, and every other URI (`algorithm_rejected`) |
| Signature | RSA PKCS#1 v1.5 and RSA-PSS with SHA-256/384/512 and a modulus of at least 2048 bits; ECDSA P-256 with SHA-256 and P-384 with SHA-384 | RSA-SHA1 by default; MD5 variants, DSA, every HMAC method, RSA below 2048 bits, and a curve that does not match the named digest always (`algorithm_rejected`) |
| Canonicalization | Canonical XML 1.0 and Exclusive XML Canonicalization 1.0, each with and without comments | Canonical XML 1.1 and anything else (`c14n_unsupported`) |
| Transform | enveloped-signature, the four canonicalization algorithms above, and base64 | XSLT, XPath, XPath Filter 2.0, and anything else (`transform_not_allowed`) |

XSLT and XPath are refused unconditionally: they turn a reference into an
arbitrary computation over the document, which is the transform-abuse threat
this project refuses rather than bounds. An HMAC `SignatureMethod` in a dossier
is a known attack shape and is refused outright, which removes the
`HMACOutputLength` truncation class with it. Canonical XML 1.1 is refused
rather than approximated with 1.0, because the two differ on `xml:base` and on
`xml:*` attribute inheritance; refusing to answer is acceptable, answering
wrongly is not.

`--allow-legacy-algorithms` admits SHA-1 digests and the RSA-SHA1 signature
method **for diagnosis only**, which matters because Hungarian dossiers span
2007 to today and older material genuinely uses SHA-1. Under the flag those
algorithms emit `algorithm_legacy_allowed` with status `unknown` rather than
`digest_algorithm_allowed`/`signature_algorithm_allowed` with status `passed`,
so the verdict is capped at `indeterminate` and the tool never vouches for the
algorithm's strength. The status is `unknown` because the check-status
vocabulary has no separate "warning" value and `unknown` is the honest reading:
the digests were recomputed and matched, and the tool cannot say whether that
means anything. The flag can only ever lower a verdict: a `failed` check is
never turned into a `passed` one, and MD5, DSA, every HMAC method, and RSA keys
below 2048 bits stay refused whatever it is set to. It does not loosen
certificate-path validation either — a SHA-1-signed certificate is still
`cert_algorithm_rejected`.

Canonicalization is implemented in-tree, over the same `roxmltree` tree the
structural parser built, rather than delegated. The candidate library named in
the design (`bergshamra-c14n`) canonicalizes its own parser's tree and selects
document subsets by that tree's node indices, so using it would mean parsing
every dossier a second time with a second parser and trusting the two trees to
agree. It sits behind the `C14nBackend` trait, so a differential backend can
be added without touching the pipeline.

### Verification limits

Reported verbatim under `data.limits` in `verify --json`.

| Limit | Default | Purpose |
| --- | --- | --- |
| `max_signatures` | 64 | `ds:Signature` elements examined per dossier. |
| `max_references_per_signature` | 32 | `ds:Reference` elements per signature. |
| `max_transforms_per_reference` | 8 | Transforms in one reference's chain. |
| `max_certificates` | 64 | Certificates admitted into path building. |
| `max_chain_length` | 8 | Certificates in one candidate path. |
| `max_paths` | 32 | Completed candidate paths explored. |
| path search expansions | 256 (fixed) | Total candidates visited during path building, successful or not. Not configurable. |
| `ds:KeyInfo` candidates | 16 (fixed) | Certificates tried as the signer. |

### Signing-certificate selection

XMLDSig places no order on `ds:KeyInfo`, and real material does list an issuer
before the signer, so taking the first `ds:X509Certificate` would turn a good
signature into a false failure. Instead every certificate in `ds:KeyInfo` (at
most 16) is a candidate, and the signing certificate is the one whose public
key actually verifies `ds:SignatureValue`. End-entity certificates are tried
before CAs so the common case costs one verification.
`signatures[].signing_certificate_index` reports which candidate was chosen,
counted from zero in document order, and is `null` when none verified — in
which case `signature_value_invalid` says how many were tried. A candidate with
a key below the minimum size or of an unsupported type is reported as
`algorithm_rejected` rather than as a mismatch.

### Where candidate certificates come from

| Source | `chain[].source` | Role |
| --- | --- | --- |
| `ds:KeyInfo/ds:X509Data/ds:X509Certificate` | `key_info` | Signing-certificate candidates, and untrusted path candidates. |
| `xades:CertificateValues/xades:EncapsulatedX509Certificate`, and any other encapsulated certificate under the signature's XAdES properties | `certificate_values` | Untrusted path candidates. This is where real dossiers carry the intermediates, and usually the root. |
| A non-self-signed file in the trust store | `trust_store` | Untrusted path candidate. |
| A self-signed file in the trust store | `trust_store` | **Trust anchor.** |

The rule that matters: **only the trust store can supply an anchor.** A
self-signed root found inside a dossier is a candidate like any other and can
never make itself trusted; a dossier that carries its own root and no store is
configured still reports `cert_path_unknown`. Candidates are deduplicated by
DER, keeping the source they were first seen in, and a certificate the store
already anchors is used only in that role, so it cannot appear twice in one
path.

### Certificate path validation

There is no general-purpose RFC 5280 path validator in Rust that fits eIDAS
signing certificates — `rustls-webpki` is Web-PKI shaped and wants a DNS name —
so this is hand-written on `x509-cert`. That is a liability, and the mitigation
is a narrow, explicitly documented subset plus heavy negative testing. The
implemented subset is:

- candidate paths built by matching the subject distinguished name of a
  candidate issuer to the issuer name of the certificate below it, comparing
  the DER encodings (no RFC 4518 string preparation), bounded by
  `max_chain_length`, `max_paths`, **and a hard budget of 256 total search
  expansions**. The first two bounds are not enough on their own: a bag of
  certificates whose names all match but which never reaches an anchor produces
  no completed paths at all while the search explores exponentially many
  prefixes. Exceeding the budget is the distinct outcome
  `cert_path_search_exhausted` — the tool stopped looking, which is not the
  same statement as "no path exists";
- every link's signature verified with the issuer's public key under the
  algorithm allowlist above;
- every certificate's validity window checked against the validation time;
- `basicConstraints` with `cA=true` required on every non-leaf, and
  `pathLenConstraint` compliance checked against the number of intermediates
  below it;
- `keyUsage` `keyCertSign` required on any non-leaf that declares the
  extension, and `digitalSignature` or `nonRepudiation` on a leaf that declares
  it; an absent `keyUsage` does not by itself fail a certificate;
- `nameConstraints`, when present on a CA, applied to every certificate below
  it, per RFC 5280 section 4.2.1.10 and **failing closed throughout** (see
  below);
- critical extensions handled as below.

**Name constraints.** `directoryName` subtrees match as an RDN-sequence prefix
of the subject. `dNSName` subtrees match a host exactly or on a label boundary,
so `example.com` covers `host.example.com` but never `notexample.com`; a
leading dot means subdomains only. `rfc822Name` subtrees match an exact mailbox
when the constraint has a local part, the exact host part when it does not, and
any mailbox at or below the domain when it starts with a dot.
`uniformResourceIdentifier` subtrees are matched **against the URI's host**,
extracted from the authority, using the same label rules — a substring match
would let `https://evil.test/example.com` satisfy `example.com`. A URI with no
host, or whose host is an IP literal, cannot satisfy a DNS-style constraint and
is a violation rather than a pass. `iPAddress` subtrees are evaluated as an
address and mask of equal width. Every remaining case fails closed: a
constraint form this validator does not implement, a `minimum`/`maximum`
distance (which RFC 5280 forbids anyway), a name form it cannot evaluate under
a constrained CA, and a permitted subtree of a type the certificate carries but
does not match are all `cert_name_constraint_violation`.

**Critical extensions.** RFC 5280 requires a verifier to reject a certificate
carrying a critical extension it does not process, so the accepted set is
exactly what is processed: `basicConstraints`, `keyUsage`, `nameConstraints`,
`subjectAltName`, and `extendedKeyUsage`. Anything else marked critical is
`cert_unsupported_critical_extension`, including `certificatePolicies` (policy
processing is not implemented), QCStatements, `cRLDistributionPoints`, and
`authorityInfoAccess` — all of which are non-critical in practice, so marking
one critical is a request for processing this tool cannot honour. A **critical**
`extendedKeyUsage` must contain `anyExtendedKeyUsage`: there is no standard EKU
for document signing, and `id-kp-emailProtection` or `id-kp-clientAuth` do not
authorise it, so anything else is `cert_key_usage_invalid`. A non-critical
`extendedKeyUsage` is a hint the issuer chose not to enforce and is not checked.

**Malformed is not absent.** An extension whose bytes do not decode as its OID
says they should is `cert_malformed` (failed). Treating a decoding failure as
absence would make a corrupt `keyUsage` or `nameConstraints` silently vanish,
which is the wrong direction for every one of them.

Not implemented in phase 1: authority/subject key identifier matching as a path
hint, certificate policies and `policyConstraints`, `inhibitAnyPolicy`,
qualified-status determination, and cross-certificate handling beyond what
plain name chaining gives.

With no trust store configured, the path check is `cert_path_unknown` with
status `unknown` — not `failed`. The tool does not know, and saying "invalid"
would be as wrong as saying "valid".

### Trust store

`--trust-store DIR` reads certificates from a directory:

```text
<dir>/anchors/*        trust anchors, PEM or DER, one or more certs per file
<dir>/intermediates/*  optional extra CA certificates for path building
```

A directory holding certificate files directly, with no `anchors`
subdirectory, is read the same way. The split between the two subdirectories is
a convention, not a grant: **the verifier classifies what it is given**, and a
certificate is a trust anchor if and only if it is self-signed. Dropping an
intermediate into `anchors/` therefore makes it an extra untrusted path
candidate, not a trusted one, and a store holding only intermediates yields no
anchors and so `cert_path_unknown`. A self-signed anchor's own signature is
deliberately not verified: RFC 5280 does not require it, and demanding it would
reject a legitimate root that signed itself with an algorithm outside this
tool's allowlist. The classification never grants trust on its own — nothing
found inside a dossier is ever an anchor, however it is signed.

Files are read in sorted order so the same store always builds the same paths;
subdirectories and symlinks are skipped rather than followed. **Every entry is
parsed as an X.509 certificate at load time**, so a store that loads is one
whose every byte was understood: one malformed entry among good ones fails the
whole store. A file above 4 MiB, a directory holding more than 1024 entries, an
entry that is not a valid certificate, and an empty store are all
`trust_store_invalid` (exit 3), and the message names the entry's ordinal, never
the file, because the path may be private. No trust anchors are compiled into
the binary; importing a pinned EU trusted-list snapshot is phase 3.

### Verify result shape

`schema_version` stays at `1`: `verify` adds a new `command` value and its own
`data`, and changes no existing field's contract. `signatures_verified` in
`inspect` and `list` output stays `false`, because those commands still do not
verify anything.

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "verify",
  "input": { "format": "microsec-es3", "bytes": 8337 },
  "data": {
    "verdict": "indeterminate",
    "verification_time": {
      "requested": "2020-06-01T00:00:00Z",
      "effective": "2020-06-01T00:00:00Z",
      "source": "requested"
    },
    "policy": {
      "revocation": "offline",
      "trust_store": "configured",
      "trust_snapshot": null,
      "legacy_algorithms_allowed": false,
      "digest_algorithms": ["sha256", "sha384", "sha512"],
      "signature_algorithms": ["rsa-pkcs1-sha256", "…"],
      "c14n_algorithms": ["http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "…"],
      "transforms": ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "…"]
    },
    "limits": { "max_signatures": 64, "…": 0 },
    "counts": {
      "signatures": 1,
      "signatures_valid": 0,
      "signatures_invalid": 0,
      "signatures_indeterminate": 1,
      "timestamps": 0
    },
    "checks": [
      { "code": "signature_count_within_limits", "status": "passed",
        "message": "the number of signatures is within the verification limits" }
    ],
    "signatures": [
      {
        "index": 0,
        "scope": "document",
        "document_index": 0,
        "signature_id": "sig-doc",
        "verdict": "indeterminate",
        "xades_level": "detected",
        "signing_time": "2020-01-01T00:00:00Z",
        "signing_certificate_index": 0,
        "signing_certificate": {
          "subject_cn": "…",
          "issuer_cn": "…",
          "serial_hex": "01a2b3",
          "not_before": "2019-01-01T00:00:00Z",
          "not_after": "2039-01-01T00:00:00Z",
          "key_algorithm": "rsa",
          "key_bits": 2048,
          "sha256_fingerprint": "…",
          "qualified": null
        },
        "chain": [
          {
            "subject_cn": "…",
            "issuer_cn": "…",
            "serial_hex": "01a2b3",
            "not_before": "2019-01-01T00:00:00Z",
            "not_after": "2039-01-01T00:00:00Z",
            "is_trust_anchor": false,
            "source": "key_info"
          },
          { "subject_cn": "…", "issuer_cn": "…", "serial_hex": "…",
            "not_before": "…", "not_after": "…",
            "is_trust_anchor": true, "source": "trust_store" }
        ],
        "references": [
          {
            "index": 0,
            "uri": "#obj0",
            "resolved_to": "Dossier/Documents/Document/Object",
            "digest_algorithm": "sha256",
            "transforms": ["http://www.w3.org/2001/10/xml-exc-c14n#"],
            "status": "passed"
          }
        ],
        "timestamps": [],
        "checks": [
          { "code": "reference_digest_ok", "status": "passed",
            "message": "4 of 4 reference digests matched" }
        ]
      }
    ]
  },
  "warnings": [],
  "errors": []
}
```

Notes on the shape:

- `checks` at the top level belongs to the dossier; each signature carries its
  own `checks`, ordered by pipeline stage, so a consumer reading top to bottom
  sees the same order the tool evaluated.
- `code` and `status` are stable; `message` is human text and is not.
- **A consumer must treat an unknown `code` as blocking unless its `status` is
  `passed`.** Later versions add codes, and a consumer that ignores what it
  does not recognise would silently weaken its own policy.
- Absent data is `null`, never an optimistic default. `qualified: null` means
  "not determined", which is different from `false`.
- `references[].resolved_to` is filled in by the resolution stage, so it is
  present even when the run stopped at a policy failure and no digest was ever
  recomputed. In that case every `references[].status` is `skipped` and
  `resolved_to` still shows what each URI pointed at.
- `signing_time` is the `xades:SigningTime` the signature **claims**,
  normalised to RFC 3339 UTC (`null` when absent or unparseable). It is read,
  never trusted: nothing authenticates it until a verified timestamp token
  binds it, which is phase 2, and it never becomes the validation time — only
  `--at` and the clock do that. The `signing_time_present` check reports that
  it was read, always with status `unknown`.
- `xades_level` is a placeholder in phase 1: `"detected"` or `null`, because
  XAdES is not validated yet. `timestamps` is always empty.
- The certificate summary is limited on purpose to subject and issuer common
  names, serial, validity, key algorithm and size, and the SHA-256
  fingerprint. Full distinguished names and subject alternative names stay out
  of the report. **`verify --json` output can contain personal data of
  signers**, which is why those fields are structured rather than interpolated
  into free text: no check message ever quotes a certificate subject, a
  document title, or payload content.

### Verify check codes

`status` is one of `passed`, `failed`, `skipped`, or `unknown`. `unknown` means
the tool could not determine the answer and is never a substitute for `failed`.

| Code | Status when emitted | Meaning |
| --- | --- | --- |
| `no_signatures` | `unknown` | The dossier carries no `ds:Signature`, so there is nothing that could be valid. |
| `signature_count_within_limits` | `passed` | The signature count is within `max_signatures`. |
| `signature_limit_exceeded` | `failed` | More signatures than `max_signatures`; the excess is not examined. |
| `sig_structure` | `passed` | `ds:SignedInfo`, `ds:SignatureValue`, the methods, and at least one reference are present and within limits. |
| `sig_structure_invalid` | `failed` | One of those is missing, malformed, or over a limit. |
| `sig_placement` | `passed` | The signature is at a placement the e-dossier format defines. |
| `sig_placement_invalid` | `failed` | It is not. |
| `c14n_method_allowed` | `passed` | `ds:CanonicalizationMethod` is implemented. |
| `c14n_unsupported` | `failed` | A canonicalization algorithm, on `ds:SignedInfo` or in a transform, is known but not implemented. |
| `signature_algorithm_allowed` | `passed` | `ds:SignatureMethod` is inside the allowlist. |
| `digest_algorithm_allowed` | `passed` | Every `ds:DigestMethod` is inside the allowlist. |
| `algorithm_rejected` | `failed` | A signature method, a digest method, or a signing key is outside the pinned policy. May appear more than once. |
| `algorithm_legacy_allowed` | `unknown` | SHA-1 was admitted because `--allow-legacy-algorithms` was given. Blocking: caps the verdict at `indeterminate`. May appear twice, once for the signature method and once for the digests. |
| `transforms_allowed` | `passed` | Every transform is inside the allowlist. |
| `transform_not_allowed` | `failed` | A transform is outside it; XSLT and XPath always are. |
| `references_same_document` | `passed` | Every `ds:Reference/@URI` is `""` or `#id`. |
| `reference_external` | `failed` | A reference names something else. Nothing is ever dereferenced. |
| `references_resolve` | `passed` | Every `#id` resolves to exactly one node in the validated ID space. |
| `reference_unresolved` | `failed` | One does not. |
| `reference_scope_complete` | `passed` | Every element the container mandates is covered. |
| `reference_scope_incomplete` | `failed` | One is not; the message names which, and says so when a reference declared the `SignedProperties` `Type` without resolving to one. |
| `reference_scope_unknown` | `unknown` | The mandated set is undefined for this signature's placement. |
| `reference_digest_ok` | `passed` | Every reference digest recomputed correctly. |
| `reference_digest_mismatch` | `failed` | One did not, or its transform chain could not be applied. |
| `signedinfo_canonicalization` | `passed` | `ds:SignedInfo` canonicalized without error. |
| `signedinfo_canonicalization_failed` | `failed` | It did not. |
| `signature_value_ok` | `passed` | `ds:SignatureValue` verified over the canonical `ds:SignedInfo`. |
| `signature_value_invalid` | `failed` | It did not verify, or is not canonical Base64. |
| `xades_present` | `passed` | `xades:QualifyingProperties` was found for this signature. |
| `xades_absent` | `skipped` | None was found; this is a bare XMLDSig signature. |
| `xades_not_validated` | `skipped` | XAdES properties are not validated in this phase. |
| `signing_certificate_available` | `passed` | A usable certificate was found in `ds:KeyInfo`. |
| `signing_certificate_missing` | `failed` | None was. |
| `signing_time_present` | `unknown` | Reports whether a claimed `xades:SigningTime` was read. Always `unknown`: the claim is unauthenticated until phase 2 binds it to a timestamp. |
| `cert_malformed` | `failed` | A certificate in the path could not be re-encoded or its signature is not a whole number of bytes. |
| `cert_path_ok` | `passed` | A path to a configured anchor was built and every rule above holds. |
| `cert_path_unknown` | `unknown` | No trust anchors were configured. |
| `cert_path_untrusted` | `failed` | No path to a configured anchor exists. The message says how many candidates were considered and names the issuer CN of the highest certificate reached, which is the public CA name a caller needs to add to the store. |
| `cert_path_search_exhausted` | `failed` | Path building hit its expansion budget. The tool stopped looking; this is not a statement that no path exists. |
| `cert_path_length_exceeded` | `failed` | A CA is followed by more intermediates than its `pathLenConstraint` allows. |
| `cert_expired` | `failed` | A certificate in the path had expired at the validation time. |
| `cert_not_yet_valid` | `failed` | One was not yet valid then. |
| `cert_signature_invalid` | `failed` | A link is not correctly signed by its issuer. |
| `cert_algorithm_rejected` | `failed` | A certificate signature algorithm or key is outside the policy. |
| `cert_key_usage_invalid` | `failed` | A CA does not permit `keyCertSign`, or the leaf permits neither `digitalSignature` nor `nonRepudiation`. |
| `cert_basic_constraints_invalid` | `failed` | An issuing certificate is not marked as a CA. |
| `cert_name_constraint_violation` | `failed` | A certificate violates a name constraint imposed by a CA above it. |
| `cert_unsupported_critical_extension` | `failed` | A certificate carries a critical extension this validator does not understand. |
| `revocation_not_checked` | `skipped` | Revocation is phase 3. Blocking: caps the verdict at `indeterminate`. |
| `timestamp_not_checked` | `skipped` | Timestamps are phase 2. Blocking: caps the verdict at `indeterminate`. |

### Verdicts

Per signature: `invalid` when any check is `failed`; otherwise `indeterminate`
when any check is `unknown` or `skipped`; otherwise `valid`. The dossier
verdict is the worst of the per-signature verdicts, and `indeterminate` when
there are no signatures — there is nothing to be valid. The terminology follows
ETSI EN 319 102-1: `valid` is TOTAL-PASSED, `invalid` is TOTAL-FAILED, and
`indeterminate` is INDETERMINATE.

Because `revocation_not_checked` and `timestamp_not_checked` are always emitted
as blocking `skipped` checks, `valid` is unreachable in this release. That is
the correct and honest outcome for a phase-1 verifier, and it is asserted by a
test.

## Extraction policy

- Decode Base64 as bytes, never by treating a dossier as locale-dependent
  text after the XML layer.
- Expand embedded dossiers recursively by default. A document flagged
  `nested_dossier`, or whose decoded bytes sniff as a dossier, is written as a
  payload file *and* parsed with the same options; its documents are extracted
  into a sibling subdirectory named after the payload file plus `.d`:

  ```text
  out/
    court.dosszie            # the embedded dossier, byte for byte
    court.dosszie.d/         # what it contains
      ruling.pdf
      annex.dosszie
      annex.dosszie.d/
        notice.html
  ```

  Subdirectories are created relative to the parent's directory descriptor
  with the same `mkdirat`/`openat` machinery as files on Unix. A nested parse
  failure never fails the run: it is reported as `nested_dossier_invalid` and
  the raw file is kept. `--no-recursive` disables expansion entirely.
- Derive an output extension from content sniffing only when the sanitised
  title has none and the dossier declares none; a declared extension always
  wins.
- Deduplicate repeated output names deterministically. Real dossiers reuse
  document titles, so when two planned outputs in the same directory fold to
  the same NFC-normalised, case-folded key, the first keeps its name and each
  later one gets `-<document index>` inserted before its extension
  (`ruling.pdf`, then `ruling-7.pdf`). A `<file>.d` subdirectory follows its
  payload file, so a renamed embedded dossier lands in `court-7.dosszie.d`;
  a directory name that clashes on its own is renamed by the same rule. Each
  rename is reported as `output_name_deduplicated`, naming the document index
  and its `dossier_path` only. Comparison stays case-insensitive, and a name
  that still collides after renaming is the residual error
  `output_name_collision`, which aborts the run with nothing written.
- All documents in the whole tree are decoded in memory and all output names,
  collisions, and destination existence are checked before the output
  directory is touched; a decode failure, an unsafe name, a collision, or a
  pre-existing destination file or subdirectory aborts with no files written.
- Derive output names from the document title only after sanitization.
  Reject empty titles, `.` / `..`, path separators, absolute paths, control,
  format, bidirectional, invisible, and private-use characters,
  non-ASCII-space whitespace, leading `.` or `-`, trailing `.` or space,
  reserved Windows device names, and over-long names. A declared MIME
  extension must be short and alphanumeric or the document is rejected; it
  is appended when the title does not already end with it. Names are
  NFC-normalised and collisions are detected case-insensitively on the
  normalised form.
- The output directory may be new or existing. Its path must not contain
  symlinks (or reparse points on Windows). A directory created by this run
  has mode `0700` on Unix; an existing directory keeps its mode.
- On Unix, the output path is opened one component at a time relative to
  the previous directory descriptor with `O_NOFOLLOW`, missing components
  are created relative to that descriptor, and files are created relative to
  the final descriptor with `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`. No
  component is ever resolved through a symlink, so swapping any part of the
  path for a link after the checks cannot redirect writes. On other
  platforms files are created by path with no-clobber semantics; the
  directory-swap race remains a residual risk there.
- Existing files are never overwritten. If creating or writing a later file
  fails, everything the same run created — files and the subdirectories it
  made, deepest first — is removed before the error is reported; the message
  says so if that clean-up itself fails.
- Enforce fixed limits for dossier bytes, document count, decoded bytes, ZIP
  member count, per-member bytes, total bytes, and compression ratio.
- Report document encryption, missing payload references, and unsupported
  transform chains explicitly.

## Verification boundary

`verify` ships the M2 phase-1 subset: canonicalization, reference digests, the
signature value, the e-dossier reference-scope rules, and certificate-path
validation against a caller-supplied trust store. Within that subset it may
report a signature `invalid`, which is a positive cryptographic finding.

**It may never report anything `valid`.** Revocation and timestamps are not
checked, XAdES qualifying properties are detected but not validated, and
qualified status is not determined, so every check that would be needed to
conclude `valid` is emitted as `skipped` and the verdict is capped at
`indeterminate`. `indeterminate` means "nothing failed", not "this is
trustworthy", and the human output says so on every run.

The rule for the other four commands is unchanged: `inspect`, `list`,
`extract`, and `validate-structure` verify nothing, `signatures_verified` and
`cryptographic_verification_performed` stay `false`, and the warning
`cryptographic_verification_not_performed` keeps its meaning for them. It is
deliberately *not* emitted by `verify`, which reports what it actually did.

Extracting a document is never proof that it was signed or that the signature
is valid. A rejection is likewise not proof of forgery: the pinned algorithm
policy refuses some genuine older dossiers, which is the correct trade and must
not be misread.

Still outside the boundary until the later phases ship: XAdES
`SigningCertificate`/`SigningCertificateV2` binding (so in phase 1 the
signing certificate is taken from `ds:KeyInfo`, which the signature covers only
if a reference says so), signing time, signature policy, level detection,
timestamps, revocation, and trusted-list qualified status.
