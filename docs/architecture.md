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

- XMLDSig/XAdES signature verification with certificate-path and revocation
  checking (M2);
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
  openszigno-core/  # XML model, bounded decoding, transforms, stable codes
  openszigno-cli/   # clap commands, human output, JSON protocol, exit codes
```

`openszigno-core` does not write files or print output. The CLI owns all
filesystem policy and serialisation. This keeps the parser testable and makes
future library use possible without weakening CLI safety.

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
company-court dossiers routinely deviate in these two ways. The warnings carry
the codes `dangling_objref`, `document_without_profile`, and
`source_size_missing`, and never change an exit status by themselves.

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
content falls through to the UTF-8 text/binary test. The categories are `pdf`, `html`, `xml`, `dossier`,
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
| `verify FILE` | Reserved for a later full XMLDSig/XAdES implementation; not currently a subcommand. | No |

All commands accept `--json` and `--allow-namespace <URI>` (repeatable).
`extract` additionally accepts `--no-recursive`, which writes an embedded
dossier as a plain payload file instead of expanding it, and
`--max-depth <N>` (default 3), which bounds the nesting levels expanded;
values above the hard cap of 8 are clamped to 8. In JSON mode, stdout contains exactly one JSON
object and diagnostics go to stderr. Document ordering is the source XML
order. No command writes XML payload bytes to stdout.

## JSON envelope

The envelope fields are always present:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, or `usage`. |
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

The `dossier` object carries `title`, `category` (or `null`), `creation_date`,
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
| `output_name_deduplicated` | `extract` | A document's output name was already taken in its directory, so it was renamed. |
| `nested_dossier_depth_limit` | `extract` | An embedded dossier was kept as a file because `--max-depth` was reached. |
| `nested_dossier_invalid` | `extract` | An embedded dossier could not be parsed; the raw payload was kept and the run continued. |

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

This is the rule that applies until `verify` ships: no command, message, or
field may state or imply that a signature, certificate, timestamp, or dossier
is valid. Signature and timestamp material is reported by presence only, and
`signatures_verified` and `cryptographic_verification_performed` are always
`false`.

`verify` remains unavailable until it can validate XMLDSig/XAdES references
against the e-dossier placement and scope rules in the primary specification.
It must use strict duplicate-ID detection and reference resolution, a pinned
algorithm policy, trust-store configuration, and an explicit online/offline
revocation policy. Extracting a document is never proof that it was signed or
that the signature is valid.
