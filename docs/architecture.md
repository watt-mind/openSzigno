# Architecture and CLI contract

## Goals

- Provide distributable, cross-platform binaries.
- Be safe by default when handling untrusted dossiers.
- Make every operation usable by agents: deterministic exit statuses and a
  documented JSON result.
- Separate **structural parsing/extraction** from **cryptographic validation**.

## Non-goals for the first release

- creating, editing, signing, timestamping, encrypting, or decrypting
  dossiers;
- declaring a signature, certificate, timestamp, or dossier legally valid;
- supporting encrypted payload extraction;
- silently accepting arbitrary XML that merely has an `.es3` suffix.

## Rust crate shape

```text
crates/
  openszigno-core/  # XML model, bounded decoding, transforms, safe extraction
  openszigno-cli/   # clap commands, human output, JSON protocol, exit codes
```

`openszigno-core` must not write files or print output. The CLI owns all
filesystem policy and serialisation. This keeps the parser testable and makes
future library/API use possible without weakening CLI safety.

The MVP uses `roxmltree` after bounded UTF-8/ISO-8859-2 decoding for
namespace-aware XML parsing, `base64` and `zip` for bounded payload decoding,
`clap` for command parsing, and `serde`/`serde_json` for the protocol.
Dependency versions and licenses are captured by `Cargo.lock` and Cargo
metadata.

## Parser safety model

The parser is a bounded whole-document parser, not a streaming one. Untrusted
input passes through these stages, each with an explicit limit:

1. **Input size.** The file is read with a hard cap (`max_input_bytes`,
   64 MiB). Larger inputs fail with `input_too_large` before parsing.
2. **Encoding.** Only the `encoding` pseudo-attribute of the XML declaration
   itself is consulted; comments or later content cannot select an encoding.
   UTF-8 and ISO-8859-2 are decoded strictly; anything else is
   `unsupported_encoding` or `invalid_encoding`.
3. **Pre-parse scan.** A linear scan over the decoded text rejects any
   `<!...>` construct outside comments and CDATA (`unsafe_xml`, which covers
   DOCTYPE and entity declarations), element nesting deeper than
   `max_xml_depth` (128), and more than `max_xml_nodes` (1,000,000) elements.
   This runs before the recursive tree parser, so deep nesting cannot exhaust
   the stack.
4. **Tree parse.** `roxmltree` parses with DTDs disabled and its own node
   limit as a backstop. Parse failures report only a line and column; element,
   attribute, and entity names from the input are never echoed.
5. **Structure.** Root element and namespace, unique unprefixed `Id`
   attributes, `OBJREF` resolution to the direct `Documents` element and to
   exactly one direct `ds:Object` per document, and `max_documents` (256).
6. **Payload decoding.** Base64 is decoded strictly (canonical padding) with
   `max_base64_chars` and `max_decoded_document_bytes` (64 MiB) limits. ZIP
   payloads must contain exactly one regular-file member with a bare name;
   the expanded size is capped while reading, and the compression ratio
   (`max_zip_compression_ratio`, 100:1) is checked on the actual decoded
   length, not on header fields. Encrypted or non-deflate ZIP members are
   reported as `unsupported_zip_member`. The decoded length must equal the
   declared `SourceSize`.
7. **Aggregate output.** The CLI enforces `max_total_decoded_bytes` (256 MiB)
   across all documents of one extraction.

Peak memory is roughly a small multiple of the input size (the raw bytes, the
decoded text, the tree, and the decoded payloads are all held at once). The
limits are compile-time defaults exposed in `inspect --json`; they are not
yet configurable on the command line.

## Command contract

| Command | Function | Mutates input? |
| --- | --- | --- |
| `inspect FILE` | Identify the format; return dossier metadata, limits, and capability warnings. | No |
| `list FILE` | Return deterministic document records and signature/timestamp presence. | No |
| `extract FILE --output DIR` | Decode supported documents into a new or existing directory without overwriting files. | No |
| `validate-structure FILE` | Apply the project's strict structural rules without validating signatures. | No |
| `verify FILE` | Reserved for a later full XMLDSig/XAdES implementation; not currently a subcommand. | No |

All commands accept `--json`. In JSON mode, stdout contains exactly one JSON
object and diagnostics go to stderr. Document ordering is the source XML
order. No command writes XML payload bytes to stdout by default.

Result envelope (from `inspect --json`; fields are always present):

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "inspect",
  "input": { "format": "microsec-es3", "bytes": 1109 },
  "data": {
    "dossier": { "title": "...", "documents": 1, "signatures_present": 0,
                 "timestamps_present": 0, "signatures_verified": false },
    "limits": { "max_input_bytes": 67108864 },
    "capabilities": { "cryptographic_verification": false }
  },
  "warnings": [],
  "errors": []
}
```

`data` is command-specific: `list` adds a `documents` array in source order,
`extract` reports `extracted`, `extracted_count`, and `skipped_count`, and
`validate-structure` reports `valid_structure` and
`cryptographic_verification_performed: false`. `warnings` and `errors` are
arrays of objects with stable `code` and human-readable `message` fields.
Messages never contain input paths, document titles, or payload content. On
failure `ok` is `false`, `data` is `null`, and `input.format` is `null` when
the input could not be parsed as a dossier.

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
`command: "usage"` and the error code `usage_error`. `--help` and `--version`
always print plain text. If stdout cannot be written (for example a closed
pipe), the process exits with status 3 without printing a panic.

## Stable codes

Error codes and the exit status they map to:

| Code | Exit | Meaning |
| --- | --- | --- |
| `io_error` | 3 | The input could not be read, or output could not be created or written for a reason other than a pre-existing file. |
| `usage_error` | 2 | Invalid command line (JSON mode only). |
| `input_too_large` | 4 | Input exceeds `max_input_bytes`. |
| `unsupported_encoding`, `invalid_encoding` | 4 | XML declaration names an unsupported encoding, or bytes are invalid for the declared encoding. |
| `unsafe_xml` | 4 | DTD/entity declaration, nesting depth, or node count limit. |
| `invalid_xml` | 4 | Not well-formed XML. |
| `wrong_root` | 4 | Root is not `Dossier` in the default Microsec namespace. |
| `missing_element`, `invalid_attribute` | 4 | Required structure is absent or malformed. |
| `duplicate_id`, `unresolved_objref` | 4 | ID uniqueness or `OBJREF` resolution failed. |
| `too_many_documents` | 4 | More than `max_documents` documents. |
| `decoded_too_large` | 4 or 5 | A declared or decoded payload exceeds a size limit (4 when detected during parsing, 5 during extraction). |
| `invalid_base64`, `source_size_mismatch` | 5 | Payload is not canonical Base64 or its length differs from `SourceSize`. |
| `invalid_zip`, `zip_member_limit`, `zip_size_limit`, `zip_ratio_limit`, `unsafe_zip_member`, `unsupported_zip_member` | 5 | ZIP payload is malformed, violates a limit, has an unsafe member path, or uses encryption/an unsupported method. |
| `unsafe_output_name` | 5 | A document title cannot be used as a filename. |
| `output_name_collision` | 5 | Two documents map to the same filename. |
| `output_exists` | 5 | A destination file already exists. |
| `unsafe_output_directory` | 5 | The output path contains a symlink or is not a real directory. |
| `total_size_limit` | 5 | Aggregate decoded size exceeds `max_total_decoded_bytes`. |

Warning codes (exit 0):

| Code | Meaning |
| --- | --- |
| `cryptographic_verification_not_performed` | Signature or timestamp material is present but was not verified. |
| `encrypted_document_unsupported` | A document declares the `encrypt` transform. |
| `unsupported_transform_chain` | A document uses a transform chain other than `base64` or `zip -> base64`. |
| `document_skipped_encrypted` | `extract` skipped an encrypted document. |
| `document_skipped_unsupported_transform` | `extract` skipped a document with an unsupported transform chain. |

## Extraction policy

- Decode Base64 as bytes, never by treating a dossier as locale-dependent
  text after the XML layer.
- All documents are decoded in memory and all output names are checked
  before the output directory is touched; a decode failure, an unsafe name,
  a collision, or a pre-existing destination file aborts with no files
  written.
- Derive output names from the document title only after sanitization.
  Reject empty titles, `.` / `..`, path separators, absolute paths, control,
  format, bidirectional, and invisible characters, non-ASCII-space
  whitespace, leading `.` or `-`, trailing `.` or space, reserved Windows
  device names, and over-long names. The MIME extension is appended only if
  it is short and alphanumeric. Names are NFC-normalised and collisions are
  detected case-insensitively on the normalised form.
- The output directory may be new or existing. Its path must not contain
  symlinks (or reparse points on Windows). A directory created by this run
  has mode `0700` on Unix; an existing directory keeps its mode.
- On Unix, files are created relative to an open directory descriptor with
  `O_CREAT|O_EXCL|O_NOFOLLOW` and mode `0600`, so swapping the output
  directory for a symlink after the checks cannot redirect writes. On other
  platforms files are created by path with no-clobber semantics; the
  directory-swap race remains a residual risk there.
- Existing files are never overwritten. If creating or writing a later file
  fails, files created by the same run are removed before the error is
  reported; the message says so if that clean-up itself fails.
- Enforce fixed limits for dossier bytes, document count, decoded bytes, ZIP
  member count, per-member bytes, total bytes, and compression ratio.
- Report document encryption, missing payload references, and unsupported
  transform chains explicitly.

## Verification boundary

`verify` remains unavailable until it can validate XMLDSig/XAdES references
against the e-dossier placement and scope rules in the primary specification.
It must use strict duplicate-ID detection and reference resolution, a pinned
algorithm policy, trust-store configuration, and an explicit online/offline
revocation policy. Extracting a document is never proof that it was signed or
that the signature is valid.
