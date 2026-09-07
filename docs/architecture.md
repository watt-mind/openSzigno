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
`clap` for command parsing, and `serde`/`serde_json` for the protocol. The XML
tree is intentionally bounded by the 64 MiB input limit and a nesting limit;
DTD/entity declarations are rejected before parsing. Dependency versions and
licenses are captured by `Cargo.lock` and Cargo metadata.

## Command contract

| Command | Function | Mutates input? |
| --- | --- | --- |
| `inspect FILE` | Identify the format; return dossier metadata, limits, and capability warnings. | No |
| `list FILE` | Return deterministic document records and signature/timestamp presence. | No |
| `extract FILE --output DIR` | Decode supported documents into a newly created or explicitly allowed directory. | No |
| `validate-structure FILE` | Apply the project's strict structural rules without validating signatures. | No |
| `verify FILE` | Reserved for a later full XMLDSig/XAdES implementation. | No |

All commands accept `--json`. In JSON mode, stdout contains exactly one JSON
object and diagnostics go to stderr. Document ordering is the source XML
order. No command writes XML payload bytes to stdout by default.

Illustrative result shape:

```json
{
  "schema_version": 1,
  "ok": true,
  "input": { "format": "microsec-es3", "bytes": 1234 },
  "dossier": { "title": "Example", "documents": 1 },
  "warnings": [],
  "errors": []
}
```

The implemented envelope also includes `command` and a `data` object containing
the command-specific result. `warnings` and `errors` are arrays of objects with
stable `code` and human-readable `message` fields.

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

## Extraction policy

- Decode Base64 as bytes, never by treating a dossier as locale-dependent
  text after the XML layer.
- Derive output names from metadata only after sanitization. Reject path
  separators, `.` / `..`, control characters, absolute paths, and collisions.
- Create output files with no-clobber semantics unless an explicit future
  `--overwrite` option is used.
- Enforce configurable limits for dossier bytes, document count, decoded
  bytes, ZIP member count, per-member bytes, total bytes, and compression
  ratio. Secure defaults are mandatory.
- Report document encryption, missing payload references, and unsupported
  transform chains explicitly.

## Verification boundary

`verify` remains unavailable until it can validate XMLDSig/XAdES references
against the e-dossier placement and scope rules in the primary specification.
It must use strict duplicate-ID detection and reference resolution, a pinned
algorithm policy, trust-store configuration, and an explicit online/offline
revocation policy. Extracting a document is never proof that it was signed or
that the signature is valid.
