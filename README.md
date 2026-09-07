# openSzigno

A safe, agent-friendly command-line tool for inspecting, listing, structurally
validating, and extracting Hungarian Microsec e-Szignó e-dossiers (`.es3`).

[![CI](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.88%2B-orange.svg)](rust-toolchain.toml)

> **Security boundary:** this release performs structural validation and
> bounded extraction only. It does **not** verify XMLDSig/XAdES signatures,
> certificates, certificate chains, revocation, timestamps, or legal
> authenticity. Successfully parsing or extracting a dossier is never evidence
> that it is authentic, signed, or legally valid.

## Why and for whom

openSzigno exists because `.es3` dossiers are XML containers that arrive from
untrusted parties and are usually opened with a desktop application. Automated
pipelines and coding agents need something else: a single binary that reads a
dossier, reports what is inside, and writes the payloads to disk without
trusting the input.

- **For agents and automation.** Every command accepts `--json` and then emits
  exactly one JSON object on stdout, with a stable envelope, stable error
  codes, and stable exit-status categories. Diagnostics go to stderr and never
  contaminate stdout.
- **For people.** Without `--json` the same commands print short, readable
  terminal output that always states the verification boundary.
- **For safety.** Untrusted input is bounded at every stage: file size, XML
  depth and node count, Base64 length, decoded payload size, ZIP member count
  and compression ratio, and aggregate extraction size. Extraction never
  overwrites an existing file and never follows a symlink out of the output
  directory.

## Install

### From source

Requires Rust 1.88 or newer.

```sh
git clone https://github.com/watt-mind/openSzigno.git
cd openSzigno
cargo build --release --locked
./target/release/openszigno --help
```

To install the binary into `~/.cargo/bin`:

```sh
cargo install --path crates/openszigno-cli --locked
```

### Prebuilt binaries

Once a version tag is published, prebuilt binaries for Linux, macOS, and
Windows are attached to the matching entry on the
[GitHub Releases](https://github.com/watt-mind/openSzigno/releases) page.
Download the archive for your platform, verify the checksum, and place the
binary somewhere on your `PATH`.

## Quick start

Human mode:

```sh
openszigno inspect tests/fixtures/plain-base64.es3
```

```text
Microsec e-Szigno dossier
Title: Unsigned synthetic plain fixture
Documents: 1
Signatures present: 0 (not verified)
Timestamps present: 0 (not verified)
```

```sh
openszigno list tests/fixtures/plain-base64.es3
```

```text
Unsigned synthetic plain fixture
[0] hello.txt | text/plain | 41 B | ["base64"]
Signatures/timestamps are listed by presence only; none were verified.
```

```sh
openszigno extract tests/fixtures/plain-base64.es3 --output ./out
```

```text
Extracted 1 document(s).
[0] hello.txt (41 B)
Extraction is not proof of signature validity.
```

Agent mode. The tool writes one compact object; the example below is
pretty-printed for readability:

```sh
openszigno inspect tests/fixtures/plain-base64.es3 --json
```

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

```sh
openszigno extract tests/fixtures/plain-base64.es3 --output ./out --json
```

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "extract",
  "input": { "format": "microsec-es3", "bytes": 1109 },
  "data": {
    "extracted": [
      { "bytes": 41, "document_index": 0, "filename": "hello.txt" }
    ],
    "extracted_count": 1,
    "skipped_count": 0
  },
  "warnings": [],
  "errors": []
}
```

A failure uses the same envelope with `ok: false`, a null `data`, and a stable
error code:

```sh
openszigno inspect tests/fixtures/doctype.es3 --json
```

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

## Command reference

| Command | What it does | Writes files? |
| --- | --- | --- |
| `openszigno inspect FILE` | Identifies the dossier and reports title, category, namespace, XML encoding, document count, signature/timestamp presence, the active limits, and capability flags. | No |
| `openszigno list FILE` | Lists document records in source XML order with title, creation date, MIME type, declared source size, `OBJREF`, and transform chain. | No |
| `openszigno validate-structure FILE` | Applies the strict structural rules and reports `valid_structure` plus `cryptographic_verification_performed: false`. | No |
| `openszigno extract FILE --output DIR` | Decodes supported payloads into `DIR`, never overwriting an existing file. | Yes |

Flags:

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--json` | all commands | Emit exactly one JSON object on stdout. |
| `-o`, `--output DIR` | `extract` | Destination directory; created if missing. |
| `-h`, `--help` | all commands | Print help as plain text. |
| `-V`, `--version` | top level | Print the version as plain text. |

A cryptographic `verify` command is not part of this release. It is planned as
milestone M2; until it ships, the rule in
[Verification boundary](docs/architecture.md#verification-boundary) applies.

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | The operation completed. Documents may have been skipped with explicit warnings. |
| `2` | Command-line usage error. |
| `3` | Input or output error, including a stdout that cannot be written. |
| `4` | Invalid, unsupported, or unsafe dossier structure. |
| `5` | Payload decoding or safe-extraction failure. |

## JSON contract in brief

In `--json` mode stdout carries exactly one object with these fields:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. Incremented on a breaking envelope change. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, or `usage`. |
| `input` | object | `format` (`"microsec-es3"` or `null`) and `bytes` (or `null`). |
| `data` | object or null | Command-specific payload; `null` on failure. |
| `warnings` | array | Objects with stable `code` and human `message`. |
| `errors` | array | Objects with stable `code` and human `message`. |

Messages never contain input paths, document titles, or payload content.
Document ordering is source XML order. The full list of stable error and
warning codes, and the exit status each maps to, is in
[docs/architecture.md](docs/architecture.md#stable-codes).

## Limits

Limits are compile-time defaults and are reported by `inspect`. They are not
yet configurable on the command line.

| Limit | Default |
| --- | --- |
| `max_input_bytes` | 64 MiB |
| `max_documents` | 256 |
| `max_base64_chars` | 96 MiB |
| `max_decoded_document_bytes` | 64 MiB |
| `max_total_decoded_bytes` | 256 MiB |
| `max_zip_members` | 16 |
| `max_zip_expanded_bytes` | 64 MiB |
| `max_zip_compression_ratio` | 100 |
| `max_xml_depth` | 128 |
| `max_xml_nodes` | 1,000,000 |

## What is not supported yet

These are planned milestones, not permanent exclusions. Until the code exists,
the tool reports presence only and claims nothing about validity. See
[docs/roadmap.md](docs/roadmap.md) for the ordered plan.

| Not yet supported | Planned as |
| --- | --- |
| Custom compatible e-dossier namespaces, for example the company-court (e-cégeljárás) dossiers. Only the default `https://www.microsec.hu/ds/e-szigno30#` namespace is accepted today. | M1 |
| XMLDSig/XAdES signature verification, including certificate-path validation and revocation checking. | M2 |
| Timestamp verification. | M3 |
| Decryption of encrypted payloads. A document that declares the `encrypt` transform is reported and skipped. | M4 |

Outside the current plan altogether:

- transform chains other than `base64` and `zip -> base64`;
- XML encodings other than UTF-8 and ISO-8859-2;
- DTDs, DOCTYPE declarations, and entity declarations, which are rejected by
  design;
- creating, editing, signing, timestamping, or encrypting dossiers.

## Documentation

- [Documentation index](docs/index.md)
- [Architecture and CLI contract](docs/architecture.md)
- [Research and source register](docs/research.md)
- [Testing and fixture policy](docs/testing.md)
- [Roadmap and residual risks](docs/roadmap.md)

## Contributing

`develop` is the default integration branch and `master` is the stable branch.
Open pull requests against `develop`. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the branch model, commit conventions, and required checks, and
[SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability.

## License and trademarks

Licensed under the [MIT License](LICENSE). Test fixtures under
`tests/fixtures/` are dedicated under CC0-1.0.

`e-Szignó`, `Microsec`, and related marks belong to their respective owners.
openSzigno is an independent project, maintained by Watt-Mind, and is not
affiliated with, endorsed by, or certified by Microsec.
