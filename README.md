# openSzigno

A safe, agent-friendly command-line tool for inspecting, listing, structurally
validating, and extracting Hungarian Microsec e-Szignó e-dossiers (`.es3`).

[![CI](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.88%2B-orange.svg)](rust-toolchain.toml)

> **Security boundary:** `openszigno verify` checks XMLDSig canonicalization,
> reference digests, signature values, the e-dossier reference-scope rules, the
> XAdES signed `SigningCertificate` binding, RFC 3161 signature timestamps, and
> certificate paths against a trust store you supply. It does **not** yet check
> revocation or qualified status, so **it can never report a signature as
> valid** — the best verdict it can reach is `indeterminate`, meaning "nothing
> failed", not "this is trustworthy". It can report a signature `invalid`, and
> that finding is meaningful. Successfully parsing or extracting a dossier is
> never evidence that it is authentic, signed, or legally valid.

## Installation

Every channel below ships the same binary, `openszigno`. Prebuilt archives
are built for five targets and carry a SHA-256 checksum file; the container
image is built for `linux/amd64` and `linux/arm64`. Homebrew, crates.io, and
the container image are available from 0.2.0 onward; 0.1.0 shipped only as
GitHub release archives and installer scripts.

| Channel | Best for |
| --- | --- |
| Homebrew | macOS and Linuxbrew users |
| Shell installer | Linux and macOS, no Rust toolchain |
| PowerShell installer | Windows, no Rust toolchain |
| `cargo binstall` | Rust users who want the prebuilt binary |
| `cargo install` | Rust users who want to build from source |
| Container image | CI and sandboxed pipelines |
| GitHub Releases | Anything else, including air-gapped copies |

### Homebrew (macOS and Linuxbrew)

```sh
brew install watt-mind/tap/openszigno
```

### Shell installer (macOS and Linux)

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/watt-mind/openSzigno/releases/download/v0.2.0/openszigno-cli-installer.sh | sh
```

### PowerShell installer (Windows)

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watt-mind/openSzigno/releases/download/v0.2.0/openszigno-cli-installer.ps1 | iex"
```

Both installers place the binary in the Cargo home directory
(`~/.cargo/bin` by default) and print what they changed.

### cargo binstall

Downloads the prebuilt archive for your platform instead of compiling it.

```sh
cargo binstall openszigno-cli
```

### cargo install

Compiles from source and needs Rust 1.88 or newer.

```sh
cargo install openszigno-cli --locked
```

### Docker

The image is `FROM scratch`: it holds the statically linked binary and
nothing else, and it runs as the numeric user `65532`. Mount the directory
holding the dossier and refer to the file by its path inside the container.

```sh
docker run --rm -v "$PWD:/work" ghcr.io/watt-mind/openszigno:0.2.0 inspect /work/file.es3 --json
```

Tags are the release tag (`v0.2.0`), the bare version (`0.2.0`), and
`latest` for the newest final release.

### Manual download

Every release attaches an archive per target plus `sha256.sum` and a
`.sha256` file next to each archive, on the
[GitHub Releases](https://github.com/watt-mind/openSzigno/releases) page.
Archives are named `openszigno-cli-<target>.tar.gz`, or `.zip` on Windows,
and unpack to a directory of the same name containing the binary, the
`README.md`, the `CHANGELOG.md`, and the `LICENSE`.

```sh
curl -LO https://github.com/watt-mind/openSzigno/releases/download/v0.2.0/openszigno-cli-x86_64-unknown-linux-musl.tar.gz
curl -LO https://github.com/watt-mind/openSzigno/releases/download/v0.2.0/openszigno-cli-x86_64-unknown-linux-musl.tar.gz.sha256
tar -xzf openszigno-cli-x86_64-unknown-linux-musl.tar.gz
```

### Verify the download

Check the archive against the `.sha256` file that sits beside it, or against
the combined `sha256.sum`, before unpacking it.

```sh
sha256sum --check openszigno-cli-x86_64-unknown-linux-musl.tar.gz.sha256
```

### From source

```sh
git clone https://github.com/watt-mind/openSzigno.git
cd openSzigno
cargo build --release --locked
./target/release/openszigno --help
```

To install that build into `~/.cargo/bin`:

```sh
cargo install --path crates/openszigno-cli --locked
```

How releases are produced is described in
[docs/releasing.md](docs/releasing.md).

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
      {
        "bytes": 41,
        "declared_type": "text/plain",
        "detected_type": "text",
        "document_index": 0,
        "dossier_path": "0",
        "filename": "hello.txt",
        "path": "hello.txt"
      }
    ],
    "extracted_count": 1,
    "nested_dossiers_extracted": 0,
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
| `openszigno inspect FILE` | Identifies the dossier and reports title, category, namespace, XML encoding, document count, embedded-dossier count, signature/timestamp presence, the active limits, and capability flags. | No |
| `openszigno list FILE` | Lists document records in source XML order with title, creation date, MIME type, declared source size (`null`/`?` when the dossier omits it), `OBJREF`, transform chain, and whether the document embeds a dossier. | No |
| `openszigno validate-structure FILE` | Applies the strict structural rules and reports `valid_structure`, `conformance_warnings`, plus `cryptographic_verification_performed: false`. | No |
| `openszigno extract FILE --output DIR` | Decodes supported payloads into `DIR`, expanding embedded dossiers into `<file>.d` subdirectories, deduplicating repeated titles, never overwriting an existing file. | Yes |
| `openszigno verify FILE` | Verifies every `ds:Signature`: canonicalization, reference digests, the signature value, the mandated e-dossier reference scope, the XAdES signed `SigningCertificate` binding, RFC 3161 signature timestamps, and the certificate path. Reports a per-signature verdict of `invalid` or `indeterminate`; **never `valid`** in this release. | No |

Flags:

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `--json` | all commands | Emit exactly one JSON object on stdout. |
| `--allow-namespace URI` | all commands | Also accept a dossier rooted in this namespace, in addition to the known-compatible ones. Repeatable. |
| `-o`, `--output DIR` | `extract` | Destination directory; created if missing. |
| `--no-recursive` | `extract` | Write an embedded dossier as a payload file instead of expanding it. |
| `--max-depth N` | `extract` | Nesting levels of embedded dossiers to expand (default 3); values above the hard cap of 8 are clamped. |
| `--trust-store DIR` | `verify` | Directory of trust anchors (`anchors/*`, PEM or DER) and optional extra CA certificates (`intermediates/*`). A directory of certificates with no `anchors` subdirectory is read as anchors. Without it, every chain check is `unknown`. |
| `--at TIME` | `verify` | Validation time as an RFC 3339 timestamp. It overrides everything: without it, a signature whose timestamp verified completely is validated at that token's `genTime`, and otherwise at the current time. Use it to ask "was this chain valid on that day" and to get reproducible results. |
| `--allow-legacy-algorithms` | `verify` | Admit SHA-1 digests and RSA-SHA1 signature methods **for diagnosis only**: they emit `algorithm_legacy_allowed` instead of a passed check, the verdict stays capped at `indeterminate`, and no failed check can become a passed one. MD5, HMAC, DSA, and RSA keys below 2048 bits stay refused. |
| `-h`, `--help` | all commands | Print help as plain text. |
| `-V`, `--version` | top level | Print the version as plain text. |

`verify` performs no network or filesystem access of its own: reference
resolution is strictly same-document, and the trust store is the only external
material a run consults. Its algorithm policy is pinned — SHA-256/384/512
digests, RSA (PKCS#1 v1.5 and PSS) at 2048 bits or more, ECDSA P-256/P-384,
Canonical XML 1.0 and Exclusive C14N 1.0 — and weak algorithms are refused
rather than warned about. The full check-code table, the trust-store layout,
and the result shape are in
[docs/architecture.md](docs/architecture.md#the-verify-command); the standing
rule is in
[Verification boundary](docs/architecture.md#verification-boundary).

## Exit statuses

| Status | Meaning |
| --- | --- |
| `0` | The operation completed. Documents may have been skipped with explicit warnings. |
| `2` | Command-line usage error. |
| `3` | Input or output error, including a stdout that cannot be written. |
| `4` | Invalid, unsupported, or unsafe dossier structure. A structural failure during `verify` also exits 4. |
| `5` | Payload decoding or safe-extraction failure. |
| `6` | `verify` completed and at least one signature is `invalid`. |
| `7` | `verify` completed, nothing is `invalid`, and the overall verdict is `indeterminate`. |

## JSON contract in brief

In `--json` mode stdout carries exactly one object with these fields:

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | number | Currently `1`. Incremented on a breaking envelope change. |
| `ok` | boolean | `false` on any failure. |
| `command` | string | `inspect`, `list`, `extract`, `validate-structure`, `verify`, or `usage`. |
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
| XAdES qualifying properties: `SigningCertificate` binding, signing time, signature policy, and level detection. | M2 phase 2 |
| Revocation checking (CRL and OCSP) and EU trusted-list import for qualified status. | M2 phase 3 |
| Timestamp verification. | M3 |
| Decryption of encrypted payloads. A document that declares the `encrypt` transform is reported and skipped. | M4 |

Outside the current plan altogether:

- e-dossier namespaces outside the documented allow-list, unless added with
  `--allow-namespace`;
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
- [Release and distribution process](docs/releasing.md)
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
