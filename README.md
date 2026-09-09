# openSzigno

A safe, agent-friendly command-line tool for inspecting, listing, structurally
validating, verifying, extracting, creating, signing, and timestamping
Hungarian Microsec e-Szignó e-dossiers (`.es3`).

[![CI](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml/badge.svg?branch=develop)](https://github.com/watt-mind/openSzigno/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.88%2B-orange.svg)](rust-toolchain.toml)

> **Security boundary:** `openszigno verify` checks XMLDSig canonicalization,
> reference digests, signature values, the e-dossier reference-scope rules,
> the XAdES signed `SigningCertificate` binding, RFC 3161 signature
> timestamps, certificate paths, and revocation, all against trust material
> you supply. It reports a signature `valid` only when every check it makes
> passed at the stated validation time; short of that the verdict is
> `indeterminate`, which means "nothing failed", not "this is trustworthy".
> No command determines a document's legal effect, and parsing or extracting
> a dossier is never evidence that it is authentic, signed, or legally valid.

## Why and for whom

`.es3` dossiers are XML containers that arrive from untrusted parties and are
usually opened with a desktop application. openSzigno is the other option: a
single binary that reads a dossier, verifies its signatures against material
you choose, and writes the payloads to disk without trusting the input.

- **Agents and automation.** Every command accepts `--json` and emits exactly
  one JSON object on stdout, with a stable envelope, stable error and warning
  codes, and stable exit statuses. Diagnostics go to stderr and never
  contaminate stdout.
- **People.** Without `--json` the same commands print short, readable
  terminal output that always states the verification boundary. `inspect` and
  `list` report the dossier's own account of itself and verify nothing, which
  is why their output carries `"verified": false`; `verify` is the only
  command that gives a cryptographic answer.
- **Hostile input.** Input is bounded at every stage: file size, XML depth and
  node count, Base64 length, decoded payload size, ZIP member count and
  compression ratio, aggregate extraction size. DTDs and entity declarations
  are rejected outright, and extraction never overwrites an existing file or
  follows a symlink out of the output directory.

## Installation

Every channel ships the same binary, `openszigno`. Prebuilt archives cover
five targets and carry SHA-256 checksums.

```sh
# Homebrew, on macOS and Linuxbrew
brew install watt-mind/tap/openszigno

# Cargo: the prebuilt archive, or a build from source (Rust 1.88 or newer)
cargo binstall openszigno-cli
cargo install openszigno-cli --locked
```

Shell and PowerShell installers, for a machine with no Rust toolchain:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/watt-mind/openSzigno/releases/download/v0.9.0/openszigno-cli-installer.sh | sh
```

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/watt-mind/openSzigno/releases/download/v0.9.0/openszigno-cli-installer.ps1 | iex"
```

Container image (`linux/amd64` and `linux/arm64`), for CI and sandboxed
pipelines. It is `FROM scratch` and runs as the numeric user `65532`:

```sh
docker run --rm -v "$PWD:/work" ghcr.io/watt-mind/openszigno:0.9.0 inspect /work/file.es3 --json
```

Otherwise take an archive and the `.sha256` file beside it from the
[releases page](https://github.com/watt-mind/openSzigno/releases), check it
with `sha256sum --check`, and unpack it. See
[docs/releasing.md](docs/releasing.md) for how releases are produced.

## Quick start

Human mode. `openszigno list tests/fixtures/plain-base64.es3` prints:

```text
Unsigned synthetic plain fixture
[0] hello.txt | text/plain | 41 B | ["base64"]
Signatures/timestamps are listed by presence only; none were verified.
```

Agent mode. `openszigno inspect tests/fixtures/plain-base64.es3 --json`
writes one compact object; this one is pretty-printed and trimmed:

```json
{
  "schema_version": 1,
  "ok": true,
  "command": "inspect",
  "input": { "format": "microsec-es3", "bytes": 1109 },
  "data": {
    "dossier": { "title": "Unsigned synthetic plain fixture", "documents": 1,
                 "signatures_present": 0, "signatures_verified": false, ... },
    ...
  },
  "warnings": [],
  "errors": []
}
```

Verification. A run needs trust material you supply, here a trust store
holding the repository's own synthetic anchor, and `--at` to pin the
validation time:

```sh
mkdir -p trust/anchors
cp tests/fixtures/xmldsig/root.pem trust/anchors/
openszigno verify tests/fixtures/xmldsig/openssl-rsa-sha256.es3 \
  --trust-store ./trust --at 2027-01-01T00:00:00Z
```

```text
Verification verdict: indeterminate
Validation time: 2027-01-01T00:00:00Z
Signatures: 1
  ...
[0] document signature: indeterminate
  validation time: 2027-01-01T00:00:00Z (source: at_flag)
  ...
  signature_value_ok: passed
  xades_absent: skipped
  ...
  cert_path_ok: passed
  ...
  revocation_status_unknown: unknown
Revocation policy: offline. A verdict of `valid` means every check passed at the stated validation time; it is not a legal opinion.
```

Exit status 7: nothing failed, but this fixture carries no XAdES properties,
no signature timestamp and no revocation data, so nothing reaches `valid`.
Adding `--online` would let the run fetch the revocation data it lacks from
the URLs the certificates themselves publish.

## Commands

| Command | Purpose | Exit statuses |
| --- | --- | --- |
| `inspect FILE` | Identify the dossier and report its metadata, the unverified signature inventory, the active limits, and capability flags. | 0, 2, 3, 4 |
| `list FILE` | List document records in source XML order, with type, size, `OBJREF`, and transform chain. | 0, 2, 3, 4 |
| `validate-structure FILE` | Apply the strict structural rules and report `valid_structure` and any conformance warnings. | 0, 2, 3, 4 |
| `extract FILE --output DIR` | Decode supported payloads into `DIR`, expanding embedded dossiers, never overwriting a file. `--document SEL --stdout` writes one payload to stdout instead. | 0, 2, 3, 4, 5 |
| `verify FILE` | Verify every `ds:Signature` against the trust material you supply and report a per-signature verdict of `valid`, `invalid`, or `indeterminate`. | 0, 2, 3, 4, 6, 7 |
| `create --output FILE --title TITLE` | Build one new, unsigned dossier from files on disk, with `--document`, `--zip`, `--embed`, `--encrypt-for`, and `--created`. Never overwrites the output. | 0, 2, 3, 4, 5 |
| `sign FILE --output FILE --key KEY` | Write a signed copy of a dossier: one enveloped XMLDSig/XAdES signature per document, or one over the dossier with `--scope dossier`, optionally timestamped with `--tsa`, and with `--csc` instead of `--key` signed by a remote qualified certificate. Never overwrites the output. | 0, 2, 3, 4, 5 |
| `timestamp FILE --output FILE --tsa URL` | Write a copy of a dossier carrying a container `es:TimeStamp`: an RFC 3161 token over the dossier, or over each selected document with `--scope document`, and no signature. Never overwrites the output. | 0, 2, 3, 4, 5 |
| `skill` | Write the embedded agent skill (`SKILL.md`) to stdout and nothing else. Takes no `FILE` and no `--json`. | 0, 2, 3 |

`create` is the writing side: it builds a new dossier from files on disk,
in the shape this tool reads back, and does nothing else to it. The output
is deterministic, so the same inputs with the same `--created` produce a
byte-identical file; every limit that bounds reading bounds writing too; an
existing output file is an error rather than an overwrite; and the dossier
it writes carries no signature, which every run says out loud.
`--encrypt-for CERT.pem` encrypts every `--document` payload for that
recipient certificate as CMS EnvelopedData, which `extract --decrypt-key`
reads back; it is the one thing that makes the output non-deterministic,
because a content key must be random. Signing a dossier is `sign`, below,
and `timestamp` writes a container `es:TimeStamp` over a dossier without
signing it: one RFC 3161 token, no key of any kind, refused rather than
written where it would break something already in the file. See
[The timestamp command](docs/architecture.md#the-timestamp-command).

Every command except `create` and `skill` takes `-` in place of the path and
reads the dossier from standard input. Every flag, the JSON envelope, the stable
error, warning and check codes, the exit statuses, and the parser limits
are specified in [docs/architecture.md](docs/architecture.md).

## Verification

`verify` reports `valid` only when every check it makes passed at the stated
validation time, which needs a trust anchor, a fully verified signature
timestamp, and fresh revocation data for every certificate in the chains;
anything missing yields `indeterminate`. You supply that material yourself:
`--trust-store` for anchors, `--trust-list` and `--lotl` with
`--trust-list-signer` for ETSI TS 119 612 lists, `--revocation-store` for CRLs
and OCSP responses. `--online` is the only thing that makes openSzigno touch
the network, and then only for the CRL and OCSP URLs published by certificates
on a path to a configured anchor, under fixed timeouts and size caps, with
loopback, private and cloud-metadata destinations refused; trust material is
never fetched. [docs/trust.md](docs/trust.md) explains how to obtain, pin, and
lay out all of it.

## Signing

`sign` is the other writing side: it takes a dossier and a key you supply and
writes a signed copy, with the reference scope, the XAdES signed properties
and the placement `verify` requires, and optionally an RFC 3161 timestamp from
a `--tsa` you name. The key, its certificate and its passphrase come from
files, never from the command line.

```sh
openszigno sign dossier.es3 --output signed.es3 \
  --key signer.p8 --cert signer.crt --chain issuing-ca.pem \
  --tsa https://tsa.example/tsa --signing-time 2026-01-02T00:00:00Z
```

`--csc CONFIG.toml` signs through a Cloud Signature Consortium API v2 service
instead of a local key, so a qualified certificate held by a remote signature
creation device signs the same structure and only the digest ever leaves the
machine; see
[Signing through a CSC service](docs/architecture.md#signing-through-a-csc-service).

**Writing is not verification.** `sign` produces a signature and checks
nothing: not the key, not the certificate, not the chain, and it says so on
every run, and `timestamp` says the same about the token it embeds.
Whether what either wrote holds is a question for `verify`, against
trust material you supply; and a `valid` verdict over a chain you built
yourself means only that the chain you chose to trust verified. It is not a
statement about anybody's identity, not a legal opinion, and not a qualified
electronic signature: a qualified signature needs a key on a qualified device,
which by construction is not a key this process can hold. See
[docs/remote-signing.md](docs/remote-signing.md).

## Documentation

- [Documentation index](docs/index.md), which lists everything else
- [Architecture and CLI contract](docs/architecture.md)
- [Trust, revocation, and qualified status](docs/trust.md)
- [ES3 specification and implementation map](docs/es3-specification.md)
- [Roadmap and residual risks](docs/roadmap.md)
- [Remote signing and qualified signatures](docs/remote-signing.md)
- [Agent skill](crates/openszigno-cli/skills/openszigno/SKILL.md): how an AI
  agent should drive the CLI to inspect, extract, decrypt, sign and verify
  dossiers. The binary carries it, so no checkout is needed to install it:

  ```sh
  mkdir -p .claude/skills/openszigno
  openszigno skill > .claude/skills/openszigno/SKILL.md
  ```

  Use `.codex/skills/openszigno/` for Codex, or `~/.claude/skills/openszigno/`
  to install it for every project instead of one.

## Contributing

`develop` is the default integration branch and `master` is the stable one, so
open pull requests against `develop`. [CONTRIBUTING.md](CONTRIBUTING.md) has
the branch model, commit conventions, and required checks;
[SECURITY.md](SECURITY.md) has the threat model and how to report a
vulnerability.

## LEGAL

openSzigno independently implements the publicly documented
[Microsec e-dossier format](https://srv.e-szigno.hu/edossier) for
interoperability, so that users can inspect and process their own documents
with an open-source tool.

EU copyright law distinguishes a program's protected expression from its
functionality and underlying ideas. In
[SAS Institute v World Programming (C-406/10)](https://eur-lex.europa.eu/legal-content/EN/ALL/?uri=CELEX%3A62010CA0406),
the Court of Justice held that functionality and data-file formats are not, as
such, protected by copyright in computer programs. That supports independent
compatible implementations; it is not permission to copy another program's
source code or documentation. Third-party specifications, schemas, reference
documents, and software remain subject to their own rights and licenses:
public availability does not itself grant redistribution rights, and this
project's MIT license does not relicense third-party material.

This is general information, not legal advice or a guarantee of legal
clearance in any jurisdiction. As the security boundary above states,
openSzigno does not determine a document's legal effect and is not a certified
validation service; see the
[verification boundary](docs/architecture.md#verification-boundary).

## License and trademarks

Licensed under the [MIT License](LICENSE); test fixtures under
`tests/fixtures/` are dedicated under CC0-1.0. `e-Szignó`, `Microsec`, and
related marks belong to their respective owners. openSzigno is an independent
project, maintained by Watt-Mind, and is not affiliated with, endorsed by, or
certified by Microsec.
