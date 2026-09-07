# openSzigno

`openSzigno` is an open-source, agent-first command-line tool for
inspecting and extracting Hungarian Microsec e-Szignó e-dossiers (`.es3`).
The project is maintained by Watt-Mind.

The intended distribution is small, portable release binaries. Its primary
interface will be stable JSON output suitable for automation and coding
agents, while preserving a readable terminal mode for people.

> **Security boundary:** openSzigno performs structural validation and bounded
> extraction. It does **not** verify XMLDSig/XAdES signatures, timestamps,
> certificate trust, or legal authenticity.

## Build

Install the stable Rust toolchain, then:

```sh
cargo build --release --locked
./target/release/openszigno --help
```

## Commands

```text
openszigno inspect FILE.es3 --json
openszigno list FILE.es3 --json
openszigno extract FILE.es3 --output DIR --json
openszigno validate-structure FILE.es3 --json
```

Omit `--json` for human-readable output. JSON mode emits exactly one object on
stdout and uses stable error codes. Extraction supports `base64` and
`zip -> base64`; encrypted or otherwise unsupported documents are reported and
skipped. Existing output files are never overwritten, output names are
sanitized from document titles, and hostile input is bounded by fixed size,
depth, and compression-ratio limits.

Cryptographic `verify` is reserved for a later milestone and is intentionally
not exposed by this release.

See:

- [Research and source register](docs/research.md)
- [Architecture and CLI contract](docs/architecture.md)
- [Fixture and test-data policy](docs/testing.md)

`e-Szignó` and `Microsec` are names of their respective owners. openSzigno is
an independent project and is not affiliated with or endorsed by Microsec.

Licensed under the [MIT License](LICENSE).
