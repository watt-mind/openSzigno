# Golden output contract

Every file in this directory is captured output of the openSzigno CLI. Taken
together they are the machine-checked form of the contract described in
[docs/architecture.md](../../docs/architecture.md#json-envelope): the JSON
envelope, the human renderer's lines, and the exit statuses, for every fixture
under [tests/fixtures](../fixtures/README.md).

`scripts/golden.py` regenerates and compares them. It builds nothing and
reaches no network; CI runs `check` against a release binary in the `golden`
job.

```sh
python3 scripts/golden.py check  --bin target/release/openszigno
python3 scripts/golden.py update --bin target/release/openszigno
```

## A difference here is a contract change

A golden file changes only because the tool's output changed. That is not a
test to be repaired; it is a change to what every consumer parses, and it is
reviewed under the `schema_version` rule:

| Change | What it requires |
| --- | --- |
| A new field, a new warning or check code, a new human line | Additive. `schema_version` stays `1`. Regenerate the goldens, and add a `CHANGELOG.md` entry under Unreleased. |
| A removed or renamed field, a changed field type, a changed meaning | Breaking. It requires a `schema_version` bump, the same pull request updating `docs/architecture.md`, and regenerated goldens. |
| A changed exit status for an existing outcome | Breaking. Exit statuses are stable at the category level; see [Exit statuses](../../docs/architecture.md#exit-statuses). |
| A path, a title, or payload content appearing anywhere | A bug, never an accepted diff. Messages never carry input paths, document titles, or payload content. |

Regenerating goldens to make a red build green, without deciding which row
above the change falls under, defeats the point of the directory.

## Layout

```text
tests/golden/<fixture>/<command>[.<variant>].json|.txt|.exit
```

`<fixture>` is the fixture's path under `tests/fixtures/` with `.es3`
removed, so `tests/fixtures/xmldsig/openssl-rsa-sha256.es3` becomes
`tests/golden/xmldsig/openssl-rsa-sha256/`.

| Suffix | Contents |
| --- | --- |
| `.json` | Stdout of the `--json` run, pretty-printed with sorted keys. The tool writes one compact line; the stored form is expanded so a diff is readable. |
| `.txt` | Stdout of the human-mode run, byte for byte apart from the masking below. |
| `.exit` | The process exit status, on its own line. |

Variants:

| Variant | Run |
| --- | --- |
| none | `<command> <fixture> --json` |
| `human` | `<command> <fixture>`, no `--json` |
| `trusted` | `verify --trust-store <anchors> --at 2026-01-02T03:04:05Z`, signed fixtures only |
| `trusted-in-validity` | The same, at `2027-01-01T00:00:00Z` |

Two groups are not driven by a fixture. `tests/golden/create/` captures
`openszigno create` building a dossier from the two committed inputs under
`tests/fixtures/create/`, in both modes, with `--created` pinned to
`2026-01-01T00:00:00Z` so the output is byte-identical on every run. It runs
in its own throwaway working directory and writes the bare relative path
`created.es3`, because `create` echoes the output path it was given and no
golden may carry a machine-local path. Its output is committed as
`tests/fixtures/created.es3`, which the fixture matrix then covers like any
other fixture.

`tests/golden/sign/` captures `sign` refusals, and only refusals. A
successful signing run cannot be a golden: it needs a private key, and this
repository commits none, synthetic or not. The two cases run over
`tests/fixtures/created.es3` in their own throwaway working directories:
`sign.missing-key`, where `--key` names a file that is not there
(`io_error`, exit 3), and `sign.csc-config-invalid`, where the `--csc`
configuration is missing `client_id` (`csc_config_invalid`, exit 4). Nothing
is contacted in either. The paths that do sign are covered by
`crates/openszigno-cli/tests/sign.rs` and `csc.rs`.

`create --encrypt-for` is deliberately **not** in the matrix. Every encrypted
document carries a fresh random content-encryption key, initialisation
vector, and key-transport padding, so no two runs produce the same bytes and
there is nothing stable to capture. It is covered by integration tests
instead: `crates/openszigno-cli/tests/create_encrypt.rs` and
`crates/openszigno-author/tests/encryption.rs`.

The commands captured over a fixture are `inspect`, `list`,
`validate-structure`, `verify` and `extract` in JSON mode, and `inspect`,
`list`, `validate-structure` and `verify` in human mode; `create` and `sign`
are captured in both modes by the two groups above. `extract` writes into a
throwaway directory under the
system temporary directory; the script fails the run if that directory's path
ever appears in captured output, because the envelope must never carry an
absolute path.

Only stdout is captured. In JSON mode stdout is the whole envelope, warnings
included; in human mode warnings and errors go to stderr, so a human golden
for a fixture that only fails is empty and its `.exit` file carries the
finding.

## The trusted runs

`tests/fixtures/xmldsig/openssl-rsa-sha256.es3` is the only signed fixture.
Its `verify.trusted*` runs pass a trust store holding a copy of the committed
synthetic anchor `tests/fixtures/xmldsig/root.pem`, and pin the validation
time with `--at` so the certificate path is judged against a fixed instant
rather than the wall clock.

Two instants are pinned because they exercise different shapes. The committed
vector certificates are valid from 2026-09-07, so `2026-01-02T03:04:05Z` is
before their `notBefore` and pins the `cert_not_yet_valid` report (exit 6);
`2027-01-01T00:00:00Z`, the instant
`crates/openszigno-verify/tests/vectors.rs` also pins, sits inside their
validity and pins the shape of a report whose path check actually ran
(`cert_path_ok`, exit 7). Neither reaches `valid`: the vector carries no
revocation data, so revocation stays unknown.

## What is masked, and nothing else

Two values move between runs. They are replaced with the literal
`<MASKED-TIME>`, which is deliberately not a valid RFC 3339 instant so a
golden that still holds a real clock reading is obvious on sight.

| Masked | Where | Rule |
| --- | --- | --- |
| `data.verification_time.effective` | JSON | Always. It is the clock reading for the run. `requested` and `source` beside it are not masked, so an `--at` run still records the instant it was given. |
| `signatures[].validation_time` | JSON | Only when the sibling `validation_time_source` is `current_time`. With `--at` the source is `at_flag` and the value is the operator's, so it stays. |
| `Validation time: ...` | Human | Always. The line renders `verification_time.effective`. |
| The indented `validation time: ... (source: current_time)` line | Human | The per-signature line, under exactly the JSON rule above. |

Nothing else is normalised. Byte counts, certificate validity dates, creation
dates, digests, and the order of every array are part of the contract and are
compared as they are produced.
