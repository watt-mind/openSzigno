#!/usr/bin/env python3
"""Golden JSON and human output contract tests for the openSzigno CLI.

Runs a fixed command matrix over every fixture in `tests/fixtures/**/*.es3`,
normalises the two time values that cannot be stable, and compares the result
against the committed files under `tests/golden/`.

Subcommands:

    check  --bin PATH   run the matrix and diff against the goldens
    update --bin PATH   run the matrix and rewrite the goldens

Neither subcommand builds anything and neither touches the network. The
binary is supplied by the caller; CI builds it once in the `golden` job.

See tests/golden/README.md for the contract these files describe.
"""

import argparse
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures"
GOLDEN = REPO / "tests" / "golden"

# The single placeholder every masked time value is normalised to. It is not
# a valid RFC 3339 instant on purpose: a golden that still carries a real
# clock reading is then obvious on sight.
MASK = "<MASKED-TIME>"

# The trusted `verify` runs pin an instant so the certificate path is judged
# against a fixed time rather than the wall clock. The first is the instant
# the ticket specifies; it predates the committed vector certificates'
# notBefore (2026-09-07), so it pins the "not yet valid" shape. The second
# sits inside their validity, the same instant
# `crates/openszigno-verify/tests/vectors.rs` pins, so the shape of a report
# whose path check actually runs is pinned too.
AT_REQUESTED = "2026-01-02T03:04:05Z"
AT_IN_VALIDITY = "2027-01-01T00:00:00Z"

# The committed synthetic anchor the trusted runs use. It is copied into a
# throwaway directory per run because a trust store is a directory of
# anchors and `tests/fixtures/xmldsig/` holds other files too.
ANCHOR = FIXTURES / "xmldsig" / "root.pem"


def fixtures():
    """Every fixture dossier, in a fixed order."""
    return sorted(FIXTURES.rglob("*.es3"), key=lambda p: p.as_posix())


def is_signed(path):
    """True when the fixture carries at least one `ds:Signature` element."""
    data = path.read_bytes()
    return b"<ds:Signature " in data or b"<ds:Signature>" in data


def cases(fixture, temp):
    """The command matrix for one fixture.

    Yields `(name, argv)` pairs. `name` is the golden basename without its
    extension; `argv` is the argument list after the binary path. Paths are
    relative to the repository root so no absolute path can reach a golden,
    except the extract output and trust-store directories, which live under
    the system temporary directory and are asserted never to appear in the
    captured output.
    """
    rel = fixture.relative_to(REPO).as_posix()
    slug = fixture.relative_to(FIXTURES).with_suffix("").as_posix().replace("/", "-")

    for command in ("inspect", "list", "validate-structure", "verify"):
        yield command, [command, rel, "--json"]
        yield f"{command}.human", [command, rel]

    # `extract` needs somewhere to write. Each run gets its own directory so
    # the no-clobber rule never turns a rerun into a different answer.
    yield "extract", [
        "extract",
        rel,
        "--output",
        str(temp / "extract" / slug),
        "--json",
    ]

    if not is_signed(fixture):
        return

    store = temp / "trust" / slug
    store.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ANCHOR, store / "root.pem")
    for variant, at in (("trusted", AT_REQUESTED), ("trusted-in-validity", AT_IN_VALIDITY)):
        base = ["verify", rel, "--trust-store", str(store), "--at", at]
        yield f"verify.{variant}", base + ["--json"]
        yield f"verify.{variant}.human", base


def mask_json(node):
    """Mask the two time values in a parsed envelope, in place.

    Exactly two things move between runs, and only these two are masked:

    - `data.verification_time.effective`, the clock reading for the run;
    - `signatures[].validation_time`, but only where the sibling
      `validation_time_source` is `current_time`. With `--at` the source is
      `at_flag` and the value is the operator's, so it stays.
    """
    if isinstance(node, list):
        for item in node:
            mask_json(item)
        return
    if not isinstance(node, dict):
        return
    effective = node.get("verification_time")
    if isinstance(effective, dict) and isinstance(effective.get("effective"), str):
        effective["effective"] = MASK
    if node.get("validation_time_source") == "current_time" and isinstance(
        node.get("validation_time"), str
    ):
        node["validation_time"] = MASK
    for value in node.values():
        mask_json(value)


def normalise_json(raw):
    """Pretty-print and mask a captured `--json` stdout."""
    if not raw.strip():
        return ""
    document = json.loads(raw)
    mask_json(document)
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def normalise_text(raw):
    """Mask the human renderer's two time lines.

    `Validation time:` renders `verification_time.effective`, and the
    indented `validation time: ... (source: ...)` renders a signature's own
    validation time; both are masked under exactly the rule the JSON masking
    uses.
    """
    lines = []
    for line in raw.replace("\r\n", "\n").split("\n"):
        if line.startswith("Validation time: "):
            line = f"Validation time: {MASK}"
        elif line.startswith("  validation time: ") and line.endswith(
            "(source: current_time)"
        ):
            line = f"  validation time: {MASK} (source: current_time)"
        lines.append(line)
    return "\n".join(lines)


def run(binary, argv, temp):
    """Run one case and return `(normalised stdout, exit status)`."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "TZ": "UTC",
        "NO_COLOR": "1",
        # A proxy picked up from the environment would be a network call the
        # matrix does not want; no case passes `--online`, and this makes a
        # regression that started fetching fail rather than succeed quietly.
        "HTTP_PROXY": "http://127.0.0.1:1",
        "HTTPS_PROXY": "http://127.0.0.1:1",
    }
    if sys.platform == "win32":  # pragma: no cover - CI runs the job on Linux
        env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", "")
    completed = subprocess.run(
        [str(binary)] + argv,
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    stdout = completed.stdout
    # No golden may carry a machine-local path. The output directories and
    # trust stores are the only absolute paths the matrix supplies, so their
    # root appearing in stdout is a contract bug, not a normalisation gap.
    if str(temp) in stdout:
        raise SystemExit(
            f"contract failure: output of `{' '.join(argv)}` leaks the temporary "
            f"directory {temp}; the envelope must never carry an absolute path"
        )
    return stdout, completed.returncode


def matrix(binary, temp):
    """Run the whole matrix and return `{relative golden path: content}`."""
    produced = {}
    for fixture in fixtures():
        directory = fixture.relative_to(FIXTURES).with_suffix("").as_posix()
        for name, argv in cases(fixture, temp):
            stdout, status = run(binary, argv, temp)
            if name.endswith(".human"):
                body, extension = normalise_text(stdout), "txt"
            else:
                body, extension = normalise_json(stdout), "json"
            produced[f"{directory}/{name}.{extension}"] = body
            produced[f"{directory}/{name}.exit"] = f"{status}\n"
    return produced


def committed():
    """Every committed golden, as `{relative path: content}`."""
    if not GOLDEN.is_dir():
        return {}
    found = {}
    for path in sorted(GOLDEN.rglob("*")):
        if not path.is_file() or path.name == "README.md":
            continue
        found[path.relative_to(GOLDEN).as_posix()] = path.read_text(encoding="utf-8")
    return found


def check(binary, temp):
    produced = matrix(binary, temp)
    stored = committed()
    failures = 0
    for name in sorted(set(produced) | set(stored)):
        expected = stored.get(name)
        actual = produced.get(name)
        if expected == actual:
            continue
        failures += 1
        if expected is None:
            print(f"golden not committed: tests/golden/{name}")
            continue
        if actual is None:
            print(f"stale golden, no case produces it: tests/golden/{name}")
            continue
        diff = difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile=f"tests/golden/{name} (committed)",
            tofile=f"tests/golden/{name} (produced)",
        )
        print(f"golden mismatch: tests/golden/{name}")
        sys.stdout.writelines(diff)
        print()
    if failures:
        print(
            f"{failures} golden file(s) differ. A difference here is a change to "
            "the output contract: review it against the schema_version rule in "
            "tests/golden/README.md, then run "
            "`python3 scripts/golden.py update --bin <binary>`."
        )
        return 1
    print(f"{len(produced)} golden file(s) match.")
    return 0


def update(binary, temp):
    produced = matrix(binary, temp)
    for name in sorted(set(committed()) - set(produced)):
        (GOLDEN / name).unlink()
        print(f"removed stale tests/golden/{name}")
    for name in sorted(produced):
        target = GOLDEN / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(produced[name], encoding="utf-8")
    for directory in sorted(GOLDEN.rglob("*"), reverse=True):
        if directory.is_dir() and not any(directory.iterdir()):
            directory.rmdir()
    print(f"wrote {len(produced)} golden file(s) under tests/golden/.")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("action", choices=("check", "update"))
    parser.add_argument(
        "--bin",
        required=True,
        help="path to an already-built openszigno binary; nothing is built here",
    )
    arguments = parser.parse_args()
    binary = Path(arguments.bin).resolve()
    if not binary.is_file():
        parser.error(f"no such binary: {binary}")
    temp = Path(tempfile.mkdtemp(prefix="openszigno-golden-"))
    try:
        return check(binary, temp) if arguments.action == "check" else update(binary, temp)
    finally:
        shutil.rmtree(temp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
