#!/usr/bin/env python3
"""Enforce a source-file length guideline.

A tracked `*.rs` file under `crates/*/src` may not exceed 800 physical
lines, and one under `crates/*/tests` may not exceed 1500, unless it is
named in `scripts/file-length-allowlist.txt`. An allowlisted file may only
shrink: the allowlist records the size at which it was grandfathered in,
and this script fails if the file has grown past that recorded size, even
while it still sits under the file's own hard limit.

The allowlist exists for files that already exceeded the limit when this
guardrail was added and whose reduction is logic-adjacent work owned by
other tickets; it must never be used to admit a new oversized file.
"""
import re
import subprocess
import sys

SRC_LIMIT = 800
TESTS_LIMIT = 1500
ALLOWLIST_PATH = "scripts/file-length-allowlist.txt"


def tracked_files():
    output = subprocess.run(
        ["git", "ls-files", "--", "crates/*/src/*.rs", "crates/*/tests/*.rs"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return sorted(line for line in output.splitlines() if line)


def limit_for(path):
    if "/src/" in path:
        return SRC_LIMIT
    if "/tests/" in path:
        return TESTS_LIMIT
    return None


def line_count(path):
    with open(path, "rb") as handle:
        return sum(1 for _ in handle)


def load_allowlist():
    """Return {path: recorded_size}. Comments (`#`) and blank lines are skipped."""
    entries = {}
    try:
        lines = open(ALLOWLIST_PATH, encoding="utf-8").read().splitlines()
    except FileNotFoundError:
        return entries
    for lineno, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^(\S+)\s+(\d+)$", line)
        if not match:
            print(
                f"{ALLOWLIST_PATH}:{lineno}: expected '<path> <size>', got: {raw}"
            )
            entries[None] = -1
            continue
        path, size = match.group(1), int(match.group(2))
        entries[path] = size
    return entries


def main():
    allowlist = load_allowlist()
    malformed = allowlist.pop(None, None) is not None
    problems = 0
    files = tracked_files()

    for path in files:
        limit = limit_for(path)
        if limit is None:
            continue
        lines = line_count(path)
        recorded = allowlist.get(path)
        if recorded is None:
            if lines > limit:
                print(
                    f"{path}: {lines} lines exceeds the {limit}-line limit "
                    f"and is not in {ALLOWLIST_PATH}"
                )
                problems += 1
            continue
        if lines > recorded:
            print(
                f"{path}: {lines} lines exceeds its allowlisted size of "
                f"{recorded}; allowlisted files may only shrink"
            )
            problems += 1

    for path in allowlist:
        if path not in files:
            print(f"{ALLOWLIST_PATH}: {path} is listed but no longer tracked")
            problems += 1

    if malformed:
        problems += 1

    print(f"file length checked, problems={problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
