#!/usr/bin/env python3
"""Enforce per-crate and patch line-coverage gates from an lcov report.

Reads an LCOV file produced by `cargo llvm-cov --workspace --lcov` and:

- computes per-crate line coverage (a crate is the first path component
  under `crates/`) and the workspace total,
- computes patch coverage: the percentage of lines added or modified by
  `git diff -U0 <base> HEAD` under `crates/*/src/**/*.rs` that lcov marks
  as covered, restricted to lines lcov actually instruments (present in a
  `DA:` record),
- enforces that every crate is at or above `MIN_CRATE_LINES` percent,
- enforces patch coverage at or above `MIN_PATCH` percent whenever at
  least `MIN_PATCH_LINES` changed instrumentable lines exist; with fewer
  than that, the patch gate is skipped and reported as such,
- enforces a ratchet against `scripts/coverage-floors.txt`: a crate (or
  the workspace total) may not drop more than `RATCHET_TOLERANCE` points
  below its recorded floor,
- prints a Markdown summary to stdout and, when set, to
  `$GITHUB_STEP_SUMMARY`.

`--update-floors` rewrites the floors file to the coverage this run
measured. It is a local convenience; CI never passes it.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field

MIN_CRATE_LINES = 90.0
MIN_PATCH = 80.0
MIN_PATCH_LINES = 20
RATCHET_TOLERANCE = 1.0
FLOORS_PATH = "scripts/coverage-floors.txt"
WORKSPACE_KEY = "workspace"


# --------------------------------------------------------------------------
# LCOV parsing
# --------------------------------------------------------------------------


@dataclass
class FileCoverage:
    """Per-line hit counts for one source file, keyed by 1-based line number."""

    lines: dict = field(default_factory=dict)

    def instrumented(self):
        return len(self.lines)

    def covered(self):
        return sum(1 for hits in self.lines.values() if hits > 0)


def crate_relpath(sf_path):
    """Return the `crates/...` relative path for an LCOV `SF:` path, or None."""
    normalized = sf_path.replace("\\", "/")
    idx = normalized.find("crates/")
    if idx == -1:
        return None
    return normalized[idx:]


def crate_name(relpath):
    parts = relpath.split("/")
    if len(parts) < 2 or parts[0] != "crates":
        return None
    return parts[1]


def parse_lcov(path):
    """Return {relpath: FileCoverage} for every `crates/...` file in the LCOV file."""
    files = {}
    current = None
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.rstrip("\n")
            if line.startswith("SF:"):
                relpath = crate_relpath(line[3:])
                current = files.setdefault(relpath, FileCoverage()) if relpath else None
            elif line.startswith("DA:") and current is not None:
                rest = line[3:].split(",")
                lineno = int(rest[0])
                hits = int(rest[1])
                # A line can be repeated (e.g. inlined instances); a line
                # counts as covered if any instance covers it.
                current.lines[lineno] = max(hits, current.lines.get(lineno, 0))
            elif line == "end_of_record":
                current = None
    return files


# --------------------------------------------------------------------------
# Per-crate / workspace aggregation
# --------------------------------------------------------------------------


def aggregate_by_crate(files):
    """Return {crate: (covered, instrumented)} plus a 'workspace' total."""
    totals = {}
    for relpath, cov in files.items():
        crate = crate_name(relpath)
        if crate is None:
            continue
        covered, instrumented = totals.get(crate, (0, 0))
        totals[crate] = (covered + cov.covered(), instrumented + cov.instrumented())
    workspace = (
        sum(c for c, _ in totals.values()),
        sum(i for _, i in totals.values()),
    )
    totals[WORKSPACE_KEY] = workspace
    return totals


def pct(covered, instrumented):
    if instrumented == 0:
        return 100.0
    return 100.0 * covered / instrumented


# --------------------------------------------------------------------------
# Floors ratchet file
# --------------------------------------------------------------------------


def load_floors(path):
    floors = {}
    if not os.path.exists(path):
        return floors
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 2:
                continue
            floors[parts[0]] = float(parts[1])
    return floors


def write_floors(path, totals):
    crates = sorted(k for k in totals if k != WORKSPACE_KEY)
    lines = [
        "# Coverage ratchet floors. One `<crate> <percent>` pair per line, plus\n",
        "# `workspace`. A CI run fails if a crate (or the workspace total) drops\n",
        f"# more than {RATCHET_TOLERANCE} points below its recorded value here.\n",
        "# Regenerate locally with:\n",
        "#   python3 scripts/coverage_gate.py --lcov lcov.info --update-floors\n",
        "# CI never updates this file.\n",
    ]
    for crate in crates:
        covered, instrumented = totals[crate]
        lines.append(f"{crate} {pct(covered, instrumented):.2f}\n")
    covered, instrumented = totals[WORKSPACE_KEY]
    lines.append(f"{WORKSPACE_KEY} {pct(covered, instrumented):.2f}\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


# --------------------------------------------------------------------------
# Patch coverage
# --------------------------------------------------------------------------


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
CHANGED_SRC_RE = re.compile(r"^crates/[^/]+/src/.*\.rs$")


def merge_base(base_ref):
    out = subprocess.run(
        ["git", "merge-base", base_ref, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return out


def changed_lines_by_file(base_sha):
    """Return {relpath: set(new-file line numbers added or modified)}."""
    diff = subprocess.run(
        ["git", "diff", "-U0", base_sha, "HEAD", "--", "crates"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    changed = {}
    current_file = None
    current_lineno = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            if path == "/dev/null":
                current_file = None
                continue
            path = path[2:] if path.startswith("b/") else path
            current_file = path if CHANGED_SRC_RE.match(path) else None
            continue
        if current_file is None:
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            current_lineno = int(hunk.group(1))
            continue
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            changed.setdefault(current_file, set()).add(current_lineno)
            current_lineno += 1
        elif line.startswith("-"):
            # Deletion only; does not advance the new-file line counter.
            continue
    return changed


def patch_coverage(files, changed):
    """Return (covered, total, per_file) restricted to lines lcov instruments."""
    covered = 0
    total = 0
    per_file = {}
    for relpath, linenos in changed.items():
        cov = files.get(relpath)
        if cov is None:
            continue
        instrumented = sorted(n for n in linenos if n in cov.lines)
        if not instrumented:
            continue
        file_covered = [n for n in instrumented if cov.lines[n] > 0]
        file_uncovered = [n for n in instrumented if cov.lines[n] == 0]
        covered += len(file_covered)
        total += len(instrumented)
        per_file[relpath] = {
            "covered": len(file_covered),
            "total": len(instrumented),
            "uncovered_lines": file_uncovered,
        }
    return covered, total, per_file


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def format_ranges(linenos):
    """Compress a sorted list of line numbers into `a-b, c` range notation."""
    if not linenos:
        return ""
    ranges = []
    start = prev = linenos[0]
    for n in linenos[1:]:
        if n == prev + 1:
            prev = n
            continue
        ranges.append(f"{start}-{prev}" if start != prev else f"{start}")
        start = prev = n
    ranges.append(f"{start}-{prev}" if start != prev else f"{start}")
    return ", ".join(ranges)


def build_summary(totals, floors, crate_failures, ratchet_failures, patch_result):
    lines = []
    lines.append("## Coverage gate")
    lines.append("")
    ws_covered, ws_instrumented = totals[WORKSPACE_KEY]
    lines.append(f"**Workspace total:** {pct(ws_covered, ws_instrumented):.2f}%")
    lines.append("")
    lines.append("| Crate | Lines | Floor | Status |")
    lines.append("| --- | --- | --- | --- |")
    for crate in sorted(k for k in totals if k != WORKSPACE_KEY):
        covered, instrumented = totals[crate]
        crate_pct = pct(covered, instrumented)
        floor = floors.get(crate)
        floor_str = f"{floor:.2f}%" if floor is not None else "-"
        status = "OK"
        if crate in crate_failures:
            status = f"FAIL (< {MIN_CRATE_LINES}% minimum)"
        elif crate in ratchet_failures:
            status = f"FAIL (ratchet, floor {floor:.2f}%)"
        lines.append(f"| {crate} | {crate_pct:.2f}% | {floor_str} | {status} |")
    if WORKSPACE_KEY in ratchet_failures:
        lines.append(
            f"| workspace | {pct(ws_covered, ws_instrumented):.2f}% | "
            f"{floors.get(WORKSPACE_KEY, 0):.2f}% | FAIL (ratchet) |"
        )
    lines.append("")

    covered, total, per_file = patch_result
    lines.append("### Patch coverage")
    lines.append("")
    if total < MIN_PATCH_LINES:
        lines.append(
            f"Not enough changed instrumentable lines ({total} < {MIN_PATCH_LINES}); "
            "patch gate skipped."
        )
    else:
        patch_pct = pct(covered, total)
        status = "OK" if patch_pct >= MIN_PATCH else f"FAIL (< {MIN_PATCH}% minimum)"
        lines.append(f"**{patch_pct:.2f}%** of {total} changed lines covered ({status}).")
        below = {
            relpath: info
            for relpath, info in per_file.items()
            if pct(info["covered"], info["total"]) < MIN_PATCH
        }
        if below:
            lines.append("")
            lines.append("Changed files below 80% patch coverage:")
            lines.append("")
            lines.append("| File | Coverage | Uncovered lines |")
            lines.append("| --- | --- | --- |")
            for relpath in sorted(below):
                info = below[relpath]
                file_pct = pct(info["covered"], info["total"])
                lines.append(
                    f"| {relpath} | {file_pct:.2f}% | "
                    f"{format_ranges(sorted(info['uncovered_lines']))} |"
                )
    lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lcov", default="lcov.info", help="Path to the LCOV file.")
    parser.add_argument(
        "--base",
        default=None,
        help="Git ref to diff against (e.g. origin/develop, or HEAD~1). "
        "The gate diffs against the merge base of this ref and HEAD.",
    )
    parser.add_argument(
        "--floors",
        default=FLOORS_PATH,
        help="Path to the ratchet floors file.",
    )
    parser.add_argument(
        "--update-floors",
        action="store_true",
        help="Rewrite the floors file to this run's coverage and exit 0. Local use only.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.lcov):
        print(f"error: lcov file not found: {args.lcov}", file=sys.stderr)
        return 2

    files = parse_lcov(args.lcov)
    totals = aggregate_by_crate(files)

    if args.update_floors:
        write_floors(args.floors, totals)
        print(f"wrote {args.floors}")
        return 0

    floors = load_floors(args.floors)

    crate_failures = set()
    ratchet_failures = set()
    for crate, (covered, instrumented) in totals.items():
        crate_pct = pct(covered, instrumented)
        if crate != WORKSPACE_KEY and crate_pct < MIN_CRATE_LINES:
            crate_failures.add(crate)
        floor = floors.get(crate)
        if floor is not None and crate_pct < floor - RATCHET_TOLERANCE:
            ratchet_failures.add(crate)

    if args.base:
        base_sha = merge_base(args.base)
        changed = changed_lines_by_file(base_sha)
    else:
        changed = {}
    patch_result = patch_coverage(files, changed)
    covered, total, _ = patch_result
    patch_failed = total >= MIN_PATCH_LINES and pct(covered, total) < MIN_PATCH

    summary = build_summary(totals, floors, crate_failures, ratchet_failures, patch_result)
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary)
            handle.write("\n")

    failed = bool(crate_failures) or bool(ratchet_failures) or patch_failed
    if failed:
        print("", file=sys.stderr)
        if crate_failures:
            print(f"crates below {MIN_CRATE_LINES}%: {sorted(crate_failures)}", file=sys.stderr)
        if ratchet_failures:
            print(f"crates that dropped past the ratchet: {sorted(ratchet_failures)}", file=sys.stderr)
        if patch_failed:
            print(f"patch coverage below {MIN_PATCH}%", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
