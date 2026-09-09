#!/usr/bin/env python3
"""Enforce per-crate and patch line-coverage gates from an lcov report.

Reads an LCOV file produced by `cargo llvm-cov --workspace --lcov` and:

- computes per-crate line coverage (a crate is the first path component
  under `crates/`) and the workspace total,
- computes patch coverage: the percentage of lines added or modified by
  `git diff -U0 <base> HEAD` under `crates/*/src/**/*.rs` that lcov marks
  as covered, restricted to lines lcov actually instruments (present in a
  `DA:` record),
- enforces that every crate under `crates/` appears in the report at all,
  and that each is at or above `MIN_CRATE_LINES` percent,
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

`--self-test` runs this file's own unit tests — the diff parser's, which
is the part with edge cases a coverage report cannot show — and exits.
"""
from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import unittest
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
    """Percentage covered, where "nothing instrumented" is zero, not 100.

    A crate with no `DA:` records is not fully covered; it is not measured at
    all — a crate dropped from the report, a build that produced no
    instrumentation, a path the lcov parser did not recognise. Reporting 100
    there let exactly the case the gate exists to catch pass it.
    """
    if instrumented == 0:
        return 0.0
    return 100.0 * covered / instrumented


def workspace_crates(crates_dir):
    """Every crate directory under `crates/`, by name.

    A crate that builds but produces no coverage records — renamed, excluded
    by a filter, or simply missing from the report — used to vanish from the
    totals and so from the gate. It is now a failure: the gate reports on
    every crate in the workspace or it reports on nothing.
    """
    if not os.path.isdir(crates_dir):
        return set()
    return {
        name
        for name in os.listdir(crates_dir)
        if os.path.isfile(os.path.join(crates_dir, name, "Cargo.toml"))
    }


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


HUNK_RE = re.compile(r"^@@ -(?:\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
CHANGED_SRC_RE = re.compile(r"^crates/[^/]+/src/.*\.rs$")
# The prefixes the diff below is asked for explicitly, so neither
# `diff.noprefix` nor `diff.mnemonicPrefix` in a contributor's configuration
# can change what this parser has to strip.
SRC_PREFIX = "a/"
DST_PREFIX = "b/"


def merge_base(base_ref):
    out = subprocess.run(
        ["git", "merge-base", base_ref, "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return out


def parse_unified_diff(diff):
    """Return {relpath: set(new-file line numbers added or modified)}.

    A `-U0` diff is parsed with a state machine rather than by matching line
    prefixes, because inside a hunk the prefixes are ambiguous: an added
    source line that itself begins with `++` reads as a `+++ b/path` file
    header, and one beginning with `--` reads as `--- a/path`. Both are real
    Rust (`x ++ y` is not, but `++i` in a comment, a doc line of `+++`, or a
    string literal is), and either one used to silently repoint every
    following line at the wrong file — or at no file, quietly shrinking the
    patch the gate measures.

    So: `diff --git` starts a header, `+++` is only a file name while a
    header is open, and `@@` opens a hunk whose body is exactly as many lines
    as its counts say. Nothing inside a hunk body is read as anything but a
    body line.
    """
    changed = {}
    current_file = None
    in_header = False
    lineno = 0
    remaining_old = 0
    remaining_new = 0

    for line in diff.splitlines():
        if remaining_old or remaining_new:
            # Inside a hunk body: the only lines that mean anything are the
            # ones the hunk counts announced.
            if line.startswith("\\"):
                # "\ No newline at end of file" belongs to the line before it.
                continue
            if line.startswith("+"):
                if current_file is not None:
                    changed.setdefault(current_file, set()).add(lineno)
                lineno += 1
                remaining_new -= 1
            elif line.startswith("-"):
                # A deletion does not advance the new-file line counter.
                remaining_old -= 1
            else:
                # Context, which -U0 does not emit, but a caller may pass a
                # diff with context all the same.
                lineno += 1
                remaining_new -= 1
                remaining_old -= 1
            continue

        if line.startswith("diff --git "):
            in_header = True
            current_file = None
            continue
        hunk = HUNK_RE.match(line)
        if hunk:
            in_header = False
            remaining_old = 1 if hunk.group(1) is None else int(hunk.group(1))
            lineno = int(hunk.group(2))
            remaining_new = 1 if hunk.group(3) is None else int(hunk.group(3))
            continue
        if in_header and line.startswith("+++ "):
            path = line[4:].split("\t", 1)[0]
            if path == "/dev/null":
                current_file = None
                continue
            if path.startswith(DST_PREFIX):
                path = path[len(DST_PREFIX) :]
            current_file = path if CHANGED_SRC_RE.match(path) else None
            continue
    return changed


def changed_lines_by_file(base_sha):
    """Return {relpath: set(new-file line numbers added or modified)}."""
    diff = subprocess.run(
        [
            "git",
            "diff",
            "-U0",
            "--no-color",
            f"--src-prefix={SRC_PREFIX}",
            f"--dst-prefix={DST_PREFIX}",
            base_sha,
            "HEAD",
            "--",
            "crates",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return parse_unified_diff(diff)


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


def build_summary(totals, floors, crate_failures, ratchet_failures, patch_result, missing=()):
    lines = []
    lines.append("## Coverage gate")
    lines.append("")
    if missing:
        lines.append(
            "**Crates absent from the report:** "
            + ", ".join(f"`{crate}`" for crate in sorted(missing))
            + ". Every crate under `crates/` must appear in the coverage "
            "totals; a crate that produced no records is unmeasured, not "
            "fully covered."
        )
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
# Self-test
# --------------------------------------------------------------------------


class DiffParserTests(unittest.TestCase):
    """The diff parser's edge cases, which a coverage report cannot show."""

    def test_added_lines_are_numbered_from_the_hunk_header(self):
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "index 1111111..2222222 100644\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -10,0 +11,2 @@\n"
            "+let a = 1;\n"
            "+let b = 2;\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {11, 12}})

    def test_an_added_line_beginning_with_plus_plus_is_not_a_file_header(self):
        """The bug this parser exists for.

        `++ ` and `+++` inside a hunk body are source, not headers. Read as a
        header, the second file's lines used to be attributed to whatever the
        fake header named — here, nothing at all.
        """
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -0,0 +1,3 @@\n"
            "++ this line begins with two pluses\n"
            "+++ b/crates/evil/src/planted.rs\n"
            "+let real = 1;\n"
            "diff --git a/crates/x/src/b.rs b/crates/x/src/b.rs\n"
            "--- a/crates/x/src/b.rs\n"
            "+++ b/crates/x/src/b.rs\n"
            "@@ -0,0 +1 @@\n"
            "+let second = 2;\n"
        )
        self.assertEqual(
            parse_unified_diff(diff),
            {"crates/x/src/a.rs": {1, 2, 3}, "crates/x/src/b.rs": {1}},
        )

    def test_a_removed_line_beginning_with_dashes_is_not_a_file_header(self):
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -1,2 +1,1 @@\n"
            "--- a/crates/evil/src/planted.rs\n"
            "-let gone = 0;\n"
            "+let kept = 1;\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {1}})

    def test_deletions_do_not_advance_the_new_file_counter(self):
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -5,3 +5,2 @@\n"
            "-one\n"
            "-two\n"
            "-three\n"
            "+kept\n"
            "+also kept\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {5, 6}})

    def test_a_hunk_header_without_counts_means_one_line(self):
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -7 +7 @@\n"
            "-old\n"
            "+new\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {7}})

    def test_only_crate_sources_are_counted(self):
        diff = (
            "diff --git a/crates/x/tests/t.rs b/crates/x/tests/t.rs\n"
            "--- a/crates/x/tests/t.rs\n"
            "+++ b/crates/x/tests/t.rs\n"
            "@@ -0,0 +1 @@\n"
            "+let ignored = 1;\n"
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -0,0 +1 @@\n"
            "+let counted = 1;\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {1}})

    def test_a_deleted_file_contributes_nothing(self):
        diff = (
            "diff --git a/crates/x/src/gone.rs b/crates/x/src/gone.rs\n"
            "deleted file mode 100644\n"
            "--- a/crates/x/src/gone.rs\n"
            "+++ /dev/null\n"
            "@@ -1,2 +0,0 @@\n"
            "-one\n"
            "-two\n"
        )
        self.assertEqual(parse_unified_diff(diff), {})

    def test_a_missing_trailing_newline_marker_is_not_a_line(self):
        diff = (
            "diff --git a/crates/x/src/a.rs b/crates/x/src/a.rs\n"
            "--- a/crates/x/src/a.rs\n"
            "+++ b/crates/x/src/a.rs\n"
            "@@ -0,0 +1 @@\n"
            "+let only = 1;\n"
            "\\ No newline at end of file\n"
        )
        self.assertEqual(parse_unified_diff(diff), {"crates/x/src/a.rs": {1}})


class ScoringTests(unittest.TestCase):
    """The two scoring rules a report cannot be trusted without."""

    def test_nothing_instrumented_is_zero_not_full_coverage(self):
        self.assertEqual(pct(0, 0), 0.0)
        self.assertEqual(pct(0, 10), 0.0)
        self.assertEqual(pct(5, 10), 50.0)


def self_test():
    """Run the tests above and report the way a gate does: 0 or 1."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite(
        loader.loadTestsFromTestCase(case) for case in (DiffParserTests, ScoringTests)
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


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
        "--crates",
        default="crates",
        help="Path to the workspace's crates directory. Every crate under it "
        "must appear in the coverage totals.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run this script's own unit tests (the diff parser's) and exit.",
    )
    parser.add_argument(
        "--update-floors",
        action="store_true",
        help="Rewrite the floors file to this run's coverage and exit 0. Local use only.",
    )
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    if not os.path.exists(args.lcov):
        print(f"error: lcov file not found: {args.lcov}", file=sys.stderr)
        return 2

    files = parse_lcov(args.lcov)
    totals = aggregate_by_crate(files)
    missing = sorted(workspace_crates(args.crates) - set(totals))

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

    summary = build_summary(
        totals, floors, crate_failures, ratchet_failures, patch_result, missing
    )
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary)
            handle.write("\n")

    failed = bool(crate_failures) or bool(ratchet_failures) or patch_failed or bool(missing)
    if failed:
        print("", file=sys.stderr)
        if missing:
            print(
                f"crates under crates/ with no coverage records: {missing}",
                file=sys.stderr,
            )
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
