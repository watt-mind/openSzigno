#!/usr/bin/env python3
"""Enforce a per-crate caught-mutant floor from a `cargo mutants` report.

Reads the `outcomes.json` that `cargo mutants` writes into its `mutants.out`
output directory and:

- computes the caught percentage for one crate as
  `caught / (caught + missed)`, deliberately excluding `timeout` and
  `unviable` outcomes from both sides of that fraction (a timeout is neither
  proof the mutant was caught nor a gap in the tests, and an unviable mutant
  never produced code that could run at all),
- enforces a ratchet against `scripts/mutants-floors.txt`: a crate may not
  drop more than `RATCHET_TOLERANCE` points below its recorded floor,
- prints a Markdown summary, including every surviving (missed) mutant's
  file, line, and description, to stdout and, when set, to
  `$GITHUB_STEP_SUMMARY`.

`--update-floors` rewrites the floors file to this run's caught percentage
for the given crate. It is a local (or nightly-workflow) convenience; a
pull-request build never passes it.

This mirrors `scripts/coverage_gate.py`'s ratchet model; see that script and
CONTRIBUTING.md's "Coverage quality gate" section for the pattern this
copies for mutation testing.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

RATCHET_TOLERANCE = 2.0
FLOORS_PATH = "scripts/mutants-floors.txt"

# The `summary` values `cargo mutants` writes into outcomes.json (see
# `mutants::outcome::SummaryOutcome` upstream). "Success" is the baseline
# (unmutated) build/test entry, not a mutant outcome, and is skipped.
CAUGHT = "CaughtMutant"
MISSED = "MissedMutant"
TIMEOUT = "Timeout"
UNVIABLE = "Unviable"
BASELINE = "Success"


# --------------------------------------------------------------------------
# outcomes.json parsing
# --------------------------------------------------------------------------


def load_outcomes(dir_path):
    """Return the list of per-mutant outcome dicts from `<dir_path>/outcomes.json`."""
    path = os.path.join(dir_path, "outcomes.json")
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data["outcomes"]


def mutant_info(outcome):
    """Return (file, line, description) for one mutant outcome."""
    mutant = outcome["scenario"]["Mutant"]
    line = mutant["span"]["start"]["line"]
    name = mutant["name"]
    # `name` is already "<file>:<line>:<col>: <description>"; keep only the
    # human-readable description after the first ": ".
    description = name.split(": ", 1)[1] if ": " in name else name
    return mutant["file"], line, description


def tally(outcomes, crate):
    """Return (caught, missed, timeout, unviable, survivors) for one crate.

    `survivors` is a list of (file, line, description) for every missed
    mutant, sorted by file then line.
    """
    caught = missed = timeout = unviable = 0
    survivors = []
    for outcome in outcomes:
        summary = outcome["summary"]
        if summary == BASELINE:
            continue
        mutant = outcome["scenario"].get("Mutant")
        if mutant is None:
            continue
        if mutant.get("package") != crate:
            continue
        if summary == CAUGHT:
            caught += 1
        elif summary == MISSED:
            missed += 1
            survivors.append(mutant_info(outcome))
        elif summary == TIMEOUT:
            timeout += 1
        elif summary == UNVIABLE:
            unviable += 1
    survivors.sort(key=lambda item: (item[0], item[1]))
    return caught, missed, timeout, unviable, survivors


def pct(caught, missed):
    denominator = caught + missed
    if denominator == 0:
        return 100.0
    return 100.0 * caught / denominator


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


def write_floors(path, crate, caught_pct):
    floors = load_floors(path)
    floors[crate] = caught_pct
    lines = [
        "# Mutation-testing ratchet floors. One `<crate> <percent>` pair per\n",
        "# line. A nightly run fails if a crate's caught-mutant percentage\n",
        f"# drops more than {RATCHET_TOLERANCE} points below its recorded value\n",
        "# here. `percent` is caught / (caught + missed); timeouts and unviable\n",
        "# mutants are excluded from both sides. Regenerate locally with:\n",
        "#   python3 scripts/mutants_gate.py --dir <mutants.out> --crate <crate> "
        "--update-floors\n",
        "# CI never updates this file.\n",
    ]
    for crate_name in sorted(floors):
        lines.append(f"{crate_name} {floors[crate_name]:.2f}\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------


def build_summary(crate, caught, missed, timeout, unviable, survivors, floor, failed):
    lines = []
    lines.append("## Mutation testing gate")
    lines.append("")
    caught_pct = pct(caught, missed)
    lines.append(f"**Crate:** `{crate}`")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("| --- | --- |")
    lines.append(f"| Caught | {caught} |")
    lines.append(f"| Missed (survivors) | {missed} |")
    lines.append(f"| Timeout | {timeout} |")
    lines.append(f"| Unviable | {unviable} |")
    lines.append("")
    floor_str = f"{floor:.2f}%" if floor is not None else "-"
    status = "OK"
    if failed:
        status = f"FAIL (ratchet, floor {floor_str})"
    lines.append(
        f"**Caught percentage:** {caught_pct:.2f}% of {caught + missed} viable, "
        f"non-timeout mutants (floor {floor_str}) — {status}"
    )
    lines.append("")
    if survivors:
        lines.append(f"### Surviving mutants ({len(survivors)})")
        lines.append("")
        lines.append("| File | Line | Description |")
        lines.append("| --- | --- | --- |")
        for file, line, description in survivors:
            lines.append(f"| {file} | {line} | {description} |")
        lines.append("")
    else:
        lines.append("No surviving mutants.")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dir",
        required=True,
        help="Path to the `mutants.out` directory `cargo mutants` wrote "
        "(the directory containing outcomes.json, not its parent).",
    )
    parser.add_argument(
        "--crate",
        required=True,
        help="Crate name to gate (e.g. openszigno-core). Outcomes are "
        "filtered to this crate's package, so a report covering more "
        "than one crate can still be gated crate by crate.",
    )
    parser.add_argument(
        "--floors",
        default=FLOORS_PATH,
        help="Path to the ratchet floors file.",
    )
    parser.add_argument(
        "--update-floors",
        action="store_true",
        help="Rewrite the floors file with this run's caught percentage "
        "for --crate and exit 0. Local/nightly convenience; a pull "
        "request build never passes it.",
    )
    args = parser.parse_args()

    outcomes_path = os.path.join(args.dir, "outcomes.json")
    if not os.path.exists(outcomes_path):
        print(f"error: outcomes file not found: {outcomes_path}", file=sys.stderr)
        return 2

    outcomes = load_outcomes(args.dir)
    caught, missed, timeout, unviable, survivors = tally(outcomes, args.crate)

    if caught + missed + timeout + unviable == 0:
        print(
            f"error: no mutants found for package '{args.crate}' in {outcomes_path}",
            file=sys.stderr,
        )
        return 2

    caught_pct = pct(caught, missed)

    if args.update_floors:
        write_floors(args.floors, args.crate, caught_pct)
        print(f"wrote {args.floors}")
        return 0

    floors = load_floors(args.floors)
    floor = floors.get(args.crate)
    failed = floor is not None and caught_pct < floor - RATCHET_TOLERANCE

    summary = build_summary(
        args.crate, caught, missed, timeout, unviable, survivors, floor, failed
    )
    print(summary)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(summary)
            handle.write("\n")

    if failed:
        print("", file=sys.stderr)
        print(
            f"'{args.crate}' caught percentage {caught_pct:.2f}% dropped more than "
            f"{RATCHET_TOLERANCE} points below its recorded floor {floor:.2f}%",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
