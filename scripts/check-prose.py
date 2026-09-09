#!/usr/bin/env python3
"""Check tracked Markdown prose style rules.

Currently enforces CONTRIBUTING.md's "no em-dashes" rule: U+2014 is
rejected outside fenced code blocks (``` or ~~~). Fenced code, being
copied output or verbatim examples, is left alone.
"""
import glob
import sys

SKIP = ("target/", "refs/", "tmp/", "samples/", "node_modules/", "fuzz/target/")
EM_DASH = "—"


def check(path):
    problems = []
    in_fence = False
    fence_marker = None
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            stripped = line.strip()
            if stripped.startswith("```") or stripped.startswith("~~~"):
                marker = stripped[:3]
                if not in_fence:
                    in_fence = True
                    fence_marker = marker
                elif stripped.startswith(fence_marker):
                    in_fence = False
                continue
            if in_fence:
                continue
            if EM_DASH in line:
                problems.append((lineno, line.rstrip()))
    return problems


def main():
    problems = 0
    for path in sorted(glob.glob("**/*.md", recursive=True)):
        if path.startswith(SKIP):
            continue
        for lineno, line in check(path):
            print(f"{path}:{lineno}: em-dash (U+2014) outside code fence: {line}")
            problems += 1
    print(f"prose checked, problems={problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
