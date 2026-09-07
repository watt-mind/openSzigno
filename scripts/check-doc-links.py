#!/usr/bin/env python3
"""Check relative Markdown links and heading anchors across the repository.

External links are not fetched; CI must stay deterministic and offline.
"""
import glob
import os
import re
import sys

SKIP = ("target/", "refs/", "tmp/", "samples/", "node_modules/")
LINK = re.compile(r"\]\(([^)\s]+)\)")
HEADING = re.compile(r"^#+ (.*)$", re.M)


def anchors(path):
    text = open(path, encoding="utf-8").read()
    result = set()
    for heading in HEADING.findall(text):
        heading = re.sub(r"`", "", heading)
        slug = re.sub(r"[^\w\- ]", "", heading.lower()).strip().replace(" ", "-")
        result.add(slug)
    return result


def main():
    problems = 0
    for path in sorted(glob.glob("**/*.md", recursive=True)):
        if path.startswith(SKIP):
            continue
        for match in LINK.finditer(open(path, encoding="utf-8").read()):
            link = match.group(1)
            if link.startswith(("http://", "https://", "mailto:")):
                continue
            target, _, anchor = link.partition("#")
            resolved = (
                path if not target else os.path.normpath(os.path.join(os.path.dirname(path), target))
            )
            if not os.path.exists(resolved):
                print(f"{path}: broken link {link}")
                problems += 1
            elif anchor and resolved.endswith(".md") and anchor not in anchors(resolved):
                print(f"{path}: missing anchor {link}")
                problems += 1
    print(f"doc links checked, problems={problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
