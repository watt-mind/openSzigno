#!/bin/sh
# commit-msg hook: enforce the Conventional Commits shape documented in
# CONTRIBUTING.md (type required, scope optional, `core`, `author`, `cli`, or `verify`).
#
# Usage:
#   scripts/commit-msg.sh          # hook mode: reads .git/COMMIT_EDITMSG,
#                                   # a no-op if that file is absent, so it
#                                   # works under any hook runner
#   scripts/commit-msg.sh <file>   # checks the given message file
#   scripts/commit-msg.sh -        # checks a message read from stdin
#
# The file/stdin forms are what CI's `hygiene` job (.github/workflows/ci.yml)
# reuses to check every commit subject in a pull request's range.
set -eu

msg_file="${1:-.git/COMMIT_EDITMSG}"

if [ "$msg_file" = "-" ]; then
  subject=$(grep -v '^#' | grep -v '^[[:space:]]*$' | head -n 1)
else
  if [ ! -f "$msg_file" ]; then
    # Hook mode (no argument): missing COMMIT_EDITMSG is not this script's
    # problem. An explicit file argument that does not exist is an error.
    [ "$#" -eq 0 ] && exit 0
    echo "commit-msg.sh: no such file: $msg_file" >&2
    exit 1
  fi
  subject=$(grep -v '^#' "$msg_file" | grep -v '^[[:space:]]*$' | head -n 1)
fi

if printf '%s' "$subject" | grep -Eq '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\((core|author|cli|verify)\))?(!)?: [a-z].*[^.]$'; then
  exit 0
fi

cat >&2 <<EOF
Commit subject must be Conventional Commits, e.g.:

  fix(core): check the ZIP compression ratio on actual decoded bytes
  feat(cli): report the detected namespace in inspect output
  ci: add a weekly Gitleaks scan

Type is required, scope (if present) is \`core\`, \`author\`, \`cli\`, or \`verify\`, the summary is
imperative, lowercase, with no trailing period. See CONTRIBUTING.md.

Offending subject: $subject
EOF
exit 1
