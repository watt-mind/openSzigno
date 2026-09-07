#!/bin/sh
# commit-msg hook: enforce the Conventional Commits shape documented in
# CONTRIBUTING.md (type required, scope optional, `core` or `cli`).
# Reads .git/COMMIT_EDITMSG directly so it works under any hook runner.
set -eu

msg_file=".git/COMMIT_EDITMSG"
[ -f "$msg_file" ] || exit 0

# First non-comment, non-empty line is the subject.
subject=$(grep -v '^#' "$msg_file" | grep -v '^[[:space:]]*$' | head -n 1)

if printf '%s' "$subject" | grep -Eq '^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\((core|cli)\))?(!)?: [a-z].*[^.]$'; then
  exit 0
fi

cat >&2 <<'EOF'
Commit subject must be Conventional Commits, e.g.:

  fix(core): check the ZIP compression ratio on actual decoded bytes
  feat(cli): report the detected namespace in inspect output
  ci: add a weekly Gitleaks scan

Type is required, scope (if present) is `core` or `cli`, the summary is
imperative, lowercase, with no trailing period. See CONTRIBUTING.md.
EOF
exit 1
