#!/usr/bin/env bash
# Stop hook: block ending a turn when lint fails on dirty Go changes.
input=$(cat)
active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null || echo false)
[ "$active" = true ] && exit 0
proj=${CLAUDE_PROJECT_DIR:-$(pwd)}
cd "$proj" 2>/dev/null || exit 0
git status --porcelain --untracked-files=all 2>/dev/null | grep -qE '(\.go|go\.mod|go\.sum|\.golangci\.yml)"?$' || exit 0
[ -f Makefile ] || exit 0
grep -qE '^lint:' Makefile || exit 0
if out=$(make -s lint 2>&1); then
  exit 0
fi
{
  echo "Lint failed on uncommitted Go changes; fix before finishing (or explain why you're stopping):"
  printf '%s\n' "$out" | tail -n 80
} >&2
exit 2
