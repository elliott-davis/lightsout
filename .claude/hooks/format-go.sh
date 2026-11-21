#!/usr/bin/env bash
# PostToolUse hook: format edited Go files with golangci-lint fmt. Never blocks.
path=$(jq -r '.tool_input.file_path // empty' 2>/dev/null) || exit 0
case "$path" in *.go) ;; *) exit 0 ;; esac
[ -f "$path" ] || exit 0
proj=${CLAUDE_PROJECT_DIR:-$(pwd)}
[ -f "$proj/Makefile" ] || exit 0
[ -f "$proj/tools/go.mod" ] || exit 0
# Call the formatter directly (no make/shell expansion of the path); "--" guards leading dashes.
if ! out=$(cd "$proj" && go tool -modfile=tools/go.mod golangci-lint fmt -- "$path" 2>&1); then
  echo "format-go: formatting failed for $path: $(printf '%s' "$out" | tail -n 1)" >&2
fi
exit 0
