#!/usr/bin/env bash
# Wrapper around OpenAI Codex: read-only ask/review, and workspace-write delegate.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  codex.sh ask [-m MODEL] [-e EFFORT] [PROMPT...]
      Ask Codex a question (read-only). Prompt from args, or stdin if no args.
  codex.sh delegate [-m MODEL] [-e EFFORT] [PROMPT...]
      Hand Codex a scoped coding task; it MAY WRITE files in the repo (workspace-write sandbox,
      no network). Prompt from args, or stdin. Lists files whose git status changed on stderr.
  codex.sh review [--uncommitted | --base BRANCH | --commit SHA] [-m MODEL] [-e EFFORT] [INSTRUCTIONS...]
      Run a Codex code review (read-only). Default target: --uncommitted.
      Instructions from args, or stdin if no args and stdin is not a terminal.
  codex.sh -h | --help

stdout: only Codex's final message. Full transcript: ${TMPDIR:-/tmp}/lightsout-codex/
Env: CODEX_BIN overrides the codex binary.
USAGE
}

die() { echo "codex.sh: $*" >&2; exit 1; }

case "${1:-}" in
  -h|--help|"") usage; [ -n "${1:-}" ] && exit 0; exit 2 ;;
esac

# Binary resolution
if [ -n "${CODEX_BIN:-}" ]; then
  codex_bin=$CODEX_BIN
elif command -v codex >/dev/null 2>&1; then
  codex_bin=$(command -v codex)
elif [ -x /Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex ]; then
  codex_bin=/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex
else
  die "codex binary not found (set CODEX_BIN, or install codex on PATH)"
fi
[ -x "$codex_bin" ] || die "codex binary not executable: $codex_bin"

# Repo root
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null || (cd "$script_dir/.." && pwd))
cd "$root"

sub=$1; shift
case "$sub" in ask|review|delegate) ;; *) usage >&2; die "unknown subcommand: $sub" ;; esac

model=""; effort=""; target=(); rest=()
while [ $# -gt 0 ]; do
  case "$1" in
    -m) [ $# -ge 2 ] || die "-m needs a value"; model=$2; shift 2 ;;
    -e) [ $# -ge 2 ] || die "-e needs a value"; effort=$2; shift 2 ;;
    --uncommitted)
      [ "$sub" = review ] || die "--uncommitted only valid for review"
      target=(--uncommitted); shift ;;
    --base|--commit)
      [ "$sub" = review ] || die "$1 only valid for review"
      [ $# -ge 2 ] || die "$1 needs a value"
      target=("$1" "$2"); shift 2 ;;
    --) shift; rest+=("$@"); break ;;
    *) rest+=("$1"); shift ;;
  esac
done

if [ ${#rest[@]} -gt 0 ]; then
  prompt="${rest[*]}"
elif [ "$sub" != review ] || [ ! -t 0 ]; then
  prompt=$(cat)
else
  prompt=""
fi

if [ "$sub" = delegate ]; then
  [ -n "$prompt" ] || die "empty prompt"
  preamble="You are implementing a scoped task delegated by another AI engineer in this repository. Follow AGENTS.md. Change only the files the task needs, don't commit, don't touch .golangci.yml, .github/, .claude/ or tools/go.mod. When done, list the files you changed and anything you couldn't verify."
  prompt="$preamble"$'\n\n'"$prompt"
fi
if [ "$sub" = ask ]; then
  [ -n "$prompt" ] || die "empty prompt"
  preamble="You are giving a second opinion to another AI engineer working in this repository. You are in a read-only sandbox: inspect files and run read-only commands as needed, but do not attempt to modify anything. Be direct: state disagreements plainly, cite file:line evidence, and say what you'd verify. Repository conventions are in AGENTS.md."
  prompt="$preamble"$'\n\n'"$prompt"
fi

logdir="${TMPDIR:-/tmp}/lightsout-codex"
logdir=${logdir//\/\//\/}
mkdir -p "$logdir"
stamp=$(date +%Y%m%d-%H%M%S)
log="$logdir/$stamp-$sub-$$.log"
out=$(mktemp "$logdir/.out.XXXXXX")
trap 'rm -f "$out"' EXIT

args=(exec)
[ "$sub" = review ] && args+=(review)
if [ "$sub" = ask ]; then
  args+=(-s read-only -C "$root")
elif [ "$sub" = delegate ]; then
  args+=(-s workspace-write -C "$root")
  if command -v go >/dev/null 2>&1; then
    gocache=$(go env GOCACHE 2>/dev/null || true)
    if [ -n "$gocache" ]; then
      args+=(-c "sandbox_workspace_write.writable_roots=[\"$gocache\"]")
    fi
  fi
else
  args+=(-c 'sandbox_mode="read-only"')
  [ ${#target[@]} -gt 0 ] || target=(--uncommitted)
  if [ -n "$prompt" ]; then
    # codex rejects target flags combined with a custom prompt: describe the target in the prompt instead.
    case "${target[0]}" in
      --uncommitted) desc="the uncommitted changes (staged, unstaged and untracked; use git status and git diff)" ;;
      --base) desc="the changes on this branch relative to base branch ${target[1]} (use git diff ${target[1]}...HEAD)" ;;
      --commit) desc="the changes introduced by commit ${target[1]} (use git show ${target[1]})" ;;
    esac
    prompt="Review $desc. Do not modify anything. Additional instructions: $prompt"
  else
    args+=("${target[@]}")
  fi
fi
args+=(--ephemeral --skip-git-repo-check -o "$out")
[ -n "$model" ] && args+=(-m "$model")
[ -n "$effort" ] && args+=(-c "model_reasoning_effort=\"$effort\"")

before=$(git status --porcelain 2>/dev/null || true)
rc=0
if [ "$sub" != review ]; then
  printf '%s' "$prompt" | "$codex_bin" "${args[@]}" - >"$log" 2>&1 || rc=$?
elif [ -n "$prompt" ]; then
  printf '%s' "$prompt" | "$codex_bin" "${args[@]}" - >"$log" 2>&1 || rc=$?
else
  "$codex_bin" "${args[@]}" </dev/null >"$log" 2>&1 || rc=$?
fi

if [ "$rc" -ne 0 ] || [ ! -s "$out" ] || ! grep -q '[^[:space:]]' "$out"; then
  echo "codex.sh: codex failed (exit $rc) or returned an empty final message. Log tail:" >&2
  tail -n 40 "$log" >&2
  echo "codex log: $log" >&2
  exit 1
fi

if [ "$sub" = delegate ]; then
  after=$(git status --porcelain 2>/dev/null || true)
  echo "files changed by codex:" >&2
  changed=$(diff <(printf '%s\n' "$before") <(printf '%s\n' "$after") | sed -n 's/^[<>] //p' | sort -u || true)
  printf '%s\n' "${changed:-(none detected)}" >&2
fi
cat "$out"
[ -z "$(tail -c1 "$out")" ] || echo
echo "codex log: $log" >&2
