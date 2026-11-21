#!/usr/bin/env bash
# Verify DCO sign-off.
#   check-dco.sh <rev-range>          every non-merge commit in the range
#   check-dco.sh --msg-file <file>    one commit message (commit-msg hook)
set -euo pipefail

fix_hint() {
	echo "Fix: amend with 'git commit --amend -s', or for a range 'git rebase --signoff <base>'." >&2
	echo "The Signed-off-by email must match the commit author email." >&2
}

# signed_off <author-email> <trailer-lines...>: succeeds if any trailer matches.
signed_off() {
	local email=$1 line
	shift
	for line in "$@"; do
		case "$line" in
		*"<$email>"*) return 0 ;;
		esac
	done
	return 1
}

if [ "${1:-}" = "--msg-file" ]; then
	[ $# -eq 2 ] || { echo "usage: $0 --msg-file <file>" >&2; exit 2; }
	email=$(git var GIT_AUTHOR_IDENT | sed -E 's/^[^<]*<([^>]*)>.*$/\1/')
	lines=()
	while IFS= read -r l; do
		[ -n "$l" ] && lines+=("$l")
	done < <(git interpret-trailers --parse --only-trailers <"$2" | grep -i '^Signed-off-by:' || true)
	if [ ${#lines[@]} -eq 0 ] || ! signed_off "$email" "${lines[@]}"; then
		echo "error: commit message lacks 'Signed-off-by: ... <$email>'." >&2
		fix_hint
		exit 1
	fi
	exit 0
fi

[ $# -eq 1 ] || { echo "usage: $0 <rev-range> | --msg-file <file>" >&2; exit 2; }

shas=$(git rev-list --no-merges "$1") || { echo "error: cannot list commits in range '$1'" >&2; exit 2; }

bad=0
while IFS= read -r sha; do
	[ -n "$sha" ] || continue
	email=$(git log -1 --format=%ae "$sha")
	lines=()
	while IFS= read -r l; do
		[ -n "$l" ] && lines+=("$l")
	done < <(git log -1 --format='%(trailers:key=Signed-off-by,valueonly,separator=%x0A)' "$sha")
	if [ ${#lines[@]} -eq 0 ] || ! signed_off "$email" "${lines[@]}"; then
		echo "error: commit $(git log -1 --format='%h %s' "$sha") (author <$email>) has no matching Signed-off-by" >&2
		bad=1
	fi
done <<<"$shas"

if [ "$bad" -ne 0 ]; then
	fix_hint
	exit 1
fi
