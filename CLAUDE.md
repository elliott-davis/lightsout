@AGENTS.md

# Claude-specific workflow

## Loop per work item

1. **Plan** (you): pick the PRD IDs, read the relevant code, decide interfaces and file layout. For decisions
   that are expensive to reverse (data model, state machines, adapter interfaces, the authorization model), get a
   Codex second opinion with the `codex` skill before building.
2. **Implement**: delegate to the `implementor` subagent with a self-contained brief: IDs, files, the intended
   change, the tests to write for each acceptance criterion, and "run `make check`". Split independent pieces into
   parallel implementors when they don't touch the same files.
3. **Review**: in parallel, in separate contexts:
   - `go-reviewer` on the diff, every time.
   - `security-reviewer` when the change touches authorization, identity, policy and contracts, gates and checks,
     sandboxing and egress, credentials, holdouts, audit, or parses untrusted input. When unsure, run it.
   - `prd-tracer` when a work item claims to complete one or more requirement IDs.
   Give reviewers the diff target and the PRD IDs, not your conclusions.
4. **Fix** confirmed findings (via the implementor), then re-review. Cap at 3 rounds. Past that, stop and tell the user (as AGT-5 does).
5. **Verify** with `make check` yourself before reporting done.

## When to use Codex

Two ways in, both built on `scripts/codex.sh`:
- The **`codex` skill**: you call Codex directly (read-only) for a quick second opinion that you'll weigh yourself.
- The **`codex-delegate` subagent**: hands Codex a whole task, either a read-only review or a scoped coding task
  (`delegate` mode, writes limited to the repo, no network), then verifies the result with `make check` and reports.
  Use it for a second, independent implementation attempt after the implementor gets stuck, or to get a review in a
  separate context. Never run it on the same files as an active implementor.

Reach for Codex:
- before committing to a design that's hard to reverse,
- after two failed hypotheses on a bug,
- when reviewers disagree, or you disagree with a reviewer,
- before declaring a PRD milestone complete (`scripts/codex.sh review --base <branch>`).

Don't use it for routine edits. Treat its answer as another reviewer's opinion. Weigh it against evidence and
resolve disagreements by testing, not by deferring to either side.

## Hooks in this repo

- After every Edit/Write of a `.go` file, the file is auto-formatted (`make fmt-files`). Don't hand-format.
- On Stop, if Go files are dirty, `make lint` runs and blocks the stop on failure. Fix the findings. Don't silence them.
- Edits to `.golangci.yml`, CI workflows, `.claude/settings.json` and `.claude/hooks/` prompt the user. That's
  intentional, so explain why the change is needed.
