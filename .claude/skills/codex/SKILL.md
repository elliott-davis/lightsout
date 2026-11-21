---
name: codex
description: Get an independent second opinion from OpenAI Codex (read-only) on a design decision, a stuck bug, a disputed review finding, or a diff. Use before committing to hard-to-reverse designs, after two failed debugging hypotheses, when reviewers disagree, or before declaring a PRD milestone complete. Also when the user says "ask codex" or "second opinion".
---

# Codex second opinion

`scripts/codex.sh` runs Codex non-interactively in a **read-only sandbox** with an ephemeral session. Codex can read
the repo and run read-only commands, and it reads `AGENTS.md`. Only its final answer is printed to stdout, and the
transcript path goes to stderr.

Codex is an external service: the prompt and any files it reads are sent to OpenAI. Never include secrets or
credentials in the prompt.

## Ask a question

Codex starts with none of your context. Write the prompt like a brief to a senior peer: goal, constraints (PRD
IDs), what you've considered or ruled out, the specific question, and which files to read. Ask it to argue
against your position, not to confirm it.

```bash
scripts/codex.sh ask <<'EOF'
Goal: design the effective-contract resolver (PRD CON-3, CON-12, CON-13).
Current plan: <the plan, with the key types/interfaces>.
Alternatives I rejected and why: <...>.
Question: what breaks with this plan? In particular <specific worry>.
Read: PRD.md (Contracts section), internal/contract/*.go.
Give a recommendation, the strongest counter-argument, and what test would settle it.
EOF
```

## Review a diff

```bash
scripts/codex.sh review --uncommitted "Focus on correctness against PRD PIP-2 and SEC-10."
scripts/codex.sh review --base main
scripts/codex.sh review --commit <sha>
```

## Options and runtime

- `-e low|medium|high|xhigh` sets the reasoning effort. The default is the user's Codex config, which is slow (xhigh). Use
  `-e medium` for quick checks and leave the default for design reviews. `-m MODEL` overrides the model.
- A default-effort run can take several minutes. Run it with `run_in_background: true`, or with a Bash `timeout` of
  600000, and keep working meanwhile.

## Using the answer

Treat it as one more independent reviewer. It is not an authority. For each point:
- If it is a checkable claim, verify it with a test or the code before acting on it.
- If it conflicts with the PRD, AGENTS.md or a decision the user already made, the user's decision wins. Mention the
  conflict to the user if it seems important.
- If you still disagree after checking, say so in your summary with your evidence, rather than silently dropping
  the point or deferring to it.

Summarize for the user what Codex said, what you verified, and what you changed as a result.
