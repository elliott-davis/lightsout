---
name: prose-lint
description: This reviews prose against PAIS's writing-style rules and recommends fixes.  Use whenever the user runs `/prose-lint`, asks to check writing style or clarity, or asks to review a commit message, PR description, doc or similar before pushing/publishing.
---

# Prose lint

Checks prose written for humans against PAIS's style rules (below) and reports problems with suggested fixes. It does not touch code behavior — only text: commit messages, PR descriptions, code comments, documentation, diagnostic/error messages, investigations, JIRA tickets, README files, and code review comments.

## Procedure

We'll use a fresh-context subagent to read the text the way an unfamiliar reader would.

1. Spawn a subagent with: the style rules below, in full; the exact text to review (a diff, a file, a draft commit message or PR description); and instructions to report each violation as the offending text (or a short pointer to it), which rule it breaks, and suggested revisions.   Warn it that the new revised wording must follow the rules too!
2. Apply it's revisions, and confirm they follow the rules.  Fix them if they don't.

## Style rules

These rules apply to all prose intended for humans to read:

- Use plain language. Avoid unnecessary metaphors.
- Be terse but clear, and prefer short but complete sentences.  A sentence with more than 35 words is highly suspect.
- Noun-phrases are not sentences.
- AI-authored prose often over-documents technical decisions, providing wordy justifications with marginal value.  Delete such justifications.
- Document each thing at most once. Cross-reference using hyperlinks.
- Describe current reality, not past decisions that have been revised. Actively prune historical context that is no longer relevant.
- Place the right content in the right location:
    - For example, a docstring above a function definition may comment on the external behavior, but comments about implementation details belong inside the function body (if they're even needed at all).
    - Similarly, a long-form design proposal or investigation should start with a high-level problem, reserving detail for later sections.
    - When writing text that users will see (e.g. docstrings on public APIs, status messages, etc.), don't talk about implementation details or technical justifications. Only describe behavior that is visible and meaningful to users.
- Avoid buzzwords, superlatives, and filler words: best-in-class, world-class, cutting-edge, next-generation, seamless, turnkey, mission-critical, enterprise-grade, leverage (just use "use"), utilize (use "use"), synergy, honestly, genuinely, etc.  Prefer a concrete technical claim ("starts a workload in under two seconds" beats "provides seamless workload deployment").

### Special cases

#### Drafting new README files
- Start with a short statement of the purpose, then show (don't just explain) how to use the program.
- Do not show code layout — the directory structure already shows that and will get out of date as changes are made.

#### Investigations
- Document observable facts, with UTC timestamps and hyperlinks to relevant logs, etc.
- Minimize any speculation on root cause unless you're very confident, and always clearly separate that from facts.

#### Function and type doc comments
A doc comment states the contract a caller relies on: what the code does, what it returns, and how it fails. For each sentence, ask whether a caller would act differently without it. If not, delete it.

These patterns show a comment that records past edits instead of the current contract:
- History: commit hashes, "since", "as of", "no longer", "still". Describe the code as it is now. Git holds the history.
- Caller policy: "only called for…", "runs every time". The call site already shows which callers run the code, and when. Keep preconditions that a caller must meet, such as call order or concurrency limits.
- Arguments with a rejected alternative: "rather than X", "not the Y path", "stays accurate even if". Keep a reason only if a reader would otherwise "fix" the code into a bug, and state it in one sentence.
- Provenance: "the same steps Makefile Z encodes". Describe the behavior directly.
- Repeated facts: a requirement already documented on a config field, type, or call site. Point to that location once, or leave it out.

Most doc comments need one to three sentences. A second paragraph is a signal to check for the patterns above.

#### Code review prose
- Focus on actionable improvements, avoid praise.
- For a potential bug, clearly enumerate how the problem could be triggered through user input and/or external state.
- Avoid detail on implementation and line-number references, unless it's a short hyperlink to the relevant code (ideally with a git-sha permalink).
- Proposed fixes and implementation details are less important, and should be brief and suggestive, not thorough.
