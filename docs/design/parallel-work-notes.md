# Field notes: parallel agent work

Status: running log, started 2026-11-21. Lightsout is built by an orchestrator running several implementor and
reviewer agents in parallel on one checkout. The problems that causes are the same ones the factory will have when it
runs many coding sessions against one repo. Each entry records what happened, what we did about it, and what it
implies for the product, with the PRD IDs it bears on. Add to it as new cases come up.

## 1. A shared working tree breaks every "is it green?" signal

**What happened.** Two or three implementors edited different packages in one working tree. The Stop hook's
`make lint`, `make check` and the reviewers' test runs repeatedly failed on *another* agent's half-written files: undefined
symbols, unused helpers waiting for their tests, gofumpt drift. A green signal for item A depended on whether item
B happened to compile at that moment.

**Workaround.**
- Scoped checks: `go test ./internal/<pkg>/...` and `golangci-lint run ./internal/<pkg>/...`.
- Telling agents and reviewers to ignore other packages.
- Explaining to the Stop hook why we were stopping.

**Product implication.** Every coding session needs its own isolated workspace: a sandbox or worktree per change
(RUN-2, SEC-3). The inner loop (AGT-1) can never share a tree with another change, or its results mean nothing. Gate
results must come from a clean checkout of an exact SHA, never from an agent's workspace (PIP-2).

## 2. "Commit what I changed" isn't well defined in a shared tree

**What happened.** The pre-commit tidy check stashes unstaged *tracked* files but not *untracked* ones. To commit one work
item while another item's new files existed, we had to move those files aside, commit, and move them back. After
each commit we re-ran `make check` in a clean `git worktree` at HEAD, to prove the commit stood alone without the
other item's uncommitted code.

**Product implication.**
- A change is an explicit set of file writes applied to a parent SHA, never "whatever is in the directory". The
  forge `BranchPusher.Push(expectedParent, change)` already models it this way (WI-08).
- Verify must build its evidence from that tree alone, at the merge-group candidate (PIP-2, PIP-1).

## 3. Repo-wide tools touch other changes' files

**What happened.** An implementor ran `make fmt`, which formats the whole repo, while another agent was mid-edit
elsewhere. After that, every brief said to format only your own files (`make fmt-files FILES=...`).

**Product implication.**
- Tools an agent runs must be scoped to its change's paths.
- Repo-wide formatters, generators and lockfile updates create overlap between otherwise independent changes. They
  are the shared non-switchable artifacts PIP-10 says to serialize, and the generated output INT-18 says must ride with its source.
- The factory should know which recipes are global, from the inner-loop recipes in AGT-8, and treat them as
  overlapping with everything.

## 4. Hidden dependencies on another change's uncommitted work

**What happened.**
- WI-08's gittree test for an over-long path segment passed only because WI-03's uncommitted pathglob change added a
  255-byte segment cap. The PRD trace caught it: WI-08 could not be committed before WI-03.
- WI-03 also added `WithDescendants`, `Segments` and `Runes` to `internal/pathglob` (WI-01, already committed). It changed
  `ValidatePath` semantics, which everything downstream depends on.

**Product implication.**
- The PR plan's dependency graph (INT-14) has to be derived from what each change actually reads and changes, not
  only from what was planned. A change that compiles against another unmerged change's code depends on it.
- Verify must catch this. Running each PR on its own merge-group candidate does exactly that (PIP-2, PIP-10).
- Changes to shared low-level packages ripple, so the planner should flag them as high-overlap.

## 5. Parallel items reach back into committed shared code

**What happened.** WI-06 (authz) needed `internal/audit` (WI-05, already committed) to accept denials without a role or
revision, and to require a hex revision on grants. That was a follow-on edit to a "done" package, made from another work item.

**Product implication.** "Done" packages get reopened by their consumers. PR shape rules (INT-18: one owner area per PR
unless the plan says otherwise) and contract ownership (CON-3: a change spanning two owners satisfies both contracts)
exist for exactly this. The planner should expect consumer-driven edits to providers and plan them as their own PR
or a declared cross-owner change.

## 6. Reviews must bind to a revision, not a live tree

**What happened.**
- Reviewers read the working tree while implementors on *other* items kept editing it.
- `git diff` doesn't show untracked files, so every review brief had to list the new files explicitly.
- One reviewer's probes ran against a scratch copy of the repo, so its timings came from a slightly different tree than the next reviewer's.

**Product implication.**
- Review evidence binds to an exact revision (SEC-10, AGT-3/AGT-4), and the diff is a tree diff between two SHAs. The forge
  `DiffReader.Compare` returns that diff, and `Review.CommitSHA` records the reviewed commit (WI-08).
- A review of a moving target isn't evidence.

## 7. Parallel reviewers duplicate and disagree

**What happened.**
- Two reviewers found the same defect in the same round:
  - the case-variant directory bypass (WI-03)
  - the unaudited denial on a cancelled context (WI-06)
  - the pusher not being bound to its change (WI-08)
- Reviewers disagreed on severity: one called the work-budget problem a blocker, another called it major.
- The orchestrator had to deduplicate, decide, and send one combined fix brief.

**Product implication.**
- Verify's review policy (WI-15) needs aggregation: deduplicate findings across reviewer agents, resolve severity
  disagreements, and send one replan or fix request (INT-15, INT-20).
- Independent reviewers are worth their cost. Each caught something the others missed.

## 8. Fix loops need a cap and an escalation path

**What happened.** WI-03 needed three fix rounds plus a fourth that the user authorized. Each round's fix exposed the
next layer of the same problem: work budgets counted segments, then runes, then didn't count gate merging. At the cap,
the orchestrator stopped and asked.

**Product implication.**
- This is AGT-5 (cap the fix loop, then escalate to a contract owner) and INT-15 (cap replans).
- The escalation needs to carry the evidence: what is fixed, what remains, and the recommended next step. That lets a human
  decide quickly without re-reading everything.

## 9. Fan-in of notifications

**What happened.** With 3–6 agents running at once, completion reports arrived interleaved. The orchestrator had to hold
partial results per item, wait for the rest of the batch, and avoid starting a fix round while a reviewer was still reading the same files.

**Product implication.**
- The control plane's event loop (WI-10) needs per-change state that holds which reviews are pending and which have returned.
- It must not start a coding run while reviews of the same revision are open, and it must treat a new push as invalidating any reviews in flight (PIP-2).

## 10. Contention on a shared package forces serialization

**What happened.** WI-07 (install config) is a new package, but it must also edit `internal/contract`. It moves the hardened
YAML parser into a shared `internal/yamlsafe`, and it adds the install revision to `contract.Baseline`. WI-04 was mid-flight in
`internal/contract` at the time, so WI-07 couldn't start until WI-04 was reviewed and committed, even though the two items are
logically independent. Every brief also had to carry a "don't touch package X" fence. Those fences were all that stopped agents from
colliding, and nothing enforced them.

**Product implication.**
- The planner must plan from the *files a change will touch*, including refactors of shared helpers, not from feature boundaries. Two features
  that both reach into one package are one serial chain (INT-14, PIP-10).
- The fences should be enforced, not just written into prompts: a change's writable paths are a contract-like scope that
  the sandbox enforces (CON-7, SEC-3). The pusher scoping in WI-08 is the same idea at the forge level.
