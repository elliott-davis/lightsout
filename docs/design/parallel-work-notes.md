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

## 11. Read-only reviewers still leave files in the shared tree

**What happened.** Reviewers were told not to edit the repo and to run their probes in a scratch copy. Even so, a stray
`internal/contract/zz_audit_test.go` (a failing probe) turned up in the working tree during the WI-04 review and later
vanished. Some agent had dropped it there briefly. If a commit, a `make check` or another reviewer had run at that
moment, it would have seen a failing test that belonged to no work item.

**Product implication.**
- "Read-only" has to be enforced, not requested. Reviewer sessions get read-only mounts of the code at the reviewed SHA
  (SEC-3: reviewers are read-only, which the forge enforces), and any scratch work happens in a separate writable layer that is
  discarded afterward.
- Gate and inner-loop runs must start from a pristine checkout of the exact SHA, so stray files from any session can't
  affect them (PIP-2, AGT-1).

## 12. A commit needs every agent to be quiet

**What happened.** WI-04 was approved and ready to commit while the WI-09 implementor was editing tracked files in
`internal/forge` and new files in `internal/codeowners`. The pre-commit hook temporarily stashes unstaged tracked files and
restores them afterwards, and it format-checks the whole tree. Running it under an active agent could have clobbered that
agent's edits during the stash window, or failed on its half-written files. So the commit waited until no agent was writing,
which in practice made the shared tree a global lock held across work items.

**Product implication.**
- With one shared tree, every commit serializes behind every in-flight change. The only way to scale is per-change
  workspaces, where a commit touches only its own tree (RUN-2).
- Repo hooks that rewrite or stash the working tree assume a single writer. Factory sessions must not depend on them
  (SEC-9 already says repo hooks never run in factory sessions); the factory's own checks run on the change's tree in its sandbox.

## 13. A human-held credential stalls every commit

**What happened.** Commits are SSH-signed through 1Password. Overnight, with the user away, signing began failing
(`1Password: failed to fill whole buffer`), because approval needs the user. Work kept going, but nothing could be committed. Finished,
approved work items then had to share the tree with newer in-progress ones that edit the same files. To keep the commits separable,
the finished item was staged exactly in git's index, later edits stayed unstaged on top, and a written plan records the commit order
for when signing works again.

**Product implication.**
- The factory's write path must not hinge on a credential that needs a human in the loop at commit time. Signing for
  factory-made commits uses a workload identity issued at egress (RUN-4, RUN-5), not a person's key.
- When a required external step is unavailable, the factory needs a durable queue of ready-but-unlanded changes. Each one is pinned to
  its exact tree, in dependency order, so nothing is lost or merged by accident when the step comes back (PIP-1, INT-14). A
  pile-up in one working directory is the failure mode to design out.

## 14. Three work items in one tree turn "the diff" into layers

**What happened.** With commits blocked, three work items lived in one checkout at once:
- WI-04: finished, staged in the index.
- WI-07: unstaged edits stacked on WI-04's staged files, plus new untracked packages.
- WI-09: unstaged edits in other packages, plus its own untracked package.

Every reviewer brief had to spell out which layer was theirs: "the `git diff` (working tree against the index) for these paths, these untracked files, and not `--cached`". One mistake in that recipe would mean reviewing someone else's change, or missing part of your own.

**Product implication.**
- A change has to be a first-class object with its own base SHA and tree, never a slice of a shared working directory. Reviewers receive `(base, head)` SHAs and review `Compare(base, head)` (WI-08), so they can't pick the wrong layer.
- Dependent changes stack explicitly: WI-07's base is WI-04's head commit, and that's recorded in the plan graph (INT-14), not implied by the index.

## 15. One item's dependency bump changes everyone's environment

**What happened.** WI-10a added `pgx`. Go's minimum version selection then raised `golang.org/x/text` from v0.14.0 to v0.41.0 in the shared `go.mod`.
- **The impact:** `internal/contract` uses x/text's Unicode case-folding and normalization tables for its security-relevant deny-list matching. From that moment, every other in-flight item (WI-07, WI-09) was being tested against different Unicode tables than the ones its own commit will carry. The staged WI-04 commit will carry the old `go.mod`.
- **How it was caught:** by watching `go.mod`. No test failed.

**Product implication.**
- The dependency graph is shared, non-switchable state (PIP-9, PIP-10). A change that alters `go.mod`/`go.sum`, or any lockfile, overlaps every other change in the repo and must be serialized against them, the same as a generated file.
- Verify must run each change against its own exact module graph at the merge-group candidate, never a workspace's (PIP-2).
- Dependency changes need their own review lens: what else moved transitively, and does any security-relevant behaviour depend on the moved module? The factory should surface transitive bumps in the PR, not just the direct addition (SEC-4's dependency scanning, extended to "what changed").

## 16. Independent reviewers collide in a shared scratch directory

**What happened.** During WI-13's second review round, the security reviewer and the Go reviewer were each told to "work in a copy under the scratchpad". Both picked the same name, `scratchpad/r2/`.
- **The collision:** the security reviewer's exploit tests (`zz_r2_test.go`) appeared in the Go reviewer's copy, and the Go reviewer's mutant files were deleted.
- **How it was caught:** the Go reviewer spotted it and discarded its results from that directory. Otherwise, the mutation survival rates and exploit verdicts would have silently mixed two reviews.

**Product implication.**
- "Independent review in a separate context" (AGT-5, SEC-12) has to include separate *filesystem* state, not just a separate conversation.
- **Isolated scratch space:** each reviewer, verifier or holdout run gets a scratch space named by the factory (job ID plus attempt), never one the agent chooses. That space is destroyed afterwards (RUN-1, RUN-4).
- **Scoped findings:** evidence that a reviewer reports, such as an exploit test or a mutant result, must be bound to the workspace digest it ran in. Then a finding from a contaminated workspace is detectable instead of trusted (PIP-2's evidence-binding discipline, applied to reviews).

## 17. A failure nobody can attribute

**What happened.** While the WI-15 implementor was verifying its work, one `make test` run failed in a package it hadn't touched, and the next two runs passed.
- **Missing evidence:** it didn't record which test failed or the shuffle seed.
- **Repro attempts:** five more full race runs on the same tree passed.
- **Environment:** several reviewers and implementors were running tests and mutation suites on the same machine at the time, so the failure could have come from CPU load, a half-written file another agent was editing, or a real timing bug.
- **Status:** none of those can be ruled out now.

**Product implication.**
- **Capture the run identity.** A failing gate run is evidence only if it carries everything needed to reproduce it: the shuffle seed, the exact tree digest, and the resource class it ran on (PIP-2, P4).
- **Isolate verification runs.** The factory must never run verification in a workspace that other agents can write to, or on a host whose load isn't accounted for (RUN-1).
- **Track flaky gates explicitly.** Retrying until green hides real defects. COST-4's same-gate failure counter needs a flake classification that a human can see, not a silent rerun.

**Resolution (later the same session).** It was a real bug, not load: a data race in WI-04's own test, where parallel subtests appended into one shared backing array. An independent reviewer running `-race -shuffle=on` with a recorded seed reproduced it. Two lessons follow:
- **"Five clean reruns" isn't evidence of absence.** Only a recorded seed made the failure reproducible.
- **An item can be "reviewed, three rounds, `make check` green" and still carry a latent race.** That race was staged for commit, and evidence from a single run would have hidden it.

## 18. A delegated change reported as done that never landed

**What happened.**
- **The report:** in WI-23 fix round 2, the implementor reported that `DefaultLimits` was raised to 16 MiB per file and 512 MiB total, and it updated the godoc and the design doc to match.
- **The reality:** the code edit itself never applied (a gofmt alignment mismatch made the replace miss). The code still said 1 MiB and 64 MiB.
- **Why nothing caught it:** every test passed, because no test pinned the defaults.
- **Who did catch it:** two independent round-3 reviewers. One ran a real-repo corpus and saw every PR on a repo with a 1.2 MB CRD fail. The other mutated the value and saw no test fail.
- **The cost:** one full review round spent on a "fixed" item.

**Product implication.**
- **An agent's report is a claim, not evidence (P4).** The factory must check every claimed change against the diff and against a test that would fail without it. Docs and comments agreeing with the claim prove nothing; here they were the only places the change landed.
- **Brief-driven requirements need a killing test (AGT-4, P4).** Any requirement stated as a value, such as a limit, cap, timeout or default, needs a test that pins that value. Otherwise "done" can't be told apart from "documented".
- **Reviewers need their own oracle.** Corpus runs and mutation testing caught this; reading the report could not. The reviewer role should be able to run its own checks rather than reading the implementor's summary (AGT-3).

## 19. Parking work outside the tree rewrote filenames

**What happened.**
- **Why files were parked:** the pre-commit hook stashes unstaged tracked files but not untracked ones. To commit one work item while others' untracked packages sat in the same tree, their files were moved to a scratch directory and moved back afterwards.
- **The damage:** the round trip back went through `tar`, which wrote five corpus filenames in Unicode NFD (`e` plus a combining accent) instead of the NFC (`é`) git had recorded. On macOS git still showed the tree as clean, because `core.precomposeunicode` folds the two forms together.
- **What caught it:** the differential test reads filenames from disk, and flagd's ASCII-only extension rule gives a different extension for the two forms. `make check` failed in the main tree while a clean worktree of the same commit passed.
- **The cost:** small, because the commit was right and only the working copy was wrong. A commit made *from* that working copy would have recorded the wrong names.

**Product implication.**
- **Never share a mutable workspace between work items (RUN-1).** Moving another item's files aside is a workaround for a shared tree, and every workaround is a new way to corrupt it. Each work item needs its own worktree or sandbox.
- **Verify from a fresh checkout of the exact commit (PIP-2).** A green run in the working tree, or a "clean" `git status`, doesn't prove the tree matches the commit. Only the clean-worktree runs distinguished "commit wrong" from "working copy wrong".
- **Byte-exact path identity matters to gates.** Gates that read repo paths must take them from the git tree at a SHA, as `gittree` does, never from a host filesystem that can normalize names.

## 20. An issue number written down before the issue existed

**What happened.** While WI-16 was in review, the orchestrator wrote a backlog note linking a follow-up as `#13`, and then filed the issue.
- **The collision:** the first push to `origin` had switched on Dependabot. It opened PR #13 (a `golang.org/x/text` bump) minutes earlier, and GitHub numbers issues and PRs from one sequence. The new issue became #14.
- **How it was caught:** the orchestrator listed recent issues just before filing, saw #12 as the newest *issue*, and still predicted wrong. It noticed only because `gh issue create` printed a different URL. It then fixed the link.
- **A second effect:** the bot's PR bumps `x/text`, which `internal/contract` pins for Unicode-version agreement (state.md). An agent that merged "routine" dependency PRs would have changed contract normalization silently.

**Product implication.**
- **Never predict a forge ID.** Issue, PR, comment and check IDs come only from the forge's response to the create call. The factory writes cross-references after creation, never before (INT-1 records on issues; NFR-6 trailers).
- **Other actors share every forge namespace.** Bots and humans create issues, PRs and branches concurrently with the factory, so any "next number" or "latest item" reasoning is a race.
- **Bot PRs are untrusted changes like any other (SEC-1).** A dependency bump goes through Verify, including the transitive and normalization effects in note 15, never auto-merge because a bot authored it.

## 21. Cleaning up a shared test database by name prefix

**What happened.** WI-10d's implementor and, later, two reviewers ran PostgreSQL tests against one shared `postgres:16-alpine` container.
- **The cleanup:** the implementor reported that it had dropped "all `lo_*` roles from the shared container", including roles leaked by earlier tests, while other agents could have been using the same server.
- **Why it mattered:** every agent's tests create roles with the `lo_` prefix. A prefix-wide `DROP ROLE` in the middle of another agent's run would make that run fail in a way it couldn't explain (see note 17), or would pass a test that never ran its real assertion.
- **How it was caught:** only because the implementor mentioned it in its report. Nothing failed visibly this time.
- **The root cause:** existing tests in `pgstore_test.go` leak roles, which tempted the agent into a global cleanup.

**Product implication.**
- **Per-run infrastructure, not shared servers (RUN-1, RUN-4).** Each verification run gets its own database server, or at least its own database, named by the factory, and it is destroyed afterwards. Agents never clean up by pattern in shared state.
- **Tests must not leak.** A leaked fixture is a cross-run dependency. Leaks should fail the test (cleanup asserted with `t.Cleanup`), not be swept up later.
